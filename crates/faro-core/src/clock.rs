//! Time sources and clock-manipulation detection (ARCHITECTURE.md §3.6, §3.7).
//!
//! Every event header carries three notions of time: wall-clock `ts_ms`, a
//! monotonic `mono_ms` and an opaque `boot_id` that scopes `mono_ms`. The
//! wall clock is under the member's control (they can change the system
//! time); the monotonic clock is not. Comparing how much each advanced
//! between two observations in the same boot exposes wall-clock jumps, and
//! comparing the wall clock with the instance's clock exposes a skewed clock
//! that was set before the service started.
//!
//! [`SystemClock`] picks, per OS, a monotonic source that **keeps counting
//! while the machine sleeps**, so a laptop lid closed for an hour does not
//! look like a one-hour wall-clock jump. See [`SystemClock::COUNTS_SLEEP`].

use faro_proto::api::HeartbeatResponse;
use faro_proto::body::TamperSignal;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time, monotonic time and the current boot identity.
///
/// Implementations must guarantee that `mono_ms` never decreases for a given
/// `boot_id`. Values of `mono_ms` from different boots are not comparable.
pub trait Clock: Send + Sync {
    /// Wall-clock time as Unix milliseconds (UTC). May jump in either direction.
    fn wall_ms(&self) -> i64;
    /// Monotonic milliseconds since an arbitrary epoch that is fixed for the
    /// lifetime of [`Clock::boot_id`].
    fn mono_ms(&self) -> u64;
    /// Opaque identifier of the epoch `mono_ms` counts from.
    fn boot_id(&self) -> String;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn wall_ms(&self) -> i64 {
        (**self).wall_ms()
    }
    fn mono_ms(&self) -> u64 {
        (**self).mono_ms()
    }
    fn boot_id(&self) -> String {
        (**self).boot_id()
    }
}

impl<C: Clock + ?Sized> Clock for Arc<C> {
    fn wall_ms(&self) -> i64 {
        (**self).wall_ms()
    }
    fn mono_ms(&self) -> u64 {
        (**self).mono_ms()
    }
    fn boot_id(&self) -> String {
        (**self).boot_id()
    }
}

impl<C: Clock + ?Sized> Clock for Box<C> {
    fn wall_ms(&self) -> i64 {
        (**self).wall_ms()
    }
    fn mono_ms(&self) -> u64 {
        (**self).mono_ms()
    }
    fn boot_id(&self) -> String {
        (**self).boot_id()
    }
}

/// The real OS clock.
///
/// | OS | monotonic source | counts sleep | boot id |
/// |---|---|---|---|
/// | macOS | `clock_gettime(CLOCK_MONOTONIC_RAW)` (= `mach_continuous_time`) | yes | `kern.bootsessionuuid`, else `kern.boottime` |
/// | Linux / Android | `clock_gettime(CLOCK_BOOTTIME)` | yes | `/proc/sys/kernel/random/boot_id` |
/// | other Unix | `clock_gettime(CLOCK_MONOTONIC)` | OS-dependent | random per process |
/// | other (Windows) | `std::time::Instant` since process start | yes (QPC) | random per process |
///
/// On macOS `CLOCK_MONOTONIC_RAW` is used rather than `CLOCK_MONOTONIC`
/// because it is immune to NTP frequency slewing as well as to `settimeofday`.
/// On Linux `CLOCK_MONOTONIC` stops during suspend, so `CLOCK_BOOTTIME` is used.
///
/// Where no OS boot identity is available, the boot id is random per process
/// and the monotonic epoch is the process start. That keeps the contract
/// ("`mono_ms` is comparable only within one `boot_id`") honest at the cost
/// of losing cross-restart comparisons.
///
/// The boot id is computed **once** at construction and cached: on macOS
/// `kern.boottime` is itself shifted when the wall clock is changed, so
/// re-reading it would let a clock change masquerade as a reboot.
#[derive(Debug)]
pub struct SystemClock {
    boot_id: String,
    /// High-water mark so a transient `clock_gettime` failure (or a
    /// non-monotone fallback) can never make `mono_ms` go backwards.
    last_mono: AtomicU64,
    #[cfg(not(unix))]
    anchor: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    /// Whether [`SystemClock::mono_ms`] keeps advancing while the machine sleeps
    /// on this platform. When `false`, callers should call
    /// [`ClockGuard::reset`] on wake to avoid false clock-manipulation alarms.
    pub const COUNTS_SLEEP: bool = cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        not(unix)
    ));

    pub fn new() -> Self {
        SystemClock {
            boot_id: os_boot_id().unwrap_or_else(random_boot_id),
            last_mono: AtomicU64::new(0),
            #[cfg(not(unix))]
            anchor: std::time::Instant::now(),
        }
    }

    #[cfg(unix)]
    fn raw_mono_ms(&self) -> Option<u64> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let id = libc::CLOCK_MONOTONIC_RAW;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let id = libc::CLOCK_BOOTTIME;
        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        )))]
        let id = libc::CLOCK_MONOTONIC;
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec and `id` is a clock id
        // supported on this target; clock_gettime only writes into `ts`.
        let rc = unsafe { libc::clock_gettime(id, &mut ts) };
        if rc != 0 {
            return None;
        }
        let secs = u64::try_from(ts.tv_sec).ok()?;
        let nanos = u64::try_from(ts.tv_nsec).ok()?;
        secs.checked_mul(1000)?.checked_add(nanos / 1_000_000)
    }

    #[cfg(not(unix))]
    fn raw_mono_ms(&self) -> Option<u64> {
        u64::try_from(self.anchor.elapsed().as_millis()).ok()
    }
}

impl Clock for SystemClock {
    fn wall_ms(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => i64::try_from(e.duration().as_millis())
                .map(|v| -v)
                .unwrap_or(i64::MIN),
        }
    }

    fn mono_ms(&self) -> u64 {
        match self.raw_mono_ms() {
            Some(now) => {
                let prev = self.last_mono.fetch_max(now, Ordering::AcqRel);
                prev.max(now)
            }
            None => {
                tracing::warn!("monotonic clock read failed; reusing last value");
                self.last_mono.load(Ordering::Acquire)
            }
        }
    }

    fn boot_id(&self) -> String {
        self.boot_id.clone()
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn sysctl_bytes(name: &std::ffi::CStr, buf: &mut [u8]) -> Option<usize> {
    let mut len: libc::size_t = buf.len();
    // SAFETY: `name` is NUL-terminated, `buf` is writable for `len` bytes and
    // sysctlbyname writes at most `len` bytes, updating `len` with the size.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && len <= buf.len()).then_some(len)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn os_boot_id() -> Option<String> {
    // Preferred: a UUID the kernel generates once per boot and never changes.
    let mut buf = [0u8; 64];
    if let Some(len) = sysctl_bytes(c"kern.bootsessionuuid", &mut buf) {
        let s = String::from_utf8_lossy(&buf[..len]);
        let s = s.trim_end_matches('\0').trim();
        if !s.is_empty() {
            return Some(format!("macos-uuid-{s}"));
        }
    }
    // Fallback: boot time. Read once (see SystemClock docs).
    let mut tv = [0u8; std::mem::size_of::<libc::timeval>()];
    let len = sysctl_bytes(c"kern.boottime", &mut tv)?;
    if len != tv.len() {
        return None;
    }
    // SAFETY: the buffer holds exactly one `timeval` written by the kernel;
    // read_unaligned tolerates the byte array's alignment.
    let tv: libc::timeval = unsafe { std::ptr::read_unaligned(tv.as_ptr().cast()) };
    Some(format!("macos-boottime-{}.{:06}", tv.tv_sec, tv.tv_usec))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_boot_id() -> Option<String> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| format!("linux-{s}"))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "linux",
    target_os = "android"
)))]
fn os_boot_id() -> Option<String> {
    None
}

fn random_boot_id() -> String {
    let b: [u8; 16] = faro_crypto::random_bytes();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("proc-{hex}")
}

/// A hand-driven clock for tests and simulations. Clones share state.
#[derive(Debug, Clone)]
pub struct ManualClock {
    inner: Arc<Mutex<ManualState>>,
}

#[derive(Debug, Clone)]
struct ManualState {
    wall_ms: i64,
    mono_ms: u64,
    boot_id: String,
    boots: u64,
}

impl ManualClock {
    pub fn new(wall_ms: i64, mono_ms: u64) -> Self {
        ManualClock {
            inner: Arc::new(Mutex::new(ManualState {
                wall_ms,
                mono_ms,
                boot_id: "manual-boot-0".into(),
                boots: 0,
            })),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut ManualState) -> T) -> T {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        f(&mut g)
    }

    /// Let real time pass: both clocks advance by `ms`.
    pub fn advance(&self, ms: u64) {
        self.with(|s| {
            s.mono_ms = s.mono_ms.saturating_add(ms);
            s.wall_ms = s
                .wall_ms
                .saturating_add(i64::try_from(ms).unwrap_or(i64::MAX));
        });
    }

    /// Change only the wall clock (what a user setting the system time does).
    pub fn jump_wall(&self, delta_ms: i64) {
        self.with(|s| s.wall_ms = s.wall_ms.saturating_add(delta_ms));
    }

    pub fn set_wall(&self, wall_ms: i64) {
        self.with(|s| s.wall_ms = wall_ms);
    }

    /// Simulate a reboot: new boot id, monotonic clock restarts at `mono_ms`.
    pub fn reboot(&self, mono_ms: u64) {
        self.with(|s| {
            s.boots += 1;
            s.boot_id = format!("manual-boot-{}", s.boots);
            s.mono_ms = mono_ms;
        });
    }
}

impl Clock for ManualClock {
    fn wall_ms(&self) -> i64 {
        self.with(|s| s.wall_ms)
    }
    fn mono_ms(&self) -> u64 {
        self.with(|s| s.mono_ms)
    }
    fn boot_id(&self) -> String {
        self.with(|s| s.boot_id.clone())
    }
}

/// One reading of a [`Clock`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockObservation {
    pub wall_ms: i64,
    pub mono_ms: u64,
    pub boot_id: String,
}

impl ClockObservation {
    pub fn read(clock: &dyn Clock) -> Self {
        // Read the boot id first so a reboot between reads can only make the
        // observation look like it belongs to the *old* boot with a large
        // mono value, never the reverse.
        let boot_id = clock.boot_id();
        let mono_ms = clock.mono_ms();
        let wall_ms = clock.wall_ms();
        ClockObservation {
            wall_ms,
            mono_ms,
            boot_id,
        }
    }
}

/// Thresholds for [`ClockGuard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockGuardConfig {
    /// Maximum tolerated `|wall_delta - mono_delta|` between two local
    /// observations in the same boot. Default 120 s: NTP corrections are
    /// normally sub-second, and even a large step after a long offline period
    /// is rare; a manual change of the time is usually minutes or more.
    pub local_threshold_ms: i64,
    /// Maximum tolerated `|local_wall - server_wall|`. Default 10 min, well
    /// above request latency and the 5 min request-signature skew window.
    pub server_threshold_ms: i64,
    /// Rate of legitimate wall-vs-monotonic divergence tolerated by the
    /// *cumulative* local check, in parts per million of elapsed monotonic
    /// time. Default 1000 ppm (86 s/day): an order of magnitude above real
    /// oscillator error and NTP corrections (typically < 100 ppm), so it never
    /// fires on honest machines, while a clock walked back in small steps
    /// (each under `local_threshold_ms`) is caught once the total exceeds
    /// `local_threshold_ms` plus this allowance.
    pub max_drift_ppm: u32,
}

impl Default for ClockGuardConfig {
    fn default() -> Self {
        ClockGuardConfig {
            local_threshold_ms: 120_000,
            server_threshold_ms: 600_000,
            max_drift_ppm: 1_000,
        }
    }
}

/// Detects wall-clock manipulation (§3.6 "Clock tampering", §3.7).
///
/// * **Local check** ([`ClockGuard::observe`]): between two observations in
///   the same boot, the wall clock and the monotonic clock must advance by
///   about the same amount. After a report the guard re-baselines, so one
///   jump yields exactly one signal.
/// * **Cumulative local check**: the same comparison against an *anchor*
///   (the first observation of the boot, or the last report). Without it a
///   clock walked back 110 s every minute would never trip the per-step
///   threshold while drifting without bound. The tolerance grows with
///   elapsed time by [`ClockGuardConfig::max_drift_ppm`] so honest
///   oscillator drift over a long uptime is not reported.
/// * **Server check** ([`ClockGuard::check_server_time`]): the local wall
///   clock must agree with the instance's clock. This catches a clock that was
///   changed while the service was not running. The signal is latched: it is
///   raised once when skew first exceeds the threshold and re-armed when the
///   clock comes back in range, so a persistently wrong clock does not spam
///   allies on every heartbeat.
#[derive(Debug, Clone)]
pub struct ClockGuard {
    cfg: ClockGuardConfig,
    last: Option<ClockObservation>,
    /// Baseline for the cumulative check; always from the same boot as `last`.
    anchor: Option<ClockObservation>,
    server_skew_reported: bool,
}

impl Default for ClockGuard {
    fn default() -> Self {
        Self::new(ClockGuardConfig::default())
    }
}

impl ClockGuard {
    pub fn new(cfg: ClockGuardConfig) -> Self {
        ClockGuard {
            cfg,
            last: None,
            anchor: None,
            server_skew_reported: false,
        }
    }

    pub fn config(&self) -> ClockGuardConfig {
        self.cfg
    }

    /// Forget the local baseline (e.g. on wake when the platform's monotonic
    /// clock does not count sleep; see [`SystemClock::COUNTS_SLEEP`]).
    pub fn reset(&mut self) {
        self.last = None;
        self.anchor = None;
    }

    /// Read `clock` and run the local check.
    pub fn observe_clock(&mut self, clock: &dyn Clock) -> Option<TamperSignal> {
        self.observe(ClockObservation::read(clock))
    }

    /// Run the local check against the previous observation.
    ///
    /// Returns `ClockManipulation { wall_delta_ms, mono_delta_ms }` with the
    /// deltas since the previous observation when they disagree by more than
    /// the threshold. A monotonic clock that went *backwards* within a boot is
    /// also reported (with a negative `mono_delta_ms`): it should be
    /// impossible and indicates a tampered time source.
    pub fn observe(&mut self, obs: ClockObservation) -> Option<TamperSignal> {
        let same_boot = self
            .last
            .as_ref()
            .is_some_and(|prev| prev.boot_id == obs.boot_id);
        let signal = if same_boot {
            let step = self.last.as_ref().and_then(|prev| {
                let (wall_delta, mono_delta) = deltas(prev, &obs);
                let drift = (wall_delta - mono_delta).abs();
                (mono_delta < 0 || drift > i128::from(self.cfg.local_threshold_ms))
                    .then(|| manipulation(wall_delta, mono_delta))
            });
            step.or_else(|| {
                // Cumulative check against the anchor. `mono` cannot have
                // gone backwards here (the step check would have fired).
                let anchor = self.anchor.as_ref()?;
                let (wall_el, mono_el) = deltas(anchor, &obs);
                let allowance = i128::from(self.cfg.local_threshold_ms)
                    + mono_el.max(0) * i128::from(self.cfg.max_drift_ppm) / 1_000_000;
                ((wall_el - mono_el).abs() > allowance).then(|| manipulation(wall_el, mono_el))
            })
        } else {
            // First observation, or a new boot: nothing to compare with.
            None
        };
        if !same_boot || signal.is_some() {
            self.anchor = Some(obs.clone());
        }
        self.last = Some(obs);
        signal
    }

    /// Compare the local wall clock (read when the response arrived) with the
    /// instance's `server_time_ms`.
    ///
    /// On a report, `wall_delta_ms` is the skew `local - server` and
    /// `mono_delta_ms` is 0 (no monotonic interval is involved).
    pub fn check_server_time(
        &mut self,
        local_wall_ms: i64,
        resp: &HeartbeatResponse,
    ) -> Option<TamperSignal> {
        self.check_server_wall(local_wall_ms, resp.server_time_ms)
    }

    /// Same as [`ClockGuard::check_server_time`] with a raw server timestamp.
    pub fn check_server_wall(
        &mut self,
        local_wall_ms: i64,
        server_wall_ms: i64,
    ) -> Option<TamperSignal> {
        let skew = i128::from(local_wall_ms) - i128::from(server_wall_ms);
        if skew.abs() > i128::from(self.cfg.server_threshold_ms) {
            if self.server_skew_reported {
                return None;
            }
            self.server_skew_reported = true;
            Some(TamperSignal::ClockManipulation {
                wall_delta_ms: saturate_i64(skew),
                mono_delta_ms: 0,
            })
        } else {
            self.server_skew_reported = false;
            None
        }
    }
}

/// `(wall, mono)` advance from `a` to `b`, exact (no overflow) in `i128`.
fn deltas(a: &ClockObservation, b: &ClockObservation) -> (i128, i128) {
    (
        i128::from(b.wall_ms) - i128::from(a.wall_ms),
        i128::from(b.mono_ms) - i128::from(a.mono_ms),
    )
}

fn manipulation(wall_delta: i128, mono_delta: i128) -> TamperSignal {
    TamperSignal::ClockManipulation {
        wall_delta_ms: saturate_i64(wall_delta),
        mono_delta_ms: saturate_i64(mono_delta),
    }
}

fn saturate_i64(v: i128) -> i64 {
    i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manip(sig: Option<TamperSignal>) -> Option<(i64, i64)> {
        match sig {
            Some(TamperSignal::ClockManipulation {
                wall_delta_ms,
                mono_delta_ms,
            }) => Some((wall_delta_ms, mono_delta_ms)),
            Some(other) => panic!("unexpected {other:?}"),
            None => None,
        }
    }

    #[test]
    fn system_clock_is_sane_and_monotone() {
        let c = SystemClock::new();
        let a = c.mono_ms();
        let w = c.wall_ms();
        let b = c.mono_ms();
        assert!(b >= a);
        // After 2020-01-01 and before 2200.
        assert!(w > 1_577_836_800_000 && w < 7_258_118_400_000, "{w}");
        let id = c.boot_id();
        assert!(!id.is_empty());
        assert_eq!(id, c.boot_id(), "boot id is cached and stable");
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert!(!id.starts_with("proc-"), "OS boot id expected, got {id}");
    }

    #[test]
    fn two_system_clocks_share_boot_id() {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        assert_eq!(SystemClock::new().boot_id(), SystemClock::new().boot_id());
    }

    #[test]
    fn normal_passage_of_time_is_quiet() {
        let c = ManualClock::new(1_000_000, 50);
        let mut g = ClockGuard::default();
        assert_eq!(g.observe_clock(&c), None);
        for _ in 0..100 {
            c.advance(30_000);
            c.jump_wall(500); // small NTP corrections
            assert_eq!(g.observe_clock(&c), None);
        }
    }

    #[test]
    fn forward_and_backward_jumps_detected_once() {
        let c = ManualClock::new(1_000_000, 50);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        c.advance(10_000);
        c.jump_wall(3_600_000);
        assert_eq!(manip(g.observe_clock(&c)), Some((3_610_000, 10_000)));
        c.advance(10_000);
        assert_eq!(g.observe_clock(&c), None, "re-baselined after report");
        c.jump_wall(-86_400_000);
        assert_eq!(manip(g.observe_clock(&c)), Some((-86_400_000, 0)));
    }

    #[test]
    fn threshold_is_inclusive_boundary() {
        let c = ManualClock::new(0, 0);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        c.jump_wall(120_000);
        assert_eq!(
            g.observe_clock(&c),
            None,
            "exactly at threshold is tolerated"
        );
        c.jump_wall(120_001);
        assert!(g.observe_clock(&c).is_some());
    }

    #[test]
    fn reboot_rebaselines() {
        let c = ManualClock::new(1_000_000, 5_000_000);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        c.reboot(10);
        c.jump_wall(5_000);
        assert_eq!(g.observe_clock(&c), None);
        c.advance(1_000);
        c.jump_wall(-1_000_000);
        assert!(g.observe_clock(&c).is_some());
    }

    #[test]
    fn mono_going_backwards_in_same_boot_is_reported() {
        let mut g = ClockGuard::default();
        let o = |w, m| ClockObservation {
            wall_ms: w,
            mono_ms: m,
            boot_id: "b".into(),
        };
        g.observe(o(1000, 1000));
        assert_eq!(manip(g.observe(o(1000, 900))), Some((0, -100)));
    }

    #[test]
    fn extreme_values_do_not_overflow() {
        let mut g = ClockGuard::default();
        let o = |w, m| ClockObservation {
            wall_ms: w,
            mono_ms: m,
            boot_id: "b".into(),
        };
        g.observe(o(i64::MIN, 0));
        // Both deltas are 2^64-1: consistent, so no signal, and no overflow.
        assert_eq!(g.observe(o(i64::MAX, u64::MAX)), None);
        // Wall jumps across the whole range while mono stands still.
        g.observe(o(i64::MIN, 5));
        assert_eq!(manip(g.observe(o(i64::MAX, 5))), Some((i64::MAX, 0)));
        // Mono jumps the whole range while wall stands still.
        g.observe(o(0, 0));
        assert_eq!(manip(g.observe(o(0, u64::MAX))), Some((0, i64::MAX)));
    }

    #[test]
    fn server_skew_latched() {
        let mut g = ClockGuard::default();
        let resp = |t| HeartbeatResponse {
            server_time_ms: t,
            next_in_secs: 300,
            acked_through: None,
        };
        assert_eq!(
            g.check_server_time(1_000_000, &resp(1_000_000 + 599_000)),
            None
        );
        assert_eq!(
            manip(g.check_server_time(1_000_000, &resp(1_000_000 + 3_600_000))),
            Some((-3_600_000, 0))
        );
        // Still skewed: not reported again.
        assert_eq!(
            g.check_server_time(1_000_000, &resp(1_000_000 + 3_600_000)),
            None
        );
        // Back in range re-arms.
        assert_eq!(g.check_server_time(1_000_000, &resp(1_000_000)), None);
        assert!(g
            .check_server_time(1_000_000 + 700_000, &resp(1_000_000))
            .is_some());
    }

    /// Regression: walking the clock back in steps that each stay under the
    /// per-step threshold used to go unnoticed forever.
    #[test]
    fn gradual_walk_back_is_detected() {
        let c = ManualClock::new(1_800_000_000_000, 0);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        let mut hits = Vec::new();
        for i in 0..60 {
            c.advance(60_000);
            c.jump_wall(-110_000);
            if let Some(sig) = manip(g.observe_clock(&c)) {
                hits.push((i, sig));
            }
        }
        // Detected on the 2nd step (220 s cumulative > 120 s + 0.12 s), then
        // re-anchored, so roughly every other step after that: never silent.
        assert_eq!(hits[0], (1, (-100_000, 120_000)));
        assert!(hits.len() >= 25, "{hits:?}");
    }

    /// Honest drift well above real oscillator error over a long uptime
    /// stays quiet: 500 ppm for 30 days is 21.6 minutes of divergence.
    #[test]
    fn slow_honest_drift_is_quiet() {
        let c = ManualClock::new(1_800_000_000_000, 0);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        for _ in 0..(30 * 24 * 60) {
            c.advance(60_000);
            c.jump_wall(30); // 30 ms per minute = 500 ppm
            assert_eq!(g.observe_clock(&c), None);
        }
    }

    #[test]
    fn reset_and_reboot_clear_the_anchor() {
        let c = ManualClock::new(0, 0);
        let mut g = ClockGuard::default();
        g.observe_clock(&c);
        c.advance(60_000);
        c.jump_wall(-100_000);
        assert_eq!(g.observe_clock(&c), None);
        g.reset();
        g.observe_clock(&c);
        c.advance(60_000);
        c.jump_wall(-100_000);
        assert_eq!(g.observe_clock(&c), None, "anchor moved by reset");
        c.reboot(0);
        g.observe_clock(&c);
        c.advance(60_000);
        c.jump_wall(-100_000);
        assert_eq!(g.observe_clock(&c), None, "anchor moved by reboot");
        c.advance(60_000);
        c.jump_wall(-100_000);
        assert!(g.observe_clock(&c).is_some());
    }

    #[test]
    fn custom_thresholds() {
        let mut g = ClockGuard::new(ClockGuardConfig {
            local_threshold_ms: 1_000,
            server_threshold_ms: 1_000,
            max_drift_ppm: 0,
        });
        let c = ManualClock::new(0, 0);
        g.observe_clock(&c);
        c.jump_wall(1_500);
        assert!(g.observe_clock(&c).is_some());
        assert!(g.check_server_wall(0, 1_001).is_some());
    }
}
