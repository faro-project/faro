//! Idle, lock, display-sleep and system-sleep state of the interactive
//! session, plus the "whose desktop is on screen" checks capture relies on.
//!
//! * **Idle**: `GetLastInputInfo`, the tick of the last keyboard or mouse
//!   input in *this* session, against `GetTickCount`. Both are 32-bit
//!   millisecond counters that wrap every 49.7 days, so the difference is
//!   taken with wrapping arithmetic.
//! * **Locked**: the lock flag of `WTSQuerySessionInformationW(…,
//!   WTSSessionInfoEx)` (`WTS_SESSIONSTATE_LOCK`). Windows 7 and Server 2008
//!   R2 report that flag inverted; Faro needs Windows 10 22H2 or later, where
//!   it is correct. When the flag reads "unknown", the input desktop decides
//!   instead (see [`input_desktop`]): a session whose input desktop is not
//!   the one the agent runs on is showing the logon desktop, which is what a
//!   locked session shows. That fallback also reads a UAC prompt as
//!   "locked" for as long as it is up.
//! * **Display asleep**: `GUID_CONSOLE_DISPLAY_STATE` through
//!   `PowerSettingRegisterNotification` with a callback (no window needed).
//!   Windows calls the callback once with the current state on registration
//!   and on every change; until the first call the display reads awake. The
//!   state is that of the *console* display: in a remote (RDP) session it
//!   says nothing about the remote client's screen. Best effort.
//! * **System sleep**: inferred without any callback by comparing two
//!   clocks, as on macOS. `GetTickCount64` keeps counting while the machine
//!   sleeps or hibernates; `QueryUnbiasedInterruptTime` does not. Their
//!   difference is the total time spent asleep since boot, so if it grew
//!   between two polls the machine slept in between and we emit
//!   `SystemSleep` followed by `SystemWake`. On Modern Standby (S0
//!   low-power idle) machines the unbiased clock keeps running through
//!   parts of standby, so short connected-standby periods may go unseen;
//!   the lock and display edges around them still are.
//!
//! # Change detection
//!
//! [`SessionState::poll_changes`] diffs successive snapshots ([`diff`]),
//! exactly as the macOS implementation does: the agent already ticks every
//! few seconds, and a poll needs no message window or service control
//! handler (`WTSRegisterSessionNotification` needs a window and a message
//! loop on the platform thread). A transition that reverts entirely between
//! two polls (lock and unlock within one tick) is not reported.
//!
//! # Secure desktop
//!
//! While UAC's consent prompt, Ctrl+Alt+Del or the lock/logon screen is up,
//! the *input desktop* is `Winlogon`, which a normal user process can't
//! open. [`input_desktop`] reports that as [`InputDesktop::Inaccessible`]
//! (or [`InputDesktop::Other`] when it can be opened but isn't ours).
//! Capture treats both as "the screen is not available", never as tamper.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use faro_platform::{SessionChange, SessionState};
use windows::core::PWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Power::{
    PowerSettingRegisterNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, POWERBROADCAST_SETTING,
};
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfoEx, WTSINFOEXW,
    WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop,
    DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, HDESK, UOI_NAME,
};
use windows::Win32::System::SystemInformation::{GetTickCount, GetTickCount64};
use windows::Win32::System::SystemServices::GUID_CONSOLE_DISPLAY_STATE;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, DEVICE_NOTIFY_CALLBACK, PBT_POWERSETTINGCHANGE, SM_REMOTESESSION,
};

/// Growth in accumulated sleep time between polls that counts as a system
/// sleep. The two clocks are not read atomically and tick at different
/// resolutions, so tiny differences are noise; real sleeps last seconds.
pub const SLEEP_DETECTION_THRESHOLD: Duration = Duration::from_secs(2);

/// `WTS_CONNECTSTATE_CLASS` values we care about.
const WTS_ACTIVE: i32 = 0;
const WTS_DISCONNECTED: i32 = 4;

/// Seconds since the last keyboard or mouse input in this session.
pub fn idle_seconds() -> u64 {
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a valid, correctly sized LASTINPUTINFO.
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return 0;
    }
    // SAFETY: no preconditions.
    let now = unsafe { GetTickCount() };
    idle_ms(now, info.dwTime) / 1000
}

/// Milliseconds from `last_input` to `now` on the wrapping 32-bit tick.
pub(crate) fn idle_ms(now: u32, last_input: u32) -> u64 {
    u64::from(now.wrapping_sub(last_input))
}

/// What the session's input desktop is, relative to the agent's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDesktop {
    /// Input goes to the desktop this thread runs on (normally `Default`).
    Ours,
    /// Input goes to another desktop we could open (its name).
    Other(String),
    /// The input desktop can't be opened: in a user process this means the
    /// secure desktop (`Winlogon`: lock screen, UAC, Ctrl+Alt+Del), or a
    /// session that is not attached to a console or remote client.
    Inaccessible,
}

impl InputDesktop {
    pub fn is_ours(&self) -> bool {
        matches!(self, InputDesktop::Ours)
    }
}

/// The name of a desktop or window-station handle.
fn object_name(handle: HANDLE) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut needed = 0u32;
    // SAFETY: `buf` is valid for its byte length, which is what we pass.
    unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            Some(buf.as_mut_ptr().cast()),
            std::mem::size_of_val(&buf) as u32,
            Some(&mut needed),
        )
    }
    .ok()?;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

/// Which desktop receives input right now (see [`InputDesktop`]).
pub fn input_desktop() -> InputDesktop {
    // SAFETY: OpenInputDesktop has no pointer arguments; the handle it
    // returns is closed below.
    let input: HDESK =
        match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) } {
            Ok(h) => h,
            Err(_) => return InputDesktop::Inaccessible,
        };
    let input_name = object_name(HANDLE(input.0));
    // SAFETY: `input` came from OpenInputDesktop and is closed once.
    let _ = unsafe { CloseDesktop(input) };
    // SAFETY: GetThreadDesktop returns a handle owned by the system that
    // must not be closed; we only read its name.
    let ours = unsafe { GetThreadDesktop(GetCurrentThreadId()) }
        .ok()
        .and_then(|h| object_name(HANDLE(h.0)));
    match (input_name, ours) {
        (Some(i), Some(o)) if i.eq_ignore_ascii_case(&o) => InputDesktop::Ours,
        (Some(i), _) => InputDesktop::Other(i),
        (None, _) => InputDesktop::Inaccessible,
    }
}

/// The lock flag of a WTS session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WtsLock {
    Locked,
    Unlocked,
    Unknown,
}

/// What WTS says about this process's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WtsSession {
    pub session_id: u32,
    /// `WTS_CONNECTSTATE_CLASS` (0 active, 4 disconnected, ...).
    pub connect_state: i32,
    pub lock: WtsLock,
}

impl WtsSession {
    /// The session is at a screen: the console's or a connected remote
    /// client's. A session switched away from (fast user switching) or
    /// whose RDP client disconnected is `WTSDisconnected` and has no screen.
    pub fn is_active(&self) -> bool {
        self.connect_state == WTS_ACTIVE
    }

    pub fn is_disconnected(&self) -> bool {
        self.connect_state == WTS_DISCONNECTED
    }
}

/// Map `WTSINFOEX_LEVEL1_W.SessionFlags`.
pub(crate) fn lock_from_flags(flags: i32) -> WtsLock {
    match u32::try_from(flags) {
        Ok(WTS_SESSIONSTATE_LOCK) => WtsLock::Locked,
        Ok(WTS_SESSIONSTATE_UNLOCK) => WtsLock::Unlocked,
        _ => WtsLock::Unknown,
    }
}

/// `WTSSessionInfoEx` for the current session.
pub fn current_wts_session() -> Option<WtsSession> {
    let mut buf = PWSTR::null();
    let mut bytes = 0u32;
    // SAFETY: out-pointers are valid; on success the buffer is freed with
    // WTSFreeMemory below.
    unsafe {
        WTSQuerySessionInformationW(
            None,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut buf,
            &mut bytes,
        )
    }
    .ok()?;
    if buf.is_null() {
        return None;
    }
    let out = if bytes as usize >= std::mem::size_of::<WTSINFOEXW>() {
        // SAFETY: the buffer holds a WTSINFOEXW (checked size); level 1 is
        // the only level Windows defines, and we check it before reading
        // the union.
        let info = unsafe { &*(buf.0 as *const WTSINFOEXW) };
        (info.Level == 1).then(|| {
            // SAFETY: Level == 1 selects WTSInfoExLevel1.
            let l1 = unsafe { &info.Data.WTSInfoExLevel1 };
            let WTS_CONNECTSTATE_CLASS(state) = l1.SessionState;
            WtsSession {
                session_id: l1.SessionId,
                connect_state: state,
                lock: lock_from_flags(l1.SessionFlags),
            }
        })
    } else {
        None
    };
    // SAFETY: `buf` came from WTSQuerySessionInformationW and is freed once.
    unsafe { WTSFreeMemory(buf.0.cast()) };
    out
}

/// Whether this process runs in a remote (RDP) session.
pub fn is_remote_session() -> bool {
    // SAFETY: no preconditions.
    unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 }
}

/// Whether the session is locked: WTS's lock flag, or, when that is
/// unknown, an input desktop that isn't ours (see module docs).
pub fn screen_locked() -> bool {
    let wts = current_wts_session().map_or(WtsLock::Unknown, |s| s.lock);
    locked_from(wts, || input_desktop().is_ours())
}

pub(crate) fn locked_from(wts: WtsLock, input_is_ours: impl FnOnce() -> bool) -> bool {
    match wts {
        WtsLock::Locked => true,
        WtsLock::Unlocked => false,
        WtsLock::Unknown => !input_is_ours(),
    }
}

/// Console display state from the power-setting callback: 0 off, 1 on,
/// 2 dimmed, [`DISPLAY_UNKNOWN`] before the first callback.
static DISPLAY_STATE: AtomicU8 = AtomicU8::new(DISPLAY_UNKNOWN);
const DISPLAY_UNKNOWN: u8 = u8::MAX;
const DISPLAY_OFF: u8 = 0;

/// Called by Windows on a thread-pool thread.
unsafe extern "system" fn display_state_changed(
    _context: *const core::ffi::c_void,
    kind: u32,
    setting: *const core::ffi::c_void,
) -> u32 {
    if kind == PBT_POWERSETTINGCHANGE && !setting.is_null() {
        // SAFETY: for PBT_POWERSETTINGCHANGE `setting` points to a
        // POWERBROADCAST_SETTING whose DataLength bytes follow it.
        let s = unsafe { &*(setting as *const POWERBROADCAST_SETTING) };
        if s.PowerSetting == GUID_CONSOLE_DISPLAY_STATE && s.DataLength >= 1 {
            // The display state is a DWORD; its low byte holds 0, 1 or 2.
            DISPLAY_STATE.store(s.Data[0], Ordering::Relaxed);
        }
    }
    0
}

/// Register the display-state callback once per process. The registration
/// is never removed: it is process-wide, tiny, and unregistering while a
/// callback may be in flight has no documented guarantees.
fn ensure_display_watch() {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        // Windows reads the parameters during the call only.
        let params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(display_state_changed),
            Context: std::ptr::null_mut(),
        };
        let mut handle: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: with DEVICE_NOTIFY_CALLBACK the recipient is a pointer to
        // DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS; the callback is a `'static`
        // function and the context is unused.
        let err = unsafe {
            PowerSettingRegisterNotification(
                &GUID_CONSOLE_DISPLAY_STATE,
                DEVICE_NOTIFY_CALLBACK,
                HANDLE(&params as *const _ as *mut core::ffi::c_void),
                &mut handle,
            )
        };
        if err.is_err() {
            tracing::debug!(code = err.0, "display state notifications unavailable");
        }
        err.is_ok()
    });
}

/// Whether the console display is off (see module docs).
pub fn display_asleep() -> bool {
    ensure_display_watch();
    DISPLAY_STATE.load(Ordering::Relaxed) == DISPLAY_OFF
}

/// Total time asleep or hibernating since boot (see module docs).
pub fn time_asleep_since_boot() -> Duration {
    // SAFETY: no preconditions.
    let total_ms = unsafe { GetTickCount64() };
    let mut unbiased_100ns = 0u64;
    // SAFETY: valid out-pointer.
    if !unsafe { QueryUnbiasedInterruptTime(&mut unbiased_100ns) }.as_bool() {
        return Duration::ZERO;
    }
    asleep_from(total_ms, unbiased_100ns)
}

pub(crate) fn asleep_from(total_ms: u64, unbiased_100ns: u64) -> Duration {
    Duration::from_millis(total_ms)
        .saturating_sub(Duration::from_nanos(unbiased_100ns.saturating_mul(100)))
}

/// One observation of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub locked: bool,
    pub display_asleep: bool,
    /// Total time the system has spent asleep since boot.
    pub slept: Duration,
}

impl SessionSnapshot {
    pub fn now() -> Self {
        SessionSnapshot {
            locked: screen_locked(),
            display_asleep: display_asleep(),
            slept: time_asleep_since_boot(),
        }
    }
}

/// Changes between two snapshots, in the order they most plausibly happened:
/// "going down" edges, then a sleep/wake pair, then "coming up" edges (the
/// same rule as the macOS implementation).
pub fn diff(prev: &SessionSnapshot, next: &SessionSnapshot) -> Vec<SessionChange> {
    let mut out = Vec::new();
    if !prev.locked && next.locked {
        out.push(SessionChange::Locked);
    }
    if !prev.display_asleep && next.display_asleep {
        out.push(SessionChange::DisplaySleep);
    }
    if next.slept.saturating_sub(prev.slept) >= SLEEP_DETECTION_THRESHOLD {
        out.push(SessionChange::SystemSleep);
        out.push(SessionChange::SystemWake);
    }
    if prev.locked && !next.locked {
        out.push(SessionChange::Unlocked);
    }
    if prev.display_asleep && !next.display_asleep {
        out.push(SessionChange::DisplayWake);
    }
    out
}

/// [`SessionState`] for Windows.
#[derive(Debug)]
pub struct WinSession {
    last: SessionSnapshot,
}

impl Default for WinSession {
    fn default() -> Self {
        Self::new()
    }
}

impl WinSession {
    /// Registers the display-state callback and takes the baseline snapshot,
    /// so the first [`poll_changes`](SessionState::poll_changes) reports only
    /// what changed after construction.
    pub fn new() -> Self {
        ensure_display_watch();
        WinSession {
            last: SessionSnapshot::now(),
        }
    }

    /// Feed an externally taken snapshot (tests, or callers that already
    /// sampled the state this tick).
    pub fn observe(&mut self, next: SessionSnapshot) -> Vec<SessionChange> {
        let changes = diff(&self.last, &next);
        self.last = next;
        changes
    }
}

impl SessionState for WinSession {
    fn idle_secs(&self) -> u64 {
        idle_seconds()
    }

    fn is_locked(&self) -> bool {
        screen_locked()
    }

    fn display_asleep(&self) -> bool {
        display_asleep()
    }

    fn poll_changes(&mut self) -> Vec<SessionChange> {
        self.observe(SessionSnapshot::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SessionChange::*;

    fn snap(locked: bool, display_asleep: bool, slept_s: u64) -> SessionSnapshot {
        SessionSnapshot {
            locked,
            display_asleep,
            slept: Duration::from_secs(slept_s),
        }
    }

    #[test]
    fn idle_wraps() {
        assert_eq!(idle_ms(5_000, 2_000), 3_000);
        assert_eq!(idle_ms(100, u32::MAX - 899), 1_000, "tick wrapped");
        assert_eq!(idle_ms(7, 7), 0);
    }

    #[test]
    fn lock_flags() {
        assert_eq!(lock_from_flags(0), WtsLock::Locked);
        assert_eq!(lock_from_flags(1), WtsLock::Unlocked);
        assert_eq!(lock_from_flags(-1), WtsLock::Unknown);
        assert_eq!(lock_from_flags(7), WtsLock::Unknown);
        assert!(locked_from(WtsLock::Locked, || true));
        assert!(!locked_from(WtsLock::Unlocked, || false));
        assert!(locked_from(WtsLock::Unknown, || false));
        assert!(!locked_from(WtsLock::Unknown, || true));
    }

    #[test]
    fn asleep_clock_math() {
        // 10 s since boot, 7 s awake (in 100 ns units) → 3 s asleep.
        assert_eq!(asleep_from(10_000, 70_000_000), Duration::from_secs(3));
        // Unbiased ahead of total (resolution noise) saturates at zero.
        assert_eq!(asleep_from(1_000, 20_000_000), Duration::ZERO);
        assert_eq!(asleep_from(0, u64::MAX), Duration::ZERO);
    }

    #[test]
    fn no_change_no_events() {
        let s = snap(false, false, 10);
        assert!(diff(&s, &s).is_empty());
        let l = snap(true, true, 10);
        assert!(diff(&l, &l).is_empty());
    }

    #[test]
    fn single_edges() {
        assert_eq!(
            diff(&snap(false, false, 0), &snap(true, false, 0)),
            vec![Locked]
        );
        assert_eq!(
            diff(&snap(true, false, 0), &snap(false, false, 0)),
            vec![Unlocked]
        );
        assert_eq!(
            diff(&snap(false, false, 0), &snap(false, true, 0)),
            vec![DisplaySleep]
        );
        assert_eq!(
            diff(&snap(false, true, 0), &snap(false, false, 0)),
            vec![DisplayWake]
        );
    }

    #[test]
    fn sleep_gap_orders_down_then_sleep_then_up() {
        assert_eq!(
            diff(&snap(false, false, 5), &snap(true, false, 3605)),
            vec![Locked, SystemSleep, SystemWake]
        );
        assert_eq!(
            diff(&snap(true, true, 0), &snap(false, false, 600)),
            vec![SystemSleep, SystemWake, Unlocked, DisplayWake]
        );
        assert!(
            diff(&snap(false, false, 100), &snap(false, false, 0)).is_empty(),
            "clock going backwards is ignored"
        );
        assert!(diff(&snap(false, false, 1), &snap(false, false, 2)).is_empty());
    }

    #[test]
    fn observe_is_edge_triggered() {
        let mut s = WinSession {
            last: snap(false, false, 0),
        };
        assert_eq!(s.observe(snap(true, false, 0)), vec![Locked]);
        assert!(s.observe(snap(true, false, 0)).is_empty(), "once");
        assert_eq!(s.observe(snap(false, false, 0)), vec![Unlocked]);
    }

    #[test]
    fn smoke_live_session_queries() {
        let mut s = WinSession::new();
        let idle = s.idle_secs();
        assert!(idle < 60 * 60 * 24 * 365, "idle {idle}s is implausible");
        let _ = s.is_locked();
        let _ = s.display_asleep();
        let _ = is_remote_session();
        let _ = input_desktop();
        assert!(s.poll_changes().len() <= 4);
        let a = time_asleep_since_boot();
        let b = time_asleep_since_boot();
        // Different clock resolutions: allow a tick of jitter either way.
        assert!(b + Duration::from_millis(50) >= a);
        if let Some(w) = current_wts_session() {
            // A test run is always inside a real session.
            assert_ne!(w.session_id, u32::MAX);
        }
    }
}
