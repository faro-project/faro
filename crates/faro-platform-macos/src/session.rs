//! Idle, lock, display-sleep and system-sleep state of the GUI session.
//!
//! * **Idle**: `CGEventSourceSecondsSinceLastEventType` over the combined
//!   session state for any input event type.
//! * **Locked**: the `CGSSessionScreenIsLocked` key of
//!   `CGSessionCopyCurrentDictionary()`. The key is only present while the
//!   screen is locked, so "absent" means unlocked.
//! * **Display asleep**: `CGDisplayIsAsleep(CGMainDisplayID())`.
//! * **System sleep**: inferred, see below.
//!
//! # Change detection
//!
//! [`SessionState::poll_changes`] diffs successive snapshots ([`diff`]).
//! This is deliberately poll-based: the notification route
//! (`com.apple.screenIsLocked` distributed notifications,
//! `NSWorkspaceWillSleepNotification`, IOKit power callbacks) needs a
//! running `CFRunLoop` on a dedicated thread plus an Objective-C observer
//! class, and the agent already ticks every few seconds. Observation is a
//! later improvement when sub-tick latency matters; a transition that
//! reverts entirely between two polls (lock and unlock within one tick) is
//! not reported.
//!
//! System sleep is detected without any callback by comparing two clocks:
//! `CLOCK_MONOTONIC_RAW` keeps counting while the Mac sleeps,
//! `CLOCK_UPTIME_RAW` does not. Their difference is the total time spent
//! asleep since boot, so if it grew between two polls the machine slept in
//! between, and we emit `SystemSleep` followed by `SystemWake`.

use std::time::Duration;

use faro_platform::{SessionChange, SessionState};
use objc2_core_graphics::{
    CGDisplayIsAsleep, CGEventSource, CGEventSourceStateID, CGEventType, CGMainDisplayID,
    CGSessionCopyCurrentDictionary,
};

use crate::cf;

/// `kCGAnyInputEventType`.
const ANY_INPUT_EVENT: CGEventType = CGEventType(!0);

/// Growth in accumulated sleep time between polls that counts as a system
/// sleep. Clock reads are not atomic with each other, so tiny differences
/// are noise; real sleeps last seconds at least.
pub const SLEEP_DETECTION_THRESHOLD: Duration = Duration::from_secs(2);

/// One observation of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub locked: bool,
    pub display_asleep: bool,
    /// Total time the system has spent asleep since boot.
    pub slept: Duration,
}

/// Seconds since the last keyboard, mouse, trackpad or tablet event in this
/// login session.
pub fn idle_seconds() -> u64 {
    let secs = CGEventSource::seconds_since_last_event_type(
        CGEventSourceStateID::CombinedSessionState,
        ANY_INPUT_EVENT,
    );
    secs_to_u64(secs)
}

/// Saturating, NaN-safe float seconds → whole seconds.
pub(crate) fn secs_to_u64(secs: f64) -> u64 {
    if secs.is_finite() && secs > 0.0 {
        // `as` saturates at u64::MAX for huge values.
        secs as u64
    } else {
        0
    }
}

/// Whether the screen of the current login session is locked.
///
/// Returns `false` when the process is not attached to a GUI session at all
/// (no session dictionary); the agent always runs inside one, and capture
/// attempts in that state fail loudly on their own.
pub fn screen_locked() -> bool {
    CGSessionCopyCurrentDictionary()
        .and_then(|d| cf::get_bool(cf::as_plist_dict(&d), "CGSSessionScreenIsLocked"))
        .unwrap_or(false)
}

/// Whether the main display is asleep.
pub fn main_display_asleep() -> bool {
    CGDisplayIsAsleep(CGMainDisplayID())
}

fn clock_ns(clock: libc::clockid_t) -> Option<u128> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer; the clock ids are supported on
    // macOS 10.12+.
    let rc = unsafe { libc::clock_gettime(clock, &mut ts) };
    if rc != 0 {
        return None;
    }
    let secs = u128::try_from(ts.tv_sec).ok()?;
    let nanos = u128::try_from(ts.tv_nsec).ok()?;
    Some(secs * 1_000_000_000 + nanos)
}

/// Total time asleep since boot (monotonic-with-sleep minus uptime).
pub fn time_asleep_since_boot() -> Duration {
    match (
        clock_ns(libc::CLOCK_MONOTONIC_RAW),
        clock_ns(libc::CLOCK_UPTIME_RAW),
    ) {
        (Some(total), Some(awake)) => {
            let ns = total.saturating_sub(awake);
            Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX))
        }
        _ => Duration::ZERO,
    }
}

impl SessionSnapshot {
    pub fn now() -> Self {
        SessionSnapshot {
            locked: screen_locked(),
            display_asleep: main_display_asleep(),
            slept: time_asleep_since_boot(),
        }
    }
}

/// Changes between two snapshots, in the order they most plausibly happened.
///
/// "Going down" edges (`Locked`, `DisplaySleep`) come first, then a system
/// sleep/wake pair if one happened in between, then "coming up" edges
/// (`Unlocked`, `DisplayWake`). This matches the usual sequence of a Mac
/// that locks and dims before sleeping and unlocks after waking.
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

/// [`SessionState`] for macOS.
#[derive(Debug)]
pub struct MacSession {
    last: SessionSnapshot,
}

impl Default for MacSession {
    fn default() -> Self {
        Self::new()
    }
}

impl MacSession {
    /// Takes the baseline snapshot immediately, so the first
    /// [`poll_changes`](SessionState::poll_changes) reports only what changed
    /// after construction.
    pub fn new() -> Self {
        MacSession {
            last: SessionSnapshot::now(),
        }
    }

    /// Feed an externally taken snapshot (used by tests and by callers that
    /// already sampled the state this tick).
    pub fn observe(&mut self, next: SessionSnapshot) -> Vec<SessionChange> {
        let changes = diff(&self.last, &next);
        self.last = next;
        changes
    }
}

impl SessionState for MacSession {
    fn idle_secs(&self) -> u64 {
        idle_seconds()
    }

    fn is_locked(&self) -> bool {
        screen_locked()
    }

    fn display_asleep(&self) -> bool {
        main_display_asleep()
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
        // Unlocked and awake → (slept 1h) → locked, display awake again.
        assert_eq!(
            diff(&snap(false, false, 5), &snap(true, false, 3605)),
            vec![Locked, SystemSleep, SystemWake]
        );
        // Locked with display off → (slept) → unlocked and awake.
        assert_eq!(
            diff(&snap(true, true, 0), &snap(false, false, 600)),
            vec![SystemSleep, SystemWake, Unlocked, DisplayWake]
        );
    }

    #[test]
    fn sleep_threshold_filters_clock_noise() {
        let a = SessionSnapshot {
            locked: false,
            display_asleep: false,
            slept: Duration::from_millis(1000),
        };
        let mut b = a;
        b.slept = Duration::from_millis(2999);
        assert!(diff(&a, &b).is_empty());
        b.slept = Duration::from_millis(3000);
        assert_eq!(diff(&a, &b), vec![SystemSleep, SystemWake]);
    }

    #[test]
    fn sleep_clock_going_backwards_is_ignored() {
        // Should never happen, but must not underflow or emit events.
        assert!(diff(&snap(false, false, 100), &snap(false, false, 0)).is_empty());
    }

    #[test]
    fn observe_updates_baseline() {
        let mut s = MacSession {
            last: snap(false, false, 0),
        };
        assert_eq!(s.observe(snap(true, false, 0)), vec![Locked]);
        assert!(
            s.observe(snap(true, false, 0)).is_empty(),
            "edge reported once"
        );
        assert_eq!(s.observe(snap(false, false, 0)), vec![Unlocked]);
    }

    #[test]
    fn secs_conversion_is_defensive() {
        assert_eq!(secs_to_u64(12.9), 12);
        assert_eq!(secs_to_u64(-1.0), 0);
        assert_eq!(secs_to_u64(f64::NAN), 0);
        assert_eq!(secs_to_u64(f64::INFINITY), 0);
        assert_eq!(secs_to_u64(1e30), u64::MAX);
    }

    #[test]
    fn smoke_live_session_queries() {
        let mut s = MacSession::new();
        let idle = s.idle_secs();
        assert!(idle < 60 * 60 * 24 * 365, "idle {idle}s is implausible");
        let _ = s.is_locked();
        let _ = s.display_asleep();
        // Immediately after construction nothing should have changed except
        // in the rare case of a real lock/sleep racing the test.
        assert!(s.poll_changes().len() <= 4);
        let a = time_asleep_since_boot();
        let b = time_asleep_since_boot();
        assert!(
            b + Duration::from_millis(1) >= a,
            "sleep clock must not go backwards"
        );
    }
}
