//! Capture scheduling (ARCHITECTURE.md §3.4).
//!
//! The scheduler is a pure, deterministic state machine: the caller passes in
//! the current time and session state, and the random source is injected, so
//! the same seed and inputs always produce the same schedule. It never sleeps
//! or reads a clock itself.
//!
//! **Time base.** All `now_ms` arguments must come from a *monotonic* clock
//! (`Clock::mono_ms`). Scheduling on the wall clock would let a member stall
//! captures by setting the system time backwards. If `now_ms` is ever smaller
//! than a previously seen value it is treated as the previous value.
//!
//! **Why exponential.** Inter-arrival times drawn from an exponential
//! distribution make the process memoryless: knowing how long ago the last
//! capture happened tells the member nothing about when the next one will be.
//! The draw is clamped (see [`interval_bounds_ms`]) so there is always a hard
//! upper bound on unmonitored time and a floor that keeps CPU use in budget.

use faro_proto::body::{Rating, SettingChange};
use faro_proto::report::ActivityState;
use rand::Rng;
use rand_distr::Exp1;

/// Smallest member-configurable mean interval, in seconds.
pub const MEAN_MIN_SECS: u32 = 30;
/// Largest member-configurable mean interval, in seconds.
pub const MEAN_MAX_SECS: u32 = 300;
/// Default mean interval, in seconds.
pub const MEAN_DEFAULT_SECS: u32 = 60;

/// The setting key used in [`SettingChange`] for the mean interval.
pub const SETTING_CAPTURE_MEAN: &str = "capture_mean_secs";

/// Clamp bounds for a regular (non-burst) interval, in milliseconds:
/// `[max(15 s, mean/4), min(mean*3, 900 s)]`.
///
/// For the default 60 s mean this is the 15–180 s window of §3.4. The lower
/// bound keeps CPU in budget; the upper bound caps how long a member can go
/// unobserved by bad luck. Clamping shifts the effective mean slightly (for a
/// 60 s mean the clamped mean is ~62 s), which is acceptable: the member-set
/// value is a target, not a contract.
pub fn interval_bounds_ms(mean_secs: u32) -> (u64, u64) {
    let mean = u64::from(mean_secs);
    let lo = 15.max(mean / 4);
    let hi = (mean * 3).min(900);
    (lo * 1000, hi.max(lo) * 1000)
}

/// Tunables. Every field has a documented default via [`Default`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Mean regular interval in seconds, within [`MEAN_MIN_SECS`]..=[`MEAN_MAX_SECS`].
    pub mean_secs: u32,
    /// The session counts as input-idle after this many seconds without
    /// input. Input-idle with the display awake and unlocked does **not**
    /// pause capture (a video or slideshow keeps the screen on with no
    /// input); it only lowers the rate, see [`Self::idle_interval_factor`].
    pub idle_threshold_secs: u64,
    /// While input-idle (and not in burst mode) each regular interval is
    /// multiplied by this factor, then capped at [`Self::idle_interval_max_ms`].
    /// The unchanged-frame skip (dHash) in the capture path avoids repeated
    /// work when the screen is static. Must be at least 1.
    pub idle_interval_factor: u32,
    /// Longest interval while input-idle, in milliseconds (default 900 s).
    pub idle_interval_max_ms: u64,
    /// How long burst mode lasts after the last qualifying result (default 120 s).
    pub burst_duration_ms: u64,
    /// Burst-mode interval is uniform in `[burst_min_ms, burst_max_ms]` (5–10 s).
    pub burst_min_ms: u64,
    pub burst_max_ms: u64,
    /// A trigger schedules a capture uniformly `[trigger_delay_min_ms,
    /// trigger_delay_max_ms]` later (1–3 s): long enough for the new window or
    /// page to render, short enough that a quick glance is still caught.
    pub trigger_delay_min_ms: u64,
    pub trigger_delay_max_ms: u64,
    /// A trigger-driven capture is never closer than this to the previous
    /// capture (default 3 s), so a flood of app switches cannot push the
    /// capture rate past `1 / trigger_min_spacing_ms`.
    pub trigger_min_spacing_ms: u64,
    /// After resuming (unlock, wake, end of idle) or at start-up the next
    /// capture happens uniformly `[resume_delay_min_ms, resume_delay_max_ms]`
    /// later: the moments right after unlocking are exactly when monitoring
    /// matters, so we do not wait for a full regular interval.
    pub resume_delay_min_ms: u64,
    pub resume_delay_max_ms: u64,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            mean_secs: MEAN_DEFAULT_SECS,
            idle_threshold_secs: 300,
            idle_interval_factor: 3,
            idle_interval_max_ms: 900_000,
            burst_duration_ms: 120_000,
            burst_min_ms: 5_000,
            burst_max_ms: 10_000,
            trigger_delay_min_ms: 1_000,
            trigger_delay_max_ms: 3_000,
            trigger_min_spacing_ms: 3_000,
            resume_delay_min_ms: 1_000,
            resume_delay_max_ms: 3_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchedulerError {
    #[error("capture mean {0}s is outside the allowed {MEAN_MIN_SECS}..={MEAN_MAX_SECS}s")]
    MeanOutOfRange(u32),
    #[error("invalid scheduler config: {0}")]
    InvalidConfig(&'static str),
}

impl SchedulerConfig {
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if !(MEAN_MIN_SECS..=MEAN_MAX_SECS).contains(&self.mean_secs) {
            return Err(SchedulerError::MeanOutOfRange(self.mean_secs));
        }
        let ranges = [
            (self.burst_min_ms, self.burst_max_ms, "burst range"),
            (
                self.trigger_delay_min_ms,
                self.trigger_delay_max_ms,
                "trigger delay range",
            ),
            (
                self.resume_delay_min_ms,
                self.resume_delay_max_ms,
                "resume delay range",
            ),
        ];
        for (lo, hi, what) in ranges {
            if lo > hi {
                return Err(SchedulerError::InvalidConfig(what));
            }
        }
        if self.idle_interval_factor == 0 {
            return Err(SchedulerError::InvalidConfig(
                "idle_interval_factor must be >= 1",
            ));
        }
        if self.burst_min_ms == 0 {
            return Err(SchedulerError::InvalidConfig("burst_min_ms must be > 0"));
        }
        if self.trigger_min_spacing_ms == 0 {
            return Err(SchedulerError::InvalidConfig(
                "trigger_min_spacing_ms must be > 0",
            ));
        }
        Ok(())
    }
}

/// What the session looks like right now (from `faro_platform::SessionState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionSnapshot {
    pub locked: bool,
    pub idle_secs: u64,
    pub display_asleep: bool,
    /// The member paused monitoring from the tray (allies are told separately
    /// through a `paused` event).
    pub member_paused: bool,
}

/// Why capturing is paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PauseReason {
    MemberPaused,
    DisplayAsleep,
    Locked,
}

impl PauseReason {
    /// How this pause appears on the report timeline.
    pub fn activity_state(self) -> ActivityState {
        match self {
            PauseReason::MemberPaused => ActivityState::Paused,
            PauseReason::DisplayAsleep => ActivityState::Asleep,
            PauseReason::Locked => ActivityState::Locked,
        }
    }
}

/// Things that make a capture worth taking soon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trigger {
    ForegroundAppChanged,
    NewUrl,
    WatchlistedDomain,
}

/// Why a capture is happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureCause {
    /// Regular randomized interval.
    Scheduled,
    /// Burst-mode follow-up after a borderline or flagged result.
    Burst,
    /// Shortly after a [`Trigger`].
    Trigger(Trigger),
    /// Promptly after start-up or a resume.
    Resume,
}

/// Details for [`Decision::CaptureNow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureInfo {
    pub cause: CaptureCause,
    /// Burst mode is active (recorded on flags as `FlagBody::burst`).
    pub burst: bool,
}

/// What the caller should do after [`Scheduler::on_tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    CaptureNow(CaptureInfo),
    /// Nothing to do; tick again at (monotonic) `ms`.
    SleepUntil(u64),
    /// Do not capture. Tick again when the session changes, or periodically.
    Paused(PauseReason),
}

/// A pause/resume edge, for the report timeline and `paused`/`resumed` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Capturing stopped (or the reason changed, e.g. idle → locked).
    Paused {
        at_ms: u64,
        reason: PauseReason,
    },
    Resumed {
        at_ms: u64,
    },
}

/// Result of [`Scheduler::on_trigger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerOutcome {
    /// A capture is now scheduled at `at_ms`.
    Scheduled { at_ms: u64 },
    /// A trigger capture was already pending at `at_ms`; nothing changed.
    Coalesced { at_ms: u64 },
    /// Ignored because capturing is paused.
    IgnoredPaused,
}

/// The capture scheduler. See module docs.
#[derive(Debug)]
pub struct Scheduler<R: Rng> {
    cfg: SchedulerConfig,
    rng: R,
    /// Next regular / burst / resume capture. `None` until the first tick.
    next_ms: Option<u64>,
    /// Cause recorded for `next_ms`.
    next_cause: CaptureCause,
    pending_trigger: Option<(u64, Trigger)>,
    burst_until_ms: Option<u64>,
    last_capture_ms: Option<u64>,
    paused: Option<PauseReason>,
    /// Input-idle (and not paused) as of the last tick.
    idle: bool,
    last_now: u64,
    transitions: Vec<Transition>,
}

impl<R: Rng> Scheduler<R> {
    pub fn new(cfg: SchedulerConfig, rng: R) -> Result<Self, SchedulerError> {
        cfg.validate()?;
        Ok(Scheduler {
            cfg,
            rng,
            next_ms: None,
            next_cause: CaptureCause::Resume,
            pending_trigger: None,
            burst_until_ms: None,
            last_capture_ms: None,
            paused: None,
            idle: false,
            last_now: 0,
            transitions: Vec::new(),
        })
    }

    pub fn config(&self) -> &SchedulerConfig {
        &self.cfg
    }

    pub fn mean_secs(&self) -> u32 {
        self.cfg.mean_secs
    }

    /// The current pause reason, if paused.
    pub fn paused(&self) -> Option<PauseReason> {
        self.paused
    }

    /// Whether the session is input-idle: capture continues, at the lower
    /// rate. (Whether it is *paused* is [`Self::paused`].)
    pub fn input_idle(&self, session: &SessionSnapshot) -> bool {
        session.idle_secs >= self.cfg.idle_threshold_secs
    }

    /// Whether the last tick found the session input-idle and not paused.
    pub fn is_idle(&self) -> bool {
        self.idle
    }

    /// Whether burst mode is active at `now_ms`.
    pub fn in_burst(&self, now_ms: u64) -> bool {
        self.burst_until_ms.is_some_and(|u| now_ms < u)
    }

    /// The earliest moment a capture is due, if any is scheduled.
    pub fn next_due_ms(&self) -> Option<u64> {
        match (self.next_ms, self.pending_trigger) {
            (Some(a), Some((b, _))) => Some(a.min(b)),
            (a, b) => a.or(b.map(|(t, _)| t)),
        }
    }

    /// Pause/resume edges since the last call, oldest first.
    pub fn drain_transitions(&mut self) -> Vec<Transition> {
        std::mem::take(&mut self.transitions)
    }

    fn clamp_now(&mut self, now_ms: u64) -> u64 {
        let now = now_ms.max(self.last_now);
        self.last_now = now;
        now
    }

    fn pause_reason(&self, s: &SessionSnapshot) -> Option<PauseReason> {
        if s.member_paused {
            Some(PauseReason::MemberPaused)
        } else if s.display_asleep {
            Some(PauseReason::DisplayAsleep)
        } else if s.locked {
            Some(PauseReason::Locked)
        } else {
            None
        }
    }

    fn uniform(&mut self, lo: u64, hi: u64) -> u64 {
        if lo >= hi {
            lo
        } else {
            self.rng.gen_range(lo..=hi)
        }
    }

    /// One regular interval: exponential with the configured mean, clamped.
    fn regular_interval_ms(&mut self) -> u64 {
        let (lo, hi) = interval_bounds_ms(self.cfg.mean_secs);
        let x: f64 = self.rng.sample(Exp1);
        let ms = x * f64::from(self.cfg.mean_secs) * 1000.0;
        // `as` saturates for out-of-range floats and maps NaN to 0; the clamp
        // then guarantees the bounds either way.
        (ms as u64).clamp(lo, hi)
    }

    fn schedule_after_capture(&mut self, now: u64) {
        if self.in_burst(now) {
            let d = self.uniform(self.cfg.burst_min_ms, self.cfg.burst_max_ms);
            self.next_ms = Some(now.saturating_add(d));
            self.next_cause = CaptureCause::Burst;
        } else {
            let mut d = self.regular_interval_ms();
            if self.idle {
                d = d
                    .saturating_mul(u64::from(self.cfg.idle_interval_factor))
                    .min(self.cfg.idle_interval_max_ms.max(d));
            }
            self.next_ms = Some(now.saturating_add(d));
            self.next_cause = CaptureCause::Scheduled;
        }
    }

    fn schedule_resume(&mut self, now: u64) {
        let d = self.uniform(self.cfg.resume_delay_min_ms, self.cfg.resume_delay_max_ms);
        let mut at = now.saturating_add(d);
        if let Some(last) = self.last_capture_ms {
            at = at.max(last.saturating_add(self.cfg.trigger_min_spacing_ms));
        }
        self.next_ms = Some(at);
        self.next_cause = CaptureCause::Resume;
    }

    /// Advance the state machine to `now_ms` (monotonic) given the session.
    pub fn on_tick(&mut self, now_ms: u64, session: &SessionSnapshot) -> Decision {
        let now = self.clamp_now(now_ms);
        if let Some(reason) = self.pause_reason(session) {
            if self.paused != Some(reason) {
                self.transitions
                    .push(Transition::Paused { at_ms: now, reason });
                self.paused = Some(reason);
            }
            // Triggers observed before the pause are stale by the time we resume.
            self.pending_trigger = None;
            self.idle = false;
            return Decision::Paused(reason);
        }
        let now_idle = self.input_idle(session);
        let was_idle = std::mem::replace(&mut self.idle, now_idle);
        if self.paused.take().is_some() {
            self.transitions.push(Transition::Resumed { at_ms: now });
            self.schedule_resume(now);
        } else if self.next_ms.is_none() {
            // First tick after start-up.
            self.schedule_resume(now);
        } else if was_idle && !self.idle && !self.in_burst(now) {
            // Input is back: do not wait out an idle-length interval.
            self.schedule_resume(now);
        }

        let next = self.next_ms.unwrap_or(now);
        let trig = self.pending_trigger;
        let trigger_due = trig.filter(|(t, _)| *t <= now && *t <= next);
        let cause = if let Some((_, t)) = trigger_due {
            Some(CaptureCause::Trigger(t))
        } else if next <= now {
            Some(self.next_cause)
        } else {
            None
        };
        match cause {
            Some(cause) => {
                let burst = self.in_burst(now);
                self.last_capture_ms = Some(now);
                // A capture satisfies any pending trigger: the screen it would
                // have seen is the one we are capturing now.
                self.pending_trigger = None;
                self.schedule_after_capture(now);
                Decision::CaptureNow(CaptureInfo { cause, burst })
            }
            None => Decision::SleepUntil(self.next_due_ms().unwrap_or(next)),
        }
    }

    /// Feed back the result of a capture taken at `now_ms`.
    ///
    /// A `medium` or `high` rating, or a result the policy engine marks as
    /// `borderline`, starts burst mode (or extends it by a full burst
    /// duration from now) and pulls the next capture in to burst cadence.
    pub fn on_result(&mut self, now_ms: u64, rating: Rating, borderline: bool) {
        let now = self.clamp_now(now_ms);
        if rating < Rating::Medium && !borderline {
            return;
        }
        let until = now.saturating_add(self.cfg.burst_duration_ms);
        self.burst_until_ms = Some(self.burst_until_ms.map_or(until, |u| u.max(until)));
        let d = self.uniform(self.cfg.burst_min_ms, self.cfg.burst_max_ms);
        let mut at = now.saturating_add(d);
        if let Some(last) = self.last_capture_ms {
            at = at.max(last.saturating_add(self.cfg.burst_min_ms));
        }
        let pull_in = match self.next_ms {
            Some(n) => at < n,
            None => true,
        };
        if pull_in {
            self.next_ms = Some(at);
            self.next_cause = CaptureCause::Burst;
        }
    }

    /// Note a trigger at `now_ms`; schedules a capture 1–3 s later, never
    /// closer than the minimum spacing to the previous capture.
    pub fn on_trigger(&mut self, now_ms: u64, trigger: Trigger) -> TriggerOutcome {
        let now = self.clamp_now(now_ms);
        if self.paused.is_some() {
            return TriggerOutcome::IgnoredPaused;
        }
        if let Some((at, _)) = self.pending_trigger {
            return TriggerOutcome::Coalesced { at_ms: at };
        }
        let d = self.uniform(self.cfg.trigger_delay_min_ms, self.cfg.trigger_delay_max_ms);
        let mut at = now.saturating_add(d);
        if let Some(last) = self.last_capture_ms {
            at = at.max(last.saturating_add(self.cfg.trigger_min_spacing_ms));
        }
        self.pending_trigger = Some((at, trigger));
        TriggerOutcome::Scheduled { at_ms: at }
    }

    /// Change the mean interval. Returns the [`SettingChange`] allies must be
    /// told about, or `None` if the value is unchanged.
    ///
    /// Takes effect from the next regular draw; an already-scheduled capture
    /// is kept (it is at most 900 s away).
    pub fn set_mean(&mut self, secs: u32) -> Result<Option<SettingChange>, SchedulerError> {
        if !(MEAN_MIN_SECS..=MEAN_MAX_SECS).contains(&secs) {
            return Err(SchedulerError::MeanOutOfRange(secs));
        }
        if secs == self.cfg.mean_secs {
            return Ok(None);
        }
        let old = std::mem::replace(&mut self.cfg.mean_secs, secs);
        Ok(Some(SettingChange {
            key: SETTING_CAPTURE_MEAN.into(),
            old: Some(old.to_string()),
            new: Some(secs.to_string()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn sched(seed: u64) -> Scheduler<StdRng> {
        Scheduler::new(SchedulerConfig::default(), StdRng::seed_from_u64(seed)).unwrap()
    }

    const ACTIVE: SessionSnapshot = SessionSnapshot {
        locked: false,
        idle_secs: 0,
        display_asleep: false,
        member_paused: false,
    };

    /// Drive the scheduler tick-by-tick to `until`, returning capture times.
    fn run(s: &mut Scheduler<StdRng>, from: u64, until: u64) -> Vec<(u64, CaptureInfo)> {
        let mut out = Vec::new();
        let mut now = from;
        while now <= until {
            match s.on_tick(now, &ACTIVE) {
                Decision::CaptureNow(info) => out.push((now, info)),
                Decision::SleepUntil(t) => {
                    assert!(t > now, "sleep target must be in the future");
                    now = t;
                }
                Decision::Paused(r) => panic!("unexpected pause {r:?}"),
            }
        }
        out
    }

    #[test]
    fn bounds_table() {
        assert_eq!(interval_bounds_ms(60), (15_000, 180_000));
        assert_eq!(interval_bounds_ms(30), (15_000, 90_000));
        assert_eq!(interval_bounds_ms(300), (75_000, 900_000));
        assert_eq!(interval_bounds_ms(100), (25_000, 300_000));
    }

    #[test]
    fn config_validation() {
        assert!(SchedulerConfig::default().validate().is_ok());
        let bad = SchedulerConfig {
            mean_secs: 29,
            ..Default::default()
        };
        assert_eq!(bad.validate(), Err(SchedulerError::MeanOutOfRange(29)));
        let bad = SchedulerConfig {
            burst_min_ms: 11_000,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
        let bad = SchedulerConfig {
            trigger_min_spacing_ms: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn deterministic_for_seed() {
        let a = run(&mut sched(7), 0, 3_600_000);
        let b = run(&mut sched(7), 0, 3_600_000);
        assert_eq!(a, b);
        let c = run(&mut sched(8), 0, 3_600_000);
        assert_ne!(a, c);
    }

    #[test]
    fn first_capture_is_prompt() {
        let caps = run(&mut sched(1), 1_000, 10_000);
        let (t, info) = caps[0];
        assert!((2_000..=4_000).contains(&t), "{t}");
        assert_eq!(info.cause, CaptureCause::Resume);
    }

    #[test]
    fn empirical_mean_is_close_to_configured() {
        let mut s = sched(42);
        let caps = run(&mut s, 0, 24 * 3_600_000);
        let gaps: Vec<u64> = caps.windows(2).map(|w| w[1].0 - w[0].0).collect();
        let mean = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
        // Clamped exponential(60 s) has mean ≈ 61.6 s.
        assert!((55_000.0..70_000.0).contains(&mean), "mean {mean}");
        // Not a fixed period: plenty of distinct gaps.
        let mut uniq = gaps.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert!(uniq.len() > gaps.len() / 2);
    }

    #[test]
    fn burst_cadence_and_expiry() {
        let mut s = sched(3);
        let caps = run(&mut s, 0, 5_000);
        let t0 = caps.last().unwrap().0;
        s.on_result(t0, Rating::High, false);
        assert!(s.in_burst(t0));
        let caps = run(&mut s, t0, t0 + 119_000);
        assert!(caps.len() >= 11, "got {}", caps.len());
        let mut prev = t0;
        for (t, info) in &caps {
            assert!((5_000..=10_000).contains(&(t - prev)), "gap {}", t - prev);
            assert!(info.burst);
            assert_eq!(info.cause, CaptureCause::Burst);
            prev = *t;
        }
        // After 120 s without new flags, cadence returns to regular.
        let later = run(&mut s, prev + 1, t0 + 3_600_000);
        assert!(later.iter().skip(1).all(|(_, i)| !i.burst));
        assert!(!s.in_burst(t0 + 120_000));
    }

    #[test]
    fn burst_extended_by_new_flags_and_borderline() {
        let mut s = sched(4);
        run(&mut s, 0, 5_000);
        s.on_result(10_000, Rating::Medium, false);
        s.on_result(100_000, Rating::Clean, true); // borderline hint
        assert!(s.in_burst(219_999));
        assert!(!s.in_burst(220_000));
        // Low and clean without the hint do nothing.
        let mut s = sched(5);
        s.on_result(0, Rating::Low, false);
        s.on_result(0, Rating::Clean, false);
        assert!(!s.in_burst(0));
    }

    #[test]
    fn pause_and_resume_transitions() {
        let mut s = sched(9);
        run(&mut s, 0, 10_000);
        let locked = SessionSnapshot {
            locked: true,
            ..ACTIVE
        };
        assert_eq!(
            s.on_tick(20_000, &locked),
            Decision::Paused(PauseReason::Locked)
        );
        assert_eq!(
            s.on_tick(30_000, &locked),
            Decision::Paused(PauseReason::Locked)
        );
        // Input-idle with the display on and unlocked is not a pause.
        let idle = SessionSnapshot {
            idle_secs: 300,
            ..ACTIVE
        };
        let locked_idle = SessionSnapshot {
            locked: true,
            ..idle
        };
        assert_eq!(
            s.on_tick(40_000, &locked_idle),
            Decision::Paused(PauseReason::Locked)
        );
        let asleep = SessionSnapshot {
            display_asleep: true,
            locked: true,
            ..ACTIVE
        };
        assert_eq!(
            s.on_tick(50_000, &asleep),
            Decision::Paused(PauseReason::DisplayAsleep)
        );
        // Triggers are ignored while paused.
        assert_eq!(
            s.on_trigger(55_000, Trigger::NewUrl),
            TriggerOutcome::IgnoredPaused
        );
        // Resume: capture within 1–3 s.
        let d = s.on_tick(1_000_000, &ACTIVE);
        assert!(matches!(d, Decision::SleepUntil(t) if (1_001_000..=1_003_000).contains(&t)));
        assert_eq!(
            s.drain_transitions(),
            vec![
                Transition::Paused {
                    at_ms: 20_000,
                    reason: PauseReason::Locked
                },
                Transition::Paused {
                    at_ms: 50_000,
                    reason: PauseReason::DisplayAsleep
                },
                Transition::Resumed { at_ms: 1_000_000 },
            ]
        );
        assert!(s.drain_transitions().is_empty());
    }

    const IDLE: SessionSnapshot = SessionSnapshot {
        idle_secs: 3600,
        ..ACTIVE
    };

    #[test]
    fn idle_threshold_is_respected() {
        let s = sched(1);
        let almost = SessionSnapshot {
            idle_secs: 299,
            ..ACTIVE
        };
        assert!(!s.input_idle(&almost));
        assert!(s.input_idle(&SessionSnapshot {
            idle_secs: 300,
            ..ACTIVE
        }));
    }

    /// Run with a fixed session, returning capture times.
    fn run_with(
        s: &mut Scheduler<StdRng>,
        session: &SessionSnapshot,
        from: u64,
        until: u64,
    ) -> Vec<u64> {
        let mut out = Vec::new();
        let mut now = from;
        while now <= until {
            match s.on_tick(now, session) {
                Decision::CaptureNow(_) => out.push(now),
                Decision::SleepUntil(t) => now = t,
                Decision::Paused(r) => panic!("unexpected pause {r:?}"),
            }
        }
        out
    }

    #[test]
    fn idle_with_display_on_keeps_capturing_at_the_lower_rate() {
        let span = 6 * 3_600_000;
        let active = run_with(&mut sched(5), &ACTIVE, 0, span).len();
        let mut s = sched(5);
        let idle = run_with(&mut s, &IDLE, 0, span);
        assert!(s.paused().is_none());
        assert!(s.is_idle());
        assert!(idle.len() > 20, "idle must keep capturing: {}", idle.len());
        assert!(
            idle.len() * 2 < active,
            "idle rate {} should be well below active {active}",
            idle.len()
        );
        // Never longer than the idle cap between captures.
        let cap = s.config().idle_interval_max_ms;
        assert!(idle.windows(2).all(|w| w[1] - w[0] <= cap));
    }

    #[test]
    fn idle_with_display_off_or_locked_pauses() {
        let mut s = sched(6);
        let asleep = SessionSnapshot {
            display_asleep: true,
            ..IDLE
        };
        assert_eq!(
            s.on_tick(0, &asleep),
            Decision::Paused(PauseReason::DisplayAsleep)
        );
        let locked = SessionSnapshot {
            locked: true,
            ..IDLE
        };
        assert_eq!(s.on_tick(1, &locked), Decision::Paused(PauseReason::Locked));
        assert!(!s.is_idle());
    }

    #[test]
    fn burst_mode_is_not_slowed_by_input_idleness() {
        let mut s = sched(7);
        let caps = run_with(&mut s, &IDLE, 0, 10_000);
        let t = *caps.last().unwrap();
        s.on_result(t, Rating::High, false);
        let burst = run_with(&mut s, &IDLE, t, t + 100_000);
        assert!(burst.len() >= 8, "burst cadence kept: {}", burst.len());
        assert!(burst.windows(2).all(|w| w[1] - w[0] <= 10_000));
    }

    #[test]
    fn input_returning_ends_the_long_idle_wait() {
        let mut s = sched(8);
        let caps = run_with(&mut s, &IDLE, 0, 3_000_000);
        let t = *caps.last().unwrap() + 1;
        // Next idle capture is scheduled far out; input resumes.
        match s.on_tick(t, &ACTIVE) {
            Decision::SleepUntil(at) => assert!(at <= t + 3_000),
            other => panic!("{other:?}"),
        }
        assert!(!s.is_idle());
    }

    #[test]
    fn zero_idle_factor_is_rejected() {
        let bad = SchedulerConfig {
            idle_interval_factor: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn trigger_schedules_soon_and_coalesces() {
        let mut s = sched(11);
        let caps = run(&mut s, 0, 5_000);
        let last = caps.last().unwrap().0;
        let now = last + 10_000;
        let TriggerOutcome::Scheduled { at_ms } = s.on_trigger(now, Trigger::ForegroundAppChanged)
        else {
            panic!()
        };
        assert!((now + 1_000..=now + 3_000).contains(&at_ms));
        assert_eq!(
            s.on_trigger(now + 100, Trigger::NewUrl),
            TriggerOutcome::Coalesced { at_ms }
        );
        // The regular capture is at least 15 s after `last`, the trigger at
        // most 13 s after it, so the trigger fires first.
        assert_eq!(s.on_tick(at_ms - 1, &ACTIVE), Decision::SleepUntil(at_ms));
        assert_eq!(
            s.on_tick(at_ms, &ACTIVE),
            Decision::CaptureNow(CaptureInfo {
                cause: CaptureCause::Trigger(Trigger::ForegroundAppChanged),
                burst: false,
            })
        );
    }

    #[test]
    fn trigger_respects_spacing_after_capture() {
        let mut s = sched(12);
        let caps = run(&mut s, 0, 5_000);
        let last = caps.last().unwrap().0;
        let TriggerOutcome::Scheduled { at_ms } = s.on_trigger(last, Trigger::WatchlistedDomain)
        else {
            panic!()
        };
        assert!(at_ms >= last + 3_000);
    }

    #[test]
    fn set_mean_validates_and_reports() {
        let mut s = sched(1);
        assert_eq!(s.set_mean(29), Err(SchedulerError::MeanOutOfRange(29)));
        assert_eq!(s.set_mean(301), Err(SchedulerError::MeanOutOfRange(301)));
        assert_eq!(s.set_mean(60), Ok(None));
        assert_eq!(
            s.set_mean(120).unwrap(),
            Some(SettingChange {
                key: "capture_mean_secs".into(),
                old: Some("60".into()),
                new: Some("120".into())
            })
        );
        assert_eq!(s.mean_secs(), 120);
    }

    #[test]
    fn time_going_backwards_is_tolerated() {
        let mut s = sched(2);
        run(&mut s, 0, 100_000);
        // Must not panic or schedule in the past relative to the high-water mark.
        match s.on_tick(5, &ACTIVE) {
            Decision::SleepUntil(t) => assert!(t > 100_000),
            Decision::CaptureNow(_) => {}
            Decision::Paused(_) => panic!(),
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Advance(u64),
        Trigger,
        Flag(bool),
        Lock(bool),
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0u64..20_000).prop_map(Op::Advance),
            3 => Just(Op::Trigger),
            1 => any::<bool>().prop_map(Op::Flag),
            1 => any::<bool>().prop_map(Op::Lock),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn regular_intervals_within_bounds(seed: u64, mean in MEAN_MIN_SECS..=MEAN_MAX_SECS) {
            let cfg = SchedulerConfig { mean_secs: mean, ..Default::default() };
            let mut s = Scheduler::new(cfg, StdRng::seed_from_u64(seed)).unwrap();
            let (lo, hi) = interval_bounds_ms(mean);
            let caps = run(&mut s, 0, 6 * 3_600_000);
            for w in caps.windows(2).skip(1) {
                let gap = w[1].0 - w[0].0;
                prop_assert!(gap >= lo && gap <= hi, "gap {} not in [{}, {}]", gap, lo, hi);
            }
        }

        /// Under arbitrary interleavings of time, triggers, flags and locks:
        /// captures never happen while paused, never closer together than the
        /// smallest configured spacing, burst is honoured, and every regular
        /// gap stays below the clamp ceiling.
        #[test]
        fn invariants_under_random_ops(seed: u64, ops in proptest::collection::vec(op(), 1..300)) {
            let cfg = SchedulerConfig::default();
            let min_gap = cfg.trigger_min_spacing_ms.min(cfg.burst_min_ms).min(15_000);
            let (_, hi) = interval_bounds_ms(cfg.mean_secs);
            let mut s = Scheduler::new(cfg.clone(), StdRng::seed_from_u64(seed)).unwrap();
            let mut now = 0u64;
            let mut locked = false;
            let mut last_cap: Option<u64> = None;
            let mut last_flag: Option<u64> = None;
            let mut active_since = 0u64;
            for o in ops {
                match o {
                    Op::Advance(d) => {
                        let target = now + d;
                        loop {
                            let snap = SessionSnapshot { locked, ..ACTIVE };
                            match s.on_tick(now, &snap) {
                                Decision::CaptureNow(info) => {
                                    prop_assert!(!locked);
                                    if let Some(l) = last_cap {
                                        prop_assert!(now - l >= min_gap, "gap {} < {}", now - l, min_gap);
                                    }
                                    let expect_burst = last_flag.is_some_and(|f| now < f + cfg.burst_duration_ms);
                                    prop_assert_eq!(info.burst, expect_burst);
                                    last_cap = Some(now);
                                }
                                Decision::SleepUntil(t) => {
                                    prop_assert!(t > now);
                                    // Nothing scheduled further than the ceiling.
                                    let base = last_cap.unwrap_or(active_since).max(active_since);
                                    prop_assert!(t <= base.max(now) + hi);
                                    if t > target { break; }
                                    now = t;
                                }
                                Decision::Paused(r) => {
                                    prop_assert!(locked);
                                    prop_assert_eq!(r, PauseReason::Locked);
                                    break;
                                }
                            }
                        }
                        now = target;
                    }
                    Op::Trigger => {
                        if let TriggerOutcome::Scheduled { at_ms } = s.on_trigger(now, Trigger::NewUrl) {
                            prop_assert!(at_ms >= now + cfg.trigger_delay_min_ms);
                            if let Some(l) = last_cap {
                                prop_assert!(at_ms >= l + cfg.trigger_min_spacing_ms);
                            }
                            prop_assert!(at_ms <= (now + cfg.trigger_delay_max_ms).max(last_cap.unwrap_or(0) + cfg.trigger_min_spacing_ms));
                        }
                    }
                    Op::Flag(borderline) => {
                        let r = if borderline { Rating::Low } else { Rating::High };
                        s.on_result(now, r, borderline);
                        last_flag = Some(now);
                        prop_assert!(s.in_burst(now));
                        // The next capture is at burst cadence.
                        if let Some(due) = s.next_due_ms() {
                            let floor = last_cap.map_or(0, |l| l + cfg.burst_min_ms);
                            prop_assert!(due <= (now + cfg.burst_max_ms).max(floor));
                        }
                    }
                    Op::Lock(l) => {
                        if locked && !l { active_since = now; }
                        locked = l;
                    }
                }
            }
        }
    }
}
