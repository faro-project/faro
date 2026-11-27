//! The current report period, kept as a replayable journal.
//!
//! `faro_core::ReportBuilder` fixes its period when it is created. The
//! service needs two shapes of report from the same observations: a full day
//! at the period boundary, and, on an orderly shutdown, a **partial** report
//! for `[start, now)` so that a restart mid-day does not lose the morning's
//! counts and timeline. So the service records observations here and builds
//! the `ReportBuilder` only when sealing.
//!
//! Domain and app observations are only journaled while the member has
//! opted in to sharing them (§6: "with the option off the builder does not
//! even keep the counts in memory"), and are purged when the option is
//! turned off. A crash or power cut (no orderly shutdown) loses the
//! journal's counts; flags and tamper were already delivered as their own
//! events. Its activity timeline, which is where unmonitored time is
//! recorded and nowhere else, is saved as it changes ([`SavedTimeline`])
//! and recovered at the next start.

use faro_core::{ReportBuilder, ReportError, ReportOptions};
use faro_proto::body::{AppInfo, FlagBody, Rating, TamperSignal};
use faro_proto::report::{ActivityState, DailyReport};
use faro_proto::DeviceId;
use serde::{Deserialize, Serialize};

pub const DAY_MS: i64 = 24 * 3600 * 1000;

/// Journal entries beyond this are dropped (with a warning), bounding memory
/// on a pathological day. A busy day is a few thousand entries.
pub const MAX_OPS: usize = 100_000;

#[derive(Debug, Clone)]
enum Op {
    Capture {
        ts: i64,
        rating: Rating,
    },
    Flag {
        seq: u64,
        ts: i64,
        flag: Box<FlagBody>,
    },
    State {
        ts: i64,
        state: ActivityState,
        account: Option<String>,
    },
    Signal {
        seq: Option<u64>,
        ts: i64,
        signal: TamperSignal,
        account: Option<String>,
    },
    Seq(u64),
    AgentRestart,
    CaptureFailure,
    Domain(String),
    App(AppInfo),
}

/// Timeline entries saved at most (the most recent are kept). A day has a
/// few dozen; this bounds the file on a pathological one.
pub const MAX_SAVED_STATES: usize = 2_000;

/// A journal's period and activity timeline, as saved in the state
/// directory (`runtime::core`, `state::TIMELINE_FILE`): states and account
/// labels only, which the sealed report carries anyway. Nothing from the
/// screen, no title, URL or domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedTimeline {
    pub start_ms: i64,
    pub end_ms: i64,
    pub states: Vec<SavedState>,
    /// When it was saved (wall clock): the service ran at least until then.
    pub saved_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedState {
    pub ts: i64,
    pub state: ActivityState,
    #[serde(default)]
    pub account: Option<String>,
}

/// Start of the report day containing `wall_ms`, for a fixed UTC offset.
pub fn day_start(wall_ms: i64, utc_offset_minutes: i32) -> i64 {
    let off = i64::from(utc_offset_minutes) * 60_000;
    wall_ms
        .saturating_add(off)
        .div_euclid(DAY_MS)
        .saturating_mul(DAY_MS)
        .saturating_sub(off)
}

#[derive(Debug, Clone)]
pub struct ReportJournal {
    start_ms: i64,
    end_ms: i64,
    ops: Vec<Op>,
    dropped: u64,
    opts: ReportOptions,
}

impl ReportJournal {
    /// A journal for `[start_ms, end_ms)` that opens in `state`.
    pub fn new(start_ms: i64, end_ms: i64, state: ActivityState, opts: ReportOptions) -> Self {
        ReportJournal {
            start_ms,
            end_ms: end_ms.max(start_ms.saturating_add(1)),
            ops: vec![Op::State {
                ts: start_ms,
                state,
                account: None,
            }],
            dropped: 0,
            opts,
        }
    }

    /// From `now_ms` to the end of its report day.
    pub fn for_day_of(
        now_ms: i64,
        utc_offset_minutes: i32,
        state: ActivityState,
        opts: ReportOptions,
    ) -> Self {
        let end = day_start(now_ms, utc_offset_minutes).saturating_add(DAY_MS);
        Self::new(now_ms, end, state, opts)
    }

    /// The journal for `saved`'s period with its timeline back, and `off`
    /// from `off_from` (the service was not running).
    pub fn recovered(saved: &SavedTimeline, off_from: i64, opts: ReportOptions) -> Self {
        let mut j = Self::new(saved.start_ms, saved.end_ms, ActivityState::Off, opts);
        let mut last = saved.start_ms;
        for st in &saved.states {
            j.state(st.ts, st.state, st.account.clone());
            last = last.max(st.ts);
        }
        j.state(off_from.max(last), ActivityState::Off, None);
        j
    }

    /// The period and timeline to save, at `now_ms`.
    pub fn saved_timeline(&self, now_ms: i64) -> SavedTimeline {
        let mut states: Vec<SavedState> = self
            .ops
            .iter()
            .filter_map(|o| match o {
                Op::State { ts, state, account } => Some(SavedState {
                    ts: *ts,
                    state: *state,
                    account: account.clone(),
                }),
                _ => None,
            })
            .collect();
        if states.len() > MAX_SAVED_STATES {
            states.drain(..states.len() - MAX_SAVED_STATES);
        }
        SavedTimeline {
            start_ms: self.start_ms,
            end_ms: self.end_ms,
            states,
            saved_ms: now_ms,
        }
    }

    pub fn start_ms(&self) -> i64 {
        self.start_ms
    }

    pub fn end_ms(&self) -> i64 {
        self.end_ms
    }

    fn push(&mut self, op: Op) {
        if self.ops.len() >= MAX_OPS {
            if self.dropped == 0 {
                tracing::warn!("report journal is full; dropping further routine entries");
            }
            self.dropped += 1;
            return;
        }
        self.ops.push(op);
    }

    /// Flags, states and tamper are kept past the routine cap (they are what
    /// allies most need in the report), up to a hard cap of twice that.
    /// Each flag and tamper signal was also delivered as its own event.
    fn push_important(&mut self, op: Op) {
        if self.ops.len() >= 2 * MAX_OPS {
            self.dropped += 1;
            return;
        }
        self.ops.push(op);
    }

    pub fn capture(&mut self, ts: i64, rating: Rating) {
        self.push(Op::Capture { ts, rating });
    }

    pub fn flag(&mut self, seq: u64, ts: i64, flag: &FlagBody) {
        self.push_important(Op::Flag {
            seq,
            ts,
            flag: Box::new(flag.clone()),
        });
    }

    /// From `ts` on, the device was in `state`, with `account` at the
    /// screen (if any).
    pub fn state(&mut self, ts: i64, state: ActivityState, account: Option<String>) {
        self.push_important(Op::State { ts, state, account });
    }

    /// A tamper or context signal; `seq` is the event that carried it, if
    /// any, and `account` the OS account it came from.
    pub fn signal(
        &mut self,
        seq: Option<u64>,
        ts: i64,
        signal: TamperSignal,
        account: Option<String>,
    ) {
        self.push_important(Op::Signal {
            seq,
            ts,
            signal,
            account,
        });
    }

    /// An event in this period that is not otherwise recorded.
    pub fn seq(&mut self, seq: u64) {
        self.push(Op::Seq(seq));
    }

    pub fn agent_restart(&mut self) {
        self.push(Op::AgentRestart);
    }

    pub fn capture_failure(&mut self) {
        self.push(Op::CaptureFailure);
    }

    pub fn domain(&mut self, domain: &str) {
        if self.opts.share_top_domains {
            self.push(Op::Domain(domain.to_owned()));
        }
    }

    pub fn app(&mut self, app: &AppInfo) {
        if self.opts.share_top_apps {
            self.push(Op::App(app.clone()));
        }
    }

    /// Apply new sharing options; turning an option off forgets what was
    /// collected under it.
    pub fn set_options(&mut self, opts: ReportOptions) {
        if !opts.share_top_domains {
            self.ops.retain(|o| !matches!(o, Op::Domain(_)));
        }
        if !opts.share_top_apps {
            self.ops.retain(|o| !matches!(o, Op::App(_)));
        }
        self.opts = opts;
    }

    /// Build the report for `[start, end_ms)`. `end_ms` is the period end,
    /// or "now" for a partial report at shutdown.
    pub fn build(
        &self,
        end_ms: i64,
        device_id: &DeviceId,
        device_name: &str,
    ) -> Result<DailyReport, ReportError> {
        let mut b = ReportBuilder::new(
            device_id.clone(),
            device_name,
            self.start_ms,
            end_ms,
            self.opts,
        )?;
        for op in &self.ops {
            match op {
                Op::Capture { ts, rating } => {
                    b.record_capture(*ts, *rating);
                }
                Op::Flag { seq, ts, flag } => {
                    b.record_flag(*seq, *ts, flag);
                }
                Op::State { ts, state, account } => {
                    b.record_account_state(*ts, *state, account.clone())
                }
                Op::Signal {
                    seq,
                    ts,
                    signal,
                    account,
                } => {
                    b.record_signal(*seq, *ts, signal.clone(), account.clone());
                }
                Op::Seq(s) => b.record_seq(*s),
                Op::AgentRestart => b.record_agent_restart(),
                Op::CaptureFailure => b.record_capture_failure(),
                Op::Domain(d) => b.record_domain(d),
                Op::App(a) => b.record_app(a),
            }
        }
        Ok(b.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::body::{Reason, ReasonSource};

    fn opts(share: bool) -> ReportOptions {
        ReportOptions {
            share_top_domains: share,
            share_top_apps: share,
        }
    }

    #[test]
    fn day_boundaries() {
        assert_eq!(day_start(DAY_MS + 5, 0), DAY_MS);
        assert_eq!(day_start(-1, 0), -DAY_MS);
        // UTC-5: local midnight is 05:00 UTC.
        let five_h = 5 * 3600 * 1000;
        assert_eq!(day_start(DAY_MS + five_h, -300), DAY_MS + five_h);
        assert_eq!(day_start(DAY_MS + five_h - 1, -300), five_h);
        let j = ReportJournal::for_day_of(DAY_MS + 10, 0, ActivityState::Active, opts(false));
        assert_eq!((j.start_ms(), j.end_ms()), (DAY_MS + 10, 2 * DAY_MS));
    }

    #[test]
    fn builds_full_and_partial_reports() {
        let dev = DeviceId::new("dev_a");
        let mut j = ReportJournal::new(0, 1000, ActivityState::Active, opts(false));
        j.capture(10, Rating::Clean);
        j.capture(20, Rating::Low);
        j.state(30, ActivityState::Locked, None);
        let flag = FlagBody {
            rating: Rating::High,
            reasons: vec![Reason {
                source: ReasonSource::Domain,
                label: "adult".into(),
                score: None,
            }],
            app: None,
            window_title: None,
            browser: None,
            thumbnail: None,
            burst: false,
            account: None,
        };
        j.flag(4, 25, &flag);
        j.signal(Some(5), 26, TamperSignal::WaylandTokenLost, None);
        j.signal(None, 27, TamperSignal::VpnActive, None);
        j.domain("example.org");
        let full = j.build(1000, &dev, "Laptop").unwrap();
        assert_eq!(full.counts.total(), 2);
        assert_eq!(full.flagged.len(), 1);
        assert_eq!((full.first_seq, full.last_seq), (Some(4), Some(5)));
        assert_eq!(full.health.tamper.len(), 1);
        assert_eq!(full.health.context.len(), 1);
        assert!(full.top_domains.is_none(), "not shared, not collected");
        assert_eq!(full.timeline.last().unwrap().end_ms, 1000);
        let partial = j.build(35, &dev, "Laptop").unwrap();
        assert_eq!(partial.period_end_ms, 35);
        assert_eq!(
            partial.timeline.last().unwrap().state,
            ActivityState::Locked
        );
        assert!(j.build(0, &dev, "Laptop").is_err(), "empty period");
    }

    /// #193: the timeline, unmonitored spans included, survives a crash;
    /// the time the service was not running is `off`.
    #[test]
    fn saved_timeline_round_trips_with_off_after_it() {
        let dev = DeviceId::new("dev_a");
        let mut j = ReportJournal::new(0, 10_000, ActivityState::Active, opts(true));
        j.capture(10, Rating::Clean);
        j.domain("example.org");
        j.state(1_000, ActivityState::Unmonitored, Some("alex".into()));
        j.state(3_000, ActivityState::Active, Some("alex".into()));
        let saved = j.saved_timeline(4_000);
        let json = serde_json::to_string(&saved).unwrap();
        assert!(
            !json.contains("example.org"),
            "only states are saved: {json}"
        );
        let back: SavedTimeline = serde_json::from_str(&json).unwrap();
        assert_eq!(back, saved);
        let r = ReportJournal::recovered(&back, 4_000, opts(true))
            .build(10_000, &dev, "L")
            .unwrap();
        assert_eq!(r.health.unmonitored_secs, 2);
        let spans: Vec<_> = r
            .timeline
            .iter()
            .map(|s| (s.start_ms, s.end_ms, s.state))
            .collect();
        assert_eq!(
            spans,
            [
                (0, 1_000, ActivityState::Active),
                (1_000, 3_000, ActivityState::Unmonitored),
                (3_000, 4_000, ActivityState::Active),
                (4_000, 10_000, ActivityState::Off),
            ]
        );
        assert_eq!(r.counts.total(), 0, "counts are not saved");
    }

    #[test]
    fn sharing_options_gate_and_purge() {
        let dev = DeviceId::new("dev_a");
        let mut j = ReportJournal::new(0, 1000, ActivityState::Active, opts(true));
        j.domain("example.org");
        j.app(&AppInfo {
            id: "a".into(),
            name: None,
        });
        let r = j.build(1000, &dev, "L").unwrap();
        assert_eq!(r.top_domains.unwrap().len(), 1);
        assert_eq!(r.top_apps.unwrap().len(), 1);
        j.set_options(opts(false));
        j.set_options(opts(true));
        let r = j.build(1000, &dev, "L").unwrap();
        assert!(r.top_domains.unwrap().is_empty(), "purged when turned off");
    }
}
