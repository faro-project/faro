//! The liveness monitor (§3.7): heartbeats → missed-check-in alerts.
//!
//! **Instance downtime vs. device tamper.** A self-hosted instance goes down
//! (a power cut, a Pi reboot), and while it is down no device can reach it.
//! Two rules keep that from ever looking like device silence:
//!
//! 1. after the instance starts, nobody is judged until a full grace period
//!    of *its own* uptime has passed (devices need time to come back and
//!    flush their queues);
//! 2. silence is only counted from `max(last_seen_at, current_started_at)`,
//!    so any part of a gap that overlaps the instance's downtime (or any
//!    earlier run) never counts.
//!
//! "Started" means the start of the current stretch of *uninterrupted*
//! running ([`crate::workers::UptimeRun::observe`]): a host suspend, a
//! paused VM or a forward jump of the wall clock (a Pi without an RTC whose
//! clock NTP corrects after boot) is downtime just like a restart, although
//! the process never restarted. Silence before a device was endorsed never
//! counts either.
//!
//! The conservative consequence: a restart gives every device a fresh grace
//! period. A device that really is being tampered with is still caught one
//! grace period later, and the hash chain shows anything it failed to
//! upload; a false "Sam's laptop went silent" because the church Pi
//! rebooted would do real harm to trust.
//!
//! The decision is the pure function [`judge`]; [`run_once`] applies it to
//! every active device. A device's next heartbeat closes its episode
//! ([`check_in`]) and raises a normal-urgency "back online" alert.
//!
//! **Upload stalls.** A device can keep heartbeating while its event uploads
//! are blocked (a member filtering `/v1/events:batch` on their own machine,
//! §9 threat 1). Each signed heartbeat claims the device's chain position;
//! when that claim stays ahead of the verified head for longer than the
//! grace period ([`upload_stalled`]), the monitor raises one urgent,
//! tamper-class `upload_stalled` alert per stall. It is
//! judged only while the device is otherwise healthy, so a device that went
//! silent is reported once, as missed.
//!
//! **Retired devices.** A device whose chain ended in an accepted `goodbye`
//! (uninstall) or that its member removed is not judged: the goodbye or the
//! removal was already the urgent alert.

use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::liveness::{self, DeviceLiveness};
use crate::error::AppError;
use crate::state::AppState;
use faro_proto::api::ServerAlertKind;
use faro_proto::{DeviceId, Urgency};

/// How often the monitor runs.
pub const MONITOR_INTERVAL_SECS: u64 = 60;

/// Inputs to one liveness decision. All times are server Unix ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessInput {
    pub now_ms: i64,
    /// When the current instance run started.
    pub run_started_ms: i64,
    pub grace_ms: i64,
    /// Last heartbeat received, if ever.
    pub last_seen_ms: Option<i64>,
    /// When the device became active (silence before its first heartbeat
    /// counts from here).
    pub active_since_ms: i64,
    /// `silence_start_ms` of the open episode, if one is open.
    pub open_episode_start_ms: Option<i64>,
}

/// What to do about one device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The instance itself has not been up for a full grace period yet.
    NotJudged,
    /// Heard from recently enough.
    Healthy,
    /// Silent for longer than the grace period since `silence_start_ms`:
    /// open an episode and raise an urgent missed check-in.
    Missed { silence_start_ms: i64 },
    /// An episode is open and the device is still silent: nothing new.
    StillMissing,
    /// An episode is open but the device has checked in since: close it.
    Recovered,
}

/// The liveness decision. See the module docs for the rules.
pub fn judge(i: &LivenessInput) -> Verdict {
    if let Some(start) = i.open_episode_start_ms {
        return match i.last_seen_ms {
            Some(seen) if seen > start => Verdict::Recovered,
            _ => Verdict::StillMissing,
        };
    }
    if i.now_ms.saturating_sub(i.run_started_ms) < i.grace_ms {
        return Verdict::NotJudged;
    }
    // A heartbeat from before endorsement (pending devices may heartbeat)
    // is older than `active_since`: silence counts from activation.
    let silence_start = i
        .last_seen_ms
        .unwrap_or(i.active_since_ms)
        .max(i.active_since_ms)
        .max(i.run_started_ms);
    if i.now_ms.saturating_sub(silence_start) > i.grace_ms {
        Verdict::Missed {
            silence_start_ms: silence_start,
        }
    } else {
        Verdict::Healthy
    }
}

/// Inputs to one upload-stall decision. All times are server Unix ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StallInput {
    pub now_ms: i64,
    pub run_started_ms: i64,
    pub grace_ms: i64,
    /// Since when heartbeats have claimed a position ahead of the head.
    pub behind_since_ms: Option<i64>,
    /// The position last claimed.
    pub reported_last_seq: Option<i64>,
    /// The verified head.
    pub held_last_seq: Option<i64>,
}

/// Whether the device's uploads have stalled: its claimed position has been
/// ahead of the verified head for longer than the grace period, counting
/// only time the instance was up for (as for silence). Returns when the
/// stall began, which identifies it.
pub fn upload_stalled(i: &StallInput) -> Option<i64> {
    let since = i.behind_since_ms?;
    let reported = i.reported_last_seq?;
    if i.held_last_seq.is_some_and(|held| held >= reported) {
        return None;
    }
    if i.now_ms.saturating_sub(i.run_started_ms) < i.grace_ms {
        return None;
    }
    let counted = since.max(i.run_started_ms);
    (i.now_ms.saturating_sub(counted) > i.grace_ms).then_some(since)
}

/// The machine-readable detail of a missed check-in: the last known state
/// (so allies see "asleep" or "shut down" rather than only "silent") and
/// when the counted silence began. Never content.
pub fn missed_detail(last_state: Option<&str>, silence_start_ms: i64) -> String {
    // Only known state names are echoed; anything else is "unknown".
    const KNOWN: [&str; 6] = [
        "active",
        "idle",
        "locked",
        "paused",
        "sleeping",
        "shutting_down",
    ];
    let state = last_state
        .filter(|s| KNOWN.contains(s))
        .unwrap_or("unknown");
    format!("last_state={state};since_ms={silence_start_ms}")
}

/// Outcome counts of one monitor pass (for logs and tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassSummary {
    pub judged: usize,
    pub missed: usize,
    pub recovered: usize,
    pub stalled: usize,
}

/// One monitor pass as the worker runs it: first notes the time with
/// `run` (so a suspend or clock jump since the last observation counts as
/// downtime), then judges from the start of the current stretch.
pub async fn pass(
    state: &AppState,
    run: &crate::workers::UptimeRun,
) -> Result<PassSummary, AppError> {
    let started = run.observe(state.now_ms());
    run_once(state, started).await
}

/// One monitor pass over every active device.
pub async fn run_once(state: &AppState, run_started_ms: i64) -> Result<PassSummary, AppError> {
    let now = state.now_ms();
    let grace_ms = i64::try_from(state.settings().liveness.grace_secs)
        .unwrap_or(i64::MAX / 1000)
        .saturating_mul(1000);
    let mut summary = PassSummary::default();
    for d in liveness::active_devices(state.db().pool()).await? {
        let input = LivenessInput {
            now_ms: now,
            run_started_ms,
            grace_ms,
            last_seen_ms: d.last_seen_at_ms,
            active_since_ms: d.active_since_ms,
            open_episode_start_ms: d.open_episode.as_ref().map(|e| e.1),
        };
        match judge(&input) {
            // Keep going: devices with open episodes can still recover.
            Verdict::NotJudged => {}
            Verdict::Healthy => {
                summary.judged += 1;
                let stall = StallInput {
                    now_ms: now,
                    run_started_ms,
                    grace_ms,
                    behind_since_ms: d.upload_behind_since_ms,
                    reported_last_seq: d.reported_last_seq,
                    held_last_seq: d.last_seq,
                };
                if let Some(since) = upload_stalled(&stall) {
                    if raise_stalled(state, &d, since, now).await? {
                        summary.stalled += 1;
                    }
                }
            }
            Verdict::StillMissing => summary.judged += 1,
            Verdict::Missed { silence_start_ms } => {
                summary.judged += 1;
                if raise_missed(state, &d, silence_start_ms, now).await? {
                    summary.missed += 1;
                }
            }
            Verdict::Recovered => {
                summary.judged += 1;
                if check_in(state, &d.device_id).await? {
                    summary.recovered += 1;
                }
            }
        }
    }
    Ok(summary)
}

async fn raise_missed(
    state: &AppState,
    d: &DeviceLiveness,
    silence_start_ms: i64,
    now: i64,
) -> Result<bool, AppError> {
    let mut tx = state.db().begin_write().await?;
    if !liveness::open_episode(&mut *tx, &d.device_id, &d.member_id, silence_start_ms, now).await? {
        return Ok(false);
    }
    let kind = ServerAlertKind::MissedCheckin;
    alerts::insert(
        &mut *tx,
        &NewAlert {
            member_id: &d.member_id,
            device_id: Some(&d.device_id),
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: Urgency::Urgent,
            event_seq: None,
            detail: Some(missed_detail(d.last_state.as_deref(), silence_start_ms)),
            dedupe_key: Some(format!("missed:{}:{silence_start_ms}", d.device_id)),
            now_ms: now,
        },
    )
    .await?;
    tx.commit().await?;
    tracing::warn!(device = %d.device_id, "device missed its check-in");
    Ok(true)
}

/// Raise the one alert for an upload stall that began at `since_ms`
/// (deduplicated on it). False if it was already raised.
async fn raise_stalled(
    state: &AppState,
    d: &DeviceLiveness,
    since_ms: i64,
    now: i64,
) -> Result<bool, AppError> {
    let kind = ServerAlertKind::UploadStalled;
    let held = d
        .last_seq
        .map_or_else(|| "none".to_owned(), |s| s.to_string());
    let created = alerts::insert(
        state.db().pool(),
        &NewAlert {
            member_id: &d.member_id,
            device_id: Some(&d.device_id),
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: Urgency::Urgent,
            event_seq: d.reported_last_seq,
            detail: Some(format!(
                "upload_stalled;reported_seq={};held_seq={held};since_ms={since_ms}",
                d.reported_last_seq.unwrap_or(-1)
            )),
            dedupe_key: Some(format!("stall:{}:{since_ms}", d.device_id)),
            now_ms: now,
        },
    )
    .await?;
    if created {
        tracing::warn!(device = %d.device_id, "device is not uploading the events it reports");
    }
    Ok(created)
}

/// A device checked in: close its open missed-check-in episode, if any, and
/// tell the same people with a normal-urgency "back online" alert. Returns
/// whether an episode was closed. Cheap when there is none (one indexed
/// lookup), so the heartbeat handler calls it on every heartbeat.
pub async fn check_in(state: &AppState, device: &DeviceId) -> Result<bool, AppError> {
    // The common case (nothing open) must not take the SQLite write lock.
    if !liveness::has_open_episode(state.db().pool(), device).await? {
        return Ok(false);
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let Some(ep) = liveness::close_open_episode(&mut tx, device, now).await? else {
        return Ok(false);
    };
    let kind = ServerAlertKind::MissedCheckin;
    alerts::insert(
        &mut *tx,
        &NewAlert {
            member_id: &ep.member_id,
            device_id: Some(device),
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: Urgency::Normal,
            event_seq: None,
            detail: Some(format!(
                "back_online;silent_ms={}",
                now.saturating_sub(ep.silence_start_ms)
            )),
            dedupe_key: Some(format!("back:{}", ep.id)),
            now_ms: now,
        },
    )
    .await?;
    tx.commit().await?;
    tracing::info!(device = %device, "device back online");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const H: i64 = 3600 * 1000;

    fn input(now: i64, started: i64, last_seen: Option<i64>) -> LivenessInput {
        LivenessInput {
            now_ms: now,
            run_started_ms: started,
            grace_ms: 3 * H,
            last_seen_ms: last_seen,
            active_since_ms: 0,
            open_episode_start_ms: None,
        }
    }

    #[test]
    fn silent_past_grace_is_missed() {
        let v = judge(&input(10 * H, 0, Some(H)));
        assert_eq!(
            v,
            Verdict::Missed {
                silence_start_ms: H
            }
        );
        assert_eq!(
            judge(&input(4 * H, 0, Some(H))),
            Verdict::Healthy,
            "exactly grace"
        );
        assert!(judge(&input(4 * H + 1, 0, Some(H))).is_missed());
    }

    #[test]
    fn restart_waits_a_full_grace_period() {
        // Device last seen long ago, instance restarted one hour ago.
        assert_eq!(judge(&input(101 * H, 100 * H, Some(H))), Verdict::NotJudged);
        // After a full grace of uptime the silence counts from the restart.
        assert_eq!(
            judge(&input(103 * H + 1, 100 * H, Some(H))),
            Verdict::Missed {
                silence_start_ms: 100 * H
            }
        );
    }

    #[test]
    fn never_seen_device_counts_from_activation() {
        let mut i = input(10 * H, 0, None);
        i.active_since_ms = 8 * H;
        assert_eq!(judge(&i), Verdict::Healthy);
        i.active_since_ms = 6 * H;
        assert_eq!(
            judge(&i),
            Verdict::Missed {
                silence_start_ms: 6 * H
            }
        );
    }

    #[test]
    fn open_episode_recovers_only_after_check_in() {
        let mut i = input(10 * H, 0, Some(H));
        i.open_episode_start_ms = Some(H);
        assert_eq!(judge(&i), Verdict::StillMissing);
        i.last_seen_ms = Some(9 * H);
        assert_eq!(judge(&i), Verdict::Recovered);
        // Recovery is noticed even during a post-restart grace period.
        i.run_started_ms = 9 * H + 1;
        assert_eq!(judge(&i), Verdict::Recovered);
    }

    #[test]
    fn silence_before_endorsement_never_counts() {
        // Last heard while pending, five hours before it was endorsed.
        let mut i = input(10 * H + 60_000, 0, Some(5 * H));
        i.active_since_ms = 10 * H;
        assert_eq!(judge(&i), Verdict::Healthy);
        i.now_ms = 13 * H + 1;
        assert_eq!(
            judge(&i),
            Verdict::Missed {
                silence_start_ms: 10 * H
            }
        );
    }

    fn stall(now: i64, since: Option<i64>, reported: Option<i64>, held: Option<i64>) -> StallInput {
        StallInput {
            now_ms: now,
            run_started_ms: 0,
            grace_ms: 3 * H,
            behind_since_ms: since,
            reported_last_seq: reported,
            held_last_seq: held,
        }
    }

    #[test]
    fn upload_stall_needs_a_full_grace_of_being_behind() {
        assert_eq!(
            upload_stalled(&stall(10 * H, Some(H), Some(9), Some(3))),
            Some(H)
        );
        assert_eq!(
            upload_stalled(&stall(10 * H, Some(H), Some(9), None)),
            Some(H)
        );
        // Exactly grace, caught up, or never behind: nothing.
        assert_eq!(
            upload_stalled(&stall(4 * H, Some(H), Some(9), Some(3))),
            None
        );
        assert_eq!(
            upload_stalled(&stall(10 * H, Some(H), Some(9), Some(9))),
            None
        );
        assert_eq!(upload_stalled(&stall(10 * H, None, Some(9), Some(3))), None);
        assert_eq!(upload_stalled(&stall(10 * H, Some(H), None, Some(3))), None);
        // The instance's own downtime does not count.
        let mut i = stall(10 * H, Some(H), Some(9), Some(3));
        i.run_started_ms = 8 * H;
        assert_eq!(upload_stalled(&i), None);
        i.now_ms = 11 * H + 1;
        assert_eq!(upload_stalled(&i), Some(H), "identified by when it began");
    }

    #[test]
    fn detail_names_state_and_never_echoes_unknown_text() {
        assert_eq!(
            missed_detail(Some("sleeping"), 5),
            "last_state=sleeping;since_ms=5"
        );
        assert_eq!(
            missed_detail(Some("evil;inject"), 5),
            "last_state=unknown;since_ms=5"
        );
        assert_eq!(missed_detail(None, 0), "last_state=unknown;since_ms=0");
    }

    impl Verdict {
        fn is_missed(self) -> bool {
            matches!(self, Verdict::Missed { .. })
        }
    }

    proptest! {
        /// The core §3.7 property: silence that lies within the instance's
        /// downtime plus one grace period never raises an alert.
        #[test]
        fn downtime_plus_grace_never_alerts(
            last_seen in 0i64..1_000 * H,
            downtime in 0i64..200 * H,
            grace in (10 * 60 * 1000i64)..(48 * H),
            into_run_frac in 0.0f64..=1.0,
            active_since in 0i64..1_000 * H,
        ) {
            // The instance went down right after the device's last
            // heartbeat, stayed down for `downtime`, and has now been back
            // for at most one grace period.
            let started = last_seen + downtime;
            let now = started + (grace as f64 * into_run_frac) as i64;
            let i = LivenessInput {
                now_ms: now,
                run_started_ms: started,
                grace_ms: grace,
                last_seen_ms: Some(last_seen),
                active_since_ms: active_since.min(last_seen),
                open_episode_start_ms: None,
            };
            prop_assert!(!judge(&i).is_missed(), "{i:?} -> {:?}", judge(&i));
        }

        /// The decision matches the specification formula exactly.
        #[test]
        fn matches_specification(
            now in 0i64..2_000 * H,
            started in 0i64..2_000 * H,
            last_seen in proptest::option::of(0i64..2_000 * H),
            active_since in 0i64..2_000 * H,
            grace in (10 * 60 * 1000i64)..(48 * H),
        ) {
            prop_assume!(started <= now);
            let i = LivenessInput {
                now_ms: now,
                run_started_ms: started,
                grace_ms: grace,
                last_seen_ms: last_seen,
                active_since_ms: active_since,
                open_episode_start_ms: None,
            };
            let silence_start = last_seen.unwrap_or(active_since).max(active_since).max(started);
            let expect_missed = now - started >= grace && now - silence_start > grace;
            prop_assert_eq!(judge(&i).is_missed(), expect_missed);
            if let Verdict::Missed { silence_start_ms } = judge(&i) {
                // Counted silence never starts before this run did.
                prop_assert!(silence_start_ms >= started);
                prop_assert_eq!(silence_start_ms, silence_start);
            }
        }

        /// Hearing from a device can only make things better.
        #[test]
        fn later_heartbeat_never_worsens(
            now in 0i64..2_000 * H,
            started in 0i64..1_000 * H,
            seen in 0i64..2_000 * H,
            later in 0i64..100 * H,
        ) {
            prop_assume!(started <= now && seen + later <= now);
            let a = judge(&input(now, started, Some(seen)));
            let b = judge(&input(now, started, Some(seen + later)));
            prop_assert!(!(b.is_missed() && !a.is_missed()));
        }
    }
}
