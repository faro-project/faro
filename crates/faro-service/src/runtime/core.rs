//! The service's core actor: one task that owns the event writer, the
//! scheduler, the detector, the clock guard and the current report, and
//! turns what the capture side and the instance tell it into events.
//!
//! | Input | Effect |
//! |---|---|
//! | tick | clock check, report rollover, scheduler → `CaptureNow` |
//! | `Frames` | detector (frames consumed and zeroized) → report; `medium`+ → `flag` event |
//! | tamper signal | [`route_signal`]: `tamper` event (urgent), or report context |
//! | agent drop / reconnect | `agent_restarted`, `agent_killed_repeatedly` past the threshold |
//! | no agent while someone is logged in | `capture_failing` tamper after [`AGENT_ABSENT_MS`] |
//! | member pause / resume | `paused` / `resumed` events |
//! | settings change | `settings_change` event |
//! | start / orderly stop | `boot` / `shutdown` events, partial report |
//!
//! Lock, idle and sleep pauses are *not* events (they would page allies'
//! digests on every screen lock); they appear on the report timeline, and
//! the heartbeat state explains silence to the instance.
//!
//! **A missing agent is tamper.** Stopping the agent (`launchctl bootout`,
//! `pkill`, turning off its login item) must not quietly end monitoring:
//! once someone is logged in at the console and no agent has been connected
//! for [`AGENT_ABSENT_MS`] of awake time, the core raises `capture_failing`
//! (urgent), and heartbeats stop saying `active` while no agent is
//! connected. Session state the agent reported (sleeping, locked) is
//! forgotten when it disconnects, so a departing agent can't leave the
//! service believing the machine sleeps.

use super::journal::{ReportJournal, DAY_MS};
use super::net::OutboxHandle;
use super::status::StatusTx;
use super::supervisor::Supervisor;
use crate::source::{SourceCommand, SourceEvent};
use crate::state::{Enrollment, StateDir, PERMISSIONS_FILE, SETTINGS_FILE};
use faro_core::clock::{Clock, ClockGuard, SystemClock};
use faro_core::{
    route_signal, seal_report, CaptureCause, CaptureInfo, Decision, EventWriter, MemberSettings,
    OutboxError, RecipientSet, Scheduler, SessionSnapshot, SignalRoute, Transition, Trigger,
};
use faro_detect::{ContextSignals, DetectionOutcome, Detector, DetectorConfig, NullClassifier};
use faro_ipc::CaptureReason;
use faro_platform::{Frame, PermissionState, SessionChange};
use faro_proto::api::DeviceState;
use faro_proto::body::{BrowserContext, EventBody, FlagBody, Rating, TamperSignal};
use faro_proto::report::ActivityState;
use faro_proto::Urgency;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Notify};

/// A capture that has not been answered after this long counts as failed.
const CAPTURE_TIMEOUT_MS: u64 = 60_000;
/// Later `Frames` batches of one capture (machines with more displays than
/// `faro_ipc::MAX_FRAMES_PER_MESSAGE`) are accepted this long after the
/// first. The IPC source only forwards batches sharing the first batch's
/// capture time, so this cannot admit unsolicited frames.
const CAPTURE_CONTINUATION_MS: u64 = 5_000;
/// Identical tamper signals within this window are reported once (the agent
/// and the service can both notice the same permission revocation).
const SIGNAL_DEDUPE_MS: u64 = 60_000;
/// Idle seconds after which the heartbeat says `idle` (the scheduler's
/// default idle threshold).
const IDLE_SECS: u64 = 300;
/// Awake time with someone at the console and no agent connected after
/// which the service raises `capture_failing`: two missed pings of the
/// slowest allowed ping interval plus launchd's relaunch throttle, with
/// margin. A real agent restart reconnects within seconds.
pub const AGENT_ABSENT_MS: u64 = 90_000;
/// Longest gap between ticks counted as awake time. A longer gap is the
/// machine sleeping (the tick loop does not run), so it must not count
/// towards "no agent for two minutes".
const MAX_TICK_GAP_MS: u64 = 5_000;
/// Awake time after which an agent's claim that the system sleeps is no
/// longer believed: a sleeping machine does not keep running the service.
/// Generous, because macOS dark wakes (Power Nap) run processes briefly.
const SLEEP_CLAIM_MAX_AWAKE_MS: u64 = 600_000;
/// How often an unsealed daily report is retried.
const REPORT_RETRY_MS: u64 = 60_000;
/// Unsealed reports kept for retry; older ones are given up (with an error).
const MAX_UNSEALED_REPORTS: usize = 8;

/// Persisted in [`PERMISSIONS_FILE`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SeenPermissions {
    /// Screen recording has been granted at some point on this enrollment.
    screen_granted: bool,
}

/// A member's request to pause monitoring (allies are told, §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PauseRequest {
    pub reason: Option<String>,
    /// Resume automatically after this long (measured on the monotonic
    /// clock, so changing the wall clock can't extend it).
    pub duration: Option<Duration>,
}

/// Control messages from the [`ServiceHandle`](super::ServiceHandle) and the
/// network tasks.
#[derive(Debug)]
pub enum Control {
    SetPause(Option<PauseRequest>),
    UpdateSettings(MemberSettings, oneshot::Sender<bool>),
    /// Seal the current report up to now and start a new one.
    CloseReport(oneshot::Sender<bool>),
    /// A heartbeat answer arrived: compare clocks.
    ServerTime {
        local_wall_ms: i64,
        server_time_ms: i64,
    },
}

struct MemberPause {
    until_mono: Option<u64>,
}

#[derive(Default)]
struct Session {
    idle_secs: u64,
    locked: bool,
    display_asleep: bool,
}

pub struct CoreParts {
    pub clock: Arc<dyn Clock>,
    pub enrollment: Arc<Enrollment>,
    pub state_dir: StateDir,
    pub writer: EventWriter<Arc<dyn Clock>>,
    pub outbox: OutboxHandle,
    pub detector: Detector,
    pub scheduler: Scheduler<StdRng>,
    pub settings: MemberSettings,
    pub utc_offset_minutes: i32,
    pub supervisor: Supervisor,
    pub capture_failure_threshold: u32,
    pub source_tx: mpsc::Sender<SourceCommand>,
    pub hb_state: watch::Sender<DeviceState>,
    pub upload_poke: Arc<Notify>,
    pub status: StatusTx,
}

pub struct Core {
    clock: Arc<dyn Clock>,
    enrollment: Arc<Enrollment>,
    state_dir: StateDir,
    writer: EventWriter<Arc<dyn Clock>>,
    outbox: OutboxHandle,
    recipients: Option<RecipientSet>,
    detector: Option<Detector>,
    scheduler: Scheduler<StdRng>,
    settings: MemberSettings,
    session: Session,
    member_pause: Option<MemberPause>,
    sleeping: bool,
    context: ContextSignals,
    agent_connected: bool,
    capture_in_flight: Option<(u64, CaptureInfo)>,
    /// The capture whose first batch was just answered: `(mono, info)`.
    last_answered: Option<(u64, CaptureInfo)>,
    journal: ReportJournal,
    activity: ActivityState,
    utc_offset_minutes: i32,
    guard: ClockGuard,
    supervisor: Supervisor,
    failures_in_row: u32,
    capture_failing_reported: bool,
    capture_failure_threshold: u32,
    screen_permission: Option<PermissionState>,
    accessibility: Option<bool>,
    seen_permissions: SeenPermissions,
    recent_signals: HashMap<String, u64>,
    /// Someone is logged in at the console (as far as the source knows).
    console_present: bool,
    /// Awake time without an agent while someone is logged in.
    agent_absent_ms: u64,
    agent_missing_reported: bool,
    /// Awake time since the agent said the system sleeps.
    asleep_awake_ms: u64,
    last_tick_mono: Option<u64>,
    /// Finished report periods whose sealing failed, with their end.
    unsealed: Vec<(ReportJournal, i64)>,
    next_report_retry: u64,
    source_tx: mpsc::Sender<SourceCommand>,
    hb_state: watch::Sender<DeviceState>,
    upload_poke: Arc<Notify>,
    status: StatusTx,
}

fn capture_reason(cause: CaptureCause) -> CaptureReason {
    match cause {
        CaptureCause::Scheduled => CaptureReason::Scheduled,
        CaptureCause::Burst => CaptureReason::Burst,
        CaptureCause::Trigger(Trigger::ForegroundAppChanged) => CaptureReason::ForegroundChanged,
        CaptureCause::Trigger(Trigger::NewUrl) => CaptureReason::UrlChanged,
        CaptureCause::Trigger(Trigger::WatchlistedDomain) => CaptureReason::WatchedDomain,
        CaptureCause::Resume => CaptureReason::SessionResumed,
    }
}

fn url_host(b: &BrowserContext) -> Option<String> {
    let u = url::Url::parse(b.url.as_deref()?).ok()?;
    u.host_str().map(str::to_owned)
}

impl Core {
    pub fn new(p: CoreParts) -> Self {
        let now = p.clock.wall_ms();
        let journal = ReportJournal::for_day_of(
            now,
            p.utc_offset_minutes,
            ActivityState::Off,
            p.settings.report_options(),
        );
        let seen_permissions = match p.state_dir.read_json(PERMISSIONS_FILE) {
            Ok(v) => v.unwrap_or_default(),
            Err(e) => {
                // Fail towards reporting: assume it was granted, so a denied
                // permission at start is reported rather than missed.
                tracing::warn!(error = %e, "stored permission state unreadable");
                SeenPermissions {
                    screen_granted: true,
                }
            }
        };
        Core {
            clock: p.clock,
            enrollment: p.enrollment,
            state_dir: p.state_dir,
            writer: p.writer,
            outbox: p.outbox,
            recipients: None,
            detector: Some(p.detector),
            scheduler: p.scheduler,
            settings: p.settings,
            session: Session::default(),
            member_pause: None,
            sleeping: false,
            context: ContextSignals::default(),
            agent_connected: false,
            capture_in_flight: None,
            last_answered: None,
            journal,
            activity: ActivityState::Off,
            utc_offset_minutes: p.utc_offset_minutes,
            guard: ClockGuard::default(),
            supervisor: p.supervisor,
            failures_in_row: 0,
            capture_failing_reported: false,
            capture_failure_threshold: p.capture_failure_threshold,
            screen_permission: None,
            accessibility: None,
            seen_permissions,
            recent_signals: HashMap::new(),
            console_present: true,
            agent_absent_ms: 0,
            agent_missing_reported: false,
            asleep_awake_ms: 0,
            last_tick_mono: None,
            unsealed: Vec::new(),
            next_report_retry: 0,
            source_tx: p.source_tx,
            hb_state: p.hb_state,
            upload_poke: p.upload_poke,
            status: p.status,
        }
    }

    // ---- events -------------------------------------------------------

    async fn recipients(&mut self) -> Option<RecipientSet> {
        if let Some(s) = &self.recipients {
            return Some(s.clone());
        }
        match self.outbox.recipients(&self.enrollment).await {
            Ok(Some(s)) => {
                self.status
                    .update(|st| st.manifest = Some(s.manifest_ref()));
                self.recipients = Some(s.clone());
                Some(s)
            }
            Ok(None) => {
                tracing::error!("no recipient manifest accepted; cannot seal events");
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot load the recipient set");
                self.status.update(|s| s.last_error = Some(e.to_string()));
                None
            }
        }
    }

    /// Seal `body` to the current recipient manifest, sign it, chain it and
    /// durably commit it. Returns its `(seq, ts_ms)`.
    async fn emit(&mut self, body: EventBody) -> Option<(u64, i64)> {
        let urgency = self.settings.urgency().urgency_for(&body);
        for attempt in 0..3 {
            let set = self.recipients().await?;
            let prepared = match self.writer.prepare(&body, urgency, &set) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, kind = %body.kind(), "cannot build event");
                    return None;
                }
            };
            let to_commit = prepared.clone();
            match self.outbox.run(move |o| o.commit(&to_commit)).await {
                Ok(_) => {
                    if let Err(e) = self.writer.adopt_committed(&prepared) {
                        tracing::error!(error = %e, "writer head out of sync after commit");
                    }
                    let h = &prepared.event().header;
                    let (seq, ts) = (h.seq, h.ts_ms);
                    tracing::debug!(seq, kind = %h.kind, urgency = %h.urgency, "event committed");
                    self.status.update(|s| {
                        s.events_committed += 1;
                        s.last_seq = Some(seq);
                    });
                    if h.urgency >= Urgency::Normal {
                        self.upload_poke.notify_one();
                    }
                    return Some((seq, ts));
                }
                Err(OutboxError::StaleRecipients { .. }) if attempt < 2 => {
                    // A newer manifest was accepted meanwhile (perhaps one
                    // that removes an ally): reload and seal again.
                    self.recipients = None;
                }
                Err(
                    OutboxError::NotNextSeq { .. }
                    | OutboxError::PrevHashMismatch { .. }
                    | OutboxError::NotSuccessor,
                ) if attempt < 2 => match self.outbox.run(|o| o.head()).await {
                    Ok(head) => self.writer.set_head(head),
                    Err(e) => {
                        tracing::error!(error = %e, "cannot re-read the chain head");
                        return None;
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, kind = %body.kind(), "cannot commit event");
                    self.status.update(|s| s.last_error = Some(e.to_string()));
                    return None;
                }
            }
        }
        None
    }

    /// Route a tamper or context signal (§3.7, PROTOCOL.md §3.3).
    pub async fn signal(&mut self, sig: TamperSignal) {
        let wall = self.clock.wall_ms();
        match route_signal(&sig) {
            SignalRoute::ReportContext => self.journal.signal(None, wall, sig),
            SignalRoute::TamperEvent => {
                let now = self.clock.mono_ms();
                self.recent_signals
                    .retain(|_, t| now.saturating_sub(*t) < SIGNAL_DEDUPE_MS);
                let key = format!("{sig:?}");
                if self.recent_signals.contains_key(&key) {
                    tracing::debug!(signal = %key, "duplicate tamper signal suppressed");
                    return;
                }
                self.recent_signals.insert(key, now);
                tracing::warn!(signal = ?sig, "tamper signal");
                let r = self
                    .emit(EventBody::Tamper {
                        signal: sig.clone(),
                    })
                    .await;
                let ts = r.map_or(wall, |(_, ts)| ts);
                self.journal.signal(r.map(|(s, _)| s), ts, sig);
                self.status.update(|s| s.tamper_events += 1);
            }
        }
    }

    // ---- lifecycle ----------------------------------------------------

    /// `boot` event and announcement of any settings change since the last
    /// run (or since the defaults, on first start).
    pub async fn startup(&mut self) {
        let body = EventBody::Boot {
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        if let Some((seq, _)) = self.emit(body).await {
            self.journal.seq(seq);
        }
        let announced: Option<MemberSettings> = match self.state_dir.read_json(SETTINGS_FILE) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "stored settings unreadable; re-announcing");
                None
            }
        };
        let baseline = announced.clone().unwrap_or_default();
        let current = self.settings.clone();
        self.announce_settings(&baseline, &current, announced.is_none())
            .await;
    }

    async fn announce_settings(
        &mut self,
        old: &MemberSettings,
        new: &MemberSettings,
        force_store: bool,
    ) -> bool {
        if let Some(body) = MemberSettings::change_event(old, new) {
            let Some((seq, _)) = self.emit(body).await else {
                // Not persisted, so the change is announced on the next try.
                return false;
            };
            self.journal.seq(seq);
        } else if !force_store {
            return true;
        }
        if let Err(e) = self.state_dir.write_json(SETTINGS_FILE, new) {
            tracing::error!(error = %e, "cannot persist announced settings");
        }
        true
    }

    /// `shutdown` event and the partial report for today so far.
    pub async fn shutdown(&mut self) {
        self.status
            .update(|s| s.phase = super::status::Phase::ShuttingDown);
        self.hb_state.send_replace(DeviceState::ShuttingDown);
        if let Some((seq, _)) = self.emit(EventBody::Shutdown).await {
            self.journal.seq(seq);
        }
        self.retry_unsealed().await;
        let now = self.clock.wall_ms();
        if now > self.journal.start_ms() {
            let j = self.journal.clone();
            if !self.seal(&j, now.min(j.end_ms())).await {
                tracing::error!("the partial report for this run could not be sealed; it is lost");
            }
        }
        let _ = self.source_tx.try_send(SourceCommand::Shutdown);
    }

    // ---- reports ------------------------------------------------------

    async fn seal(&mut self, journal: &ReportJournal, end_ms: i64) -> bool {
        let report = match journal.build(
            end_ms,
            &self.enrollment.device_id,
            &self.enrollment.device_name,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(error = %e, "cannot build report");
                return false;
            }
        };
        for _ in 0..2 {
            let Some(set) = self.recipients().await else {
                return false;
            };
            let sealed = match seal_report(
                &report,
                &self.enrollment.instance_id,
                &self.enrollment.member_id,
                &set,
                self.writer.signing_key(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "cannot seal report");
                    return false;
                }
            };
            match self.outbox.run(move |o| o.add_report(&sealed)).await {
                Ok(_) => {
                    tracing::info!(
                        start = report.period_start_ms,
                        end = report.period_end_ms,
                        "report queued"
                    );
                    self.status.update(|s| s.reports_queued += 1);
                    self.upload_poke.notify_one();
                    return true;
                }
                Err(OutboxError::StaleRecipients { .. }) => self.recipients = None,
                Err(e) => {
                    tracing::error!(error = %e, "cannot queue report");
                    return false;
                }
            }
        }
        false
    }

    async fn rollover(&mut self, wall: i64) {
        let end = self.journal.end_ms();
        let next = if wall < end.saturating_add(DAY_MS) {
            ReportJournal::new(
                end,
                end.saturating_add(DAY_MS),
                self.activity,
                self.settings.report_options(),
            )
        } else {
            // The wall clock jumped by more than a day (or the machine was
            // off): start from now.
            ReportJournal::for_day_of(
                wall,
                self.utc_offset_minutes,
                self.activity,
                self.settings.report_options(),
            )
        };
        let done = std::mem::replace(&mut self.journal, next);
        if !self.seal(&done, end).await {
            self.keep_unsealed(done, end);
        }
    }

    /// Keep a finished period whose report could not be sealed, to retry
    /// it, instead of silently dropping a day of reporting.
    fn keep_unsealed(&mut self, journal: ReportJournal, end: i64) {
        tracing::error!(
            start = journal.start_ms(),
            end,
            "cannot seal the report; will retry"
        );
        if self.unsealed.len() >= MAX_UNSEALED_REPORTS {
            let (old, _) = self.unsealed.remove(0);
            tracing::error!(
                start = old.start_ms(),
                "giving up on an unsealed report after repeated failures"
            );
        }
        self.unsealed.push((journal, end));
        self.next_report_retry = self.clock.mono_ms().saturating_add(REPORT_RETRY_MS);
        let n = self.unsealed.len() as u64;
        self.status.update(|s| {
            s.reports_unsealed = n;
            s.last_error = Some("a report could not be sealed; retrying".into());
        });
    }

    async fn retry_unsealed(&mut self) {
        let pending = std::mem::take(&mut self.unsealed);
        for (journal, end) in pending {
            if !self.seal(&journal, end).await {
                self.unsealed.push((journal, end));
            }
        }
        self.next_report_retry = self.clock.mono_ms().saturating_add(REPORT_RETRY_MS);
        let n = self.unsealed.len() as u64;
        self.status.update(|s| s.reports_unsealed = n);
    }

    /// Seal `[start, now)` and start a fresh journal at now.
    async fn close_report_now(&mut self) -> bool {
        let now = self.clock.wall_ms();
        if now <= self.journal.start_ms() {
            return false;
        }
        let end = now.min(self.journal.end_ms());
        let next = ReportJournal::new(
            end,
            self.journal.end_ms(),
            self.activity,
            self.settings.report_options(),
        );
        let done = std::mem::replace(&mut self.journal, next);
        self.seal(&done, end).await
    }

    fn set_activity(&mut self, state: ActivityState) {
        if state != self.activity {
            self.journal.state(self.clock.wall_ms(), state);
            self.activity = state;
        }
    }

    // ---- scheduling ---------------------------------------------------

    fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            locked: self.session.locked,
            idle_secs: self.session.idle_secs,
            display_asleep: self.session.display_asleep || self.sleeping,
            member_paused: self.member_pause.is_some(),
        }
    }

    fn device_state(&self) -> DeviceState {
        if self.sleeping {
            DeviceState::Sleeping
        } else if self.member_pause.is_some() {
            DeviceState::Paused
        } else if !self.agent_connected {
            // Nothing is being captured. `idle` is the closest state the
            // protocol has (an `unmonitored` state is a faro-proto request);
            // never `active`, and the missing agent itself is a tamper event.
            DeviceState::Idle
        } else if self.session.locked {
            DeviceState::Locked
        } else if self.session.display_asleep || self.session.idle_secs >= IDLE_SECS {
            DeviceState::Idle
        } else {
            DeviceState::Active
        }
    }

    fn publish_state(&self) {
        let s = self.device_state();
        self.hb_state.send_if_modified(|cur| {
            if *cur == s || *cur == DeviceState::ShuttingDown {
                false
            } else {
                *cur = s;
                true
            }
        });
    }

    pub async fn tick(&mut self) {
        let mono = self.clock.mono_ms();
        let wall = self.clock.wall_ms();
        let awake = self
            .last_tick_mono
            .map_or(0, |t| mono.saturating_sub(t))
            .min(MAX_TICK_GAP_MS);
        self.last_tick_mono = Some(mono);
        if let Some(sig) = self.guard.observe_clock(&*self.clock) {
            self.signal(sig).await;
        }
        self.check_agent_absence(awake).await;
        if self.sleeping {
            self.asleep_awake_ms = self.asleep_awake_ms.saturating_add(awake);
            if self.asleep_awake_ms > SLEEP_CLAIM_MAX_AWAKE_MS {
                tracing::warn!(
                    awake_ms = self.asleep_awake_ms,
                    "the agent reported system sleep but the service kept running; resuming capture"
                );
                self.sleeping = false;
                self.asleep_awake_ms = 0;
            }
        }
        if !self.unsealed.is_empty() && mono >= self.next_report_retry {
            self.retry_unsealed().await;
        }
        if self
            .member_pause
            .as_ref()
            .and_then(|p| p.until_mono)
            .is_some_and(|u| mono >= u)
        {
            self.set_pause(None).await;
        }
        if wall >= self.journal.end_ms() {
            self.rollover(wall).await;
        }
        if self
            .capture_in_flight
            .is_some_and(|(t, _)| mono.saturating_sub(t) > CAPTURE_TIMEOUT_MS)
        {
            self.capture_in_flight = None;
            self.capture_failed("capture request timed out").await;
        }
        if !self.agent_connected {
            self.publish_state();
            return;
        }
        let decision = self.scheduler.on_tick(mono, &self.snapshot());
        for t in self.scheduler.drain_transitions() {
            match t {
                Transition::Paused { reason, .. } => self.set_activity(reason.activity_state()),
                Transition::Resumed { .. } => self.set_activity(ActivityState::Active),
            }
        }
        let was_unmonitored = matches!(
            self.activity,
            ActivityState::Unmonitored | ActivityState::Off
        );
        if was_unmonitored && self.scheduler.paused().is_none() {
            self.set_activity(ActivityState::Active);
        }
        self.publish_state();
        if let Decision::CaptureNow(info) = decision {
            if self.capture_in_flight.is_some() {
                return;
            }
            match self
                .source_tx
                .try_send(SourceCommand::CaptureNow(capture_reason(info.cause)))
            {
                Ok(()) => self.capture_in_flight = Some((mono, info)),
                Err(_) => {
                    self.capture_failed("capture driver is not accepting requests")
                        .await
                }
            }
        }
    }

    /// Count awake time without an agent while someone is logged in, and
    /// raise `capture_failing` once it passes [`AGENT_ABSENT_MS`].
    async fn check_agent_absence(&mut self, awake_ms: u64) {
        // A member pause is announced to allies, so a missing agent during
        // it hides nothing; the count resumes when the pause ends.
        if self.agent_connected || !self.console_present || self.member_pause.is_some() {
            return;
        }
        self.agent_absent_ms = self.agent_absent_ms.saturating_add(awake_ms);
        if self.agent_absent_ms < AGENT_ABSENT_MS || self.agent_missing_reported {
            return;
        }
        self.agent_missing_reported = true;
        tracing::warn!(
            absent_ms = self.agent_absent_ms,
            "no capture agent is connected although someone is logged in"
        );
        self.status.update(|s| s.agent_missing = true);
        // No capture can happen without an agent. A dedicated
        // `agent_missing` signal is a faro-proto request; `capture_failing`
        // is the accurate existing one (urgent, immediate alert).
        let missed = self.failures_in_row.max(1);
        self.capture_failing_reported = true;
        self.signal(TamperSignal::CaptureFailing {
            consecutive_failures: missed,
        })
        .await;
    }

    async fn capture_failed(&mut self, reason: &str) {
        tracing::warn!(%reason, "capture failed");
        self.failures_in_row = self.failures_in_row.saturating_add(1);
        self.journal.capture_failure();
        self.status.update(|s| s.capture_failures += 1);
        if self.failures_in_row >= self.capture_failure_threshold && !self.capture_failing_reported
        {
            self.capture_failing_reported = true;
            self.signal(TamperSignal::CaptureFailing {
                consecutive_failures: self.failures_in_row,
            })
            .await;
        }
    }

    async fn on_frames(&mut self, frames: Vec<Frame>) {
        let now = self.clock.mono_ms();
        let (info, continuation) = match self.capture_in_flight.take() {
            Some((_, info)) => {
                self.last_answered = Some((now, info));
                (info, false)
            }
            None => match self.last_answered {
                Some((t, info)) if now.saturating_sub(t) <= CAPTURE_CONTINUATION_MS => (info, true),
                _ => {
                    // Only answers to our own requests are classified.
                    drop(frames);
                    tracing::warn!("frames without an outstanding capture request; dropped");
                    return;
                }
            },
        };
        let Some(mut det) = self.detector.take() else {
            drop(frames);
            return;
        };
        let signals = self.context.clone();
        // Classification is CPU-bound (and ONNX later): off the async
        // threads. Each frame is moved into `process`, which zeroizes it.
        let joined = tokio::task::spawn_blocking(move || {
            let mut outcomes: Vec<DetectionOutcome> = Vec::new();
            let mut errors = Vec::new();
            for f in frames {
                match det.process(f, &signals) {
                    Ok(o) => outcomes.push(o),
                    Err(e) => errors.push(e.to_string()),
                }
            }
            (det, outcomes, errors)
        })
        .await;
        let (outcomes, errors) = match joined {
            Ok((det, o, e)) => {
                self.detector = Some(det);
                (o, e)
            }
            Err(_) => {
                // The frames were dropped (zeroized) with the task. Keep
                // capturing with a context-only detector rather than stop.
                tracing::error!("detector panicked; falling back to context-only detection");
                self.detector = Detector::new(
                    &DetectorConfig::default(),
                    Box::new(NullClassifier::new()),
                    None,
                )
                .ok();
                (Vec::new(), vec!["detector panicked".to_owned()])
            }
        };
        for e in &errors {
            tracing::warn!(error = %e, "frame classification failed");
        }
        let borderline = outcomes.iter().any(|o| o.borderline);
        let Some(best) = outcomes.into_iter().max_by_key(|o| o.rating) else {
            if !continuation {
                self.capture_failed("no frame could be classified").await;
            }
            return;
        };
        self.failures_in_row = 0;
        self.capture_failing_reported = false;
        let mono = self.clock.mono_ms();
        let wall = self.clock.wall_ms();
        self.scheduler.on_result(mono, best.rating, borderline);
        // A continuation batch is more displays of a capture already
        // counted; it can still raise a flag for what those displays show.
        if !continuation {
            self.journal.capture(wall, best.rating);
            if let Some(app) = &self.context.app {
                self.journal.app(app);
            }
            if let Some(host) = self.context.browser.as_ref().and_then(url_host) {
                self.journal.domain(&host);
            }
            self.status.update(|s| s.captures += 1);
        }
        if best.rating >= Rating::Medium {
            let flag = FlagBody {
                rating: best.rating,
                reasons: best.reasons,
                app: self.context.app.clone(),
                window_title: self.context.window_title.clone(),
                browser: self.context.browser.clone(),
                thumbnail: best.thumbnail,
                burst: info.burst,
            };
            if let Some((seq, ts)) = self.emit(EventBody::Flag(flag.clone())).await {
                self.journal.flag(seq, ts, &flag);
                self.status.update(|s| s.flags += 1);
            }
        }
    }

    // ---- inputs -------------------------------------------------------

    pub async fn on_source(&mut self, ev: SourceEvent) {
        let mono = self.clock.mono_ms();
        match ev {
            SourceEvent::Connected { agent_version, .. } => {
                tracing::info!(%agent_version, "capture side connected");
                self.agent_connected = true;
                self.agent_absent_ms = 0;
                self.agent_missing_reported = false;
                // A new agent reports its own state; the machine is evidently
                // awake if it connects.
                self.sleeping = false;
                self.asleep_awake_ms = 0;
                self.status.update(|s| {
                    s.agent_connected = true;
                    s.agent_missing = false;
                });
                if let Some(r) = self.supervisor.on_connect(mono) {
                    self.journal.agent_restart();
                    if let Some((seq, _)) = self
                        .emit(EventBody::AgentRestarted {
                            count_last_hour: r.count_last_hour,
                        })
                        .await
                    {
                        self.journal.seq(seq);
                    }
                }
            }
            SourceEvent::Disconnected { reason, expected } => {
                tracing::info!(%reason, expected, "capture side disconnected");
                self.agent_connected = false;
                self.capture_in_flight = None;
                // Whatever the departed agent claimed about sleep no longer
                // stands; it must not keep explaining silence.
                self.sleeping = false;
                self.asleep_awake_ms = 0;
                self.status.update(|s| s.agent_connected = false);
                self.set_activity(if expected {
                    ActivityState::Off
                } else {
                    ActivityState::Unmonitored
                });
                if let Some(sig) = self.supervisor.on_disconnect(mono, expected) {
                    self.signal(sig).await;
                }
                self.publish_state();
            }
            SourceEvent::ConsoleSession { present } => {
                tracing::info!(present, "console session");
                self.console_present = present;
                if !present {
                    // Nobody to monitor: the absence clock starts over at
                    // the next login.
                    self.agent_absent_ms = 0;
                }
            }
            SourceEvent::Frames(frames) => self.on_frames(frames).await,
            SourceEvent::CaptureFailed { reason } => {
                self.capture_in_flight = None;
                self.capture_failed(&reason).await;
            }
            SourceEvent::Foreground { app, title } => {
                let changed =
                    self.context.app.as_ref().map(|a| &a.id) != app.as_ref().map(|a| &a.id);
                self.context.app = app;
                self.context.window_title = title;
                if changed && self.agent_connected {
                    self.scheduler
                        .on_trigger(mono, Trigger::ForegroundAppChanged);
                }
            }
            SourceEvent::Browser(b) => {
                let changed = b.url.is_some()
                    && self.context.browser.as_ref().and_then(|c| c.url.as_ref()) != b.url.as_ref();
                self.context.browser = Some(b);
                if changed && self.agent_connected {
                    self.scheduler.on_trigger(mono, Trigger::NewUrl);
                }
            }
            SourceEvent::Session {
                idle_secs,
                locked,
                display_asleep,
            } => {
                self.session = Session {
                    idle_secs,
                    locked,
                    display_asleep,
                };
                self.publish_state();
            }
            SourceEvent::SessionChanged(c) => {
                match c {
                    SessionChange::Locked => self.session.locked = true,
                    SessionChange::Unlocked => {
                        self.session.locked = false;
                        self.session.idle_secs = 0;
                    }
                    SessionChange::DisplaySleep => self.session.display_asleep = true,
                    SessionChange::DisplayWake => self.session.display_asleep = false,
                    SessionChange::SystemSleep => {
                        if !self.sleeping {
                            self.asleep_awake_ms = 0;
                        }
                        self.sleeping = true;
                        self.set_activity(ActivityState::Asleep);
                    }
                    SessionChange::SystemWake => {
                        self.sleeping = false;
                        if !SystemClock::COUNTS_SLEEP {
                            self.guard.reset();
                        }
                    }
                }
                self.publish_state();
            }
            SourceEvent::Permission {
                screen,
                accessibility,
            } => {
                let was = self.screen_permission.replace(screen);
                let granted = screen == PermissionState::Granted;
                // Revoked while we watched, or revoked while the service was
                // stopped (granted before, on this enrollment, but not now).
                let revoked = !granted
                    && match was {
                        Some(prev) => prev == PermissionState::Granted,
                        None => self.seen_permissions.screen_granted,
                    };
                if revoked {
                    self.signal(TamperSignal::PermissionRevoked {
                        permission: "screen_recording".into(),
                    })
                    .await;
                }
                if granted && !self.seen_permissions.screen_granted {
                    self.seen_permissions.screen_granted = true;
                    if let Err(e) = self
                        .state_dir
                        .write_json(PERMISSIONS_FILE, &self.seen_permissions)
                    {
                        tracing::error!(error = %e, "cannot persist the permission state");
                    }
                }
                if let Some(now) = accessibility {
                    let was = self.accessibility.replace(now);
                    if was == Some(true) && !now {
                        self.signal(TamperSignal::PermissionRevoked {
                            permission: "accessibility".into(),
                        })
                        .await;
                    }
                }
            }
            SourceEvent::Tamper(sig) => self.signal(sig).await,
        }
    }

    /// The capture side ended (its task returned). Treated as an
    /// unexpected disconnect.
    pub async fn source_gone(&mut self) {
        if self.agent_connected {
            self.on_source(SourceEvent::Disconnected {
                reason: "capture driver stopped".into(),
                expected: false,
            })
            .await;
        }
    }

    async fn set_pause(&mut self, req: Option<PauseRequest>) {
        match (req, self.member_pause.is_some()) {
            (Some(r), _) => {
                let until_mono = r.duration.map(|d| {
                    self.clock
                        .mono_ms()
                        .saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                });
                let until_ms = r.duration.map(|d| {
                    self.clock
                        .wall_ms()
                        .saturating_add(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
                });
                if let Some((seq, _)) = self
                    .emit(EventBody::Paused {
                        reason: r.reason,
                        until_ms,
                    })
                    .await
                {
                    self.journal.seq(seq);
                }
                self.member_pause = Some(MemberPause { until_mono });
            }
            (None, true) => {
                self.member_pause = None;
                if let Some((seq, _)) = self.emit(EventBody::Resumed).await {
                    self.journal.seq(seq);
                }
            }
            (None, false) => {}
        }
        self.publish_state();
    }

    pub async fn on_control(&mut self, c: Control) {
        match c {
            Control::SetPause(r) => self.set_pause(r).await,
            Control::UpdateSettings(new, reply) => {
                let old = self.settings.clone();
                let ok = self.announce_settings(&old, &new, false).await;
                if ok {
                    if let Err(e) = self.scheduler.set_mean(new.capture_mean_secs()) {
                        tracing::error!(error = %e, "scheduler refused the new capture mean");
                    }
                    self.journal.set_options(new.report_options());
                    self.settings = new;
                }
                let _ = reply.send(ok);
            }
            Control::CloseReport(reply) => {
                let ok = self.close_report_now().await;
                let _ = reply.send(ok);
            }
            Control::ServerTime {
                local_wall_ms,
                server_time_ms,
            } => {
                if let Some(sig) = self.guard.check_server_wall(local_wall_ms, server_time_ms) {
                    self.signal(sig).await;
                }
            }
        }
    }
}
