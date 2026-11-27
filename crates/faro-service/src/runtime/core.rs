//! The service's core actor: one task that owns the event writer, the
//! scheduler, the detector, the clock guard and the current report, and
//! turns what the capture side and the instance tell it into events.
//!
//! | Input | Effect |
//! |---|---|
//! | tick | clock check, report rollover, scheduler → `CaptureNow` |
//! | `Frames` | detector (frames consumed and zeroized) → report; `medium`+ → `flag` event |
//! | tamper signal | [`route_signal`]: `tamper` event (urgent), or report context |
//! | captures failing past the threshold (failures among the last [`CAPTURE_OUTCOME_WINDOW`] attempts) | one `capture_failing`, or `permission_revoked` (`never_granted` if it never was) when Screen Recording is off |
//! | agent drop / reconnect (any session) | `agent_restarted`, `agent_killed_repeatedly` past the threshold |
//! | a session (any account) without an agent | `unmonitored_user_session` tamper after [`AGENT_ABSENT_MS`], or [`ABSENT_IN_WINDOW_MS`] within [`ABSENCE_WINDOW_MS`]; again every [`ABSENCE_RERAISE_MS`] |
//! | the session at the screen has its agent, but nothing captures from it | `capture_failing` tamper after [`capture_stall_ms`] |
//! | an agent connects | the login notice in its session (§12) |
//! | member pause / resume | `paused` / `resumed` events |
//! | settings change | `settings_change` event |
//! | start / orderly stop | `boot` / `shutdown` events, partial report |
//!
//! Lock, idle and sleep pauses are *not* events (they would page allies'
//! digests on every screen lock); they appear on the report timeline, and
//! the heartbeat state explains silence to the instance.
//!
//! **Every account is monitored (§3.1).** The source reports every
//! interactive session and whether its agent is connected. A session of
//! any account, at the screen or switched away from, whose agent has not
//! been connected for [`AGENT_ABSENT_MS`] of awake time raises
//! `unmonitored_user_session` for that account (urgent). Stopping the agent
//! (`launchctl bootout`, `pkill`, turning off its login item), or switching
//! to or creating an account without one, must not quietly end monitoring.
//!
//! **A connected agent must be captured from.** A session at the screen
//! whose agent is connected, with nothing pausing capture (a member pause,
//! a locked screen, sleep, idle), should see a capture attempt every
//! regular interval. If the core has had no capture target for it, or made
//! no attempt, for [`capture_stall_ms`] of awake time, that is a bug or
//! tamper that would otherwise stop monitoring without a word (an agent
//! restart once left the core without a target): it raises
//! `capture_failing` for that account (urgent), once until the next
//! attempt. Allies read "Faro couldn't see the screen N times in a row",
//! N being the captures missed at the mean interval.
//!
//! **Capture follows the screen.** Captures go to the *capture target*, the
//! agent of the session at the screen. Heartbeats stop saying `active`
//! while there is none. Session state the target reported (sleeping,
//! locked, permissions, foreground) is forgotten when the target changes,
//! so a departing agent can't leave the service believing the machine
//! sleeps, and one account's state is never attributed to another.
//!
//! **Accounts in events.** Flags and per-session tamper signals carry the
//! account's short name inside the encrypted body (§3.6), and the report
//! timeline records which account was at the screen.

use super::journal::{ReportJournal, SavedTimeline, DAY_MS};
use super::net::OutboxHandle;
use super::status::StatusTx;
use super::supervisor::Supervisor;
use crate::source::{CaptureTarget, SessionStatus, SourceCommand, SourceEvent};
use crate::state::{Enrollment, StateDir, PERMISSIONS_FILE, SETTINGS_FILE, TIMELINE_FILE};
use crate::update::artifacts::Swaps;
use faro_core::clock::{Clock, ClockGuard, SystemClock};
use faro_core::scheduler::interval_bounds_ms;
use faro_core::{
    route_signal, seal_report, CaptureCause, CaptureInfo, Decision, EventWriter, MemberSettings,
    OutboxError, RecipientSet, Scheduler, SessionSnapshot, SignalRoute, Transition, Trigger,
};
use faro_detect::{ContextSignals, DetectionOutcome, Detector, DetectorConfig, NullClassifier};
use faro_ipc::status::{CaptureFailure, CaptureState, PermissionsReport, SessionReport};
use faro_ipc::CaptureReason;
use faro_platform::{Frame, PermissionState, SessionChange};
use faro_proto::api::DeviceState;
use faro_proto::body::{BrowserContext, EventBody, FlagBody, Rating, TamperSignal};
use faro_proto::report::ActivityState;
use faro_proto::Urgency;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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
/// Tamper signals with the same [`SignalKey`] within this window are
/// reported once (the agent and the service can both notice the same
/// permission revocation).
const SIGNAL_DEDUPE_MS: u64 = 60_000;

/// What makes two tamper signals one report within [`SIGNAL_DEDUPE_MS`]:
/// the variant and the account, and for the two variants whose detail comes
/// from a short fixed list, the permission (and `never_granted`) or the
/// component. Agents may only name permissions the IPC source allows, and
/// never send `integrity_failure`. Free text and counters are left out, so
/// changing them does not defeat the dedupe.
type SignalKey = (
    std::mem::Discriminant<TamperSignal>,
    Option<String>,
    Option<String>,
);

fn signal_key(sig: &TamperSignal, account: &Option<String>) -> SignalKey {
    let detail = match sig {
        TamperSignal::PermissionRevoked {
            permission,
            never_granted,
        } => Some(format!("{permission}/{never_granted}")),
        TamperSignal::IntegrityFailure { component } => Some(component.clone()),
        _ => None,
    };
    (std::mem::discriminant(sig), detail, account.clone())
}

/// Events whose commit failed wait in memory for the next tick, at most
/// this many (flags carry a thumbnail). Past it the least urgent are
/// dropped, and the count is logged.
const MAX_QUEUED_EVENTS: usize = 32;
/// Commits that keep failing for this long stop the heartbeats (see
/// [`Core::note_commit_result`]). Three heartbeat intervals.
const COMMIT_FAILING_ALARM_MS: u64 = 15 * 60 * 1000;

/// A "reported once" condition. It is set when the tamper event for it has
/// committed, never before, so a failed commit leaves the condition to be
/// raised again.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Latch {
    Absence(String),
    /// A session's absences added up within [`ABSENCE_WINDOW_MS`].
    AbsenceWindow(String),
    Stall,
    CaptureFailing,
    ScreenOff,
    AgentKilled,
}

/// What happens once a queued event commits.
enum Follow {
    /// A flag: it goes on the report and the status counter.
    Flag(FlagBody),
    /// A tamper event: the dedupe entry and the latches are set.
    Tamper { key: SignalKey, latches: Vec<Latch> },
    /// A settings change: it is now announced, so remember that.
    Settings(MemberSettings),
}

struct Queued {
    body: EventBody,
    urgency: Urgency,
    follow: Follow,
}

/// How an event that was handed to [`Core::emit_queued`] ended up.
#[derive(Debug, PartialEq, Eq)]
enum Emitted {
    /// Committed as `(seq, ts_ms)`.
    Committed(u64, i64),
    /// Kept for the next tick.
    Queued,
    /// Not kept: it cannot be built, or the queue was full of more urgent
    /// events.
    Dropped,
}

/// Why a commit attempt failed.
#[derive(Debug, PartialEq, Eq)]
enum CommitFail {
    /// The outbox or the recipient set could not be used; worth retrying.
    Transient,
    /// The event cannot be built; retrying changes nothing.
    Permanent,
}

/// Awake time a session can go without a connected agent before the
/// service raises `unmonitored_user_session` (§3.7): two missed pings of
/// the slowest allowed ping interval plus launchd's relaunch throttle, with
/// margin. A real agent restart reconnects within seconds.
pub const AGENT_ABSENT_MS: u64 = 90_000;
/// The sliding window over which a session's absences add up (#193), so
/// an agent that leaves for just under [`AGENT_ABSENT_MS`] again and again
/// is caught too.
pub const ABSENCE_WINDOW_MS: u64 = 3_600_000;
/// Awake time without an agent within [`ABSENCE_WINDOW_MS`] that raises
/// `unmonitored_user_session` although no single absence reached
/// [`AGENT_ABSENT_MS`]: 3 minutes an hour (5 %). An agent restart (crash,
/// update) or a login reconnects within seconds, so it takes many of them
/// to get there, and the kill-loop signal counts those.
pub const ABSENT_IN_WINDOW_MS: u64 = 2 * AGENT_ABSENT_MS;
/// While a reported absence lasts, `unmonitored_user_session` is raised
/// again after this much more awake time: allies hear it is still going
/// on, since heartbeats can only say `idle` (no state the instance has
/// means "unmonitored").
pub const ABSENCE_RERAISE_MS: u64 = 3_600_000;
/// Absence is kept in buckets of this much monotonic time.
const ABSENCE_BUCKET_MS: u64 = 60_000;
/// Capture attempts over which failures are counted towards
/// `capture_failing` (#192): twice the largest allowed
/// `capture_failure_threshold`, so N failures in a row are always caught,
/// and so are N failures among the last ten, which no success in between
/// resets (half of all captures at the default of 5). Counted in attempts,
/// not time, so it holds at the slower idle capture rate too.
pub const CAPTURE_OUTCOME_WINDOW: usize = 10;
/// Awake time the session at the screen may go without a capture attempt,
/// while its agent is connected and nothing pauses capture, before the
/// service raises `capture_failing` (§3.7): the longest regular interval
/// plus two mean intervals. 5 minutes at the default 60 s mean, 25 at the
/// 300 s maximum (changing the mean is announced to allies). Always longer
/// than any interval the scheduler draws and than [`CAPTURE_TIMEOUT_MS`].
pub fn capture_stall_ms(mean_secs: u32) -> u64 {
    let (_, longest) = interval_bounds_ms(mean_secs);
    longest.saturating_add(u64::from(mean_secs).saturating_mul(2_000))
}
/// The session key used when the source does not list sessions (the
/// in-process platform): one implicit session, monitored while the source
/// has a capture target.
const IMPLICIT_SESSION: &str = "";
/// Longest gap between ticks counted as awake time. A longer gap is the
/// machine sleeping (the tick loop does not run), so it must not count
/// towards "no agent for two minutes".
const MAX_TICK_GAP_MS: u64 = 5_000;
/// Awake time after which an agent's claim that the system sleeps is no
/// longer believed: a sleeping machine does not keep running the service.
/// Generous, because macOS dark wakes (Power Nap) run processes briefly.
///
/// The budget is spent across claims and restored only by real sleep (a
/// tick gap of [`SLEPT_GAP_MS`]), so claiming sleep again after a claimed
/// wake does not start a new one.
const SLEEP_CLAIM_MAX_AWAKE_MS: u64 = 600_000;
/// A gap between ticks this long is the machine having slept (or being
/// off): the monotonic clock counts sleep, the tick loop does not run.
const SLEPT_GAP_MS: u64 = 30_000;
/// Awake time a session may be claimed locked while input keeps arriving
/// (idle time below the idle threshold) before the claim is not believed.
/// A real lock follows input that stops: the idle threshold passes, and the
/// agent says so within its resend interval (60 s). Twice that, at least
/// [`SLEEP_CLAIM_MAX_AWAKE_MS`].
fn locked_active_max_ms(idle_threshold_secs: u64) -> u64 {
    idle_threshold_secs
        .saturating_mul(2_000)
        .saturating_add(60_000)
        .max(SLEEP_CLAIM_MAX_AWAKE_MS)
}
/// How often the report timeline is saved ([`TIMELINE_FILE`]) besides at
/// every change, so its end is known after a power cut.
const TIMELINE_SAVE_MS: u64 = 60_000;
/// How often an unsealed daily report is retried.
const REPORT_RETRY_MS: u64 = 60_000;
/// Unsealed reports kept for retry; older ones are given up (with an error).
const MAX_UNSEALED_REPORTS: usize = 8;

/// The permission name in `permission_revoked` for Screen Recording, the
/// permission desktop captures need. A source can name another one
/// ([`crate::source::FrameSource::capture_permission`]: Android's
/// accessibility service); "Screen Recording" in this module means
/// whichever permission that is.
pub const SCREEN_RECORDING: &str = "screen_recording";

/// How a capture refused for want of `permission` reads in
/// `CaptureFailed` (the agent's `PlatformError::PermissionDenied`):
/// `permission denied: screen_recording` on desktops.
fn denied_reason(permission: &str) -> String {
    format!("permission denied: {permission}")
}

/// Persisted in [`PERMISSIONS_FILE`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SeenPermissions {
    /// Assume screen recording was granted for every account: written by
    /// earlier versions, and set (not persisted) when the file is
    /// unreadable, so a denied permission is reported rather than missed.
    #[serde(default)]
    screen_granted: bool,
    /// Accounts that granted screen recording at some point on this
    /// enrollment (the permission is per account on macOS).
    #[serde(default)]
    screen_granted_accounts: BTreeSet<String>,
}

impl SeenPermissions {
    fn granted_before(&self, account: &str) -> bool {
        self.screen_granted || self.screen_granted_accounts.contains(account)
    }
}

/// How long one session has been without an agent.
#[derive(Debug, Default)]
struct Absence {
    ms: u64,
    reported: bool,
    /// Raise it again once `ms` reaches this ([`ABSENCE_RERAISE_MS`]).
    reraise_at_ms: u64,
}

impl Absence {
    /// For the status: past the limit, or reported (also when its window
    /// was).
    fn unmonitored(&self) -> bool {
        self.ms >= AGENT_ABSENT_MS || self.reported
    }
}

/// How long the session at the screen has had a connected agent that
/// nothing was captured from.
#[derive(Debug, Default)]
struct Stall {
    /// The session counted; the count restarts when another one is at the
    /// screen.
    session: Option<String>,
    /// Awake, unpaused time since the last capture attempt.
    ms: u64,
    reported: bool,
}

/// The login notice shown in every account's session (§12). The device
/// knows the instance and its own name, and how many allies the member's
/// manifest lists, but not their names (the manifest carries ids and keys
/// only), so it says what it can say truthfully.
pub fn login_notice(
    instance_name: &str,
    device_name: &str,
    allies: Option<usize>,
) -> (String, String) {
    let shared = match allies {
        Some(0) => "the member (no allies yet)".to_owned(),
        Some(1) => "the member and their 1 ally".to_owned(),
        Some(n) => format!("the member and their {n} allies"),
        None => "the member and their allies".to_owned(),
    };
    if cfg!(target_os = "android") {
        // A phone: Faro covers the Android user it is installed in, not
        // every account (docs/ANDROID.md §13), so the notice claims no more.
        return (
            "This phone is monitored by Faro".to_owned(),
            format!(
                "This phone (\"{device_name}\") is monitored by Faro for a member of \
                 {instance_name}. Screenshots are blurred on this phone and shared, \
                 encrypted, only with {shared}."
            ),
        );
    }
    (
        "This computer is monitored by Faro".to_owned(),
        format!(
            "Every account on this computer (\"{device_name}\") is monitored by Faro for a \
             member of {instance_name}. Screenshots are blurred on this computer and shared, \
             encrypted, only with {shared}. Switching to or creating another account does \
             not turn monitoring off."
        ),
    )
}

/// An account name as an event label: `None` if unknown.
fn label(account: &str) -> Option<String> {
    Some(faro_proto::body::account_label(account)).filter(|a| !a.is_empty())
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
    /// A tamper signal from a task outside the core (an update package
    /// that failed its signature check).
    Tamper(TamperSignal),
    /// The OS says the system clock was set (Windows
    /// `SERVICE_CONTROL_TIMECHANGE`): compare wall and monotonic time now
    /// instead of at the next tick.
    ClockChanged,
}

struct MemberPause {
    until_mono: Option<u64>,
    /// The same end on the wall clock, as allies were told it, for the
    /// status (the menu's "Paused until …"). Never used to end the pause.
    until_ms: Option<i64>,
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
    /// The permission captures need, as `permission_revoked` names it
    /// ([`SCREEN_RECORDING`] on desktops).
    pub capture_permission: &'static str,
    pub source_tx: mpsc::Sender<SourceCommand>,
    pub hb_state: watch::Sender<DeviceState>,
    pub upload_poke: Arc<Notify>,
    pub status: StatusTx,
    /// New models and domain lists from the update task.
    pub swaps: Arc<Swaps>,
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
    /// The agent captures go to (the session at the screen).
    target: Option<CaptureTarget>,
    /// Connected agents: session id → account.
    agents: BTreeMap<String, String>,
    /// Connected agents: session id → version (for the status).
    agent_versions: BTreeMap<String, String>,
    /// The sessions the source listed (`None`: it does not list them).
    sessions: Option<Vec<SessionStatus>>,
    /// Sessions currently without an agent.
    absence: BTreeMap<String, Absence>,
    /// Awake time each listed session was without an agent, in
    /// `(bucket start, ms)` buckets of monotonic time, over the last
    /// [`ABSENCE_WINDOW_MS`].
    absent_history: BTreeMap<String, VecDeque<(u64, u64)>>,
    /// Sessions whose windowed absence has been reported; cleared after a
    /// window with no absence.
    absence_window_reported: BTreeSet<String>,
    /// The session at the screen has its agent but is not captured from.
    stall: Stall,
    /// Sessions shown the login notice since they began.
    noticed: BTreeSet<String>,
    capture_in_flight: Option<(u64, CaptureInfo)>,
    /// The capture whose first batch was just answered: `(mono, info)`.
    last_answered: Option<(u64, CaptureInfo)>,
    journal: ReportJournal,
    activity: ActivityState,
    /// The account recorded with `activity` on the timeline.
    activity_account: Option<String>,
    utc_offset_minutes: i32,
    guard: ClockGuard,
    supervisor: Supervisor,
    failures_in_row: u32,
    /// The last [`CAPTURE_OUTCOME_WINDOW`] capture attempts: `true` failed.
    capture_outcomes: VecDeque<bool>,
    capture_failing_reported: bool,
    capture_failure_threshold: u32,
    /// [`CoreParts::capture_permission`].
    capture_permission: &'static str,
    screen_permission: Option<PermissionState>,
    /// A Screen Recording `permission_revoked` was sent for the capture
    /// target since its permission was last seen granted. The failures it
    /// causes are then not reported a second time (§3.7). Set only where
    /// the service itself saw the permission off, never by a signal a
    /// source forwarded, so a forged one cannot silence later reports.
    screen_off_reported: bool,
    accessibility: Option<bool>,
    seen_permissions: SeenPermissions,
    recent_signals: HashMap<SignalKey, u64>,
    /// Awake time the agent has said the system sleeps, since it last
    /// really slept.
    asleep_awake_ms: u64,
    /// The capture target says its session is locked.
    claimed_locked: bool,
    /// Awake time it has said so while input kept arriving.
    locked_active_ms: u64,
    /// That passed [`locked_active_max_ms`]: the claim is ignored until the
    /// session is idle or unlocked.
    lock_disbelieved: bool,
    /// When the timeline is next saved (monotonic).
    next_timeline_save: u64,
    last_tick_mono: Option<u64>,
    /// Finished report periods whose sealing failed, with their end.
    unsealed: Vec<(ReportJournal, i64)>,
    next_report_retry: u64,
    /// Events that could not be committed yet, oldest first.
    queued: Vec<Queued>,
    /// Since when (monotonic) commits have been failing, if they are.
    commit_failing_since: Option<u64>,
    /// Events dropped from a full queue since start.
    dropped_events: u64,
    source_tx: mpsc::Sender<SourceCommand>,
    hb_state: watch::Sender<DeviceState>,
    upload_poke: Arc<Notify>,
    status: StatusTx,
    swaps: Arc<Swaps>,
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

/// An empty context is how the agent says no browser tab is known.
fn browser_context(b: BrowserContext) -> Option<BrowserContext> {
    (b != BrowserContext::default()).then_some(b)
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
                    ..SeenPermissions::default()
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
            target: None,
            agents: BTreeMap::new(),
            agent_versions: BTreeMap::new(),
            sessions: None,
            absence: BTreeMap::new(),
            absent_history: BTreeMap::new(),
            absence_window_reported: BTreeSet::new(),
            stall: Stall::default(),
            noticed: BTreeSet::new(),
            capture_in_flight: None,
            last_answered: None,
            journal,
            activity: ActivityState::Off,
            activity_account: None,
            utc_offset_minutes: p.utc_offset_minutes,
            guard: ClockGuard::default(),
            supervisor: p.supervisor,
            failures_in_row: 0,
            capture_outcomes: VecDeque::new(),
            capture_failing_reported: false,
            capture_failure_threshold: p.capture_failure_threshold,
            capture_permission: p.capture_permission,
            screen_permission: None,
            screen_off_reported: false,
            accessibility: None,
            seen_permissions,
            recent_signals: HashMap::new(),
            asleep_awake_ms: 0,
            claimed_locked: false,
            locked_active_ms: 0,
            lock_disbelieved: false,
            next_timeline_save: 0,
            last_tick_mono: None,
            unsealed: Vec::new(),
            next_report_retry: 0,
            queued: Vec::new(),
            commit_failing_since: None,
            dropped_events: 0,
            source_tx: p.source_tx,
            hb_state: p.hb_state,
            upload_poke: p.upload_poke,
            status: p.status,
            swaps: p.swaps,
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
    /// durably commit it. Returns its `(seq, ts_ms)`. A failure is not
    /// retried: for a flag or a tamper event use [`Self::emit_queued`].
    async fn emit(&mut self, body: EventBody) -> Option<(u64, i64)> {
        let urgency = self.settings.urgency().urgency_for(&body);
        let r = self.try_commit(&body, urgency).await;
        self.note_commit_result(&r);
        r.ok()
    }

    /// [`Self::emit`] for an event that must not be lost: when the commit
    /// fails it waits in a bounded in-memory queue and is retried on every
    /// tick, re-sealed then (so to a newer manifest if one was accepted
    /// meanwhile; its timestamp is the commit's). `follow` runs when it has
    /// committed, now or later.
    async fn emit_queued(&mut self, body: EventBody, follow: Follow) -> Emitted {
        let urgency = self.settings.urgency().urgency_for(&body);
        // Behind events already waiting, so the chain keeps their order.
        if self.queued.is_empty() {
            let r = self.try_commit(&body, urgency).await;
            self.note_commit_result(&r);
            match r {
                Ok((seq, ts)) => {
                    self.apply_follow(follow, seq, ts);
                    return Emitted::Committed(seq, ts);
                }
                Err(CommitFail::Permanent) => return Emitted::Dropped,
                Err(CommitFail::Transient) => {}
            }
        }
        let kind = body.kind();
        if self.queued.len() >= MAX_QUEUED_EVENTS {
            // Make room by dropping the least urgent, the oldest of those
            // (the newest says the most about the present), unless the new
            // event is less urgent than all of them.
            let least = self.queued.iter().map(|e| e.urgency).min();
            let victim = least
                .filter(|l| *l <= urgency)
                .and_then(|l| self.queued.iter().position(|e| e.urgency == l));
            self.dropped_events += 1;
            let dropped = self.dropped_events;
            match victim {
                Some(i) => {
                    self.queued.remove(i);
                    tracing::error!(
                        dropped,
                        "the event queue is full; dropped its least urgent event"
                    );
                }
                None => {
                    tracing::error!(%kind, dropped, "the event queue is full of more urgent events; dropped this one");
                    return Emitted::Dropped;
                }
            }
        }
        tracing::warn!(%kind, queued = self.queued.len() + 1, "event not committed; will retry");
        self.queued.push(Queued {
            body,
            urgency,
            follow,
        });
        Emitted::Queued
    }

    /// Commit the queued events, most urgent first, until one fails.
    async fn retry_queued(&mut self) {
        // Stable: equal urgencies keep their order.
        self.queued.sort_by_key(|q| std::cmp::Reverse(q.urgency));
        while let Some(q) = self.queued.first() {
            let (body, urgency) = (q.body.clone(), q.urgency);
            let r = self.try_commit(&body, urgency).await;
            self.note_commit_result(&r);
            let q = match r {
                Err(CommitFail::Transient) => return,
                Ok((seq, ts)) => {
                    let q = self.queued.remove(0);
                    self.apply_follow(q.follow, seq, ts);
                    continue;
                }
                Err(CommitFail::Permanent) => self.queued.remove(0),
            };
            tracing::error!(kind = %q.body.kind(), "dropped a queued event that cannot be built");
        }
    }

    /// Track how long commits have been failing. Once it has been
    /// [`COMMIT_FAILING_ALARM_MS`], heartbeats stop (`Heartbeater::send`):
    /// the instance's liveness monitor alerts on silence, and nothing else
    /// it can see would tell it that this device can no longer record.
    fn note_commit_result(&mut self, r: &Result<(u64, i64), CommitFail>) {
        match r {
            Ok(_) => {
                if self.commit_failing_since.take().is_some() {
                    tracing::info!("the outbox accepts events again");
                    self.status.update(|s| s.commit_failing = false);
                }
            }
            Err(CommitFail::Permanent) => {}
            Err(CommitFail::Transient) => {
                let now = self.clock.mono_ms();
                let since = *self.commit_failing_since.get_or_insert(now);
                if now.saturating_sub(since) >= COMMIT_FAILING_ALARM_MS {
                    self.status.update_if(|s| {
                        let first = !s.commit_failing;
                        s.commit_failing = true;
                        first
                    });
                }
            }
        }
    }

    fn apply_follow(&mut self, follow: Follow, seq: u64, ts: i64) {
        match follow {
            Follow::Flag(flag) => {
                self.journal.flag(seq, ts, &flag);
                self.status.update(|s| s.flags += 1);
            }
            Follow::Tamper { key, latches } => {
                self.recent_signals.insert(key, self.clock.mono_ms());
                for l in latches {
                    self.set_latch(l);
                }
            }
            Follow::Settings(new) => {
                self.journal.seq(seq);
                self.persist_settings(&new);
            }
        }
    }

    fn set_latch(&mut self, l: Latch) {
        match l {
            Latch::Absence(id) => {
                if let Some(a) = self.absence.get_mut(&id) {
                    a.reported = true;
                    a.reraise_at_ms = a.ms.saturating_add(ABSENCE_RERAISE_MS);
                }
                self.update_session_status();
            }
            Latch::AbsenceWindow(id) => {
                // Only while the window still holds absence; otherwise the
                // condition is already over.
                if self.absent_history.get(&id).is_some_and(|h| !h.is_empty()) {
                    self.absence_window_reported.insert(id);
                }
            }
            Latch::Stall => self.stall.reported = true,
            Latch::CaptureFailing => self.capture_failing_reported = true,
            Latch::ScreenOff => self.screen_off_reported = true,
            Latch::AgentKilled => self.supervisor.mark_reported(self.clock.mono_ms()),
        }
    }

    /// A tamper event that sets this latch is waiting to commit.
    fn latch_pending(&self, l: &Latch) -> bool {
        self.queued.iter().any(|q| match &q.follow {
            Follow::Tamper { latches, .. } => latches.contains(l),
            _ => false,
        })
    }

    /// The condition behind `l` is over: a queued event must not set it
    /// when it commits.
    fn cancel_latch(&mut self, l: &Latch) {
        for q in &mut self.queued {
            if let Follow::Tamper { latches, .. } = &mut q.follow {
                latches.retain(|x| x != l);
            }
        }
    }

    /// One attempt to seal and commit `body`, with the recovery from a
    /// stale manifest or chain head.
    async fn try_commit(
        &mut self,
        body: &EventBody,
        urgency: Urgency,
    ) -> Result<(u64, i64), CommitFail> {
        for attempt in 0..3 {
            let Some(set) = self.recipients().await else {
                return Err(CommitFail::Transient);
            };
            let prepared = match self.writer.prepare(body, urgency, &set) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, kind = %body.kind(), "cannot build event");
                    return Err(CommitFail::Permanent);
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
                    return Ok((seq, ts));
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
                        return Err(CommitFail::Transient);
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, kind = %body.kind(), "cannot commit event");
                    self.status.update(|s| s.last_error = Some(e.to_string()));
                    return Err(CommitFail::Transient);
                }
            }
        }
        Err(CommitFail::Transient)
    }

    /// Route a tamper or context signal that concerns the whole computer
    /// (§3.7, PROTOCOL.md §3.3).
    pub async fn signal(&mut self, sig: TamperSignal) {
        self.signal_for(sig, None).await;
    }

    /// Route a signal from `account`'s session.
    async fn signal_for(&mut self, sig: TamperSignal, account: Option<String>) {
        self.signal_latched(sig, account, Vec::new()).await;
    }

    /// [`Self::signal_for`] for a condition that is reported once: `latches`
    /// are set when the event has committed.
    async fn signal_latched(
        &mut self,
        sig: TamperSignal,
        account: Option<String>,
        latches: Vec<Latch>,
    ) {
        let wall = self.clock.wall_ms();
        match route_signal(&sig) {
            SignalRoute::ReportContext => self.journal.signal(None, wall, sig, account),
            SignalRoute::TamperEvent => {
                let now = self.clock.mono_ms();
                self.recent_signals
                    .retain(|_, t| now.saturating_sub(*t) < SIGNAL_DEDUPE_MS);
                let key = signal_key(&sig, &account);
                let waiting = self
                    .queued
                    .iter()
                    .any(|q| matches!(&q.follow, Follow::Tamper { key: k, .. } if *k == key));
                if self.recent_signals.contains_key(&key) || waiting {
                    tracing::debug!(signal = ?sig, "duplicate tamper signal suppressed");
                    return;
                }
                tracing::debug!(signal = ?sig, "tamper signal detail");
                tracing::warn!(account = ?account, "tamper signal");
                // The dedupe entry and the latches are set when it commits.
                let follow = Follow::Tamper { key, latches };
                let body = EventBody::Tamper {
                    signal: sig.clone(),
                    account: account.clone(),
                };
                let seq_ts = match self.emit_queued(body, follow).await {
                    Emitted::Committed(seq, ts) => Some((seq, ts)),
                    Emitted::Queued | Emitted::Dropped => None,
                };
                let ts = seq_ts.map_or(wall, |(_, ts)| ts);
                self.journal
                    .signal(seq_ts.map(|(s, _)| s), ts, sig, account);
                self.status.update(|s| s.tamper_events += 1);
            }
        }
    }

    // ---- lifecycle ----------------------------------------------------

    /// `boot` event and announcement of any settings change since the last
    /// run (or since the defaults, on first start).
    pub async fn startup(&mut self) {
        self.recover_timeline().await;
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
        // Queued if it cannot be committed now: the settings from
        // `service.toml` are in force, and must still be announced.
        self.announce_settings(&baseline, &current, announced.is_none(), true)
            .await;
    }

    async fn announce_settings(
        &mut self,
        old: &MemberSettings,
        new: &MemberSettings,
        force_store: bool,
        queue: bool,
    ) -> bool {
        if let Some(body) = MemberSettings::change_event(old, new) {
            if queue {
                // Remembered as announced once the event has committed.
                return matches!(
                    self.emit_queued(body, Follow::Settings(new.clone())).await,
                    Emitted::Committed(..)
                );
            }
            let Some((seq, _)) = self.emit(body).await else {
                // Not persisted, so the change is announced on the next try.
                return false;
            };
            self.journal.seq(seq);
        } else if !force_store {
            return true;
        }
        self.persist_settings(new);
        true
    }

    fn persist_settings(&self, new: &MemberSettings) {
        if let Err(e) = self.state_dir.write_json(SETTINGS_FILE, new) {
            tracing::error!(error = %e, "cannot persist announced settings");
        }
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
            if self.seal(&j, now.min(j.end_ms())).await {
                if let Err(e) = self.state_dir.remove(TIMELINE_FILE) {
                    tracing::warn!(error = %e, "cannot remove the saved report timeline");
                }
            } else {
                // Its timeline is recovered at the next start.
                tracing::error!("the partial report for this run could not be sealed");
                self.save_timeline();
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
        self.reopen_activity();
        // Saved first: a crash after sealing must not seal it again.
        self.save_timeline();
        if !self.seal(&done, end).await {
            self.keep_unsealed(done, end);
        }
    }

    /// Save the current period's timeline ([`TIMELINE_FILE`]), so a power
    /// cut or crash does not lose it (#193): unmonitored time in particular
    /// is on the report only. Recovered by [`Self::recover_timeline`].
    fn save_timeline(&mut self) {
        self.next_timeline_save = self.clock.mono_ms().saturating_add(TIMELINE_SAVE_MS);
        let saved = self.journal.saved_timeline(self.clock.wall_ms());
        if let Err(e) = self.state_dir.write_json(TIMELINE_FILE, &saved) {
            tracing::warn!(error = %e, "cannot save the report timeline");
        }
    }

    /// The previous run ended without sealing its report (a crash or power
    /// cut): put its saved timeline back. The same report day continues in
    /// the current journal, with the time the service was not running as
    /// `off`; an earlier day is sealed as its own report, up to when the
    /// timeline was last saved. Counts and flags from before are not saved
    /// (the flags were delivered as events).
    async fn recover_timeline(&mut self) {
        let saved: SavedTimeline = match self.state_dir.read_json(TIMELINE_FILE) {
            Ok(Some(t)) => t,
            Ok(None) => return,
            Err(e) => {
                tracing::warn!(error = %e, "saved report timeline unreadable; dropped");
                self.save_timeline();
                return;
            }
        };
        let now = self.clock.wall_ms();
        let (start, end) = (self.journal.start_ms(), self.journal.end_ms());
        if saved.end_ms == end && saved.start_ms < start {
            tracing::info!("recovered today's report timeline from the last run");
            self.journal = ReportJournal::recovered(
                &saved,
                saved.saved_ms.min(now),
                self.settings.report_options(),
            );
            self.reopen_activity();
        } else if saved.end_ms <= start && saved.saved_ms > saved.start_ms {
            let until = saved.saved_ms.min(saved.end_ms);
            let j = ReportJournal::recovered(&saved, until, self.settings.report_options());
            tracing::info!("sealing the last run's unsealed report from its saved timeline");
            if !self.seal(&j, until).await {
                self.keep_unsealed(j, until);
            }
        } else {
            tracing::warn!("saved report timeline does not fit the current period; dropped");
        }
        self.save_timeline();
    }

    /// A new journal opens in the current state; record its account too.
    fn reopen_activity(&mut self) {
        if self.activity_account.is_some() {
            let start = self.journal.start_ms();
            self.journal
                .state(start, self.activity, self.activity_account.clone());
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
        self.reopen_activity();
        self.save_timeline();
        self.seal(&done, end).await
    }

    /// Record what the device is doing, and which account is at the screen
    /// while that matters.
    fn set_activity(&mut self, state: ActivityState) {
        let account = match state {
            ActivityState::Active | ActivityState::Idle | ActivityState::Locked => {
                self.target_account()
            }
            ActivityState::Unmonitored => self
                .target_account()
                .or_else(|| self.active_session().and_then(|s| label(&s.account))),
            ActivityState::Asleep | ActivityState::Paused | ActivityState::Off => None,
        };
        if state != self.activity || account != self.activity_account {
            self.journal
                .state(self.clock.wall_ms(), state, account.clone());
            self.activity = state;
            self.activity_account = account;
            self.save_timeline();
        }
    }

    // ---- sessions -----------------------------------------------------

    fn capturing(&self) -> bool {
        self.target.is_some()
    }

    fn target_account(&self) -> Option<String> {
        self.target.as_ref().and_then(|t| label(&t.account))
    }

    fn active_session(&self) -> Option<&SessionStatus> {
        self.sessions.as_ref()?.iter().find(|s| s.active)
    }

    /// Someone is at the screen (always assumed when the source does not
    /// list sessions).
    fn someone_active(&self) -> bool {
        self.sessions
            .as_ref()
            .is_none_or(|l| l.iter().any(|s| s.active))
    }

    /// Point captures at another agent (or none). Everything the previous
    /// target reported is forgotten.
    fn set_target(&mut self, target: Option<CaptureTarget>) {
        if target == self.target {
            return;
        }
        tracing::info!(
            account = ?target.as_ref().map(|t| &t.account),
            "capture target"
        );
        self.target = target;
        self.capture_in_flight = None;
        self.last_answered = None;
        self.sleeping = false;
        // `asleep_awake_ms` is kept: it is about the machine, and an agent
        // restart must not renew it.
        self.session = Session::default();
        self.claimed_locked = false;
        self.locked_active_ms = 0;
        self.lock_disbelieved = false;
        self.context = ContextSignals::default();
        self.screen_permission = None;
        self.screen_off_reported = false;
        self.cancel_latch(&Latch::ScreenOff);
        self.accessibility = None;
        let connected = self.capturing();
        let account = self.target_account();
        self.status.update(|s| {
            s.agent_connected = connected;
            s.capture_account = account.clone();
            s.permissions = PermissionsReport {
                account,
                ..PermissionsReport::default()
            };
        });
        self.update_session_status();
        match &self.target {
            // Same state, another account: a new span on the timeline.
            Some(_) => self.set_activity(self.activity),
            None if !self.someone_active() => self.set_activity(ActivityState::Off),
            None => {}
        }
        self.publish_state();
    }

    /// Show the login notice (§12) once per session.
    async fn login_notice(&mut self, session: &str) {
        if !self.noticed.insert(session.to_owned()) {
            return;
        }
        let allies = self.recipients().await.map(|s| s.allies().len());
        let (title, body) = login_notice(
            &self.enrollment.instance_name,
            &self.enrollment.device_name,
            allies,
        );
        if self
            .source_tx
            .try_send(SourceCommand::ShowNotice {
                session: Some(session.to_owned()),
                title,
                body,
            })
            .is_err()
        {
            tracing::warn!("cannot queue the login notice");
            self.noticed.remove(session);
        }
    }

    fn update_session_status(&self) {
        let missing: Vec<String> = self
            .absence
            .iter()
            .filter(|(_, a)| a.unmonitored())
            .map(|(id, _)| self.account_of(id))
            .collect();
        let sessions = self.sessions.as_ref().map_or(1, Vec::len);
        let agents = self.agents.len();
        let list = self.session_list();
        self.status.update(|s| {
            s.agent_missing = !missing.is_empty();
            s.unmonitored_accounts = missing;
            s.sessions = sessions;
            s.agents = agents;
            s.session_list = list;
        });
    }

    /// Every session the source listed, and any connected agent it did not
    /// list (a source that does not list sessions), for the status.
    fn session_list(&self) -> Vec<SessionReport> {
        let target = self.target.as_ref().map(|t| t.session.as_str());
        let entry = |id: &str, account: &str, at_screen: bool| SessionReport {
            session: id.to_owned(),
            account: account.to_owned(),
            at_screen,
            agent_connected: self.agents.contains_key(id),
            agent_version: self.agent_versions.get(id).cloned(),
            capture_target: target == Some(id),
            unmonitored: self.absence.get(id).is_some_and(Absence::unmonitored),
        };
        let listed = self.sessions.as_deref().unwrap_or_default();
        let mut out: Vec<SessionReport> = listed
            .iter()
            .map(|s| entry(&s.id, &s.account, s.active))
            .collect();
        for (id, account) in &self.agents {
            if !listed.iter().any(|s| &s.id == id) {
                out.push(entry(id, account, target == Some(id.as_str())));
            }
        }
        out
    }

    /// Whether captures run, and why not, for the status.
    fn capture_state(&self) -> CaptureState {
        if self.member_pause.is_some() {
            CaptureState::Paused
        } else if self.sleeping {
            CaptureState::Asleep
        } else if !self.capturing() {
            if self.someone_active() {
                CaptureState::NoAgent
            } else {
                CaptureState::LoginWindow
            }
        } else if self.session.locked {
            CaptureState::Locked
        } else if self.session.display_asleep {
            CaptureState::Idle
        } else {
            CaptureState::Active
        }
    }

    fn account_of(&self, session: &str) -> String {
        self.sessions
            .as_ref()
            .and_then(|l| l.iter().find(|s| s.id == session))
            .map(|s| s.account.clone())
            .or_else(|| self.agents.get(session).cloned())
            .unwrap_or_default()
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
        } else if !self.capturing() {
            // Nothing is being captured. `idle` is the closest state the
            // protocol has (an `unmonitored` state is a faro-proto request);
            // never `active`, and the missing agent itself is a tamper event.
            DeviceState::Idle
        } else if self.session.locked {
            DeviceState::Locked
        } else if self.session.display_asleep
            || self.session.idle_secs >= self.scheduler.config().idle_threshold_secs
        {
            // Display asleep, or awake with no input (capturing at the lower
            // rate).
            DeviceState::Idle
        } else {
            DeviceState::Active
        }
    }

    fn publish_state(&self) {
        let state = self.capture_state();
        let account = self.target_account();
        let paused_until = self.member_pause.as_ref().and_then(|p| p.until_ms);
        self.status.update_if(|s| {
            let changed = s.capture.state != state
                || s.capture.target_account != account
                || s.capture.paused_until_ms != paused_until;
            s.capture.state = state;
            s.capture.target_account = account;
            s.capture.paused_until_ms = paused_until;
            changed
        });
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
        self.apply_swaps();
        let mono = self.clock.mono_ms();
        let wall = self.clock.wall_ms();
        let gap = self.last_tick_mono.map_or(0, |t| mono.saturating_sub(t));
        let awake = gap.min(MAX_TICK_GAP_MS);
        self.last_tick_mono = Some(mono);
        if gap >= SLEPT_GAP_MS {
            // The machine really slept: a later sleep claim is believed
            // again for a while.
            self.asleep_awake_ms = 0;
        }
        self.retry_queued().await;
        if let Some(sig) = self.guard.observe_clock(&*self.clock) {
            self.signal(sig).await;
        }
        self.check_agent_absence(awake).await;
        self.check_capture_stall(awake).await;
        if self.sleeping {
            self.asleep_awake_ms = self.asleep_awake_ms.saturating_add(awake);
            if self.asleep_awake_ms > SLEEP_CLAIM_MAX_AWAKE_MS {
                tracing::warn!(
                    awake_ms = self.asleep_awake_ms,
                    "the agent reported system sleep but the service kept running; resuming capture"
                );
                // The budget stays spent until the machine really sleeps.
                self.sleeping = false;
            }
        }
        self.check_lock_claim(awake);
        if mono >= self.next_timeline_save {
            self.save_timeline();
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
        if !self.capturing() {
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
        if self.scheduler.paused().is_none() {
            // Input-idle with the display on is not a pause: capture goes on
            // at the lower rate, and the timeline says "idle".
            self.set_activity(if self.scheduler.is_idle() {
                ActivityState::Idle
            } else {
                ActivityState::Active
            });
        }
        self.publish_state();
        if let Decision::CaptureNow(info) = decision {
            if self.capture_in_flight.is_some() {
                return;
            }
            // An attempt, answered or not: a failure is counted by
            // `capture_failed`, not as a stall.
            self.stall.ms = 0;
            self.stall.reported = false;
            self.cancel_latch(&Latch::Stall);
            self.status
                .update(|s| s.capture.last_attempt_ms = Some(wall));
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

    /// Set `session.locked` from the target's claim, unless the claim is
    /// not believed ([`locked_active_max_ms`]). The doubt ends when the
    /// session is idle or unlocked.
    fn apply_lock_claim(&mut self) {
        let idle_threshold = self.scheduler.config().idle_threshold_secs;
        if !self.claimed_locked || self.session.idle_secs >= idle_threshold {
            self.locked_active_ms = 0;
            self.lock_disbelieved = false;
        }
        self.session.locked = self.claimed_locked && !self.lock_disbelieved;
    }

    /// Count awake time the session is claimed locked while input keeps
    /// arriving, and stop believing the claim past
    /// [`locked_active_max_ms`]: a locked screen that never goes idle is
    /// someone using the computer.
    fn check_lock_claim(&mut self, awake_ms: u64) {
        let idle_threshold = self.scheduler.config().idle_threshold_secs;
        if !self.claimed_locked
            || self.lock_disbelieved
            || self.sleeping
            || self.session.idle_secs >= idle_threshold
        {
            return;
        }
        self.locked_active_ms = self.locked_active_ms.saturating_add(awake_ms);
        if self.locked_active_ms > locked_active_max_ms(idle_threshold) {
            tracing::warn!(
                active_ms = self.locked_active_ms,
                "the agent reports a locked screen that is in use; resuming capture"
            );
            self.lock_disbelieved = true;
            self.apply_lock_claim();
            self.publish_state();
        }
    }

    /// Add `awake_ms` of absence to `session`'s window, and return the
    /// window's total.
    fn note_absent(&mut self, session: &str, now: u64, awake_ms: u64) -> u64 {
        let h = self.absent_history.entry(session.to_owned()).or_default();
        if awake_ms > 0 {
            let bucket = now - now % ABSENCE_BUCKET_MS;
            match h.back_mut() {
                Some((b, ms)) if *b == bucket => *ms = ms.saturating_add(awake_ms),
                _ => h.push_back((bucket, awake_ms)),
            }
        }
        h.iter().map(|(_, ms)| *ms).sum()
    }

    /// Drop absence older than [`ABSENCE_WINDOW_MS`] and the windows of
    /// sessions that ended; a window left empty re-arms its report.
    fn trim_absence_windows(&mut self, now: u64) {
        let listed: Vec<String> = match &self.sessions {
            Some(list) => list.iter().map(|s| s.id.clone()).collect(),
            None => vec![IMPLICIT_SESSION.to_owned()],
        };
        self.absent_history.retain(|id, h| {
            while h
                .front()
                .is_some_and(|(b, _)| now.saturating_sub(*b) > ABSENCE_WINDOW_MS)
            {
                h.pop_front();
            }
            listed.contains(id) && !h.is_empty()
        });
        let over: Vec<String> = self
            .absence_window_reported
            .iter()
            .filter(|id| !self.absent_history.contains_key(*id))
            .cloned()
            .collect();
        for id in over {
            self.absence_window_reported.remove(&id);
            self.cancel_latch(&Latch::AbsenceWindow(id));
        }
    }

    /// Count awake time each session has been without an agent, and raise
    /// `unmonitored_user_session` for its account once that passes
    /// [`AGENT_ABSENT_MS`] in one go, or [`ABSENT_IN_WINDOW_MS`] within
    /// [`ABSENCE_WINDOW_MS`]; again every [`ABSENCE_RERAISE_MS`] while one
    /// absence lasts. Only awake time counts, and none during a member
    /// pause.
    async fn check_agent_absence(&mut self, awake_ms: u64) {
        // A member pause is announced to allies, so a missing agent during
        // it hides nothing; the count resumes when the pause ends.
        if self.member_pause.is_some() {
            return;
        }
        let missing: Vec<(String, String, bool)> = match &self.sessions {
            Some(list) => list
                .iter()
                .filter(|s| !s.agent)
                .map(|s| (s.id.clone(), s.account.clone(), s.active))
                .collect(),
            None if !self.capturing() => vec![(
                IMPLICIT_SESSION.to_owned(),
                self.agents.values().next().cloned().unwrap_or_default(),
                true,
            )],
            None => Vec::new(),
        };
        self.absence
            .retain(|id, _| missing.iter().any(|(m, _, _)| m == id));
        let now = self.clock.mono_ms();
        self.trim_absence_windows(now);
        let mut newly = Vec::new();
        for (id, account, active) in missing {
            let in_window = self.note_absent(&id, now, awake_ms);
            let window_open = !self.absence_window_reported.contains(&id);
            let a = self.absence.entry(id.clone()).or_default();
            a.ms = a.ms.saturating_add(awake_ms);
            // Latched once the event has committed; until then it is
            // raised again each tick, unless one is already waiting.
            let first = !a.reported
                && (a.ms >= AGENT_ABSENT_MS || (window_open && in_window >= ABSENT_IN_WINDOW_MS));
            let again = a.reported && a.ms >= a.reraise_at_ms;
            if first || again {
                newly.push((id, account, active, a.ms));
            }
        }
        newly.retain(|(id, ..)| !self.latch_pending(&Latch::Absence(id.clone())));
        if newly.is_empty() {
            return;
        }
        // Publish the missing accounts before the tamper events count up, so
        // nobody watching the status sees a tamper event without its cause.
        self.update_session_status();
        for (id, account, active, absent_ms) in newly {
            tracing::warn!(
                %account,
                absent_ms,
                "a session has had no Faro agent connected"
            );
            let user = label(&account).unwrap_or_else(|| "unknown".to_owned());
            // Any report of a session's absence also covers its window.
            self.signal_latched(
                TamperSignal::UnmonitoredUserSession { user },
                label(&account),
                vec![Latch::Absence(id.clone()), Latch::AbsenceWindow(id)],
            )
            .await;
            if active && !self.capturing() {
                self.set_activity(ActivityState::Unmonitored);
            }
        }
    }

    /// The session at the screen, if its agent is connected: `(id,
    /// account)`. With a source that does not list sessions, the connected
    /// agent's.
    fn monitored_session(&self) -> Option<(String, String)> {
        match &self.sessions {
            Some(list) => list
                .iter()
                .find(|s| s.active && s.agent && self.agents.contains_key(&s.id))
                .map(|s| (s.id.clone(), s.account.clone())),
            None => self
                .agents
                .iter()
                .next()
                .map(|(id, account)| (id.clone(), account.clone())),
        }
    }

    /// Capture is legitimately paused: by the member (allies were told),
    /// or because the session is locked or the display asleep (the
    /// scheduler's pause reasons, plus system sleep). Input-idle is not a
    /// pause.
    fn capture_paused(&self) -> bool {
        let s = self.snapshot();
        s.member_paused || s.display_asleep || s.locked
    }

    /// Count awake time the session at the screen has had its agent
    /// connected while the core made no capture attempt (it has no capture
    /// target, or the schedule produced nothing), and raise
    /// `capture_failing` for its account once that passes
    /// [`capture_stall_ms`]. Pauses stop the count without resetting it;
    /// an attempt resets it.
    async fn check_capture_stall(&mut self, awake_ms: u64) {
        let Some((session, account)) = self.monitored_session() else {
            // The login window, or no agent (`unmonitored_user_session`
            // covers that).
            self.stall = Stall::default();
            return;
        };
        if self.stall.session.as_deref() != Some(session.as_str()) {
            self.stall = Stall {
                session: Some(session),
                ..Stall::default()
            };
        }
        if self.capture_in_flight.is_some() || self.capture_paused() {
            return;
        }
        self.stall.ms = self.stall.ms.saturating_add(awake_ms);
        let mean_secs = self.scheduler.mean_secs();
        let mut limit = capture_stall_ms(mean_secs);
        if self.scheduler.is_idle() {
            // Input-idle stretches the interval; the stall limit follows.
            let cfg = self.scheduler.config();
            limit =
                limit.max(cfg.idle_interval_max_ms + u64::from(mean_secs).saturating_mul(2_000));
        }
        if self.stall.ms < limit || self.stall.reported || self.latch_pending(&Latch::Stall) {
            return;
        }
        let missed = self.stall.ms / u64::from(mean_secs.max(1)).saturating_mul(1000);
        let missed = u32::try_from(missed).unwrap_or(u32::MAX).max(1);
        tracing::warn!(
            %account,
            stalled_ms = self.stall.ms,
            has_target = self.capturing(),
            "the session at the screen has its agent connected but nothing is captured from it"
        );
        self.signal_latched(
            TamperSignal::CaptureFailing {
                consecutive_failures: missed,
            },
            label(&account),
            vec![Latch::Stall],
        )
        .await;
    }

    /// Record one capture attempt's outcome in the window; returns the
    /// failures in it.
    fn note_capture_outcome(&mut self, failed: bool) -> u32 {
        if self.capture_outcomes.len() >= CAPTURE_OUTCOME_WINDOW {
            self.capture_outcomes.pop_front();
        }
        self.capture_outcomes.push_back(failed);
        let n = self.capture_outcomes.iter().filter(|f| **f).count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Count a failed capture, and raise `capture_failing` (or
    /// `permission_revoked`) once `capture_failure_threshold` of the last
    /// [`CAPTURE_OUTCOME_WINDOW`] attempts failed.
    async fn capture_failed(&mut self, reason: &str) {
        tracing::warn!(%reason, "capture failed");
        self.failures_in_row = self.failures_in_row.saturating_add(1);
        let in_window = self.note_capture_outcome(true);
        self.journal.capture_failure();
        let failure = CaptureFailure {
            at_ms: self.clock.wall_ms(),
            reason: faro_ipc::status::short_reason(reason),
        };
        let in_row = self.failures_in_row;
        self.status.update(|s| {
            s.capture_failures += 1;
            s.capture.consecutive_failures = in_row;
            s.capture.last_failure = Some(failure);
        });
        if in_window >= self.capture_failure_threshold
            && !self.capture_failing_reported
            && !self.latch_pending(&Latch::CaptureFailing)
        {
            let account = self.target_account();
            let denied = reason.contains(&denied_reason(self.capture_permission))
                || self.screen_permission == Some(PermissionState::Denied);
            let mut latches = vec![Latch::CaptureFailing];
            let sig = match (denied, self.screen_off_reported) {
                // Allies were already told Screen Recording is off.
                (true, true) => {
                    self.capture_failing_reported = true;
                    return;
                }
                // Off without a revocation the service saw: never granted
                // here (a new install, or a reinstall that dropped the
                // grant), or turned off in a way it missed.
                (true, false) => {
                    latches.push(Latch::ScreenOff);
                    TamperSignal::PermissionRevoked {
                        permission: self.capture_permission.into(),
                        never_granted: !self
                            .seen_permissions
                            .granted_before(account.as_deref().unwrap_or_default()),
                    }
                }
                (false, _) => TamperSignal::CaptureFailing {
                    consecutive_failures: self.failures_in_row.max(in_window),
                },
            };
            self.signal_latched(sig, account, latches).await;
        }
    }

    /// A capture that saw only a window kept out of captures (Android's
    /// `FLAG_SECURE`). It failed, and counts as a failure on the report
    /// and in the status, but not towards `capture_failing`: the source
    /// reports the window itself (`window_hidden_from_capture`, after its
    /// own debounce, or not at all for the system's own windows), and one
    /// cause gives one signal (§3.7).
    fn capture_hidden(&mut self) {
        tracing::info!("capture hidden by a secure window");
        self.journal.capture_failure();
        let failure = CaptureFailure {
            at_ms: self.clock.wall_ms(),
            reason: crate::source::HIDDEN_FROM_CAPTURE.to_owned(),
        };
        self.status.update(|s| {
            s.capture_failures += 1;
            s.capture.last_failure = Some(failure);
        });
    }

    /// Hand a model or domain list the update task installed to the
    /// detector. Between captures only: never while frames are being
    /// classified, and no frame is involved.
    fn apply_swaps(&mut self) {
        let model = self.swaps.take_model();
        let domains = self.swaps.take_blocklist();
        if model.is_none() && domains.is_none() {
            return;
        }
        let Some(det) = self.detector.as_mut() else {
            tracing::warn!("no detector to take the update; it applies at the next start");
            return;
        };
        if let Some(m) = model {
            tracing::info!(model = %m.label, "image model switched");
            det.set_classifier(m.value);
            let report = super::status::artifact(&m.label, true);
            self.status.update(|s| {
                s.model = Some(m.label);
                s.detection.model = Some(report);
                s.detection.model_missing = None;
            });
        }
        if let Some(d) = domains {
            tracing::info!(list = %d.label, "domain list switched");
            det.set_domains(Some(d.value));
            let report = super::status::artifact(&d.label, true);
            self.status.update(|s| {
                s.blocklist = Some(d.label);
                s.detection.domains = Some(report);
                s.detection.domains_missing = None;
            });
        }
    }

    async fn on_frames(&mut self, frames: Vec<Frame>) {
        self.apply_swaps();
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
        if !continuation {
            let in_window = self.note_capture_outcome(false);
            // Re-armed once the window no longer holds enough failures.
            if in_window < self.capture_failure_threshold {
                self.capture_failing_reported = false;
                self.cancel_latch(&Latch::CaptureFailing);
            }
        }
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
            self.status.update(|s| {
                s.captures += 1;
                s.capture.last_success_ms = Some(wall);
                s.capture.consecutive_failures = 0;
            });
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
                account: self.target_account(),
            };
            // Kept for a retry if the commit fails.
            self.emit_queued(EventBody::Flag(flag.clone()), Follow::Flag(flag))
                .await;
        }
    }

    // ---- inputs -------------------------------------------------------

    pub async fn on_source(&mut self, ev: SourceEvent) {
        let mono = self.clock.mono_ms();
        match ev {
            SourceEvent::AgentConnected {
                session,
                account,
                agent_version,
            } => {
                tracing::info!(%agent_version, %account, "agent connected");
                self.agents.insert(session.clone(), account);
                self.agent_versions.insert(session.clone(), agent_version);
                self.absence.remove(&session);
                self.cancel_latch(&Latch::Absence(session.clone()));
                self.update_session_status();
                if let Some(r) = self.supervisor.on_connect(mono, &session) {
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
                self.login_notice(&session).await;
            }
            SourceEvent::AgentDisconnected {
                session,
                account,
                reason,
                expected,
            } => {
                tracing::info!(%reason, %account, expected, "agent disconnected");
                self.agents.remove(&session);
                self.agent_versions.remove(&session);
                if self.target.as_ref().is_some_and(|t| t.session == session) {
                    self.set_target(None);
                    self.set_activity(if expected || !self.someone_active() {
                        ActivityState::Off
                    } else {
                        ActivityState::Unmonitored
                    });
                }
                if let Some(sig) = self.supervisor.on_disconnect(mono, &session, expected) {
                    if !self.latch_pending(&Latch::AgentKilled) {
                        self.signal_latched(sig, label(&account), vec![Latch::AgentKilled])
                            .await;
                    }
                }
                self.update_session_status();
                self.publish_state();
            }
            SourceEvent::Sessions(list) => {
                if let Some(old) = &self.sessions {
                    for ended in old.iter().filter(|o| !list.iter().any(|n| n.id == o.id)) {
                        tracing::info!(account = %ended.account, "session ended");
                        self.supervisor.forget(&ended.id);
                        self.noticed.remove(&ended.id);
                    }
                }
                self.sessions = Some(list);
                if !self.capturing() && !self.someone_active() {
                    // Nobody to monitor (the login window).
                    self.set_activity(ActivityState::Off);
                }
                self.update_session_status();
            }
            SourceEvent::CaptureTarget(t) => self.set_target(t),
            SourceEvent::Frames(frames) => self.on_frames(frames).await,
            SourceEvent::CaptureFailed { reason } => {
                self.capture_in_flight = None;
                self.capture_failed(&reason).await;
            }
            SourceEvent::CaptureHidden => {
                self.capture_in_flight = None;
                self.capture_hidden();
            }
            SourceEvent::Foreground { app, title } => {
                let changed =
                    self.context.app.as_ref().map(|a| &a.id) != app.as_ref().map(|a| &a.id);
                self.context.app = app;
                self.context.window_title = title;
                if changed {
                    // The tab belonged to the previous app. The agent sends
                    // the new app's tab, if any, right after.
                    self.context.browser = None;
                }
                if changed && self.capturing() {
                    self.scheduler
                        .on_trigger(mono, Trigger::ForegroundAppChanged);
                }
            }
            SourceEvent::Browser(b) => {
                let changed = b.url.is_some()
                    && self.context.browser.as_ref().and_then(|c| c.url.as_ref()) != b.url.as_ref();
                self.context.browser = browser_context(b);
                if changed && self.capturing() {
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
                self.claimed_locked = locked;
                self.apply_lock_claim();
                self.publish_state();
            }
            SourceEvent::SessionChanged(c) => {
                match c {
                    SessionChange::Locked => {
                        self.claimed_locked = true;
                        self.apply_lock_claim();
                    }
                    SessionChange::Unlocked => {
                        self.claimed_locked = false;
                        self.session.idle_secs = 0;
                        self.apply_lock_claim();
                    }
                    SessionChange::DisplaySleep => self.session.display_asleep = true,
                    SessionChange::DisplayWake => self.session.display_asleep = false,
                    SessionChange::SystemSleep => {
                        if self.asleep_awake_ms > SLEEP_CLAIM_MAX_AWAKE_MS {
                            tracing::warn!(
                                "the agent reported system sleep again without the machine sleeping; ignored"
                            );
                        } else {
                            self.sleeping = true;
                            self.set_activity(ActivityState::Asleep);
                        }
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
                let account = self.target_account();
                let key = account.clone().unwrap_or_default();
                let was = self.screen_permission.replace(screen);
                let granted = screen == PermissionState::Granted;
                // Revoked while we watched, or revoked while the service was
                // stopped (granted before by this account, on this
                // enrollment, but not now).
                let revoked = !granted
                    && match was {
                        Some(prev) => prev == PermissionState::Granted,
                        None => self.seen_permissions.granted_before(&key),
                    };
                if revoked {
                    self.signal_latched(
                        TamperSignal::PermissionRevoked {
                            permission: self.capture_permission.into(),
                            never_granted: false,
                        },
                        account.clone(),
                        vec![Latch::ScreenOff],
                    )
                    .await;
                }
                if granted {
                    // Turning it off again is a new signal.
                    self.screen_off_reported = false;
                    self.cancel_latch(&Latch::ScreenOff);
                }
                if granted && self.seen_permissions.screen_granted_accounts.insert(key) {
                    if let Err(e) = self
                        .state_dir
                        .write_json(PERMISSIONS_FILE, &self.seen_permissions)
                    {
                        tracing::error!(error = %e, "cannot persist the permission state");
                    }
                }
                let reported = PermissionsReport {
                    account: account.clone(),
                    screen_recording: Some(screen.into()),
                    accessibility,
                };
                self.status.update(|s| s.permissions = reported);
                if let Some(now) = accessibility {
                    let was = self.accessibility.replace(now);
                    if was == Some(true) && !now {
                        self.signal_for(
                            TamperSignal::PermissionRevoked {
                                permission: "accessibility".into(),
                                never_granted: false,
                            },
                            account,
                        )
                        .await;
                    }
                }
            }
            SourceEvent::Tamper { signal, account } => {
                let account = account.as_deref().and_then(label);
                self.signal_for(signal, account).await
            }
        }
    }

    /// The capture side ended (its task returned). Treated as an
    /// unexpected disconnect of every agent.
    pub async fn source_gone(&mut self) {
        let agents: Vec<(String, String)> = std::mem::take(&mut self.agents).into_iter().collect();
        for (session, account) in agents {
            self.agents.insert(session.clone(), account.clone());
            self.on_source(SourceEvent::AgentDisconnected {
                session,
                account,
                reason: "capture driver stopped".into(),
                expected: false,
            })
            .await;
        }
        self.set_target(None);
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
                self.member_pause = Some(MemberPause {
                    until_mono,
                    until_ms,
                });
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
                let ok = self.announce_settings(&old, &new, false, false).await;
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
            Control::Tamper(sig) => self.signal(sig).await,
            Control::ClockChanged => {
                if let Some(sig) = self.guard.observe_clock(&*self.clock) {
                    self.signal(sig).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_browser_context_clears() {
        assert_eq!(browser_context(BrowserContext::default()), None);
        let private = BrowserContext {
            incognito: true,
            ..BrowserContext::default()
        };
        assert_eq!(browser_context(private.clone()), Some(private));
    }

    #[test]
    fn a_stall_outlasts_every_interval_and_a_lost_answer() {
        assert_eq!(capture_stall_ms(60), 300_000);
        assert_eq!(capture_stall_ms(300), 1_500_000);
        for mean in faro_core::scheduler::MEAN_MIN_SECS..=faro_core::scheduler::MEAN_MAX_SECS {
            let (_, longest) = interval_bounds_ms(mean);
            let stall = capture_stall_ms(mean);
            assert!(stall > longest && stall > CAPTURE_TIMEOUT_MS, "{mean}");
        }
    }

    #[test]
    fn reduced_urls_keep_their_host() {
        let b = BrowserContext {
            url: Some("https://example.test/".into()),
            ..BrowserContext::default()
        };
        assert_eq!(url_host(&b).as_deref(), Some("example.test"));
    }
}
