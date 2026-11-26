//! Observable service status, for `faro-service status`, tests driving the
//! runtime in-process, and the agent's status menu (each agent gets a
//! `faro_ipc::MemberStatus` made from the report, see [`feed_loop`]).
//!
//! The runtime keeps a [`ServiceStatus`] in a watch channel. While it runs,
//! [`write_loop`] turns it into a [`StatusReport`] (`faro_ipc::status`, the
//! documented, serializable form) and writes it to [`STATUS_FILE`] in the
//! state directory: on every change (at most about once a second) and at
//! least every [`STATUS_REFRESH_SECS`]. `faro-service status` reads it back
//! with [`read_status_file`]. The file is 0600 in the 0700 state directory,
//! like every other state file, and holds no content (see
//! `faro_ipc::status`).

use crate::state::{StateDir, StateError};
use faro_core::clock::Clock;
use faro_ipc::status::{
    ArtifactReport, ArtifactSource, CaptureReport, CaptureState, DetectionReport, HealthReport,
    PermissionsReport, ServicePhase, SessionReport, StatusReport, UpdatesReport,
    STATUS_REFRESH_SECS, STATUS_SCHEMA,
};
use faro_proto::api::DeviceState;
use faro_proto::keys::ManifestRef;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// The status file in the state directory.
pub const STATUS_FILE: &str = "status.json";

/// Changes are written this long after the first one, so a burst of
/// updates is one write.
const WRITE_DEBOUNCE: Duration = Duration::from_secs(1);

/// Where the service is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Starting,
    /// Enrolled, waiting for the member to endorse the device. Nothing is
    /// sealed or captured in this phase; heartbeats are sent.
    AwaitingEndorsement,
    Running,
    ShuttingDown,
    Stopped,
}

impl From<Phase> for ServicePhase {
    fn from(p: Phase) -> Self {
        match p {
            Phase::Starting => ServicePhase::Starting,
            Phase::AwaitingEndorsement => ServicePhase::AwaitingEndorsement,
            Phase::Running => ServicePhase::Running,
            Phase::ShuttingDown => ServicePhase::ShuttingDown,
            Phase::Stopped => ServicePhase::Stopped,
        }
    }
}

/// A snapshot of what the service is doing. No content, only counters and
/// states.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub phase: Phase,
    /// The agent of the session at the screen is connected (captures can
    /// run).
    pub agent_connected: bool,
    /// The account of the session at the screen, while its agent captures.
    pub capture_account: Option<String>,
    /// Interactive sessions the source reports (1 for a source that does
    /// not list sessions).
    pub sessions: usize,
    /// Connected agents, one per session.
    pub agents: usize,
    /// Some session has had no agent connected for longer than the service
    /// tolerates; an `unmonitored_user_session` tamper event was raised.
    /// Cleared once every session has an agent again.
    pub agent_missing: bool,
    /// The accounts of those sessions.
    pub unmonitored_accounts: Vec<String>,
    /// Daily reports that could not be sealed yet and are being retried.
    pub reports_unsealed: u64,
    /// Events durably committed to the outbox since start.
    pub events_committed: u64,
    /// The newest committed `seq`.
    pub last_seq: Option<u64>,
    /// The instance's latest `acked_through`.
    pub acked_through: Option<u64>,
    pub captures: u64,
    pub capture_failures: u64,
    pub flags: u64,
    pub tamper_events: u64,
    pub reports_queued: u64,
    pub reports_uploaded: u64,
    pub heartbeats_sent: u64,
    pub last_heartbeat_state: Option<DeviceState>,
    /// The recipient manifest the device seals to.
    pub manifest: Option<ManifestRef>,
    /// Set when the instance served a manifest the device refused
    /// (rollback, equivocation, bad signature). Shown to the member.
    pub manifest_warning: Option<String>,
    /// The image model in use (`opennsfw 1.0.0+int8`; `null 0` without one).
    pub model: Option<String>,
    /// The domain list in use (`domains 1.0.0`), if any.
    pub blocklist: Option<String>,
    /// The instance's identity no longer matches the pin; uploads paused.
    pub identity_mismatch: bool,
    pub last_error: Option<String>,
    /// Every session and its agent ([`StatusReport::sessions`]).
    pub session_list: Vec<SessionReport>,
    /// Capture state, target and the latest attempts.
    pub capture: CaptureReport,
    /// The capture target's permissions.
    pub permissions: PermissionsReport,
    /// The model and domain list in use, with where they came from.
    pub detection: DetectionReport,
    /// Client updates.
    pub updates: UpdatesReport,
    /// The enrolled instance's name and address.
    pub instance_name: Option<String>,
    pub instance_url: Option<String>,
    /// The last time the instance answered a heartbeat.
    pub last_contact_ms: Option<i64>,
    /// Since when heartbeats fail because the instance can't be reached.
    pub unreachable_since_ms: Option<i64>,
}

impl ServiceStatus {
    /// The serializable report, for a service that started at `started_ms`,
    /// made at `now_ms`.
    pub fn report(&self, started_ms: i64, now_ms: i64) -> StatusReport {
        let mut capture = self.capture.clone();
        if matches!(self.phase, Phase::ShuttingDown | Phase::Stopped) {
            capture.state = CaptureState::Stopped;
        }
        StatusReport {
            schema: STATUS_SCHEMA,
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: std::process::id(),
            started_ms,
            updated_ms: now_ms,
            phase: self.phase.into(),
            sessions: self.session_list.clone(),
            capture,
            permissions: self.permissions.clone(),
            detection: self.detection.clone(),
            updates: self.updates.clone(),
            health: HealthReport {
                last_heartbeat: self.last_heartbeat_state,
                heartbeats_sent: self.heartbeats_sent,
                captures: self.captures,
                capture_failures: self.capture_failures,
                flags: self.flags,
                tamper_events: self.tamper_events,
                events_committed: self.events_committed,
                last_seq: self.last_seq,
                acked_through: self.acked_through,
                reports_uploaded: self.reports_uploaded,
                reports_unsealed: self.reports_unsealed,
                manifest_warning: self.manifest_warning.clone(),
                identity_mismatch: self.identity_mismatch,
                last_error: self.last_error.clone(),
                last_contact_ms: self.last_contact_ms,
                unreachable_since_ms: self.unreachable_since_ms,
            },
            log_file: crate::logging::log_file().map(str::to_owned),
            instance_name: self.instance_name.clone(),
            instance_url: self.instance_url.clone(),
        }
    }
}

/// Shared sender; cheap to clone.
#[derive(Clone)]
pub struct StatusTx(Arc<watch::Sender<ServiceStatus>>);

impl StatusTx {
    pub fn new() -> (Self, watch::Receiver<ServiceStatus>) {
        let (tx, rx) = watch::channel(ServiceStatus::default());
        (StatusTx(Arc::new(tx)), rx)
    }

    pub fn update(&self, f: impl FnOnce(&mut ServiceStatus)) {
        self.0.send_modify(f);
    }

    /// Like [`update`](Self::update), but watchers are woken only if `f`
    /// returns true (it changed something). For updates made on every tick.
    pub fn update_if(&self, f: impl FnOnce(&mut ServiceStatus) -> bool) {
        self.0.send_if_modified(f);
    }
}

/// Write the report for `status` to [`STATUS_FILE`].
pub fn write_status_file(
    dir: &StateDir,
    status: &ServiceStatus,
    started_ms: i64,
    now_ms: i64,
) -> Result<(), StateError> {
    dir.write_json(STATUS_FILE, &status.report(started_ms, now_ms))
}

/// The last report the service wrote, if any.
pub fn read_status_file(dir: &StateDir) -> Result<Option<StatusReport>, StateError> {
    dir.read_json(STATUS_FILE)
}

/// Keep [`STATUS_FILE`] current until `stop` flips. See the module docs.
pub async fn write_loop(
    dir: StateDir,
    mut rx: watch::Receiver<ServiceStatus>,
    clock: Arc<dyn Clock>,
    started_ms: i64,
    mut stop: watch::Receiver<bool>,
) {
    let refresh = Duration::from_secs(STATUS_REFRESH_SECS);
    let mut warned = false;
    loop {
        let snapshot = rx.borrow_and_update().clone();
        if let Err(e) = write_status_file(&dir, &snapshot, started_ms, clock.wall_ms()) {
            if !warned {
                tracing::warn!(error = %e, "cannot write the status file");
                warned = true;
            }
        } else {
            warned = false;
        }
        let changed = tokio::select! {
            r = rx.changed() => {
                if r.is_err() {
                    return;
                }
                true
            }
            _ = tokio::time::sleep(refresh) => false,
            _ = stop.wait_for(|s| *s) => return,
        };
        if changed {
            tokio::select! {
                _ = tokio::time::sleep(WRITE_DEBOUNCE) => {}
                _ = stop.wait_for(|s| *s) => return,
            }
        }
    }
}

/// The reports the capture source turns into each agent's
/// `faro_ipc::MemberStatus` (`SourceIo::status`).
pub type StatusFeed = watch::Receiver<Option<Arc<StatusReport>>>;

/// Keep `feed` at the latest report until `stop` flips: on every change,
/// at most about once a second ([`WRITE_DEBOUNCE`]). The source sends an
/// agent a new status only when its view changed, so the counters that
/// change with every capture cost nothing.
pub async fn feed_loop(
    mut rx: watch::Receiver<ServiceStatus>,
    feed: watch::Sender<Option<Arc<StatusReport>>>,
    clock: Arc<dyn Clock>,
    started_ms: i64,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        let snapshot = rx.borrow_and_update().clone();
        let report = Arc::new(snapshot.report(started_ms, clock.wall_ms()));
        if feed.send(Some(report)).is_err() {
            return;
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return },
            _ = stop.wait_for(|s| *s) => return,
        }
        tokio::select! {
            _ = tokio::time::sleep(WRITE_DEBOUNCE) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
    }
}

/// A model or domain list label (`opennsfw 1.0.0+int8`, `domains 1.0.0`,
/// `domains`) as a report entry.
pub(crate) fn artifact(label: &str, from_channel: bool) -> ArtifactReport {
    let (name, version) = label.split_once(' ').unwrap_or((label, ""));
    ArtifactReport {
        name: name.to_owned(),
        version: version.to_owned(),
        source: if from_channel {
            ArtifactSource::UpdateChannel
        } else {
            ArtifactSource::Packaged
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_labels() {
        assert_eq!(
            artifact("opennsfw 1.0.0+int8", false),
            ArtifactReport {
                name: "opennsfw".into(),
                version: "1.0.0+int8".into(),
                source: ArtifactSource::Packaged,
            }
        );
        let d = artifact("domains", true);
        assert_eq!((d.name.as_str(), d.version.as_str()), ("domains", ""));
        assert_eq!(d.source, ArtifactSource::UpdateChannel);
    }

    #[test]
    fn a_stopping_service_reports_no_capture() {
        let mut s = ServiceStatus {
            phase: Phase::Running,
            ..ServiceStatus::default()
        };
        s.capture.state = CaptureState::Active;
        assert_eq!(s.report(1, 2).capture.state, CaptureState::Active);
        s.phase = Phase::ShuttingDown;
        let r = s.report(1, 2);
        assert_eq!(r.capture.state, CaptureState::Stopped);
        assert_eq!(r.phase, ServicePhase::ShuttingDown);
        assert_eq!(r.pid, std::process::id());
    }

    #[test]
    fn the_file_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path()).unwrap();
        assert_eq!(read_status_file(&dir).unwrap(), None);
        let s = ServiceStatus {
            phase: Phase::Running,
            flags: 3,
            ..ServiceStatus::default()
        };
        write_status_file(&dir, &s, 10, 20).unwrap();
        let r = read_status_file(&dir).unwrap().unwrap();
        assert_eq!(r, s.report(10, 20));
        assert_eq!(r.health.flags, 3);
    }
}
