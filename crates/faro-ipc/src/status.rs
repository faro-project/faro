//! What the running service is doing, as plain data: [`StatusReport`].
//!
//! The service keeps one of these up to date and writes it to
//! `status.json` in its state directory (`faro-service status` reads it
//! there). It lives in this crate, not in `faro-service`, so that the agent
//! can show it too (a menu-bar status menu) without depending on the
//! service: no [`AgentMsg`](crate::AgentMsg) or
//! [`ServiceMsg`](crate::ServiceMsg) carries it yet, so defining it here
//! changes nothing on the wire.
//!
//! **No content.** A report holds states, times, counters, account short
//! names, versions and short diagnostics. Never a URL, a window title, an
//! app name or anything from a frame.
//!
//! **Encoding.** Every type here serializes with JSON (the status file) and
//! with postcard (the agent protocol, should a message carry it), so there
//! are no `skip_serializing_if` fields, flattened structs or untagged
//! enums. Fields and variants are append-only, as in
//! [`messages`](crate::messages). Every struct is `#[serde(default)]`, so a
//! JSON reader accepts a report from an older or newer service; bump
//! [`STATUS_SCHEMA`] when a field changes meaning.
//!
//! Times are wall-clock milliseconds since the Unix epoch (`*_ms`), as the
//! service's clock saw them.

use faro_proto::api::DeviceState;
use serde::{Deserialize, Serialize};

use crate::messages::WirePermissionState;

/// The version of [`StatusReport`]'s meaning. Readers should show what they
/// understand of a report with a higher schema rather than refuse it.
pub const STATUS_SCHEMA: u32 = 1;

/// A snapshot of the running service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusReport {
    /// [`STATUS_SCHEMA`] of the service that wrote it.
    pub schema: u32,
    /// The service's own version (`0.1.0-beta.1`).
    pub service_version: String,
    /// The service's process id.
    pub pid: u32,
    /// When this service process started.
    pub started_ms: i64,
    /// When this report was made. The service rewrites the file at least
    /// every [`STATUS_REFRESH_SECS`], so an older one means the service is
    /// not running (or the computer was asleep).
    pub updated_ms: i64,
    pub phase: ServicePhase,
    /// Every interactive session the service knows of, with its agent.
    pub sessions: Vec<SessionReport>,
    pub capture: CaptureReport,
    pub permissions: PermissionsReport,
    pub detection: DetectionReport,
    pub updates: UpdatesReport,
    pub health: HealthReport,
    /// The log file the service writes (`/Library/Logs/Faro/faro-service.log`),
    /// or `None` when it logs to stderr (a development run).
    pub log_file: Option<String>,
}

/// How often the service rewrites the status file when nothing changed.
pub const STATUS_REFRESH_SECS: u64 = 30;

impl Default for StatusReport {
    fn default() -> Self {
        StatusReport {
            schema: STATUS_SCHEMA,
            service_version: String::new(),
            pid: 0,
            started_ms: 0,
            updated_ms: 0,
            phase: ServicePhase::default(),
            sessions: Vec::new(),
            capture: CaptureReport::default(),
            permissions: PermissionsReport::default(),
            detection: DetectionReport::default(),
            updates: UpdatesReport::default(),
            health: HealthReport::default(),
            log_file: None,
        }
    }
}

impl StatusReport {
    /// Whether a report this old still describes a running service: it was
    /// refreshed within three refresh periods of `now_ms` and its phase is
    /// not `stopped`.
    pub fn is_fresh(&self, now_ms: i64) -> bool {
        let limit = i64::try_from(STATUS_REFRESH_SECS * 3 * 1000).unwrap_or(i64::MAX);
        self.phase != ServicePhase::Stopped && now_ms.saturating_sub(self.updated_ms) <= limit
    }
}

/// Where the service is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServicePhase {
    #[default]
    Starting,
    /// Enrolled, waiting for the member to approve the computer. Nothing is
    /// captured yet.
    AwaitingEndorsement,
    Running,
    ShuttingDown,
    /// Stopped in an orderly way (the last report a service writes).
    Stopped,
}

/// One interactive session and its agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionReport {
    /// The session id agents send (`uid:501`; empty for a source that does
    /// not list sessions).
    pub session: String,
    /// The account's short name (empty if unknown).
    pub account: String,
    /// The session is the one at the screen.
    pub at_screen: bool,
    /// Its agent is connected.
    pub agent_connected: bool,
    /// The connected agent's version.
    pub agent_version: Option<String>,
    /// Captures go to this session's agent.
    pub capture_target: bool,
    /// The session has gone without an agent long enough that an
    /// `unmonitored_user_session` tamper event was raised for it.
    pub unmonitored: bool,
}

/// Whether captures run right now, and why not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    /// Capturing has not started (the service is starting or waiting for
    /// approval).
    #[default]
    NotStarted,
    /// Captures run.
    Active,
    /// The person at the screen is idle or the display is off: captures are
    /// paused until they come back.
    Idle,
    /// The screen is locked.
    Locked,
    /// The computer is asleep.
    Asleep,
    /// The member paused monitoring (allies were told).
    Paused,
    /// Nobody is logged in at the screen (the login window).
    LoginWindow,
    /// Someone is at the screen but their session's agent is not connected.
    NoAgent,
    /// The service stopped capturing (it is stopping).
    Stopped,
}

/// Captures: the current target and the latest attempts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureReport {
    pub state: CaptureState,
    /// The account whose agent captures (the capture target), if any.
    pub target_account: Option<String>,
    /// The last time the service asked for a capture.
    pub last_attempt_ms: Option<i64>,
    /// The last capture that was classified.
    pub last_success_ms: Option<i64>,
    /// Failed captures since the last success.
    pub consecutive_failures: u32,
    /// The most recent failure, even if a capture succeeded since.
    pub last_failure: Option<CaptureFailure>,
}

/// A failed capture.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureFailure {
    pub at_ms: i64,
    /// A short diagnostic (`permission denied: screen_recording`), never
    /// screen content. At most [`MAX_REASON_CHARS`] characters.
    pub reason: String,
}

/// Longest diagnostic string a report carries.
pub const MAX_REASON_CHARS: usize = 200;

/// `s`, cut to [`MAX_REASON_CHARS`] characters.
pub fn short_reason(s: &str) -> String {
    s.chars().take(MAX_REASON_CHARS).collect()
}

/// OS permissions, as the capture target's agent last reported them. All
/// `None` while there is no capture target or it has not reported yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PermissionsReport {
    /// The account they were reported for (permissions are per account on
    /// macOS).
    pub account: Option<String>,
    pub screen_recording: Option<WirePermissionState>,
    /// `None` also on platforms without such a permission.
    pub accessibility: Option<bool>,
}

/// Where a model or domain list in use came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSource {
    /// Installed with the package (or handed to the service by a test).
    #[default]
    Packaged,
    /// Installed from the update channel.
    UpdateChannel,
}

/// A model or domain list in use.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArtifactReport {
    pub name: String,
    /// Empty if the bundle has no version.
    pub version: String,
    pub source: ArtifactSource,
}

/// What rates captures.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionReport {
    /// The image model in use; `None` when frames are rated from context
    /// signals only.
    pub model: Option<ArtifactReport>,
    /// Why there is no image model (`image model (missing)`, `no image model
    /// installed`), when `model` is `None`.
    pub model_missing: Option<String>,
    /// The domain list in use, if any.
    pub domains: Option<ArtifactReport>,
    /// Why there is no domain list, when `domains` is `None`.
    pub domains_missing: Option<String>,
}

/// Client updates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatesReport {
    /// Updates are checked (the package ships the project's root of trust).
    pub enabled: bool,
    /// Why they are not, when `enabled` is false.
    pub disabled_reason: Option<String>,
    /// The channel the instance named at the last check.
    pub channel: Option<String>,
    pub last_check_ms: Option<i64>,
    /// What the last check found (`up to date`, `installing 0.2.0`, an
    /// error), at most [`MAX_REASON_CHARS`] characters.
    pub last_result: Option<String>,
    /// The last check failed (`last_result` says why).
    pub last_check_failed: bool,
}

/// Uploads, heartbeats and warnings since the service started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HealthReport {
    /// The state the last heartbeat told the instance.
    pub last_heartbeat: Option<DeviceState>,
    pub heartbeats_sent: u64,
    pub captures: u64,
    pub capture_failures: u64,
    pub flags: u64,
    pub tamper_events: u64,
    pub events_committed: u64,
    /// The newest event written.
    pub last_seq: Option<u64>,
    /// The newest event the instance acknowledged.
    pub acked_through: Option<u64>,
    pub reports_uploaded: u64,
    /// Daily reports that could not be sealed yet.
    pub reports_unsealed: u64,
    /// The instance served a recipient list the computer refused.
    pub manifest_warning: Option<String>,
    /// The instance's identity no longer matches the pin; uploads paused.
    pub identity_mismatch: bool,
    /// The last error the service recorded.
    pub last_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StatusReport {
        StatusReport {
            service_version: "0.1.0-beta.1".into(),
            pid: 42,
            started_ms: 1_000,
            updated_ms: 2_000,
            phase: ServicePhase::Running,
            sessions: vec![SessionReport {
                session: "uid:501".into(),
                account: "alex".into(),
                at_screen: true,
                agent_connected: true,
                agent_version: Some("0.1.0-beta.1".into()),
                capture_target: true,
                unmonitored: false,
            }],
            capture: CaptureReport {
                state: CaptureState::Active,
                target_account: Some("alex".into()),
                last_attempt_ms: Some(1_900),
                last_success_ms: Some(1_500),
                consecutive_failures: 1,
                last_failure: Some(CaptureFailure {
                    at_ms: 1_900,
                    reason: "permission denied: screen_recording".into(),
                }),
            },
            permissions: PermissionsReport {
                account: Some("alex".into()),
                screen_recording: Some(WirePermissionState::Denied),
                accessibility: Some(true),
            },
            detection: DetectionReport {
                model: Some(ArtifactReport {
                    name: "opennsfw".into(),
                    version: "1.0.0+int8".into(),
                    source: ArtifactSource::Packaged,
                }),
                model_missing: None,
                domains: None,
                domains_missing: Some("no domain list installed".into()),
            },
            updates: UpdatesReport {
                enabled: true,
                disabled_reason: None,
                channel: Some("stable".into()),
                last_check_ms: Some(1_200),
                last_result: Some("up to date".into()),
                last_check_failed: false,
            },
            health: HealthReport {
                last_heartbeat: Some(DeviceState::Active),
                acked_through: Some(3),
                ..HealthReport::default()
            },
            log_file: Some("/Library/Logs/Faro/faro-service.log".into()),
            ..StatusReport::default()
        }
    }

    #[test]
    fn round_trips_through_json_and_postcard() {
        let r = sample();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<StatusReport>(&json).unwrap(), r);
        let bytes = postcard::to_allocvec(&r).unwrap();
        assert_eq!(postcard::from_bytes::<StatusReport>(&bytes).unwrap(), r);
    }

    #[test]
    fn json_readers_tolerate_missing_and_unknown_fields() {
        let r: StatusReport =
            serde_json::from_str(r#"{"schema":2,"phase":"running","later":1}"#).unwrap();
        assert_eq!(r.phase, ServicePhase::Running);
        assert_eq!(r.capture, CaptureReport::default());
        let v = serde_json::to_value(sample()).unwrap();
        assert_eq!(v["capture"]["state"], "active");
        assert_eq!(v["detection"]["model"]["source"], "packaged");
    }

    #[test]
    fn freshness() {
        let r = sample();
        assert!(r.is_fresh(2_000 + 90_000));
        assert!(!r.is_fresh(2_000 + 90_001));
        let stopped = StatusReport {
            phase: ServicePhase::Stopped,
            ..sample()
        };
        assert!(!stopped.is_fresh(2_000));
    }

    #[test]
    fn reasons_are_capped() {
        assert_eq!(short_reason(&"é".repeat(500)).chars().count(), 200);
    }
}
