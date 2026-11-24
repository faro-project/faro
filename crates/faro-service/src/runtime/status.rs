//! Observable service status, for the tray UI (later), `faro-service
//! status`, and tests driving the runtime in-process.

use faro_proto::api::DeviceState;
use faro_proto::keys::ManifestRef;
use std::sync::Arc;
use tokio::sync::watch;

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

/// A snapshot of what the service is doing. No content, only counters and
/// states.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceStatus {
    pub phase: Phase,
    pub agent_connected: bool,
    /// Someone is logged in at the console but no agent has been connected
    /// for longer than the service tolerates; a `capture_failing` tamper
    /// event was raised. Cleared when an agent connects.
    pub agent_missing: bool,
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
    /// The instance's identity no longer matches the pin; uploads paused.
    pub identity_mismatch: bool,
    pub last_error: Option<String>,
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
}
