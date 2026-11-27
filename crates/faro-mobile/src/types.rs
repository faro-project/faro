//! The records and enums Swift sees, and their mapping to `faro-proto`.
//!
//! These use only the protocol's existing types. The iPhone tamper signals
//! (`screen_time_revoked`, `filter_off`, `settings_cleared`), the iOS
//! context items and the `ios` platform come from the protocol issue
//! (#140); whichever of the two lands second adds them here.

use faro_proto::api::{DeviceState, Platform};
use faro_proto::body::{SettingChange, TamperSignal};

/// The platform this crate enrolls as.
///
/// `Platform::Ios` comes with the protocol issue (#140). Until then an
/// iPhone enrolls as `macos`, the nearest platform the instance accepts
/// today. Nothing on the device depends on it.
pub const PLATFORM: Platform = Platform::Macos;

/// The platform string for update selection (`faro_update::Selection`).
/// Data bundles are listed for platform `any`, which matches it.
pub const UPDATE_PLATFORM: &str = "ios";

/// What the member is shown before enrolling.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct InstancePreview {
    /// The instance's base URL.
    pub url: String,
    /// The instance's name, sanitized for display.
    pub name: String,
    pub instance_id: String,
    /// The instance identity key's fingerprint. Pass it back to
    /// [`crate::FaroCore::enroll`], which refuses if the instance answers
    /// with another key by then.
    pub identity_fingerprint: String,
    /// Whether the link names the member's key (`m`), so enrollment checks
    /// it. Without it, show [`EnrolledDevice::member_fingerprint`] for the
    /// member to compare with their web app.
    pub link_names_member_key: bool,
}

/// What enrollment established.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrolledDevice {
    pub device_id: String,
    /// The device key's fingerprint, which the member's web app shows for
    /// the pending device: the member compares the two before approving.
    pub device_fingerprint: String,
    /// The pinned member key's fingerprint (the safety code).
    pub member_fingerprint: String,
    pub instance_name: String,
}

/// Where approval stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Approval {
    /// The member hasn't approved this device yet.
    Pending,
    /// Approved: the endorsement verified against the pinned member key
    /// and the recipient list is bootstrapped. Events can be recorded.
    Approved,
}

/// The device's state, for the status screen.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CoreStatus {
    pub enrolled: bool,
    pub approved: bool,
    pub instance_name: Option<String>,
    pub instance_url: Option<String>,
    pub device_id: Option<String>,
    pub member_fingerprint: Option<String>,
    /// The next event's `seq`: events recorded so far on this enrollment.
    pub next_seq: u64,
    /// Events not yet acknowledged by the instance.
    pub pending_events: u64,
    /// The recipient manifest version events are sealed to.
    pub manifest_version: Option<u64>,
}

/// An active tamper signal (an urgent `tamper` event), from the signals
/// the protocol has today.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Tamper {
    /// A permission Faro needs is off. `never_granted`: it was never seen
    /// granted on this enrollment, rather than turned off.
    PermissionRevoked {
        permission: String,
        never_granted: bool,
    },
    /// A Faro component or data file failed its integrity check. A fixed
    /// string, never anything the member typed.
    IntegrityFailure { component: String },
    /// The wall clock moved against the monotonic clock.
    ClockManipulation {
        wall_delta_ms: i64,
        mono_delta_ms: i64,
    },
}

impl From<Tamper> for TamperSignal {
    fn from(t: Tamper) -> Self {
        match t {
            Tamper::PermissionRevoked {
                permission,
                never_granted,
            } => TamperSignal::PermissionRevoked {
                permission,
                never_granted,
            },
            Tamper::IntegrityFailure { component } => TamperSignal::IntegrityFailure { component },
            Tamper::ClockManipulation {
                wall_delta_ms,
                mono_delta_ms,
            } => TamperSignal::ClockManipulation {
                wall_delta_ms,
                mono_delta_ms,
            },
        }
    }
}

/// A context signal: listed in the daily report, never an alert.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Context {
    VpnActive,
    VirtualMachine,
    RemoteDesktop,
    BrowserWithoutExtension { browser: String },
}

impl From<Context> for TamperSignal {
    fn from(c: Context) -> Self {
        match c {
            Context::VpnActive => TamperSignal::VpnActive,
            Context::VirtualMachine => TamperSignal::VirtualMachine,
            Context::RemoteDesktop => TamperSignal::RemoteDesktop,
            Context::BrowserWithoutExtension { browser } => {
                TamperSignal::BrowserWithoutExtension { browser }
            }
        }
    }
}

/// One setting change that allies are told about (`settings_change`).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SettingChangeRecord {
    pub key: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Bounds on what a settings change may carry.
pub const MAX_SETTING_CHANGES: usize = 32;
pub const MAX_SETTING_KEY: usize = 64;
pub const MAX_SETTING_VALUE: usize = 512;

impl SettingChangeRecord {
    pub(crate) fn into_proto(self) -> Result<SettingChange, String> {
        let key_ok = (1..=MAX_SETTING_KEY).contains(&self.key.len())
            && self
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if !key_ok {
            return Err(format!(
                "a setting key is 1-{MAX_SETTING_KEY} letters, digits, '_', '.' or '-'"
            ));
        }
        for v in [&self.old_value, &self.new_value].into_iter().flatten() {
            if v.len() > MAX_SETTING_VALUE || v.chars().any(char::is_control) {
                return Err(format!(
                    "a setting value is at most {MAX_SETTING_VALUE} bytes, without control characters"
                ));
            }
        }
        Ok(SettingChange {
            key: self.key,
            old: self.old_value,
            new: self.new_value,
        })
    }
}

/// What a heartbeat reports (PROTOCOL.md §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HeartbeatState {
    Active,
    Idle,
    Locked,
    Paused,
    Sleeping,
    ShuttingDown,
}

impl From<HeartbeatState> for DeviceState {
    fn from(s: HeartbeatState) -> Self {
        match s {
            HeartbeatState::Active => DeviceState::Active,
            HeartbeatState::Idle => DeviceState::Idle,
            HeartbeatState::Locked => DeviceState::Locked,
            HeartbeatState::Paused => DeviceState::Paused,
            HeartbeatState::Sleeping => DeviceState::Sleeping,
            HeartbeatState::ShuttingDown => DeviceState::ShuttingDown,
        }
    }
}

/// The instance's answer to a heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct HeartbeatAnswer {
    /// The instance's clock, Unix ms.
    pub server_time_ms: i64,
    /// When the instance suggests the next heartbeat.
    pub next_in_secs: u64,
    /// The highest `seq` the instance holds contiguously.
    pub acked_through: Option<u64>,
}

/// What [`crate::FaroCore::upload_pending`] did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct UploadOutcome {
    /// The highest `seq` the instance acknowledged, if any.
    pub acked_through: Option<u64>,
    /// Events still waiting.
    pub pending_events: u64,
    pub reports_uploaded: u32,
    /// The recipient manifest version events are now sealed to.
    pub manifest_version: Option<u64>,
    /// What went wrong without stopping the upload: the instance's newest
    /// recipient manifest refused (a rollback, equivocation or a bad
    /// signature; the device keeps the one it has), an acknowledgement
    /// beyond the local chain, a report the instance will never accept.
    pub warnings: Vec<String>,
}

/// The domain bundle in use.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DomainsInfo {
    pub version: String,
    pub domains: u64,
    /// The checked manifest; `faro_detect::load_domains` reads the bundle
    /// next to it.
    pub manifest_path: String,
}

/// What a domain bundle update did.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DomainsUpdate {
    /// The instance has no update channel.
    Unavailable,
    /// Nothing newer is listed.
    UpToDate,
    /// A newer bundle was verified, checked and installed.
    Installed { info: DomainsInfo },
    /// A newer bundle is signed but failed the checks: it is recorded and
    /// never downloaded again.
    Rejected { version: String, reason: String },
}
