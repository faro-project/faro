//! The records and enums Swift sees, and their mapping to `faro-proto`
//! (PROTOCOL.md §3, including the iPhone signals and bodies).

use faro_proto::api::{DeviceState, Platform};
use faro_proto::body::{BlockedHost, EventBody, FilterOffCause, SettingChange, TamperSignal};
use std::collections::BTreeMap;

/// The platform this crate enrolls as.
pub const PLATFORM: Platform = Platform::Ios;

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

/// An active tamper signal: an urgent `tamper` event, tamper-class on the
/// instance (docs/IOS.md §10.2).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Tamper {
    /// Screen Time authorization is no longer approved: the shields and
    /// `denyAppRemoval` are gone, and Faro can be deleted.
    ScreenTimeRevoked,
    /// The DNS filter is off.
    FilterOff { cause: FilterCause },
    /// Faro's ManagedSettings store was found cleared or changed while
    /// authorization still stands.
    SettingsCleared,
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

/// Why the DNS filter is off, as far as the phone can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FilterCause {
    /// The VPN was switched off.
    VpnDisconnected,
    /// Connect On Demand was turned off.
    OnDemandOff,
    /// Another VPN took over.
    OtherVpn,
    /// The Faro VPN profile was deleted.
    ProfileRemoved,
    /// The tunnel stopped reporting and nothing says why.
    Unknown,
}

impl From<FilterCause> for FilterOffCause {
    fn from(c: FilterCause) -> Self {
        match c {
            FilterCause::VpnDisconnected => FilterOffCause::VpnDisconnected,
            FilterCause::OnDemandOff => FilterOffCause::OnDemandOff,
            FilterCause::OtherVpn => FilterOffCause::OtherVpn,
            FilterCause::ProfileRemoved => FilterOffCause::ProfileRemoved,
            FilterCause::Unknown => FilterOffCause::Unknown,
        }
    }
}

impl From<Tamper> for TamperSignal {
    fn from(t: Tamper) -> Self {
        match t {
            Tamper::ScreenTimeRevoked => TamperSignal::ScreenTimeRevoked,
            Tamper::FilterOff { cause } => TamperSignal::FilterOff {
                cause: cause.into(),
            },
            Tamper::SettingsCleared => TamperSignal::SettingsCleared,
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
    /// Connections to DNS-over-HTTPS resolvers were dropped.
    DohDropped,
    /// Another VPN is connected.
    OtherVpn,
    /// The phone looks jailbroken.
    JailbreakSuspected,
    VpnActive,
    VirtualMachine,
    RemoteDesktop,
    BrowserWithoutExtension {
        browser: String,
    },
}

impl From<Context> for TamperSignal {
    fn from(c: Context) -> Self {
        match c {
            Context::DohDropped => TamperSignal::DohDropped,
            Context::OtherVpn => TamperSignal::OtherVpn,
            Context::JailbreakSuspected => TamperSignal::JailbreakSuspected,
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

/// A loosening that waits before it applies (docs/IOS.md §9), carried by
/// the `settings_change` that announces it, applies it or cancels it. All
/// times are Unix ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct PendingLoosening {
    /// When the member asked for it.
    pub requested_at_ms: Option<i64>,
    /// When it applies.
    pub takes_effect_at_ms: Option<i64>,
    /// When the member cancelled it, if they did.
    pub cancelled_at_ms: Option<i64>,
    /// The delay in force, in seconds.
    pub delay_secs: Option<u64>,
}

/// Bounds on a summary.
pub const MAX_SUMMARY_HOSTS: usize = 200;
pub const MAX_CATEGORY: usize = 32;
pub const MAX_HOST: usize = 253;

/// One host in a [`BlockedSummaryRecord`]: the host only, never a path or
/// a query.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BlockedHostRecord {
    pub host: String,
    pub category: String,
    pub count: u32,
}

/// Blocked DNS lookups in one bucket (`blocked_summary`, docs/IOS.md §11).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct BlockedSummaryRecord {
    /// Start of the bucket, Unix ms.
    pub bucket_start_ms: i64,
    pub bucket_secs: u64,
    /// Blocked lookups per category.
    pub by_category: std::collections::HashMap<String, u32>,
    /// The hosts listed (adult and gambling only).
    pub hosts: Vec<BlockedHostRecord>,
    /// Blocked lookups of hosts not listed.
    pub other_hosts: u32,
}

/// How often a Screen Time shield was shown or closed in one bucket
/// (`shield_summary`). Counts only, never app names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct ShieldSummaryRecord {
    /// Start of the bucket, Unix ms.
    pub bucket_start_ms: i64,
    pub bucket_secs: u64,
    pub shown: u32,
    pub closed: u32,
}

fn category_ok(c: &str) -> bool {
    (1..=MAX_CATEGORY).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A DNS host name as the filter matched it: lowercase letters, digits,
/// `-` and `.`, at most 253 bytes. Anything that could carry a path, a
/// query or a port is refused.
fn host_ok(h: &str) -> bool {
    (1..=MAX_HOST).contains(&h.len())
        && !h.starts_with('.')
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

impl BlockedSummaryRecord {
    pub(crate) fn into_body(self) -> Result<EventBody, String> {
        if self.bucket_secs == 0 {
            return Err("a bucket lasts at least a second".into());
        }
        if self.hosts.len() > MAX_SUMMARY_HOSTS || self.by_category.len() > MAX_SUMMARY_HOSTS {
            return Err(format!(
                "a summary lists at most {MAX_SUMMARY_HOSTS} hosts and categories"
            ));
        }
        let mut by_category = BTreeMap::new();
        for (c, n) in self.by_category {
            if !category_ok(&c) {
                return Err(format!("{c:?} is not a category name"));
            }
            by_category.insert(c, n);
        }
        let mut hosts = Vec::with_capacity(self.hosts.len());
        for h in self.hosts {
            if !host_ok(&h.host) {
                return Err("a listed host is a DNS name only (lowercase, no path or port)".into());
            }
            if !category_ok(&h.category) {
                return Err(format!("{:?} is not a category name", h.category));
            }
            hosts.push(BlockedHost {
                host: h.host,
                category: h.category,
                count: h.count,
            });
        }
        Ok(EventBody::BlockedSummary {
            bucket_start: self.bucket_start_ms,
            bucket_secs: self.bucket_secs,
            by_category,
            hosts,
            other_hosts: self.other_hosts,
        })
    }
}

impl ShieldSummaryRecord {
    pub(crate) fn into_body(self) -> Result<EventBody, String> {
        if self.bucket_secs == 0 {
            return Err("a bucket lasts at least a second".into());
        }
        Ok(EventBody::ShieldSummary {
            bucket_start: self.bucket_start_ms,
            bucket_secs: self.bucket_secs,
            shown: self.shown,
            closed: self.closed,
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
