//! HTTP API request/response types (ARCHITECTURE.md §4.5).

use crate::encoding::{Canonical, EncPublicKey, Hash32, SignPublicKey, Signature};
use crate::event::{EventKind, SignedEvent, Urgency};
use crate::ids::{DeviceId, InstanceId, UserId};
use crate::keys::{
    AllyEndorsement, DeviceEndorsement, MemberEncKeyBinding, RecipientManifest, Signed,
};
use serde::{Deserialize, Serialize};

/// Wire protocol version advertised in `/.well-known/faro`.
pub const PROTOCOL_VERSION: u16 = 1;

/// Path of the discovery document.
pub const WELL_KNOWN_PATH: &str = "/.well-known/faro";

/// `GET /.well-known/faro`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WellKnown {
    pub instance_id: InstanceId,
    pub name: String,
    /// Ed25519 instance identity key; pinned by clients at enrollment.
    pub identity_pubkey: SignPublicKey,
    pub server_version: String,
    pub min_client_version: String,
    pub protocol: u16,
}

/// Client platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Windows,
    Linux,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Macos => "macos",
            Platform::Windows => "windows",
            Platform::Linux => "linux",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "macos" => Some(Self::Macos),
            "windows" => Some(Self::Windows),
            "linux" => Some(Self::Linux),
            _ => None,
        }
    }
}

/// `POST /v1/devices/enroll`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// One-time code the member created in the web app (`XXXX-XXXX`).
    pub enroll_code: String,
    pub sign_pubkey: SignPublicKey,
    pub platform: Platform,
    pub device_name: String,
    pub client_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub instance_id: InstanceId,
    pub device_id: DeviceId,
    /// Bearer token; every request is *also* signed with the device key.
    pub device_token: String,
    pub member_id: UserId,
    /// The member's signing key. The device pins it and only trusts ally keys
    /// and its own endorsement if signed by this key.
    pub member_sign_pubkey: SignPublicKey,
}

/// `POST /v1/devices/{id}/endorse` (from the member's web/tray session).
pub type DeviceEndorseRequest = Signed<DeviceEndorsement>;

/// `GET /v1/members/{id}/keys` — everything a device needs to encrypt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberKeysResponse {
    pub member_id: UserId,
    pub member_sign_pubkey: SignPublicKey,
    pub member_enc_key: Signed<MemberEncKeyBinding>,
    /// Active allies only. Devices must verify every signature against the
    /// pinned member key and ignore entries that fail.
    pub allies: Vec<Signed<AllyEndorsement>>,
}

/// A member-signed [`RecipientManifest`]: the only thing devices use to pick
/// recipients.
///
/// * `GET /v1/members/{id}/recipient-manifest` (that member's device, or the
///   member): the **latest** manifest the instance holds.
/// * `PUT /v1/me/recipient-manifest` (member session): upload a new version.
///   The instance verifies the signature with the member's signing key and
///   requires `version` to be exactly one more than the stored version, and
///   every listed ally to have an active or just-approved link whose stored
///   key matches. Approving or removing an ally, and any key rotation, must
///   come with a new manifest.
///
/// See `docs/PROTOCOL.md` §5.1 for the device-side rules.
pub type SignedRecipientManifest = Signed<RecipientManifest>;

/// Header names for device request authentication.
pub mod auth_headers {
    pub const DEVICE: &str = "faro-device";
    pub const TIMESTAMP: &str = "faro-timestamp";
    pub const SIGNATURE: &str = "faro-signature";
}

/// Canonical bytes a device signs for each authenticated request. The
/// signature goes in the `faro-signature` header (base64url), alongside a
/// bearer device token. Servers reject timestamps more than 5 minutes off.
pub fn request_signing_bytes(
    method: &str,
    path_and_query: &str,
    device_id: &DeviceId,
    ts_ms: i64,
    body: &[u8],
) -> Vec<u8> {
    Canonical::new("faro/request/v1")
        .str(&method.to_ascii_uppercase())
        .str(path_and_query)
        .str(device_id.as_str())
        .i64(ts_ms)
        .fixed(Hash32::of(body).as_bytes())
        .finish()
}

/// Maximum allowed clock skew for signed requests.
pub const REQUEST_MAX_SKEW_MS: i64 = 5 * 60 * 1000;

/// `POST /v1/events:batch`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsBatchRequest {
    /// Must be in ascending `seq` order.
    pub events: Vec<SignedEvent>,
}

/// Per-event outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EventResult {
    Accepted {
        seq: u64,
    },
    /// Already stored with an identical header; safe to drop from the outbox.
    Duplicate {
        seq: u64,
    },
    Rejected {
        seq: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsBatchResponse {
    pub results: Vec<EventResult>,
    /// Highest contiguous seq the instance holds for this device; the device
    /// may prune its outbox up to here.
    pub acked_through: Option<u64>,
}

/// Device state as reported in heartbeats (plaintext metadata; §3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Active,
    Idle,
    Locked,
    Paused,
    /// Sent just before the OS sleeps, so silence afterwards is explained.
    Sleeping,
    /// Sent during an orderly shutdown.
    ShuttingDown,
}

impl DeviceState {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceState::Active => "active",
            DeviceState::Idle => "idle",
            DeviceState::Locked => "locked",
            DeviceState::Paused => "paused",
            DeviceState::Sleeping => "sleeping",
            DeviceState::ShuttingDown => "shutting_down",
        }
    }
}

/// `POST /v1/heartbeat` — signed liveness ping; not part of the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    pub instance_id: InstanceId,
    pub device_id: DeviceId,
    pub ts_ms: i64,
    pub mono_ms: u64,
    pub boot_id: String,
    pub state: DeviceState,
    /// The device's latest chain position, so the instance can tell when the
    /// device holds events it has not uploaded.
    pub last_seq: Option<u64>,
    pub last_hash: Option<Hash32>,
}

impl Heartbeat {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new("faro/heartbeat/v1")
            .str(self.instance_id.as_str())
            .str(self.device_id.as_str())
            .i64(self.ts_ms)
            .u64(self.mono_ms)
            .str(&self.boot_id)
            .str(self.state.as_str())
            .u64(self.last_seq.map(|s| s.wrapping_add(1)).unwrap_or(0))
            .fixed(self.last_hash.unwrap_or(Hash32::ZERO).as_bytes())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    pub heartbeat: Heartbeat,
    pub sig: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// Server wall clock, Unix ms — the device compares it with its own clock.
    pub server_time_ms: i64,
    /// Suggested next heartbeat interval.
    pub next_in_secs: u64,
    /// Latest contiguous seq held, so the device can resend anything missing.
    pub acked_through: Option<u64>,
}

/// Alerts the **instance** raises on its own (it can see only metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerAlertKind {
    MissedCheckin,
    ChainGap,
    InvalidSignature,
    ClockSkew,
    DeviceRemoved,
    AllyRemoved,
    /// The member approved a new ally (§5.4: "ally added or removed").
    AllyAdded,
    /// The member changed a setting held on the server (for example shorter
    /// retention), so allies are told just as for device settings changes.
    MemberSettingsChanged,
    /// The device's signed heartbeats claim events (`last_seq`) the instance
    /// has not received, for longer than the liveness grace period: it is
    /// alive but not uploading what it records. Tamper-class.
    UploadStalled,
    /// An instance admin disabled the member's account: they can no longer
    /// sign in (their devices keep reporting). Raised on the disabled user,
    /// who is told although disabled, and their allies. Tamper-class: it is
    /// never silent.
    AccountDisabled,
    /// An admin re-enabled the member's account.
    AccountEnabled,
    /// An admin disabled the account of one of the member's allies, who can
    /// no longer sign in to see the member's alerts. Raised on the member;
    /// the alert names the ally. Tamper-class, like removing an ally.
    AllyDisabled,
    /// An admin re-enabled the account of one of the member's allies.
    AllyEnabled,
}

impl ServerAlertKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ServerAlertKind::MissedCheckin => "missed_checkin",
            ServerAlertKind::ChainGap => "chain_gap",
            ServerAlertKind::InvalidSignature => "invalid_signature",
            ServerAlertKind::ClockSkew => "clock_skew",
            ServerAlertKind::DeviceRemoved => "device_removed",
            ServerAlertKind::AllyRemoved => "ally_removed",
            ServerAlertKind::AllyAdded => "ally_added",
            ServerAlertKind::MemberSettingsChanged => "member_settings_changed",
            ServerAlertKind::UploadStalled => "upload_stalled",
            ServerAlertKind::AccountDisabled => "account_disabled",
            ServerAlertKind::AccountEnabled => "account_enabled",
            ServerAlertKind::AllyDisabled => "ally_disabled",
            ServerAlertKind::AllyEnabled => "ally_enabled",
        }
    }

    pub const ALL: [ServerAlertKind; 13] = [
        ServerAlertKind::MissedCheckin,
        ServerAlertKind::ChainGap,
        ServerAlertKind::InvalidSignature,
        ServerAlertKind::ClockSkew,
        ServerAlertKind::DeviceRemoved,
        ServerAlertKind::AllyRemoved,
        ServerAlertKind::AllyAdded,
        ServerAlertKind::MemberSettingsChanged,
        ServerAlertKind::UploadStalled,
        ServerAlertKind::AccountDisabled,
        ServerAlertKind::AccountEnabled,
        ServerAlertKind::AllyDisabled,
        ServerAlertKind::AllyEnabled,
    ];

    /// Inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn urgency(self) -> Urgency {
        match self {
            ServerAlertKind::MissedCheckin
            | ServerAlertKind::ChainGap
            | ServerAlertKind::InvalidSignature
            | ServerAlertKind::ClockSkew
            | ServerAlertKind::DeviceRemoved
            | ServerAlertKind::UploadStalled
            | ServerAlertKind::AccountDisabled
            | ServerAlertKind::AllyDisabled => Urgency::Urgent,
            ServerAlertKind::AllyRemoved
            | ServerAlertKind::AllyAdded
            | ServerAlertKind::MemberSettingsChanged
            | ServerAlertKind::AccountEnabled
            | ServerAlertKind::AllyEnabled => Urgency::Normal,
        }
    }
}

/// One row in `GET /v1/ally/feed`: metadata only; content is fetched as a blob
/// and decrypted in the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeedItem {
    Event {
        member_id: UserId,
        device_id: DeviceId,
        seq: u64,
        ts_ms: i64,
        kind: EventKind,
        urgency: Urgency,
        blob_id: Option<String>,
    },
    Report {
        member_id: UserId,
        device_id: DeviceId,
        report_id: String,
        period_start_ms: i64,
        period_end_ms: i64,
        blob_id: String,
    },
    Alert {
        member_id: UserId,
        device_id: Option<DeviceId>,
        alert_id: String,
        kind: ServerAlertKind,
        urgency: Urgency,
        ts_ms: i64,
        detail: Option<String>,
    },
}

/// Uniform JSON error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

/// An ally's public encryption key as uploaded at invite acceptance, together
/// with their passphrase-wrapped private key (opaque to the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllyKeyUpload {
    pub enc_pubkey: EncPublicKey,
    /// Serialized `faro_crypto::WrappedSecret`, opaque to the server.
    pub wrapped_privkey: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_bytes_bind_everything() {
        let d = DeviceId::new("dev_a");
        let a = request_signing_bytes("post", "/v1/heartbeat", &d, 1, b"{}");
        assert_eq!(
            a,
            request_signing_bytes("POST", "/v1/heartbeat", &d, 1, b"{}")
        );
        assert_ne!(
            a,
            request_signing_bytes("POST", "/v1/heartbeat", &d, 2, b"{}")
        );
        assert_ne!(
            a,
            request_signing_bytes("POST", "/v1/heartbeat", &d, 1, b"{ }")
        );
        assert_ne!(
            a,
            request_signing_bytes("POST", "/v1/events:batch", &d, 1, b"{}")
        );
    }

    #[test]
    fn server_alert_kinds_roundtrip() {
        for k in ServerAlertKind::ALL {
            assert_eq!(ServerAlertKind::parse(k.as_str()), Some(k));
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
        assert_eq!(ServerAlertKind::parse("nope"), None);
    }

    #[test]
    fn server_alert_urgency() {
        assert_eq!(ServerAlertKind::ChainGap.urgency(), Urgency::Urgent);
        assert_eq!(ServerAlertKind::MissedCheckin.urgency(), Urgency::Urgent);
    }
}
