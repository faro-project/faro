//! The signed, hash-chained event model (ARCHITECTURE.md §3.6).
//!
//! An event is a plaintext **header** (seen by the instance) plus an optional
//! encrypted **body** (seen only by the member and their allies).
//!
//! * The header is signed by the device's Ed25519 key over
//!   [`EventHeader::signing_bytes`].
//! * The header commits to the body via `body_hash = BLAKE3(nonce || ciphertext)`,
//!   so the instance can verify the hash chain from headers alone, even after
//!   body blobs have expired under retention.
//! * `prev_hash` is the [`EventHeader::chain_hash`] of the previous event from
//!   the same device; the first event uses [`genesis_hash`].

use crate::encoding::{b64, Canonical, Hash32, Nonce24, Signature};
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Current header format version.
pub const EVENT_HEADER_VERSION: u16 = 1;

const TAG_HEADER: &str = "faro/event-header/v1";
const TAG_GENESIS: &str = "faro/genesis/v1";
const TAG_BODY_AAD: &str = "faro/event-body/v1";

/// What an event is about. Visible to the instance (metadata, §5.3).
///
/// Liveness heartbeats are *not* chain events; they use the dedicated
/// [`crate::api::Heartbeat`] message so that 288 pings/day do not bloat the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A periodic capture summary (clean or low results); normally aggregated
    /// into the daily report instead of being uploaded one by one.
    Capture,
    /// A capture rated `medium` or `high` (or `low`, if the member opted in).
    Flag,
    /// A tamper signal (permission revoked, integrity failure, clock skew, ...).
    Tamper,
    SettingsChange,
    AgentRestarted,
    Paused,
    Resumed,
    /// Uninstall, or the device being moved to a different instance.
    Goodbye,
    Boot,
    Shutdown,
}

impl EventKind {
    pub const ALL: [EventKind; 10] = [
        EventKind::Capture,
        EventKind::Flag,
        EventKind::Tamper,
        EventKind::SettingsChange,
        EventKind::AgentRestarted,
        EventKind::Paused,
        EventKind::Resumed,
        EventKind::Goodbye,
        EventKind::Boot,
        EventKind::Shutdown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Capture => "capture",
            EventKind::Flag => "flag",
            EventKind::Tamper => "tamper",
            EventKind::SettingsChange => "settings_change",
            EventKind::AgentRestarted => "agent_restarted",
            EventKind::Paused => "paused",
            EventKind::Resumed => "resumed",
            EventKind::Goodbye => "goodbye",
            EventKind::Boot => "boot",
            EventKind::Shutdown => "shutdown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The lowest urgency the instance will accept for this kind.
    ///
    /// The member controls the device, so a modified client could sign a
    /// tamper event as `none`. The instance therefore **raises** the urgency of
    /// incoming events to at least this floor (§3.7, §5.4): tamper and
    /// uninstall are always urgent; settings changes and pauses always reach
    /// allies at least in the digest.
    pub fn min_urgency(self) -> Urgency {
        match self {
            EventKind::Tamper | EventKind::Goodbye => Urgency::Urgent,
            EventKind::SettingsChange | EventKind::Paused | EventKind::Resumed => Urgency::Normal,
            EventKind::Capture
            | EventKind::Flag
            | EventKind::AgentRestarted
            | EventKind::Boot
            | EventKind::Shutdown => Urgency::None,
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Plaintext, device-signed notification urgency (§5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Urgency {
    /// Only in the daily report.
    None,
    /// Bundled into the next hourly digest.
    Normal,
    /// Immediate email + Web Push.
    Urgent,
}

impl Urgency {
    pub fn as_str(self) -> &'static str {
        match self {
            Urgency::None => "none",
            Urgency::Normal => "normal",
            Urgency::Urgent => "urgent",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Urgency::None),
            "normal" => Some(Urgency::Normal),
            "urgent" => Some(Urgency::Urgent),
            _ => None,
        }
    }
}

impl fmt::Display for Urgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The plaintext event header. Everything here is visible to the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeader {
    pub v: u16,
    pub instance_id: InstanceId,
    pub device_id: DeviceId,
    /// Strictly increasing per device, starting at 0.
    pub seq: u64,
    pub prev_hash: Hash32,
    /// Wall-clock time, Unix milliseconds (UTC).
    pub ts_ms: i64,
    /// Monotonic milliseconds since boot.
    pub mono_ms: u64,
    /// Opaque per-boot identifier; `mono_ms` is only comparable within one boot.
    pub boot_id: String,
    pub kind: EventKind,
    pub urgency: Urgency,
    /// BLAKE3(nonce || ciphertext) of the encrypted body, or all-zero if none.
    pub body_hash: Hash32,
    /// Ciphertext length in bytes (0 if no body).
    pub body_len: u64,
}

impl EventHeader {
    /// Canonical bytes covered by the device signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_HEADER)
            .u16(self.v)
            .str(self.instance_id.as_str())
            .str(self.device_id.as_str())
            .u64(self.seq)
            .fixed(self.prev_hash.as_bytes())
            .i64(self.ts_ms)
            .u64(self.mono_ms)
            .str(&self.boot_id)
            .str(self.kind.as_str())
            .str(self.urgency.as_str())
            .fixed(self.body_hash.as_bytes())
            .u64(self.body_len)
            .finish()
    }

    /// The hash the *next* event must carry as `prev_hash`.
    pub fn chain_hash(&self) -> Hash32 {
        Hash32::of(&self.signing_bytes())
    }

    /// Additional authenticated data for this event's body ciphertext. Binds the
    /// ciphertext to its device and sequence number so the instance cannot
    /// swap bodies between events.
    pub fn body_aad(&self) -> Vec<u8> {
        body_aad(&self.instance_id, &self.device_id, self.seq)
    }
}

/// The `prev_hash` of a device's first event (`seq == 0`).
pub fn genesis_hash(instance_id: &InstanceId, device_id: &DeviceId) -> Hash32 {
    Hash32::of(
        &Canonical::new(TAG_GENESIS)
            .str(instance_id.as_str())
            .str(device_id.as_str())
            .finish(),
    )
}

/// AAD for an event body. See [`EventHeader::body_aad`].
pub fn body_aad(instance_id: &InstanceId, device_id: &DeviceId, seq: u64) -> Vec<u8> {
    Canonical::new(TAG_BODY_AAD)
        .str(instance_id.as_str())
        .str(device_id.as_str())
        .u64(seq)
        .finish()
}

/// A per-recipient wrapped content key: `crypto_box_seal(CK, recipient_pubkey)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub recipient: UserId,
    /// [`crate::keys::key_id`] of the recipient's encryption public key, so a
    /// recipient with several historical keys knows which one to try.
    pub key_id: String,
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
}

/// Content encrypted with XChaCha20-Poly1305 under a random per-item key,
/// plus one [`Envelope`] per recipient (each active ally **and** the member).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItem {
    /// Always `"xchacha20poly1305"` in v1.
    pub alg: String,
    pub nonce: Nonce24,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    pub envelopes: Vec<Envelope>,
}

impl EncryptedItem {
    pub const ALG: &'static str = "xchacha20poly1305";

    /// `BLAKE3(nonce || ciphertext)`; what headers commit to as `body_hash`.
    pub fn body_hash(&self) -> Hash32 {
        let mut h = blake3::Hasher::new();
        h.update(self.nonce.as_bytes());
        h.update(&self.ciphertext);
        Hash32(*h.finalize().as_bytes())
    }
}

/// A header, the device's signature over it, and the optional encrypted body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    pub header: EventHeader,
    pub sig: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<EncryptedItem>,
}

/// Structural problems with an event that need no keys to detect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventShapeError {
    #[error("unsupported header version {0}")]
    Version(u16),
    #[error("body_hash/body_len do not match the attached body")]
    BodyMismatch,
    #[error("header declares a body but none is attached")]
    MissingBody,
    #[error("unsupported body algorithm {0:?}")]
    Alg(String),
}

impl SignedEvent {
    /// Check the header/body commitments. Does **not** verify the signature or
    /// the chain; see `faro-crypto` and `faro-core::chain` for that.
    ///
    /// `body_present_expected` should be `false` when the body was legitimately
    /// stripped (e.g. a header-only re-upload after blob retention).
    pub fn check_shape(&self, body_present_expected: bool) -> Result<(), EventShapeError> {
        if self.header.v != EVENT_HEADER_VERSION {
            return Err(EventShapeError::Version(self.header.v));
        }
        match &self.body {
            Some(b) => {
                if b.alg != EncryptedItem::ALG {
                    return Err(EventShapeError::Alg(b.alg.clone()));
                }
                if b.body_hash() != self.header.body_hash
                    || b.ciphertext.len() as u64 != self.header.body_len
                {
                    return Err(EventShapeError::BodyMismatch);
                }
            }
            None => {
                let declares_body =
                    self.header.body_len != 0 || self.header.body_hash != Hash32::ZERO;
                if declares_body && body_present_expected {
                    return Err(EventShapeError::MissingBody);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> EventHeader {
        let inst = InstanceId::new("inst_test");
        let dev = DeviceId::new("dev_test");
        EventHeader {
            v: EVENT_HEADER_VERSION,
            prev_hash: genesis_hash(&inst, &dev),
            instance_id: inst,
            device_id: dev,
            seq: 0,
            ts_ms: 1_795_000_000_000,
            mono_ms: 1234,
            boot_id: "boot".into(),
            kind: EventKind::Boot,
            urgency: Urgency::None,
            body_hash: Hash32::ZERO,
            body_len: 0,
        }
    }

    #[test]
    fn kinds_roundtrip() {
        for k in EventKind::ALL {
            assert_eq!(EventKind::parse(k.as_str()), Some(k));
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
        }
    }

    #[test]
    fn every_field_changes_signing_bytes() {
        let base = header();
        let b = base.signing_bytes();
        let mut variants = Vec::new();
        let mut h = base.clone();
        h.seq = 1;
        variants.push(h);
        let mut h = base.clone();
        h.urgency = Urgency::Urgent;
        variants.push(h);
        let mut h = base.clone();
        h.kind = EventKind::Tamper;
        variants.push(h);
        let mut h = base.clone();
        h.ts_ms += 1;
        variants.push(h);
        let mut h = base.clone();
        h.mono_ms += 1;
        variants.push(h);
        let mut h = base.clone();
        h.body_len = 5;
        variants.push(h);
        let mut h = base.clone();
        h.body_hash = Hash32::of(b"x");
        variants.push(h);
        let mut h = base.clone();
        h.prev_hash = Hash32::ZERO;
        variants.push(h);
        let mut h = base.clone();
        h.boot_id = "boot2".into();
        variants.push(h);
        let mut h = base.clone();
        h.device_id = DeviceId::new("dev_other");
        variants.push(h);
        let mut h = base.clone();
        h.instance_id = InstanceId::new("inst_other");
        variants.push(h);
        for v in variants {
            assert_ne!(v.signing_bytes(), b, "{v:?}");
        }
    }

    #[test]
    fn genesis_is_device_specific() {
        let i = InstanceId::new("inst_a");
        assert_ne!(
            genesis_hash(&i, &DeviceId::new("dev_a")),
            genesis_hash(&i, &DeviceId::new("dev_b"))
        );
    }

    #[test]
    fn urgency_floor() {
        assert_eq!(EventKind::Tamper.min_urgency(), Urgency::Urgent);
        assert_eq!(EventKind::Goodbye.min_urgency(), Urgency::Urgent);
        assert_eq!(EventKind::SettingsChange.min_urgency(), Urgency::Normal);
        assert!(Urgency::Urgent > Urgency::Normal && Urgency::Normal > Urgency::None);
    }

    #[test]
    fn header_json_roundtrip() {
        let h = header();
        let j = serde_json::to_string(&h).unwrap();
        let back: EventHeader = serde_json::from_str(&j).unwrap();
        assert_eq!(h, back);
        assert_eq!(h.chain_hash(), back.chain_hash());
    }
}
