//! Key identifiers and the member-signed **endorsements** that make the key
//! directory trustworthy even if the instance is not (§5.2, §5.3).
//!
//! A device encrypts only to ally keys carrying a valid endorsement from the
//! member's signing key, which the device pinned at enrollment. The instance
//! stores and serves endorsements but cannot forge them.

use crate::encoding::{Canonical, EncPublicKey, Hash32, SignPublicKey, Signature};
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};

const TAG_ALLY_ENDORSEMENT: &str = "faro/ally-endorsement/v1";
const TAG_DEVICE_ENDORSEMENT: &str = "faro/device-endorsement/v1";
const TAG_MEMBER_SELF: &str = "faro/member-enc-key/v1";
const TAG_KEY_ID: &str = "faro/key-id/v1";
const TAG_SAFETY: &str = "faro/safety-code/v1";

/// Short, stable identifier for a public key: first 8 bytes of a tagged
/// BLAKE3 hash, lowercase hex (16 chars).
pub fn key_id(pubkey: &[u8]) -> String {
    let h = Hash32::of(&Canonical::new(TAG_KEY_ID).bytes(pubkey).finish());
    hex::encode(&h.0[..8])
}

/// "Member M, on instance I, approves ally A whose encryption key is K."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllyEndorsement {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub ally_id: UserId,
    pub ally_enc_pubkey: EncPublicKey,
    /// Unix ms when the member approved this key. Lets devices prefer the newest.
    pub endorsed_at_ms: i64,
}

impl AllyEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_ALLY_ENDORSEMENT)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.ally_id.as_str())
            .fixed(self.ally_enc_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .finish()
    }
}

/// "Member M, on instance I, owns device D whose signing key is K."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEndorsement {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub device_id: DeviceId,
    pub device_sign_pubkey: SignPublicKey,
    pub endorsed_at_ms: i64,
}

impl DeviceEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_DEVICE_ENDORSEMENT)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.device_id.as_str())
            .fixed(self.device_sign_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .finish()
    }
}

/// The member binding their own encryption key to their signing key, so
/// devices can encrypt a copy of every item to the member (transparency, §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberEncKeyBinding {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub member_enc_pubkey: EncPublicKey,
    pub endorsed_at_ms: i64,
}

impl MemberEncKeyBinding {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_MEMBER_SELF)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .fixed(self.member_enc_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .finish()
    }
}

/// Any endorsement plus the member's signature over its `signing_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    #[serde(flatten)]
    pub body: T,
    pub sig: Signature,
}

/// Human-comparable **safety code** for a pair of keys (§5.2 item 4).
///
/// Order-independent: both parties compute the same code. Twelve groups of
/// five digits, like Signal's safety numbers.
pub fn safety_code(a: &[u8], b: &[u8]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let h = Hash32::of(&Canonical::new(TAG_SAFETY).bytes(lo).bytes(hi).finish());
    // Expand to 60 digits with an XOF so every group has uniform-ish entropy.
    let mut xof = blake3::Hasher::new();
    xof.update(h.as_bytes());
    let mut out = [0u8; 60];
    xof.finalize_xof().fill(&mut out);
    let digits: Vec<u8> = out.iter().map(|b| b'0' + (b % 10)).collect();
    digits
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap().to_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_shape() {
        let id = key_id(&[1u8; 32]);
        assert_eq!(id.len(), 16);
        assert_ne!(id, key_id(&[2u8; 32]));
    }

    #[test]
    fn safety_code_symmetric() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = safety_code(&a, &b);
        assert_eq!(c, safety_code(&b, &a));
        assert_eq!(c.split(' ').count(), 12);
        assert_ne!(c, safety_code(&a, &[3u8; 32]));
    }

    #[test]
    fn endorsements_are_domain_separated() {
        let ally = AllyEndorsement {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            ally_id: UserId::new("usr_a"),
            ally_enc_pubkey: EncPublicKey([9; 32]),
            endorsed_at_ms: 1,
        };
        let dev = DeviceEndorsement {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            device_id: DeviceId::new("dev_a"),
            device_sign_pubkey: SignPublicKey([9; 32]),
            endorsed_at_ms: 1,
        };
        assert_ne!(ally.signing_bytes()[..20], dev.signing_bytes()[..20]);
    }

    #[test]
    fn signed_flattens() {
        let s = Signed {
            body: MemberEncKeyBinding {
                instance_id: InstanceId::new("inst_a"),
                member_id: UserId::new("usr_m"),
                member_enc_pubkey: EncPublicKey([1; 32]),
                endorsed_at_ms: 5,
            },
            sig: Signature([0; 64]),
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert!(v.get("member_id").is_some() && v.get("sig").is_some());
        let back: Signed<MemberEncKeyBinding> = serde_json::from_value(v).unwrap();
        assert_eq!(back, s);
    }
}
