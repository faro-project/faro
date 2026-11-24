//! Key identifiers and the member-signed **endorsements** that make the key
//! directory trustworthy even if the instance is not (§5.2, §5.3).
//!
//! A device encrypts only to keys the member signed with the signing key the
//! device pinned at enrollment. The instance stores and serves these
//! documents but cannot forge them.
//!
//! Individual [`AllyEndorsement`]s record that a member approved an ally, but
//! they cannot express **removal**: a removed ally's old endorsement still
//! verifies, so an instance that kept serving it could keep that ally reading.
//! The authority for "who may a device encrypt to right now" is therefore the
//! [`RecipientManifest`]: a single member-signed, **versioned** list that
//! devices only ever move forward through (see `docs/PROTOCOL.md` §5.1).

use crate::encoding::{Canonical, EncPublicKey, Hash32, SignPublicKey, Signature};
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};

const TAG_RECIPIENT_MANIFEST: &str = "faro/recipient-manifest/v1";
const TAG_ALLY_ENDORSEMENT: &str = "faro/ally-endorsement/v1";
const TAG_DEVICE_ENDORSEMENT: &str = "faro/device-endorsement/v2";
const TAG_MEMBER_SELF: &str = "faro/member-enc-key/v1";
const TAG_KEY_ID: &str = "faro/key-id/v1";
const TAG_SAFETY: &str = "faro/safety-code/v1";

/// Short, stable identifier for a public key: first 8 bytes of a tagged
/// BLAKE3 hash, lowercase hex (16 chars).
pub fn key_id(pubkey: &[u8]) -> String {
    let h = Hash32::of(&Canonical::new(TAG_KEY_ID).bytes(pubkey).finish());
    hex::encode(&h.0[..8])
}

/// Upper bound on allies in one manifest. Keeps manifests (and the work a
/// device does per item, one sealed box per recipient) bounded even if the
/// instance serves a hostile document.
pub const MAX_MANIFEST_ALLIES: usize = 32;

/// One ally entry in a [`RecipientManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAlly {
    pub ally_id: UserId,
    pub enc_pubkey: EncPublicKey,
}

/// "As of version N, member M on instance I wants devices to encrypt to
/// exactly: their own key K_m, and these allies with these keys."
///
/// * Versions start at 1 and strictly increase per member. Every change
///   (approve, remove, ally key rotation, member key rotation) is a new
///   version signed by the member.
/// * Devices persist the highest `(version, hash)` they accepted and refuse
///   anything older (**rollback**: re-serving a pre-removal manifest) or a
///   different document at the same version (**equivocation**).
/// * Allies are sorted strictly ascending by `ally_id`, so one logical set has
///   exactly one encoding, and duplicates are impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientManifest {
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub version: u64,
    pub issued_at_ms: i64,
    pub member_enc_pubkey: EncPublicKey,
    pub allies: Vec<ManifestAlly>,
}

/// Structural problems with a manifest that need no keys to detect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest version must be at least 1")]
    ZeroVersion,
    #[error("manifest lists {0} allies, more than the maximum of {MAX_MANIFEST_ALLIES}")]
    TooManyAllies(usize),
    #[error("manifest allies are not sorted strictly by ally_id (unsorted or duplicate: {0})")]
    NotSorted(UserId),
    #[error("manifest lists the member as their own ally")]
    MemberIsAlly,
    #[error("malformed id in manifest: {0}")]
    MalformedId(String),
}

impl RecipientManifest {
    /// Check the structural rules from the type docs. Signature checks are
    /// the caller's job (`faro_crypto::verify_signed`).
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version == 0 {
            return Err(ManifestError::ZeroVersion);
        }
        if self.allies.len() > MAX_MANIFEST_ALLIES {
            return Err(ManifestError::TooManyAllies(self.allies.len()));
        }
        if !self.instance_id.is_well_formed() {
            return Err(ManifestError::MalformedId(self.instance_id.to_string()));
        }
        if !self.member_id.is_well_formed() {
            return Err(ManifestError::MalformedId(self.member_id.to_string()));
        }
        for (i, a) in self.allies.iter().enumerate() {
            if !a.ally_id.is_well_formed() {
                return Err(ManifestError::MalformedId(a.ally_id.to_string()));
            }
            if a.ally_id == self.member_id {
                return Err(ManifestError::MemberIsAlly);
            }
            if i > 0 && self.allies[i - 1].ally_id >= a.ally_id {
                return Err(ManifestError::NotSorted(a.ally_id.clone()));
            }
        }
        Ok(())
    }

    /// Canonical bytes the member signs. Callers must [`validate`] first;
    /// the encoding itself is total so it never panics on a bounded manifest.
    ///
    /// [`validate`]: Self::validate
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canonical::new(TAG_RECIPIENT_MANIFEST)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .u64(self.version)
            .i64(self.issued_at_ms)
            .fixed(self.member_enc_pubkey.as_bytes())
            .u64(self.allies.len() as u64);
        for a in &self.allies {
            c = c.str(a.ally_id.as_str()).fixed(a.enc_pubkey.as_bytes());
        }
        c.finish()
    }

    /// Identity of this exact document: `BLAKE3(signing_bytes)`.
    pub fn hash(&self) -> Hash32 {
        Hash32::of(&self.signing_bytes())
    }

    /// The `(version, hash)` pair devices persist and reports carry.
    pub fn reference(&self) -> ManifestRef {
        ManifestRef {
            version: self.version,
            hash: self.hash(),
        }
    }
}

/// A pointer to one exact manifest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestRef {
    pub version: u64,
    pub hash: Hash32,
}

/// "Member M, on instance I, approves ally A whose encryption key is K."
///
/// Kept as the record of an individual approval (and for the safety-code
/// flow). Devices do **not** use endorsements to pick recipients; they use
/// the [`RecipientManifest`], which can express removal.
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
    /// The member's current [`RecipientManifest`] when they approved this
    /// device. The device's **first** accepted manifest must be at least this
    /// version (and exactly this document at this version), so an instance
    /// can't bootstrap a new or reinstalled device onto a pre-removal
    /// manifest. See `docs/PROTOCOL.md` §5.1 "Bootstrapping".
    pub min_manifest: ManifestRef,
}

impl DeviceEndorsement {
    pub fn signing_bytes(&self) -> Vec<u8> {
        Canonical::new(TAG_DEVICE_ENDORSEMENT)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.device_id.as_str())
            .fixed(self.device_sign_pubkey.as_bytes())
            .i64(self.endorsed_at_ms)
            .u64(self.min_manifest.version)
            .fixed(self.min_manifest.hash.as_bytes())
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

    fn manifest(allies: &[&str]) -> RecipientManifest {
        RecipientManifest {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            version: 1,
            issued_at_ms: 1,
            member_enc_pubkey: EncPublicKey([1; 32]),
            allies: allies
                .iter()
                .map(|a| ManifestAlly {
                    ally_id: UserId::new(*a),
                    enc_pubkey: EncPublicKey([2; 32]),
                })
                .collect(),
        }
    }

    #[test]
    fn manifest_validation() {
        assert_eq!(manifest(&["usr_a", "usr_b"]).validate(), Ok(()));
        assert_eq!(manifest(&[]).validate(), Ok(()));
        assert!(matches!(
            manifest(&["usr_b", "usr_a"]).validate(),
            Err(ManifestError::NotSorted(_))
        ));
        assert!(matches!(
            manifest(&["usr_a", "usr_a"]).validate(),
            Err(ManifestError::NotSorted(_))
        ));
        assert_eq!(
            manifest(&["usr_m"]).validate(),
            Err(ManifestError::MemberIsAlly)
        );
        assert!(matches!(
            manifest(&["dev_x"]).validate(),
            Err(ManifestError::MalformedId(_))
        ));
        let mut m = manifest(&[]);
        m.version = 0;
        assert_eq!(m.validate(), Err(ManifestError::ZeroVersion));
        let ids: Vec<String> = (0..=MAX_MANIFEST_ALLIES)
            .map(|i| format!("usr_{i:03}"))
            .collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(
            manifest(&refs).validate(),
            Err(ManifestError::TooManyAllies(MAX_MANIFEST_ALLIES + 1))
        );
    }

    #[test]
    fn manifest_bytes_bind_every_field() {
        let base = manifest(&["usr_a"]);
        let b = base.signing_bytes();
        let mut v = Vec::new();
        let mut m = base.clone();
        m.version = 2;
        v.push(m);
        let mut m = base.clone();
        m.issued_at_ms = 2;
        v.push(m);
        let mut m = base.clone();
        m.member_enc_pubkey = EncPublicKey([9; 32]);
        v.push(m);
        let mut m = base.clone();
        m.allies[0].enc_pubkey = EncPublicKey([9; 32]);
        v.push(m);
        let mut m = base.clone();
        m.allies[0].ally_id = UserId::new("usr_b");
        v.push(m);
        let mut m = base.clone();
        m.allies.clear();
        v.push(m);
        let mut m = base.clone();
        m.member_id = UserId::new("usr_n");
        v.push(m);
        let mut m = base.clone();
        m.instance_id = InstanceId::new("inst_b");
        v.push(m);
        for m in v {
            assert_ne!(m.signing_bytes(), b, "{m:?}");
            assert_ne!(m.hash(), base.hash());
        }
    }

    #[test]
    fn manifest_length_prefix_prevents_ambiguity() {
        // Two allies vs one ally whose id would absorb the next entry's bytes
        // must not collide (the u64 count + per-field lengths prevent it).
        let two = manifest(&["usr_a", "usr_b"]);
        let one = manifest(&["usr_a"]);
        assert_ne!(two.signing_bytes(), one.signing_bytes());
    }

    #[test]
    fn manifest_json_roundtrip() {
        let m = manifest(&["usr_a"]);
        let back: RecipientManifest =
            serde_json::from_str(&serde_json::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.reference(), m.reference());
    }

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
            min_manifest: ManifestRef {
                version: 1,
                hash: Hash32::ZERO,
            },
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
