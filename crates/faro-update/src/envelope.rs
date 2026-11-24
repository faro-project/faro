//! DSSE-style signed envelopes and threshold verification.
//!
//! ```json
//! {
//!   "payload_type": "application/vnd.faro.timestamp+json",
//!   "payload": "<base64url, no padding>",
//!   "signatures": [{"keyid": "<16 hex>", "sig": "<base64url Ed25519>"}]
//! }
//! ```
//!
//! Signatures cover the pre-authentication encoding
//! `Canonical("faro/update-envelope/v1") ‖ str(payload_type) ‖ bytes(payload)`
//! (see [`faro_proto::encoding::Canonical`]): the payload type is bound into
//! the signature, lengths are explicit, and the signed bytes are the decoded
//! payload, so there is exactly one interpretation of what was signed and
//! nothing about the JSON wrapper (whitespace, field order, base64 quirks)
//! can matter. The payload is parsed **only after** its signatures verify.

use crate::error::UpdateError;
use crate::metadata::{Role, RoleKeys, RoleMetadata};
use faro_crypto::SigningKey;
use faro_proto::encoding::{b64_decode, b64_encode, Canonical};
use faro_proto::keys::key_id;
use faro_proto::{SignPublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Domain-separation tag for the envelope's signing input.
pub const ENVELOPE_TAG: &str = "faro/update-envelope/v1";

/// Upper bound on signature entries in one envelope. A root needs at most a
/// handful; the cap bounds the Ed25519 work a hostile mirror can force.
pub const MAX_SIGNATURES: usize = 32;

/// One signature entry. Both fields are kept as raw strings so that a
/// malformed entry is *ignored* during threshold counting rather than making
/// the whole envelope unparseable: a mirror appending garbage must not be
/// able to invalidate otherwise good metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSignature {
    pub keyid: String,
    pub sig: String,
}

/// A signed metadata document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub payload_type: String,
    /// base64url (unpadded) of the payload bytes.
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

/// The pre-authentication encoding that signatures cover.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    Canonical::new(ENVELOPE_TAG)
        .str(payload_type)
        .bytes(payload)
        .finish()
}

impl Envelope {
    /// Sign arbitrary payload bytes under `payload_type`. Low-level: prefer
    /// [`crate::MetadataSigner`], which validates the metadata first. Keys
    /// are de-duplicated so the result never carries two entries per key.
    pub fn sign_raw(payload_type: &str, payload: &[u8], keys: &[&SigningKey]) -> Envelope {
        let mut env = Envelope {
            payload_type: payload_type.to_owned(),
            payload: b64_encode(payload),
            signatures: Vec::new(),
        };
        for k in keys {
            env.add_signature_over(payload, k);
        }
        env
    }

    /// Add (or replace) `key`'s signature. This is how offline root key
    /// holders co-sign one at a time without ever being in the same room.
    pub fn add_signature(&mut self, key: &SigningKey) -> Result<(), UpdateError> {
        let payload = b64_decode(&self.payload).map_err(|e| UpdateError::MalformedEnvelope {
            role: role_for_payload_type(&self.payload_type).unwrap_or(Role::Root),
            reason: format!("payload is not base64url: {e}"),
        })?;
        self.add_signature_over(&payload, key);
        Ok(())
    }

    fn add_signature_over(&mut self, payload: &[u8], key: &SigningKey) {
        let keyid = key_id(key.public().as_bytes());
        let sig = key.sign_raw(&pae(&self.payload_type, payload));
        self.signatures.retain(|s| s.keyid != keyid);
        self.signatures.push(EnvelopeSignature {
            keyid,
            sig: sig.to_b64(),
        });
    }

    /// Parse an envelope for `role`, enforcing the role's size cap *before*
    /// handing the bytes to the JSON parser.
    pub fn parse(role: Role, bytes: &[u8]) -> Result<Envelope, UpdateError> {
        let max = role.max_envelope_bytes();
        if bytes.len() > max {
            return Err(UpdateError::TooLarge {
                role,
                len: bytes.len(),
                max,
            });
        }
        serde_json::from_slice(bytes).map_err(|e| UpdateError::MalformedEnvelope {
            role,
            reason: e.to_string(),
        })
    }

    /// Serialize for storage or serving. Pretty-printed: the bytes are hashed
    /// by the timestamp as-is, so any stable form works, and humans read
    /// these files during release ceremonies.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serializing a struct of strings to JSON cannot fail.
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    /// The decoded payload **without any verification**. For tooling and
    /// tests that need to inspect what is being signed; never use the result
    /// to make a trust decision.
    pub fn unverified_payload(&self) -> Result<Vec<u8>, UpdateError> {
        b64_decode(&self.payload).map_err(|e| UpdateError::MalformedEnvelope {
            role: role_for_payload_type(&self.payload_type).unwrap_or(Role::Root),
            reason: format!("payload is not base64url: {e}"),
        })
    }

    /// Check the payload type and that at least `role_keys.threshold`
    /// distinct authorised keys signed; return the payload bytes.
    ///
    /// Counting rules (TUF §5.4-style):
    /// * only key ids listed in `role_keys` count — a key that is valid for
    ///   another role, or unknown, is ignored;
    /// * each key id counts at most once, however many entries it has;
    /// * a malformed entry (bad base64, wrong length, bad signature) is
    ///   ignored rather than fatal, but obviously can't count.
    pub(crate) fn verify_role(
        &self,
        role: Role,
        keys: &BTreeMap<String, SignPublicKey>,
        role_keys: &RoleKeys,
    ) -> Result<Vec<u8>, UpdateError> {
        if self.payload_type != role.payload_type() {
            return Err(UpdateError::WrongPayloadType {
                expected: role.payload_type().to_owned(),
                found: self.payload_type.clone(),
            });
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(UpdateError::TooManySignatures {
                role,
                count: self.signatures.len(),
                max: MAX_SIGNATURES,
            });
        }
        let payload = b64_decode(&self.payload).map_err(|e| UpdateError::MalformedEnvelope {
            role,
            reason: format!("payload is not base64url: {e}"),
        })?;
        let msg = pae(&self.payload_type, &payload);

        let authorised = role_keys.keyid_set();
        let mut counted: BTreeSet<&str> = BTreeSet::new();
        for entry in &self.signatures {
            let id = entry.keyid.as_str();
            if !authorised.contains(id) || counted.contains(id) {
                continue;
            }
            let Some(pk) = keys.get(id) else { continue };
            let Some(sig) = Signature::from_b64(&entry.sig) else {
                continue;
            };
            if faro_crypto::verify(pk, &msg, &sig).is_ok() {
                counted.insert(id);
            }
        }
        let threshold = role_keys.threshold as usize;
        // A zero threshold is rejected by root validation; the `max(1)` keeps
        // this function safe even if called with an unvalidated role.
        if counted.len() < threshold.max(1) {
            return Err(UpdateError::ThresholdNotMet {
                role,
                valid: counted.len(),
                threshold,
            });
        }
        Ok(payload)
    }
}

fn role_for_payload_type(pt: &str) -> Option<Role> {
    [Role::Root, Role::Targets, Role::Timestamp]
        .into_iter()
        .find(|r| r.payload_type() == pt)
}

/// Parse and structurally validate an already-authenticated payload.
pub(crate) fn parse_payload<T: RoleMetadata>(payload: &[u8]) -> Result<T, UpdateError> {
    let meta: T = serde_json::from_slice(payload).map_err(|e| UpdateError::InvalidMetadata {
        role: T::ROLE,
        reason: e.to_string(),
    })?;
    meta.validate()
        .map_err(|reason| UpdateError::InvalidMetadata {
            role: T::ROLE,
            reason,
        })?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyset(keys: &[&SigningKey]) -> BTreeMap<String, SignPublicKey> {
        keys.iter()
            .map(|k| (key_id(k.public().as_bytes()), k.public()))
            .collect()
    }

    fn ids(keys: &[&SigningKey]) -> Vec<String> {
        keys.iter().map(|k| key_id(k.public().as_bytes())).collect()
    }

    #[test]
    fn pae_binds_type_and_length() {
        // Shifting a byte between type and payload must change the encoding.
        assert_ne!(pae("ab", b"c"), pae("a", b"bc"));
        assert_ne!(pae("t", b""), pae("t", b"\0"));
    }

    #[test]
    fn malformed_entries_are_ignored_not_fatal() {
        let a = SigningKey::generate();
        let b = SigningKey::generate();
        let mut env = Envelope::sign_raw(Role::Timestamp.payload_type(), b"{}", &[&a]);
        let id_b = key_id(b.public().as_bytes());
        env.signatures.insert(
            0,
            EnvelopeSignature {
                keyid: id_b.clone(),
                sig: "!!not base64!!".into(),
            },
        );
        env.signatures.insert(
            0,
            EnvelopeSignature {
                keyid: id_b,
                sig: b64_encode(&[0u8; 10]),
            },
        );
        let rk = RoleKeys::new(ids(&[&a, &b]), 1);
        assert!(env
            .verify_role(Role::Timestamp, &keyset(&[&a, &b]), &rk)
            .is_ok());
        let rk2 = RoleKeys::new(ids(&[&a, &b]), 2);
        assert_eq!(
            env.verify_role(Role::Timestamp, &keyset(&[&a, &b]), &rk2),
            Err(UpdateError::ThresholdNotMet {
                role: Role::Timestamp,
                valid: 1,
                threshold: 2
            })
        );
    }

    #[test]
    fn bad_entry_before_good_entry_for_same_key_still_counts() {
        // A mirror can't knock out a key by prepending a bogus entry for it.
        let a = SigningKey::generate();
        let mut env = Envelope::sign_raw(Role::Timestamp.payload_type(), b"{}", &[&a]);
        env.signatures.insert(
            0,
            EnvelopeSignature {
                keyid: key_id(a.public().as_bytes()),
                sig: Signature([7u8; 64]).to_b64(),
            },
        );
        let rk = RoleKeys::new(ids(&[&a]), 1);
        assert!(env
            .verify_role(Role::Timestamp, &keyset(&[&a]), &rk)
            .is_ok());
    }

    #[test]
    fn signature_is_bound_to_payload_type() {
        let a = SigningKey::generate();
        let mut env = Envelope::sign_raw(Role::Targets.payload_type(), b"{}", &[&a]);
        // Relabel as timestamp: type check fails first...
        env.payload_type = Role::Timestamp.payload_type().into();
        let rk = RoleKeys::new(ids(&[&a]), 1);
        assert!(matches!(
            env.verify_role(Role::Targets, &keyset(&[&a]), &rk),
            Err(UpdateError::WrongPayloadType { .. })
        ));
        // ...and even when checked as that role the signature doesn't verify.
        assert!(matches!(
            env.verify_role(Role::Timestamp, &keyset(&[&a]), &rk),
            Err(UpdateError::ThresholdNotMet { valid: 0, .. })
        ));
    }

    #[test]
    fn too_many_signatures_rejected() {
        let a = SigningKey::generate();
        let mut env = Envelope::sign_raw(Role::Timestamp.payload_type(), b"{}", &[&a]);
        let extra = env.signatures[0].clone();
        env.signatures
            .extend(std::iter::repeat_n(extra, MAX_SIGNATURES));
        let rk = RoleKeys::new(ids(&[&a]), 1);
        assert!(matches!(
            env.verify_role(Role::Timestamp, &keyset(&[&a]), &rk),
            Err(UpdateError::TooManySignatures { .. })
        ));
    }

    #[test]
    fn parse_enforces_size_cap_before_json() {
        let big = vec![b' '; Role::Timestamp.max_envelope_bytes() + 1];
        assert!(matches!(
            Envelope::parse(Role::Timestamp, &big),
            Err(UpdateError::TooLarge { .. })
        ));
    }

    #[test]
    fn add_signature_replaces_existing_entry() {
        let a = SigningKey::generate();
        let mut env = Envelope::sign_raw(Role::Root.payload_type(), b"{}", &[&a, &a]);
        assert_eq!(env.signatures.len(), 1);
        env.add_signature(&a).unwrap();
        assert_eq!(env.signatures.len(), 1);
    }
}
