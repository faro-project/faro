//! Ed25519 signing and verification over canonical `signing_bytes()`.

use crate::CryptoError;
use ed25519_dalek::Signer;
use faro_proto::api::{Heartbeat, SignedHeartbeat};
use faro_proto::keys::{
    AllyEndorsement, DeviceEndorsement, KeyRewrap, MemberEncKeyBinding, RecipientManifest, Signed,
};
use faro_proto::report::ReportHeader;
use faro_proto::{EventHeader, SignPublicKey, Signature};
use zeroize::Zeroizing;

/// Anything with a canonical signing representation.
pub trait SignedBytes {
    fn signed_bytes(&self) -> Vec<u8>;
}

macro_rules! impl_signed_bytes {
    ($($t:ty),*) => {$(
        impl SignedBytes for $t {
            fn signed_bytes(&self) -> Vec<u8> { self.signing_bytes() }
        }
    )*};
}
impl_signed_bytes!(
    EventHeader,
    AllyEndorsement,
    DeviceEndorsement,
    KeyRewrap,
    MemberEncKeyBinding,
    RecipientManifest,
    ReportHeader,
    Heartbeat
);

/// An Ed25519 signing key. Zeroized on drop (via `ed25519-dalek`'s `zeroize` feature).
pub struct SigningKey(ed25519_dalek::SigningKey);

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey(pub={})", self.public().to_b64())
    }
}

impl SigningKey {
    pub fn generate() -> Self {
        SigningKey(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(secret))
    }

    /// The 32-byte seed. Handle with care; it is wrapped in `Zeroizing`.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> SignPublicKey {
        SignPublicKey(self.0.verifying_key().to_bytes())
    }

    pub fn sign_raw(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg).to_bytes())
    }

    pub fn sign<T: SignedBytes>(&self, item: &T) -> Signature {
        self.sign_raw(&item.signed_bytes())
    }

    /// Wrap an endorsement (or any [`SignedBytes`] value) with this key's signature.
    pub fn endorse<T: SignedBytes>(&self, body: T) -> Signed<T> {
        let sig = self.sign(&body);
        Signed { body, sig }
    }

    pub fn sign_heartbeat(&self, heartbeat: Heartbeat) -> SignedHeartbeat {
        let sig = self.sign(&heartbeat);
        SignedHeartbeat { heartbeat, sig }
    }
}

/// Strict Ed25519 verification (rejects small-order keys and malleable signatures).
pub fn verify(pk: &SignPublicKey, msg: &[u8], sig: &Signature) -> Result<(), CryptoError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk.as_bytes())
        .map_err(|_| CryptoError::BadPublicKey)?;
    if vk.is_weak() {
        return Err(CryptoError::BadPublicKey);
    }
    let sig = ed25519_dalek::Signature::from_bytes(&sig.0);
    vk.verify_strict(msg, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

/// Verify a [`SignedBytes`] value.
pub fn verify_item<T: SignedBytes>(
    pk: &SignPublicKey,
    item: &T,
    sig: &Signature,
) -> Result<(), CryptoError> {
    verify(pk, &item.signed_bytes(), sig)
}

/// Verify a member-signed endorsement.
pub fn verify_signed<T: SignedBytes>(pk: &SignPublicKey, s: &Signed<T>) -> Result<(), CryptoError> {
    verify_item(pk, &s.body, &s.sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::{DeviceId, EncPublicKey, InstanceId, UserId};

    #[test]
    fn sign_verify_roundtrip() {
        let k = SigningKey::generate();
        let sig = k.sign_raw(b"hello");
        assert!(verify(&k.public(), b"hello", &sig).is_ok());
        assert_eq!(
            verify(&k.public(), b"hellO", &sig),
            Err(CryptoError::BadSignature)
        );
        let other = SigningKey::generate();
        assert_eq!(
            verify(&other.public(), b"hello", &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn seed_roundtrip() {
        let k = SigningKey::generate();
        let k2 = SigningKey::from_bytes(&k.to_bytes());
        assert_eq!(k.public(), k2.public());
    }

    #[test]
    fn rejects_weak_key() {
        // The identity point is a small-order key.
        let mut id = [0u8; 32];
        id[0] = 1;
        assert_eq!(
            verify(&SignPublicKey(id), b"x", &Signature([0; 64])),
            Err(CryptoError::BadPublicKey)
        );
    }

    #[test]
    fn endorsement_roundtrip() {
        let member = SigningKey::generate();
        let e = member.endorse(AllyEndorsement {
            instance_id: InstanceId::new("inst_a"),
            member_id: UserId::new("usr_m"),
            ally_id: UserId::new("usr_a"),
            ally_enc_pubkey: EncPublicKey([4; 32]),
            endorsed_at_ms: 10,
        });
        assert!(verify_signed(&member.public(), &e).is_ok());
        let mut forged = e.clone();
        forged.body.ally_enc_pubkey = EncPublicKey([5; 32]);
        assert!(verify_signed(&member.public(), &forged).is_err());
        let _ = DeviceId::new("dev_x");
    }
}
