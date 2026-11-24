//! Public-key validity checks shared by every component that accepts keys
//! from outside: devices (manifests), the server (uploads, enrollment) and
//! release tooling.

use crate::CryptoError;
use faro_proto::{EncPublicKey, SignPublicKey};

/// X25519 public keys of small order (libsodium's `has_small_order` list,
/// compared with the top bit cleared). Sealing to any of them yields a shared
/// secret the attacker can compute without a private key.
const SMALL_ORDER: [[u8; 32]; 7] = [
    // 0 (order 4)
    [0; 32],
    // 1 (order 1)
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // order-8 points
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (order 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (= 0)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (= 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Whether `k` is a low-order X25519 point (ignoring the unused top bit).
pub fn is_weak_x25519(k: &EncPublicKey) -> bool {
    let mut masked = k.0;
    masked[31] &= 0x7f;
    SMALL_ORDER.contains(&masked)
}

/// Check that `pk` is a usable Ed25519 public key: a valid point encoding and
/// not of small order. Use this when *accepting* a key (enrollment, member key
/// upload) rather than probing with a dummy signature.
pub fn validate_sign_pubkey(pk: &SignPublicKey) -> Result<(), CryptoError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk.as_bytes())
        .map_err(|_| CryptoError::BadPublicKey)?;
    if vk.is_weak() {
        return Err(CryptoError::BadPublicKey);
    }
    Ok(())
}

/// Check that `pk` is a usable X25519 public key (not a small-order point,
/// to which a sealed box would be readable by anyone).
pub fn validate_enc_pubkey(pk: &EncPublicKey) -> Result<(), CryptoError> {
    if is_weak_x25519(pk) {
        return Err(CryptoError::BadPublicKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_small_order_enc_keys_ignoring_top_bit() {
        for p in SMALL_ORDER {
            assert!(is_weak_x25519(&EncPublicKey(p)));
            let mut hi = p;
            hi[31] |= 0x80;
            assert!(is_weak_x25519(&EncPublicKey(hi)), "top bit must be ignored");
        }
        let good = crate::EncryptionKeypair::generate().public();
        assert!(!is_weak_x25519(&good));
        assert!(validate_enc_pubkey(&good).is_ok());
    }

    #[test]
    fn sign_key_validation() {
        assert!(validate_sign_pubkey(&crate::SigningKey::generate().public()).is_ok());
        let mut identity = [0u8; 32];
        identity[0] = 1; // the identity point: small order
        assert_eq!(
            validate_sign_pubkey(&SignPublicKey(identity)),
            Err(CryptoError::BadPublicKey)
        );
    }
}
