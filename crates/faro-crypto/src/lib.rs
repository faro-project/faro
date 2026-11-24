//! # faro-crypto
//!
//! All cryptography Faro uses (ARCHITECTURE.md §5.1), behind a small API:
//!
//! | Purpose | Primitive |
//! |---|---|
//! | Device / member / instance signing | Ed25519 (`ed25519-dalek`, strict verification) |
//! | Ally / member encryption keys | X25519 |
//! | Per-item content encryption | XChaCha20-Poly1305 with a random content key (CK) |
//! | Key wrap to each recipient | `crypto_box_seal` (libsodium-compatible sealed box) |
//! | Passphrase / recovery-code wrapping | Argon2id → XChaCha20-Poly1305 |
//! | Hashing | BLAKE3 |
//!
//! Sealed boxes and Argon2id (p = 1) are byte-compatible with libsodium, so the
//! ally web app can use `libsodium.js` to open what devices produce.

pub mod chain;
mod passphrase;
mod seal;
mod sign;

pub use chain::{verify_chain, verify_next, ChainError, ChainHead, Link};
pub use passphrase::{
    generate_recovery_code, unwrap_secret, wrap_secret, KdfParams, WrappedSecret,
};
pub use seal::{open_item, seal_item, seal_to, EncryptionKeypair, Recipient};
pub use sign::{verify, verify_item, verify_signed, SignedBytes, SigningKey};

pub use zeroize::Zeroizing;

/// Errors from this crate. Deliberately coarse: callers must not be able to
/// distinguish *why* a decryption failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid public key")]
    BadPublicKey,
    #[error("decryption failed")]
    Decrypt,
    #[error("no envelope for this recipient")]
    NoEnvelope,
    #[error("encryption failed")]
    Encrypt,
    #[error("unsupported algorithm or parameters: {0}")]
    Unsupported(String),
    #[error("key derivation failed")]
    Kdf,
}

/// Fill a fixed-size array from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::RngCore;
    let mut b = [0u8; N];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}

/// BLAKE3 convenience re-export.
pub fn hash(bytes: &[u8]) -> faro_proto::Hash32 {
    faro_proto::Hash32::of(bytes)
}
