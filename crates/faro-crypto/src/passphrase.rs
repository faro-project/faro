//! Passphrase and recovery-code wrapping of private keys (§5.2).
//!
//! An ally's (or member's) X25519 private key is wrapped in the browser with a
//! passphrase-derived key and uploaded, so the user can unlock it on several
//! devices. The server stores the [`WrappedSecret`] opaquely.
//!
//! Argon2id with `p = 1` matches libsodium's `crypto_pwhash_ALG_ARGON2ID13`,
//! so the browser (libsodium.js) and Rust derive identical keys.

use crate::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use faro_proto::encoding::b64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const WRAP_AAD: &[u8] = b"faro/wrapped-secret/v1";

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Lanes. Must be 1 for libsodium compatibility.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes — libsodium's `MODERATE`-ish and usable in a browser.
    fn default() -> Self {
        KdfParams {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for unit tests only.
    pub fn insecure_for_tests() -> Self {
        KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Reject parameters that libsodium cannot reproduce (`p != 1`) or that
    /// are absurd, so a malformed or hostile blob cannot make the client burn
    /// unbounded memory/CPU.
    fn validate(&self) -> Result<(), CryptoError> {
        if self.p_cost != 1 {
            return Err(CryptoError::Unsupported("argon2id p_cost must be 1".into()));
        }
        if self.m_cost_kib < 8
            || self.m_cost_kib > 4 * 1024 * 1024
            || self.t_cost == 0
            || self.t_cost > 64
        {
            return Err(CryptoError::Unsupported(
                "argon2id parameters out of range".into(),
            ));
        }
        Ok(())
    }
}

/// A secret encrypted under a passphrase-derived key. JSON-serializable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedSecret {
    pub v: u16,
    /// Always `"argon2id13"`.
    pub kdf: String,
    pub params: KdfParams,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

fn derive(
    passphrase: &[u8],
    salt: &[u8],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params.validate()?;
    let p = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| CryptoError::Kdf)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(passphrase, salt, out.as_mut())
        .map_err(|_| CryptoError::Kdf)?;
    Ok(out)
}

/// Wrap `secret` under `passphrase`.
pub fn wrap_secret(
    secret: &[u8],
    passphrase: &[u8],
    params: KdfParams,
) -> Result<WrappedSecret, CryptoError> {
    // libsodium's crypto_pwhash salt is 16 bytes.
    let salt = crate::random_bytes::<16>();
    let nonce = crate::random_bytes::<24>();
    let key = derive(passphrase, &salt, params)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| CryptoError::Encrypt)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret,
                aad: WRAP_AAD,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(WrappedSecret {
        v: 1,
        kdf: "argon2id13".into(),
        params,
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Unwrap a [`WrappedSecret`]. Wrong passphrase and corrupted data are
/// indistinguishable (`CryptoError::Decrypt`).
pub fn unwrap_secret(
    w: &WrappedSecret,
    passphrase: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if w.v != 1 || w.kdf != "argon2id13" {
        return Err(CryptoError::Unsupported(format!(
            "wrapped secret v{} {}",
            w.v, w.kdf
        )));
    }
    if w.salt.len() != 16 || w.nonce.len() != 24 {
        return Err(CryptoError::Decrypt);
    }
    let key = derive(passphrase, &w.salt, w.params)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| CryptoError::Decrypt)?;
    cipher
        .decrypt(
            XNonce::from_slice(&w.nonce),
            Payload {
                msg: &w.ciphertext,
                aad: WRAP_AAD,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Decrypt)
}

/// Crockford base32 alphabet (no I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a human-transcribable recovery code: 160 random bits as 32
/// Crockford-base32 characters in 8 groups of 4, e.g. `7K2M-…`.
pub fn generate_recovery_code() -> Zeroizing<String> {
    let bytes = Zeroizing::new(crate::random_bytes::<20>());
    let mut out = String::with_capacity(39);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut n = 0;
    for &b in bytes.iter() {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(CROCKFORD[((acc >> bits) & 31) as usize] as char);
            n += 1;
        }
    }
    Zeroizing::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap() {
        let w = wrap_secret(
            b"0123456789abcdef0123456789abcdef",
            b"correct horse",
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        let json = serde_json::to_string(&w).unwrap();
        let w2: WrappedSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(
            &**unwrap_secret(&w2, b"correct horse").unwrap(),
            b"0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            unwrap_secret(&w2, b"wrong").unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn rejects_bad_params() {
        let mut w = wrap_secret(b"x", b"p", KdfParams::insecure_for_tests()).unwrap();
        w.params.p_cost = 4;
        assert!(matches!(
            unwrap_secret(&w, b"p"),
            Err(CryptoError::Unsupported(_))
        ));
    }

    #[test]
    fn recovery_code_shape() {
        let c = generate_recovery_code();
        assert_eq!(c.len(), 39);
        assert_eq!(c.split('-').count(), 8);
        assert!(c
            .chars()
            .all(|ch| ch == '-' || CROCKFORD.contains(&(ch as u8))));
        assert_ne!(*c, *generate_recovery_code());
    }
}
