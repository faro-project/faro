//! Multi-recipient content encryption.
//!
//! `seal_item` encrypts a plaintext once under a fresh random 32-byte content
//! key (CK) with XChaCha20-Poly1305, then wraps CK to each recipient with a
//! libsodium-compatible sealed box. The member is always one of the recipients
//! (transparency: the member can read everything their allies can).

use crate::CryptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use faro_proto::keys::key_id;
use faro_proto::{EncPublicKey, EncryptedItem, Envelope, Nonce24, UserId};
use zeroize::Zeroizing;

/// An X25519 keypair used to receive sealed content keys.
pub struct EncryptionKeypair {
    secret: crypto_box::SecretKey,
    public: EncPublicKey,
}

impl std::fmt::Debug for EncryptionKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EncryptionKeypair(pub={})", self.public.to_b64())
    }
}

impl EncryptionKeypair {
    pub fn generate() -> Self {
        let secret = crypto_box::SecretKey::generate(&mut rand_core::OsRng);
        Self::from_secret(secret)
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_secret(crypto_box::SecretKey::from_bytes(*bytes))
    }

    fn from_secret(secret: crypto_box::SecretKey) -> Self {
        let public = EncPublicKey(*secret.public_key().as_bytes());
        EncryptionKeypair { secret, public }
    }

    pub fn public(&self) -> EncPublicKey {
        self.public
    }

    pub fn key_id(&self) -> String {
        key_id(self.public.as_bytes())
    }

    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Open a sealed box addressed to this key.
    pub fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.secret
            .unseal(sealed)
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }
}

/// Seal `msg` to a public key (libsodium `crypto_box_seal`).
pub fn seal_to(pubkey: &EncPublicKey, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crypto_box::PublicKey::from_bytes(pubkey.0)
        .seal(&mut rand_core::OsRng, msg)
        .map_err(|_| CryptoError::Encrypt)
}

/// One recipient of an encrypted item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub user_id: UserId,
    pub pubkey: EncPublicKey,
}

/// Encrypt `plaintext` for every recipient. `aad` binds the ciphertext to its
/// context (e.g. [`faro_proto::EventHeader::body_aad`]).
pub fn seal_item(
    plaintext: &[u8],
    aad: &[u8],
    recipients: &[Recipient],
) -> Result<EncryptedItem, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::Unsupported("no recipients".into()));
    }
    let ck = Zeroizing::new(crate::random_bytes::<32>());
    let nonce = crate::random_bytes::<24>();
    let cipher =
        XChaCha20Poly1305::new_from_slice(ck.as_slice()).map_err(|_| CryptoError::Encrypt)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    let envelopes = recipients
        .iter()
        .map(|r| {
            Ok(Envelope {
                recipient: r.user_id.clone(),
                key_id: key_id(r.pubkey.as_bytes()),
                wrapped_key: seal_to(&r.pubkey, ck.as_slice())?,
            })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(EncryptedItem {
        alg: EncryptedItem::ALG.to_owned(),
        nonce: Nonce24(nonce),
        ciphertext,
        envelopes,
    })
}

/// Decrypt an item as `me`, using `keypair`. Tries the envelope whose
/// `key_id` matches first, then any other envelope addressed to `me` (in case
/// the recipient rotated keys and the sender used an older one).
pub fn open_item(
    item: &EncryptedItem,
    aad: &[u8],
    me: &UserId,
    keypair: &EncryptionKeypair,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if item.alg != EncryptedItem::ALG {
        return Err(CryptoError::Unsupported(item.alg.clone()));
    }
    let my_kid = keypair.key_id();
    let mut candidates: Vec<&Envelope> = item
        .envelopes
        .iter()
        .filter(|e| &e.recipient == me)
        .collect();
    if candidates.is_empty() {
        return Err(CryptoError::NoEnvelope);
    }
    candidates.sort_by_key(|e| e.key_id != my_kid);
    for env in candidates {
        let Ok(ck) = keypair.unseal(&env.wrapped_key) else {
            continue;
        };
        if ck.len() != 32 {
            continue;
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&ck).map_err(|_| CryptoError::Decrypt)?;
        return cipher
            .decrypt(
                XNonce::from_slice(item.nonce.as_bytes()),
                Payload {
                    msg: &item.ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt);
    }
    Err(CryptoError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (EncryptionKeypair, EncryptionKeypair, Vec<Recipient>) {
        let member = EncryptionKeypair::generate();
        let ally = EncryptionKeypair::generate();
        let recips = vec![
            Recipient {
                user_id: UserId::new("usr_member"),
                pubkey: member.public(),
            },
            Recipient {
                user_id: UserId::new("usr_ally"),
                pubkey: ally.public(),
            },
        ];
        (member, ally, recips)
    }

    #[test]
    fn every_recipient_can_open() {
        let (member, ally, recips) = setup();
        let item = seal_item(b"secret report", b"aad", &recips).unwrap();
        assert_eq!(item.envelopes.len(), 2);
        assert_eq!(
            &**open_item(&item, b"aad", &UserId::new("usr_member"), &member).unwrap(),
            b"secret report"
        );
        assert_eq!(
            &**open_item(&item, b"aad", &UserId::new("usr_ally"), &ally).unwrap(),
            b"secret report"
        );
    }

    #[test]
    fn wrong_aad_or_key_fails() {
        let (_member, ally, recips) = setup();
        let item = seal_item(b"x", b"aad", &recips).unwrap();
        assert_eq!(
            open_item(&item, b"other", &UserId::new("usr_ally"), &ally).unwrap_err(),
            CryptoError::Decrypt
        );
        let stranger = EncryptionKeypair::generate();
        assert_eq!(
            open_item(&item, b"aad", &UserId::new("usr_ally"), &stranger).unwrap_err(),
            CryptoError::Decrypt
        );
        assert_eq!(
            open_item(&item, b"aad", &UserId::new("usr_nobody"), &stranger).unwrap_err(),
            CryptoError::NoEnvelope
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (_m, ally, recips) = setup();
        let mut item = seal_item(b"hello world", b"a", &recips).unwrap();
        item.ciphertext[0] ^= 1;
        assert!(open_item(&item, b"a", &UserId::new("usr_ally"), &ally).is_err());
    }

    #[test]
    fn swapped_envelope_fails() {
        // An instance moving an ally's envelope onto a different item must not work.
        let (_m, ally, recips) = setup();
        let a = seal_item(b"one", b"a", &recips).unwrap();
        let mut b = seal_item(b"two", b"a", &recips).unwrap();
        b.envelopes = a.envelopes.clone();
        assert!(open_item(&b, b"a", &UserId::new("usr_ally"), &ally).is_err());
    }

    #[test]
    fn keypair_secret_roundtrip() {
        let k = EncryptionKeypair::generate();
        let k2 = EncryptionKeypair::from_secret_bytes(&k.secret_bytes());
        assert_eq!(k.public(), k2.public());
    }

    #[test]
    fn requires_recipients() {
        assert!(seal_item(b"x", b"", &[]).is_err());
    }
}
