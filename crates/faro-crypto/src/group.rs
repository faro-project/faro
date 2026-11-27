//! Sealing, signing, verifying and opening group messages (GROUPS.md §10.2,
//! PROTOCOL.md §11): reach outs and notes on proposals and join requests.
//!
//! A receiving client must call [`verify_group_message`] with the author's
//! member signing key before it shows anything: structure first (cheap, and
//! bounds the work a hostile document causes), then the body against the
//! signed header, then the signature. Only then does it [`open_group_message`].

use crate::seal::{open_item, seal_item, EncryptionKeypair, Recipient};
use crate::sign::{verify_item, SignedBytes, SigningKey};
use crate::CryptoError;
use faro_proto::group::{body_aad, GroupMessage, SealedGroupMessage};
use faro_proto::keys::Signed;
use faro_proto::{EncPublicKey, Hash32, SignPublicKey, UserId};
use zeroize::Zeroizing;

impl SignedBytes for GroupMessage {
    fn signed_bytes(&self) -> Vec<u8> {
        self.signing_bytes()
    }
}

/// Seal `plaintext` (if any) to every recipient in `message` and to the
/// author's own `author_enc` key, set `body_hash`, and sign with the
/// author's member key. `message.body_hash` is overwritten.
pub fn seal_group_message(
    author_sign: &SigningKey,
    author_enc: &EncPublicKey,
    mut message: GroupMessage,
    plaintext: Option<&[u8]>,
) -> Result<SealedGroupMessage, CryptoError> {
    message.body_hash = Hash32::ZERO;
    message
        .validate()
        .map_err(|e| CryptoError::Invalid(e.to_string()))?;
    let body = match plaintext {
        None => None,
        Some(pt) => {
            let mut recipients: Vec<Recipient> = message
                .recipients
                .iter()
                .map(|r| Recipient {
                    user_id: r.user_id.clone(),
                    pubkey: r.enc_pubkey,
                })
                .collect();
            recipients.push(Recipient {
                user_id: message.author_id.clone(),
                pubkey: *author_enc,
            });
            let aad = body_aad(&message.instance_id, &message.item_id);
            let item = seal_item(pt, &aad, &recipients)?;
            message.body_hash = item.body_hash();
            Some(item)
        }
    };
    let sig = author_sign.sign(&message);
    Ok(SealedGroupMessage {
        message: Signed { body: message, sig },
        body,
    })
}

/// Check a message before showing it: its structure, its body against the
/// signed header, and the author's signature with `author_pk` (their member
/// signing key). A forged or altered message fails here.
pub fn verify_group_message(
    author_pk: &SignPublicKey,
    sealed: &SealedGroupMessage,
) -> Result<(), CryptoError> {
    sealed
        .validate()
        .map_err(|e| CryptoError::Invalid(e.to_string()))?;
    verify_item(author_pk, &sealed.message.body, &sealed.message.sig)
}

/// Decrypt a verified message's body as `me` (the author or a recipient).
/// `Ok(None)` for a message without a body.
pub fn open_group_message(
    sealed: &SealedGroupMessage,
    me: &UserId,
    keypair: &EncryptionKeypair,
) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
    let Some(body) = &sealed.body else {
        return Ok(None);
    };
    let m = &sealed.message.body;
    open_item(body, &body_aad(&m.instance_id, &m.item_id), me, keypair).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::group::{GroupMessageKind, MessageRecipient};
    use faro_proto::InstanceId;

    fn message(recipient: &EncryptionKeypair) -> GroupMessage {
        GroupMessage {
            instance_id: InstanceId::new("inst_a"),
            group_id: None,
            item_id: "0123456789abcdef0123456789abcdef".into(),
            kind: GroupMessageKind::ReachOut,
            author_id: UserId::new("usr_sam"),
            issued_at_ms: 5,
            recipients: vec![MessageRecipient {
                user_id: UserId::new("usr_jo"),
                enc_pubkey: recipient.public(),
            }],
            body_hash: Hash32([7; 32]),
        }
    }

    #[test]
    fn round_trip_and_forgeries() {
        let sam = SigningKey::generate();
        let sam_enc = EncryptionKeypair::generate();
        let jo = EncryptionKeypair::generate();
        let s = seal_group_message(
            &sam,
            &sam_enc.public(),
            message(&jo),
            Some(b"{\"text\":\"rough night\"}"),
        )
        .unwrap();
        verify_group_message(&sam.public(), &s).unwrap();
        for (who, k) in [("usr_jo", &jo), ("usr_sam", &sam_enc)] {
            let pt = open_group_message(&s, &UserId::new(who), k)
                .unwrap()
                .unwrap();
            assert_eq!(&**pt, b"{\"text\":\"rough night\"}");
        }

        // Someone else's key (an operator's), an edited header, a swapped body.
        let mallory = SigningKey::generate();
        assert_eq!(
            verify_group_message(&mallory.public(), &s),
            Err(CryptoError::BadSignature)
        );
        let mut edited = s.clone();
        edited.message.body.issued_at_ms += 1;
        assert_eq!(
            verify_group_message(&sam.public(), &edited),
            Err(CryptoError::BadSignature)
        );
        let forged = seal_group_message(
            &mallory,
            &sam_enc.public(),
            message(&jo),
            Some(b"{\"text\":\"forged\"}"),
        )
        .unwrap();
        assert_eq!(
            verify_group_message(&sam.public(), &forged),
            Err(CryptoError::BadSignature)
        );
        let mut swapped = s.clone();
        swapped.body = forged.body.clone();
        assert!(matches!(
            verify_group_message(&sam.public(), &swapped),
            Err(CryptoError::Invalid(_))
        ));
        // A body moved to another item doesn't open there either.
        let mut moved = forged.clone();
        moved.message.body.item_id = "ffffffffffffffffffffffffffffffff".into();
        assert!(open_group_message(&moved, &UserId::new("usr_jo"), &jo).is_err());
    }

    #[test]
    fn content_free() {
        let sam = SigningKey::generate();
        let jo = EncryptionKeypair::generate();
        let s = seal_group_message(&sam, &jo.public(), message(&jo), None).unwrap();
        assert_eq!(s.message.body.body_hash, Hash32::ZERO);
        verify_group_message(&sam.public(), &s).unwrap();
        assert!(open_group_message(&s, &UserId::new("usr_jo"), &jo)
            .unwrap()
            .is_none());
    }
}
