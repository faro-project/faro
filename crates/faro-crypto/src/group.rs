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
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use faro_proto::group::{
    body_aad, epoch_key_id, epoch_wrap_aad, GroupMessage, SealedGroupMessage, EPOCH_WRAPPED_KEY_LEN,
};
use faro_proto::keys::Signed;
use faro_proto::{EncPublicKey, EncryptedItem, Envelope, Hash32, Nonce24, SignPublicKey, UserId};
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

/// Seal `plaintext` (if any) for the whole group with the epoch key
/// `epoch_key` of `message.epoch`, and sign with the author's key. The body
/// is encrypted under a random content key, which one envelope wraps with
/// the epoch key (PROTOCOL.md §11.2). `message.recipients` must be empty and
/// `message.body_hash` is overwritten.
pub fn seal_group_message_to_epoch(
    author_sign: &SigningKey,
    epoch_key: &[u8; 32],
    mut message: GroupMessage,
    plaintext: Option<&[u8]>,
) -> Result<SealedGroupMessage, CryptoError> {
    message.body_hash = Hash32::ZERO;
    message
        .validate()
        .map_err(|e| CryptoError::Invalid(e.to_string()))?;
    let (Some(epoch), Some(group)) = (message.epoch, message.group_id.clone()) else {
        return Err(CryptoError::Invalid("not a whole-group message".into()));
    };
    let body = match plaintext {
        None => None,
        Some(pt) => {
            let ck = Zeroizing::new(crate::random_bytes::<32>());
            let nonce = crate::random_bytes::<24>();
            let cipher = XChaCha20Poly1305::new_from_slice(ck.as_slice())
                .map_err(|_| CryptoError::Encrypt)?;
            let ciphertext = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: pt,
                        aad: &body_aad(&message.instance_id, &message.item_id),
                    },
                )
                .map_err(|_| CryptoError::Encrypt)?;
            let wrap_nonce = crate::random_bytes::<24>();
            let wrapper = XChaCha20Poly1305::new_from_slice(epoch_key.as_slice())
                .map_err(|_| CryptoError::Encrypt)?;
            let mut wrapped = wrap_nonce.to_vec();
            wrapped.extend(
                wrapper
                    .encrypt(
                        XNonce::from_slice(&wrap_nonce),
                        Payload {
                            msg: ck.as_slice(),
                            aad: &epoch_wrap_aad(
                                &message.instance_id,
                                &group,
                                &message.item_id,
                                epoch,
                            ),
                        },
                    )
                    .map_err(|_| CryptoError::Encrypt)?,
            );
            debug_assert_eq!(wrapped.len(), EPOCH_WRAPPED_KEY_LEN);
            let item = EncryptedItem {
                alg: EncryptedItem::ALG.to_owned(),
                nonce: Nonce24(nonce),
                ciphertext,
                envelopes: vec![Envelope {
                    recipient: message.author_id.clone(),
                    key_id: epoch_key_id(epoch),
                    wrapped_key: wrapped,
                }],
            };
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

/// Decrypt a verified whole-group message's body with the epoch key of its
/// epoch. `Ok(None)` for a message without a body.
pub fn open_group_message_with_epoch(
    sealed: &SealedGroupMessage,
    epoch_key: &[u8; 32],
) -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
    let Some(body) = &sealed.body else {
        return Ok(None);
    };
    let m = &sealed.message.body;
    let (Some(epoch), Some(group)) = (m.epoch, m.group_id.as_deref()) else {
        return Err(CryptoError::Invalid("not a whole-group message".into()));
    };
    if body.alg != EncryptedItem::ALG {
        return Err(CryptoError::Unsupported(body.alg.clone()));
    }
    let [env] = body.envelopes.as_slice() else {
        return Err(CryptoError::NoEnvelope);
    };
    if env.wrapped_key.len() != EPOCH_WRAPPED_KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    let (wrap_nonce, wrapped) = env.wrapped_key.split_at(24);
    let wrapper = XChaCha20Poly1305::new_from_slice(epoch_key.as_slice())
        .map_err(|_| CryptoError::Decrypt)?;
    let ck = Zeroizing::new(
        wrapper
            .decrypt(
                XNonce::from_slice(wrap_nonce),
                Payload {
                    msg: wrapped,
                    aad: &epoch_wrap_aad(&m.instance_id, group, &m.item_id, epoch),
                },
            )
            .map_err(|_| CryptoError::Decrypt)?,
    );
    let cipher =
        XChaCha20Poly1305::new_from_slice(ck.as_slice()).map_err(|_| CryptoError::Decrypt)?;
    cipher
        .decrypt(
            XNonce::from_slice(body.nonce.as_bytes()),
            Payload {
                msg: &body.ciphertext,
                aad: &body_aad(&m.instance_id, &m.item_id),
            },
        )
        .map(|p| Some(Zeroizing::new(p)))
        .map_err(|_| CryptoError::Decrypt)
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
    if m.epoch.is_some() {
        // Whole-group messages open with the epoch key, not a person's key.
        return Err(CryptoError::NoEnvelope);
    }
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
            epoch: None,
            parent_id: None,
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

    fn whole_group(kind: GroupMessageKind) -> GroupMessage {
        GroupMessage {
            instance_id: InstanceId::new("inst_a"),
            group_id: Some("fedcba9876543210fedcba9876543210".into()),
            item_id: "0123456789abcdef0123456789abcdef".into(),
            kind,
            author_id: UserId::new("usr_sam"),
            issued_at_ms: 5,
            recipients: vec![],
            body_hash: Hash32::ZERO,
            epoch: Some(3),
            parent_id: None,
        }
    }

    #[test]
    fn whole_group_round_trip_and_forgeries() {
        let sam = SigningKey::generate();
        let key = [7u8; 32];
        let s = seal_group_message_to_epoch(
            &sam,
            &key,
            whole_group(GroupMessageKind::CheckIn),
            Some(b"{\"scale\":4}"),
        )
        .unwrap();
        verify_group_message(&sam.public(), &s).unwrap();
        assert_eq!(s.body.as_ref().unwrap().envelopes.len(), 1);
        let pt = open_group_message_with_epoch(&s, &key).unwrap().unwrap();
        assert_eq!(&**pt, b"{\"scale\":4}");
        // Another epoch key, another epoch number, another item, another group.
        assert!(open_group_message_with_epoch(&s, &[8u8; 32]).is_err());
        for edit in [
            (|m: &mut GroupMessage| m.epoch = Some(4)) as fn(&mut GroupMessage),
            |m| m.item_id = "ffffffffffffffffffffffffffffffff".into(),
            |m| m.group_id = Some("00000000000000000000000000000000".into()),
        ] {
            let mut moved = s.clone();
            edit(&mut moved.message.body);
            assert!(open_group_message_with_epoch(&moved, &key).is_err());
            assert!(verify_group_message(&sam.public(), &moved).is_err());
        }
        // Not a person's message: the person-key path refuses it.
        let kp = EncryptionKeypair::generate();
        assert!(open_group_message(&s, &UserId::new("usr_sam"), &kp).is_err());
        // Content-free, whole group.
        let cf =
            seal_group_message_to_epoch(&sam, &key, whole_group(GroupMessageKind::ReachOut), None)
                .unwrap();
        verify_group_message(&sam.public(), &cf).unwrap();
        assert!(open_group_message_with_epoch(&cf, &key).unwrap().is_none());
        // A whole-group message that names recipients is refused.
        let mut bad = whole_group(GroupMessageKind::CheckIn);
        bad.recipients = message(&kp).recipients;
        assert!(seal_group_message_to_epoch(&sam, &key, bad, Some(b"x")).is_err());
    }

    #[test]
    fn reply_signs_its_parent() {
        let sam = SigningKey::generate();
        let jo = EncryptionKeypair::generate();
        let mut m = message(&jo);
        m.group_id = Some("fedcba9876543210fedcba9876543210".into());
        m.kind = GroupMessageKind::CheckInReply;
        m.parent_id = Some("11111111111111111111111111111111".into());
        let s = seal_group_message(&sam, &jo.public(), m, Some(b"{\"text\":\"proud of you\"}"))
            .unwrap();
        verify_group_message(&sam.public(), &s).unwrap();
        let mut moved = s.clone();
        moved.message.body.parent_id = Some("22222222222222222222222222222222".into());
        assert_eq!(
            verify_group_message(&sam.public(), &moved),
            Err(CryptoError::BadSignature)
        );
        let mut orphan = s;
        orphan.message.body.parent_id = None;
        assert!(verify_group_message(&sam.public(), &orphan).is_err());
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
