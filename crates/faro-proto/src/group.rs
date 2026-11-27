//! Signed, encrypted **group messages**: reach outs and the notes on
//! alliance proposals and join requests (GROUPS.md §10.2, PROTOCOL.md §11).
//!
//! One person writes a message for specific people. The instance stores and
//! routes it, but can neither read it nor forge it:
//!
//! * **Encryption** is the item construction every Faro item uses
//!   (PROTOCOL.md §4.1): a random content key with XChaCha20-Poly1305, under
//!   [`body_aad`], wrapped with `crypto_box_seal` to each recipient **and
//!   the author**, so the author can read what they sent.
//! * **Authenticity:** the author signs [`GroupMessage::signing_bytes`] with
//!   their member signing key. The signature covers the instance, the group,
//!   the item, the kind, the author, the time, every recipient with the key
//!   it was sealed to, and the ciphertext (through `body_hash`). Without it,
//!   an operator who knows everyone's public keys could write a message
//!   "from" anyone.
//!
//! **Whole-group mode** (reach outs and check-ins to a group of any size,
//! GROUPS.md §10.5): `epoch` names the group's epoch (PROTOCOL.md §10.3),
//! `recipients` is empty, and the body has a single envelope that wraps the
//! content key with that epoch's group key ([`epoch_wrap_aad`]) instead of
//! sealing it to each person. Whoever holds the epoch key can read it.
//!
//! A message may have no body (`body_hash` all zero): a signed, content-free
//! reach out. People without a member signing key send reach outs that are
//! not group messages at all (no signature, no body), which clients mark
//! "Sent through the server. Can't be verified."

use crate::encoding::{Canonical, EncPublicKey, Hash32};
use crate::event::EncryptedItem;
use crate::ids::{InstanceId, UserId};
use crate::keys::{key_id, Signed};
use serde::{Deserialize, Serialize};

const TAG_GROUP_MESSAGE: &str = "faro/group-message/v1";
const TAG_GROUP_MESSAGE_BODY: &str = "faro/group-message-body/v1";
const TAG_GROUP_MESSAGE_EPOCH: &str = "faro/group-message-epoch/v1";

/// Recipients of one message, not counting the author's own copy. The same
/// bound as a recipient manifest's allies ([`crate::keys::MAX_MANIFEST_ALLIES`]),
/// so a hostile instance can't make a client do unbounded work, and well
/// inside the instance's 64 envelopes per item.
pub const MAX_MESSAGE_RECIPIENTS: usize = 32;

/// Characters (Unicode scalar values) in a message's text.
pub const MAX_MESSAGE_CHARS: usize = 500;

/// Bytes of ciphertext in one message: the longest text in UTF-8 (4 bytes a
/// character), its JSON and the AEAD tag fit with room to spare.
pub const MAX_MESSAGE_CIPHERTEXT: usize = 4096;

/// Bytes of ciphertext in a check-in: three texts of [`MAX_MESSAGE_CHARS`]
/// characters in UTF-8, the scale and the JSON around them.
pub const MAX_CHECK_IN_CIPHERTEXT: usize = 8192;

/// Bytes of an epoch-wrapped content key: a 24-byte nonce, the 32-byte key
/// and the 16-byte AEAD tag.
pub const EPOCH_WRAPPED_KEY_LEN: usize = 24 + 32 + 16;

/// The `key_id` of the one envelope of a whole-group message.
pub fn epoch_key_id(epoch: u64) -> String {
    format!("epoch:{epoch}")
}

/// What a message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMessageKind {
    /// "I'm struggling": to the author's allies, a group's facilitators or
    /// named people.
    ReachOut,
    /// A note on an alliance proposal, to the person it is sent to.
    ProposalNote,
    /// A note on a request to join a listed group, to its facilitators.
    JoinRequestNote,
    /// A check-in (GROUPS.md §8.6): a 1 to 5 scale and up to three short
    /// texts, to the author's allies in the group, its facilitators, named
    /// people or the whole group. Stored in the group's feed, never
    /// notified.
    CheckIn,
    /// A private reply to a check-in, to its author alone.
    CheckInReply,
}

impl GroupMessageKind {
    pub const ALL: [GroupMessageKind; 5] = [
        GroupMessageKind::ReachOut,
        GroupMessageKind::ProposalNote,
        GroupMessageKind::JoinRequestNote,
        GroupMessageKind::CheckIn,
        GroupMessageKind::CheckInReply,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            GroupMessageKind::ReachOut => "reach_out",
            GroupMessageKind::ProposalNote => "proposal_note",
            GroupMessageKind::JoinRequestNote => "join_request_note",
            GroupMessageKind::CheckIn => "check_in",
            GroupMessageKind::CheckInReply => "check_in_reply",
        }
    }

    /// Whether this kind may be sealed to the whole group (epoch mode).
    pub fn may_go_to_group(self) -> bool {
        matches!(self, GroupMessageKind::ReachOut | GroupMessageKind::CheckIn)
    }

    /// Longest ciphertext a body of this kind may have.
    pub fn max_ciphertext(self) -> usize {
        match self {
            GroupMessageKind::CheckIn => MAX_CHECK_IN_CIPHERTEXT,
            _ => MAX_MESSAGE_CIPHERTEXT,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One person a message is sealed to, with the key the author sealed it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRecipient {
    pub user_id: UserId,
    pub enc_pubkey: EncPublicKey,
}

/// "Author A, on instance I, wrote item X of this kind (in group G) at T,
/// for exactly these people with these keys, and its ciphertext is H."
///
/// * `item_id` and `group_id` are 32 lowercase hex characters, the form
///   of the instance's own ids. The author's client picks `item_id` at
///   random, so it is known before anything is stored, and the instance
///   files the message under it.
/// * `group_id` is `None` only for a reach out outside any group. Notes
///   always name their group.
/// * Recipients are sorted strictly ascending by `user_id`, so one set has
///   exactly one encoding. The author is not one of them: their own copy is
///   always there (one more envelope).
/// * `body_hash` is `BLAKE3(nonce ‖ ciphertext)` of the encrypted body
///   ([`EncryptedItem::body_hash`]), or 32 zero bytes when there is none.
/// * `epoch` is set exactly for a whole-group message (module docs): then
///   `recipients` is empty and the kind is a reach out or a check-in.
/// * `parent_id` names the check-in a reply answers, and only a reply has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMessage {
    pub instance_id: InstanceId,
    #[serde(default)]
    pub group_id: Option<String>,
    pub item_id: String,
    pub kind: GroupMessageKind,
    pub author_id: UserId,
    pub issued_at_ms: i64,
    pub recipients: Vec<MessageRecipient>,
    pub body_hash: Hash32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
}

/// Structural problems with a message that need no keys to find.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GroupMessageError {
    #[error("malformed id in message: {0}")]
    MalformedId(String),
    #[error("a message needs at least one recipient")]
    NoRecipients,
    #[error("message lists {0} recipients, more than the maximum of {MAX_MESSAGE_RECIPIENTS}")]
    TooManyRecipients(usize),
    #[error("recipients are not sorted strictly by user_id (unsorted or duplicate: {0})")]
    NotSorted(UserId),
    #[error("the author is listed as a recipient")]
    AuthorIsRecipient,
    #[error("a {0} must name its group")]
    NoGroup(&'static str),
    #[error("a proposal note or a reply has exactly one recipient")]
    ProposalNoteRecipients,
    #[error("only a reach out or a check-in goes to the whole group")]
    EpochKind,
    #[error("a whole-group message names its group and has no recipients")]
    EpochRecipients,
    #[error("a reply names the check-in it answers, and nothing else does")]
    Parent,
    #[error("the body does not match the signed message")]
    BodyMismatch,
    #[error("unsupported body: {0}")]
    BadBody(String),
    #[error("envelopes do not match the recipients")]
    Envelopes,
}

/// 32 lowercase hex characters: an id in the instance's own form.
pub fn is_hex_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl GroupMessage {
    /// Check the rules in the type docs. Signature checks are the caller's
    /// job (`faro_crypto::verify_group_message`). Runs before any
    /// signature check, so a hostile document costs little.
    pub fn validate(&self) -> Result<(), GroupMessageError> {
        if !self.instance_id.is_well_formed() {
            return Err(GroupMessageError::MalformedId(self.instance_id.to_string()));
        }
        if !self.author_id.is_well_formed() {
            return Err(GroupMessageError::MalformedId(self.author_id.to_string()));
        }
        if !is_hex_id(&self.item_id) {
            return Err(GroupMessageError::MalformedId(self.item_id.clone()));
        }
        match &self.group_id {
            Some(g) if !is_hex_id(g) => return Err(GroupMessageError::MalformedId(g.clone())),
            None if self.kind != GroupMessageKind::ReachOut => {
                return Err(GroupMessageError::NoGroup(self.kind.as_str()))
            }
            _ => {}
        }
        match (&self.parent_id, self.kind) {
            (Some(p), GroupMessageKind::CheckInReply) if is_hex_id(p) && *p != self.item_id => {}
            (Some(p), GroupMessageKind::CheckInReply) => {
                return Err(GroupMessageError::MalformedId(p.clone()))
            }
            (None, GroupMessageKind::CheckInReply) | (Some(_), _) => {
                return Err(GroupMessageError::Parent)
            }
            (None, _) => {}
        }
        if let Some(epoch) = self.epoch {
            if !self.kind.may_go_to_group() {
                return Err(GroupMessageError::EpochKind);
            }
            if self.group_id.is_none() || !self.recipients.is_empty() || epoch == 0 {
                return Err(GroupMessageError::EpochRecipients);
            }
            return Ok(());
        }
        if self.recipients.is_empty() {
            return Err(GroupMessageError::NoRecipients);
        }
        if self.recipients.len() > MAX_MESSAGE_RECIPIENTS {
            return Err(GroupMessageError::TooManyRecipients(self.recipients.len()));
        }
        if matches!(
            self.kind,
            GroupMessageKind::ProposalNote | GroupMessageKind::CheckInReply
        ) && self.recipients.len() != 1
        {
            return Err(GroupMessageError::ProposalNoteRecipients);
        }
        for (i, r) in self.recipients.iter().enumerate() {
            if !r.user_id.is_well_formed() {
                return Err(GroupMessageError::MalformedId(r.user_id.to_string()));
            }
            if r.user_id == self.author_id {
                return Err(GroupMessageError::AuthorIsRecipient);
            }
            if i > 0 && self.recipients[i - 1].user_id >= r.user_id {
                return Err(GroupMessageError::NotSorted(r.user_id.clone()));
            }
        }
        Ok(())
    }

    /// Canonical bytes the author signs. Callers must [`validate`] first.
    ///
    /// [`validate`]: Self::validate
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canonical::new(TAG_GROUP_MESSAGE)
            .str(self.instance_id.as_str())
            // Never a valid group id, so "no group" can't collide with one.
            .str(self.group_id.as_deref().unwrap_or(""))
            .str(&self.item_id)
            .str(self.kind.as_str())
            .str(self.author_id.as_str())
            .i64(self.issued_at_ms)
            .u64(self.recipients.len() as u64);
        for r in &self.recipients {
            c = c.str(r.user_id.as_str()).fixed(r.enc_pubkey.as_bytes());
        }
        c = c.fixed(self.body_hash.as_bytes());
        // Appended only when present, so a message without them signs
        // exactly the bytes it always did. The tags keep the two apart.
        if let Some(epoch) = self.epoch {
            c = c.str("epoch").u64(epoch);
        }
        if let Some(parent) = &self.parent_id {
            c = c.str("parent").str(parent);
        }
        c.finish()
    }

    /// Whether `user` is the author or a recipient.
    pub fn is_for(&self, user: &UserId) -> bool {
        &self.author_id == user || self.recipients.iter().any(|r| &r.user_id == user)
    }
}

/// The AAD of a message's encrypted body: it binds the ciphertext to the
/// item, so the instance can't move a body to another message.
pub fn body_aad(instance_id: &InstanceId, item_id: &str) -> Vec<u8> {
    Canonical::new(TAG_GROUP_MESSAGE_BODY)
        .str(instance_id.as_str())
        .str(item_id)
        .finish()
}

/// The AAD under which an epoch key wraps a whole-group message's content
/// key: it binds the wrapped key to the group, the item and the epoch.
pub fn epoch_wrap_aad(
    instance_id: &InstanceId,
    group_id: &str,
    item_id: &str,
    epoch: u64,
) -> Vec<u8> {
    Canonical::new(TAG_GROUP_MESSAGE_EPOCH)
        .str(instance_id.as_str())
        .str(group_id)
        .str(item_id)
        .u64(epoch)
        .finish()
}

/// The plaintext of a message's body, as UTF-8 JSON. Readers ignore fields
/// they don't know.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageText {
    /// At most [`MAX_MESSAGE_CHARS`] characters, not blank.
    pub text: String,
}

impl MessageText {
    pub fn is_valid(&self) -> bool {
        !self.text.trim().is_empty() && self.text.chars().count() <= MAX_MESSAGE_CHARS
    }
}

/// The plaintext of a check-in's body (GROUPS.md §8.6), as UTF-8 JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckInText {
    /// "How's it going?", 1 (struggling) to 5 (going well).
    pub scale: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub went_well: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub was_hard: Option<String>,
    /// "What I'd like from the group".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask: Option<String>,
}

impl CheckInText {
    /// A scale of 1 to 5, and each text, when there is one, not blank and
    /// at most [`MAX_MESSAGE_CHARS`] characters.
    pub fn is_valid(&self) -> bool {
        (1..=5).contains(&self.scale)
            && [&self.went_well, &self.was_hard, &self.ask]
                .into_iter()
                .flatten()
                .all(|t| !t.trim().is_empty() && t.chars().count() <= MAX_MESSAGE_CHARS)
    }
}

/// A message as uploaded and served: the signed header and the encrypted
/// body, if there is one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedGroupMessage {
    pub message: Signed<GroupMessage>,
    #[serde(default)]
    pub body: Option<EncryptedItem>,
}

impl SealedGroupMessage {
    /// [`GroupMessage::validate`], then the body against the signed
    /// header: present exactly when `body_hash` isn't zero, hashing to it,
    /// within [`MAX_MESSAGE_CIPHERTEXT`], with exactly one envelope for each
    /// recipient (under the signed key's id) and one for the author.
    pub fn validate(&self) -> Result<(), GroupMessageError> {
        let m = &self.message.body;
        m.validate()?;
        let Some(body) = &self.body else {
            return if m.body_hash == Hash32::ZERO {
                Ok(())
            } else {
                Err(GroupMessageError::BodyMismatch)
            };
        };
        if m.body_hash == Hash32::ZERO || body.body_hash() != m.body_hash {
            return Err(GroupMessageError::BodyMismatch);
        }
        if body.alg != EncryptedItem::ALG {
            return Err(GroupMessageError::BadBody(body.alg.clone()));
        }
        if body.ciphertext.len() > m.kind.max_ciphertext() {
            return Err(GroupMessageError::BadBody("ciphertext too long".into()));
        }
        if let Some(epoch) = m.epoch {
            // One envelope: the content key wrapped with the epoch key.
            return match body.envelopes.as_slice() {
                [e] if e.recipient == m.author_id
                    && e.key_id == epoch_key_id(epoch)
                    && e.wrapped_key.len() == EPOCH_WRAPPED_KEY_LEN =>
                {
                    Ok(())
                }
                _ => Err(GroupMessageError::Envelopes),
            };
        }
        if body.envelopes.len() != m.recipients.len() + 1 {
            return Err(GroupMessageError::Envelopes);
        }
        let mut author_copies = 0;
        for e in &body.envelopes {
            if e.recipient == m.author_id {
                author_copies += 1;
                continue;
            }
            let Some(r) = m.recipients.iter().find(|r| r.user_id == e.recipient) else {
                return Err(GroupMessageError::Envelopes);
            };
            if e.key_id != key_id(r.enc_pubkey.as_bytes()) {
                return Err(GroupMessageError::Envelopes);
            }
            if body
                .envelopes
                .iter()
                .filter(|o| o.recipient == e.recipient)
                .count()
                != 1
            {
                return Err(GroupMessageError::Envelopes);
            }
        }
        if author_copies != 1 {
            return Err(GroupMessageError::Envelopes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Signature;
    use crate::event::Envelope;
    use crate::Nonce24;

    const ITEM: &str = "0123456789abcdef0123456789abcdef";
    const GROUP: &str = "fedcba9876543210fedcba9876543210";

    fn msg(recipients: &[&str]) -> GroupMessage {
        GroupMessage {
            instance_id: InstanceId::new("inst_a"),
            group_id: Some(GROUP.into()),
            item_id: ITEM.into(),
            kind: GroupMessageKind::ReachOut,
            author_id: UserId::new("usr_m"),
            issued_at_ms: 1,
            recipients: recipients
                .iter()
                .map(|r| MessageRecipient {
                    user_id: UserId::new(*r),
                    enc_pubkey: EncPublicKey([2; 32]),
                })
                .collect(),
            body_hash: Hash32::ZERO,
            epoch: None,
            parent_id: None,
        }
    }

    #[test]
    fn validation() {
        assert_eq!(msg(&["usr_a", "usr_b"]).validate(), Ok(()));
        assert_eq!(msg(&[]).validate(), Err(GroupMessageError::NoRecipients));
        assert!(matches!(
            msg(&["usr_b", "usr_a"]).validate(),
            Err(GroupMessageError::NotSorted(_))
        ));
        assert!(matches!(
            msg(&["usr_a", "usr_a"]).validate(),
            Err(GroupMessageError::NotSorted(_))
        ));
        assert_eq!(
            msg(&["usr_m"]).validate(),
            Err(GroupMessageError::AuthorIsRecipient)
        );
        let ids: Vec<String> = (0..=MAX_MESSAGE_RECIPIENTS)
            .map(|i| format!("usr_{i:03}"))
            .collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(
            msg(&refs).validate(),
            Err(GroupMessageError::TooManyRecipients(33))
        );
        assert_eq!(msg(&refs[..32]).validate(), Ok(()));
        let mut m = msg(&["usr_a"]);
        m.item_id = "msg_1".into();
        assert!(matches!(
            m.validate(),
            Err(GroupMessageError::MalformedId(_))
        ));
        let mut m = msg(&["usr_a"]);
        m.group_id = Some("../x".into());
        assert!(matches!(
            m.validate(),
            Err(GroupMessageError::MalformedId(_))
        ));
        let mut m = msg(&["usr_a"]);
        m.group_id = None;
        assert_eq!(m.validate(), Ok(()), "a reach out outside any group");
        m.kind = GroupMessageKind::JoinRequestNote;
        assert!(matches!(m.validate(), Err(GroupMessageError::NoGroup(_))));
        let mut m = msg(&["usr_a", "usr_b"]);
        m.kind = GroupMessageKind::ProposalNote;
        assert_eq!(m.validate(), Err(GroupMessageError::ProposalNoteRecipients));
    }

    #[test]
    fn signing_bytes_bind_every_field() {
        let base = msg(&["usr_a"]);
        let b = base.signing_bytes();
        let mut v = Vec::new();
        let mut m = base.clone();
        m.instance_id = InstanceId::new("inst_b");
        v.push(m);
        let mut m = base.clone();
        m.group_id = None;
        v.push(m);
        let mut m = base.clone();
        m.group_id = Some("00000000000000000000000000000000".into());
        v.push(m);
        let mut m = base.clone();
        m.item_id = "11111111111111111111111111111111".into();
        v.push(m);
        let mut m = base.clone();
        m.kind = GroupMessageKind::ProposalNote;
        v.push(m);
        let mut m = base.clone();
        m.author_id = UserId::new("usr_n");
        v.push(m);
        let mut m = base.clone();
        m.issued_at_ms = 2;
        v.push(m);
        let mut m = base.clone();
        m.recipients[0].user_id = UserId::new("usr_b");
        v.push(m);
        let mut m = base.clone();
        m.recipients[0].enc_pubkey = EncPublicKey([3; 32]);
        v.push(m);
        let mut m = base.clone();
        m.recipients.clear();
        v.push(m);
        let mut m = base.clone();
        m.body_hash = Hash32([1; 32]);
        v.push(m);
        for m in v {
            assert_ne!(m.signing_bytes(), b, "{m:?}");
        }
        assert!(b.starts_with(b"faro/group-message/v1\0"));
    }

    #[test]
    fn whole_group_and_reply_rules() {
        // Whole group: an epoch, no recipients, a group, a reach out or a check-in.
        let mut m = msg(&[]);
        m.epoch = Some(2);
        assert_eq!(m.validate(), Ok(()));
        m.kind = GroupMessageKind::CheckIn;
        assert_eq!(m.validate(), Ok(()));
        m.epoch = Some(0);
        assert_eq!(m.validate(), Err(GroupMessageError::EpochRecipients));
        m.epoch = Some(2);
        m.group_id = None;
        assert!(matches!(m.validate(), Err(GroupMessageError::NoGroup(_))));
        m.group_id = Some(GROUP.into());
        m.recipients = msg(&["usr_a"]).recipients;
        assert_eq!(m.validate(), Err(GroupMessageError::EpochRecipients));
        let mut m = msg(&[]);
        m.epoch = Some(2);
        m.kind = GroupMessageKind::ProposalNote;
        assert_eq!(m.validate(), Err(GroupMessageError::EpochKind));
        m.kind = GroupMessageKind::CheckInReply;
        m.parent_id = Some(ITEM.replace('0', "1"));
        assert_eq!(m.validate(), Err(GroupMessageError::EpochKind));
        // A check-in to named people needs recipients, like any message.
        let mut m = msg(&[]);
        m.kind = GroupMessageKind::CheckIn;
        assert_eq!(m.validate(), Err(GroupMessageError::NoRecipients));
        // A reply has one recipient and names its parent, and nothing else has a parent.
        let mut m = msg(&["usr_a"]);
        m.kind = GroupMessageKind::CheckInReply;
        assert_eq!(m.validate(), Err(GroupMessageError::Parent));
        m.parent_id = Some(ITEM.into());
        assert!(matches!(
            m.validate(),
            Err(GroupMessageError::MalformedId(_))
        ));
        m.parent_id = Some(GROUP.into());
        assert_eq!(m.validate(), Ok(()));
        m.recipients = msg(&["usr_a", "usr_b"]).recipients;
        assert_eq!(m.validate(), Err(GroupMessageError::ProposalNoteRecipients));
        let mut m = msg(&["usr_a"]);
        m.parent_id = Some(GROUP.into());
        assert_eq!(m.validate(), Err(GroupMessageError::Parent));
        // Epoch and parent are signed, and a message without them signs as before.
        let base = msg(&["usr_a"]);
        let mut e = base.clone();
        e.epoch = Some(1);
        let mut p = base.clone();
        p.kind = GroupMessageKind::CheckInReply;
        let mut p2 = p.clone();
        p.parent_id = Some(GROUP.into());
        p2.parent_id = Some(ITEM.replace('0', "1"));
        let all = [
            base.signing_bytes(),
            e.signing_bytes(),
            p.signing_bytes(),
            p2.signing_bytes(),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
        e.epoch = Some(2);
        assert_ne!(e.signing_bytes(), all[1]);
    }

    #[test]
    fn whole_group_body_has_one_epoch_envelope() {
        let mut m = msg(&[]);
        m.epoch = Some(3);
        m.kind = GroupMessageKind::CheckIn;
        let mut b = body(&[("usr_m", &[0])]);
        b.envelopes[0].key_id = epoch_key_id(3);
        b.envelopes[0].wrapped_key = vec![0; EPOCH_WRAPPED_KEY_LEN];
        m.body_hash = b.body_hash();
        let sealed = |m: &GroupMessage, b: &EncryptedItem| SealedGroupMessage {
            message: Signed {
                body: m.clone(),
                sig: Signature([0; 64]),
            },
            body: Some(b.clone()),
        };
        assert_eq!(sealed(&m, &b).validate(), Ok(()));
        for edit in [
            (|b: &mut EncryptedItem| b.envelopes[0].key_id = epoch_key_id(4))
                as fn(&mut EncryptedItem),
            |b| b.envelopes[0].recipient = UserId::new("usr_x"),
            |b| b.envelopes[0].wrapped_key = vec![0; 48],
            |b| b.envelopes.push(b.envelopes[0].clone()),
        ] {
            let mut bad = b.clone();
            edit(&mut bad);
            m.body_hash = bad.body_hash();
            assert_eq!(
                sealed(&m, &bad).validate(),
                Err(GroupMessageError::Envelopes)
            );
        }
        // A check-in's ciphertext may be longer than a note's, but not unbounded.
        let mut long = b.clone();
        long.ciphertext = vec![1; MAX_MESSAGE_CIPHERTEXT + 1];
        m.body_hash = long.body_hash();
        assert_eq!(sealed(&m, &long).validate(), Ok(()));
        long.ciphertext = vec![1; MAX_CHECK_IN_CIPHERTEXT + 1];
        m.body_hash = long.body_hash();
        assert!(matches!(
            sealed(&m, &long).validate(),
            Err(GroupMessageError::BadBody(_))
        ));
    }

    #[test]
    fn check_in_text_limits() {
        let ok = CheckInText {
            scale: 3,
            went_well: Some("walked".into()),
            was_hard: None,
            ask: None,
        };
        assert!(ok.is_valid());
        for scale in [0, 6] {
            assert!(!CheckInText {
                scale,
                ..ok.clone()
            }
            .is_valid());
        }
        let blank = CheckInText {
            was_hard: Some("  ".into()),
            ..ok.clone()
        };
        assert!(!blank.is_valid());
        let long = CheckInText {
            ask: Some("x".repeat(MAX_MESSAGE_CHARS + 1)),
            ..ok
        };
        assert!(!long.is_valid());
        let v = serde_json::to_value(CheckInText {
            scale: 2,
            went_well: None,
            was_hard: None,
            ask: None,
        })
        .unwrap();
        assert_eq!(v, serde_json::json!({"scale": 2}));
    }

    #[test]
    fn kinds_round_trip() {
        for k in GroupMessageKind::ALL {
            assert_eq!(GroupMessageKind::parse(k.as_str()), Some(k));
            let j = serde_json::to_string(&k).unwrap();
            assert_eq!(j, format!("\"{}\"", k.as_str()));
        }
    }

    fn body(env: &[(&str, &[u8])]) -> EncryptedItem {
        EncryptedItem {
            alg: EncryptedItem::ALG.into(),
            nonce: Nonce24([0; 24]),
            ciphertext: vec![1, 2, 3],
            envelopes: env
                .iter()
                .map(|(r, k)| Envelope {
                    recipient: UserId::new(*r),
                    key_id: key_id(k),
                    wrapped_key: vec![0; 48],
                })
                .collect(),
        }
    }

    #[test]
    fn body_must_match_the_header() {
        let rk = [2u8; 32];
        let ak = [9u8; 32];
        let mut m = msg(&["usr_a"]);
        let b = body(&[("usr_a", &rk), ("usr_m", &ak)]);
        m.body_hash = b.body_hash();
        let sealed = |m: &GroupMessage, b: Option<EncryptedItem>| SealedGroupMessage {
            message: Signed {
                body: m.clone(),
                sig: Signature([0; 64]),
            },
            body: b,
        };
        assert_eq!(sealed(&m, Some(b.clone())).validate(), Ok(()));
        assert_eq!(
            sealed(&m, None).validate(),
            Err(GroupMessageError::BodyMismatch)
        );
        let mut other = b.clone();
        other.ciphertext.push(0);
        assert_eq!(
            sealed(&m, Some(other)).validate(),
            Err(GroupMessageError::BodyMismatch)
        );
        // No author copy, a stranger's envelope, a key other than the signed one.
        for env in [
            vec![("usr_a", &rk[..])],
            vec![("usr_a", &rk[..]), ("usr_m", &ak[..]), ("usr_x", &rk[..])],
            vec![("usr_a", &ak[..]), ("usr_m", &ak[..])],
            vec![("usr_x", &rk[..]), ("usr_m", &ak[..])],
            vec![("usr_m", &ak[..]), ("usr_m", &ak[..])],
        ] {
            let mut bb = body(&env);
            bb.ciphertext = b.ciphertext.clone();
            assert_eq!(
                sealed(&m, Some(bb)).validate(),
                Err(GroupMessageError::Envelopes),
                "{env:?}"
            );
        }
        let mut empty = m.clone();
        empty.body_hash = Hash32::ZERO;
        assert_eq!(sealed(&empty, None).validate(), Ok(()));
        assert_eq!(
            sealed(&empty, Some(b)).validate(),
            Err(GroupMessageError::BodyMismatch)
        );
    }

    #[test]
    fn json_shape() {
        let mut m = msg(&["usr_a"]);
        m.group_id = None;
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["kind"], "reach_out");
        assert!(v["group_id"].is_null());
        let back: GroupMessage = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn text_limits() {
        assert!(MessageText { text: "hi".into() }.is_valid());
        assert!(!MessageText { text: "  ".into() }.is_valid());
        assert!(MessageText {
            text: "é".repeat(MAX_MESSAGE_CHARS)
        }
        .is_valid());
        assert!(!MessageText {
            text: "é".repeat(MAX_MESSAGE_CHARS + 1)
        }
        .is_valid());
    }
}
