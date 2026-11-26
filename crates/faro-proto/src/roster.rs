//! The **group roster log** (docs/PROTOCOL.md §10, GROUPS.md §10.3): who is
//! in a group, with which keys and roles, as a facilitator-signed,
//! hash-chained log of changes, plus signed snapshots and per-epoch group
//! keys.
//!
//! It is built like the recipient manifest (PROTOCOL.md §5.1), so that the
//! instance stores and serves it but can't add a reader, roll it back, or
//! fork it unnoticed:
//!
//! * Every [`RosterEntry`] names its group, its `seq` (0, 1, 2, …) and the
//!   chain hash of the previous entry (`prev_hash`; the genesis hash for
//!   `seq = 0`). Its identity is `BLAKE3(signing_bytes)`.
//! * An entry is valid only if its `signer` was a facilitator with a
//!   signing key in the roster **as of the previous entry**. The first
//!   entry is signed by the group's creator, who joins in it as a
//!   facilitator with that key.
//! * Every join, leave, removal and key change rotates the **epoch key** in
//!   the same entry. The entry carries only a commitment to the new key
//!   ([`epoch_key_check`]); the key itself is sealed to each participant
//!   separately and checked against the commitment when opened.
//! * A [`RosterSnapshot`] is the full roster at one `seq`, signed by a
//!   facilitator in it, so a new joiner doesn't replay the whole history.
//!
//! This module is the structural half (no keys, no RNG). Signature and key
//! checks, sealing and opening are in `faro_crypto::roster`.

use crate::encoding::{Canonical, EncPublicKey, Hash32, SignPublicKey};
use crate::ids::{InstanceId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const TAG_ROSTER_ENTRY: &str = "faro/group-roster/v1";
const TAG_ROSTER_GENESIS: &str = "faro/group-roster-genesis/v1";
const TAG_ROSTER_SNAPSHOT: &str = "faro/group-roster-snapshot/v1";
const TAG_EPOCH_KEY: &str = "faro/group-epoch-key/v1";
const TAG_GROUP_SAFETY: &str = "faro/group-safety-code/v1";

/// Changes in one entry. Bounds the work one hostile entry can cause; a
/// facilitator's client splits larger batches over several entries.
pub const MAX_ROSTER_CHANGES: usize = 256;
/// Participants in one snapshot (a sanity bound: the 8 MiB download cap,
/// [`MAX_ROSTER_SNAPSHOT_BYTES`], is reached first).
pub const MAX_ROSTER_MEMBERS: usize = 100_000;
/// A facilitator's client signs a snapshot once the head is this many
/// entries past the last one (GROUPS.md Appendix A).
pub const ROSTER_SNAPSHOT_INTERVAL: u64 = 256;
/// Clients refuse a snapshot download larger than this before parsing it
/// (roughly 40,000 participants).
pub const MAX_ROSTER_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
/// Entries per page of `GET /v1/groups/{id}/roster`.
pub const ROSTER_PAGE: usize = 100;
/// An epoch key sealed to one participant: `crypto_box_seal` of 32 bytes.
pub const SEALED_EPOCH_KEY_LEN: usize = 32 + 16 + 32;

/// A participant's role in the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Facilitator,
    Participant,
}

impl GroupRole {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupRole::Facilitator => "facilitator",
            GroupRole::Participant => "participant",
        }
    }
}

/// `prefix`-less ids such as group ids: 1 to 64 of `[A-Za-z0-9_-]`.
pub fn is_well_formed_group_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One change in a [`RosterEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RosterChange {
    /// Someone joins, with their keys. `sign_pubkey` is set for people who
    /// have a signing key (members, and facilitators who made one).
    Join {
        user_id: UserId,
        role: GroupRole,
        enc_pubkey: EncPublicKey,
        #[serde(default)]
        sign_pubkey: Option<SignPublicKey>,
    },
    /// They left.
    Leave { user_id: UserId },
    /// A facilitator removed them (or their account was deleted).
    Remove { user_id: UserId },
    /// Their role changed.
    Role { user_id: UserId, role: GroupRole },
    /// Their keys changed (a new encryption key, or a signing key made when
    /// they became a facilitator).
    Keys {
        user_id: UserId,
        enc_pubkey: EncPublicKey,
        #[serde(default)]
        sign_pubkey: Option<SignPublicKey>,
    },
}

impl RosterChange {
    pub fn user_id(&self) -> &UserId {
        match self {
            RosterChange::Join { user_id, .. }
            | RosterChange::Leave { user_id }
            | RosterChange::Remove { user_id }
            | RosterChange::Role { user_id, .. }
            | RosterChange::Keys { user_id, .. } => user_id,
        }
    }

    /// Whether this change must rotate the epoch key in the same entry:
    /// everything that changes who can open it.
    pub fn needs_rotation(&self) -> bool {
        !matches!(self, RosterChange::Role { .. })
    }

    fn encode(&self, c: Canonical) -> Canonical {
        match self {
            RosterChange::Join {
                user_id,
                role,
                enc_pubkey,
                sign_pubkey,
            } => c
                .str("join")
                .str(user_id.as_str())
                .str(role.as_str())
                .fixed(enc_pubkey.as_bytes())
                .bytes(opt_key(sign_pubkey)),
            RosterChange::Leave { user_id } => c.str("leave").str(user_id.as_str()),
            RosterChange::Remove { user_id } => c.str("remove").str(user_id.as_str()),
            RosterChange::Role { user_id, role } => {
                c.str("role").str(user_id.as_str()).str(role.as_str())
            }
            RosterChange::Keys {
                user_id,
                enc_pubkey,
                sign_pubkey,
            } => c
                .str("keys")
                .str(user_id.as_str())
                .fixed(enc_pubkey.as_bytes())
                .bytes(opt_key(sign_pubkey)),
        }
    }
}

/// An optional key is a length-prefixed byte string of 0 or 32 bytes.
fn opt_key(k: &Option<SignPublicKey>) -> &[u8] {
    k.as_ref().map(|k| k.as_bytes().as_slice()).unwrap_or(&[])
}

/// A new epoch key, committed to in the entry that rotates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRotation {
    /// The previous epoch + 1 (the first entry starts epoch 1).
    pub epoch: u64,
    /// [`epoch_key_check`] of the new key.
    pub key_check: Hash32,
}

/// One facilitator-signed change set. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    pub instance_id: InstanceId,
    pub group_id: String,
    pub seq: u64,
    pub prev_hash: Hash32,
    /// The signer's clock, Unix ms. Informational: not checked for order.
    pub at_ms: i64,
    pub signer: UserId,
    /// Sorted strictly by `user_id`: at most one change per person.
    pub changes: Vec<RosterChange>,
    #[serde(default)]
    pub epoch: Option<EpochRotation>,
}

/// Why an entry, a snapshot or a head is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    #[error("malformed roster document: {0}")]
    Malformed(String),
    #[error("the roster document is for another instance or group")]
    WrongGroup,
    #[error("rollback: the roster is at seq {have}, this is seq {got}")]
    Rollback { have: u64, got: u64 },
    #[error("an entry is missing: expected seq {expected}, got {got}")]
    Gap { expected: u64, got: u64 },
    #[error("fork at seq {seq}: the roster's history was changed")]
    Fork { seq: u64 },
    #[error("{0} was not a facilitator")]
    NotAFacilitator(UserId),
    #[error("{0} has no signing key in the roster")]
    NoSigningKey(UserId),
    #[error("the signature does not verify")]
    BadSignature,
    #[error("unusable key for {0}")]
    WeakKey(UserId),
    #[error("{0} is already in the roster")]
    AlreadyMember(UserId),
    #[error("{0} is not in the roster")]
    NotAMember(UserId),
    #[error("the change for {0} changes nothing")]
    NoChange(UserId),
    #[error("the epoch must be {expected}, not {got}")]
    EpochNotNext { expected: u64, got: u64 },
    #[error("invalid first entry: {0}")]
    BadGenesis(&'static str),
}

fn malformed(s: impl Into<String>) -> RosterError {
    RosterError::Malformed(s.into())
}

fn check_ids(instance: &InstanceId, group: &str, signer: &UserId) -> Result<(), RosterError> {
    if !instance.is_well_formed() {
        return Err(malformed("instance id"));
    }
    if !is_well_formed_group_id(group) {
        return Err(malformed("group id"));
    }
    if !signer.is_well_formed() {
        return Err(malformed("signer id"));
    }
    Ok(())
}

impl RosterEntry {
    /// The structural rules that need no keys and no roster: ids, bounds,
    /// sort order, and that every change that needs a rotation has one.
    pub fn validate(&self) -> Result<(), RosterError> {
        check_ids(&self.instance_id, &self.group_id, &self.signer)?;
        if self.changes.len() > MAX_ROSTER_CHANGES {
            return Err(malformed(format!(
                "more than {MAX_ROSTER_CHANGES} changes in one entry"
            )));
        }
        if self.changes.is_empty() && self.epoch.is_none() {
            return Err(malformed("an entry changes nothing"));
        }
        for (i, c) in self.changes.iter().enumerate() {
            if !c.user_id().is_well_formed() {
                return Err(malformed("user id"));
            }
            if i > 0 && self.changes[i - 1].user_id() >= c.user_id() {
                return Err(malformed(
                    "changes are not sorted by user, or name someone twice",
                ));
            }
        }
        match self.epoch {
            Some(e) if e.epoch == 0 || e.epoch == u64::MAX => Err(malformed("epoch out of range")),
            None if self.changes.iter().any(RosterChange::needs_rotation) => Err(malformed(
                "joins, leaves, removals and key changes must rotate the epoch key",
            )),
            _ => Ok(()),
        }
    }

    /// Canonical bytes the signer signs. Callers must [`validate`] first.
    ///
    /// [`validate`]: Self::validate
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canonical::new(TAG_ROSTER_ENTRY)
            .str(self.instance_id.as_str())
            .str(&self.group_id)
            .u64(self.seq)
            .fixed(self.prev_hash.as_bytes())
            .i64(self.at_ms)
            .str(self.signer.as_str())
            .u64(self.changes.len() as u64);
        for ch in &self.changes {
            c = ch.encode(c);
        }
        match &self.epoch {
            // Option<u64>: n + 1, then the commitment.
            Some(e) => c
                .u64(e.epoch.saturating_add(1))
                .fixed(e.key_check.as_bytes()),
            None => c.u64(0),
        }
        .finish()
    }

    /// Chain hash: `BLAKE3(signing_bytes)`. The next entry's `prev_hash`.
    pub fn hash(&self) -> Hash32 {
        Hash32::of(&self.signing_bytes())
    }

    pub fn head(&self) -> RosterHead {
        RosterHead {
            seq: self.seq,
            hash: self.hash(),
        }
    }
}

/// `prev_hash` of the first entry: binds the log to one instance and group.
pub fn genesis_prev_hash(instance: &InstanceId, group: &str) -> Hash32 {
    Hash32::of(
        &Canonical::new(TAG_ROSTER_GENESIS)
            .str(instance.as_str())
            .str(group)
            .finish(),
    )
}

/// The commitment to an epoch key that a roster entry carries. Whoever opens
/// a sealed epoch key checks it against this, so the instance can't hand
/// anyone a key of its own.
pub fn epoch_key_check(instance: &InstanceId, group: &str, epoch: u64, key: &[u8; 32]) -> Hash32 {
    Hash32::of(
        &Canonical::new(TAG_EPOCH_KEY)
            .str(instance.as_str())
            .str(group)
            .u64(epoch)
            .fixed(key)
            .finish(),
    )
}

/// The **group safety code**: a fingerprint of the roster head that people
/// compare in person (GROUPS.md §10.3 item 5). Same format as the ally
/// safety code: 12 groups of 5 digits.
pub fn group_safety_code(instance: &InstanceId, group: &str, head: &RosterHead) -> String {
    let h = Hash32::of(
        &Canonical::new(TAG_GROUP_SAFETY)
            .str(instance.as_str())
            .str(group)
            .u64(head.seq)
            .fixed(head.hash.as_bytes())
            .finish(),
    );
    crate::keys::digits_from_hash(&h)
}

/// A pointer to one exact entry: what clients persist as their checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RosterHead {
    pub seq: u64,
    pub hash: Hash32,
}

/// One participant in a [`RosterState`] or [`RosterSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterMember {
    pub user_id: UserId,
    pub role: GroupRole,
    pub enc_pubkey: EncPublicKey,
    #[serde(default)]
    pub sign_pubkey: Option<SignPublicKey>,
}

/// The full roster at one `seq`, signed by a facilitator in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterSnapshot {
    pub instance_id: InstanceId,
    pub group_id: String,
    /// The entry this snapshot is the state after.
    pub seq: u64,
    /// That entry's chain hash.
    pub head: Hash32,
    pub at_ms: i64,
    pub signer: UserId,
    pub epoch: u64,
    pub epoch_key_check: Hash32,
    /// Sorted strictly by `user_id`.
    pub members: Vec<RosterMember>,
}

impl RosterSnapshot {
    pub fn validate(&self) -> Result<(), RosterError> {
        check_ids(&self.instance_id, &self.group_id, &self.signer)?;
        if self.members.len() > MAX_ROSTER_MEMBERS {
            return Err(malformed("too many members"));
        }
        if self.epoch == 0 {
            return Err(malformed("a snapshot's epoch is at least 1"));
        }
        for (i, m) in self.members.iter().enumerate() {
            if !m.user_id.is_well_formed() {
                return Err(malformed("user id"));
            }
            if i > 0 && self.members[i - 1].user_id >= m.user_id {
                return Err(malformed("members are not sorted by user, or listed twice"));
            }
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut c = Canonical::new(TAG_ROSTER_SNAPSHOT)
            .str(self.instance_id.as_str())
            .str(&self.group_id)
            .u64(self.seq)
            .fixed(self.head.as_bytes())
            .i64(self.at_ms)
            .str(self.signer.as_str())
            .u64(self.epoch)
            .fixed(self.epoch_key_check.as_bytes())
            .u64(self.members.len() as u64);
        for m in &self.members {
            c = c
                .str(m.user_id.as_str())
                .str(m.role.as_str())
                .fixed(m.enc_pubkey.as_bytes())
                .bytes(opt_key(&m.sign_pubkey));
        }
        c.finish()
    }

    pub fn head(&self) -> RosterHead {
        RosterHead {
            seq: self.seq,
            hash: self.head,
        }
    }

    /// The key the snapshot must be signed with: its signer's, who must be a
    /// facilitator with a signing key in it. Call after [`Self::validate`].
    pub fn signer_key(&self) -> Result<SignPublicKey, RosterError> {
        let m = self
            .members
            .binary_search_by(|m| m.user_id.cmp(&self.signer))
            .map(|i| &self.members[i])
            .map_err(|_| RosterError::NotAMember(self.signer.clone()))?;
        if m.role != GroupRole::Facilitator {
            return Err(RosterError::NotAFacilitator(self.signer.clone()));
        }
        m.sign_pubkey
            .ok_or_else(|| RosterError::NoSigningKey(self.signer.clone()))
    }
}

/// How a head the instance reports compares with a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadStatus {
    /// The same entry.
    Same,
    /// Further along: fetch the entries after the checkpoint.
    Ahead,
}

/// The roster as of one entry: what clients keep and apply entries to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterState {
    pub instance_id: InstanceId,
    pub group_id: String,
    /// The `seq` the next entry must have (0 before the first entry).
    pub next_seq: u64,
    /// The last entry's chain hash, or the genesis hash before the first.
    pub head: Hash32,
    /// The current epoch (0 before the first entry).
    pub epoch: u64,
    pub epoch_key_check: Hash32,
    pub members: BTreeMap<UserId, RosterMember>,
}

impl RosterState {
    /// An empty roster, before the first entry.
    pub fn new(instance_id: InstanceId, group_id: String) -> Self {
        let head = genesis_prev_hash(&instance_id, &group_id);
        RosterState {
            instance_id,
            group_id,
            next_seq: 0,
            head,
            epoch: 0,
            epoch_key_check: Hash32::ZERO,
            members: BTreeMap::new(),
        }
    }

    /// The state a (validated, verified) snapshot describes.
    pub fn from_snapshot(s: &RosterSnapshot) -> Self {
        RosterState {
            instance_id: s.instance_id.clone(),
            group_id: s.group_id.clone(),
            next_seq: s.seq.saturating_add(1),
            head: s.head,
            epoch: s.epoch,
            epoch_key_check: s.epoch_key_check,
            members: s
                .members
                .iter()
                .map(|m| (m.user_id.clone(), m.clone()))
                .collect(),
        }
    }

    /// The last applied entry, if any.
    pub fn checkpoint(&self) -> Option<RosterHead> {
        self.next_seq.checked_sub(1).map(|seq| RosterHead {
            seq,
            hash: self.head,
        })
    }

    /// The snapshot of this state, to be signed by `signer`.
    pub fn snapshot(&self, at_ms: i64, signer: UserId) -> Option<RosterSnapshot> {
        let head = self.checkpoint()?;
        Some(RosterSnapshot {
            instance_id: self.instance_id.clone(),
            group_id: self.group_id.clone(),
            seq: head.seq,
            head: head.hash,
            at_ms,
            signer,
            epoch: self.epoch,
            epoch_key_check: self.epoch_key_check,
            members: self.members.values().cloned().collect(),
        })
    }

    /// Whether `s` describes exactly this state (ignoring who signed it and when).
    pub fn matches_snapshot(&self, s: &RosterSnapshot) -> bool {
        self.checkpoint() == Some(s.head())
            && s.instance_id == self.instance_id
            && s.group_id == self.group_id
            && s.epoch == self.epoch
            && s.epoch_key_check == self.epoch_key_check
            && s.members.len() == self.members.len()
            && s.members
                .iter()
                .zip(self.members.values())
                .all(|(a, b)| a == b)
    }

    pub fn member(&self, user: &UserId) -> Option<&RosterMember> {
        self.members.get(user)
    }

    pub fn is_facilitator(&self, user: &UserId) -> bool {
        self.member(user)
            .is_some_and(|m| m.role == GroupRole::Facilitator)
    }

    /// Compare a head the instance reports with this state's checkpoint:
    /// an older `seq` is a rollback, the same `seq` with another hash a fork.
    pub fn check_head(&self, head: &RosterHead) -> Result<HeadStatus, RosterError> {
        match self.checkpoint() {
            None => Ok(HeadStatus::Ahead),
            Some(c) if head.seq < c.seq => Err(RosterError::Rollback {
                have: c.seq,
                got: head.seq,
            }),
            Some(c) if head.seq == c.seq && head.hash != c.hash => {
                Err(RosterError::Fork { seq: c.seq })
            }
            Some(c) if head.seq == c.seq => Ok(HeadStatus::Same),
            Some(_) => Ok(HeadStatus::Ahead),
        }
    }

    /// Every check of `entry` against this state that needs no
    /// cryptography: group, chain position, signer, each change, epoch.
    /// Returns the key the entry's signature must verify against. Call
    /// [`RosterEntry::validate`] first.
    pub fn check(&self, entry: &RosterEntry) -> Result<SignPublicKey, RosterError> {
        if entry.instance_id != self.instance_id || entry.group_id != self.group_id {
            return Err(RosterError::WrongGroup);
        }
        if entry.seq < self.next_seq {
            return Err(RosterError::Rollback {
                have: self.next_seq.saturating_sub(1),
                got: entry.seq,
            });
        }
        if entry.seq > self.next_seq {
            return Err(RosterError::Gap {
                expected: self.next_seq,
                got: entry.seq,
            });
        }
        if entry.prev_hash != self.head {
            return Err(RosterError::Fork { seq: entry.seq });
        }
        let expected_epoch = self.epoch.saturating_add(1);
        if let Some(e) = entry.epoch {
            if e.epoch != expected_epoch {
                return Err(RosterError::EpochNotNext {
                    expected: expected_epoch,
                    got: e.epoch,
                });
            }
        }
        let key = if self.next_seq == 0 {
            self.genesis_signer_key(entry)?
        } else {
            let m = self
                .member(&entry.signer)
                .ok_or_else(|| RosterError::NotAFacilitator(entry.signer.clone()))?;
            if m.role != GroupRole::Facilitator {
                return Err(RosterError::NotAFacilitator(entry.signer.clone()));
            }
            m.sign_pubkey
                .ok_or_else(|| RosterError::NoSigningKey(entry.signer.clone()))?
        };
        for c in &entry.changes {
            let present = self.member(c.user_id());
            match (c, present) {
                (RosterChange::Join { user_id, .. }, Some(_)) => {
                    return Err(RosterError::AlreadyMember(user_id.clone()))
                }
                (RosterChange::Join { .. }, None) => {}
                (_, None) => return Err(RosterError::NotAMember(c.user_id().clone())),
                (RosterChange::Leave { .. } | RosterChange::Remove { .. }, Some(_)) => {}
                (RosterChange::Role { user_id, role }, Some(m)) => {
                    if m.role == *role {
                        return Err(RosterError::NoChange(user_id.clone()));
                    }
                }
                (
                    RosterChange::Keys {
                        user_id,
                        enc_pubkey,
                        sign_pubkey,
                    },
                    Some(m),
                ) => {
                    if m.enc_pubkey == *enc_pubkey && m.sign_pubkey == *sign_pubkey {
                        return Err(RosterError::NoChange(user_id.clone()));
                    }
                }
            }
        }
        Ok(key)
    }

    /// The first entry: only joins, the signer among them as a facilitator
    /// with a signing key (the key it is signed with), and epoch 1.
    fn genesis_signer_key(&self, entry: &RosterEntry) -> Result<SignPublicKey, RosterError> {
        if entry.epoch.is_none() {
            return Err(RosterError::BadGenesis("it must start epoch 1"));
        }
        let mut key = None;
        for c in &entry.changes {
            match c {
                RosterChange::Join {
                    user_id,
                    role,
                    sign_pubkey,
                    ..
                } => {
                    if *user_id == entry.signer {
                        if *role != GroupRole::Facilitator {
                            return Err(RosterError::BadGenesis(
                                "its signer must join as a facilitator",
                            ));
                        }
                        key = *sign_pubkey;
                    }
                }
                _ => return Err(RosterError::BadGenesis("it may only add people")),
            }
        }
        key.ok_or(RosterError::BadGenesis(
            "its signer must join in it with a signing key",
        ))
    }

    /// Apply an entry that passed [`Self::check`] and its signature check.
    pub fn apply_checked(&mut self, entry: &RosterEntry) {
        for c in &entry.changes {
            match c {
                RosterChange::Join {
                    user_id,
                    role,
                    enc_pubkey,
                    sign_pubkey,
                } => {
                    self.members.insert(
                        user_id.clone(),
                        RosterMember {
                            user_id: user_id.clone(),
                            role: *role,
                            enc_pubkey: *enc_pubkey,
                            sign_pubkey: *sign_pubkey,
                        },
                    );
                }
                RosterChange::Leave { user_id } | RosterChange::Remove { user_id } => {
                    self.members.remove(user_id);
                }
                RosterChange::Role { user_id, role } => {
                    if let Some(m) = self.members.get_mut(user_id) {
                        m.role = *role;
                    }
                }
                RosterChange::Keys {
                    user_id,
                    enc_pubkey,
                    sign_pubkey,
                } => {
                    if let Some(m) = self.members.get_mut(user_id) {
                        m.enc_pubkey = *enc_pubkey;
                        m.sign_pubkey = *sign_pubkey;
                    }
                }
            }
        }
        if let Some(e) = entry.epoch {
            self.epoch = e.epoch;
            self.epoch_key_check = e.key_check;
        }
        self.next_seq = entry.seq.saturating_add(1);
        self.head = entry.hash();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst() -> InstanceId {
        InstanceId::new("inst_a")
    }

    fn join(u: &str, role: GroupRole, sign: Option<u8>) -> RosterChange {
        RosterChange::Join {
            user_id: UserId::new(u),
            role,
            enc_pubkey: EncPublicKey([9; 32]),
            sign_pubkey: sign.map(|b| SignPublicKey([b; 32])),
        }
    }

    fn rot(epoch: u64) -> Option<EpochRotation> {
        Some(EpochRotation {
            epoch,
            key_check: Hash32([epoch as u8; 32]),
        })
    }

    fn genesis() -> RosterEntry {
        RosterEntry {
            instance_id: inst(),
            group_id: "g1".into(),
            seq: 0,
            prev_hash: genesis_prev_hash(&inst(), "g1"),
            at_ms: 1,
            signer: UserId::new("usr_f"),
            changes: vec![
                join("usr_a", GroupRole::Participant, None),
                join("usr_f", GroupRole::Facilitator, Some(1)),
            ],
            epoch: rot(1),
        }
    }

    #[test]
    fn genesis_applies_and_chains() {
        let mut s = RosterState::new(inst(), "g1".into());
        let g = genesis();
        g.validate().unwrap();
        assert_eq!(s.check(&g).unwrap(), SignPublicKey([1; 32]));
        s.apply_checked(&g);
        assert_eq!(s.checkpoint(), Some(g.head()));
        assert_eq!(s.members.len(), 2);
        assert_eq!(s.epoch, 1);

        let next = RosterEntry {
            seq: 1,
            prev_hash: g.hash(),
            changes: vec![RosterChange::Leave {
                user_id: UserId::new("usr_a"),
            }],
            epoch: rot(2),
            ..g.clone()
        };
        next.validate().unwrap();
        assert!(s.check(&next).is_ok());
        // Rollback, gap, fork, wrong epoch.
        let mut r = next.clone();
        r.seq = 0;
        assert!(matches!(s.check(&r), Err(RosterError::Rollback { .. })));
        let mut r = next.clone();
        r.seq = 2;
        assert!(matches!(s.check(&r), Err(RosterError::Gap { .. })));
        let mut r = next.clone();
        r.prev_hash = Hash32::ZERO;
        assert_eq!(s.check(&r), Err(RosterError::Fork { seq: 1 }));
        let mut r = next.clone();
        r.epoch = rot(3);
        assert!(matches!(s.check(&r), Err(RosterError::EpochNotNext { .. })));
        // A participant can't sign.
        let mut r = next.clone();
        r.signer = UserId::new("usr_a");
        assert_eq!(
            s.check(&r),
            Err(RosterError::NotAFacilitator(UserId::new("usr_a")))
        );
        s.apply_checked(&next);
        assert_eq!(s.members.len(), 1);
        assert_eq!(s.epoch, 2);
    }

    #[test]
    fn validation_rules() {
        let g = genesis();
        let mut e = g.clone();
        e.changes.reverse();
        assert!(e.validate().is_err(), "unsorted");
        let mut e = g.clone();
        e.epoch = None;
        assert!(e.validate().is_err(), "a join without rotation");
        let mut e = g.clone();
        e.changes = vec![RosterChange::Role {
            user_id: UserId::new("usr_a"),
            role: GroupRole::Facilitator,
        }];
        e.epoch = None;
        assert!(e.validate().is_ok(), "a role change needs no rotation");
        e.changes.clear();
        assert!(e.validate().is_err(), "empty");
        e.epoch = rot(4);
        assert!(e.validate().is_ok(), "a pure rotation");
        let mut e = g.clone();
        e.group_id = "bad/id".into();
        assert!(e.validate().is_err());
        let mut e = g.clone();
        e.changes = (0..=MAX_ROSTER_CHANGES)
            .map(|i| join(&format!("usr_{i:04}"), GroupRole::Participant, None))
            .collect();
        assert!(e.validate().is_err());
    }

    #[test]
    fn genesis_rules() {
        let s = RosterState::new(inst(), "g1".into());
        let mut g = genesis();
        g.changes[1] = join("usr_f", GroupRole::Participant, Some(1));
        assert!(matches!(s.check(&g), Err(RosterError::BadGenesis(_))));
        let mut g = genesis();
        g.changes[1] = join("usr_f", GroupRole::Facilitator, None);
        assert!(matches!(s.check(&g), Err(RosterError::BadGenesis(_))));
        let mut g = genesis();
        g.signer = UserId::new("usr_z");
        assert!(matches!(s.check(&g), Err(RosterError::BadGenesis(_))));
        let mut g = genesis();
        g.prev_hash = genesis_prev_hash(&inst(), "g2");
        assert_eq!(s.check(&g), Err(RosterError::Fork { seq: 0 }));
    }

    #[test]
    fn every_field_is_bound() {
        let g = genesis();
        let base = g.signing_bytes();
        let mut v = vec![];
        let mut e = g.clone();
        e.seq = 1;
        v.push(e);
        let mut e = g.clone();
        e.at_ms = 2;
        v.push(e);
        let mut e = g.clone();
        e.signer = UserId::new("usr_g");
        v.push(e);
        let mut e = g.clone();
        e.epoch = rot(2);
        v.push(e);
        let mut e = g.clone();
        e.changes[0] = join("usr_a", GroupRole::Participant, Some(3));
        v.push(e);
        let mut e = g.clone();
        e.changes[0] = join("usr_a", GroupRole::Facilitator, None);
        v.push(e);
        let mut e = g.clone();
        e.instance_id = InstanceId::new("inst_b");
        v.push(e);
        for e in v {
            assert_ne!(e.signing_bytes(), base, "{e:?}");
        }
        // A leave and a removal of the same person differ.
        let mut a = g.clone();
        a.changes = vec![RosterChange::Leave {
            user_id: UserId::new("usr_a"),
        }];
        let mut b = a.clone();
        b.changes = vec![RosterChange::Remove {
            user_id: UserId::new("usr_a"),
        }];
        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn snapshot_roundtrip() {
        let mut s = RosterState::new(inst(), "g1".into());
        let g = genesis();
        s.apply_checked(&g);
        let snap = s.snapshot(5, UserId::new("usr_f")).unwrap();
        snap.validate().unwrap();
        assert_eq!(snap.signer_key().unwrap(), SignPublicKey([1; 32]));
        assert!(s.matches_snapshot(&snap));
        let back = RosterState::from_snapshot(&snap);
        assert_eq!(back, s);
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: RosterSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snap);
        let mut other = snap.clone();
        other.signer = UserId::new("usr_a");
        assert!(matches!(
            other.signer_key(),
            Err(RosterError::NotAFacilitator(_))
        ));
    }

    #[test]
    fn heads() {
        let mut s = RosterState::new(inst(), "g1".into());
        let g = genesis();
        s.apply_checked(&g);
        assert_eq!(s.check_head(&g.head()), Ok(HeadStatus::Same));
        assert_eq!(
            s.check_head(&RosterHead {
                seq: 0,
                hash: Hash32::ZERO
            }),
            Err(RosterError::Fork { seq: 0 })
        );
        assert_eq!(
            s.check_head(&RosterHead {
                seq: 5,
                hash: Hash32::ZERO
            }),
            Ok(HeadStatus::Ahead)
        );
    }

    #[test]
    fn json_shape() {
        let g = genesis();
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["changes"][0]["kind"], "join");
        assert!(v["changes"][0]["sign_pubkey"].is_null());
        let back: RosterEntry = serde_json::from_value(v).unwrap();
        assert_eq!(back, g);
    }
}
