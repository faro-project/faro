//! `group_roster_log`, `group_roster_members`, `group_roster_snapshots`,
//! `group_epochs`, `group_epoch_keys` and `participant_sign_keys`
//! (docs/GROUPS.md §10.3, §15 "Phase C"; docs/PROTOCOL.md §10).
//!
//! Only SQL lives here; the rules are in [`crate::api::group_roster`].
//! `group_roster_members` mirrors the roster as of the log's head, so the
//! instance can check an upload against it without replaying the log.

use super::parse_col;
use crate::db::repo::groups::Role;
use crate::db::{to_i64, to_u64};
use faro_crypto::roster::SignedRosterEntry;
use faro_proto::roster::{GroupRole, RosterChange, RosterHead, RosterMember, RosterState};
use faro_proto::{EncPublicKey, Hash32, InstanceId, SignPublicKey, UserId};
use sqlx::any::AnyRow;
use sqlx::{Any, AnyConnection, Executor, Row};

fn role_str(r: GroupRole) -> &'static str {
    r.as_str()
}

fn parse_role(s: &str) -> Option<GroupRole> {
    match s {
        "facilitator" => Some(GroupRole::Facilitator),
        "participant" => Some(GroupRole::Participant),
        _ => None,
    }
}

fn bad_u64(v: u64) -> sqlx::Error {
    sqlx::Error::Encode(format!("{v} does not fit a BIGINT").into())
}

fn big(v: u64) -> Result<i64, sqlx::Error> {
    to_i64(v).ok_or_else(|| bad_u64(v))
}

/// The log's head, if it has any entry.
pub async fn head<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Option<RosterHead>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT seq, hash FROM group_roster_log WHERE group_id = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(group)
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(RosterHead {
        seq: to_u64(r.try_get("seq")?)?,
        hash: parse_col(&r, "hash", Hash32::from_prefixed_hex)?,
    }))
}

/// The current epoch and its key commitment (0 and zero before the first entry).
pub async fn current_epoch<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<(u64, Hash32), sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT epoch, key_check FROM group_epochs WHERE group_id = $1
         ORDER BY epoch DESC LIMIT 1",
    )
    .bind(group)
    .fetch_optional(e)
    .await?
    else {
        return Ok((0, Hash32::ZERO));
    };
    Ok((
        to_u64(r.try_get("epoch")?)?,
        parse_col(&r, "key_check", Hash32::from_prefixed_hex)?,
    ))
}

fn member_from_row(r: &AnyRow) -> Result<RosterMember, sqlx::Error> {
    let sign: Option<String> = r.try_get("sign_pubkey")?;
    Ok(RosterMember {
        user_id: UserId::new(r.try_get::<String, _>("user_id")?),
        role: parse_col(r, "role", parse_role)?,
        enc_pubkey: parse_col(r, "enc_pubkey", EncPublicKey::from_b64)?,
        sign_pubkey: match sign {
            None => None,
            Some(s) => Some(SignPublicKey::from_b64(&s).ok_or_else(|| {
                sqlx::Error::Decode("invalid value in column sign_pubkey".into())
            })?),
        },
    })
}

/// The roster as of the log's head, as the instance mirrors it.
pub async fn load_state(
    conn: &mut AnyConnection,
    instance: &InstanceId,
    group: &str,
) -> Result<RosterState, sqlx::Error> {
    let mut state = RosterState::new(instance.clone(), group.to_owned());
    if let Some(h) = head(&mut *conn, group).await? {
        state.next_seq = h.seq.saturating_add(1);
        state.head = h.hash;
    }
    (state.epoch, state.epoch_key_check) = current_epoch(&mut *conn, group).await?;
    let rows = sqlx::query(
        "SELECT user_id, role, enc_pubkey, sign_pubkey FROM group_roster_members
         WHERE group_id = $1",
    )
    .bind(group)
    .fetch_all(&mut *conn)
    .await?;
    for r in &rows {
        let m = member_from_row(r)?;
        state.members.insert(m.user_id.clone(), m);
    }
    Ok(state)
}

/// Store an accepted entry and bring the members mirror and the epoch up to
/// date. Inserting the log row first means a concurrent upload of the same
/// `seq` fails on the primary key before anything else changes.
pub async fn store_entry(
    conn: &mut AnyConnection,
    entry: &SignedRosterEntry,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let e = &entry.body;
    let json = serde_json::to_string(entry).map_err(|err| sqlx::Error::Encode(Box::new(err)))?;
    sqlx::query(
        "INSERT INTO group_roster_log
            (group_id, seq, prev_hash, hash, signer_id, epoch, entry_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&e.group_id)
    .bind(big(e.seq)?)
    .bind(e.prev_hash.to_prefixed_hex())
    .bind(e.hash().to_prefixed_hex())
    .bind(e.signer.as_str())
    .bind(e.epoch.map(|r| big(r.epoch)).transpose()?)
    .bind(json)
    .bind(now_ms)
    .execute(&mut *conn)
    .await?;
    for c in &e.changes {
        match c {
            RosterChange::Join {
                user_id,
                role,
                enc_pubkey,
                sign_pubkey,
            } => {
                sqlx::query(
                    "INSERT INTO group_roster_members
                        (group_id, user_id, role, enc_pubkey, sign_pubkey)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(&e.group_id)
                .bind(user_id.as_str())
                .bind(role_str(*role))
                .bind(enc_pubkey.to_b64())
                .bind(sign_pubkey.map(|k| k.to_b64()))
                .execute(&mut *conn)
                .await?;
            }
            RosterChange::Leave { user_id } | RosterChange::Remove { user_id } => {
                sqlx::query(
                    "DELETE FROM group_roster_members WHERE group_id = $1 AND user_id = $2",
                )
                .bind(&e.group_id)
                .bind(user_id.as_str())
                .execute(&mut *conn)
                .await?;
            }
            RosterChange::Role { user_id, role } => {
                sqlx::query(
                    "UPDATE group_roster_members SET role = $1 WHERE group_id = $2 AND user_id = $3",
                )
                .bind(role_str(*role))
                .bind(&e.group_id)
                .bind(user_id.as_str())
                .execute(&mut *conn)
                .await?;
            }
            RosterChange::Keys {
                user_id,
                enc_pubkey,
                sign_pubkey,
            } => {
                sqlx::query(
                    "UPDATE group_roster_members SET enc_pubkey = $1, sign_pubkey = $2
                     WHERE group_id = $3 AND user_id = $4",
                )
                .bind(enc_pubkey.to_b64())
                .bind(sign_pubkey.map(|k| k.to_b64()))
                .bind(&e.group_id)
                .bind(user_id.as_str())
                .execute(&mut *conn)
                .await?;
            }
        }
    }
    if let Some(r) = e.epoch {
        sqlx::query(
            "INSERT INTO group_epochs (group_id, epoch, seq, key_check, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&e.group_id)
        .bind(big(r.epoch)?)
        .bind(big(e.seq)?)
        .bind(r.key_check.to_prefixed_hex())
        .bind(now_ms)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Store each participant's sealed copy of an epoch key.
pub async fn store_epoch_keys(
    conn: &mut AnyConnection,
    group: &str,
    epoch: u64,
    keys: &[(UserId, String)],
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let epoch = big(epoch)?;
    for (user, sealed) in keys {
        sqlx::query(
            "INSERT INTO group_epoch_keys (group_id, epoch, user_id, sealed_key, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(group)
        .bind(epoch)
        .bind(user.as_str())
        .bind(sealed)
        .bind(now_ms)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Signed entries with `seq > after` (all, from 0, when `after` is None),
/// oldest first, at most `limit`, as the stored JSON text.
pub async fn entries_after<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    after: Option<u64>,
    limit: i64,
) -> Result<Vec<String>, sqlx::Error> {
    let from = match after {
        Some(a) => big(a)?.saturating_add(1),
        None => 0,
    };
    sqlx::query(
        "SELECT entry_json FROM group_roster_log WHERE group_id = $1 AND seq >= $2
         ORDER BY seq LIMIT $3",
    )
    .bind(group)
    .bind(from)
    .bind(limit)
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| r.try_get("entry_json"))
    .collect()
}

/// The latest snapshot at or below `max_seq` (any when None): `(seq, json)`.
pub async fn snapshot<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    max_seq: Option<u64>,
) -> Result<Option<(u64, String)>, sqlx::Error> {
    let max = match max_seq {
        Some(m) => big(m)?,
        None => i64::MAX,
    };
    let Some(r) = sqlx::query(
        "SELECT seq, snapshot_json FROM group_roster_snapshots
         WHERE group_id = $1 AND seq <= $2 ORDER BY seq DESC LIMIT 1",
    )
    .bind(group)
    .bind(max)
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some((
        to_u64(r.try_get("seq")?)?,
        r.try_get("snapshot_json")?,
    )))
}

/// The seq of the latest snapshot, if any.
pub async fn latest_snapshot_seq<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Option<u64>, sqlx::Error> {
    let r = sqlx::query("SELECT MAX(seq) AS s FROM group_roster_snapshots WHERE group_id = $1")
        .bind(group)
        .fetch_one(e)
        .await?;
    r.try_get::<Option<i64>, _>("s")?.map(to_u64).transpose()
}

pub async fn store_snapshot<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    head: &RosterHead,
    signer: &UserId,
    json: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO group_roster_snapshots
            (group_id, seq, hash, signer_id, snapshot_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(group)
    .bind(big(head.seq)?)
    .bind(head.hash.to_prefixed_hex())
    .bind(signer.as_str())
    .bind(json)
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// One participant's sealed copy of an epoch key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MyEpochKey {
    pub epoch: u64,
    /// The entry that started the epoch.
    pub seq: u64,
    pub key_check: Hash32,
    pub sealed_key: String,
}

/// `user`'s copy of epoch `epoch` (the latest they have when None).
pub async fn epoch_key_of<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    epoch: Option<u64>,
) -> Result<Option<MyEpochKey>, sqlx::Error> {
    let max = match epoch {
        Some(n) => big(n)?,
        None => i64::MAX,
    };
    let min = match epoch {
        Some(n) => big(n)?,
        None => 0,
    };
    let Some(r) = sqlx::query(
        "SELECT k.epoch, k.sealed_key, g.seq, g.key_check
         FROM group_epoch_keys k
         JOIN group_epochs g ON g.group_id = k.group_id AND g.epoch = k.epoch
         WHERE k.group_id = $1 AND k.user_id = $2 AND k.epoch >= $3 AND k.epoch <= $4
         ORDER BY k.epoch DESC LIMIT 1",
    )
    .bind(group)
    .bind(user.as_str())
    .bind(min)
    .bind(max)
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(MyEpochKey {
        epoch: to_u64(r.try_get("epoch")?)?,
        seq: to_u64(r.try_get("seq")?)?,
        key_check: parse_col(&r, "key_check", Hash32::from_prefixed_hex)?,
        sealed_key: r.try_get("sealed_key")?,
    }))
}

/// An active participant with the keys the instance has for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyedParticipant {
    pub user_id: UserId,
    pub role: Role,
    /// Their member encryption key, else their ally key. None: they have
    /// neither yet, so they can't be added to the roster.
    pub enc_pubkey: Option<EncPublicKey>,
    /// Their member signing key, else a group signing key sealed to the
    /// encryption key above.
    pub sign_pubkey: Option<SignPublicKey>,
}

fn opt_key<T>(
    r: &AnyRow,
    col: &str,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>, sqlx::Error> {
    let s: Option<String> = r.try_get(col)?;
    Ok(s.as_deref().and_then(parse))
}

/// Every active participant of `group` with their current keys.
pub async fn keyed_participants<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
) -> Result<Vec<KeyedParticipant>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT p.user_id, p.role, mk.enc_pubkey AS member_enc, mk.sign_pubkey AS member_sign,
                (SELECT k.enc_pubkey FROM ally_keys k
                  WHERE k.user_id = p.user_id AND k.revoked_at IS NULL
                  ORDER BY k.created_at DESC LIMIT 1) AS ally_enc,
                s.sign_pubkey AS part_sign, s.enc_pubkey AS part_sign_enc
         FROM group_participants p
         LEFT JOIN member_keys mk ON mk.user_id = p.user_id
         LEFT JOIN participant_sign_keys s ON s.user_id = p.user_id
         WHERE p.group_id = $1 AND p.state = 'active'
         ORDER BY p.user_id",
    )
    .bind(group)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            let member_enc = opt_key(r, "member_enc", EncPublicKey::from_b64)?;
            let member_sign = opt_key(r, "member_sign", SignPublicKey::from_b64)?;
            let ally_enc = opt_key(r, "ally_enc", EncPublicKey::from_b64)?;
            let part_sign = opt_key(r, "part_sign", SignPublicKey::from_b64)?;
            let part_sign_enc = opt_key(r, "part_sign_enc", EncPublicKey::from_b64)?;
            let enc_pubkey = member_enc.or(ally_enc);
            let sign_pubkey = match member_enc {
                Some(_) => member_sign,
                // A group signing key is only good with the key it is sealed to.
                None => part_sign.filter(|_| part_sign_enc.is_some() && part_sign_enc == ally_enc),
            };
            Ok(KeyedParticipant {
                user_id: UserId::new(r.try_get::<String, _>("user_id")?),
                role: parse_col(r, "role", Role::parse)?,
                enc_pubkey,
                sign_pubkey,
            })
        })
        .collect()
}

/// How `user`'s latest stay in `group` ended: `Some(true)` removed,
/// `Some(false)` left, None if they have no ended stay (or no rows: their
/// account was deleted).
pub async fn was_removed<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
) -> Result<Option<bool>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT state FROM group_participants
         WHERE group_id = $1 AND user_id = $2 AND state <> 'active'
         ORDER BY ended_at DESC LIMIT 1",
    )
    .bind(group)
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(r.try_get::<String, _>("state")? == "removed"))
}

/// Whether `user` was an active participant of `group` at `at_ms` and still
/// is: the rule for serving a group item (GROUPS.md §10.5: only people who
/// were participants when it arrived, and never a departed one).
pub async fn may_read_item<'e>(
    e: impl Executor<'e, Database = Any>,
    group: &str,
    user: &UserId,
    item_created_at_ms: i64,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM group_participants
         WHERE group_id = $1 AND user_id = $2 AND state = 'active' AND joined_at <= $3",
    )
    .bind(group)
    .bind(user.as_str())
    .bind(item_created_at_ms)
    .fetch_optional(e)
    .await?
    .is_some())
}

// ---- Group signing keys -----------------------------------------------------

/// A group signing key for someone without member keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantSignKey {
    pub sign_pubkey: SignPublicKey,
    /// The encryption key the seed is sealed to.
    pub enc_pubkey: EncPublicKey,
    /// base64url `crypto_box_seal(seed, enc_pubkey)`.
    pub sealed_seed: String,
    pub created_at_ms: i64,
}

pub async fn sign_key_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Option<ParticipantSignKey>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT sign_pubkey, enc_pubkey, sealed_seed, created_at FROM participant_sign_keys
         WHERE user_id = $1",
    )
    .bind(user.as_str())
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(ParticipantSignKey {
        sign_pubkey: parse_col(&r, "sign_pubkey", SignPublicKey::from_b64)?,
        enc_pubkey: parse_col(&r, "enc_pubkey", EncPublicKey::from_b64)?,
        sealed_seed: r.try_get("sealed_seed")?,
        created_at_ms: r.try_get("created_at")?,
    }))
}

/// Store a group signing key; false if the user already has one. A key used
/// by someone else surfaces as a unique violation.
pub async fn insert_sign_key<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    key: &ParticipantSignKey,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "INSERT INTO participant_sign_keys (user_id, sign_pubkey, enc_pubkey, sealed_seed, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user.as_str())
    .bind(key.sign_pubkey.to_b64())
    .bind(key.enc_pubkey.to_b64())
    .bind(&key.sealed_seed)
    .bind(key.created_at_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}
