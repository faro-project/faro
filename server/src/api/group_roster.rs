//! Group roster log, snapshots and epoch keys (docs/GROUPS.md §10.3, §10.5,
//! §16 "Phase C"; docs/PROTOCOL.md §10), and the keys people need for them.
//!
//! | Route | Who |
//! |---|---|
//! | `GET /v1/groups/{id}/roster?after_seq=` | participants: log entries after `after_seq`, 100 per page, with the head and the latest snapshot's seq |
//! | `GET /v1/groups/{id}/roster/snapshot?max_seq=` | participants: the latest signed snapshot (at or below `max_seq`) |
//! | `GET /v1/groups/{id}/roster/pending` | participants: the changes a facilitator's client should sign next |
//! | `POST /v1/groups/{id}/roster` | facilitators: one signed entry, with the new epoch key sealed to everyone in the roster after it |
//! | `POST /v1/groups/{id}/roster/snapshot` | facilitators: a signed snapshot of the roster at the head |
//! | `GET /v1/groups/{id}/epoch-key?epoch=` | participants: their sealed copy of the current (or a given) epoch key |
//! | `PUT /v1/me/ally-key` | anyone without one: create their encryption key (it is also their ally key) |
//! | `GET`, `PUT /v1/me/group-sign-key` | people without member keys: their group signing key, sealed to their encryption key |
//!
//! ## The instance is not the trust anchor
//!
//! Clients verify every entry against their own persisted checkpoint and
//! the roster as of the previous entry (signer a facilitator, signature,
//! chain, no rollback or fork), and every epoch key against the commitment
//! in the signed entry. What the instance checks on upload is there to keep
//! garbage out and to tie the roster to who is actually in the group:
//!
//! 1. the entry passes the same checks clients run
//!    ([`faro_crypto::roster::apply_entry`]) against the instance's mirror of
//!    the roster, and is signed by the caller, an active facilitator;
//! 2. every change matches the group: a join or key change carries the
//!    keys the instance holds for that person and their current role; a
//!    leave or removal names someone who is no longer an active
//!    participant;
//! 3. an entry that rotates the epoch comes with exactly one sealed key for
//!    each person in the roster after it, all of them active participants,
//!    so a new epoch never goes to someone who left.
//!
//! **Departed participants** get `404` from every route here at once (they
//! are no longer active), before any facilitator has signed their removal.

use super::groups::{load, load_in_tx, require_facilitator, require_writable};
use super::{ApiJson, RosterJson};
use crate::auth::session::SessionUser;
use crate::db::repo::group_roster::{self as repo, KeyedParticipant, ParticipantSignKey};
use crate::db::repo::groups::Role;
use crate::db::repo::{allies, is_unique_violation, member_keys};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use faro_crypto::roster::{SignedRosterEntry, SignedRosterSnapshot};
use faro_proto::api::AllyKeyUpload;
use faro_proto::encoding::b64_decode;
use faro_proto::keys::key_id;
use faro_proto::roster::{
    GroupRole, RosterChange, RosterError, RosterHead, ROSTER_PAGE, ROSTER_SNAPSHOT_INTERVAL,
    SEALED_EPOCH_KEY_LEN,
};
use faro_proto::{EncPublicKey, Hash32, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

fn group_role(r: Role) -> GroupRole {
    match r {
        Role::Facilitator => GroupRole::Facilitator,
        Role::Participant => GroupRole::Participant,
    }
}

/// A roster error as an API error: a stale head (someone else signed first)
/// is a conflict to retry after reloading; anything else a bad request.
fn roster_error(e: RosterError) -> AppError {
    let msg = e.to_string();
    let msg = if msg.len() > 160 {
        format!("{}…", &msg[..msg.floor_char_boundary(160)])
    } else {
        msg
    };
    match e {
        RosterError::Rollback { .. }
        | RosterError::Gap { .. }
        | RosterError::Fork { .. }
        | RosterError::EpochNotNext { .. } => AppError::conflict("roster_conflict", msg),
        _ => AppError::bad_request("invalid_roster_entry", msg),
    }
}

// ---- Reading the log ---------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RosterQuery {
    pub after_seq: Option<u64>,
}

/// `GET /v1/groups/{id}/roster`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterPage {
    /// The log's head, or null before the first entry.
    pub head: Option<RosterHead>,
    pub epoch: u64,
    /// The latest snapshot's seq, for a client without a checkpoint.
    pub latest_snapshot_seq: Option<u64>,
    /// Signed entries after `after_seq` (from 0 without it), oldest first.
    pub entries: Vec<serde_json::Value>,
    /// More entries follow: ask again after the last one.
    pub more: bool,
}

/// `GET /v1/groups/{id}/roster?after_seq=`
pub async fn get_roster(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<RosterQuery>,
) -> AppResult<Json<RosterPage>> {
    load(&state, &s, &id).await?;
    let mut conn = state.db().pool().acquire().await?;
    let limit = i64::try_from(ROSTER_PAGE).unwrap_or(100);
    let mut raw = repo::entries_after(&mut *conn, &id, q.after_seq, limit + 1).await?;
    let more = raw.len() > ROSTER_PAGE;
    raw.truncate(ROSTER_PAGE);
    let entries = raw
        .iter()
        .map(|t| serde_json::from_str(t))
        .collect::<Result<Vec<serde_json::Value>, _>>()
        .map_err(|e| AppError::Internal(format!("stored roster entry: {e}")))?;
    Ok(Json(RosterPage {
        head: repo::head(&mut *conn, &id).await?,
        epoch: repo::current_epoch(&mut *conn, &id).await?.0,
        latest_snapshot_seq: repo::latest_snapshot_seq(&mut *conn, &id).await?,
        entries,
        more,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SnapshotQuery {
    pub max_seq: Option<u64>,
}

/// `GET /v1/groups/{id}/roster/snapshot?max_seq=`: the stored signed
/// snapshot, byte for byte. `404` if there is none.
pub async fn get_snapshot(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<SnapshotQuery>,
) -> AppResult<impl IntoResponse> {
    load(&state, &s, &id).await?;
    let (_, json) = repo::snapshot(state.db().pool(), &id, q.max_seq)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], json))
}

// ---- Pending work --------------------------------------------------------------

/// `GET /v1/groups/{id}/roster/pending`: how the signed roster differs from
/// who is in the group. A facilitator's client checks these changes against
/// its own verified roster before signing them; nobody else can sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterPending {
    pub head: Option<RosterHead>,
    pub epoch: u64,
    /// Sorted by user, at most one per person (a second change for the same
    /// person shows up once the first is signed).
    pub changes: Vec<RosterChange>,
    /// Participants who have no encryption key yet, so can't be added.
    pub waiting_for_keys: Vec<UserId>,
    /// Someone who left is still in the signed roster, or someone's keys
    /// changed: whole-group posting waits for a facilitator.
    pub posting_paused: bool,
    /// The head is [`ROSTER_SNAPSHOT_INTERVAL`] or more entries past the
    /// last snapshot.
    pub snapshot_due: bool,
    pub latest_snapshot_seq: Option<u64>,
}

/// The diff behind [`RosterPending`]: the instance's roster mirror against
/// the group's active participants and their current keys.
async fn pending_changes(
    conn: &mut sqlx::AnyConnection,
    state: &AppState,
    group: &str,
) -> AppResult<(RosterPending, HashMap<UserId, KeyedParticipant>)> {
    let roster = repo::load_state(&mut *conn, state.instance_id(), group).await?;
    let people: HashMap<UserId, KeyedParticipant> = repo::keyed_participants(&mut *conn, group)
        .await?
        .into_iter()
        .map(|p| (p.user_id.clone(), p))
        .collect();
    let mut changes = Vec::new();
    let mut waiting = Vec::new();
    for p in people.values() {
        let Some(enc) = p.enc_pubkey else {
            if !roster.members.contains_key(&p.user_id) {
                waiting.push(p.user_id.clone());
            }
            continue;
        };
        let role = group_role(p.role);
        match roster.member(&p.user_id) {
            None => changes.push(RosterChange::Join {
                user_id: p.user_id.clone(),
                role,
                enc_pubkey: enc,
                sign_pubkey: p.sign_pubkey,
            }),
            Some(m) if m.enc_pubkey != enc || m.sign_pubkey != p.sign_pubkey => {
                changes.push(RosterChange::Keys {
                    user_id: p.user_id.clone(),
                    enc_pubkey: enc,
                    sign_pubkey: p.sign_pubkey,
                })
            }
            Some(m) if m.role != role => changes.push(RosterChange::Role {
                user_id: p.user_id.clone(),
                role,
            }),
            Some(_) => {}
        }
    }
    for u in roster.members.keys() {
        if !people.contains_key(u) {
            // No rows at all: their account was deleted, which counts as a removal.
            let left = repo::was_removed(&mut *conn, group, u).await? == Some(false);
            changes.push(if left {
                RosterChange::Leave { user_id: u.clone() }
            } else {
                RosterChange::Remove { user_id: u.clone() }
            });
        }
    }
    changes.sort_by(|a, b| a.user_id().cmp(b.user_id()));
    waiting.sort();
    let head = roster.checkpoint();
    let latest = repo::latest_snapshot_seq(&mut *conn, group).await?;
    let since = head.map_or(0, |h| {
        (h.seq + 1).saturating_sub(latest.map_or(0, |s| s.saturating_add(1)))
    });
    let posting_paused = changes.iter().any(|c| {
        matches!(
            c,
            RosterChange::Leave { .. } | RosterChange::Remove { .. } | RosterChange::Keys { .. }
        )
    });
    Ok((
        RosterPending {
            head,
            epoch: roster.epoch,
            changes,
            waiting_for_keys: waiting,
            posting_paused,
            snapshot_due: since >= ROSTER_SNAPSHOT_INTERVAL,
            latest_snapshot_seq: latest,
        },
        people,
    ))
}

/// `GET /v1/groups/{id}/roster/pending`
pub async fn get_pending(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<RosterPending>> {
    load(&state, &s, &id).await?;
    let mut conn = state.db().pool().acquire().await?;
    Ok(Json(pending_changes(&mut conn, &state, &id).await?.0))
}

// ---- Uploading entries and snapshots ---------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKeyUpload {
    pub user_id: UserId,
    /// base64url `crypto_box_seal` of the 32-byte epoch key.
    pub sealed_key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostEntry {
    pub entry: SignedRosterEntry,
    #[serde(default)]
    pub epoch_keys: Vec<SealedKeyUpload>,
}

fn mismatch(code: &'static str, msg: impl Into<String>) -> AppError {
    AppError::conflict(code, msg)
}

/// Rule 2 (module docs): every change matches who is in the group.
fn check_against_group(
    changes: &[RosterChange],
    people: &HashMap<UserId, KeyedParticipant>,
) -> AppResult<()> {
    let keys_match = |p: &KeyedParticipant, enc: &EncPublicKey, sign: &Option<SignPublicKey>| {
        p.enc_pubkey.as_ref() == Some(enc) && p.sign_pubkey == *sign
    };
    for c in changes {
        let p = people.get(c.user_id());
        match (c, p) {
            (RosterChange::Leave { .. } | RosterChange::Remove { .. }, None) => {}
            (RosterChange::Leave { user_id } | RosterChange::Remove { user_id }, Some(_)) => {
                return Err(mismatch(
                    "roster_still_participant",
                    format!("{user_id} is still in the group"),
                ))
            }
            (_, None) => {
                return Err(mismatch(
                    "roster_not_participant",
                    format!("{} is not in the group", c.user_id()),
                ))
            }
            (
                RosterChange::Join {
                    role,
                    enc_pubkey,
                    sign_pubkey,
                    ..
                },
                Some(p),
            ) => {
                if group_role(p.role) != *role || !keys_match(p, enc_pubkey, sign_pubkey) {
                    return Err(mismatch(
                        "roster_keys_mismatch",
                        format!("{} has other keys or another role", p.user_id),
                    ));
                }
            }
            (RosterChange::Role { role, .. }, Some(p)) => {
                if group_role(p.role) != *role {
                    return Err(mismatch(
                        "roster_keys_mismatch",
                        format!("{} has another role", p.user_id),
                    ));
                }
            }
            (
                RosterChange::Keys {
                    enc_pubkey,
                    sign_pubkey,
                    ..
                },
                Some(p),
            ) => {
                if !keys_match(p, enc_pubkey, sign_pubkey) {
                    return Err(mismatch(
                        "roster_keys_mismatch",
                        format!("{} has other keys", p.user_id),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `POST /v1/groups/{id}/roster`: a facilitator's signed entry. Returns the
/// new head.
pub async fn post_entry(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    RosterJson(req): RosterJson<PostEntry>,
) -> AppResult<(StatusCode, Json<RosterHead>)> {
    s.require_not_being_deleted()?;
    let e = &req.entry.body;
    e.validate().map_err(roster_error)?;
    if e.group_id != id || &e.instance_id != state.instance_id() {
        return Err(AppError::bad_request(
            "roster_entry_mismatch",
            "the entry must name this instance and group",
        ));
    }
    if e.signer != s.user.id {
        return Err(AppError::bad_request(
            "roster_signer_mismatch",
            "sign roster entries as yourself",
        ));
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;

    // 1. The checks every client runs, against the instance's mirror.
    let mut roster = repo::load_state(&mut tx, state.instance_id(), &id).await?;
    faro_crypto::roster::apply_entry(&mut roster, &req.entry).map_err(roster_error)?;

    // 2. The changes match the group.
    let people: HashMap<UserId, KeyedParticipant> = repo::keyed_participants(&mut *tx, &id)
        .await?
        .into_iter()
        .map(|p| (p.user_id.clone(), p))
        .collect();
    check_against_group(&e.changes, &people)?;

    // 3. A new epoch goes to exactly the roster after the entry, all of
    // whom are in the group.
    let mut sealed = Vec::with_capacity(req.epoch_keys.len());
    match e.epoch {
        Some(_) => {
            if let Some(gone) = roster.members.keys().find(|u| !people.contains_key(*u)) {
                return Err(mismatch(
                    "roster_still_lists_departed",
                    format!("remove {gone} before starting a new epoch"),
                ));
            }
            let mut seen = HashSet::new();
            for k in &req.epoch_keys {
                if !roster.members.contains_key(&k.user_id) || !seen.insert(&k.user_id) {
                    return Err(AppError::bad_request(
                        "invalid_epoch_keys",
                        format!("unexpected or repeated epoch key for {}", k.user_id),
                    ));
                }
                if b64_decode(&k.sealed_key).map(|b| b.len()) != Ok(SEALED_EPOCH_KEY_LEN) {
                    return Err(AppError::bad_request(
                        "invalid_epoch_keys",
                        "a sealed epoch key is 80 bytes, base64url",
                    ));
                }
                sealed.push((k.user_id.clone(), k.sealed_key.clone()));
            }
            if seen.len() != roster.members.len() {
                return Err(AppError::bad_request(
                    "invalid_epoch_keys",
                    "seal the new epoch key to everyone in the roster",
                ));
            }
        }
        None if !req.epoch_keys.is_empty() => {
            return Err(AppError::bad_request(
                "invalid_epoch_keys",
                "epoch keys come only with an entry that starts an epoch",
            ));
        }
        None => {}
    }

    match repo::store_entry(&mut tx, &req.entry, now).await {
        Ok(()) => {}
        Err(err) if is_unique_violation(&err) => {
            return Err(AppError::conflict(
                "roster_conflict",
                "someone else updated the roster first; reload and try again",
            ))
        }
        Err(err) => return Err(err.into()),
    }
    if let Some(r) = e.epoch {
        repo::store_epoch_keys(&mut tx, &id, r.epoch, &sealed, now).await?;
    }
    tx.commit().await?;
    tracing::info!(group = %id, seq = e.seq, epoch = ?e.epoch.map(|r| r.epoch), "roster entry stored");
    Ok((StatusCode::CREATED, Json(e.head())))
}

/// `POST /v1/groups/{id}/roster/snapshot`: a facilitator's signed snapshot
/// of the roster at the head (it must describe exactly the instance's
/// mirror, and be signed by the caller as a facilitator in it).
pub async fn post_snapshot(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    RosterJson(snap): RosterJson<SignedRosterSnapshot>,
) -> AppResult<StatusCode> {
    s.require_not_being_deleted()?;
    if snap.body.signer != s.user.id {
        return Err(AppError::bad_request(
            "roster_signer_mismatch",
            "sign snapshots as yourself",
        ));
    }
    faro_crypto::roster::verify_snapshot(&snap).map_err(roster_error)?;
    let json = serde_json::to_string(&snap).map_err(|e| AppError::Internal(e.to_string()))?;
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let (group, me) = load_in_tx(&mut tx, &s.user.id, &id).await?;
    require_facilitator(&me)?;
    require_writable(&state, &group)?;
    let roster = repo::load_state(&mut tx, state.instance_id(), &id).await?;
    if !roster.matches_snapshot(&snap.body) {
        return Err(AppError::conflict(
            "roster_conflict",
            "the snapshot isn't the roster at its head; reload and try again",
        ));
    }
    match repo::store_snapshot(&mut *tx, &id, &snap.body.head(), &s.user.id, &json, now).await {
        Ok(()) => {}
        // Someone else snapshotted the same head: theirs is as good.
        Err(err) if is_unique_violation(&err) => return Ok(StatusCode::NO_CONTENT),
        Err(err) => return Err(err.into()),
    }
    tx.commit().await?;
    Ok(StatusCode::CREATED)
}

// ---- Epoch keys -------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct EpochQuery {
    pub epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochKeyView {
    pub epoch: u64,
    /// The entry that started this epoch, whose `key_check` the opened key
    /// must match.
    pub seq: u64,
    pub key_check: Hash32,
    pub sealed_key: String,
}

/// `GET /v1/groups/{id}/epoch-key?epoch=`: the caller's sealed copy of the
/// current epoch key (or of `epoch`). `404` if they have none: they joined
/// later, or no facilitator has added them yet.
pub async fn get_epoch_key(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    Query(q): Query<EpochQuery>,
) -> AppResult<Json<EpochKeyView>> {
    load(&state, &s, &id).await?;
    let k = repo::epoch_key_of(state.db().pool(), &id, &s.user.id, q.epoch)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(EpochKeyView {
        epoch: k.epoch,
        seq: k.seq,
        key_check: k.key_check,
        sealed_key: k.sealed_key,
    }))
}

// ---- Keys for people who have none ------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncKeyCreated {
    pub enc_pubkey: EncPublicKey,
    pub key_id: String,
}

/// `PUT /v1/me/ally-key`: someone with no encryption key creates one, to
/// receive group content (GROUPS.md §10.3 item 1). It is stored as their
/// ally key, in the same format, so the same passphrase, recovery code and
/// passphrase change apply, and it is reused if they later become someone's
/// ally. `409 ally_key_exists` if they have one.
pub async fn put_my_enc_key(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(up): ApiJson<AllyKeyUpload>,
) -> AppResult<(StatusCode, Json<EncKeyCreated>)> {
    s.require_not_being_deleted()?;
    if faro_crypto::validate_enc_pubkey(&up.enc_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_enc_pubkey",
            "enc_pubkey is not a usable X25519 key",
        ));
    }
    if !up.wrapped_privkey.is_object()
        || up.wrapped_privkey.to_string().len() > super::keys::MAX_WRAPPED_BYTES
    {
        return Err(AppError::bad_request(
            "invalid_wrapped_key",
            "wrapped_privkey must be a JSON object of at most 8 KiB",
        ));
    }
    let mut tx = state.db().begin_write().await?;
    if allies::live_key(&mut *tx, &s.user.id).await?.is_some() {
        return Err(AppError::conflict(
            "ally_key_exists",
            "you already have an encryption key; unlock it and use it",
        ));
    }
    allies::insert_key(
        &mut *tx,
        &s.user.id,
        &up.enc_pubkey,
        &up.wrapped_privkey,
        state.now_ms(),
    )
    .await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(EncKeyCreated {
            enc_pubkey: up.enc_pubkey,
            key_id: key_id(up.enc_pubkey.as_bytes()),
        }),
    ))
}

/// A group signing key, as stored and served.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSignKey {
    pub sign_pubkey: SignPublicKey,
    /// The encryption key (their ally key) the seed is sealed to.
    pub enc_pubkey: EncPublicKey,
    /// base64url `crypto_box_seal` of the 32-byte Ed25519 seed.
    pub sealed_seed: String,
}

/// `GET /v1/me/group-sign-key`
pub async fn get_my_sign_key(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<GroupSignKey>> {
    let k = repo::sign_key_of(state.db().pool(), &s.user.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(GroupSignKey {
        sign_pubkey: k.sign_pubkey,
        enc_pubkey: k.enc_pubkey,
        sealed_seed: k.sealed_seed,
    }))
}

/// `PUT /v1/me/group-sign-key`: an ally-only person creates a signing key
/// when they become a facilitator (GROUPS.md decision 6). The seed is sealed
/// to their own encryption key, so their passphrase (or recovery code)
/// unlocks it with that key, and a passphrase change keeps it working.
/// Members use their member signing key instead (`409 has_member_keys`).
pub async fn put_my_sign_key(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<GroupSignKey>,
) -> AppResult<(StatusCode, Json<GroupSignKey>)> {
    s.require_not_being_deleted()?;
    if faro_crypto::validate_sign_pubkey(&req.sign_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_sign_pubkey",
            "sign_pubkey is not a usable Ed25519 key",
        ));
    }
    if b64_decode(&req.sealed_seed).map(|b| b.len()) != Ok(32 + 48) {
        return Err(AppError::bad_request(
            "invalid_sealed_seed",
            "sealed_seed is a 32-byte seed sealed to your encryption key (80 bytes, base64url)",
        ));
    }
    let mut tx = state.db().begin_write().await?;
    if member_keys::get(&mut *tx, &s.user.id).await?.is_some() {
        return Err(AppError::conflict(
            "has_member_keys",
            "you sign with your member key",
        ));
    }
    match allies::live_key(&mut *tx, &s.user.id).await? {
        Some(k) if k.enc_pubkey == req.enc_pubkey => {}
        _ => {
            return Err(AppError::conflict(
                "enc_key_mismatch",
                "seal the seed to your current encryption key",
            ))
        }
    }
    let row = ParticipantSignKey {
        sign_pubkey: req.sign_pubkey,
        enc_pubkey: req.enc_pubkey,
        sealed_seed: req.sealed_seed.clone(),
        created_at_ms: state.now_ms(),
    };
    match repo::insert_sign_key(&mut *tx, &s.user.id, &row).await {
        Ok(true) => {}
        Ok(false) => {
            return Err(AppError::conflict(
                "sign_key_exists",
                "you already have a group signing key",
            ))
        }
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::bad_request(
                "invalid_sign_pubkey",
                "that key is already in use",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    tx.commit().await?;
    tracing::info!("group signing key created");
    Ok((StatusCode::CREATED, Json(req)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_heads_are_conflicts() {
        assert!(matches!(
            roster_error(RosterError::Fork { seq: 1 }),
            AppError::Conflict { .. }
        ));
        assert!(matches!(
            roster_error(RosterError::BadSignature),
            AppError::BadRequest { .. }
        ));
    }
}
