//! `ally_links` and `ally_keys` (§4.3, §5.2).
//!
//! Link lifecycle: `pending` (the ally accepted an invite and uploaded a
//! key) → `active` (the member signed an [`AllyEndorsement`] of that key) →
//! `removed` (by the member, or the ally left). At most one live (pending or
//! active) link exists per (member, ally) pair, enforced by a partial unique
//! index. Removed links are kept as a record until retention removes them.
//!
//! An ally has **one** live encryption key, shared by all the members they
//! support: replacing it would silently drop them from every other member's
//! key directory, so a second, different key is refused (see
//! [`crate::api::invites`]).

use super::parse_col;
use crate::tokens::new_hex_id;
use faro_proto::keys::{AllyEndorsement, Signed};
use faro_proto::{EncPublicKey, SignPublicKey, UserId};
use sqlx::{Any, Executor, Row};

/// Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Pending,
    Active,
    Removed,
}

impl LinkState {
    pub fn as_str(self) -> &'static str {
        match self {
            LinkState::Pending => "pending",
            LinkState::Active => "active",
            LinkState::Removed => "removed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "removed" => Some(Self::Removed),
            _ => None,
        }
    }
}

/// A live link joined with the other party's account and keys.
#[derive(Debug, Clone)]
pub struct LinkView {
    pub link_id: String,
    pub member_id: UserId,
    pub ally_id: UserId,
    pub state: LinkState,
    pub created_at_ms: i64,
    pub activated_at_ms: Option<i64>,
    /// The other party's display name (the ally's when listing a member's
    /// allies, the member's when listing an ally's members).
    pub other_display_name: String,
    pub other_email: String,
    /// The end of the hold, if the other party asked for their account to
    /// be deleted (§12).
    pub other_deletion_purge_after_ms: Option<i64>,
    /// The ally's live encryption key, if any.
    pub ally_enc_pubkey: Option<EncPublicKey>,
    /// The member's signing key, if set.
    pub member_sign_pubkey: Option<SignPublicKey>,
}

/// The shared `SELECT … FROM ally_links l` prefix of the link views, as a
/// macro so each query is a `concat!`-built `&'static str` (no dynamic SQL).
macro_rules! view_select {
    () => {
        "SELECT l.id, l.member_id, l.ally_id, l.state, l.created_at,
            l.activated_at, o.display_name, o.email, o.deletion_purge_after,
            (SELECT k.enc_pubkey FROM ally_keys k
              WHERE k.user_id = l.ally_id AND k.revoked_at IS NULL
              ORDER BY k.created_at DESC LIMIT 1) AS ally_enc_pubkey,
            (SELECT m.sign_pubkey FROM member_keys m WHERE m.user_id = l.member_id)
              AS member_sign_pubkey
         FROM ally_links l"
    };
}

fn view_from_row(r: &sqlx::any::AnyRow) -> Result<LinkView, sqlx::Error> {
    Ok(LinkView {
        link_id: r.try_get("id")?,
        member_id: UserId::new(r.try_get::<String, _>("member_id")?),
        ally_id: UserId::new(r.try_get::<String, _>("ally_id")?),
        state: parse_col(r, "state", LinkState::parse)?,
        created_at_ms: r.try_get("created_at")?,
        activated_at_ms: r.try_get("activated_at")?,
        other_display_name: r.try_get("display_name")?,
        other_email: r.try_get("email")?,
        other_deletion_purge_after_ms: r.try_get("deletion_purge_after")?,
        ally_enc_pubkey: super::parse_opt_col(r, "ally_enc_pubkey", EncPublicKey::from_b64)?,
        member_sign_pubkey: super::parse_opt_col(r, "member_sign_pubkey", SignPublicKey::from_b64)?,
    })
}

/// A member's live (pending and active) links, with each ally's details.
pub async fn list_for_member<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<Vec<LinkView>, sqlx::Error> {
    sqlx::query(concat!(
        view_select!(),
        " JOIN users o ON o.id = l.ally_id
         WHERE l.member_id = $1 AND l.state <> 'removed'
         ORDER BY l.created_at, l.id"
    ))
    .bind(member.as_str())
    .fetch_all(e)
    .await?
    .iter()
    .map(view_from_row)
    .collect()
}

/// An ally's live links, with each member's details.
pub async fn list_for_ally<'e>(
    e: impl Executor<'e, Database = Any>,
    ally: &UserId,
) -> Result<Vec<LinkView>, sqlx::Error> {
    sqlx::query(concat!(
        view_select!(),
        " JOIN users o ON o.id = l.member_id
         WHERE l.ally_id = $1 AND l.state <> 'removed'
         ORDER BY l.created_at, l.id"
    ))
    .bind(ally.as_str())
    .fetch_all(e)
    .await?
    .iter()
    .map(view_from_row)
    .collect()
}

/// The live link between `member` and `ally`, if any.
pub async fn live_state<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    ally: &UserId,
) -> Result<Option<LinkState>, sqlx::Error> {
    sqlx::query(
        "SELECT state FROM ally_links
         WHERE member_id = $1 AND ally_id = $2 AND state <> 'removed'",
    )
    .bind(member.as_str())
    .bind(ally.as_str())
    .fetch_optional(e)
    .await?
    .map(|r| parse_col(&r, "state", LinkState::parse))
    .transpose()
}

/// Whether `ally` currently has an **active** link to `member`. This, not
/// device-declared envelope recipients, is what authorises feed and blob
/// access.
pub async fn is_active<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    ally: &UserId,
) -> Result<bool, sqlx::Error> {
    Ok(live_state(e, member, ally).await? == Some(LinkState::Active))
}

/// Number of live links a member has (to cap allies per member).
pub async fn count_live<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<i64, sqlx::Error> {
    sqlx::query("SELECT COUNT(*) AS n FROM ally_links WHERE member_id = $1 AND state <> 'removed'")
        .bind(member.as_str())
        .fetch_one(e)
        .await?
        .try_get("n")
}

/// Create a pending link. A live link for the pair already existing
/// surfaces as a unique violation.
pub async fn insert_pending<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    ally: &UserId,
    now_ms: i64,
) -> Result<String, sqlx::Error> {
    let id = new_hex_id();
    sqlx::query(
        "INSERT INTO ally_links (id, member_id, ally_id, state, created_at)
         VALUES ($1, $2, $3, 'pending', $4)",
    )
    .bind(&id)
    .bind(member.as_str())
    .bind(ally.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(id)
}

/// pending → active with the member's endorsement. False if not pending.
pub async fn activate<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    ally: &UserId,
    endorsement_json: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE ally_links SET state = 'active', endorsement_json = $1, activated_at = $2
         WHERE member_id = $3 AND ally_id = $4 AND state = 'pending'",
    )
    .bind(endorsement_json)
    .bind(now_ms)
    .bind(member.as_str())
    .bind(ally.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Remove the live link, returning the state it was in (None if there was
/// no live link).
pub async fn remove(
    conn: &mut sqlx::AnyConnection,
    member: &UserId,
    ally: &UserId,
    now_ms: i64,
) -> Result<Option<LinkState>, sqlx::Error> {
    let Some(prev) = live_state(&mut *conn, member, ally).await? else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE ally_links SET state = 'removed', removed_at = $1
         WHERE member_id = $2 AND ally_id = $3 AND state <> 'removed'",
    )
    .bind(now_ms)
    .bind(member.as_str())
    .bind(ally.as_str())
    .execute(&mut *conn)
    .await?;
    Ok(Some(prev))
}

/// An ally's live encryption key with its wrapped private half.
#[derive(Debug, Clone, PartialEq)]
pub struct AllyKeyRow {
    pub id: String,
    pub enc_pubkey: EncPublicKey,
    pub key_id: String,
    pub wrapped_privkey: serde_json::Value,
    pub created_at_ms: i64,
}

pub async fn live_key<'e>(
    e: impl Executor<'e, Database = Any>,
    ally: &UserId,
) -> Result<Option<AllyKeyRow>, sqlx::Error> {
    let Some(r) = sqlx::query(
        "SELECT id, enc_pubkey, key_id, wrapped_privkey, created_at FROM ally_keys
         WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(ally.as_str())
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(AllyKeyRow {
        id: r.try_get("id")?,
        enc_pubkey: parse_col(&r, "enc_pubkey", EncPublicKey::from_b64)?,
        key_id: r.try_get("key_id")?,
        wrapped_privkey: parse_col(&r, "wrapped_privkey", |s| serde_json::from_str(s).ok())?,
        created_at_ms: r.try_get("created_at")?,
    }))
}

pub async fn insert_key<'e>(
    e: impl Executor<'e, Database = Any>,
    ally: &UserId,
    enc_pubkey: &EncPublicKey,
    wrapped_privkey: &serde_json::Value,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ally_keys (id, user_id, enc_pubkey, key_id, wrapped_privkey, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new_hex_id())
    .bind(ally.as_str())
    .bind(enc_pubkey.to_b64())
    .bind(faro_proto::keys::key_id(enc_pubkey.as_bytes()))
    .bind(wrapped_privkey.to_string())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// Replace the wrapped private half of the live ally key `key_row_id`, if
/// it still holds exactly `old` (so of two changes made from the same
/// challenge, only one lands). The public key is never touched. Returns
/// whether a row changed.
pub async fn replace_wrapped<'e>(
    e: impl Executor<'e, Database = Any>,
    key_row_id: &str,
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE ally_keys SET wrapped_privkey = $1
         WHERE id = $2 AND wrapped_privkey = $3 AND revoked_at IS NULL",
    )
    .bind(new.to_string())
    .bind(key_row_id)
    .bind(old.to_string())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Ids of the member's active allies (notification recipients).
pub async fn active_ally_ids<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<Vec<UserId>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT ally_id FROM ally_links WHERE member_id = $1 AND state = 'active'
         ORDER BY activated_at, id",
    )
    .bind(member.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("ally_id")?)))
        .collect()
}

/// Ids of the members `ally` is an active ally for.
pub async fn active_member_ids<'e>(
    e: impl Executor<'e, Database = Any>,
    ally: &UserId,
) -> Result<Vec<UserId>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT member_id FROM ally_links WHERE ally_id = $1 AND state = 'active'
         ORDER BY activated_at, id",
    )
    .bind(ally.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("member_id")?)))
        .collect()
}

/// Every live (pending or active) link `user` is part of, as member or as
/// ally: `(member, ally)` pairs.
pub async fn live_links_of<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
) -> Result<Vec<(UserId, UserId)>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT member_id, ally_id FROM ally_links
         WHERE (member_id = $1 OR ally_id = $1) AND state <> 'removed'
         ORDER BY created_at, id",
    )
    .bind(user.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok((
                UserId::new(r.try_get::<String, _>("member_id")?),
                UserId::new(r.try_get::<String, _>("ally_id")?),
            ))
        })
        .collect()
}

/// One active, member-endorsed ally of `member`, as stored.
#[derive(Debug, Clone)]
pub struct ActiveAlly {
    pub ally_id: UserId,
    pub endorsement: Signed<AllyEndorsement>,
}

/// Active links that carry a member endorsement. Rows whose stored JSON does
/// not parse are skipped (and logged) rather than failing the whole directory:
/// a device must still be able to encrypt to the remaining allies.
pub async fn active_endorsed<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<Vec<ActiveAlly>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT ally_id, endorsement_json FROM ally_links
         WHERE member_id = $1 AND state = 'active' AND endorsement_json IS NOT NULL
         ORDER BY activated_at, id",
    )
    .bind(member.as_str())
    .fetch_all(e)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let ally_id = UserId::new(r.try_get::<String, _>("ally_id")?);
        match parse_col(r, "endorsement_json", |s| serde_json::from_str(s).ok()) {
            Ok(endorsement) => out.push(ActiveAlly {
                ally_id,
                endorsement,
            }),
            Err(_) => tracing::warn!(ally = %ally_id, "skipping unparseable ally endorsement"),
        }
    }
    Ok(out)
}

/// The ally's current (non-revoked) encryption public keys.
pub async fn live_enc_keys<'e>(
    e: impl Executor<'e, Database = Any>,
    ally: &UserId,
) -> Result<Vec<EncPublicKey>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT enc_pubkey FROM ally_keys WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(ally.as_str())
            .fetch_all(e)
            .await?;
    rows.iter()
        .map(|r| parse_col(r, "enc_pubkey", EncPublicKey::from_b64))
        .collect()
}
