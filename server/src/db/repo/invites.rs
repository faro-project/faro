//! `invites`: single-use, hashed, expiring invitations (§4.3, §7).
//!
//! * `kind = 'ally'`: a member invites someone to be their ally. Redeemed by
//!   `POST /v1/invites/{token}/accept` from a session for the invited email.
//! * `kind = 'member'`: an admin invites someone to become a member. Redeemed
//!   when the invited address first signs in.
//!
//! An outstanding invite of either kind lets its email address sign in (and
//! so create an account) under `invite-only` registration.

use faro_proto::UserId;
use sqlx::{Any, AnyConnection, Executor, Row};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteKind {
    Member,
    Ally,
}

impl InviteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InviteKind::Member => "member",
            InviteKind::Ally => "ally",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "member" => Some(Self::Member),
            "ally" => Some(Self::Ally),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRow {
    pub token_hash: String,
    pub kind: InviteKind,
    pub inviter_id: UserId,
    pub email: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    row: &InviteRow,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invites (token_hash, kind, inviter_id, email, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&row.token_hash)
    .bind(row.kind.as_str())
    .bind(row.inviter_id.as_str())
    .bind(&row.email)
    .bind(row.created_at_ms)
    .bind(row.expires_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

fn from_row(r: &sqlx::any::AnyRow) -> Result<InviteRow, sqlx::Error> {
    Ok(InviteRow {
        token_hash: r.try_get("token_hash")?,
        kind: super::parse_col(r, "kind", InviteKind::parse)?,
        inviter_id: UserId::new(r.try_get::<String, _>("inviter_id")?),
        email: r.try_get::<Option<String>, _>("email")?.unwrap_or_default(),
        created_at_ms: r.try_get("created_at")?,
        expires_at_ms: r.try_get("expires_at")?,
    })
}

/// An unused, unexpired invite by token hash.
pub async fn find_live<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    now_ms: i64,
) -> Result<Option<InviteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT token_hash, kind, inviter_id, email, created_at, expires_at FROM invites
         WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(token_hash)
    .bind(now_ms)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

/// Atomically mark an invite used by `user`. True if it was still live.
pub async fn consume<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    user: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE invites SET used_at = $1, used_by = $2
         WHERE token_hash = $3 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(user.as_str())
    .bind(token_hash)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Which live invite kinds exist for `email` (for sign-in under invite-only).
pub async fn live_kinds_for_email<'e>(
    e: impl Executor<'e, Database = Any>,
    email: &str,
    now_ms: i64,
) -> Result<Vec<InviteKind>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT DISTINCT kind FROM invites
         WHERE email = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(email)
    .bind(now_ms)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| super::parse_col(r, "kind", InviteKind::parse))
        .collect()
}

/// Redeem every live member invite for `email` (on first sign-in).
pub async fn consume_member_invites(
    conn: &mut AnyConnection,
    email: &str,
    user: &UserId,
    now_ms: i64,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE invites SET used_at = $1, used_by = $2
         WHERE email = $3 AND kind = 'member' AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(user.as_str())
    .bind(email)
    .execute(&mut *conn)
    .await?;
    Ok(r.rows_affected())
}

/// Live invites a user has sent (to cap how many one account can have open).
pub async fn count_live_by_inviter<'e>(
    e: impl Executor<'e, Database = Any>,
    inviter: &UserId,
    now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM invites
         WHERE inviter_id = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(inviter.as_str())
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}
