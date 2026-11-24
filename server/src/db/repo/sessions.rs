//! `sessions`: browser sessions, keyed by the hash of the cookie value.

use super::users::{self, User};
use sqlx::{Any, Executor, Row};

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    id_hash: &str,
    user_id: &faro_proto::UserId,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO sessions (id_hash, user_id, created_at, expires_at, last_seen_at)
         VALUES ($1, $2, $3, $4, $3)",
    )
    .bind(id_hash)
    .bind(user_id.as_str())
    .bind(now_ms)
    .bind(expires_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// A live session's user, plus when the session was last touched.
pub struct LiveSession {
    pub user: User,
    pub last_seen_at_ms: i64,
}

/// Look up an unexpired session whose user is not disabled.
pub async fn lookup<'e>(
    e: impl Executor<'e, Database = Any>,
    id_hash: &str,
    now_ms: i64,
) -> Result<Option<LiveSession>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT u.id, u.email, u.display_name, u.is_admin, u.is_member, u.is_ally,
                u.disabled, u.created_at, s.last_seen_at
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.id_hash = $1 AND s.expires_at > $2 AND u.disabled = 0",
    )
    .bind(id_hash)
    .bind(now_ms)
    .fetch_optional(e)
    .await?;
    match row {
        None => Ok(None),
        Some(r) => Ok(Some(LiveSession {
            user: users::from_row(&r)?,
            last_seen_at_ms: r.try_get("last_seen_at")?,
        })),
    }
}

pub async fn touch<'e>(
    e: impl Executor<'e, Database = Any>,
    id_hash: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET last_seen_at = $1 WHERE id_hash = $2")
        .bind(now_ms)
        .bind(id_hash)
        .execute(e)
        .await?;
    Ok(())
}

pub async fn delete<'e>(
    e: impl Executor<'e, Database = Any>,
    id_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE id_hash = $1")
        .bind(id_hash)
        .execute(e)
        .await?;
    Ok(())
}
