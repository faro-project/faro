//! `setup_tokens` and `magic_links`: single-use, hashed, expiring secrets.
//!
//! Consumption is a single conditional `UPDATE … WHERE used_at IS NULL AND
//! expires_at > now`, so two concurrent redemptions of the same token cannot
//! both succeed: exactly one sees an affected row.

use faro_proto::UserId;
use sqlx::{Any, AnyConnection, Executor, Row};

/// Issue a new setup token, invalidating any earlier unused ones so at most
/// one is ever valid.
pub async fn replace_setup_token(
    conn: &mut AnyConnection,
    token_hash: &str,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE setup_tokens SET used_at = $1 WHERE used_at IS NULL")
        .bind(now_ms)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO setup_tokens (token_hash, created_at, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(token_hash)
    .bind(now_ms)
    .bind(expires_at_ms)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn has_valid_setup_token<'e>(
    e: impl Executor<'e, Database = Any>,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM setup_tokens WHERE used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .fetch_one(e)
    .await?;
    Ok(row.try_get::<i64, _>("n")? > 0)
}

/// Atomically mark a setup token used. True if it was valid.
pub async fn consume_setup_token<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE setup_tokens SET used_at = $1
         WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(token_hash)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn insert_magic_link<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
    email: &str,
    user_id: Option<&UserId>,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO magic_links (token_hash, email, user_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(token_hash)
    .bind(email)
    .bind(user_id.map(|u| u.as_str().to_owned()))
    .bind(now_ms)
    .bind(expires_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// What a redeemed magic link was for.
#[derive(Debug, Clone)]
pub struct RedeemedLink {
    pub email: String,
    pub user_id: Option<UserId>,
}

/// Atomically redeem a magic link. `None` if unknown, used or expired.
pub async fn consume_magic_link(
    conn: &mut AnyConnection,
    token_hash: &str,
    now_ms: i64,
) -> Result<Option<RedeemedLink>, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE magic_links SET used_at = $1
         WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(token_hash)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() != 1 {
        return Ok(None);
    }
    let row = sqlx::query("SELECT email, user_id FROM magic_links WHERE token_hash = $1")
        .bind(token_hash)
        .fetch_one(&mut *conn)
        .await?;
    Ok(Some(RedeemedLink {
        email: row.try_get("email")?,
        user_id: row
            .try_get::<Option<String>, _>("user_id")?
            .map(UserId::new),
    }))
}
