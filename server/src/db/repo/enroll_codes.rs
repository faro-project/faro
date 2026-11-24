//! `enroll_codes`: short, single-use device enrollment codes.

use faro_proto::{DeviceId, UserId};
use sqlx::{Any, AnyConnection, Executor, Row};

pub async fn count_outstanding<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    now_ms: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "SELECT COUNT(*) AS n FROM enroll_codes
         WHERE member_id = $1 AND used_at IS NULL AND expires_at > $2",
    )
    .bind(member.as_str())
    .bind(now_ms)
    .fetch_one(e)
    .await?
    .try_get("n")
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    code_hash: &str,
    member: &UserId,
    now_ms: i64,
    expires_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO enroll_codes (code_hash, member_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(code_hash)
    .bind(member.as_str())
    .bind(now_ms)
    .bind(expires_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// Atomically redeem a code; returns the member it is bound to.
pub async fn consume(
    conn: &mut AnyConnection,
    code_hash: &str,
    now_ms: i64,
) -> Result<Option<UserId>, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE enroll_codes SET used_at = $1
         WHERE code_hash = $2 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now_ms)
    .bind(code_hash)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() != 1 {
        return Ok(None);
    }
    let row = sqlx::query("SELECT member_id FROM enroll_codes WHERE code_hash = $1")
        .bind(code_hash)
        .fetch_one(&mut *conn)
        .await?;
    Ok(Some(UserId::new(row.try_get::<String, _>("member_id")?)))
}

pub async fn link_device<'e>(
    e: impl Executor<'e, Database = Any>,
    code_hash: &str,
    device: &DeviceId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE enroll_codes SET device_id = $1 WHERE code_hash = $2")
        .bind(device.as_str())
        .bind(code_hash)
        .execute(e)
        .await?;
    Ok(())
}
