//! `member_keys`: a member's public keys plus their opaque wrapped private keys.

use super::parse_col;
use faro_proto::keys::{MemberEncKeyBinding, Signed};
use faro_proto::{EncPublicKey, SignPublicKey, UserId};
use sqlx::{Any, Executor, Row};

#[derive(Debug, Clone, PartialEq)]
pub struct MemberKeysRow {
    pub user_id: UserId,
    pub sign_pubkey: SignPublicKey,
    pub enc_pubkey: EncPublicKey,
    pub enc_binding: Signed<MemberEncKeyBinding>,
    pub wrapped_sign_key: serde_json::Value,
    pub wrapped_enc_key: serde_json::Value,
    pub recovery_wrapped: serde_json::Value,
    pub created_at_ms: i64,
}

fn json_col<T: serde::de::DeserializeOwned>(
    row: &sqlx::any::AnyRow,
    col: &str,
) -> Result<T, sqlx::Error> {
    parse_col(row, col, |s| serde_json::from_str(s).ok())
}

/// Insert keys for a user who has none. Returns false if keys already exist
/// for this user. A `sign_pubkey` already used by another member surfaces as
/// a unique-violation error.
pub async fn insert_new<'e>(
    e: impl Executor<'e, Database = Any>,
    row: &MemberKeysRow,
) -> Result<bool, sqlx::Error> {
    let binding =
        serde_json::to_string(&row.enc_binding).map_err(|e| sqlx::Error::Encode(Box::new(e)))?;
    let r = sqlx::query(
        "INSERT INTO member_keys (user_id, sign_pubkey, enc_pubkey, enc_binding_json,
                                  wrapped_sign_key, wrapped_enc_key, recovery_wrapped,
                                  created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(row.user_id.as_str())
    .bind(row.sign_pubkey.to_b64())
    .bind(row.enc_pubkey.to_b64())
    .bind(binding)
    .bind(row.wrapped_sign_key.to_string())
    .bind(row.wrapped_enc_key.to_string())
    .bind(row.recovery_wrapped.to_string())
    .bind(row.created_at_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn get<'e>(
    e: impl Executor<'e, Database = Any>,
    user_id: &UserId,
) -> Result<Option<MemberKeysRow>, sqlx::Error> {
    let Some(row) = sqlx::query(
        "SELECT user_id, sign_pubkey, enc_pubkey, enc_binding_json, wrapped_sign_key,
                wrapped_enc_key, recovery_wrapped, created_at
         FROM member_keys WHERE user_id = $1",
    )
    .bind(user_id.as_str())
    .fetch_optional(e)
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(MemberKeysRow {
        user_id: UserId::new(row.try_get::<String, _>("user_id")?),
        sign_pubkey: parse_col(&row, "sign_pubkey", SignPublicKey::from_b64)?,
        enc_pubkey: parse_col(&row, "enc_pubkey", EncPublicKey::from_b64)?,
        enc_binding: json_col(&row, "enc_binding_json")?,
        wrapped_sign_key: json_col(&row, "wrapped_sign_key")?,
        wrapped_enc_key: json_col(&row, "wrapped_enc_key")?,
        recovery_wrapped: json_col(&row, "recovery_wrapped")?,
        created_at_ms: row.try_get("created_at")?,
    }))
}

/// Just the member's signing key (hot path for device endorsement checks).
pub async fn sign_pubkey<'e>(
    e: impl Executor<'e, Database = Any>,
    user_id: &UserId,
) -> Result<Option<SignPublicKey>, sqlx::Error> {
    let Some(row) = sqlx::query("SELECT sign_pubkey FROM member_keys WHERE user_id = $1")
        .bind(user_id.as_str())
        .fetch_optional(e)
        .await?
    else {
        return Ok(None);
    };
    parse_col(&row, "sign_pubkey", SignPublicKey::from_b64).map(Some)
}
