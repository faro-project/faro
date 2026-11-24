//! `instance`: the single row describing this instance.

use super::parse_col;
use faro_proto::{InstanceId, SignPublicKey};
use sqlx::{Any, Executor, Row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRow {
    pub id: InstanceId,
    pub name: String,
    pub identity_pubkey: SignPublicKey,
    pub created_at_ms: i64,
}

pub async fn get<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<Option<InstanceRow>, sqlx::Error> {
    let Some(row) = sqlx::query("SELECT id, name, identity_pubkey, created_at FROM instance")
        .fetch_optional(e)
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(InstanceRow {
        id: parse_col(&row, "id", |s| {
            let id = InstanceId::new(s);
            id.is_well_formed().then_some(id)
        })?,
        name: row.try_get("name")?,
        identity_pubkey: parse_col(&row, "identity_pubkey", SignPublicKey::from_b64)?,
        created_at_ms: row.try_get("created_at")?,
    }))
}

/// Insert the instance row if none exists. Returns whether this call created it.
pub async fn insert_if_absent<'e>(
    e: impl Executor<'e, Database = Any>,
    row: &InstanceRow,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "INSERT INTO instance (id, singleton, name, identity_pubkey, created_at)
         VALUES ($1, 1, $2, $3, $4)
         ON CONFLICT (singleton) DO NOTHING",
    )
    .bind(row.id.as_str())
    .bind(&row.name)
    .bind(row.identity_pubkey.to_b64())
    .bind(row.created_at_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn set_name<'e>(
    e: impl Executor<'e, Database = Any>,
    name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE instance SET name = $1")
        .bind(name)
        .execute(e)
        .await?;
    Ok(())
}

/// The admin's stored setting overrides (see [`crate::settings`]).
pub async fn settings_json<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<String, sqlx::Error> {
    let row = sqlx::query("SELECT settings_json FROM instance")
        .fetch_optional(e)
        .await?;
    match row {
        Some(r) => r.try_get("settings_json"),
        None => Ok(String::new()),
    }
}

pub async fn set_settings_json<'e>(
    e: impl Executor<'e, Database = Any>,
    json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE instance SET settings_json = $1")
        .bind(json)
        .execute(e)
        .await?;
    Ok(())
}
