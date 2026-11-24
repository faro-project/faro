//! `reports` and `report_recipients`.

use crate::blob::BlobId;
use faro_proto::{DeviceId, Hash32, UserId};
use sqlx::{Any, Executor, Row};

pub struct NewReport<'a> {
    pub id: &'a str,
    pub member_id: &'a UserId,
    pub device_id: &'a DeviceId,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub first_seq: Option<i64>,
    pub last_seq: Option<i64>,
    pub header_json: &'a str,
    pub header_hash: &'a Hash32,
    pub sig_b64: &'a str,
    pub blob_id: &'a BlobId,
    pub received_at_ms: i64,
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    r: &NewReport<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO reports (id, member_id, device_id, period_start_ms, period_end_ms, first_seq,
                              last_seq, header_json, header_hash, sig, blob_id, received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(r.id)
    .bind(r.member_id.as_str())
    .bind(r.device_id.as_str())
    .bind(r.period_start_ms)
    .bind(r.period_end_ms)
    .bind(r.first_seq)
    .bind(r.last_seq)
    .bind(r.header_json)
    .bind(r.header_hash.to_prefixed_hex())
    .bind(r.sig_b64)
    .bind(r.blob_id.as_str())
    .bind(r.received_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// The id of an already-stored report with the same signed header.
pub async fn find_by_header<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &DeviceId,
    header_hash: &Hash32,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query("SELECT id FROM reports WHERE device_id = $1 AND header_hash = $2")
        .bind(device.as_str())
        .bind(header_hash.to_prefixed_hex())
        .fetch_optional(e)
        .await?
        .map(|r| r.try_get("id"))
        .transpose()
}

pub async fn insert_recipient<'e>(
    e: impl Executor<'e, Database = Any>,
    report_id: &str,
    recipient: &UserId,
    key_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO report_recipients (report_id, recipient_id, key_id)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(report_id)
    .bind(recipient.as_str())
    .bind(key_id)
    .execute(e)
    .await?;
    Ok(())
}

/// A stored report not yet fanned out to notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndispatchedReport {
    pub id: String,
    pub member_id: UserId,
}

pub async fn undispatched<'e>(
    e: impl Executor<'e, Database = Any>,
    limit: i64,
) -> Result<Vec<UndispatchedReport>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, member_id FROM reports WHERE dispatched_at IS NULL
         ORDER BY received_at, id LIMIT $1",
    )
    .bind(limit)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(UndispatchedReport {
                id: r.try_get("id")?,
                member_id: UserId::new(r.try_get::<String, _>("member_id")?),
            })
        })
        .collect()
}

pub async fn mark_dispatched<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE reports SET dispatched_at = $1 WHERE id = $2")
        .bind(now_ms)
        .bind(id)
        .execute(e)
        .await?;
    Ok(())
}
