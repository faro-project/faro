//! `events`, `event_recipients` and `blobs`.

use super::parse_col;
use crate::blob::BlobId;
use crate::db::to_i64;
use faro_proto::{DeviceId, Hash32, UserId};
use sqlx::{Any, Executor, Row};

/// Which kind of ciphertext a blob holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobKind {
    EventBody,
    Report,
}

impl BlobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BlobKind::EventBody => "event_body",
            BlobKind::Report => "report",
        }
    }
}

fn seq_i64(seq: u64) -> Result<i64, sqlx::Error> {
    to_i64(seq).ok_or_else(|| sqlx::Error::Encode("seq overflow".into()))
}

/// Ciphertext bytes currently stored for a device (event bodies and reports).
pub async fn device_stored_bytes<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &faro_proto::DeviceId,
) -> Result<u64, sqlx::Error> {
    let n: i64 = sqlx::query_scalar(
        "SELECT CAST(COALESCE(SUM(b.size), 0) AS BIGINT) FROM blobs b
         WHERE b.id IN (SELECT blob_id FROM events WHERE device_id = $1 AND blob_id IS NOT NULL
                        UNION
                        SELECT blob_id FROM reports WHERE device_id = $1 AND blob_id IS NOT NULL)",
    )
    .bind(device.as_str())
    .fetch_one(e)
    .await?;
    Ok(u64::try_from(n).unwrap_or(0))
}

pub async fn insert_blob<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &BlobId,
    kind: BlobKind,
    owner_member: &UserId,
    size: usize,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    let size = i64::try_from(size).map_err(|_| sqlx::Error::Encode("blob size overflow".into()))?;
    sqlx::query(
        "INSERT INTO blobs (id, kind, owner_member_id, size, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id.as_str())
    .bind(kind.as_str())
    .bind(owner_member.as_str())
    .bind(size)
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(())
}

/// The stored header hash at `(device, seq)`, if any.
pub async fn stored_header_hash<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &DeviceId,
    seq: u64,
) -> Result<Option<Hash32>, sqlx::Error> {
    let row = sqlx::query("SELECT header_hash FROM events WHERE device_id = $1 AND seq = $2")
        .bind(device.as_str())
        .bind(seq_i64(seq)?)
        .fetch_optional(e)
        .await?;
    row.map(|r| parse_col(&r, "header_hash", Hash32::from_prefixed_hex))
        .transpose()
}

pub struct NewEvent<'a> {
    pub device_id: &'a DeviceId,
    pub member_id: &'a UserId,
    pub seq: u64,
    pub ts_ms: i64,
    pub kind: &'a str,
    pub urgency: &'a str,
    pub effective_urgency: &'a str,
    pub header_json: &'a str,
    pub header_hash: &'a Hash32,
    pub sig_b64: &'a str,
    pub blob_id: Option<&'a BlobId>,
    pub received_at_ms: i64,
}

pub async fn insert_event<'e>(
    e: impl Executor<'e, Database = Any>,
    ev: &NewEvent<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO events (device_id, seq, member_id, ts_ms, kind, urgency, effective_urgency,
                             header_json, header_hash, sig, blob_id, received_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(ev.device_id.as_str())
    .bind(seq_i64(ev.seq)?)
    .bind(ev.member_id.as_str())
    .bind(ev.ts_ms)
    .bind(ev.kind)
    .bind(ev.urgency)
    .bind(ev.effective_urgency)
    .bind(ev.header_json)
    .bind(ev.header_hash.to_prefixed_hex())
    .bind(ev.sig_b64)
    .bind(ev.blob_id.map(|b| b.as_str().to_owned()))
    .bind(ev.received_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

pub async fn insert_recipient<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &DeviceId,
    seq: u64,
    recipient: &UserId,
    key_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO event_recipients (device_id, seq, recipient_id, key_id)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
    )
    .bind(device.as_str())
    .bind(seq_i64(seq)?)
    .bind(recipient.as_str())
    .bind(key_id)
    .execute(e)
    .await?;
    Ok(())
}

/// One stored header, as `GET /v1/ally/chain` serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHeader {
    pub header_json: String,
    pub sig: String,
    pub received_at_ms: i64,
}

/// Up to `limit` of `member`'s `device`'s stored headers from `from_seq`
/// (inclusive), by `seq`. A device of another member gives none.
pub async fn headers_from<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
    device: &DeviceId,
    from_seq: u64,
    limit: i64,
) -> Result<Vec<StoredHeader>, sqlx::Error> {
    // A `from_seq` past i64::MAX can't match anything.
    let Some(from) = to_i64(from_seq) else {
        return Ok(Vec::new());
    };
    sqlx::query(
        "SELECT header_json, sig, received_at FROM events
         WHERE member_id = $1 AND device_id = $2 AND seq >= $3
         ORDER BY seq LIMIT $4",
    )
    .bind(member.as_str())
    .bind(device.as_str())
    .bind(from)
    .bind(limit)
    .fetch_all(e)
    .await?
    .iter()
    .map(|r| {
        Ok(StoredHeader {
            header_json: r.try_get("header_json")?,
            sig: r.try_get("sig")?,
            received_at_ms: r.try_get("received_at")?,
        })
    })
    .collect()
}
