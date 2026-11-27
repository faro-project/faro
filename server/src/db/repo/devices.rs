//! `devices`: enrolled devices, their keys, liveness and verified chain head.

use super::{parse_col, parse_opt_col};
use crate::db::{to_i64, to_u64};
use faro_proto::api::Platform;
use faro_proto::{DeviceId, Hash32, SignPublicKey, UserId};
use serde::Serialize;
use sqlx::any::AnyRow;
use sqlx::{Any, Executor, Row};

/// Device lifecycle (§3.8, §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Enrolled with a code; waiting for the member key to sign the device key.
    PendingEndorsement,
    /// Endorsed by the member; may upload events and reports.
    Active,
    /// Removed; its token no longer authenticates.
    Removed,
}

impl DeviceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceStatus::PendingEndorsement => "pending_endorsement",
            DeviceStatus::Active => "active",
            DeviceStatus::Removed => "removed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending_endorsement" => Some(Self::PendingEndorsement),
            "active" => Some(Self::Active),
            "removed" => Some(Self::Removed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    pub id: DeviceId,
    pub owner_user_id: UserId,
    pub platform: Platform,
    pub name: String,
    pub sign_pubkey: SignPublicKey,
    pub status: DeviceStatus,
    /// `Signed<DeviceEndorsement>` JSON once endorsed.
    pub member_sig: Option<String>,
    pub enrolled_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
    /// Verified chain head (highest stored seq and its chain hash).
    pub last_seq: Option<u64>,
    pub last_hash: Option<Hash32>,
}

/// The column list every device read selects, as a macro so that queries
/// can be assembled with `concat!` into `&'static str` (sqlx only accepts
/// static SQL without an explicit audit).
macro_rules! columns {
    () => {
        "id, owner_user_id, platform, name, sign_pubkey, status, member_sig,
         enrolled_at, last_seen_at, last_seq, last_hash"
    };
}

fn from_row(row: &AnyRow) -> Result<DeviceRow, sqlx::Error> {
    Ok(DeviceRow {
        id: DeviceId::new(row.try_get::<String, _>("id")?),
        owner_user_id: UserId::new(row.try_get::<String, _>("owner_user_id")?),
        platform: parse_col(row, "platform", Platform::parse)?,
        name: row.try_get("name")?,
        sign_pubkey: parse_col(row, "sign_pubkey", SignPublicKey::from_b64)?,
        status: parse_col(row, "status", DeviceStatus::parse)?,
        member_sig: row.try_get("member_sig")?,
        enrolled_at_ms: row.try_get("enrolled_at")?,
        last_seen_at_ms: row.try_get("last_seen_at")?,
        last_seq: row
            .try_get::<Option<i64>, _>("last_seq")?
            .map(to_u64)
            .transpose()?,
        last_hash: parse_opt_col(row, "last_hash", Hash32::from_prefixed_hex)?,
    })
}

pub struct NewDevice<'a> {
    pub id: &'a DeviceId,
    pub owner_user_id: &'a UserId,
    pub platform: Platform,
    pub name: &'a str,
    pub client_version: &'a str,
    pub sign_pubkey: &'a SignPublicKey,
    pub token_hash: &'a str,
    pub now_ms: i64,
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    d: &NewDevice<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices (id, owner_user_id, platform, name, client_version, sign_pubkey,
                              token_hash, status, enrolled_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending_endorsement', $8)",
    )
    .bind(d.id.as_str())
    .bind(d.owner_user_id.as_str())
    .bind(d.platform.as_str())
    .bind(d.name)
    .bind(d.client_version)
    .bind(d.sign_pubkey.to_b64())
    .bind(d.token_hash)
    .bind(d.now_ms)
    .execute(e)
    .await?;
    Ok(())
}

pub async fn by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &DeviceId,
) -> Result<Option<DeviceRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM devices WHERE id = $1"
    ))
    .bind(id.as_str())
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

pub async fn by_token_hash<'e>(
    e: impl Executor<'e, Database = Any>,
    token_hash: &str,
) -> Result<Option<DeviceRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM devices WHERE token_hash = $1"
    ))
    .bind(token_hash)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

pub async fn sign_pubkey_in_use<'e>(
    e: impl Executor<'e, Database = Any>,
    pk: &SignPublicKey,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 AS x FROM devices WHERE sign_pubkey = $1")
            .bind(pk.to_b64())
            .fetch_optional(e)
            .await?
            .is_some(),
    )
}

/// Mark a pending device active with the member's endorsement. Returns false
/// if the device was not pending (or not the caller's).
pub async fn activate<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &DeviceId,
    owner: &UserId,
    endorsement_json: &str,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE devices SET status = 'active', member_sig = $1, endorsed_at = $2
         WHERE id = $3 AND owner_user_id = $4 AND status = 'pending_endorsement'",
    )
    .bind(endorsement_json)
    .bind(now_ms)
    .bind(id.as_str())
    .bind(owner.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Compare-and-set the verified chain head. `expected` is the head the caller
/// verified against; if another writer moved it meanwhile, nothing changes and
/// `false` is returned.
///
/// The same update keeps the liveness bookkeeping in step with the head:
/// `upload_behind_since` clears once the head reaches the position the
/// device last claimed in a heartbeat, and `goodbye_at` is `goodbye_at_ms`
/// (set for an accepted `goodbye`, cleared by any later event).
pub async fn advance_head<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &DeviceId,
    expected_last_seq: Option<u64>,
    new_seq: u64,
    new_hash: &Hash32,
    goodbye_at_ms: Option<i64>,
) -> Result<bool, sqlx::Error> {
    let new_seq = to_i64(new_seq).ok_or_else(|| sqlx::Error::Encode("seq overflow".into()))?;
    let q = match expected_last_seq {
        None => sqlx::query(
            "UPDATE devices SET last_seq = $1, last_hash = $2, goodbye_at = $3,
                    upload_behind_since = CASE WHEN reported_last_seq > $1
                                               THEN upload_behind_since ELSE NULL END
             WHERE id = $4 AND last_seq IS NULL",
        )
        .bind(new_seq)
        .bind(new_hash.to_prefixed_hex())
        .bind(goodbye_at_ms)
        .bind(id.as_str()),
        Some(old) => {
            let old = to_i64(old).ok_or_else(|| sqlx::Error::Encode("seq overflow".into()))?;
            sqlx::query(
                "UPDATE devices SET last_seq = $1, last_hash = $2, goodbye_at = $3,
                        upload_behind_since = CASE WHEN reported_last_seq > $1
                                                   THEN upload_behind_since ELSE NULL END
                 WHERE id = $4 AND last_seq = $5",
            )
            .bind(new_seq)
            .bind(new_hash.to_prefixed_hex())
            .bind(goodbye_at_ms)
            .bind(id.as_str())
            .bind(old)
        }
    };
    Ok(q.execute(e).await?.rows_affected() == 1)
}

pub struct HeartbeatUpdate<'a> {
    pub now_ms: i64,
    pub state: &'a str,
    pub boot_id: &'a str,
    pub reported_last_seq: Option<i64>,
    pub reported_last_hash: Option<String>,
}

/// Record a heartbeat. A device heard from is no longer "gone" after a
/// `goodbye`. `upload_behind_since` starts when the claimed position first
/// gets ahead of the verified head and clears when it is not (any more).
pub async fn record_heartbeat<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &DeviceId,
    hb: &HeartbeatUpdate<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = $1, last_state = $2, last_boot_id = $3,
                            reported_last_seq = $4, reported_last_hash = $5, goodbye_at = NULL,
                            upload_behind_since =
                                CASE WHEN $4 IS NOT NULL AND (last_seq IS NULL OR $4 > last_seq)
                                     THEN COALESCE(upload_behind_since, $1) ELSE NULL END
         WHERE id = $6",
    )
    .bind(hb.now_ms)
    .bind(hb.state)
    .bind(hb.boot_id)
    .bind(hb.reported_last_seq)
    .bind(hb.reported_last_hash.clone())
    .bind(id.as_str())
    .execute(e)
    .await?;
    Ok(())
}

/// Retire a device at its owner's request: its token stops authenticating
/// at once ([`crate::device_auth`]) and the liveness monitor forgets it.
/// False if `owner` has no such live device.
pub async fn remove<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &DeviceId,
    owner: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE devices SET status = 'removed', removed_at = $1
         WHERE id = $2 AND owner_user_id = $3 AND status <> 'removed'",
    )
    .bind(now_ms)
    .bind(id.as_str())
    .bind(owner.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// All non-removed devices of a member, oldest first.
pub async fn list_for_owner<'e>(
    e: impl Executor<'e, Database = Any>,
    owner: &UserId,
) -> Result<Vec<DeviceRow>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM devices WHERE owner_user_id = $1 AND status <> 'removed'
         ORDER BY enrolled_at, id"
    ))
    .bind(owner.as_str())
    .fetch_all(e)
    .await?
    .iter()
    .map(from_row)
    .collect()
}

/// The platform of each of a member's devices, removed ones included: a
/// goodbye is the last thing a removed device says, and the feed still shows
/// it. Platform is not secret from anyone who can read the feed.
pub async fn platforms_for_owner<'e>(
    e: impl Executor<'e, Database = Any>,
    owner: &UserId,
) -> Result<Vec<(DeviceId, Platform)>, sqlx::Error> {
    sqlx::query("SELECT id, platform FROM devices WHERE owner_user_id = $1")
        .bind(owner.as_str())
        .fetch_all(e)
        .await?
        .iter()
        .map(|row| {
            Ok((
                DeviceId::new(row.try_get::<String, _>("id")?),
                parse_col(row, "platform", Platform::parse)?,
            ))
        })
        .collect()
}
