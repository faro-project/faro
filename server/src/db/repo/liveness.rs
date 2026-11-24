//! `liveness_episodes` and the device facts the liveness monitor reads.

use super::parse_col;
use crate::tokens::new_hex_id;
use faro_proto::{DeviceId, UserId};
use sqlx::{Any, AnyConnection, Executor, Row};

/// What the monitor knows about one active device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLiveness {
    pub device_id: DeviceId,
    pub member_id: UserId,
    /// Server receive time of the last heartbeat.
    pub last_seen_at_ms: Option<i64>,
    /// Last reported state (`sleeping`, `shutting_down`, ...).
    pub last_state: Option<String>,
    /// When the device became active (endorsed), or enrolled if unknown.
    pub active_since_ms: i64,
    /// The open missed-check-in episode, if any: (id, silence_start_ms).
    pub open_episode: Option<(String, i64)>,
    /// Chain position the device last claimed in a signed heartbeat.
    pub reported_last_seq: Option<i64>,
    /// The verified head the instance holds.
    pub last_seq: Option<i64>,
    /// Since when the claim has been ahead of the verified head.
    pub upload_behind_since_ms: Option<i64>,
}

/// Every active device the monitor judges. A device whose chain ended in an
/// accepted `goodbye` (and that has not been heard from since) is left out:
/// the goodbye was the alert.
pub async fn active_devices<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<Vec<DeviceLiveness>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT d.id, d.owner_user_id, d.last_seen_at, d.last_state,
                COALESCE(d.endorsed_at, d.enrolled_at) AS active_since,
                d.reported_last_seq, d.last_seq, d.upload_behind_since,
                e.id AS episode_id, e.silence_start_ms
         FROM devices d
         LEFT JOIN liveness_episodes e ON e.device_id = d.id AND e.closed_at IS NULL
         WHERE d.status = 'active' AND d.goodbye_at IS NULL
         ORDER BY d.id",
    )
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            let episode_id: Option<String> = r.try_get("episode_id")?;
            let start: Option<i64> = r.try_get("silence_start_ms")?;
            Ok(DeviceLiveness {
                device_id: DeviceId::new(r.try_get::<String, _>("id")?),
                member_id: UserId::new(r.try_get::<String, _>("owner_user_id")?),
                last_seen_at_ms: r.try_get("last_seen_at")?,
                last_state: r.try_get("last_state")?,
                active_since_ms: r.try_get("active_since")?,
                open_episode: episode_id.zip(start),
                reported_last_seq: r.try_get("reported_last_seq")?,
                last_seq: r.try_get("last_seq")?,
                upload_behind_since_ms: r.try_get("upload_behind_since")?,
            })
        })
        .collect()
}

/// Open an episode. False if the device already has an open one.
pub async fn open_episode<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &DeviceId,
    member: &UserId,
    silence_start_ms: i64,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "INSERT INTO liveness_episodes (id, device_id, member_id, silence_start_ms, opened_at)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(new_hex_id())
    .bind(device.as_str())
    .bind(member.as_str())
    .bind(silence_start_ms)
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// A closed episode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedEpisode {
    pub id: String,
    pub member_id: UserId,
    pub silence_start_ms: i64,
}

/// Close the device's open episode, if any (on check-in).
pub async fn close_open_episode(
    conn: &mut AnyConnection,
    device: &DeviceId,
    now_ms: i64,
) -> Result<Option<ClosedEpisode>, sqlx::Error> {
    let Some(row) = sqlx::query(
        "SELECT id, member_id, silence_start_ms FROM liveness_episodes
         WHERE device_id = $1 AND closed_at IS NULL",
    )
    .bind(device.as_str())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let id: String = row.try_get("id")?;
    let r = sqlx::query(
        "UPDATE liveness_episodes SET closed_at = $1 WHERE id = $2 AND closed_at IS NULL",
    )
    .bind(now_ms)
    .bind(&id)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() != 1 {
        return Ok(None);
    }
    Ok(Some(ClosedEpisode {
        id,
        member_id: parse_col(&row, "member_id", |s| Some(UserId::new(s)))?,
        silence_start_ms: row.try_get("silence_start_ms")?,
    }))
}

/// Whether the device has an open episode (read-only fast path).
pub async fn has_open_episode<'e>(
    e: impl Executor<'e, Database = Any>,
    device: &DeviceId,
) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 AS x FROM liveness_episodes WHERE device_id = $1 AND closed_at IS NULL",
    )
    .bind(device.as_str())
    .fetch_optional(e)
    .await?
    .is_some())
}
