//! `alerts`: things allies may need to be told about.
//!
//! Rows are written by ingest (stage A) and fanned out to `notifications` by
//! the stage-B notifier, which picks up rows with `dispatched_at IS NULL`.
//! `detail` is a short machine code (e.g. `"missing 3..=7"`), never content.

use crate::tokens::new_hex_id;
use faro_proto::{DeviceId, Urgency, UserId};
use sqlx::{Any, Executor};

/// Who raised the alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSource {
    /// Mirrors an uploaded event; `kind` is an `EventKind`.
    Device,
    /// Raised by the instance; `kind` is a `ServerAlertKind`.
    Server,
}

impl AlertSource {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertSource::Device => "device",
            AlertSource::Server => "server",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewAlert<'a> {
    pub member_id: &'a UserId,
    pub device_id: Option<&'a DeviceId>,
    pub source: AlertSource,
    pub kind: &'a str,
    pub urgency: Urgency,
    pub event_seq: Option<i64>,
    pub detail: Option<String>,
    /// Alerts with the same key are recorded once. Used so a device retrying
    /// the same bad upload does not page its allies every minute.
    pub dedupe_key: Option<String>,
    pub now_ms: i64,
}

/// Insert an alert. Returns false if an alert with the same dedupe key exists.
pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    a: &NewAlert<'_>,
) -> Result<bool, sqlx::Error> {
    insert_with_extra_recipient(e, a, None).await
}

/// Like [`insert`], with one recipient beyond the member and their current
/// allies: the ally who was just removed must be told although they are no
/// longer an ally (§3.7).
pub async fn insert_with_extra_recipient<'e>(
    e: impl Executor<'e, Database = Any>,
    a: &NewAlert<'_>,
    extra_recipient: Option<&UserId>,
) -> Result<bool, sqlx::Error> {
    insert_routed(e, a, extra_recipient, None).await
}

/// The most general insert: `extra_recipient` is told in addition to the
/// member and their active allies; `skip_recipient` is an ally who is *not*
/// told through this alert (the ally just added, who gets their own notice).
/// The member themself is never skipped (see [`crate::notify`]).
pub async fn insert_routed<'e>(
    e: impl Executor<'e, Database = Any>,
    a: &NewAlert<'_>,
    extra_recipient: Option<&UserId>,
    skip_recipient: Option<&UserId>,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "INSERT INTO alerts (id, member_id, device_id, source, kind, urgency, event_seq, detail,
                             dedupe_key, created_at, extra_recipient_id, skip_recipient_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         ON CONFLICT (dedupe_key) DO NOTHING",
    )
    .bind(new_hex_id())
    .bind(a.member_id.as_str())
    .bind(a.device_id.map(|d| d.as_str().to_owned()))
    .bind(a.source.as_str())
    .bind(a.kind)
    .bind(a.urgency.as_str())
    .bind(a.event_seq)
    .bind(a.detail.clone())
    .bind(a.dedupe_key.clone())
    .bind(a.now_ms)
    .bind(extra_recipient.map(|u| u.as_str().to_owned()))
    .bind(skip_recipient.map(|u| u.as_str().to_owned()))
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// A compact view of an alert row (used by tests and, later, the feed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRow {
    pub member_id: String,
    pub device_id: Option<String>,
    pub source: String,
    pub kind: String,
    pub urgency: String,
    pub event_seq: Option<i64>,
    pub detail: Option<String>,
    pub created_at_ms: i64,
}

pub async fn list_for_member<'e>(
    e: impl Executor<'e, Database = Any>,
    member: &UserId,
) -> Result<Vec<AlertRow>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT member_id, device_id, source, kind, urgency, event_seq, detail, created_at
         FROM alerts WHERE member_id = $1 ORDER BY created_at, id",
    )
    .bind(member.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(AlertRow {
                member_id: r.try_get("member_id")?,
                device_id: r.try_get("device_id")?,
                source: r.try_get("source")?,
                kind: r.try_get("kind")?,
                urgency: r.try_get("urgency")?,
                event_seq: r.try_get("event_seq")?,
                detail: r.try_get("detail")?,
                created_at_ms: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// An alert that has not yet been fanned out to notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndispatchedAlert {
    pub id: String,
    pub member_id: UserId,
    pub device_id: Option<DeviceId>,
    pub source: String,
    pub kind: String,
    pub urgency: Urgency,
    pub extra_recipient: Option<UserId>,
    pub skip_recipient: Option<UserId>,
}

pub async fn undispatched<'e>(
    e: impl Executor<'e, Database = Any>,
    limit: i64,
) -> Result<Vec<UndispatchedAlert>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, member_id, device_id, source, kind, urgency, extra_recipient_id,
                skip_recipient_id FROM alerts
         WHERE dispatched_at IS NULL ORDER BY created_at, id LIMIT $1",
    )
    .bind(limit)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            Ok(UndispatchedAlert {
                id: r.try_get("id")?,
                member_id: UserId::new(r.try_get::<String, _>("member_id")?),
                device_id: r
                    .try_get::<Option<String>, _>("device_id")?
                    .map(DeviceId::new),
                source: r.try_get("source")?,
                kind: r.try_get("kind")?,
                urgency: super::parse_col(r, "urgency", Urgency::parse)?,
                extra_recipient: r
                    .try_get::<Option<String>, _>("extra_recipient_id")?
                    .map(UserId::new),
                skip_recipient: r
                    .try_get::<Option<String>, _>("skip_recipient_id")?
                    .map(UserId::new),
            })
        })
        .collect()
}

pub async fn mark_dispatched<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE alerts SET dispatched_at = $1 WHERE id = $2")
        .bind(now_ms)
        .bind(id)
        .execute(e)
        .await?;
    Ok(())
}
