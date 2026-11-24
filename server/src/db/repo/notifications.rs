//! `notifications` and `notification_prefs` (§5.4).
//!
//! A notification row records that one recipient should be (or, with status
//! `suppressed`, chose not to be) told about one alert or report. Delivery
//! state: `pending` → `sent`, or after [`crate::notify::policy::MAX_ATTEMPTS`]
//! failures `failed`. `last_error` holds a short machine code only (never a
//! server response, which could echo addresses).

use super::parse_col;
use crate::notify::policy::{Mode, QuietHours};
use crate::tokens::new_hex_id;
use faro_proto::{DeviceId, Urgency, UserId};
use sqlx::{Any, Executor, Row};

/// What a notification is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Alert(String),
    Report(String),
}

pub struct NewNotification<'a> {
    pub target: &'a Target,
    pub recipient: &'a UserId,
    pub urgency: Urgency,
    /// `None` records a suppressed (`off`) notification.
    pub mode: Option<Mode>,
    pub due_at_ms: i64,
    pub now_ms: i64,
}

/// Insert unless this recipient already has a row for this target.
pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    n: &NewNotification<'_>,
) -> Result<bool, sqlx::Error> {
    let (alert_id, report_id) = match n.target {
        Target::Alert(a) => (Some(a.clone()), None),
        Target::Report(r) => (None, Some(r.clone())),
    };
    let (status, mode) = match n.mode {
        None | Some(Mode::Off) => ("suppressed", Mode::Immediate),
        Some(m) => ("pending", m),
    };
    let r = sqlx::query(
        "INSERT INTO notifications (id, alert_id, report_id, recipient_id, channel, urgency,
                                    status, attempts, created_at, mode, due_at, next_attempt_at)
         VALUES ($1, $2, $3, $4, 'email', $5, $6, 0, $7, $8, $9, $9)
         ON CONFLICT DO NOTHING",
    )
    .bind(new_hex_id())
    .bind(alert_id)
    .bind(report_id)
    .bind(n.recipient.as_str())
    .bind(n.urgency.as_str())
    .bind(status)
    .bind(n.now_ms)
    .bind(mode.as_str())
    .bind(n.due_at_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// A pending notification that is due, with everything needed to word it.
#[derive(Debug, Clone)]
pub struct DueNotification {
    pub id: String,
    pub recipient_id: UserId,
    pub recipient_email: String,
    /// The recipient's account is disabled: do not send.
    pub recipient_disabled: bool,
    /// The recipient is still entitled to hear about this member (they are
    /// the member, an active ally, or the alert's extra recipient). An ally
    /// removed after the row was queued is not.
    pub entitled: bool,
    pub member_id: UserId,
    pub member_name: String,
    pub device_id: Option<DeviceId>,
    pub device_name: Option<String>,
    pub urgency: Urgency,
    pub attempts: i64,
    /// When the notification was queued.
    pub created_at_ms: i64,
    /// `Some((source, kind))` for alerts, `None` for reports.
    pub alert: Option<(String, String)>,
    /// This recipient is the alert's extra recipient (the removed ally).
    pub to_extra_recipient: bool,
}

/// Due pending notifications of one mode, oldest first.
pub async fn due<'e>(
    e: impl Executor<'e, Database = Any>,
    mode: Mode,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<DueNotification>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT n.id, n.recipient_id, n.urgency, n.attempts, n.created_at,
                r.email AS recipient_email, r.disabled AS recipient_disabled,
                COALESCE(a.member_id, rp.member_id) AS member_id,
                COALESCE(a.device_id, rp.device_id) AS device_id,
                a.source AS alert_source, a.kind AS alert_kind,
                a.extra_recipient_id,
                m.display_name AS member_name, d.name AS device_name,
                CASE WHEN n.recipient_id = COALESCE(a.member_id, rp.member_id)
                       OR n.recipient_id = a.extra_recipient_id
                       OR EXISTS (SELECT 1 FROM ally_links l
                                  WHERE l.member_id = COALESCE(a.member_id, rp.member_id)
                                    AND l.ally_id = n.recipient_id AND l.state = 'active')
                     THEN 1 ELSE 0 END AS entitled
         FROM notifications n
         JOIN users r ON r.id = n.recipient_id
         LEFT JOIN alerts a ON a.id = n.alert_id
         LEFT JOIN reports rp ON rp.id = n.report_id
         JOIN users m ON m.id = COALESCE(a.member_id, rp.member_id)
         LEFT JOIN devices d ON d.id = COALESCE(a.device_id, rp.device_id)
         WHERE n.status = 'pending' AND n.mode = $1 AND n.due_at <= $2
           AND n.next_attempt_at <= $2
         ORDER BY n.created_at, n.id
         LIMIT $3",
    )
    .bind(mode.as_str())
    .bind(now_ms)
    .bind(limit)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            let recipient_id = UserId::new(r.try_get::<String, _>("recipient_id")?);
            let extra: Option<String> = r.try_get("extra_recipient_id")?;
            let source: Option<String> = r.try_get("alert_source")?;
            let kind: Option<String> = r.try_get("alert_kind")?;
            Ok(DueNotification {
                id: r.try_get("id")?,
                to_extra_recipient: extra.as_deref() == Some(recipient_id.as_str()),
                recipient_id,
                recipient_email: r.try_get("recipient_email")?,
                recipient_disabled: r.try_get::<i64, _>("recipient_disabled")? != 0,
                entitled: r.try_get::<i64, _>("entitled")? != 0,
                member_id: UserId::new(r.try_get::<String, _>("member_id")?),
                member_name: r.try_get("member_name")?,
                device_id: r
                    .try_get::<Option<String>, _>("device_id")?
                    .map(DeviceId::new),
                device_name: r.try_get("device_name")?,
                urgency: parse_col(r, "urgency", Urgency::parse)?,
                attempts: r.try_get("attempts")?,
                created_at_ms: r.try_get("created_at")?,
                alert: source.zip(kind),
            })
        })
        .collect()
}

pub async fn mark_sent<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE notifications SET status = 'sent', sent_at = $1, attempts = attempts + 1,
                                  last_error = NULL
         WHERE id = $2 AND status = 'pending'",
    )
    .bind(now_ms)
    .bind(id)
    .execute(e)
    .await?;
    Ok(())
}

/// Record a failed attempt: schedule a retry at `next_attempt_at_ms`, or
/// give up (`failed`) when `give_up`.
pub async fn mark_attempt_failed<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    error_code: &str,
    next_attempt_at_ms: i64,
    give_up: bool,
) -> Result<(), sqlx::Error> {
    let sql = if give_up {
        "UPDATE notifications SET attempts = attempts + 1, last_error = $1,
                                  next_attempt_at = $2, status = 'failed'
         WHERE id = $3 AND status = 'pending'"
    } else {
        "UPDATE notifications SET attempts = attempts + 1, last_error = $1,
                                  next_attempt_at = $2
         WHERE id = $3 AND status = 'pending'"
    };
    sqlx::query(sql)
        .bind(error_code)
        .bind(next_attempt_at_ms)
        .bind(id)
        .execute(e)
        .await?;
    Ok(())
}

/// Postpone a pending notification after a failure that was not its fault
/// (the instance's mail setup failed): records the code, leaves `attempts`
/// alone.
pub async fn postpone<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    error_code: &str,
    next_attempt_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE notifications SET last_error = $1, next_attempt_at = $2
         WHERE id = $3 AND status = 'pending'",
    )
    .bind(error_code)
    .bind(next_attempt_at_ms)
    .bind(id)
    .execute(e)
    .await?;
    Ok(())
}

/// Push a pending notification's due time out (quiet hours).
pub async fn defer<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
    due_at_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE notifications SET due_at = $1 WHERE id = $2 AND status = 'pending'")
        .bind(due_at_ms)
        .bind(id)
        .execute(e)
        .await?;
    Ok(())
}

pub async fn suppress<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE notifications SET status = 'suppressed' WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .execute(e)
    .await?;
    Ok(())
}

/// When an ally's link ends, drop their queued notifications about that
/// member, except the notice telling them about the removal itself.
pub async fn suppress_pending_about_member<'e>(
    e: impl Executor<'e, Database = Any>,
    recipient: &UserId,
    member: &UserId,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE notifications SET status = 'suppressed'
         WHERE recipient_id = $1 AND status = 'pending'
           AND (alert_id IN (SELECT id FROM alerts WHERE member_id = $2
                               AND (extra_recipient_id IS NULL OR extra_recipient_id <> $1))
                OR report_id IN (SELECT id FROM reports WHERE member_id = $2))",
    )
    .bind(recipient.as_str())
    .bind(member.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected())
}

/// Delivery failure counts for the admin overview (counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeliveryCounts {
    /// Gave up after the maximum number of attempts.
    pub failed: i64,
    /// Pending after at least one failed attempt.
    pub retrying: i64,
    pub pending: i64,
    pub sent: i64,
}

pub async fn delivery_counts<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<DeliveryCounts, sqlx::Error> {
    let r = sqlx::query(
        "SELECT
            COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed,
            COALESCE(SUM(CASE WHEN status = 'pending' AND attempts > 0 THEN 1 ELSE 0 END), 0)
                AS retrying,
            COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) AS pending,
            COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0) AS sent
         FROM notifications",
    )
    .fetch_one(e)
    .await?;
    Ok(DeliveryCounts {
        failed: r.try_get("failed")?,
        retrying: r.try_get("retrying")?,
        pending: r.try_get("pending")?,
        sent: r.try_get("sent")?,
    })
}

/// One recipient's preferences about one member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecipientPrefs {
    pub urgent: Option<Mode>,
    pub normal: Option<Mode>,
    pub none: Option<Mode>,
    pub quiet: Option<QuietHours>,
}

impl RecipientPrefs {
    /// The stored mode for an urgency (None: use the default).
    pub fn stored_mode(&self, u: Urgency) -> Option<Mode> {
        match u {
            Urgency::Urgent => self.urgent,
            Urgency::Normal => self.normal,
            Urgency::None => self.none,
        }
    }
}

pub async fn get_prefs<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &UserId,
    member: &UserId,
) -> Result<RecipientPrefs, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT urgency, mode, quiet_start_min, quiet_end_min, tz_offset_min
         FROM notification_prefs WHERE user_id = $1 AND member_id = $2 AND channel = 'email'",
    )
    .bind(user.as_str())
    .bind(member.as_str())
    .fetch_all(e)
    .await?;
    let mut p = RecipientPrefs::default();
    for r in &rows {
        let u = parse_col(r, "urgency", Urgency::parse)?;
        let m = parse_col(r, "mode", Mode::parse)?;
        match u {
            Urgency::Urgent => p.urgent = Some(m),
            Urgency::Normal => p.normal = Some(m),
            Urgency::None => p.none = Some(m),
        }
        let start: Option<i64> = r.try_get("quiet_start_min")?;
        let end: Option<i64> = r.try_get("quiet_end_min")?;
        let tz: Option<i64> = r.try_get("tz_offset_min")?;
        if let (Some(s), Some(e)) = (start, end) {
            let q = QuietHours {
                start_min: u16::try_from(s).unwrap_or(0),
                end_min: u16::try_from(e).unwrap_or(0),
                tz_offset_min: i16::try_from(tz.unwrap_or(0)).unwrap_or(0),
            };
            // Stored values were validated on write; anything else is
            // corruption and is ignored rather than mis-scheduling mail.
            if q.is_valid() {
                p.quiet = Some(q);
            }
        }
    }
    Ok(p)
}

/// Replace a recipient's preferences about a member (all three urgencies
/// share the quiet hours).
pub async fn put_prefs(
    conn: &mut sqlx::AnyConnection,
    user: &UserId,
    member: &UserId,
    modes: [(Urgency, Mode); 3],
    quiet: Option<QuietHours>,
) -> Result<(), sqlx::Error> {
    for (u, m) in modes {
        sqlx::query(
            "INSERT INTO notification_prefs (user_id, member_id, urgency, channel, mode,
                                             quiet_start_min, quiet_end_min, tz_offset_min)
             VALUES ($1, $2, $3, 'email', $4, $5, $6, $7)
             ON CONFLICT (user_id, member_id, urgency, channel) DO UPDATE SET
                mode = excluded.mode, quiet_start_min = excluded.quiet_start_min,
                quiet_end_min = excluded.quiet_end_min, tz_offset_min = excluded.tz_offset_min",
        )
        .bind(user.as_str())
        .bind(member.as_str())
        .bind(u.as_str())
        .bind(m.as_str())
        .bind(quiet.map(|q| i64::from(q.start_min)))
        .bind(quiet.map(|q| i64::from(q.end_min)))
        .bind(quiet.map(|q| i64::from(q.tz_offset_min)))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}
