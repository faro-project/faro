//! Limits on what one device (and one member) may push at the instance, and
//! the one place device-driven alerts are raised (#194).
//!
//! * **Ingest limits** ([`check_ingest`], [`check_report`]): token buckets per
//!   device and per member, refused with HTTP 429 and `Retry-After`.
//! * **Alerts** ([`raise`]): every alert from a device upload goes through
//!   here. A repeat of an existing dedupe key is *counted* on that alert; a
//!   new alert beyond the device's or member's alert budget is *folded* into
//!   one `alerts_coalesced` alert per interval whose detail says how many
//!   were folded. Nothing is dropped silently, so an honest tamper alert
//!   behind a flood still reaches allies.
//! * **Rejected-upload keys** ([`interval_key`]): keyed by device and time
//!   interval, never by attacker-chosen values (`seq`, header hash).
//! * **Storage quota** ([`quota_bytes`]).

use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::devices::DeviceRow;
use crate::error::AppError;
use crate::ratelimit::Limit;
use crate::state::AppState;
use faro_proto::api::ServerAlertKind;
use faro_proto::DeviceId;

fn deny(retry_after_secs: u64) -> AppError {
    AppError::TooManyRequests { retry_after_secs }
}

/// Take the request, per-device and per-member event budgets for a batch of
/// `events` events.
pub fn check_ingest(state: &AppState, dev: &DeviceRow, events: usize) -> Result<(), AppError> {
    let c = &state.config().device_limits;
    let now = state.now_ms();
    let rl = state.rate_limiter();
    let n = u32::try_from(events).unwrap_or(u32::MAX);
    rl.check_device(
        &format!("req:{}", dev.id),
        Limit::per_minute(c.requests_per_minute),
        1,
        now,
    )
    .map_err(deny)?;
    rl.check_device(
        &format!("ev:{}", dev.id),
        Limit::per_hour(c.events_per_device_per_hour),
        n,
        now,
    )
    .map_err(deny)?;
    rl.check_device(
        &format!("evm:{}", dev.owner_user_id),
        Limit::per_hour(c.events_per_member_per_hour),
        n,
        now,
    )
    .map_err(deny)
}

/// Take the request and report budgets for one report upload.
pub fn check_report(state: &AppState, dev: &DeviceRow) -> Result<(), AppError> {
    let c = &state.config().device_limits;
    let now = state.now_ms();
    let rl = state.rate_limiter();
    rl.check_device(
        &format!("req:{}", dev.id),
        Limit::per_minute(c.requests_per_minute),
        1,
        now,
    )
    .map_err(deny)?;
    rl.check_device(
        &format!("rep:{}", dev.id),
        Limit::per_hour(c.reports_per_device_per_hour),
        1,
        now,
    )
    .map_err(deny)
}

/// The dedupe interval number for `now_ms`.
fn bucket(state: &AppState, now_ms: i64) -> i64 {
    let secs = i64::try_from(state.config().device_limits.alert_coalesce_secs).unwrap_or(i64::MAX);
    now_ms.div_euclid(secs.saturating_mul(1000).max(1000))
}

/// A dedupe key that coalesces per device per interval: `{prefix}:{device}:{interval}`.
pub fn interval_key(state: &AppState, prefix: &str, dev: &DeviceId) -> String {
    format!("{prefix}:{dev}:{}", bucket(state, state.now_ms()))
}

/// The device's storage quota in bytes, or `None` if disabled.
pub fn quota_bytes(state: &AppState) -> Option<u64> {
    match state.config().device_limits.storage_quota_mib {
        0 => None,
        mib => Some(mib.saturating_mul(1024 * 1024)),
    }
}

/// Raise an alert from a device upload (see the module docs). Returns true
/// if a new alert row was created for `a` itself.
pub async fn raise(
    state: &AppState,
    conn: &mut sqlx::AnyConnection,
    a: &NewAlert<'_>,
) -> Result<bool, sqlx::Error> {
    if let Some(key) = &a.dedupe_key {
        if alerts::exists(&mut *conn, key).await? {
            let base = a.detail.as_deref().unwrap_or("");
            alerts::bump_repeat(&mut *conn, key, base).await?;
            return Ok(false);
        }
    }
    let c = &state.config().device_limits;
    let now = state.now_ms();
    let rl = state.rate_limiter();
    let member = a.member_id;
    let over_device = a.device_id.is_some_and(|d| {
        rl.check_device(
            &format!("al:{d}"),
            Limit::per_hour(c.alerts_per_device_per_hour),
            1,
            now,
        )
        .is_err()
    });
    let over_member = rl
        .check_device(
            &format!("alm:{member}"),
            Limit::per_hour(c.alerts_per_member_per_hour),
            1,
            now,
        )
        .is_err();
    if !over_device && !over_member {
        return alerts::insert(&mut *conn, a).await;
    }
    // Fold into one alert per (device or member, interval).
    let scope = a
        .device_id
        .map_or_else(|| member.to_string(), ToString::to_string);
    let key = format!("fold:{scope}:{}", bucket(state, now));
    if !alerts::bump_repeat(&mut *conn, &key, "coalesced").await? {
        let kind = ServerAlertKind::AlertsCoalesced;
        let created = alerts::insert(
            &mut *conn,
            &NewAlert {
                member_id: member,
                device_id: a.device_id,
                source: AlertSource::Server,
                kind: kind.as_str(),
                urgency: kind.urgency(),
                event_seq: None,
                detail: Some("coalesced;folded=1".to_owned()),
                dedupe_key: Some(key.clone()),
                now_ms: now,
            },
        )
        .await?;
        if created {
            sqlx::query("UPDATE alerts SET repeat_count = 1 WHERE dedupe_key = $1")
                .bind(&key)
                .execute(&mut *conn)
                .await?;
        } else {
            alerts::bump_repeat(&mut *conn, &key, "coalesced").await?;
        }
    }
    tracing::warn!(member = %member, kind = a.kind, "alert folded: rate limit exceeded");
    Ok(false)
}
