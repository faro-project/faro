//! Per-recipient notification preferences (§5.4) and a member's own
//! retention choice (§8).
//!
//! `GET|PUT /v1/me/notification-prefs?member_id=…`: how the caller wants to
//! hear about one member, per urgency (`immediate` / `digest` / `off`), with
//! optional quiet hours. Callable by the member (about themself) and by
//! anyone with a live link to that member. `off` may be stored for any
//! urgency, but tamper-class alerts are still delivered in the digest
//! ([`crate::notify::policy::effective_mode`]); the response says so.
//!
//! `GET|PUT /v1/me/retention`: a member may shorten (never lengthen) how
//! long their data is kept, within [`crate::retention::MIN_MEMBER_DAYS`].
//! Shortening any window raises a normal-urgency `member_settings_changed`
//! alert, so allies learn that less history will be kept, just as they
//! learn about a device's `settings_change`.

use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::config::RetentionConfig;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::{allies, notifications};
use crate::error::{AppError, AppResult};
use crate::notify::policy::{default_mode, Mode, QuietHours};
use crate::retention::{self, RetentionOverride};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use faro_proto::api::ServerAlertKind;
use faro_proto::{Urgency, UserId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct PrefsQuery {
    pub member_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPrefs {
    pub member_id: UserId,
    pub urgent: Mode,
    pub normal: Mode,
    pub none: Mode,
    pub quiet_hours: Option<QuietHours>,
    /// Tamper alerts (uninstall, permission revoked, chain gap, missed
    /// check-in, invalid signature, ally removed) are never dropped: with
    /// `off` they still arrive in the digest.
    pub tamper_minimum: Mode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutPrefs {
    pub member_id: String,
    pub urgent: Option<Mode>,
    pub normal: Option<Mode>,
    pub none: Option<Mode>,
    pub quiet_hours: Option<QuietHours>,
}

async fn authorize(state: &AppState, caller: &UserId, member: &str) -> AppResult<UserId> {
    let member = UserId::new(member);
    if !member.is_well_formed() {
        return Err(AppError::NotFound);
    }
    if *caller == member
        || allies::live_state(state.db().pool(), &member, caller)
            .await?
            .is_some()
    {
        Ok(member)
    } else {
        Err(AppError::NotFound)
    }
}

async fn current(state: &AppState, user: &UserId, member: UserId) -> AppResult<NotificationPrefs> {
    let p = notifications::get_prefs(state.db().pool(), user, &member).await?;
    let pick = |u: Urgency| p.stored_mode(u).unwrap_or_else(|| default_mode(u));
    Ok(NotificationPrefs {
        urgent: pick(Urgency::Urgent),
        normal: pick(Urgency::Normal),
        none: pick(Urgency::None),
        quiet_hours: p.quiet,
        tamper_minimum: Mode::Digest,
        member_id: member,
    })
}

/// `GET /v1/me/notification-prefs?member_id=`
pub async fn get_prefs(
    State(state): State<AppState>,
    s: SessionUser,
    Query(q): Query<PrefsQuery>,
) -> AppResult<Json<NotificationPrefs>> {
    let member = authorize(&state, &s.user.id, &q.member_id).await?;
    Ok(Json(current(&state, &s.user.id, member).await?))
}

/// `PUT /v1/me/notification-prefs`
pub async fn put_prefs(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<PutPrefs>,
) -> AppResult<Json<NotificationPrefs>> {
    let member = authorize(&state, &s.user.id, &req.member_id).await?;
    if let Some(q) = &req.quiet_hours {
        if !q.is_valid() {
            return Err(AppError::bad_request(
                "invalid_quiet_hours",
                "quiet hours need minutes in 0..1440 and an offset within ±14 hours",
            ));
        }
    }
    let cur = current(&state, &s.user.id, member.clone()).await?;
    let modes = [
        (Urgency::Urgent, req.urgent.unwrap_or(cur.urgent)),
        (Urgency::Normal, req.normal.unwrap_or(cur.normal)),
        (Urgency::None, req.none.unwrap_or(cur.none)),
    ];
    let mut tx = state.db().begin_write().await?;
    notifications::put_prefs(&mut tx, &s.user.id, &member, modes, req.quiet_hours).await?;
    tx.commit().await?;
    Ok(Json(current(&state, &s.user.id, member).await?))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionView {
    /// The instance's windows (the maximum).
    pub instance: RetentionConfig,
    /// What the member chose (already clamped).
    pub chosen: RetentionOverride,
    /// What applies to the member's data.
    pub effective: RetentionConfig,
    /// The shortest window a member may choose.
    pub min_days: u32,
}

async fn retention_view(state: &AppState, member: &UserId) -> AppResult<RetentionView> {
    let instance = state.settings().retention;
    let chosen = retention::get_override(state, member).await?;
    Ok(RetentionView {
        effective: retention::effective(&instance, &chosen),
        instance,
        chosen,
        min_days: retention::MIN_MEMBER_DAYS,
    })
}

/// `GET /v1/me/retention`
pub async fn get_retention(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<RetentionView>> {
    s.require_member()?;
    Ok(Json(retention_view(&state, &s.user.id).await?))
}

/// `PUT /v1/me/retention`: values are clamped into the allowed range and
/// stored clamped, so the response shows what will actually apply.
pub async fn put_retention(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<RetentionOverride>,
) -> AppResult<Json<RetentionView>> {
    s.require_member()?;
    let instance = state.settings().retention;
    let eff = retention::effective(&instance, &req);
    let clamped = RetentionOverride {
        event_header_days: req.event_header_days.map(|_| eff.event_header_days),
        blob_days: req.blob_days.map(|_| eff.blob_days),
        alert_days: req.alert_days.map(|_| eff.alert_days),
    };
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let before = retention::effective(
        &instance,
        &retention::load_override(&mut *tx, &s.user.id).await?,
    );
    // A changed window applies to data received from now on only.
    let since = retention::load_since(&mut *tx, &s.user.id)
        .await?
        .after_change(&before, &eff, now);
    retention::store_override(&mut *tx, &s.user.id, &clamped, &since, now).await?;
    let shorter = retention::shortened(&before, &eff);
    if !shorter.is_empty() {
        let kind = ServerAlertKind::MemberSettingsChanged;
        alerts::insert(
            &mut *tx,
            &NewAlert {
                member_id: &s.user.id,
                device_id: None,
                source: AlertSource::Server,
                kind: kind.as_str(),
                urgency: kind.urgency(),
                event_seq: None,
                // Which windows got shorter: setting names, never content.
                detail: Some(format!("retention_shortened:{}", shorter.join(","))),
                dedupe_key: None,
                now_ms: now,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Json(retention_view(&state, &s.user.id).await?))
}
