//! The admin console API (§4.3): instance configuration and **operational
//! metadata only**.
//!
//! An instance admin can configure registration, retention and the liveness
//! grace period, test SMTP, invite members, and see aggregate counts and the
//! account list. There is deliberately no admin route to any member's keys,
//! devices, allies, feed, blobs, alerts or reports, and the admin role
//! grants nothing on the member/ally routes either (they check the caller's
//! own relationships). Delivery problems are visible as counts, never as
//! recipients or messages.

use super::ApiJson;
use crate::auth::normalize_email;
use crate::auth::session::SessionUser;
use crate::db::repo::invites::InviteKind;
use crate::db::repo::notifications::{self, DeliveryCounts};
use crate::db::repo::stats::{self, DeviceCounts, LastSeenBuckets, StorageBytes, UserCounts};
use crate::db::repo::{instance, users};
use crate::error::{AppError, AppResult};
use crate::mailer::Email;
use crate::settings::{InstanceSettings, SettingsPatch, StoredSettings};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub instance_name: String,
    pub server_version: String,
    pub users: UserCounts,
    pub devices: DeviceCounts,
    /// Active devices by time since their last check-in.
    pub last_seen: LastSeenBuckets,
    pub storage: StorageBytes,
    /// Notification delivery, counts only.
    pub notifications: DeliveryCounts,
    pub smtp_configured: bool,
    pub settings: InstanceSettings,
}

/// `GET /admin/api/overview`
pub async fn overview(State(state): State<AppState>, s: SessionUser) -> AppResult<Json<Overview>> {
    s.require_admin()?;
    let pool = state.db().pool();
    Ok(Json(Overview {
        instance_name: state.config().instance.name.clone(),
        server_version: crate::SERVER_VERSION.to_owned(),
        users: stats::users(pool).await?,
        devices: stats::devices(pool).await?,
        last_seen: stats::last_seen(pool, state.now_ms()).await?,
        storage: stats::storage(pool, state.db().backend()).await?,
        notifications: notifications::delivery_counts(pool).await?,
        smtp_configured: state.config().smtp.is_configured(),
        settings: state.settings(),
    }))
}

/// `GET /admin/api/users`: account metadata (no relationships, no content).
pub async fn list_users(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<users::AdminUserRow>>> {
    s.require_admin()?;
    Ok(Json(users::list_for_admin(state.db().pool()).await?))
}

/// `GET /admin/api/settings`
pub async fn get_settings(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<InstanceSettings>> {
    s.require_admin()?;
    Ok(Json(state.settings()))
}

/// `PATCH /admin/api/settings`: validated with the config-file rules, stored
/// in the database, applied immediately.
pub async fn patch_settings(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> AppResult<Json<InstanceSettings>> {
    s.require_admin()?;
    let mut tx = state.db().begin_write().await?;
    let mut stored =
        StoredSettings::from_json(&instance::settings_json(&mut *tx).await?).unwrap_or_default();
    stored.apply(&patch);
    let resolved = InstanceSettings::resolve(state.config(), &stored)
        .map_err(|e| AppError::bad_request("invalid_settings", e.to_string()))?;
    instance::set_settings_json(&mut *tx, &stored.to_json()).await?;
    tx.commit().await?;
    state.set_settings(resolved.clone());
    tracing::info!(admin = %s.user.id, "instance settings changed");
    Ok(Json(resolved))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpTestResult {
    pub ok: bool,
    /// Short error code on failure (never server response text).
    pub error: Option<String>,
    /// Where the test went: always the calling admin's own address, so the
    /// endpoint cannot be used to send mail to arbitrary people.
    pub sent_to: String,
}

/// `POST /admin/api/smtp-test`
pub async fn smtp_test(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<SmtpTestResult>> {
    s.require_admin()?;
    let mail = Email {
        to: s.user.email.clone(),
        subject: format!("{}: test email", state.config().instance.name),
        text: format!(
            "This is a test email from {} ({}). If you can read it, email delivery works.\n",
            state.config().instance.name,
            state.config().public_url
        ),
    };
    let r = state.mailer().send(mail).await;
    Ok(Json(SmtpTestResult {
        ok: r.is_ok(),
        error: r.err().map(|e| e.code().to_owned()),
        sent_to: s.user.email,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminInvite {
    pub email: String,
}

/// `POST /admin/api/invites`: invite someone to become a member (§7
/// "Instance admin" step 3). The invitee becomes a member by signing in with
/// the invited address; nothing about their keys, devices or allies is in
/// the admin's hands.
pub async fn invite_member(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<AdminInvite>,
) -> AppResult<(StatusCode, Json<super::invites::InviteCreated>)> {
    s.require_admin()?;
    let email = normalize_email(&req.email)
        .ok_or_else(|| AppError::bad_request("invalid_email", "invalid email address"))?;
    if let Some(u) = users::by_email(state.db().pool(), &email).await? {
        if u.roles.member {
            return Err(AppError::conflict(
                "already_member",
                "this account is already a member",
            ));
        }
    }
    let created = super::invites::create(&state, &s.user, InviteKind::Member, &email).await?;
    Ok((StatusCode::CREATED, Json(created)))
}
