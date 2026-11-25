//! The admin console API (§4.3): instance configuration and **operational
//! metadata only**.
//!
//! An instance admin can configure registration, retention and the liveness
//! grace period, test SMTP, invite members, see aggregate counts and the
//! account list, disable or re-enable accounts, grant or revoke the admin
//! role ([`crate::roles`]), and ask for an account to be deleted (with the
//! same hold and notices as when the person asks, [`super::account`]).
//! There is deliberately no admin route to
//! any member's keys, devices, allies, feed, blobs, alerts or reports, and
//! the admin role
//! grants nothing on the member/ally routes either (they check the caller's
//! own relationships). Delivery problems are visible as counts, never as
//! recipients or messages.
//!
//! **Disabling is never silent.** Admins are users like any other: one
//! admin can disable another's account, never their own, and never the last
//! enabled admin's. The disabled person, their allies, and the members they
//! are an ally for (with those members' other allies) are always told, by
//! alerts that cannot be switched off (see [`crate::notify`]). A disabled
//! account can't sign in and its sessions end, but its devices keep
//! reporting and alerting allies: disabling an account is not a way to stop
//! anyone being monitored.

use super::ApiJson;
use crate::auth::normalize_email;
use crate::auth::session::SessionUser;
use crate::db::repo::admin_log;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::invites::InviteKind;
use crate::db::repo::notifications::{self, DeliveryCounts};
use crate::db::repo::stats::{self, DeviceCounts, LastSeenBuckets, StorageBytes, UserCounts};
use crate::db::repo::{allies, instance, sessions, users};
use crate::error::{AppError, AppResult};
use crate::mailer::Email;
use crate::settings::{InstanceSettings, SettingsPatch, StoredSettings};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::ServerAlertKind;
use faro_proto::UserId;
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
    /// Accounts waiting to be deleted, and purges held up for more than 7
    /// days past their hold because their notices can't be delivered.
    pub deletions: users::DeletionCounts,
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
        deletions: users::deletion_counts(pool, state.now_ms()).await?,
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

/// `PUT /admin/api/users/{id}/admin` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAdmin {
    pub admin: bool,
}

/// `PUT /admin/api/users/{id}/admin`: grant (`{"admin": true}`) or revoke
/// the admin role of another account. Told to the person and every other
/// admin; see [`crate::roles`].
pub async fn set_admin_role(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SetAdmin>,
) -> AppResult<Json<crate::roles::AdminRole>> {
    s.require_admin()?;
    let target = UserId::new(id);
    let r = crate::roles::set_admin(
        &state,
        &target,
        req.admin,
        crate::roles::By::Admin(&s.user.id),
    )
    .await?;
    Ok(Json(r))
}

/// `DELETE /admin/api/users/{id}` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteUser {
    /// The account's email address, typed out.
    pub confirm_email: String,
}

/// `DELETE /admin/api/users/{id}`: ask for another account to be deleted,
/// disabled or not. The same 7-day hold, notices and purge as when the
/// person asks ([`super::account`]); the notices say the instance
/// administrator asked. Needs a sign-in within the last
/// [`REAUTH_WINDOW_MS`](super::account::REAUTH_WINDOW_MS) and the
/// account's address typed out. Written to the admin log.
pub async fn delete_user(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<DeleteUser>,
) -> AppResult<(StatusCode, Json<super::account::DeletionRequested>)> {
    s.require_admin()?;
    let target = UserId::new(id);
    if target == s.user.id {
        return Err(AppError::bad_request(
            "cannot_delete_self",
            "delete your own account in Settings",
        ));
    }
    let now = state.now_ms();
    if now.saturating_sub(s.session_started_at_ms) > super::account::REAUTH_WINDOW_MS {
        return Err(AppError::Forbidden("reauth_required"));
    }
    let mut tx = state.db().begin_write().await?;
    let user = users::by_id(&mut *tx, &target)
        .await?
        .ok_or(AppError::NotFound)?;
    if normalize_email(&req.confirm_email).as_deref() != Some(user.email.as_str()) {
        return Err(AppError::bad_request(
            "confirmation_mismatch",
            "type the account's email address to confirm",
        ));
    }
    let by = super::account::By::Admin(&s.user.id);
    let r = super::account::start(&mut tx, &user, by, now).await?;
    tx.commit().await?;
    tracing::info!(
        admin = %s.user.id,
        user = %target,
        purge_after_ms = r.deletion.purge_after_ms,
        "account deletion requested by an admin"
    );
    Ok((StatusCode::ACCEPTED, Json(r)))
}

/// `POST /admin/api/users/{id}/deletion/cancel`: cancel a deletion an admin
/// asked for, during its hold. Any admin may; the person may too, from
/// their own session. A deletion the person asked for is theirs to cancel
/// (`409 not_admin_deletion`).
pub async fn cancel_user_deletion(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
    ApiJson(_): ApiJson<super::account::CancelDeletion>,
) -> AppResult<Json<super::account::DeletionCancelled>> {
    s.require_admin()?;
    let target = UserId::new(id);
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let user = users::by_id(&mut *tx, &target)
        .await?
        .ok_or(AppError::NotFound)?;
    let by = super::account::By::Admin(&s.user.id);
    let r = super::account::cancel(&mut tx, &user, by, now).await?;
    tx.commit().await?;
    tracing::info!(admin = %s.user.id, user = %target, "account deletion cancelled by an admin");
    Ok(Json(r))
}

/// Entries `GET /admin/api/log` returns.
pub const LOG_LIMIT: i64 = 200;

/// `GET /admin/api/log`: the most recent admin log entries, newest first
/// (who was made an admin or stopped being one, which deletions admins
/// asked for or were cancelled, by whom, and when).
pub async fn log(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<admin_log::Entry>>> {
    s.require_admin()?;
    Ok(Json(admin_log::recent(state.db().pool(), LOG_LIMIT).await?))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub user_id: UserId,
    pub disabled: bool,
}

/// `POST /admin/api/users/{id}/disable`
pub async fn disable_user(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<AccountStatus>> {
    set_account_disabled(&state, &s, UserId::new(id), true).await
}

/// `POST /admin/api/users/{id}/enable`
pub async fn enable_user(
    State(state): State<AppState>,
    s: SessionUser,
    Path(id): Path<String>,
) -> AppResult<Json<AccountStatus>> {
    set_account_disabled(&state, &s, UserId::new(id), false).await
}

async fn set_account_disabled(
    state: &AppState,
    s: &SessionUser,
    target: UserId,
    disabled: bool,
) -> AppResult<Json<AccountStatus>> {
    s.require_admin()?;
    if disabled && target == s.user.id {
        return Err(AppError::bad_request(
            "cannot_disable_self",
            "you cannot disable your own account; ask another admin",
        ));
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let user = users::by_id(&mut *tx, &target)
        .await?
        .ok_or(AppError::NotFound)?;
    // The person may still cancel, or the purge settles it: either way,
    // not a moment to change who can sign in.
    if user.deletion.is_some() {
        return Err(AppError::conflict(
            "account_deleting",
            "this account is being deleted",
        ));
    }
    if disabled
        && user.roles.admin
        && users::count_enabled_admins_except(&mut *tx, &target).await? == 0
    {
        return Err(AppError::conflict(
            "last_admin",
            "the instance must keep at least one enabled admin",
        ));
    }
    if !users::set_disabled(&mut *tx, &target, disabled).await? {
        return Err(if disabled {
            AppError::conflict("already_disabled", "this account is already disabled")
        } else {
            AppError::conflict("not_disabled", "this account is not disabled")
        });
    }
    if disabled {
        sessions::delete_for_user(&mut *tx, &target).await?;
    }

    let (own, as_ally) = if disabled {
        (
            ServerAlertKind::AccountDisabled,
            ServerAlertKind::AllyDisabled,
        )
    } else {
        (
            ServerAlertKind::AccountEnabled,
            ServerAlertKind::AllyEnabled,
        )
    };
    // The person themself and their allies.
    alerts::insert(
        &mut *tx,
        &NewAlert {
            member_id: &target,
            device_id: None,
            source: AlertSource::Server,
            kind: own.as_str(),
            urgency: own.urgency(),
            event_seq: None,
            detail: Some(format!("by:{}", s.user.id)),
            dedupe_key: Some(format!("{}:{target}:{now}", own.as_str())),
            now_ms: now,
        },
    )
    .await?;
    // Each member they are an ally for, and that member's other allies. The
    // person is skipped there: they hear about it from the alert above.
    for member in allies::active_member_ids(&mut *tx, &target).await? {
        alerts::insert_routed(
            &mut *tx,
            &NewAlert {
                member_id: &member,
                device_id: None,
                source: AlertSource::Server,
                kind: as_ally.as_str(),
                urgency: as_ally.urgency(),
                event_seq: None,
                detail: Some(format!("ally:{target}")),
                dedupe_key: Some(format!("{}:{member}:{target}:{now}", as_ally.as_str())),
                now_ms: now,
            },
            None,
            Some(&target),
            Some(&target),
        )
        .await?;
    }
    tx.commit().await?;
    tracing::info!(admin = %s.user.id, user = %target, disabled, "account status changed");
    Ok(Json(AccountStatus {
        user_id: target,
        disabled,
    }))
}
