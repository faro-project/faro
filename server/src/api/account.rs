//! Deleting an account (§12), for members and allies alike: your own, or
//! (from the admin console) someone else's.
//!
//! * `DELETE /v1/me` with `{"confirm_email": …}` asks for the deletion. It
//!   needs a session signed in within [`REAUTH_WINDOW_MS`] and the
//!   account's own address typed out. Nothing is removed yet: a **hold** of
//!   [`HOLD_MS`] starts, and everyone in an accountability partnership with
//!   the person is told at once, by alerts that can't be switched off:
//!   `account_deleted` on the person (to them and their allies) and
//!   `ally_deleted` on each member they are an ally for (to that member and
//!   their other allies). The person's other sessions end.
//! * During the hold **nothing else changes**. Their computers keep
//!   reporting and their allies keep receiving alerts (disabling or
//!   deleting an account never stops monitoring early), links stay as they
//!   are, and the person can still sign in. Only what the purge would have
//!   to undo is refused ([`SessionUser::require_not_being_deleted`]):
//!   inviting, enrolling computers and approving new ones or new allies.
//! * `POST /v1/me/deletion/cancel` cancels, until the purge starts. The same
//!   people are told again (`account_deletion_cancelled`, also tamper-class),
//!   with both times. A later request starts a new hold.
//! * After the hold, [`crate::deletion`] purges the account once every
//!   notice has been delivered.
//!
//! **An admin may ask too** (`DELETE /admin/api/users/{id}`, in
//! [`super::admin`]): for an erasure request from someone who can't sign
//! in, or to remove a disabled account. It is the same request, hold,
//! notices and purge ([`start`], [`cancel`]), with these differences:
//!
//! * The admin types the account's address and needs the same recent
//!   sign-in. Never their own account (they use `DELETE /v1/me`).
//! * The notices say the account is "being deleted by the instance
//!   administrator" (`requested_by=admin` in their detail). A disabled
//!   person is emailed too, though they hear nothing else.
//! * The person keeps their sessions, so they see the banner and can
//!   cancel. During the hold either the person or any admin may cancel
//!   (`POST /admin/api/users/{id}/deletion/cancel`); the cancellation tells
//!   the same people. An admin can't cancel a deletion the person asked
//!   for themself.
//! * The request and its cancellation are written to the admin log and
//!   emailed to every admin.
//!
//! The only admin's account may not be deleted, by anyone: the instance
//! would have nobody to run it.

use super::ApiJson;
use crate::auth::normalize_email;
use crate::auth::session::SessionUser;
use crate::db::repo::admin_log::{self, Action, Via};
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::users::{self, PendingDeletion};
use crate::db::repo::{allies, sessions};
use crate::error::{AppError, AppResult};
use crate::retention::MIN_MEMBER_DAYS;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::ServerAlertKind;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};

/// How long after the request nothing is removed: the shortest retention
/// window a member may choose, so allies can still open what was sent
/// recently (§4.3), and the person can change their mind.
pub const HOLD_MS: i64 = MIN_MEMBER_DAYS as i64 * 24 * 3600 * 1000;

/// Deleting needs a session signed in this recently.
pub const REAUTH_WINDOW_MS: i64 = 10 * 60 * 1000;

/// `DELETE /v1/me` body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteMe {
    /// The account's own email address, typed out.
    pub confirm_email: String,
}

/// Who a deletion notice (or its cancellation) went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Told {
    /// The person's own active allies.
    pub allies: usize,
    /// Members the person is an active ally for (each with their other
    /// allies).
    pub members: usize,
}

/// `DELETE /v1/me` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequested {
    pub deletion: PendingDeletion,
    pub told: Told,
}

/// `POST /v1/me/deletion/cancel` body: nothing, but a JSON body is required
/// (the CSRF defence of [`ApiJson`]).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelDeletion {}

/// `POST /v1/me/deletion/cancel` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionCancelled {
    pub requested_at_ms: i64,
    pub cancelled_at_ms: i64,
    pub told: Told,
}

/// Who asks for a deletion, or cancels one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum By<'a> {
    /// The person themself, in Settings or the banner.
    Person,
    /// An admin, under Admin → People ([`super::admin::delete_user`]).
    Admin(&'a UserId),
}

impl By<'_> {
    fn is_admin(self) -> bool {
        matches!(self, By::Admin(_))
    }
}

/// The notice raised on the person and on each member they are an ally for.
enum Notice {
    Requested {
        purge_after_ms: i64,
        by_admin: bool,
    },
    Cancelled {
        requested_at_ms: i64,
        requested_by_admin: bool,
        by_admin: bool,
    },
}

impl Notice {
    fn kinds(&self) -> (ServerAlertKind, ServerAlertKind) {
        match self {
            Notice::Requested { .. } => (
                ServerAlertKind::AccountDeleted,
                ServerAlertKind::AllyDeleted,
            ),
            Notice::Cancelled { .. } => (
                ServerAlertKind::AccountDeletionCancelled,
                ServerAlertKind::AccountDeletionCancelled,
            ),
        }
    }

    /// The `key=value;…` detail the email takes its wording from: the date
    /// or time, and `requested_by=admin` / `cancelled_by=admin` when an
    /// admin asked or cancelled (absent: the person did).
    fn detail(&self) -> String {
        match *self {
            Notice::Requested {
                purge_after_ms,
                by_admin,
            } => {
                let by = if by_admin { ";requested_by=admin" } else { "" };
                format!("purge_after={purge_after_ms}{by}")
            }
            Notice::Cancelled {
                requested_at_ms,
                requested_by_admin,
                by_admin,
            } => {
                let asked = if requested_by_admin {
                    ";requested_by=admin"
                } else {
                    ""
                };
                let by = if by_admin { ";cancelled_by=admin" } else { "" };
                format!("requested={requested_at_ms}{asked}{by}")
            }
        }
    }
}

/// Inside `tx`: raise `notice` on `user` (told to them and their active
/// allies) and on every member they are an active ally for (told to that
/// member and their other allies, naming `user`), exactly as disabling an
/// account does. Returns who was told.
async fn raise(
    tx: &mut sqlx::AnyConnection,
    user: &UserId,
    notice: &Notice,
    now: i64,
) -> AppResult<Told> {
    let (own, as_ally) = notice.kinds();
    alerts::insert(
        &mut *tx,
        &NewAlert {
            member_id: user,
            device_id: None,
            source: AlertSource::Server,
            kind: own.as_str(),
            urgency: own.urgency(),
            event_seq: None,
            detail: Some(notice.detail()),
            dedupe_key: Some(format!("{}:{user}:{now}", own.as_str())),
            now_ms: now,
        },
    )
    .await?;
    let members = allies::active_member_ids(&mut *tx, user).await?;
    for member in &members {
        alerts::insert_routed(
            &mut *tx,
            &NewAlert {
                member_id: member,
                device_id: None,
                source: AlertSource::Server,
                kind: as_ally.as_str(),
                urgency: as_ally.urgency(),
                event_seq: None,
                detail: Some(format!("ally={user};{}", notice.detail())),
                dedupe_key: Some(format!("{}:{member}:{user}:{now}", as_ally.as_str())),
                now_ms: now,
            },
            None,
            // The person hears about it from their own notice.
            Some(user),
            Some(user),
        )
        .await?;
    }
    Ok(Told {
        allies: allies::active_ally_ids(&mut *tx, user).await?.len(),
        members: members.len(),
    })
}

/// Inside a transaction that starts a relationship or a device for `user`:
/// refuse if their account is being deleted. The session check
/// ([`SessionUser::require_not_being_deleted`]) answers early; this one
/// can't race a deletion request committed in between.
pub(crate) async fn refuse_if_being_deleted<'e>(
    e: impl sqlx::Executor<'e, Database = sqlx::Any>,
    user: &UserId,
) -> AppResult<()> {
    if users::is_being_deleted(e, user).await? {
        Err(crate::auth::session::account_being_deleted())
    } else {
        Ok(())
    }
}

/// Inside `tx`: start the hold for `user` and tell everyone (module docs).
/// Refuses an account already being deleted, and the instance's last
/// enabled admin. An admin's request is also written to the admin log and
/// emailed to every admin. The caller checks who may ask.
pub(crate) async fn start(
    tx: &mut sqlx::AnyConnection,
    user: &users::User,
    by: By<'_>,
    now: i64,
) -> AppResult<DeletionRequested> {
    let id = &user.id;
    let already = || {
        AppError::conflict(
            "already_deleting",
            match by {
                By::Person => "your account is already being deleted",
                By::Admin(_) => "this account is already being deleted",
            },
        )
    };
    if user.deletion.is_some() {
        return Err(already());
    }
    if user.roles.admin && users::count_enabled_admins_except(&mut *tx, id).await? == 0 {
        return Err(AppError::conflict(
            "last_admin",
            match by {
                By::Person => "you are the instance's only admin, so your account can't be deleted",
                By::Admin(_) => "the instance must keep at least one enabled admin",
            },
        ));
    }
    let purge_after_ms = now.saturating_add(HOLD_MS);
    let by_admin = by.is_admin();
    if !users::request_deletion(&mut *tx, id, now, purge_after_ms, by_admin).await? {
        return Err(already());
    }
    let notice = Notice::Requested {
        purge_after_ms,
        by_admin,
    };
    let told = raise(tx, id, &notice, now).await?;
    if let By::Admin(admin) = by {
        log(tx, Action::DeletionRequested, id, admin, now).await?;
    }
    Ok(DeletionRequested {
        deletion: PendingDeletion {
            requested_at_ms: now,
            purge_after_ms,
            started_at_ms: None,
            by_admin,
        },
        told,
    })
}

/// Inside `tx`: cancel the pending deletion of `user` before its purge
/// starts, and tell the same people again. The person may cancel any
/// deletion of their account. An admin may cancel only one an admin asked
/// for, never the person's own request. Cancelling a deletion an admin
/// asked for is written to the admin log and emailed to every admin,
/// whoever cancels it.
pub(crate) async fn cancel(
    tx: &mut sqlx::AnyConnection,
    user: &users::User,
    by: By<'_>,
    now: i64,
) -> AppResult<DeletionCancelled> {
    let id = &user.id;
    let Some(pending) = user.deletion else {
        return Err(AppError::conflict(
            "not_deleting",
            match by {
                By::Person => "your account is not being deleted",
                By::Admin(_) => "this account is not being deleted",
            },
        ));
    };
    if by.is_admin() && !pending.by_admin {
        return Err(AppError::conflict(
            "not_admin_deletion",
            "this person asked for their account to be deleted; only they can cancel it",
        ));
    }
    if pending.started_at_ms.is_some()
        || !users::cancel_deletion(&mut *tx, id, pending.requested_at_ms).await?
    {
        return Err(AppError::conflict(
            "deletion_in_progress",
            match by {
                By::Person => "your account is already being deleted and can no longer be kept",
                By::Admin(_) => "this account is already being deleted and can no longer be kept",
            },
        ));
    }
    let notice = Notice::Cancelled {
        requested_at_ms: pending.requested_at_ms,
        requested_by_admin: pending.by_admin,
        by_admin: by.is_admin(),
    };
    let told = raise(tx, id, &notice, now).await?;
    if pending.by_admin {
        let actor = match by {
            By::Admin(admin) => admin,
            By::Person => id,
        };
        log(tx, Action::DeletionCancelled, id, actor, now).await?;
    }
    Ok(DeletionCancelled {
        requested_at_ms: pending.requested_at_ms,
        cancelled_at_ms: now,
        told,
    })
}

/// Write `action` about `user` to the admin log and email it to every
/// enabled admin but `user`, who hears from their own notice.
async fn log(
    tx: &mut sqlx::AnyConnection,
    action: Action,
    user: &UserId,
    actor: &UserId,
    now: i64,
) -> AppResult<()> {
    let entry = admin_log::insert(&mut *tx, action, user, Some(actor), Via::Console, now).await?;
    let admins = users::enabled_admin_ids_except(&mut *tx, user).await?;
    crate::roles::tell(tx, entry, &admins, now).await
}

/// `DELETE /v1/me`: ask for your account to be deleted (module docs).
pub async fn delete_me(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(req): ApiJson<DeleteMe>,
) -> AppResult<(StatusCode, Json<DeletionRequested>)> {
    let now = state.now_ms();
    if now.saturating_sub(s.session_started_at_ms) > REAUTH_WINDOW_MS {
        return Err(AppError::Forbidden("reauth_required"));
    }
    if normalize_email(&req.confirm_email).as_deref() != Some(s.user.email.as_str()) {
        return Err(AppError::bad_request(
            "confirmation_mismatch",
            "type your account's email address to confirm",
        ));
    }
    let id = &s.user.id;
    let mut tx = state.db().begin_write().await?;
    let user = users::by_id(&mut *tx, id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let r = start(&mut tx, &user, By::Person, now).await?;
    // Anyone else signed in as this person is signed out; this session
    // stays, so they can cancel.
    sessions::delete_others_for_user(&mut *tx, id, &s.session_hash).await?;
    tx.commit().await?;
    tracing::info!(
        user = %id,
        purge_after_ms = r.deletion.purge_after_ms,
        "account deletion requested"
    );
    Ok((StatusCode::ACCEPTED, Json(r)))
}

/// `POST /v1/me/deletion/cancel`: cancel a pending deletion of your
/// account before the purge starts, whoever asked for it (module docs).
/// Needs only a signed-in session.
pub async fn cancel_deletion(
    State(state): State<AppState>,
    s: SessionUser,
    ApiJson(_): ApiJson<CancelDeletion>,
) -> AppResult<Json<DeletionCancelled>> {
    let now = state.now_ms();
    let id = &s.user.id;
    let mut tx = state.db().begin_write().await?;
    let user = users::by_id(&mut *tx, id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let r = cancel(&mut tx, &user, By::Person, now).await?;
    tx.commit().await?;
    tracing::info!(user = %id, "account deletion cancelled");
    Ok(Json(r))
}
