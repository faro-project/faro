//! Granting and revoking the admin role (§4.3).
//!
//! An admin grants or revokes the role for another account in the admin
//! console (`PUT /admin/api/users/{id}/admin`). Someone with access to the
//! server can grant it from the command line (`faro-server admin grant`),
//! the way back in when nobody can sign in as an admin any more. With
//! `--create`, the command line also creates the account if no account
//! has the address ([`create_admin`]).
//!
//! The rules:
//!
//! * Nobody changes their own role.
//! * The instance keeps at least one enabled admin who is not being deleted
//!   (the same rule as disabling and deleting accounts).
//! * The role is not granted to a disabled account or changed on one being
//!   deleted. A disabled admin's role can still be revoked.
//! * **Every change is told**, by email, to the person and to every other
//!   enabled admin, the one who made it included. It is written to the
//!   [`admin_log`], which the admin console shows. These notices are not
//!   tamper-class: the role changes nothing about monitoring.
//!
//! The role never gives access to content: admin routes return
//! configuration and account metadata only (invariant 2).

use crate::db::repo::admin_log::{self, Action, Via};
use crate::db::repo::notifications::{self, NewNotification, Target};
use crate::db::repo::users;
use crate::error::{AppError, AppResult};
use crate::notify::policy::Mode;
use crate::state::AppState;
use faro_proto::{Urgency, UserId};
use serde::{Deserialize, Serialize};

/// Who is changing the role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum By<'a> {
    /// An admin, in the admin console.
    Admin(&'a UserId),
    /// `faro-server admin grant` on the server.
    CommandLine,
}

/// The result of a role change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRole {
    pub user_id: UserId,
    pub admin: bool,
    /// How many people are emailed about it: the person and every other
    /// enabled admin.
    pub told: usize,
}

/// Inside `tx`: email admin log entry `entry` to `recipients`, at once.
/// These are notification rows like any other, sent by the notifier, but
/// not alerts: there is nothing to fan out, and no preference applies.
pub(crate) async fn tell(
    tx: &mut sqlx::AnyConnection,
    entry: String,
    recipients: &[UserId],
    now: i64,
) -> AppResult<()> {
    let target = Target::AdminLog(entry);
    for r in recipients {
        notifications::insert(
            &mut *tx,
            &NewNotification {
                target: &target,
                recipient: r,
                urgency: Urgency::Normal,
                mode: Some(Mode::Immediate),
                due_at_ms: now,
                now_ms: now,
            },
        )
        .await?;
    }
    Ok(())
}

/// Grant (`admin: true`) or revoke the admin role of `target` (module docs).
pub async fn set_admin(
    state: &AppState,
    target: &UserId,
    admin: bool,
    by: By<'_>,
) -> AppResult<AdminRole> {
    let actor = match by {
        By::Admin(a) => Some(a),
        By::CommandLine => None,
    };
    if actor == Some(target) {
        return Err(AppError::bad_request(
            "cannot_change_own_role",
            "you cannot change your own admin role; ask another admin",
        ));
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let r = set_admin_in(&mut tx, target, admin, by, now).await?;
    tx.commit().await?;
    tracing::info!(
        actor = actor.map(UserId::as_str),
        user = %target,
        admin,
        via = match by {
            By::Admin(_) => Via::Console,
            By::CommandLine => Via::CommandLine,
        }
        .as_str(),
        "admin role changed"
    );
    Ok(r)
}

/// `faro-server admin grant --create`: create an account for `email` (an
/// address with no account yet, already normalized) and make it an admin,
/// in one transaction. The account starts the way the first admin's does
/// at setup: a member, so they can set up keys at their first sign-in,
/// named `display_name` (already normalized). Nobody is signed in: the
/// person signs in with an email link like anyone else, which also proves
/// the address is theirs. Written to the admin log as `account_created`
/// (emailed to the person, saying how to sign in) and `admin_granted`
/// (emailed to the person and every other admin, as usual).
pub async fn create_admin(
    state: &AppState,
    email: &str,
    display_name: &str,
) -> AppResult<AdminRole> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    if users::by_email(&mut *tx, email).await?.is_some() {
        return Err(AppError::conflict(
            "email_in_use",
            "an account with this email already exists",
        ));
    }
    let user = users::User {
        id: UserId::from_random(&faro_crypto::random_bytes::<16>()),
        email: email.to_owned(),
        display_name: display_name.to_owned(),
        roles: users::Roles {
            admin: false,
            member: true,
            ally: false,
        },
        disabled: false,
        created_at_ms: now,
        deletion: None,
    };
    users::insert(&mut *tx, &user).await?;
    let entry = admin_log::insert(
        &mut *tx,
        Action::AccountCreated,
        &user.id,
        None,
        Via::CommandLine,
        now,
    )
    .await?;
    tell(&mut tx, entry, std::slice::from_ref(&user.id), now).await?;
    let r = set_admin_in(&mut tx, &user.id, true, By::CommandLine, now).await?;
    tx.commit().await?;
    tracing::info!(user = %user.id, "admin account created from the command line");
    Ok(r)
}

/// [`set_admin`] inside `tx`, so `faro-server admin grant --create` can
/// create the account in the same transaction. The caller has checked
/// that nobody changes their own role.
pub(crate) async fn set_admin_in(
    tx: &mut sqlx::AnyConnection,
    target: &UserId,
    admin: bool,
    by: By<'_>,
    now: i64,
) -> AppResult<AdminRole> {
    let actor = match by {
        By::Admin(a) => Some(a),
        By::CommandLine => None,
    };
    let user = users::by_id(&mut *tx, target)
        .await?
        .ok_or(AppError::NotFound)?;
    if user.deletion.is_some() {
        return Err(AppError::conflict(
            "account_deleting",
            "this account is being deleted",
        ));
    }
    if admin && user.disabled {
        return Err(AppError::conflict(
            "account_disabled",
            "this account is disabled; re-enable it first",
        ));
    }
    if !admin && users::count_enabled_admins_except(&mut *tx, target).await? == 0 {
        return Err(AppError::conflict(
            "last_admin",
            "the instance must keep at least one enabled admin",
        ));
    }
    if !users::set_admin(&mut *tx, target, admin).await? {
        return Err(if admin {
            AppError::conflict("already_admin", "this account is already an admin")
        } else {
            AppError::conflict("not_admin", "this account is not an admin")
        });
    }
    let action = if admin {
        Action::AdminGranted
    } else {
        Action::AdminRevoked
    };
    let via = match by {
        By::Admin(_) => Via::Console,
        By::CommandLine => Via::CommandLine,
    };
    let entry = admin_log::insert(&mut *tx, action, target, actor, via, now).await?;
    let mut recipients = vec![target.clone()];
    recipients.extend(users::enabled_admin_ids_except(&mut *tx, target).await?);
    tell(tx, entry, &recipients, now).await?;
    Ok(AdminRole {
        user_id: target.clone(),
        admin,
        // A disabled person hears nothing (see `crate::notify`).
        told: recipients.len() - usize::from(user.disabled),
    })
}
