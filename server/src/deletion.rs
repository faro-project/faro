//! The account-deletion purge (§12): once a deletion's hold has passed and
//! every deletion notice has been delivered, remove everything the instance
//! stores about the person. The request and the cancel are in
//! [`crate::api::account`].
//!
//! **The gate.** An account is purged only when (a) its hold
//! (`deletion_purge_after`) has passed and (b) every `account_deleted`,
//! `ally_deleted` and `account_deletion_cancelled` notice about it has been
//! fanned out and none of its notifications is still pending
//! ([`deletion::notices_final`]): the notices are raised on the person's
//! account and name them, so they must go out first. A failure about one
//! recipient becomes final after the notifier's retries; an instance-wide
//! mail failure never does, so **the purge waits until mail works**. The
//! admin console and `faro-server doctor` report a purge that has waited
//! more than [`users::OVERDUE_AFTER_MS`] past its hold.
//!
//! **The stages**, each idempotent, so a crash anywhere just means the next
//! pass picks up where this one stopped (the user row goes last):
//!
//! 0. One transaction marks the purge as started (it can no longer be
//!    cancelled), records the token hash of each of the person's computers
//!    in `deleted_device_tokens` and retires them (from now on they get
//!    `403 account_deleted`: monitoring stops here, not at the request), and
//!    ends every link the person is part of, as member or ally, without a
//!    new alert ([`EndReason::AccountDeleted`]).
//! 1. Their ciphertext and content rows go through the retention code path
//!    ([`retention::purge_member`]): blob rows, then the files, then
//!    reports, events and alerts. A crash between a blob row and its file
//!    leaves an orphan file, which the retention sweep removes.
//! 2. One transaction deletes every remaining row naming them, table by
//!    table ([`deletion::PURGE_BY_ID`]), and then the user row. It refuses
//!    to run while any of their blobs is left.

use crate::api::allies::{end_link, EndReason};
use crate::db::repo::{allies, deletion, users};
use crate::error::AppError;
use crate::retention;
use crate::state::AppState;
use faro_proto::UserId;

/// How often the worker looks for accounts to purge.
pub const PURGE_INTERVAL_SECS: u64 = 60;

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeSummary {
    /// Accounts deleted.
    pub purged: usize,
    /// Accounts past their hold whose notices are still being delivered.
    pub waiting: usize,
}

/// One pass: purge every account whose hold has passed and whose notices
/// are delivered.
pub async fn run_once(state: &AppState) -> Result<PurgeSummary, AppError> {
    let mut s = PurgeSummary::default();
    let pool = state.db().pool();
    for user in users::due_for_purge(pool, state.now_ms()).await? {
        if !deletion::notices_final(pool, &user).await? {
            s.waiting += 1;
            continue;
        }
        if purge(state, &user).await? {
            s.purged += 1;
        }
    }
    if s.waiting > 0 {
        tracing::info!(
            waiting = s.waiting,
            "account deletions are waiting for their notices to be delivered"
        );
    }
    Ok(s)
}

/// Purge one account whose gate is open (see the module docs). False if it
/// is not due (cancelled meanwhile) or content was left for the next pass.
pub async fn purge(state: &AppState, user: &UserId) -> Result<bool, AppError> {
    if !stop_and_purge_content(state, user).await? {
        return Ok(false);
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    let Some(row) = users::by_id(&mut *tx, user).await? else {
        return Ok(true);
    };
    if deletion::blob_count(&mut *tx, user).await? > 0 {
        // Uploaded between the stages (it can't be any more): their
        // files must go after their rows, so the next pass runs stage 1
        // again.
        tracing::warn!(user = %user, "content left after the purge's first stage; retrying");
        return Ok(false);
    }
    deletion::delete_rows(&mut tx, user, &row.email, now).await?;
    tx.commit().await?;
    tracing::info!(user = %user, "account deleted");
    Ok(true)
}

/// Stages 0 and 1 of [`purge`]: stop the account's computers, end its
/// links, and delete its content. False if the account is not due. Public
/// so tests can stop a purge halfway, as a crash would.
pub async fn stop_and_purge_content(state: &AppState, user: &UserId) -> Result<bool, AppError> {
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    if !users::start_purge(&mut *tx, user, now).await? {
        return Ok(false);
    }
    deletion::insert_device_tombstones(&mut *tx, user, now).await?;
    deletion::retire_devices(&mut tx, user, now).await?;
    for (member, ally) in allies::live_links_of(&mut *tx, user).await? {
        end_link(&mut tx, &member, &ally, EndReason::AccountDeleted, now).await?;
    }
    tx.commit().await?;
    let s = retention::purge_member(state, user).await?;
    tracing::info!(
        user = %user,
        blobs = s.blobs,
        events = s.events,
        reports = s.reports,
        alerts = s.alerts,
        "account content deleted"
    );
    Ok(true)
}
