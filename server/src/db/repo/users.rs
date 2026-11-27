//! `users`: accounts for members, allies and instance admins.

use super::parse_col;
use crate::db::flag;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::any::AnyRow;
use sqlx::{Any, Executor, Row};

/// Role flags. One account may hold several (an admin is often also a member).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Roles {
    pub admin: bool,
    pub member: bool,
    pub ally: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub roles: Roles,
    #[serde(skip)]
    pub disabled: bool,
    pub created_at_ms: i64,
    /// The person asked for their account to be deleted (§12). Reported by
    /// `GET /v1/me` on its own, not as part of the user.
    #[serde(skip)]
    pub deletion: Option<PendingDeletion>,
}

/// A requested account deletion (§12): nothing is removed until the hold
/// has passed, and the person can cancel until the purge starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingDeletion {
    pub requested_at_ms: i64,
    /// The end of the hold: the purge starts after this, once every
    /// deletion notice has been delivered.
    pub purge_after_ms: i64,
    /// When the purge started (from then on it can't be cancelled).
    pub started_at_ms: Option<i64>,
    /// An admin asked for it, not the person: then the person or any admin
    /// may cancel it. Only the person may cancel their own request.
    pub by_admin: bool,
}

/// The column list [`from_row`] reads, as a macro so queries can be built
/// with `concat!` into `&'static str` (no dynamic SQL).
macro_rules! columns {
    () => {
        "id, email, display_name, is_admin, is_member, is_ally, disabled, created_at,
         deletion_requested_at, deletion_purge_after, deletion_started_at, deletion_by_admin"
    };
}

pub(crate) fn from_row(row: &AnyRow) -> Result<User, sqlx::Error> {
    Ok(User {
        id: parse_col(row, "id", |s| {
            let id = UserId::new(s);
            id.is_well_formed().then_some(id)
        })?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        roles: Roles {
            admin: row.try_get::<i64, _>("is_admin")? != 0,
            member: row.try_get::<i64, _>("is_member")? != 0,
            ally: row.try_get::<i64, _>("is_ally")? != 0,
        },
        disabled: row.try_get::<i64, _>("disabled")? != 0,
        created_at_ms: row.try_get("created_at")?,
        deletion: deletion_from_row(row)?,
    })
}

fn deletion_from_row(row: &AnyRow) -> Result<Option<PendingDeletion>, sqlx::Error> {
    let requested: Option<i64> = row.try_get("deletion_requested_at")?;
    let purge_after: Option<i64> = row.try_get("deletion_purge_after")?;
    let (Some(requested_at_ms), Some(purge_after_ms)) = (requested, purge_after) else {
        return Ok(None);
    };
    Ok(Some(PendingDeletion {
        requested_at_ms,
        purge_after_ms,
        started_at_ms: row.try_get("deletion_started_at")?,
        by_admin: row.try_get::<i64, _>("deletion_by_admin")? != 0,
    }))
}

pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    user: &User,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, email, display_name, is_admin, is_member, is_ally, disabled, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(user.id.as_str())
    .bind(&user.email)
    .bind(&user.display_name)
    .bind(flag(user.roles.admin))
    .bind(flag(user.roles.member))
    .bind(flag(user.roles.ally))
    .bind(flag(user.disabled))
    .bind(user.created_at_ms)
    .execute(e)
    .await?;
    Ok(())
}

pub async fn by_id<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query(concat!("SELECT ", columns!(), " FROM users WHERE id = $1"))
        .bind(id.as_str())
        .fetch_optional(e)
        .await?
        .as_ref()
        .map(from_row)
        .transpose()
}

pub async fn by_email<'e>(
    e: impl Executor<'e, Database = Any>,
    email: &str,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM users WHERE email = $1"
    ))
    .bind(email)
    .fetch_optional(e)
    .await?
    .as_ref()
    .map(from_row)
    .transpose()
}

pub async fn count_admins<'e>(e: impl Executor<'e, Database = Any>) -> Result<i64, sqlx::Error> {
    let row = sqlx::query("SELECT COUNT(*) AS n FROM users WHERE is_admin = 1")
        .fetch_one(e)
        .await?;
    row.try_get("n")
}

/// Enabled admins other than `except` who are not being deleted (so the
/// last one can't be disabled or deleted).
pub async fn count_enabled_admins_except<'e>(
    e: impl Executor<'e, Database = Any>,
    except: &UserId,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM users
         WHERE is_admin = 1 AND disabled = 0 AND deletion_requested_at IS NULL AND id <> $1",
    )
    .bind(except.as_str())
    .fetch_one(e)
    .await?;
    row.try_get("n")
}

/// Enabled admins other than `except`, oldest account first: who is told
/// when the admin role changes. Admins being deleted are included (they
/// are admins until the purge).
pub async fn enabled_admin_ids_except<'e>(
    e: impl Executor<'e, Database = Any>,
    except: &UserId,
) -> Result<Vec<UserId>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id FROM users WHERE is_admin = 1 AND disabled = 0 AND id <> $1
         ORDER BY created_at, id",
    )
    .bind(except.as_str())
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("id")?)))
        .collect()
}

/// Every member account (including disabled ones: their devices keep
/// reporting), for an instance-wide alert to their allies.
pub async fn member_ids<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<Vec<UserId>, sqlx::Error> {
    let rows = sqlx::query("SELECT id FROM users WHERE is_member = 1 ORDER BY created_at, id")
        .fetch_all(e)
        .await?;
    rows.iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("id")?)))
        .collect()
}

/// Grant or revoke the admin role. Returns false if the account already
/// had that value.
pub async fn set_admin<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    admin: bool,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query("UPDATE users SET is_admin = $1 WHERE id = $2 AND is_admin <> $1")
        .bind(flag(admin))
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(r.rows_affected() == 1)
}

/// Set an account's disabled flag. Returns false if it already had that value.
pub async fn set_disabled<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    disabled: bool,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query("UPDATE users SET disabled = $1 WHERE id = $2 AND disabled <> $1")
        .bind(flag(disabled))
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn touch_login<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    now_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
        .bind(now_ms)
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(())
}

/// Change an account's display name (already normalized).
pub async fn set_display_name<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    display_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET display_name = $1 WHERE id = $2")
        .bind(display_name)
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(())
}

/// Grant the ally role (idempotent).
pub async fn grant_ally<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET is_ally = 1 WHERE id = $1")
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(())
}

/// Grant the member role (idempotent).
pub async fn grant_member<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET is_member = 1 WHERE id = $1")
        .bind(id.as_str())
        .execute(e)
        .await?;
    Ok(())
}

/// Record a deletion request (§12), by the person or (`by_admin`) by an
/// admin. False if one is already pending.
pub async fn request_deletion<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    now_ms: i64,
    purge_after_ms: i64,
    by_admin: bool,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE users SET deletion_requested_at = $1, deletion_purge_after = $2,
                          deletion_started_at = NULL, deletion_by_admin = $4
         WHERE id = $3 AND deletion_requested_at IS NULL",
    )
    .bind(now_ms)
    .bind(purge_after_ms)
    .bind(id.as_str())
    .bind(flag(by_admin))
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Cancel the deletion requested at `requested_at_ms`. False if there is no
/// such request any more or its purge has started.
///
/// Paired with [`start_purge`]: each checks the column the other sets, so
/// on Postgres, where both may run at once, whichever takes the row lock
/// second re-reads the row and changes nothing.
pub async fn cancel_deletion<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    requested_at_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE users SET deletion_requested_at = NULL, deletion_purge_after = NULL,
                          deletion_by_admin = 0
         WHERE id = $1 AND deletion_requested_at = $2 AND deletion_started_at IS NULL",
    )
    .bind(id.as_str())
    .bind(requested_at_ms)
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Mark the purge of `id` as started, if its hold has passed. True if it
/// is started (now or earlier): from then on it can't be cancelled.
pub async fn start_purge<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
    now_ms: i64,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query(
        "UPDATE users SET deletion_started_at = COALESCE(deletion_started_at, $1)
         WHERE id = $2 AND deletion_requested_at IS NOT NULL AND deletion_purge_after <= $1",
    )
    .bind(now_ms)
    .bind(id.as_str())
    .execute(e)
    .await?;
    Ok(r.rows_affected() == 1)
}

/// Accounts whose hold has passed, oldest first: the purge worker's queue.
pub async fn due_for_purge<'e>(
    e: impl Executor<'e, Database = Any>,
    now_ms: i64,
) -> Result<Vec<UserId>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id FROM users
         WHERE deletion_requested_at IS NOT NULL AND deletion_purge_after <= $1
         ORDER BY deletion_purge_after, id",
    )
    .bind(now_ms)
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| Ok(UserId::new(r.try_get::<String, _>("id")?)))
        .collect()
}

/// Whether `id` has a deletion pending: re-checked inside the transactions
/// that create relationships or devices.
pub async fn is_being_deleted<'e>(
    e: impl Executor<'e, Database = Any>,
    id: &UserId,
) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 AS x FROM users WHERE id = $1 AND deletion_requested_at IS NOT NULL")
            .bind(id.as_str())
            .fetch_optional(e)
            .await?
            .is_some(),
    )
}

/// A purge this long past its hold is reported to the admin (console and
/// `doctor`): its notices could not be delivered, so it waits for mail.
pub const OVERDUE_AFTER_MS: i64 = 7 * 24 * 3600 * 1000;

/// Pending deletions, for the admin overview and `doctor` (counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionCounts {
    /// Accounts with a deletion requested and not yet purged.
    pub pending: i64,
    /// Of those, purges waiting more than [`OVERDUE_AFTER_MS`] past their
    /// hold.
    pub overdue: i64,
}

pub async fn deletion_counts<'e>(
    e: impl Executor<'e, Database = Any>,
    now_ms: i64,
) -> Result<DeletionCounts, sqlx::Error> {
    let r = sqlx::query(
        "SELECT COUNT(*) AS pending,
                COALESCE(SUM(CASE WHEN deletion_purge_after < $1 THEN 1 ELSE 0 END), 0) AS overdue
         FROM users WHERE deletion_requested_at IS NOT NULL",
    )
    .bind(now_ms.saturating_sub(OVERDUE_AFTER_MS))
    .fetch_one(e)
    .await?;
    Ok(DeletionCounts {
        pending: r.try_get("pending")?,
        overdue: r.try_get("overdue")?,
    })
}

/// One row of the admin user list: account metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminUserRow {
    pub id: UserId,
    pub email: String,
    pub display_name: String,
    pub roles: Roles,
    pub disabled: bool,
    pub created_at_ms: i64,
    pub last_login_at_ms: Option<i64>,
    /// The end of the hold, if the account is being deleted.
    pub deletion_purge_after_ms: Option<i64>,
    /// The deletion was asked for by an admin (any admin may cancel it),
    /// not by the person.
    pub deletion_by_admin: bool,
    /// Non-removed devices.
    pub device_count: i64,
    /// Most recent heartbeat of any of the user's devices.
    pub devices_last_seen_at_ms: Option<i64>,
}

pub async fn list_for_admin<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<Vec<AdminUserRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT u.id, u.email, u.display_name, u.is_admin, u.is_member, u.is_ally, u.disabled,
                u.created_at, u.last_login_at, u.deletion_requested_at,
                u.deletion_purge_after, u.deletion_started_at, u.deletion_by_admin,
                (SELECT COUNT(*) FROM devices d
                  WHERE d.owner_user_id = u.id AND d.status <> 'removed') AS device_count,
                (SELECT MAX(d.last_seen_at) FROM devices d
                  WHERE d.owner_user_id = u.id AND d.status <> 'removed') AS devices_last_seen
         FROM users u ORDER BY u.created_at, u.id",
    )
    .fetch_all(e)
    .await?;
    rows.iter()
        .map(|r| {
            let u = from_row(r)?;
            Ok(AdminUserRow {
                id: u.id,
                email: u.email,
                display_name: u.display_name,
                roles: u.roles,
                disabled: u.disabled,
                created_at_ms: u.created_at_ms,
                last_login_at_ms: r.try_get("last_login_at")?,
                deletion_purge_after_ms: u.deletion.map(|d| d.purge_after_ms),
                deletion_by_admin: u.deletion.is_some_and(|d| d.by_admin),
                device_count: r.try_get("device_count")?,
                devices_last_seen_at_ms: r.try_get("devices_last_seen")?,
            })
        })
        .collect()
}
