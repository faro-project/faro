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
}

/// The column list [`from_row`] reads, as a macro so queries can be built
/// with `concat!` into `&'static str` (no dynamic SQL).
macro_rules! columns {
    () => {
        "id, email, display_name, is_admin, is_member, is_ally, disabled, created_at"
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
    })
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

/// Enabled admins other than `except` (so the last one can't be disabled).
pub async fn count_enabled_admins_except<'e>(
    e: impl Executor<'e, Database = Any>,
    except: &UserId,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled = 0 AND id <> $1",
    )
    .bind(except.as_str())
    .fetch_one(e)
    .await?;
    row.try_get("n")
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
                u.created_at, u.last_login_at,
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
                device_count: r.try_get("device_count")?,
                devices_last_seen_at_ms: r.try_get("devices_last_seen")?,
            })
        })
        .collect()
}
