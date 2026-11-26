//! `admin_log`: what admins did to accounts (§4.3): granting and revoking
//! the admin role ([`crate::roles`]), and account deletions an admin asked
//! for, with their cancellation ([`crate::api::admin`]), accounts disabled
//! and re-enabled, and accounts created from the command line. Shown in the
//! admin console and emailed to the admins (and, for a role change, the
//! person). Entries are kept: no
//! retention window applies to them, and the account-deletion purge only
//! NULLs the ids in them.

use crate::tokens::new_hex_id;
use faro_proto::UserId;
use serde::{Deserialize, Serialize};
use sqlx::{Any, Executor, Row};

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    AdminGranted,
    AdminRevoked,
    /// An admin asked for the account to be deleted (§12).
    DeletionRequested,
    /// A deletion an admin asked for was cancelled, by an admin or by the
    /// person (then `actor_id` is the person themself).
    DeletionCancelled,
    /// `faro-server admin grant --create` created the account (followed
    /// by `admin_granted`).
    AccountCreated,
    /// An admin disabled the account. The person and their partners have
    /// their own notices (invariant 6); this entry is for the admins.
    AccountDisabled,
    /// An admin re-enabled a disabled account.
    AccountEnabled,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::AdminGranted => "admin_granted",
            Action::AdminRevoked => "admin_revoked",
            Action::DeletionRequested => "deletion_requested",
            Action::DeletionCancelled => "deletion_cancelled",
            Action::AccountCreated => "account_created",
            Action::AccountDisabled => "account_disabled",
            Action::AccountEnabled => "account_enabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin_granted" => Some(Action::AdminGranted),
            "admin_revoked" => Some(Action::AdminRevoked),
            "deletion_requested" => Some(Action::DeletionRequested),
            "deletion_cancelled" => Some(Action::DeletionCancelled),
            "account_created" => Some(Action::AccountCreated),
            "account_disabled" => Some(Action::AccountDisabled),
            "account_enabled" => Some(Action::AccountEnabled),
            _ => None,
        }
    }
}

/// Where the action came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// In the web app (or its API): an admin in the admin console, or the
    /// person cancelling a deletion an admin asked for.
    Console,
    /// `faro-server admin …` on the server itself: no admin account did it.
    CommandLine,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Console => "console",
            Via::CommandLine => "command_line",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "console" => Some(Via::Console),
            "command_line" => Some(Via::CommandLine),
            _ => None,
        }
    }
}

/// Record an action. Returns the new entry's id.
pub async fn insert<'e>(
    e: impl Executor<'e, Database = Any>,
    action: Action,
    user: &UserId,
    actor: Option<&UserId>,
    via: Via,
    now_ms: i64,
) -> Result<String, sqlx::Error> {
    let id = new_hex_id();
    sqlx::query(
        "INSERT INTO admin_log (id, action, user_id, actor_id, via, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(action.as_str())
    .bind(user.as_str())
    .bind(actor.map(|a| a.as_str().to_owned()))
    .bind(via.as_str())
    .bind(now_ms)
    .execute(e)
    .await?;
    Ok(id)
}

/// An account named in the log. `None` in [`Entry`] once it is deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: UserId,
    pub display_name: String,
    pub email: String,
}

/// One entry, for the admin console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub action: Action,
    /// The account it was about.
    pub user: Option<Account>,
    /// The admin who did it: `None` from the command line, or once that
    /// account is deleted.
    pub actor: Option<Account>,
    pub via: Via,
    pub at_ms: i64,
}

/// The most recent entries, newest first.
pub async fn recent<'e>(
    e: impl Executor<'e, Database = Any>,
    limit: i64,
) -> Result<Vec<Entry>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT l.id, l.action, l.via, l.created_at,
                u.id AS user_id, u.display_name AS user_name, u.email AS user_email,
                a.id AS actor_id, a.display_name AS actor_name, a.email AS actor_email
         FROM admin_log l
         LEFT JOIN users u ON u.id = l.user_id
         LEFT JOIN users a ON a.id = l.actor_id
         ORDER BY l.created_at DESC, l.id DESC
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(e)
    .await?;
    let account = |r: &sqlx::any::AnyRow, p: &str| -> Result<Option<Account>, sqlx::Error> {
        let id: Option<String> = r.try_get(format!("{p}_id").as_str())?;
        let Some(id) = id else { return Ok(None) };
        Ok(Some(Account {
            id: UserId::new(id),
            display_name: r.try_get(format!("{p}_name").as_str())?,
            email: r.try_get(format!("{p}_email").as_str())?,
        }))
    };
    rows.iter()
        .map(|r| {
            Ok(Entry {
                id: r.try_get("id")?,
                action: super::parse_col(r, "action", Action::parse)?,
                user: account(r, "user")?,
                actor: account(r, "actor")?,
                via: super::parse_col(r, "via", Via::parse)?,
                at_ms: r.try_get("created_at")?,
            })
        })
        .collect()
}
