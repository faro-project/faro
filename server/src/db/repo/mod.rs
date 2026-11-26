//! Repository functions: all SQL lives here, grouped by table.
//!
//! Handlers never build SQL themselves; they call these functions inside a
//! transaction (`&mut *tx`) or directly on the pool.

pub mod admin_log;
pub mod alerts;
pub mod allies;
pub mod auth_tokens;
pub mod branding;
pub mod deletion;
pub mod devices;
pub mod enroll_codes;
pub mod events;
pub mod feed;
pub mod group_listing;
pub mod group_notices;
pub mod groups;
pub mod instance;
pub mod invites;
pub mod liveness;
pub mod manifests;
pub mod member_keys;
pub mod notifications;
pub mod proposals;
pub mod reports;
pub mod sessions;
pub mod stats;
pub mod uptime;
pub mod users;

use sqlx::any::AnyRow;
use sqlx::Row;

/// Decode a TEXT column through a parser, mapping failure to a decode error
/// (only reachable through database corruption or a buggy migration).
pub(crate) fn parse_col<T>(
    row: &AnyRow,
    col: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<T, sqlx::Error> {
    let s: String = row.try_get(col)?;
    parse(&s).ok_or_else(|| sqlx::Error::Decode(format!("invalid value in column {col}").into()))
}

/// Like [`parse_col`] for a nullable column.
pub(crate) fn parse_opt_col<T>(
    row: &AnyRow,
    col: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, sqlx::Error> {
    let s: Option<String> = row.try_get(col)?;
    match s {
        None => Ok(None),
        Some(s) => parse(&s)
            .map(Some)
            .ok_or_else(|| sqlx::Error::Decode(format!("invalid value in column {col}").into())),
    }
}

/// Whether an error is a UNIQUE / PRIMARY KEY violation.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.is_unique_violation())
}
