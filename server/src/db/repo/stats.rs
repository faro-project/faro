//! Aggregate counts for the admin overview (§4.3: operational metadata
//! only). Nothing here is per member: every query is a `COUNT` / `SUM`
//! over the whole instance.
//!
//! **Portability.** On Postgres `SUM` over a `BIGINT` column is `NUMERIC`,
//! which sqlx's `Any` driver cannot decode (the whole row fails). So flags
//! are counted with `SUM(CASE … THEN 1 ELSE 0 END)` (int4 sums to bigint)
//! and byte totals are cast back with `CAST(… AS BIGINT)`; a unit test
//! checks every `SUM(` in the repository code follows one of the two.

use crate::db::Backend;
use serde::{Deserialize, Serialize};
use sqlx::{Any, AnyPool, Executor, Row};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCounts {
    pub total: i64,
    pub admins: i64,
    pub members: i64,
    pub allies: i64,
    pub disabled: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCounts {
    pub pending_endorsement: i64,
    pub active: i64,
    pub removed: i64,
}

/// Active devices bucketed by time since their last heartbeat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSeenBuckets {
    pub within_1h: i64,
    pub within_24h: i64,
    pub within_7d: i64,
    pub older: i64,
    pub never: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBytes {
    /// Ciphertext blobs (event bodies and reports).
    pub blobs: i64,
    pub blob_count: i64,
    /// The database itself, if the backend can tell.
    pub database: Option<i64>,
}

fn sum_col(r: &sqlx::any::AnyRow, c: &str) -> Result<i64, sqlx::Error> {
    r.try_get::<i64, _>(c)
}

pub async fn users<'e>(e: impl Executor<'e, Database = Any>) -> Result<UserCounts, sqlx::Error> {
    let r = sqlx::query(
        "SELECT COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN is_admin = 1 THEN 1 ELSE 0 END), 0) AS admins,
                COALESCE(SUM(CASE WHEN is_member = 1 THEN 1 ELSE 0 END), 0) AS members,
                COALESCE(SUM(CASE WHEN is_ally = 1 THEN 1 ELSE 0 END), 0) AS allies,
                COALESCE(SUM(CASE WHEN disabled = 1 THEN 1 ELSE 0 END), 0) AS disabled
         FROM users",
    )
    .fetch_one(e)
    .await?;
    Ok(UserCounts {
        total: sum_col(&r, "total")?,
        admins: sum_col(&r, "admins")?,
        members: sum_col(&r, "members")?,
        allies: sum_col(&r, "allies")?,
        disabled: sum_col(&r, "disabled")?,
    })
}

pub async fn devices<'e>(
    e: impl Executor<'e, Database = Any>,
) -> Result<DeviceCounts, sqlx::Error> {
    let r = sqlx::query(
        "SELECT
            COALESCE(SUM(CASE WHEN status = 'pending_endorsement' THEN 1 ELSE 0 END), 0) AS p,
            COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) AS a,
            COALESCE(SUM(CASE WHEN status = 'removed' THEN 1 ELSE 0 END), 0) AS r
         FROM devices",
    )
    .fetch_one(e)
    .await?;
    Ok(DeviceCounts {
        pending_endorsement: sum_col(&r, "p")?,
        active: sum_col(&r, "a")?,
        removed: sum_col(&r, "r")?,
    })
}

pub async fn last_seen<'e>(
    e: impl Executor<'e, Database = Any>,
    now_ms: i64,
) -> Result<LastSeenBuckets, sqlx::Error> {
    const H: i64 = 3600 * 1000;
    let r = sqlx::query(
        "SELECT
            COALESCE(SUM(CASE WHEN last_seen_at IS NULL THEN 1 ELSE 0 END), 0) AS never,
            COALESCE(SUM(CASE WHEN last_seen_at >= $1 THEN 1 ELSE 0 END), 0) AS h1,
            COALESCE(SUM(CASE WHEN last_seen_at < $1 AND last_seen_at >= $2 THEN 1 ELSE 0 END), 0)
                AS h24,
            COALESCE(SUM(CASE WHEN last_seen_at < $2 AND last_seen_at >= $3 THEN 1 ELSE 0 END), 0)
                AS d7,
            COALESCE(SUM(CASE WHEN last_seen_at < $3 THEN 1 ELSE 0 END), 0) AS older
         FROM devices WHERE status = 'active'",
    )
    .bind(now_ms - H)
    .bind(now_ms - 24 * H)
    .bind(now_ms - 7 * 24 * H)
    .fetch_one(e)
    .await?;
    Ok(LastSeenBuckets {
        within_1h: sum_col(&r, "h1")?,
        within_24h: sum_col(&r, "h24")?,
        within_7d: sum_col(&r, "d7")?,
        older: sum_col(&r, "older")?,
        never: sum_col(&r, "never")?,
    })
}

pub async fn storage(pool: &AnyPool, backend: Backend) -> Result<StorageBytes, sqlx::Error> {
    let r = sqlx::query(
        "SELECT CAST(COALESCE(SUM(size), 0) AS BIGINT) AS bytes, COUNT(*) AS n FROM blobs",
    )
    .fetch_one(pool)
    .await?;
    let database = match backend {
        Backend::Sqlite => sqlx::query(
            "SELECT page_count * page_size AS n FROM pragma_page_count(), pragma_page_size()",
        )
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|r| r.try_get::<i64, _>("n").ok()),
        Backend::Postgres => sqlx::query("SELECT pg_database_size(current_database()) AS n")
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .and_then(|r| r.try_get::<i64, _>("n").ok()),
    };
    Ok(StorageBytes {
        blobs: sum_col(&r, "bytes")?,
        blob_count: sum_col(&r, "n")?,
        database,
    })
}

#[cfg(test)]
mod tests {
    /// Every `SUM(` in the server's SQL must be portable to Postgres via the
    /// `Any` driver (see the module docs): either summing a `CASE` (an int4
    /// expression) or wrapped in `CAST(… AS BIGINT)`.
    #[test]
    fn sums_decode_on_postgres() {
        let sources = [
            include_str!("stats.rs"),
            include_str!("notifications.rs"),
            include_str!("users.rs"),
            include_str!("feed.rs"),
            include_str!("alerts.rs"),
            include_str!("allies.rs"),
            include_str!("devices.rs"),
            include_str!("events.rs"),
            include_str!("liveness.rs"),
            include_str!("reports.rs"),
            include_str!("manifests.rs"),
            include_str!("sessions.rs"),
            include_str!("instance.rs"),
            include_str!("invites.rs"),
            include_str!("enroll_codes.rs"),
            include_str!("member_keys.rs"),
            include_str!("auth_tokens.rs"),
            include_str!("uptime.rs"),
            include_str!("../../retention.rs"),
        ];
        let needle = ["SU", "M("].concat();
        let mut checked = 0;
        for src in sources {
            for (i, _) in src.match_indices(&needle) {
                let after = &src[i + needle.len()..];
                let before = &src[..i];
                let in_case = after.trim_start().starts_with("CASE ");
                let cast = before.trim_end().ends_with("CAST(COALESCE(")
                    || before.trim_end().ends_with("CAST(");
                // Skip this test's own needle construction and prose.
                let is_sql = after
                    .split(')')
                    .next()
                    .is_some_and(|arg| !arg.contains('"') && !arg.contains('`'));
                if !is_sql {
                    continue;
                }
                checked += 1;
                assert!(
                    in_case || cast,
                    "non-portable SUM at: {}",
                    &src[i..(i + 60).min(src.len())]
                );
            }
        }
        assert!(checked >= 10, "the scan found the queries ({checked})");
    }
}
