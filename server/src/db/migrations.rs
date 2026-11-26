//! Embedded schema migrations.
//!
//! The SQL is compiled into the binary (`include_str!`) so a single static
//! binary can create and upgrade its own database: there is nothing to ship
//! alongside it. We implement sqlx's public [`MigrationSource`] rather than
//! using `sqlx::migrate!()` so that no compile-time macros are needed.
//!
//! Every migration so far is portable SQL shared by both backends. If a future
//! migration needs dialect-specific SQL, give it a per-backend variant in
//! `sources` (keeping the same version number and description on both
//! sides) rather than forking the whole list.

use super::Backend;
use sqlx::error::BoxDynError;
use sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use sqlx::SqlStr;
use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;

/// `(version, description, sql)` for each migration, in order.
fn sources(backend: Backend) -> Vec<(i64, &'static str, &'static str)> {
    match backend {
        Backend::Sqlite | Backend::Postgres => {
            vec![
                (1, "init", include_str!("../../migrations/0001_init.sql")),
                (
                    2,
                    "allies_notifier_liveness",
                    include_str!("../../migrations/0002_allies_notifier_liveness.sql"),
                ),
                (
                    3,
                    "recipient_manifests",
                    include_str!("../../migrations/0003_recipient_manifests.sql"),
                ),
                (
                    4,
                    "liveness_retention_fixes",
                    include_str!("../../migrations/0004_liveness_retention_fixes.sql"),
                ),
                (
                    5,
                    "account_status_alerts",
                    include_str!("../../migrations/0005_account_status_alerts.sql"),
                ),
                (
                    6,
                    "account_deletion",
                    include_str!("../../migrations/0006_account_deletion.sql"),
                ),
                (
                    7,
                    "branding",
                    include_str!("../../migrations/0007_branding.sql"),
                ),
                (
                    8,
                    "admin_log",
                    include_str!("../../migrations/0008_admin_log.sql"),
                ),
                (
                    9,
                    "admin_deletion",
                    include_str!("../../migrations/0009_admin_deletion.sql"),
                ),
                (
                    10,
                    "groups",
                    include_str!("../../migrations/0010_groups.sql"),
                ),
                (
                    13,
                    "group_roster",
                    include_str!("../../migrations/0013_group_roster.sql"),
                ),
            ]
        }
    }
}

/// Number of embedded migrations for `backend` (for `doctor`).
pub fn count(backend: Backend) -> i64 {
    i64::try_from(sources(backend).len()).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, Copy)]
struct Embedded(Backend);

type ResolveFuture = Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send>>;

impl MigrationSource<'static> for Embedded {
    fn resolve(self) -> ResolveFuture {
        let migrations = sources(self.0)
            .into_iter()
            .map(|(version, desc, sql)| {
                Migration::new(
                    version,
                    Cow::Borrowed(desc),
                    MigrationType::Simple,
                    SqlStr::from_static(sql),
                    false,
                )
            })
            .collect();
        Box::pin(async move { Ok(migrations) })
    }
}

pub async fn migrator(backend: Backend) -> Result<Migrator, sqlx::migrate::MigrateError> {
    Migrator::new(Embedded(backend)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_strictly_increase() {
        for b in [Backend::Sqlite, Backend::Postgres] {
            let v: Vec<i64> = sources(b).iter().map(|s| s.0).collect();
            assert!(v.windows(2).all(|w| w[0] < w[1]));
            assert!(v.iter().all(|&x| x > 0));
        }
    }

    #[test]
    fn schema_stays_portable() {
        // Guard against SQLite-only or Postgres-only constructs creeping in.
        for (_, _, sql) in sources(Backend::Sqlite) {
            let code: String = sql
                .lines()
                .map(|l| l.split("--").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n")
                .to_ascii_uppercase();
            let words: Vec<&str> = code
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .collect();
            for banned in [
                "AUTOINCREMENT",
                "SERIAL",
                "BIGSERIAL",
                "BLOB",
                "BYTEA",
                "BOOLEAN",
                "JSONB",
                "ROWID",
                "TIMESTAMPTZ",
                "INTEGER",
            ] {
                assert!(!words.contains(&banned), "non-portable SQL: {banned}");
            }
        }
    }
}
