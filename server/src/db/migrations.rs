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
                    11,
                    "alliance_proposals",
                    include_str!("../../migrations/0011_alliance_proposals.sql"),
                ),
                (
                    12,
                    "group_listing_meetings",
                    include_str!("../../migrations/0012_group_listing_meetings.sql"),
                ),
                (
                    13,
                    "group_roster",
                    include_str!("../../migrations/0013_group_roster.sql"),
                ),
                (
                    14,
                    "group_messages",
                    include_str!("../../migrations/0014_group_messages.sql"),
                ),
                (
                    15,
                    "group_sharing",
                    include_str!("../../migrations/0015_group_sharing.sql"),
                ),
                (
                    16,
                    "group_posts",
                    include_str!("../../migrations/0016_group_posts.sql"),
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

    /// Migration 16 rebuilds `reach_outs` to widen its `audience` CHECK.
    /// SQLite enforces foreign keys, so dropping the parent must not cascade
    /// over `reach_out_recipients`: rows, answers, links and indexes survive.
    #[tokio::test]
    async fn rebuilding_reach_outs_keeps_its_data() {
        use sqlx::{Connection, Row};
        let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut conn)
            .await
            .unwrap();
        let all = sources(Backend::Sqlite);
        let (last, before) = all.split_last().unwrap();
        assert_eq!(last.0, 16);
        for (_, _, sql) in before {
            sqlx::raw_sql(*sql).execute(&mut conn).await.unwrap();
        }
        for sql in [
            "INSERT INTO users (id, email, display_name, created_at)
             VALUES ('usr_a', 'a@x', 'A', 1), ('usr_b', 'b@x', 'B', 1)",
            "INSERT INTO accountability_groups (id, name, created_at) VALUES ('g1', 'G', 1)",
            "INSERT INTO group_messages (id, kind, author_id, group_id, message_json, created_at)
             VALUES ('m1', 'reach_out', 'usr_a', 'g1', '{}', 1)",
            "INSERT INTO reach_outs (id, sender_id, group_id, audience, created_at, sig, blob_ref)
             VALUES ('r1', 'usr_a', 'g1', 'people', 10, 'sig', 'm1'),
                    ('r2', 'usr_a', NULL, 'allies', 20, NULL, NULL)",
            "INSERT INTO reach_out_recipients (reach_out_id, recipient_id, answered_at, answer)
             VALUES ('r1', 'usr_b', 15, 'call'), ('r2', 'usr_b', NULL, NULL)",
        ] {
            sqlx::query(sql).execute(&mut conn).await.unwrap();
        }

        sqlx::raw_sql(last.2).execute(&mut conn).await.unwrap();

        let rows =
            sqlx::query("SELECT id, audience, group_id, blob_ref, sig FROM reach_outs ORDER BY id")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get::<String, _>("audience"), "people");
        assert_eq!(
            rows[0].get::<Option<String>, _>("blob_ref").as_deref(),
            Some("m1")
        );
        assert_eq!(
            rows[0].get::<Option<String>, _>("group_id").as_deref(),
            Some("g1")
        );
        let rec = sqlx::query(
            "SELECT reach_out_id, answered_at, answer FROM reach_out_recipients
             ORDER BY reach_out_id",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(rec.len(), 2);
        assert_eq!(rec[0].get::<Option<i64>, _>("answered_at"), Some(15));
        assert_eq!(
            rec[0].get::<Option<String>, _>("answer").as_deref(),
            Some("call")
        );
        assert_eq!(rec[1].get::<Option<String>, _>("answer"), None);

        // The new audience is allowed, a bad one isn't, the links still
        // cascade, and the helper tables and indexes are as they were.
        sqlx::query(
            "INSERT INTO reach_outs (id, sender_id, group_id, audience, created_at)
             VALUES ('r3', 'usr_a', 'g1', 'group', 30)",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        assert!(sqlx::query(
            "INSERT INTO reach_outs (id, sender_id, audience, created_at)
             VALUES ('r4', 'usr_a', 'everyone', 30)"
        )
        .execute(&mut conn)
        .await
        .is_err());
        sqlx::query("DELETE FROM reach_outs WHERE id = 'r1'")
            .execute(&mut conn)
            .await
            .unwrap();
        let left: i64 = sqlx::query("SELECT COUNT(*) AS n FROM reach_out_recipients")
            .fetch_one(&mut conn)
            .await
            .unwrap()
            .get("n");
        assert_eq!(left, 1, "deleting a reach out deletes its recipients");
        let names: Vec<String> = sqlx::query(
            "SELECT name FROM sqlite_master WHERE tbl_name IN ('reach_outs', 'reach_out_recipients')
               AND type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get("name"))
        .collect();
        assert_eq!(
            names,
            [
                "reach_out_recipients_recipient",
                "reach_outs_created",
                "reach_outs_sender"
            ]
        );
        let leftovers: i64 = sqlx::query(
            "SELECT COUNT(*) AS n FROM sqlite_master
             WHERE name IN ('reach_outs_new', 'reach_out_recipients_save')",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap()
        .get("n");
        assert_eq!(leftovers, 0);
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
