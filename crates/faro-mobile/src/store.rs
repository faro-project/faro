//! The one database in the app group container (docs/IOS.md §13).
//!
//! Everything lives in `faro_core`'s outbox file, `outbox.sqlite3`, in the
//! directory the app passes in: the outbox's own tables (events, reports,
//! chain head, recipient checkpoint; `faro_core::outbox`) and two of this
//! crate's, which the outbox never touches:
//!
//! | Table | Contents |
//! |---|---|
//! | `mobile_state` | small JSON records by key: the enrollment (without its token, which is in the key store), the verified endorsement, the update trust state, the installed domain bundle, Leave Faro's progress, whether a clock skew was reported |
//! | `mobile_context` | context signals for the daily report (§10.2 "context"), oldest first |
//! | `mobile_report_log` | the facts the daily report is built from (`crate::reports`): blocked and shield summaries, protection samples, flags, loosenings. Kept a few days, then dropped |
//!
//! Every process (the app, the tunnel) opens its own connections, in WAL
//! mode with a busy timeout, so readers never block and writers queue for
//! the lock. Chain appends take it with `BEGIN EXCLUSIVE`
//! (`faro_core::Outbox::append_exclusive`); the records here change in
//! `IMMEDIATE` transactions. Nothing in this file is plaintext about what
//! the member did: event bodies are sealed before they reach the outbox,
//! and context signals are conditions of the phone (a VPN is active), not
//! activity.

use crate::error::FaroError;
use faro_core::outbox::OUTBOX_FILE;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long a connection waits for another process's write lock. A chain
/// append holds it for a few milliseconds, so this is only reached if a
/// process stalls while holding it.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// `mobile_state` keys.
pub(crate) const ENROLLMENT: &str = "enrollment";
pub(crate) const ENDORSEMENT: &str = "endorsement";
pub(crate) const UPDATE_TRUST: &str = "update_trust";
pub(crate) const DOMAINS: &str = "domains";
/// Leave Faro's progress (`crate::core::Leaving`): once set, nothing more
/// is recorded or sent but the goodbye.
pub(crate) const LEAVING: &str = "leaving";
/// Whether a clock skew against the instance was reported and not yet
/// seen back in range (one signal per skew, across processes).
pub(crate) const CLOCK_SKEW: &str = "clock_skew_reported";
/// Bucket starts already turned into `blocked_summary` events.
pub(crate) const BLOCKED_REPORTED: &str = "blocked_reported";
/// The shield counters' totals at the last flush.
pub(crate) const SHIELD_BASELINE: &str = "shield_baseline";
/// The end of the last period a report was queued for.
pub(crate) const REPORT_QUEUED_THROUGH: &str = "report_queued_through";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mobile_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_context (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    json  TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS mobile_report_log (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    json  TEXT NOT NULL
) STRICT;
";

/// Context records kept at most; the oldest go first.
const MAX_CONTEXT: i64 = 10_000;
/// Report-log rows kept at most; the oldest go first.
const MAX_REPORT_LOG: i64 = 20_000;

/// This crate's tables. See the module docs.
pub(crate) struct Store {
    conn: Connection,
}

/// Create `dir` if missing (0700 on Unix).
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), FaroError> {
    if !dir.exists() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(dir).map_err(FaroError::storage)?;
    }
    Ok(())
}

pub(crate) fn database_path(dir: &Path) -> PathBuf {
    dir.join(OUTBOX_FILE)
}

impl Store {
    pub(crate) fn open(dir: &Path) -> Result<Store, FaroError> {
        ensure_dir(dir)?;
        let path = database_path(dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&path)
                .map_err(FaroError::storage)?;
        }
        let mut conn = Connection::open(&path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(FaroError::storage(format!(
                "could not enable WAL (got {mode})"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        tx.commit()?;
        Ok(Store { conn })
    }

    pub(crate) fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, FaroError> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM mobile_state WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|s| {
            serde_json::from_str(&s)
                .map_err(|e| FaroError::storage(format!("stored {key} is corrupt: {e}")))
        })
        .transpose()
    }

    /// Store `value` under `key`, replacing what is there.
    pub(crate) fn put<T: Serialize>(&self, key: &str, value: &T) -> Result<(), FaroError> {
        let json = serde_json::to_string(value).map_err(FaroError::storage)?;
        self.conn.execute(
            "INSERT INTO mobile_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, json],
        )?;
        Ok(())
    }

    /// Store `value` under `key` unless something is there already, in one
    /// transaction. Returns whether it was stored.
    pub(crate) fn put_new<T: Serialize>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<bool, FaroError> {
        let json = serde_json::to_string(value).map_err(FaroError::storage)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n = tx.execute(
            "INSERT INTO mobile_state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO NOTHING",
            params![key, json],
        )?;
        tx.commit()?;
        Ok(n == 1)
    }

    /// Read `key`, let `f` change it, and store the result, in one
    /// immediate transaction, so two processes never both act on the same
    /// old value. `f` returns the new value (`None` leaves the record as
    /// it is) and whatever it wants handed back.
    pub(crate) fn update<T, R>(
        &mut self,
        key: &str,
        f: impl FnOnce(Option<T>) -> (Option<T>, R),
    ) -> Result<R, FaroError>
    where
        T: Serialize + DeserializeOwned,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM mobile_state WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        let old = raw
            .map(|s| {
                serde_json::from_str(&s)
                    .map_err(|e| FaroError::storage(format!("stored {key} is corrupt: {e}")))
            })
            .transpose()?;
        let (new, out) = f(old);
        if let Some(new) = new {
            let json = serde_json::to_string(&new).map_err(FaroError::storage)?;
            tx.execute(
                "INSERT INTO mobile_state (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, json],
            )?;
        }
        tx.commit()?;
        Ok(out)
    }

    /// Set the boolean record `key` to `value` in one transaction and
    /// return what it was (`false` if missing). Nothing is written when it
    /// already holds `value`. Two processes racing see exactly one `false`
    /// to `true` change between them.
    pub(crate) fn swap_flag(&mut self, key: &str, value: bool) -> Result<bool, FaroError> {
        self.update::<bool, bool>(key, |old| {
            let old = old.unwrap_or(false);
            ((old != value).then_some(value), old)
        })
    }

    /// Add one fact for the daily report.
    pub(crate) fn add_fact(&mut self, ts_ms: i64, json: &str) -> Result<(), FaroError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO mobile_report_log (ts_ms, json) VALUES (?1, ?2)",
            params![ts_ms, json],
        )?;
        tx.execute(
            "DELETE FROM mobile_report_log WHERE id <= (SELECT MAX(id) FROM mobile_report_log) - ?1",
            [MAX_REPORT_LOG],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Facts with `since_ms <= ts < until_ms`, oldest first.
    pub(crate) fn facts_between(
        &self,
        since_ms: i64,
        until_ms: i64,
    ) -> Result<Vec<(i64, String)>, FaroError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts_ms, json FROM mobile_report_log
             WHERE ts_ms >= ?1 AND ts_ms < ?2 ORDER BY ts_ms ASC, id ASC",
        )?;
        let rows = stmt.query_map([since_ms, until_ms], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drop facts older than `before_ms`.
    pub(crate) fn prune_facts(&self, before_ms: i64) -> Result<(), FaroError> {
        self.conn.execute(
            "DELETE FROM mobile_report_log WHERE ts_ms < ?1",
            [before_ms],
        )?;
        Ok(())
    }

    pub(crate) fn add_context(&mut self, ts_ms: i64, json: &str) -> Result<(), FaroError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO mobile_context (ts_ms, json) VALUES (?1, ?2)",
            params![ts_ms, json],
        )?;
        tx.execute(
            "DELETE FROM mobile_context WHERE id <= (SELECT MAX(id) FROM mobile_context) - ?1",
            [MAX_CONTEXT],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Context records at or after `since_ms`, oldest first.
    pub(crate) fn context_since(&self, since_ms: i64) -> Result<Vec<(i64, String)>, FaroError> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT ts_ms, json FROM mobile_context WHERE ts_ms >= ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([since_ms], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_context() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(&d.path().join("group")).unwrap();
        assert_eq!(s.get::<u32>("x").unwrap(), None);
        assert!(s.put_new("x", &1u32).unwrap());
        assert!(!s.put_new("x", &2u32).unwrap(), "never replaced");
        assert_eq!(s.get::<u32>("x").unwrap(), Some(1));
        s.put("x", &3u32).unwrap();
        assert_eq!(s.get::<u32>("x").unwrap(), Some(3));
        assert!(!s.swap_flag("f", true).unwrap());
        assert!(s.swap_flag("f", true).unwrap(), "already set");
        assert!(s.swap_flag("f", false).unwrap());
        assert!(!s.swap_flag("f", false).unwrap());
        s.add_context(5, "{}").unwrap();
        s.add_context(9, "[]").unwrap();
        assert_eq!(s.context_since(6).unwrap(), vec![(9, "[]".to_owned())]);
        // A second connection (another process) sees the same records.
        let again = Store::open(&d.path().join("group")).unwrap();
        assert_eq!(again.get::<u32>("x").unwrap(), Some(3));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(database_path(&d.path().join("group")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
