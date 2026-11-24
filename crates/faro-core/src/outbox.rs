//! The encrypted outbox (ARCHITECTURE.md §3.6 "Outbox").
//!
//! A SQLite file in the service's protected directory that holds events and
//! reports until the instance acknowledges them, plus the durable chain head.
//!
//! **Only ciphertext goes in.** The write API accepts nothing but a
//! [`PreparedEvent`] (a signed event with an encrypted body, only obtainable
//! from `EventWriter::prepare`) and a [`ReportUpload`] (already sealed). There
//! is no way to store a plaintext body or an image through this type (§3.5).
//!
//! **Crash safety.** The event row and the new chain head are written in one
//! `IMMEDIATE` transaction with `synchronous=FULL` in WAL mode, so after a
//! crash either both are on disk or neither is. Because the writer only
//! adopts the new head after `commit` returns, a `seq` is never signed for two
//! different events.
//!
//! **Retention.** While offline the outbox keeps about 30 days of events and
//! prunes clean data first (see [`Outbox::prune`]). Every pruned range is
//! recorded so the next report can explain the resulting chain gap.
//!
//! **Age clock.** Ages are measured on a stored timestamp that never goes
//! backwards (the header's wall-clock `ts_ms`, raised to the highest value
//! stored so far). The wall clock belongs to the member: without the
//! high-water mark, setting it back 40 days before a flagged capture would
//! make that fresh event look 40 days old and prunable the moment the clock
//! is restored.

use crate::writer::PreparedEvent;
use faro_crypto::ChainHead;
use faro_proto::report::ReportUpload;
use faro_proto::{DeviceId, Hash32, InstanceId, SignedEvent, Urgency};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};

/// File name of the outbox database inside the caller's directory.
pub const OUTBOX_FILE: &str = "outbox.sqlite3";
/// Schema version written to `meta`.
pub const SCHEMA_VERSION: u32 = 1;
/// Default maximum age of unsent data: 30 days.
pub const DEFAULT_MAX_AGE_MS: i64 = 30 * 24 * 3600 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("outbox schema version {found} is newer than supported {SCHEMA_VERSION}")]
    UnsupportedSchema { found: u32 },
    #[error("outbox belongs to {stored_instance}/{stored_device}, not {instance}/{device}")]
    WrongIdentity {
        stored_instance: String,
        stored_device: String,
        instance: InstanceId,
        device: DeviceId,
    },
    #[error("event is for a different instance or device")]
    ForeignEvent,
    #[error("event shape invalid: {0}")]
    Shape(#[from] faro_proto::event::EventShapeError),
    #[error("event seq {got} is not the next seq {expected}")]
    NotNextSeq { expected: u64, got: u64 },
    #[error("event at seq {seq} does not chain from the stored head")]
    PrevHashMismatch { seq: u64 },
    #[error("prepared head is not the successor of the stored head")]
    NotSuccessor,
    #[error("ack through {acked} is beyond the chain head (next seq {next_seq})")]
    AckBeyondHead { acked: u64, next_seq: u64 },
    #[error("stored data is corrupt: {0}")]
    Corrupt(String),
    #[error("value out of range for storage: {0}")]
    Range(&'static str),
}

/// A contiguous range of events dropped without being uploaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedRange {
    pub from_seq: u64,
    pub to_seq: u64,
    pub reason: PruneReason,
    pub at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneReason {
    /// Older than the maximum age.
    Age,
    /// Dropped to stay under the size cap.
    Size,
}

impl PruneReason {
    fn as_str(self) -> &'static str {
        match self {
            PruneReason::Age => "age",
            PruneReason::Size => "size",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "age" => Some(PruneReason::Age),
            "size" => Some(PruneReason::Size),
            _ => None,
        }
    }
}

/// Limits for [`Outbox::prune`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePolicy {
    /// Events older than this (by header `ts_ms`) are dropped unless urgent.
    pub max_age_ms: i64,
    /// Total stored event bytes are kept at or below this.
    pub max_bytes: u64,
}

impl Default for PrunePolicy {
    fn default() -> Self {
        PrunePolicy {
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// What [`Outbox::prune`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    pub ranges: Vec<PrunedRange>,
    pub events_deleted: u64,
    pub reports_deleted: u64,
    pub bytes_after: u64,
}

/// Counts for status displays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboxStats {
    pub events: u64,
    pub event_bytes: u64,
    pub reports: u64,
    pub oldest_seq: Option<u64>,
}

/// A stored report awaiting upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReport {
    pub id: i64,
    pub upload: ReportUpload,
}

/// The outbox. See module docs.
#[derive(Debug)]
pub struct Outbox {
    conn: Connection,
    path: PathBuf,
    instance_id: InstanceId,
    device_id: DeviceId,
}

fn to_i64(v: u64, what: &'static str) -> Result<i64, OutboxError> {
    i64::try_from(v).map_err(|_| OutboxError::Range(what))
}

fn to_u64(v: i64, what: &'static str) -> Result<u64, OutboxError> {
    u64::try_from(v).map_err(|_| OutboxError::Corrupt(format!("negative {what}")))
}

fn urgency_rank(u: Urgency) -> u8 {
    match u {
        Urgency::None => 0,
        Urgency::Normal => 1,
        Urgency::Urgent => 2,
    }
}

#[cfg(unix)]
fn restrict_perms(path: &Path) -> Result<(), OutboxError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Create with 0600 so there is no window where the file is world-readable.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    for suffix in ["-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let p = PathBuf::from(p);
        if p.exists() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) -> Result<(), OutboxError> {
    // On Windows the service's state directory carries a SYSTEM-only ACL
    // (ARCHITECTURE §3.3); files inherit it.
    Ok(())
}

/// `meta` key holding the age-clock high-water mark (see module docs).
const META_AGE_HW: &str = "age_hw_ms";

/// Read the age-clock high-water mark, raise it to `ts_ms`, store it and
/// return the value to record as the row's age timestamp. Must run inside
/// the caller's write transaction so the mark and the row commit together.
fn bump_age_clock(tx: &rusqlite::Transaction<'_>, ts_ms: i64) -> Result<i64, OutboxError> {
    let hw: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            [META_AGE_HW],
            |r| r.get(0),
        )
        .optional()?;
    let hw = match hw {
        Some(v) => Some(
            v.parse::<i64>()
                .map_err(|_| OutboxError::Corrupt(format!("{META_AGE_HW} {v:?}")))?,
        ),
        None => None,
    };
    let age = hw.map_or(ts_ms, |hw| hw.max(ts_ms));
    tx.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![META_AGE_HW, age.to_string()],
    )?;
    Ok(age)
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS chain_state (
    id        INTEGER PRIMARY KEY CHECK (id = 0),
    next_seq  INTEGER NOT NULL CHECK (next_seq >= 0),
    prev_hash TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS events (
    seq     INTEGER PRIMARY KEY CHECK (seq >= 0),
    kind    TEXT NOT NULL,
    urgency TEXT NOT NULL CHECK (urgency IN ('none', 'normal', 'urgent')),
    -- age clock: header ts_ms raised to the high-water mark (module docs)
    ts_ms   INTEGER NOT NULL,
    size    INTEGER NOT NULL CHECK (size >= 0),
    json    TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start INTEGER NOT NULL,
    period_end   INTEGER NOT NULL,
    -- age clock: period_end raised to the high-water mark (module docs)
    age_ms       INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    json         TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS pruned (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    from_seq INTEGER NOT NULL,
    to_seq   INTEGER NOT NULL,
    reason   TEXT NOT NULL,
    at       INTEGER NOT NULL
) STRICT;
";

impl Outbox {
    /// Open (or create) the outbox in `dir` for this device.
    ///
    /// `dir` should be the service's protected state directory; it is created
    /// (mode 0700 on Unix) if missing. The database file is forced to 0600.
    /// Opening an outbox that belongs to another instance/device fails, so a
    /// re-enrolled device never mixes chains.
    pub fn open(
        dir: &Path,
        instance_id: &InstanceId,
        device_id: &DeviceId,
    ) -> Result<Outbox, OutboxError> {
        if !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(dir)?;
        }
        let path = dir.join(OUTBOX_FILE);
        restrict_perms(&path)?;
        let mut conn = Connection::open(&path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(OutboxError::Corrupt(format!(
                "could not enable WAL (got {mode})"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL")?;
        // Overwrite deleted content rather than leaving it in free pages.
        conn.pragma_update(None, "secure_delete", "ON")?;
        restrict_perms(&path)?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(SCHEMA)?;
        let version: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        match version {
            None => {
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1), ('instance_id', ?2), ('device_id', ?3)",
                    params![SCHEMA_VERSION.to_string(), instance_id.as_str(), device_id.as_str()],
                )?;
                let g = ChainHead::genesis(instance_id, device_id);
                tx.execute(
                    "INSERT INTO chain_state (id, next_seq, prev_hash) VALUES (0, 0, ?1)",
                    params![g.prev_hash.to_prefixed_hex()],
                )?;
            }
            Some(v) => {
                let found: u32 = v
                    .parse()
                    .map_err(|_| OutboxError::Corrupt(format!("schema_version {v:?}")))?;
                if found > SCHEMA_VERSION {
                    return Err(OutboxError::UnsupportedSchema { found });
                }
                let get = |k: &str| -> Result<String, OutboxError> {
                    tx.query_row("SELECT value FROM meta WHERE key = ?1", [k], |r| r.get(0))
                        .optional()?
                        .ok_or_else(|| OutboxError::Corrupt(format!("missing meta {k}")))
                };
                let si = get("instance_id")?;
                let sd = get("device_id")?;
                if si != instance_id.as_str() || sd != device_id.as_str() {
                    return Err(OutboxError::WrongIdentity {
                        stored_instance: si,
                        stored_device: sd,
                        instance: instance_id.clone(),
                        device: device_id.clone(),
                    });
                }
            }
        }
        tx.commit()?;

        let ob = Outbox {
            conn,
            path,
            instance_id: instance_id.clone(),
            device_id: device_id.clone(),
        };
        // Sanity: stored events must all be behind the head.
        let head = ob.head()?;
        let max_seq: Option<i64> = ob
            .conn
            .query_row("SELECT MAX(seq) FROM events", [], |r| r.get(0))?;
        if let Some(m) = max_seq {
            if to_u64(m, "seq")? >= head.next_seq {
                return Err(OutboxError::Corrupt(format!(
                    "event seq {m} at or beyond head {}",
                    head.next_seq
                )));
            }
        }
        Ok(ob)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The durable chain head.
    pub fn head(&self) -> Result<ChainHead, OutboxError> {
        let (next, prev): (i64, String) = self.conn.query_row(
            "SELECT next_seq, prev_hash FROM chain_state WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(ChainHead {
            next_seq: to_u64(next, "next_seq")?,
            prev_hash: Hash32::from_prefixed_hex(&prev)
                .ok_or_else(|| OutboxError::Corrupt("prev_hash".into()))?,
        })
    }

    /// Durably store `prepared` and advance the stored head, atomically.
    ///
    /// Rejected unless the event is for this outbox's instance/device, its
    /// body commitments hold, it carries exactly the stored head's `seq` and
    /// `prev_hash`, and its `new_head` is the true successor.
    pub fn commit(&mut self, prepared: &PreparedEvent) -> Result<ChainHead, OutboxError> {
        let ev = prepared.event();
        let h = &ev.header;
        if h.instance_id != self.instance_id || h.device_id != self.device_id {
            return Err(OutboxError::ForeignEvent);
        }
        ev.check_shape(true)?;
        let json = serde_json::to_string(ev)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (next, prev): (i64, String) = tx.query_row(
            "SELECT next_seq, prev_hash FROM chain_state WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let stored = ChainHead {
            next_seq: to_u64(next, "next_seq")?,
            prev_hash: Hash32::from_prefixed_hex(&prev)
                .ok_or_else(|| OutboxError::Corrupt("prev_hash".into()))?,
        };
        if h.seq != stored.next_seq {
            return Err(OutboxError::NotNextSeq {
                expected: stored.next_seq,
                got: h.seq,
            });
        }
        if h.prev_hash != stored.prev_hash {
            return Err(OutboxError::PrevHashMismatch { seq: h.seq });
        }
        let mut successor = stored;
        successor.advance(h);
        if prepared.new_head() != successor || prepared.prev_head() != stored {
            return Err(OutboxError::NotSuccessor);
        }
        let age_ms = bump_age_clock(&tx, h.ts_ms)?;
        tx.execute(
            "INSERT INTO events (seq, kind, urgency, ts_ms, size, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                to_i64(h.seq, "seq")?,
                h.kind.as_str(),
                h.urgency.as_str(),
                age_ms,
                to_i64(json.len() as u64, "size")?,
                json
            ],
        )?;
        tx.execute(
            "UPDATE chain_state SET next_seq = ?1, prev_hash = ?2 WHERE id = 0",
            params![
                to_i64(successor.next_seq, "next_seq")?,
                successor.prev_hash.to_prefixed_hex()
            ],
        )?;
        tx.commit()?;
        Ok(successor)
    }

    /// Up to `limit` unacknowledged events, oldest first.
    pub fn pending(&self, limit: usize) -> Result<Vec<SignedEvent>, OutboxError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self
            .conn
            .prepare_cached("SELECT seq, json FROM events ORDER BY seq ASC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, json) = row?;
            let ev: SignedEvent = serde_json::from_str(&json)
                .map_err(|e| OutboxError::Corrupt(format!("event {seq}: {e}")))?;
            if to_i64(ev.header.seq, "seq")? != seq {
                return Err(OutboxError::Corrupt(format!(
                    "row {seq} holds seq {}",
                    ev.header.seq
                )));
            }
            out.push(ev);
        }
        Ok(out)
    }

    /// Drop events the instance holds (`seq <= acked`). Returns rows deleted.
    ///
    /// An ack beyond the head is refused: it means the instance and device
    /// disagree about the chain (e.g. the outbox was reset), which deserves
    /// attention rather than silent deletion.
    pub fn ack_through(&mut self, acked: u64) -> Result<u64, OutboxError> {
        let head = self.head()?;
        if acked >= head.next_seq {
            return Err(OutboxError::AckBeyondHead {
                acked,
                next_seq: head.next_seq,
            });
        }
        let n = self.conn.execute(
            "DELETE FROM events WHERE seq <= ?1",
            [to_i64(acked, "seq")?],
        )?;
        Ok(n as u64)
    }

    /// Queue a sealed report for upload. Returns its local id.
    pub fn add_report(&mut self, upload: &ReportUpload) -> Result<i64, OutboxError> {
        let json = serde_json::to_string(upload)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let age_ms = bump_age_clock(&tx, upload.header.period_end_ms)?;
        tx.execute(
            "INSERT INTO reports (period_start, period_end, age_ms, size, json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                upload.header.period_start_ms,
                upload.header.period_end_ms,
                age_ms,
                to_i64(json.len() as u64, "size")?,
                json
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Reports awaiting upload, oldest first.
    pub fn pending_reports(&self) -> Result<Vec<PendingReport>, OutboxError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT id, json FROM reports ORDER BY id ASC")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            let upload = serde_json::from_str(&json)
                .map_err(|e| OutboxError::Corrupt(format!("report {id}: {e}")))?;
            out.push(PendingReport { id, upload });
        }
        Ok(out)
    }

    /// Remove an uploaded report. Returns whether it existed.
    pub fn ack_report(&mut self, id: i64) -> Result<bool, OutboxError> {
        Ok(self
            .conn
            .execute("DELETE FROM reports WHERE id = ?1", [id])?
            > 0)
    }

    pub fn stats(&self) -> Result<OutboxStats, OutboxError> {
        let (events, bytes, oldest): (i64, i64, Option<i64>) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(size), 0), MIN(seq) FROM events",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let reports: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM reports", [], |r| r.get(0))?;
        Ok(OutboxStats {
            events: to_u64(events, "count")?,
            event_bytes: to_u64(bytes, "size")?,
            reports: to_u64(reports, "count")?,
            oldest_seq: oldest.map(|s| to_u64(s, "seq")).transpose()?,
        })
    }

    /// Every pruned range recorded so far, oldest first.
    pub fn pruned_ranges(&self) -> Result<Vec<PrunedRange>, OutboxError> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT from_seq, to_seq, reason, at FROM pruned ORDER BY id ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (f, t, reason, at) = row?;
            out.push(PrunedRange {
                from_seq: to_u64(f, "from_seq")?,
                to_seq: to_u64(t, "to_seq")?,
                reason: PruneReason::parse(&reason)
                    .ok_or_else(|| OutboxError::Corrupt(format!("prune reason {reason:?}")))?,
                at_ms: at,
            });
        }
        Ok(out)
    }

    /// Enforce retention while offline.
    ///
    /// 1. **Age:** `none` events (clean captures, heartbeats, low flags)
    ///    whose age clock is before `now_ms - max_age_ms` are dropped, and so
    ///    are reports whose period ended before that cutoff. `normal` and
    ///    `urgent` events (medium/high flags, settings changes, pauses,
    ///    tamper) are **never** dropped for age, only for size: `now_ms` is
    ///    the member-controlled wall clock, so a clock set 31 days ahead must
    ///    not be enough to erase the flags allies are waiting for. They are
    ///    few and small, and the size cap still bounds them.
    /// 2. **Size:** while stored event bytes exceed `max_bytes`, drop the
    ///    oldest `none` events, then the oldest `normal`, and only then the
    ///    oldest `urgent`.
    ///
    /// "Oldest" in step 2 is by `seq`, not by the wall clock.
    /// Deleted seqs are recorded as contiguous ranges in `pruned`; the chain
    /// gap this leaves is visible to the instance by design.
    pub fn prune(&mut self, now_ms: i64, policy: PrunePolicy) -> Result<PruneOutcome, OutboxError> {
        let cutoff = now_ms.saturating_sub(policy.max_age_ms.max(0));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: Vec<(u64, Urgency, i64, u64)> = {
            let mut stmt =
                tx.prepare("SELECT seq, urgency, ts_ms, size FROM events ORDER BY seq ASC")?;
            let it = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?;
            let mut v = Vec::new();
            for row in it {
                let (seq, u, ts, size) = row?;
                let u = Urgency::parse(&u)
                    .ok_or_else(|| OutboxError::Corrupt(format!("urgency {u:?}")))?;
                v.push((to_u64(seq, "seq")?, u, ts, to_u64(size, "size")?));
            }
            v
        };

        let mut age_drop = Vec::new();
        let mut kept: Vec<(u64, Urgency, u64)> = Vec::new();
        for (seq, u, ts, size) in rows {
            if ts < cutoff && u == Urgency::None {
                age_drop.push(seq);
            } else {
                kept.push((seq, u, size));
            }
        }
        let mut total: u64 = kept.iter().map(|k| k.2).sum();
        let mut size_drop = Vec::new();
        if total > policy.max_bytes {
            let mut order: Vec<&(u64, Urgency, u64)> = kept.iter().collect();
            // Stable sort: by urgency class, seq order within a class.
            order.sort_by_key(|(seq, u, _)| (urgency_rank(*u), *seq));
            for (seq, _, size) in order {
                if total <= policy.max_bytes {
                    break;
                }
                size_drop.push(*seq);
                total -= size;
            }
            size_drop.sort_unstable();
        }

        let mut ranges = Vec::new();
        for (seqs, reason) in [
            (&age_drop, PruneReason::Age),
            (&size_drop, PruneReason::Size),
        ] {
            {
                let mut del = tx.prepare_cached("DELETE FROM events WHERE seq = ?1")?;
                for s in seqs.iter() {
                    del.execute([to_i64(*s, "seq")?])?;
                }
            }
            for (from, to) in contiguous_ranges(seqs) {
                tx.execute(
                    "INSERT INTO pruned (from_seq, to_seq, reason, at) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        to_i64(from, "seq")?,
                        to_i64(to, "seq")?,
                        reason.as_str(),
                        now_ms
                    ],
                )?;
                ranges.push(PrunedRange {
                    from_seq: from,
                    to_seq: to,
                    reason,
                    at_ms: now_ms,
                });
            }
        }
        let reports_deleted = tx.execute("DELETE FROM reports WHERE age_ms < ?1", [cutoff])? as u64;
        tx.commit()?;
        if !ranges.is_empty() {
            tracing::warn!(?ranges, "pruned unsent events from outbox");
        }
        Ok(PruneOutcome {
            events_deleted: (age_drop.len() + size_drop.len()) as u64,
            ranges,
            reports_deleted,
            bytes_after: total,
        })
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        &self.conn
    }
}

/// Collapse sorted seqs into inclusive runs of consecutive integers.
fn contiguous_ranges(sorted: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &s in sorted {
        match out.last_mut() {
            Some((_, to)) if to.checked_add(1) == Some(s) => *to = s,
            _ => out.push((s, s)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, ManualClock};
    use crate::recipients::tests::Fixture;
    use crate::writer::EventWriter;
    use faro_crypto::{verify_chain, SigningKey};
    use faro_proto::body::{EventBody, FlagBody, Rating, TamperSignal};

    struct Env {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        f: Fixture,
        clock: ManualClock,
        w: EventWriter<ManualClock>,
        ob: Outbox,
    }

    fn env() -> Env {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("state");
        let f = Fixture::new(1);
        let dev = DeviceId::new("dev_test");
        let ob = Outbox::open(&dir, &f.inst, &dev).unwrap();
        let clock = ManualClock::new(1_800_000_000_000, 0);
        let w = EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev,
            ob.head().unwrap(),
            clock.clone(),
        );
        Env {
            _dir: td,
            dir,
            f,
            clock,
            w,
            ob,
        }
    }

    fn flag(r: Rating) -> EventBody {
        EventBody::Flag(FlagBody {
            rating: r,
            reasons: vec![],
            app: None,
            window_title: None,
            browser: None,
            thumbnail: None,
            burst: false,
        })
    }

    impl Env {
        fn write(&mut self, body: EventBody, u: Urgency) -> SignedEvent {
            let set = self.f.set();
            self.w.write(&mut self.ob, &body, u, &set).unwrap()
        }
        fn reopen(&mut self) {
            self.ob = Outbox::open(&self.dir, &self.f.inst, self.w.device_id()).unwrap();
        }
    }

    #[test]
    fn commit_pending_ack_roundtrip() {
        let mut e = env();
        assert_eq!(
            e.ob.head().unwrap(),
            ChainHead::genesis(&e.f.inst, e.w.device_id())
        );
        for _ in 0..5 {
            e.write(EventBody::Shutdown, Urgency::None);
        }
        let pend = e.ob.pending(100).unwrap();
        assert_eq!(
            pend.iter().map(|p| p.header.seq).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        let (head, gaps) = verify_chain(
            &e.f.inst,
            e.w.device_id(),
            &e.w.signing_key().public(),
            &pend,
            true,
        )
        .unwrap();
        assert!(gaps.is_empty());
        assert_eq!(head, e.ob.head().unwrap());
        assert_eq!(e.ob.pending(2).unwrap().len(), 2);
        assert_eq!(e.ob.ack_through(2).unwrap(), 3);
        assert_eq!(e.ob.pending(100).unwrap()[0].header.seq, 3);
        assert!(matches!(
            e.ob.ack_through(5),
            Err(OutboxError::AckBeyondHead {
                acked: 5,
                next_seq: 5
            })
        ));
        assert_eq!(e.ob.stats().unwrap().events, 2);
    }

    #[test]
    fn reopen_preserves_head_and_events() {
        let mut e = env();
        for _ in 0..3 {
            e.write(EventBody::Resumed, Urgency::None);
        }
        let head = e.ob.head().unwrap();
        e.reopen();
        assert_eq!(e.ob.head().unwrap(), head);
        assert_eq!(e.ob.pending(10).unwrap().len(), 3);
        // A fresh writer resuming from the stored head continues the chain.
        e.write(EventBody::Resumed, Urgency::None);
        let all = e.ob.pending(10).unwrap();
        verify_chain(
            &e.f.inst,
            e.w.device_id(),
            &e.w.signing_key().public(),
            &all,
            true,
        )
        .unwrap();
    }

    #[test]
    fn rejects_non_successor() {
        let mut e = env();
        let set = e.f.set();
        let p =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        // Lying about the resulting head.
        let bad = p.clone().with_new_head(ChainHead {
            next_seq: 7,
            prev_hash: Hash32::ZERO,
        });
        assert!(matches!(e.ob.commit(&bad), Err(OutboxError::NotSuccessor)));
        e.ob.commit(&p).unwrap();
        // Committing the same prepared event twice (replay) is rejected.
        assert!(matches!(
            e.ob.commit(&p),
            Err(OutboxError::NotNextSeq {
                expected: 1,
                got: 0
            })
        ));
        // An event prepared on a stale head (writer never adopted) is rejected.
        let stale =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        assert!(matches!(
            e.ob.commit(&stale),
            Err(OutboxError::NotNextSeq { .. })
        ));
        assert_eq!(e.ob.head().unwrap(), p.new_head());
    }

    #[test]
    fn rejects_fork_at_same_seq() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None);
        // Writer pointed at a forged head with the right seq but wrong hash.
        let set = e.f.set();
        e.w.set_head(ChainHead {
            next_seq: 1,
            prev_hash: Hash32::of(b"forged"),
        });
        let p =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        assert!(matches!(
            e.ob.commit(&p),
            Err(OutboxError::PrevHashMismatch { seq: 1 })
        ));
    }

    #[test]
    fn commit_is_atomic() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None);
        let head = e.ob.head().unwrap();
        // Plant a row at the next seq so the INSERT fails after validation;
        // the head update in the same transaction must roll back with it.
        e.ob.raw()
            .execute(
                "INSERT INTO events (seq, kind, urgency, ts_ms, size, json) VALUES (1, 'x', 'none', 0, 0, '{}')",
                [],
            )
            .unwrap();
        let set = e.f.set();
        let p =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        assert!(matches!(e.ob.commit(&p), Err(OutboxError::Sql(_))));
        assert_eq!(e.ob.head().unwrap(), head);
        assert_eq!(e.w.head(), head, "writer did not adopt");
        // The planted row now makes the store inconsistent; reopening detects it.
        assert!(matches!(
            Outbox::open(&e.dir, &e.f.inst, e.w.device_id()),
            Err(OutboxError::Corrupt(_))
        ));
    }

    #[test]
    fn rejects_foreign_identity() {
        let e = env();
        assert!(matches!(
            Outbox::open(&e.dir, &InstanceId::new("inst_other"), e.w.device_id()),
            Err(OutboxError::WrongIdentity { .. })
        ));
        assert!(matches!(
            Outbox::open(&e.dir, &e.f.inst, &DeviceId::new("dev_other")),
            Err(OutboxError::WrongIdentity { .. })
        ));
    }

    #[test]
    fn rejects_event_for_other_device() {
        let mut e = env();
        let td = tempfile::tempdir().unwrap();
        let mut other = Outbox::open(td.path(), &e.f.inst, &DeviceId::new("dev_other")).unwrap();
        let set = e.f.set();
        let p =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        assert!(matches!(other.commit(&p), Err(OutboxError::ForeignEvent)));
        e.ob.commit(&p).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None);
        let mode = std::fs::metadata(e.ob.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let wal = PathBuf::from(format!("{}-wal", e.ob.path().display()));
        if wal.exists() {
            let mode = std::fs::metadata(&wal).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "wal mode {mode:o}");
        }
        let dmode = std::fs::metadata(&e.dir).unwrap().permissions().mode();
        assert_eq!(dmode & 0o777, 0o700);
    }

    #[test]
    fn stores_no_plaintext() {
        let mut e = env();
        let marker = "very-private-window-title-marker";
        e.write(
            EventBody::Flag(FlagBody {
                rating: Rating::High,
                reasons: vec![],
                app: None,
                window_title: Some(marker.into()),
                browser: None,
                thumbnail: None,
                burst: false,
            }),
            Urgency::Urgent,
        );
        drop(e.ob);
        // Checkpoint happened or not, scan both the db and the WAL.
        for suffix in ["", "-wal"] {
            let p = PathBuf::from(format!("{}{}", e.dir.join(OUTBOX_FILE).display(), suffix));
            if let Ok(bytes) = std::fs::read(&p) {
                assert!(
                    !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                    "plaintext found in {p:?}"
                );
            }
        }
    }

    #[test]
    fn prune_order_none_then_normal_then_urgent() {
        let mut e = env();
        // seq: 0 none, 1 urgent, 2 normal, 3 none, 4 normal, 5 urgent
        let plan = [
            (flag(Rating::Clean), Urgency::None),
            (
                EventBody::Tamper {
                    signal: TamperSignal::WaylandTokenLost,
                },
                Urgency::Urgent,
            ),
            (EventBody::Resumed, Urgency::Normal),
            (EventBody::Shutdown, Urgency::None),
            (EventBody::Resumed, Urgency::Normal),
            (flag(Rating::High), Urgency::Urgent),
        ];
        for (b, u) in plan {
            e.write(b, u);
        }
        let sizes: Vec<u64> =
            e.ob.pending(10)
                .unwrap()
                .iter()
                .map(|ev| serde_json::to_string(ev).unwrap().len() as u64)
                .collect();
        let total: u64 = sizes.iter().sum();
        let now = e.clock.wall_ms();

        // Cap that forces removal of both `none` events and exactly one `normal`.
        let cap = total - sizes[0] - sizes[3] - 1;
        let out =
            e.ob.prune(
                now,
                PrunePolicy {
                    max_age_ms: DEFAULT_MAX_AGE_MS,
                    max_bytes: cap,
                },
            )
            .unwrap();
        let left: Vec<u64> =
            e.ob.pending(10)
                .unwrap()
                .iter()
                .map(|x| x.header.seq)
                .collect();
        assert_eq!(left, vec![1, 4, 5]);
        assert_eq!(out.events_deleted, 3);
        assert!(out.bytes_after <= cap);
        assert_eq!(
            out.ranges
                .iter()
                .map(|r| (r.from_seq, r.to_seq))
                .collect::<Vec<_>>(),
            vec![(0, 0), (2, 3)]
        );
        assert!(out.ranges.iter().all(|r| r.reason == PruneReason::Size));

        // Urgent goes only when nothing else is left.
        let out =
            e.ob.prune(
                now,
                PrunePolicy {
                    max_age_ms: DEFAULT_MAX_AGE_MS,
                    max_bytes: sizes[5],
                },
            )
            .unwrap();
        let left: Vec<u64> =
            e.ob.pending(10)
                .unwrap()
                .iter()
                .map(|x| x.header.seq)
                .collect();
        assert_eq!(left, vec![5]);
        assert_eq!(
            out.ranges
                .iter()
                .map(|r| (r.from_seq, r.to_seq))
                .collect::<Vec<_>>(),
            vec![(1, 1), (4, 4)]
        );
        assert_eq!(e.ob.pruned_ranges().unwrap().len(), 4);

        // Under the cap: no-op.
        let out = e.ob.prune(now, PrunePolicy::default()).unwrap();
        assert_eq!(out.events_deleted, 0);
        assert!(out.ranges.is_empty());
    }

    #[test]
    fn prune_by_age_spares_normal_and_urgent() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None); // 0
        e.write(EventBody::Resumed, Urgency::Normal); // 1
        e.write(
            EventBody::Tamper {
                signal: TamperSignal::WaylandTokenLost,
            },
            Urgency::Urgent,
        ); // 2
        e.clock.advance(31 * 24 * 3_600_000);
        e.write(EventBody::Shutdown, Urgency::None); // 3 (recent)
        let out =
            e.ob.prune(e.clock.wall_ms(), PrunePolicy::default())
                .unwrap();
        let left: Vec<u64> =
            e.ob.pending(10)
                .unwrap()
                .iter()
                .map(|x| x.header.seq)
                .collect();
        assert_eq!(left, vec![1, 2, 3], "only `none` events age out");
        assert_eq!(
            out.ranges,
            vec![PrunedRange {
                from_seq: 0,
                to_seq: 0,
                reason: PruneReason::Age,
                at_ms: e.clock.wall_ms()
            }]
        );
        // Head is untouched by pruning: the chain continues and the instance
        // sees the gap.
        assert_eq!(e.ob.head().unwrap().next_seq, 4);
    }

    /// Regression: setting the clock back 40 days before a flagged capture
    /// made the fresh event age-prunable as soon as the clock was restored.
    #[test]
    fn backdated_events_do_not_age_out() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None); // 0, honest time
        e.clock.jump_wall(-40 * 86_400_000);
        e.write(flag(Rating::Low), Urgency::None); // 1, backdated
        e.write(flag(Rating::Medium), Urgency::Normal); // 2, backdated
        e.clock.jump_wall(40 * 86_400_000);
        let out =
            e.ob.prune(e.clock.wall_ms(), PrunePolicy::default())
                .unwrap();
        assert_eq!(out.events_deleted, 0);
        assert_eq!(e.ob.pending(10).unwrap().len(), 3);
        // The high-water mark survives acks and reopening.
        e.ob.ack_through(2).unwrap();
        e.reopen();
        e.clock.jump_wall(-40 * 86_400_000);
        e.write(flag(Rating::Low), Urgency::None); // 3
        e.clock.jump_wall(40 * 86_400_000);
        let out =
            e.ob.prune(e.clock.wall_ms(), PrunePolicy::default())
                .unwrap();
        assert_eq!(out.events_deleted, 0);
        // The signed header still carries the (backdated) wall clock: the
        // instance and the clock guard see the manipulation.
        let ev = &e.ob.pending(10).unwrap()[0];
        assert!(ev.header.ts_ms < e.clock.wall_ms() - 39 * 86_400_000);
    }

    /// A clock jumped forward at prune time can only drop `none` events.
    #[test]
    fn forward_clock_cannot_erase_flags() {
        let mut e = env();
        e.write(flag(Rating::Clean), Urgency::None); // 0
        e.write(flag(Rating::Medium), Urgency::Normal); // 1
        e.write(flag(Rating::High), Urgency::Urgent); // 2
        let now = e.clock.wall_ms() + 31 * 86_400_000;
        let out = e.ob.prune(now, PrunePolicy::default()).unwrap();
        assert_eq!(out.events_deleted, 1);
        let left: Vec<u64> =
            e.ob.pending(10)
                .unwrap()
                .iter()
                .map(|x| x.header.seq)
                .collect();
        assert_eq!(left, vec![1, 2]);
    }

    /// Commit atomicity when the *second* statement (the head update) fails
    /// after the event INSERT succeeded.
    #[test]
    fn commit_is_atomic_when_head_update_fails() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None);
        let head = e.ob.head().unwrap();
        e.ob.raw()
            .execute_batch(
                "CREATE TRIGGER boom BEFORE UPDATE ON chain_state BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();
        let set = e.f.set();
        let p =
            e.w.prepare(&EventBody::Shutdown, Urgency::None, &set)
                .unwrap();
        assert!(matches!(e.ob.commit(&p), Err(OutboxError::Sql(_))));
        let n: i64 =
            e.ob.raw()
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                .unwrap();
        assert_eq!(n, 1, "event row rolled back with the failed head update");
        assert_eq!(e.ob.head().unwrap(), head);
    }

    fn report(e: &Env, start: i64, end: i64) -> ReportUpload {
        let b = crate::report::ReportBuilder::new(
            e.w.device_id().clone(),
            "Laptop-X",
            start,
            end,
            crate::report::ReportOptions::default(),
        )
        .unwrap();
        crate::report::seal_report(
            &b.finish(),
            &e.f.inst,
            &e.f.member,
            &e.f.set(),
            e.w.signing_key(),
        )
        .unwrap()
    }

    #[test]
    fn reports_queue_ack_and_age_out() {
        let mut e = env();
        const DAY: i64 = 86_400_000;
        let now = e.clock.wall_ms();
        let old = report(&e, now - 40 * DAY, now - 39 * DAY);
        let a = e.ob.add_report(&old).unwrap();
        let fresh = report(&e, now - DAY, now);
        let b = e.ob.add_report(&fresh).unwrap();
        // A report backdated *after* a fresher one was stored is aged by the
        // high-water mark, so it does not age out immediately.
        let backdated = report(&e, now - 50 * DAY, now - 49 * DAY);
        let c = e.ob.add_report(&backdated).unwrap();
        let p = e.ob.pending_reports().unwrap();
        assert_eq!(p.iter().map(|r| r.id).collect::<Vec<_>>(), vec![a, b, c]);
        assert_eq!(p[1].upload, fresh);

        let out = e.ob.prune(now, PrunePolicy::default()).unwrap();
        assert_eq!(out.reports_deleted, 1, "only the genuinely old report");
        let ids: Vec<_> =
            e.ob.pending_reports()
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect();
        assert_eq!(ids, vec![b, c]);
        assert!(e.ob.ack_report(b).unwrap());
        assert!(!e.ob.ack_report(b).unwrap(), "second ack is a no-op");
        assert_eq!(e.ob.stats().unwrap().reports, 1);
    }

    #[test]
    fn contiguous_ranges_cases() {
        assert_eq!(contiguous_ranges(&[]), vec![]);
        assert_eq!(
            contiguous_ranges(&[1, 2, 3, 5, 7, 8]),
            vec![(1, 3), (5, 5), (7, 8)]
        );
        assert_eq!(
            contiguous_ranges(&[u64::MAX - 1, u64::MAX]),
            vec![(u64::MAX - 1, u64::MAX)]
        );
    }

    #[test]
    fn corrupt_row_is_reported_not_panicked() {
        let mut e = env();
        e.write(EventBody::Shutdown, Urgency::None);
        e.ob.raw()
            .execute("UPDATE events SET json = 'not json' WHERE seq = 0", [])
            .unwrap();
        assert!(matches!(e.ob.pending(10), Err(OutboxError::Corrupt(_))));
    }
}
