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
//! **Several processes.** On iOS the app and its packet tunnel append to one
//! chain in one database. [`Outbox::append_exclusive`] does the whole append
//! (read the head and the recipient checkpoint, seal and sign the event on
//! them, store it with the new head) in one `BEGIN EXCLUSIVE` transaction,
//! so no other connection can write in between and `seq` and `prev_hash`
//! stay strict whichever process appends. [`Outbox::commit`] is for a single
//! writer that holds the head itself (the desktop service, which also holds
//! the state directory's lock).
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
//!
//! **Recipient-manifest checkpoint.** The outbox also holds the highest
//! [`ManifestRef`] the device has accepted (PROTOCOL.md §5.1), **together
//! with the signed manifest itself**. It lives here, not in a side file,
//! because it is security state with the same needs as the chain head:
//!
//! * It must survive crashes and only ever move forward, which a single
//!   `IMMEDIATE` transaction guarantees even when two components race.
//! * The ref and the document must never disagree. §5.1 says the device keeps
//!   using its last accepted manifest when a fetch is rejected or fails; after
//!   a restart while offline (or while the instance withholds or rolls back
//!   the manifest) that document has to come from disk, or the device could
//!   not seal anything, tamper events included. A cache kept elsewhere could
//!   lag the checkpoint after a crash and then be refused as a rollback.
//!   [`Outbox::current_recipients`] re-verifies the stored document on load.
//! * There is no public way to move the checkpoint except by presenting a
//!   manifest that passes every device rule, so a bogus ref from
//!   instance-supplied data cannot freeze the device on an old list.
//! * [`Outbox::commit`] and [`Outbox::add_report`] refuse anything sealed to
//!   a manifest other than the current checkpoint, in the same transaction
//!   that stores it. A `RecipientSet` held by a long-running task therefore
//!   cannot keep encrypting to an ally removed in the meantime.
//!
//! A fresh database has no checkpoint and must be seeded explicitly with
//! [`Outbox::bootstrap_manifest`] (see [`ManifestAnchor`] for why).
//!
//! **Schema versions.** `meta.schema_version` records the layout. Opening an
//! older database applies the missing steps from `MIGRATIONS` in the same
//! transaction that reads the version, so an upgrade is all-or-nothing and
//! existing rows are kept.

use crate::clock::Clock;
use crate::recipients::{ManifestDecision, RecipientError, RecipientSet};
use crate::report::SealedReport;
use crate::writer::{EventWriter, PreparedEvent, WriterError};
use faro_crypto::ChainHead;
use faro_proto::api::SignedRecipientManifest;
use faro_proto::body::EventBody;
use faro_proto::keys::ManifestRef;
use faro_proto::report::ReportUpload;
use faro_proto::{DeviceId, Hash32, InstanceId, SignPublicKey, SignedEvent, Urgency, UserId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};

/// File name of the outbox database inside the caller's directory.
pub const OUTBOX_FILE: &str = "outbox.sqlite3";
/// Schema version written to `meta`.
///
/// * 1: events, reports, pruned ranges, chain head, age clock.
/// * 2: adds `manifest_checkpoint` (the accepted ref and its signed manifest).
pub const SCHEMA_VERSION: u32 = 2;
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
    /// A recipient manifest was refused. The stored checkpoint is unchanged;
    /// keep using [`Outbox::current_recipients`] and warn the member.
    #[error(transparent)]
    Manifest(#[from] RecipientError),
    /// No recipient manifest has been accepted on this device yet, so there
    /// is no checkpoint to judge a fetched one against. Seed it with
    /// [`Outbox::bootstrap_manifest`].
    #[error("no recipient manifest accepted yet; bootstrap the outbox first")]
    NotBootstrapped,
    /// [`Outbox::bootstrap_manifest`] on a device that already has a
    /// checkpoint. Bootstrapping again would let a caller re-run trust on
    /// first use, so later manifests go through [`Outbox::accept_manifest`].
    #[error("recipient manifest already bootstrapped at version {}", checkpoint.version)]
    AlreadyBootstrapped { checkpoint: ManifestRef },
    /// The event or report was sealed to a recipient set that is not the
    /// stored checkpoint, typically because a newer manifest (perhaps one
    /// that removes an ally) was accepted after the set was obtained. Nothing
    /// was stored; reload the set with [`Outbox::current_recipients`] and seal
    /// again.
    #[error("sealed to recipient manifest version {}, but the checkpoint is {}", used.version,
        current.map_or_else(|| "unset".to_string(), |c| format!("version {}", c.version)))]
    StaleRecipients {
        used: ManifestRef,
        current: Option<ManifestRef>,
    },
}

/// How the very first recipient manifest on a device is judged
/// ([`Outbox::bootstrap_manifest`]).
///
/// With no checkpoint, the §5.1 rules accept any genuinely signed version,
/// including one from before an ally was removed or a key was rotated. A
/// newly enrolled or reinstalled device fetching from a hostile instance
/// would then seal everything to the removed ally. The outbox therefore
/// refuses to make that choice implicitly ([`OutboxError::NotBootstrapped`]):
/// the caller has to say where freshness comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestAnchor {
    /// A ref obtained from the member's own client, out of band from the
    /// instance (e.g. carried in the enrollment link or handed over
    /// locally). The first manifest must be exactly this one or newer.
    /// Only the accepted manifest is stored, never the anchor alone, so a
    /// wrong anchor cannot freeze the device: bootstrapping simply fails.
    AtLeast(ManifestRef),
    /// Trust on first use: accept whatever genuinely signed manifest arrives
    /// first. Rollback protection starts from that manifest. Use only when
    /// no anchor is available, and surface the accepted ally list to the
    /// member so a stale one is noticed.
    TrustOnFirstUse,
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

/// Steps from schema version `n - 1` to `n`, as `(n, sql)`, in order.
///
/// [`SCHEMA`] is frozen at version 1: changing it would make fresh and
/// upgraded databases diverge. New tables and columns go here, and every
/// database (fresh or old) runs exactly the steps it lacks.
const MIGRATIONS: &[(u32, &str)] = &[(
    2,
    "
CREATE TABLE manifest_checkpoint (
    id            INTEGER PRIMARY KEY CHECK (id = 0),
    version       INTEGER NOT NULL CHECK (version >= 1),
    hash          TEXT NOT NULL,
    -- the SignedRecipientManifest whose reference is (version, hash)
    manifest_json TEXT NOT NULL
) STRICT;
",
)];

/// Read the manifest checkpoint through `conn` (a plain connection or an
/// open transaction).
fn read_checkpoint(conn: &Connection) -> Result<Option<ManifestRef>, OutboxError> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT version, hash FROM manifest_checkpoint WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    row.map(|(v, h)| {
        Ok(ManifestRef {
            version: to_u64(v, "manifest version")?,
            hash: Hash32::from_prefixed_hex(&h)
                .ok_or_else(|| OutboxError::Corrupt("manifest checkpoint hash".into()))?,
        })
    })
    .transpose()
}

/// Write `manifest` (whose reference is `r`) as the checkpoint. Must run
/// inside the caller's `IMMEDIATE` transaction, after the caller compared it
/// with the checkpoint read in that same transaction, so no other writer can
/// slip in between the comparison and the write.
fn store_checkpoint_in(
    tx: &rusqlite::Transaction<'_>,
    manifest: &SignedRecipientManifest,
    r: ManifestRef,
) -> Result<(), OutboxError> {
    let version = to_i64(r.version, "manifest version")?;
    let json = serde_json::to_string(manifest)?;
    tx.execute(
        "INSERT INTO manifest_checkpoint (id, version, hash, manifest_json) VALUES (0, ?1, ?2, ?3)
         ON CONFLICT(id) DO UPDATE SET version = excluded.version, hash = excluded.hash,
             manifest_json = excluded.manifest_json",
        params![version, r.hash.to_prefixed_hex(), json],
    )?;
    tracing::info!(version = r.version, hash = %r.hash, "recipient manifest checkpoint advanced");
    Ok(())
}

/// Refuse ciphertext sealed to any manifest but the stored checkpoint. Runs
/// inside the transaction that would store it, so a checkpoint advanced by
/// another connection a moment earlier is seen.
fn require_current_manifest(
    tx: &rusqlite::Transaction<'_>,
    used: ManifestRef,
) -> Result<(), OutboxError> {
    let current = read_checkpoint(tx)?;
    if current != Some(used) {
        return Err(OutboxError::StaleRecipients { used, current });
    }
    Ok(())
}

/// Bring a database at schema `from` up to [`SCHEMA_VERSION`] inside `tx`.
fn migrate(tx: &rusqlite::Transaction<'_>, from: u32) -> Result<(), OutboxError> {
    for &(to, sql) in MIGRATIONS.iter().filter(|(to, _)| *to > from) {
        tx.execute_batch(sql)?;
        tx.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            [to.to_string()],
        )?;
        tracing::info!(from, to, "migrated outbox schema");
    }
    Ok(())
}

/// The chain head through `conn` (a plain connection or an open
/// transaction).
fn read_head(conn: &Connection) -> Result<ChainHead, OutboxError> {
    let (next, prev): (i64, String) = conn.query_row(
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

/// Check `prepared` against the head and checkpoint read in `tx`, then
/// store it and the new head there (see [`Outbox::commit`]). The caller
/// commits `tx`.
fn commit_in(
    tx: &rusqlite::Transaction<'_>,
    prepared: &PreparedEvent,
    instance_id: &InstanceId,
    device_id: &DeviceId,
) -> Result<ChainHead, OutboxError> {
    let ev = prepared.event();
    let h = &ev.header;
    if &h.instance_id != instance_id || &h.device_id != device_id {
        return Err(OutboxError::ForeignEvent);
    }
    ev.check_shape(true)?;
    let json = serde_json::to_string(ev)?;
    require_current_manifest(tx, prepared.manifest_ref())?;
    let stored = read_head(tx)?;
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
    let age_ms = bump_age_clock(tx, h.ts_ms)?;
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
    Ok(successor)
}

/// The recipient set of the checkpoint stored in `conn`, re-verified (see
/// [`Outbox::current_recipients`]).
fn current_recipients_in(
    conn: &Connection,
    instance_id: &InstanceId,
    pinned_member_sign_pubkey: &SignPublicKey,
    member_id: &UserId,
) -> Result<Option<RecipientSet>, OutboxError> {
    let row: Option<(i64, String, String)> = conn
        .query_row(
            "SELECT version, hash, manifest_json FROM manifest_checkpoint WHERE id = 0",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((version, hash, json)) = row else {
        return Ok(None);
    };
    let stored = ManifestRef {
        version: to_u64(version, "manifest version")?,
        hash: Hash32::from_prefixed_hex(&hash)
            .ok_or_else(|| OutboxError::Corrupt("manifest checkpoint hash".into()))?,
    };
    let manifest: SignedRecipientManifest = serde_json::from_str(&json)
        .map_err(|e| OutboxError::Corrupt(format!("stored recipient manifest: {e}")))?;
    let (set, decision) = RecipientSet::from_manifest(
        &manifest,
        pinned_member_sign_pubkey,
        instance_id,
        member_id,
        Some(stored),
    )
    .map_err(|e| OutboxError::Corrupt(format!("stored recipient manifest: {e}")))?;
    if decision != ManifestDecision::Unchanged {
        return Err(OutboxError::Corrupt(format!(
            "stored recipient manifest is version {}, checkpoint is version {}",
            set.manifest_ref().version,
            stored.version
        )));
    }
    Ok(Some(set))
}

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
        // How long to wait for another connection's transaction. SQLite's
        // busy handler polls rather than queues, so a connection that
        // commits and begins again straight away can keep the others
        // waiting past this. Nothing does that here: the service has one
        // connection, shared by all its tasks, and the `status` and `enroll`
        // commands make a few short transactions (#53).
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
                // A fresh database starts at the frozen version-1 layout
                // and then takes the same migration path as an old one.
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('instance_id', ?1), ('device_id', ?2)",
                    params![instance_id.as_str(), device_id.as_str()],
                )?;
                let g = ChainHead::genesis(instance_id, device_id);
                tx.execute(
                    "INSERT INTO chain_state (id, next_seq, prev_hash) VALUES (0, 0, ?1)",
                    params![g.prev_hash.to_prefixed_hex()],
                )?;
                migrate(&tx, 1)?;
            }
            Some(v) => {
                let found: u32 = v
                    .parse()
                    .map_err(|_| OutboxError::Corrupt(format!("schema_version {v:?}")))?;
                if found > SCHEMA_VERSION {
                    return Err(OutboxError::UnsupportedSchema { found });
                }
                if found == 0 {
                    return Err(OutboxError::Corrupt("schema_version 0".into()));
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
                migrate(&tx, found)?;
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
        read_head(&self.conn)
    }

    /// Durably store `prepared` and advance the stored head, atomically.
    ///
    /// Rejected unless the event is for this outbox's instance/device, its
    /// body commitments hold, its body was sealed to the manifest that is the
    /// stored checkpoint ([`OutboxError::StaleRecipients`]), it carries
    /// exactly the stored head's `seq` and `prev_hash`, and its `new_head` is
    /// the true successor.
    pub fn commit(&mut self, prepared: &PreparedEvent) -> Result<ChainHead, OutboxError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head = commit_in(&tx, prepared, &self.instance_id, &self.device_id)?;
        tx.commit()?;
        Ok(head)
    }

    /// Append one event to a chain that several processes write, such as
    /// the iOS app and its packet tunnel sharing one database in the app
    /// group container (docs/IOS.md §13).
    ///
    /// Everything happens in one `BEGIN EXCLUSIVE` transaction, so no other
    /// connection, in this process or another, can write in between:
    ///
    /// 1. the stored chain head and the recipient checkpoint are read;
    /// 2. `writer` is moved to that head, and the event is sealed to that
    ///    checkpoint's recipients and signed on it ([`EventWriter::prepare`]);
    /// 3. it is checked exactly as [`Outbox::commit`] checks an event, and
    ///    stored together with the new head;
    /// 4. only after the commit does `writer` adopt the new head.
    ///
    /// So `seq` and `prev_hash` stay strict whichever process appends, a
    /// `seq` is never signed for two events, and the body is sealed to the
    /// checkpoint in force at that moment, never to a set another process
    /// has since replaced. If anything fails the transaction rolls back and
    /// nothing is stored; the signed event is dropped unseen.
    ///
    /// A device with no checkpoint yet is [`OutboxError::NotBootstrapped`].
    /// The lock is held while one body is sealed and signed, a few
    /// milliseconds; other writers wait for it up to the busy timeout
    /// ([`Outbox::set_busy_timeout`]).
    pub fn append_exclusive<C: Clock>(
        &mut self,
        writer: &mut EventWriter<C>,
        body: &EventBody,
        urgency: Urgency,
        pinned_member_sign_pubkey: &SignPublicKey,
        member_id: &UserId,
    ) -> Result<SignedEvent, WriterError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)
            .map_err(OutboxError::from)?;
        let recipients =
            current_recipients_in(&tx, &self.instance_id, pinned_member_sign_pubkey, member_id)?
                .ok_or(OutboxError::NotBootstrapped)?;
        writer.set_head(read_head(&tx)?);
        let prepared = writer.prepare(body, urgency, &recipients)?;
        commit_in(&tx, &prepared, &self.instance_id, &self.device_id)?;
        tx.commit().map_err(OutboxError::from)?;
        writer.adopt_committed(&prepared)?;
        Ok(prepared.into_event())
    }

    /// How long a statement waits for another connection's lock before
    /// failing with `SQLITE_BUSY` ([`Outbox::open`] sets 5 seconds).
    pub fn set_busy_timeout(&self, timeout: std::time::Duration) -> Result<(), OutboxError> {
        self.conn.busy_timeout(timeout)?;
        Ok(())
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
    ///
    /// Refused with [`OutboxError::StaleRecipients`] unless it was sealed to
    /// the manifest that is the stored checkpoint.
    pub fn add_report(&mut self, sealed: &SealedReport) -> Result<i64, OutboxError> {
        let upload = sealed.upload();
        let json = serde_json::to_string(upload)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_current_manifest(&tx, sealed.manifest_ref())?;
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

    /// The highest recipient manifest this device has accepted, if any.
    pub fn manifest_checkpoint(&self) -> Result<Option<ManifestRef>, OutboxError> {
        read_checkpoint(&self.conn)
    }

    /// Accept the first recipient manifest on this device and make it the
    /// checkpoint, judged by `anchor` (see [`ManifestAnchor`]). Runs every
    /// other §5.1 rule as [`Outbox::accept_manifest`] does.
    ///
    /// Refused with [`OutboxError::AlreadyBootstrapped`] once a checkpoint
    /// exists. With [`ManifestAnchor::AtLeast`], a manifest older than the
    /// anchor is [`RecipientError::Rollback`] and a different one at the
    /// anchor's version is [`RecipientError::Equivocation`]; nothing is
    /// stored in either case.
    pub fn bootstrap_manifest(
        &mut self,
        manifest: &SignedRecipientManifest,
        pinned_member_sign_pubkey: &SignPublicKey,
        member_id: &UserId,
        anchor: ManifestAnchor,
    ) -> Result<RecipientSet, OutboxError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(checkpoint) = read_checkpoint(&tx)? {
            return Err(OutboxError::AlreadyBootstrapped { checkpoint });
        }
        let floor = match anchor {
            ManifestAnchor::AtLeast(r) => Some(r),
            ManifestAnchor::TrustOnFirstUse => None,
        };
        // Unchanged (exactly the anchor) and Advanced both mean "acceptable";
        // either way nothing is on disk yet, so store it.
        let (set, _) = RecipientSet::from_manifest(
            manifest,
            pinned_member_sign_pubkey,
            &self.instance_id,
            member_id,
            floor,
        )?;
        store_checkpoint_in(&tx, manifest, set.manifest_ref())?;
        tx.commit()?;
        Ok(set)
    }

    /// Verify a fetched `manifest` for this outbox's instance and `member_id`
    /// against the stored checkpoint and, if it is newer, make it the
    /// checkpoint, all in one `IMMEDIATE` transaction (PROTOCOL.md §5.1):
    ///
    /// * a higher version: stored, [`ManifestDecision::Advanced`];
    /// * exactly the stored manifest: nothing written,
    ///   [`ManifestDecision::Unchanged`] (so retries are harmless);
    /// * a lower version: [`RecipientError::Rollback`];
    /// * the same version with another hash: [`RecipientError::Equivocation`];
    /// * a version above `i64::MAX`: [`OutboxError::Range`] (SQLite cannot
    ///   store it, and handing out a set whose checkpoint is not on disk
    ///   would let a restart accept a rollback).
    ///
    /// The comparison is made against the row **on disk** inside the write
    /// transaction, so a stale caller or a racing connection can never move
    /// the checkpoint backwards. The set is only returned once its checkpoint
    /// is committed. On error nothing is written; keep using
    /// [`Outbox::current_recipients`].
    pub fn accept_manifest(
        &mut self,
        manifest: &SignedRecipientManifest,
        pinned_member_sign_pubkey: &SignPublicKey,
        member_id: &UserId,
    ) -> Result<(RecipientSet, ManifestDecision), OutboxError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let checkpoint = read_checkpoint(&tx)?.ok_or(OutboxError::NotBootstrapped)?;
        let (set, decision) = RecipientSet::from_manifest(
            manifest,
            pinned_member_sign_pubkey,
            &self.instance_id,
            member_id,
            Some(checkpoint),
        )?;
        if let ManifestDecision::Advanced(r) = decision {
            store_checkpoint_in(&tx, manifest, r)?;
        }
        tx.commit()?;
        Ok((set, decision))
    }

    /// The recipient set of the stored checkpoint, rebuilt from disk without
    /// any network access: what the device keeps sealing to when a fetch
    /// fails or is rejected (§5.1), and what it starts with after a restart.
    /// `None` before [`Outbox::bootstrap_manifest`].
    ///
    /// The stored document is re-verified with every §5.1 rule against the
    /// stored ref, using the caller's pinned key and member id. Anything but
    /// an exact match (edited row, swapped document, different pinned key)
    /// is [`OutboxError::Corrupt`]: this state is only ever written after
    /// passing those rules, so a failure means the database was tampered
    /// with or belongs to another enrollment.
    pub fn current_recipients(
        &self,
        pinned_member_sign_pubkey: &SignPublicKey,
        member_id: &UserId,
    ) -> Result<Option<RecipientSet>, OutboxError> {
        current_recipients_in(
            &self.conn,
            &self.instance_id,
            pinned_member_sign_pubkey,
            member_id,
        )
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> &Connection {
        &self.conn
    }

    /// rusqlite 0.41 takes `&mut Connection` for hooks such as `busy_handler`.
    #[cfg(test)]
    pub(crate) fn raw_mut(&mut self) -> &mut Connection {
        &mut self.conn
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
    use crate::writer::{open_event_body, EventWriter};
    use faro_crypto::{verify_chain, SigningKey};
    use faro_proto::body::{EventBody, FlagBody, Rating, TamperSignal};

    struct Env {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        f: Fixture,
        clock: ManualClock,
        w: EventWriter<ManualClock>,
        ob: Outbox,
        /// The set of the bootstrapped version-1 manifest (the checkpoint).
        set: RecipientSet,
    }

    /// An outbox bootstrapped (trust on first use) with the fixture's
    /// version-1 manifest.
    fn env() -> Env {
        let td = tempfile::tempdir().unwrap();
        let dir = td.path().join("state");
        let f = Fixture::new(1);
        let dev = DeviceId::new("dev_test");
        let mut ob = Outbox::open(&dir, &f.inst, &dev).unwrap();
        let set = ob
            .bootstrap_manifest(
                &f.manifest(1),
                &f.member_sign.public(),
                &f.member,
                ManifestAnchor::TrustOnFirstUse,
            )
            .unwrap();
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
            set,
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
            account: None,
        })
    }

    impl Env {
        fn write(&mut self, body: EventBody, u: Urgency) -> SignedEvent {
            self.w.write(&mut self.ob, &body, u, &self.set).unwrap()
        }
        fn pinned(&self) -> SignPublicKey {
            self.f.member_sign.public()
        }
        fn accept(
            &mut self,
            m: &SignedRecipientManifest,
        ) -> Result<(RecipientSet, ManifestDecision), OutboxError> {
            let pinned = self.pinned();
            self.ob.accept_manifest(m, &pinned, &self.f.member)
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
        let set = e.set.clone();
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
        let set = e.set.clone();
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
        let set = e.set.clone();
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
        other
            .bootstrap_manifest(
                &e.f.manifest(1),
                &e.pinned(),
                &e.f.member,
                ManifestAnchor::TrustOnFirstUse,
            )
            .unwrap();
        let set = e.set.clone();
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
                account: None,
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
                    account: None,
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
                account: None,
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
        let set = e.set.clone();
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

    fn report(e: &Env, start: i64, end: i64) -> SealedReport {
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
            &e.set,
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
        assert_eq!(&p[1].upload, fresh.upload());

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

    fn schema_version(ob: &Outbox) -> String {
        ob.raw()
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// The fixture's manifest at `version` with every ally removed.
    fn without_allies(f: &Fixture, version: u64) -> SignedRecipientManifest {
        let mut body = f.body(version);
        body.allies.clear();
        f.sign(body)
    }

    fn envelope_ids(ev: &SignedEvent) -> Vec<UserId> {
        ev.body
            .as_ref()
            .unwrap()
            .envelopes
            .iter()
            .map(|e| e.recipient.clone())
            .collect()
    }

    #[test]
    fn checkpoint_and_manifest_persist_across_reopen() {
        let mut e = env();
        let v1 = e.f.manifest(1).body.reference();
        assert_eq!(e.ob.manifest_checkpoint().unwrap(), Some(v1));
        let v3 = e.f.manifest(3);
        let (set3, d) = e.accept(&v3).unwrap();
        assert_eq!(d, ManifestDecision::Advanced(v3.body.reference()));
        e.reopen();
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v3.body.reference())
        );
        // Rebuilt from disk alone, no fetch.
        assert_eq!(
            e.ob.current_recipients(&e.pinned(), &e.f.member).unwrap(),
            Some(set3)
        );
        assert_eq!(schema_version(&e.ob), SCHEMA_VERSION.to_string());
    }

    #[test]
    fn checkpoint_cannot_regress() {
        let mut e = env();
        let v2 = e.f.manifest(2);
        e.accept(&v2).unwrap();
        // Idempotent for the identical manifest.
        assert_eq!(e.accept(&v2).unwrap().1, ManifestDecision::Unchanged);
        assert!(matches!(
            e.accept(&e.f.manifest(1)),
            Err(OutboxError::Manifest(RecipientError::Rollback { have, got }))
                if have == v2.body.reference() && got.version == 1
        ));
        let mut fork = e.f.body(2);
        fork.issued_at_ms += 1;
        let fork = e.f.sign(fork);
        assert!(matches!(
            e.accept(&fork),
            Err(OutboxError::Manifest(RecipientError::Equivocation {
                version: 2,
                ..
            }))
        ));
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v2.body.reference())
        );
        let v9 = e.f.manifest(9);
        assert_eq!(
            e.accept(&v9).unwrap().1,
            ManifestDecision::Advanced(v9.body.reference())
        );
        // A stale caller on a second connection cannot undo it: the check
        // runs against the row on disk, not a cached value.
        let mut other = Outbox::open(&e.dir, &e.f.inst, e.w.device_id()).unwrap();
        assert!(matches!(
            other.accept_manifest(&e.f.manifest(5), &e.pinned(), &e.f.member),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v9.body.reference())
        );
        // A genuinely signed version SQLite cannot store is refused, not
        // truncated, and no set is handed out for it.
        for huge in [1u64 << 63, u64::MAX] {
            assert!(matches!(
                e.accept(&e.f.manifest(huge)),
                Err(OutboxError::Range(_))
            ));
        }
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v9.body.reference())
        );
        assert_eq!(
            e.ob.current_recipients(&e.pinned(), &e.f.member)
                .unwrap()
                .unwrap()
                .manifest_ref(),
            v9.body.reference()
        );
    }

    /// Six connections race to move the checkpoint, each presenting the
    /// versions in its own order. After its own `accept_manifest`, a
    /// connection must never read a checkpoint below the version it
    /// presented, and the newest manifest wins in the end.
    ///
    /// The connections are opened first and then race in rounds: in each
    /// round every connection makes one `accept_manifest` call, all at once.
    /// That is how the outbox is shared in practice (one update, then other
    /// work), and every round has six writers contending for the lock.
    ///
    /// Free-running loops are not a race at all. SQLite's busy handler polls
    /// instead of queueing, so a connection that commits and begins again
    /// straight away keeps the lock while the others sleep: the threads ran
    /// one after another, and the last one to get the lock waited for the
    /// others' whole runs. On the Windows runner that passed the 5 s busy
    /// timeout (#53). In rounds, a connection waits for at most five single
    /// updates.
    #[test]
    fn racing_checkpoint_updates_never_move_backwards() {
        let e = env();
        const VERSIONS: u64 = 40;
        const THREADS: u64 = 6;
        let manifests: std::sync::Arc<Vec<SignedRecipientManifest>> =
            std::sync::Arc::new((1..=VERSIONS).map(|v| e.f.manifest(v)).collect());
        let round = std::sync::Arc::new(std::sync::Barrier::new(THREADS as usize));
        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let mut ob = Outbox::open(&e.dir, &e.f.inst, e.w.device_id()).unwrap();
                let pinned = e.pinned();
                let member = e.f.member.clone();
                let manifests = manifests.clone();
                let round = round.clone();
                std::thread::spawn(move || -> Result<(), String> {
                    let mut step = |i: u64| -> Result<(), String> {
                        // Each thread walks the versions in a different order.
                        let v = (i * (2 * t + 1) + t) % VERSIONS + 1;
                        let m = &manifests[(v - 1) as usize];
                        match ob.accept_manifest(m, &pinned, &member) {
                            Ok(_) => {}
                            Err(OutboxError::Manifest(RecipientError::Rollback { .. })) => {}
                            Err(other) => return Err(format!("accepting v{v}: {other:?}")),
                        }
                        let now = ob
                            .manifest_checkpoint()
                            .map_err(|err| format!("reading after v{v}: {err:?}"))?
                            .ok_or("checkpoint disappeared")?;
                        if now.version < v {
                            return Err(format!("checkpoint went below {v}: {now:?}"));
                        }
                        Ok(())
                    };
                    let mut result = Ok(());
                    for i in 0..VERSIONS {
                        // Keep meeting the others after a failure, so they
                        // are not left waiting at the barrier.
                        round.wait();
                        if result.is_ok() {
                            result = step(i);
                        }
                    }
                    result
                })
            })
            .collect();
        for (t, handle) in threads.into_iter().enumerate() {
            if let Err(err) = handle.join().unwrap() {
                panic!("thread {t}: {err}");
            }
        }
        let last = manifests.last().unwrap().body.reference();
        assert_eq!(e.ob.manifest_checkpoint().unwrap(), Some(last));
        // The stored document moved with the ref.
        assert_eq!(
            e.ob.current_recipients(&e.pinned(), &e.f.member)
                .unwrap()
                .unwrap()
                .manifest_ref(),
            last
        );
    }

    /// Sends once on the first contended lock, then keeps waiting (up to
    /// about ten seconds). Used by `checkpoint_compare_runs_under_the_write_lock`.
    static ON_FIRST_BUSY: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
        std::sync::Mutex::new(None);

    fn signal_then_wait(count: i32) -> bool {
        if let Some(tx) = ON_FIRST_BUSY.lock().unwrap().take() {
            let _ = tx.send(());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        count < 2_000
    }

    /// Deterministic check that the checkpoint is read *under* the write
    /// lock. Another connection holds the lock with an uncommitted move to
    /// v3. The busy handler lets it commit only once `accept_manifest` is
    /// waiting for the lock. An implementation that read the checkpoint
    /// before taking the lock would have seen v1 and written v2 over v3.
    #[test]
    fn checkpoint_compare_runs_under_the_write_lock() {
        let e = env();
        let v2 = e.f.manifest(2);
        let v3 = e.f.manifest(3);
        let mut ob = Outbox::open(&e.dir, &e.f.inst, e.w.device_id()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        *ON_FIRST_BUSY.lock().unwrap() = Some(tx);
        ob.raw_mut().busy_handler(Some(signal_then_wait)).unwrap();

        let other = Connection::open(e.ob.path()).unwrap();
        other.execute_batch("BEGIN IMMEDIATE").unwrap();
        other
            .execute(
                "UPDATE manifest_checkpoint SET version = 3, hash = ?1, manifest_json = ?2",
                params![
                    v3.body.hash().to_prefixed_hex(),
                    serde_json::to_string(&v3).unwrap()
                ],
            )
            .unwrap();

        let pinned = e.pinned();
        let member = e.f.member.clone();
        let t = std::thread::spawn(move || ob.accept_manifest(&v2, &pinned, &member).map(|_| ()));
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("accept_manifest never waited for the write lock");
        other.execute_batch("COMMIT").unwrap();
        let got = t.join().unwrap();
        assert!(
            matches!(
                got,
                Err(OutboxError::Manifest(RecipientError::Rollback { have, .. }))
                    if have == v3.body.reference()
            ),
            "{got:?}"
        );
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v3.body.reference())
        );
    }

    /// End to end: ally removed in v2, device restarts, instance re-serves v1.
    #[test]
    fn accept_manifest_blocks_reinstating_removed_ally_after_restart() {
        let mut e = env();
        let removed = e.f.allies[0].0.clone();
        let v1 = e.f.manifest(1);
        let v2 = without_allies(&e.f, 2);

        assert_eq!(e.accept(&v1).unwrap().1, ManifestDecision::Unchanged);
        let (set2, d) = e.accept(&v2).unwrap();
        assert_eq!(d, ManifestDecision::Advanced(v2.body.reference()));
        assert_eq!(set2.recipients().len(), 1);

        e.reopen();
        assert!(matches!(
            e.accept(&v1),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v2.body.reference())
        );
        let (again, d) = e.accept(&v2).unwrap();
        assert_eq!(d, ManifestDecision::Unchanged);
        let ev =
            e.w.write(&mut e.ob, &EventBody::Resumed, Urgency::None, &again)
                .unwrap();
        assert!(!envelope_ids(&ev).contains(&removed));
    }

    #[test]
    fn rejected_manifest_does_not_touch_checkpoint() {
        let mut e = env();
        let cp = e.ob.manifest_checkpoint().unwrap();
        // Signed by an attacker at a much higher version: the checkpoint can
        // only move by presenting a manifest the pinned key signed.
        let forged = SigningKey::generate().endorse(e.f.body(50));
        assert!(matches!(
            e.accept(&forged),
            Err(OutboxError::Manifest(RecipientError::BadSignature))
        ));
        // Genuine, but for another member.
        assert!(matches!(
            e.ob.accept_manifest(&e.f.manifest(2), &e.pinned(), &UserId::new("usr_other")),
            Err(OutboxError::Manifest(RecipientError::WrongMember { .. }))
        ));
        assert_eq!(e.ob.manifest_checkpoint().unwrap(), cp);
        // The genuine v2 is still accepted afterwards: nothing was frozen.
        assert!(matches!(
            e.accept(&e.f.manifest(2)).unwrap().1,
            ManifestDecision::Advanced(_)
        ));
    }

    /// Regression (critical): a fresh device had no checkpoint, so it took
    /// whatever genuinely signed manifest the instance served first, even one
    /// from before an ally's removal. Now the first manifest needs an
    /// explicit anchor.
    #[test]
    fn fresh_outbox_requires_an_explicit_bootstrap() {
        let f = Fixture::new(1);
        let pinned = f.member_sign.public();
        let removed = f.allies[0].0.clone();
        let v1 = f.manifest(1); // still lists the ally
        let v2 = without_allies(&f, 2); // the ally was removed
        let dev = DeviceId::new("dev_new_laptop");
        let td = tempfile::tempdir().unwrap();
        let mut ob = Outbox::open(td.path(), &f.inst, &dev).unwrap();
        assert_eq!(ob.manifest_checkpoint().unwrap(), None);
        assert_eq!(ob.current_recipients(&pinned, &f.member).unwrap(), None);

        // The instance serves the pre-removal v1 to the new device.
        assert!(matches!(
            ob.accept_manifest(&v1, &pinned, &f.member),
            Err(OutboxError::NotBootstrapped)
        ));
        // Nothing can be stored without a checkpoint, even sealed to a set
        // built inside the crate.
        let mut w = EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev.clone(),
            ob.head().unwrap(),
            ManualClock::new(1_800_000_000_000, 0),
        );
        assert!(matches!(
            w.write(&mut ob, &EventBody::Resumed, Urgency::None, &f.set()),
            Err(crate::writer::WriterError::Outbox(
                OutboxError::StaleRecipients { current: None, .. }
            ))
        ));

        // The member's client handed the device v2's ref at enrollment.
        let anchor = ManifestAnchor::AtLeast(v2.body.reference());
        assert!(matches!(
            ob.bootstrap_manifest(&v1, &pinned, &f.member, anchor),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));
        let mut fork = f.body(2);
        fork.issued_at_ms += 7;
        assert!(matches!(
            ob.bootstrap_manifest(&f.sign(fork), &pinned, &f.member, anchor),
            Err(OutboxError::Manifest(RecipientError::Equivocation { .. }))
        ));
        assert_eq!(
            ob.manifest_checkpoint().unwrap(),
            None,
            "rejections store nothing"
        );
        let set = ob
            .bootstrap_manifest(&v2, &pinned, &f.member, anchor)
            .unwrap();
        assert_eq!(set.manifest_ref(), v2.body.reference());
        let ev = w
            .write(&mut ob, &EventBody::Resumed, Urgency::None, &set)
            .unwrap();
        assert_eq!(envelope_ids(&ev), vec![f.member.clone()]);
        assert!(!envelope_ids(&ev).contains(&removed));
        // Bootstrapping is one-time: it cannot be used to re-run TOFU.
        assert!(matches!(
            ob.bootstrap_manifest(&v1, &pinned, &f.member, ManifestAnchor::TrustOnFirstUse),
            Err(OutboxError::AlreadyBootstrapped { checkpoint }) if checkpoint == v2.body.reference()
        ));
        assert!(matches!(
            ob.accept_manifest(&v1, &pinned, &f.member),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));

        // A manifest newer than the anchor is fine; a bogus anchor (one no
        // signed manifest reaches) just fails and leaves nothing behind.
        let td2 = tempfile::tempdir().unwrap();
        let mut ob2 = Outbox::open(td2.path(), &f.inst, &dev).unwrap();
        let bogus = ManifestAnchor::AtLeast(ManifestRef {
            version: 1 << 40,
            hash: Hash32::of(b"bogus"),
        });
        assert!(matches!(
            ob2.bootstrap_manifest(&v2, &pinned, &f.member, bogus),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));
        assert_eq!(ob2.manifest_checkpoint().unwrap(), None);
        let v3 = f.manifest(3);
        ob2.bootstrap_manifest(&v3, &pinned, &f.member, anchor)
            .unwrap();
        assert_eq!(
            ob2.manifest_checkpoint().unwrap(),
            Some(v3.body.reference())
        );
    }

    /// Regression: a set obtained before another component accepted a
    /// manifest removing an ally could still be committed, so the removed
    /// ally kept receiving new items.
    #[test]
    fn stale_set_cannot_be_committed_after_checkpoint_advanced() {
        let mut e = env();
        let removed = e.f.allies[0].0.clone();
        let set1 = e.set.clone();
        assert!(set1.recipients().iter().any(|r| r.user_id == removed));
        let head = e.ob.head().unwrap();

        // Another connection (say, the sync task) accepts v2.
        let v2 = without_allies(&e.f, 2);
        let mut sync = Outbox::open(&e.dir, &e.f.inst, e.w.device_id()).unwrap();
        sync.accept_manifest(&v2, &e.pinned(), &e.f.member).unwrap();

        let used = set1.manifest_ref();
        let stale = |r: Result<SignedEvent, crate::writer::WriterError>| {
            matches!(
                r,
                Err(crate::writer::WriterError::Outbox(OutboxError::StaleRecipients {
                    used: u,
                    current: Some(c),
                })) if u == used && c == v2.body.reference()
            )
        };
        assert!(stale(e.w.write(
            &mut e.ob,
            &EventBody::Resumed,
            Urgency::None,
            &set1
        )));
        assert_eq!(e.ob.head().unwrap(), head, "nothing stored");
        assert_eq!(e.w.head(), head, "writer did not adopt");
        assert_eq!(e.ob.stats().unwrap().events, 0);
        // Same for reports.
        let r = report(&e, 1_000, 2_000);
        assert!(matches!(
            e.ob.add_report(&r),
            Err(OutboxError::StaleRecipients { .. })
        ));
        assert!(e.ob.pending_reports().unwrap().is_empty());

        // A set built against the wrong checkpoint inside the crate (the
        // misuse the public API no longer allows) is refused too, and so is
        // one newer than the checkpoint that was never persisted.
        let (unchecked, _) = e.f.accept(&e.f.manifest(1), None).unwrap();
        let (ahead, _) = e.f.accept(&e.f.manifest(7), None).unwrap();
        for s in [&unchecked, &ahead] {
            let p = e.w.prepare(&EventBody::Resumed, Urgency::None, s).unwrap();
            assert!(matches!(
                e.ob.commit(&p),
                Err(OutboxError::StaleRecipients { .. })
            ));
        }

        // Reloading the current set works and never reaches the removed ally.
        let current =
            e.ob.current_recipients(&e.pinned(), &e.f.member)
                .unwrap()
                .unwrap();
        let ev =
            e.w.write(&mut e.ob, &EventBody::Resumed, Urgency::None, &current)
                .unwrap();
        assert!(open_event_body(&ev, &removed, &e.f.allies[0].1).is_err());
        assert!(open_event_body(&ev, &e.f.member, &e.f.member_enc).is_ok());
        let r = crate::report::seal_report(
            &crate::report::ReportBuilder::new(
                e.w.device_id().clone(),
                "Laptop-X",
                1_000,
                2_000,
                crate::report::ReportOptions::default(),
            )
            .unwrap()
            .finish(),
            &e.f.inst,
            &e.f.member,
            &current,
            e.w.signing_key(),
        )
        .unwrap();
        e.ob.add_report(&r).unwrap();
    }

    /// Regression: only the ref was stored, so a device restarting with no
    /// network (or facing a withheld or rolled-back manifest) had no set and
    /// could not record anything, tamper events included.
    #[test]
    fn restart_offline_keeps_sealing_to_last_accepted_manifest() {
        let mut e = env();
        let removed = e.f.allies[0].0.clone();
        let v2 = without_allies(&e.f, 2);
        e.accept(&v2).unwrap();

        e.reopen(); // restart; the instance is unreachable
        let set =
            e.ob.current_recipients(&e.pinned(), &e.f.member)
                .unwrap()
                .expect("set rebuilt from disk");
        assert_eq!(set.manifest_ref(), v2.body.reference());
        let ev =
            e.w.write(
                &mut e.ob,
                &EventBody::Tamper {
                    signal: TamperSignal::WaylandTokenLost,
                    account: None,
                },
                Urgency::Urgent,
                &set,
            )
            .unwrap();
        assert!(open_event_body(&ev, &removed, &e.f.allies[0].1).is_err());

        // A hostile instance re-serves v1: rejected, and the stored v2 is
        // still what the device seals to.
        assert!(matches!(
            e.accept(&e.f.manifest(1)),
            Err(OutboxError::Manifest(RecipientError::Rollback { .. }))
        ));
        assert_eq!(
            e.ob.current_recipients(&e.pinned(), &e.f.member).unwrap(),
            Some(set.clone())
        );

        // A failure while storing v3 (standing in for a crash) leaves both
        // the old ref and the old document, never one without the other.
        e.ob.raw()
            .execute_batch(
                "CREATE TRIGGER boom BEFORE UPDATE ON manifest_checkpoint
                 BEGIN SELECT RAISE(ABORT, 'boom'); END;",
            )
            .unwrap();
        assert!(matches!(
            e.accept(&e.f.manifest(3)),
            Err(OutboxError::Sql(_))
        ));
        e.reopen();
        assert_eq!(
            e.ob.manifest_checkpoint().unwrap(),
            Some(v2.body.reference())
        );
        assert_eq!(
            e.ob.current_recipients(&e.pinned(), &e.f.member).unwrap(),
            Some(set)
        );
    }

    #[test]
    fn tampered_checkpoint_row_is_corrupt_not_trusted() {
        let mut e = env();
        let v2 = e.f.manifest(2);
        e.accept(&v2).unwrap();
        let pinned = e.pinned();
        let member = e.f.member.clone();
        let corrupt = |ob: &Outbox, pinned: &SignPublicKey| {
            matches!(
                ob.current_recipients(pinned, &member),
                Err(OutboxError::Corrupt(_))
            )
        };
        // The wrong pinned key (another enrollment) does not verify.
        assert!(corrupt(&e.ob, &SigningKey::generate().public()));

        // A genuine older document swapped in under the v2 ref.
        e.ob.raw()
            .execute(
                "UPDATE manifest_checkpoint SET manifest_json = ?1",
                [serde_json::to_string(&e.f.manifest(1)).unwrap()],
            )
            .unwrap();
        assert!(corrupt(&e.ob, &pinned));
        // The ref lowered to match an older document.
        let v1 = e.f.manifest(1);
        e.ob.raw()
            .execute(
                "UPDATE manifest_checkpoint SET version = 1, hash = ?1",
                [v1.body.hash().to_prefixed_hex()],
            )
            .unwrap();
        assert!(
            e.ob.current_recipients(&pinned, &member).unwrap().is_some(),
            "consistent v1 row verifies (rollback by editing the file is out of scope)"
        );
        // A newer genuine document under an older ref.
        e.ob.raw()
            .execute(
                "UPDATE manifest_checkpoint SET manifest_json = ?1",
                [serde_json::to_string(&e.f.manifest(5)).unwrap()],
            )
            .unwrap();
        assert!(corrupt(&e.ob, &pinned));
        // Garbage JSON and a bad hash.
        e.ob.raw()
            .execute("UPDATE manifest_checkpoint SET manifest_json = 'nope'", [])
            .unwrap();
        assert!(corrupt(&e.ob, &pinned));
        e.ob.raw()
            .execute("UPDATE manifest_checkpoint SET hash = 'nope'", [])
            .unwrap();
        assert!(corrupt(&e.ob, &pinned));
        assert!(matches!(
            e.ob.manifest_checkpoint(),
            Err(OutboxError::Corrupt(_))
        ));
        assert!(matches!(e.accept(&v2), Err(OutboxError::Corrupt(_))));
        let p =
            e.w.prepare(&EventBody::Resumed, Urgency::None, &e.set)
                .unwrap();
        assert!(matches!(e.ob.commit(&p), Err(OutboxError::Corrupt(_))));
    }

    /// The version-1 layout exactly as shipped, before the checkpoint table.
    const SCHEMA_V1_AS_SHIPPED: &str = "
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
        CREATE TABLE chain_state (
            id INTEGER PRIMARY KEY CHECK (id = 0),
            next_seq INTEGER NOT NULL CHECK (next_seq >= 0),
            prev_hash TEXT NOT NULL
        ) STRICT;
        CREATE TABLE events (
            seq INTEGER PRIMARY KEY CHECK (seq >= 0),
            kind TEXT NOT NULL,
            urgency TEXT NOT NULL CHECK (urgency IN ('none', 'normal', 'urgent')),
            ts_ms INTEGER NOT NULL,
            size INTEGER NOT NULL CHECK (size >= 0),
            json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            period_start INTEGER NOT NULL,
            period_end INTEGER NOT NULL,
            age_ms INTEGER NOT NULL,
            size INTEGER NOT NULL,
            json TEXT NOT NULL
        ) STRICT;
        CREATE TABLE pruned (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_seq INTEGER NOT NULL,
            to_seq INTEGER NOT NULL,
            reason TEXT NOT NULL,
            at INTEGER NOT NULL
        ) STRICT;
    ";

    #[test]
    fn migrates_v1_database_and_keeps_data() {
        let td = tempfile::tempdir().unwrap();
        let f = Fixture::new(1);
        let dev = DeviceId::new("dev_old");
        let clock = ManualClock::new(1_800_000_000_000, 0);
        let mut w = EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev.clone(),
            ChainHead::genesis(&f.inst, &dev),
            clock,
        );
        let p = w
            .prepare(&EventBody::Resumed, Urgency::Normal, &f.set())
            .unwrap();
        w.adopt_committed(&p).unwrap();
        let json = serde_json::to_string(p.event()).unwrap();
        {
            let c = Connection::open(td.path().join(OUTBOX_FILE)).unwrap();
            c.execute_batch(SCHEMA_V1_AS_SHIPPED).unwrap();
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1'),
                 ('instance_id', ?1), ('device_id', ?2), ('age_hw_ms', '1800000000000')",
                params![f.inst.as_str(), dev.as_str()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO chain_state (id, next_seq, prev_hash) VALUES (0, 1, ?1)",
                [w.head().prev_hash.to_prefixed_hex()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO events (seq, kind, urgency, ts_ms, size, json)
                 VALUES (0, 'resumed', 'normal', 1800000000000, ?1, ?2)",
                params![json.len() as i64, json],
            )
            .unwrap();
            c.execute(
                "INSERT INTO pruned (from_seq, to_seq, reason, at) VALUES (0, 0, 'age', 7)",
                [],
            )
            .unwrap();
        }

        let mut ob = Outbox::open(td.path(), &f.inst, &dev).unwrap();
        assert_eq!(schema_version(&ob), "2");
        assert_eq!(ob.head().unwrap(), w.head());
        assert_eq!(ob.pending(10).unwrap(), vec![p.event().clone()]);
        assert_eq!(ob.pruned_ranges().unwrap().len(), 1);
        assert_eq!(ob.manifest_checkpoint().unwrap(), None);
        // An upgraded device has no checkpoint either and must bootstrap.
        let v4 = f.manifest(4);
        let pinned = f.member_sign.public();
        assert!(matches!(
            ob.accept_manifest(&v4, &pinned, &f.member),
            Err(OutboxError::NotBootstrapped)
        ));
        let set = ob
            .bootstrap_manifest(&v4, &pinned, &f.member, ManifestAnchor::TrustOnFirstUse)
            .unwrap();
        // The chain continues from the migrated head.
        w.write(&mut ob, &EventBody::Shutdown, Urgency::None, &set)
            .unwrap();
        drop(ob);
        let ob = Outbox::open(td.path(), &f.inst, &dev).unwrap();
        assert_eq!(ob.manifest_checkpoint().unwrap(), Some(v4.body.reference()));
        assert_eq!(
            ob.current_recipients(&pinned, &f.member).unwrap(),
            Some(set)
        );
        assert_eq!(ob.pending(10).unwrap().len(), 2);
    }

    #[test]
    fn failed_migration_leaves_v1_database_intact() {
        let td = tempfile::tempdir().unwrap();
        let f = Fixture::new(0);
        let dev = DeviceId::new("dev_old");
        {
            let c = Connection::open(td.path().join(OUTBOX_FILE)).unwrap();
            c.execute_batch(SCHEMA_V1_AS_SHIPPED).unwrap();
            c.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', '1'),
                 ('instance_id', ?1), ('device_id', ?2)",
                params![f.inst.as_str(), dev.as_str()],
            )
            .unwrap();
            c.execute(
                "INSERT INTO chain_state (id, next_seq, prev_hash) VALUES (0, 0, ?1)",
                [ChainHead::genesis(&f.inst, &dev)
                    .prev_hash
                    .to_prefixed_hex()],
            )
            .unwrap();
            // Make the v2 step fail halfway: its table name is taken.
            c.execute_batch("CREATE TABLE manifest_checkpoint (x INTEGER)")
                .unwrap();
        }
        assert!(matches!(
            Outbox::open(td.path(), &f.inst, &dev),
            Err(OutboxError::Sql(_))
        ));
        let c = Connection::open(td.path().join(OUTBOX_FILE)).unwrap();
        let v: String = c
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, "1", "version is not bumped when a step fails");
    }

    #[test]
    fn rejects_newer_or_zero_schema() {
        let e = env();
        e.ob.raw()
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                [(SCHEMA_VERSION + 1).to_string()],
            )
            .unwrap();
        assert!(matches!(
            Outbox::open(&e.dir, &e.f.inst, e.w.device_id()),
            Err(OutboxError::UnsupportedSchema { found }) if found == SCHEMA_VERSION + 1
        ));
        e.ob.raw()
            .execute(
                "UPDATE meta SET value = '0' WHERE key = 'schema_version'",
                [],
            )
            .unwrap();
        assert!(matches!(
            Outbox::open(&e.dir, &e.f.inst, e.w.device_id()),
            Err(OutboxError::Corrupt(_))
        ));
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

    /// A writer with the same device key and a fresh connection, as another
    /// process (the iOS tunnel next to the app) has.
    fn second_writer(e: &Env) -> (Outbox, EventWriter<ManualClock>) {
        let ob = Outbox::open(&e.dir, &e.f.inst, e.w.device_id()).unwrap();
        let w = EventWriter::new(
            SigningKey::from_bytes(&e.w.signing_key().to_bytes()),
            e.f.inst.clone(),
            e.w.device_id().clone(),
            ChainHead::genesis(&e.f.inst, e.w.device_id()),
            e.clock.clone(),
        );
        (ob, w)
    }

    #[test]
    fn append_exclusive_follows_heads_written_by_other_connections() {
        let mut e = env();
        let pinned = e.pinned();
        let member = e.f.member.clone();
        let (mut other, mut w2) = second_writer(&e);
        // Both writers start at genesis; each append reads the stored head.
        for i in 0..6 {
            let (ob, w) = if i % 2 == 0 {
                (&mut e.ob, &mut e.w)
            } else {
                (&mut other, &mut w2)
            };
            let ev = ob
                .append_exclusive(w, &EventBody::Resumed, Urgency::None, &pinned, &member)
                .unwrap();
            assert_eq!(ev.header.seq, i);
            assert_eq!(w.head(), ob.head().unwrap(), "the writer adopts the head");
        }
        let all = e.ob.pending(100).unwrap();
        assert_eq!(
            all.iter().map(|p| p.header.seq).collect::<Vec<_>>(),
            (0..6).collect::<Vec<_>>()
        );
        let (head, gaps) = verify_chain(
            &e.f.inst,
            e.w.device_id(),
            &e.w.signing_key().public(),
            &all,
            true,
        )
        .unwrap();
        assert!(gaps.is_empty());
        assert_eq!(head, e.ob.head().unwrap());
    }

    #[test]
    fn append_exclusive_is_strict_across_concurrent_connections() {
        let e = env();
        let seed = e.w.signing_key().to_bytes();
        let pinned = e.pinned();
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let (dir, inst, dev, member) = (
                    e.dir.clone(),
                    e.f.inst.clone(),
                    e.w.device_id().clone(),
                    e.f.member.clone(),
                );
                let seed = *seed;
                let clock = e.clock.clone();
                std::thread::spawn(move || {
                    let mut ob = Outbox::open(&dir, &inst, &dev).unwrap();
                    ob.set_busy_timeout(std::time::Duration::from_secs(60))
                        .unwrap();
                    let head = ob.head().unwrap();
                    let mut w =
                        EventWriter::new(SigningKey::from_bytes(&seed), inst, dev, head, clock);
                    for _ in 0..25 {
                        ob.append_exclusive(
                            &mut w,
                            &EventBody::Resumed,
                            Urgency::None,
                            &pinned,
                            &member,
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let all = e.ob.pending(1000).unwrap();
        assert_eq!(all.len(), 100);
        let (_, gaps) = verify_chain(
            &e.f.inst,
            e.w.device_id(),
            &e.w.signing_key().public(),
            &all,
            true,
        )
        .unwrap();
        assert!(gaps.is_empty());
    }

    #[test]
    fn append_exclusive_seals_to_the_checkpoint_in_force() {
        let mut e = env();
        let pinned = e.pinned();
        let member = e.f.member.clone();
        let (mut other, _) = second_writer(&e);
        // Another process accepts v2, which removes the ally.
        let mut body = e.f.body(2);
        body.allies.clear();
        let v2 = e.f.member_sign.endorse(body);
        other.accept_manifest(&v2, &pinned, &member).unwrap();
        // This process never fetched v2, and its append is sealed to it.
        let ev =
            e.ob.append_exclusive(
                &mut e.w,
                &EventBody::Resumed,
                Urgency::None,
                &pinned,
                &member,
            )
            .unwrap();
        let (ally, ally_key) = &e.f.allies[0];
        assert!(open_event_body(&ev, ally, ally_key).is_err());
        assert_eq!(
            open_event_body(&ev, &member, &e.f.member_enc).unwrap(),
            EventBody::Resumed
        );
        // A set obtained before v2 is still refused by `commit`.
        let stale =
            e.w.prepare(&EventBody::Resumed, Urgency::None, &e.set)
                .unwrap();
        assert!(matches!(
            e.ob.commit(&stale),
            Err(OutboxError::StaleRecipients { .. })
        ));
    }

    #[test]
    fn append_exclusive_needs_a_checkpoint_and_stores_nothing_on_failure() {
        let td = tempfile::tempdir().unwrap();
        let f = Fixture::new(0);
        let dev = DeviceId::new("dev_test");
        let mut ob = Outbox::open(td.path(), &f.inst, &dev).unwrap();
        let mut w = EventWriter::new(
            SigningKey::generate(),
            f.inst.clone(),
            dev.clone(),
            ob.head().unwrap(),
            ManualClock::new(1_800_000_000_000, 0),
        );
        let pinned = f.member_sign.public();
        assert!(matches!(
            ob.append_exclusive(
                &mut w,
                &EventBody::Resumed,
                Urgency::None,
                &pinned,
                &f.member
            ),
            Err(WriterError::Outbox(OutboxError::NotBootstrapped))
        ));
        // A wrong pinned key makes the stored checkpoint unverifiable.
        ob.bootstrap_manifest(
            &f.manifest(1),
            &pinned,
            &f.member,
            ManifestAnchor::TrustOnFirstUse,
        )
        .unwrap();
        let wrong = SigningKey::generate().public();
        assert!(matches!(
            ob.append_exclusive(
                &mut w,
                &EventBody::Resumed,
                Urgency::None,
                &wrong,
                &f.member
            ),
            Err(WriterError::Outbox(OutboxError::Corrupt(_)))
        ));
        assert_eq!(ob.head().unwrap(), ChainHead::genesis(&f.inst, &dev));
        assert!(ob.pending(10).unwrap().is_empty());
    }
}
