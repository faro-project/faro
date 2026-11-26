//! The update mirror (ARCHITECTURE.md §3.8, §4.1 item 7; PROTOCOL.md §8).
//!
//! Clients ask *their instance* for updates, and the instance mirrors the
//! project's signed releases. The instance is not trusted with them: every
//! client verifies the project's signatures itself (`faro-update`), so a
//! compromised instance can delay updates but never push code.
//!
//! The mirror verifies too, as defence in depth and so it never caches or
//! serves garbage. It holds the project's root of trust (`updates.root`)
//! and runs the same [`Updater`] state machine as a client: it walks root
//! rotations, verifies the timestamp and the targets it commits to, and
//! only stores artifacts whose signed length and BLAKE3 match. What it
//! serves is exactly the bytes it verified.
//!
//! **What is cached.** Each refresh prefetches, for every kind, platform
//! and arch the release lists, the artifact the instance's channel selects
//! (what an up-to-date client will ask for). That covers models and
//! blocklists too (platform and arch `any`): the newest in the channel,
//! whatever its `min_client`. Any other listed artifact (an older release
//! for an older OS, or a model for clients below a newer one's
//! `min_client`) is fetched from upstream the first time a client asks
//! for it. Artifacts are stored by BLAKE3, so a
//! name reused across releases can never serve stale bytes, and anything no
//! longer listed is deleted after the next successful refresh. Server
//! releases (`kind = server`) are listed but never fetched: no client
//! installs them.
//!
//! **Air-gapped instances** have no upstream: `faro-server updates import`
//! runs the same refresh against a directory and copies every listed
//! artifact it finds. A running server picks the result up on its next
//! pass ([`Mirror::reload`]).
//!
//! **One writer at a time.** A refresh or import holds `mirror.lock` in the
//! mirror directory, so `serve` and `updates import` never interleave; a
//! pass that finds it held is skipped. Files are replaced by rename, so a
//! reader never sees a half-written one.
//!
//! On-disk layout under `<data_dir>/updates` (not included in backups:
//! everything here can be fetched again):
//!
//! ```text
//! trust.json              the mirror's faro_update::TrustedState
//! status.json             the outcome of the latest refresh ([`MirrorStatus`])
//! mirror.lock             held during a refresh or import
//! meta/timestamp.json     the verified documents, byte for byte as served
//! meta/targets.json
//! meta/roots/<n>.json
//! artifacts/<blake3 hex>  verified artifacts
//! tmp/                    downloads in progress
//! ```

pub mod api;
pub mod upstream;

use crate::state::KeyedLocks;
use axum::body::Bytes;
use faro_proto::Hash32;
use faro_update::metadata::{MAX_ROOT_BYTES, MAX_TARGETS_BYTES, MAX_TIMESTAMP_BYTES};
use faro_update::{
    Channel, Selection, TargetInfo, TargetKind, TargetsMeta, TrustedState, UpdateError, Updater,
    VerifiedTargets,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use upstream::{FetchError, Upstream};

/// Name of the mirror directory under the data directory.
pub const MIRROR_DIR: &str = "updates";
/// Largest artifact the mirror stores (an int8 model or a client package is
/// far below this).
pub const MAX_ARTIFACT_BYTES: u64 = 1 << 30;
/// Most root rotations walked in one refresh.
const MAX_ROOT_STEPS: u64 = 64;

const TRUST_FILE: &str = "trust.json";
const STATUS_FILE: &str = "status.json";
const LOCK_FILE: &str = "mirror.lock";

#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("the update root of trust is not a valid signed root: {0}")]
    BadRoot(#[source] UpdateError),
    #[error("{0}")]
    Verify(#[from] UpdateError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("upstream has no {0}")]
    Missing(&'static str),
    #[error("another refresh or import is running")]
    Busy,
    #[error("I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("background fetch failed: {0}")]
    Task(String),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> MirrorError + '_ {
    move |source| MirrorError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Which listed artifacts a refresh copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefetch {
    /// What the channel selects for each kind/platform/arch (online
    /// mirrors; anything else is fetched on demand).
    Selected,
    /// Everything listed (air-gapped imports, which have no "on demand").
    All,
}

/// The verified documents currently served.
#[derive(Debug)]
pub struct Served {
    pub timestamp: Bytes,
    pub targets: Bytes,
    /// Root rotations the mirror holds, by version.
    pub roots: BTreeMap<u64, Bytes>,
    /// The mirror's trusted root version.
    pub root_version: u64,
    verified: VerifiedTargets,
}

impl Served {
    /// A listed artifact clients may download (never `kind = server`).
    pub fn client_target(&self, name: &str) -> Option<TargetInfo> {
        self.verified
            .get(name)
            .filter(|t| t.custom.kind != TargetKind::Server)
    }
}

/// One cached artifact, for status output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedArtifact {
    pub name: String,
    pub kind: TargetKind,
    pub platform: String,
    pub arch: String,
    pub version: String,
    pub length: u64,
}

/// The outcome of the latest refresh, written to `status.json` for
/// `faro-server doctor` and `faro-server updates status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MirrorStatus {
    /// The upstream URL or import directory.
    pub source: Option<String>,
    pub last_attempt_ms: Option<i64>,
    pub last_success_ms: Option<i64>,
    /// Why the latest attempt failed (`None` if it succeeded).
    pub last_error: Option<String>,
    pub root_version: Option<u64>,
    pub timestamp_version: Option<u64>,
    pub timestamp_expires_ms: Option<i64>,
    pub targets_version: Option<u64>,
    pub targets_expires_ms: Option<i64>,
    /// Listed artifacts the mirror holds.
    pub cached: Vec<CachedArtifact>,
    /// Artifacts the latest refresh meant to copy but couldn't, with why.
    pub failed: Vec<String>,
}

/// The mirror. Shared by every request through [`crate::AppState`].
#[derive(Debug)]
pub struct Mirror {
    dir: PathBuf,
    /// The configured root envelope (`updates.root`).
    root: Vec<u8>,
    upstream: Option<Upstream>,
    served: RwLock<Option<Arc<Served>>>,
    /// One download per artifact at a time.
    fetches: KeyedLocks,
    /// One refresh per process at a time (the file lock covers processes).
    refreshing: tokio::sync::Mutex<()>,
}

impl Mirror {
    /// Open the mirror in `dir` with the project root `root_envelope`.
    /// Fails if the root isn't a validly self-signed root document.
    pub fn open(
        dir: PathBuf,
        root_envelope: Vec<u8>,
        upstream: Option<Upstream>,
    ) -> Result<Self, MirrorError> {
        Updater::bootstrap(&root_envelope).map_err(MirrorError::BadRoot)?;
        for sub in ["meta/roots", "artifacts", "tmp"] {
            let p = dir.join(sub);
            std::fs::create_dir_all(&p).map_err(io_err(&p))?;
        }
        Ok(Mirror {
            dir,
            root: root_envelope,
            upstream,
            served: RwLock::new(None),
            fetches: KeyedLocks::default(),
            refreshing: tokio::sync::Mutex::new(()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn upstream(&self) -> Option<&Upstream> {
        self.upstream.as_ref()
    }

    /// What is served right now, if anything.
    pub fn served(&self) -> Option<Arc<Served>> {
        self.served
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_served(&self, s: Option<Arc<Served>>) {
        *self.served.write().unwrap_or_else(|p| p.into_inner()) = s;
    }

    /// The trust state on disk, or the configured root when there is none
    /// (or when the configured root is newer than the stored one, or a
    /// different root of the same version: the admin installed a new root
    /// file, which wins).
    fn load_trust(&self) -> Result<Updater, MirrorError> {
        let configured = Updater::bootstrap(&self.root).map_err(MirrorError::BadRoot)?;
        let path = self.dir.join(TRUST_FILE);
        let stored = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice::<TrustedState>(&b) {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(error = %e, "ignoring unreadable update trust state");
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_err(&path)(e)),
        };
        let Some(stored) = stored else {
            return Ok(configured);
        };
        let (have, want) = (stored.root().version, configured.state().root().version);
        if have < want
            || (have == want
                && stored.root_payload_hash() != configured.state().root_payload_hash())
        {
            tracing::info!(
                stored = have,
                configured = want,
                "starting update trust from the configured root"
            );
            return Ok(configured);
        }
        Ok(Updater::from_state(stored))
    }

    fn save_trust(&self, u: &Updater) -> Result<(), MirrorError> {
        let bytes = serde_json::to_vec_pretty(u.state())
            .map_err(|e| MirrorError::Task(format!("cannot serialize trust state: {e}")))?;
        write_atomic(&self.dir.join(TRUST_FILE), &bytes)
    }

    /// Re-read the served documents from disk and re-verify them against
    /// the stored trust state at `now_ms`. Serves nothing if they are
    /// missing, or no longer verify (expired: clients would refuse them
    /// anyway). Returns whether anything is served.
    pub fn reload(&self, now_ms: i64) -> Result<bool, MirrorError> {
        let served = self.load_served(now_ms)?;
        let any = served.is_some();
        self.set_served(served.map(Arc::new));
        Ok(any)
    }

    fn load_served(&self, now_ms: i64) -> Result<Option<Served>, MirrorError> {
        let meta = self.dir.join("meta");
        let (Some(ts), Some(tg)) = (
            read_optional(&meta.join("timestamp.json"))?,
            read_optional(&meta.join("targets.json"))?,
        ) else {
            return Ok(None);
        };
        // Verifying the same documents again against the state that
        // accepted them is idempotent; the scratch copy is not persisted.
        let mut u = self.load_trust()?;
        let verified = match u
            .verify_timestamp(&ts, now_ms)
            .and_then(|_| u.verify_targets(&tg, now_ms))
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "stored update metadata no longer verifies; serving none");
                return Ok(None);
            }
        };
        Ok(Some(Served {
            timestamp: Bytes::from(ts),
            targets: Bytes::from(tg),
            roots: self.read_roots()?,
            root_version: u.state().root().version,
            verified,
        }))
    }

    fn read_roots(&self) -> Result<BTreeMap<u64, Bytes>, MirrorError> {
        let dir = self.dir.join("meta/roots");
        let mut out = BTreeMap::new();
        for entry in std::fs::read_dir(&dir).map_err(io_err(&dir))? {
            let entry = entry.map_err(io_err(&dir))?;
            let name = entry.file_name();
            let Some(n) = name
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                .and_then(|s| s.parse::<u64>().ok())
            else {
                continue;
            };
            let bytes = std::fs::read(entry.path()).map_err(io_err(&entry.path()))?;
            out.insert(n, Bytes::from(bytes));
        }
        Ok(out)
    }

    /// One refresh from the configured upstream (the periodic worker).
    /// Without an upstream this only re-reads what an import left on disk.
    pub async fn refresh(
        &self,
        now_ms: i64,
        channel: &Channel,
    ) -> Result<MirrorStatus, MirrorError> {
        match self.upstream.clone() {
            Some(up) => {
                self.refresh_from(&up, now_ms, channel, Prefetch::Selected)
                    .await
            }
            None => {
                self.reload(now_ms)?;
                Ok(self.read_status())
            }
        }
    }

    /// Refresh from `upstream`, record the outcome in `status.json` and,
    /// on success, serve the result.
    pub async fn refresh_from(
        &self,
        upstream: &Upstream,
        now_ms: i64,
        channel: &Channel,
        prefetch: Prefetch,
    ) -> Result<MirrorStatus, MirrorError> {
        let _one = self.refreshing.lock().await;
        let lock = self.try_lock_file()?;
        let mut status = self.read_status();
        status.source = Some(upstream.describe());
        status.last_attempt_ms = Some(now_ms);
        let result = self
            .refresh_locked(upstream, now_ms, channel, prefetch)
            .await;
        match &result {
            Ok((served, failed)) => {
                status.last_success_ms = Some(now_ms);
                status.last_error = None;
                status.failed = failed.clone();
                status.cached = self.cached_artifacts(&served.verified);
                self.set_served(Some(served.clone()));
            }
            Err(e) => status.last_error = Some(e.to_string()),
        }
        if let Ok(u) = self.load_trust() {
            let st = u.state();
            status.root_version = Some(st.root().version);
            status.timestamp_version = st.timestamp().map(|t| t.version);
            status.timestamp_expires_ms = st.timestamp().map(|t| t.expires_ms);
            status.targets_version = st.targets().map(|t| t.version);
            status.targets_expires_ms = st.targets().map(|t| t.expires_ms);
        }
        if let Err(e) = write_atomic(
            &self.dir.join(STATUS_FILE),
            &serde_json::to_vec_pretty(&status).unwrap_or_default(),
        ) {
            tracing::warn!(error = %e, "cannot record update mirror status");
        }
        drop(lock);
        result.map(|_| status)
    }

    async fn refresh_locked(
        &self,
        upstream: &Upstream,
        now_ms: i64,
        channel: &Channel,
        prefetch: Prefetch,
    ) -> Result<(Arc<Served>, Vec<String>), MirrorError> {
        let mut u = self.load_trust()?;
        let outcome = self
            .verify_from(upstream, &mut u, now_ms, channel, prefetch)
            .await;
        // Persist even on failure: a rejected document can still have
        // raised the observed-time mark (faro_update::TrustedState).
        self.save_trust(&u)?;
        outcome
    }

    async fn verify_from(
        &self,
        upstream: &Upstream,
        u: &mut Updater,
        now_ms: i64,
        channel: &Channel,
        prefetch: Prefetch,
    ) -> Result<(Arc<Served>, Vec<String>), MirrorError> {
        // 1. Root rotations.
        for _ in 0..MAX_ROOT_STEPS {
            let next = u.state().root().version + 1;
            let path = format!("roots/{next}.json");
            let Some(bytes) = upstream.get_meta(&path, MAX_ROOT_BYTES).await? else {
                break;
            };
            u.update_root(&bytes)?;
            write_atomic(&self.dir.join("meta").join(&path), &bytes)?;
            tracing::info!(version = next, "update root rotated");
        }

        // 2. Timestamp.
        let ts_bytes = upstream
            .get_meta("timestamp.json", MAX_TIMESTAMP_BYTES)
            .await?
            .ok_or(MirrorError::Missing("timestamp.json"))?;
        let ts = u.verify_timestamp(&ts_bytes, now_ms)?;

        // 3. The targets it commits to: reuse ours if it is the same file.
        let local = self.dir.join("meta/targets.json");
        let committed = ts.targets_meta;
        let tg_bytes = match read_optional(&local)? {
            Some(b) if TargetsMeta::describe(&b, committed.version) == committed => b,
            _ => upstream
                .get_meta("targets.json", MAX_TARGETS_BYTES)
                .await?
                .ok_or(MirrorError::Missing("targets.json"))?,
        };
        let verified = u.verify_targets(&tg_bytes, now_ms)?;

        // 4. Artifacts, before the new documents are published, so clients
        //    following them find what they list.
        let wanted = match prefetch {
            Prefetch::Selected => selected_targets(&verified, channel),
            Prefetch::All => verified
                .iter()
                .filter(|t| t.custom.kind != TargetKind::Server)
                .collect(),
        };
        let mut failed = Vec::new();
        for info in &wanted {
            match self.ensure_cached(upstream, info).await {
                Ok(true) => {}
                Ok(false) => failed.push(format!("{}: not found upstream", info.name)),
                Err(e) => {
                    tracing::warn!(target = %info.name, error = %e, "could not mirror artifact");
                    failed.push(format!("{}: {e}", info.name));
                }
            }
        }

        // 5. Publish and tidy up.
        write_atomic(&self.dir.join("meta/timestamp.json"), &ts_bytes)?;
        write_atomic(&local, &tg_bytes)?;
        self.collect_garbage(&verified);

        let served = Arc::new(Served {
            timestamp: Bytes::from(ts_bytes),
            targets: Bytes::from(tg_bytes),
            roots: self.read_roots()?,
            root_version: u.state().root().version,
            verified,
        });
        Ok((served, failed))
    }

    fn artifact_path(&self, hash: &Hash32) -> PathBuf {
        self.dir
            .join("artifacts")
            .join(hex::encode(hash.as_bytes()))
    }

    /// Make sure `info` is in the cache, fetching it from `upstream` if
    /// not. `Ok(false)`: upstream doesn't have it.
    async fn ensure_cached(
        &self,
        upstream: &Upstream,
        info: &TargetInfo,
    ) -> Result<bool, MirrorError> {
        let path = self.artifact_path(&info.blake3);
        let _one = self.fetches.lock(&info.blake3.to_prefixed_hex()).await;
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(true);
        }
        let tmp = self.dir.join("tmp").join(format!(
            "{}.{}",
            hex::encode(info.blake3.as_bytes()),
            crate::tokens::new_hex_id()
        ));
        let fetched = upstream
            .fetch_artifact(info, MAX_ARTIFACT_BYTES, &tmp)
            .await;
        match fetched {
            Ok(true) => {
                tokio::fs::rename(&tmp, &path)
                    .await
                    .map_err(io_err(&path))?;
                tracing::info!(target = %info.name, bytes = info.length, "mirrored artifact");
                Ok(true)
            }
            Ok(false) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Ok(false)
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e.into())
            }
        }
    }

    /// The cached file for a served artifact, fetching it from upstream on
    /// first request. `None`: not listed, a server release, or not
    /// available (no upstream to fetch it from, or upstream lacks it).
    pub async fn artifact(self: &Arc<Self>, name: &str) -> Result<Option<PathBuf>, MirrorError> {
        let Some(info) = self.served().and_then(|s| s.client_target(name)) else {
            return Ok(None);
        };
        let path = self.artifact_path(&info.blake3);
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(Some(path));
        }
        let Some(up) = self.upstream.clone() else {
            return Ok(None);
        };
        // A task of its own, so a client that gives up doesn't abort a
        // download the next client will want.
        let me = self.clone();
        let task = tokio::spawn(async move { me.ensure_cached(&up, &info).await });
        match task.await {
            Ok(Ok(true)) => Ok(Some(path)),
            Ok(Ok(false)) => Ok(None),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(MirrorError::Task(e.to_string())),
        }
    }

    /// Delete cached artifacts `verified` no longer lists, and leftovers of
    /// interrupted downloads. Best effort.
    fn collect_garbage(&self, verified: &VerifiedTargets) {
        let keep: BTreeSet<String> = verified
            .iter()
            .map(|t| hex::encode(t.blake3.as_bytes()))
            .collect();
        if let Ok(entries) = std::fs::read_dir(self.dir.join("artifacts")) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if !keep.contains(&name) {
                    tracing::info!(artifact = %name, "removing artifact no longer listed");
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        // Only this process's refresh holds the lock, but a lazy download
        // in another process may be writing to tmp: leave anything recent.
        if let Ok(entries) = std::fs::read_dir(self.dir.join("tmp")) {
            for e in entries.flatten() {
                let old = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > 24 * 3600);
                if old {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }

    fn cached_artifacts(&self, verified: &VerifiedTargets) -> Vec<CachedArtifact> {
        verified
            .iter()
            .filter(|t| self.artifact_path(&t.blake3).exists())
            .map(|t| CachedArtifact {
                name: t.name,
                kind: t.custom.kind,
                platform: t.custom.platform,
                arch: t.custom.arch,
                version: t.custom.version.to_string(),
                length: t.length,
            })
            .collect()
    }

    /// The latest recorded status (default if none was recorded yet).
    pub fn read_status(&self) -> MirrorStatus {
        read_status(&self.dir)
    }

    fn try_lock_file(&self) -> Result<std::fs::File, MirrorError> {
        let path = self.dir.join(LOCK_FILE);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(io_err(&path))?;
        match f.try_lock() {
            Ok(()) => Ok(f),
            Err(std::fs::TryLockError::WouldBlock) => Err(MirrorError::Busy),
            Err(std::fs::TryLockError::Error(e)) => Err(io_err(&path)(e)),
        }
    }
}

/// The status recorded in a mirror directory, without opening the mirror
/// (for `doctor`, which must not create anything).
pub fn read_status(dir: &Path) -> MirrorStatus {
    std::fs::read(dir.join(STATUS_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// For each kind/platform/arch combination listed (servers excluded), what
/// `channel` selects for a client with nothing installed and no OS limit.
pub fn selected_targets(verified: &VerifiedTargets, channel: &Channel) -> Vec<TargetInfo> {
    let combos: BTreeSet<(TargetKind, String, String)> = verified
        .iter()
        .filter(|t| t.custom.kind != TargetKind::Server)
        .map(|t| (t.custom.kind, t.custom.platform, t.custom.arch))
        .collect();
    let mut out: BTreeMap<String, TargetInfo> = BTreeMap::new();
    for (kind, platform, arch) in &combos {
        let pick = verified.select_with(&Selection {
            channel,
            kind: *kind,
            platform,
            arch,
            current_version: None,
            os_version: None,
            allow_downgrade: false,
        });
        if let Some(t) = pick {
            out.insert(t.name.clone(), t);
        }
    }
    out.into_values().collect()
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, MirrorError> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

/// Replace `path` with `bytes` so that readers see the old or the new
/// file, never a mix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), MirrorError> {
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(io_err(parent))?;
    let tmp = parent.join(format!(
        ".{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        crate::tokens::new_hex_id()
    ));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        io_err(path)(e)
    })
}
