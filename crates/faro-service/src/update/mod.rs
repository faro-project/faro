//! Client self-update (ARCHITECTURE.md §3.8, PROTOCOL.md §8.2).
//!
//! The service asks *its instance* for updates and trusts only the
//! project. It holds the project's root of trust (shipped in the package,
//! `/Library/Faro/update-root.json` on macOS) and a persisted
//! [`TrustedState`] (`update-trust.json` in the state directory), and on
//! each [`ClientUpdater::check`]:
//!
//! 1. asks `GET /v1/updates` whether the instance has a release and which
//!    channel its admin chose;
//! 2. walks root rotations, then verifies the timestamp and the targets it
//!    commits to (retrying once if the mirror switched release between the
//!    two requests);
//! 3. selects a client package for this platform, arch and OS version in
//!    that channel, **never older than or equal to the running version**:
//!    the instance can hold a computer back, never move it back;
//! 4. downloads it with streaming verification against the signed length
//!    and BLAKE3;
//! 5. has the platform [`Installer`] check the package itself, and only
//!    then installs it. On macOS that is Faro's Developer ID signature and
//!    notarization ([`signature`]), then the version inside the package,
//!    which must be the target's and above the running one
//!    ([`package_version`]).
//!
//! The trust state is saved after every verification step, `Ok` or `Err`
//! (a rejected document can still raise the observed-time mark that stops
//! a rolled-back clock from reviving expired metadata).
//!
//! **Failed installs.** Before starting an install the updater records it
//! as pending (`update-attempts.json`). The next service start compares its
//! own version with the pending one. If the install didn't take, that
//! package counts one failure, and after [`MAX_INSTALL_ATTEMPTS`] it is
//! skipped until the project publishes another. A failing package is
//! never retried in a loop.
//!
//! **Rejected packages.** A package that fails the package check with
//! positive evidence that it isn't what the metadata says (not Faro's, or
//! another version than the target's) is recorded in `rejected` in
//! `update-attempts.json` and never retried. The check that rejects it
//! returns [`Outcome::Rejected`], and later checks that select it again
//! return [`Outcome::PreviouslyRejected`] with the same reason, so the
//! service can raise a tamper-class integrity failure (once per start: a
//! report lost before activation is made again). Nothing is installed and no install is recorded as
//! pending. A check that can't conclude installs nothing and is tried
//! again at the next check.
//!
//! **Who installs.** Only a packaged, root-run service has an installer
//! ([`install::platform_installer`]). Anywhere else (a development build,
//! Linux, where packages will come from the project's repository) the
//! updater still checks and logs what is available, but installs nothing.

pub mod artifacts;
pub mod fetch;
pub mod install;
pub mod package_version;
pub mod signature;

use crate::state::{StateDir, StateError};
use faro_core::clock::Clock;
use faro_proto::Hash32;
use faro_update::metadata::{MAX_ROOT_BYTES, MAX_TARGETS_BYTES, MAX_TIMESTAMP_BYTES};
use faro_update::{
    Channel, Selection, TargetInfo, TargetKind, TrustedState, UpdateError, Updater, Version,
};
use fetch::{FetchError, UpdateFetcher};
use install::{InstallError, Installer};
use serde::{Deserialize, Serialize};
use signature::PackageCheckError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The persisted [`TrustedState`].
pub const TRUST_FILE: &str = "update-trust.json";
/// Pending install and failure counts ([`Attempts`]).
pub const ATTEMPTS_FILE: &str = "update-attempts.json";
/// Downloaded packages, in the state directory.
pub const DOWNLOAD_DIR: &str = "updates";
/// Largest package accepted.
pub const MAX_PACKAGE_BYTES: u64 = 1 << 30;
/// Failed installs of one package before it is skipped.
pub const MAX_INSTALL_ATTEMPTS: u32 = 3;
/// A pending install younger than this may still be running.
pub const PENDING_GRACE_MS: i64 = 30 * 60 * 1000;
/// Most root rotations walked in one check.
const MAX_ROOT_STEPS: u64 = 64;

#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error("the update root of trust is not a valid signed root: {0}")]
    BadRoot(#[source] UpdateError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("update metadata rejected: {0}")]
    Verify(#[from] UpdateError),
    #[error("the instance's mirror has no {0}")]
    Missing(&'static str),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Install(#[from] InstallError),
    /// The package's own check (its signature or the version inside it)
    /// couldn't conclude (never a rejection: that is
    /// [`Outcome::Rejected`]).
    #[error(transparent)]
    Package(PackageCheckError),
    #[error("cannot manage downloads in {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// What this computer is, for target selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSpec {
    /// `macos`, `windows` or `linux`.
    pub platform: String,
    /// `aarch64`, `x86_64`, ...
    pub arch: String,
    /// The running OS version; `None` skips `min_os` checks.
    pub os_version: Option<Version>,
    /// The running client version.
    pub installed: Version,
}

impl ClientSpec {
    /// This computer and this build.
    pub fn this_machine() -> Self {
        ClientSpec {
            platform: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            os_version: os_version(),
            installed: Version::parse(env!("CARGO_PKG_VERSION"))
                .unwrap_or_else(|_| Version::new(0, 0, 0)),
        }
    }
}

/// The macOS product version (`kern.osproductversion`, e.g. `14.6.1`).
#[cfg(target_os = "macos")]
fn os_version() -> Option<Version> {
    let name = c"kern.osproductversion";
    let mut buf = [0u8; 64];
    let mut len = buf.len();
    // SAFETY: `name` is NUL-terminated; `buf`/`len` describe a writable
    // buffer of `len` bytes; no new value is set.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..len.min(buf.len())]).ok()?;
    faro_update::metadata::parse_os_version(s.trim_end_matches('\0').trim())
}

#[cfg(not(target_os = "macos"))]
fn os_version() -> Option<Version> {
    None
}

/// An install that was started and not yet confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub name: String,
    pub version: String,
    pub blake3: Hash32,
    /// The version that was running when it started.
    pub from_version: String,
    pub started_ms: i64,
}

/// `update-attempts.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Attempts {
    pub pending: Option<Pending>,
    /// Failed installs by package BLAKE3 (`b3:…`).
    pub failures: BTreeMap<String, u32>,
    /// Packages the package check rejected, by BLAKE3, with the
    /// reason. Never retried.
    pub rejected: BTreeMap<String, String>,
}

/// The result of a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The instance has no verified release to offer (its mirror is off or
    /// hasn't refreshed yet).
    Unavailable,
    /// Nothing newer for this computer in the instance's channel.
    UpToDate,
    /// A newer release exists, but this service can't install it (not a
    /// packaged install, or a platform that doesn't self-update).
    NotInstallable { version: Version },
    /// That package already failed [`MAX_INSTALL_ATTEMPTS`] times.
    GaveUp { version: Version },
    /// An install started less than [`PENDING_GRACE_MS`] ago.
    InstallPending { version: String },
    /// The install of `version` has started.
    Installing { version: Version },
    /// The package for `version` failed its package check just now (its
    /// signature, or the version inside it): not installed, and never
    /// retried. Report it as tamper.
    Rejected { version: Version, reason: String },
    /// That package was rejected by an earlier check, for `reason`.
    PreviouslyRejected { version: Version, reason: String },
}

/// What happened to the previous install, judged at service start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// Now running `version`.
    Installed { version: String },
    /// Still on the old version; that package has failed `failures` times.
    Failed { version: String, failures: u32 },
}

/// Checks the instance's mirror and installs client updates. See the
/// module docs.
pub struct ClientUpdater {
    dir: StateDir,
    root: Vec<u8>,
    fetch: UpdateFetcher,
    clock: Arc<dyn Clock>,
    spec: ClientSpec,
    installer: Option<Arc<dyn Installer>>,
    /// The channel the instance named at the last check (for the status).
    last_channel: std::sync::Mutex<Option<String>>,
}

impl std::fmt::Debug for ClientUpdater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientUpdater")
            .field("dir", &self.dir)
            .field("fetch", &self.fetch)
            .field("spec", &self.spec)
            .field("installer", &self.installer)
            .finish_non_exhaustive()
    }
}

impl ClientUpdater {
    /// `root` is the project's root envelope. Fails if it isn't a validly
    /// self-signed root.
    pub fn new(
        dir: StateDir,
        root: Vec<u8>,
        fetch: UpdateFetcher,
        clock: Arc<dyn Clock>,
        spec: ClientSpec,
        installer: Option<Arc<dyn Installer>>,
    ) -> Result<Self, CheckError> {
        Updater::bootstrap(&root).map_err(CheckError::BadRoot)?;
        Ok(ClientUpdater {
            dir,
            root,
            fetch,
            clock,
            spec,
            installer,
            last_channel: std::sync::Mutex::new(None),
        })
    }

    pub fn spec(&self) -> &ClientSpec {
        &self.spec
    }

    /// The clock checks are timed with.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// The channel the instance named at the last check that reached its
    /// update information.
    pub fn last_channel(&self) -> Option<String> {
        self.last_channel.lock().ok()?.clone()
    }

    /// The recorded attempts.
    pub fn attempts(&self) -> Result<Attempts, CheckError> {
        Ok(self.dir.read_json(ATTEMPTS_FILE)?.unwrap_or_default())
    }

    fn save_attempts(&self, a: &Attempts) -> Result<(), CheckError> {
        Ok(self.dir.write_json(ATTEMPTS_FILE, a)?)
    }

    /// The trust state: stored, or the shipped root when there is none or
    /// the shipped root is newer (an upgrade brought a rotated root) or
    /// differs at the same version.
    fn load_trust(&self) -> Result<Updater, CheckError> {
        let shipped = Updater::bootstrap(&self.root).map_err(CheckError::BadRoot)?;
        let stored: Option<TrustedState> = match self.dir.read_json(TRUST_FILE) {
            Ok(s) => s,
            Err(StateError::Corrupt { .. }) => {
                tracing::warn!("ignoring unreadable update trust state");
                None
            }
            Err(e) => return Err(e.into()),
        };
        let Some(stored) = stored else {
            return Ok(shipped);
        };
        let (have, want) = (stored.root().version, shipped.state().root().version);
        if have < want
            || (have == want && stored.root_payload_hash() != shipped.state().root_payload_hash())
        {
            return Ok(shipped);
        }
        Ok(Updater::from_state(stored))
    }

    fn save_trust(&self, u: &Updater) -> Result<(), CheckError> {
        Ok(self.dir.write_json(TRUST_FILE, u.state())?)
    }

    /// At service start: judge the install recorded as pending, if any.
    /// Too recent to judge (it may still be running): left pending.
    pub fn settle_pending(&self) -> Result<Option<Settled>, CheckError> {
        let mut a = self.attempts()?;
        let Some(p) = a.pending.clone() else {
            return Ok(None);
        };
        let target = Version::parse(&p.version).ok();
        let now = self.clock.wall_ms();
        let settled = if target.as_ref().is_some_and(|t| self.spec.installed >= *t) {
            a.failures.remove(&p.blake3.to_prefixed_hex());
            tracing::info!(version = %p.version, from = %p.from_version, "update installed");
            Settled::Installed { version: p.version }
        } else if now.saturating_sub(p.started_ms) < PENDING_GRACE_MS && now >= p.started_ms {
            return Ok(None);
        } else {
            let n = a.failures.entry(p.blake3.to_prefixed_hex()).or_insert(0);
            *n += 1;
            tracing::warn!(
                version = %p.version,
                failures = *n,
                "the update did not install; still running {}",
                self.spec.installed
            );
            Settled::Failed {
                version: p.version,
                failures: *n,
            }
        };
        a.pending = None;
        self.save_attempts(&a)?;
        Ok(Some(settled))
    }

    /// One check; see the module docs.
    pub async fn check(&self) -> Result<Outcome, CheckError> {
        if let Some(inst) = &self.installer {
            inst.cleanup();
        }
        self.settle_pending()?;
        if let Some(p) = self.attempts()?.pending {
            return Ok(Outcome::InstallPending { version: p.version });
        }

        let Some(info) = self.fetch.info().await?.filter(|i| i.available) else {
            return Ok(Outcome::Unavailable);
        };
        let channel = info.channel.parse::<Channel>().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "the instance names an invalid channel; using stable");
            Channel::stable()
        });
        if let Ok(mut c) = self.last_channel.lock() {
            *c = Some(channel.to_string());
        }

        let mut u = self.load_trust()?;
        let verified = {
            let r = self.verify(&mut u).await;
            self.save_trust(&u)?;
            r?
        };

        let Some(target) = verified.select_with(&Selection {
            channel: &channel,
            kind: TargetKind::Client,
            platform: &self.spec.platform,
            arch: &self.spec.arch,
            current_version: Some(&self.spec.installed),
            os_version: self.spec.os_version.as_ref(),
            allow_downgrade: false,
        }) else {
            return Ok(Outcome::UpToDate);
        };
        let version = target.custom.version.clone();
        let failures = self
            .attempts()?
            .failures
            .get(&target.blake3.to_prefixed_hex())
            .copied()
            .unwrap_or(0);
        if failures >= MAX_INSTALL_ATTEMPTS {
            return Ok(Outcome::GaveUp { version });
        }
        let Some(installer) = &self.installer else {
            tracing::info!(%version, "an update is available; this service doesn't install updates");
            return Ok(Outcome::NotInstallable { version });
        };
        let key = target.blake3.to_prefixed_hex();
        if let Some(reason) = self.attempts()?.rejected.get(&key).cloned() {
            return Ok(Outcome::PreviouslyRejected { version, reason });
        }

        let package = self.download(&target).await?;
        let checked = {
            let (i, p, t) = (installer.clone(), package.clone(), target.clone());
            let installed = self.spec.installed.clone();
            tokio::task::spawn_blocking(move || i.check_package(&p, &t, &installed))
                .await
                .unwrap_or_else(|e| {
                    Err(PackageCheckError::Unconfirmed(format!(
                        "the check did not finish: {e}"
                    )))
                })
        };
        match checked {
            Ok(()) => {}
            Err(PackageCheckError::Rejected(reason)) => {
                tracing::error!(
                    %version,
                    %reason,
                    package = %package.display(),
                    "refusing the update package; kept for inspection"
                );
                let mut a = self.attempts()?;
                a.rejected.insert(key, reason.clone());
                self.save_attempts(&a)?;
                return Ok(Outcome::Rejected { version, reason });
            }
            Err(e) => return Err(CheckError::Package(e)),
        }
        let mut a = self.attempts()?;
        a.pending = Some(Pending {
            name: target.name.clone(),
            version: version.to_string(),
            blake3: target.blake3,
            from_version: self.spec.installed.to_string(),
            started_ms: self.clock.wall_ms(),
        });
        self.save_attempts(&a)?;
        tracing::info!(%version, from = %self.spec.installed, "installing update");
        if let Err(e) = installer.install(&package, &target) {
            a.pending = None;
            *a.failures.entry(key).or_insert(0) += 1;
            self.save_attempts(&a)?;
            return Err(e.into());
        }
        Ok(Outcome::Installing { version })
    }

    /// Roots, timestamp, targets. One retry if the mirror switched release
    /// between the timestamp and the targets.
    async fn verify(&self, u: &mut Updater) -> Result<faro_update::VerifiedTargets, CheckError> {
        for _ in 0..MAX_ROOT_STEPS {
            let next = u.state().root().version + 1;
            let Some(bytes) = self
                .fetch
                .meta(&format!("roots/{next}.json"), MAX_ROOT_BYTES)
                .await?
            else {
                break;
            };
            u.update_root(&bytes)?;
            self.save_trust(u)?;
            tracing::info!(version = next, "update root rotated");
        }
        let mut retried = false;
        loop {
            let now = self.clock.wall_ms();
            let ts = self
                .fetch
                .meta("timestamp.json", MAX_TIMESTAMP_BYTES)
                .await?
                .ok_or(CheckError::Missing("timestamp.json"))?;
            u.verify_timestamp(&ts, now)?;
            self.save_trust(u)?;
            let tg = self
                .fetch
                .meta("targets.json", MAX_TARGETS_BYTES)
                .await?
                .ok_or(CheckError::Missing("targets.json"))?;
            match u.verify_targets(&tg, now) {
                Err(UpdateError::TimestampMismatch(_)) if !retried => {
                    retried = true;
                    self.save_trust(u)?;
                }
                r => return Ok(r?),
            }
        }
    }

    /// The verified package on disk, downloading it unless an earlier
    /// download still verifies. Other downloads are removed.
    async fn download(&self, target: &TargetInfo) -> Result<PathBuf, CheckError> {
        let dir = self.dir.path().join(DOWNLOAD_DIR);
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| CheckError::Io { path, source }
        };
        create_private_dir(&dir).map_err(io(&dir))?;
        let file = dir.join(package_file_name(target));
        for entry in std::fs::read_dir(&dir).map_err(io(&dir))?.flatten() {
            if entry.path() != file {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        if file.exists() {
            let (f, t) = (file.clone(), target.clone());
            let ok = tokio::task::spawn_blocking(move || {
                std::fs::File::open(&f).ok().is_some_and(|r| {
                    faro_update::verify_target_stream(
                        std::io::BufReader::new(r),
                        &t,
                        MAX_PACKAGE_BYTES,
                    )
                    .is_ok()
                })
            })
            .await
            .unwrap_or(false);
            if ok {
                return Ok(file);
            }
            let _ = std::fs::remove_file(&file);
        }
        let partial = file.with_extension("partial");
        let _ = std::fs::remove_file(&partial);
        tracing::info!(version = %target.custom.version, bytes = target.length, "downloading update");
        match self
            .fetch
            .artifact(target, MAX_PACKAGE_BYTES, &partial)
            .await
        {
            Ok(true) => {
                std::fs::rename(&partial, &file).map_err(io(&file))?;
                Ok(file)
            }
            Ok(false) => {
                let _ = std::fs::remove_file(&partial);
                Err(CheckError::Missing("package"))
            }
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                Err(e.into())
            }
        }
    }
}

/// `<blake3 hex>.<ext>`, keeping a safe extension from the target name
/// (`installer` cares about `.pkg`).
fn package_file_name(t: &TargetInfo) -> String {
    let hex = hex::encode(t.blake3.as_bytes());
    let ext = Path::new(&t.name)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| (1..=8).contains(&e.len()) && e.bytes().all(|b| b.is_ascii_alphanumeric()));
    match ext {
        Some(e) => format!("{hex}.{e}"),
        None => hex,
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}
