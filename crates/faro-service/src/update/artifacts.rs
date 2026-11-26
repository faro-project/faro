//! Models and blocklists from the signed update channel (ARCHITECTURE.md
//! §3.8, PROTOCOL.md §8.2).
//!
//! The package ships an image model and a domain bundle. The
//! update channel can bring newer ones without a client release. They use
//! the same mirror and the same trust state as client updates
//! ([`ClientUpdater::check_artifacts`]), and each one is a data bundle
//! (`faro_update::bundle`): its manifest and the file it describes, in one
//! signed target.
//!
//! **Selection.** Kind `model` or `blocklist`, platform and arch `any` (or
//! this computer's), the instance's channel, `min_os`, and `min_client`
//! against the running client. A target is installed only if its version
//! is above the packaged copy's, above the one installed from the channel,
//! and not below the highest ever installed: models and blocklists never go
//! back. Models are fetched only by a build that can run them (ONNX
//! Runtime, [`ModelRuntime`]).
//!
//! **Install.** The bundle is downloaded by its signed length and BLAKE3,
//! unpacked into a staging directory in `artifacts/` in the state
//! directory, and checked exactly as the packaged copy is: models with
//! `faro_detect::load_model` (licence allowlist, attribution, BLAKE3 of the
//! weights) plus a version that matches the target, a label this client's
//! policy reads as explicit, and ONNX Runtime loading it; blocklists with
//! `faro_detect::load_domains`. Only then is the staging directory renamed
//! into place, the notice written, and the record (`update-artifacts.json`)
//! switched to it. A bundle that fails these checks was signed but can't
//! be used: it is recorded as rejected, by BLAKE3, and never downloaded
//! again. Nothing else changes.
//!
//! **Hot swap.** The checked classifier or categorizer goes into [`Swaps`],
//! which the core takes between two captures and hands to the detector.
//! No frame is involved: the model is built from the files, not from
//! anything the screen showed, and nothing is written but the files above.
//!
//! **At start** ([`Artifacts::start`]) the installed copy is used if it is
//! newer than the packaged one and still matches what was installed. One
//! that doesn't (altered, removed) is an urgent `integrity_failure` and is
//! removed, so the packaged copy takes over and the next check installs it
//! again. One that is no newer than the packaged copy (the client was
//! updated since) is removed quietly.
//!
//! **Attribution.** Each installed artifact's notice (author, copyright,
//! source, licence, changes, and the licence texts) is written next to the
//! packaged notices (`/Library/Faro/notices` for the packaged service) as
//! [`MODEL_NOTICE`] or [`BLOCKLIST_NOTICE`], and removed when the artifact
//! is no longer in use.

use super::{CheckError, ClientUpdater};
use crate::model::{ModelLoad, ModelRuntime};
use crate::state::StateDir;
use faro_detect::{
    load_domains, load_model, Classifier, DetectError, DomainCategorizer, DomainsManifest,
    ModelInfo, PolicyConfig,
};
use faro_proto::body::TamperSignal;
use faro_proto::Hash32;
use faro_update::bundle::{read_bundle_manifest, BundleError};
use faro_update::{Channel, Selection, TargetInfo, TargetKind, VerifiedTargets, Version};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What is installed, in the state directory.
pub const RECORD_FILE: &str = "update-artifacts.json";
/// Installed artifacts, in the state directory.
pub const STORE_DIR: &str = "artifacts";
/// Largest data bundle accepted.
pub const MAX_DATA_BYTES: u64 = 512 << 20;
/// The notices of installed artifacts, next to the packaged ones.
pub const MODEL_NOTICE: &str = "update-model.txt";
pub const BLOCKLIST_NOTICE: &str = "update-blocklist.txt";
/// `integrity_failure` components for an installed artifact that no
/// longer matches what was installed. Fixed strings, never manifest text.
pub const MODEL_UPDATE_CHANGED: &str = "image model update (changed)";
pub const BLOCKLIST_UPDATE_CHANGED: &str = "domain list update (changed)";
/// A packaged domain bundle that is there but doesn't load.
pub const BLOCKLIST_CHANGED: &str = "domain list (changed)";
/// The packaged service's domain bundle is not there: the package ships
/// one, so it was removed.
pub const BLOCKLIST_MISSING: &str = "domain list (missing)";

const MODEL_MANIFEST_FILE: &str = "manifest.json";
const DOMAINS_MANIFEST_FILE: &str = "domains.manifest.json";
const DOWNLOADS: &str = "downloads";

/// One installed artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installed {
    /// The target it came from.
    pub name: String,
    pub version: String,
    /// The bundle's BLAKE3 (the target's).
    pub blake3: Hash32,
    /// The unpacked manifest's BLAKE3, checked at every start.
    pub manifest_blake3: Hash32,
}

/// What the channel installed for one kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Slot {
    /// In use (when newer than the packaged copy).
    pub current: Option<Installed>,
    /// The highest version ever installed. Never lowered: the channel
    /// never installs anything below it.
    pub highest: Option<String>,
    /// Bundles that were signed but failed the checks, by BLAKE3 (`b3:…`),
    /// with the reason. Never downloaded again.
    pub rejected: BTreeMap<String, String>,
}

/// `update-artifacts.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub model: Slot,
    pub blocklist: Slot,
}

impl Record {
    fn slot(&self, kind: TargetKind) -> &Slot {
        match kind {
            TargetKind::Model => &self.model,
            _ => &self.blocklist,
        }
    }

    fn slot_mut(&mut self, kind: TargetKind) -> &mut Slot {
        match kind {
            TargetKind::Model => &mut self.model,
            _ => &mut self.blocklist,
        }
    }
}

/// A new classifier or categorizer for the detector, with a label for the
/// service status (`opennsfw 1.1.0`, `domains 1.2.0`).
pub struct Swap<T> {
    pub value: T,
    pub label: String,
}

/// Handed from the update task to the core. The newest one wins.
#[derive(Default)]
pub struct Swaps {
    model: Mutex<Option<Swap<Box<dyn Classifier>>>>,
    blocklist: Mutex<Option<Swap<DomainCategorizer>>>,
}

impl std::fmt::Debug for Swaps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Swaps").finish_non_exhaustive()
    }
}

impl Swaps {
    pub fn take_model(&self) -> Option<Swap<Box<dyn Classifier>>> {
        self.model.lock().ok()?.take()
    }

    pub fn take_blocklist(&self) -> Option<Swap<DomainCategorizer>> {
        self.blocklist.lock().ok()?.take()
    }

    fn put_model(&self, s: Swap<Box<dyn Classifier>>) {
        if let Ok(mut m) = self.model.lock() {
            *m = Some(s);
        }
    }

    fn put_blocklist(&self, s: Swap<DomainCategorizer>) {
        if let Ok(mut m) = self.blocklist.lock() {
            *m = Some(s);
        }
    }
}

/// Where artifacts go and what this build can use.
#[derive(Debug, Clone)]
pub struct ArtifactConfig {
    /// The service's state directory.
    pub dir: StateDir,
    /// Where notices are written ([`default_notices_dir`]).
    pub notices: PathBuf,
    /// `None`: models are neither fetched nor used.
    pub runtime: Option<Arc<dyn ModelRuntime>>,
}

/// Whether this process is the packaged service, run from its installed
/// location.
pub fn is_packaged_service() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .is_some_and(|p| p == Path::new(faro_platform_macos::pkg_layout::SERVICE_PROGRAM))
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// The packaged service writes notices next to the packaged ones; any other
/// build into `notices/` in its state directory.
pub fn default_notices_dir(state_dir: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if is_packaged_service() {
            return PathBuf::from(faro_platform_macos::pkg_layout::NOTICES_DIR);
        }
    }
    state_dir.join("notices")
}

/// The packaged domain bundle's manifest, on platforms that have a place
/// for one.
pub fn packaged_domains_manifest() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(
            faro_platform_macos::pkg_layout::DOMAINS_MANIFEST,
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// A domain bundle the service starts with, from the package or a test.
pub struct PackagedDomains {
    pub categorizer: DomainCategorizer,
    /// `None` when it has no manifest (a test's): then any version from the
    /// channel is newer.
    pub version: Option<Version>,
}

/// Load the packaged domain bundle at `path`, if there is one. One that is
/// there but doesn't load is reported as tamper, and so is a missing one
/// when it is `required` (the packaged service: the package ships one).
pub fn load_packaged_domains(
    path: &Path,
    required: bool,
) -> (Option<PackagedDomains>, Option<TamperSignal>) {
    match load_domains(path) {
        Ok(l) => {
            tracing::info!(version = %l.manifest.version, domains = l.categorizer.len(), "domain list loaded");
            let version = Version::parse(&l.manifest.version).ok();
            (
                Some(PackagedDomains {
                    categorizer: l.categorizer,
                    version,
                }),
                None,
            )
        }
        Err(DetectError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            if required {
                tracing::error!(path = %path.display(), "the packaged domain list is missing");
                (None, Some(integrity(BLOCKLIST_MISSING)))
            } else {
                (None, None)
            }
        }
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "the packaged domain list does not load");
            (None, Some(integrity(BLOCKLIST_CHANGED)))
        }
    }
}

/// `faro-service domains-check`: load a domain bundle exactly as `run`
/// loads the packaged one ([`load_domains`]: the manifest, the licences and
/// attribution, the bundle's length, BLAKE3 and domain count). Prints the
/// bundle, then one line per source.
pub fn check_domains(manifest: &Path, out: &mut dyn Write) -> Result<(), DetectError> {
    let l = load_domains(manifest)?;
    let m = &l.manifest;
    let _ = writeln!(
        out,
        "domains      {} {} domains, blake3 {} verified",
        m.version,
        l.categorizer.len(),
        m.bundle.blake3
    );
    for s in &m.sources {
        let _ = writeln!(
            out,
            "source       {} {} {} {} domains",
            s.name, s.category, s.license, s.domains
        );
    }
    Ok(())
}

fn integrity(component: &str) -> TamperSignal {
    TamperSignal::IntegrityFailure {
        component: component.to_owned(),
    }
}

/// What the service starts with ([`Artifacts::start`]).
pub struct Start {
    pub classifier: Box<dyn Classifier>,
    pub domains: Option<DomainCategorizer>,
    /// For the service status.
    pub model_label: String,
    pub blocklist_label: Option<String>,
    /// The model and domain list in use came from the update channel, not
    /// the package (for the service status).
    pub model_from_channel: bool,
    pub blocklist_from_channel: bool,
    /// Integrity failures to report once the service runs.
    pub tamper: Vec<TamperSignal>,
    pub artifacts: Artifacts,
}

/// The update task's view of installed artifacts. See the module docs.
#[derive(Debug)]
pub struct Artifacts {
    cfg: ArtifactConfig,
    packaged_model: Option<Version>,
    packaged_blocklist: Option<Version>,
    swaps: Arc<Swaps>,
}

/// The outcome of checking one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactOutcome {
    /// Nothing newer that this client can use.
    UpToDate,
    /// Installed and handed to the detector.
    Installed { version: Version },
    /// Signed, but it failed the checks: not installed, never retried.
    Rejected { version: Version, reason: String },
    /// Rejected by an earlier check.
    PreviouslyRejected { version: Version, reason: String },
}

/// Why an unpacked bundle can't be used.
enum Refusal {
    /// The bundle itself is wrong: record it and never retry.
    Rejected(String),
    /// Something local failed (disk, permissions): try again later.
    Local(CheckError),
}

fn local(path: &Path) -> impl FnOnce(std::io::Error) -> Refusal + '_ {
    move |source| {
        Refusal::Local(CheckError::Io {
            path: path.to_owned(),
            source,
        })
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> CheckError + '_ {
    move |source| CheckError::Io {
        path: path.to_owned(),
        source,
    }
}

/// An error from `load_model` / `load_domains` on files this service just
/// wrote: reading them is local, anything else is the bundle's fault.
fn refusal(e: DetectError) -> Refusal {
    match e {
        DetectError::Io { path, source } => Refusal::Local(CheckError::Io { path, source }),
        e => Refusal::Rejected(e.to_string()),
    }
}

/// A checked artifact, ready to swap in.
enum Ready {
    Model(Box<dyn Classifier>, String),
    Blocklist(DomainCategorizer, String),
}

impl Artifacts {
    /// At service start: the classifier and domain bundle to use, between
    /// the packaged copies and those installed from the channel. See the
    /// module docs.
    pub fn start(
        cfg: ArtifactConfig,
        packaged_model: ModelLoad,
        packaged_domains: Option<PackagedDomains>,
    ) -> Start {
        let mut tamper: Vec<TamperSignal> = packaged_model.tamper.into_iter().collect();
        let mut record = read_record(&cfg.dir);
        let before = record.clone();
        let packaged_model_version = (packaged_model.classifier.info().name != "null")
            .then(|| Version::parse(&packaged_model.classifier.info().version).ok())
            .flatten();
        let packaged_blocklist_version = packaged_domains.as_ref().and_then(|d| d.version.clone());
        let a = Artifacts {
            cfg,
            packaged_model: packaged_model_version,
            packaged_blocklist: packaged_blocklist_version,
            swaps: Arc::new(Swaps::default()),
        };

        let mut classifier = packaged_model.classifier;
        let mut domains = packaged_domains.map(|d| d.categorizer);
        let mut blocklist_label = domains.as_ref().map(|_| match &a.packaged_blocklist {
            Some(v) => format!("domains {v}"),
            None => "domains".to_owned(),
        });
        let (mut model_from_channel, mut blocklist_from_channel) = (false, false);
        for kind in [TargetKind::Model, TargetKind::Blocklist] {
            match a.start_one(&mut record, kind, &mut tamper) {
                Some(Ready::Model(c, _)) => {
                    classifier = c;
                    model_from_channel = true;
                }
                Some(Ready::Blocklist(d, label)) => {
                    domains = Some(d);
                    blocklist_label = Some(label);
                    blocklist_from_channel = true;
                }
                None => {}
            }
        }
        if record != before {
            if let Err(e) = a.cfg.dir.write_json(RECORD_FILE, &record) {
                tracing::warn!(error = %e, "cannot update the installed-artifacts record");
            }
        }
        let i = classifier.info();
        let model_label = format!("{} {}", i.name, i.version);
        Start {
            classifier,
            domains,
            model_label,
            blocklist_label,
            model_from_channel,
            blocklist_from_channel,
            tamper,
            artifacts: a,
        }
    }

    /// The installed copy of `kind` to use instead of the packaged one, if
    /// any; retires one that is no newer or no longer matches. Writes or
    /// removes the notice, and removes leftover directories.
    fn start_one(
        &self,
        record: &mut Record,
        kind: TargetKind,
        tamper: &mut Vec<TamperSignal>,
    ) -> Option<Ready> {
        if kind == TargetKind::Model && self.cfg.runtime.is_none() {
            // Can't run it; keep the record for a build that can.
            remove_notice(&self.cfg.notices, kind);
            return None;
        }
        let packaged = self.packaged(kind).cloned();
        let slot = record.slot_mut(kind);
        let mut ready = None;
        if let Some(cur) = slot.current.clone() {
            let version = Version::parse(&cur.version).ok();
            if version.is_none()
                || packaged
                    .as_ref()
                    .is_some_and(|p| version.as_ref() <= Some(p))
            {
                tracing::info!(kind = ?kind, version = %cur.version, "the packaged copy is as new; removing the one from the update channel");
                slot.current = None;
            } else {
                let dir = self.store(kind).join(hex::encode(cur.blake3.as_bytes()));
                match self.reload(kind, &dir, &cur) {
                    Ok(r) => {
                        tracing::info!(kind = ?kind, version = %cur.version, "using the copy from the update channel");
                        ready = Some(r);
                    }
                    Err(e) => {
                        tracing::error!(kind = ?kind, version = %cur.version, error = %e, "the copy from the update channel no longer matches what was installed; using the packaged one");
                        tamper.push(integrity(match kind {
                            TargetKind::Model => MODEL_UPDATE_CHANGED,
                            _ => BLOCKLIST_UPDATE_CHANGED,
                        }));
                        slot.current = None;
                    }
                }
            }
        }
        let keep = slot
            .current
            .as_ref()
            .map(|c| hex::encode(c.blake3.as_bytes()));
        remove_other_dirs(&self.store(kind), keep.as_deref());
        if keep.is_none() {
            remove_notice(&self.cfg.notices, kind);
        } else {
            let dir = self.store(kind).join(keep.as_deref().unwrap_or_default());
            if let Err(e) = write_notice_from(&self.cfg.notices, kind, &dir) {
                tracing::warn!(error = %e, "cannot write the update's notice");
            }
        }
        ready
    }

    /// Load an installed copy again, checking its manifest against the
    /// record first.
    fn reload(&self, kind: TargetKind, dir: &Path, cur: &Installed) -> Result<Ready, String> {
        let manifest = dir.join(manifest_file(kind));
        let bytes = std::fs::read(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
        if Hash32::of(&bytes) != cur.manifest_blake3 {
            return Err("the manifest changed".into());
        }
        let version = Version::parse(&cur.version).map_err(|e| e.to_string())?;
        match load(self.cfg.runtime.as_ref(), kind, &manifest, &version) {
            Ok(r) => Ok(r),
            Err(Refusal::Rejected(r)) => Err(r),
            Err(Refusal::Local(e)) => Err(e.to_string()),
        }
    }

    fn packaged(&self, kind: TargetKind) -> Option<&Version> {
        match kind {
            TargetKind::Model => self.packaged_model.as_ref(),
            _ => self.packaged_blocklist.as_ref(),
        }
    }

    fn store(&self, kind: TargetKind) -> PathBuf {
        self.cfg.dir.path().join(STORE_DIR).join(kind_dir(kind))
    }

    /// What the core takes swaps from.
    pub fn swaps(&self) -> Arc<Swaps> {
        self.swaps.clone()
    }

    /// The kinds this build checks.
    pub fn kinds(&self) -> Vec<TargetKind> {
        let mut k = Vec::new();
        if self.cfg.runtime.is_some() {
            k.push(TargetKind::Model);
        }
        k.push(TargetKind::Blocklist);
        k
    }

    /// The record of what is installed.
    pub fn record(&self) -> Record {
        read_record(&self.cfg.dir)
    }
}

/// Check an unpacked artifact and build what the detector needs, the same
/// way at install and at every start. Runs on a blocking thread.
fn load(
    runtime: Option<&Arc<dyn ModelRuntime>>,
    kind: TargetKind,
    manifest: &Path,
    version: &Version,
) -> Result<Ready, Refusal> {
    match kind {
        TargetKind::Model => {
            let runtime =
                runtime.ok_or_else(|| Refusal::Rejected("this build can't run models".into()))?;
            let model = load_model(manifest).map_err(refusal)?;
            let info = model.info().clone();
            check_version(&info.version, version)?;
            check_labels(&info)?;
            let label = format!("{} {}", info.name, info.version);
            let c = runtime
                .open(model)
                .map_err(|e| Refusal::Rejected(format!("the model doesn't load: {e}")))?;
            Ok(Ready::Model(c, label))
        }
        _ => {
            let l = load_domains(manifest).map_err(refusal)?;
            check_version(&l.manifest.version, version)?;
            let label = format!("domains {}", l.manifest.version);
            Ok(Ready::Blocklist(l.categorizer, label))
        }
    }
}

fn read_record(dir: &StateDir) -> Record {
    match dir.read_json(RECORD_FILE) {
        Ok(r) => r.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(error = %e, "ignoring an unreadable installed-artifacts record");
            Record::default()
        }
    }
}

fn kind_dir(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Model => "model",
        _ => "blocklist",
    }
}

fn manifest_file(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Model => MODEL_MANIFEST_FILE,
        _ => DOMAINS_MANIFEST_FILE,
    }
}

fn notice_file(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Model => MODEL_NOTICE,
        _ => BLOCKLIST_NOTICE,
    }
}

/// The manifest's version must be the target's: the signed listing says
/// what this bundle is.
fn check_version(manifest: &str, target: &Version) -> Result<(), Refusal> {
    match Version::parse(manifest) {
        Ok(v) if v == *target => Ok(()),
        _ => Err(Refusal::Rejected(format!(
            "the manifest says version {manifest:?}, the signed target {target}"
        ))),
    }
}

/// A model none of whose labels this client reads as explicit would leave
/// images unrated while looking installed.
fn check_labels(info: &ModelInfo) -> Result<(), Refusal> {
    let policy = PolicyConfig::default();
    if info
        .labels
        .iter()
        .any(|l| policy.explicit_labels.contains(l))
    {
        Ok(())
    } else {
        Err(Refusal::Rejected(format!(
            "none of the model's labels ({}) is one this client reads as explicit",
            info.labels.join(", ")
        )))
    }
}

/// A plain file name: no directories, not hidden.
fn is_plain_file_name(name: &str) -> bool {
    let mut b = name.bytes();
    (1..=128).contains(&name.len())
        && matches!(b.next(), Some(c) if c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The payload's file name, from the manifest. Only a plain file name that
/// isn't the manifest's own.
fn payload_name(kind: TargetKind, manifest: &[u8]) -> Result<String, Refusal> {
    let name = match kind {
        TargetKind::Model => serde_json::from_slice::<ModelInfo>(manifest)
            .map(|m| m.file)
            .map_err(|e| Refusal::Rejected(format!("invalid model manifest: {e}")))?,
        _ => serde_json::from_slice::<DomainsManifest>(manifest)
            .map(|m| m.bundle.file)
            .map_err(|e| Refusal::Rejected(format!("invalid domain manifest: {e}")))?,
    };
    if !is_plain_file_name(&name) || name == manifest_file(kind) {
        return Err(Refusal::Rejected(format!(
            "the manifest names {name:?}, not a plain file name"
        )));
    }
    Ok(name)
}

/// Unpack a verified bundle into a new `staging` directory. Returns the
/// manifest's path and BLAKE3.
fn unpack(kind: TargetKind, bundle: &Path, staging: &Path) -> Result<(PathBuf, Hash32), Refusal> {
    let mut r = std::io::BufReader::new(std::fs::File::open(bundle).map_err(local(bundle))?);
    let manifest = read_bundle_manifest(&mut r).map_err(|e| match e {
        BundleError::Io(source) => Refusal::Local(CheckError::Io {
            path: bundle.to_owned(),
            source,
        }),
        e => Refusal::Rejected(e.to_string()),
    })?;
    let payload = payload_name(kind, &manifest)?;
    if staging.exists() {
        std::fs::remove_dir_all(staging).map_err(local(staging))?;
    }
    create_private_dir(staging).map_err(local(staging))?;
    let manifest_path = staging.join(manifest_file(kind));
    write_synced(&manifest_path, &mut &manifest[..])?;
    let payload_path = staging.join(&payload);
    write_synced(&payload_path, &mut r)?;
    sync_dir(staging).map_err(local(staging))?;
    Ok((manifest_path, Hash32::of(&manifest)))
}

fn write_synced(path: &Path, from: &mut impl std::io::Read) -> Result<(), Refusal> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(local(path))?;
    std::io::copy(from, &mut f).map_err(local(path))?;
    f.sync_all().map_err(local(path))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Remove every entry of `store` but `keep`.
fn remove_other_dirs(store: &Path, keep: Option<&str>) {
    let Ok(entries) = std::fs::read_dir(store) else {
        return;
    };
    for e in entries.flatten() {
        if keep.is_some_and(|k| e.file_name() == k) {
            continue;
        }
        let p = e.path();
        let _ = if p.is_dir() {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
    }
}

/// The notice for an artifact: who made it, under what terms, what was
/// changed, and the licence texts. Only manifest text, as the packaged
/// notices are.
pub fn notice_text(kind: TargetKind, manifest: &[u8]) -> Option<String> {
    match kind {
        TargetKind::Model => {
            let m: ModelInfo = serde_json::from_slice(manifest).ok()?;
            let mut out = format!(
                "Image model {} {}, installed through Faro's update channel.\n\
                 Used under the {} licence.\n\n",
                m.name, m.version, m.license
            );
            if let Some(a) = &m.attribution {
                out.push_str(&a.notice_lines());
            }
            if let Some(t) = &m.license_text {
                out.push('\n');
                out.push_str(t.trim_end());
                out.push('\n');
            }
            Some(out)
        }
        _ => {
            let m: DomainsManifest = serde_json::from_slice(manifest).ok()?;
            Some(m.notice_text(&format!(
                "Domain list {}, installed through Faro's update channel.",
                m.version
            )))
        }
    }
}

fn write_notice_from(notices: &Path, kind: TargetKind, dir: &Path) -> std::io::Result<()> {
    let manifest = std::fs::read(dir.join(manifest_file(kind)))?;
    let text = notice_text(kind, &manifest).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable manifest")
    })?;
    std::fs::create_dir_all(notices)?;
    let path = notices.join(notice_file(kind));
    let tmp = notices.join(format!(".{}.tmp", notice_file(kind)));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(text.as_bytes())?;
    f.sync_all()?;
    drop(f);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, &path)
}

fn remove_notice(notices: &Path, kind: TargetKind) {
    let _ = std::fs::remove_file(notices.join(notice_file(kind)));
}

impl ClientUpdater {
    /// Check the instance's mirror for models and blocklists, and install
    /// what is newer. One result per kind this build checks; an error for
    /// one kind doesn't stop the other. See the [module docs](self).
    pub async fn check_artifacts(
        &self,
        a: &Artifacts,
    ) -> Result<Vec<(TargetKind, Result<ArtifactOutcome, CheckError>)>, CheckError> {
        let Some(info) = self.fetch.info().await?.filter(|i| i.available) else {
            return Ok(Vec::new());
        };
        let channel = info.channel.parse::<Channel>().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "the instance names an invalid channel; using stable");
            Channel::stable()
        });
        let mut u = self.load_trust()?;
        let verified = {
            let r = self.verify(&mut u).await;
            self.save_trust(&u)?;
            r?
        };
        let mut out = Vec::new();
        for kind in a.kinds() {
            let r = self.check_kind(a, &verified, &channel, kind).await;
            out.push((kind, r));
        }
        Ok(out)
    }

    async fn check_kind(
        &self,
        a: &Artifacts,
        verified: &VerifiedTargets,
        channel: &Channel,
        kind: TargetKind,
    ) -> Result<ArtifactOutcome, CheckError> {
        let q = Selection {
            channel,
            kind,
            platform: &self.spec.platform,
            arch: &self.spec.arch,
            current_version: None,
            os_version: self.spec.os_version.as_ref(),
            allow_downgrade: false,
        };
        let Some(target) = verified.select_for(&q, &self.spec.installed) else {
            return Ok(ArtifactOutcome::UpToDate);
        };
        let version = target.custom.version.clone();
        let record = a.record();
        let slot = record.slot(kind);
        let parse = |v: &Option<String>| v.as_deref().and_then(|v| Version::parse(v).ok());
        let current = parse(&slot.current.as_ref().map(|c| c.version.clone()));
        let highest = parse(&slot.highest);
        if a.packaged(kind).is_some_and(|p| version <= *p)
            || current.is_some_and(|c| version <= c)
            || highest.is_some_and(|h| version < h)
        {
            return Ok(ArtifactOutcome::UpToDate);
        }
        if let Some(reason) = slot.rejected.get(&target.blake3.to_prefixed_hex()) {
            return Ok(ArtifactOutcome::PreviouslyRejected {
                version,
                reason: reason.clone(),
            });
        }

        let store = a.store(kind);
        let hex = hex::encode(target.blake3.as_bytes());
        let bundle = self.download_data(&target).await?;
        let staging = store.join(format!(".{hex}.staging"));
        let loaded = {
            let (k, b, s, v) = (kind, bundle.clone(), staging.clone(), version.clone());
            let runtime = a.cfg.runtime.clone();
            tokio::task::spawn_blocking(move || {
                let (manifest, manifest_blake3) = unpack(k, &b, &s)?;
                let ready = load(runtime.as_ref(), k, &manifest, &v)?;
                Ok::<_, Refusal>((ready, manifest_blake3))
            })
            .await
            .unwrap_or_else(|e| Err(Refusal::Rejected(format!("the check did not finish: {e}"))))
        };
        let _ = std::fs::remove_file(&bundle);
        let (ready, manifest_blake3) = match loaded {
            Ok(r) => r,
            Err(Refusal::Local(e)) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(e);
            }
            Err(Refusal::Rejected(reason)) => {
                let _ = std::fs::remove_dir_all(&staging);
                tracing::error!(kind = ?kind, %version, %reason, "refusing the update: it is signed, but fails the checks");
                let mut record = a.record();
                record
                    .slot_mut(kind)
                    .rejected
                    .insert(target.blake3.to_prefixed_hex(), reason.clone());
                a.cfg.dir.write_json(RECORD_FILE, &record)?;
                return Ok(ArtifactOutcome::Rejected { version, reason });
            }
        };

        // Commit: the directory, the notice, then the record.
        let dest = store.join(&hex);
        if dest.exists() {
            std::fs::remove_dir_all(&dest).map_err(io_err(&dest))?;
        }
        std::fs::rename(&staging, &dest).map_err(io_err(&dest))?;
        sync_dir(&store).map_err(io_err(&store))?;
        if let Err(e) = write_notice_from(&a.cfg.notices, kind, &dest) {
            tracing::warn!(error = %e, "cannot write the update's notice");
        }
        let mut record = a.record();
        let slot = record.slot_mut(kind);
        let old = slot.current.replace(Installed {
            name: target.name.clone(),
            version: version.to_string(),
            blake3: target.blake3,
            manifest_blake3,
        });
        if parse(&slot.highest).is_none_or(|h| version > h) {
            slot.highest = Some(version.to_string());
        }
        a.cfg.dir.write_json(RECORD_FILE, &record)?;
        if let Some(old) = old.filter(|o| o.blake3 != target.blake3) {
            let _ = std::fs::remove_dir_all(store.join(hex::encode(old.blake3.as_bytes())));
        }
        tracing::info!(kind = ?kind, %version, "installed from the update channel");
        match ready {
            Ready::Model(value, label) => a.swaps.put_model(Swap { value, label }),
            Ready::Blocklist(value, label) => a.swaps.put_blocklist(Swap { value, label }),
        }
        Ok(ArtifactOutcome::Installed { version })
    }

    /// Download a data bundle into the store, verified against its signed
    /// length and BLAKE3.
    async fn download_data(&self, target: &TargetInfo) -> Result<PathBuf, CheckError> {
        let dir = self.dir.path().join(STORE_DIR).join(DOWNLOADS);
        create_private_dir(&dir).map_err(io_err(&dir))?;
        remove_other_dirs(&dir, None);
        let file = dir.join(format!("{}.data", hex::encode(target.blake3.as_bytes())));
        let partial = file.with_extension("partial");
        tracing::info!(version = %target.custom.version, bytes = target.length, name = %target.name, "downloading update");
        match self.fetch.artifact(target, MAX_DATA_BYTES, &partial).await {
            Ok(true) => {
                std::fs::rename(&partial, &file).map_err(io_err(&file))?;
                Ok(file)
            }
            Ok(false) => {
                let _ = std::fs::remove_file(&partial);
                Err(CheckError::Missing("artifact"))
            }
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_detect::{
        Attribution, Category, DomainCategorizerBuilder, DomainSource, DomainsBundleInfo,
        DOMAINS_MANIFEST_FORMAT,
    };

    /// A domain bundle and its manifest in `dir`; returns the manifest.
    fn domains(dir: &Path) -> PathBuf {
        let mut b = DomainCategorizerBuilder::new();
        b.add_domain("bet.example", Category::Gambling).unwrap();
        let bytes = b.build().unwrap().to_bytes();
        std::fs::write(dir.join("domains.bin"), &bytes).unwrap();
        let m = DomainsManifest {
            format: DOMAINS_MANIFEST_FORMAT.into(),
            notice: "Test.".into(),
            version: "1.2.3".into(),
            bundle: DomainsBundleInfo {
                file: "domains.bin".into(),
                bytes: bytes.len() as u64,
                blake3: blake3::hash(&bytes).to_hex().to_string(),
            },
            domains: 1,
            unapproved_included: false,
            sources: vec![DomainSource {
                name: "bets".into(),
                category: Category::Gambling,
                format: "domains".into(),
                license: "CC-BY-4.0".into(),
                approved: true,
                origin: "bets.txt".into(),
                homepage: None,
                blake3: "0".repeat(64),
                attribution: Some(Attribution {
                    author: "B".into(),
                    copyright: vec![],
                    source_url: "https://example.org/b".into(),
                    license_url: "https://creativecommons.org/licenses/by/4.0/".into(),
                    changes: "Compiled.".into(),
                }),
                lines: 1,
                domains: 1,
                skipped: 0,
            }],
            license_texts: BTreeMap::new(),
        };
        let p = dir.join(DOMAINS_MANIFEST_FILE);
        std::fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
        p
    }

    fn component(t: Option<TamperSignal>) -> Option<String> {
        t.map(|t| match t {
            TamperSignal::IntegrityFailure { component } => component,
            other => panic!("{other:?}"),
        })
    }

    #[test]
    fn the_packaged_domain_list_loads_or_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let p = domains(dir.path());
        for required in [false, true] {
            let (d, t) = load_packaged_domains(&p, required);
            let d = d.expect("loads");
            assert_eq!(d.version, Some(Version::new(1, 2, 3)));
            assert_eq!(d.categorizer.len(), 1);
            assert!(t.is_none());
        }
        // Missing: tamper only for the packaged service, which ships one.
        let gone = dir.path().join("gone/domains.manifest.json");
        let (d, t) = load_packaged_domains(&gone, false);
        assert!(d.is_none() && t.is_none());
        let (d, t) = load_packaged_domains(&gone, true);
        assert!(d.is_none());
        assert_eq!(component(t).as_deref(), Some(BLOCKLIST_MISSING));
        // There but altered: always tamper.
        std::fs::write(dir.path().join("domains.bin"), b"changed").unwrap();
        for required in [false, true] {
            let (d, t) = load_packaged_domains(&p, required);
            assert!(d.is_none());
            assert_eq!(component(t).as_deref(), Some(BLOCKLIST_CHANGED));
        }
    }

    #[test]
    fn domains_check_prints_what_it_verified() {
        let dir = tempfile::tempdir().unwrap();
        let p = domains(dir.path());
        let mut out = Vec::new();
        check_domains(&p, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(lines[0].starts_with("domains      1.2.3 1 domains, blake3 "));
        assert!(lines[0].ends_with(" verified"));
        assert_eq!(lines[1], "source       bets gambling CC-BY-4.0 1 domains");
        std::fs::write(dir.path().join("domains.bin"), b"changed").unwrap();
        assert!(check_domains(&p, &mut Vec::new()).is_err());
    }

    #[test]
    fn payload_names_must_be_plain() {
        let model = |file: &str| {
            let mut v: serde_json::Value = serde_json::from_slice(include_bytes!(
                "../../../faro-detect/models/opennsfw/manifest.json"
            ))
            .unwrap();
            v["file"] = file.into();
            serde_json::to_vec(&v).unwrap()
        };
        assert!(payload_name(TargetKind::Model, &model("m.onnx")).is_ok());
        for bad in ["../m.onnx", "sub/m.onnx", ".m", "manifest.json", ""] {
            assert!(
                matches!(
                    payload_name(TargetKind::Model, &model(bad)),
                    Err(Refusal::Rejected(_))
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            payload_name(TargetKind::Blocklist, b"{}"),
            Err(Refusal::Rejected(_))
        ));
    }

    /// The packaged manifests' versions are semver, so the service can
    /// compare them with versions from the update channel.
    #[test]
    fn packaged_model_versions_are_semver() {
        for m in [
            &include_bytes!("../../../faro-detect/models/opennsfw/manifest.json")[..],
            &include_bytes!("../../../faro-detect/models/opennsfw/manifest-fp32.json")[..],
        ] {
            let info: ModelInfo = serde_json::from_slice(m).unwrap();
            assert!(Version::parse(&info.version).is_ok(), "{}", info.version);
            check_labels(&info).map_err(|_| "labels").unwrap();
        }
    }

    #[test]
    fn model_notices_carry_the_attribution_and_licence() {
        let m = include_bytes!("../../../faro-detect/models/opennsfw/manifest.json");
        let text = notice_text(TargetKind::Model, m).unwrap();
        assert!(text.contains("Image model opennsfw 1.0.0+int8"));
        assert!(text.contains("Copyright 2016, Yahoo Inc."));
        assert!(text.contains("Redistribution and use in source and binary forms"));
        assert!(notice_text(TargetKind::Model, b"{").is_none());
    }
}
