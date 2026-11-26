//! Models and blocklists through the signed update channel
//! (`faro_service::update::artifacts`, PROTOCOL.md §8.2).
//!
//! A fake instance serves a directory as its mirror, signed by a toy
//! project (`faro_update::testing`), so a malicious or broken instance is
//! easy to play. Models run on a stand-in for ONNX Runtime that only
//! records what it was handed: no weights are needed, and none exist.

use axum::routing::get;
use axum::{Json, Router};
use faro_core::{Clock, SystemClock};
use faro_detect::attribution::Attribution;
use faro_detect::{
    Category, ChannelOrder, Classifier, DetectError, DomainCategorizerBuilder, DomainSource,
    DomainsBundleInfo, DomainsManifest, ImageScores, InputSize, ModelInfo, OutputActivation,
    TensorLayout, VerifiedModel, DOMAINS_MANIFEST_FORMAT,
};
use faro_platform::Frame;
use faro_proto::api::UpdatesInfo;
use faro_proto::body::TamperSignal;
use faro_service::client::ClientOptions;
use faro_service::model::{ModelLoad, ModelRuntime};
use faro_service::state::StateDir;
use faro_service::update::artifacts::{
    ArtifactConfig, ArtifactOutcome, Artifacts, PackagedDomains, Start, BLOCKLIST_NOTICE,
    BLOCKLIST_UPDATE_CHANGED, MODEL_NOTICE, MODEL_UPDATE_CHANGED, RECORD_FILE, STORE_DIR,
};
use faro_service::update::fetch::UpdateFetcher;
use faro_service::update::{CheckError, ClientSpec, ClientUpdater};
use faro_update::bundle::bundle_bytes;
use faro_update::testing::{Artifact, ToyProject, DAY_MS};
use faro_update::{TargetKind, Version};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use url::Url;

fn now() -> i64 {
    SystemClock::new().wall_ms()
}

// ---- artifacts ------------------------------------------------------------

fn attribution() -> Attribution {
    Attribution {
        author: "Test Authors".into(),
        copyright: vec!["Copyright 2026 Test Authors".into()],
        source_url: "https://example.org/model".into(),
        license_url: "https://example.org/model/LICENSE".into(),
        changes: "None.".into(),
    }
}

fn model_info(version: &str, license: &str, weights: &[u8]) -> ModelInfo {
    ModelInfo {
        name: "test".into(),
        version: version.into(),
        file: "test.onnx".into(),
        input_size: InputSize {
            width: 8,
            height: 8,
        },
        labels: vec!["sfw".into(), "nsfw".into()],
        mean: [0.0; 3],
        std: [1.0; 3],
        channel_order: ChannelOrder::Rgb,
        layout: TensorLayout::Nchw,
        input_scale: 1.0 / 255.0,
        output: OutputActivation::Probabilities,
        license: license.into(),
        license_text: Some("Permission is hereby granted, free of charge (test).".into()),
        attribution: Some(attribution()),
        blake3: blake3::hash(weights).to_hex().to_string(),
    }
}

fn model_bundle(info: &ModelInfo, weights: &[u8]) -> Vec<u8> {
    bundle_bytes(&serde_json::to_vec(info).unwrap(), weights).unwrap()
}

/// A model target: `version` in the listing and the manifest.
fn model(version: &str) -> Artifact {
    let weights = format!("weights {version}").into_bytes();
    model_artifact(version, &model_bundle(&model_info(version, "MIT", &weights), &weights))
}

fn model_artifact(version: &str, content: &[u8]) -> Artifact {
    Artifact::new(
        &format!("model/any/test-{version}-stable.data"),
        TargetKind::Model,
        "any",
        "any",
        version,
        content,
    )
}

fn domains_manifest(version: &str, bytes: &[u8], domains: usize) -> DomainsManifest {
    DomainsManifest {
        format: DOMAINS_MANIFEST_FORMAT.into(),
        notice: "Compiled from the lists below.".into(),
        version: version.into(),
        bundle: DomainsBundleInfo {
            file: "domains.bin".into(),
            bytes: bytes.len() as u64,
            blake3: blake3::hash(bytes).to_hex().to_string(),
        },
        domains,
        unapproved_included: false,
        sources: vec![DomainSource {
            name: "adult-list".into(),
            category: Category::Adult,
            format: "domains".into(),
            license: "MIT".into(),
            approved: true,
            origin: "https://example.org/list.txt".into(),
            homepage: None,
            blake3: "0".repeat(64),
            attribution: Some(attribution()),
            lines: domains,
            domains,
            skipped: 0,
        }],
        license_texts: [("MIT".to_owned(), "Permission is hereby granted (test).".to_owned())]
            .into(),
    }
}

fn blocklist_with(version: &str, edit: impl FnOnce(&mut DomainsManifest)) -> Artifact {
    let mut b = DomainCategorizerBuilder::new();
    b.add_domain(&format!("adult-{}.test", version.replace('.', "-")), Category::Adult)
        .unwrap();
    let bytes = b.build().unwrap().to_bytes();
    let mut m = domains_manifest(version, &bytes, 1);
    edit(&mut m);
    let content = bundle_bytes(&serde_json::to_vec(&m).unwrap(), &bytes).unwrap();
    Artifact::new(
        &format!("blocklist/any/domains-{version}-stable.data"),
        TargetKind::Blocklist,
        "any",
        "any",
        version,
        &content,
    )
}

fn blocklist(version: &str) -> Artifact {
    blocklist_with(version, |_| {})
}

// ---- a stand-in for ONNX Runtime -----------------------------------------

/// Answers with no scores; only its manifest matters here.
struct Fixed(ModelInfo);

impl Classifier for Fixed {
    fn info(&self) -> &ModelInfo {
        &self.0
    }
    fn classify(&mut self, _frame: &Frame) -> Result<ImageScores, DetectError> {
        Ok(ImageScores::empty())
    }
}

/// Records each model it is asked to open; refuses when `fail` is set (as
/// ONNX Runtime does with bytes that aren't a model).
#[derive(Debug, Default)]
struct FakeRuntime {
    opened: Mutex<Vec<(String, Vec<u8>)>>,
    fail: std::sync::atomic::AtomicBool,
}

impl ModelRuntime for FakeRuntime {
    fn open(&self, model: VerifiedModel) -> Result<Box<dyn Classifier>, DetectError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(DetectError::Classifier("not an ONNX model".into()));
        }
        self.opened
            .lock()
            .unwrap()
            .push((model.info().version.clone(), model.bytes().to_vec()));
        Ok(Box::new(Fixed(model.info().clone())))
    }
}

impl FakeRuntime {
    fn opened(&self) -> Vec<String> {
        self.opened
            .lock()
            .unwrap()
            .iter()
            .map(|(v, _)| v.clone())
            .collect()
    }
}

// ---- a fake instance and a device -----------------------------------------

struct FakeInstance {
    project: ToyProject,
    dir: tempfile::TempDir,
    url: Url,
    requests: Arc<AtomicUsize>,
}

impl FakeInstance {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let r = requests.clone();
        let app = Router::new()
            .route(
                "/v1/updates",
                get(|| async {
                    Json(UpdatesInfo {
                        available: true,
                        channel: "stable".into(),
                    })
                }),
            )
            .fallback_service(tower_http::services::ServeDir::new(dir.path()))
            .layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let r = r.clone();
                    async move {
                        if req.uri().path().contains("/targets/") {
                            r.fetch_add(1, Ordering::SeqCst);
                        }
                        next.run(req).await
                    }
                },
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeInstance {
            project: ToyProject::new(now() + 365 * DAY_MS),
            dir,
            url: faro_service::link::parse_instance_url(&format!("http://{addr}")).unwrap(),
            requests,
        }
    }

    fn mirror(&self) -> PathBuf {
        self.dir.path().join("v1/updates")
    }

    fn publish(&mut self, artifacts: &[Artifact]) {
        let dir = self.mirror();
        self.project
            .publish(&dir, artifacts, now() + 7 * DAY_MS)
            .unwrap();
    }

    /// Artifact downloads served so far.
    fn downloads(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

struct Device {
    _tmp: tempfile::TempDir,
    dir: StateDir,
    notices: PathBuf,
    runtime: Arc<FakeRuntime>,
}

fn device() -> Device {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path().join("state")).unwrap();
    let notices = tmp.path().join("notices");
    Device {
        _tmp: tmp,
        dir,
        notices,
        runtime: Arc::new(FakeRuntime::default()),
    }
}

fn spec(client: &str) -> ClientSpec {
    ClientSpec {
        platform: "macos".into(),
        arch: "aarch64".into(),
        os_version: None,
        installed: Version::parse(client).unwrap(),
    }
}

fn updater(inst: &FakeInstance, dev: &Device, client: &str) -> ClientUpdater {
    let fetch = UpdateFetcher::new(inst.url.clone(), &ClientOptions::default()).unwrap();
    ClientUpdater::new(
        dev.dir.clone(),
        inst.project.first_root(),
        fetch,
        Arc::new(SystemClock::new()),
        spec(client),
        None,
    )
    .unwrap()
}

/// What the service does at start, with a packaged model of `packaged`
/// (none if `None`) and no packaged domain list.
fn start(dev: &Device, packaged: Option<&str>) -> Start {
    start_with(dev, packaged, Some(dev.runtime.clone()), None)
}

fn start_with(
    dev: &Device,
    packaged: Option<&str>,
    runtime: Option<Arc<FakeRuntime>>,
    domains: Option<PackagedDomains>,
) -> Start {
    let classifier: Box<dyn Classifier> = match packaged {
        Some(v) => Box::new(Fixed(model_info(v, "MIT", b"packaged"))),
        None => Box::new(faro_detect::NullClassifier::new()),
    };
    Artifacts::start(
        ArtifactConfig {
            dir: dev.dir.clone(),
            notices: dev.notices.clone(),
            runtime: runtime.map(|r| r as Arc<dyn ModelRuntime>),
        },
        ModelLoad {
            classifier,
            tamper: None,
        },
        domains,
    )
}

type Results = Vec<(TargetKind, Result<ArtifactOutcome, CheckError>)>;

async fn check(u: &ClientUpdater, a: &Artifacts) -> Results {
    u.check_artifacts(a).await.expect("metadata verifies")
}

fn outcome(r: &Results, kind: TargetKind) -> &ArtifactOutcome {
    match &r.iter().find(|(k, _)| *k == kind).expect("checked").1 {
        Ok(o) => o,
        Err(e) => panic!("{kind:?}: {e}"),
    }
}

fn installed(v: &str) -> ArtifactOutcome {
    ArtifactOutcome::Installed {
        version: Version::parse(v).unwrap(),
    }
}

/// The store's directories for `kind` (staging and downloads included).
fn store(dev: &Device, kind: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dev.dir.path().join(STORE_DIR).join(kind))
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn record_json(dev: &Device) -> Option<Vec<u8>> {
    std::fs::read(dev.dir.path().join(RECORD_FILE)).ok()
}

fn integrity(component: &str) -> TamperSignal {
    TamperSignal::IntegrityFailure {
        component: component.into(),
    }
}

// ---- tests ----------------------------------------------------------------

/// A newer model and a newer blocklist install next to the packaged copy,
/// with their notices, and are handed over for the detector.
#[tokio::test]
async fn a_newer_model_and_blocklist_install_and_are_swapped_in() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.0.0"), model("1.1.0"), blocklist("1.0.0")]);
    let dev = device();
    let s = start(&dev, Some("1.0.0"));
    assert_eq!(s.model_label, "test 1.0.0");
    assert!(s.tamper.is_empty());
    let a = s.artifacts;
    let u = updater(&inst, &dev, "1.0.0");

    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &installed("1.1.0"));
    assert_eq!(outcome(&r, TargetKind::Blocklist), &installed("1.0.0"));
    // ONNX Runtime got the verified weights, exactly.
    assert_eq!(dev.runtime.opened(), ["1.1.0"]);
    assert_eq!(
        dev.runtime.opened.lock().unwrap()[0].1,
        b"weights 1.1.0".to_vec()
    );

    let swaps = a.swaps();
    let m = swaps.take_model().expect("a model to swap in");
    assert_eq!(m.label, "test 1.1.0");
    assert_eq!(m.value.info().version, "1.1.0");
    let d = swaps.take_blocklist().expect("a list to swap in");
    assert_eq!(d.label, "domains 1.0.0");
    assert_eq!(
        d.value.categorize_url("https://adult-1-0-0.test/"),
        [Category::Adult]
    );
    assert!(swaps.take_model().is_none(), "taken once");

    // Attribution travels with each one, next to the packaged notices.
    let notice = std::fs::read_to_string(dev.notices.join(MODEL_NOTICE)).unwrap();
    assert!(notice.contains("Image model test 1.1.0"), "{notice}");
    assert!(notice.contains("Copyright 2026 Test Authors"));
    assert!(notice.contains("Permission is hereby granted, free of charge (test)."));
    let notice = std::fs::read_to_string(dev.notices.join(BLOCKLIST_NOTICE)).unwrap();
    assert!(notice.contains("Domain list 1.0.0") && notice.contains("adult-list"));
    assert!(notice.contains("Permission is hereby granted (test)."));

    // One directory each; no download or staging left behind.
    assert_eq!(store(&dev, "model").len(), 1);
    assert_eq!(store(&dev, "blocklist").len(), 1);
    assert!(store(&dev, "downloads").is_empty());
    let rec = a.record();
    assert_eq!(rec.model.current.as_ref().unwrap().version, "1.1.0");
    assert_eq!(rec.model.highest.as_deref(), Some("1.1.0"));

    // Up to date now: nothing is downloaded again.
    let before = inst.downloads();
    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);
    assert_eq!(outcome(&r, TargetKind::Blocklist), &ArtifactOutcome::UpToDate);
    assert_eq!(inst.downloads(), before);
}

/// At the next start the installed copies are used. One that was altered
/// is reported and dropped for the packaged copy, and the next check
/// installs it again.
#[tokio::test]
async fn restarts_use_the_installed_copy_unless_it_changed() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.1.0"), blocklist("1.0.0")]);
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    check(&u, &start(&dev, Some("1.0.0")).artifacts).await;

    let s = start(&dev, Some("1.0.0"));
    assert_eq!(s.model_label, "test 1.1.0");
    assert_eq!(s.blocklist_label.as_deref(), Some("domains 1.0.0"));
    assert!(s.domains.is_some());
    assert!(s.tamper.is_empty());

    // Someone edits the installed weights and the domain manifest.
    let model_dir = dev
        .dir
        .path()
        .join(STORE_DIR)
        .join("model")
        .join(&store(&dev, "model")[0]);
    std::fs::write(model_dir.join("test.onnx"), b"other weights").unwrap();
    let list_dir = dev
        .dir
        .path()
        .join(STORE_DIR)
        .join("blocklist")
        .join(&store(&dev, "blocklist")[0]);
    let p = list_dir.join("domains.manifest.json");
    let mut text = std::fs::read_to_string(&p).unwrap();
    text.push(' ');
    std::fs::write(&p, text).unwrap();

    let s = start(&dev, Some("1.0.0"));
    assert_eq!(s.model_label, "test 1.0.0", "the packaged copy");
    assert!(s.domains.is_none());
    assert_eq!(
        s.tamper,
        [
            integrity(MODEL_UPDATE_CHANGED),
            integrity(BLOCKLIST_UPDATE_CHANGED)
        ]
    );
    assert!(store(&dev, "model").is_empty() && store(&dev, "blocklist").is_empty());
    assert!(!dev.notices.join(MODEL_NOTICE).exists());
    assert!(!dev.notices.join(BLOCKLIST_NOTICE).exists());

    // Reported once: the next start is clean, and the next check repairs.
    let s = start(&dev, Some("1.0.0"));
    assert!(s.tamper.is_empty());
    let r = check(&u, &s.artifacts).await;
    assert_eq!(outcome(&r, TargetKind::Model), &installed("1.1.0"));
    assert_eq!(outcome(&r, TargetKind::Blocklist), &installed("1.0.0"));
    assert_eq!(start(&dev, Some("1.0.0")).model_label, "test 1.1.0");
}

/// A client update that ships a newer model replaces the installed one:
/// it is removed, and nothing older is installed again.
#[tokio::test]
async fn a_newer_packaged_copy_wins() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.1.0")]);
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    check(&u, &start(&dev, Some("1.0.0")).artifacts).await;
    assert_eq!(store(&dev, "model").len(), 1);

    let s = start(&dev, Some("1.2.0"));
    assert_eq!(s.model_label, "test 1.2.0");
    assert!(s.tamper.is_empty());
    assert!(store(&dev, "model").is_empty());
    assert!(!dev.notices.join(MODEL_NOTICE).exists());
    let r = check(&u, &s.artifacts).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);
}

/// Bytes that don't match the signed target are never installed; nothing
/// changes, on disk or in the detector.
#[tokio::test]
async fn a_tampered_artifact_is_refused_and_changes_nothing() {
    let mut inst = FakeInstance::start().await;
    let m = model("1.1.0");
    let b = blocklist("1.0.0");
    inst.publish(&[m.clone(), b.clone()]);
    // The instance serves other bytes under both names.
    for a in [&m, &b] {
        let mut bytes = a.content.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(inst.mirror().join("targets").join(&a.name), bytes).unwrap();
    }
    let dev = device();
    let a = start(&dev, Some("1.0.0")).artifacts;
    let u = updater(&inst, &dev, "1.0.0");
    let r = check(&u, &a).await;
    for (kind, res) in &r {
        assert!(
            matches!(res, Err(CheckError::Fetch(_))),
            "{kind:?}: {res:?}"
        );
    }
    assert!(dev.runtime.opened().is_empty());
    assert!(a.swaps().take_model().is_none() && a.swaps().take_blocklist().is_none());
    assert!(store(&dev, "model").is_empty() && store(&dev, "blocklist").is_empty());
    assert!(store(&dev, "downloads").is_empty());
    assert!(record_json(&dev).is_none(), "no record written");
    assert!(!dev.notices.exists());
}

/// Only what the project signed is installed: an artifact the instance
/// adds without a listing, or lists in metadata the project didn't sign,
/// is never fetched.
#[tokio::test]
async fn unlisted_or_forged_artifacts_are_ignored() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.0.0")]);
    let extra = model("9.0.0");
    let path = inst.mirror().join("targets").join(&extra.name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &extra.content).unwrap();
    let dev = device();
    let a = start(&dev, Some("1.0.0")).artifacts;
    let u = updater(&inst, &dev, "1.0.0");
    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);

    // Metadata from another project that lists it.
    let mut forger = ToyProject::new(now() + 365 * DAY_MS);
    forger
        .publish(&inst.mirror(), &[extra], now() + 7 * DAY_MS)
        .unwrap();
    assert!(matches!(
        u.check_artifacts(&a).await,
        Err(CheckError::Verify(_))
    ));
    assert_eq!(inst.downloads(), 0);
    assert!(dev.runtime.opened().is_empty());
    assert!(record_json(&dev).is_none());
}

/// Never back: not below the packaged copy, not below what was installed,
/// whatever the instance's listing offers.
#[tokio::test]
async fn older_artifacts_are_never_installed() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("0.9.0"), model("1.0.0")]);
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    let a = start(&dev, Some("1.0.0")).artifacts;
    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);

    inst.publish(&[model("1.2.0"), blocklist("2.0.0")]);
    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &installed("1.2.0"));
    assert_eq!(outcome(&r, TargetKind::Blocklist), &installed("2.0.0"));
    let rec = record_json(&dev);

    // The next release lists only older ones (the admin moved channels,
    // or the release was pulled).
    inst.publish(&[model("1.1.0"), blocklist("1.9.0")]);
    let before = inst.downloads();
    let r = check(&u, &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);
    assert_eq!(outcome(&r, TargetKind::Blocklist), &ArtifactOutcome::UpToDate);
    assert_eq!(inst.downloads(), before);
    assert_eq!(record_json(&dev), rec, "nothing changed");
    // Not even after the installed copy was lost: the floor is the highest
    // version ever installed.
    std::fs::remove_dir_all(dev.dir.path().join(STORE_DIR)).unwrap();
    let s = start(&dev, Some("1.0.0"));
    assert_eq!(s.model_label, "test 1.0.0");
    let r = check(&u, &s.artifacts).await;
    assert_eq!(outcome(&r, TargetKind::Model), &ArtifactOutcome::UpToDate);
    assert_eq!(outcome(&r, TargetKind::Blocklist), &ArtifactOutcome::UpToDate);
}

/// A signed bundle that fails the checks the packaged copy passes (a
/// licence that isn't on the allowlist, missing attribution, a manifest
/// that contradicts the listing, weights that don't match, a model this
/// client can't read or run, an unapproved list) is refused, recorded, and
/// never downloaded again. What is in use stays.
#[tokio::test]
async fn signed_but_unusable_artifacts_are_refused_once() {
    let mut inst = FakeInstance::start().await;
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    inst.publish(&[model("1.1.0")]);
    let a = start(&dev, Some("1.0.0")).artifacts;
    check(&u, &a).await;
    a.swaps().take_model();
    let opened = dev.runtime.opened();

    let bad_model = |v: &str, edit: fn(&mut ModelInfo)| {
        let weights = format!("weights {v}").into_bytes();
        let mut info = model_info(v, "MIT", &weights);
        edit(&mut info);
        model_artifact(v, &model_bundle(&info, &weights))
    };
    let cases: Vec<(Artifact, &str)> = vec![
        (
            bad_model("1.2.0", |i| i.license = "AGPL-3.0-only".into()),
            "not Apache-2.0 compatible",
        ),
        (bad_model("1.3.0", |i| i.attribution = None), "attribution"),
        (bad_model("1.4.0", |i| i.version = "1.4.1".into()), "1.4.1"),
        (bad_model("1.5.0", |i| i.blake3 = "0".repeat(64)), "integrity"),
        (
            bad_model("1.6.0", |i| i.labels = vec!["cat".into(), "dog".into()]),
            "explicit",
        ),
        (bad_model("1.7.0", |i| i.file = "../escape".into()), "plain file name"),
        (
            model_artifact("1.8.0", b"not a bundle at all"),
            "not a Faro data bundle",
        ),
    ];
    for (artifact, why) in cases {
        let v = artifact.version.clone();
        inst.publish(&[model("1.1.0"), artifact]);
        let r = check(&u, &a).await;
        match outcome(&r, TargetKind::Model) {
            ArtifactOutcome::Rejected { version, reason } => {
                assert_eq!(*version, v);
                assert!(reason.contains(why), "{v}: {reason}");
            }
            o => panic!("{v}: {o:?}"),
        }
        // Not again.
        let before = inst.downloads();
        let r = check(&u, &a).await;
        assert!(
            matches!(
                outcome(&r, TargetKind::Model),
                ArtifactOutcome::PreviouslyRejected { .. }
            ),
            "{v}"
        );
        assert_eq!(inst.downloads(), before, "{v}: not downloaded again");
    }

    // ONNX Runtime refuses the weights.
    dev.runtime.fail.store(true, Ordering::SeqCst);
    inst.publish(&[model("2.0.0")]);
    let r = check(&u, &a).await;
    assert!(matches!(
        outcome(&r, TargetKind::Model),
        ArtifactOutcome::Rejected { reason, .. } if reason.contains("doesn't load")
    ));
    dev.runtime.fail.store(false, Ordering::SeqCst);

    // Lists that couldn't have shipped.
    for (b, why) in [
        (
            blocklist_with("1.0.0", |m| m.unapproved_included = true),
            "unapproved",
        ),
        (
            blocklist_with("1.1.0", |m| m.sources[0].license = "GPL-3.0-only".into()),
            "GPL-3.0-only",
        ),
        (
            blocklist_with("1.2.0", |m| m.license_texts.clear()),
            "travel",
        ),
    ] {
        inst.publish(&[b]);
        let r = check(&u, &a).await;
        assert!(
            matches!(
                outcome(&r, TargetKind::Blocklist),
                ArtifactOutcome::Rejected { reason, .. } if reason.contains(why)
            ),
            "{why}: {r:?}"
        );
    }

    // Still 1.1.0, nothing swapped, one model directory, no list.
    assert_eq!(dev.runtime.opened(), opened);
    assert!(a.swaps().take_model().is_none() && a.swaps().take_blocklist().is_none());
    let rec = a.record();
    assert_eq!(rec.model.current.unwrap().version, "1.1.0");
    assert_eq!(rec.model.rejected.len(), 8);
    assert!(rec.blocklist.current.is_none());
    assert_eq!(store(&dev, "model").len(), 1);
    assert!(store(&dev, "blocklist").is_empty());
    assert!(store(&dev, "downloads").is_empty());
    assert_eq!(start(&dev, Some("1.0.0")).model_label, "test 1.1.0");
}

/// A model that needs a newer client is left to newer clients; this one
/// takes the newest it can use.
#[tokio::test]
async fn min_client_holds_older_clients_back() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.1.0"), model("1.2.0").min_client("2.0.0")]);
    let dev = device();
    let a = start(&dev, Some("1.0.0")).artifacts;
    let r = check(&updater(&inst, &dev, "1.9.0"), &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &installed("1.1.0"));
    let r = check(&updater(&inst, &dev, "2.0.0"), &a).await;
    assert_eq!(outcome(&r, TargetKind::Model), &installed("1.2.0"));
}

/// A build without ONNX Runtime doesn't fetch models, and leaves an
/// installed one for a build that can run it.
#[tokio::test]
async fn without_a_model_runtime_only_blocklists_are_checked() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[model("1.1.0"), blocklist("1.0.0")]);
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    let a = start_with(&dev, None, None, None).artifacts;
    let r = check(&u, &a).await;
    assert_eq!(r.len(), 1);
    assert_eq!(outcome(&r, TargetKind::Blocklist), &installed("1.0.0"));

    // Installed by a build that can, then started by one that can't.
    check(&u, &start(&dev, None).artifacts).await;
    assert_eq!(store(&dev, "model").len(), 1);
    let s = start_with(&dev, None, None, None);
    assert_eq!(s.model_label, "null 0");
    assert!(s.tamper.is_empty());
    assert_eq!(store(&dev, "model").len(), 1, "kept");
    assert_eq!(start(&dev, None).model_label, "test 1.1.0");
}

/// A packaged domain list counts like the packaged model: only a newer one
/// from the channel replaces it.
#[tokio::test]
async fn a_packaged_domain_list_is_replaced_only_by_a_newer_one() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&[blocklist("1.0.0")]);
    let dev = device();
    let u = updater(&inst, &dev, "1.0.0");
    let packaged = |v: &str| PackagedDomains {
        categorizer: DomainCategorizerBuilder::new().build().unwrap(),
        version: Some(Version::parse(v).unwrap()),
    };
    let s = start_with(&dev, None, None, Some(packaged("1.0.0")));
    assert_eq!(s.blocklist_label.as_deref(), Some("domains 1.0.0"));
    let r = check(&u, &s.artifacts).await;
    assert_eq!(outcome(&r, TargetKind::Blocklist), &ArtifactOutcome::UpToDate);
    let s = start_with(&dev, None, None, Some(packaged("0.9.0")));
    let r = check(&u, &s.artifacts).await;
    assert_eq!(outcome(&r, TargetKind::Blocklist), &installed("1.0.0"));
}
