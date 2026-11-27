//! Client self-update (`faro_service::update`, PROTOCOL.md §8.2).
//!
//! Most tests run against a **fake instance**: a localhost HTTP server whose
//! `/v1/updates/…` is a directory the test writes, signed by a toy project
//! (`faro_update::testing`). That makes a malicious or broken instance easy
//! to play: forged metadata, rollbacks, wrong bytes. One test runs against
//! the real `faro-server` mirror. The installer is a fake that records what
//! it was handed.

use axum::routing::get;
use axum::{Json, Router};
use faro_core::{Clock, ManualClock, SystemClock};
use faro_proto::api::UpdatesInfo;
use faro_service::client::ClientOptions;
use faro_service::state::StateDir;
use faro_service::update::fetch::UpdateFetcher;
use faro_service::update::install::{InstallError, Installer};
use faro_service::update::signature::PackageCheckError;
use faro_service::update::{
    CheckError, ClientSpec, ClientUpdater, Outcome, Settled, ATTEMPTS_FILE, MAX_INSTALL_ATTEMPTS,
    PENDING_GRACE_MS, TRUST_FILE,
};
use faro_update::testing::{write_release, write_root, Artifact, ToyProject, DAY_MS};
use faro_update::{TargetInfo, TargetKind, Version};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use url::Url;

const PKG: &str = "client/macos/aarch64/Faro-1.2.0.pkg";

fn now() -> i64 {
    SystemClock::new().wall_ms()
}

fn mac(name: &str, version: &str, content: &[u8]) -> Artifact {
    Artifact::new(
        name,
        TargetKind::Client,
        "macos",
        "aarch64",
        version,
        content,
    )
}

fn catalog() -> Vec<Artifact> {
    vec![
        mac("client/macos/aarch64/Faro-1.1.0.pkg", "1.1.0", b"pkg 1.1.0"),
        mac(PKG, "1.2.0", b"pkg 1.2.0"),
        mac(
            "client/macos/aarch64/Faro-1.3.0-beta.1.pkg",
            "1.3.0-beta.1",
            b"beta",
        )
        .channels(&["beta"]),
        Artifact::new(
            "client/macos/x86_64/Faro-9.0.0.pkg",
            TargetKind::Client,
            "macos",
            "x86_64",
            "9.0.0",
            b"intel",
        ),
        Artifact::new(
            "client/windows/x86_64/Faro-9.0.0.msi",
            TargetKind::Client,
            "windows",
            "x86_64",
            "9.0.0",
            b"win",
        ),
        Artifact::new(
            "models/m-9.0.0.onnx",
            TargetKind::Model,
            "any",
            "any",
            "9.0.0",
            b"model",
        ),
    ]
}

fn spec(installed: &str) -> ClientSpec {
    ClientSpec {
        platform: "macos".into(),
        arch: "aarch64".into(),
        os_version: Some(Version::new(14, 0, 0)),
        installed: Version::parse(installed).unwrap(),
    }
}

/// Records every install it is asked for; optionally refuses. `verdict`
/// plays the package signature check (`None` passes).
#[derive(Debug, Default)]
struct FakeInstaller {
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    refuse: bool,
    verdict: Mutex<Option<PackageCheckError>>,
    checked: Mutex<Vec<String>>,
}

impl Installer for FakeInstaller {
    fn check_package(
        &self,
        package: &Path,
        target: &TargetInfo,
        installed: &Version,
    ) -> Result<(), PackageCheckError> {
        assert!(package.is_file(), "checked on disk, after the download");
        assert!(
            target.custom.version > *installed,
            "given the running version to compare the package with"
        );
        self.checked.lock().unwrap().push(target.name.clone());
        match self.verdict.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn install(&self, package: &Path, target: &TargetInfo) -> Result<(), InstallError> {
        let bytes = std::fs::read(package).unwrap();
        self.calls
            .lock()
            .unwrap()
            .push((target.name.clone(), bytes));
        if self.refuse {
            return Err(InstallError::Start("refused by the test".into()));
        }
        Ok(())
    }
}

impl FakeInstaller {
    fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.calls.lock().unwrap().clone()
    }

    fn checked(&self) -> Vec<String> {
        self.checked.lock().unwrap().clone()
    }

    fn set_verdict(&self, v: Option<PackageCheckError>) {
        *self.verdict.lock().unwrap() = v;
    }
}

/// An instance whose mirror is a directory: `<dir>/v1/updates/…`.
struct FakeInstance {
    project: ToyProject,
    dir: tempfile::TempDir,
    info: Arc<Mutex<UpdatesInfo>>,
    url: Url,
}

impl FakeInstance {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let info = Arc::new(Mutex::new(UpdatesInfo {
            available: true,
            channel: "stable".into(),
        }));
        let i = info.clone();
        let app = Router::new()
            .route(
                "/v1/updates",
                get(move || {
                    let i = i.lock().unwrap().clone();
                    async move { Json(i) }
                }),
            )
            .fallback_service(tower_http::services::ServeDir::new(dir.path()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeInstance {
            project: ToyProject::new(now() + 365 * DAY_MS),
            dir,
            info,
            url: faro_service::link::parse_instance_url(&format!("http://{addr}")).unwrap(),
        }
    }

    fn mirror(&self) -> PathBuf {
        self.dir.path().join("v1/updates")
    }

    fn publish(&mut self, artifacts: &[Artifact]) -> faro_update::testing::Release {
        let dir = self.mirror();
        self.project
            .publish(&dir, artifacts, now() + 7 * DAY_MS)
            .unwrap()
    }

    fn set_channel(&self, ch: &str) {
        self.info.lock().unwrap().channel = ch.into();
    }
}

struct Device {
    _tmp: tempfile::TempDir,
    dir: StateDir,
}

fn device() -> Device {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path().join("state")).unwrap();
    Device { _tmp: tmp, dir }
}

fn updater(
    inst: &FakeInstance,
    dev: &Device,
    spec: ClientSpec,
    installer: Option<Arc<FakeInstaller>>,
    clock: Arc<dyn Clock>,
) -> ClientUpdater {
    let fetch = UpdateFetcher::new(inst.url.clone(), &ClientOptions::default()).unwrap();
    ClientUpdater::new(
        dev.dir.clone(),
        inst.project.first_root(),
        fetch,
        clock,
        spec,
        installer.map(|i| i as Arc<dyn Installer>),
    )
    .unwrap()
}

fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock::new())
}

#[tokio::test]
async fn installs_the_newest_stable_release_for_this_computer() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();
    let installer = Arc::new(FakeInstaller::default());
    let u = updater(
        &inst,
        &dev,
        spec("1.0.0"),
        Some(installer.clone()),
        system_clock(),
    );

    let out = u.check().await.unwrap();
    assert_eq!(
        out,
        Outcome::Installing {
            version: Version::new(1, 2, 0)
        }
    );
    // Not the beta, not another arch, platform or kind: exactly these bytes.
    assert_eq!(
        installer.calls(),
        vec![(PKG.to_owned(), b"pkg 1.2.0".to_vec())]
    );
    let pending = u.attempts().unwrap().pending.unwrap();
    assert_eq!(pending.version, "1.2.0");
    assert_eq!(pending.from_version, "1.0.0");
    assert!(dev.dir.exists(TRUST_FILE), "trust state persisted");

    // Until it is settled, a second check doesn't start another install.
    assert!(matches!(
        u.check().await.unwrap(),
        Outcome::InstallPending { .. }
    ));
    assert_eq!(installer.calls().len(), 1);
}

#[tokio::test]
async fn follows_the_instance_channel_but_never_downgrades() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();

    inst.set_channel("beta");
    let u = updater(&inst, &dev, spec("1.0.0"), None, system_clock());
    assert_eq!(
        u.check().await.unwrap(),
        Outcome::NotInstallable {
            version: Version::parse("1.3.0-beta.1").unwrap()
        },
        "no installer: reported, never installed"
    );

    // stable-1 selects 1.1.0; a computer already on 1.2.0 keeps it.
    inst.set_channel("stable-1");
    let u = updater(&inst, &dev, spec("1.2.0"), None, system_clock());
    assert_eq!(u.check().await.unwrap(), Outcome::UpToDate);
    let u = updater(&inst, &dev, spec("1.2.0"), None, system_clock());
    inst.set_channel("stable");
    assert_eq!(u.check().await.unwrap(), Outcome::UpToDate);
    // An invalid channel from the instance falls back to stable.
    inst.set_channel("Not A Channel");
    let u = updater(&inst, &dev, spec("1.1.0"), None, system_clock());
    assert_eq!(
        u.check().await.unwrap(),
        Outcome::NotInstallable {
            version: Version::new(1, 2, 0)
        }
    );
}

#[tokio::test]
async fn an_instance_without_a_release_offers_nothing() {
    let inst = FakeInstance::start().await;
    let dev = device();
    inst.info.lock().unwrap().available = false;
    let u = updater(&inst, &dev, spec("1.0.0"), None, system_clock());
    assert_eq!(u.check().await.unwrap(), Outcome::Unavailable);
}

/// A malicious instance can't get anything installed: not a forged
/// release, not a rolled-back one, not bytes that don't match.
#[tokio::test]
async fn a_malicious_instance_gets_nothing_installed() {
    let mut inst = FakeInstance::start().await;
    let dev = device();
    let installer = Arc::new(FakeInstaller::default());

    // Release 1 (1.1.0 only) is seen first, then release 2.
    let r1 = inst.publish(&catalog()[..1]);
    let u = updater(
        &inst,
        &dev,
        spec("1.1.0"),
        Some(installer.clone()),
        system_clock(),
    );
    assert_eq!(u.check().await.unwrap(), Outcome::UpToDate);
    inst.publish(&catalog()[..2]);
    let u = updater(
        &inst,
        &dev,
        spec("1.2.0"),
        Some(installer.clone()),
        system_clock(),
    );
    assert_eq!(u.check().await.unwrap(), Outcome::UpToDate);

    // Rolled back to release 1.
    write_release(&inst.mirror(), &r1).unwrap();
    let err = u.check().await.unwrap_err();
    assert!(matches!(err, CheckError::Verify(_)), "{err}");
    assert!(err.to_string().contains("rollback"), "{err}");

    // A release signed by someone else.
    let mut other = ToyProject::new(now() + 365 * DAY_MS);
    let forged = other.release(&[mac(PKG, "9.9.9", b"evil")], now() + DAY_MS);
    write_release(&inst.mirror(), &forged).unwrap();
    let err = u.check().await.unwrap_err();
    assert!(err.to_string().contains("threshold"), "{err}");

    // A genuine release whose package bytes the instance swapped.
    let mut evil = mac("client/macos/aarch64/Faro-1.4.0.pkg", "1.4.0", b"pkg 1.4.0");
    inst.publish(&[evil.clone()]);
    evil.content = b"pkg 1.4.X".to_vec();
    faro_update::testing::write_artifact(&inst.mirror(), &evil).unwrap();
    let err = u.check().await.unwrap_err();
    assert!(err.to_string().contains("hash mismatch"), "{err}");

    assert!(installer.calls().is_empty());
    let downloads = std::fs::read_dir(dev.dir.path().join("updates"))
        .unwrap()
        .count();
    assert_eq!(downloads, 0, "nothing unverified is left on disk");
}

#[tokio::test]
async fn root_rotations_are_followed() {
    let mut inst = FakeInstance::start().await;
    let (v, root2) = inst.project.rotate_root();
    write_root(&inst.mirror(), v, &root2).unwrap();
    inst.publish(&catalog());
    let dev = device();
    let u = updater(&inst, &dev, spec("1.2.0"), None, system_clock());
    assert_eq!(u.check().await.unwrap(), Outcome::UpToDate);
    let trust: serde_json::Value = dev.dir.read_json(TRUST_FILE).unwrap().unwrap();
    assert_eq!(trust["root"]["version"], 2);
}

/// A package that doesn't install counts a failure at the next start, and
/// after a few it is skipped. One that does clears the record.
#[tokio::test]
async fn failed_installs_are_counted_and_eventually_skipped() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();
    let clock = ManualClock::new(now(), 0);
    let installer = Arc::new(FakeInstaller::default());

    for attempt in 1..=MAX_INSTALL_ATTEMPTS {
        let u = updater(
            &inst,
            &dev,
            spec("1.0.0"),
            Some(installer.clone()),
            Arc::new(clock.clone()),
        );
        assert!(matches!(
            u.check().await.unwrap(),
            Outcome::Installing { .. }
        ));
        // The service comes back still on 1.0.0. Too soon to judge…
        let u = updater(
            &inst,
            &dev,
            spec("1.0.0"),
            Some(installer.clone()),
            Arc::new(clock.clone()),
        );
        assert_eq!(u.settle_pending().unwrap(), None);
        // …and after the grace period, a failure.
        clock.jump_wall(PENDING_GRACE_MS + 1);
        assert_eq!(
            u.settle_pending().unwrap(),
            Some(Settled::Failed {
                version: "1.2.0".into(),
                failures: attempt
            })
        );
    }
    let u = updater(
        &inst,
        &dev,
        spec("1.0.0"),
        Some(installer.clone()),
        Arc::new(clock.clone()),
    );
    assert_eq!(
        u.check().await.unwrap(),
        Outcome::GaveUp {
            version: Version::new(1, 2, 0)
        }
    );
    assert_eq!(installer.calls().len() as u32, MAX_INSTALL_ATTEMPTS);

    // The project publishes 1.2.1: a new package, a fresh start.
    let mut cat = catalog();
    cat.push(mac(
        "client/macos/aarch64/Faro-1.2.1.pkg",
        "1.2.1",
        b"pkg 1.2.1",
    ));
    inst.publish(&cat);
    assert!(matches!(
        u.check().await.unwrap(),
        Outcome::Installing { .. }
    ));
    // This one takes: the next start runs 1.2.1 and clears the record.
    let u = updater(
        &inst,
        &dev,
        spec("1.2.1"),
        Some(installer.clone()),
        Arc::new(clock.clone()),
    );
    assert_eq!(
        u.settle_pending().unwrap(),
        Some(Settled::Installed {
            version: "1.2.1".into()
        })
    );
    let attempts = u.attempts().unwrap();
    assert!(attempts.pending.is_none());
    assert!(dev.dir.exists(ATTEMPTS_FILE));
}

#[tokio::test]
async fn an_installer_that_refuses_counts_as_a_failure_at_once() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();
    let installer = Arc::new(FakeInstaller {
        refuse: true,
        ..FakeInstaller::default()
    });
    let u = updater(&inst, &dev, spec("1.0.0"), Some(installer), system_clock());
    assert!(matches!(
        u.check().await.unwrap_err(),
        CheckError::Install(_)
    ));
    let a = u.attempts().unwrap();
    assert!(a.pending.is_none());
    assert_eq!(a.failures.values().copied().collect::<Vec<_>>(), vec![1]);
}

/// The metadata approves a package that isn't Faro's (the update keys
/// leaked): it is never installed, nothing is left pending, it is reported
/// once, and it is never tried again. The next release is.
#[tokio::test]
async fn a_package_that_fails_its_signature_check_is_never_installed() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();
    let installer = Arc::new(FakeInstaller::default());
    installer.set_verdict(Some(PackageCheckError::Rejected(
        "signed by team ZZZZZ99999, not ABCDE12345".into(),
    )));
    let u = updater(
        &inst,
        &dev,
        spec("1.0.0"),
        Some(installer.clone()),
        system_clock(),
    );

    assert_eq!(
        u.check().await.unwrap(),
        Outcome::Rejected {
            version: Version::new(1, 2, 0),
            reason: "signed by team ZZZZZ99999, not ABCDE12345".into()
        }
    );
    assert_eq!(installer.checked(), [PKG]);
    assert!(installer.calls().is_empty(), "never installed");
    let a = u.attempts().unwrap();
    assert!(a.pending.is_none(), "no install recorded");
    assert!(a.failures.is_empty());
    assert_eq!(a.rejected.len(), 1);

    // Later checks don't download or check it again, even if a check
    // would now pass. They give the reason, for the service to report.
    installer.set_verdict(None);
    assert_eq!(
        u.check().await.unwrap(),
        Outcome::PreviouslyRejected {
            version: Version::new(1, 2, 0),
            reason: "signed by team ZZZZZ99999, not ABCDE12345".into()
        }
    );
    assert_eq!(installer.checked().len(), 1);
    assert!(installer.calls().is_empty());

    // A new release is a new package.
    let mut cat = catalog();
    cat.push(mac(
        "client/macos/aarch64/Faro-1.2.1.pkg",
        "1.2.1",
        b"pkg 1.2.1",
    ));
    inst.publish(&cat);
    assert!(matches!(
        u.check().await.unwrap(),
        Outcome::Installing { .. }
    ));
    assert_eq!(
        installer.calls(),
        vec![(
            "client/macos/aarch64/Faro-1.2.1.pkg".to_owned(),
            b"pkg 1.2.1".to_vec()
        )]
    );
}

/// A check that can't conclude (a tool failed, Gatekeeper couldn't confirm
/// notarization) installs nothing, records nothing, and is tried again.
#[tokio::test]
async fn an_unconfirmed_signature_installs_nothing_and_is_retried() {
    let mut inst = FakeInstance::start().await;
    inst.publish(&catalog());
    let dev = device();
    let installer = Arc::new(FakeInstaller::default());
    installer.set_verdict(Some(PackageCheckError::Unconfirmed(
        "spctl: timed out".into(),
    )));
    let u = updater(
        &inst,
        &dev,
        spec("1.0.0"),
        Some(installer.clone()),
        system_clock(),
    );
    assert!(matches!(
        u.check().await.unwrap_err(),
        CheckError::Package(PackageCheckError::Unconfirmed(_))
    ));
    assert!(installer.calls().is_empty());
    let a = u.attempts().unwrap();
    assert!(a.pending.is_none() && a.failures.is_empty() && a.rejected.is_empty());

    installer.set_verdict(None);
    assert!(matches!(
        u.check().await.unwrap(),
        Outcome::Installing { .. }
    ));
    assert_eq!(installer.checked(), [PKG, PKG]);
    assert_eq!(installer.calls().len(), 1);
}

/// Against the real instance: the mirror imports a release, and a client
/// trusting only the project root installs what it serves.
#[tokio::test]
async fn installs_through_a_real_faro_server_mirror() {
    let project_dir = tempfile::tempdir().unwrap();
    let mut project = ToyProject::new(now() + 365 * DAY_MS);
    let root_file = project_dir.path().join("root.json");
    std::fs::write(&root_file, project.first_root()).unwrap();
    let release_dir = project_dir.path().join("release");
    project
        .publish(&release_dir, &catalog(), now() + 7 * DAY_MS)
        .unwrap();

    let t = server::TestApp::with_config(move |c| c.updates.root = Some(root_file)).await;
    t.state
        .updates()
        .unwrap()
        .refresh_from(
            &faro_server::updates::upstream::Upstream::Dir(release_dir),
            now(),
            &faro_update::Channel::stable(),
            faro_server::updates::Prefetch::All,
        )
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = faro_server::router::build(t.state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let dev = device();
    let installer = Arc::new(FakeInstaller::default());
    let url = faro_service::link::parse_instance_url(&format!("http://{addr}")).unwrap();
    let u = ClientUpdater::new(
        dev.dir.clone(),
        project.first_root(),
        UpdateFetcher::new(url, &ClientOptions::default()).unwrap(),
        system_clock(),
        spec("1.0.0"),
        Some(installer.clone() as Arc<dyn Installer>),
    )
    .unwrap();
    assert!(matches!(
        u.check().await.unwrap(),
        Outcome::Installing { .. }
    ));
    assert_eq!(
        installer.calls(),
        vec![(PKG.to_owned(), b"pkg 1.2.0".to_vec())]
    );
}

#[allow(dead_code, clippy::all)]
#[path = "../../../server/tests/common/mod.rs"]
mod server;
