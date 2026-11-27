//! The domain bundle from the signed update channel, served by the real
//! instance's update mirror (docs/IOS.md §7.2, §14; PROTOCOL.md §8.2).
//!
//! A toy project (`faro_update::testing`) signs the releases. The instance
//! is configured with its root and imports each release as an air-gapped
//! mirror would; the phone verifies against the root the test passes in,
//! as the app passes the one it ships with.

mod support;

use faro_detect::attribution::Attribution;
use faro_detect::{
    Category, DomainCategorizerBuilder, DomainSource, DomainsBundleInfo, DomainsManifest,
    DOMAINS_MANIFEST_FORMAT,
};
use faro_mobile::{DomainsUpdate, FaroError};
use faro_proto::body::{EventBody, TamperSignal};
use faro_server::updates::upstream::Upstream;
use faro_server::updates::Prefetch;
use faro_update::bundle::bundle_bytes;
use faro_update::testing::{Artifact, ToyProject, DAY_MS};
use faro_update::{Channel, TargetKind};
use std::path::PathBuf;
use support::{approved_phone, blocking, Phone, World};

fn now() -> i64 {
    use faro_core::Clock;
    faro_core::SystemClock::new().wall_ms()
}

fn domains_manifest(version: &str, bytes: &[u8]) -> DomainsManifest {
    DomainsManifest {
        format: DOMAINS_MANIFEST_FORMAT.into(),
        notice: "Compiled from the lists below.".into(),
        version: version.into(),
        bundle: DomainsBundleInfo {
            file: "domains.bin".into(),
            bytes: bytes.len() as u64,
            blake3: blake3::hash(bytes).to_hex().to_string(),
        },
        domains: 1,
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
            attribution: Some(Attribution {
                author: "Test Authors".into(),
                copyright: vec!["Copyright 2026 Test Authors".into()],
                source_url: "https://example.org/list".into(),
                license_url: "https://example.org/list/LICENSE".into(),
                changes: "None.".into(),
            }),
            lines: 1,
            domains: 1,
            skipped: 0,
        }],
        license_texts: [(
            "MIT".to_owned(),
            "Permission is hereby granted (test).".to_owned(),
        )]
        .into(),
    }
}

fn host(version: &str) -> String {
    format!("adult-{}.test", version.replace('.', "-"))
}

/// A blocklist target for `version`; `edit` changes its manifest.
fn blocklist_with(version: &str, edit: impl FnOnce(&mut DomainsManifest)) -> Artifact {
    let mut b = DomainCategorizerBuilder::new();
    b.add_domain(&host(version), Category::Adult).unwrap();
    let bytes = b.build().unwrap().to_bytes();
    let mut m = domains_manifest(version, &bytes);
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

/// The project, where it publishes, and an instance whose mirror trusts it.
struct Channelled {
    project: ToyProject,
    release_dir: tempfile::TempDir,
    w: World,
}

impl Channelled {
    async fn new() -> Self {
        let project = ToyProject::new(now() + 365 * DAY_MS);
        let release_dir = tempfile::tempdir().unwrap();
        let root_file = release_dir.path().join("trusted-root.json");
        std::fs::write(&root_file, project.first_root()).unwrap();
        let w = World::with_config(move |c| c.updates.root = Some(root_file)).await;
        Channelled {
            project,
            release_dir,
            w,
        }
    }

    fn dir(&self) -> PathBuf {
        self.release_dir.path().join("release")
    }

    /// Publish `artifacts` and have the instance import the release.
    async fn publish(&mut self, artifacts: &[Artifact]) {
        let dir = self.dir();
        self.project
            .publish(&dir, artifacts, now() + 7 * DAY_MS)
            .unwrap();
        let status = self
            .w
            .t
            .state
            .updates()
            .expect("mirror configured")
            .refresh_from(
                &Upstream::Dir(dir),
                self.w.t.clock_ms(),
                &Channel::stable(),
                Prefetch::All,
            )
            .await
            .expect("the instance imports the release");
        assert!(status.last_error.is_none(), "{:?}", status.last_error);
    }

    fn root(&self) -> Vec<u8> {
        self.project.first_root()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installs_newer_bundles_from_the_instance_mirror() {
    let mut ch = Channelled::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&ch.w, &phone).await;

    let c = core.clone();
    assert_eq!(blocking(move || c.installed_domains().unwrap()).await, None);
    ch.publish(&[blocklist("1.0.0")]).await;
    let (c, root) = (core.clone(), ch.root());
    let (first, again) = blocking(move || {
        (
            c.update_domains(root.clone()).unwrap(),
            c.update_domains(root).unwrap(),
        )
    })
    .await;
    let DomainsUpdate::Installed { info } = first else {
        panic!("{first:?}")
    };
    assert_eq!(info.version, "1.0.0");
    assert_eq!(info.domains, 1);
    assert_eq!(again, DomainsUpdate::UpToDate);
    let c = core.clone();
    let (installed, loaded) = blocking(move || {
        (
            c.installed_domains().unwrap(),
            c.load_installed_domains().unwrap(),
        )
    })
    .await;
    assert_eq!(installed, Some(info.clone()));
    let (loaded, _) = loaded.unwrap();
    assert_eq!(
        loaded
            .categorizer
            .categorize_url(&format!("https://{}/", host("1.0.0"))),
        vec![Category::Adult]
    );

    // A newer release replaces it, and the old directory goes.
    ch.publish(&[blocklist("1.0.0"), blocklist("1.1.0")]).await;
    let (c, root) = (core.clone(), ch.root());
    let second = blocking(move || c.update_domains(root).unwrap()).await;
    let DomainsUpdate::Installed { info: newer } = second else {
        panic!("{second:?}")
    };
    assert_eq!(newer.version, "1.1.0");
    assert!(!std::path::Path::new(&info.manifest_path).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_metadata_not_signed_under_the_root_passed_in() {
    let mut ch = Channelled::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&ch.w, &phone).await;
    ch.publish(&[blocklist("1.0.0")]).await;
    // Another project's root: the instance's release isn't signed by it.
    let other = ToyProject::new(now() + 365 * DAY_MS).first_root();
    let c = core.clone();
    let (wrong, garbage, installed) = blocking(move || {
        (
            c.update_domains(other),
            c.update_domains(b"not a root".to_vec()),
            c.installed_domains().unwrap(),
        )
    })
    .await;
    assert!(matches!(wrong, Err(FaroError::Update { .. })), "{wrong:?}");
    assert!(
        matches!(garbage, Err(FaroError::Update { .. })),
        "{garbage:?}"
    );
    assert_eq!(installed, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_bundle_that_fails_the_checks_is_rejected_for_good() {
    let mut ch = Channelled::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&ch.w, &phone).await;
    // Signed, but the manifest says another version than the target.
    ch.publish(&[blocklist_with("1.0.0", |m| m.version = "9.9.9".into())])
        .await;
    let (c, root) = (core.clone(), ch.root());
    let (first, again, installed) = blocking(move || {
        (
            c.update_domains(root.clone()).unwrap(),
            c.update_domains(root).unwrap(),
            c.installed_domains().unwrap(),
        )
    })
    .await;
    assert!(
        matches!(&first, DomainsUpdate::Rejected { version, .. } if version == "1.0.0"),
        "{first:?}"
    );
    assert_eq!(first, again, "recorded, not retried");
    assert_eq!(installed, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_bundle_that_changed_is_removed_and_reported() {
    let mut ch = Channelled::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&ch.w, &phone).await;
    ch.publish(&[blocklist("1.0.0")]).await;
    let (c, root) = (core.clone(), ch.root());
    let up = blocking(move || c.update_domains(root).unwrap()).await;
    let DomainsUpdate::Installed { info } = up else {
        panic!("{up:?}")
    };
    // Someone edits the installed list.
    let bin = std::path::Path::new(&info.manifest_path).with_file_name("domains.bin");
    std::fs::write(&bin, b"edited").unwrap();
    let c = core.clone();
    let (installed, events) = blocking(move || {
        (
            c.installed_domains().unwrap(),
            c.pending_events(10).unwrap(),
        )
    })
    .await;
    assert_eq!(installed, None);
    let body =
        faro_core::open_event_body(events.last().unwrap(), &ch.w.member, &ch.w.member_keys.enc)
            .unwrap();
    assert_eq!(
        body,
        EventBody::tamper(TamperSignal::IntegrityFailure {
            component: "domain list update (changed)".into()
        })
    );
    // The next update installs it again.
    let (c, root) = (core.clone(), ch.root());
    let again = blocking(move || c.update_domains(root).unwrap()).await;
    assert!(
        matches!(again, DomainsUpdate::Installed { .. }),
        "{again:?}"
    );
}
