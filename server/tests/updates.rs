//! The update mirror (§3.8): verification of what it caches, what it
//! serves, on-demand fetches, garbage collection, rollback and tamper
//! refusal, the admin channel setting, and that a client verifying against
//! the project root accepts exactly what the mirror serves.
//!
//! Releases are signed by a toy project (`faro_update::testing`). Online
//! mirrors fetch from a real HTTP server on localhost serving a directory;
//! air-gapped imports read the directory directly.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use faro_server::updates::upstream::Upstream;
use faro_server::updates::{Mirror, MirrorError, Prefetch};
use faro_update::testing::{
    write_artifact, write_release, write_root, Artifact, ToyProject, DAY_MS,
};
use faro_update::{Channel, TargetKind, Updater};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PKG_110: &str = "client/macos/aarch64/Faro-1.1.0.pkg";
const PKG_100: &str = "client/macos/aarch64/Faro-1.0.0.pkg";
const MODEL: &str = "models/explicit-1.0.0.onnx";
const SERVER: &str = "server/linux/aarch64/faro-server-1.1.0";

fn now() -> i64 {
    use faro_server::clock::Clock;
    faro_server::clock::SystemClock.now_ms()
}

fn catalog() -> Vec<Artifact> {
    vec![
        Artifact::new(
            PKG_100,
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.0.0",
            b"pkg 1.0.0",
        ),
        Artifact::new(
            PKG_110,
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.1.0",
            b"pkg 1.1.0",
        ),
        Artifact::new(
            MODEL,
            TargetKind::Model,
            "any",
            "any",
            "1.0.0",
            b"onnx weights",
        ),
        Artifact::new(
            SERVER,
            TargetKind::Server,
            "linux",
            "aarch64",
            "1.1.0",
            b"server",
        ),
    ]
}

/// A project, the directory it publishes to, and the root file an instance
/// is configured with.
struct Upstr {
    project: ToyProject,
    dir: tempfile::TempDir,
    root_file: PathBuf,
}

impl Upstr {
    fn new(now_ms: i64) -> Self {
        let project = ToyProject::new(now_ms + 365 * DAY_MS);
        let dir = tempfile::tempdir().unwrap();
        let root_file = dir.path().join("trusted-root.json");
        std::fs::write(&root_file, project.first_root()).unwrap();
        Upstr {
            project,
            dir,
            root_file,
        }
    }

    fn release_dir(&self) -> PathBuf {
        self.dir.path().join("release")
    }

    fn publish(
        &mut self,
        artifacts: &[Artifact],
        expires_ms: i64,
    ) -> faro_update::testing::Release {
        let dir = self.release_dir();
        self.project.publish(&dir, artifacts, expires_ms).unwrap()
    }
}

/// Serve `dir` over plain HTTP on localhost; returns the base URL.
async fn http_upstream(dir: PathBuf) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback_service(tower_http::services::ServeDir::new(dir));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn air_gapped(up: &Upstr) -> TestApp {
    let root = up.root_file.clone();
    TestApp::with_config(move |c| c.updates.root = Some(root)).await
}

async fn online(up: &Upstr) -> TestApp {
    let base = http_upstream(up.release_dir()).await;
    let root = up.root_file.clone();
    TestApp::with_config(move |c| {
        c.updates.root = Some(root);
        c.updates.upstream = Some(base);
    })
    .await
}

fn mirror(t: &TestApp) -> &Arc<Mirror> {
    t.state.updates().expect("mirror configured")
}

async fn import(
    t: &TestApp,
    dir: &Path,
) -> Result<faro_server::updates::MirrorStatus, MirrorError> {
    mirror(t)
        .refresh_from(
            &Upstream::Dir(dir.to_owned()),
            t.clock_ms(),
            &Channel::stable(),
            Prefetch::All,
        )
        .await
}

async fn refresh(t: &TestApp) -> Result<faro_server::updates::MirrorStatus, MirrorError> {
    let channel = t.state.settings().updates.channel.parse().unwrap();
    mirror(t).refresh(t.clock_ms(), &channel).await
}

fn cached_names(s: &faro_server::updates::MirrorStatus) -> Vec<String> {
    s.cached.iter().map(|a| a.name.clone()).collect()
}

#[tokio::test]
async fn off_without_a_root_of_trust() {
    let t = TestApp::new().await;
    assert!(t.state.updates().is_none());
    let r = t.get("/v1/updates", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body, json!({"available": false, "channel": "stable"}));
    for path in [
        "/v1/updates/timestamp.json",
        "/v1/updates/targets.json",
        "/v1/updates/roots/2.json",
        "/v1/updates/targets/anything",
    ] {
        assert_eq!(
            t.get(path, None).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn bootstrap_refuses_an_invalid_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root.json");
    std::fs::write(&root, b"{\"not\":\"a root\"}").unwrap();
    let mut cfg = common::test_config(dir.path());
    cfg.updates.root = Some(root);
    let err = faro_server::bootstrap::open(
        cfg,
        Arc::new(faro_server::mailer::TestMailer::new()),
        Arc::new(faro_server::clock::ManualClock::starting_now()),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("root of trust"), "{err}");
}

/// What the mirror serves is byte-for-byte what the project signed, and a
/// client that trusts only the project root accepts it and the artifact.
#[tokio::test]
async fn imported_release_is_served_and_verifies_for_a_client() {
    let now = now();
    let mut up = Upstr::new(now);
    let release = up.publish(&catalog(), now + 7 * DAY_MS);
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);

    let status = import(&t, &up.release_dir()).await.unwrap();
    assert!(status.last_error.is_none());
    assert_eq!(status.targets_version, Some(1));
    let mut names = cached_names(&status);
    names.sort();
    assert_eq!(
        names,
        vec![PKG_100, PKG_110, MODEL],
        "imports copy every client artifact"
    );

    let info = t.get("/v1/updates", None).await;
    assert_eq!(info.body, json!({"available": true, "channel": "stable"}));
    let ts = t.get("/v1/updates/timestamp.json", None).await;
    assert_eq!(ts.status, StatusCode::OK);
    assert_eq!(ts.headers["content-type"], "application/json");
    assert_eq!(ts.raw, release.timestamp);
    let tg = t.get("/v1/updates/targets.json", None).await;
    assert_eq!(tg.raw, release.targets);

    // A client: only the project root, then what the instance served.
    let mut client = Updater::bootstrap(&up.project.first_root()).unwrap();
    client.verify_timestamp(&ts.raw, now).unwrap();
    let verified = client.verify_targets(&tg.raw, now).unwrap();
    let pick = verified
        .select(
            &Channel::stable(),
            TargetKind::Client,
            "macos",
            "aarch64",
            None,
        )
        .unwrap();
    assert_eq!(pick.name, PKG_110);
    let art = t
        .get(&format!("/v1/updates/targets/{}", pick.name), None)
        .await;
    assert_eq!(art.status, StatusCode::OK);
    assert_eq!(art.headers["content-type"], "application/octet-stream");
    faro_update::verify_target_stream(&art.raw[..], &pick, 1 << 20).unwrap();

    // Server releases are never handed out; unknown names are 404.
    assert_eq!(
        t.get(&format!("/v1/updates/targets/{SERVER}"), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get("/v1/updates/targets/nope", None).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn artifacts_support_range_requests() {
    let now = now();
    let mut up = Upstr::new(now);
    up.publish(&catalog(), now + 7 * DAY_MS);
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);
    import(&t, &up.release_dir()).await.unwrap();
    let req = axum::http::Request::builder()
        .uri(format!("/v1/updates/targets/{PKG_110}"))
        .header("range", "bytes=4-")
        .body(axum::body::Body::empty())
        .unwrap();
    let r = t.send(req).await;
    assert_eq!(r.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(r.raw, b"1.1.0");
}

/// An online mirror prefetches only what the channel selects, fetches
/// anything else listed on first request, and never fetches server
/// releases.
#[tokio::test]
async fn online_mirror_prefetches_the_selection_and_fetches_the_rest_on_demand() {
    let now = now();
    let mut up = Upstr::new(now);
    up.publish(&catalog(), now + 7 * DAY_MS);
    let t = online(&up).await;
    t.clock.set_ms(now);

    let status = refresh(&t).await.unwrap();
    assert!(status.failed.is_empty(), "{:?}", status.failed);
    let mut names = cached_names(&status);
    names.sort();
    assert_eq!(names, vec![PKG_110, MODEL]);

    let old = t.get(&format!("/v1/updates/targets/{PKG_100}"), None).await;
    assert_eq!(old.status, StatusCode::OK);
    assert_eq!(old.raw, b"pkg 1.0.0");
    assert_eq!(
        t.get(&format!("/v1/updates/targets/{SERVER}"), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// Bytes that don't match the signed hash never enter the cache, from a
/// prefetch or an on-demand fetch.
#[tokio::test]
async fn tampered_artifacts_are_refused() {
    let now = now();
    let mut up = Upstr::new(now);
    let mut cat = catalog();
    up.publish(&cat, now + 7 * DAY_MS);
    // Same length, different bytes, for both client packages.
    for a in cat.iter_mut().filter(|a| a.kind == TargetKind::Client) {
        a.content = a.content.iter().map(|b| b ^ 1).collect();
        write_artifact(&up.release_dir(), a).unwrap();
    }
    let t = online(&up).await;
    t.clock.set_ms(now);

    let status = refresh(&t).await.unwrap();
    assert_eq!(cached_names(&status), vec![MODEL]);
    assert_eq!(status.failed.len(), 1);
    assert!(
        status.failed[0].contains("hash mismatch"),
        "{:?}",
        status.failed
    );

    let r = t.get(&format!("/v1/updates/targets/{PKG_100}"), None).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.error_code(), "upstream_unavailable");
    let artifacts = std::fs::read_dir(mirror(&t).dir().join("artifacts"))
        .unwrap()
        .count();
    assert_eq!(artifacts, 1, "only the model is stored");
}

/// Metadata the project didn't sign, or older than what the mirror has,
/// is refused, and the mirror keeps serving what it had.
#[tokio::test]
async fn forged_or_rolled_back_metadata_is_refused() {
    let now = now();
    let mut up = Upstr::new(now);
    let r1 = up.publish(&catalog(), now + 7 * DAY_MS);
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);
    import(&t, &up.release_dir()).await.unwrap();
    let r2 = up.publish(&catalog()[1..], now + 7 * DAY_MS);
    import(&t, &up.release_dir()).await.unwrap();

    // Roll back to release 1.
    write_release(&up.release_dir(), &r1).unwrap();
    let err = import(&t, &up.release_dir()).await.unwrap_err();
    assert!(err.to_string().contains("rollback"), "{err}");

    // A different project's release.
    let mut other = ToyProject::new(now + 365 * DAY_MS);
    let forged = other.release(&catalog(), now + 7 * DAY_MS);
    write_release(&up.release_dir(), &forged).unwrap();
    let err = import(&t, &up.release_dir()).await.unwrap_err();
    assert!(err.to_string().contains("threshold"), "{err}");

    let served = t.get("/v1/updates/targets.json", None).await;
    assert_eq!(served.raw, r2.targets, "still serving release 2");
    let status = mirror(&t).read_status();
    assert!(status.last_error.is_some());
    assert_eq!(status.targets_version, Some(2));
}

/// A new release replaces the old one, and artifacts it no longer lists
/// are deleted.
#[tokio::test]
async fn artifacts_no_longer_listed_are_removed() {
    let now = now();
    let mut up = Upstr::new(now);
    up.publish(&catalog(), now + 7 * DAY_MS);
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);
    import(&t, &up.release_dir()).await.unwrap();
    let count = || {
        std::fs::read_dir(mirror(&t).dir().join("artifacts"))
            .unwrap()
            .count()
    };
    assert_eq!(count(), 3);

    up.publish(&catalog()[1..], now + 7 * DAY_MS);
    let status = import(&t, &up.release_dir()).await.unwrap();
    assert_eq!(status.targets_version, Some(2));
    assert_eq!(count(), 2);
    assert_eq!(
        t.get(&format!("/v1/updates/targets/{PKG_100}"), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// After a restart the mirror serves what it had, without waiting for
/// upstream, unless it has expired since.
#[tokio::test]
async fn restart_serves_stored_metadata_until_it_expires() {
    let now = now();
    let mut up = Upstr::new(now);
    // Targets good for a week, the timestamp for a day.
    let release = up
        .project
        .release_expiring(&catalog(), now + 7 * DAY_MS, now + DAY_MS);
    write_release(&up.release_dir(), &release).unwrap();
    for a in catalog() {
        write_artifact(&up.release_dir(), &a).unwrap();
    }
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);
    import(&t, &up.release_dir()).await.unwrap();

    // A second mirror over the same directory, as after a restart.
    let reopened =
        Mirror::open(mirror(&t).dir().to_owned(), up.project.first_root(), None).unwrap();
    assert!(reopened.reload(now + 1000).unwrap());
    assert_eq!(reopened.served().unwrap().targets, release.targets);
    assert!(!reopened.reload(now + DAY_MS).unwrap(), "expired");
    assert!(reopened.served().is_none());

    // The project re-signs the timestamp; the next import serves again.
    let fresh = up.project.refresh_timestamp(&release, now + 3 * DAY_MS);
    write_release(&up.release_dir(), &fresh).unwrap();
    t.clock.set_ms(now + DAY_MS);
    import(&t, &up.release_dir()).await.unwrap();
    assert_eq!(
        t.get("/v1/updates/timestamp.json", None).await.raw,
        fresh.timestamp
    );
}

#[tokio::test]
async fn root_rotations_are_followed_and_served() {
    let now = now();
    let mut up = Upstr::new(now);
    let (v2, root2) = up.project.rotate_root();
    write_root(&up.release_dir(), v2, &root2).unwrap();
    up.publish(&catalog(), now + 7 * DAY_MS);
    let t = online(&up).await;
    t.clock.set_ms(now);

    let status = refresh(&t).await.unwrap();
    assert_eq!(status.root_version, Some(2));
    let r = t.get("/v1/updates/roots/2.json", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.raw, root2);
    assert_eq!(
        t.get("/v1/updates/roots/3.json", None).await.status,
        StatusCode::NOT_FOUND
    );
    // Root 1 the mirror never stored: passed through from upstream when
    // present there, otherwise 404 (clients ship root 1).
    assert_eq!(
        t.get("/v1/updates/roots/1.json", None).await.status,
        StatusCode::NOT_FOUND
    );
    write_root(&up.release_dir(), 1, &up.project.first_root()).unwrap();
    let r1 = t.get("/v1/updates/roots/1.json", None).await;
    assert_eq!(r1.raw, up.project.first_root());
    for bad in ["0.json", "x.json", "2", "2.json.bak"] {
        assert_eq!(
            t.get(&format!("/v1/updates/roots/{bad}"), None)
                .await
                .status,
            StatusCode::NOT_FOUND,
            "{bad}"
        );
    }
}

/// The admin's channel is what clients are told to follow and what the
/// mirror prefetches; it is validated like the config file.
#[tokio::test]
async fn admin_channel_setting_drives_clients_and_prefetch() {
    let now = now();
    let mut up = Upstr::new(now);
    let mut cat = catalog();
    cat.push(
        Artifact::new(
            "client/macos/aarch64/Faro-1.2.0-beta.1.pkg",
            TargetKind::Client,
            "macos",
            "aarch64",
            "1.2.0-beta.1",
            b"beta",
        )
        .channels(&["beta"]),
    );
    up.publish(&cat, now + 7 * DAY_MS);
    let t = online(&up).await;
    t.clock.set_ms(now);
    let (_, admin) = t.setup_admin("admin@example.org").await;

    let bad = t
        .call(
            Method::PATCH,
            "/admin/api/settings",
            Some(json!({"update_channel": "Beta!"})),
            Some(&admin),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.error_code(), "invalid_settings");

    let ok = t
        .call(
            Method::PATCH,
            "/admin/api/settings",
            Some(json!({"update_channel": "beta"})),
            Some(&admin),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.body);
    assert_eq!(ok.body["updates"]["channel"], "beta");
    let status = refresh(&t).await.unwrap();
    assert!(
        cached_names(&status).contains(&"client/macos/aarch64/Faro-1.2.0-beta.1.pkg".to_owned())
    );
    let info = t.get("/v1/updates", None).await;
    assert_eq!(info.body, json!({"available": true, "channel": "beta"}));
}

/// Models and blocklists (platform `any`) are prefetched like client
/// packages: the newest in the instance's channel, whatever `min_client`
/// it needs (older clients' choices are fetched on demand). A client
/// downloads exactly the signed bytes.
#[tokio::test]
async fn models_and_blocklists_are_prefetched_for_the_channel() {
    let now = now();
    let mut up = Upstr::new(now);
    let art = |name: &str, kind, version: &str| {
        Artifact::new(name, kind, "any", "any", version, name.as_bytes())
    };
    up.publish(
        &[
            art("model/any/m-1.0.0-stable.data", TargetKind::Model, "1.0.0"),
            art("model/any/m-1.1.0-beta.data", TargetKind::Model, "1.1.0").channels(&["beta"]),
            art(
                "blocklist/any/domains-1.0.0-stable.data",
                TargetKind::Blocklist,
                "1.0.0",
            ),
            art(
                "blocklist/any/domains-2.0.0-stable.data",
                TargetKind::Blocklist,
                "2.0.0",
            )
            .min_client("9.0.0"),
        ],
        now + 7 * DAY_MS,
    );
    let t = online(&up).await;
    t.clock.set_ms(now);

    let status = refresh(&t).await.unwrap();
    assert!(status.failed.is_empty(), "{:?}", status.failed);
    let mut names = cached_names(&status);
    names.sort();
    assert_eq!(
        names,
        [
            "blocklist/any/domains-2.0.0-stable.data",
            "model/any/m-1.0.0-stable.data"
        ]
    );
    let kinds: Vec<_> = status.cached.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&TargetKind::Model) && kinds.contains(&TargetKind::Blocklist));
    // The older list, for clients below its min_client, on demand.
    let old = t
        .get(
            "/v1/updates/targets/blocklist/any/domains-1.0.0-stable.data",
            None,
        )
        .await;
    assert_eq!(old.status, StatusCode::OK);
    assert_eq!(old.raw, b"blocklist/any/domains-1.0.0-stable.data");

    let status = mirror(&t)
        .refresh(t.clock_ms(), &Channel::Named("beta".into()))
        .await
        .unwrap();
    assert!(cached_names(&status).contains(&"model/any/m-1.1.0-beta.data".to_owned()));
}

#[tokio::test]
async fn doctor_reports_mirror_health() {
    use faro_server::doctor::{check_updates, Level, Report};
    let now = now();
    let mut up = Upstr::new(now);
    up.publish(&catalog(), now + DAY_MS);
    let t = air_gapped(&up).await;
    t.clock.set_ms(now);
    let level = |at: i64| {
        let mut r = Report::default();
        check_updates(t.state.config(), at, &mut r);
        r.get("updates")
            .map(|c| (c.level, c.detail.clone()))
            .unwrap()
    };

    let (l, d) = level(now);
    assert_eq!(l, Level::Warn);
    assert!(d.contains("no release mirrored yet"), "{d}");
    import(&t, &up.release_dir()).await.unwrap();
    let (l, d) = level(now);
    assert_eq!(l, Level::Ok, "{d}");
    let (l, d) = level(now + DAY_MS);
    assert_eq!(l, Level::Warn);
    assert!(d.contains("expired"), "{d}");

    let mut off = Report::default();
    check_updates(&common::test_config(t.dir.path()), now, &mut off);
    assert_eq!(off.get("updates").unwrap().level, Level::Warn);
}
