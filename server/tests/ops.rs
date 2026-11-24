//! Operator tooling: `backup`, `doctor`, built-in TLS, and the workers
//! started by `serve`.

mod common;

use common::*;
use faro_proto::{EventKind, Urgency};
use faro_server::doctor::Level;
use std::io::Read;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn backup_is_a_consistent_restorable_snapshot() {
    let t = TestApp::new().await;
    let (_m, _s, _k, mut dev) = t.active_device().await;
    let evs = vec![
        dev.next_event(EventKind::Flag, Urgency::Urgent),
        dev.next_event(EventKind::Capture, Urgency::None),
    ];
    t.post_events(&dev, &evs).await;
    let cfg_path = t.dir.path().join("faro.toml");
    std::fs::write(&cfg_path, "dev = true\n").unwrap();
    let out = t.dir.path().join("backup.tar");

    let report = faro_server::backup::run(t.state.config(), Some(&cfg_path), &out)
        .await
        .unwrap();
    assert!(report.database_included);
    assert_eq!(report.blob_files, 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the archive holds the identity key");
    }

    // Unpack and check every part.
    let restore = t.dir.path().join("restore");
    std::fs::create_dir_all(&restore).unwrap();
    let mut names = Vec::new();
    let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
    for e in ar.entries().unwrap() {
        let mut e = e.unwrap();
        let path = e.path().unwrap().to_string_lossy().into_owned();
        if path == "BACKUP-INFO.txt" {
            let mut s = String::new();
            e.read_to_string(&mut s).unwrap();
            assert!(s.contains(t.state.instance_id().as_str()));
        }
        names.push(path);
        e.unpack_in(&restore).unwrap();
    }
    for must in ["BACKUP-INFO.txt", "faro.db", "identity.key", "faro.toml"] {
        assert!(names.iter().any(|n| n == must), "{must} missing: {names:?}");
    }
    assert_eq!(names.iter().filter(|n| n.starts_with("blobs/")).count(), 2);
    assert!(!names.iter().any(|n| n.contains("tmp")));
    assert_eq!(
        std::fs::read(restore.join("identity.key")).unwrap(),
        std::fs::read(t.state.config().data_dir.join("identity.key")).unwrap()
    );

    // The restored data directory boots as the same instance with the data.
    let mut cfg = t.state.config().clone();
    cfg.data_dir = restore.clone();
    let restored = faro_server::bootstrap::open(
        cfg,
        Arc::new(faro_server::mailer::TestMailer::new()),
        Arc::new(faro_server::clock::ManualClock::starting_now()),
    )
    .await
    .unwrap();
    assert_eq!(restored.instance_id(), t.state.instance_id());
    assert_eq!(count(&restored, "SELECT COUNT(*) FROM events").await, 2);
    let id: String = sqlx::Row::try_get(
        &sqlx::query("SELECT id FROM blobs LIMIT 1")
            .fetch_one(restored.db().pool())
            .await
            .unwrap(),
        "id",
    )
    .unwrap();
    let blob = restored
        .blobs()
        .get(&faro_server::blob::BlobId::parse(&id).unwrap())
        .await
        .unwrap();
    assert!(serde_json::from_slice::<faro_proto::EncryptedItem>(&blob).is_ok());

    // Never overwrites, and leaves no scratch files behind.
    assert!(matches!(
        faro_server::backup::run(t.state.config(), None, &out).await,
        Err(faro_server::backup::BackupError::Exists(_))
    ));
    let leftovers: Vec<_> = std::fs::read_dir(t.dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn backup_refuses_an_uninitialised_data_dir() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let r = faro_server::backup::run(&cfg, None, &dir.path().join("b.tar")).await;
    assert!(matches!(
        r,
        Err(faro_server::backup::BackupError::NotInitialized(_))
    ));
    assert!(!dir.path().join("data").join("faro.db").exists());
}

#[tokio::test]
async fn doctor_reports_problems_without_changing_anything() {
    // Fresh, never initialised: failures, and nothing created.
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let r = faro_server::doctor::run(&cfg, false).await;
    assert!(r.has_failures());
    assert_eq!(r.get("data_dir").unwrap().level, Level::Fail);
    assert_eq!(r.get("identity.key").unwrap().level, Level::Fail);
    assert_eq!(r.get("database").unwrap().level, Level::Fail);
    assert!(!cfg.data_dir.exists(), "doctor must not create anything");

    // An initialised dev instance.
    let t = TestApp::new().await;
    let r = faro_server::doctor::run(t.state.config(), false).await;
    let text = r.render();
    assert_eq!(r.get("database").unwrap().level, Level::Ok, "{text}");
    assert_eq!(r.get("identity").unwrap().level, Level::Ok, "{text}");
    assert_eq!(r.get("identity.key").unwrap().level, Level::Ok, "{text}");
    assert_eq!(
        r.get("tls").unwrap().level,
        Level::Warn,
        "dev is plain HTTP"
    );
    assert_eq!(
        r.get("smtp").unwrap().level,
        Level::Warn,
        "dev without SMTP"
    );
    assert!(r.get("disk").is_some());
    assert!(r
        .get("settings")
        .unwrap()
        .detail
        .contains("registration open"));

    // A world-readable identity key is a failure.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = t.state.config().data_dir.join("identity.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = faro_server::doctor::run(t.state.config(), false).await;
        assert_eq!(r.get("identity.key").unwrap().level, Level::Fail);
    }
    // A key that does not match the database is a failure.
    std::fs::write(t.state.config().data_dir.join("identity.key"), [7u8; 32]).unwrap();
    let r = faro_server::doctor::run(t.state.config(), false).await;
    assert_eq!(r.get("identity").unwrap().level, Level::Fail);
}

fn self_signed(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
    (cert, key, ck.cert.der().to_vec())
}

#[tokio::test]
async fn static_tls_serves_the_api_over_tls13() {
    let t = TestApp::new().await;
    let (cert, key, der) = self_signed(t.dir.path());
    let mode = faro_server::tls::load_static(&cert, &key).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(faro_server::server::run_tls(
        t.state.clone(),
        listener,
        mode,
        async {
            let _ = stop_rx.await;
        },
    ));

    // A plaintext client gets no HTTP answer.
    let mut plain = tokio::net::TcpStream::connect(addr).await.unwrap();
    plain
        .write_all(b"GET /.well-known/faro HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        plain.read_to_end(&mut buf),
    )
    .await;
    assert!(!String::from_utf8_lossy(&buf).contains("HTTP/1.1 200"));

    // A TLS client trusting the certificate gets the API.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(der))
        .unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    tls.write_all(
        b"GET /.well-known/faro HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = String::new();
    tls.read_to_string(&mut resp).await.unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.contains(t.state.instance_id().as_str()));

    stop_tx.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[test]
fn static_tls_rejects_bad_files() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = self_signed(dir.path());
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    assert!(faro_server::tls::load_static(&empty, &key).is_err());
    assert!(faro_server::tls::load_static(&cert, &empty).is_err());
    assert!(faro_server::tls::load_static(&dir.path().join("missing"), &key).is_err());
    // Key and certificate that do not belong together.
    let (_, other_key, _) = {
        let d2 = dir.path().join("2");
        std::fs::create_dir_all(&d2).unwrap();
        self_signed(&d2)
    };
    assert!(faro_server::tls::load_static(&cert, &other_key).is_err());
}

#[tokio::test]
async fn acme_mode_starts_without_network_and_stops_on_cancel() {
    let t = TestApp::with_config(|c| {
        c.public_url = "https://faro.example.org".into();
        c.tls.acme_domain = Some("faro.example.org".into());
        // An unroutable directory: the order fails and is retried, but
        // setting up the listener never blocks on it.
        c.tls.acme_directory = Some("https://127.0.0.1:9/directory".into());
    })
    .await;
    let cancel = tokio_util::sync::CancellationToken::new();
    let (mode, task) = faro_server::tls::from_config(t.state.config(), cancel.clone())
        .unwrap()
        .unwrap();
    assert!(format!("{mode:?}").contains("Acme"));
    assert!(t.state.config().data_dir.join("acme").is_dir());
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(5), task.unwrap())
        .await
        .expect("ACME task stops on cancel")
        .unwrap();
}

#[tokio::test]
async fn serve_runs_workers_and_stops_them_on_shutdown() {
    let t = TestApp::new().await;
    let (_m, _s, _k, mut dev) = t.active_device().await;
    let ev = dev.next_event(EventKind::Tamper, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(faro_server::server::run(t.state.clone(), listener, async {
        let _ = stop_rx.await;
    }));
    // The notifier worker picks up the tamper alert by itself.
    let mail = wait_for_mail(&t, "sam@example.org", "Urgent: new alert for sam").await;
    assert!(mail.text.contains("Open Faro to view"));
    stop_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(20), server)
        .await
        .expect("shutdown completes")
        .unwrap()
        .unwrap();
}
