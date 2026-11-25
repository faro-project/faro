//! Real Unix-domain-socket tests: directory checks, socket permissions,
//! peer credentials, verifier rejection and an end-to-end frame transfer.
#![cfg(unix)]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use faro_ipc::handshake::AgentHello;
use faro_ipc::{
    accept_agent, hello, AgentMsg, AllowSameUid, AllowUids, BindOptions, IpcClient, IpcError,
    IpcServer, PeerInfo, ServiceMsg, HELLO_TIMEOUT,
};
use faro_platform::PixelFormat;

fn euid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

fn egid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::getegid() }
}

/// A private tempdir with a short path (macOS limits socket paths to 104 B).
fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o777
}

#[tokio::test]
async fn end_to_end_handshake_and_frames() {
    let dir = private_dir();
    let path = dir.path().join("agent.sock");
    let server = IpcServer::bind(&path, AllowSameUid).unwrap();
    assert_eq!(mode_of(server.path()), 0o600);

    let srv_path = server.path().to_path_buf();
    let client = tokio::spawn(async move {
        let mut conn = IpcClient::connect_verified(&srv_path, &AllowSameUid)
            .await
            .unwrap();
        // The agent sees the service's credentials too.
        let sp = *conn.peer().unwrap();
        assert_eq!(sp.uid, euid());
        let welcome = hello(
            &mut conn,
            AgentHello::new("0.1.0", "console", "alice"),
            HELLO_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(welcome.protocol_version, faro_ipc::PROTOCOL_VERSION);

        // Wait for a capture request, answer with a 2-display capture.
        let ServiceMsg::CaptureNow { .. } = conn.recv().await.unwrap() else {
            panic!("expected CaptureNow");
        };
        let big = faro_platform::Frame::new(
            1920,
            1080,
            PixelFormat::Bgra8,
            1,
            vec![0x40; 1920 * 1080 * 4],
        )
        .unwrap();
        let frames = vec![
            faro_ipc::WireFrame::from_frame(big),
            frame(100, 50, 0x7F, 2),
        ];
        for m in AgentMsg::frames_batches(123, frames) {
            conn.send(&m).await.unwrap();
        }
        // Liveness.
        let ServiceMsg::Ping { nonce } = conn.recv().await.unwrap() else {
            panic!("expected Ping");
        };
        conn.send(&AgentMsg::Pong { nonce }).await.unwrap();
        conn.send(&AgentMsg::Goodbye).await.unwrap();
    });

    let mut conn = server.accept().await.unwrap();
    let peer: PeerInfo = *conn.peer().unwrap();
    assert_eq!(peer.uid, euid());
    assert_eq!(peer.gid, egid());
    assert_eq!(peer.pid, Some(std::process::id()));
    if cfg!(target_vendor = "apple") {
        let token = peer.macos_audit_token.expect("audit token on macOS");
        assert_eq!(token[1], euid(), "audit token euid");
        assert_eq!(token[5], std::process::id(), "audit token pid");
    }

    // accept_agent checks Hello.pid against the kernel's pid: same process.
    let h = accept_agent(&mut conn, HELLO_TIMEOUT).await.unwrap();
    assert_eq!(h.user, "alice");
    assert_eq!(h.pid, std::process::id());

    conn.send(&ServiceMsg::CaptureNow {
        reason: faro_ipc::CaptureReason::Startup,
    })
    .await
    .unwrap();
    let AgentMsg::Frames {
        captured_at_mono_ms,
        frames,
    } = conn.recv().await.unwrap()
    else {
        panic!("expected Frames");
    };
    assert_eq!(captured_at_mono_ms, 123);
    let mut frames = frames.into_iter();
    let f1 = frames.next().unwrap().into_frame().unwrap();
    assert_eq!((f1.width(), f1.height(), f1.display_id()), (768, 432, 1));
    assert_eq!(f1.format(), PixelFormat::Bgra8);
    assert!(f1.pixels().iter().all(|&b| b == 0x40));
    let f2 = frames.next().unwrap().into_frame().unwrap();
    assert_eq!((f2.width(), f2.height(), f2.display_id()), (100, 50, 2));
    assert!(f2.pixels().iter().all(|&b| b == 0x7F));
    assert!(frames.next().is_none());

    let rtt = faro_ipc::ping(&mut conn, Duration::from_secs(5), |m| {
        panic!("unexpected {}", m.kind())
    })
    .await
    .unwrap();
    assert!(rtt < Duration::from_secs(5));
    assert_eq!(conn.recv().await.unwrap(), AgentMsg::Goodbye);
    assert!(matches!(conn.recv().await, Err(IpcError::Closed)));
    client.await.unwrap();

    // Drop removes our socket file.
    let p = server.path().to_path_buf();
    drop(server);
    assert!(!p.exists());
    // No staging directories were left behind.
    let leftovers: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".faro-ipc"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn rejected_peer_is_disconnected_and_server_keeps_serving() {
    let dir = private_dir();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    // Reject the first peer (as if its uid were wrong), accept the second.
    let verifier = move |p: &PeerInfo| {
        if c.fetch_add(1, Ordering::SeqCst) == 0 {
            AllowUids::new([p.uid.wrapping_add(1)]).verify_peer(p)
        } else {
            AllowSameUid.verify_peer(p)
        }
    };
    let server = IpcServer::bind(dir.path().join("s.sock"), verifier).unwrap();
    let path = server.path().to_path_buf();

    let mut rejected = IpcClient::connect(&path).await.unwrap();
    let e = server.accept().await.unwrap_err();
    assert!(matches!(e, IpcError::PeerRejected(_)), "{e:?}");
    // The rejected client sees the connection closed with nothing sent.
    let r = rejected.recv().await;
    assert!(
        matches!(r, Err(IpcError::Closed))
            || matches!(&r, Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionReset),
        "{r:?}"
    );

    let mut ok = IpcClient::connect(&path).await.unwrap();
    let mut conn = server.accept().await.unwrap();
    ok.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(conn.recv().await.unwrap(), AgentMsg::Goodbye);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// Small extension so the closures above read naturally.
trait VerifyExt {
    fn verify_peer(&self, p: &PeerInfo) -> faro_ipc::Result<()>;
}
impl<T: faro_ipc::PeerVerifier> VerifyExt for T {
    fn verify_peer(&self, p: &PeerInfo) -> faro_ipc::Result<()> {
        self.verify(p)
    }
}

#[tokio::test]
async fn agent_refuses_non_root_server() {
    if euid() == 0 {
        return; // the property is about an impostor; meaningless as root
    }
    let dir = private_dir();
    let server = IpcServer::bind(dir.path().join("s.sock"), AllowSameUid).unwrap();
    let r = IpcClient::connect_verified(server.path(), &AllowUids::root()).await;
    assert!(matches!(r, Err(IpcError::PeerRejected(_))), "{r:?}");
}

#[tokio::test]
async fn world_or_group_writable_dir_is_rejected() {
    for mode in [0o777, 0o770, 0o722, 0o1777] {
        let dir = private_dir();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        let r = IpcServer::bind(dir.path().join("s.sock"), AllowSameUid);
        assert!(
            matches!(r, Err(IpcError::InsecureSocketDir { .. })),
            "mode {mode:o}: {r:?}"
        );
        assert!(!dir.path().join("s.sock").exists());
    }
}

#[tokio::test]
async fn writable_ancestor_rejected_unless_sticky() {
    let root = private_dir();
    let mid = root.path().join("m");
    let leaf = mid.join("l");
    fs::create_dir_all(&leaf).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();

    fs::set_permissions(&mid, fs::Permissions::from_mode(0o777)).unwrap();
    let r = IpcServer::bind(leaf.join("s.sock"), AllowSameUid);
    assert!(
        matches!(&r, Err(IpcError::InsecureSocketDir { path, .. }) if path.ends_with("m")),
        "{r:?}"
    );

    // Sticky world-writable ancestors (like /tmp) are fine.
    fs::set_permissions(&mid, fs::Permissions::from_mode(0o1777)).unwrap();
    let server = IpcServer::bind(leaf.join("s.sock"), AllowSameUid).unwrap();
    drop(server);
}

#[tokio::test]
async fn symlinked_parent_is_resolved_and_checked() {
    let real = private_dir();
    let links = private_dir();
    let link = links.path().join("ln");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();
    let server = IpcServer::bind(link.join("s.sock"), AllowSameUid).unwrap();
    assert_eq!(
        server.path(),
        fs::canonicalize(real.path()).unwrap().join("s.sock")
    );

    // A symlink pointing into an insecure directory is caught after
    // resolution.
    let bad = private_dir();
    fs::set_permissions(bad.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let link2 = links.path().join("ln2");
    std::os::unix::fs::symlink(bad.path(), &link2).unwrap();
    assert!(matches!(
        IpcServer::bind(link2.join("s.sock"), AllowSameUid),
        Err(IpcError::InsecureSocketDir { .. })
    ));
}

#[tokio::test]
async fn stale_socket_is_replaced_live_one_is_not() {
    let dir = private_dir();
    let path = dir.path().join("s.sock");
    {
        // Simulate a crash: a bound socket file whose listener is gone.
        let _l = std::os::unix::net::UnixListener::bind(&path).unwrap();
    }
    assert!(path.exists());
    let server = IpcServer::bind(&path, AllowSameUid).unwrap();
    // And it works.
    let mut c = IpcClient::connect(server.path()).await.unwrap();
    let mut s = server.accept().await.unwrap();
    c.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(s.recv().await.unwrap(), AgentMsg::Goodbye);

    // A second server must not steal the live socket.
    let r = IpcServer::bind(&path, AllowSameUid);
    assert!(matches!(r, Err(IpcError::AddrInUse(_))), "{r:?}");
    // The first server's socket is untouched and still accepting.
    let _c2 = IpcClient::connect(server.path()).await.unwrap();
    let _s2 = server.accept().await.unwrap();
}

#[tokio::test]
async fn non_socket_at_path_is_never_replaced() {
    let dir = private_dir();
    let path = dir.path().join("s.sock");
    fs::write(&path, b"precious").unwrap();
    let r = IpcServer::bind(&path, AllowSameUid);
    assert!(
        matches!(r, Err(IpcError::InvalidSocketPath { .. })),
        "{r:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), b"precious");

    let target = dir.path().join("target");
    fs::write(&target, b"x").unwrap();
    let link = dir.path().join("link.sock");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(matches!(
        IpcServer::bind(&link, AllowSameUid),
        Err(IpcError::InvalidSocketPath { .. })
    ));
    assert_eq!(fs::read(&target).unwrap(), b"x");
}

#[tokio::test]
async fn group_mode_applies_mode_and_group() {
    let dir = private_dir();
    let server = IpcServer::bind_with(
        dir.path().join("s.sock"),
        BindOptions::group_access(egid()),
        AllowSameUid,
    )
    .unwrap();
    let md = fs::symlink_metadata(server.path()).unwrap();
    assert_eq!(md.mode() & 0o777, 0o660);
    assert_eq!(md.gid(), egid());

    let r = IpcServer::bind_with(
        dir.path().join("t.sock"),
        BindOptions {
            mode: 0o666,
            ..BindOptions::default()
        },
        AllowSameUid,
    );
    assert!(matches!(r, Err(IpcError::InvalidOptions(_))));
}

#[tokio::test]
async fn drop_does_not_remove_a_replacement_socket() {
    let dir = private_dir();
    let path = dir.path().join("s.sock");
    let server = IpcServer::bind(&path, AllowSameUid).unwrap();
    let real = server.path().to_path_buf();
    // Someone (e.g. an admin) replaces the socket file with a new one.
    fs::remove_file(&real).unwrap();
    let _other = std::os::unix::net::UnixListener::bind(&real).unwrap();
    drop(server);
    assert!(real.exists(), "server deleted a socket it did not create");
}

#[tokio::test]
async fn slow_hello_times_out_over_a_real_socket() {
    let dir = private_dir();
    let server = IpcServer::bind(dir.path().join("s.sock"), AllowSameUid).unwrap();
    let _silent = IpcClient::connect(server.path()).await.unwrap();
    let mut conn = server.accept().await.unwrap();
    let r = accept_agent(&mut conn, Duration::from_millis(50)).await;
    assert!(matches!(r, Err(IpcError::Timeout { .. })), "{r:?}");
}

#[tokio::test]
async fn garbage_from_a_verified_peer_is_a_typed_error() {
    use tokio::io::AsyncWriteExt;
    let dir = private_dir();
    let server = IpcServer::bind(dir.path().join("s.sock"), AllowSameUid).unwrap();
    let mut raw = tokio::net::UnixStream::connect(server.path())
        .await
        .unwrap();
    let mut conn = server.accept().await.unwrap();
    raw.write_all(b"\x89PNG\r\n\x1a\n not raw pixels")
        .await
        .unwrap();
    assert!(matches!(conn.recv().await, Err(IpcError::BadMagic)));
}

/// The enroll socket's own message types travel over the same transport,
/// one request and one answer per connection.
#[tokio::test]
async fn enroll_request_and_response_round_trip() {
    use faro_ipc::{
        EnrollClientConnection, EnrollRequest, EnrollResponse, EnrollServerConnection,
        EnrollStatus,
    };
    let dir = private_dir();
    let path = faro_ipc::enroll_socket_path(&dir.path().join("agent.sock"), None);
    let server = IpcServer::bind(&path, AllowSameUid).unwrap();
    assert_eq!(mode_of(server.path()), 0o600);
    let srv = tokio::spawn(async move {
        let mut conn: EnrollServerConnection<_> = server.accept_typed().await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), EnrollRequest::Status);
        conn.send(&EnrollResponse::Status(EnrollStatus {
            enrolled: false,
            instance_name: None,
            instance_url: None,
            endorsed: false,
        }))
        .await
        .unwrap();
    });
    let mut conn: EnrollClientConnection<_> =
        IpcClient::connect_verified_typed(&path, &AllowSameUid)
            .await
            .unwrap();
    conn.send(&EnrollRequest::Status).await.unwrap();
    match conn.recv().await.unwrap() {
        EnrollResponse::Status(s) => assert!(!s.enrolled),
        other => panic!("unexpected {other:?}"),
    }
    srv.await.unwrap();

    // A listener that is not who the agent expects gets nothing.
    let _server = IpcServer::bind(&path, AllowSameUid).unwrap();
    let other = AllowUids::new([euid().wrapping_add(1)]);
    let r = IpcClient::connect_verified_typed::<EnrollRequest, EnrollResponse>(&path, &other).await;
    assert!(matches!(r, Err(IpcError::PeerRejected(_))));
}
