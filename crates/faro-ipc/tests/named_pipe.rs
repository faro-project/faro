//! Real named-pipe tests (Windows): the counterpart of `unix_socket.rs`.
//! Squatting and replacement, peer identity on both ends, verifier
//! rejection, an end-to-end frame transfer, and the accept loop's
//! behaviour under bursts, cancellation and clients that leave early.
//!
//! Everything runs as one account, so the checks that need a second
//! account (that another user cannot open the pipe or add an instance of
//! it) are covered by reading the applied security descriptor back, in the
//! unit tests of `named_pipe.rs`.
#![cfg(windows)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use faro_ipc::handshake::AgentHello;
use faro_ipc::{
    accept_agent, hello, AgentMsg, AllowSameUser, AllowSids, AllowSystemService, AllowUids,
    BindOptions, IpcClient, IpcError, IpcServer, PeerInfo, PeerVerifier, ServiceMsg, Sid,
    HELLO_TIMEOUT,
};
use faro_platform::PixelFormat;
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

/// A pipe name no other test (or concurrent test run) uses, in its own
/// "directory" so names derived from it (the enroll pipe) are unique too.
/// No dots, so the per-account and enroll names are built as for the real
/// `\\.\pipe\faro\agent`.
fn unique(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    PathBuf::from(format!(
        r"\\.\pipe\faro-ipc-test-{}-{}\{tag}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

fn me() -> Sid {
    faro_ipc::current_account().unwrap()
}

/// Does any instance of the per-account pipe `name` (`<base>.<our SID>`)
/// exist? Asked through the public API: `resolve_agent_socket` picks the
/// per-account name only when it exists.
fn exists(name: &Path) -> bool {
    let sid = me();
    let base = name
        .to_str()
        .unwrap()
        .strip_suffix(&format!(".{sid}"))
        .expect("a per-account name");
    let base = PathBuf::from(base);
    faro_ipc::resolve_agent_socket(&base, sid) != base
}

fn per_account(tag: &str) -> PathBuf {
    faro_ipc::session_socket_path(&unique(tag), me())
}

#[tokio::test]
async fn end_to_end_handshake_and_frames() {
    let name = per_account("agent");
    let server = IpcServer::bind(&name, AllowSameUser).unwrap();
    assert_eq!(server.path(), name);
    assert!(exists(&name));

    let srv_name = name.clone();
    let client = tokio::spawn(async move {
        let mut conn = IpcClient::connect_verified(&srv_name, &AllowSameUser)
            .await
            .unwrap();
        // The agent sees the service's identity too: pid, session, and the
        // pipe's owner.
        let sp = *conn.peer().unwrap();
        assert_eq!(sp.windows_sid, Some(me()));
        assert_eq!(sp.pid, Some(std::process::id()));
        assert_eq!(sp.uid, PeerInfo::NO_ID);
        let welcome = hello(
            &mut conn,
            AgentHello::new("0.1.0", "console", "alice"),
            HELLO_TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(welcome.protocol_version, faro_ipc::PROTOCOL_VERSION);

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
        let ServiceMsg::Ping { nonce } = conn.recv().await.unwrap() else {
            panic!("expected Ping");
        };
        conn.send(&AgentMsg::Pong { nonce }).await.unwrap();
        conn.send(&AgentMsg::Goodbye).await.unwrap();
        sp
    });

    let mut conn = server.accept().await.unwrap();
    let peer: PeerInfo = *conn.peer().unwrap();
    assert_eq!(peer.windows_sid, Some(me()));
    assert_eq!(peer.pid, Some(std::process::id()));
    assert_eq!((peer.uid, peer.gid), (PeerInfo::NO_ID, PeerInfo::NO_ID));
    assert!(peer.macos_audit_token.is_none());

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
    let sp = client.await.unwrap();
    // Both ends agree on the session (the same process is on both).
    assert_eq!(sp.windows_session_id, peer.windows_session_id);
    assert!(peer.windows_session_id.is_some());

    // Pipes leave nothing behind: once every handle is closed the name is
    // gone, and a new server can bind it (no stale endpoint to clean up).
    // (tokio closes a pipe handle once its pending I/O is cancelled, which
    // the runtime finishes shortly after the drop.)
    drop(conn);
    drop(server);
    let mut gone = false;
    for _ in 0..100 {
        if !exists(&name) {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(gone, "the pipe outlived its server");
    let again = IpcServer::bind(&name, AllowSameUser).unwrap();
    drop(again);
}

#[tokio::test]
async fn rejected_peer_is_disconnected_and_server_keeps_serving() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    // Reject the first peer (as if its account were wrong), accept the
    // second.
    let verifier = move |p: &PeerInfo| {
        if c.fetch_add(1, Ordering::SeqCst) == 0 {
            AllowSids::new(["S-1-5-21-1-2-3-1001".parse().unwrap()]).verify(p)
        } else {
            AllowSameUser.verify(p)
        }
    };
    let server = IpcServer::bind(unique("reject"), verifier).unwrap();
    let name = server.path().to_path_buf();

    let mut rejected = IpcClient::connect(&name).await.unwrap();
    let e = server.accept().await.unwrap_err();
    assert!(matches!(e, IpcError::PeerRejected(_)), "{e:?}");
    // The rejected client sees the connection closed with nothing sent.
    let r = rejected.recv().await;
    assert!(
        matches!(r, Err(IpcError::Closed))
            || matches!(&r, Err(IpcError::Io(e)) if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            )),
        "{r:?}"
    );
    // Writing to it fails too.
    assert!(rejected.send(&AgentMsg::Goodbye).await.is_err());

    let mut ok = IpcClient::connect(&name).await.unwrap();
    let mut conn = server.accept().await.unwrap();
    ok.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(conn.recv().await.unwrap(), AgentMsg::Goodbye);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn agent_refuses_a_server_that_is_not_the_system_service() {
    // A same-user "service" (what an impostor that took the name first
    // would be) fails every production check of the server.
    let server = Arc::new(IpcServer::bind(unique("impostor"), AllowSameUser).unwrap());
    // A pipe has no backlog beyond its waiting instance, so keep accepting
    // (as the service's accept loop does) for the next client to get one.
    let srv = server.clone();
    let accepting = tokio::spawn(async move {
        loop {
            drop(srv.accept().await);
        }
    });
    for v in [
        &AllowSystemService as &dyn PeerVerifier,
        &AllowSids::local_system(),
        &AllowUids::root(),
    ] {
        let r = IpcClient::connect_verified(server.path(), v).await;
        assert!(matches!(r, Err(IpcError::PeerRejected(_))), "{r:?}");
    }
    // The dev escape (`--trust-same-uid-service`) accepts it.
    IpcClient::connect_verified(server.path(), &AllowSameUser)
        .await
        .unwrap();
    accepting.abort();
}

#[tokio::test]
async fn a_squatted_name_is_refused_not_shared() {
    // Someone created the name first, with a default security descriptor.
    let name = unique("squat");
    let squatter = ServerOptions::new().create(&name).unwrap();
    let r = IpcServer::bind(&name, AllowSameUser);
    assert!(matches!(r, Err(IpcError::AddrInUse(_))), "{r:?}");
    // The squatter's pipe is untouched: a client still reaches it.
    let _c = ClientOptions::new().open(&name).unwrap();
    squatter.connect().await.unwrap();
}

#[tokio::test]
async fn a_live_server_is_not_stolen() {
    let name = unique("live");
    let server = IpcServer::bind(&name, AllowSameUser).unwrap();
    let r = IpcServer::bind(&name, AllowSameUser);
    assert!(matches!(r, Err(IpcError::AddrInUse(_))), "{r:?}");

    // Also after a client has connected, i.e. once the first instance has
    // been handed out and replaced: the name never lapses.
    let mut c = IpcClient::connect(&name).await.unwrap();
    let mut s = server.accept().await.unwrap();
    assert!(matches!(
        IpcServer::bind(&name, AllowSameUser),
        Err(IpcError::AddrInUse(_))
    ));
    exercise(&mut s, &mut c).await;
    drop((s, c));
    assert!(matches!(
        IpcServer::bind(&name, AllowSameUser),
        Err(IpcError::AddrInUse(_))
    ));
    // The first server is still accepting.
    let _c2 = IpcClient::connect(&name).await.unwrap();
    let _s2 = server.accept().await.unwrap();
}

/// Round-trip one message so the connection is known to work.
async fn exercise(
    s: &mut faro_ipc::ServiceConnection<faro_ipc::ServerStream>,
    c: &mut faro_ipc::AgentConnection<faro_ipc::ClientStream>,
) {
    c.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(s.recv().await.unwrap(), AgentMsg::Goodbye);
}

#[tokio::test]
async fn a_client_that_leaves_before_accept_does_not_stall_the_server() {
    let server = Arc::new(IpcServer::bind(unique("early"), AllowSameUser).unwrap());
    let name = server.path().to_path_buf();
    // Connects and closes before the server calls accept.
    drop(IpcClient::connect(&name).await.unwrap());
    let srv = server.clone();
    let accepting = tokio::spawn(async move {
        // As on Unix, the early leaver may be handed out (and read as
        // closed) or skipped; either way the next client is served.
        loop {
            let mut s = srv.accept().await.unwrap();
            match s.recv().await {
                Ok(m) => return m,
                Err(IpcError::Closed) => continue,
                Err(e) => panic!("{e:?}"),
            }
        }
    });
    let mut c = IpcClient::connect(&name).await.unwrap();
    c.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(accepting.await.unwrap(), AgentMsg::Goodbye);
}

#[tokio::test]
async fn a_burst_of_clients_is_all_served() {
    const N: usize = 24;
    let server = IpcServer::bind(unique("burst"), AllowSameUser).unwrap();
    let name = server.path().to_path_buf();
    let clients: Vec<_> = (0..N)
        .map(|_| {
            let name = name.clone();
            tokio::spawn(async move {
                let mut c = IpcClient::connect_verified(&name, &AllowSameUser)
                    .await
                    .unwrap();
                c.send(&AgentMsg::Goodbye).await.unwrap();
                // Hold the connection until the server has read from it.
                let _ = c.recv().await;
            })
        })
        .collect();
    let mut conns = Vec::new();
    for _ in 0..N {
        let mut s = server.accept().await.unwrap();
        assert_eq!(s.recv().await.unwrap(), AgentMsg::Goodbye);
        conns.push(s);
    }
    drop(conns);
    for c in clients {
        c.await.unwrap();
    }
}

#[tokio::test]
async fn accept_is_cancel_safe() {
    let server = IpcServer::bind(unique("cancel"), AllowSameUser).unwrap();
    let r = tokio::time::timeout(Duration::from_millis(30), server.accept()).await;
    assert!(r.is_err(), "nobody connected");
    let mut c = IpcClient::connect(server.path()).await.unwrap();
    let mut s = server.accept().await.unwrap();
    c.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(s.recv().await.unwrap(), AgentMsg::Goodbye);
}

#[tokio::test]
async fn only_local_pipe_names_are_accepted() {
    for bad in [
        r"\\server\pipe\faro\agent",
        r"C:\ProgramData\Faro\agent.sock",
        r"\\.\pipe\",
        r"\\.\pipe\faro/agent",
    ] {
        assert!(
            matches!(
                IpcServer::bind(bad, AllowSameUser),
                Err(IpcError::InvalidSocketPath { .. })
            ),
            "bind {bad}"
        );
        assert!(
            matches!(
                IpcClient::connect(bad).await,
                Err(IpcError::InvalidSocketPath { .. })
            ),
            "connect {bad}"
        );
    }
}

#[tokio::test]
async fn nobody_listening_is_not_found() {
    let r = IpcClient::connect(unique("absent")).await;
    assert!(
        matches!(&r, Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound),
        "{r:?}"
    );
}

#[tokio::test]
async fn bind_for_another_account() {
    // The pipe is for another account; we stay its owner (and so can still
    // connect, as the service can), and the agent still sees us as owner.
    let other: Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
    let server = IpcServer::bind_with(
        unique("other"),
        BindOptions::for_account(other),
        AllowSameUser,
    )
    .unwrap();
    let c = IpcClient::connect_verified(server.path(), &AllowSameUser)
        .await
        .unwrap();
    assert_eq!(c.peer().unwrap().windows_sid, Some(me()));
    let s = server.accept().await.unwrap();
    assert_eq!(s.peer().unwrap().windows_sid, Some(me()));
}

#[tokio::test]
async fn per_account_names_resolve_only_when_bound() {
    let base = unique("resolve");
    let own = faro_ipc::session_socket_path(&base, me());
    assert_eq!(faro_ipc::resolve_agent_socket(&base, me()), base);
    let server = IpcServer::bind(&own, AllowSameUser).unwrap();
    assert_eq!(faro_ipc::resolve_agent_socket(&base, me()), own);
    // Probing the name does not use up the listening instance.
    let mut c = IpcClient::connect(&own).await.unwrap();
    let mut s = server.accept().await.unwrap();
    c.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(s.recv().await.unwrap(), AgentMsg::Goodbye);
}

#[tokio::test]
async fn slow_hello_times_out_over_a_real_pipe() {
    let server = IpcServer::bind(unique("slow"), AllowSameUser).unwrap();
    let _silent = IpcClient::connect(server.path()).await.unwrap();
    let mut conn = server.accept().await.unwrap();
    let r = accept_agent(&mut conn, Duration::from_millis(50)).await;
    assert!(matches!(r, Err(IpcError::Timeout { .. })), "{r:?}");
}

#[tokio::test]
async fn garbage_from_a_verified_peer_is_a_typed_error() {
    use tokio::io::AsyncWriteExt;
    let server = IpcServer::bind(unique("garbage"), AllowSameUser).unwrap();
    // A raw client (tokio's defaults; we own the pipe, so its broader
    // GENERIC_WRITE request is granted).
    let mut raw = ClientOptions::new().open(server.path()).unwrap();
    let mut conn = server.accept().await.unwrap();
    raw.write_all(b"\x89PNG\r\n\x1a\n not raw pixels")
        .await
        .unwrap();
    assert!(matches!(conn.recv().await, Err(IpcError::BadMagic)));
}

/// The enroll pipe's own message types travel over the same transport,
/// one request and one answer per connection.
#[tokio::test]
async fn enroll_request_and_response_round_trip() {
    use faro_ipc::{
        EnrollClientConnection, EnrollRequest, EnrollResponse, EnrollServerConnection, EnrollStatus,
    };
    let base = unique("enrolltest");
    let name = faro_ipc::enroll_socket_path(&base, None);
    assert!(name.to_str().unwrap().ends_with(r"\enroll"), "{name:?}");
    let server = IpcServer::bind(&name, AllowSameUser).unwrap();
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
        server
    });
    let mut conn: EnrollClientConnection<_> =
        IpcClient::connect_verified_typed(&name, &AllowSameUser)
            .await
            .unwrap();
    conn.send(&EnrollRequest::Status).await.unwrap();
    match conn.recv().await.unwrap() {
        EnrollResponse::Status(s) => assert!(!s.enrolled),
        other => panic!("unexpected {other:?}"),
    }
    let _server = srv.await.unwrap();

    // A listener that is not who the agent expects gets nothing.
    let other = AllowSids::new(["S-1-5-21-1-2-3-1001".parse().unwrap()]);
    let r = IpcClient::connect_verified_typed::<EnrollRequest, EnrollResponse>(&name, &other).await;
    assert!(matches!(r, Err(IpcError::PeerRejected(_))));
}

/// A peer whose verification is slow (a signature check waiting on the
/// network) must not hold up the accept loop: the next client connects and
/// is verified while the first is still being checked.
#[tokio::test]
async fn a_slow_verification_does_not_block_the_next_accept() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let verifier = move |_: &PeerInfo| {
        if c.fetch_add(1, Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_millis(1500));
        }
        Ok(())
    };
    let server = IpcServer::bind(unique("slow-verify"), verifier).unwrap();
    let name = server.path().to_path_buf();

    let _first = IpcClient::connect(&name).await.unwrap();
    let slow = server.accept_pending().await.unwrap();
    let slow = tokio::spawn(slow.verify());
    // Let it start (and take the slow path) before the next client arrives.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut second = IpcClient::connect(&name).await.unwrap();
    let started = std::time::Instant::now();
    let mut conn = server
        .accept_pending()
        .await
        .unwrap()
        .verify()
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "the second peer waited for the first's verification"
    );
    second.send(&AgentMsg::Goodbye).await.unwrap();
    assert_eq!(conn.recv().await.unwrap(), AgentMsg::Goodbye);
    assert!(slow.await.unwrap().is_ok());
}
