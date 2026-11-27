//! Drives the agent's real loop against an in-test service: a `faro-ipc`
//! server on a Unix socket in a private tempdir (a uniquely named pipe on
//! Windows), with the synthetic platform standing in for the screen.
#![cfg(any(unix, windows))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use faro_agent::{Agent, AgentConfig, AgentError, Backoff, ExitReason, ServiceTrust};
use faro_ipc::{
    accept_agent, AgentMsg, AllowSameUser, CaptureReason, IpcError, IpcServer, ServiceConnection,
    ServiceMsg, ShutdownReason, WirePermissionState, WirePixelFormat, WireSessionChange,
    HELLO_TIMEOUT,
};
use faro_platform::synthetic::{Scene, Script};
use faro_platform::{AppInfo, BrowserContext, PermissionState, SessionChange, TamperSignal};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(5);

type Conn = ServiceConnection<faro_ipc::ServerStream>;

/// A private (0700) tempdir with a short path: macOS caps socket paths at
/// 104 bytes and `faro-ipc` refuses group/world-writable directories.
fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    d
}

/// The agent endpoint for a test: `agent.sock` in the tempdir, or on
/// Windows a pipe named after it (unique per test).
fn agent_endpoint(dir: &tempfile::TempDir) -> PathBuf {
    #[cfg(unix)]
    {
        dir.path().join("agent.sock")
    }
    #[cfg(windows)]
    {
        let unique = dir.path().file_name().unwrap().to_string_lossy();
        PathBuf::from(format!(r"\\.\pipe\faro-agent-test-{unique}\agent"))
    }
}

fn config(path: &Path) -> AgentConfig {
    let mut c = AgentConfig::new(path);
    c.service_trust = ServiceTrust::SameUid;
    c.session = "uid:test".into();
    c.user = "member".into();
    c.poll_interval = Duration::from_millis(20);
    c.backoff = Backoff {
        initial: Duration::from_millis(20),
        max: Duration::from_millis(200),
    };
    c.send_timeout = Duration::from_secs(5);
    c
}

type Notices = Arc<Mutex<Vec<(String, String)>>>;

struct Harness {
    _dir: tempfile::TempDir,
    path: PathBuf,
    script: Script,
    notices: Notices,
    stop: Option<oneshot::Sender<()>>,
    agent: JoinHandle<Result<ExitReason, AgentError>>,
}

impl Harness {
    /// Bind a server first (so the agent's first attempt can succeed), then
    /// start the agent with `trust`.
    async fn start_with(script: Script, trust: ServiceTrust) -> (Harness, IpcServer) {
        let dir = private_dir();
        let path = agent_endpoint(&dir);
        let server = IpcServer::bind(&path, AllowSameUser).expect("bind");
        let mut cfg = config(&path);
        cfg.service_trust = trust;
        let notices: Notices = Arc::default();
        let sink = notices.clone();
        let agent =
            Agent::new(cfg, script.platform()).with_notice_sink(move |title: &str, body: &str| {
                sink.lock()
                    .unwrap()
                    .push((title.to_owned(), body.to_owned()));
            });
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let agent = tokio::spawn(agent.run(async move {
            let _ = stop_rx.await;
        }));
        (
            Harness {
                _dir: dir,
                path,
                script,
                notices,
                stop: Some(stop_tx),
                agent,
            },
            server,
        )
    }

    async fn start(script: Script) -> (Harness, IpcServer) {
        Self::start_with(script, ServiceTrust::SameUid).await
    }

    async fn exit(self) -> Result<ExitReason, AgentError> {
        tokio::time::timeout(WAIT, self.agent)
            .await
            .expect("agent exits in time")
            .expect("agent task did not panic")
    }
}

/// Accept one connection and run the service side of the handshake.
async fn accept(server: &IpcServer) -> (Conn, faro_ipc::AgentHello) {
    let mut conn = tokio::time::timeout(WAIT, server.accept())
        .await
        .expect("agent connects in time")
        .expect("accept");
    let hello = accept_agent(&mut conn, HELLO_TIMEOUT)
        .await
        .expect("handshake");
    (conn, hello)
}

/// Receive until `want` matches, returning everything seen before it and
/// the match itself.
async fn recv_until(
    conn: &mut Conn,
    mut want: impl FnMut(&AgentMsg) -> bool,
) -> (Vec<AgentMsg>, AgentMsg) {
    let mut before = Vec::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let msg = conn
            .recv_timeout(left, "expected agent message")
            .await
            .unwrap_or_else(|e| panic!("waiting for message: {e}; saw {before:?}"));
        if want(&msg) {
            return (before, msg);
        }
        before.push(msg);
    }
}

fn is_frames(m: &AgentMsg) -> bool {
    matches!(m, AgentMsg::Frames { .. })
}

#[tokio::test]
async fn handshake_then_initial_state() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, hello) = accept(&server).await;
    assert_eq!(hello.protocol_version, faro_ipc::PROTOCOL_VERSION);
    assert_eq!(hello.agent_version, faro_agent::AGENT_VERSION);
    assert_eq!(hello.pid, std::process::id());
    assert_eq!(hello.session, "uid:test");
    assert_eq!(hello.user, "member");

    // Right after the handshake the full state arrives, unprompted.
    let (_, perm) = recv_until(&mut conn, |m| matches!(m, AgentMsg::Permission { .. })).await;
    assert_eq!(
        perm,
        AgentMsg::Permission {
            screen: WirePermissionState::Granted,
            accessibility: None,
        }
    );
    let (_, session) = recv_until(&mut conn, |m| matches!(m, AgentMsg::Session { .. })).await;
    assert_eq!(
        session,
        AgentMsg::Session {
            idle_secs: 0,
            locked: false,
            display_asleep: false,
        }
    );
    let (_, fg) = recv_until(&mut conn, |m| matches!(m, AgentMsg::Foreground { .. })).await;
    assert_eq!(
        fg,
        AgentMsg::Foreground {
            app: Some(AppInfo {
                id: "com.example.editor".into(),
                name: Some("Editor".into()),
            }),
            title: Some("Untitled".into()),
        }
    );
    // No capture without a request: the service owns the schedule.
    tokio::time::sleep(Duration::from_millis(150)).await;
    while let Ok(m) = conn.recv_timeout(Duration::from_millis(10), "drain").await {
        assert!(!is_frames(&m), "agent captured without being asked");
    }
    drop(h);
}

#[tokio::test]
async fn capture_now_sends_downscaled_frames() {
    let script = Script::new();
    script.with(|s| {
        s.width = 1920;
        s.height = 1080;
        s.displays = 2;
        s.scene = Scene::Pattern(7);
    });
    let (_h, server) = Harness::start(script).await;
    let (mut conn, _) = accept(&server).await;

    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Startup,
    })
    .await
    .unwrap();
    let (_, msg) = recv_until(&mut conn, is_frames).await;
    let AgentMsg::Frames {
        captured_at_mono_ms,
        frames,
    } = msg
    else {
        unreachable!()
    };
    assert!(captured_at_mono_ms > 0);
    assert_eq!(frames.len(), 2);
    for (i, f) in frames.iter().enumerate() {
        assert_eq!((f.width(), f.height()), (768, 432));
        assert_eq!(f.display_id(), i as u32);
        assert_eq!(f.format(), WirePixelFormat::Rgba8);
        assert_eq!(f.pixels().len(), 768 * 432 * 4);
        f.check().unwrap();
    }
}

#[tokio::test]
async fn many_displays_are_batched_with_one_timestamp() {
    let script = Script::new();
    script.with(|s| s.displays = faro_ipc::MAX_FRAMES_PER_MESSAGE as u32 + 1);
    let (_h, server) = Harness::start(script).await;
    let (mut conn, _) = accept(&server).await;

    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Scheduled,
    })
    .await
    .unwrap();
    let (_, first) = recv_until(&mut conn, is_frames).await;
    let (_, second) = recv_until(&mut conn, is_frames).await;
    let (
        AgentMsg::Frames {
            captured_at_mono_ms: t1,
            frames: f1,
        },
        AgentMsg::Frames {
            captured_at_mono_ms: t2,
            frames: f2,
        },
    ) = (first, second)
    else {
        unreachable!()
    };
    assert_eq!(t1, t2, "batches of one capture share the timestamp");
    assert_eq!(f1.len(), faro_ipc::MAX_FRAMES_PER_MESSAGE);
    assert_eq!(f2.len(), 1);
    // 1280x800 synthetic displays come out at 768x480.
    assert_eq!((f2[0].width(), f2[0].height()), (768, 480));
}

#[tokio::test]
async fn permission_revocation_reports_and_keeps_running() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    recv_until(&mut conn, |m| matches!(m, AgentMsg::Foreground { .. })).await;

    h.script.with(|s| s.permission = PermissionState::Denied);
    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Scheduled,
    })
    .await
    .unwrap();
    let (before, failed) =
        recv_until(&mut conn, |m| matches!(m, AgentMsg::CaptureFailed { .. })).await;
    assert!(
        before.contains(&AgentMsg::Permission {
            screen: WirePermissionState::Denied,
            accessibility: None,
        }),
        "Permission(Denied) must precede CaptureFailed; saw {before:?}"
    );
    assert!(!before.iter().any(is_frames));
    let AgentMsg::CaptureFailed { reason } = failed else {
        unreachable!()
    };
    assert!(reason.contains("permission"), "reason: {reason}");

    // Still alive and answering.
    conn.send(&ServiceMsg::Ping { nonce: 41 }).await.unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: 41 }).await;

    // Re-granting is reported by the next poll, and captures work again.
    h.script.with(|s| s.permission = PermissionState::Granted);
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Permission {
            screen: WirePermissionState::Granted,
            accessibility: None,
        }
    })
    .await;
    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Scheduled,
    })
    .await
    .unwrap();
    recv_until(&mut conn, is_frames).await;
}

/// The person at the screen is told Screen Recording is off once, not on
/// every poll or capture, and again when it goes off after a capture
/// worked in between.
#[tokio::test]
async fn screen_recording_off_is_shown_once_per_change() {
    let screen_off = || {
        (
            faro_agent::SCREEN_RECORDING_OFF.title.to_owned(),
            faro_agent::SCREEN_RECORDING_OFF.body.to_owned(),
        )
    };
    let script = Script::new();
    script.with(|s| s.permission = PermissionState::Denied);
    let (h, server) = Harness::start(script).await;
    let (mut conn, _) = accept(&server).await;
    for _ in 0..2 {
        conn.send(&ServiceMsg::CaptureNow {
            reason: CaptureReason::Scheduled,
        })
        .await
        .unwrap();
        recv_until(&mut conn, |m| matches!(m, AgentMsg::CaptureFailed { .. })).await;
    }
    // Several polls later (a Pong proves everything before it was handled).
    tokio::time::sleep(Duration::from_millis(100)).await;
    conn.send(&ServiceMsg::Ping { nonce: 1 }).await.unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: 1 }).await;
    assert_eq!(*h.notices.lock().unwrap(), vec![screen_off()]);

    h.script.with(|s| s.permission = PermissionState::Granted);
    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Scheduled,
    })
    .await
    .unwrap();
    recv_until(&mut conn, is_frames).await;
    h.script.with(|s| s.permission = PermissionState::Denied);
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Permission {
            screen: WirePermissionState::Denied,
            accessibility: None,
        }
    })
    .await;
    conn.send(&ServiceMsg::Ping { nonce: 2 }).await.unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: 2 }).await;
    assert_eq!(*h.notices.lock().unwrap(), vec![screen_off(), screen_off()]);
}

#[tokio::test]
async fn os_capture_failure_is_reported() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    h.script.with(|s| s.fail_capture = true);
    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Burst,
    })
    .await
    .unwrap();
    let (before, _) = recv_until(&mut conn, |m| matches!(m, AgentMsg::CaptureFailed { .. })).await;
    assert!(!before.iter().any(is_frames));
}

#[tokio::test]
async fn ping_gets_pong() {
    let (_h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    // The service-side helper sends Ping and waits for the matching Pong.
    let rtt = faro_ipc::ping(&mut conn, WAIT, |_| {}).await.expect("pong");
    assert!(rtt < WAIT);
    conn.send(&ServiceMsg::Ping { nonce: u64::MAX })
        .await
        .unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: u64::MAX }).await;
}

#[tokio::test]
async fn state_changes_and_tamper_are_forwarded() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    recv_until(&mut conn, |m| matches!(m, AgentMsg::Foreground { .. })).await;

    h.script.with(|s| {
        s.app = Some(AppInfo {
            id: "org.example.browser".into(),
            name: None,
        });
        s.title = Some("A page".into());
    });
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Foreground {
            app: Some(AppInfo {
                id: "org.example.browser".into(),
                name: None,
            }),
            title: Some("A page".into()),
        }
    })
    .await;

    h.script.with(|s| {
        s.locked = true;
        s.changes.push(SessionChange::Locked);
        s.tamper.push(TamperSignal::RemoteDesktop);
    });
    recv_until(&mut conn, |m| {
        *m == AgentMsg::SessionChanged(WireSessionChange::Locked)
    })
    .await;
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Tamper(TamperSignal::RemoteDesktop)
    })
    .await;
    recv_until(&mut conn, |m| {
        matches!(m, AgentMsg::Session { locked: true, .. })
    })
    .await;

    // Crossing the idle threshold is a change too.
    h.script.with(|s| {
        s.locked = false;
        s.idle_secs = 3600;
    });
    recv_until(&mut conn, |m| {
        matches!(
            m,
            AgentMsg::Session {
                idle_secs: 3600,
                locked: false,
                ..
            }
        )
    })
    .await;
}

#[tokio::test]
async fn browser_tab_follows_the_foreground() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    // No browser: the first report clears whatever the service held, and
    // comes after the foreground.
    let (_, fg) = recv_until(&mut conn, |m| {
        matches!(m, AgentMsg::Foreground { .. } | AgentMsg::Browser(_))
    })
    .await;
    assert!(matches!(fg, AgentMsg::Foreground { .. }));
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Browser(BrowserContext::default())
    })
    .await;

    let tab = BrowserContext {
        url: Some("https://example.test/".into()),
        title: None,
        incognito: false,
    };
    h.script.with(|s| {
        s.app = Some(AppInfo {
            id: "com.apple.Safari".into(),
            name: None,
        });
        s.browser = Some(tab.clone());
    });
    let (_, fg) = recv_until(&mut conn, |m| {
        matches!(m, AgentMsg::Foreground { app: Some(a), .. } if a.id == "com.apple.Safari")
            || matches!(m, AgentMsg::Browser(b) if b.url.is_some())
    })
    .await;
    assert!(
        matches!(fg, AgentMsg::Foreground { .. }),
        "the app comes before its tab"
    );
    recv_until(&mut conn, |m| *m == AgentMsg::Browser(tab.clone())).await;

    // Leaving the browser clears the tab.
    h.script.with(|s| s.browser = None);
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Browser(BrowserContext::default())
    })
    .await;
}

/// A window hidden from capture goes to the service and the person at the
/// screen is told which app it is.
#[tokio::test]
async fn hidden_window_is_forwarded_and_shown() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    let signal = TamperSignal::WindowHiddenFromCapture {
        app: "Viewer".into(),
    };
    h.script.with(|s| s.tamper.push(signal.clone()));
    recv_until(&mut conn, |m| *m == AgentMsg::Tamper(signal.clone())).await;
    let notices = h.notices.lock().unwrap().clone();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0], faro_agent::window_hidden_notice("Viewer"));
    assert!(notices[0].1.contains("\u{201c}Viewer\u{201d}"));
}

#[tokio::test]
async fn show_notice_reaches_the_sink() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    conn.send(&ServiceMsg::ShowNotice {
        title: "Faro is running".into(),
        body: "Your allies: Bob.".into(),
    })
    .await
    .unwrap();
    // A Pong after the notice proves the notice was handled first.
    conn.send(&ServiceMsg::Ping { nonce: 1 }).await.unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: 1 }).await;
    assert_eq!(
        *h.notices.lock().unwrap(),
        vec![("Faro is running".to_owned(), "Your allies: Bob.".to_owned())]
    );
}

#[tokio::test]
async fn shutdown_exits_cleanly_with_goodbye() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    conn.send(&ServiceMsg::Shutdown {
        reason: ShutdownReason::SessionEnded,
    })
    .await
    .unwrap();
    recv_until(&mut conn, |m| *m == AgentMsg::Goodbye).await;
    let exit = h.exit().await.expect("clean exit");
    assert_eq!(exit, ExitReason::Shutdown(ShutdownReason::SessionEnded));
    // And it does not come back.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), server.accept())
            .await
            .is_err(),
        "agent reconnected after Shutdown"
    );
}

#[tokio::test]
async fn stop_says_goodbye() {
    let (mut h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    // Stop once the agent is serving (it has sent its initial state). A stop
    // that lands mid-handshake abandons the connection without Goodbye.
    recv_until(&mut conn, |m| matches!(m, AgentMsg::Foreground { .. })).await;
    let _ = h.stop.take().unwrap().send(());
    recv_until(&mut conn, |m| *m == AgentMsg::Goodbye).await;
    assert_eq!(h.exit().await.unwrap(), ExitReason::Stopped);
}

#[tokio::test]
async fn stop_while_disconnected() {
    let (mut h, server) = Harness::start(Script::new()).await;
    drop(server); // nothing to connect to
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = h.stop.take().unwrap().send(());
    assert_eq!(h.exit().await.unwrap(), ExitReason::Stopped);
}

#[tokio::test]
async fn shutdown_during_handshake_is_obeyed() {
    let (h, server) = Harness::start(Script::new()).await;
    let mut conn = tokio::time::timeout(WAIT, server.accept())
        .await
        .unwrap()
        .unwrap();
    let hello = conn.recv_timeout(WAIT, "Hello").await.unwrap();
    assert!(matches!(hello, AgentMsg::Hello { .. }));
    conn.send(&ServiceMsg::Shutdown {
        reason: ShutdownReason::Superseded,
    })
    .await
    .unwrap();
    assert_eq!(
        h.exit().await.unwrap(),
        ExitReason::Shutdown(ShutdownReason::Superseded)
    );
}

#[tokio::test]
async fn reconnects_after_service_restart_and_delivers_queued_signals() {
    let (h, server) = Harness::start(Script::new()).await;
    let (mut conn, _) = accept(&server).await;
    recv_until(&mut conn, |m| matches!(m, AgentMsg::Foreground { .. })).await;

    // The service goes away (socket removed, connection closed).
    #[cfg(unix)]
    let path = server.path().to_path_buf();
    drop(conn);
    drop(server);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Things happen while nobody is listening.
    h.script.with(|s| {
        s.changes.push(SessionChange::DisplaySleep);
        s.tamper.push(TamperSignal::PermissionRevoked {
            permission: "screen_recording".into(),
            never_granted: false,
        });
    });
    // Let a few failed reconnects (and polls) go by.
    tokio::time::sleep(Duration::from_millis(300)).await;
    #[cfg(unix)]
    assert!(!path.exists());

    let server = IpcServer::bind(&h.path, AllowSameUser).expect("rebind");
    let (mut conn, hello) = accept(&server).await;
    assert_eq!(hello.pid, std::process::id());
    recv_until(&mut conn, |m| {
        *m == AgentMsg::SessionChanged(WireSessionChange::DisplaySleep)
    })
    .await;
    recv_until(&mut conn, |m| {
        *m == AgentMsg::Tamper(TamperSignal::PermissionRevoked {
            permission: "screen_recording".into(),
            never_granted: false,
        })
    })
    .await;
    // Full state is resent to the new service, and capture works.
    recv_until(&mut conn, |m| matches!(m, AgentMsg::Permission { .. })).await;
    conn.send(&ServiceMsg::CaptureNow {
        reason: CaptureReason::Startup,
    })
    .await
    .unwrap();
    recv_until(&mut conn, is_frames).await;
}

#[tokio::test]
async fn agent_started_before_service_connects_when_it_appears() {
    let dir = private_dir();
    let path = agent_endpoint(&dir);
    let script = Script::new();
    let agent = Agent::new(config(&path), script.platform());
    let task = tokio::spawn(agent.run(std::future::pending::<()>()));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let server = IpcServer::bind(&path, AllowSameUser).unwrap();
    let (mut conn, _) = accept(&server).await;
    faro_ipc::ping(&mut conn, WAIT, |_| {}).await.unwrap();
    task.abort();
}

/// In production the agent requires a root listener; a same-uid process on
/// the socket path must not even receive `Hello`, let alone frames.
#[tokio::test]
async fn refuses_a_non_root_service_in_production_mode() {
    // On Windows the test server is never LocalSystem.
    // SAFETY: no preconditions.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: running as root, so the test server *is* root");
        return;
    }
    let (_h, server) = Harness::start_with(Script::new(), ServiceTrust::Root).await;
    for _ in 0..2 {
        let mut conn = tokio::time::timeout(WAIT, server.accept())
            .await
            .unwrap()
            .unwrap();
        let r = conn.recv_timeout(WAIT, "Hello").await;
        assert!(
            matches!(r, Err(IpcError::Closed)),
            "impostor service received {r:?}"
        );
    }
}

type Statuses = Arc<Mutex<Vec<faro_agent::status_menu::Seen>>>;

/// Records what the status menu would show.
struct StatusSink(Statuses);

impl faro_agent::NoticeSink for StatusSink {
    fn show(&mut self, _title: &str, _body: &str) {}

    fn status(&mut self, seen: &faro_agent::status_menu::Seen) {
        self.0.lock().unwrap().push(seen.clone());
    }
}

/// Wait until the latest status matches.
async fn status_until(statuses: &Statuses, want: impl Fn(&faro_agent::status_menu::Seen) -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if statuses.lock().unwrap().last().is_some_and(&want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "statuses: {:?}",
            statuses.lock().unwrap()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A stand-in for the service's enroll socket that answers every `Status`
/// with "enrolled, waiting for approval".
fn fake_enroll_socket(agent_socket: &Path) -> JoinHandle<()> {
    use faro_ipc::{EnrollRequest, EnrollResponse, EnrollStatus};
    let path = faro_ipc::enroll_socket_path(agent_socket, None);
    let server = IpcServer::bind(&path, AllowSameUser).expect("bind enroll");
    tokio::spawn(async move {
        loop {
            let Ok(mut conn) = server.accept_typed::<EnrollResponse, EnrollRequest>().await else {
                continue;
            };
            if let Ok(EnrollRequest::Status) = conn.recv().await {
                let _ = conn
                    .send(&EnrollResponse::Status(EnrollStatus {
                        enrolled: true,
                        instance_name: Some("Sam's Faro".into()),
                        instance_url: Some("https://faro.example.org/".into()),
                        endorsed: false,
                    }))
                    .await;
            }
        }
    })
}

/// The status menu hears the enroll socket while the service's agent
/// socket isn't there, then the service's own `Status` once connected, and
/// each change only once. Nothing the agent sends back depends on it.
#[tokio::test]
async fn the_status_menu_follows_the_service() {
    use faro_agent::status_menu::{Enrollment, Seen};
    use faro_ipc::status::CaptureState;
    let dir = private_dir();
    let path = agent_endpoint(&dir);
    let enroll = fake_enroll_socket(&path);
    let statuses: Statuses = Arc::default();
    let script = Script::new();
    let agent =
        Agent::new(config(&path), script.platform()).with_notice_sink(StatusSink(statuses.clone()));
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let agent = tokio::spawn(agent.run(async move {
        let _ = stop_rx.await;
    }));

    // No agent socket yet: the computer waits for its member's approval.
    status_until(&statuses, |s| {
        matches!(s, Seen::NotConnected(Enrollment::AwaitingApproval { name, .. }) if name == "Sam's Faro")
    })
    .await;
    // Asked again on every retry, but told only once.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(statuses.lock().unwrap().len(), 1, "{statuses:?}");

    // The service starts and sends its view.
    let server = IpcServer::bind(&path, AllowSameUser).expect("bind");
    let (mut conn, _) = accept(&server).await;
    let status = faro_ipc::MemberStatus {
        instance_name: "Sam's Faro".into(),
        capture: Some(CaptureState::Active),
        ..faro_ipc::MemberStatus::default()
    };
    for _ in 0..2 {
        conn.send(&ServiceMsg::Status(status.clone()))
            .await
            .unwrap();
    }
    conn.send(&ServiceMsg::Ping { nonce: 9 }).await.unwrap();
    let (before, _) = recv_until(&mut conn, |m| *m == AgentMsg::Pong { nonce: 9 }).await;
    // The agent answers nothing to a status.
    assert!(
        before
            .iter()
            .all(|m| !matches!(m, AgentMsg::Pong { .. } | AgentMsg::Goodbye)),
        "{before:?}"
    );
    status_until(&statuses, |s| *s == Seen::Connected(status.clone())).await;
    assert_eq!(statuses.lock().unwrap().len(), 2, "{statuses:?}");

    // The service goes away: back to what the enroll socket says.
    drop(conn);
    drop(server);
    status_until(&statuses, |s| matches!(s, Seen::NotConnected(_))).await;

    let _ = stop_tx.send(());
    let exit = tokio::time::timeout(WAIT, agent).await.unwrap().unwrap();
    assert!(matches!(exit, Ok(ExitReason::Stopped)), "{exit:?}");
    enroll.abort();
}
