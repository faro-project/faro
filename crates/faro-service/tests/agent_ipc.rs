//! The real session agent (`faro_agent::Agent` on the synthetic platform)
//! against the service's real IPC source (`IpcFrameSource` on a Unix
//! socket), inside a running `Service` talking to the real instance.
//!
//! The other suites drive the service through `InProcessFrameSource`, which
//! cannot catch IPC-level bugs; these tests cover what only the IPC path
//! does: answering captures across the answer window, refusing a second
//! connection, classifying agent departures by whether the session ended
//! (not by what the agent says), and monitoring every account: one agent
//! per session, captures following the session at the screen, and urgent
//! tamper for a session whose agent never connects. Sessions are modelled
//! with `IpcFrameSource::with_sessions`, since a test can neither create
//! accounts nor log a real user out; every modelled session belongs to the
//! test's own uid and is told apart by its id, as two accounts' sessions
//! would be.

#![cfg(unix)]

// Shared with tests/e2e.rs; not every helper is used here.
#[allow(dead_code)]
mod e2e_support;

use clap::Parser;
use e2e_support::*;
use faro_agent::{Agent, AgentConfig, ExitReason, ServiceTrust};
use faro_ipc::{hello, AgentHello, IpcClient};
use faro_proto::api::DeviceState;
use faro_proto::body::{EventBody, TamperSignal};
use faro_proto::{EventKind, Urgency};
use faro_service::runtime::AGENT_ABSENT_MS;
use faro_service::source::ipc::IpcFrameSource;
use faro_service::source::sessions::SessionEntry;
use faro_service::{AgentSpawn, Phase};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The sessions the IPC source sees.
#[derive(Clone, Default)]
struct Logins(Arc<Mutex<Vec<SessionEntry>>>);

impl Logins {
    /// `alex` logged in at the screen.
    fn alex() -> Logins {
        let l = Logins::default();
        l.log_in("alex", true);
        l
    }
    fn log_in(&self, account: &str, active: bool) {
        self.0.lock().unwrap().push(SessionEntry {
            id: session_of(account),
            uid: euid(),
            account: account.into(),
            active,
        });
    }
    fn log_out(&self, account: &str) {
        let id = session_of(account);
        self.0.lock().unwrap().retain(|s| s.id != id);
    }
    /// Fast user switching: `account` comes to the screen.
    fn switch_to(&self, account: &str) {
        let id = session_of(account);
        for s in self.0.lock().unwrap().iter_mut() {
            s.active = s.id == id;
        }
    }
}

fn session_of(account: &str) -> String {
    format!("session-{account}")
}

fn ipc_source(socket: &Path, logins: &Logins) -> IpcFrameSource {
    let l = logins.0.clone();
    IpcFrameSource::new(socket, [])
        .with_ping(Duration::from_millis(100), Duration::from_secs(10))
        .with_sessions(Arc::new(move || Some(l.lock().unwrap().clone())))
        // A short capture-answer window so the test waits past it; the
        // session-end grace and session re-check as in production, scaled.
        .with_timings(
            Duration::from_millis(400),
            Duration::from_millis(500),
            Duration::from_millis(20),
        )
}

/// The notices one agent was asked to show.
#[derive(Clone, Default)]
struct Notices(Arc<Mutex<Vec<String>>>);

impl Notices {
    fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// A running real agent.
struct RealAgent {
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<ExitReason, faro_agent::AgentError>>,
}

impl RealAgent {
    /// The agent in `account`'s session.
    fn start(dev: &Device, socket: &Path, account: &str) -> RealAgent {
        Self::start_noting(dev, socket, account, Notices::default())
    }

    /// As [`start`](Self::start), recording the notices it is asked to show.
    fn start_noting(dev: &Device, socket: &Path, account: &str, notices: Notices) -> RealAgent {
        let mut cfg = AgentConfig::new(socket);
        cfg.session = session_of(account);
        // The test service runs as our own uid, not root.
        cfg.service_trust = ServiceTrust::SameUid;
        cfg.poll_interval = Duration::from_millis(50);
        cfg.backoff = faro_agent::Backoff {
            initial: Duration::from_millis(20),
            max: Duration::from_millis(200),
        };
        let seen = notices.0.clone();
        let agent = Agent::new(cfg, dev.script.platform()).with_notice_sink(
            move |title: &str, body: &str| {
                seen.lock().unwrap().push(format!("{title}\n{body}"));
            },
        );
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(agent.run(async move {
            let _ = rx.await;
        }));
        RealAgent {
            stop: Some(tx),
            task,
        }
    }

    /// SIGTERM-style stop: the agent says `Goodbye` and exits.
    async fn stop(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        let r = tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("agent stops in time")
            .expect("agent task");
        assert!(matches!(r, Ok(ExitReason::Stopped)), "{r:?}");
    }
}

struct Setup {
    w: World,
    dev: Device,
    logins: Logins,
    socket: PathBuf,
    _sock_dir: tempfile::TempDir,
}

/// An endorsed, running device whose capture side is the IPC source, with
/// `logins` as its sessions; no agent connected yet.
async fn setup_with(logins: Logins, classifier: Box<dyn faro_detect::Classifier>) -> Setup {
    let w = World::new().await;
    let mut dev = w.enroll_device().await;
    let sock_dir = tempfile::tempdir().expect("socket dir");
    let socket = sock_dir.path().join("agent.sock");
    dev.start_with(classifier, Box::new(ipc_source(&socket, &logins)));
    dev.wait("awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    w.endorse(&dev).await;
    dev.wait("running with boot sealed", |s| {
        s.phase == Phase::Running && s.last_seq.is_some()
    })
    .await;
    Setup {
        w,
        dev,
        logins,
        socket,
        _sock_dir: sock_dir,
    }
}

async fn setup() -> Setup {
    setup_with(Logins::alex(), quiet_classifier()).await
}

/// Decrypt `dev`'s event `seq` as the ally.
async fn ally_body(w: &World, dev: &Device, seq: u64) -> EventBody {
    let item = w.event_item(&w.ally.session, dev, seq).await;
    serde_json::from_slice(
        &open_event(&item, dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
    )
    .expect("EventBody")
}

/// Move the device clock forward by `ms` in 500 ms steps (the core counts
/// awake time per tick, capped at 5 s, so steps must stay small), stopping
/// early once `pred` holds. Returns the last status.
async fn advance(
    dev: &Device,
    ms: u64,
    mut pred: impl FnMut(&faro_service::ServiceStatus) -> bool,
) -> faro_service::ServiceStatus {
    let mut driven = 0;
    loop {
        let st = dev.status();
        if pred(&st) || driven >= ms {
            return st;
        }
        dev.clock.advance(500);
        driven += 500;
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
}

/// The kinds of every event of `dev` the instance stored, in `seq` order
/// (the feed hides `none`-urgency kinds such as `agent_restarted`).
async fn kinds(w: &World, dev: &Device) -> Vec<String> {
    use sqlx::Row;
    dev.upload_all().await;
    sqlx::query("SELECT kind FROM events WHERE device_id = $1 ORDER BY seq")
        .bind(dev.enrollment.device_id.as_str())
        .fetch_all(w.t.state.db().pool())
        .await
        .expect("query events")
        .iter()
        .map(|r| r.try_get::<String, _>("kind").expect("kind column"))
        .collect()
}

/// Captures through the real agent are not later counted as failures; a
/// second connection is refused without disturbing the agent; an agent
/// that leaves while its user is still logged in is an unexpected
/// departure, and staying away raises an urgent tamper event; when it comes
/// back, `agent_restarted` is logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agent_capture_impostor_and_silent_stop() {
    let Setup {
        w,
        mut dev,
        logins: _logins,
        socket,
        _sock_dir,
    } = setup().await;
    let agent = RealAgent::start(&dev, &socket, "alex");
    dev.wait("agent connected", |s| s.agent_connected).await;

    // A capture through the real agent, then well past the answer window.
    dev.drive_until("a capture", |s| s.captures >= 1).await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let st = dev.status();
    assert_eq!(
        st.capture_failures, 0,
        "an answered capture is not a failure: {st:?}"
    );

    // An impostor running as the same user gets no Welcome, and the real
    // agent stays connected.
    let mut impostor = IpcClient::connect(&socket).await.expect("connect");
    let r = hello(
        &mut impostor,
        AgentHello::new("impostor", "s1", "me"),
        Duration::from_secs(5),
    )
    .await;
    assert!(r.is_err(), "impostor refused");
    drop(impostor);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let st = dev.status();
    assert!(st.agent_connected, "{st:?}");
    assert_eq!(st.tamper_events, 0);

    // `launchctl bootout` / `pkill`: the agent says Goodbye and exits while
    // its user is still logged in.
    agent.stop().await;
    dev.wait("agent gone", |s| !s.agent_connected).await;
    dev.handle().heartbeat_now();
    dev.wait("heartbeat no longer active", |s| {
        s.last_heartbeat_state == Some(DeviceState::Idle)
    })
    .await;
    let st = advance(&dev, AGENT_ABSENT_MS * 2, |s| s.tamper_events >= 1).await;
    let st = if st.tamper_events >= 1 {
        st
    } else {
        dev.wait("missing-agent tamper", |s| s.tamper_events >= 1)
            .await
    };
    assert!(st.agent_missing, "{st:?}");
    assert_eq!(st.tamper_events, 1);
    assert!(
        st.captures >= 1 && st.last_seq.is_some(),
        "boot and the tamper event were committed"
    );
    assert_eq!(st.unmonitored_accounts, ["alex"]);
    let seq = dev.upload_all().await;
    let ev = w.feed_event(&w.ally.session, &dev, seq).await;
    assert_eq!(ev.kind, EventKind::Tamper);
    assert_eq!(ev.urgency, Urgency::Urgent);
    match ally_body(&w, &dev, seq).await {
        EventBody::Tamper {
            signal: TamperSignal::UnmonitoredUserSession { user },
            account,
        } => {
            assert_eq!(user, "alex");
            assert_eq!(account.as_deref(), Some("alex"));
        }
        other => panic!("{other:?}"),
    }

    // The agent comes back (launchd relaunch): a restart is logged.
    let committed = dev.status().events_committed;
    let agent = RealAgent::start(&dev, &socket, "alex");
    let st = dev
        .wait("agent reconnected and restart logged", |s| {
            s.agent_connected && s.events_committed > committed
        })
        .await;
    assert!(!st.agent_missing);
    let k = kinds(&w, &dev).await;
    assert_eq!(
        k.last().map(String::as_str),
        Some(EventKind::AgentRestarted.as_str()),
        "{k:?}"
    );

    agent.stop().await;
    dev.shutdown().await;
}

/// Logging out ends the session: the agent leaving then is expected, and
/// no agent at the login window is not tamper.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_leaving_at_logout_is_not_tamper() {
    let Setup {
        w,
        mut dev,
        logins,
        socket,
        _sock_dir,
    } = setup().await;
    let agent = RealAgent::start(&dev, &socket, "alex");
    dev.wait("agent connected", |s| s.agent_connected).await;
    dev.drive_until("a capture", |s| s.captures >= 1).await;

    agent.stop().await;
    logins.log_out("alex");
    dev.wait("agent gone", |s| !s.agent_connected).await;
    // Let the source classify the departure and report no sessions.
    tokio::time::sleep(Duration::from_millis(800)).await;
    // Longer than the absence threshold of device time.
    advance(&dev, AGENT_ABSENT_MS + 10_000, |s| s.tamper_events > 0).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let st = dev.status();
    assert_eq!(st.tamper_events, 0, "{st:?}");
    assert!(!st.agent_missing, "{st:?}");
    let k = kinds(&w, &dev).await;
    assert_eq!(k, ["boot"], "nothing but the boot event: {k:?}");
    dev.shutdown().await;
}

/// The `account` labels of `dev`'s flag events, oldest first, as the ally
/// decrypts them.
async fn flag_accounts(w: &World, dev: &Device) -> Vec<Option<String>> {
    let last = dev.upload_all().await;
    let mut out = Vec::new();
    for ev in w.feed_events(&w.ally.session).await {
        if ev.kind != EventKind::Flag {
            continue;
        }
        match ally_body(w, dev, ev.seq).await {
            EventBody::Flag(f) => out.push(f.account),
            other => panic!("{other:?}"),
        }
    }
    assert!(last > 0);
    out
}

/// Two accounts logged in at once (fast user switching), each with its own
/// agent: both are told they are monitored, captures go to the account at
/// the screen, flags say which account they came from, and switching users
/// is neither a disconnect nor tamper.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_account_has_an_agent_and_capture_follows_the_screen() {
    let logins = Logins::alex();
    logins.log_in("guest", false);
    let Setup {
        w,
        mut dev,
        logins,
        socket,
        _sock_dir,
    } = setup_with(logins, explicit_classifier()).await;
    let (alex_notices, guest_notices) = (Notices::default(), Notices::default());
    let alex = RealAgent::start_noting(&dev, &socket, "alex", alex_notices.clone());
    let guest = RealAgent::start_noting(&dev, &socket, "guest", guest_notices.clone());
    let st = dev
        .wait("both agents connected", |s| {
            s.agents == 2 && s.capture_account.as_deref() == Some("alex")
        })
        .await;
    assert_eq!(st.sessions, 2);

    dev.drive_until("a flag from alex", |s| s.flags >= 1).await;
    assert_eq!(flag_accounts(&w, &dev).await, [Some("alex".to_owned())]);

    // Switch to the guest account: its agent captures now, and alex's agent
    // stays connected in the background.
    logins.switch_to("guest");
    dev.wait("capturing the guest session", |s| {
        s.capture_account.as_deref() == Some("guest") && s.agents == 2
    })
    .await;
    let flags = dev.status().flags;
    dev.drive_until("a flag from guest", |s| s.flags > flags)
        .await;
    let accounts = flag_accounts(&w, &dev).await;
    assert_eq!(accounts.first(), Some(&Some("alex".to_owned())));
    assert_eq!(accounts.last(), Some(&Some("guest".to_owned())));

    let st = dev.status();
    assert_eq!(st.tamper_events, 0, "switching users is not tamper: {st:?}");
    assert!(!st.agent_missing);
    let k = kinds(&w, &dev).await;
    assert!(
        !k.iter().any(|k| k == EventKind::AgentRestarted.as_str()),
        "{k:?}"
    );

    // Each session got the login notice once, naming the instance.
    for (who, n) in [("alex", &alex_notices), ("guest", &guest_notices)] {
        let all = n.all();
        assert_eq!(all.len(), 1, "{who}: {all:?}");
        assert!(
            all[0].starts_with("This computer is monitored by Faro"),
            "{all:?}"
        );
        assert!(all[0].contains("Every account on this computer"), "{all:?}");
    }

    alex.stop().await;
    guest.stop().await;
    dev.shutdown().await;
}

/// A new account logs in and its agent never connects: after the absence
/// threshold that is urgent tamper naming the account, even though another
/// account is being monitored at the screen. Switching to it stops capture
/// (there is nothing to capture with), and once its agent connects the
/// device is fully monitored again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_whose_agent_never_connects_is_tamper() {
    let Setup {
        w,
        mut dev,
        logins,
        socket,
        _sock_dir,
    } = setup().await;
    let alex = RealAgent::start(&dev, &socket, "alex");
    dev.wait("alex's agent connected", |s| s.agent_connected)
        .await;
    dev.drive_until("a capture", |s| s.captures >= 1).await;

    // A new account appears (created after install), in the background.
    logins.log_in("newbie", false);
    dev.wait("the new session is listed", |s| s.sessions == 2)
        .await;
    let st = advance(&dev, AGENT_ABSENT_MS * 2, |s| s.tamper_events >= 1).await;
    let st = if st.tamper_events >= 1 {
        st
    } else {
        dev.wait("unmonitored-session tamper", |s| s.tamper_events >= 1)
            .await
    };
    assert_eq!(st.unmonitored_accounts, ["newbie"], "{st:?}");
    assert!(st.agent_connected, "alex is still monitored: {st:?}");
    assert_eq!(st.capture_account.as_deref(), Some("alex"));
    let seq = dev.upload_all().await;
    let ev = w.feed_event(&w.ally.session, &dev, seq).await;
    assert_eq!((ev.kind, ev.urgency), (EventKind::Tamper, Urgency::Urgent));
    match ally_body(&w, &dev, seq).await {
        EventBody::Tamper {
            signal: TamperSignal::UnmonitoredUserSession { user },
            account,
        } => {
            assert_eq!(user, "newbie");
            assert_eq!(account.as_deref(), Some("newbie"));
        }
        other => panic!("{other:?}"),
    }

    // Switching to it: nothing can capture, and heartbeats stop saying
    // `active`.
    logins.switch_to("newbie");
    dev.wait("no capture target", |s| !s.agent_connected).await;
    dev.handle().heartbeat_now();
    dev.wait("heartbeat no longer active", |s| {
        s.last_heartbeat_state == Some(DeviceState::Idle)
    })
    .await;

    // Its agent finally connects: monitored again, and the alarm clears.
    let newbie = RealAgent::start(&dev, &socket, "newbie");
    let st = dev
        .wait("capturing the new account", |s| {
            s.capture_account.as_deref() == Some("newbie") && s.agents == 2
        })
        .await;
    assert!(
        !st.agent_missing && st.unmonitored_accounts.is_empty(),
        "{st:?}"
    );
    assert_eq!(st.tamper_events, 1, "reported once: {st:?}");

    alex.stop().await;
    newbie.stop().await;
    dev.shutdown().await;
}

/// Regression: `--spawn-agent` launched `faro-agent --socket <path>`, which
/// the agent's CLI rejects (it needs the `run` subcommand), so the dev agent
/// crash-looped forever.
#[test]
fn spawn_agent_arguments_parse_with_the_agent_cli() {
    let spec = AgentSpawn::new("/usr/local/bin/faro-agent", "/tmp/faro-test/agent.sock");
    let argv = std::iter::once("faro-agent".to_owned()).chain(spec.resolved_args());
    let cli = faro_agent::cli::Cli::try_parse_from(argv).expect("faro-agent accepts them");
    let faro_agent::cli::Command::Run(args) = cli.command;
    assert_eq!(args.socket, PathBuf::from("/tmp/faro-test/agent.sock"));
    if euid() != 0 {
        assert!(
            args.trust_same_uid_service,
            "a user-run dev service must be trusted"
        );
    }
}

/// Regression: the agent reported idle crossings at 60 s while the service
/// pauses capture (and heartbeats `idle`) at the scheduler's threshold, so
/// the crossing that matters arrived only with the periodic resend.
#[test]
fn agent_idle_threshold_matches_the_scheduler() {
    let agent = AgentConfig::new("/tmp/x.sock").idle_threshold.as_secs();
    let scheduler = faro_core::SchedulerConfig::default().idle_threshold_secs;
    assert_eq!(agent, scheduler);
}
