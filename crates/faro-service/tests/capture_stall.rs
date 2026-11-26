//! The core's safety net for silent capture stops (#80): the session at the
//! screen has its agent connected, nothing pauses capture, and yet the core
//! has no capture target or makes no capture attempt. After
//! `capture_stall_ms` of awake time that is urgent `capture_failing` tamper
//! for the account.
//!
//! The service runs against the real instance with a scripted capture side
//! (`Scripted`), so a test can send the core exactly what a source would,
//! including what the IPC source sent before #79: an agent restarting in
//! the same session announced as connected again, but never as the capture
//! target. Every capture request is answered with a plain frame.

// Shared with tests/e2e.rs; not every helper is used here.
#[allow(dead_code)]
mod e2e_support;

use e2e_support::*;
use faro_platform::{Frame, PixelFormat, SessionChange};
use faro_proto::body::{EventBody, TamperSignal};
use faro_proto::{EventKind, Urgency};
use faro_service::runtime::capture_stall_ms;
use faro_service::source::{BoxFuture, CaptureTarget, SessionStatus};
use faro_service::{
    FrameSource, PauseRequest, Phase, ServiceStatus, SourceCommand, SourceEvent, SourceIo,
};
use std::time::Duration;
use tokio::sync::mpsc;

const ALEX: &str = "uid:501";
const BEA: &str = "uid:502";

/// A capture side that forwards what the test sends and answers every
/// capture request with one grey frame.
struct Scripted {
    events: mpsc::UnboundedReceiver<SourceEvent>,
}

fn grey_frame() -> Frame {
    Frame::new(64, 48, PixelFormat::Rgba8, 0, vec![128; 64 * 48 * 4]).expect("frame")
}

impl FrameSource for Scripted {
    fn run(self: Box<Self>, mut io: SourceIo) -> BoxFuture {
        let mut events = self.events;
        Box::pin(async move {
            let mut open = true;
            loop {
                tokio::select! {
                    ev = events.recv(), if open => match ev {
                        Some(ev) => {
                            if io.events.send(ev).await.is_err() {
                                return;
                            }
                        }
                        None => open = false,
                    },
                    cmd = io.commands.recv() => match cmd {
                        Some(SourceCommand::CaptureNow(_)) => {
                            let frames = SourceEvent::Frames(vec![grey_frame()]);
                            if io.events.send(frames).await.is_err() {
                                return;
                            }
                        }
                        Some(SourceCommand::ShowNotice { .. }) => {}
                        Some(SourceCommand::Shutdown) | None => return,
                    },
                }
            }
        })
    }

    fn name(&self) -> &'static str {
        "scripted"
    }
}

struct Setup {
    w: World,
    dev: Device,
    tx: mpsc::UnboundedSender<SourceEvent>,
}

impl Setup {
    /// Cut the device off from the instance. These tests drive the device
    /// clock far beyond the instance's (which stays put), and the device's
    /// `ClockGuard` would rightly call a 10-minute skew in a heartbeat
    /// answer clock manipulation. Offline, the core still counts every
    /// tamper signal in its status.
    fn offline(&self) {
        self.w.gate.cut();
    }

    fn send(&self, ev: SourceEvent) {
        self.tx.send(ev).expect("source running");
    }

    fn sessions(&self, list: &[(&str, &str, bool)]) {
        self.send(SourceEvent::Sessions(
            list.iter()
                .map(|(id, account, active)| SessionStatus {
                    id: (*id).to_owned(),
                    account: (*account).to_owned(),
                    active: *active,
                    agent: true,
                })
                .collect(),
        ));
    }

    fn connected(&self, session: &str, account: &str) {
        self.send(SourceEvent::AgentConnected {
            session: session.to_owned(),
            account: account.to_owned(),
            agent_version: "test".to_owned(),
        });
    }

    fn disconnected(&self, session: &str, account: &str, expected: bool) {
        self.send(SourceEvent::AgentDisconnected {
            session: session.to_owned(),
            account: account.to_owned(),
            reason: "test".to_owned(),
            expected,
        });
    }

    fn target(&self, t: Option<(&str, &str)>) {
        self.send(SourceEvent::CaptureTarget(t.map(|(session, account)| {
            CaptureTarget {
                session: session.to_owned(),
                account: account.to_owned(),
            }
        })));
    }
}

/// An endorsed, running device whose capture side is [`Scripted`], with
/// alex logged in at the screen, their agent connected and captured from.
async fn setup() -> Setup {
    let w = World::new().await;
    let mut dev = w.enroll_device().await;
    let (tx, events) = mpsc::unbounded_channel();
    dev.start_with(quiet_classifier(), Box::new(Scripted { events }));
    dev.wait("awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    w.endorse(&dev).await;
    dev.wait("running with boot sealed", |s| {
        s.phase == Phase::Running && s.last_seq.is_some()
    })
    .await;
    let s = Setup { w, dev, tx };
    s.sessions(&[(ALEX, "alex", true)]);
    s.connected(ALEX, "alex");
    s.target(Some((ALEX, "alex")));
    s.dev
        .wait("capturing from alex", |st| {
            st.capture_account.as_deref() == Some("alex")
        })
        .await;
    let n = s.dev.status().captures;
    s.dev.drive_until("a capture", |st| st.captures > n).await;
    s
}

/// The default capture mean is 60 s.
fn stall_ms() -> u64 {
    capture_stall_ms(60)
}

/// Move the device clock forward by `ms` in 500 ms steps (the core counts
/// awake time per tick, capped at 5 s), stopping early once `pred` holds.
async fn advance(
    dev: &Device,
    ms: u64,
    mut pred: impl FnMut(&ServiceStatus) -> bool,
) -> ServiceStatus {
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

/// Let the core take in what was just sent.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// The agent restarts and the core is told it connected again, but not
/// that it is the capture target (what the IPC source did before #79).
/// Raises `capture_failing` for alex once, after the stall threshold.
async fn restart_without_target(s: &Setup) -> ServiceStatus {
    let tampers = s.dev.status().tamper_events;
    s.disconnected(ALEX, "alex", false);
    s.connected(ALEX, "alex");
    s.sessions(&[(ALEX, "alex", true)]);
    s.dev
        .wait("no capture target", |st| {
            !st.agent_connected && st.agents == 1
        })
        .await;
    let st = advance(&s.dev, stall_ms() * 3, |st| st.tamper_events > tampers).await;
    assert!(
        st.tamper_events > tampers,
        "no tamper after {} ms without captures: {st:?}",
        stall_ms() * 3
    );
    st
}

/// Decrypt `dev`'s event `seq` as the ally.
async fn ally_body(w: &World, dev: &Device, seq: u64) -> EventBody {
    let item = w.event_item(&w.ally.session, dev, seq).await;
    serde_json::from_slice(
        &open_event(&item, dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
    )
    .expect("EventBody")
}

/// The #79 bug, reintroduced: the agent restarts in the same session and
/// the core never gets a capture target back. Before #80 nothing noticed;
/// now allies get an urgent alert naming the account, once, and the net
/// re-arms when captures resume.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connected_agent_nothing_captures_from_is_tamper() {
    let mut s = setup().await;
    let captures = s.dev.status().captures;

    let st = restart_without_target(&s).await;
    assert_eq!(st.tamper_events, 1, "{st:?}");
    assert_eq!(st.captures, captures, "nothing was captured: {st:?}");
    let seq = s.dev.upload_all().await;
    let ev = s.w.feed_event(&s.w.ally.session, &s.dev, seq).await;
    assert_eq!((ev.kind, ev.urgency), (EventKind::Tamper, Urgency::Urgent));
    match ally_body(&s.w, &s.dev, seq).await {
        EventBody::Tamper {
            signal:
                TamperSignal::CaptureFailing {
                    consecutive_failures,
                },
            account,
        } => {
            // The captures missed at the 60 s mean.
            assert_eq!(u64::from(consecutive_failures), stall_ms() / 60_000);
            assert_eq!(account.as_deref(), Some("alex"));
        }
        other => panic!("{other:?}"),
    }
    s.offline();

    // Reported once while it lasts.
    let st = advance(&s.dev, stall_ms() * 2, |_| false).await;
    assert_eq!(st.tamper_events, 1, "reported once: {st:?}");

    // Captures resume: no further alert, and a later stall is reported
    // again.
    s.target(Some((ALEX, "alex")));
    s.dev
        .drive_until("captures again", |st| st.captures > captures)
        .await;
    let st = advance(&s.dev, stall_ms() * 2, |_| false).await;
    assert_eq!(st.tamper_events, 1, "{st:?}");
    let st = restart_without_target(&s).await;
    assert_eq!(st.tamper_events, 2, "{st:?}");

    s.dev.shutdown().await;
}

/// No capture for well over the threshold, for reasons that are not
/// tamper: a member pause, a locked screen, the display asleep, fast user
/// switching (to another account and to the login window) and logging
/// out. None of them raises anything. At the end the same amount of time
/// with the #79 bug does, so the time driven was enough to notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pauses_locks_logouts_and_user_switching_are_not_tamper() {
    let mut s = setup().await;
    s.offline();
    let long = stall_ms() * 2;
    let quiet = |st: &ServiceStatus| st.tamper_events > 0;

    // A member pause (allies are told with a `paused` event).
    s.dev
        .handle()
        .pause(PauseRequest {
            reason: None,
            duration: None,
        })
        .await;
    settle().await;
    let before = s.dev.status().captures;
    let st = advance(&s.dev, long, quiet).await;
    assert_eq!(st.tamper_events, 0, "paused: {st:?}");
    assert_eq!(st.captures, before, "nothing captured while paused: {st:?}");
    s.dev.handle().resume().await;
    s.dev
        .drive_until("captures after the pause", |st| st.captures > before)
        .await;

    // The screen locked, then the display asleep.
    for (start, end) in [
        (SessionChange::Locked, SessionChange::Unlocked),
        (SessionChange::DisplaySleep, SessionChange::DisplayWake),
    ] {
        s.send(SourceEvent::SessionChanged(start));
        settle().await;
        let before = s.dev.status().captures;
        let st = advance(&s.dev, long, quiet).await;
        assert_eq!(st.tamper_events, 0, "{start:?}: {st:?}");
        assert_eq!(st.captures, before, "{start:?}: {st:?}");
        s.send(SourceEvent::SessionChanged(end));
        s.dev
            .drive_until("captures again", |st| st.captures > before)
            .await;
    }

    // Fast user switching: bea logs in and comes to the screen; captures
    // follow her.
    s.sessions(&[(ALEX, "alex", false), (BEA, "bea", true)]);
    s.connected(BEA, "bea");
    s.target(Some((BEA, "bea")));
    s.dev
        .wait("capturing from bea", |st| {
            st.capture_account.as_deref() == Some("bea")
        })
        .await;
    let st = advance(&s.dev, long, quiet).await;
    assert_eq!(st.tamper_events, 0, "switched to bea: {st:?}");

    // Switching to the login window: both sessions continue in the
    // background, nobody is at the screen.
    s.sessions(&[(ALEX, "alex", false), (BEA, "bea", false)]);
    s.target(None);
    s.dev
        .wait("no capture target", |st| !st.agent_connected)
        .await;
    let st = advance(&s.dev, long, quiet).await;
    assert_eq!(st.tamper_events, 0, "login window: {st:?}");

    // Both log out.
    s.disconnected(BEA, "bea", true);
    s.disconnected(ALEX, "alex", true);
    s.send(SourceEvent::Sessions(Vec::new()));
    s.dev
        .wait("no sessions or agents", |st| st.agents == 0)
        .await;
    let st = advance(&s.dev, long, quiet).await;
    assert_eq!(st.tamper_events, 0, "logged out: {st:?}");

    // Control: alex logs in again and the agent is never made the capture
    // target. That is noticed within the same time.
    s.sessions(&[(ALEX, "alex", true)]);
    s.connected(ALEX, "alex");
    s.dev.wait("alex's agent", |st| st.agents == 1).await;
    let st = advance(&s.dev, long, quiet).await;
    assert_eq!(st.tamper_events, 1, "the stall is noticed: {st:?}");

    s.dev.shutdown().await;
}
