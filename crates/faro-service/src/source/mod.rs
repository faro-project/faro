//! Where frames and session context come from (ARCHITECTURE.md §3.1).
//!
//! In production the capture side is the per-session **agent**, connected
//! over `faro-ipc` ([`ipc::IpcFrameSource`]: Unix sockets, or named pipes
//! on Windows, where [`win_agents`] also launches the agents). Tests, the
//! headless E2E client and development builds can instead drive an
//! [`AgentPlatform`](faro_platform::AgentPlatform) in-process
//! ([`InProcessFrameSource`], e.g. over `faro_platform::synthetic::Script`).
//!
//! A source is an actor: the service sends it [`SourceCommand`]s (capture
//! now, show a notice, shut down) and receives [`SourceEvent`]s. The service
//! owns the schedule (§3.4); a source never captures on its own initiative.
//!
//! **Sessions.** Every OS account is monitored (§3.1), so a source can have
//! one agent per interactive session. It reports each agent's arrival and
//! departure ([`SourceEvent::AgentConnected`] / [`SourceEvent::AgentDisconnected`],
//! for supervision), the list of sessions and whether each has an agent
//! ([`SourceEvent::Sessions`], so the core can raise tamper for a session
//! nobody monitors), and which agent captures ([`SourceEvent::CaptureTarget`]:
//! the agent of the session at the screen). Capture-side events (frames,
//! foreground, idle and lock state, permissions) come from the capture
//! target only; tamper signals come from every agent, labelled with its
//! account.
//!
//! **Privacy.** [`SourceEvent::Frames`] carries unblurred
//! [`Frame`](faro_platform::Frame)s. They are moved, never copied, and are
//! zeroized when dropped (including if a channel is closed with frames still
//! queued). `SourceEvent`'s `Debug` never prints pixels.

#[cfg(any(unix, windows))]
pub mod codesign;
mod in_process;
#[cfg(any(unix, windows))]
pub mod ipc;
#[cfg(any(unix, windows))]
pub mod sessions;
#[cfg(windows)]
pub mod win_agents;

pub use in_process::InProcessFrameSource;

use faro_ipc::{CaptureReason, StatusReport};
use faro_platform::{Frame, PermissionState, SessionChange};
use faro_proto::body::{AppInfo, BrowserContext, TamperSignal};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// Commands from the service to the capture side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCommand {
    /// Capture every display of the capture target's session now and answer
    /// with `Frames` or `CaptureFailed`.
    CaptureNow(CaptureReason),
    /// Show a user-visible notice (the login notice and the monthly consent
    /// notice, §12) in one session, or in every session if `session` is
    /// `None`.
    ShowNotice {
        session: Option<String>,
        title: String,
        body: String,
    },
    /// Stop: tell the agents the service is stopping and return.
    Shutdown,
}

/// One interactive session, as a source sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionStatus {
    /// The session id agents send in `Hello` (`uid:<uid>`, `wts:<id>` on
    /// Windows).
    pub id: String,
    /// The account's short name (the label in events, §3.6).
    pub account: String,
    /// At the screen right now.
    pub active: bool,
    /// Its agent is connected.
    pub agent: bool,
}

/// The agent captures go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureTarget {
    pub session: String,
    /// Empty if the source does not know the account.
    pub account: String,
}

/// Events from the capture side.
pub enum SourceEvent {
    /// A session's agent completed the handshake.
    AgentConnected {
        session: String,
        account: String,
        agent_version: String,
    },
    /// A session's agent went away. `expected` is true only when the source
    /// itself saw the agent's session end (logout); an agent saying goodbye
    /// while its session continues, a dropped connection, a protocol failure
    /// and a missed ping are all unexpected (§3.7).
    AgentDisconnected {
        session: String,
        account: String,
        reason: String,
        expected: bool,
    },
    /// The interactive sessions right now, sent whenever the list or an
    /// agent's presence changes. Sources that cannot list sessions (the
    /// in-process platform, which is always connected) never send it.
    Sessions(Vec<SessionStatus>),
    /// Captures now go to (and capture-side events come from) this agent;
    /// `None`: no agent can capture (nobody at the screen, or the agent of
    /// the session at the screen is not connected).
    CaptureTarget(Option<CaptureTarget>),
    /// The answer to a `CaptureNow`: one frame per display.
    Frames(Vec<Frame>),
    /// A requested capture failed. Never contains screen content.
    CaptureFailed {
        reason: String,
    },
    Foreground {
        app: Option<AppInfo>,
        title: Option<String>,
    },
    Browser(BrowserContext),
    Session {
        idle_secs: u64,
        locked: bool,
        display_asleep: bool,
    },
    SessionChanged(SessionChange),
    Permission {
        screen: PermissionState,
        accessibility: Option<bool>,
    },
    /// A tamper or context signal from an agent, with its session's account
    /// (`None` if unknown).
    Tamper {
        signal: TamperSignal,
        account: Option<String>,
    },
}

impl fmt::Debug for SourceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceEvent::AgentConnected {
                session,
                account,
                agent_version,
            } => f
                .debug_struct("AgentConnected")
                .field("session", session)
                .field("account", account)
                .field("agent_version", agent_version)
                .finish(),
            SourceEvent::AgentDisconnected {
                session,
                account,
                reason,
                expected,
            } => f
                .debug_struct("AgentDisconnected")
                .field("session", session)
                .field("account", account)
                .field("reason", reason)
                .field("expected", expected)
                .finish(),
            SourceEvent::Sessions(s) => f.debug_tuple("Sessions").field(s).finish(),
            SourceEvent::CaptureTarget(t) => f.debug_tuple("CaptureTarget").field(t).finish(),
            SourceEvent::Frames(frames) => write!(f, "Frames({} frames)", frames.len()),
            SourceEvent::CaptureFailed { reason } => f
                .debug_struct("CaptureFailed")
                .field("reason", reason)
                .finish(),
            // Window titles and URLs are sensitive; keep them out of logs.
            SourceEvent::Foreground { app, .. } => f
                .debug_struct("Foreground")
                .field("app", &app.as_ref().map(|a| &a.id))
                .finish_non_exhaustive(),
            SourceEvent::Browser(_) => f.write_str("Browser(..)"),
            SourceEvent::Session {
                idle_secs,
                locked,
                display_asleep,
            } => f
                .debug_struct("Session")
                .field("idle_secs", idle_secs)
                .field("locked", locked)
                .field("display_asleep", display_asleep)
                .finish(),
            SourceEvent::SessionChanged(c) => f.debug_tuple("SessionChanged").field(c).finish(),
            SourceEvent::Permission {
                screen,
                accessibility,
            } => f
                .debug_struct("Permission")
                .field("screen", screen)
                .field("accessibility", accessibility)
                .finish(),
            SourceEvent::Tamper { signal, account } => f
                .debug_struct("Tamper")
                .field("signal", signal)
                .field("account", account)
                .finish(),
        }
    }
}

/// The channels a running source uses.
pub struct SourceIo {
    /// Closed (returns `None`) when the service is gone: the source must
    /// then stop.
    pub commands: mpsc::Receiver<SourceCommand>,
    pub events: mpsc::Sender<SourceEvent>,
    /// The service's latest status report (`None` until the first). A
    /// source with agents sends each one its
    /// [`MemberStatus`](faro_ipc::MemberStatus) view of it
    /// (`ServiceMsg::Status`); others ignore it.
    pub status: watch::Receiver<Option<Arc<StatusReport>>>,
}

impl SourceIo {
    /// The channels with a status feed that never changes (tests, and
    /// sources driven without a service).
    pub fn new(commands: mpsc::Receiver<SourceCommand>, events: mpsc::Sender<SourceEvent>) -> Self {
        let (_tx, status) = watch::channel(None);
        SourceIo {
            commands,
            events,
            status,
        }
    }
}

/// A boxed, sendable future.
pub type BoxFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// The capture side of the service. See the module docs.
pub trait FrameSource: Send + 'static {
    /// Run until [`SourceCommand::Shutdown`] or until the command channel
    /// closes. The service spawns the returned future.
    fn run(self: Box<Self>, io: SourceIo) -> BoxFuture;

    /// Short name for logs.
    fn name(&self) -> &'static str;
}
