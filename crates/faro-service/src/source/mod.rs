//! Where frames and session context come from (ARCHITECTURE.md §3.1).
//!
//! In production the capture side is the per-session **agent**, connected
//! over `faro-ipc` ([`ipc::IpcFrameSource`], Unix only for now). Tests, the
//! headless E2E client and development builds can instead drive an
//! [`AgentPlatform`](faro_platform::AgentPlatform) in-process
//! ([`InProcessFrameSource`], e.g. over `faro_platform::synthetic::Script`).
//!
//! A source is an actor: the service sends it [`SourceCommand`]s (capture
//! now, show a notice, shut down) and receives [`SourceEvent`]s. The service
//! owns the schedule (§3.4); a source never captures on its own initiative.
//!
//! **Privacy.** [`SourceEvent::Frames`] carries unblurred
//! [`Frame`](faro_platform::Frame)s. They are moved, never copied, and are
//! zeroized when dropped (including if a channel is closed with frames still
//! queued). `SourceEvent`'s `Debug` never prints pixels.

#[cfg(unix)]
pub mod codesign;
mod in_process;
#[cfg(unix)]
pub mod ipc;

pub use in_process::InProcessFrameSource;

use faro_ipc::CaptureReason;
use faro_platform::{Frame, PermissionState, SessionChange};
use faro_proto::body::{AppInfo, BrowserContext, TamperSignal};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;

/// Commands from the service to the capture side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceCommand {
    /// Capture every display now and answer with `Frames` or `CaptureFailed`.
    CaptureNow(CaptureReason),
    /// Show a user-visible notice (e.g. the monthly consent notice, §12).
    ShowNotice { title: String, body: String },
    /// Stop: tell the agent the service is stopping and return.
    Shutdown,
}

/// Events from the capture side.
pub enum SourceEvent {
    /// An agent (or the in-process platform) is ready to capture.
    Connected {
        agent_version: String,
        session: String,
        user: String,
    },
    /// The agent went away. `expected` is true only when the source itself
    /// saw the agent's session end (logout, user switch); an agent saying
    /// goodbye while its session continues, a dropped connection, a protocol
    /// failure and a missed ping are all unexpected (§3.7).
    Disconnected {
        reason: String,
        expected: bool,
    },
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
    Tamper(TamperSignal),
    /// Whether anyone is logged in at the console. While nobody is, a
    /// missing agent is explained (the login window has no agent); while
    /// someone is, it is not. Sources that always have a session (the
    /// in-process platform) never send this.
    ConsoleSession {
        present: bool,
    },
}

impl fmt::Debug for SourceEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourceEvent::Connected {
                agent_version,
                session,
                user,
            } => f
                .debug_struct("Connected")
                .field("agent_version", agent_version)
                .field("session", session)
                .field("user", user)
                .finish(),
            SourceEvent::Disconnected { reason, expected } => f
                .debug_struct("Disconnected")
                .field("reason", reason)
                .field("expected", expected)
                .finish(),
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
            SourceEvent::Tamper(t) => f.debug_tuple("Tamper").field(t).finish(),
            SourceEvent::ConsoleSession { present } => f
                .debug_struct("ConsoleSession")
                .field("present", present)
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
