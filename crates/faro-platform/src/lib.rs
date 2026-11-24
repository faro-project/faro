//! # faro-platform
//!
//! The seam between Faro's portable core and each operating system
//! (ARCHITECTURE.md §3.2). Every OS crate (`faro-platform-macos`, `-windows`,
//! `-linux`) implements these traits; `synthetic` provides deterministic
//! implementations for tests and for the headless E2E client.
//!
//! The traits are split by *process*: capture, foreground, session state and
//! tamper polling run in the per-user **agent**; [`ServiceHost`] runs in the
//! privileged **service**.

pub mod frame;
pub mod synthetic;

pub use faro_proto::body::{AppInfo, TamperSignal};
pub use frame::{Frame, FrameError, PixelFormat, MAX_FRAME_SIDE};

/// OS permission state for screen capture (TCC on macOS, portal on Wayland).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionState {
    Granted,
    Denied,
    NotDetermined,
    /// The platform has no such permission (e.g. X11, Windows desktop duplication).
    NotRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not available on this platform/session: {0}")]
    Unavailable(String),
    #[error("os error: {0}")]
    Os(String),
}

pub type Result<T> = std::result::Result<T, PlatformError>;

/// Grabs the current contents of every display.
pub trait ScreenCapture: Send {
    /// Capture all displays. Implementations should downscale to
    /// [`MAX_FRAME_SIDE`] as early as possible (ideally in the OS API).
    fn capture_all_displays(&mut self) -> Result<Vec<Frame>>;
    fn permission_state(&self) -> PermissionState;
}

/// The frontmost application and window.
pub trait ForegroundInfo: Send {
    fn active_app(&self) -> Option<AppInfo>;
    fn window_title(&self) -> Option<String>;
}

/// A change in the interactive session, used to pause capture and to explain
/// gaps in the timeline (§3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionChange {
    Locked,
    Unlocked,
    DisplaySleep,
    DisplayWake,
    SystemSleep,
    SystemWake,
}

/// Idle / lock / sleep state of the interactive session.
pub trait SessionState: Send {
    fn idle_secs(&self) -> u64;
    fn is_locked(&self) -> bool;
    fn display_asleep(&self) -> bool {
        false
    }
    /// Drain session changes observed since the last call. Poll-based so
    /// implementations can bridge OS callbacks through a channel.
    fn poll_changes(&mut self) -> Vec<SessionChange> {
        Vec::new()
    }
}

/// Polls OS-specific tamper and context signals (§3.7).
pub trait TamperSignals: Send {
    fn poll(&mut self) -> Vec<TamperSignal>;
}

/// Opaque OS session identifier (Windows session id, macOS/Linux uid+seat).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub user: String,
    pub graphical: bool,
    pub active: bool,
}

/// Process id of a spawned agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentPid(pub u32);

/// Service-side OS integration.
pub trait ServiceHost: Send {
    /// Register the service/daemon and per-user agent with the OS.
    fn install(&self) -> Result<()>;
    fn list_sessions(&self) -> Result<Vec<SessionInfo>>;
    /// Launch (or ask the OS to launch) the agent inside a user session.
    fn spawn_agent_in_session(&self, session: &SessionId) -> Result<AgentPid>;
}

/// Everything the agent needs, bundled. OS crates provide a constructor.
pub struct AgentPlatform {
    pub capture: Box<dyn ScreenCapture>,
    pub foreground: Box<dyn ForegroundInfo>,
    pub session: Box<dyn SessionState>,
    pub tamper: Box<dyn TamperSignals>,
}
