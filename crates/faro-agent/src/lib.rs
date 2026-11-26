//! # faro-agent
//!
//! The unprivileged per-session agent (ARCHITECTURE.md §3.1). It runs inside
//! the member's graphical login session because that is the only place a
//! screen can be captured, and it does as little as possible there:
//!
//! * it connects to the privileged service over [`faro_ipc`], introduces
//!   itself (`Hello`: protocol version, pid, session, user) and then
//! * captures every display **only when the service asks** (`CaptureNow`;
//!   the service owns the schedule, §3.4), moves the raw pixels into
//!   `Frames` messages and drops them as soon as they are written;
//! * reports foreground app/window, the browser tab where the platform can
//!   read it, session state (idle, locked, display asleep), permission
//!   state, session edges and tamper signals, both periodically and when
//!   they change;
//! * answers liveness pings, shows service notices, and exits when told to;
//! * hands what it knows of the service to the menu-bar status menu
//!   ([`status_menu`]): the service's `Status` view of this session while
//!   connected, and the enroll socket's answer (not enrolled, waiting for
//!   approval) while not.
//!
//! On macOS it also opens `faro://enroll` links ([`enroll`]): it shows
//! the instance to confirm and asks the service to enroll the computer,
//! which happens only once an administrator approves in the system's own
//! dialog.
//!
//! It holds no keys, no event log and no schedule. Everything it knows is
//! either about to be sent or is the last value it sent (so it can report
//! changes), plus a small bounded queue of session edges and tamper signals
//! observed while the service was unreachable, which it delivers on
//! reconnect so a revocation during a service restart is not lost.
//!
//! ## Privacy invariants
//!
//! * **Frames never touch storage.** Pixels go from the platform's zeroizing
//!   [`faro_platform::Frame`] into a [`faro_ipc::WireFrame`] by moving the
//!   buffer ([`Frame::into_parts`](faro_platform::Frame::into_parts)), are
//!   encoded into the codec's zeroizing buffer, written to the socket, and
//!   dropped (zeroized). Nothing here writes files; nothing logs pixels.
//! * **Window titles are sensitive.** They are sent to the service (it needs
//!   them for context signals, §3.5) but logged only at `debug` level, never
//!   at `info` or above. Message kinds, not contents, are what get logged.
//! * **Browser URLs are more sensitive still.** The platform reduces them to
//!   `scheme://host/` before the agent sees them, and the agent never logs
//!   them at any level.
//! * **The agent only streams to the real service.** In production it
//!   requires the socket's listener to be root ([`ServiceTrust::Root`]), so a
//!   same-user impostor listening on a stale path gets nothing.
//!
//! ## Platforms
//!
//! * **macOS**: `faro_platform_macos::MacPlatform::agent_platform()`, plus
//!   the Accessibility trust check for the `Permission` message. The binary
//!   also shows the menu-bar icon and the service's notices
//!   (`faro_platform_macos::ui`, §12), which take the main thread.
//! * **Windows**: `faro_platform_windows::WinPlatform::agent_platform()`.
//!   The binary is a GUI-subsystem program (`WM_ENDSESSION` needs that) that
//!   shows the tray icon, the notice and the enrollment windows
//!   (`faro_platform_windows::ui`), and takes `faro://` links through
//!   `faro-agent open-url "<link>"`. The service is a LocalSystem service
//!   on a named pipe; enrollment is approved by an elevated
//!   `faro-service approve-enroll` helper (UAC).
//! * **Linux**: no platform layer yet (ARCHITECTURE.md §3.3 puts it in
//!   Phase 2). The binary refuses to start there rather than pretend. The
//!   run loop itself is transport-generic and compiles on any Unix.
//!
//! ## Synthetic mode
//!
//! [`faro_platform::synthetic`] drives the agent in tests (see
//! `tests/agent_loop.rs`). The binary accepts `--synthetic` only when built
//! with the `dev` cargo feature, because the agent is the same signed
//! binary the service trusts: a release build that could be told to capture
//! a fake screen would let a member blind their allies with one flag.

pub mod cli;
pub mod config;
pub mod enroll;
pub mod frames;
pub mod identity;
pub mod notice;
// The pending-signal queue only serves the agent loop, which runs on Unix and Windows.
#[cfg(any(unix, windows))]
mod pending;
pub mod platform;
#[cfg(any(unix, windows))]
mod run;
pub mod status_menu;

pub use config::{AgentConfig, Backoff, ServiceTrust, DEFAULT_SOCKET_PATH};
pub use notice::{
    window_hidden_notice, LogNotices, NoticeSink, SettingsNotice, SCREEN_RECORDING_OFF,
};
pub use platform::{AccessibilityProbe, PlatformWorker, WorkerGone};
#[cfg(any(unix, windows))]
pub use run::{Agent, AgentError, ExitReason, AGENT_VERSION};
