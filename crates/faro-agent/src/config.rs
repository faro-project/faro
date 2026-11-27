//! Agent configuration: where the service is, whom to trust, and timing.

use std::path::PathBuf;
use std::time::Duration;

use faro_ipc::{AllowSameUser, AllowSystemService, PeerVerifier};

use crate::identity;

/// Where the service listens by default.
///
/// The socket lives in a root-owned directory (ARCHITECTURE.md §3.1 "Local
/// IPC"); `faro-ipc` refuses to bind or trust anything in a directory that
/// another user could write to. `/var/run` is the macOS spelling (a symlink
/// to `/private/var/run`), `/run` the Linux one. The service must agree;
/// both ends can override it (`--socket`, `FARO_AGENT_SOCKET`).
#[cfg(target_os = "macos")]
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/faro/agent.sock";
#[cfg(not(any(target_os = "macos", windows)))]
pub const DEFAULT_SOCKET_PATH: &str = "/run/faro/agent.sock";
/// Windows: the service's base pipe (`faro_ipc`); it binds one per account
/// next to it, `agent.<SID>`.
#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\faro\agent";

/// The service's idle threshold (`faro_core` scheduler default and the
/// heartbeat's `idle` state).
pub const DEFAULT_IDLE_THRESHOLD_SECS: u64 = 300;

/// Who the agent accepts as "the service" on the other end of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceTrust {
    /// Production: the listener must run as root (LocalSystem on Windows).
    /// The real service is a LaunchDaemon / system unit / Windows service, so anything else on the socket path is an
    /// impostor and must not receive frames.
    Root,
    /// Development and tests: the listener runs as our own uid (account). Never use
    /// this in production; any process of the session user could then pose
    /// as the service.
    SameUid,
}

impl ServiceTrust {
    pub(crate) fn verifier(self) -> Box<dyn PeerVerifier> {
        match self {
            ServiceTrust::Root => Box::new(AllowSystemService),
            ServiceTrust::SameUid => Box::new(AllowSameUser),
        }
    }
}

/// Exponential reconnect backoff. Doubles from `initial` up to `max` after
/// each failed attempt and resets after a successful handshake.
///
/// No jitter: there is exactly one agent per session talking to one local
/// service, so there is no thundering herd to spread out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(30),
        }
    }
}

impl Backoff {
    /// The delay after `current`.
    pub fn next(&self, current: Duration) -> Duration {
        current
            .saturating_mul(2)
            .clamp(self.initial, self.max.max(self.initial))
    }
}

/// Everything [`crate::Agent`] needs besides the platform.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The service's socket.
    pub socket_path: PathBuf,
    /// Who must be listening on it.
    pub service_trust: ServiceTrust,
    /// Opaque session identifier sent in `Hello`. Defaults to `uid:<uid>`,
    /// the form `faro-platform-macos`'s `MacServiceHost::list_sessions`
    /// uses, so the service can match the agent to the session it expects.
    pub session: String,
    /// Login name sent in `Hello`.
    pub user: String,
    /// How often foreground, session, permission and tamper state is
    /// sampled. ARCHITECTURE.md §3.3 asks for the permission to be checked
    /// "on every tick"; a revocation is reported within one interval.
    pub poll_interval: Duration,
    /// How often the full state (permission, session, foreground) is sent
    /// even when nothing changed, so the service's view self-heals and
    /// `idle_secs` keeps advancing.
    pub resend_interval: Duration,
    /// Idle time at which the session counts as "idle" for change
    /// detection: crossing it in either direction sends `Session` at once,
    /// so the service can pause and resume capture promptly (§3.4). It must
    /// equal the service's idle threshold (the scheduler pauses and the
    /// heartbeat says `idle` at 300 s): with a lower value the crossing the
    /// service acts on would only be learned from the periodic resend, up to
    /// `resend_interval` late.
    pub idle_threshold: Duration,
    /// Upper bound on one outgoing message write. A service that stops
    /// reading would otherwise wedge the agent; after this the connection is
    /// treated as lost and re-established.
    pub send_timeout: Duration,
    /// Deadline for the service's `Welcome`.
    pub hello_timeout: Duration,
    pub backoff: Backoff,
}

impl AgentConfig {
    /// Production defaults for the current process's session.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        AgentConfig {
            socket_path: socket_path.into(),
            service_trust: ServiceTrust::Root,
            session: identity::default_session_id(),
            user: identity::login_name(),
            poll_interval: Duration::from_secs(2),
            resend_interval: Duration::from_secs(60),
            idle_threshold: Duration::from_secs(DEFAULT_IDLE_THRESHOLD_SECS),
            send_timeout: Duration::from_secs(30),
            hello_timeout: faro_ipc::HELLO_TIMEOUT,
            backoff: Backoff::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let b = Backoff {
            initial: Duration::from_millis(100),
            max: Duration::from_millis(500),
        };
        let mut d = b.initial;
        let mut seen = vec![d];
        for _ in 0..5 {
            d = b.next(d);
            seen.push(d);
        }
        let ms: Vec<u128> = seen.iter().map(Duration::as_millis).collect();
        assert_eq!(ms, vec![100, 200, 400, 500, 500, 500]);
    }

    #[test]
    fn backoff_tolerates_max_below_initial() {
        let b = Backoff {
            initial: Duration::from_secs(2),
            max: Duration::from_secs(1),
        };
        assert_eq!(b.next(Duration::ZERO), Duration::from_secs(2));
    }

    #[test]
    fn defaults_are_production_safe() {
        let c = AgentConfig::new(DEFAULT_SOCKET_PATH);
        assert_eq!(c.service_trust, ServiceTrust::Root);
        assert!(!c.session.is_empty());
        assert!(!c.user.is_empty());
    }
}
