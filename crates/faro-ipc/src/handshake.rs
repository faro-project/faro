//! Connection setup and liveness (ARCHITECTURE.md §3.1, §3.7).
//!
//! ```text
//! agent                          service
//!   |---- Hello{version,...} ------>|   within HELLO_TIMEOUT, first message
//!   |<--- Welcome{version,...} -----|   or Shutdown{reason} and close
//!   |            ...                |
//!   |<--- Ping{nonce} --------------|   periodically
//!   |---- Pong{nonce} ------------->|   within the ping timeout, else hung
//! ```
//!
//! A hung or unresponsive agent must be *detected* (so the service can
//! relaunch it and log `agent_restarted`, §3.1), which is what [`ping`] is
//! for. Every wait here has a deadline; nothing blocks indefinitely on the
//! peer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::codec::PROTOCOL_VERSION;
use crate::connection::{AgentConnection, ServiceConnection};
use crate::error::{IpcError, Result};
use crate::messages::{AgentMsg, ServiceMsg, ShutdownReason};

/// How long the service waits for `Hello` after accepting (§3.1 spec: 5 s).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// A sensible default for [`ping`]. Agents answer pings from their message
/// loop, so even a busy capture should reply well within this.
pub const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest accepted `agent_version` / `session` / `user` string in `Hello`.
/// These end up in logs and the event log; bounding them keeps a hostile
/// agent from bloating either.
pub const MAX_HELLO_FIELD_LEN: usize = 256;

/// Version string this build reports in `Welcome`. Agent, service and this
/// crate share the workspace version, so it is the service's version.
pub const SERVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The validated contents of an agent's `Hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHello {
    pub protocol_version: u16,
    pub agent_version: String,
    pub pid: u32,
    pub session: String,
    pub user: String,
}

impl AgentHello {
    /// A `Hello` for this build of the agent.
    pub fn new(
        agent_version: impl Into<String>,
        session: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        AgentHello {
            protocol_version: PROTOCOL_VERSION,
            agent_version: agent_version.into(),
            pid: std::process::id(),
            session: session.into(),
            user: user.into(),
        }
    }

    fn into_msg(self) -> AgentMsg {
        AgentMsg::Hello {
            protocol_version: self.protocol_version,
            agent_version: self.agent_version,
            pid: self.pid,
            session: self.session,
            user: self.user,
        }
    }

    fn check_fields(&self) -> Result<()> {
        for (field, value) in [
            ("agent_version", &self.agent_version),
            ("session", &self.session),
            ("user", &self.user),
        ] {
            if value.len() > MAX_HELLO_FIELD_LEN {
                return Err(IpcError::FieldTooLong {
                    field,
                    len: value.len(),
                    max: MAX_HELLO_FIELD_LEN,
                });
            }
        }
        Ok(())
    }
}

/// What the agent learns from `Welcome`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceWelcome {
    pub protocol_version: u16,
    pub service_version: String,
}

/// Service side: run the handshake on a freshly accepted connection,
/// replying with this build's [`SERVICE_VERSION`].
pub async fn accept_agent<S>(
    conn: &mut ServiceConnection<S>,
    timeout: Duration,
) -> Result<AgentHello>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_agent_with_version(conn, timeout, SERVICE_VERSION).await
}

/// Service side: as [`accept_agent`], with an explicit version string.
///
/// Requires the first message to be a well-formed `Hello` within `timeout`,
/// speaking [`PROTOCOL_VERSION`], with bounded fields, and (when the kernel
/// reported a peer pid) claiming the pid the kernel sees. On success replies
/// `Welcome`. On a protocol problem it sends a best-effort `Shutdown` with
/// the reason before returning the error; the caller should then drop the
/// connection.
pub async fn accept_agent_with_version<S>(
    conn: &mut ServiceConnection<S>,
    timeout: Duration,
    service_version: &str,
) -> Result<AgentHello>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hello = read_agent_hello(conn, timeout).await?;
    welcome_agent_with_version(conn, service_version).await?;
    Ok(hello)
}

/// Service side, first half of [`accept_agent`]: read and check the agent's
/// `Hello` without answering it, so the caller can decide whether to admit
/// this agent (for example, whether its session already has one) before
/// sending `Welcome` with [`welcome_agent`]. Dropping the connection instead
/// makes the agent's [`hello`] fail, and a real agent retries.
pub async fn read_agent_hello<S>(
    conn: &mut ServiceConnection<S>,
    timeout: Duration,
) -> Result<AgentHello>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let msg = conn.recv_timeout(timeout, "agent Hello").await?;
    let hello = match msg {
        AgentMsg::Hello {
            protocol_version,
            agent_version,
            pid,
            session,
            user,
        } => AgentHello {
            protocol_version,
            agent_version,
            pid,
            session,
            user,
        },
        other => {
            refuse(conn, ShutdownReason::ProtocolViolation).await;
            return Err(IpcError::UnexpectedMessage {
                expected: "Hello",
                got: other.kind(),
            });
        }
    };
    if hello.protocol_version != PROTOCOL_VERSION {
        refuse(conn, ShutdownReason::IncompatibleVersion).await;
        return Err(IpcError::VersionMismatch {
            peer: hello.protocol_version,
            ours: PROTOCOL_VERSION,
        });
    }
    if let Err(e) = hello.check_fields() {
        refuse(conn, ShutdownReason::ProtocolViolation).await;
        return Err(e);
    }
    if let Some(actual) = conn.peer().and_then(|p| p.pid) {
        if actual != hello.pid {
            refuse(conn, ShutdownReason::ProtocolViolation).await;
            return Err(IpcError::PidMismatch {
                claimed: hello.pid,
                actual,
            });
        }
    }
    Ok(hello)
}

/// Service side, second half of [`accept_agent`]: admit an agent whose
/// `Hello` [`read_agent_hello`] accepted.
pub async fn welcome_agent<S>(conn: &mut ServiceConnection<S>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    welcome_agent_with_version(conn, SERVICE_VERSION).await
}

async fn welcome_agent_with_version<S>(
    conn: &mut ServiceConnection<S>,
    service_version: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    conn.send(&ServiceMsg::Welcome {
        protocol_version: PROTOCOL_VERSION,
        service_version: service_version.to_owned(),
    })
    .await
}

/// Best effort: the connection is being abandoned anyway, so a failure to
/// deliver the reason is not itself an error worth surfacing.
async fn refuse<S>(conn: &mut ServiceConnection<S>, reason: ShutdownReason)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        conn.send(&ServiceMsg::Shutdown { reason }),
    )
    .await;
}

/// Agent side: send `Hello` and wait (up to `timeout`) for `Welcome`.
pub async fn hello<S>(
    conn: &mut AgentConnection<S>,
    greeting: AgentHello,
    timeout: Duration,
) -> Result<ServiceWelcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    greeting.check_fields()?;
    conn.send(&greeting.into_msg()).await?;
    match conn.recv_timeout(timeout, "service Welcome").await? {
        ServiceMsg::Welcome {
            protocol_version,
            service_version,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return Err(IpcError::VersionMismatch {
                    peer: protocol_version,
                    ours: PROTOCOL_VERSION,
                });
            }
            Ok(ServiceWelcome {
                protocol_version,
                service_version,
            })
        }
        ServiceMsg::Shutdown { reason } => Err(IpcError::PeerShutdown(reason)),
        other => Err(IpcError::UnexpectedMessage {
            expected: "Welcome",
            got: other.kind(),
        }),
    }
}

/// Process-wide nonce source. Nonces only need to be unique per connection
/// (so a late `Pong` for an earlier ping is not mistaken for this one); a
/// global counter gives that without per-connection state.
static NEXT_NONCE: AtomicU64 = AtomicU64::new(1);

/// Service side: liveness probe. Sends `Ping` and waits until the matching
/// `Pong` arrives or `timeout` elapses (an overall deadline, so a chatty
/// agent that never answers still times out).
///
/// Any other message that arrives meanwhile is handed to `on_other` in
/// order, so no frames or tamper signals are lost. `Pong`s with a stale
/// nonce are dropped. Returns the round-trip time.
///
/// Because [`Connection::recv`](crate::Connection::recv) is
/// cancellation-safe, a timeout leaves the connection usable; it is the
/// caller's policy whether a missed pong means "kill and relaunch".
pub async fn ping<S, F>(
    conn: &mut ServiceConnection<S>,
    timeout: Duration,
    mut on_other: F,
) -> Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(AgentMsg),
{
    let nonce = NEXT_NONCE.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    let deadline = start + timeout;
    tokio::time::timeout_at(deadline, conn.send(&ServiceMsg::Ping { nonce }))
        .await
        .map_err(|_| IpcError::Timeout {
            what: "sending Ping",
            after: timeout,
        })??;
    loop {
        let msg = match tokio::time::timeout_at(deadline, conn.recv()).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(IpcError::Timeout {
                    what: "agent Pong",
                    after: timeout,
                })
            }
        };
        match msg {
            AgentMsg::Pong { nonce: n } if n == nonce => return Ok(start.elapsed()),
            AgentMsg::Pong { .. } => {}
            other => on_other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::Connection;
    use crate::peer::PeerInfo;
    use tokio::io::duplex;

    fn pair() -> (
        ServiceConnection<tokio::io::DuplexStream>,
        AgentConnection<tokio::io::DuplexStream>,
    ) {
        let (a, b) = duplex(1 << 16);
        (Connection::new(a), Connection::new(b))
    }

    #[tokio::test]
    async fn happy_handshake() {
        let (mut svc, mut agent) = pair();
        let h = AgentHello::new("0.1.0", "console", "alice");
        let expected = h.clone();
        let (s, a) = tokio::join!(
            accept_agent_with_version(&mut svc, HELLO_TIMEOUT, "9.9.9"),
            hello(&mut agent, h, HELLO_TIMEOUT)
        );
        assert_eq!(s.unwrap(), expected);
        let w = a.unwrap();
        assert_eq!(w.service_version, "9.9.9");
        assert_eq!(w.protocol_version, PROTOCOL_VERSION);
    }

    #[tokio::test(start_paused = true)]
    async fn silent_agent_times_out() {
        let (mut svc, _agent) = pair();
        let r = accept_agent(&mut svc, HELLO_TIMEOUT).await;
        assert!(matches!(r, Err(IpcError::Timeout { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn non_hello_first_is_refused_with_shutdown() {
        let (mut svc, mut agent) = pair();
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        let r = accept_agent(&mut svc, HELLO_TIMEOUT).await;
        assert!(matches!(
            r,
            Err(IpcError::UnexpectedMessage {
                expected: "Hello",
                got: "Goodbye"
            })
        ));
        assert_eq!(
            agent.recv().await.unwrap(),
            ServiceMsg::Shutdown {
                reason: ShutdownReason::ProtocolViolation
            }
        );
    }

    #[tokio::test]
    async fn wrong_hello_version_is_refused() {
        let (mut svc, mut agent) = pair();
        let mut h = AgentHello::new("0.1.0", "s", "u");
        h.protocol_version = PROTOCOL_VERSION + 1;
        agent.send(&h.into_msg()).await.unwrap();
        assert!(matches!(
            accept_agent(&mut svc, HELLO_TIMEOUT).await,
            Err(IpcError::VersionMismatch { .. })
        ));
        assert_eq!(
            agent.recv().await.unwrap(),
            ServiceMsg::Shutdown {
                reason: ShutdownReason::IncompatibleVersion
            }
        );
    }

    #[tokio::test]
    async fn oversized_hello_fields_rejected_both_sides() {
        let (mut svc, mut agent) = pair();
        let h = AgentHello::new("0.1.0", "s", "u".repeat(MAX_HELLO_FIELD_LEN + 1));
        // The agent helper refuses to send it...
        assert!(matches!(
            hello(&mut agent, h.clone(), HELLO_TIMEOUT).await,
            Err(IpcError::FieldTooLong { field: "user", .. })
        ));
        // ...and the service refuses it if sent raw.
        agent.send(&h.into_msg()).await.unwrap();
        assert!(matches!(
            accept_agent(&mut svc, HELLO_TIMEOUT).await,
            Err(IpcError::FieldTooLong { field: "user", .. })
        ));
    }

    #[tokio::test]
    async fn pid_must_match_kernel_view() {
        let (a, b) = duplex(1 << 16);
        let peer = PeerInfo {
            uid: 501,
            gid: 20,
            pid: Some(4242),
            macos_audit_token: None,
        };
        let mut svc: ServiceConnection<_> = Connection::with_peer(a, Some(peer));
        let mut agent: AgentConnection<_> = Connection::new(b);
        let mut h = AgentHello::new("0.1.0", "s", "u");
        h.pid = 1; // lie
        agent.send(&h.into_msg()).await.unwrap();
        assert!(matches!(
            accept_agent(&mut svc, HELLO_TIMEOUT).await,
            Err(IpcError::PidMismatch {
                claimed: 1,
                actual: 4242
            })
        ));
    }

    #[tokio::test]
    async fn agent_sees_shutdown_instead_of_welcome() {
        let (mut svc, mut agent) = pair();
        let h = AgentHello::new("0.1.0", "s", "u");
        let svc_side = async {
            let _ = svc.recv().await.unwrap();
            svc.send(&ServiceMsg::Shutdown {
                reason: ShutdownReason::Updating,
            })
            .await
            .unwrap();
        };
        let (_, r) = tokio::join!(svc_side, hello(&mut agent, h, HELLO_TIMEOUT));
        assert!(matches!(
            r,
            Err(IpcError::PeerShutdown(ShutdownReason::Updating))
        ));
    }

    #[tokio::test]
    async fn ping_passes_through_other_messages_and_ignores_stale_pongs() {
        let (mut svc, mut agent) = pair();
        let agent_side = async {
            let ServiceMsg::Ping { nonce } = agent.recv().await.unwrap() else {
                panic!("expected ping");
            };
            agent
                .send(&AgentMsg::Pong {
                    nonce: nonce.wrapping_sub(1),
                })
                .await
                .unwrap();
            agent
                .send(&AgentMsg::Session {
                    idle_secs: 3,
                    locked: false,
                    display_asleep: false,
                })
                .await
                .unwrap();
            agent.send(&AgentMsg::Pong { nonce }).await.unwrap();
        };
        let mut others = Vec::new();
        let (_, rtt) = tokio::join!(
            agent_side,
            ping(&mut svc, DEFAULT_PING_TIMEOUT, |m| others.push(m))
        );
        assert!(rtt.is_ok());
        assert_eq!(
            others,
            vec![AgentMsg::Session {
                idle_secs: 3,
                locked: false,
                display_asleep: false
            }]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn hung_agent_detected_and_connection_survives() {
        let (mut svc, mut agent) = pair();
        let r = ping(&mut svc, Duration::from_secs(2), |_| {}).await;
        assert!(matches!(
            r,
            Err(IpcError::Timeout {
                what: "agent Pong",
                ..
            })
        ));
        // The agent wakes up late; the connection is still in sync.
        let ServiceMsg::Ping { nonce } = agent.recv().await.unwrap() else {
            panic!("expected ping");
        };
        agent.send(&AgentMsg::Pong { nonce }).await.unwrap();
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        assert_eq!(svc.recv().await.unwrap(), AgentMsg::Pong { nonce });
        assert_eq!(svc.recv().await.unwrap(), AgentMsg::Goodbye);
    }

    #[tokio::test(start_paused = true)]
    async fn chatty_agent_that_never_pongs_still_times_out() {
        let (mut svc, mut agent) = pair();
        let chatter = async {
            loop {
                if agent
                    .send(&AgentMsg::Session {
                        idle_secs: 0,
                        locked: false,
                        display_asleep: false,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        let mut seen = 0usize;
        let r = tokio::select! {
            r = ping(&mut svc, Duration::from_secs(1), |_| seen += 1) => r,
            _ = chatter => unreachable!("chatter never ends while svc is alive"),
        };
        assert!(matches!(r, Err(IpcError::Timeout { .. })));
        assert!(seen >= 5);
    }
}
