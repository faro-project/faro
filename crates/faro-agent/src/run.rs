//! The agent's connection loop.
//!
//! ```text
//!  ┌──────────── run ─────────────┐
//!  │ connect (verified) + Hello   │──fail──▶ wait(backoff) ──┐
//!  │        │ Welcome             │  (keeps polling, queues   │
//!  │        ▼                     │   edges and tamper)       │
//!  │ serve: select! {             │◀──────────────────────────┘
//!  │   stop        → Goodbye, exit│
//!  │   ServiceMsg  → capture/pong/│
//!  │                 notice/exit  │
//!  │   capture done→ Frames | Permission+CaptureFailed
//!  │   observation → edges, tamper, changed state
//!  │   poll tick   → ask platform for an observation
//!  │ }  connection lost ──────────┼──▶ wait(backoff) → reconnect
//!  └──────────────────────────────┘
//! ```
//!
//! The loop never captures on its own initiative: the service owns the
//! schedule (§3.4). One capture runs at a time; `CaptureNow` requests that
//! arrive while one is running are coalesced into a single follow-up
//! capture, so the service always gets a frame taken *after* its most
//! recent request without the agent queueing captures it cannot keep up
//! with.

use std::future::Future;
use std::pin::{pin, Pin};
use std::time::Duration;

use faro_ipc::{
    hello, AgentConnection, AgentHello, AgentMsg, IpcClient, IpcError, PeerVerifier, ServiceMsg,
    ShutdownReason, WirePermissionState,
};
use faro_platform::{AgentPlatform, AppInfo, BrowserContext, PermissionState};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tokio::time::{Instant, Interval, MissedTickBehavior};

use crate::config::AgentConfig;
use crate::notice::{LogNotices, NoticeSink};
use crate::pending::{Pending, Signal};
use crate::platform::{
    AccessibilityProbe, Capture, CaptureOutcome, Observation, PlatformWorker, WorkerGone,
};

/// The version this agent reports in `Hello`.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Longest `CaptureFailed::reason` the agent sends. Reasons are diagnostics
/// from the OS layer; bounding them keeps the service's log tidy.
const MAX_REASON_LEN: usize = 256;

/// How long a best-effort `Goodbye` may take before the agent exits anyway.
const GOODBYE_TIMEOUT: Duration = Duration::from_secs(1);

/// Why [`Agent::run`] returned normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// The service told the agent to exit.
    Shutdown(ShutdownReason),
    /// The caller's `stop` future completed (e.g. SIGTERM at logout).
    Stopped,
}

/// Failures the agent cannot recover from by reconnecting.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("could not start the platform thread: {0}")]
    SpawnPlatform(#[source] std::io::Error),
    #[error(transparent)]
    PlatformGone(#[from] WorkerGone),
}

/// The session agent. Build it, then [`run`](Self::run) it.
pub struct Agent {
    config: AgentConfig,
    platform: AgentPlatform,
    accessibility: Option<AccessibilityProbe>,
    notices: Box<dyn NoticeSink>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("config", &self.config)
            .field("accessibility_probe", &self.accessibility.is_some())
            .finish_non_exhaustive()
    }
}

impl Agent {
    pub fn new(config: AgentConfig, platform: AgentPlatform) -> Self {
        Agent {
            config,
            platform,
            accessibility: None,
            notices: Box::new(LogNotices),
        }
    }

    /// Report the Accessibility permission (macOS) in `Permission` messages.
    pub fn with_accessibility_probe(mut self, probe: AccessibilityProbe) -> Self {
        self.accessibility = Some(probe);
        self
    }

    /// Where `ShowNotice` goes. Defaults to [`LogNotices`].
    pub fn with_notice_sink(mut self, sink: impl NoticeSink + 'static) -> Self {
        self.notices = Box::new(sink);
        self
    }

    /// Run until the service says `Shutdown`, `stop` completes, or the
    /// platform thread dies. Connection problems are never fatal: the agent
    /// reconnects with backoff for as long as it runs.
    ///
    /// Must be called inside a Tokio runtime with I/O and time enabled.
    pub async fn run(self, stop: impl Future<Output = ()>) -> Result<ExitReason, AgentError> {
        let worker = PlatformWorker::spawn(self.platform, self.accessibility)
            .map_err(AgentError::SpawnPlatform)?;
        let mut poll = tokio::time::interval(self.config.poll_interval.max(MIN_POLL));
        poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut rt = Runtime {
            verifier: self.config.service_trust.verifier(),
            config: self.config,
            worker,
            notices: self.notices,
            pending: Pending::default(),
            observing: None,
            poll,
        };
        rt.run(pin!(stop)).await
    }
}

/// A zero interval would make `tokio::time::interval` panic and a tiny one
/// would spin the platform thread.
const MIN_POLL: Duration = Duration::from_millis(10);

/// What ended a connection, internally.
enum Fail {
    /// Reconnect.
    Lost(IpcError),
    /// Exit with an error.
    Fatal(AgentError),
}

impl From<IpcError> for Fail {
    fn from(e: IpcError) -> Self {
        Fail::Lost(e)
    }
}

impl From<WorkerGone> for Fail {
    fn from(e: WorkerGone) -> Self {
        Fail::Fatal(e.into())
    }
}

/// Session state as compared for "did it change": the exact idle seconds
/// change every poll, so only crossing the idle threshold counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionKey {
    locked: bool,
    display_asleep: bool,
    idle: bool,
}

/// What this connection's service was last told. Reset per connection, so
/// the full state goes out right after every handshake.
#[derive(Default)]
struct Reported {
    permission: Option<(WirePermissionState, Option<bool>)>,
    session: Option<SessionKey>,
    foreground: Option<(Option<AppInfo>, Option<String>)>,
    browser: Option<Option<BrowserContext>>,
    last_full: Option<Instant>,
}

struct Runtime {
    config: AgentConfig,
    verifier: Box<dyn PeerVerifier>,
    worker: PlatformWorker,
    notices: Box<dyn NoticeSink>,
    pending: Pending,
    /// The in-flight observation. Kept across connections: the platform has
    /// already drained the edges and tamper signals in it.
    observing: Option<oneshot::Receiver<Observation>>,
    poll: Interval,
}

/// Await an optional one-shot; pending forever when there is none, so it can
/// sit in a `select!` branch. Polling by reference is cancellation-safe.
async fn recv_opt<T>(
    rx: &mut Option<oneshot::Receiver<T>>,
) -> Result<T, oneshot::error::RecvError> {
    match rx {
        Some(rx) => rx.await,
        None => std::future::pending().await,
    }
}

/// Send with a deadline. `Connection::send` is not cancellation-safe, so a
/// timeout leaves the connection write-broken and the caller reconnects.
async fn send(
    conn: &mut AgentConnection<UnixStream>,
    timeout: Duration,
    msg: &AgentMsg,
) -> Result<(), IpcError> {
    match tokio::time::timeout(timeout, conn.send(msg)).await {
        Ok(r) => r,
        Err(_) => Err(IpcError::Timeout {
            what: "sending to the service",
            after: timeout,
        }),
    }
}

fn bounded_reason(mut s: String) -> String {
    if s.len() > MAX_REASON_LEN {
        let mut cut = MAX_REASON_LEN;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

impl Runtime {
    async fn run<F: Future<Output = ()>>(
        &mut self,
        mut stop: Pin<&mut F>,
    ) -> Result<ExitReason, AgentError> {
        let mut delay = self.config.backoff.initial;
        loop {
            // Connect first when both are ready: a handshake that just
            // completed is then closed properly (with `Goodbye`) by `serve`,
            // which checks `stop` before anything else.
            let attempt = tokio::select! {
                biased;
                r = self.connect() => r,
                () = &mut stop => return Ok(ExitReason::Stopped),
            };
            match attempt {
                Ok(mut conn) => {
                    delay = self.config.backoff.initial;
                    match self.serve(&mut conn, stop.as_mut()).await {
                        Ok(exit) => return Ok(exit),
                        Err(Fail::Fatal(e)) => return Err(e),
                        Err(Fail::Lost(e)) => {
                            tracing::info!(error = %e, "connection to the service lost; reconnecting");
                        }
                    }
                }
                Err(Fail::Lost(IpcError::PeerShutdown(reason))) => {
                    tracing::info!(
                        ?reason,
                        "service declined the connection with Shutdown; exiting"
                    );
                    return Ok(ExitReason::Shutdown(reason));
                }
                Err(Fail::Lost(e)) => {
                    tracing::warn!(
                        error = %e,
                        socket = %self.config.socket_path.display(),
                        retry_in = ?delay,
                        "could not connect to the service"
                    );
                }
                Err(Fail::Fatal(e)) => return Err(e),
            }
            if self.wait(delay, stop.as_mut()).await? {
                return Ok(ExitReason::Stopped);
            }
            delay = self.config.backoff.next(delay);
        }
    }

    // `&mut self` (not `&self`) keeps the future `Send` without requiring
    // `Runtime: Sync` (the notice sink is only `Send`).
    async fn connect(&mut self) -> Result<AgentConnection<UnixStream>, Fail> {
        let timeout = self.config.hello_timeout;
        // A root service binds one socket per account (every account is
        // monitored, §3.1); re-resolved on every attempt because it appears
        // only once the service has seen this session.
        let socket = resolve_socket(&self.config.socket_path);
        let connecting = IpcClient::connect_verified(&socket, self.verifier.as_ref());
        let mut conn = match tokio::time::timeout(timeout, connecting).await {
            Ok(r) => r?,
            Err(_) => {
                return Err(Fail::Lost(IpcError::Timeout {
                    what: "connecting to the service",
                    after: timeout,
                }))
            }
        };
        let greeting = AgentHello::new(
            AGENT_VERSION,
            self.config.session.clone(),
            self.config.user.clone(),
        );
        let welcome = hello(&mut conn, greeting, timeout).await?;
        tracing::info!(
            service_version = %welcome.service_version,
            "connected to the service"
        );
        Ok(conn)
    }

    /// Sleep for `delay` while the service is away, still polling the
    /// platform so session edges and tamper signals are queued, not missed.
    /// Returns `true` if `stop` fired.
    async fn wait<F: Future<Output = ()>>(
        &mut self,
        delay: Duration,
        mut stop: Pin<&mut F>,
    ) -> Result<bool, AgentError> {
        let mut deadline = pin!(tokio::time::sleep(delay));
        loop {
            tokio::select! {
                biased;
                () = &mut stop => return Ok(true),
                () = &mut deadline => return Ok(false),
                obs = recv_opt(&mut self.observing) => {
                    self.observing = None;
                    let mut obs = obs.map_err(|_| WorkerGone)?;
                    self.queue_signals(&mut obs);
                }
                _ = self.poll.tick() => self.start_observe()?,
            }
        }
    }

    fn start_observe(&mut self) -> Result<(), WorkerGone> {
        if self.observing.is_none() {
            self.observing = Some(self.worker.observe()?);
        }
        Ok(())
    }

    fn queue_signals(&mut self, obs: &mut Observation) {
        for c in obs.changes.drain(..) {
            tracing::debug!(change = ?c, "session change");
            self.pending.push(Signal::Session(c.into()));
        }
        for t in obs.tamper.drain(..) {
            tracing::info!(signal = ?t, "tamper signal observed");
            self.pending.push(Signal::Tamper(t));
        }
    }

    async fn flush_pending(&mut self, conn: &mut AgentConnection<UnixStream>) -> Result<(), Fail> {
        while let Some(sig) = self.pending.front() {
            let msg = match sig {
                Signal::Session(c) => AgentMsg::SessionChanged(*c),
                Signal::Tamper(t) => AgentMsg::Tamper(t.clone()),
            };
            // Pop only once sent: a signal must survive a failed send.
            send(conn, self.config.send_timeout, &msg).await?;
            self.pending.pop_front();
        }
        Ok(())
    }

    async fn serve<F: Future<Output = ()>>(
        &mut self,
        conn: &mut AgentConnection<UnixStream>,
        mut stop: Pin<&mut F>,
    ) -> Result<ExitReason, Fail> {
        let mut reported = Reported::default();
        let mut capture: Option<oneshot::Receiver<CaptureOutcome>> = None;
        let mut capture_again = false;
        // Deliver what was queued while disconnected, then sample at once so
        // the service has the full state right after the handshake.
        self.flush_pending(conn).await?;
        self.poll.reset_immediately();
        loop {
            tokio::select! {
                biased;
                () = &mut stop => {
                    goodbye(conn).await;
                    return Ok(ExitReason::Stopped);
                }
                msg = conn.recv() => match msg? {
                    ServiceMsg::CaptureNow { reason } => {
                        tracing::debug!(?reason, "capture requested");
                        if capture.is_some() {
                            capture_again = true;
                        } else {
                            capture = Some(self.worker.capture()?);
                        }
                    }
                    ServiceMsg::Ping { nonce } => {
                        send(conn, self.config.send_timeout, &AgentMsg::Pong { nonce }).await?;
                    }
                    ServiceMsg::ShowNotice { title, body } => self.notices.show(&title, &body),
                    ServiceMsg::Shutdown { reason } => {
                        tracing::info!(?reason, "service requested shutdown");
                        goodbye(conn).await;
                        return Ok(ExitReason::Shutdown(reason));
                    }
                    ServiceMsg::Welcome { .. } => {
                        tracing::warn!("ignoring an unexpected Welcome from the service");
                    }
                },
                out = recv_opt(&mut capture) => {
                    capture = None;
                    let out = out.map_err(|_| WorkerGone)?;
                    self.deliver_capture(conn, out, &mut reported).await?;
                    if std::mem::take(&mut capture_again) {
                        capture = Some(self.worker.capture()?);
                    }
                }
                obs = recv_opt(&mut self.observing) => {
                    self.observing = None;
                    let obs = obs.map_err(|_| WorkerGone)?;
                    self.report(conn, obs, &mut reported).await?;
                }
                _ = self.poll.tick() => self.start_observe()?,
            }
        }
    }

    async fn deliver_capture(
        &mut self,
        conn: &mut AgentConnection<UnixStream>,
        out: CaptureOutcome,
        reported: &mut Reported,
    ) -> Result<(), Fail> {
        let timeout = self.config.send_timeout;
        match out.result {
            Ok(Capture {
                captured_at_mono_ms,
                frames,
            }) => {
                let displays = frames.len();
                // Each batch is dropped (zeroized) right after it is written;
                // on a failed send the rest drop with the iterator.
                for msg in AgentMsg::frames_batches(captured_at_mono_ms, frames) {
                    send(conn, timeout, &msg).await?;
                }
                tracing::debug!(displays, "capture sent");
            }
            Err(e) => {
                if e.is_permission_denied() {
                    // The capture itself was refused, so report "denied" even
                    // if the preflight check raced and still says granted.
                    let screen = match out.permission {
                        PermissionState::Granted => PermissionState::Denied,
                        other => other,
                    };
                    let perm = (WirePermissionState::from(screen), out.accessibility);
                    send(
                        conn,
                        timeout,
                        &AgentMsg::Permission {
                            screen: perm.0,
                            accessibility: perm.1,
                        },
                    )
                    .await?;
                    reported.permission = Some(perm);
                }
                tracing::warn!(error = %e, "capture failed");
                let reason = bounded_reason(e.to_string());
                send(conn, timeout, &AgentMsg::CaptureFailed { reason }).await?;
            }
        }
        Ok(())
    }

    async fn report(
        &mut self,
        conn: &mut AgentConnection<UnixStream>,
        mut obs: Observation,
        reported: &mut Reported,
    ) -> Result<(), Fail> {
        let timeout = self.config.send_timeout;
        self.queue_signals(&mut obs);
        self.flush_pending(conn).await?;

        let now = Instant::now();
        let full = reported
            .last_full
            .is_none_or(|t| now.duration_since(t) >= self.config.resend_interval);

        let perm = (WirePermissionState::from(obs.permission), obs.accessibility);
        if full || reported.permission != Some(perm) {
            if let Some(prev) = reported.permission.filter(|p| *p != perm) {
                tracing::info!(
                    from = ?prev.0, to = ?perm.0,
                    accessibility = ?perm.1,
                    "permission state changed"
                );
            }
            send(
                conn,
                timeout,
                &AgentMsg::Permission {
                    screen: perm.0,
                    accessibility: perm.1,
                },
            )
            .await?;
            reported.permission = Some(perm);
        }

        let key = SessionKey {
            locked: obs.locked,
            display_asleep: obs.display_asleep,
            idle: obs.idle_secs >= self.config.idle_threshold.as_secs(),
        };
        if full || reported.session != Some(key) {
            send(
                conn,
                timeout,
                &AgentMsg::Session {
                    idle_secs: obs.idle_secs,
                    locked: obs.locked,
                    display_asleep: obs.display_asleep,
                },
            )
            .await?;
            reported.session = Some(key);
        }

        let foreground = (obs.app, obs.title);
        if full || reported.foreground.as_ref() != Some(&foreground) {
            // Titles are sensitive: debug only (crate docs).
            tracing::debug!(app = ?foreground.0, title = ?foreground.1, "foreground");
            let msg = AgentMsg::Foreground {
                app: foreground.0.clone(),
                title: foreground.1.clone(),
            };
            send(conn, timeout, &msg).await?;
            reported.foreground = Some(foreground);
        }

        // After `Foreground`: the service drops the browser context when the
        // app changes, and this brings the new one. `None` goes out as an
        // empty context, which clears it. URLs are never logged.
        if full || reported.browser.as_ref() != Some(&obs.browser) {
            let msg = AgentMsg::Browser(obs.browser.clone().unwrap_or_default());
            send(conn, timeout, &msg).await?;
            reported.browser = Some(obs.browser);
        }

        if full {
            reported.last_full = Some(now);
        }
        Ok(())
    }
}

/// Best effort: the agent is leaving either way.
async fn goodbye(conn: &mut AgentConnection<UnixStream>) {
    if let Err(e) = send(conn, GOODBYE_TIMEOUT, &AgentMsg::Goodbye).await {
        tracing::debug!(error = %e, "could not say Goodbye");
    }
}

/// The socket to connect to: this account's own socket next to the
/// configured path if the service bound one, else the configured path.
fn resolve_socket(base: &std::path::Path) -> std::path::PathBuf {
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    faro_ipc::resolve_agent_socket(base, uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_bounded_on_char_boundaries() {
        assert_eq!(bounded_reason("short".into()), "short");
        let long = "é".repeat(MAX_REASON_LEN);
        let cut = bounded_reason(long);
        assert!(cut.len() <= MAX_REASON_LEN);
        assert!(cut.chars().all(|c| c == 'é'));
    }
}
