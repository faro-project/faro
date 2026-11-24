//! The session agent over `faro-ipc` (ARCHITECTURE.md §3.1 "Local IPC").
//!
//! * **Socket.** A Unix socket in a root-owned directory (created 0755 if
//!   missing; `faro-ipc` refuses a directory anyone else can write to). When
//!   the service runs as root the socket is owned by the current **console
//!   user** with mode 0600, so only that user's agent can connect; on a
//!   console-user change (fast user switching) the socket is re-bound for
//!   the new user.
//! * **Peers.** Every connection is checked by the kernel's peer
//!   credentials before a byte is read: the uid must be the session owner's
//!   (the console user for a root service, looked up at accept time; our own
//!   uid for a non-root development service) or one of `ipc.allowed_uids`.
//!   A uid is not enough on its own, since every process the console user
//!   runs has it, so the binary's **code signature** must also satisfy
//!   `ipc.agent_requirement` ([`super::codesign`]). A root service without
//!   a requirement refuses every agent unless the crate is built with the
//!   `dev` feature ([`IpcFrameSource::peer_policy`]).
//! * **One agent per session.** While the session owner's agent is
//!   connected, further connections are refused (closed before the
//!   handshake; a real agent retries with backoff). Only an agent whose
//!   session is no longer the console session is superseded (and told
//!   `Shutdown { Superseded }`).
//! * **Departures are classified by the service, not the agent.** An agent
//!   saying `Goodbye` proves nothing: anything running as the user can send
//!   it, and `launchctl bootout` or `pkill` make the real agent send it too.
//!   A disconnect counts as *expected* only when the service sees the
//!   agent's session end (the console user logged out or switched) within
//!   a short grace period; every other departure is unexpected and goes
//!   to supervision (§3.7), however politely the agent left.
//! * **Frames only on request.** The service owns the schedule (§3.4):
//!   `Frames` that do not answer an outstanding `CaptureNow` are dropped
//!   (and zeroized) unread, so a misbehaving agent cannot make the
//!   privileged service classify frames at its own rate. Repeated
//!   unsolicited frames end the connection as a protocol violation.
//! * **Liveness.** The agent is pinged every `ping_every`; a missed pong
//!   drops the connection (a hung agent counts as a disconnect, §3.7).
//!   Whether a console session exists at all is reported to the core as
//!   [`SourceEvent::ConsoleSession`], so it can tell "nobody is logged in"
//!   from "the agent is missing".

use super::codesign;
use super::{BoxFuture, FrameSource, SourceCommand, SourceEvent, SourceIo};
use faro_ipc::{
    accept_agent, AgentMsg, BindOptions, IpcError, IpcServer, PeerInfo, ServiceConnection,
    ServiceMsg, ShutdownReason, HELLO_TIMEOUT,
};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::time::Instant;

/// How long a `CaptureNow` stays answerable.
const CAPTURE_ANSWER_WINDOW: Duration = Duration::from_secs(30);
/// Unsolicited `Frames` tolerated per connection before disconnecting.
const MAX_UNSOLICITED: u32 = 3;
/// How often the console user is re-checked.
const CONSOLE_RECHECK: Duration = Duration::from_secs(5);
/// How long after an agent leaves the service waits to see its session end
/// (at logout launchd stops the agent a moment before `/dev/console`
/// changes hands) before calling the departure unexpected.
const SESSION_END_GRACE: Duration = Duration::from_secs(10);

/// Who owns the console session right now (`None`: nobody is logged in).
pub type SessionOwner = Arc<dyn Fn() -> Option<u32> + Send + Sync>;

/// How connecting agents are verified beyond their uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPolicy {
    /// The binary's code signature must satisfy this designated requirement.
    CodeRequirement(String),
    /// The uid check only: a non-root service (which has nothing a user
    /// could not already do), or a `dev` build.
    UidOnly,
}

/// See the module docs.
#[derive(Clone)]
pub struct IpcFrameSource {
    socket_path: PathBuf,
    allowed_uids: BTreeSet<u32>,
    ping_every: Duration,
    ping_timeout: Duration,
    code_requirement: Option<String>,
    session_owner: SessionOwner,
    capture_window: Duration,
    session_end_grace: Duration,
    recheck: Duration,
}

impl fmt::Debug for IpcFrameSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcFrameSource")
            .field("socket_path", &self.socket_path)
            .field("allowed_uids", &self.allowed_uids)
            .field("ping_every", &self.ping_every)
            .field("code_requirement", &self.code_requirement)
            .finish_non_exhaustive()
    }
}

impl IpcFrameSource {
    pub fn new(
        socket_path: impl Into<PathBuf>,
        allowed_uids: impl IntoIterator<Item = u32>,
    ) -> Self {
        IpcFrameSource {
            socket_path: socket_path.into(),
            allowed_uids: allowed_uids.into_iter().collect(),
            ping_every: Duration::from_secs(30),
            ping_timeout: faro_ipc::DEFAULT_PING_TIMEOUT,
            code_requirement: None,
            session_owner: Arc::new(default_session_owner),
            capture_window: CAPTURE_ANSWER_WINDOW,
            session_end_grace: SESSION_END_GRACE,
            recheck: CONSOLE_RECHECK,
        }
    }

    pub fn with_ping(mut self, every: Duration, timeout: Duration) -> Self {
        self.ping_every = every.max(Duration::from_millis(10));
        self.ping_timeout = timeout.max(Duration::from_millis(10));
        self
    }

    /// Require connecting agents to satisfy this code-signing requirement
    /// (`ipc.agent_requirement`).
    pub fn with_code_requirement(mut self, requirement: Option<String>) -> Self {
        self.code_requirement = requirement;
        self
    }

    /// Replace the console-session lookup (default: [`console_uid`] for a
    /// root service, our own uid otherwise). Tests use this to model
    /// logouts and user switches.
    pub fn with_session_owner(mut self, owner: SessionOwner) -> Self {
        self.session_owner = owner;
        self
    }

    /// Shorten the capture-answer window, the session-end grace period and
    /// the console re-check interval (tests).
    pub fn with_timings(
        mut self,
        capture_window: Duration,
        session_end_grace: Duration,
        recheck: Duration,
    ) -> Self {
        self.capture_window = capture_window.max(Duration::from_millis(10));
        self.session_end_grace = session_end_grace;
        self.recheck = recheck.max(Duration::from_millis(10));
        self
    }

    /// How peers will be verified, or why no agent can be accepted.
    ///
    /// A root service must verify the agent's code signature: otherwise any
    /// program the member runs could stand in for the agent and report a
    /// sleeping or locked screen forever. Only a `dev` build may skip it.
    pub fn peer_policy(&self) -> Result<PeerPolicy, String> {
        if let Some(r) = &self.code_requirement {
            codesign::check_requirement(r).map_err(|e| format!("ipc.agent_requirement: {e}"))?;
            return Ok(PeerPolicy::CodeRequirement(r.clone()));
        }
        if euid() != 0 || cfg!(feature = "dev") {
            return Ok(PeerPolicy::UidOnly);
        }
        Err(
            "a root service needs `ipc.agent_requirement` (the agent's code-signing \
             requirement) to tell the real agent from any program the user runs; \
             only builds with the `dev` feature accept agents by uid alone"
                .into(),
        )
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn default_session_owner() -> Option<u32> {
    if euid() == 0 {
        console_uid()
    } else {
        // A non-root development service serves its own user's session.
        Some(euid())
    }
}

/// The uid of the user logged in at the console, if any.
///
/// * macOS: the owner of `/dev/console` (root while the login window shows).
/// * Linux: `ACTIVE_UID` of `seat0` as recorded by systemd-logind.
pub fn console_uid() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        (uid != 0).then_some(uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let s = std::fs::read_to_string("/run/systemd/seats/seat0").ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("ACTIVE_UID="))
            .and_then(|v| v.trim().parse().ok())
            .filter(|&uid| uid != 0)
    }
}

/// Whether `uid`'s session is the one being monitored right now.
#[derive(Clone)]
struct Sessions {
    owner: SessionOwner,
    allowed: BTreeSet<u32>,
}

impl Sessions {
    fn present(&self, uid: u32) -> bool {
        (self.owner)() == Some(uid) || self.allowed.contains(&uid)
    }
    fn anyone(&self) -> bool {
        (self.owner)().is_some()
    }
}

/// The peer check run on every accepted connection, before any byte is
/// read.
fn verifier(
    sessions: Sessions,
    policy: Result<PeerPolicy, String>,
) -> impl Fn(&PeerInfo) -> faro_ipc::Result<()> + Send + Sync {
    move |peer: &PeerInfo| {
        if !sessions.present(peer.uid) {
            return Err(IpcError::peer_rejected(format!(
                "uid {} is not the console user or an allowed uid",
                peer.uid
            )));
        }
        match &policy {
            Ok(PeerPolicy::UidOnly) => Ok(()),
            Ok(PeerPolicy::CodeRequirement(r)) => codesign::verify_peer(peer, r)
                .map_err(|e| IpcError::peer_rejected(format!("pid {:?}: {e}", peer.pid))),
            Err(why) => Err(IpcError::peer_rejected(why.clone())),
        }
    }
}

fn ensure_socket_dir(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o755);
            b.create(dir)?;
        }
    }
    Ok(())
}

struct Agent {
    conn: ServiceConnection<UnixStream>,
    uid: Option<u32>,
    /// Outstanding `CaptureNow`: when sent, and the capture time of the
    /// first answering batch (later batches of the same capture share it).
    capture: Option<(Instant, Option<u64>)>,
    unsolicited: u32,
    ping: Option<(u64, Instant)>,
    goodbye: bool,
}

/// An agent that closed its connection; whether that was expected is
/// decided once the service has seen whether its session ended.
struct Departure {
    uid: Option<u32>,
    reason: String,
    goodbye: bool,
    deadline: Instant,
}

enum Step {
    Command(Option<SourceCommand>),
    Accepted(faro_ipc::Result<ServiceConnection<UnixStream>>),
    Message(faro_ipc::Result<AgentMsg>),
    Ping,
    Recheck,
}

async fn recv(agent: &mut Option<Agent>) -> faro_ipc::Result<AgentMsg> {
    match agent {
        Some(a) => a.conn.recv().await,
        None => std::future::pending().await,
    }
}

async fn accept(server: &Option<IpcServer>) -> faro_ipc::Result<ServiceConnection<UnixStream>> {
    match server {
        Some(s) => s.accept().await,
        None => std::future::pending().await,
    }
}

/// Classify a pending departure: `Some` once it is decided (the session
/// ended, the grace period passed, or `force`).
fn resolve(d: &Departure, sessions: &Sessions, force: bool) -> Option<SourceEvent> {
    if d.uid.is_some_and(|u| !sessions.present(u)) {
        return Some(SourceEvent::Disconnected {
            reason: format!("{}; the agent's session ended", d.reason),
            expected: true,
        });
    }
    if force || Instant::now() >= d.deadline {
        let reason = if d.goodbye {
            "the agent said goodbye but its session is still active".to_owned()
        } else {
            d.reason.clone()
        };
        return Some(SourceEvent::Disconnected {
            reason,
            expected: false,
        });
    }
    None
}

impl IpcFrameSource {
    fn sessions(&self) -> Sessions {
        Sessions {
            owner: self.session_owner.clone(),
            allowed: self.allowed_uids.clone(),
        }
    }

    fn bind(&self, owner: Option<u32>) -> faro_ipc::Result<IpcServer> {
        ensure_socket_dir(&self.socket_path)?;
        let options = BindOptions {
            mode: 0o600,
            group: None,
            owner,
        };
        IpcServer::bind_with(
            &self.socket_path,
            options,
            verifier(self.sessions(), self.peer_policy()),
        )
    }

    /// The owner the socket should have right now (`None` = ourselves).
    fn wanted_owner(&self) -> Option<u32> {
        if euid() == 0 {
            (self.session_owner)()
        } else {
            None
        }
    }

    async fn run_inner(self, io: SourceIo) {
        let SourceIo {
            mut commands,
            events,
        } = io;
        if let Err(why) = self.peer_policy() {
            // Fail closed and loudly: every agent is refused, and the core
            // raises tamper once no agent has been connected for a while.
            tracing::error!(%why, "no agent can be verified; refusing all agent connections");
        }
        let sessions = self.sessions();
        let mut present = sessions.anyone();
        if events
            .send(SourceEvent::ConsoleSession { present })
            .await
            .is_err()
        {
            return;
        }
        let mut owner = self.wanted_owner();
        let mut server = match self.bind(owner) {
            Ok(s) => {
                tracing::info!(path = %s.path().display(), "listening for the session agent");
                Some(s)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %self.socket_path.display(), "cannot bind agent socket; will retry");
                None
            }
        };
        let mut agent: Option<Agent> = None;
        let mut departed: Option<Departure> = None;
        let mut nonce: u64 = 0;
        let mut ping_tick = tokio::time::interval(self.ping_every);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut recheck = tokio::time::interval(self.recheck);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            let step = tokio::select! {
                c = commands.recv() => Step::Command(c),
                a = accept(&server) => Step::Accepted(a),
                m = recv(&mut agent) => Step::Message(m),
                _ = ping_tick.tick() => Step::Ping,
                _ = recheck.tick() => Step::Recheck,
            };
            match step {
                Step::Command(None) | Step::Command(Some(SourceCommand::Shutdown)) => {
                    if let Some(mut a) = agent.take() {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(1),
                            a.conn.send(&ServiceMsg::Shutdown {
                                reason: ShutdownReason::ServiceStopping,
                            }),
                        )
                        .await;
                    }
                    return;
                }
                Step::Command(Some(SourceCommand::CaptureNow(reason))) => {
                    let Some(a) = agent.as_mut() else {
                        let _ = events
                            .send(SourceEvent::CaptureFailed {
                                reason: "no agent connected".into(),
                            })
                            .await;
                        continue;
                    };
                    match a.conn.send(&ServiceMsg::CaptureNow { reason }).await {
                        Ok(()) => a.capture = Some((Instant::now(), None)),
                        Err(e) => {
                            // The agent is gone (a broken pipe is how an agent that
                            // just closed often shows up first).
                            if !agent_left(
                                &mut agent,
                                &mut departed,
                                &events,
                                &sessions,
                                self.session_end_grace,
                                format!("send failed: {e}"),
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }
                }
                Step::Command(Some(SourceCommand::ShowNotice { title, body })) => {
                    if let Some(a) = agent.as_mut() {
                        if let Err(e) = a.conn.send(&ServiceMsg::ShowNotice { title, body }).await {
                            // The agent is gone (a broken pipe is how an agent that
                            // just closed often shows up first).
                            if !agent_left(
                                &mut agent,
                                &mut departed,
                                &events,
                                &sessions,
                                self.session_end_grace,
                                format!("send failed: {e}"),
                            )
                            .await
                            {
                                return;
                            }
                        }
                    }
                }
                Step::Accepted(Err(e)) => {
                    // A rejected peer or a transient accept error: keep listening.
                    tracing::warn!(error = %e, "agent connection refused");
                }
                Step::Accepted(Ok(mut conn)) => {
                    let peer_uid = conn.peer().map(|p| p.uid);
                    if agent
                        .as_ref()
                        .is_some_and(|a| a.uid.is_some_and(|u| sessions.present(u)))
                    {
                        // The session's agent is connected and healthy (a
                        // hung one is dropped by the ping check). A second
                        // connection is either an impostor or a relaunched
                        // agent racing the old one's close; closing before
                        // the handshake makes a real agent retry shortly.
                        tracing::warn!(uid = ?peer_uid, "refusing a second agent connection while the session's agent is connected");
                        drop(conn);
                        continue;
                    }
                    // Report the previous agent's departure before the new
                    // arrival: a reconnect within the grace period is a
                    // restart.
                    if let Some(d) = departed.take() {
                        if let Some(ev) = resolve(&d, &sessions, true) {
                            if events.send(ev).await.is_err() {
                                return;
                            }
                        }
                    }
                    match accept_agent(&mut conn, HELLO_TIMEOUT).await {
                        Ok(hello) => {
                            if let Some(mut old) = agent.take() {
                                // Only an agent whose session is no longer
                                // the console session gets here.
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    old.conn.send(&ServiceMsg::Shutdown {
                                        reason: ShutdownReason::Superseded,
                                    }),
                                )
                                .await;
                                let _ = events
                                    .send(SourceEvent::Disconnected {
                                        reason: "superseded: the old agent's session is no longer the console session".into(),
                                        expected: true,
                                    })
                                    .await;
                            }
                            tracing::info!(pid = hello.pid, uid = ?peer_uid, version = %hello.agent_version, "agent connected");
                            agent = Some(Agent {
                                conn,
                                uid: peer_uid,
                                capture: None,
                                unsolicited: 0,
                                ping: None,
                                goodbye: false,
                            });
                            if events
                                .send(SourceEvent::Connected {
                                    agent_version: hello.agent_version,
                                    session: hello.session,
                                    user: hello.user,
                                })
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(e) => tracing::warn!(error = %e, "agent handshake failed"),
                    }
                }
                Step::Message(Err(e)) => {
                    let reason = match e {
                        IpcError::Closed => "agent closed the connection".to_owned(),
                        other => other.to_string(),
                    };
                    if !agent_left(
                        &mut agent,
                        &mut departed,
                        &events,
                        &sessions,
                        self.session_end_grace,
                        reason,
                    )
                    .await
                    {
                        return;
                    }
                }
                Step::Message(Ok(msg)) => {
                    let Some(a) = agent.as_mut() else { continue };
                    match handle_msg(a, msg, self.capture_window) {
                        Handled::Forward(ev) => {
                            if events.send(ev).await.is_err() {
                                return;
                            }
                        }
                        Handled::Nothing => {}
                        Handled::Violation(why) => {
                            if let Some(a) = agent.as_mut() {
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(1),
                                    a.conn.send(&ServiceMsg::Shutdown {
                                        reason: ShutdownReason::ProtocolViolation,
                                    }),
                                )
                                .await;
                            }
                            drop_agent(&mut agent, &events, why).await;
                        }
                    }
                }
                Step::Ping => {
                    let Some(a) = agent.as_mut() else { continue };
                    if let Some((_, sent)) = a.ping {
                        if sent.elapsed() > self.ping_timeout {
                            drop_agent(&mut agent, &events, "agent stopped answering pings".into())
                                .await;
                            continue;
                        }
                    }
                    if let Some((sent, first)) = a.capture {
                        if sent.elapsed() > self.capture_window {
                            // The answer window closed. Only a request that
                            // got no frames at all is a failure; an answered
                            // one just stops accepting continuation batches.
                            a.capture = None;
                            if first.is_none() {
                                let _ = events
                                    .send(SourceEvent::CaptureFailed {
                                        reason: "agent did not answer the capture request".into(),
                                    })
                                    .await;
                            }
                        }
                    }
                    if a.ping.is_none() {
                        nonce = nonce.wrapping_add(1);
                        match a.conn.send(&ServiceMsg::Ping { nonce }).await {
                            Ok(()) => a.ping = Some((nonce, Instant::now())),
                            Err(e) => {
                                // The agent is gone (a broken pipe is how an agent that
                                // just closed often shows up first).
                                if !agent_left(
                                    &mut agent,
                                    &mut departed,
                                    &events,
                                    &sessions,
                                    self.session_end_grace,
                                    format!("send failed: {e}"),
                                )
                                .await
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
                Step::Recheck => {
                    if let Some(d) = &departed {
                        if let Some(ev) = resolve(d, &sessions, false) {
                            departed = None;
                            if events.send(ev).await.is_err() {
                                return;
                            }
                        }
                    }
                    let now_present = sessions.anyone();
                    if now_present != present {
                        present = now_present;
                        tracing::info!(present, "console session changed");
                        if events
                            .send(SourceEvent::ConsoleSession { present })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    let wanted = self.wanted_owner();
                    if server.is_none() || (euid() == 0 && wanted != owner) {
                        // Drop the old listener first so the path is free;
                        // IpcServer removes only its own socket.
                        server = None;
                        owner = wanted;
                        match self.bind(owner) {
                            Ok(s) => {
                                tracing::info!(path = %s.path().display(), owner = ?owner, "agent socket (re)bound");
                                server = Some(s);
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "cannot bind agent socket; will retry")
                            }
                        }
                    }
                }
            }
        }
    }
}

enum Handled {
    Forward(SourceEvent),
    Nothing,
    Violation(String),
}

fn handle_msg(a: &mut Agent, msg: AgentMsg, window: Duration) -> Handled {
    match msg {
        AgentMsg::Hello { .. } => Handled::Violation("second Hello".into()),
        AgentMsg::Frames {
            captured_at_mono_ms,
            frames,
        } => {
            let answers = match a.capture {
                Some((sent, first)) if sent.elapsed() <= window => {
                    first.is_none_or(|t| t == captured_at_mono_ms)
                }
                _ => false,
            };
            if !answers {
                // `frames` drops here, zeroizing the pixels unread.
                drop(frames);
                a.unsolicited += 1;
                tracing::warn!(count = a.unsolicited, "agent sent frames nobody asked for");
                return if a.unsolicited > MAX_UNSOLICITED {
                    Handled::Violation("repeated unsolicited frames".into())
                } else {
                    Handled::Nothing
                };
            }
            if let Some(c) = a.capture.as_mut() {
                c.1 = Some(captured_at_mono_ms);
            }
            let mut out = Vec::with_capacity(frames.len());
            for wf in frames {
                match wf.into_frame() {
                    Ok(f) => out.push(f),
                    Err(e) => {
                        // `out` drops (zeroized) with the rest.
                        return Handled::Forward(SourceEvent::CaptureFailed {
                            reason: format!("invalid frame from agent: {e}"),
                        });
                    }
                }
            }
            if out.is_empty() {
                return Handled::Forward(SourceEvent::CaptureFailed {
                    reason: "agent returned no frames".into(),
                });
            }
            Handled::Forward(SourceEvent::Frames(out))
        }
        AgentMsg::Foreground { app, title } => {
            Handled::Forward(SourceEvent::Foreground { app, title })
        }
        AgentMsg::Browser(b) => Handled::Forward(SourceEvent::Browser(b)),
        AgentMsg::Session {
            idle_secs,
            locked,
            display_asleep,
        } => Handled::Forward(SourceEvent::Session {
            idle_secs,
            locked,
            display_asleep,
        }),
        AgentMsg::SessionChanged(c) => Handled::Forward(SourceEvent::SessionChanged(c.into())),
        AgentMsg::Permission {
            screen,
            accessibility,
        } => Handled::Forward(SourceEvent::Permission {
            screen: screen.into(),
            accessibility,
        }),
        AgentMsg::Tamper(t) => Handled::Forward(SourceEvent::Tamper(t)),
        AgentMsg::CaptureFailed { reason } => {
            a.capture = None;
            let reason: String = reason
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            Handled::Forward(SourceEvent::CaptureFailed { reason })
        }
        AgentMsg::Pong { nonce } => {
            if a.ping.is_some_and(|(n, _)| n == nonce) {
                a.ping = None;
            }
            Handled::Nothing
        }
        AgentMsg::Goodbye => {
            // Recorded for the log only: the departure is classified by
            // whether the session ended, not by what the agent says.
            a.goodbye = true;
            Handled::Nothing
        }
    }
}

/// The agent's connection ended: it closed, or a write failed because it
/// went away. Whether that was expected is decided by its session, now or
/// within the grace period (`departed`). Returns false if the core is gone.
async fn agent_left(
    agent: &mut Option<Agent>,
    departed: &mut Option<Departure>,
    events: &mpsc::Sender<SourceEvent>,
    sessions: &Sessions,
    grace: Duration,
    reason: String,
) -> bool {
    let Some(a) = agent.take() else { return true };
    tracing::info!(%reason, goodbye = a.goodbye, "agent left");
    let d = Departure {
        uid: a.uid,
        reason,
        goodbye: a.goodbye,
        deadline: Instant::now() + grace,
    };
    match resolve(&d, sessions, false) {
        Some(ev) => events.send(ev).await.is_ok(),
        None => {
            *departed = Some(d);
            true
        }
    }
}

/// Drop the agent after misbehaviour the service observed itself (ping
/// timeout, protocol violation): always unexpected.
async fn drop_agent(agent: &mut Option<Agent>, events: &mpsc::Sender<SourceEvent>, reason: String) {
    if agent.take().is_some() {
        tracing::warn!(%reason, "agent connection lost");
        let _ = events
            .send(SourceEvent::Disconnected {
                reason,
                expected: false,
            })
            .await;
    }
}

impl FrameSource for IpcFrameSource {
    fn name(&self) -> &'static str {
        "ipc"
    }

    fn run(self: Box<Self>, io: SourceIo) -> BoxFuture {
        Box::pin((*self).run_inner(io))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_ipc::{hello, AgentConnection, AgentHello, IpcClient, WireFrame, WirePixelFormat};
    use std::sync::Mutex;

    fn wire_frame() -> WireFrame {
        WireFrame::new(4, 4, WirePixelFormat::Rgba8, 0, vec![7u8; 64]).unwrap()
    }

    /// A console session the test can log out of.
    fn session(uid: Option<u32>) -> (Arc<Mutex<Option<u32>>>, SessionOwner) {
        let cell = Arc::new(Mutex::new(uid));
        let c = cell.clone();
        (cell, Arc::new(move || *c.lock().unwrap()))
    }

    struct Harness {
        sock: PathBuf,
        cmd: mpsc::Sender<SourceCommand>,
        ev: mpsc::Receiver<SourceEvent>,
        task: tokio::task::JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        async fn start(owner: SessionOwner, capture_window: Duration) -> Harness {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("run").join("agent.sock");
            let src = Box::new(
                IpcFrameSource::new(&sock, [])
                    .with_ping(Duration::from_millis(50), Duration::from_secs(60))
                    .with_session_owner(owner)
                    .with_timings(
                        capture_window,
                        Duration::from_millis(1000),
                        Duration::from_millis(20),
                    ),
            );
            let (cmd, cmd_rx) = mpsc::channel(4);
            let (ev_tx, mut ev) = mpsc::channel(16);
            let task = tokio::spawn(src.run(SourceIo {
                commands: cmd_rx,
                events: ev_tx,
            }));
            assert!(matches!(
                ev.recv().await,
                Some(SourceEvent::ConsoleSession { present: true })
            ));
            for _ in 0..400 {
                if sock.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Harness {
                sock,
                cmd,
                ev,
                task,
                _dir: dir,
            }
        }

        async fn connect(&mut self) -> AgentConnection<UnixStream> {
            let mut agent = IpcClient::connect(&self.sock).await.unwrap();
            hello(
                &mut agent,
                AgentHello::new("test-agent", "s1", "me"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            match self.next().await {
                SourceEvent::Connected { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
            agent
        }

        /// The next event that is not a ping-driven non-event.
        async fn next(&mut self) -> SourceEvent {
            tokio::time::timeout(Duration::from_secs(10), self.ev.recv())
                .await
                .expect("an event in time")
                .expect("source still running")
        }

        async fn stop(self) {
            self.cmd.send(SourceCommand::Shutdown).await.unwrap();
            self.task.await.unwrap();
        }
    }

    /// Answer pings until `want` arrives.
    async fn serve_until(
        agent: &mut AgentConnection<UnixStream>,
        mut want: impl FnMut(&ServiceMsg) -> bool,
    ) -> ServiceMsg {
        loop {
            let m = agent.recv().await.unwrap();
            if want(&m) {
                return m;
            }
            match m {
                ServiceMsg::Ping { nonce } => agent.send(&AgentMsg::Pong { nonce }).await.unwrap(),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// Answer pings for `d` of real time.
    async fn serve_for(agent: &mut AgentConnection<UnixStream>, d: Duration) {
        let _ = tokio::time::timeout(d, serve_until(agent, |_| false)).await;
    }

    #[tokio::test]
    async fn agent_roundtrip_and_unsolicited_frames() {
        let (_cell, owner) = session(Some(euid()));
        let mut h = Harness::start(owner, Duration::from_secs(30)).await;
        let mut agent = h.connect().await;

        // Unsolicited frames are dropped, not forwarded.
        agent
            .send(&AgentMsg::Frames {
                captured_at_mono_ms: 1,
                frames: vec![wire_frame()],
            })
            .await
            .unwrap();
        agent
            .send(&AgentMsg::Tamper(faro_proto::body::TamperSignal::VpnActive))
            .await
            .unwrap();
        assert!(matches!(h.next().await, SourceEvent::Tamper(_)));

        // A requested capture is answered.
        h.cmd
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        serve_until(&mut agent, |m| matches!(m, ServiceMsg::CaptureNow { .. })).await;
        agent
            .send(&AgentMsg::Frames {
                captured_at_mono_ms: 2,
                frames: vec![wire_frame()],
            })
            .await
            .unwrap();
        match h.next().await {
            SourceEvent::Frames(f) => assert_eq!(f[0].width(), 4),
            other => panic!("unexpected {other:?}"),
        }
        drop(agent);
        h.stop().await;
    }

    /// Regression: an answered capture used to be reported as failed once
    /// the answer window passed.
    #[tokio::test]
    async fn answered_capture_is_not_reported_failed_after_the_window() {
        let (_cell, owner) = session(Some(euid()));
        let mut h = Harness::start(owner, Duration::from_millis(200)).await;
        let mut agent = h.connect().await;
        h.cmd
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        serve_until(&mut agent, |m| matches!(m, ServiceMsg::CaptureNow { .. })).await;
        agent
            .send(&AgentMsg::Frames {
                captured_at_mono_ms: 2,
                frames: vec![wire_frame()],
            })
            .await
            .unwrap();
        assert!(matches!(h.next().await, SourceEvent::Frames(_)));
        // Well past the window, with pings ticking every 50 ms.
        serve_for(&mut agent, Duration::from_millis(700)).await;
        assert!(
            h.ev.try_recv().is_err(),
            "no CaptureFailed for an answered capture"
        );
        // An unanswered request still fails.
        h.cmd
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        serve_until(&mut agent, |m| matches!(m, ServiceMsg::CaptureNow { .. })).await;
        let served = serve_for(&mut agent, Duration::from_secs(10));
        let ev = tokio::select! {
            _ = served => panic!("no capture failure"),
            ev = h.next() => ev,
        };
        match ev {
            SourceEvent::CaptureFailed { reason } => assert!(reason.contains("did not answer")),
            other => panic!("unexpected {other:?}"),
        }
        drop(agent);
        h.stop().await;
    }

    /// Regression: a second same-uid connection used to supersede the real
    /// agent (which then exited for good) with an expected disconnect.
    #[tokio::test]
    async fn second_connection_is_refused_while_the_agent_is_connected() {
        let (_cell, owner) = session(Some(euid()));
        let mut h = Harness::start(owner, Duration::from_secs(30)).await;
        let mut agent = h.connect().await;

        let mut impostor = IpcClient::connect(&h.sock).await.unwrap();
        let r = hello(
            &mut impostor,
            AgentHello::new("impostor", "s1", "me"),
            Duration::from_secs(5),
        )
        .await;
        assert!(r.is_err(), "the impostor gets no Welcome");
        // The real agent is untouched: no Shutdown, still pinged.
        let m = serve_until(&mut agent, |m| matches!(m, ServiceMsg::Ping { .. })).await;
        let ServiceMsg::Ping { nonce } = m else {
            unreachable!()
        };
        agent.send(&AgentMsg::Pong { nonce }).await.unwrap();
        serve_for(&mut agent, Duration::from_millis(200)).await;
        assert!(h.ev.try_recv().is_err(), "no disconnect reported");
        drop(agent);
        drop(impostor);
        h.stop().await;
    }

    /// Regression: `Goodbye` used to make any departure "expected".
    #[tokio::test]
    async fn departures_are_classified_by_the_session_not_the_agent() {
        let (cell, owner) = session(Some(euid()));
        let mut h = Harness::start(owner, Duration::from_secs(30)).await;

        // Goodbye while the session is still active: unexpected (after the
        // grace period).
        let mut agent = h.connect().await;
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        drop(agent);
        match h.next().await {
            // (The reason depends on whether the service read the Goodbye
            // or hit the closed socket with a ping first.)
            SourceEvent::Disconnected { expected, reason } => assert!(!expected, "{reason}"),
            other => panic!("unexpected {other:?}"),
        }

        // A crash (no goodbye) is unexpected too.
        let agent = h.connect().await;
        drop(agent);
        match h.next().await {
            SourceEvent::Disconnected { expected, .. } => assert!(!expected),
            other => panic!("unexpected {other:?}"),
        }

        // Leaving at logout (the session ends within the grace period) is
        // expected, and the core hears that nobody is logged in.
        let mut agent = h.connect().await;
        // (At logout the agent is stopped a moment before the console
        // changes hands; either order must work within the grace period.)
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        drop(agent);
        *cell.lock().unwrap() = None;
        let mut saw_absent = false;
        loop {
            match h.next().await {
                SourceEvent::Disconnected { expected, reason } => {
                    assert!(expected, "{reason}");
                    break;
                }
                SourceEvent::ConsoleSession { present: false } => saw_absent = true,
                other => panic!("unexpected {other:?}"),
            }
        }
        if !saw_absent {
            assert!(matches!(
                h.next().await,
                SourceEvent::ConsoleSession { present: false }
            ));
        }
        h.stop().await;
    }

    #[test]
    fn uid_only_policy_is_for_non_root_or_dev() {
        let src = IpcFrameSource::new("/tmp/x.sock", []);
        if euid() != 0 || cfg!(feature = "dev") {
            assert_eq!(src.peer_policy(), Ok(PeerPolicy::UidOnly));
        } else {
            assert!(src.peer_policy().is_err());
        }
        #[cfg(target_os = "macos")]
        {
            let bad = src.clone().with_code_requirement(Some("nonsense (".into()));
            assert!(
                bad.peer_policy().is_err(),
                "a bad requirement fails at start"
            );
            let ok = src.with_code_requirement(Some("anchor apple generic".into()));
            assert!(matches!(
                ok.peer_policy(),
                Ok(PeerPolicy::CodeRequirement(_))
            ));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let req = src.with_code_requirement(Some("anything".into()));
            assert!(req.peer_policy().is_err(), "no silent fallback to uid-only");
        }
    }
}
