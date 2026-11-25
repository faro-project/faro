//! The session agents over `faro-ipc` (ARCHITECTURE.md §3.1 "Local IPC").
//!
//! Every OS account is monitored, so the service serves **one agent per
//! interactive session**, for every account at once.
//!
//! * **Sessions.** The list of interactive sessions comes from a
//!   [`SessionLister`] ([`sessions::default_lister`]: the OS session list
//!   for a root service, our own session for a development service). It is
//!   re-read every `recheck` and whenever an agent claims a session the
//!   service has not seen yet.
//! * **Sockets.** A root service binds one socket per account,
//!   [`faro_ipc::session_socket_path`] (`agent.<uid>.sock` next to the
//!   configured path), owned by that account with mode 0600, in a
//!   root-owned directory (created 0755 if missing; `faro-ipc` refuses one
//!   anyone else can write to). Sockets follow the session list: a new
//!   account's socket appears within one recheck of its login, and an
//!   account's socket is removed when its last session ends. A non-root
//!   development service binds the configured path itself.
//! * **Peers.** Every connection is checked by the kernel's peer
//!   credentials before a byte is read: the uid must be the socket's
//!   account (root service) or own a listed session (development service),
//!   or be one of `ipc.allowed_uids`. A uid is not enough on its own, since
//!   every process the account runs has it, so the binary's **code
//!   signature** must also satisfy `ipc.agent_requirement`
//!   ([`super::codesign`]). A root service without a requirement refuses
//!   every agent unless the crate is built with the `dev` feature
//!   ([`IpcFrameSource::peer_policy`]).
//! * **One agent per session.** The agent's `Hello` names its session; the
//!   session must be listed and owned by the connecting uid (an allowed uid
//!   may claim any listed session). While a session's agent is connected,
//!   further connections for it are closed before `Welcome` (a real agent
//!   retries with backoff). An agent whose session ended is told
//!   `Shutdown { SessionEnded }`.
//! * **Departures are classified by the service, not the agent.** An agent
//!   saying `Goodbye` proves nothing: anything running as the user can send
//!   it, and `launchctl bootout` or `pkill` make the real agent send it too.
//!   A disconnect counts as *expected* only when the service sees the
//!   agent's session end (its user logged out) within a short grace
//!   period; every other departure is unexpected and goes to supervision
//!   (§3.7), however politely the agent left. Switching users does not end
//!   the switched-away session, so its agent must stay connected.
//! * **Capture follows the screen.** Captures go to the agent of the active
//!   session (the one at the screen; [`SourceEvent::CaptureTarget`]), and
//!   only its frames, foreground, idle/lock and permission state reach the
//!   core. Other agents' latest state is kept and replayed when their
//!   session becomes active (fast user switching). Tamper signals are
//!   forwarded from every agent, labelled with the account.
//! * **Frames only on request.** The service owns the schedule (§3.4):
//!   `Frames` that do not answer an outstanding `CaptureNow` are dropped
//!   (and zeroized) unread, so a misbehaving agent cannot make the
//!   privileged service classify frames at its own rate. Repeated
//!   unsolicited frames end the connection as a protocol violation. A
//!   *late* answer (to a request whose answer window closed, or that was
//!   withdrawn when the screen changed hands) is dropped too, but not held
//!   against the agent: a slow agent is not a misbehaving one.
//! * **Liveness.** Every agent is pinged every `ping_every`; a missed pong
//!   drops the connection (a hung agent counts as a disconnect, §3.7).
//!   The session list, with whether each session has an agent, is reported
//!   to the core as [`SourceEvent::Sessions`], so it can raise tamper for a
//!   session nobody monitors.

use super::codesign;
use super::sessions::{self, SessionEntry, SessionLister};
use super::{
    BoxFuture, CaptureTarget, FrameSource, SessionStatus, SourceCommand, SourceEvent, SourceIo,
};
use faro_ipc::{
    read_agent_hello, welcome_agent, AgentHello, AgentMsg, BindOptions, IpcError, IpcServer,
    PeerInfo, ServiceConnection, ServiceMsg, ShutdownReason, HELLO_TIMEOUT,
};
use faro_proto::body::account_label;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How long a `CaptureNow` stays answerable.
const CAPTURE_ANSWER_WINDOW: Duration = Duration::from_secs(30);
/// Unsolicited `Frames` tolerated per connection before disconnecting.
const MAX_UNSOLICITED: u32 = 3;
/// Late answers an agent can be owed at once (see [`Agent::late`]).
const MAX_LATE: u32 = 4;
/// How often the session list is re-read.
const SESSION_RECHECK: Duration = Duration::from_secs(5);
/// How long after an agent leaves the service waits to see its session end
/// (at logout launchd stops the agent a moment before the session list
/// changes) before calling the departure unexpected.
const SESSION_END_GRACE: Duration = Duration::from_secs(10);
/// Messages queued to one agent before it counts as stuck.
const AGENT_QUEUE: usize = 16;

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
    sessions: SessionLister,
    per_account_sockets: bool,
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
            .field("per_account_sockets", &self.per_account_sockets)
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
            sessions: sessions::default_lister(),
            per_account_sockets: euid() == 0,
            capture_window: CAPTURE_ANSWER_WINDOW,
            session_end_grace: SESSION_END_GRACE,
            recheck: SESSION_RECHECK,
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

    /// Replace the session list (default: [`sessions::default_lister`]).
    /// Tests use this to model logins, logouts and user switches.
    pub fn with_sessions(mut self, lister: SessionLister) -> Self {
        self.sessions = lister;
        self
    }

    /// Shorten the capture-answer window, the session-end grace period and
    /// the session re-check interval (tests).
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

    /// How peers will be verified, or why no agent can be accepted. See
    /// [`peer_policy`].
    pub fn peer_policy(&self) -> Result<PeerPolicy, String> {
        peer_policy(self.code_requirement.as_deref())
    }
}

/// How the agent is verified beyond its uid, or why it can't be. The agent
/// sockets and the enroll socket (`crate::enroll_server`) use the same rule.
///
/// A root service must verify the agent's code signature: otherwise any
/// program the member runs could stand in for the agent and report a
/// sleeping or locked screen forever. Only a `dev` build may skip it.
pub fn peer_policy(code_requirement: Option<&str>) -> Result<PeerPolicy, String> {
    if let Some(r) = code_requirement {
        codesign::check_requirement(r).map_err(|e| format!("ipc.agent_requirement: {e}"))?;
        return Ok(PeerPolicy::CodeRequirement(r.to_owned()));
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

/// Check `peer` against `policy` (after its uid was checked).
pub(crate) fn check_policy(
    peer: &PeerInfo,
    policy: &Result<PeerPolicy, String>,
) -> faro_ipc::Result<()> {
    match policy {
        Ok(PeerPolicy::UidOnly) => Ok(()),
        Ok(PeerPolicy::CodeRequirement(r)) => codesign::verify_peer(peer, r)
            .map_err(|e| IpcError::peer_rejected(format!("pid {:?}: {e}", peer.pid))),
        Err(why) => Err(IpcError::peer_rejected(why.clone())),
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The last good session list, shared with the peer verifiers.
type SessionSnapshot = Arc<Mutex<Vec<SessionEntry>>>;

fn snapshot_uids(s: &SessionSnapshot) -> BTreeSet<u32> {
    s.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|e| e.uid)
        .collect()
}

/// Which uids a listener admits (checked before any byte is read).
#[derive(Clone)]
enum Admit {
    /// A per-account socket: only that account (or an allowed uid).
    Account(u32),
    /// The development socket: any uid that owns a listed session.
    AnySession(SessionSnapshot),
}

fn verifier(
    admit: Admit,
    allowed: BTreeSet<u32>,
    policy: Result<PeerPolicy, String>,
) -> impl Fn(&PeerInfo) -> faro_ipc::Result<()> + Send + Sync {
    move |peer: &PeerInfo| {
        let ok = allowed.contains(&peer.uid)
            || match &admit {
                Admit::Account(uid) => peer.uid == *uid,
                Admit::AnySession(s) => snapshot_uids(s).contains(&peer.uid),
            };
        if !ok {
            return Err(IpcError::peer_rejected(format!(
                "uid {} has no session this socket serves",
                peer.uid
            )));
        }
        check_policy(peer, &policy)
    }
}

/// Create the socket's directory (0755) if it is missing.
pub(crate) fn ensure_socket_dir(path: &Path) -> std::io::Result<()> {
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

/// A connection whose `Hello` was read but not yet answered.
struct Arrival {
    conn: ServiceConnection<UnixStream>,
    hello: AgentHello,
}

/// A bound socket accepting connections; dropping it closes the socket
/// (and `IpcServer` removes its own socket file).
struct Listener(JoinHandle<()>);

impl Drop for Listener {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Accept connections and read each one's `Hello` in its own task, so a
/// slow or silent client cannot hold up the source.
async fn listen(server: IpcServer, arrivals: mpsc::Sender<Arrival>) {
    loop {
        match server.accept().await {
            Ok(mut conn) => {
                let tx = arrivals.clone();
                tokio::spawn(async move {
                    match read_agent_hello(&mut conn, HELLO_TIMEOUT).await {
                        Ok(hello) => {
                            let _ = tx.send(Arrival { conn, hello }).await;
                        }
                        Err(e) => tracing::warn!(error = %e, "agent handshake failed"),
                    }
                });
            }
            Err(e) => {
                // A rejected peer or a transient accept error: keep
                // listening, without spinning on a persistent error.
                tracing::warn!(error = %e, "agent connection refused");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

/// From an agent's connection task.
struct Inbound {
    conn_id: u64,
    msg: faro_ipc::Result<AgentMsg>,
}

/// Own one agent's connection: forward what it sends, send what the source
/// queues. Ends when either side closes; a `Shutdown` is the last message.
async fn serve_agent(
    mut conn: ServiceConnection<UnixStream>,
    conn_id: u64,
    mut outbox: mpsc::Receiver<ServiceMsg>,
    inbox: mpsc::Sender<Inbound>,
) {
    loop {
        tokio::select! {
            out = outbox.recv() => {
                let Some(m) = out else { return };
                let last = matches!(m, ServiceMsg::Shutdown { .. });
                let sent = if last {
                    tokio::time::timeout(Duration::from_secs(1), conn.send(&m))
                        .await
                        .unwrap_or(Ok(()))
                } else {
                    conn.send(&m).await
                };
                if let Err(e) = sent {
                    let _ = inbox.send(Inbound { conn_id, msg: Err(e) }).await;
                    return;
                }
                if last {
                    return;
                }
            }
            // `recv` is cancellation-safe; `send` (above) is never raced.
            r = conn.recv() => {
                let end = r.is_err();
                if inbox.send(Inbound { conn_id, msg: r }).await.is_err() || end {
                    return;
                }
            }
        }
    }
}

/// What an agent last reported about its session, replayed to the core
/// when its session becomes the capture target.
#[derive(Default)]
struct Cached {
    foreground: Option<SourceEvent>,
    browser: Option<SourceEvent>,
    session: Option<SourceEvent>,
    permission: Option<SourceEvent>,
}

impl Cached {
    fn replay(&self) -> Vec<SourceEvent> {
        [
            &self.permission,
            &self.session,
            &self.foreground,
            &self.browser,
        ]
        .into_iter()
        .filter_map(|e| e.as_ref().and_then(clone_state))
        .collect()
    }
}

/// Copies of the state events [`Cached`] holds (never frames).
fn clone_state(e: &SourceEvent) -> Option<SourceEvent> {
    Some(match e {
        SourceEvent::Foreground { app, title } => SourceEvent::Foreground {
            app: app.clone(),
            title: title.clone(),
        },
        SourceEvent::Browser(b) => SourceEvent::Browser(b.clone()),
        SourceEvent::Session {
            idle_secs,
            locked,
            display_asleep,
        } => SourceEvent::Session {
            idle_secs: *idle_secs,
            locked: *locked,
            display_asleep: *display_asleep,
        },
        SourceEvent::Permission {
            screen,
            accessibility,
        } => SourceEvent::Permission {
            screen: *screen,
            accessibility: *accessibility,
        },
        _ => return None,
    })
}

struct Agent {
    conn_id: u64,
    tx: mpsc::Sender<ServiceMsg>,
    session: String,
    account: String,
    /// Outstanding `CaptureNow`: when sent, and the capture time of the
    /// first answering batch (later batches of the same capture share it).
    capture: Option<(Instant, Option<u64>)>,
    unsolicited: u32,
    /// Requests that closed before any frames came (window passed, or
    /// withdrawn): the agent may still answer each once, late. Capped, so
    /// this cannot excuse a flood.
    late: u32,
    /// The capture time of the late answer being dropped, so its later
    /// batches are excused too.
    late_ts: Option<u64>,
    ping: Option<(u64, Instant)>,
    goodbye: bool,
    cached: Cached,
}

/// An agent that closed its connection; whether that was expected is
/// decided once the service has seen whether its session ended.
struct Departure {
    account: String,
    reason: String,
    goodbye: bool,
    deadline: Instant,
}

enum Handled {
    Forward(SourceEvent),
    Nothing,
    Violation(String),
}

/// The running source. See the module docs.
struct Run {
    cfg: IpcFrameSource,
    policy: Result<PeerPolicy, String>,
    events: mpsc::Sender<SourceEvent>,
    arrivals_tx: mpsc::Sender<Arrival>,
    inbox_tx: mpsc::Sender<Inbound>,
    sessions: Vec<SessionEntry>,
    snapshot: SessionSnapshot,
    listeners: BTreeMap<Option<u32>, Listener>,
    agents: BTreeMap<String, Agent>,
    departed: BTreeMap<String, Departure>,
    /// The last `Sessions` sent to the core.
    reported: Option<Vec<SessionStatus>>,
    /// The last `CaptureTarget` sent to the core.
    target: Option<CaptureTarget>,
    next_conn: u64,
    nonce: u64,
}

/// The core is gone: stop.
struct Closed;

type Step = Result<(), Closed>;

impl Run {
    async fn emit(&self, ev: SourceEvent) -> Step {
        self.events.send(ev).await.map_err(|_| Closed)
    }

    /// Re-read the session list; on failure keep the last good one.
    fn refresh_sessions(&mut self) {
        if let Some(mut list) = (self.cfg.sessions)() {
            list.sort_by(|a, b| a.id.cmp(&b.id));
            list.dedup_by(|a, b| a.id == b.id);
            for s in &mut list {
                s.account = account_label(&s.account);
            }
            *self.snapshot.lock().unwrap_or_else(PoisonError::into_inner) = list.clone();
            self.sessions = list;
        }
    }

    fn listed(&self, session: &str) -> Option<&SessionEntry> {
        self.sessions.iter().find(|s| s.id == session)
    }

    fn bind(&self, path: &Path, owner: Option<u32>, admit: Admit) -> faro_ipc::Result<IpcServer> {
        ensure_socket_dir(path)?;
        let options = BindOptions {
            mode: 0o600,
            group: None,
            owner,
        };
        IpcServer::bind_with(
            path,
            options,
            verifier(admit, self.cfg.allowed_uids.clone(), self.policy.clone()),
        )
    }

    /// Bind sockets for accounts that gained a session, close those whose
    /// sessions all ended.
    fn sync_listeners(&mut self) {
        let wanted: BTreeSet<Option<u32>> = if self.cfg.per_account_sockets {
            self.sessions
                .iter()
                .map(|s| s.uid)
                .chain(self.cfg.allowed_uids.iter().copied())
                .map(Some)
                .collect()
        } else {
            [None].into()
        };
        self.listeners.retain(|k, _| wanted.contains(k));
        for key in wanted {
            if self.listeners.contains_key(&key) {
                continue;
            }
            let bound = match key {
                Some(uid) => {
                    let path = faro_ipc::session_socket_path(&self.cfg.socket_path, uid);
                    self.bind(&path, Some(uid), Admit::Account(uid))
                }
                None => self.bind(
                    &self.cfg.socket_path,
                    None,
                    Admit::AnySession(self.snapshot.clone()),
                ),
            };
            match bound {
                Ok(server) => {
                    tracing::info!(path = %server.path().display(), uid = ?key, "listening for session agents");
                    let task = tokio::spawn(listen(server, self.arrivals_tx.clone()));
                    self.listeners.insert(key, Listener(task));
                }
                Err(e) => {
                    tracing::warn!(error = %e, uid = ?key, "cannot bind agent socket; will retry")
                }
            }
        }
    }

    fn statuses(&self) -> Vec<SessionStatus> {
        self.sessions
            .iter()
            .map(|s| SessionStatus {
                id: s.id.clone(),
                account: s.account.clone(),
                active: s.active,
                agent: self.agents.contains_key(&s.id),
            })
            .collect()
    }

    async fn report_sessions(&mut self) -> Step {
        let now = self.statuses();
        if self.reported.as_ref() == Some(&now) {
            return Ok(());
        }
        self.reported = Some(now.clone());
        self.emit(SourceEvent::Sessions(now)).await
    }

    /// Point captures at the active session's agent. While the current
    /// target's departure is still being classified, keep it: the core
    /// hears the departure first, then the change.
    async fn sync_target(&mut self) -> Step {
        let desired = self
            .sessions
            .iter()
            .find(|s| s.active && self.agents.contains_key(&s.id))
            .map(|s| CaptureTarget {
                session: s.id.clone(),
                account: s.account.clone(),
            });
        if desired == self.target {
            return Ok(());
        }
        if desired.is_none()
            && self
                .target
                .as_ref()
                .is_some_and(|t| self.departed.contains_key(&t.session))
        {
            return Ok(());
        }
        tracing::info!(from = ?self.target.as_ref().map(|t| &t.account), to = ?desired.as_ref().map(|t| &t.account), "capture target changed");
        self.target = desired.clone();
        // An answer to a capture sent to the old target no longer counts
        // (and arrives late, which is not the agent's fault).
        for a in self.agents.values_mut() {
            if let Some((_, None)) = a.capture.take() {
                a.late = (a.late + 1).min(MAX_LATE);
            }
        }
        self.emit(SourceEvent::CaptureTarget(desired.clone()))
            .await?;
        if let Some(t) = desired {
            let replay = self
                .agents
                .get(&t.session)
                .map(|a| a.cached.replay())
                .unwrap_or_default();
            for ev in replay {
                self.emit(ev).await?;
            }
        }
        Ok(())
    }

    fn is_target(&self, session: &str) -> bool {
        self.target.as_ref().is_some_and(|t| t.session == session)
    }

    /// Classify a pending departure: `Some(expected)` once it is decided
    /// (the session ended, the grace period passed, or `force`).
    fn decide(&self, session: &str, d: &Departure, force: bool) -> Option<(bool, String)> {
        if self.listed(session).is_none() {
            return Some((true, format!("{}; the agent's session ended", d.reason)));
        }
        if force || Instant::now() >= d.deadline {
            let reason = if d.goodbye {
                "the agent said goodbye but its session is still active".to_owned()
            } else {
                d.reason.clone()
            };
            return Some((false, reason));
        }
        None
    }

    async fn resolve_departures(&mut self, force_session: Option<&str>) -> Step {
        let ids: Vec<String> = self.departed.keys().cloned().collect();
        for id in ids {
            let force = force_session == Some(id.as_str());
            let Some(d) = self.departed.get(&id) else {
                continue;
            };
            if let Some((expected, reason)) = self.decide(&id, d, force) {
                let d = self.departed.remove(&id).expect("present");
                self.emit(SourceEvent::AgentDisconnected {
                    session: id,
                    account: d.account,
                    reason,
                    expected,
                })
                .await?;
            }
        }
        Ok(())
    }

    /// The agent's connection ended: it closed, or a write failed because
    /// it went away. Whether that was expected is decided by its session,
    /// now or within the grace period.
    async fn agent_left(&mut self, session: &str, reason: String) -> Step {
        let Some(a) = self.agents.remove(session) else {
            return Ok(());
        };
        tracing::info!(%reason, account = %a.account, goodbye = a.goodbye, "agent left");
        self.departed.insert(
            session.to_owned(),
            Departure {
                account: a.account,
                reason,
                goodbye: a.goodbye,
                deadline: Instant::now() + self.cfg.session_end_grace,
            },
        );
        self.resolve_departures(None).await?;
        self.report_sessions().await?;
        self.sync_target().await
    }

    /// Drop an agent after misbehaviour the service observed itself (ping
    /// timeout, protocol violation): always unexpected.
    async fn drop_agent(&mut self, session: &str, why: ShutdownReason, reason: String) -> Step {
        let Some(a) = self.agents.remove(session) else {
            return Ok(());
        };
        tracing::warn!(%reason, account = %a.account, "agent connection dropped");
        let _ = a.tx.try_send(ServiceMsg::Shutdown { reason: why });
        self.emit(SourceEvent::AgentDisconnected {
            session: session.to_owned(),
            account: a.account,
            reason,
            expected: false,
        })
        .await?;
        self.report_sessions().await?;
        self.sync_target().await
    }

    /// Queue a message to an agent; a full or closed queue means the agent
    /// is gone or stuck.
    async fn send_to(&mut self, session: &str, msg: ServiceMsg) -> Step {
        let Some(a) = self.agents.get(session) else {
            return Ok(());
        };
        match a.tx.try_send(msg) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.agent_left(session, "agent connection closed".into())
                    .await
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drop_agent(
                    session,
                    ShutdownReason::ProtocolViolation,
                    "agent stopped reading its connection".into(),
                )
                .await
            }
        }
    }

    async fn on_arrival(&mut self, mut arrival: Arrival) -> Step {
        let peer_uid = arrival.conn.peer().map(|p| p.uid);
        let hello = arrival.hello;
        if self.listed(&hello.session).is_none() {
            // Perhaps a login the last recheck has not seen yet.
            self.refresh_sessions();
        }
        let owner_ok = match (self.listed(&hello.session), peer_uid) {
            (Some(s), Some(uid)) => s.uid == uid || self.cfg.allowed_uids.contains(&uid),
            _ => false,
        };
        if !owner_ok {
            tracing::warn!(session = %hello.session, uid = ?peer_uid, "refusing an agent for a session that is not listed or not its own");
            return Ok(());
        }
        if self.agents.contains_key(&hello.session) {
            // The session's agent is connected and healthy (a hung one is
            // dropped by the ping check). A second connection is either an
            // impostor or a relaunched agent racing the old one's close;
            // closing before `Welcome` makes a real agent retry shortly.
            tracing::warn!(session = %hello.session, uid = ?peer_uid, "refusing a second agent connection for a session whose agent is connected");
            return Ok(());
        }
        if let Err(e) = welcome_agent(&mut arrival.conn).await {
            tracing::warn!(error = %e, "agent handshake failed");
            return Ok(());
        }
        // Report the previous agent's departure before the new arrival: a
        // reconnect within the grace period is a restart.
        if self.departed.contains_key(&hello.session) {
            self.resolve_departures(Some(&hello.session)).await?;
        }
        let account = self
            .listed(&hello.session)
            .map(|s| s.account.clone())
            .unwrap_or_default();
        self.next_conn += 1;
        let conn_id = self.next_conn;
        let (tx, rx) = mpsc::channel(AGENT_QUEUE);
        tokio::spawn(serve_agent(
            arrival.conn,
            conn_id,
            rx,
            self.inbox_tx.clone(),
        ));
        tracing::info!(pid = hello.pid, uid = ?peer_uid, account = %account, version = %hello.agent_version, "agent connected");
        self.agents.insert(
            hello.session.clone(),
            Agent {
                conn_id,
                tx,
                session: hello.session.clone(),
                account: account.clone(),
                capture: None,
                unsolicited: 0,
                late: 0,
                late_ts: None,
                ping: None,
                goodbye: false,
                cached: Cached::default(),
            },
        );
        self.emit(SourceEvent::AgentConnected {
            session: hello.session,
            account,
            agent_version: hello.agent_version,
        })
        .await?;
        self.report_sessions().await?;
        self.sync_target().await
    }

    fn session_of(&self, conn_id: u64) -> Option<String> {
        self.agents
            .values()
            .find(|a| a.conn_id == conn_id)
            .map(|a| a.session.clone())
    }

    async fn on_inbound(&mut self, inbound: Inbound) -> Step {
        let Some(session) = self.session_of(inbound.conn_id) else {
            // From a connection already dropped; frames zeroize here.
            return Ok(());
        };
        let msg = match inbound.msg {
            Ok(m) => m,
            Err(e) => {
                let reason = match e {
                    IpcError::Closed => "agent closed the connection".to_owned(),
                    other => other.to_string(),
                };
                return self.agent_left(&session, reason).await;
            }
        };
        let target = self.is_target(&session);
        let window = self.cfg.capture_window;
        let Some(a) = self.agents.get_mut(&session) else {
            return Ok(());
        };
        match handle_msg(a, msg, window, target) {
            Handled::Forward(ev) => self.emit(ev).await,
            Handled::Nothing => Ok(()),
            Handled::Violation(why) => {
                self.drop_agent(&session, ShutdownReason::ProtocolViolation, why)
                    .await
            }
        }
    }

    async fn on_command(&mut self, cmd: SourceCommand) -> Step {
        match cmd {
            SourceCommand::Shutdown => Ok(()),
            SourceCommand::CaptureNow(reason) => {
                let session = self
                    .target
                    .as_ref()
                    .map(|t| t.session.clone())
                    .filter(|s| self.agents.contains_key(s));
                let Some(session) = session else {
                    return self
                        .emit(SourceEvent::CaptureFailed {
                            reason: "no agent connected for the session at the screen".into(),
                        })
                        .await;
                };
                if let Some(a) = self.agents.get_mut(&session) {
                    a.capture = Some((Instant::now(), None));
                }
                self.send_to(&session, ServiceMsg::CaptureNow { reason })
                    .await
            }
            SourceCommand::ShowNotice {
                session,
                title,
                body,
            } => {
                let to: Vec<String> = match session {
                    Some(s) => vec![s],
                    None => self.agents.keys().cloned().collect(),
                };
                for s in to {
                    self.send_to(
                        &s,
                        ServiceMsg::ShowNotice {
                            title: title.clone(),
                            body: body.clone(),
                        },
                    )
                    .await?;
                }
                Ok(())
            }
        }
    }

    async fn on_ping(&mut self) -> Step {
        let sessions: Vec<String> = self.agents.keys().cloned().collect();
        for session in sessions {
            let timeout = self.cfg.ping_timeout;
            let window = self.cfg.capture_window;
            let Some(a) = self.agents.get_mut(&session) else {
                continue;
            };
            if a.ping.is_some_and(|(_, sent)| sent.elapsed() > timeout) {
                self.drop_agent(
                    &session,
                    ShutdownReason::ProtocolViolation,
                    "agent stopped answering pings".into(),
                )
                .await?;
                continue;
            }
            let mut unanswered = false;
            if let Some((sent, first)) = a.capture {
                if sent.elapsed() > window {
                    // The answer window closed. Only a request that got no
                    // frames at all is a failure; an answered one just
                    // stops accepting continuation batches.
                    a.capture = None;
                    unanswered = first.is_none();
                    if unanswered {
                        a.late = (a.late + 1).min(MAX_LATE);
                    }
                }
            }
            let ping = if a.ping.is_none() {
                self.nonce = self.nonce.wrapping_add(1);
                a.ping = Some((self.nonce, Instant::now()));
                Some(self.nonce)
            } else {
                None
            };
            if unanswered && self.is_target(&session) {
                self.emit(SourceEvent::CaptureFailed {
                    reason: "agent did not answer the capture request".into(),
                })
                .await?;
            }
            if let Some(nonce) = ping {
                self.send_to(&session, ServiceMsg::Ping { nonce }).await?;
            }
        }
        Ok(())
    }

    async fn on_recheck(&mut self) -> Step {
        self.refresh_sessions();
        self.sync_listeners();
        // An agent still connected after its session ended (a process
        // lingering past logout) is told so; leaving then is expected.
        let ended: Vec<String> = self
            .agents
            .keys()
            .filter(|id| self.listed(id).is_none())
            .cloned()
            .collect();
        for session in ended {
            if let Some(a) = self.agents.remove(&session) {
                let _ = a.tx.try_send(ServiceMsg::Shutdown {
                    reason: ShutdownReason::SessionEnded,
                });
                self.emit(SourceEvent::AgentDisconnected {
                    session,
                    account: a.account,
                    reason: "the agent's session ended".into(),
                    expected: true,
                })
                .await?;
            }
        }
        self.resolve_departures(None).await?;
        self.report_sessions().await?;
        self.sync_target().await
    }

    async fn shutdown(&mut self) {
        for a in self.agents.values() {
            let _ = a.tx.try_send(ServiceMsg::Shutdown {
                reason: ShutdownReason::ServiceStopping,
            });
        }
        // Let the connection tasks deliver it.
        let tasks: Vec<_> = std::mem::take(&mut self.agents)
            .into_values()
            .map(|a| a.tx)
            .collect();
        let deadline = Instant::now() + Duration::from_secs(1);
        for tx in tasks {
            let left = deadline.saturating_duration_since(Instant::now());
            let _ = tokio::time::timeout(left, tx.closed()).await;
        }
        self.listeners.clear();
    }
}

impl IpcFrameSource {
    async fn run_inner(self, io: SourceIo) {
        let SourceIo {
            mut commands,
            events,
        } = io;
        let policy = self.peer_policy();
        if let Err(why) = &policy {
            // Fail closed and loudly: every agent is refused, and the core
            // raises tamper once a session has had no agent for a while.
            tracing::error!(%why, "no agent can be verified; refusing all agent connections");
        }
        let (arrivals_tx, mut arrivals) = mpsc::channel(8);
        let (inbox_tx, mut inbox) = mpsc::channel(32);
        let mut ping_tick = tokio::time::interval(self.ping_every);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut recheck = tokio::time::interval(self.recheck);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut run = Run {
            cfg: self,
            policy,
            events,
            arrivals_tx,
            inbox_tx,
            sessions: Vec::new(),
            snapshot: Arc::default(),
            listeners: BTreeMap::new(),
            agents: BTreeMap::new(),
            departed: BTreeMap::new(),
            reported: None,
            target: None,
            next_conn: 0,
            nonce: 0,
        };
        run.refresh_sessions();
        run.sync_listeners();
        if run.report_sessions().await.is_err() {
            return;
        }

        loop {
            let step = tokio::select! {
                c = commands.recv() => match c {
                    None | Some(SourceCommand::Shutdown) => break,
                    Some(c) => run.on_command(c).await,
                },
                Some(a) = arrivals.recv() => run.on_arrival(a).await,
                Some(m) = inbox.recv() => run.on_inbound(m).await,
                _ = ping_tick.tick() => run.on_ping().await,
                _ = recheck.tick() => run.on_recheck().await,
            };
            if step.is_err() {
                break;
            }
        }
        run.shutdown().await;
    }
}

fn handle_msg(a: &mut Agent, msg: AgentMsg, window: Duration, target: bool) -> Handled {
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
                // A late answer: to a request still open but past its window
                // (the ping tick has not closed it yet), to one that closed
                // unanswered, or more batches of such an answer.
                let open_but_late =
                    matches!(a.capture, Some((sent, None)) if sent.elapsed() > window);
                let excused = if open_but_late || a.late_ts == Some(captured_at_mono_ms) {
                    true
                } else if a.late > 0 {
                    a.late -= 1;
                    true
                } else {
                    false
                };
                // `frames` drops here, zeroizing the pixels unread.
                drop(frames);
                if excused {
                    a.late_ts = Some(captured_at_mono_ms);
                    tracing::debug!("late capture answer dropped");
                    return Handled::Nothing;
                }
                a.unsolicited += 1;
                tracing::warn!(count = a.unsolicited, "agent sent frames nobody asked for");
                return if a.unsolicited > MAX_UNSOLICITED {
                    Handled::Violation("repeated unsolicited frames".into())
                } else {
                    Handled::Nothing
                };
            }
            if !target {
                // Asked before its session left the screen.
                drop(frames);
                a.capture = None;
                return Handled::Nothing;
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
        AgentMsg::Foreground { app, title } => state(
            target,
            &mut a.cached.foreground,
            SourceEvent::Foreground { app, title },
        ),
        AgentMsg::Browser(b) => state(target, &mut a.cached.browser, SourceEvent::Browser(b)),
        AgentMsg::Session {
            idle_secs,
            locked,
            display_asleep,
        } => state(
            target,
            &mut a.cached.session,
            SourceEvent::Session {
                idle_secs,
                locked,
                display_asleep,
            },
        ),
        AgentMsg::SessionChanged(c) => {
            if target {
                Handled::Forward(SourceEvent::SessionChanged(c.into()))
            } else {
                Handled::Nothing
            }
        }
        AgentMsg::Permission {
            screen,
            accessibility,
        } => state(
            target,
            &mut a.cached.permission,
            SourceEvent::Permission {
                screen: screen.into(),
                accessibility,
            },
        ),
        AgentMsg::Tamper(t) => Handled::Forward(SourceEvent::Tamper {
            signal: t,
            account: Some(a.account.clone()).filter(|s| !s.is_empty()),
        }),
        AgentMsg::CaptureFailed { reason } => {
            a.capture = None;
            if !target {
                return Handled::Nothing;
            }
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

/// Keep the latest state event; forward it if the agent is the target.
fn state(target: bool, slot: &mut Option<SourceEvent>, ev: SourceEvent) -> Handled {
    let forward = if target { clone_state(&ev) } else { None };
    *slot = Some(ev);
    match forward {
        Some(ev) => Handled::Forward(ev),
        None => Handled::Nothing,
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
    use faro_ipc::{hello, AgentConnection, IpcClient, WireFrame, WirePixelFormat};

    fn wire_frame() -> WireFrame {
        WireFrame::new(4, 4, WirePixelFormat::Rgba8, 0, vec![7u8; 64]).unwrap()
    }

    /// Sessions the test can log into, out of and switch between. Every
    /// session belongs to our own uid (a test cannot create accounts), and
    /// is told apart by its id, as distinct accounts' sessions would be.
    #[derive(Clone, Default)]
    struct Logins(Arc<Mutex<Vec<SessionEntry>>>);

    impl Logins {
        fn with(ids: &[(&str, bool)]) -> Logins {
            let l = Logins::default();
            for (id, active) in ids {
                l.log_in(id, *active);
            }
            l
        }
        fn log_in(&self, id: &str, active: bool) {
            self.0.lock().unwrap().push(SessionEntry {
                id: id.into(),
                uid: euid(),
                account: format!("acct-{id}"),
                active,
            });
        }
        fn log_out(&self, id: &str) {
            self.0.lock().unwrap().retain(|s| s.id != id);
        }
        /// Make `id` the session at the screen.
        fn switch_to(&self, id: &str) {
            for s in self.0.lock().unwrap().iter_mut() {
                s.active = s.id == id;
            }
        }
        fn lister(&self) -> SessionLister {
            let l = self.0.clone();
            Arc::new(move || Some(l.lock().unwrap().clone()))
        }
    }

    struct Harness {
        sock: PathBuf,
        cmd: mpsc::Sender<SourceCommand>,
        ev: mpsc::Receiver<SourceEvent>,
        task: JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        async fn start(logins: &Logins, capture_window: Duration) -> Harness {
            // Private, whatever the umask: the socket checks refuse a group-writable
            // directory, and tempfile leaves the mode to the umask (002 on many Linux
            // accounts).
            let dir = tempfile::Builder::new()
                .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .tempdir()
                .unwrap();
            let sock = dir.path().join("run").join("agent.sock");
            let mut src = IpcFrameSource::new(&sock, [])
                .with_ping(Duration::from_millis(50), Duration::from_secs(60))
                .with_sessions(logins.lister())
                .with_timings(
                    capture_window,
                    Duration::from_millis(1000),
                    Duration::from_millis(20),
                );
            // Even when the tests run as root: one socket for everyone.
            src.per_account_sockets = false;
            let (cmd, cmd_rx) = mpsc::channel(4);
            let (ev_tx, mut ev) = mpsc::channel(64);
            let task = tokio::spawn(Box::new(src).run(SourceIo {
                commands: cmd_rx,
                events: ev_tx,
            }));
            assert!(matches!(ev.recv().await, Some(SourceEvent::Sessions(_))));
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

        /// Connect an agent for `session`; returns once the source reports
        /// it connected.
        async fn connect(&mut self, session: &str) -> AgentConnection<UnixStream> {
            let mut agent = IpcClient::connect(&self.sock).await.unwrap();
            hello(
                &mut agent,
                AgentHello::new("test-agent", session, "me"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            self.until(
                |e| matches!(e, SourceEvent::AgentConnected { session: s, .. } if s == session),
            )
            .await;
            agent
        }

        async fn next(&mut self) -> SourceEvent {
            tokio::time::timeout(Duration::from_secs(10), self.ev.recv())
                .await
                .expect("an event in time")
                .expect("source still running")
        }

        /// Skip events until one matches.
        async fn until(&mut self, mut want: impl FnMut(&SourceEvent) -> bool) -> SourceEvent {
            loop {
                let e = self.next().await;
                if want(&e) {
                    return e;
                }
            }
        }

        async fn stop(self) {
            self.cmd.send(SourceCommand::Shutdown).await.unwrap();
            self.task.await.unwrap();
        }
    }

    fn target_is(e: &SourceEvent, session: Option<&str>) -> bool {
        matches!(e, SourceEvent::CaptureTarget(t) if t.as_ref().map(|t| t.session.as_str()) == session)
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
        let logins = Logins::with(&[("s1", true)]);
        let mut h = Harness::start(&logins, Duration::from_secs(30)).await;
        let mut agent = h.connect("s1").await;
        h.until(|e| target_is(e, Some("s1"))).await;

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
        match h.until(|e| !matches!(e, SourceEvent::Sessions(_))).await {
            SourceEvent::Tamper { account, .. } => assert_eq!(account.as_deref(), Some("acct-s1")),
            other => panic!("unexpected {other:?}"),
        }

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
        let logins = Logins::with(&[("s1", true)]);
        let mut h = Harness::start(&logins, Duration::from_millis(200)).await;
        let mut agent = h.connect("s1").await;
        h.until(|e| target_is(e, Some("s1"))).await;
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

    /// Regression: a slow agent answering after the answer window was
    /// counted as sending unsolicited frames, and dropped for a protocol
    /// violation after a few slow captures (told `Shutdown`, so it exited
    /// for good). Late answers are dropped without counting; frames nobody
    /// ever asked for still end the connection.
    #[tokio::test]
    async fn late_answers_are_excused_but_floods_are_not() {
        let logins = Logins::with(&[("s1", true)]);
        let mut h = Harness::start(&logins, Duration::from_millis(100)).await;
        let mut agent = h.connect("s1").await;
        h.until(|e| target_is(e, Some("s1"))).await;
        for i in 0..(MAX_UNSOLICITED + 3) {
            h.cmd
                .send(SourceCommand::CaptureNow(
                    faro_ipc::CaptureReason::Scheduled,
                ))
                .await
                .unwrap();
            serve_until(&mut agent, |m| matches!(m, ServiceMsg::CaptureNow { .. })).await;
            // Too slow: the window closes first.
            let failed = tokio::select! {
                _ = serve_for(&mut agent, Duration::from_secs(10)) => panic!("no capture failure"),
                ev = h.until(|e| matches!(e, SourceEvent::CaptureFailed { .. })) => ev,
            };
            assert!(matches!(failed, SourceEvent::CaptureFailed { .. }));
            // Two batches of the same late capture.
            for _ in 0..2 {
                agent
                    .send(&AgentMsg::Frames {
                        captured_at_mono_ms: 100 + u64::from(i),
                        frames: vec![wire_frame()],
                    })
                    .await
                    .unwrap();
            }
            // Let the source read them before the next request: answers
            // carry no request id, so a late answer arriving after the next
            // `CaptureNow` simply answers that one.
            serve_for(&mut agent, Duration::from_millis(150)).await;
        }
        serve_for(&mut agent, Duration::from_millis(300)).await;
        while let Ok(ev) = h.ev.try_recv() {
            assert!(
                !matches!(
                    ev,
                    SourceEvent::AgentDisconnected { .. } | SourceEvent::Frames(_)
                ),
                "late answers are neither forwarded nor held against the agent: {ev:?}"
            );
        }

        // Frames for requests that were never made: a flood ends it.
        for i in 0..=(MAX_UNSOLICITED + MAX_LATE) {
            agent
                .send(&AgentMsg::Frames {
                    captured_at_mono_ms: 1_000 + u64::from(i),
                    frames: vec![wire_frame()],
                })
                .await
                .unwrap();
        }
        match h
            .until(|e| matches!(e, SourceEvent::AgentDisconnected { .. }))
            .await
        {
            SourceEvent::AgentDisconnected {
                reason, expected, ..
            } => {
                assert!(!expected && reason.contains("unsolicited"), "{reason}")
            }
            _ => unreachable!(),
        }
        drop(agent);
        h.stop().await;
    }

    /// Regression: a second same-uid connection used to supersede the real
    /// agent (which then exited for good) with an expected disconnect.
    #[tokio::test]
    async fn second_connection_is_refused_while_the_agent_is_connected() {
        let logins = Logins::with(&[("s1", true)]);
        let mut h = Harness::start(&logins, Duration::from_secs(30)).await;
        let mut agent = h.connect("s1").await;
        h.until(|e| target_is(e, Some("s1"))).await;

        let mut impostor = IpcClient::connect(&h.sock).await.unwrap();
        let r = hello(
            &mut impostor,
            AgentHello::new("impostor", "s1", "me"),
            Duration::from_secs(5),
        )
        .await;
        assert!(r.is_err(), "the impostor gets no Welcome");
        // A session that is not listed is refused too.
        let mut stray = IpcClient::connect(&h.sock).await.unwrap();
        let r = hello(
            &mut stray,
            AgentHello::new("stray", "nobody-logged-in", "me"),
            Duration::from_secs(5),
        )
        .await;
        assert!(r.is_err(), "an unlisted session gets no Welcome");
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
        drop(stray);
        h.stop().await;
    }

    /// Regression: `Goodbye` used to make any departure "expected".
    #[tokio::test]
    async fn departures_are_classified_by_the_session_not_the_agent() {
        let logins = Logins::with(&[("s1", true)]);
        let mut h = Harness::start(&logins, Duration::from_secs(30)).await;

        // Goodbye while the session is still active: unexpected (after the
        // grace period).
        let mut agent = h.connect("s1").await;
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        drop(agent);
        match h
            .until(|e| matches!(e, SourceEvent::AgentDisconnected { .. }))
            .await
        {
            // (The reason depends on whether the service read the Goodbye
            // or hit the closed socket with a ping first.)
            SourceEvent::AgentDisconnected {
                expected, reason, ..
            } => {
                assert!(!expected, "{reason}")
            }
            other => panic!("unexpected {other:?}"),
        }
        h.until(|e| target_is(e, None)).await;

        // A crash (no goodbye) is unexpected too.
        let agent = h.connect("s1").await;
        drop(agent);
        match h
            .until(|e| matches!(e, SourceEvent::AgentDisconnected { .. }))
            .await
        {
            SourceEvent::AgentDisconnected { expected, .. } => assert!(!expected),
            other => panic!("unexpected {other:?}"),
        }

        // Leaving at logout (the session ends within the grace period) is
        // expected, and the core hears that the session is gone.
        let mut agent = h.connect("s1").await;
        // (At logout the agent is stopped a moment before the session list
        // changes; either order must work within the grace period.)
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        drop(agent);
        logins.log_out("s1");
        let mut saw_empty = false;
        loop {
            match h.next().await {
                SourceEvent::AgentDisconnected {
                    expected, reason, ..
                } => {
                    assert!(expected, "{reason}");
                    break;
                }
                SourceEvent::Sessions(s) if s.is_empty() => saw_empty = true,
                SourceEvent::Sessions(_) | SourceEvent::CaptureTarget(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        if !saw_empty {
            h.until(|e| matches!(e, SourceEvent::Sessions(s) if s.is_empty()))
                .await;
        }
        h.stop().await;
    }

    /// Two accounts logged in at once (fast user switching): both agents
    /// stay connected, captures follow the session at the screen, the
    /// background agent's state is replayed when its session comes to the
    /// front, and a session that has no agent is reported as such.
    #[tokio::test]
    async fn one_agent_per_session_and_capture_follows_the_screen() {
        let logins = Logins::with(&[("s1", true), ("s2", false)]);
        let mut h = Harness::start(&logins, Duration::from_secs(30)).await;
        let mut a1 = h.connect("s1").await;
        h.until(|e| target_is(e, Some("s1"))).await;
        let mut a2 = h.connect("s2").await;
        match h.until(|e| matches!(e, SourceEvent::Sessions(_))).await {
            SourceEvent::Sessions(s) => {
                assert!(s.iter().all(|s| s.agent), "{s:?}");
                assert_eq!(s.iter().filter(|s| s.active).count(), 1);
            }
            _ => unreachable!(),
        }
        // The background agent's state is kept, not forwarded.
        a2.send(&AgentMsg::Session {
            idle_secs: 7,
            locked: false,
            display_asleep: false,
        })
        .await
        .unwrap();
        a2.send(&AgentMsg::Tamper(faro_proto::body::TamperSignal::VpnActive))
            .await
            .unwrap();
        match h.next().await {
            SourceEvent::Tamper { account, .. } => assert_eq!(account.as_deref(), Some("acct-s2")),
            other => panic!("the background session state leaked: {other:?}"),
        }

        // Switch users: captures now go to s2, and its state is replayed.
        logins.switch_to("s2");
        let ev = h
            .until(|e| matches!(e, SourceEvent::CaptureTarget(_)))
            .await;
        match ev {
            SourceEvent::CaptureTarget(Some(t)) => {
                assert_eq!((t.session.as_str(), t.account.as_str()), ("s2", "acct-s2"))
            }
            other => panic!("unexpected {other:?}"),
        }
        match h.next().await {
            SourceEvent::Session { idle_secs, .. } => assert_eq!(idle_secs, 7),
            other => panic!("unexpected {other:?}"),
        }
        h.cmd
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        serve_until(&mut a2, |m| matches!(m, ServiceMsg::CaptureNow { .. })).await;
        // The switched-away agent is still pinged, never asked to capture.
        serve_until(&mut a1, |m| matches!(m, ServiceMsg::Ping { .. })).await;

        // A third account logs in at the screen; no agent connects for it.
        // The core hears that the session has no agent, then that nobody
        // can capture.
        logins.log_in("s3", false);
        logins.switch_to("s3");
        h.until(|e| {
            matches!(e, SourceEvent::Sessions(s)
                if s.iter().any(|s| s.id == "s3" && s.active && !s.agent))
        })
        .await;
        h.until(|e| target_is(e, None)).await;

        // A notice for every session reaches both agents.
        h.cmd
            .send(SourceCommand::ShowNotice {
                session: None,
                title: "t".into(),
                body: "b".into(),
            })
            .await
            .unwrap();
        for a in [&mut a1, &mut a2] {
            serve_until(a, |m| matches!(m, ServiceMsg::ShowNotice { .. })).await;
        }
        drop((a1, a2));
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
