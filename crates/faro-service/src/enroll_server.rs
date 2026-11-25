//! Enrolling from the session agent, without Terminal (issue #62,
//! ARCHITECTURE.md §3.8).
//!
//! An installed service starts before the computer is enrolled and waits
//! for `enrollment.json` (`cli::wait_for_enrollment`). Before it waits, it
//! starts this server, which stays up for the life of the process (so it
//! can also answer "already enrolled").
//!
//! * **Sockets.** A root service binds one socket per account with a GUI
//!   session, `enroll.<uid>.sock` next to the agent sockets, owned by that
//!   account with mode 0600 ([`faro_ipc::enroll_socket_path`]). The set
//!   follows logins like the agent sockets do. A non-root development
//!   service binds `enroll.sock` for its own user.
//! * **Peers.** Checked by the kernel before a byte is read, like the agent
//!   sockets ([`crate::source::ipc::peer_policy`]): the socket's own uid,
//!   and, when `ipc.agent_requirement` is set, the agent's code signature.
//! * **Requests** ([`faro_ipc::EnrollRequest`]): one per connection.
//!   `Status` and `Preview` change nothing. `Enroll` runs [`EnrollService`]'s
//!   steps: parse the link (the CLI's parsers), refuse if enrolled,
//!   discover the instance, require the identity the person confirmed, ask
//!   an administrator ([`Approver`]), then call [`enroll::enroll`], whose
//!   confirm step checks the identity once more. So the instance key
//!   pinning, the link's member-key check (`m`) and invariant 3 run exactly
//!   the CLI's code. One enrollment at a time.
//! * **Approval.** The [`Approver`] is a trait so tests can fake it, but
//!   the binary always uses [`SystemApprover`] (macOS Authorization
//!   Services, `faro_platform_macos::authorization`), with no flag or
//!   setting to swap it. The `dev` feature changes who may *connect* (any
//!   process of the user, when no code requirement is set); it never
//!   changes approval, so a development package can't enroll without an
//!   administrator either.
//!
//! After `Enroll` succeeds, `wait_for_enrollment` finds `enrollment.json`
//! and activation continues as after `faro-service enroll`.

use crate::accounts::{self, Accounts};
use crate::client::{ClientError, ClientOptions, InstanceClient};
use crate::config::Config;
use crate::enroll::{self, EnrollError, EnrollParams, InstanceInfo};
use crate::link::{self, EnrollCode};
use crate::state::{self, StateDir, StateError};
use faro_core::clock::{Clock, SystemClock};
use faro_ipc::{
    EnrollDone, EnrollPreview, EnrollRequest, EnrollResponse, EnrollStatus, EnrollTarget,
    FailureKind, AUTHORIZATION_LEN,
};
use reqwest::StatusCode;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// How long an administrator has to answer the prompt.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);

/// Why an [`Approver`] said no.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    /// Cancelled, or the name and password were refused.
    #[error("no administrator approved")]
    NotApproved,
    /// Approval can't be asked for here (no mechanism, or its rule is
    /// missing or altered).
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Failed(String),
}

/// Asks an administrator to approve enrolling. Blocks until they answer.
pub trait Approver: Send + Sync + 'static {
    /// `authorization` is the agent's `AuthorizationExternalForm`; `prompt`
    /// is the service's own explanation, naming the instance it discovered.
    fn approve(
        &self,
        authorization: &[u8; AUTHORIZATION_LEN],
        prompt: &str,
    ) -> Result<(), ApprovalError>;
}

/// The approver the binary uses: Authorization Services on macOS (see
/// `faro_platform_macos::authorization`), nothing elsewhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemApprover;

impl Approver for SystemApprover {
    #[cfg(target_os = "macos")]
    fn approve(
        &self,
        authorization: &[u8; AUTHORIZATION_LEN],
        prompt: &str,
    ) -> Result<(), ApprovalError> {
        use faro_platform_macos::authorization::{approve_enrollment, AuthError, RuleCheck};
        // Only root may (and must) fix the rule; a development service
        // running as the user checks it and refuses if it is wrong.
        let may_write = euid() == 0;
        match approve_enrollment(authorization, prompt, may_write) {
            Ok(RuleCheck::Correct) => Ok(()),
            Ok(RuleCheck::Rewritten(why)) => {
                tracing::warn!(
                    previous = why.as_deref().unwrap_or("missing"),
                    "the org.faro.enroll authorization rule was set up again"
                );
                Ok(())
            }
            Err(AuthError::Denied | AuthError::Canceled) => Err(ApprovalError::NotApproved),
            Err(e @ AuthError::InteractionNotAllowed) => {
                Err(ApprovalError::Unavailable(e.to_string()))
            }
            Err(e @ (AuthError::RuleMissing | AuthError::RuleAltered(_))) => {
                tracing::error!(error = %e, "refusing to ask for approval");
                Err(ApprovalError::Unavailable(e.to_string()))
            }
            Err(e @ AuthError::AlreadyAuthorized) => {
                tracing::error!(error = %e, "refusing an authorization approved elsewhere");
                Err(ApprovalError::Failed(e.to_string()))
            }
            Err(e @ AuthError::Os { .. }) => Err(ApprovalError::Failed(e.to_string())),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn approve(
        &self,
        _authorization: &[u8; AUTHORIZATION_LEN],
        _prompt: &str,
    ) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable(
            "enrolling from the agent needs macOS; use `faro-service enroll`".into(),
        ))
    }
}

#[cfg(unix)]
fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The text of the administrator prompt: the instance as the service
/// discovered it, never as the agent described it.
pub fn approval_prompt(name: &str, url: &Url) -> String {
    let clean = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).collect() };
    let host = url.host_str().unwrap_or("");
    format!(
        "Faro wants to enroll this computer with \u{201c}{}\u{201d} ({}). Faro will then \
         monitor every account on this computer. Enter an administrator\u{2019}s name and \
         password to allow this.",
        clean(name),
        clean(host)
    )
}

type AccountLister = Arc<dyn Fn() -> Option<Accounts> + Send + Sync>;

/// Answers enroll requests. See the module docs.
pub struct EnrollService {
    state_dir: PathBuf,
    client: ClientOptions,
    clock: Arc<dyn Clock>,
    approver: Arc<dyn Approver>,
    accounts: AccountLister,
    device_name: Option<String>,
    approval_timeout: Duration,
    enrolling: Arc<tokio::sync::Mutex<()>>,
}

impl std::fmt::Debug for EnrollService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollService")
            .field("state_dir", &self.state_dir)
            .field("approval_timeout", &self.approval_timeout)
            .finish_non_exhaustive()
    }
}

/// The parsed target.
struct Target {
    instance: Url,
    code: EnrollCode,
    member_key: Option<String>,
}

fn fail(kind: FailureKind, detail: impl Into<String>) -> EnrollResponse {
    EnrollResponse::failed(kind, detail)
}

impl EnrollService {
    pub fn new(state_dir: impl Into<PathBuf>, client: ClientOptions, approver: Arc<dyn Approver>) -> Self {
        EnrollService {
            state_dir: state_dir.into(),
            client,
            clock: Arc::new(SystemClock::new()),
            approver,
            accounts: Arc::new(accounts::local_accounts),
            device_name: None,
            approval_timeout: APPROVAL_TIMEOUT,
            enrolling: Arc::default(),
        }
    }

    /// The service's settings (`state_dir`, `[network]`), with `approver`.
    pub fn from_config(config: &Config, approver: Arc<dyn Approver>) -> Self {
        let client = ClientOptions {
            timeout: config.network.request_timeout(),
            ca_file: config.network.ca_file.clone(),
        };
        Self::new(config.state_dir.clone(), client, approver)
    }

    /// Tests: the device's clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Tests: the accounts the preview lists.
    pub fn with_accounts(mut self, f: impl Fn() -> Option<Accounts> + Send + Sync + 'static) -> Self {
        self.accounts = Arc::new(f);
        self
    }

    /// The device name (default: the host name, as for the CLI).
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }

    /// Tests: how long to wait for an administrator.
    pub fn with_approval_timeout(mut self, d: Duration) -> Self {
        self.approval_timeout = d;
        self
    }

    /// Answer one request.
    pub async fn handle(&self, req: EnrollRequest) -> EnrollResponse {
        tracing::info!(request = req.kind(), "enroll request from the agent");
        let resp = match req {
            EnrollRequest::Status => self.status(),
            EnrollRequest::Preview(target) => self.preview(&target).await,
            EnrollRequest::Enroll {
                target,
                confirmed_instance,
                confirmed_identity,
                authorization,
            } => {
                self.enroll(&target, &confirmed_instance, &confirmed_identity, &authorization)
                    .await
            }
        };
        match &resp {
            EnrollResponse::Failed { kind, detail } => {
                tracing::info!(?kind, %detail, "enroll request refused")
            }
            other => tracing::info!(response = other.kind(), "enroll request answered"),
        }
        resp
    }

    fn dir(&self) -> Result<StateDir, EnrollResponse> {
        StateDir::open(&self.state_dir).map_err(|e| fail(FailureKind::Failed, e.to_string()))
    }

    fn status(&self) -> EnrollResponse {
        let dir = match self.dir() {
            Ok(d) => d,
            Err(r) => return r,
        };
        match dir.enrollment() {
            Ok(e) => EnrollResponse::Status(EnrollStatus {
                enrolled: true,
                instance_name: Some(e.instance_name.clone()),
                instance_url: Some(e.instance_url.clone()),
                endorsed: matches!(dir.endorsement(), Ok(Some(_))),
            }),
            Err(StateError::NotEnrolled) => EnrollResponse::Status(EnrollStatus {
                enrolled: false,
                instance_name: None,
                instance_url: None,
                endorsed: false,
            }),
            Err(e) => fail(FailureKind::Failed, e.to_string()),
        }
    }

    /// Refuse if the computer is enrolled.
    fn not_enrolled(&self) -> Result<StateDir, EnrollResponse> {
        let dir = self.dir()?;
        match dir.enrollment() {
            Ok(e) => Err(fail(
                FailureKind::AlreadyEnrolled,
                format!("enrolled with {} ({})", e.instance_name, e.instance_url),
            )),
            Err(StateError::NotEnrolled) => Ok(dir),
            Err(e) => Err(fail(FailureKind::Failed, e.to_string())),
        }
    }

    fn parse(target: &EnrollTarget) -> Result<Target, EnrollResponse> {
        let bad = |e: link::LinkError| fail(FailureKind::BadInput, e.to_string());
        match target {
            EnrollTarget::Link(l) => {
                let l = link::parse_enroll_link(l).map_err(bad)?;
                Ok(Target {
                    instance: l.instance,
                    code: l.code,
                    member_key: l.member_key,
                })
            }
            EnrollTarget::Manual { instance, code } => Ok(Target {
                instance: link::parse_instance_url(instance).map_err(bad)?,
                code: EnrollCode::parse(code).map_err(bad)?,
                member_key: None,
            }),
        }
    }

    async fn discover(&self, url: &Url) -> Result<InstanceInfo, EnrollResponse> {
        let client = InstanceClient::new(url.clone(), self.clock.clone(), &self.client)
            .map_err(|e| failure(&e.into()))?;
        enroll::discover(&client).await.map_err(|e| failure(&e))
    }

    fn device_name(&self) -> Result<String, EnrollResponse> {
        enroll::device_name(self.device_name.as_deref())
            .map_err(|e| fail(FailureKind::Failed, e.to_string()))
    }

    async fn preview(&self, target: &EnrollTarget) -> EnrollResponse {
        let t = match Self::parse(target) {
            Ok(t) => t,
            Err(r) => return r,
        };
        if let Err(r) = self.not_enrolled() {
            return r;
        }
        let info = match self.discover(&t.instance).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let device_name = match self.device_name() {
            Ok(n) => n,
            Err(r) => return r,
        };
        let lister = self.accounts.clone();
        let accounts = tokio::task::spawn_blocking(move || lister())
            .await
            .ok()
            .flatten();
        EnrollResponse::Preview(EnrollPreview {
            instance_name: info.name.clone(),
            instance_url: info.url.to_string(),
            instance_id: info.well_known.instance_id.as_str().to_owned(),
            identity_key: *info.well_known.identity_pubkey.as_bytes(),
            device_name,
            guest_enabled: accounts.as_ref().is_some_and(|a| a.guest_enabled),
            accounts: accounts.map(|a| a.names),
            member_key_in_link: t.member_key.is_some(),
        })
    }

    async fn enroll(
        &self,
        target: &EnrollTarget,
        confirmed_instance: &str,
        confirmed_identity: &[u8; 32],
        authorization: &[u8; AUTHORIZATION_LEN],
    ) -> EnrollResponse {
        let Ok(guard) = self.enrolling.clone().try_lock_owned() else {
            return fail(FailureKind::Busy, "another enrollment is in progress");
        };
        let t = match Self::parse(target) {
            Ok(t) => t,
            Err(r) => return r,
        };
        let dir = match self.not_enrolled() {
            Ok(d) => d,
            Err(r) => return r,
        };
        let device_name = match self.device_name() {
            Ok(n) => n,
            Err(r) => return r,
        };
        let info = match self.discover(&t.instance).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        let confirmed = |info: &InstanceInfo| {
            info.well_known.identity_pubkey.as_bytes() == confirmed_identity
                && info.well_known.instance_id.as_str() == confirmed_instance
        };
        if !confirmed(&info) {
            return fail(
                FailureKind::InstanceChanged,
                "the instance answers with another identity than the one you confirmed",
            );
        }

        // The prompt names what the service discovered itself. The
        // approver blocks (a dialog), so it runs on the blocking pool; the
        // lock goes with it, so a dialog left open after the timeout still
        // keeps a second enrollment out until it closes.
        let prompt = approval_prompt(&info.name, &info.url);
        let approver = self.approver.clone();
        let auth = *authorization;
        let asked = tokio::task::spawn_blocking(move || {
            let r = approver.approve(&auth, &prompt);
            (guard, r)
        });
        let _guard = match tokio::time::timeout(self.approval_timeout, asked).await {
            Err(_) => {
                return fail(
                    FailureKind::NotApproved,
                    "no administrator answered in time",
                )
            }
            Ok(Err(e)) => return fail(FailureKind::Failed, format!("approval failed: {e}")),
            Ok(Ok((_, Err(ApprovalError::NotApproved)))) => {
                return fail(FailureKind::NotApproved, "no administrator approved")
            }
            Ok(Ok((_, Err(ApprovalError::Unavailable(why))))) => {
                return fail(FailureKind::Unavailable, why)
            }
            Ok(Ok((_, Err(ApprovalError::Failed(why))))) => {
                return fail(FailureKind::Failed, why)
            }
            Ok(Ok((guard, Ok(())))) => guard,
        };
        tracing::info!(instance = %info.url, "an administrator approved enrolling");

        let params = EnrollParams {
            instance: t.instance,
            code: t.code,
            device_name,
            client: self.client.clone(),
            member_key: t.member_key,
        };
        let member_key_checked = params.member_key.is_some();
        // The CLI's enrollment, pinning and member-key check; its confirm
        // step re-checks the identity the person confirmed.
        let enrollment = match enroll::enroll(&dir, self.clock.clone(), &params, confirmed).await {
            Ok(e) => e,
            Err(e) => return failure(&e),
        };
        let key = match state::load_device_key(&dir) {
            Ok(k) => k,
            Err(e) => return fail(FailureKind::Failed, e.to_string()),
        };
        EnrollResponse::Enrolled(EnrollDone {
            device_fingerprint: enroll::device_fingerprint(&key.public()),
            member_fingerprint: enroll::member_fingerprint(&enrollment.member_sign_pubkey),
            member_key_checked,
        })
    }
}

/// The failure kind for an enrollment error.
pub fn failure_kind(e: &EnrollError) -> FailureKind {
    match e {
        EnrollError::Client(c) => match c {
            ClientError::Api { code, .. } if code == "invalid_enroll_code" => {
                FailureKind::WrongCode
            }
            ClientError::Api { status, .. } if *status == StatusCode::UNAUTHORIZED => {
                FailureKind::WrongCode
            }
            ClientError::Transport(_) => FailureKind::Unreachable,
            c if c.is_transient() => FailureKind::Unreachable,
            ClientError::Api { status, .. } if *status == StatusCode::NOT_FOUND => {
                FailureKind::NotFaro
            }
            ClientError::Json(_) | ClientError::TooLarge { .. } => FailureKind::NotFaro,
            _ => FailureKind::Failed,
        },
        EnrollError::InvalidInstance(_) => FailureKind::NotFaro,
        EnrollError::Declined => FailureKind::InstanceChanged,
        EnrollError::MemberKeyMismatch { .. } => FailureKind::MemberKeyMismatch,
        EnrollError::State(StateError::AlreadyEnrolled { .. }) => FailureKind::AlreadyEnrolled,
        _ => FailureKind::Failed,
    }
}

fn failure(e: &EnrollError) -> EnrollResponse {
    fail(failure_kind(e), e.to_string())
}

#[cfg(unix)]
pub use listener::EnrollServer;

#[cfg(unix)]
mod listener {
    use super::EnrollService;
    use crate::config::Config;
    use crate::source::ipc::{check_policy, ensure_socket_dir, peer_policy, PeerPolicy};
    use crate::source::sessions::{self, SessionLister};
    use faro_ipc::{
        BindOptions, EnrollResponse, EnrollServerConnection, FailureKind, IpcError, IpcServer,
        PeerInfo,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::UnixStream;
    use tokio::sync::Semaphore;
    use tokio::task::JoinHandle;

    /// How long a client has to send its request.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    /// Requests served at once (one of them may be an enrollment).
    const MAX_CONCURRENT: usize = 4;
    /// How often the session list is re-read.
    const RECHECK: Duration = Duration::from_secs(5);

    /// The enroll sockets. See the module docs.
    pub struct EnrollServer {
        service: Arc<EnrollService>,
        agent_socket: PathBuf,
        code_requirement: Option<String>,
        per_account: bool,
        sessions: SessionLister,
        recheck: Duration,
    }

    impl std::fmt::Debug for EnrollServer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EnrollServer")
                .field("agent_socket", &self.agent_socket)
                .field("per_account", &self.per_account)
                .finish_non_exhaustive()
        }
    }

    struct Listener(JoinHandle<()>);

    impl Drop for Listener {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    impl EnrollServer {
        /// Sockets next to `config.ipc.socket_path`, peers checked with
        /// `config.ipc.agent_requirement`.
        pub fn new(service: EnrollService, config: &Config) -> Self {
            EnrollServer {
                service: Arc::new(service),
                agent_socket: config.ipc.socket_path.clone(),
                code_requirement: config.ipc.agent_requirement.clone(),
                per_account: super::euid() == 0,
                sessions: sessions::default_lister(),
                recheck: RECHECK,
            }
        }

        /// Tests: one socket for the test's own uid, at the development
        /// path, whatever uid the test runs as.
        pub fn single_socket(mut self) -> Self {
            self.per_account = false;
            self
        }

        /// The socket path for `uid` (`None`: the development socket).
        pub fn socket_path(&self, uid: Option<u32>) -> PathBuf {
            faro_ipc::enroll_socket_path(&self.agent_socket, uid)
        }

        /// Serve until dropped (the caller aborts the task).
        pub async fn run(self) {
            let policy = peer_policy(self.code_requirement.as_deref());
            if let Err(why) = &policy {
                tracing::error!(%why, "no agent can be verified; enrolling from the agent is off");
                return std::future::pending().await;
            }
            let slots = Arc::new(Semaphore::new(MAX_CONCURRENT));
            let mut listeners: BTreeMap<Option<u32>, Listener> = BTreeMap::new();
            let mut wanted: BTreeSet<Option<u32>> = [None].into();
            loop {
                if self.per_account {
                    if let Some(list) = (self.sessions)() {
                        wanted = list.iter().map(|s| Some(s.uid)).collect();
                    }
                }
                listeners.retain(|k, _| wanted.contains(k));
                for key in &wanted {
                    if listeners.contains_key(key) {
                        continue;
                    }
                    match self.bind(*key, policy.clone()) {
                        Ok(server) => {
                            tracing::info!(path = %server.path().display(), uid = ?key, "listening for enroll requests");
                            let task = tokio::spawn(accept_loop(
                                server,
                                self.service.clone(),
                                slots.clone(),
                            ));
                            listeners.insert(*key, Listener(task));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, uid = ?key, "cannot bind the enroll socket; will retry")
                        }
                    }
                }
                tokio::time::sleep(self.recheck).await;
            }
        }

        fn bind(
            &self,
            owner: Option<u32>,
            policy: Result<PeerPolicy, String>,
        ) -> faro_ipc::Result<IpcServer> {
            let path = self.socket_path(owner);
            ensure_socket_dir(&path)?;
            let admit = owner.unwrap_or_else(super::euid);
            let verify = move |peer: &PeerInfo| {
                if peer.uid != admit {
                    return Err(IpcError::peer_rejected(format!(
                        "uid {} may not use this enroll socket",
                        peer.uid
                    )));
                }
                check_policy(peer, &policy)
            };
            IpcServer::bind_with(
                &path,
                BindOptions {
                    mode: 0o600,
                    group: None,
                    owner,
                },
                verify,
            )
        }
    }

    async fn accept_loop(server: IpcServer, service: Arc<EnrollService>, slots: Arc<Semaphore>) {
        loop {
            match server.accept_typed::<EnrollResponse, faro_ipc::EnrollRequest>().await {
                Ok(conn) => {
                    let service = service.clone();
                    let slot = slots.clone().try_acquire_owned();
                    tokio::spawn(async move {
                        serve(conn, &service, slot.is_ok()).await;
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "enroll connection refused");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    }

    async fn serve(
        mut conn: EnrollServerConnection<UnixStream>,
        service: &EnrollService,
        have_slot: bool,
    ) {
        let req = match conn.recv_timeout(REQUEST_TIMEOUT, "an enroll request").await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "no enroll request");
                return;
            }
        };
        let resp = if have_slot {
            service.handle(req).await
        } else {
            EnrollResponse::failed(FailureKind::Busy, "too many requests at once")
        };
        if let Err(e) = conn.send(&resp).await {
            tracing::warn!(error = %e, "could not answer the enroll request");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_names_the_instance_without_control_characters() {
        let url = Url::parse("https://faro.example.org/").unwrap();
        let p = approval_prompt("Sam\u{7}'s Faro", &url);
        assert!(p.contains("\u{201c}Sam's Faro\u{201d} (faro.example.org)"), "{p}");
        assert!(p.contains("every account"));
        assert!(!p.chars().any(char::is_control));
    }

    #[test]
    fn errors_map_to_kinds() {
        let api = |status: u16, code: &str| {
            EnrollError::Client(ClientError::Api {
                status: StatusCode::from_u16(status).unwrap(),
                code: code.into(),
                message: String::new(),
            })
        };
        assert_eq!(failure_kind(&api(401, "invalid_enroll_code")), FailureKind::WrongCode);
        assert_eq!(failure_kind(&api(503, "x")), FailureKind::Unreachable);
        assert_eq!(failure_kind(&api(404, "not_found")), FailureKind::NotFaro);
        assert_eq!(failure_kind(&api(409, "member_keys_required")), FailureKind::Failed);
        assert_eq!(failure_kind(&EnrollError::Declined), FailureKind::InstanceChanged);
        assert_eq!(
            failure_kind(&EnrollError::InvalidInstance("x".into())),
            FailureKind::NotFaro
        );
        assert_eq!(
            failure_kind(&EnrollError::MemberKeyMismatch {
                expected: "a".into(),
                got: "b".into()
            }),
            FailureKind::MemberKeyMismatch
        );
    }
}
