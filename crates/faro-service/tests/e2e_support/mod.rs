//! Harness for the end-to-end tests in `tests/e2e.rs` (ARCHITECTURE.md §10,
//! "E2E": the real server plus a headless client in synthetic-capture mode).
//!
//! * **The instance** is the real `faro-server` application, built exactly as
//!   the server's own integration tests build it: `server/tests/common/mod.rs`
//!   is compiled in here unchanged (`#[path]`), so SQLite lives in a temp
//!   dir, mail goes to a `TestMailer` and the server's clock is a
//!   `ManualClock`. The same `AppState` is also served over TCP on
//!   127.0.0.1, so the service's real reqwest client, request signing and
//!   response caps are exercised end to end.
//! * **The browsers** (member and ally) are simulated with faro-crypto
//!   directly through that harness: keys, wrapped secrets, endorsements and
//!   recipient manifests are really generated and signed, and the in-process
//!   router serves their requests with real session cookies.
//! * **The device** is `faro_service::Service` with a synthetic
//!   [`Script`] as its frame source, enrolled through `faro_service::enroll`
//!   against the TCP listener, and driven through `ServiceHandle`.
//!
//! **Why a front door ([`Gate`]).** The device pins the instance URL at
//! enrollment, so stopping and restarting the server must not change its
//! address. The gate is a tiny TCP forwarder with a fixed port in front of
//! whichever server task is currently running; it can also drop every
//! connection while the server stays up (a member blocking Faro at the
//! firewall), which is how the liveness test silences a running device.
//!
//! **Why the server's background workers are not started.** The notifier
//! must be a single sender (it does not claim rows with locks), and the
//! liveness worker would treat a jump of the `ManualClock` as a host
//! suspend. Tests therefore call `notify::dispatch`/`send_immediate` and
//! `liveness::run_once` themselves, exactly like the server's own tests,
//! instead of using `faro_server::server::run`.
//!
//! **Time.** The server's `ManualClock` stays at its start time unless a
//! test advances it. The device runs on its own `faro_core::ManualClock`,
//! advanced only by [`Device::drive_until`] in small steps while a test
//! waits for the scheduler to act. Two budgets keep the two clocks
//! compatible: the instance rejects requests more than 5 minutes from its
//! clock (the client corrects its stamps from the `Date` header only beyond
//! a 60 s offset, and `Date` is real time), and the device's `ClockGuard`
//! reports clock manipulation when its wall clock is more than 10 minutes
//! from the server time a heartbeat returns. [`MAX_DRIVE_MS`] keeps every
//! test well inside both.

use faro_core::ManualClock as DeviceClock;
use faro_crypto::{open_item, CryptoError, EncryptionKeypair, Zeroizing};
use faro_detect::{Classifier, ImageScores, ScriptedClassifier};
use faro_platform::synthetic::Script;
use faro_proto::api::FeedItem;
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::{DeviceEndorsement, ManifestRef};
use faro_proto::{body_aad, DeviceId, EncryptedItem, EventKind, SignPublicKey, Urgency, UserId};
use faro_server::api::feed::FeedResponse;
use faro_server::AppState;
use faro_service::client::ClientOptions;
use faro_service::enroll::{self, EnrollError, EnrollParams};
use faro_service::link::{parse_instance_url, EnrollCode};
use faro_service::state::{self, Enrollment, StateDir};
use faro_service::{
    Config, FrameSource, InProcessFrameSource, Phase, Service, ServiceHandle, ServiceStatus,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinHandle};

#[path = "../../../../server/tests/common/mod.rs"]
pub mod server;

pub use server::{Ally, MemberKeys, Resp, TestApp};

pub const ADMIN_EMAIL: &str = "admin@example.org";
pub const MEMBER_EMAIL: &str = "sam@example.org";
pub const ALLY_EMAIL: &str = "alex@example.org";
pub const DEVICE_NAME: &str = "Laptop";

/// Real-time limit for any single wait.
const REAL_TIMEOUT: Duration = Duration::from_secs(30);
/// Device time added per step by [`Device::drive_until`]. Small enough that
/// a capture being classified (debug build, on the blocking pool) is never
/// mistaken for a hung one (`CAPTURE_TIMEOUT_MS` is 60 s of device time).
const DRIVE_STEP_MS: u64 = 50;
/// Upper bound on device time one [`Device::drive_until`] may add (see the
/// module docs, "Time").
pub const MAX_DRIVE_MS: u64 = 120_000;

/// Opt-in logs: `FARO_TEST_LOG=1 cargo test -p faro-service --test e2e`.
pub fn init_logging() {
    if std::env::var_os("FARO_TEST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("faro_service=debug,faro_core=debug,faro_server=info")
            .with_test_writer()
            .try_init();
    }
}

/// The classifier that makes every capture an explicit-content hit, so the
/// fusion policy rates it `High`.
pub fn explicit_classifier() -> Box<dyn Classifier> {
    let scores = ImageScores::new([("explicit", 0.95f32)]).expect("valid scripted scores");
    Box::new(ScriptedClassifier::new(scores))
}

/// No image model: captures are rated from context only, which the
/// synthetic editor scene never triggers. Events then come only from what a
/// test injects (tamper signals), which keeps chains short and exact.
pub fn quiet_classifier() -> Box<dyn Classifier> {
    Box::new(faro_detect::NullClassifier::new())
}

// ----- the front door ---------------------------------------------------------

#[derive(Default)]
struct GateState {
    /// Where to forward new connections; `None` drops them on accept.
    target: Option<SocketAddr>,
    /// Live forwarding tasks, aborted (both sockets closed) on [`Gate::cut`].
    conns: Vec<AbortHandle>,
}

/// A TCP forwarder with a fixed address. See the module docs.
pub struct Gate {
    addr: SocketAddr,
    shared: Arc<Mutex<GateState>>,
    accept: JoinHandle<()>,
}

impl Gate {
    async fn start(target: SocketAddr) -> Gate {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gate");
        let addr = listener.local_addr().expect("gate address");
        let shared = Arc::new(Mutex::new(GateState {
            target: Some(target),
            conns: Vec::new(),
        }));
        let accept = tokio::spawn(accept_loop(listener, shared.clone()));
        Gate {
            addr,
            shared,
            accept,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The URL the device enrolls with (plain http is accepted for loopback).
    pub fn url(&self) -> url::Url {
        parse_instance_url(&format!("http://{}", self.addr)).expect("loopback instance URL")
    }

    /// Forward new connections to `target`.
    fn open(&self, target: SocketAddr) {
        self.lock().target = Some(target);
    }

    /// Refuse new connections and close every open one.
    pub fn cut(&self) {
        let mut g = self.lock();
        g.target = None;
        for c in g.conns.drain(..) {
            c.abort();
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.accept.abort();
        self.cut();
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Mutex<GateState>>) {
    loop {
        let mut inbound = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!(error = %e, "gate accept failed");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        // Decide and register under one lock, so a concurrent `cut` either
        // sees this connection (and aborts it) or this connection sees the
        // cut (and is dropped).
        let mut g = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(target) = g.target else {
            drop(inbound);
            continue;
        };
        let task = tokio::spawn(async move {
            if let Ok(mut outbound) = TcpStream::connect(target).await {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            }
        });
        g.conns.retain(|c| !c.is_finished());
        g.conns.push(task.abort_handle());
    }
}

/// One run of the HTTP listener over the shared `AppState`.
struct Backend {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

impl Backend {
    async fn serve(state: AppState) -> Backend {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
        let addr = listener.local_addr().expect("server address");
        let app = faro_server::router::build(state);
        let (stop, stopped) = oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .expect("server listener failed");
        });
        Backend { addr, stop, join }
    }

    async fn stop(self) {
        let _ = self.stop.send(());
        tokio::time::timeout(Duration::from_secs(10), self.join)
            .await
            .expect("server stops within 10 s")
            .expect("server task");
    }
}

// ----- the world: instance, member, ally ---------------------------------------

/// The instance with an admin, a member with keys and an approved ally:
/// manifest v1 (member only) then v2 (member + ally), as in onboarding (§7).
pub struct World {
    pub t: TestApp,
    pub gate: Gate,
    backend: Option<Backend>,
    /// The server clock when the instance started: the liveness monitor's
    /// `run_started`.
    pub started_ms: i64,
    pub member: UserId,
    pub member_session: String,
    pub member_keys: MemberKeys,
    pub ally: Ally,
}

impl World {
    pub async fn new() -> World {
        init_logging();
        let t = TestApp::new().await;
        let started_ms = t.clock_ms();
        let backend = Backend::serve(t.state.clone()).await;
        let gate = Gate::start(backend.addr).await;

        // First run: the admin completes setup with the one-time token.
        let (_admin, _admin_session) = t.setup_admin(ADMIN_EMAIL).await;
        // The member signs in with a magic link (open registration for
        // example.org), creates their keys and the first manifest.
        let (member, member_session) = t.sign_in(MEMBER_EMAIL).await;
        let member_keys = t.create_member_keys(&member, &member_session).await;
        let v1 = t
            .latest_manifest(&member, &member_session)
            .await
            .expect("manifest v1 stored");
        assert_eq!(v1.body.version, 1);
        assert!(v1.body.allies.is_empty(), "v1 lists only the member");
        // Invite → the ally signs in and accepts with their key → the member
        // endorses that key and signs manifest v2 with it.
        let ally = t
            .link_ally(&member, &member_keys, &member_session, ALLY_EMAIL)
            .await;
        let v2 = t
            .latest_manifest(&member, &member_session)
            .await
            .expect("manifest v2 stored");
        assert_eq!(v2.body.version, 2);
        assert_eq!(v2.body.allies.len(), 1);
        assert_eq!(v2.body.allies[0].ally_id, ally.id);
        assert_eq!(v2.body.allies[0].enc_pubkey, ally.keys.enc.public());

        World {
            t,
            gate,
            backend: Some(backend),
            started_ms,
            member,
            member_session,
            member_keys,
            ally,
        }
    }

    pub fn state(&self) -> &AppState {
        &self.t.state
    }

    /// The manifest the instance currently serves to the member.
    pub async fn manifest(&self) -> SignedRecipientManifest {
        self.t
            .latest_manifest(&self.member, &self.member_session)
            .await
            .expect("member has a manifest")
    }

    /// The member removes the ally, signing the next manifest without them.
    pub async fn remove_ally(&self) -> SignedRecipientManifest {
        let before = self.manifest().await.body.version;
        let r = self
            .t
            .remove_ally(
                &self.member,
                &self.member_keys,
                &self.member_session,
                &self.ally.id,
            )
            .await;
        assert_eq!(r.status, axum::http::StatusCode::NO_CONTENT, "{:?}", r.body);
        let m = self.manifest().await;
        assert_eq!(m.body.version, before + 1);
        assert!(m.body.allies.iter().all(|a| a.ally_id != self.ally.id));
        m
    }

    /// The member key fingerprint the member's browser puts into the
    /// enrollment link (`m`).
    pub fn member_key_id(&self) -> String {
        enroll::member_fingerprint(&self.member_keys.sign.public())
    }

    /// The member creates an enroll code and the device enrolls with it,
    /// pinning the member key from the link. The device is pending; nothing
    /// runs yet.
    pub async fn enroll_device(&self) -> Device {
        self.try_enroll(Some(self.member_key_id()))
            .await
            .expect("enrollment")
    }

    /// Enroll with `member_key` as the link's `m` parameter.
    pub async fn try_enroll(&self, member_key: Option<String>) -> Result<Device, EnrollError> {
        let code = self.t.enroll_code(&self.member_session).await;
        let tmp = tempfile::tempdir().expect("device tempdir");
        let state_dir = tmp.path().join("state");
        let dir = StateDir::open(&state_dir).expect("state dir");
        let clock = DeviceClock::new(self.t.clock_ms(), 10_000_000);
        let params = EnrollParams {
            instance: self.gate.url(),
            code: EnrollCode::parse(&code).expect("server codes parse"),
            device_name: DEVICE_NAME.into(),
            client: ClientOptions::default(),
            member_key,
        };
        let mut shown = None;
        let enrollment = enroll::enroll(&dir, Arc::new(clock.clone()), &params, |info| {
            shown = Some(info.well_known.instance_id.clone());
            true
        })
        .await?;
        assert_eq!(shown.as_ref(), Some(&self.t.instance_id()));
        // Pinned at enrollment: the member's signing key and the instance.
        assert_eq!(enrollment.member_id, self.member);
        assert_eq!(
            enrollment.member_sign_pubkey,
            self.member_keys.sign.public()
        );
        assert_eq!(enrollment.instance_id, self.t.instance_id());
        assert_eq!(
            enrollment.instance_identity_pubkey,
            self.t.state.identity().public()
        );
        Ok(Device {
            state_dir,
            dir,
            enrollment,
            clock,
            script: Script::new(),
            utc_offset_minutes: 0,
            handle: None,
            _tmp: tmp,
        })
    }

    /// The member's browser endorses the pending device: it lists the
    /// member's devices, checks the key fingerprint against the one the
    /// device shows, and signs a `DeviceEndorsement` anchored to the
    /// manifest current right now. Returns that anchor.
    pub async fn endorse(&self, dev: &Device) -> ManifestRef {
        let r = self
            .t
            .get("/v1/me/devices", Some(&self.member_session))
            .await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        let listed = r
            .body
            .as_array()
            .expect("device list")
            .iter()
            .find(|d| d["device_id"] == dev.enrollment.device_id.as_str())
            .expect("the enrolled device is listed")
            .clone();
        assert_eq!(listed["status"], "pending_endorsement");
        assert_eq!(listed["name"], DEVICE_NAME);
        // What the member compares: the instance's key id for the pending
        // device and the fingerprint the device itself displays.
        assert_eq!(listed["key_id"], dev.fingerprint().as_str());
        let device_key: SignPublicKey =
            serde_json::from_value(listed["sign_pubkey"].clone()).expect("sign_pubkey");
        let min_manifest = self.manifest().await.body.reference();
        let e = self.member_keys.sign.endorse(DeviceEndorsement {
            instance_id: self.t.instance_id(),
            member_id: self.member.clone(),
            device_id: dev.enrollment.device_id.clone(),
            device_sign_pubkey: device_key,
            endorsed_at_ms: self.t.clock_ms(),
            min_manifest,
        });
        let r = self
            .t
            .post(
                &format!("/v1/devices/{}/endorse", dev.enrollment.device_id),
                serde_json::to_value(e).expect("endorsement json"),
                Some(&self.member_session),
            )
            .await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        min_manifest
    }

    /// Enroll, start the service (it waits for the endorsement), endorse,
    /// and wait until it runs and has sealed its `boot` event to the current
    /// manifest.
    pub async fn active_device(&self, classifier: Box<dyn Classifier>) -> Device {
        let mut dev = self.enroll_device().await;
        dev.start(classifier);
        dev.wait("awaiting endorsement", |s| {
            s.phase == Phase::AwaitingEndorsement
        })
        .await;
        let anchor = self.endorse(&dev).await;
        // The manifest shows once the recipients are loaded to seal `boot`;
        // `last_seq` once that event is committed.
        let st = dev
            .wait("running with boot sealed", |s| {
                s.phase == Phase::Running && s.manifest.is_some() && s.last_seq.is_some()
            })
            .await;
        assert_eq!(st.manifest, Some(anchor), "bootstrapped at the anchor");
        dev
    }

    /// Stop the HTTP listener (the device sees the instance as down). The
    /// database and blobs stay, as on a real restart.
    pub async fn stop_server(&mut self) {
        self.gate.cut();
        if let Some(b) = self.backend.take() {
            b.stop().await;
        }
    }

    /// Start a new HTTP listener over the same state and open the gate.
    pub async fn start_server(&mut self) {
        assert!(self.backend.is_none(), "server already running");
        let b = Backend::serve(self.t.state.clone()).await;
        self.gate.open(b.addr);
        self.backend = Some(b);
    }

    /// Feed events visible to `session` (effective urgency ≥ normal).
    pub async fn feed_events(&self, session: &str) -> Vec<FeedEvent> {
        let r = self.t.feed(&self.member, session).await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        let page: FeedResponse = serde_json::from_value(r.body).expect("feed page");
        assert!(!page.has_more, "tests stay within one feed page");
        page.items
            .into_iter()
            .filter_map(|e| match e.item {
                FeedItem::Event {
                    device_id,
                    seq,
                    kind,
                    urgency,
                    blob_id,
                    ..
                } => Some(FeedEvent {
                    device_id,
                    seq,
                    kind,
                    urgency,
                    blob_id,
                }),
                _ => None,
            })
            .collect()
    }

    /// The feed entry for event `seq` of `dev`, as `session` sees it.
    pub async fn feed_event(&self, session: &str, dev: &Device, seq: u64) -> FeedEvent {
        self.feed_events(session)
            .await
            .into_iter()
            .find(|e| e.device_id == dev.enrollment.device_id && e.seq == seq)
            .unwrap_or_else(|| panic!("event {seq} is not in the feed"))
    }

    /// `GET /v1/blobs/{id}` as `session`.
    pub async fn blob(&self, session: &str, id: &str) -> Resp {
        self.t.get(&format!("/v1/blobs/{id}"), Some(session)).await
    }

    /// The ciphertext of event `seq`, fetched as `session` (must succeed).
    pub async fn event_item(&self, session: &str, dev: &Device, seq: u64) -> EncryptedItem {
        let ev = self.feed_event(session, dev, seq).await;
        let blob = ev.blob_id.expect("event has a body");
        let r = self.blob(session, &blob).await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        serde_json::from_slice(&r.raw).expect("blob is an EncryptedItem")
    }

    /// Every `seq` the instance stored for `dev`, ascending.
    pub async fn stored_seqs(&self, dev: &Device) -> Vec<i64> {
        use sqlx::Row;
        sqlx::query("SELECT seq FROM events WHERE device_id = $1 ORDER BY seq")
            .bind(dev.enrollment.device_id.as_str())
            .fetch_all(self.t.state.db().pool())
            .await
            .expect("query events")
            .iter()
            .map(|r| r.try_get::<i64, _>("seq").expect("seq column"))
            .collect()
    }

    /// Alerts raised for the member: `(kind, urgency, detail)`.
    pub async fn alerts(&self) -> Vec<(String, String, Option<String>)> {
        self.t
            .alerts(&self.member)
            .await
            .into_iter()
            .map(|a| (a.kind, a.urgency, a.detail))
            .collect()
    }
}

/// One event row of the feed.
#[derive(Debug, Clone)]
pub struct FeedEvent {
    pub device_id: DeviceId,
    pub seq: u64,
    pub kind: EventKind,
    /// The instance's *effective* urgency (PROTOCOL.md §3.3).
    pub urgency: Urgency,
    pub blob_id: Option<String>,
}

/// Decrypt an event body as `me`, the way the ally web app does: the AAD
/// binds the ciphertext to this instance, device and `seq`.
pub fn open_event(
    item: &EncryptedItem,
    dev: &Device,
    seq: u64,
    me: &UserId,
    key: &EncryptionKeypair,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let aad = body_aad(&dev.enrollment.instance_id, &dev.enrollment.device_id, seq);
    open_item(item, &aad, me, key)
}

/// The recipients an item was wrapped to, sorted.
pub fn envelope_recipients(item: &EncryptedItem) -> Vec<UserId> {
    let mut v: Vec<UserId> = item.envelopes.iter().map(|e| e.recipient.clone()).collect();
    v.sort();
    v
}

// ----- the device ------------------------------------------------------------------

/// An enrolled device: its state dir, its clock and synthetic screen, and
/// (once started) the running service.
pub struct Device {
    pub state_dir: PathBuf,
    pub dir: StateDir,
    pub enrollment: Enrollment,
    pub clock: DeviceClock,
    pub script: Script,
    /// `report.utc_offset_minutes` for the next [`Device::start`].
    pub utc_offset_minutes: i32,
    handle: Option<ServiceHandle>,
    _tmp: tempfile::TempDir,
}

impl Device {
    /// The fingerprint the device displays for the member to compare.
    pub fn fingerprint(&self) -> String {
        let key = state::load_device_key(&self.dir).expect("device key");
        enroll::device_fingerprint(&key.public())
    }

    /// Build and spawn the service on this state dir (again, after
    /// [`Device::shutdown`], to model a restart).
    pub fn start(&mut self, classifier: Box<dyn Classifier>) {
        let source = Box::new(InProcessFrameSource::new(
            self.script.platform(),
            Duration::from_millis(10),
        ));
        self.start_with(classifier, source);
    }

    /// As [`Device::start`], with another frame source (for example the
    /// real IPC source with a real `faro-agent`).
    pub fn start_with(&mut self, classifier: Box<dyn Classifier>, source: Box<dyn FrameSource>) {
        assert!(self.handle.is_none(), "service already running");
        let mut cfg = Config {
            state_dir: self.state_dir.clone(),
            ..Config::default()
        };
        // Poll for the endorsement and retry uploads every second; heartbeats
        // and manifest refreshes keep their (validated) production minimums
        // and are poked explicitly by the tests.
        cfg.network.endorsement_poll_secs = 1;
        cfg.network.upload_interval_secs = 1;
        cfg.report.utc_offset_minutes = self.utc_offset_minutes;
        let service = Service::builder(cfg)
            .clock(Arc::new(self.clock.clone()))
            .boxed_frame_source(source)
            .classifier(classifier)
            .tick_interval(Duration::from_millis(10))
            .scheduler_seed(7)
            .build()
            .expect("service builds");
        self.handle = Some(service.spawn());
    }

    pub fn handle(&self) -> &ServiceHandle {
        self.handle.as_ref().expect("service is running")
    }

    pub fn status(&self) -> ServiceStatus {
        self.handle().status()
    }

    /// Graceful stop (shutdown event, partial report, final upload and a
    /// `shutting_down` heartbeat when the instance is reachable).
    pub async fn shutdown(&mut self) {
        let h = self.handle.take().expect("service is running");
        tokio::time::timeout(REAL_TIMEOUT, h.shutdown())
            .await
            .expect("service stops in time")
            .expect("service stopped cleanly");
    }

    /// Wait for `pred` without moving the device clock.
    pub async fn wait(
        &self,
        what: &str,
        mut pred: impl FnMut(&ServiceStatus) -> bool,
    ) -> ServiceStatus {
        let h = self.handle();
        let st = match tokio::time::timeout(REAL_TIMEOUT, h.wait_for(&mut pred)).await {
            Ok(s) => s,
            Err(_) => panic!("timed out waiting for {what}; status: {:?}", h.status()),
        };
        assert!(
            pred(&st),
            "service stopped while waiting for {what}: {st:?}"
        );
        st
    }

    /// Let device time pass in small steps until `pred` holds, so the
    /// capture scheduler acts (start-up capture after 1-3 s, then the
    /// regular or burst schedule). Bounded by [`MAX_DRIVE_MS`] of device
    /// time and [`REAL_TIMEOUT`] of real time.
    pub async fn drive_until(
        &self,
        what: &str,
        mut pred: impl FnMut(&ServiceStatus) -> bool,
    ) -> ServiceStatus {
        let mut rx = self.handle().subscribe();
        let deadline = tokio::time::Instant::now() + REAL_TIMEOUT;
        let mut driven = 0u64;
        loop {
            let st = rx.borrow_and_update().clone();
            if pred(&st) {
                return st;
            }
            assert_ne!(st.phase, Phase::Stopped, "service stopped before {what}");
            assert!(
                driven < MAX_DRIVE_MS,
                "no {what} after {driven} ms of device time; status: {st:?}"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out driving to {what}; status: {st:?}"
            );
            self.clock.advance(DRIVE_STEP_MS);
            driven += DRIVE_STEP_MS;
            let _ = tokio::time::timeout(Duration::from_millis(5), rx.changed()).await;
        }
    }

    /// Poke the uploader and wait until the instance acknowledged every
    /// committed event. Returns the last `seq`.
    pub async fn upload_all(&self) -> u64 {
        let last = self.status().last_seq.expect("something was committed");
        self.handle().upload_now();
        self.wait("everything acknowledged", |s| {
            s.acked_through.is_some_and(|a| a >= last)
        })
        .await;
        last
    }
}

// ----- the "no unblurred pixels" probe ------------------------------------------

/// Length of the pixel runs searched for: 8 RGBA pixels.
const PROBE_LEN: usize = 32;

/// Every pixel-aligned 32-byte run of the synthetic screen's raw frames.
/// A copy of the raw pixels anywhere (at any byte alignment) contains one of
/// these runs at some offset, so searching all offsets of a haystack for
/// the pixel-aligned runs finds it.
pub struct PixelProbe {
    runs: HashSet<[u8; PROBE_LEN]>,
    /// Cheap prefilter on the first two bytes of a run.
    first2: Vec<bool>,
    pub frame_bytes: usize,
}

impl PixelProbe {
    /// Render exactly what the device's capture renders for the current
    /// scene (the synthetic capture is deterministic). The frames are
    /// zeroized when dropped here, as everywhere else.
    pub fn capture(script: &Script) -> PixelProbe {
        let mut platform = script.platform();
        let frames = platform
            .capture
            .capture_all_displays()
            .expect("synthetic capture");
        let mut runs = HashSet::new();
        let mut first2 = vec![false; 1 << 16];
        let mut frame_bytes = 0;
        // A few bytes of raw pixels at an odd offset, to prove the probe
        // finds what it is meant to find (it would otherwise pass vacuously).
        let mut self_check = vec![0x7Bu8; 3];
        for f in &frames {
            let px = f.pixels();
            frame_bytes += px.len();
            for chunk_start in (0..px.len().saturating_sub(PROBE_LEN)).step_by(4) {
                let mut run = [0u8; PROBE_LEN];
                run.copy_from_slice(&px[chunk_start..chunk_start + PROBE_LEN]);
                first2[usize::from(run[0]) << 8 | usize::from(run[1])] = true;
                runs.insert(run);
            }
            if self_check.len() == 3 {
                let mid = px.len() / 2 + 1;
                self_check.extend_from_slice(&px[mid..mid + 3 * PROBE_LEN]);
            }
        }
        drop(frames);
        assert!(!runs.is_empty(), "the probe saw pixels");
        let probe = PixelProbe {
            runs,
            first2,
            frame_bytes,
        };
        assert!(probe.found_in(&self_check), "the probe detects raw pixels");
        self_check.fill(0);
        probe
    }

    /// Whether `hay` contains any raw-pixel run, at any offset.
    pub fn found_in(&self, hay: &[u8]) -> bool {
        hay.windows(PROBE_LEN).any(|w| {
            self.first2[usize::from(w[0]) << 8 | usize::from(w[1])]
                && <[u8; PROBE_LEN]>::try_from(w).is_ok_and(|a| self.runs.contains(&a))
        })
    }

    /// Assert that no file under `root` (databases, WAL files, blobs, JSON
    /// state) contains a raw-pixel run.
    pub fn assert_absent_under(&self, root: &Path) {
        let mut stack = vec![root.to_path_buf()];
        let mut scanned = 0usize;
        while let Some(p) = stack.pop() {
            let meta = std::fs::symlink_metadata(&p).expect("stat");
            if meta.is_dir() {
                for e in std::fs::read_dir(&p).expect("read_dir") {
                    stack.push(e.expect("dir entry").path());
                }
            } else if meta.is_file() {
                let bytes = std::fs::read(&p).expect("read file");
                assert!(
                    !self.found_in(&bytes),
                    "raw frame pixels persisted in {}",
                    p.display()
                );
                scanned += 1;
            }
        }
        assert!(scanned > 0, "nothing to scan under {}", root.display());
    }
}

/// Notification emails must say *that* something happened, never what
/// (§5.4): no event kind, rating, app, title or image data.
pub fn assert_content_free(m: &faro_server::mailer::Email, extra: &[&str]) {
    let all = format!("{}\n{}", m.subject, m.text).to_lowercase();
    let mut forbidden = vec![
        "flag",
        "explicit",
        "high",
        "tamper",
        "screen_recording",
        "permission",
        "editor",
        "untitled",
        "thumbnail",
        "png",
    ];
    forbidden.extend_from_slice(extra);
    for word in forbidden {
        assert!(
            !all.contains(&word.to_lowercase()),
            "notification email mentions {word:?}: {:?}",
            m.subject
        );
    }
}
