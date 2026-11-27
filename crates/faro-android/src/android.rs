//! [`FaroAndroid`]: enrollment, approval, and faro-service's runtime
//! embedded in the app process.

use crate::error::{enroll_err, service_err, state_err};
use crate::platform::{map_tamper, mono_clock, MonoClock, Shared, ACCESSIBILITY};
use crate::status::{android_status, Seen};
use crate::types::{
    AndroidPlatform, AndroidStatus, AndroidTamper, ApprovalState, EnrollPreview, EnrolledDevice,
    FaroAndroidError, SessionEvent,
};
use faro_core::clock::{Clock, SystemClock};
use faro_core::Outbox;
use faro_detect::Classifier;
use faro_ipc::MemberStatus;
use faro_proto::api::Platform;
use faro_proto::SignPublicKey;
use faro_service::client::{ClientOptions, InstanceClient};
use faro_service::enroll::{self, EndorsementPoll, EnrollError, EnrollParams, InstanceInfo};
use faro_service::link::{parse_enroll_link, parse_instance_url, EnrollCode, EnrollLink};
use faro_service::state::{self, StateDir, ENDORSEMENT_FILE};
use faro_service::{
    Config, InProcessFrameSource, Phase, Service, ServiceError, ServiceHandle, ServiceSignals,
    ServiceStatus,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The oldest instance that knows the `android` platform. `faro-server`
/// learned it in the first release that has this crate, `0.1.0-beta.1`
/// (pre-releases sort below it, so `0.1.0-alpha.*` and anything older is
/// refused). Instances report their version in `/.well-known/faro`
/// (`server_version`); one that isn't a semantic version is refused too.
/// **Raise this** if Android ships in a later release than the server
/// change that added the platform.
pub const MIN_SERVER_VERSION: &str = "0.1.0-beta.1";

/// Where the packaged image model's manifest is, under the state directory
/// (`<data_dir>/faro`): `models/opennsfw/manifest.json`, next to the
/// `opennsfw-int8.onnx` it names. The app copies both there from its assets
/// before it creates [`FaroAndroid`] (`ModelAssets` in the Kotlin app).
pub const MODEL_MANIFEST: &str = "models/opennsfw/manifest.json";

/// The session the in-process source reports (the status menu's view is
/// scoped to it).
const SESSION: &str = "android";
/// How often the platform's state (foreground, session, permission,
/// tamper) is polled.
const POLL_EVERY: Duration = Duration::from_secs(2);
/// [`FaroAndroid::start`] waits this long for the service to come up when
/// an earlier one is still stopping, before returning and finishing the
/// start in the background.
const START_WAIT: Duration = Duration::from_millis(500);
/// [`FaroAndroid::report_tamper_now`]'s budget.
const TAMPER_BUDGET: Duration = Duration::from_secs(5);
/// Of which waiting for the event to be recorded.
const TAMPER_RECORD_WAIT: Duration = Duration::from_millis(1500);

/// Whether an instance that reports `server_version` knows Android.
pub fn server_supports_android(server_version: &str) -> bool {
    let min = semver::Version::parse(MIN_SERVER_VERSION).expect("valid constant");
    semver::Version::parse(server_version.trim()).is_ok_and(|v| v >= min)
}

fn check_instance(info: &InstanceInfo) -> Result<(), FaroAndroidError> {
    if server_supports_android(&info.well_known.server_version) {
        Ok(())
    } else {
        Err(FaroAndroidError::Instance(format!(
            "{} runs Faro {}, which is too old for Android phones (it needs {MIN_SERVER_VERSION} \
             or later). Ask whoever runs it to update.",
            info.name,
            info.well_known
                .server_version
                .chars()
                .take(40)
                .collect::<String>()
        )))
    }
}

/// Builds a fresh classifier for each start (tests).
pub type ClassifierFactory = Arc<dyn Fn() -> Box<dyn Classifier> + Send + Sync>;
/// Adjusts the service configuration (tests).
pub type Configure = Arc<dyn Fn(&mut Config) + Send + Sync>;

/// How [`FaroAndroid`] is set up. Kotlin always gets the defaults
/// ([`FaroAndroid::new`]); tests change them ([`FaroAndroid::with_options`]).
#[derive(Clone)]
pub struct AndroidOptions {
    pub client: ClientOptions,
    /// How often the platform is polled.
    pub poll_every: Duration,
    /// The service's tick.
    pub tick: Duration,
    /// Instead of the packaged model.
    pub classifier: Option<ClassifierFactory>,
    /// The app was built with the image model in its assets. Then the model
    /// at [`MODEL_MANIFEST`] must be there and work: missing, changed or
    /// unloadable is an urgent `integrity_failure`, and a build without
    /// ONNX Runtime counts as unloadable. Not set (a development build with
    /// no model), the core rates from context signals and raises nothing.
    pub model_packaged: bool,
    pub configure: Option<Configure>,
    /// For the secure-window debounce.
    pub mono: MonoClock,
    pub clock: Arc<dyn Clock>,
}

impl Default for AndroidOptions {
    fn default() -> Self {
        AndroidOptions {
            client: ClientOptions {
                product: "faro-android",
                ..ClientOptions::default()
            },
            poll_every: POLL_EVERY,
            tick: Duration::from_secs(1),
            classifier: None,
            model_packaged: false,
            configure: None,
            mono: mono_clock(),
            clock: Arc::new(SystemClock::new()),
        }
    }
}

/// What the member confirmed in [`FaroAndroid::preview_enrollment`].
struct Pin {
    instance: url::Url,
    identity: SignPublicKey,
}

#[derive(Default)]
struct Run {
    /// The member wants it running (the last call was `start`).
    want: bool,
    /// A start waits for an earlier runtime to finish stopping.
    starting: bool,
    handle: Option<ServiceHandle>,
    signals: Option<ServiceSignals>,
    started_ms: i64,
    /// The shutdown of the previous runtime.
    stopping: Option<tokio::task::JoinHandle<()>>,
    /// Why the last start failed.
    error: Option<String>,
}

struct Inner {
    dir: StateDir,
    shared: Arc<Shared>,
    opts: AndroidOptions,
    rt: Option<tokio::runtime::Runtime>,
    preview: Mutex<Option<Pin>>,
    /// Endorsed and bootstrapped: the runtime can run.
    approved: AtomicBool,
    /// The member removed the device (or the account was deleted).
    retired: Arc<AtomicBool>,
    run: Mutex<Run>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Droppable anywhere, an async context included.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The service's runtime ended by itself (its status channel closed).
fn ended(h: &ServiceHandle) -> bool {
    h.subscribe().has_changed().is_err()
}

/// Faro on the phone: one per process, owned by the foreground service.
///
/// Enrollment calls (`preview_enrollment`, `enroll`, `poll_approval`) talk
/// to the instance and block the calling thread for up to the request
/// timeout: call them off the main thread. `start`, `stop`, `status` and
/// `session_changed` return at once and are safe from any thread.
/// `report_tamper_now` blocks for up to about five seconds.
#[derive(uniffi::Object)]
pub struct FaroAndroid {
    inner: Arc<Inner>,
}

#[uniffi::export]
impl FaroAndroid {
    /// Open Faro on `data_dir` (the app's no-backup files directory; the
    /// state lives in `<data_dir>/faro`, created 0700). `model_packaged` is
    /// whether the app carries the image model (its manifest is in the
    /// assets); the app has then copied it to `<data_dir>/faro/models/opennsfw`
    /// ([`MODEL_MANIFEST`]), and the core treats a model that isn't there,
    /// or doesn't match its manifest, as tamper.
    #[uniffi::constructor]
    pub fn new(
        data_dir: String,
        platform: Arc<dyn AndroidPlatform>,
        model_packaged: bool,
    ) -> Result<Arc<Self>, FaroAndroidError> {
        crate::logging::init();
        let opts = AndroidOptions {
            model_packaged,
            ..AndroidOptions::default()
        };
        Self::with_options(PathBuf::from(data_dir), platform, opts)
    }

    /// Parse a `faro://enroll?…` link (or an instance address and code,
    /// separated by white space), ask the instance who it is, and return
    /// what the member confirms. Refuses instances too old to know Android
    /// ([`MIN_SERVER_VERSION`]).
    pub fn preview_enrollment(&self, link: String) -> Result<EnrollPreview, FaroAndroidError> {
        let link = parse_link(&link)?;
        let i = &self.inner;
        let client =
            InstanceClient::new(link.instance.clone(), i.opts.clock.clone(), &i.opts.client)
                .map_err(|e| enroll_err(e.into()))?;
        let info = i.block_on(enroll::discover(&client))?.map_err(enroll_err)?;
        check_instance(&info)?;
        *lock(&i.preview) = Some(Pin {
            instance: info.url.clone(),
            identity: info.well_known.identity_pubkey,
        });
        Ok(EnrollPreview {
            instance_name: info.name,
            instance_url: info.url.to_string(),
            member_fingerprint: link.member_key,
        })
    }

    /// Enroll with the instance the member confirmed in
    /// [`Self::preview_enrollment`] (which must come first, for the same
    /// instance): it must still answer with the identity shown. Creates
    /// the device key, registers as `android`, pins the member key (the
    /// link's `m`, when it has one) and returns the device fingerprint the
    /// member compares in the web app. The device then waits for approval.
    pub fn enroll(
        &self,
        link: String,
        device_name: String,
    ) -> Result<EnrolledDevice, FaroAndroidError> {
        let link = parse_link(&link)?;
        let i = &self.inner;
        let identity = match &*lock(&i.preview) {
            Some(p) if p.instance == link.instance => p.identity,
            _ => {
                return Err(FaroAndroidError::Invalid(
                    "confirm the instance first (preview the enrollment link)".into(),
                ))
            }
        };
        let device_name = enroll::device_name(Some(&device_name)).map_err(enroll_err)?;
        let params = EnrollParams {
            instance: link.instance.clone(),
            code: link.code,
            device_name,
            client: i.opts.client.clone(),
            member_key: link.member_key,
        };
        let mut too_old = None;
        let dir = i.dir.clone();
        let clock = i.opts.clock.clone();
        let result = i.block_on(async {
            enroll::enroll_as(&dir, clock, &params, Platform::Android, |info| {
                if let Err(e) = check_instance(info) {
                    too_old = Some(e);
                    return false;
                }
                info.well_known.identity_pubkey == identity
            })
            .await
        })?;
        let enrollment = match result {
            Ok(e) => e,
            Err(EnrollError::Declined) => {
                return Err(too_old.unwrap_or_else(|| {
                    FaroAndroidError::Integrity(
                        "the instance answered with another identity than the one shown; \
                         enroll again from the start"
                            .into(),
                    )
                }))
            }
            Err(e) => return Err(enroll_err(e)),
        };
        *lock(&i.preview) = None;
        i.retired.store(false, Ordering::SeqCst);
        let key = state::load_device_key(&i.dir).map_err(state_err)?;
        Ok(EnrolledDevice {
            device_id: enrollment.device_id.to_string(),
            device_fingerprint: enroll::device_fingerprint(&key.public()),
        })
    }

    /// Ask the instance once whether the member has approved this device.
    /// On approval the endorsement is verified against the member key
    /// pinned at enrollment, and the recipients are bootstrapped no lower
    /// than the anchor the member signed into it. While the runtime runs it
    /// does this itself, and this only reads its state.
    pub fn poll_approval(&self) -> Result<ApprovalState, FaroAndroidError> {
        let i = &self.inner;
        let e = i.dir.enrollment().map_err(state_err)?;
        if i.retired.load(Ordering::SeqCst) {
            return Ok(ApprovalState::Refused);
        }
        if i.approved.load(Ordering::SeqCst) {
            return Ok(ApprovalState::Active);
        }
        if let Some(phase) = i.running_phase() {
            return Ok(if phase == Phase::Running {
                i.approved.store(true, Ordering::SeqCst);
                ApprovalState::Active
            } else {
                ApprovalState::Pending
            });
        }
        // Not running: activate here, holding the state directory so a
        // runtime can't start meanwhile.
        let _lock = match i.dir.try_lock() {
            Ok(l) => l,
            Err(faro_service::state::StateError::Busy { .. }) => return Ok(ApprovalState::Pending),
            Err(e) => return Err(state_err(e)),
        };
        let key = Arc::new(state::load_device_key(&i.dir).map_err(state_err)?);
        let client =
            enroll::device_client(&e, key.clone(), i.opts.clock.clone(), &i.opts.client, None)
                .map_err(enroll_err)?;
        let dir = i.dir.clone();
        let outcome = i.block_on(async {
            match enroll::poll_endorsement(&client, &e, &key.public()).await? {
                EndorsementPoll::Pending => Ok(false),
                EndorsementPoll::Endorsed(signed) => {
                    enroll::activate(&dir, &client, &e, &key, &signed).await?;
                    Ok(true)
                }
            }
        })?;
        match outcome {
            Ok(true) => {
                i.approved.store(true, Ordering::SeqCst);
                tracing::info!("the member approved this phone");
                Ok(ApprovalState::Active)
            }
            Ok(false) => Ok(ApprovalState::Pending),
            Err(e) if is_retired(&e) => {
                i.retired.store(true, Ordering::SeqCst);
                Ok(ApprovalState::Refused)
            }
            Err(e) => Err(enroll_err(e)),
        }
    }

    /// Start the embedded runtime on Faro's own threads. Idempotent.
    /// Requires an enrollment (before approval the runtime only heartbeats
    /// and waits for it). Returns at once; if an earlier runtime is still
    /// stopping, the start completes when it has.
    pub fn start(&self) -> Result<(), FaroAndroidError> {
        Inner::start(&self.inner)
    }

    /// Stop gracefully (a `shutdown` event, a final upload and the
    /// shutting-down heartbeat), in the background. Returns at once.
    /// Idempotent.
    pub fn stop(&self) {
        self.inner.stop();
    }

    /// The status screen's and the notification's state.
    pub fn status(&self) -> AndroidStatus {
        self.inner.status()
    }

    /// An urgent signal Kotlin learns by callback (device admin
    /// `onDisableRequested`). Records it and tries to upload it before
    /// returning, within about five seconds; if that fails it stays queued.
    /// A secure window goes through the same debounce as a refused capture.
    pub fn report_tamper_now(&self, signal: AndroidTamper) {
        self.inner.report_tamper_now(signal);
    }

    /// The screen locked or unlocked, or the display slept or woke. The
    /// runtime sees it at its next poll (within two seconds).
    pub fn session_changed(&self, change: SessionEvent) {
        self.inner.shared.session_changed(change);
    }
}

impl FaroAndroid {
    /// [`Self::new`] with other options (tests).
    pub fn with_options(
        data_dir: PathBuf,
        platform: Arc<dyn AndroidPlatform>,
        opts: AndroidOptions,
    ) -> Result<Arc<Self>, FaroAndroidError> {
        if !data_dir.is_absolute() {
            return Err(FaroAndroidError::Invalid(
                "the data directory must be an absolute path".into(),
            ));
        }
        let dir = StateDir::open(data_dir.join("faro")).map_err(state_err)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("faro-rt")
            .enable_all()
            .build()
            .map_err(|e| FaroAndroidError::Storage(format!("cannot start Faro's threads: {e}")))?;
        let approved = is_approved(&dir);
        Ok(Arc::new(FaroAndroid {
            inner: Arc::new(Inner {
                dir,
                shared: Shared::new(platform, opts.mono.clone()),
                opts,
                rt: Some(rt),
                preview: Mutex::default(),
                approved: AtomicBool::new(approved),
                retired: Arc::new(AtomicBool::new(false)),
                run: Mutex::default(),
            }),
        }))
    }

    /// The state directory (tests).
    pub fn state_dir(&self) -> &std::path::Path {
        self.inner.dir.path()
    }

    /// The running runtime's status (tests).
    pub fn service_status(&self) -> Option<ServiceStatus> {
        lock(&self.inner.run)
            .handle
            .as_ref()
            .map(ServiceHandle::status)
    }
}

/// Endorsed, and the outbox bootstrapped from the endorsement.
fn is_approved(dir: &StateDir) -> bool {
    let Ok(e) = dir.enrollment() else {
        return false;
    };
    if !dir.file(ENDORSEMENT_FILE).exists() {
        return false;
    }
    Outbox::open(dir.path(), &e.instance_id, &e.device_id)
        .and_then(|o| o.manifest_checkpoint())
        .is_ok_and(|c| c.is_some())
}

fn is_retired(e: &EnrollError) -> bool {
    match e {
        EnrollError::DeviceRemoved => true,
        EnrollError::Client(c) => c.retired().is_some(),
        _ => false,
    }
}

/// A `faro://enroll` link, or `<instance address> <code>`.
fn parse_link(s: &str) -> Result<EnrollLink, FaroAndroidError> {
    let s = s.trim();
    let invalid = |e: faro_service::link::LinkError| FaroAndroidError::Invalid(e.to_string());
    if s.starts_with("faro:") {
        return parse_enroll_link(s).map_err(invalid);
    }
    let mut parts = s.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some(url), Some(code), None) => Ok(EnrollLink {
            instance: parse_instance_url(url).map_err(invalid)?,
            code: EnrollCode::parse(code).map_err(invalid)?,
            member_key: None,
        }),
        _ => Err(FaroAndroidError::Invalid(
            "expected an enrollment link (faro://enroll?…), or the instance's address and the \
             code"
                .into(),
        )),
    }
}

impl Inner {
    fn rt(&self) -> &tokio::runtime::Runtime {
        self.rt.as_ref().expect("the runtime lives as long as Faro")
    }

    /// Run `f` on Faro's runtime and wait for it. Refuses (rather than
    /// panicking) when called from inside a Tokio runtime.
    fn block_on<F: std::future::Future>(&self, f: F) -> Result<F::Output, FaroAndroidError> {
        if tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::CurrentThread)
        {
            return Err(FaroAndroidError::Invalid(
                "this call blocks; make it from a background thread".into(),
            ));
        }
        Ok(tokio::task::block_in_place(|| self.rt().block_on(f)))
    }

    /// The running runtime's phase, if one runs.
    fn running_phase(&self) -> Option<Phase> {
        let mut run = lock(&self.run);
        self.reap(&mut run);
        run.handle.as_ref().map(|h| h.status().phase)
    }

    /// Forget a runtime that ended by itself, and learn why.
    fn reap(&self, run: &mut Run) {
        if !run.handle.as_ref().is_some_and(ended) {
            return;
        }
        let h = run.handle.take().expect("checked");
        run.signals = None;
        let retired = self.retired.clone();
        let prev = run.stopping.take();
        run.stopping = Some(self.rt().spawn(async move {
            if let Some(p) = prev {
                let _ = p.await;
            }
            match h.shutdown().await {
                Ok(()) => tracing::info!("the runtime stopped"),
                Err(ServiceError::DeviceRemoved) => {
                    tracing::warn!("the member removed this phone; the runtime stopped");
                    retired.store(true, Ordering::SeqCst);
                }
                Err(e) => tracing::error!(error = %e, "the runtime stopped"),
            }
        }));
    }

    fn start(this: &Arc<Inner>) -> Result<(), FaroAndroidError> {
        this.dir.enrollment().map_err(state_err)?;
        if this.retired.load(Ordering::SeqCst) {
            return Err(FaroAndroidError::State(
                "the member removed this phone; enroll it again".into(),
            ));
        }
        let mut run = lock(&this.run);
        run.want = true;
        this.reap(&mut run);
        if run.handle.is_some() || run.starting {
            return Ok(());
        }
        if let Some(prev) = run.stopping.take() {
            if !prev.is_finished() {
                run.starting = true;
                drop(run);
                let weak = Arc::downgrade(this);
                let (tx, rx) = std::sync::mpsc::channel();
                this.rt().spawn(async move {
                    let _ = prev.await;
                    if let Some(inner) = weak.upgrade() {
                        let _ = tx.send(inner.finish_start());
                    }
                });
                return match rx.recv_timeout(START_WAIT) {
                    Ok(r) => r,
                    Err(_) => Ok(()),
                };
            }
        }
        this.build_into(&mut run)
    }

    /// A start that waited for the previous runtime to stop.
    fn finish_start(&self) -> Result<(), FaroAndroidError> {
        let mut run = lock(&self.run);
        run.starting = false;
        if !run.want || run.handle.is_some() {
            return Ok(());
        }
        self.build_into(&mut run)
    }

    fn build_into(&self, run: &mut Run) -> Result<(), FaroAndroidError> {
        match self.build() {
            Ok((handle, signals)) => {
                run.handle = Some(handle);
                run.signals = Some(signals);
                run.started_ms = self.opts.clock.wall_ms();
                run.error = None;
                tracing::info!("the runtime started");
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot start the runtime");
                run.error = Some(e.to_string());
                Err(e)
            }
        }
    }

    fn build(&self) -> Result<(ServiceHandle, ServiceSignals), FaroAndroidError> {
        let mut cfg = Config {
            state_dir: self.dir.path().to_owned(),
            ..Config::default()
        };
        if let Some(c) = &self.opts.configure {
            c(&mut cfg);
        }
        let platform = self.shared.platform().clone();
        let source = InProcessFrameSource::new(self.shared.agent_platform(), self.opts.poll_every)
            .with_label(SESSION)
            .with_capture_permission(ACCESSIBILITY)
            .with_notice(move |title, body| platform.show_notice(format!("{title}\n\n{body}")));
        let mut b = Service::builder(cfg)
            .clock(self.opts.clock.clone())
            .boxed_frame_source(Box::new(source))
            .tick_interval(self.opts.tick);
        if let Some(c) = &self.opts.classifier {
            b = b.classifier(c());
        } else if self.opts.model_packaged {
            // `model_manifest` makes the model required: missing, changed
            // or unloadable raises `integrity_failure`.
            b = b.model_manifest(self.dir.path().join(MODEL_MANIFEST));
        }
        let service = b.build().map_err(service_err)?;
        let signals = service.signals();
        let _enter = self.rt().enter();
        Ok((service.spawn(), signals))
    }

    fn stop(&self) {
        let mut run = lock(&self.run);
        run.want = false;
        let Some(h) = run.handle.take() else {
            return;
        };
        run.signals = None;
        let prev = run.stopping.take();
        let retired = self.retired.clone();
        run.stopping = Some(self.rt().spawn(async move {
            if let Some(p) = prev {
                let _ = p.await;
            }
            match h.shutdown().await {
                Ok(()) => tracing::info!("the runtime stopped"),
                Err(ServiceError::DeviceRemoved) => retired.store(true, Ordering::SeqCst),
                Err(e) => tracing::error!(error = %e, "the runtime stopped with an error"),
            }
        }));
    }

    fn status(&self) -> AndroidStatus {
        let Ok(e) = self.dir.enrollment() else {
            return android_status(&Seen::NotEnrolled);
        };
        if self.retired.load(Ordering::SeqCst) {
            return android_status(&Seen::Removed);
        }
        let mut run = lock(&self.run);
        self.reap(&mut run);
        let approved = self.approved.load(Ordering::SeqCst);
        let seen = match &run.handle {
            Some(h) => {
                let s = h.status();
                if s.phase == Phase::Running {
                    self.approved.store(true, Ordering::SeqCst);
                }
                let report = s.report(run.started_ms, self.opts.clock.wall_ms());
                Seen::Running(MemberStatus::for_session(&report, SESSION))
            }
            None if approved => Seen::NotRunning {
                error: run.error.clone(),
            },
            None => Seen::AwaitingApproval {
                instance_name: e.instance_name.clone(),
            },
        };
        let mut st = android_status(&seen);
        // Approval is known even while the runtime still says it waits.
        st.active = st.active || (approved && st.problem.as_deref() != Some("removed"));
        st
    }

    fn report_tamper_now(self: &Arc<Self>, signal: AndroidTamper) {
        let sig = match &signal {
            AndroidTamper::SecureWindow { app } => {
                self.shared.observe_secure(app);
                return;
            }
            other => map_tamper(other).expect("mapped"),
        };
        if self.dir.enrollment().is_err() {
            tracing::warn!(signal = ?sig, "not enrolled; the signal has nowhere to go");
            return;
        }
        let deadline = Instant::now() + TAMPER_BUDGET;
        if lock(&self.run).handle.is_none() {
            if let Err(e) = Inner::start(self) {
                tracing::error!(error = %e, signal = ?sig, "cannot start the runtime to record a signal");
                return;
            }
        }
        let this = self.clone();
        let wait = async move {
            // The runtime may still be starting (after an earlier stop).
            let (signals, mut rx) = loop {
                {
                    let run = lock(&this.run);
                    if let (Some(s), Some(h)) = (&run.signals, &run.handle) {
                        break (s.clone(), h.subscribe());
                    }
                }
                if Instant::now() >= deadline {
                    tracing::warn!("the runtime didn't start in time; the signal is lost");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let before = rx.borrow().tamper_events;
            tracing::warn!(signal = ?sig, "urgent signal from the app");
            // Queued until the runtime runs, if it is still starting.
            signals.tamper(sig);
            let left = |cap: Option<Duration>| {
                let rest = deadline.saturating_duration_since(Instant::now());
                cap.map_or(rest, |c| c.min(rest))
            };
            let recorded = tokio::time::timeout(
                left(Some(TAMPER_RECORD_WAIT)),
                rx.wait_for(|s| s.tamper_events > before),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            if !recorded {
                // A duplicate within the dedupe window, or not running yet.
                tracing::info!("the signal isn't recorded yet");
            }
            if let Some(h) = &lock(&this.run).handle {
                h.upload_now();
            }
            let uploaded = tokio::time::timeout(
                left(None),
                rx.wait_for(|s| s.last_seq.is_some() && s.acked_through >= s.last_seq),
            )
            .await
            .is_ok_and(|r| r.is_ok());
            if uploaded {
                tracing::info!("the signal is uploaded");
            } else {
                tracing::warn!("the signal stays queued; it is uploaded later");
            }
        };
        if self.block_on(async {}).is_err() {
            // Inside a single-threaded runtime (not how Kotlin calls it):
            // don't block it.
            self.rt().spawn(wait);
            return;
        }
        let _ = self.block_on(wait);
    }
}
