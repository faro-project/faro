//! `faro-service run`: the long-running service (ARCHITECTURE.md §3.1).
//!
//! ```text
//!             ┌──────────── FrameSource (agent over IPC / in-process) ───────────┐
//!             │ Frames, foreground, session, tamper            CaptureNow, ...   │
//!             ▼                                                     ▲            │
//!   ┌──────────────────── core actor ───────────────────────────────┴─┐          │
//!   │ scheduler · detector · clock guard · supervisor · report journal│          │
//!   │ EventWriter ──▶ Outbox (sealed to the current manifest only)    │          │
//!   └───────┬───────────────────────────────▲─────────────────────────┘          │
//!           │ poke                          │ server time                        │
//!   uploader (events, reports, prune)   heartbeat   manifest + identity refresh  │
//! ```
//!
//! Everything is constructible in-process ([`Service::builder`]) with an
//! injectable clock, frame source, classifier and instance URL, so the
//! whole runtime can be driven against a real in-process `faro-server` in
//! tests.
//!
//! Before the device is endorsed the service only heartbeats and polls for
//! the endorsement; it seals nothing until the outbox is bootstrapped from
//! the endorsement's manifest anchor (PROTOCOL.md §5.1).

mod core;
mod goodbye;
pub mod journal;
mod net;
pub mod spawn;
mod status;
pub mod supervisor;
mod updates;

pub use self::core::{capture_stall_ms, PauseRequest, AGENT_ABSENT_MS};
pub use goodbye::{say_goodbye, GoodbyeError, GoodbyeOptions, GoodbyeOutcome};
pub use spawn::AgentSpawn;
pub use status::{Phase, ServiceStatus};

use self::core::{Control, Core, CoreParts};
use crate::backoff::Backoff;
use crate::client::{ClientError, ClientOptions, InstanceClient};
use crate::config::Config;
use crate::enroll::{self, EndorsementPoll, EnrollError};
use crate::model::ModelRuntime;
use crate::source::{FrameSource, SourceCommand, SourceEvent, SourceIo};
use crate::state::{self, Enrollment, StateDir, StateError, ENDORSEMENT_FILE};
use crate::update::artifacts::{self, ArtifactConfig, Artifacts, Swaps};
use crate::update::fetch::{FetchError, UpdateFetcher};
use crate::update::install::{platform_installer, Installer};
use crate::update::{CheckError, ClientSpec, ClientUpdater};
use faro_core::clock::{Clock, SystemClock};
use faro_core::{
    EventWriter, MemberSettings, OutboxError, PrunePolicy, Scheduler, SchedulerConfig,
    SchedulerError,
};
use faro_crypto::SigningKey;
use faro_detect::{Classifier, DetectError, Detector, DetectorConfig, DomainCategorizer};
use faro_proto::api::DeviceState;
use faro_proto::body::TamperSignal;
use net::{
    periodic, Heartbeater, IdentityGate, ManifestRefresher, OutboxHandle, UploadStop, Uploader,
};
use rand::SeedableRng;
use status::StatusTx;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinSet;
use url::Url;

/// How often outbox retention runs.
const PRUNE_EVERY: Duration = Duration::from_secs(3600);
/// Final upload attempt on shutdown.
const SHUTDOWN_FLUSH: Duration = Duration::from_secs(10);
/// Final heartbeat attempt on shutdown.
const SHUTDOWN_HEARTBEAT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Enroll(#[from] EnrollError),
    #[error("detector: {0}")]
    Detect(#[from] DetectError),
    #[error("scheduler: {0}")]
    Scheduler(#[from] SchedulerError),
    #[error("no frame source is available on this platform; inject one with ServiceBuilder::frame_source")]
    NoFrameSource,
    #[error("cannot verify the session agent: {0}")]
    AgentVerification(String),
    #[error("the member removed this device on the instance")]
    DeviceRemoved,
    #[error("the service task failed: {0}")]
    Join(String),
    #[error("updates: {0}")]
    Update(#[from] Box<CheckError>),
    #[error("updates: {0}")]
    UpdateFetch(#[from] Box<FetchError>),
}

/// Test overrides for the update task ([`ServiceBuilder::updates`]).
#[derive(Debug, Clone, Default)]
pub struct UpdateOverrides {
    /// The root of trust instead of the packaged file.
    pub root: Option<Vec<u8>>,
    /// The installer instead of the platform one.
    pub installer: Option<Arc<dyn Installer>>,
    /// This computer, instead of [`ClientSpec::this_machine`].
    pub spec: Option<ClientSpec>,
    /// Delay before the first check.
    pub first_check: Option<Duration>,
    /// What runs models from the update channel, instead of this build's
    /// ([`crate::model::default_runtime`]).
    pub model_runtime: Option<Arc<dyn ModelRuntime>>,
    /// Where notices of installed models and blocklists go, instead of
    /// [`artifacts::default_notices_dir`].
    pub notices_dir: Option<PathBuf>,
}

/// The packaged root of trust, if this platform ships one and it exists.
fn packaged_update_root() -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    let path = Some(std::path::Path::new(
        faro_platform_macos::pkg_layout::UPDATE_ROOT,
    ));
    #[cfg(not(target_os = "macos"))]
    let path: Option<&std::path::Path> = None;
    let path = path?;
    match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(path = %path.display(), "no update root of trust; updates are off");
            None
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot read the update root of trust; updates are off");
            None
        }
    }
}

/// Builds a [`Service`]. See the module docs.
pub struct ServiceBuilder {
    config: Config,
    clock: Option<Arc<dyn Clock>>,
    source: Option<Box<dyn FrameSource>>,
    classifier: Option<Box<dyn Classifier>>,
    model_manifest: Option<PathBuf>,
    domains: Option<DomainCategorizer>,
    base_url: Option<Url>,
    seed: Option<u64>,
    tick: Duration,
    spawn_agent: Option<AgentSpawn>,
    updates: UpdateOverrides,
}

impl ServiceBuilder {
    pub fn new(config: Config) -> Self {
        ServiceBuilder {
            config,
            clock: None,
            source: None,
            classifier: None,
            model_manifest: None,
            domains: None,
            base_url: None,
            seed: None,
            tick: Duration::from_secs(1),
            spawn_agent: None,
            updates: UpdateOverrides::default(),
        }
    }

    /// Override `config.state_dir` (`--state-dir`).
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config.state_dir = dir.into();
        self
    }

    /// Default: [`SystemClock`].
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Default: the agent over IPC at `config.ipc.socket_path` (Unix).
    pub fn frame_source(mut self, source: impl FrameSource) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn boxed_frame_source(mut self, source: Box<dyn FrameSource>) -> Self {
        self.source = Some(source);
        self
    }

    /// Use this classifier instead of loading a model (tests).
    pub fn classifier(mut self, classifier: Box<dyn Classifier>) -> Self {
        self.classifier = Some(classifier);
        self
    }

    /// Load the image model from this manifest instead of the packaged one
    /// ([`crate::model::packaged_manifest`]). A model missing from here is
    /// reported like a missing packaged one.
    pub fn model_manifest(mut self, path: impl Into<PathBuf>) -> Self {
        self.model_manifest = Some(path.into());
        self
    }

    pub fn domains(mut self, domains: DomainCategorizer) -> Self {
        self.domains = Some(domains);
        self
    }

    /// Talk to this base URL instead of the enrolled `instance_url` (tests
    /// whose in-process server listens on an ephemeral port). The pinned
    /// identity is still enforced.
    pub fn instance_base_url(mut self, url: Url) -> Self {
        self.base_url = Some(url);
        self
    }

    /// Deterministic capture schedule (tests).
    pub fn scheduler_seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// How often the core re-evaluates the schedule and clocks (default
    /// 1 s). Tests driving a `ManualClock` use a short tick.
    pub fn tick_interval(mut self, tick: Duration) -> Self {
        self.tick = tick.max(Duration::from_millis(1));
        self
    }

    /// Override parts of the update task (tests).
    pub fn updates(mut self, o: UpdateOverrides) -> Self {
        self.updates = o;
        self
    }

    /// Development: launch and relaunch the agent binary.
    pub fn spawn_agent(mut self, spec: AgentSpawn) -> Self {
        self.spawn_agent = Some(spec);
        self
    }

    pub fn build(self) -> Result<Service, ServiceError> {
        self.config.validate()?;
        let dir = StateDir::open(&self.config.state_dir)?;
        // Before reading the chain head: nothing else may append to it.
        let lock = dir.try_lock()?;
        let enrollment = Arc::new(dir.enrollment()?);
        let key = state::load_device_key(&dir)?;
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock::new()));
        let opts = ClientOptions {
            timeout: self.config.network.request_timeout(),
            ca_file: self.config.network.ca_file.clone(),
        };
        let key_for_net = Arc::new(SigningKey::from_bytes(&key.to_bytes()));
        let client = enroll::device_client(
            &enrollment,
            key_for_net.clone(),
            clock.clone(),
            &opts,
            self.base_url,
        )?;
        let updater = match self.updates.root.clone().or_else(packaged_update_root) {
            Some(root) => {
                let fetch = UpdateFetcher::new(client.base_url().clone(), &opts)
                    .map_err(|e| ServiceError::UpdateFetch(Box::new(e)))?;
                let installer = self
                    .updates
                    .installer
                    .clone()
                    .or_else(|| platform_installer(dir.path()));
                let spec = self
                    .updates
                    .spec
                    .clone()
                    .unwrap_or_else(ClientSpec::this_machine);
                Some(
                    ClientUpdater::new(dir.clone(), root, fetch, clock.clone(), spec, installer)
                        .map_err(|e| ServiceError::Update(Box::new(e)))?,
                )
            }
            None => None,
        };
        let update_first_check = self.updates.first_check;
        let outbox =
            faro_core::Outbox::open(dir.path(), &enrollment.instance_id, &enrollment.device_id)?;
        let head = outbox.head()?;
        let source = match self.source {
            Some(s) => s,
            None => default_source(&self.config)?,
        };
        let packaged_model = match self.classifier {
            Some(classifier) => crate::model::ModelLoad {
                classifier,
                tamper: None,
            },
            None => {
                let (path, required) = match self.model_manifest {
                    Some(p) => (Some(p), true),
                    None => (
                        crate::model::packaged_manifest(),
                        crate::model::model_required(),
                    ),
                };
                crate::model::load_classifier(path.as_deref(), required)
            }
        };
        let (packaged_domains, domains_tamper) = match self.domains {
            Some(categorizer) => (
                Some(artifacts::PackagedDomains {
                    categorizer,
                    version: None,
                }),
                None,
            ),
            None => match artifacts::packaged_domains_manifest() {
                Some(p) => artifacts::load_packaged_domains(&p),
                None => (None, None),
            },
        };
        let start = Artifacts::start(
            ArtifactConfig {
                dir: dir.clone(),
                notices: self
                    .updates
                    .notices_dir
                    .clone()
                    .unwrap_or_else(|| artifacts::default_notices_dir(dir.path())),
                runtime: self
                    .updates
                    .model_runtime
                    .clone()
                    .or_else(crate::model::default_runtime),
            },
            packaged_model,
            packaged_domains,
        );
        let mut model_tamper = start.tamper;
        model_tamper.extend(domains_tamper);
        let detector = Detector::new(&DetectorConfig::default(), start.classifier, start.domains)?;
        let artifacts = start.artifacts;
        let settings = state::settings_in_effect(&dir, self.config.member_settings.as_ref());
        let rng = match self.seed {
            Some(s) => rand::rngs::StdRng::seed_from_u64(s),
            None => rand::rngs::StdRng::from_entropy(),
        };
        let scheduler = Scheduler::new(
            SchedulerConfig {
                mean_secs: settings.capture_mean_secs(),
                ..SchedulerConfig::default()
            },
            rng,
        )?;
        let writer = EventWriter::new(
            key,
            enrollment.instance_id.clone(),
            enrollment.device_id.clone(),
            head,
            clock.clone(),
        );
        let (status, status_rx) = StatusTx::new();
        status.update(|s| {
            s.model = Some(start.model_label);
            s.blocklist = start.blocklist_label;
        });
        let (control_tx, control_rx) = mpsc::channel(64);
        Ok(Service {
            config: self.config,
            dir,
            enrollment,
            key: key_for_net,
            clock,
            client,
            outbox: OutboxHandle::new(outbox),
            source,
            detector,
            scheduler,
            settings,
            writer,
            tick: self.tick,
            spawn_agent: self.spawn_agent,
            status,
            status_rx,
            control_tx,
            control_rx,
            pokes: Pokes::default(),
            updater,
            update_first_check,
            model_tamper,
            artifacts,
            lock,
        })
    }
}

#[cfg(unix)]
fn default_source(config: &Config) -> Result<Box<dyn FrameSource>, ServiceError> {
    let ping = Duration::from_secs(config.capture.agent_ping_secs);
    let source = crate::source::ipc::IpcFrameSource::new(
        &config.ipc.socket_path,
        config.ipc.allowed_uids.iter().copied(),
    )
    .with_ping(ping, faro_ipc::DEFAULT_PING_TIMEOUT.min(ping))
    .with_code_requirement(config.ipc.agent_requirement.clone());
    // Refuse to start rather than run a service no agent can connect to
    // (or, worse, one any program can pose as the agent to).
    source
        .peer_policy()
        .map_err(ServiceError::AgentVerification)?;
    Ok(Box::new(source))
}

#[cfg(not(unix))]
fn default_source(_config: &Config) -> Result<Box<dyn FrameSource>, ServiceError> {
    // TODO(windows): faro-ipc has no named-pipe transport yet.
    Err(ServiceError::NoFrameSource)
}

#[derive(Clone, Default)]
struct Pokes {
    upload: Arc<Notify>,
    heartbeat: Arc<Notify>,
    manifest: Arc<Notify>,
}

/// A built, not yet running service.
pub struct Service {
    config: Config,
    dir: StateDir,
    enrollment: Arc<Enrollment>,
    key: Arc<SigningKey>,
    clock: Arc<dyn Clock>,
    client: InstanceClient,
    outbox: OutboxHandle,
    source: Box<dyn FrameSource>,
    detector: Detector,
    scheduler: Scheduler<rand::rngs::StdRng>,
    settings: MemberSettings,
    writer: EventWriter<Arc<dyn Clock>>,
    tick: Duration,
    spawn_agent: Option<AgentSpawn>,
    status: StatusTx,
    status_rx: watch::Receiver<ServiceStatus>,
    control_tx: mpsc::Sender<Control>,
    control_rx: mpsc::Receiver<Control>,
    pokes: Pokes,
    updater: Option<ClientUpdater>,
    update_first_check: Option<Duration>,
    /// The image model or domain list is missing, altered or unusable
    /// ([`crate::model::ModelLoad::tamper`], [`Artifacts::start`]);
    /// reported at start.
    model_tamper: Vec<TamperSignal>,
    /// Models and blocklists from the update channel.
    artifacts: Artifacts,
    /// Held until `run` returns ([`StateDir::try_lock`]).
    lock: state::StateLock,
}

impl Service {
    pub fn builder(config: Config) -> ServiceBuilder {
        ServiceBuilder::new(config)
    }

    pub fn enrollment(&self) -> &Enrollment {
        &self.enrollment
    }

    /// Run on the current task until `shutdown` completes, then stop
    /// gracefully (`shutdown` event, partial report, final upload and a
    /// `shutting_down` heartbeat).
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) -> Result<(), ServiceError> {
        let Service {
            config,
            dir,
            enrollment,
            key,
            clock,
            client,
            outbox,
            source,
            detector,
            scheduler,
            settings,
            writer,
            tick,
            spawn_agent,
            status,
            status_rx: _,
            control_tx,
            mut control_rx,
            pokes,
            updater,
            update_first_check,
            model_tamper,
            artifacts,
            lock: _lock,
        } = self;
        let swaps: Arc<Swaps> = artifacts.swaps();
        tokio::pin!(shutdown);
        let (stop_tx, stop_rx) = watch::channel(false);
        let gate = IdentityGate::new_open();
        let (hb_state_tx, hb_state_rx) = watch::channel(DeviceState::Active);
        let heartbeater = Arc::new(Heartbeater {
            client: client.clone(),
            outbox: outbox.clone(),
            clock: clock.clone(),
            key: key.clone(),
            enrollment: enrollment.clone(),
            status: status.clone(),
            gate: gate.clone(),
        });
        let uploader = Arc::new(Uploader {
            client: client.clone(),
            outbox: outbox.clone(),
            clock: clock.clone(),
            status: status.clone(),
            gate: gate.clone(),
            prune: PrunePolicy::default(),
        });
        let refresher = Arc::new(ManifestRefresher {
            client: client.clone(),
            outbox: outbox.clone(),
            enrollment: enrollment.clone(),
            status: status.clone(),
            gate: gate.clone(),
        });
        let mut tasks = JoinSet::new();

        // The pin is checked before anything is sent; a transient failure
        // here is fine (the refresh loop re-checks).
        if let Err(e) = refresher.check_identity().await {
            tracing::warn!(error = %e, "could not confirm the instance identity at start");
        }
        // Updates run from the start, before activation too: a computer
        // waiting for its member's endorsement still gets fixes.
        if let Some(updater) = updater {
            tasks.spawn(updates::update_loop(
                updater,
                artifacts,
                update_first_check.unwrap_or_else(updates::default_first_check),
                config.updates.check_interval(),
                control_tx.clone(),
                stop_rx.clone(),
            ));
        }
        tasks.spawn(heartbeat_loop(
            heartbeater.clone(),
            hb_state_rx,
            pokes.heartbeat.clone(),
            control_tx.clone(),
            config.network.heartbeat_interval(),
            stop_rx.clone(),
        ));

        // ---- activation --------------------------------------------------
        let bootstrapped = outbox.run(|o| o.manifest_checkpoint()).await?.is_some();
        if !bootstrapped {
            status.update(|s| s.phase = Phase::AwaitingEndorsement);
            let activation = activate_loop(
                &dir,
                &client,
                &enrollment,
                &key,
                &outbox,
                config.network.endorsement_poll_interval(),
            );
            tokio::select! {
                r = activation => r?,
                _ = &mut shutdown => {
                    tracing::info!("stopping before activation completed");
                    let _ = stop_tx.send(true);
                    let _ = tokio::time::timeout(
                        SHUTDOWN_HEARTBEAT,
                        heartbeater.send(DeviceState::ShuttingDown),
                    )
                    .await;
                    finish(tasks).await;
                    status.update(|s| s.phase = Phase::Stopped);
                    return Ok(());
                }
            }
        }
        status.update(|s| s.phase = Phase::Running);

        // ---- running -----------------------------------------------------
        let (src_cmd_tx, src_cmd_rx) = mpsc::channel::<SourceCommand>(8);
        let (src_ev_tx, src_ev_rx) = mpsc::channel::<SourceEvent>(64);
        tracing::info!(source = source.name(), "starting capture driver");
        let mut source_task = tokio::spawn(source.run(SourceIo {
            commands: src_cmd_rx,
            events: src_ev_tx,
        }));
        if let Some(spec) = spawn_agent {
            tasks.spawn(spawn::supervise(spec, stop_rx.clone()));
        }
        {
            let up = uploader.clone();
            tasks.spawn(periodic(
                config.network.upload_interval(),
                pokes.upload.clone(),
                stop_rx.clone(),
                move || {
                    let up = up.clone();
                    async move { upload_pass(&up).await }
                },
            ));
        }
        {
            let up = uploader.clone();
            tasks.spawn(periodic(
                PRUNE_EVERY,
                Arc::new(Notify::new()),
                stop_rx.clone(),
                move || {
                    let up = up.clone();
                    async move {
                        up.prune().await;
                        true
                    }
                },
            ));
        }
        {
            let r = refresher.clone();
            tasks.spawn(periodic(
                config.network.manifest_refresh_interval(),
                pokes.manifest.clone(),
                stop_rx.clone(),
                move || {
                    let r = r.clone();
                    async move {
                        let id = r.check_identity().await;
                        let m = r.refresh().await;
                        match (&id, &m) {
                            (Err(e), _) | (Ok(()), Err(e)) => {
                                tracing::info!(error = %e, "manifest refresh failed; will retry");
                                false
                            }
                            _ => true,
                        }
                    }
                },
            ));
        }

        let mut core = Core::new(CoreParts {
            clock: clock.clone(),
            enrollment: enrollment.clone(),
            state_dir: dir.clone(),
            writer,
            outbox: outbox.clone(),
            detector,
            scheduler,
            settings,
            utc_offset_minutes: config.report.utc_offset_minutes,
            supervisor: supervisor::Supervisor::new(
                config.capture.agent_kill_threshold,
                config.capture.agent_kill_window_secs,
            ),
            capture_failure_threshold: config.capture.capture_failure_threshold,
            source_tx: src_cmd_tx,
            hb_state: hb_state_tx,
            upload_poke: pokes.upload.clone(),
            status: status.clone(),
            swaps,
        });
        core.startup().await;
        for sig in model_tamper {
            core.signal(sig).await;
        }
        pokes.upload.notify_one();

        let mut ticker = tokio::time::interval(tick);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut src_ev_rx = Some(src_ev_rx);
        enum Step {
            Stop,
            Source(Option<SourceEvent>),
            Control(Option<Control>),
            Tick,
        }
        loop {
            let step = tokio::select! {
                _ = &mut shutdown => Step::Stop,
                ev = recv_opt(&mut src_ev_rx) => Step::Source(ev),
                c = control_rx.recv() => Step::Control(c),
                _ = ticker.tick() => Step::Tick,
            };
            match step {
                Step::Stop => break,
                Step::Source(Some(ev)) => core.on_source(ev).await,
                Step::Source(None) => {
                    tracing::error!("capture driver stopped unexpectedly");
                    src_ev_rx = None;
                    core.source_gone().await;
                }
                Step::Control(Some(c)) => core.on_control(c).await,
                // We hold a sender ourselves, so this can't happen.
                Step::Control(None) => {}
                Step::Tick => core.tick().await,
            }
        }

        // ---- graceful shutdown -------------------------------------------
        tracing::info!("shutting down");
        let _ = stop_tx.send(true);
        core.shutdown().await;
        if tokio::time::timeout(Duration::from_secs(3), &mut source_task)
            .await
            .is_err()
        {
            source_task.abort();
        }
        drop(core);
        match tokio::time::timeout(SHUTDOWN_FLUSH, uploader.drain()).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = ?e, "final upload incomplete; events stay queued"),
            Err(_) => tracing::warn!("final upload timed out; events stay queued"),
        }
        if let Ok(Err(e)) = tokio::time::timeout(
            SHUTDOWN_HEARTBEAT,
            heartbeater.send(DeviceState::ShuttingDown),
        )
        .await
        {
            tracing::warn!(error = ?e, "could not send the shutting-down heartbeat");
        }
        finish(tasks).await;
        status.update(|s| s.phase = Phase::Stopped);
        Ok(())
    }

    /// Spawn on the current Tokio runtime and return a control handle.
    pub fn spawn(self) -> ServiceHandle {
        let control = self.control_tx.clone();
        let status = self.status_rx.clone();
        let pokes = self.pokes.clone();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let join = tokio::spawn(self.run(async move {
            let _ = stop_rx.await;
        }));
        ServiceHandle {
            control,
            stop: Some(stop_tx),
            join,
            status,
            pokes,
        }
    }
}

async fn recv_opt(rx: &mut Option<mpsc::Receiver<SourceEvent>>) -> Option<SourceEvent> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

async fn finish(mut tasks: JoinSet<()>) {
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(Duration::from_secs(3), drain)
        .await
        .is_err()
    {
        tasks.abort_all();
    }
}

async fn upload_pass(up: &Uploader) -> bool {
    match up.drain().await {
        Ok(()) | Err(UploadStop::Gated) => true,
        Err(UploadStop::Client(e)) if e.is_pending_endorsement() => true,
        Err(UploadStop::Client(e)) => {
            tracing::info!(error = %e, "upload failed; events stay queued");
            false
        }
        Err(UploadStop::Outbox(e)) => {
            tracing::error!(error = %e, "outbox error during upload");
            false
        }
    }
}

async fn heartbeat_loop(
    hb: Arc<Heartbeater>,
    mut state_rx: watch::Receiver<DeviceState>,
    poke: Arc<Notify>,
    control: mpsc::Sender<Control>,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    let mut backoff = Backoff::new(Duration::from_secs(2), every);
    let mut wait = Duration::ZERO;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = poke.notified() => {}
            r = state_rx.changed() => if r.is_err() { return },
            _ = stop.wait_for(|s| *s) => return,
        }
        if *stop.borrow() {
            return;
        }
        let state = *state_rx.borrow_and_update();
        match hb.send(state).await {
            Ok(resp) => {
                backoff.reset();
                let _ = control.try_send(Control::ServerTime {
                    local_wall_ms: hb.clock.wall_ms(),
                    server_time_ms: resp.server_time_ms,
                });
                // Follow the instance's suggestion within sane bounds.
                let suggested = Duration::from_secs(resp.next_in_secs.clamp(60, 900));
                wait = suggested.min(every);
            }
            Err(UploadStop::Gated) => wait = every,
            Err(e) => {
                wait = backoff.next_delay().min(every);
                tracing::info!(error = ?e, retry_in = ?wait, "heartbeat failed");
            }
        }
    }
}

/// Wait for the member's endorsement, verify it, and bootstrap the outbox
/// from the endorsement's manifest anchor. Retries until it succeeds; a
/// forged endorsement or a manifest below the anchor is refused and waited
/// out, never accepted.
async fn activate_loop(
    dir: &StateDir,
    client: &InstanceClient,
    enrollment: &Enrollment,
    key: &SigningKey,
    outbox: &OutboxHandle,
    poll: Duration,
) -> Result<(), ServiceError> {
    tracing::info!(
        fingerprint = %enroll::device_fingerprint(&key.public()),
        "waiting for the member to endorse this device"
    );
    let mut backoff = Backoff::new(poll, Duration::from_secs(300));
    loop {
        let r = activate_once(dir, client, enrollment, key, outbox).await;
        let delay = match r {
            Ok(true) => return Ok(()),
            Ok(false) => {
                backoff.reset();
                poll
            }
            Err(EnrollError::DeviceRemoved) => return Err(ServiceError::DeviceRemoved),
            Err(EnrollError::Client(e)) if e.is_transient() => backoff.next_delay(),
            Err(e) => {
                tracing::warn!(error = %e, "activation refused; waiting for a valid endorsement and manifest");
                backoff.next_delay().max(poll)
            }
        };
        tokio::time::sleep(delay).await;
    }
}

/// `Ok(true)` once bootstrapped, `Ok(false)` while still pending.
async fn activate_once(
    dir: &StateDir,
    client: &InstanceClient,
    enrollment: &Enrollment,
    key: &SigningKey,
    outbox: &OutboxHandle,
) -> Result<bool, EnrollError> {
    let signed = match enroll::poll_endorsement(client, enrollment, &key.public()).await? {
        EndorsementPoll::Pending => return Ok(false),
        EndorsementPoll::Endorsed(s) => *s,
    };
    let endorsement = enroll::verify_endorsement(&signed, enrollment, &key.public())?;
    dir.write_json(ENDORSEMENT_FILE, &signed)?;
    let manifest = client.recipient_manifest(&enrollment.member_id).await?;
    let e = enrollment.clone();
    let set = outbox
        .run(move |o| {
            if o.manifest_checkpoint()?.is_some() {
                return o
                    .current_recipients(&e.member_sign_pubkey, &e.member_id)?
                    .ok_or(OutboxError::NotBootstrapped);
            }
            enroll::bootstrap_from_endorsement(o, &manifest, &e, &endorsement)
        })
        .await?;
    tracing::info!(
        version = set.manifest_ref().version,
        allies = set.allies().len(),
        "device endorsed; recipient manifest bootstrapped"
    );
    Ok(true)
}

/// Controls a service started with [`Service::spawn`].
pub struct ServiceHandle {
    control: mpsc::Sender<Control>,
    stop: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<Result<(), ServiceError>>,
    status: watch::Receiver<ServiceStatus>,
    pokes: Pokes,
}

impl ServiceHandle {
    /// The latest status.
    pub fn status(&self) -> ServiceStatus {
        self.status.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<ServiceStatus> {
        self.status.clone()
    }

    /// Wait until `pred` holds for the status (or the service stops).
    pub async fn wait_for(&self, mut pred: impl FnMut(&ServiceStatus) -> bool) -> ServiceStatus {
        let mut rx = self.status.clone();
        let found = rx
            .wait_for(|s| pred(s) || s.phase == Phase::Stopped)
            .await
            .map(|s| s.clone());
        found.unwrap_or_else(|_| self.status())
    }

    /// Upload queued events and reports now.
    pub fn upload_now(&self) {
        self.pokes.upload.notify_one();
    }

    /// Send a heartbeat now.
    pub fn heartbeat_now(&self) {
        self.pokes.heartbeat.notify_one();
    }

    /// Re-check the instance identity and fetch the recipient manifest now.
    pub fn refresh_manifest_now(&self) {
        self.pokes.manifest.notify_one();
    }

    /// Member pause (allies get a `paused` event).
    pub async fn pause(&self, req: PauseRequest) {
        let _ = self.control.send(Control::SetPause(Some(req))).await;
    }

    /// End a member pause (allies get a `resumed` event).
    pub async fn resume(&self) {
        let _ = self.control.send(Control::SetPause(None)).await;
    }

    /// Apply new member settings; allies get a `settings_change` event.
    /// Returns false if the change could not be recorded (and was not
    /// applied).
    pub async fn update_settings(&self, settings: MemberSettings) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .control
            .send(Control::UpdateSettings(settings, tx))
            .await
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    /// Seal the report for the period so far and queue it.
    pub async fn close_report(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        if self.control.send(Control::CloseReport(tx)).await.is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    /// Stop gracefully and wait for the service to finish.
    pub async fn shutdown(mut self) -> Result<(), ServiceError> {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.join
            .await
            .map_err(|e| ServiceError::Join(e.to_string()))?
    }
}
