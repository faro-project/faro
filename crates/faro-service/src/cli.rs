//! The `faro-service` command line.
//!
//! ```text
//! faro-service [--config FILE] [--state-dir DIR] [-v] enroll (--link faro://enroll?... | --instance URL --code XXXX-XXXX [--member-key ID]) [--name NAME] [--yes] [--no-wait]
//! faro-service [--config FILE] [--state-dir DIR] [-v] run [--socket PATH] [--spawn-agent BIN] [--capture ipc|in-process]
//! faro-service [--config FILE] [--state-dir DIR] status [--json]
//! faro-service [--config FILE] [--state-dir DIR] diagnose [--lines N] [--output DIR] [--yes | --print]
//! faro-service [--config FILE] [--state-dir DIR] goodbye [--reason uninstalled|account-deleted | --moved-to HOST] [--within SECS]
//! faro-service model-check [--manifest PATH] [--runs N]
//! faro-service domains-check [--manifest PATH]
//! faro-service run-service                          (Windows: the SCM entry point)
//! faro-service install-service | uninstall-service  (Windows: development conveniences)
//! faro-service approve-enroll --request <64 hex>    (Windows: the elevated approval helper)
//! ```
//!
//! On Windows the MSI registers the service itself with `run-service` as
//! its argument. `run-service` talks to the Service Control Manager; started
//! from a console instead it runs like `run`. Without `--state-dir` and
//! `--config` the Windows defaults are `C:\ProgramData\Faro`
//! (`faro_platform_windows::layout::DATA_DIR`) and its `service.toml`.
//!
//! `goodbye` exits 0 once allies have been told (or there was nobody to
//! tell, or they were told already because the instance retired this
//! device), 1 if nothing was written (the service may be restarted safely),
//! and [`EXIT_GOODBYE_QUEUED`] if the goodbye was written but not delivered.

use crate::client::{ClientOptions, Retired};
use crate::config::Config;
use crate::enroll::{self, EnrollParams, InstanceInfo};
use crate::link::{self, EnrollCode};
use crate::runtime::{
    say_goodbye, AgentSpawn, GoodbyeError, GoodbyeOptions, GoodbyeOutcome, Service, ServiceError,
};
use crate::state::{self, StateDir, StateError};
use clap::{Parser, Subcommand, ValueEnum};
use faro_core::clock::{Clock, SystemClock};
use faro_proto::body::GoodbyeReason;
use std::future::Future;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// `goodbye`'s exit status when the goodbye was written but the instance
/// did not acknowledge it: the uninstaller goes ahead and says so.
pub const EXIT_GOODBYE_QUEUED: u8 = 3;

/// How often an unenrolled `run` checks whether `enroll` has finished.
const ENROLLMENT_POLL: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(name = "faro-service", version, about = "The privileged Faro service")]
pub struct Cli {
    /// Config file (default: the platform's service.toml).
    #[arg(long, global = true, env = "FARO_SERVICE_CONFIG")]
    pub config: Option<PathBuf>,
    /// State directory override, for development and tests.
    #[arg(long, global = true, env = "FARO_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// More logging (-v debug, -vv trace). `RUST_LOG` overrides; without
    /// either, `log_level` in the config ([`crate::logging`]).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CaptureMode {
    /// The session agent over the local socket (production).
    Ipc,
    /// Capture inside this process (development on macOS only; the service
    /// must then run as the logged-in user).
    InProcess,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Enroll this device with an instance.
    Enroll {
        /// A faro://enroll?i=…&c=… link from the web app.
        #[arg(long, conflicts_with_all = ["instance", "code"])]
        link: Option<String>,
        /// Instance URL (default: `instance_url` from the config).
        #[arg(long)]
        instance: Option<String>,
        /// The one-time code shown in the web app (XXXX-XXXX).
        #[arg(long)]
        code: Option<String>,
        /// Your member key's fingerprint as the web app shows it (16 hex
        /// characters). The device refuses an instance that answers with a
        /// different member key. Links carry it as `m`.
        #[arg(long, conflicts_with = "link")]
        member_key: Option<String>,
        /// Device name shown to the member and allies (default: host name).
        #[arg(long)]
        name: Option<String>,
        /// Don't ask to confirm the instance name.
        #[arg(long)]
        yes: bool,
        /// Exit after enrolling instead of waiting for the endorsement
        /// (`run` finishes activation).
        #[arg(long)]
        no_wait: bool,
    },
    /// Run the service.
    Run {
        /// Agent socket path (overrides `ipc.socket_path`).
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Development: launch and relaunch this agent binary.
        #[arg(long)]
        spawn_agent: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "ipc")]
        capture: CaptureMode,
    },
    /// Show enrollment, the outbox, and what the running service is doing:
    /// agents, captures, permissions, the model and updates (no network
    /// access).
    Status {
        /// Print JSON (`status_view::StatusView`) instead.
        #[arg(long)]
        json: bool,
    },
    /// Make a problem report to send to whoever helps you with Faro: a zip
    /// on your Desktop with the status, versions, launchd jobs and the
    /// last lines of the logs, with web addresses, email addresses, host
    /// names and window titles taken out. Shows what is in it, and writes
    /// it only when you say so. Needs sudo.
    Diagnose {
        /// Lines from the end of each log.
        #[arg(long, default_value_t = crate::diagnose::DEFAULT_LINES, value_name = "N")]
        lines: usize,
        /// Folder to write the zip to (default: your Desktop).
        #[arg(long, value_name = "DIR")]
        output: Option<PathBuf>,
        /// Write it without asking (it still lists what is in it).
        #[arg(long)]
        yes: bool,
        /// Print everything the report would hold, and write nothing.
        #[arg(long, conflicts_with_all = ["yes", "output"])]
        print: bool,
    },
    /// Tell allies that monitoring ends on purpose (the uninstaller runs
    /// this after stopping the service). Writes an urgent `goodbye` event
    /// and uploads it.
    Goodbye {
        #[arg(
            long,
            value_enum,
            default_value = "uninstalled",
            conflicts_with = "moved_to"
        )]
        reason: GoodbyeKind,
        /// The device is moving to another instance (its host name is
        /// shown to allies of this one).
        #[arg(long, value_name = "HOST")]
        moved_to: Option<String>,
        /// Seconds to keep trying to deliver the goodbye once written.
        #[arg(long, default_value_t = 60, value_name = "SECS")]
        within: u64,
    },
    /// Windows: run as the Windows service (what the Service Control
    /// Manager starts). From a console it runs in the foreground like `run`.
    #[cfg(windows)]
    #[command(name = "run-service")]
    RunService,
    /// Windows, development: register this computer's `C:\Program
    /// Files\Faro\faro-service.exe run-service` with the Service Control
    /// Manager (the MSI does this itself). Needs an elevated administrator.
    #[cfg(windows)]
    InstallService,
    /// Windows, development: stop and remove the service registration.
    #[cfg(windows)]
    UninstallService,
    /// Windows: the elevated helper of an administrator's approval of
    /// enrolling from the agent (the agent starts it through UAC). Records
    /// the approval with the service and exits 0 (approved), 10 (refused),
    /// 11 (no service) or 12 (bad arguments).
    #[cfg(windows)]
    ApproveEnroll {
        /// The request id, 64 hex digits.
        #[arg(long)]
        request: String,
    },
    /// Load the image model as `run` does (licence, attribution and
    /// digest checks), classify a few synthetic frames and time it. Reads
    /// no state and no screen.
    ModelCheck {
        /// Model manifest (default: the packaged one).
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Timed classifications.
        #[arg(long, default_value_t = 20)]
        runs: usize,
    },
    /// Load the domain category list as `run` does (licence, attribution
    /// and digest checks) and print its version and sources. Reads no state.
    DomainsCheck {
        /// Domain list manifest (default: the packaged one).
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GoodbyeKind {
    /// Faro is being removed from this computer.
    Uninstalled,
    /// The member is deleting their account.
    AccountDeleted,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    State(#[from] crate::state::StateError),
    #[error(transparent)]
    Enroll(#[from] enroll::EnrollError),
    #[error(transparent)]
    Link(#[from] link::LinkError),
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Outbox(#[from] faro_core::OutboxError),
    #[error(transparent)]
    Status(#[from] crate::status_view::GatherError),
    #[error(transparent)]
    Report(#[from] crate::diagnose::WriteError),
    #[error("{0}")]
    Usage(String),
    #[error(transparent)]
    Goodbye(#[from] GoodbyeError),
    /// Not a failure to report as one: see [`EXIT_GOODBYE_QUEUED`].
    #[error("the goodbye (event {seq}) is written but was not delivered: {error}")]
    GoodbyeQueued { seq: u64, error: String },
    #[error("cannot start the async runtime: {0}")]
    Runtime(std::io::Error),
    #[error("image model {}: {source}", path.display())]
    Model {
        path: PathBuf,
        source: crate::model::OpenError,
    },
    #[error("domain list {}: {source}", path.display())]
    Domains {
        path: PathBuf,
        source: faro_detect::DetectError,
    },
}

/// Entry point for the binary.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    crate::logging::init(&cli);
    // Windows: the commands that don't start a runtime the usual way.
    #[cfg(windows)]
    let cli = match windows::early(cli) {
        Ok(code) => return code,
        Err(cli) => cli,
    };
    run_cli(cli)
}

fn run_cli(cli: Cli) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)
    {
        Ok(rt) => rt,
        Err(e) => {
            crate::logging::fail(&e);
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(dispatch(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e @ CliError::GoodbyeQueued { .. }) => {
            crate::logging::fail(&e);
            ExitCode::from(EXIT_GOODBYE_QUEUED)
        }
        Err(e) => {
            crate::logging::fail(&e);
            ExitCode::FAILURE
        }
    }
}

fn load_config(cli: &Cli) -> Result<Config, CliError> {
    let mut c = Config::load(cli.config.as_deref())?;
    if let Some(d) = &cli.state_dir {
        c.state_dir =
            std::path::absolute(d).map_err(|e| CliError::Usage(format!("bad --state-dir: {e}")))?;
    }
    c.validate()?;
    Ok(c)
}

async fn dispatch(cli: Cli) -> Result<(), CliError> {
    // Needs no configuration or state.
    if let Command::ModelCheck { manifest, runs } = &cli.command {
        return cmd_model_check(manifest.clone(), *runs);
    }
    if let Command::DomainsCheck { manifest } = &cli.command {
        return cmd_domains_check(manifest.clone());
    }
    #[cfg(windows)]
    windows::require_administrator(&cli)?;
    let config = load_config(&cli)?;
    match cli.command {
        Command::Enroll {
            link,
            instance,
            code,
            member_key,
            name,
            yes,
            no_wait,
        } => {
            let (instance, code, member_key) = match link {
                Some(l) => {
                    let l = link::parse_enroll_link(&l)?;
                    (l.instance, l.code, l.member_key)
                }
                None => {
                    let url = instance
                        .or_else(|| config.instance_url.clone())
                        .ok_or_else(|| {
                            CliError::Usage("--instance or --link is required".into())
                        })?;
                    let code = code.ok_or_else(|| CliError::Usage("--code is required".into()))?;
                    let member_key = member_key
                        .as_deref()
                        .map(link::parse_member_key_id)
                        .transpose()?;
                    (
                        link::parse_instance_url(&url)?,
                        EnrollCode::parse(&code)?,
                        member_key,
                    )
                }
            };
            let opts = EnrollOptions {
                name,
                member_key,
                yes,
                no_wait,
            };
            cmd_enroll(&config, instance, code, opts).await
        }
        Command::Run {
            socket,
            spawn_agent,
            capture,
        } => {
            let mut config = config;
            if let Some(s) = socket {
                config.ipc.socket_path = s;
            }
            cmd_run(config, spawn_agent, capture).await
        }
        Command::Status { json } => cmd_status(&config, json),
        Command::Diagnose {
            lines,
            output,
            yes,
            print,
        } => {
            let config_file = cli
                .config
                .clone()
                .unwrap_or_else(crate::config::default_config_path);
            let opts = DiagnoseOptions {
                lines,
                output,
                yes,
                print,
                development: cli.state_dir.is_some(),
            };
            cmd_diagnose(&config, config_file, opts)
        }
        Command::Goodbye {
            reason,
            moved_to,
            within,
        } => {
            let reason = match (moved_to, reason) {
                (Some(host), _) => {
                    let host = host.trim().to_owned();
                    if host.is_empty() || host.len() > 253 || host.contains(['/', ' ']) {
                        return Err(CliError::Usage(
                            "--moved-to takes the new instance's host name".into(),
                        ));
                    }
                    GoodbyeReason::MovedInstance {
                        new_instance_host: host,
                    }
                }
                (None, GoodbyeKind::Uninstalled) => GoodbyeReason::Uninstalled,
                (None, GoodbyeKind::AccountDeleted) => GoodbyeReason::AccountDeleted,
            };
            let mut opts = GoodbyeOptions::new(reason);
            opts.deliver_within = Duration::from_secs(within);
            cmd_goodbye(&config, opts).await
        }
        #[cfg(windows)]
        Command::RunService
        | Command::InstallService
        | Command::UninstallService
        | Command::ApproveEnroll { .. } => unreachable!("handled in main"),
        Command::ModelCheck { .. } | Command::DomainsCheck { .. } => {
            unreachable!("handled above")
        }
    }
}

fn cmd_domains_check(manifest: Option<PathBuf>) -> Result<(), CliError> {
    use crate::update::artifacts;
    let manifest = manifest
        .or_else(artifacts::packaged_domains_manifest)
        .ok_or_else(|| {
            CliError::Usage("no packaged domain list on this platform; give --manifest".into())
        })?;
    artifacts::check_domains(&manifest, &mut std::io::stdout().lock()).map_err(|source| {
        CliError::Domains {
            path: manifest,
            source,
        }
    })
}

fn cmd_model_check(manifest: Option<PathBuf>, runs: usize) -> Result<(), CliError> {
    let manifest = manifest
        .or_else(crate::model::packaged_manifest)
        .ok_or_else(|| {
            CliError::Usage("no packaged model on this platform; give --manifest".into())
        })?;
    crate::model::check(&manifest, runs, &mut std::io::stdout().lock()).map_err(|source| {
        CliError::Model {
            path: manifest,
            source,
        }
    })
}

async fn cmd_goodbye(config: &Config, opts: GoodbyeOptions) -> Result<(), CliError> {
    match say_goodbye(config, opts).await? {
        GoodbyeOutcome::Delivered { seq } => {
            println!("Goodbye delivered (event {seq}): your allies are being told.");
            Ok(())
        }
        GoodbyeOutcome::NotEnrolled => {
            println!("This device is not enrolled; there is nobody to tell.");
            Ok(())
        }
        GoodbyeOutcome::NotActivated => {
            println!(
                "This device was never approved by its member; no ally was told about it, \
                 so there is nobody to tell."
            );
            Ok(())
        }
        GoodbyeOutcome::AlreadyRetired(Retired::DeviceRemoved) => {
            println!(
                "This computer was removed from Faro by its member, and their allies were told \
                 then. There is nobody left to tell."
            );
            Ok(())
        }
        GoodbyeOutcome::AlreadyRetired(Retired::AccountDeleted) => {
            println!(
                "The Faro account this computer reported to was deleted, and its allies were \
                 told then. There is nobody left to tell."
            );
            Ok(())
        }
        GoodbyeOutcome::Queued { seq, error } => Err(CliError::GoodbyeQueued { seq, error }),
    }
}

fn confirm_prompt(info: &InstanceInfo) -> bool {
    print!(
        "{}",
        crate::accounts::enrollment_notice(crate::accounts::local_accounts().as_ref())
    );
    println!();
    println!("Instance: {}", info.name);
    println!("URL:      {}", info.url);
    println!("ID:       {}", info.well_known.instance_id);
    print!("Enroll this device with this instance? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

struct EnrollOptions {
    name: Option<String>,
    member_key: Option<String>,
    yes: bool,
    no_wait: bool,
}

async fn cmd_enroll(
    config: &Config,
    instance: url::Url,
    code: EnrollCode,
    o: EnrollOptions,
) -> Result<(), CliError> {
    let EnrollOptions {
        name,
        member_key,
        yes,
        no_wait,
    } = o;
    let dir = StateDir::open(&config.state_dir)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let opts = ClientOptions {
        timeout: config.network.request_timeout(),
        ca_file: config.network.ca_file.clone(),
    };
    let params = EnrollParams {
        instance,
        code,
        device_name: enroll::device_name(name.as_deref())?,
        client: opts.clone(),
        member_key: member_key.clone(),
    };
    let enrollment = enroll::enroll(&dir, clock.clone(), &params, |info| {
        if yes {
            print!(
                "{}",
                crate::accounts::enrollment_notice(crate::accounts::local_accounts().as_ref())
            );
            println!("Enrolling with {} ({})", info.name, info.url);
            true
        } else {
            confirm_prompt(info)
        }
    })
    .await?;
    let key = Arc::new(state::load_device_key(&dir)?);
    println!("Enrolled as device {}.", enrollment.device_id);
    println!(
        "Device key fingerprint: {}  (check that the web app shows the same before approving)",
        enroll::device_fingerprint(&key.public())
    );
    let member = enroll::member_fingerprint(&enrollment.member_sign_pubkey);
    if member_key.is_some() {
        println!("Member key:             {member}  (matches the enrollment link)");
    } else {
        println!(
            "Member key safety code: {member}  (check that your web app shows the same member key; \
             if it does not, the instance substituted its own key: remove this device)"
        );
    }
    if no_wait {
        println!("Approve the device in the web app; `faro-service run` finishes activation.");
        return Ok(());
    }
    if installed_service_running() {
        // The installed service is waiting for this enrollment and will
        // pick it up; activating here too would race it.
        println!(
            "Approve the device in the web app. The Faro service is running and finishes \
             activation once you do."
        );
        return Ok(());
    }
    println!("Waiting for you to approve this device in the web app (Ctrl-C to stop waiting)…");
    let client = enroll::device_client(&enrollment, key.clone(), clock, &opts, None)?;
    let device_pubkey = key.public();
    let poll = config.network.endorsement_poll_interval();
    let waited = tokio::select! {
        r = enroll::await_endorsement(&client, &enrollment, &device_pubkey, poll) => Some(r?),
        _ = tokio::signal::ctrl_c() => None,
    };
    let Some(signed) = waited else {
        println!("Stopped waiting; `faro-service run` finishes activation once approved.");
        return Ok(());
    };
    enroll::activate(&dir, &client, &enrollment, &key, &signed).await?;
    println!("Device approved and active.");
    Ok(())
}

/// Whether the packaged service (launchd daemon) is installed, so it, not
/// this command, activates the device.
fn installed_service_running() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new(faro_platform_macos::pkg_layout::DAEMON_PLIST).exists()
    }
    #[cfg(windows)]
    {
        use faro_platform_windows::scm::{service_state, ServiceState};
        matches!(
            service_state(faro_platform_windows::layout::SERVICE_NAME),
            Ok(Some(ServiceState::Running | ServiceState::StartPending))
        )
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        false
    }
}

/// An installed service starts before the member enrolls the device. Rather
/// than exit (and be restarted by launchd every few seconds), wait for
/// `faro-service enroll` to write the enrollment record. Returns `false` if
/// `stop` fired first.
async fn wait_for_enrollment(
    dir: &StateDir,
    every: Duration,
    stop: impl Future<Output = ()>,
) -> Result<bool, CliError> {
    let enrolled = |dir: &StateDir| match dir.enrollment() {
        Ok(_) => Ok(true),
        Err(StateError::NotEnrolled) => Ok(false),
        Err(e) => Err(CliError::State(e)),
    };
    if enrolled(dir)? {
        return Ok(true);
    }
    tracing::info!("this device is not enrolled yet; waiting for `faro-service enroll`");
    tokio::pin!(stop);
    loop {
        tokio::select! {
            _ = &mut stop => return Ok(false),
            _ = tokio::time::sleep(every) => {}
        }
        if enrolled(dir)? {
            tracing::info!("enrolled; starting");
            return Ok(true);
        }
    }
}

async fn cmd_run(
    config: Config,
    spawn_agent: Option<PathBuf>,
    capture: CaptureMode,
) -> Result<(), CliError> {
    cmd_run_until(config, spawn_agent, capture, shutdown_signal(), None).await
}

/// `run` until `shutdown` completes. `signals`, if given, receives the
/// running service's [`crate::ServiceSignals`] once it is built (after
/// enrollment).
async fn cmd_run_until(
    config: Config,
    spawn_agent: Option<PathBuf>,
    capture: CaptureMode,
    shutdown: impl Future<Output = ()> + Send,
    signals: Option<tokio::sync::oneshot::Sender<crate::ServiceSignals>>,
) -> Result<(), CliError> {
    let dir = StateDir::open(&config.state_dir)?;
    // Windows: the agents come up before enrollment too (the agent is what
    // enrolls the computer), started and kept by the service itself.
    #[cfg(windows)]
    let _launcher = start_agent_launcher(spawn_agent.is_none() && capture == CaptureMode::Ipc);
    // Up before the wait, for the life of the process: the agent can enroll
    // the computer through it (an administrator approves), and ask whether
    // it is enrolled.
    let _enroll_server = start_enroll_server(&config);
    tokio::pin!(shutdown);
    if !wait_for_enrollment(&dir, ENROLLMENT_POLL, &mut shutdown).await? {
        return Ok(());
    }
    let socket = config.ipc.socket_path.clone();
    let mut b = Service::builder(config);
    if let Some(p) = spawn_agent {
        b = b.spawn_agent(AgentSpawn::new(p, socket));
    }
    match capture {
        CaptureMode::Ipc => {}
        CaptureMode::InProcess => b = b.boxed_frame_source(in_process_source()?),
    }
    let service = b.build()?;
    tracing::info!(device = %service.enrollment().device_id, instance = %service.enrollment().instance_url, "starting");
    if let Some(tx) = signals {
        let _ = tx.send(service.signals());
    }
    service.run(shutdown).await?;
    Ok(())
}

/// Windows: start the launcher of the per-session agents, if this is the
/// LocalSystem service (only it may start a process in another session).
#[cfg(windows)]
fn start_agent_launcher(wanted: bool) -> AbortOnDrop {
    if wanted && crate::win::is_system() {
        AbortOnDrop(Some(tokio::spawn(
            crate::source::win_agents::AgentLauncher::production().run(),
        )))
    } else {
        AbortOnDrop(None)
    }
}

/// Aborts the enroll server's task when dropped.
struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(t) = self.0.take() {
            t.abort();
        }
    }
}

/// The enroll sockets (`crate::enroll_server`). Approval always goes
/// through [`SystemApprover`](crate::enroll_server::SystemApprover): there
/// is deliberately no option to use another.
fn start_enroll_server(config: &Config) -> AbortOnDrop {
    #[cfg(any(unix, windows))]
    {
        use crate::enroll_server::{EnrollServer, EnrollService, SystemApprover};
        let service = EnrollService::from_config(config, Arc::new(SystemApprover));
        AbortOnDrop(Some(tokio::spawn(EnrollServer::new(service, config).run())))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = config;
        AbortOnDrop(None)
    }
}

#[cfg(target_os = "macos")]
fn in_process_source() -> Result<Box<dyn crate::source::FrameSource>, CliError> {
    Ok(Box::new(crate::source::InProcessFrameSource::new(
        faro_platform_macos::MacPlatform::agent_platform(),
        std::time::Duration::from_secs(1),
    )))
}

#[cfg(not(target_os = "macos"))]
fn in_process_source() -> Result<Box<dyn crate::source::FrameSource>, CliError> {
    Err(CliError::Usage(
        "--capture in-process is only available on macOS".into(),
    ))
}

/// SIGTERM (launchd/systemd stop) or SIGINT.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot install the SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Windows: the commands that need the process before a runtime exists
/// (`run-service`'s dispatcher must be called from the main thread) or no
/// runtime at all. `Err(cli)` hands the rest to the usual path.
#[cfg(windows)]
mod windows {
    use super::*;
    use faro_platform_windows::layout;
    use faro_platform_windows::scm::{self, ServiceContext, ServiceControl};
    use faro_platform_windows::ui::approval::{exit, ApprovalRequest};
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    /// How often Faro's program files are checked for write access by
    /// other accounts.
    const INTEGRITY_EVERY: Duration = Duration::from_secs(60);

    /// `status`, `enroll`, `goodbye` and `diagnose` read or write the
    /// service's state directory, which only administrators can open. From
    /// a terminal that is not elevated, say so rather than let the first
    /// file access fail with "access denied". A development run with its
    /// own `--state-dir` needs no administrator.
    pub(super) fn require_administrator(cli: &Cli) -> Result<(), CliError> {
        let name = match &cli.command {
            Command::Status { .. } => "status",
            Command::Enroll { .. } => "enroll",
            Command::Goodbye { .. } => "goodbye",
            Command::Diagnose { .. } => "diagnose",
            _ => return Ok(()),
        };
        if cli.state_dir.is_some() || faro_platform_windows::acl::running_elevated() {
            return Ok(());
        }
        Err(CliError::Usage(format!(
            "`faro-service {name}` needs an administrator, because Faro's files are open to \
             administrators only. Run this in a terminal opened as administrator: right-click \
             Start, choose Terminal (Admin) or Windows PowerShell (Admin), approve the prompt, \
             and run it again."
        )))
    }

    #[allow(clippy::result_large_err)]
    pub(super) fn early(cli: Cli) -> Result<ExitCode, Cli> {
        match &cli.command {
            Command::InstallService => Ok(registration(true)),
            Command::UninstallService => Ok(registration(false)),
            Command::ApproveEnroll { request } => {
                let args = ["approve-enroll", "--request", request.as_str()];
                let code = match ApprovalRequest::parse_helper_arguments(&args) {
                    Some(r) => approve_enroll(&cli, &r),
                    None => exit::BAD_ARGUMENTS,
                };
                Ok(ExitCode::from(code as u8))
            }
            Command::RunService => Ok(run_service(cli)),
            _ => Err(cli),
        }
    }

    fn registration(install: bool) -> ExitCode {
        let r = if install {
            // The same argv the MSI registers.
            scm::install_service(
                std::path::Path::new(layout::SERVICE_PROGRAM),
                &["run-service".to_owned()],
            )
        } else {
            scm::uninstall_service()
        };
        match r {
            Ok(()) => {
                println!(
                    "{}",
                    if install {
                        "Service registered."
                    } else {
                        "Service removed."
                    }
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::logging::fail(&format!(
                    "{} needs an elevated administrator: {e}",
                    if install {
                        "install-service"
                    } else {
                        "uninstall-service"
                    }
                ));
                ExitCode::FAILURE
            }
        }
    }

    /// The approval helper: tell the service an elevated administrator
    /// approved `request`. Returns the exit code.
    fn approve_enroll(cli: &Cli, request: &ApprovalRequest) -> u32 {
        use faro_ipc::{
            AllowSameUser, AllowSystemService, EnrollRequest, EnrollResponse, IpcClient, Sid,
        };
        let base = load_config(cli)
            .map(|c| c.ipc.socket_path)
            .unwrap_or_else(|_| crate::config::default_socket_path());
        // The admin pipe of a real service, else a development service's.
        let path = faro_ipc::resolve_enroll_socket(&base, Sid::BUILTIN_ADMINISTRATORS);
        let production =
            path == faro_ipc::enroll_socket_path(&base, Some(Sid::BUILTIN_ADMINISTRATORS));
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return exit::NO_SERVICE;
        };
        rt.block_on(async {
            let conn = if production {
                IpcClient::connect_verified_typed::<EnrollRequest, EnrollResponse>(
                    &path,
                    &AllowSystemService,
                )
                .await
            } else {
                IpcClient::connect_verified_typed::<EnrollRequest, EnrollResponse>(
                    &path,
                    &AllowSameUser,
                )
                .await
            };
            let Ok(mut conn) = conn else {
                return exit::NO_SERVICE;
            };
            let sent = conn
                .send(&EnrollRequest::ApproveEnroll {
                    request: *request.bytes(),
                })
                .await;
            if sent.is_err() {
                return exit::NO_SERVICE;
            }
            match conn
                .recv_timeout(Duration::from_secs(15), "the approval answer")
                .await
            {
                Ok(EnrollResponse::Approved) => exit::APPROVED,
                Ok(_) => exit::REFUSED,
                Err(_) => exit::NO_SERVICE,
            }
        })
    }

    /// `run-service`: the SCM's dispatcher, or the foreground when started
    /// from a console.
    fn run_service(cli: Cli) -> ExitCode {
        let slot = Arc::new(Mutex::new(Some(cli)));
        let for_service = slot.clone();
        let r = scm::run_service_dispatcher(move |ctx| {
            let cli = for_service.lock().ok().and_then(|mut s| s.take());
            match cli {
                Some(cli) => service_main(cli, ctx),
                None => 1,
            }
        });
        match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) if scm::is_not_a_service(&e) => {
                let Some(mut cli) = slot.lock().ok().and_then(|mut s| s.take()) else {
                    return ExitCode::FAILURE;
                };
                cli.command = Command::Run {
                    socket: None,
                    spawn_agent: None,
                    capture: CaptureMode::Ipc,
                };
                run_cli(cli)
            }
            Err(e) => {
                crate::logging::fail(&format!("cannot connect to the service manager: {e}"));
                ExitCode::FAILURE
            }
        }
    }

    /// On the SCM's service thread: the whole service.
    fn service_main(cli: Cli, ctx: ServiceContext) -> u32 {
        if let Err(e) = crate::win::prepare_dirs() {
            tracing::error!(error = %e, "cannot protect the state and log directories");
        }
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                crate::logging::fail(&CliError::Runtime(e));
                return 1;
            }
        };
        let ServiceContext {
            controls, status, ..
        } = ctx;
        let code = rt.block_on(async move {
            let config = match load_config(&cli) {
                Ok(c) => c,
                Err(e) => {
                    crate::logging::fail(&e);
                    return 1;
                }
            };
            // The SCM's channel into tokio.
            let (tx, mut controls_rx) = mpsc::unbounded_channel();
            std::thread::spawn(move || {
                while let Ok(c) = controls.recv() {
                    if tx.send(c).is_err() {
                        break;
                    }
                }
            });
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let mut stop_tx = Some(stop_tx);
            let (sig_tx, sig_rx) = tokio::sync::oneshot::channel();
            let mut sig_rx = Some(sig_rx);
            let mut signals: Option<crate::ServiceSignals> = None;
            let run = cmd_run_until(
                config,
                None,
                CaptureMode::Ipc,
                async move {
                    let _ = stop_rx.await;
                },
                Some(sig_tx),
            );
            tokio::pin!(run);
            status.running();
            let mut integrity = tokio::time::interval(INTEGRITY_EVERY);
            integrity.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut reported: BTreeSet<String> = BTreeSet::new();
            let result = loop {
                tokio::select! {
                    r = &mut run => break r,
                    Some(c) = controls_rx.recv() => match c {
                        ServiceControl::Stop
                        | ServiceControl::Shutdown
                        | ServiceControl::Preshutdown => {
                            tracing::info!("the service manager asked the service to stop");
                            if let Some(tx) = stop_tx.take() {
                                let _ = tx.send(());
                            }
                        }
                        ServiceControl::SessionChange(ev) => {
                            tracing::info!(kind = ?ev.kind, session = ev.session, "session change");
                            crate::win::notify_session_change();
                        }
                        ServiceControl::TimeChange => {
                            tracing::info!("the system clock was set");
                            if let Some(s) = &signals {
                                s.clock_changed();
                            }
                        }
                        ServiceControl::Power(_) => {}
                    },
                    Some(Ok(s)) = async {
                        match sig_rx.as_mut() {
                            Some(rx) => Some(rx.await),
                            None => std::future::pending().await,
                        }
                    } => {
                        signals = Some(s);
                        sig_rx = None;
                    },
                    _ = integrity.tick() => {
                        if let Some(s) = &signals {
                            check_program_files(s, &mut reported).await;
                        }
                    }
                }
            };
            match result {
                Ok(()) => 0,
                Err(e) => {
                    crate::logging::fail(&e);
                    1
                }
            }
        });
        // Let tasks that block (the control bridge thread) not hold the
        // process up.
        rt.shutdown_timeout(Duration::from_secs(2));
        code
    }

    /// Tamper (§3.7): Faro's program files must not be writable by anyone
    /// but SYSTEM, Administrators and TrustedInstaller. Each offending
    /// path is reported once per process as an `IntegrityFailure`.
    async fn check_program_files(signals: &crate::ServiceSignals, reported: &mut BTreeSet<String>) {
        let found = tokio::task::spawn_blocking(writable_program_files)
            .await
            .unwrap_or_default();
        for rel in found {
            if reported.insert(rel.clone()) {
                tracing::error!(path = %rel, "a Faro program file can be changed by other accounts");
                signals.tamper(faro_proto::body::TamperSignal::IntegrityFailure {
                    component: format!("program files: {rel} can be changed by other accounts"),
                });
            }
        }
    }

    /// Paths under `layout::PROGRAM_DIR` (relative) that other accounts
    /// may write. Only the installed service has such a directory.
    fn writable_program_files() -> Vec<String> {
        use faro_platform_windows::acl::writable_by_others;
        let root = std::path::Path::new(layout::PROGRAM_DIR);
        if !crate::win::is_system() || !root.is_dir() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut todo = vec![(root.to_path_buf(), 0usize)];
        let mut seen = 0usize;
        while let Some((dir, depth)) = todo.pop() {
            if let Ok(true) = writable_by_others(&dir) {
                out.push(rel(root, &dir));
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.flatten() {
                seen += 1;
                if seen > 500 {
                    return out;
                }
                let p = e.path();
                let Ok(t) = e.file_type() else { continue };
                if t.is_dir() {
                    if depth < 3 {
                        todo.push((p, depth + 1));
                    }
                } else if let Ok(true) = writable_by_others(&p) {
                    out.push(rel(root, &p));
                }
            }
        }
        out
    }

    fn rel(root: &std::path::Path, p: &std::path::Path) -> String {
        p.strip_prefix(root)
            .map(|r| r.display().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ".".to_owned())
    }
}

fn cmd_status(config: &Config, json: bool) -> Result<(), CliError> {
    let now = SystemClock::new().wall_ms();
    let view = crate::status_view::gather(config, now)?;
    if json {
        let text = serde_json::to_string_pretty(&view)
            .map_err(|e| CliError::Usage(format!("cannot print the status: {e}")))?;
        println!("{text}");
    } else {
        print!("{}", view.text(now));
    }
    Ok(())
}

struct DiagnoseOptions {
    lines: usize,
    output: Option<PathBuf>,
    yes: bool,
    print: bool,
    /// `--state-dir` was given: a development run, which needn't be root.
    #[cfg_attr(not(unix), allow(dead_code))]
    development: bool,
}

/// `diagnose`: collect the report, show what is in it, and write it once
/// the member says so (`crate::diagnose`).
fn cmd_diagnose(config: &Config, config_file: PathBuf, o: DiagnoseOptions) -> Result<(), CliError> {
    use crate::diagnose;
    use std::io::IsTerminal;
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        if !root && !o.development {
            return Err(CliError::Usage(
                "diagnose reads the service's state and logs, so it needs an administrator: \
                 sudo /Library/Faro/bin/faro-service diagnose"
                    .into(),
            ));
        }
    }
    let member = diagnose::member();
    let sources = diagnose::Sources::installed(config, config_file, member.as_ref(), o.lines);
    let now = SystemClock::new().wall_ms();
    let report = diagnose::collect(config, &sources, now);
    if o.print {
        print!("{}", report.full_text());
        return Ok(());
    }
    let owner = member.as_ref().map(|m| (m.uid, m.gid));
    let dir = match o.output {
        Some(d) => {
            std::path::absolute(&d).map_err(|e| CliError::Usage(format!("bad --output: {e}")))?
        }
        None => {
            let m = member.as_ref().ok_or_else(|| {
                CliError::Usage(if cfg!(windows) {
                    "this is running as the SYSTEM account, which has no Desktop to put the \
                     report on; choose a folder with --output"
                        .into()
                } else {
                    "can't tell whose Desktop the report goes on; choose a folder with --output"
                        .into()
                })
            })?;
            diagnose::desktop(m)?
        }
    };
    println!("Faro problem report");
    println!();
    println!(
        "It goes to {} and holds:",
        dir.join(format!("{}.zip", report.name)).display()
    );
    println!();
    print!("{}", report.summary());
    println!();
    if !o.yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Usage(
                "nothing written: run it in a terminal to see what is in the report first, \
                 or add --yes"
                    .into(),
            ));
        }
        loop {
            print!("Write it? Type y to write it, s to show everything in it first, n to stop: ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            let read = std::io::stdin().lock().read_line(&mut line).unwrap_or(0);
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" if read > 0 => break,
                "s" | "show" if read > 0 => {
                    println!();
                    print!("{}", report.full_text());
                }
                _ => {
                    println!("Nothing written.");
                    return Ok(());
                }
            }
        }
    }
    let path = diagnose::write_zip(&report, &dir, owner)?;
    println!("Wrote {}.", path.display());
    println!(
        "Send it to whoever helps you with Faro (the member guide's \"Reporting a problem\" \
         says where). The files in it are plain text: open it to check them first."
    );
    Ok(())
}

/// A note when `[dev_thresholds]` is set: lowered (a development build) or
/// ignored. `installers/macos/check-pkg.sh` reads it.
#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn run_waits_for_enrollment_until_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path().join("state")).unwrap();
        let stopped = wait_for_enrollment(&dir, Duration::from_millis(5), async {
            tokio::time::sleep(Duration::from_millis(30)).await;
        })
        .await
        .unwrap();
        assert!(!stopped, "not enrolled, so it waits until told to stop");
    }

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_status() {
        let c = Cli::try_parse_from(["faro-service", "status"]).unwrap();
        assert!(matches!(c.command, Command::Status { json: false }));
        let c = Cli::try_parse_from(["faro-service", "status", "--json"]).unwrap();
        assert!(matches!(c.command, Command::Status { json: true }));
    }

    #[test]
    fn parses_diagnose() {
        let c = Cli::try_parse_from(["faro-service", "diagnose"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Diagnose {
                lines: crate::diagnose::DEFAULT_LINES,
                output: None,
                yes: false,
                print: false
            }
        ));
        let c =
            Cli::try_parse_from(["faro-service", "diagnose", "--lines", "50", "--yes"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Diagnose {
                lines: 50,
                yes: true,
                ..
            }
        ));
        assert!(Cli::try_parse_from(["faro-service", "diagnose", "--print", "--yes"]).is_err());
    }

    #[test]
    fn parses_goodbye() {
        let c = Cli::try_parse_from(["faro-service", "goodbye"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Goodbye {
                reason: GoodbyeKind::Uninstalled,
                moved_to: None,
                within: 60
            }
        ));
        let c = Cli::try_parse_from(["faro-service", "goodbye", "--moved-to", "faro.example.net"])
            .unwrap();
        assert!(matches!(
            c.command,
            Command::Goodbye {
                moved_to: Some(_),
                ..
            }
        ));
        assert!(Cli::try_parse_from([
            "faro-service",
            "goodbye",
            "--reason",
            "account-deleted",
            "--moved-to",
            "x.example"
        ])
        .is_err());
    }

    #[test]
    fn parses_enroll_and_run() {
        let c = Cli::try_parse_from([
            "faro-service",
            "--state-dir",
            "/tmp/x",
            "enroll",
            "--instance",
            "https://a.example",
            "--code",
            "ABCD-1234",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(c.command, Command::Enroll { yes: true, .. }));
        assert!(Cli::try_parse_from([
            "faro-service",
            "enroll",
            "--link",
            "faro://enroll?i=x&c=y",
            "--code",
            "ABCD-1234"
        ])
        .is_err());
        let c =
            Cli::try_parse_from(["faro-service", "run", "--spawn-agent", "/bin/agent"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Run {
                capture: CaptureMode::Ipc,
                ..
            }
        ));
    }
}
