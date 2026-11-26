//! The `faro-service` command line.
//!
//! ```text
//! faro-service [--config FILE] [--state-dir DIR] [-v] enroll (--link faro://enroll?... | --instance URL --code XXXX-XXXX [--member-key ID]) [--name NAME] [--yes] [--no-wait]
//! faro-service [--config FILE] [--state-dir DIR] [-v] run [--socket PATH] [--spawn-agent BIN] [--capture ipc|in-process]
//! faro-service [--config FILE] [--state-dir DIR] status
//! faro-service [--config FILE] [--state-dir DIR] goodbye [--reason uninstalled|account-deleted | --moved-to HOST] [--within SECS]
//! faro-service model-check [--manifest PATH] [--runs N]
//! ```
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
    /// Show enrollment and outbox state (no network access).
    Status,
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
}

/// Entry point for the binary.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    crate::logging::init(&cli);
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
        Command::Status => cmd_status(&config),
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
        Command::ModelCheck { .. } => unreachable!("handled above"),
    }
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
    #[cfg(not(target_os = "macos"))]
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
    let dir = StateDir::open(&config.state_dir)?;
    // Up before the wait, for the life of the process: the agent can enroll
    // the computer through it (an administrator approves), and ask whether
    // it is enrolled.
    let _enroll_server = start_enroll_server(&config);
    if !wait_for_enrollment(&dir, ENROLLMENT_POLL, shutdown_signal()).await? {
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
    service.run(shutdown_signal()).await?;
    Ok(())
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
    #[cfg(unix)]
    {
        use crate::enroll_server::{EnrollServer, EnrollService, SystemApprover};
        let service = EnrollService::from_config(config, Arc::new(SystemApprover));
        AbortOnDrop(Some(tokio::spawn(EnrollServer::new(service, config).run())))
    }
    #[cfg(not(unix))]
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

fn cmd_status(config: &Config) -> Result<(), CliError> {
    let dir = StateDir::open(&config.state_dir)?;
    let e = match dir.enrollment() {
        Ok(e) => e,
        Err(crate::state::StateError::NotEnrolled) => {
            println!("Not enrolled. State directory: {}", dir.path().display());
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let key = state::load_device_key(&dir)?;
    println!("Instance:     {} ({})", e.instance_name, e.instance_url);
    println!("Instance id:  {}", e.instance_id);
    println!("Device:       {} \"{}\"", e.device_id, e.device_name);
    println!(
        "Fingerprint:  {}",
        enroll::device_fingerprint(&key.public())
    );
    println!("Member:       {}", e.member_id);
    println!(
        "Member key:   {}  (compare with the member key your web app shows)",
        enroll::member_fingerprint(&e.member_sign_pubkey)
    );
    println!(
        "Endorsed:     {}",
        if dir.endorsement()?.is_some() {
            "yes"
        } else {
            "no (waiting for approval)"
        }
    );
    let outbox = faro_core::Outbox::open(dir.path(), &e.instance_id, &e.device_id)?;
    match outbox.current_recipients(&e.member_sign_pubkey, &e.member_id)? {
        Some(set) => println!(
            "Recipients:   manifest v{} (member + {} allies)",
            set.manifest_ref().version,
            set.allies().len()
        ),
        None => println!("Recipients:   none yet (not bootstrapped)"),
    }
    let stats = outbox.stats()?;
    let head = outbox.head()?;
    println!(
        "Outbox:       {} events ({} bytes), {} reports queued; next seq {}",
        stats.events, stats.event_bytes, stats.reports, head.next_seq
    );
    Ok(())
}

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
