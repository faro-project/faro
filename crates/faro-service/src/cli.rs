//! The `faro-service` command line.
//!
//! ```text
//! faro-service [--config FILE] [--state-dir DIR] [-v] enroll (--link faro://enroll?... | --instance URL --code XXXX-XXXX [--member-key ID]) [--name NAME] [--yes] [--no-wait]
//! faro-service [--config FILE] [--state-dir DIR] [-v] run [--socket PATH] [--spawn-agent BIN] [--capture ipc|in-process]
//! faro-service [--config FILE] [--state-dir DIR] status
//! ```

use crate::client::ClientOptions;
use crate::config::Config;
use crate::enroll::{self, EnrollParams, InstanceInfo};
use crate::link::{self, EnrollCode};
use crate::runtime::{AgentSpawn, Service, ServiceError};
use crate::state::{self, StateDir};
use clap::{Parser, Subcommand, ValueEnum};
use faro_core::clock::{Clock, SystemClock};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(name = "faro-service", version, about = "The privileged Faro service")]
pub struct Cli {
    /// Config file (default: the platform's service.toml).
    #[arg(long, global = true, env = "FARO_SERVICE_CONFIG")]
    pub config: Option<PathBuf>,
    /// State directory override, for development and tests.
    #[arg(long, global = true, env = "FARO_STATE_DIR")]
    pub state_dir: Option<PathBuf>,
    /// More logging (-v debug, -vv trace). `RUST_LOG` overrides.
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
    #[error("cannot start the async runtime: {0}")]
    Runtime(std::io::Error),
}

/// Entry point for the binary.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("faro-service: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(dispatch(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("faro-service: {e}");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(verbose: u8) {
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
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
    }
}

fn confirm_prompt(info: &InstanceInfo) -> bool {
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

async fn cmd_run(
    config: Config,
    spawn_agent: Option<PathBuf>,
    capture: CaptureMode,
) -> Result<(), CliError> {
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
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
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
