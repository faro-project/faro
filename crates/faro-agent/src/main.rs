//! `faro-agent`: the per-session agent binary. See the library docs for
//! what it does; this file only parses arguments, picks the platform layer,
//! sets up logging and signals, and runs [`faro_agent::Agent`].
//!
//! launchd starts it as `faro-agent run` (see
//! `faro_platform_macos::LaunchdJob::agent`).

use std::process::ExitCode;

use clap::Parser;
use faro_agent::cli::{Cli, Command, RunArgs};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging();
    let Command::Run(args) = cli.command;
    run(args)
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    // Default to `info`: titles and notice bodies are logged only at
    // `debug`, so a default log never contains them.
    let filter = EnvFilter::try_from_env("FARO_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(unix)]
fn run(args: RunArgs) -> ExitCode {
    use faro_agent::{Agent, AgentConfig, ExitReason};

    let mut config = AgentConfig::new(args.socket.clone());
    if let Some(s) = args.session.clone() {
        config.session = s;
    }
    if let Some(u) = args.user.clone() {
        config.user = u;
    }
    #[cfg(feature = "dev")]
    if args.trust_same_uid_service {
        tracing::warn!("development mode: trusting a service that runs as our own uid");
        config.service_trust = faro_agent::ServiceTrust::SameUid;
    }

    let (platform, accessibility) = match select_platform(&args) {
        Ok(p) => p,
        Err(msg) => {
            tracing::error!("{msg}");
            return ExitCode::FAILURE;
        }
    };
    let mut agent = Agent::new(config, platform);
    if let Some(probe) = accessibility {
        agent = agent.with_accessibility_probe(probe);
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let stop = match termination() {
            Ok(stop) => stop,
            Err(e) => {
                tracing::error!(error = %e, "could not install signal handlers");
                return None;
            }
        };
        Some(agent.run(stop).await)
    });
    match result {
        Some(Ok(ExitReason::Shutdown(reason))) => {
            tracing::info!(?reason, "exiting at the service's request");
            ExitCode::SUCCESS
        }
        Some(Ok(ExitReason::Stopped)) => {
            tracing::info!("exiting on signal");
            ExitCode::SUCCESS
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "agent failed");
            ExitCode::FAILURE
        }
        None => ExitCode::FAILURE,
    }
}

#[cfg(not(unix))]
fn run(_args: RunArgs) -> ExitCode {
    // TODO(windows): needs the named-pipe transport in faro-ipc and a
    // faro-platform-windows crate; neither exists yet.
    tracing::error!("faro-agent is not available on this operating system yet");
    ExitCode::FAILURE
}

/// Completes on SIGTERM (launchd/systemd at logout) or SIGINT.
#[cfg(unix)]
fn termination() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    })
}

type Platform = (
    faro_platform::AgentPlatform,
    Option<faro_agent::AccessibilityProbe>,
);

#[cfg(unix)]
#[allow(unused_variables)] // `args` is only read in `dev` builds
fn select_platform(args: &RunArgs) -> Result<Platform, String> {
    #[cfg(feature = "dev")]
    if args.synthetic {
        tracing::warn!("development mode: capturing a synthetic screen, not the real one");
        return Ok((faro_platform::synthetic::Script::new().platform(), None));
    }
    native_platform()
}

#[cfg(target_os = "macos")]
fn native_platform() -> Result<Platform, String> {
    let probe: faro_agent::AccessibilityProbe =
        Box::new(faro_platform_macos::accessibility_trusted);
    Ok((
        faro_platform_macos::MacPlatform::agent_platform(),
        Some(probe),
    ))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn native_platform() -> Result<Platform, String> {
    // Linux ships in Phase 2 (ARCHITECTURE.md §3.3), after the Wayland
    // spike. Refusing is better than running an agent that captures nothing.
    Err("no platform layer for this operating system yet \
         (development builds can use `--synthetic` with `--features dev`)"
        .to_owned())
}
