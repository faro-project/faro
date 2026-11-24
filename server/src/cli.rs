//! Command-line interface: `faro-server serve | init | backup | doctor | version`.
//!
//! * `init` creates the data directory and the instance identity key,
//!   migrates the database, and prints a one-time setup token for the web
//!   setup wizard. Re-running it mints a fresh token (invalidating the old
//!   one) until an admin exists.
//! * `serve` does the same startup checks, prints a setup token on first run
//!   if none is outstanding (so `docker compose up` works without a separate
//!   `init`), and serves HTTP until SIGINT/SIGTERM.
//! * `backup --out FILE.tar` writes a consistent snapshot (database, identity
//!   key, config, blobs); see [`crate::backup`].
//! * `doctor` checks the configuration and environment; see [`crate::doctor`].
//! * `version` prints the server and protocol versions.
//!
//! Secrets printed here (setup tokens) go to **stdout/stderr only**, never
//! through `tracing`, so they do not end up in structured log pipelines.

use crate::bootstrap;
use crate::clock::SystemClock;
use crate::config::{Config, ConfigError};
use crate::mailer::{LogMailer, Mailer, SmtpMailer};
use crate::server;
use clap::{Parser, Subcommand};
use faro_proto::keys::key_id;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "faro-server",
    version,
    about = "Faro self-hosted instance server"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the instance.
    Serve {
        /// Path to faro.toml (optional; FARO_* env vars override it).
        #[arg(long, env = "FARO_CONFIG")]
        config: Option<PathBuf>,
        /// Running behind a TLS-terminating reverse proxy or tunnel.
        #[arg(long)]
        behind_proxy: bool,
        /// Development mode: http:// allowed, no Secure cookies/HSTS, emails
        /// (including sign-in links) printed to stderr.
        #[arg(long)]
        dev: bool,
    },
    /// Create the data directory and identity key; print a setup token.
    Init {
        /// Path to faro.toml (optional; FARO_* env vars override it).
        #[arg(long, env = "FARO_CONFIG")]
        config: Option<PathBuf>,
        /// Development mode (see `serve --dev`).
        #[arg(long)]
        dev: bool,
    },
    /// Write a consistent backup tarball (database snapshot, identity key,
    /// config, blobs).
    Backup {
        /// Path to faro.toml (optional; FARO_* env vars override it).
        #[arg(long, env = "FARO_CONFIG")]
        config: Option<PathBuf>,
        /// Output file, e.g. faro-2026-11-24.tar. Must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Development mode (see `serve --dev`).
        #[arg(long)]
        dev: bool,
    },
    /// Check the configuration and environment and print a report.
    Doctor {
        /// Path to faro.toml (optional; FARO_* env vars override it).
        #[arg(long, env = "FARO_CONFIG")]
        config: Option<PathBuf>,
        /// Development mode (see `serve --dev`).
        #[arg(long)]
        dev: bool,
        /// Do not connect to the SMTP server.
        #[arg(long)]
        no_smtp_check: bool,
    },
    /// Print version information.
    Version,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Bootstrap(#[from] bootstrap::BootstrapError),
    #[error(transparent)]
    Serve(#[from] server::ServeError),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("cannot start async runtime: {0}")]
    Runtime(std::io::Error),
    #[error(transparent)]
    Mail(#[from] crate::mailer::MailError),
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
    #[error(transparent)]
    Backup(#[from] crate::backup::BackupError),
    #[error("doctor found problems")]
    DoctorFailed,
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: std::net::SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// Load the configuration: file (if any), then env, then CLI flags, then
/// validate once with everything applied.
pub fn load_config(
    path: Option<&Path>,
    env: impl IntoIterator<Item = (String, String)>,
    behind_proxy: bool,
    dev: bool,
) -> Result<Config, ConfigError> {
    let mut cfg = match path {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|source| ConfigError::Io {
                path: p.to_owned(),
                source,
            })?;
            Config::from_toml_str(&text, p)?
        }
        None => Config::default(),
    };
    for unknown in cfg.apply_env(env)? {
        // Names only; values can be secrets.
        eprintln!("warning: ignoring unknown environment variable {unknown}");
    }
    cfg.behind_proxy |= behind_proxy;
    cfg.dev |= dev;
    cfg.validate()?;
    Ok(cfg)
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("FARO_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info"));
    // Ignore the error if a subscriber is already installed (tests).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn mailer_for(cfg: &Config) -> Result<Arc<dyn Mailer>, CliError> {
    if cfg.smtp.is_configured() {
        return Ok(Arc::new(SmtpMailer::from_config(&cfg.smtp)?));
    }
    if !cfg.dev {
        tracing::warn!(
            "SMTP is not configured: sign-in links and alerts cannot be emailed \
             (set [smtp] in faro.toml or FARO_SMTP_*)"
        );
    }
    Ok(Arc::new(LogMailer::new(cfg.dev)))
}

fn print_setup_token(cfg: &Config, token: &str) {
    eprintln!(
        "\nOne-time setup token (valid 24 hours, single use):\n\n    {token}\n\n\
         Open {}/setup and paste it to create the admin account.\n",
        cfg.public_url
    );
}

async fn run_init(cfg: Config) -> Result<(), CliError> {
    let mailer = mailer_for(&cfg)?;
    let state = bootstrap::open(cfg, mailer, Arc::new(SystemClock)).await?;
    let pk = state.identity().public();
    println!("Faro instance ready.");
    println!("  data dir:     {}", state.config().data_dir.display());
    println!("  instance id:  {}", state.instance_id());
    println!(
        "  identity key: {} (key id {})",
        pk.to_b64(),
        key_id(pk.as_bytes())
    );
    match bootstrap::issue_setup_token(&state).await? {
        Some(token) => print_setup_token(state.config(), &token),
        None => println!("This instance already has an admin; no setup token issued."),
    }
    state.db().close().await;
    Ok(())
}

async fn run_serve(cfg: Config) -> Result<(), CliError> {
    let listen = cfg.listen;
    let mailer = mailer_for(&cfg)?;
    let state = bootstrap::open(cfg, mailer, Arc::new(SystemClock)).await?;
    if let Some(token) = bootstrap::ensure_setup_token(&state).await? {
        print_setup_token(state.config(), &token);
    }
    let cancel = tokio_util::sync::CancellationToken::new();
    let tls = crate::tls::from_config(state.config(), cancel.clone())?;
    if tls.is_none() && !state.config().behind_proxy && !state.config().dev {
        tracing::warn!(
            "serving plain HTTP: configure [tls] (acme_domain or cert_path/key_path), \
             run behind a TLS-terminating proxy (--behind-proxy), or use --dev locally"
        );
    }
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|source| CliError::Listen {
            addr: listen,
            source,
        })?;
    let result = match tls {
        Some((mode, acme_task)) => {
            let r = server::run_tls(state, listener, mode, server::shutdown_signal()).await;
            cancel.cancel();
            if let Some(t) = acme_task {
                let _ = t.await;
            }
            r
        }
        None => server::run(state, listener, server::shutdown_signal()).await,
    };
    result?;
    Ok(())
}

async fn run_backup(cfg: Config, config_path: Option<&Path>, out: &Path) -> Result<(), CliError> {
    let report = crate::backup::run(&cfg, config_path, out).await?;
    println!("Backup written to {}", report.path.display());
    println!(
        "  database: {}",
        if report.database_included {
            "included (SQLite snapshot)"
        } else {
            "NOT included (Postgres)"
        }
    );
    println!("  blobs:    {} files", report.blob_files);
    println!("  The archive contains the instance identity key: store it securely.");
    if let Some(g) = report.postgres_guidance {
        println!("\n{g}");
    }
    Ok(())
}

async fn run_doctor(cfg: Config, check_smtp: bool) -> Result<(), CliError> {
    let report = crate::doctor::run(&cfg, check_smtp).await;
    print!("{}", report.render());
    if report.has_failures() {
        return Err(CliError::DoctorFailed);
    }
    Ok(())
}

/// Entry point used by `main`.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Version = cli.command {
        println!(
            "faro-server {} (protocol {})",
            crate::SERVER_VERSION,
            faro_proto::api::PROTOCOL_VERSION
        );
        return ExitCode::SUCCESS;
    }
    init_tracing();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)
        .and_then(|rt| {
            rt.block_on(async {
                match cli.command {
                    Command::Serve {
                        config,
                        behind_proxy,
                        dev,
                    } => {
                        run_serve(load_config(
                            config.as_deref(),
                            std::env::vars(),
                            behind_proxy,
                            dev,
                        )?)
                        .await
                    }
                    Command::Init { config, dev } => {
                        run_init(load_config(
                            config.as_deref(),
                            std::env::vars(),
                            false,
                            dev,
                        )?)
                        .await
                    }
                    Command::Backup { config, out, dev } => {
                        let cfg = load_config(config.as_deref(), std::env::vars(), false, dev)?;
                        run_backup(cfg, config.as_deref(), &out).await
                    }
                    Command::Doctor {
                        config,
                        dev,
                        no_smtp_check,
                    } => {
                        let cfg = load_config(config.as_deref(), std::env::vars(), false, dev)?;
                        run_doctor(cfg, !no_smtp_check).await
                    }
                    Command::Version => Ok(()),
                }
            })
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn flags_apply_before_validation() {
        // Defaults have an http:// public URL, which only --dev permits.
        assert!(load_config(None, Vec::new(), false, false).is_err());
        let cfg = load_config(None, Vec::new(), true, true).unwrap();
        assert!(cfg.dev && cfg.behind_proxy);
    }

    #[test]
    fn env_still_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("faro.toml");
        std::fs::write(&p, "public_url = \"https://a.example.org\"\n").unwrap();
        let cfg = load_config(
            Some(&p),
            vec![("FARO_PUBLIC_URL".into(), "https://b.example.org".into())],
            false,
            false,
        )
        .unwrap();
        assert_eq!(cfg.public_url, "https://b.example.org");
    }
}
