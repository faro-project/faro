//! Where `faro-service` logs, and how much.
//!
//! **Where.** The packaged service, started by launchd as `run`, writes its
//! log to `/Library/Logs/Faro/faro-service.log`
//! (`faro_platform_macos::pkg_layout::SERVICE_LOG`): root:admin, 0640, so
//! an administrator of the Mac can read it without `sudo`, rotated at 5 MiB
//! with three old files kept (`faro_platform::logfile`). It writes the file
//! itself rather than through the daemon plist's `StandardErrorPath`
//! because launchd holds a file it opened for the job open, so the file
//! couldn't be rotated under a running service. Every other command, and
//! `run` started from a terminal or from a development build, logs to
//! stderr as before. If the log file can't be opened, the service logs to
//! stderr and says why.
//!
//! **How much.** `RUST_LOG` wins, then `-v` (debug) and `-vv` (trace), then
//! `log_level` in `service.toml`, then `info`. At `info` and above nothing
//! private is logged: no URLs, window titles, notice texts or anything from
//! a frame (`faro-platform`'s `log_privacy` test checks the log calls).
//!
//! **Panics** are logged too (as an `error` with target `panic`): launchd
//! discards the service's stderr, where the default hook writes them.

use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};

use tracing_subscriber::EnvFilter;

use crate::cli::{Cli, Command};
use crate::config::Config;

/// Whether the log goes to the log file rather than stderr.
static TO_FILE: AtomicBool = AtomicBool::new(false);

/// Set up logging for this invocation of the command line.
pub fn init(cli: &Cli) {
    let config_level = Config::load(cli.config.as_deref())
        .ok()
        .and_then(|c| c.log_level);
    let filter = filter(cli.verbose, config_level.as_deref());
    if matches!(cli.command, Command::Run { .. }) && packaged_and_detached() {
        match open_service_log() {
            Ok(file) => {
                let ok = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .try_init()
                    .is_ok();
                if ok {
                    TO_FILE.store(true, Ordering::Relaxed);
                    log_panics();
                }
                return;
            }
            Err(e) => {
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(std::io::stderr)
                    .try_init();
                tracing::error!(error = %e, "cannot open the log file; logging to stderr");
                return;
            }
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

/// Report why the command failed: on stderr, and in the log file when the
/// log goes there (launchd discards the service's stderr).
pub fn fail(e: &dyn Display) {
    if TO_FILE.load(Ordering::Relaxed) {
        tracing::error!("faro-service: {e}");
    }
    eprintln!("faro-service: {e}");
}

/// The filter: `RUST_LOG`, else `-v`, else the config's `log_level`, else
/// `info`. A `log_level` that doesn't parse (`Config::validate` refuses
/// it later) counts as unset.
pub fn filter(verbose: u8, config_level: Option<&str>) -> EnvFilter {
    if let Ok(f) = EnvFilter::try_from_default_env() {
        return f;
    }
    let level = match verbose {
        0 => config_level.unwrap_or("info"),
        1 => "debug",
        _ => "trace",
    };
    EnvFilter::builder()
        .parse(level)
        .unwrap_or_else(|_| EnvFilter::new("info"))
}

fn log_panics() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        tracing::error!(target: "panic", "{panic}");
        previous(panic);
    }));
}

/// The packaged service (`/Library/Faro/bin/faro-service`) with no
/// terminal on stderr: started by launchd, not by someone in Terminal.
#[cfg(target_os = "macos")]
fn packaged_and_detached() -> bool {
    use std::io::IsTerminal;
    use std::path::Path;
    let packaged = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .is_some_and(|p| p == Path::new(faro_platform_macos::pkg_layout::SERVICE_PROGRAM));
    packaged && !std::io::stderr().is_terminal()
}

#[cfg(not(target_os = "macos"))]
fn packaged_and_detached() -> bool {
    false
}

/// Open `SERVICE_LOG`, making its directory root:admin 0750 first. Files
/// created in it later (on rotation) take the directory's group, as every
/// new file does on macOS.
#[cfg(target_os = "macos")]
fn open_service_log() -> std::io::Result<faro_platform::logfile::RotatingFile> {
    use faro_platform_macos::pkg_layout as layout;
    use std::os::unix::fs::{chown, PermissionsExt};
    match std::fs::create_dir(layout::LOG_DIR) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let meta = std::fs::symlink_metadata(layout::LOG_DIR)?;
    if !meta.is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a directory",
            layout::LOG_DIR
        )));
    }
    chown(layout::LOG_DIR, Some(0), Some(layout::LOG_GID))?;
    std::fs::set_permissions(
        layout::LOG_DIR,
        std::fs::Permissions::from_mode(layout::LOG_DIR_MODE),
    )?;
    let file = faro_platform::logfile::RotatingFile::open(
        layout::SERVICE_LOG,
        layout::service_log_rotation(),
    )?;
    chown(layout::SERVICE_LOG, Some(0), Some(layout::LOG_GID))?;
    Ok(file)
}

#[cfg(not(target_os = "macos"))]
fn open_service_log() -> std::io::Result<faro_platform::logfile::RotatingFile> {
    Err(std::io::Error::other("no log file on this system"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_level_comes_from_flags_then_config_then_info() {
        // RUST_LOG is not set in the test environment (cargo doesn't set it).
        if std::env::var_os("RUST_LOG").is_some() {
            return;
        }
        assert_eq!(filter(0, None).to_string(), "info");
        assert_eq!(
            filter(0, Some("faro_service=debug")).to_string(),
            "faro_service=debug"
        );
        assert_eq!(filter(1, Some("warn")).to_string(), "debug");
        assert_eq!(filter(2, None).to_string(), "trace");
        assert_eq!(filter(0, Some("x=loud")).to_string(), "info");
    }
}
