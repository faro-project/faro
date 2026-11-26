//! `faro-agent`: the per-session agent binary. See the library docs for
//! what it does; this file only parses arguments, picks the platform layer,
//! sets up logging and signals, and runs [`faro_agent::Agent`]. On macOS
//! the main thread runs the menu-bar icon and notice window instead
//! (`faro_platform_macos::ui`), and the agent runs on a worker thread.
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

/// Logs to stderr, or, for the packaged agent started by launchd, to
/// `~/Library/Logs/Faro/faro-agent.log` (`pkg_layout::agent_log`; 0600,
/// rotated at 5 MiB, three old files kept). The agent writes the file
/// itself because its plist is one global LaunchAgent for every account,
/// and launchd doesn't expand `~` in `StandardErrorPath`.
fn init_logging() {
    use tracing_subscriber::EnvFilter;
    // Default to `info`: window titles, URLs and notice bodies are logged
    // only at `debug`, so a default log never contains them.
    let filter = EnvFilter::try_from_env("FARO_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    #[cfg(target_os = "macos")]
    if let Some(log) = packaged_log() {
        match open_log(&log) {
            Ok(file) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file))
                    .init();
                // launchd discards the agent's stderr, where the default
                // hook writes panics.
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |panic| {
                    tracing::error!(target: "panic", "{panic}");
                    previous(panic);
                }));
                return;
            }
            Err(e) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_writer(std::io::stderr)
                    .init();
                tracing::error!(error = %e, "cannot open the log file; logging to stderr");
                return;
            }
        }
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

/// The log file, for the packaged agent with no terminal on stderr and a
/// home directory to log in.
#[cfg(target_os = "macos")]
fn packaged_log() -> Option<std::path::PathBuf> {
    use faro_platform_macos::pkg_layout;
    use std::io::IsTerminal;
    let packaged = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .is_some_and(|p| p == std::path::Path::new(pkg_layout::AGENT_PROGRAM));
    if !packaged || std::io::stderr().is_terminal() {
        return None;
    }
    let home = std::path::PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute().then(|| pkg_layout::agent_log(&home))
}

/// Open the agent's log, creating `~/Library/Logs/Faro` (0700) if needed.
#[cfg(target_os = "macos")]
fn open_log(log: &std::path::Path) -> std::io::Result<faro_platform::logfile::RotatingFile> {
    use faro_platform_macos::pkg_layout;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = log
        .parent()
        .ok_or_else(|| std::io::Error::other("no log directory"))?;
    if let Some(logs) = dir.parent() {
        std::fs::create_dir_all(logs)?; // ~/Library/Logs, normally there
    }
    match std::fs::DirBuilder::new()
        .mode(pkg_layout::AGENT_LOG_DIR_MODE)
        .create(dir)
    {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    std::fs::set_permissions(
        dir,
        std::fs::Permissions::from_mode(pkg_layout::AGENT_LOG_DIR_MODE),
    )?;
    faro_platform::logfile::RotatingFile::open(log, pkg_layout::agent_log_rotation())
}

#[cfg(unix)]
fn run(args: RunArgs) -> ExitCode {
    #[cfg(target_os = "macos")]
    if ui_wanted(&args) {
        return run_with_ui(args);
    }
    exit_code(run_agent(args, faro_agent::LogNotices, None))
}

#[cfg(unix)]
fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "macos")]
#[allow(unused_variables)] // `args` is only read in `dev` builds
fn ui_wanted(args: &RunArgs) -> bool {
    #[cfg(feature = "dev")]
    if args.no_ui {
        tracing::warn!("development mode: no menu-bar icon or notice window");
        return false;
    }
    true
}

/// macOS: AppKit takes the main thread for the menu-bar icon and the
/// notice window (`faro_platform_macos::ui`), and the agent runs on a
/// worker thread, which ends the process when the agent stops.
#[cfg(target_os = "macos")]
fn run_with_ui(args: RunArgs) -> ExitCode {
    use faro_platform_macos::ui::{MainThreadMarker, SessionUi};
    use std::sync::Arc;

    let Some(mtm) = MainThreadMarker::new() else {
        tracing::error!("the agent's UI must start on the main thread");
        return ExitCode::FAILURE;
    };
    // AppKit's Quit (sent at logout) stops the agent the way SIGTERM does,
    // so it still says Goodbye.
    let quit = Arc::new(tokio::sync::Notify::new());
    let ui = {
        let quit = quit.clone();
        SessionUi::new(mtm, move || {
            tracing::info!("asked to quit");
            quit.notify_one();
        })
    };
    let mut notices = MacNotices(ui.handle());
    // The menu's About and "Report a problem…" are filled from the start;
    // the agent reports changes from here on.
    faro_agent::NoticeSink::status(&mut notices, &faro_agent::status_menu::Seen::Starting);
    offer_enrollment(&ui, &args);
    let agent = std::thread::Builder::new()
        .name("faro-agent".to_owned())
        .spawn(move || {
            let ok = run_agent(args, notices, Some(quit));
            std::process::exit(if ok { 0 } else { 1 });
        });
    if let Err(e) = agent {
        tracing::error!(error = %e, "could not start the agent thread");
        return ExitCode::FAILURE;
    }
    ui.run();
    // AppKit's loop doesn't return on its own; the agent thread exits.
    ExitCode::FAILURE
}

/// Notices in the menu-bar UI.
#[cfg(target_os = "macos")]
struct MacNotices(faro_platform_macos::ui::UiHandle);

#[cfg(target_os = "macos")]
impl faro_agent::NoticeSink for MacNotices {
    fn show(&mut self, title: &str, body: &str) {
        tracing::info!(title, "showing a service notice");
        tracing::debug!(title, body, "service notice body");
        self.0.show_notice(title, body);
    }

    fn screen_recording_off(&mut self) {
        let n = faro_agent::SCREEN_RECORDING_OFF;
        self.0
            .show_settings_notice(faro_platform_macos::ui::SettingsNotice {
                title: n.title.to_owned(),
                body: n.body.to_owned(),
                open: n.open.to_owned(),
                later: n.later.to_owned(),
                url: n.url.to_owned(),
            });
    }

    fn status(&mut self, seen: &faro_agent::status_menu::Seen) {
        use faro_agent::status_menu::{about, local_utc_offset_secs, report_problem, status_menu};
        use faro_platform_macos::ui::{ReportProblem, StatusFix, StatusMenu};
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let menu = status_menu(seen, now_ms, local_utc_offset_secs(now_ms));
        let about = about(faro_agent::AGENT_VERSION, seen);
        let report = report_problem();
        // The status line is a state, never content: fine at `info`.
        tracing::info!(status = %menu.line, "status menu");
        self.0.set_status(StatusMenu {
            detail: menu.detail().to_owned(),
            line: menu.line,
            problem: menu.problem,
            fix: menu.fix.map(|f| StatusFix {
                label: f.label,
                url: f.url,
            }),
            web_app: menu.web_app,
            about_title: about.title,
            about_body: about.body,
            report: Some(ReportProblem {
                title: report.title,
                body: report.body,
                copy: report.copy,
                command: report.command,
            }),
        });
    }
}

/// `faro://enroll` links and "Enroll this computer…" (issue #62): each runs
/// `faro_agent::enroll::run_flow` on a worker thread, one at a time, which
/// reaches the UI through blocking calls on the main queue.
#[cfg(target_os = "macos")]
fn offer_enrollment(ui: &faro_platform_macos::ui::SessionUi, args: &RunArgs) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let handle = ui.handle();
    let base = args.socket.clone();
    let trust = service_trust(args);
    let open = Arc::new(AtomicBool::new(false));
    ui.on_enroll(move |link| {
        if open.swap(true, Ordering::SeqCst) {
            tracing::info!("an enrollment is already open");
            return;
        }
        // The link carries a one-time code: never logged.
        tracing::info!(from_link = link.is_some(), "starting enrollment");
        let (open2, base) = (open.clone(), base.clone());
        let spawned = std::thread::Builder::new()
            .name("faro-enroll".to_owned())
            .spawn(move || {
                // SAFETY: geteuid has no preconditions and cannot fail.
                let uid = unsafe { libc::geteuid() };
                let socket = faro_ipc::resolve_enroll_socket(&base, uid);
                faro_agent::enroll::run_flow(
                    &MacEnrollUi(handle),
                    &MacAuthorizer,
                    &socket,
                    trust,
                    link,
                );
                open2.store(false, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            tracing::error!(error = %e, "could not start the enrollment thread");
            open.store(false, Ordering::SeqCst);
        }
    });
}

#[cfg(target_os = "macos")]
struct MacEnrollUi(faro_platform_macos::ui::UiHandle);

#[cfg(target_os = "macos")]
impl faro_agent::enroll::EnrollUi for MacEnrollUi {
    fn ask_target(&self, s: &faro_agent::enroll::PasteScreen) -> Option<(String, String)> {
        self.0
            .ask_enroll_target(&faro_platform_macos::ui::TwoFields {
                title: s.title.clone(),
                body: s.body.clone(),
                first_label: s.first_label.clone(),
                first_placeholder: s.first_placeholder.clone(),
                second_label: s.second_label.clone(),
                second_placeholder: s.second_placeholder.clone(),
                ok: s.ok.clone(),
                cancel: s.cancel.clone(),
            })
    }

    fn confirm(&self, s: &faro_agent::enroll::Screen, ok: &str, cancel: &str) -> bool {
        self.0.confirm(&s.title, &s.body, ok, cancel)
    }

    fn show(&self, s: &faro_agent::enroll::Screen, problem: bool) {
        self.0.message(&s.title, &s.body, problem);
    }
}

/// An empty authorization for the service to ask an administrator with.
#[cfg(target_os = "macos")]
struct MacAuthorizer;

#[cfg(target_os = "macos")]
impl faro_agent::enroll::Authorizer for MacAuthorizer {
    fn create(
        &self,
    ) -> Result<(Box<dyn std::any::Any>, [u8; faro_ipc::AUTHORIZATION_LEN]), String> {
        use faro_platform_macos::authorization::Authorization;
        let auth = Authorization::new_empty().map_err(|e| e.to_string())?;
        let ext = auth.external_form().map_err(|e| e.to_string())?;
        Ok((Box::new(auth), ext))
    }
}

/// Who the agent accepts as the service: root, unless a `dev` build was
/// told to trust its own uid. Only the macOS enrollment flow asks.
#[cfg(target_os = "macos")]
#[allow(unused_variables)] // `args` is only read in `dev` builds
fn service_trust(args: &RunArgs) -> faro_agent::ServiceTrust {
    #[cfg(feature = "dev")]
    if args.trust_same_uid_service {
        return faro_agent::ServiceTrust::SameUid;
    }
    faro_agent::ServiceTrust::Root
}

/// Run the agent until it stops. `quit`, if given, stops it like SIGTERM.
#[cfg(unix)]
fn run_agent(
    args: RunArgs,
    notices: impl faro_agent::NoticeSink + 'static,
    quit: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> bool {
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
            return false;
        }
    };
    let mut agent = Agent::new(config, platform).with_notice_sink(notices);
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
            return false;
        }
    };
    let result = runtime.block_on(async {
        let stop = match termination(quit) {
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
            true
        }
        Some(Ok(ExitReason::Stopped)) => {
            tracing::info!("exiting on signal");
            true
        }
        Some(Err(e)) => {
            tracing::error!(error = %e, "agent failed");
            false
        }
        None => false,
    }
}

#[cfg(not(unix))]
fn run(_args: RunArgs) -> ExitCode {
    // TODO(windows): needs the named-pipe transport in faro-ipc and a
    // faro-platform-windows crate; neither exists yet.
    tracing::error!("faro-agent is not available on this operating system yet");
    ExitCode::FAILURE
}

/// Completes on SIGTERM (launchd/systemd at logout), SIGINT, or `quit`.
#[cfg(unix)]
fn termination(
    quit: Option<std::sync::Arc<tokio::sync::Notify>>,
) -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(async move {
        let quit = async {
            match quit {
                Some(q) => q.notified().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            () = quit => {}
        }
    })
}

#[cfg(unix)]
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
