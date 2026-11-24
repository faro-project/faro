//! Phase 0 spike #1 tool (ARCHITECTURE.md §13): ScreenCaptureKit behaviour,
//! permission persistence and re-prompt behaviour, ideally run from a
//! LaunchAgent.
//!
//! Prints permission state, displays, per-display frame size and capture
//! latency, plus the session/foreground/tamper readings the agent would
//! see. It **never writes pixels anywhere**: frames are measured (size,
//! fraction of non-zero bytes) and dropped, which zeroizes them.
//!
//! ```text
//! cargo run -p faro-platform-macos --example capture_probe -- [options]
//!   --repeat N         capture N times (default 1)
//!   --interval SECS    seconds between repeats (default 60)
//!   --request          call CGRequestScreenCaptureAccess() first (may prompt)
//!   --print-agent-plist PATH_TO_LOG
//!                      print a LaunchAgent plist that runs this probe every
//!                      run under launchd, logging to PATH_TO_LOG, then exit
//! ```

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("capture_probe: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("capture_probe only runs on macOS");
}

#[cfg(target_os = "macos")]
mod probe {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use faro_platform::{ForegroundInfo, ScreenCapture, ServiceHost, SessionState};
    use faro_platform_macos::{
        accessibility_trusted, active_displays, request_screen_capture_access,
        screen_capture_permission, tamper, LaunchdJob, MacForeground, MacPlatform,
        MacScreenCapture, MacSession, ProgramLocation,
    };

    struct Args {
        repeat: u32,
        interval: Duration,
        request: bool,
        print_plist: Option<String>,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            repeat: 1,
            interval: Duration::from_secs(60),
            request: false,
            print_plist: None,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
            match flag.as_str() {
                "--repeat" => {
                    a.repeat = value("--repeat")?
                        .parse()
                        .map_err(|e| format!("--repeat: {e}"))?
                }
                "--interval" => {
                    let secs: u64 = value("--interval")?
                        .parse()
                        .map_err(|e| format!("--interval: {e}"))?;
                    a.interval = Duration::from_secs(secs);
                }
                "--request" => a.request = true,
                "--print-agent-plist" => a.print_plist = Some(value("--print-agent-plist")?),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(a)
    }

    fn print_agent_plist(log: &str) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut job = LaunchdJob::agent(ProgramLocation::Absolute(exe));
        job.label = "org.faro.capture-probe".into();
        job.args = vec!["--repeat".into(), "1".into()];
        // Run once per load / login; launchd re-runs it every 5 minutes so
        // the spike can watch permission persistence over days.
        job.keep_alive = false;
        job.start_interval = Some(300);
        job.stdout_path = Some(log.into());
        job.stderr_path = Some(log.into());
        let xml = job.to_plist_xml().map_err(|e| e.to_string())?;
        print!("{xml}");
        eprintln!(
            "# install: save as ~/Library/LaunchAgents/org.faro.capture-probe.plist, then\n\
             #   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.faro.capture-probe.plist"
        );
        Ok(())
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn report_environment() {
        println!("== environment ==");
        println!("pid                 : {}", std::process::id());
        println!("screen_recording    : {:?}", screen_capture_permission());
        println!("accessibility       : {}", accessibility_trusted());
        let session = MacSession::new();
        println!("idle_secs           : {}", session.idle_secs());
        println!("locked              : {}", session.is_locked());
        println!("display_asleep      : {}", session.display_asleep());
        let fg = MacForeground::new();
        match fg.active_app() {
            Some(app) => println!("active_app          : {} ({:?})", app.id, app.name),
            None => println!("active_app          : <none>"),
        }
        // Titles can be sensitive; report only whether one is readable.
        match fg.window_title() {
            Some(t) => println!("window_title        : <{} chars>", t.chars().count()),
            None => println!("window_title        : <unavailable>"),
        }
        let obs = tamper::observe();
        println!(
            "tamper observation  : vm={} vpn={} sr={} ax={}",
            obs.virtual_machine, obs.vpn, obs.screen_recording, obs.accessibility
        );
        match MacPlatform::service_host().list_sessions() {
            Ok(s) => {
                for s in s {
                    println!(
                        "session             : {} user={} active={}",
                        s.id.0, s.user, s.active
                    );
                }
            }
            Err(e) => println!("sessions            : error {e}"),
        }
        match active_displays() {
            Ok(ids) => println!("active displays     : {ids:?}"),
            Err(e) => println!("active displays     : error {e}"),
        }
    }

    fn capture_round(n: u32, cap: &mut MacScreenCapture) {
        println!(
            "== capture #{n} at unix {} (permission {:?}, backend {:?}) ==",
            unix_now(),
            cap.permission_state(),
            cap.backend()
        );
        let started = Instant::now();
        match cap.capture_each() {
            Err(e) => println!("capture failed after {:?}: {e}", started.elapsed()),
            Ok(results) => {
                for d in results {
                    match d.result {
                        Ok(frame) => {
                            let px = frame.pixels();
                            let nonzero = px.iter().filter(|&&b| b != 0).count();
                            println!(
                                "display {:>10}: {}x{} {:?} in {:?} (non-zero bytes {:.1}%)",
                                d.display_id,
                                frame.width(),
                                frame.height(),
                                frame.format(),
                                d.latency,
                                100.0 * nonzero as f64 / px.len().max(1) as f64
                            );
                            // Dropping the frame zeroizes its pixels.
                            frame.destroy();
                        }
                        Err(e) => {
                            println!(
                                "display {:>10}: error after {:?}: {e}",
                                d.display_id, d.latency
                            )
                        }
                    }
                }
                println!("total               : {:?}", started.elapsed());
            }
        }
    }

    pub fn run() -> Result<(), String> {
        let args = parse_args()?;
        if let Some(log) = args.print_plist {
            return print_agent_plist(&log);
        }
        if args.request {
            println!(
                "requesting access   : granted={}",
                request_screen_capture_access()
            );
        }
        report_environment();
        let mut cap = MacScreenCapture::new();
        for n in 1..=args.repeat.max(1) {
            if n > 1 {
                std::thread::sleep(args.interval);
            }
            capture_round(n, &mut cap);
        }
        Ok(())
    }
}
