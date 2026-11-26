//! Epic #85 spike 1 tool: capture from the session agent on Windows
//! (DXGI Desktop Duplication, GDI fallback), ideally run as the agent would
//! be: in the user's session, started by the service.
//!
//! Prints the session state (WTS connect and lock state, input desktop,
//! RDP), the monitors, and for each capture round the backend, frame size
//! and latency per display, plus this process's CPU time and memory around
//! each capture. It **never writes pixels anywhere**: frames are measured
//! (size, fraction of non-zero bytes) and dropped, which zeroizes them.
//! Window titles and URLs are never printed (only their length).
//!
//! ```text
//! cargo run --release -p faro-platform-windows --example capture_probe -- [options]
//!   --repeat N         capture N times (default 5)
//!   --interval SECS    seconds between repeats (default 2; fractions allowed)
//!   --gdi              use only the GDI fallback
//!   --quiet            print only the per-round summary line
//!   --other-desktop    create a desktop, switch to it for about a second,
//!                      capture from it and the foreground read, then switch
//!                      back (a watchdog thread switches back after 4 s no
//!                      matter what). Expect: not "unavailable", frames
//!                      captured, input desktop reported as Other(..).
//! ```
//!
//! To check the lock screen, UAC and fast user switching, run it with a
//! long `--repeat` and lock, elevate or switch user meanwhile: those rounds
//! should say `unavailable`, never fail with an OS error.

#[cfg(windows)]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("capture_probe: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("capture_probe only runs on Windows");
}

#[cfg(windows)]
mod probe {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use faro_platform::{ForegroundInfo, SessionState};
    use faro_platform_windows::capture::{monitors, screen_unavailable};
    use faro_platform_windows::session::{
        current_wts_session, input_desktop, is_remote_session, WinSession,
    };
    use faro_platform_windows::{tamper, WinForeground, WinScreenCapture};
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    struct Args {
        repeat: u32,
        interval: Duration,
        gdi: bool,
        quiet: bool,
        other_desktop: bool,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            repeat: 5,
            interval: Duration::from_secs(2),
            gdi: false,
            quiet: false,
            other_desktop: false,
        };
        let mut it = std::env::args().skip(1);
        while let Some(flag) = it.next() {
            let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
            match flag.as_str() {
                "--repeat" => a.repeat = value("--repeat")?.parse().map_err(|e| format!("{e}"))?,
                "--interval" => {
                    let s: f64 = value("--interval")?.parse().map_err(|e| format!("{e}"))?;
                    a.interval = Duration::try_from_secs_f64(s).map_err(|e| format!("{e}"))?;
                }
                "--gdi" => a.gdi = true,
                "--quiet" => a.quiet = true,
                "--other-desktop" => a.other_desktop = true,
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(a)
    }

    /// This process's user + kernel CPU time.
    fn cpu_time() -> Duration {
        let (mut c, mut e, mut k, mut u) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: valid out-pointers; the pseudo-handle needs no closing.
        if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) }.is_err()
        {
            return Duration::ZERO;
        }
        let t = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime);
        Duration::from_nanos((t(k) + t(u)) * 100)
    }

    /// (working set, private bytes) in bytes.
    fn memory() -> (usize, usize) {
        let mut m = PROCESS_MEMORY_COUNTERS_EX {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };
        // SAFETY: a PROCESS_MEMORY_COUNTERS_EX with cb set, as the call
        // accepts.
        let ok = unsafe {
            GetProcessMemoryInfo(
                GetCurrentProcess(),
                &mut m as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
                m.cb,
            )
        };
        if ok.is_err() {
            return (0, 0);
        }
        (m.WorkingSetSize, m.PrivateUsage)
    }

    fn mib(b: usize) -> f64 {
        b as f64 / (1024.0 * 1024.0)
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
        println!("remote session      : {}", is_remote_session());
        match current_wts_session() {
            Some(w) => println!(
                "wts session         : id={} connect_state={} lock={:?}",
                w.session_id, w.connect_state, w.lock
            ),
            None => println!("wts session         : <unavailable>"),
        }
        println!("input desktop       : {:?}", input_desktop());
        println!("screen unavailable  : {:?}", screen_unavailable());
        let session = WinSession::new();
        println!("idle_secs           : {}", session.idle_secs());
        println!("locked              : {}", session.is_locked());
        // The display callback fires asynchronously right after
        // registration; give it a moment.
        std::thread::sleep(Duration::from_millis(100));
        println!("display_asleep      : {}", session.display_asleep());
        let fg = WinForeground::new();
        match fg.active_app() {
            Some(app) => println!("active_app          : {} ({:?})", app.id, app.name),
            None => println!("active_app          : <none>"),
        }
        match fg.window_title() {
            Some(t) => println!("window_title        : <{} chars>", t.chars().count()),
            None => println!("window_title        : <none>"),
        }
        let obs = tamper::observe();
        println!(
            "tamper observation  : vm={} vpn={}",
            obs.virtual_machine, obs.vpn
        );
        for m in monitors() {
            println!(
                "monitor             : display {} at ({}, {}) {}x{}{}",
                m.display_id,
                m.rect.0,
                m.rect.1,
                m.rect.2,
                m.rect.3,
                if m.primary { " primary" } else { "" }
            );
        }
    }

    /// A user-created desktop that has the input while this exists. The
    /// watchdog restores `Default` after `limit` even if the caller hangs.
    fn other_desktop_round(gdi: bool) -> Result<(), String> {
        use windows::core::w;
        use windows::Win32::System::StationsAndDesktops::DESKTOP_ACCESS_FLAGS;
        use windows::Win32::System::StationsAndDesktops::{
            CloseDesktop, CreateDesktopW, OpenDesktopW, SwitchDesktop, DESKTOP_CONTROL_FLAGS,
            DESKTOP_SWITCHDESKTOP,
        };
        const GENERIC_ALL: u32 = 0x1000_0000;
        // SAFETY: plain handle calls; every handle is closed below.
        let default = unsafe {
            OpenDesktopW(
                w!("Default"),
                DESKTOP_CONTROL_FLAGS(0),
                false,
                DESKTOP_SWITCHDESKTOP.0,
            )
        }
        .map_err(|e| format!("OpenDesktop(Default): {e}"))?;
        // SAFETY: as above.
        let other = unsafe {
            CreateDesktopW(
                w!("FaroProbeDesktop"),
                None,
                None,
                DESKTOP_CONTROL_FLAGS(0),
                GENERIC_ALL,
                None,
            )
        }
        .map_err(|e| format!("CreateDesktop: {e}"))?;
        let default_raw = default.0 as isize;
        // Always come back, whatever the capture does.
        let watchdog = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(4));
            // SAFETY: the handle outlives this thread (joined below).
            let _ = unsafe {
                SwitchDesktop(windows::Win32::System::StationsAndDesktops::HDESK(
                    default_raw as *mut _,
                ))
            };
        });
        // SAFETY: valid desktop handle.
        unsafe { SwitchDesktop(other) }.map_err(|e| format!("SwitchDesktop: {e}"))?;
        std::thread::sleep(Duration::from_millis(400));
        let desk = input_desktop();
        let unavailable = screen_unavailable();
        let mut cap = if gdi {
            WinScreenCapture::gdi_only()
        } else {
            WinScreenCapture::new()
        };
        let result = cap.capture_each();
        let fg = WinForeground::new().active_app().is_some();
        // SAFETY: valid handles.
        let _ = unsafe { SwitchDesktop(default) };
        let _ = watchdog.join();
        // SAFETY: closed once.
        unsafe {
            let _ = CloseDesktop(other);
            let _ = CloseDesktop(default);
        }
        let _ = DESKTOP_ACCESS_FLAGS(0);
        println!("input desktop while switched: {desk:?}");
        println!("screen unavailable          : {unavailable:?}");
        println!("foreground read found an app: {fg} (a bare desktop has none)");
        match result {
            Ok(r) => {
                for d in &r {
                    println!(
                        "display {:>3} {:?}: {}",
                        d.display_id,
                        d.backend,
                        match &d.result {
                            Ok(f) => format!("{}x{} captured", f.width(), f.height()),
                            Err(e) => format!("error: {e}"),
                        }
                    );
                }
                if r.iter().any(|d| d.result.is_ok()) && unavailable.is_none() {
                    println!("OK: the user-created desktop was captured");
                    Ok(())
                } else {
                    Err("no display captured from the other desktop".into())
                }
            }
            Err(e) => Err(format!("capture on the other desktop failed: {e}")),
        }
    }

    pub fn run() -> Result<(), String> {
        let args = parse_args()?;
        if args.other_desktop {
            return other_desktop_round(args.gdi);
        }
        if !args.quiet {
            report_environment();
        }
        let mut cap = if args.gdi {
            WinScreenCapture::gdi_only()
        } else {
            WinScreenCapture::new()
        };
        let (ws0, pv0) = memory();
        println!(
            "baseline memory     : working set {:.1} MiB, private {:.1} MiB",
            mib(ws0),
            mib(pv0)
        );
        let mut cpu_total = Duration::ZERO;
        let mut wall_total = Duration::ZERO;
        let mut ok_rounds = 0u32;
        for n in 1..=args.repeat.max(1) {
            if n > 1 {
                std::thread::sleep(args.interval);
            }
            let cpu0 = cpu_time();
            let started = Instant::now();
            let result = cap.capture_each();
            let wall = started.elapsed();
            let cpu = cpu_time().saturating_sub(cpu0);
            let (ws, pv) = memory();
            match result {
                Err(e) => println!(
                    "#{n:<3} unix {} unavailable/failed after {wall:?}: {e} (unavailable={})",
                    unix_now(),
                    e.is_unavailable()
                ),
                Ok(results) => {
                    ok_rounds += 1;
                    cpu_total += cpu;
                    wall_total += wall;
                    for d in &results {
                        if args.quiet {
                            continue;
                        }
                        match &d.result {
                            Ok(frame) => {
                                let px = frame.pixels();
                                let nonzero = px
                                    .as_chunks::<4>()
                                    .0
                                    .iter()
                                    .filter(|p| p[0] | p[1] | p[2] != 0)
                                    .count();
                                println!(
                                    "     display {:>3} {:?}: {}x{} {:?} in {:?} (non-black px {:.1}%)",
                                    d.display_id,
                                    d.backend,
                                    frame.width(),
                                    frame.height(),
                                    frame.format(),
                                    d.latency,
                                    100.0 * nonzero as f64 / (px.len() / 4).max(1) as f64
                                );
                            }
                            Err(e) => println!(
                                "     display {:>3} {:?}: error after {:?}: {e}",
                                d.display_id, d.backend, d.latency
                            ),
                        }
                    }
                    let frames = results.iter().filter(|d| d.result.is_ok()).count();
                    println!(
                        "#{n:<3} {frames} frame(s), wall {wall:?}, cpu {cpu:?}, working set {:.1} MiB, private {:.1} MiB, duplications opened {}",
                        mib(ws),
                        mib(pv),
                        cap.duplications_opened()
                    );
                    // Dropping `results` zeroizes every frame.
                }
            }
        }
        if ok_rounds > 0 {
            println!(
                "== mean over {ok_rounds} capture(s): wall {:?}, cpu {:?} ==",
                wall_total / ok_rounds,
                cpu_total / ok_rounds
            );
        }
        Ok(())
    }
}
