//! Checks the browser tab URL path by hand (`faro_platform_windows::browser`).
//!
//! By default it reads the foreground window, as the agent does, every
//! `--interval` seconds: run it, then switch to a browser. With `--all` it
//! reads every visible top-level window of a supported browser instead, so
//! no window has to be brought to the front.
//!
//! ```text
//! cargo run -p faro-platform-windows --example browser_probe -- [options]
//!   --repeat N         read N times (default 15)
//!   --interval SECS    seconds between reads (default 2)
//!   --all              read every supported browser window, not just the
//!                      foreground one
//!   --dump             also print the UI Automation walk: depth, control
//!                      type, class name, automation id and the decision
//!                      for each node (never names or values)
//!   --show-url         print the reduced URL (`scheme://host/`); without
//!                      it only whether one was found is printed
//! ```
//!
//! It prints to the terminal only and writes nothing else.

#[cfg(windows)]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("browser_probe: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("browser_probe only runs on Windows");
}

#[cfg(windows)]
mod probe {
    use std::time::{Duration, Instant};

    use faro_platform_windows::browser::{self, Browser, Visit};
    use faro_platform_windows::foreground::{exe_id, foreground_window, window_process};
    use windows::core::BOOL;
    use windows::Win32::Foundation::{HWND, LPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindow, IsWindowVisible, GW_OWNER,
    };

    struct Args {
        repeat: u32,
        interval: Duration,
        all: bool,
        dump: bool,
        show_url: bool,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            repeat: 15,
            interval: Duration::from_secs(2),
            all: false,
            dump: false,
            show_url: false,
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
                "--all" => a.all = true,
                "--dump" => a.dump = true,
                "--show-url" => a.show_url = true,
                other => return Err(format!("unknown option {other:?}")),
            }
        }
        Ok(a)
    }

    unsafe extern "system" fn collect(hwnd: HWND, data: LPARAM) -> BOOL {
        // SAFETY: `data` is the `&mut Vec<HWND>` passed by `browser_windows`.
        let out = unsafe { &mut *(data.0 as *mut Vec<HWND>) };
        // SAFETY: plain queries on a window handle.
        let visible = unsafe { IsWindowVisible(hwnd).as_bool() };
        // Owned windows are popups and menus, not browser windows.
        let owned = unsafe { GetWindow(hwnd, GW_OWNER) }.is_ok_and(|o| !o.0.is_null());
        if visible && !owned {
            out.push(hwnd);
        }
        true.into()
    }

    /// Visible, unowned top-level windows of supported browsers.
    fn browser_windows() -> Vec<(HWND, u32, Browser)> {
        let mut all: Vec<HWND> = Vec::new();
        // SAFETY: the callback only touches `all` through the LPARAM.
        let _ = unsafe { EnumWindows(Some(collect), LPARAM(&mut all as *mut Vec<HWND> as isize)) };
        all.into_iter()
            .filter_map(|h| {
                let (pid, path) = window_process(h)?;
                let b = Browser::from_exe_name(&exe_id(&path)?)?;
                Some((h, pid, b))
            })
            .collect()
    }

    fn read(hwnd: HWND, label: &str, b: Browser, args: &Args) {
        if args.dump {
            println!("  walk of {label}:");
            let mut n = 0usize;
            let found = browser::debug_walk(hwnd, b, |depth, node, visit| {
                n += 1;
                if visit != Visit::Skip || node.control_type == 50004 || depth <= 3 {
                    println!(
                        "    {:indent$}type={} class={:?} id={:?} focus={} -> {:?}",
                        "",
                        node.control_type,
                        node.class_name,
                        node.automation_id,
                        node.has_focus,
                        visit,
                        indent = depth * 2
                    );
                }
            });
            println!("  {n} nodes visited, address field found: {found}");
        }
        let started = Instant::now();
        let url = browser::tab_url(hwnd, b);
        let ms = started.elapsed().as_millis();
        let shown = match (&url, args.show_url) {
            (Some(u), true) => u.clone(),
            (Some(u), false) => format!("<reduced URL, {} chars>", u.len()),
            (None, _) => "no URL".to_owned(),
        };
        println!("{label}: {shown}  [{ms} ms]");
    }

    pub fn run() -> Result<(), String> {
        let args = parse_args()?;
        for i in 0..args.repeat.max(1) {
            if i > 0 {
                std::thread::sleep(args.interval);
            }
            if args.all {
                let wins = browser_windows();
                if wins.is_empty() {
                    println!("no supported browser windows");
                }
                for (h, pid, b) in wins {
                    read(h, &format!("{b:?} pid {pid}"), b, &args);
                }
                continue;
            }
            let Some(h) = foreground_window() else {
                println!("no foreground window");
                continue;
            };
            let app = window_process(h).and_then(|(_, p)| exe_id(&p));
            match app.as_deref().and_then(Browser::from_exe_name) {
                Some(b) => read(
                    h,
                    &format!("{} ({b:?})", app.as_deref().unwrap_or("?")),
                    b,
                    &args,
                ),
                None => println!(
                    "{}: not a supported browser",
                    app.as_deref().unwrap_or("unknown app")
                ),
            }
        }
        Ok(())
    }
}
