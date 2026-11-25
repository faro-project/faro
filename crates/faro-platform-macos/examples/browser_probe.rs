//! Checks the browser tab URL path by hand (`faro_platform_macos::browser`).
//!
//! Prints what the agent would send: the frontmost app's bundle id and the
//! reduced tab URL (`scheme://host/`), or why there is none. Run it from a
//! terminal that has Accessibility, then switch to a browser.
//!
//! ```text
//! cargo run -p faro-platform-macos --example browser_probe -- [options]
//!   --repeat N         read N times (default 15)
//!   --interval SECS    seconds between reads (default 2)
//!   --pid PID          read this process instead of the frontmost app
//!   --as BROWSER       with --pid: safari, chrome, edge, brave or arc
//!                      (default safari)
//! ```
//!
//! It prints to the terminal only and writes nothing else.

#[cfg(target_os = "macos")]
fn main() {
    if let Err(e) = probe::run() {
        eprintln!("browser_probe: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("browser_probe only runs on macOS");
}

#[cfg(target_os = "macos")]
mod probe {
    use std::time::{Duration, Instant};

    use faro_platform::ForegroundInfo;
    use faro_platform_macos::browser::{self, Browser};
    use faro_platform_macos::{accessibility_trusted, MacForeground};

    struct Args {
        repeat: u32,
        interval: Duration,
        pid: Option<i32>,
        browser: Browser,
    }

    fn parse_args() -> Result<Args, String> {
        let mut a = Args {
            repeat: 15,
            interval: Duration::from_secs(2),
            pid: None,
            browser: Browser::Safari,
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
                "--pid" => a.pid = Some(value("--pid")?.parse().map_err(|e| format!("{e}"))?),
                "--as" => {
                    a.browser = match value("--as")?.as_str() {
                        "safari" => Browser::Safari,
                        "chrome" => Browser::Chrome,
                        "edge" => Browser::Edge,
                        "brave" => Browser::Brave,
                        "arc" => Browser::Arc,
                        other => return Err(format!("unknown browser {other:?}")),
                    }
                }
                other => return Err(format!("unknown option {other:?}")),
            }
        }
        Ok(a)
    }

    pub fn run() -> Result<(), String> {
        let args = parse_args()?;
        println!("accessibility trusted: {}", accessibility_trusted());
        let fg = MacForeground::new();
        for i in 0..args.repeat {
            if i > 0 {
                std::thread::sleep(args.interval);
            }
            let started = Instant::now();
            let line = match args.pid {
                Some(pid) => {
                    let url = browser::tab_url(pid, args.browser);
                    format!("pid {pid} as {:?}: {}", args.browser, show(url.as_deref()))
                }
                None => {
                    let app = fg.active_app().map(|a| a.id);
                    let kind = app.as_deref().and_then(Browser::from_bundle_id);
                    let ctx = fg.browser();
                    let url = ctx.as_ref().and_then(|c| c.url.as_deref());
                    format!(
                        "{} ({}): {}",
                        app.as_deref().unwrap_or("no frontmost app"),
                        kind.map_or("not a supported browser".to_owned(), |b| format!("{b:?}")),
                        show(url)
                    )
                }
            };
            println!("{line}  [{} ms]", started.elapsed().as_millis());
        }
        Ok(())
    }

    fn show(url: Option<&str>) -> &str {
        url.unwrap_or("no URL")
    }
}
