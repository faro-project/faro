//! Shows the agent's menu-bar icon and a sample monitoring notice, for
//! checking the UI without a service:
//!
//! ```text
//! cargo run -p faro-platform-macos --example session_ui [SECONDS]
//! ```
//!
//! The notice appears after a second; the process exits after SECONDS
//! (default 30) or when asked to quit.

#[cfg(target_os = "macos")]
fn main() {
    use faro_platform_macos::ui::{MainThreadMarker, SessionUi};
    use std::time::Duration;

    let secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let mtm = MainThreadMarker::new().expect("main runs on the main thread");
    let ui = SessionUi::new(mtm, || {
        eprintln!("asked to quit");
        std::process::exit(0);
    });
    let handle = ui.handle();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(1));
        handle.show_notice(
            "This computer is monitored by Faro",
            "Every account on this computer (\"Example Mac\") is monitored by Faro for a \
             member of Example Instance. Screenshots are blurred on this computer and \
             shared, encrypted, only with the member and their 2 allies.",
        );
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("time is up");
        std::process::exit(0);
    });
    ui.run();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the session UI exists on macOS only");
}
