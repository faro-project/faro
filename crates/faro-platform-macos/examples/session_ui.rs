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
    // "Enroll this computer…" shows the enrollment windows with sample
    // text (no service, nothing is enrolled), to check their layout.
    ui.on_enroll(move |link| {
        std::thread::spawn(move || {
            let fields = handle.ask_enroll_target(&faro_platform_macos::ui::TwoFields {
                title: "Enroll this computer".into(),
                body: "Paste the enrollment link from the Computers page of your Faro web app. \
                       Or type your Faro address and the code shown there."
                    .into(),
                first_label: "Enrollment link or Faro address".into(),
                first_placeholder: "faro://enroll?\u{2026}  or  faro.example.org".into(),
                second_label: "Code (not needed with a link)".into(),
                second_placeholder: "ABCD-1234".into(),
                ok: "Continue".into(),
                cancel: "Cancel".into(),
            });
            eprintln!("link {link:?}, fields {fields:?}");
            if fields.is_none() && link.is_none() {
                return;
            }
            let yes = handle.confirm(
                "Enroll this computer with \u{201c}Example Instance\u{201d}?",
                "Address: https://faro.example.org/\n\nFaro will monitor every account on \
                 this computer, including accounts created later.\nAccounts: alex, sam",
                "Enroll",
                "Cancel",
            );
            if yes {
                handle.message(
                    "This computer is enrolled",
                    "Sample only: nothing was enrolled.",
                    false,
                );
            }
        });
    });
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
