//! Shows the agent's menu-bar icon and a sample monitoring notice, for
//! checking the UI without a service:
//!
//! ```text
//! cargo run -p faro-platform-macos --example session_ui [SECONDS]
//! ```
//!
//! The notice appears after a second; the process exits after SECONDS
//! (default 30) or when asked to quit. The menu shows a sample status
//! ("Screen Recording is off", with its fix; `FARO_SAMPLE_STATUS=ok` for
//! "Monitoring"), "Open Faro" and "About Faro…".

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
    // A sample status menu: a problem with its fix, "Open Faro" and About.
    // `FARO_SAMPLE_STATUS=ok` shows "Monitoring" instead.
    let problem = std::env::var("FARO_SAMPLE_STATUS").as_deref() != Ok("ok");
    handle.set_status(faro_platform_macos::ui::StatusMenu {
        line: if problem {
            "Screen Recording is off".into()
        } else {
            "Monitoring".into()
        },
        detail: if problem {
            "Faro can't see the screen, and your allies are told. Open System Settings \
             \u{2192} Privacy & Security \u{2192} Screen & System Audio Recording and switch on \
             Faro Agent."
                .into()
        } else {
            "Faro is working on this Mac. There is nothing to do.".into()
        },
        problem,
        fix: problem.then(|| faro_platform_macos::ui::StatusFix {
            label: "Open Screen Recording Settings\u{2026}".into(),
            url: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
                .into(),
        }),
        web_app: Some("https://faro.example.org/".into()),
        about_title: "About Faro".into(),
        about_body: "Faro Agent 0.1.0-beta.1 (sample)\nInstance: Example Instance \
                     (https://faro.example.org/)\n\nThird-party notices are in \
                     /Library/Faro/notices."
            .into(),
        report: Some(faro_platform_macos::ui::ReportProblem {
            title: "Report a problem".into(),
            body: "Sample: open Terminal and run the command below.\n    \
                   sudo /Library/Faro/bin/faro-service diagnose"
                .into(),
            copy: "Copy Command".into(),
            command: "sudo /Library/Faro/bin/faro-service diagnose".into(),
        }),
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
