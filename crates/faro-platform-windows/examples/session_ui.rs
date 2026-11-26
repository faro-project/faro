//! Shows the agent's tray icon and a sample monitoring notice, for checking
//! the UI without a service:
//!
//! ```text
//! cargo run -p faro-platform-windows --example session_ui [SECONDS]
//! cargo run -p faro-platform-windows --example session_ui open-url "faro://enroll?i=x&c=y"
//! cargo run -p faro-platform-windows --example session_ui register-url-scheme
//! cargo run -p faro-platform-windows --example session_ui unregister-url-scheme
//! ```
//!
//! The notice appears after a second (`FARO_SAMPLE_NOTICE=0` skips it); the
//! process exits after SECONDS (default 30) or when the session ends. The
//! menu shows a sample status (a problem with its fix;
//! `FARO_SAMPLE_STATUS=ok` for "Monitoring"), "Open Faro", "Report a
//! problem…" and "About Faro…". "Enroll this computer…", or a link sent
//! with `open-url` from a second process, shows the enrollment windows
//! with sample text (nothing is enrolled).
//!
//! `register-url-scheme` registers this example for `faro://` links in
//! the current account only (HKCU), so clicking a link exercises the real
//! path; `unregister-url-scheme` removes it again.

#[cfg(windows)]
fn main() {
    use faro_platform_windows::ui::{self, url, MainThreadMarker, SessionUi};
    use std::time::Duration;

    tracing_subscriber_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some(url::OPEN_URL_COMMAND) => {
            let link = args.get(1).cloned().unwrap_or_default();
            match url::forward_link(&link, url::FORWARD_WAIT) {
                Ok(()) => eprintln!("forwarded the link"),
                Err(e) => {
                    eprintln!("could not forward the link: {e}");
                    ui::show_message("Faro can't open this link", &e.to_string(), true);
                    std::process::exit(1);
                }
            }
            return;
        }
        Some("register-url-scheme") => {
            let exe = std::env::current_exe().expect("own path");
            url::register_for_current_user(&exe).expect("register");
            eprintln!("faro:// now opens {} for this account", exe.display());
            return;
        }
        Some("unregister-url-scheme") => {
            url::unregister_for_current_user().expect("unregister");
            eprintln!("removed this account's faro:// registration");
            return;
        }
        _ => {}
    }

    let secs: u64 = args.first().and_then(|s| s.parse().ok()).unwrap_or(30);
    let mtm = MainThreadMarker::new().expect("main runs first");
    let ui = SessionUi::new(mtm, || {
        eprintln!("asked to quit");
        std::process::exit(0);
    });
    eprintln!(
        "tray icon created (first in session: {})",
        ui.is_first_in_session()
    );
    let handle = ui.handle();
    ui.on_enroll(move |link| {
        eprintln!("enroll requested (from a link: {})", link.is_some());
        std::thread::spawn(move || {
            if link.is_none() {
                let fields = handle.ask_enroll_target(&ui::TwoFields {
                    title: "Enroll this computer".into(),
                    body: "Paste the enrollment link from the Computers page of your Faro \
                           web app. Or type your Faro address and the code shown there."
                        .into(),
                    first_label: "Enrollment link or Faro address".into(),
                    first_placeholder: "faro://enroll?\u{2026}  or  faro.example.org".into(),
                    second_label: "Code (not needed with a link)".into(),
                    second_placeholder: "ABCD-1234".into(),
                    ok: "Continue".into(),
                    cancel: "Cancel".into(),
                });
                eprintln!("fields given: {}", fields.is_some());
                if fields.is_none() {
                    return;
                }
            }
            let yes = handle.confirm(
                "Enroll this computer with \u{201c}Example Instance\u{201d}?",
                "Address: https://faro.example.org/\nThis computer will be called \
                 \u{201c}Example PC\u{201d}.\n\nFaro will monitor every account on this \
                 computer, including accounts created later.\nAccounts: alex, sam\n\nOnly \
                 continue if this is your Faro instance. Next, an administrator of this \
                 computer approves in the Windows prompt.",
                "Enroll",
                "Cancel",
            );
            if yes {
                handle.message(
                    "This computer is enrolled",
                    "Sample only: nothing was enrolled.\n\n0123 4567 89ab cdef",
                    false,
                );
            }
        });
    });
    let problem = std::env::var("FARO_SAMPLE_STATUS").as_deref() != Ok("ok");
    handle.set_status(ui::StatusMenu {
        line: if problem {
            "Can't reach Example Instance".into()
        } else {
            "Monitoring".into()
        },
        detail: if problem {
            "Faro keeps checking this screen and sends the reports when the instance is \
             reachable again. Check that this computer is online."
                .into()
        } else {
            "Faro is working on this computer. There is nothing to do.".into()
        },
        problem,
        fix: problem.then(|| ui::StatusFix {
            label: "Open Network Settings\u{2026}".into(),
            url: "ms-settings:network-status".into(),
        }),
        web_app: Some("https://faro.example.org/".into()),
        about_title: "About Faro".into(),
        about_body: "Faro Agent 0.1.0-beta.1 (sample)\nInstance: Example Instance \
                     (https://faro.example.org/)\n\nThird-party notices are in \
                     C:\\Program Files\\Faro\\notices."
            .into(),
        report: Some(ui::ReportProblem {
            title: "Report a problem".into(),
            body: "Sample: open Terminal as administrator and run the command below.\n    \
                   \"C:\\Program Files\\Faro\\faro-service.exe\" diagnose"
                .into(),
            copy: "Copy Command".into(),
            command: "\"C:\\Program Files\\Faro\\faro-service.exe\" diagnose".into(),
        }),
    });
    let notice = std::env::var("FARO_SAMPLE_NOTICE").as_deref() != Ok("0");
    std::thread::spawn(move || {
        if notice {
            std::thread::sleep(Duration::from_secs(1));
            handle.show_notice(
                "This computer is monitored by Faro",
                "Every account on this computer (\"Example PC\") is monitored by Faro for a \
                 member of Example Instance. Screenshots are blurred on this computer and \
                 shared, encrypted, only with the member and their 2 allies.",
            );
        }
        std::thread::sleep(Duration::from_secs(secs));
        eprintln!("time is up");
        std::process::exit(0);
    });
    ui.run();
}

/// Logs to stderr at `FARO_LOG` (default `info`).
#[cfg(windows)]
fn tracing_subscriber_init() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("FARO_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("the session UI exists on Windows only");
}
