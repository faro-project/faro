//! The launchd plists the `.pkg` installs are checked in under
//! `installers/macos/payload` so the package build needs no Rust tool to
//! produce them. This test keeps them identical to what the generator
//! (`pkg_daemon_job`, `pkg_agent_job`) produces. After changing either:
//!
//! ```text
//! FARO_BLESS=1 cargo test -p faro-platform-macos --test installer_plists
//! ```
#![cfg(target_os = "macos")]

use faro_platform_macos::{pkg_agent_job, pkg_daemon_job, pkg_layout, LaunchdJob};
use std::path::PathBuf;

fn payload(installed: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../installers/macos/payload")
        .join(installed.trim_start_matches('/'))
}

fn check(job: LaunchdJob, installed: &str) {
    let want = job.to_plist_xml().expect("valid job");
    let path = payload(installed);
    if std::env::var_os("FARO_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &want).unwrap();
        return;
    }
    let have = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with FARO_BLESS=1)", path.display()));
    assert_eq!(
        have,
        want,
        "{} is out of date; run with FARO_BLESS=1",
        path.display()
    );
}

#[test]
fn checked_in_plists_match_the_generator() {
    check(pkg_daemon_job(), pkg_layout::DAEMON_PLIST);
    check(pkg_agent_job(), pkg_layout::AGENT_PLIST);
}

/// `Faro Agent.app` opens `faro://enroll` links (issue #62): its
/// Info.plist registers the `faro` scheme, under the bundle id the service's
/// code-signing requirement names.
#[test]
fn the_agent_bundle_opens_faro_links() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../installers/macos/Info.plist.in");
    let info: plist::Dictionary = plist::from_file(&path).expect("Info.plist.in parses");
    assert_eq!(
        info.get("CFBundleIdentifier").and_then(|v| v.as_string()),
        Some("org.faro.agent")
    );
    let schemes: Vec<&str> = info
        .get("CFBundleURLTypes")
        .and_then(|v| v.as_array())
        .expect("CFBundleURLTypes")
        .iter()
        .filter_map(|t| t.as_dictionary()?.get("CFBundleURLSchemes")?.as_array())
        .flatten()
        .filter_map(|s| s.as_string())
        .collect();
    assert_eq!(schemes, ["faro"]);
}

#[test]
fn the_agent_runs_in_every_gui_session() {
    let xml = pkg_agent_job().to_plist_xml().unwrap();
    // A global LaunchAgent limited to Aqua: one copy per account's GUI
    // session, kept alive by launchd.
    assert!(xml.contains("<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>"));
    assert!(xml.contains(pkg_layout::AGENT_PROGRAM));
    assert!(pkg_layout::AGENT_PLIST.starts_with("/Library/LaunchAgents/"));
}
