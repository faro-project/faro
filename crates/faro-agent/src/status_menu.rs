//! The words of the menu-bar status menu (issue #89): what Faro is doing,
//! and what to do when something is wrong.
//!
//! The agent learns the state two ways:
//!
//! * **Connected** to the service: the service sends
//!   [`MemberStatus`] (`ServiceMsg::Status`), a view scoped to this
//!   session and this computer, after `Welcome` and whenever it changes.
//! * **Not connected**: the service only opens the agent's socket once the
//!   computer is enrolled and approved, so the agent asks the enroll
//!   socket's `Status` instead ([`Enrollment`]), which says whether the
//!   computer is enrolled and approved.
//!
//! [`status_menu`] and [`about`] turn that into text. They are pure
//! functions, so the text is tested here; the menu itself is AppKit
//! (`faro_platform_macos::ui`). Nothing here, and nothing on the menu,
//! changes what the service does: the menu has no way to stop monitoring,
//! pause or hide anything.

use faro_ipc::status::{CaptureState, ServicePhase};
use faro_ipc::{EnrollStatus, MemberStatus, WirePermissionState};

use crate::notice::SCREEN_RECORDING_OFF;

/// What the agent knows of the service.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Seen {
    /// Nothing yet: the agent has just started.
    #[default]
    Starting,
    /// The service's latest status for this session.
    Connected(MemberStatus),
    /// No session connection; what the enroll socket said.
    NotConnected(Enrollment),
}

/// The enroll socket's answer, when the agent can't connect to the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enrollment {
    /// The computer is not enrolled: Faro monitors nothing.
    NotEnrolled,
    /// Enrolled, waiting for the member to approve it in the web app.
    AwaitingApproval { name: String, url: String },
    /// Enrolled and approved, but the agent's connection isn't up (the
    /// service is starting, or something is wrong).
    Approved { name: String, url: String },
    /// The service doesn't answer at all.
    NoService,
}

impl Enrollment {
    /// From the enroll socket's `Status`, or why it didn't answer.
    pub fn from_status(answer: Result<&EnrollStatus, &str>) -> Self {
        let Ok(s) = answer else {
            return Enrollment::NoService;
        };
        let name = s.instance_name.clone().unwrap_or_default();
        let url = s.instance_url.clone().unwrap_or_default();
        match (s.enrolled, s.endorsed) {
            (false, _) => Enrollment::NotEnrolled,
            (true, false) => Enrollment::AwaitingApproval { name, url },
            (true, true) => Enrollment::Approved { name, url },
        }
    }
}

/// A menu item that fixes the problem: its title, and the URL it opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    pub label: String,
    pub url: String,
}

/// The status part of the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMenu {
    /// The status line ("Monitoring", "Screen Recording is off").
    pub line: String,
    /// What it means and what to do, shown when the line is clicked.
    pub hint: Option<String>,
    /// The item that fixes it, if one can.
    pub fix: Option<Fix>,
    /// The instance's web app, for "Open Faro", if known.
    pub web_app: Option<String>,
    /// The line is a problem (shown as a warning).
    pub problem: bool,
}

/// Shown when the status line is clicked and nothing needs doing.
pub const NOTHING_TO_DO: &str = "Faro is working on this Mac. There is nothing to do.";

impl StatusMenu {
    /// What the line means and what to do, for when it is clicked.
    pub fn detail(&self) -> &str {
        self.hint.as_deref().unwrap_or(NOTHING_TO_DO)
    }
}

/// The About window's title.
pub const ABOUT_TITLE: &str = "About Faro";
/// Where the package installs the third-party notices
/// (`faro_platform_macos::pkg_layout::NOTICES_DIR`).
pub const NOTICES_DIR: &str = "/Library/Faro/notices";

/// The System Settings pane for Accessibility.
pub const ACCESSIBILITY_SETTINGS: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility";

/// Captures failing this many times in a row is shown as a problem. A
/// single failure is often a display waking up.
pub const FAILING_AFTER: u32 = 3;

/// The status menu for `seen`. `now_ms` and `utc_offset_secs` (local time
/// minus UTC) only format a pause's end.
pub fn status_menu(seen: &Seen, now_ms: i64, utc_offset_secs: i64) -> StatusMenu {
    match seen {
        Seen::Starting => plain("Connecting to the Faro service\u{2026}", None),
        Seen::Connected(m) => connected(m, now_ms, utc_offset_secs),
        Seen::NotConnected(e) => not_connected(e),
    }
}

fn plain(line: &str, hint: Option<String>) -> StatusMenu {
    StatusMenu {
        line: line.to_owned(),
        hint,
        fix: None,
        web_app: None,
        problem: false,
    }
}

fn problem(line: impl Into<String>, hint: impl Into<String>) -> StatusMenu {
    StatusMenu {
        line: line.into(),
        hint: Some(hint.into()),
        fix: None,
        web_app: None,
        problem: true,
    }
}

/// The instance's name, or words for it when unknown.
fn instance(name: &str) -> String {
    if name.trim().is_empty() {
        "your Faro instance".to_owned()
    } else {
        format!("\u{201c}{name}\u{201d}")
    }
}

fn connected(m: &MemberStatus, now_ms: i64, offset: i64) -> StatusMenu {
    let name = instance(&m.instance_name);
    let stopping = matches!(m.phase, ServicePhase::ShuttingDown | ServicePhase::Stopped)
        || m.capture == Some(CaptureState::Stopped);
    let mut menu = if stopping {
        plain(
            "Faro is stopping",
            Some(
                "The Faro service is stopping, for an update or a restart. It starts again \
                 by itself. If this lasts more than a few minutes, restart the Mac."
                    .to_owned(),
            ),
        )
    } else if m.identity_mismatch {
        problem(
            format!("Faro stopped sending to {name}"),
            format!(
                "{name} doesn't have the identity this Mac was enrolled with, so Faro sends \
                 it nothing. Your allies will see that this Mac stopped checking in. Tell \
                 whoever runs your instance."
            ),
        )
    } else if m.screen_recording == Some(WirePermissionState::Denied) {
        StatusMenu {
            fix: Some(Fix {
                label: "Open Screen Recording Settings\u{2026}".to_owned(),
                url: SCREEN_RECORDING_OFF.url.to_owned(),
            }),
            ..problem(
                "Screen Recording is off",
                "Faro can't see the screen, and your allies are told. Open System Settings \
                 \u{2192} Privacy & Security \u{2192} Screen & System Audio Recording and switch \
                 on Faro Agent. If it is on already (after Faro was reinstalled, for \
                 example), select it, remove it with the \u{2212} button and add it again.",
            )
        }
    } else if m.consecutive_failures >= FAILING_AFTER {
        problem(
            "Faro can't take screenshots",
            "Screenshots keep failing on this Mac, and your allies are told if this goes \
             on. Restart the Mac. If it still says so, tell whoever runs your instance.",
        )
    } else if m.unreachable_since_ms.is_some() {
        problem(
            format!("Can't reach {name}"),
            format!(
                "Check that this Mac is online. Faro keeps monitoring and keeps what it \
                 records on this Mac, encrypted, and sends it once {name} answers. If this \
                 lasts, your allies see that this Mac stopped checking in."
            ),
        )
    } else if m.capture == Some(CaptureState::Paused) {
        let line = match m.paused_until_ms {
            Some(until) => format!("Paused until {}", clock_time(until, now_ms, offset)),
            None => "Paused".to_owned(),
        };
        let hint = if m.paused_until_ms.is_some() {
            "Monitoring is paused, and your allies were told. It starts again by itself."
        } else {
            "Monitoring is paused, and your allies were told."
        };
        plain(&line, Some(hint.to_owned()))
    } else if m.capture == Some(CaptureState::NotStarted) {
        plain("Starting\u{2026}", None)
    } else if m.accessibility == Some(false) {
        StatusMenu {
            fix: Some(Fix {
                label: "Open Accessibility Settings\u{2026}".to_owned(),
                url: ACCESSIBILITY_SETTINGS.to_owned(),
            }),
            ..plain(
                "Monitoring",
                Some(
                    "Accessibility is off for Faro Agent, so Faro can't tell which website \
                     a browser shows. Open System Settings \u{2192} Privacy & Security \u{2192} \
                     Accessibility and switch on Faro Agent."
                        .to_owned(),
                ),
            )
        }
    } else if m.updates_failing {
        plain(
            "Monitoring",
            Some(
                "Faro couldn't check for updates. It tries again later. If this lasts, \
                 tell whoever runs your instance."
                    .to_owned(),
            ),
        )
    } else {
        plain("Monitoring", None)
    };
    menu.web_app = web_app_url(&m.instance_url, "");
    menu
}

fn not_connected(e: &Enrollment) -> StatusMenu {
    match e {
        Enrollment::NotEnrolled => plain(
            "Not enrolled",
            Some(
                "Faro monitors nothing on this Mac yet. To enroll it, create an enrollment \
                 code on the Computers page of your Faro web app, then choose Enroll this \
                 computer\u{2026} in this menu and paste the link."
                    .to_owned(),
            ),
        ),
        Enrollment::AwaitingApproval { name, url } => {
            let computers = web_app_url(url, "computers");
            StatusMenu {
                fix: computers.clone().map(|url| Fix {
                    label: "Open the Computers Page\u{2026}".to_owned(),
                    url,
                }),
                web_app: web_app_url(url, ""),
                ..plain(
                    "Waiting for approval in the web app",
                    Some(format!(
                        "This Mac is enrolled with {}. Open the Computers page of the web \
                         app, check that it shows the same code this Mac showed, and \
                         approve the computer. Monitoring starts then.",
                        instance(name)
                    )),
                )
            }
        }
        Enrollment::Approved { url, .. } => StatusMenu {
            web_app: web_app_url(url, ""),
            ..plain(
                "Connecting to the Faro service\u{2026}",
                Some(
                    "If this lasts more than a few minutes, log out and back in, or restart \
                     the Mac. Your allies are told if this account goes unmonitored."
                        .to_owned(),
                ),
            )
        },
        Enrollment::NoService => problem(
            "The Faro service isn't running",
            "Restart the Mac. If it still says so, tell whoever runs your instance.",
        ),
    }
}

/// The page `page` of the web app at `instance_url`, if that is an
/// `https://` (or `http://`) address with nothing odd in it. The address
/// comes from the service, which took it from the enrollment, but the menu
/// opens it with the system's default handler, so it is checked anyway.
pub fn web_app_url(instance_url: &str, page: &str) -> Option<String> {
    let url = instance_url;
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))?;
    let host_end = rest.find('/').unwrap_or(rest.len());
    if host_end == 0
        || url.len() > 2048
        || url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '<' | '>' | '\\'))
    {
        return None;
    }
    let base = url.trim_end_matches('/');
    Some(if page.is_empty() {
        format!("{base}/")
    } else {
        format!("{base}/{page}")
    })
}

/// The About window: its title and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct About {
    pub title: String,
    pub body: String,
}

/// The About window for this agent (`agent_version`) and what it knows of
/// the service.
pub fn about(agent_version: &str, seen: &Seen) -> About {
    let mut lines = vec![format!("Faro Agent {agent_version}")];
    let (name, url) = match seen {
        Seen::Connected(m) => {
            if !m.service_version.is_empty() {
                lines.push(format!("Faro service {}", m.service_version));
            }
            (m.instance_name.as_str(), m.instance_url.as_str())
        }
        Seen::NotConnected(
            Enrollment::AwaitingApproval { name, url } | Enrollment::Approved { name, url },
        ) => (name.as_str(), url.as_str()),
        _ => ("", ""),
    };
    match (name.trim().is_empty(), url.trim().is_empty()) {
        (false, false) => lines.push(format!("Instance: {name} ({url})")),
        (false, true) => lines.push(format!("Instance: {name}")),
        (true, false) => lines.push(format!("Instance: {url}")),
        (true, true) => lines.push("Instance: not enrolled".to_owned()),
    }
    lines.push(String::new());
    lines.push(
        "Faro is free software under the Apache License 2.0. It includes third-party \
         software, whose licences and notices are in "
            .to_owned()
            + NOTICES_DIR
            + ".",
    );
    About {
        title: ABOUT_TITLE.to_owned(),
        body: lines.join("\n"),
    }
}

/// `at_ms` as a local clock time ("15:40"), with the day when it isn't
/// today ("Tue 15:40", or "3 Dec 15:40" a week or more away).
pub fn clock_time(at_ms: i64, now_ms: i64, utc_offset_secs: i64) -> String {
    let local = |ms: i64| ms.div_euclid(1000) + utc_offset_secs;
    let (at, now) = (local(at_ms), local(now_ms));
    let (day, secs) = (at.div_euclid(86_400), at.rem_euclid(86_400));
    let time = format!("{:02}:{:02}", secs / 3600, secs % 3600 / 60);
    let days_away = day - now.div_euclid(86_400);
    if days_away == 0 {
        time
    } else if (1..7).contains(&days_away) {
        const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        // 1970-01-01 was a Thursday.
        format!("{} {time}", WEEKDAYS[day.rem_euclid(7) as usize])
    } else {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let (_, month, dom) = civil_from_days(day);
        format!("{dom} {} {time}", MONTHS[(month - 1) as usize])
    }
}

/// (year, month 1–12, day 1–31) of a day count since 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The local time's offset from UTC at `at_ms`, in seconds.
#[cfg(unix)]
pub fn local_utc_offset_secs(at_ms: i64) -> i64 {
    let t: libc::time_t = (at_ms.div_euclid(1000)) as libc::time_t;
    // SAFETY: `tm` is plain data that `localtime_r` fills in; both
    // pointers are valid for the call.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> MemberStatus {
        MemberStatus {
            service_version: "0.1.0-beta.1".into(),
            phase: ServicePhase::Running,
            instance_name: "Sam's Faro".into(),
            instance_url: "https://faro.example.org/".into(),
            capture: Some(CaptureState::Active),
            screen_recording: Some(WirePermissionState::Granted),
            accessibility: Some(true),
            ..MemberStatus::default()
        }
    }

    fn menu(m: MemberStatus) -> StatusMenu {
        status_menu(&Seen::Connected(m), 0, 0)
    }

    #[test]
    fn monitoring() {
        let s = menu(running());
        assert_eq!(s.line, "Monitoring");
        assert_eq!(s.hint, None);
        assert_eq!(s.fix, None);
        assert!(!s.problem);
        assert_eq!(s.web_app.as_deref(), Some("https://faro.example.org/"));
        // Idle, locked or another session at the screen: still monitoring.
        for capture in [
            Some(CaptureState::Idle),
            Some(CaptureState::Locked),
            Some(CaptureState::Asleep),
            None,
        ] {
            assert_eq!(
                menu(MemberStatus {
                    capture,
                    ..running()
                })
                .line,
                "Monitoring"
            );
        }
    }

    #[test]
    fn screen_recording_off_links_to_its_settings() {
        let s = menu(MemberStatus {
            screen_recording: Some(WirePermissionState::Denied),
            consecutive_failures: 9,
            ..running()
        });
        assert_eq!(s.line, "Screen Recording is off");
        assert!(s.problem);
        assert!(s.hint.unwrap().contains("Screen & System Audio Recording"));
        let fix = s.fix.unwrap();
        assert_eq!(fix.url, SCREEN_RECORDING_OFF.url);
        assert!(fix.label.starts_with("Open Screen Recording Settings"));
    }

    #[test]
    fn failing_captures_and_an_unreachable_instance() {
        let s = menu(MemberStatus {
            consecutive_failures: FAILING_AFTER,
            ..running()
        });
        assert_eq!(s.line, "Faro can't take screenshots");
        assert!(s.problem);
        assert_eq!(
            menu(MemberStatus {
                consecutive_failures: FAILING_AFTER - 1,
                ..running()
            })
            .line,
            "Monitoring"
        );
        let s = menu(MemberStatus {
            unreachable_since_ms: Some(1),
            ..running()
        });
        assert_eq!(s.line, "Can't reach \u{201c}Sam's Faro\u{201d}");
        assert!(s.hint.unwrap().contains("online"));
        let s = menu(MemberStatus {
            unreachable_since_ms: Some(1),
            instance_name: String::new(),
            ..running()
        });
        assert_eq!(s.line, "Can't reach your Faro instance");
    }

    #[test]
    fn identity_mismatch_comes_first() {
        let s = menu(MemberStatus {
            identity_mismatch: true,
            unreachable_since_ms: Some(1),
            screen_recording: Some(WirePermissionState::Denied),
            ..running()
        });
        assert_eq!(s.line, "Faro stopped sending to \u{201c}Sam's Faro\u{201d}");
        assert!(s.hint.unwrap().contains("whoever runs your instance"));
    }

    #[test]
    fn paused_until() {
        // 2026-11-25 14:00 UTC.
        let now = 1_795_615_200_000;
        let until = now + 90 * 60 * 1000;
        let m = MemberStatus {
            capture: Some(CaptureState::Paused),
            paused_until_ms: Some(until),
            ..running()
        };
        let s = status_menu(&Seen::Connected(m.clone()), now, 0);
        assert_eq!(s.line, "Paused until 15:30");
        assert!(s.hint.unwrap().contains("allies were told"));
        assert!(!s.problem);
        // In UTC−5 it is 10:30 there.
        assert_eq!(
            status_menu(&Seen::Connected(m.clone()), now, -5 * 3600).line,
            "Paused until 10:30"
        );
        let open_ended = MemberStatus {
            paused_until_ms: None,
            ..m
        };
        assert_eq!(menu(open_ended).line, "Paused");
    }

    #[test]
    fn clock_times() {
        // 2026-11-25 (a Wednesday) 14:00 UTC.
        let now = 1_795_615_200_000;
        let h = 3_600_000;
        assert_eq!(clock_time(now, now, 0), "14:00");
        assert_eq!(clock_time(now + 11 * h, now, 0), "Thu 01:00");
        assert_eq!(clock_time(now + 6 * 24 * h, now, 0), "Tue 14:00");
        assert_eq!(clock_time(now + 8 * 24 * h, now, 0), "3 Dec 14:00");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(20_517), (2026, 3, 5));
    }

    #[test]
    fn accessibility_and_updates_are_hints_under_monitoring() {
        let s = menu(MemberStatus {
            accessibility: Some(false),
            ..running()
        });
        assert_eq!(s.line, "Monitoring");
        assert_eq!(s.fix.unwrap().url, ACCESSIBILITY_SETTINGS);
        let s = menu(MemberStatus {
            updates_failing: true,
            ..running()
        });
        assert_eq!(s.line, "Monitoring");
        assert!(s.hint.unwrap().contains("updates"));
    }

    #[test]
    fn stopping_and_starting() {
        let s = menu(MemberStatus {
            phase: ServicePhase::ShuttingDown,
            ..running()
        });
        assert_eq!(s.line, "Faro is stopping");
        let s = menu(MemberStatus {
            capture: Some(CaptureState::NotStarted),
            ..running()
        });
        assert_eq!(s.line, "Starting\u{2026}");
        assert_eq!(
            status_menu(&Seen::Starting, 0, 0).line,
            "Connecting to the Faro service\u{2026}"
        );
    }

    fn enroll(enrolled: bool, endorsed: bool) -> EnrollStatus {
        EnrollStatus {
            enrolled,
            instance_name: enrolled.then(|| "Sam's Faro".into()),
            instance_url: enrolled.then(|| "https://faro.example.org".into()),
            endorsed,
        }
    }

    #[test]
    fn before_the_service_connects() {
        let e = |s: Result<&EnrollStatus, &str>| {
            status_menu(&Seen::NotConnected(Enrollment::from_status(s)), 0, 0)
        };
        let s = e(Ok(&enroll(false, false)));
        assert_eq!(s.line, "Not enrolled");
        assert!(s.hint.unwrap().contains("Enroll this computer"));
        assert_eq!(s.web_app, None);

        let s = e(Ok(&enroll(true, false)));
        assert_eq!(s.line, "Waiting for approval in the web app");
        assert!(s.hint.unwrap().contains("\u{201c}Sam's Faro\u{201d}"));
        assert_eq!(
            s.fix.unwrap().url,
            "https://faro.example.org/computers".to_owned()
        );
        assert_eq!(s.web_app.as_deref(), Some("https://faro.example.org/"));

        let s = e(Ok(&enroll(true, true)));
        assert_eq!(s.line, "Connecting to the Faro service\u{2026}");
        assert!(!s.problem);

        let s = e(Err("connection refused"));
        assert_eq!(s.line, "The Faro service isn't running");
        assert!(s.problem);
    }

    #[test]
    fn only_web_addresses_are_opened() {
        assert_eq!(
            web_app_url("https://faro.example.org", "computers").as_deref(),
            Some("https://faro.example.org/computers")
        );
        assert_eq!(
            web_app_url("http://127.0.0.1:8080/", "").as_deref(),
            Some("http://127.0.0.1:8080/")
        );
        for bad in [
            "",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "x-apple.systempreferences:x",
            "https://",
            "https:///path",
            "https://a b.example",
            "https://a.example/\n",
        ] {
            assert_eq!(web_app_url(bad, ""), None, "{bad:?}");
        }
    }

    #[test]
    fn about_names_versions_instance_and_notices() {
        let a = about("0.1.0-beta.1", &Seen::Connected(running()));
        assert_eq!(a.title, "About Faro");
        assert!(a.body.contains("Faro Agent 0.1.0-beta.1"), "{}", a.body);
        assert!(a.body.contains("Faro service 0.1.0-beta.1"), "{}", a.body);
        assert!(
            a.body
                .contains("Instance: Sam's Faro (https://faro.example.org/)"),
            "{}",
            a.body
        );
        assert!(a.body.contains(NOTICES_DIR), "{}", a.body);
        let a = about("1", &Seen::NotConnected(Enrollment::NotEnrolled));
        assert!(a.body.contains("Instance: not enrolled"), "{}", a.body);
        #[cfg(target_os = "macos")]
        assert_eq!(NOTICES_DIR, faro_platform_macos::pkg_layout::NOTICES_DIR);
    }

    #[test]
    fn every_line_explains_itself() {
        assert_eq!(menu(running()).detail(), NOTHING_TO_DO);
        let s = menu(MemberStatus {
            unreachable_since_ms: Some(1),
            ..running()
        });
        assert_eq!(Some(s.detail()), s.hint.as_deref());
    }

    #[test]
    fn nothing_offers_to_stop_or_hide() {
        // The menu can open settings, the web app and the notices; nothing
        // in its words offers to pause, stop, quit or hide Faro.
        let mut texts = Vec::new();
        let states = [
            Seen::Starting,
            Seen::Connected(running()),
            Seen::Connected(MemberStatus {
                screen_recording: Some(WirePermissionState::Denied),
                ..running()
            }),
            Seen::Connected(MemberStatus {
                capture: Some(CaptureState::Paused),
                ..running()
            }),
            Seen::NotConnected(Enrollment::NotEnrolled),
            Seen::NotConnected(Enrollment::NoService),
        ];
        for s in &states {
            let m = status_menu(s, 0, 0);
            texts.push(m.line);
            texts.extend(m.fix.map(|f| f.label));
        }
        for t in texts {
            let lower = t.to_lowercase();
            for word in ["pause", "stop", "quit", "hide", "turn off", "disable"] {
                assert!(
                    !lower.contains(word)
                        || lower.starts_with("paused")
                        || lower.contains("is stopping"),
                    "{t:?} offers to {word}"
                );
            }
        }
    }
}
