//! `faro-service status`: what the state directory and the running service
//! say, as text or JSON.
//!
//! [`gather`] reads everything without network access: the enrollment,
//! the outbox, and the [`StatusReport`] the running service writes to
//! [`STATUS_FILE`](crate::runtime::status::STATUS_FILE). [`StatusView`] is
//! what `--json` prints; [`StatusView::text`] is the plain output. Both
//! leave out anything a capture could reveal (`faro_ipc::status`).

use crate::config::Config;
use crate::enroll;
use crate::runtime::status::read_status_file;
use crate::state::{self, StateDir, StateError};
use faro_ipc::status::{
    ArtifactReport, ArtifactSource, CaptureState, ServicePhase, StatusReport, ThresholdsReport,
};
use faro_ipc::WirePermissionState;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Everything `status` shows. `--json` prints it as is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub state_dir: String,
    /// `None`: not enrolled.
    pub enrollment: Option<EnrollmentView>,
    pub outbox: Option<OutboxView>,
    /// The service's process is alive and its report is current
    /// ([`StatusReport::is_fresh`]).
    pub service_running: bool,
    /// The last report the service wrote; `None` if it has not written one
    /// (not run since enrollment, or a version from before reports).
    pub service: Option<StatusReport>,
    /// The status file exists but could not be read.
    pub service_error: Option<String>,
    /// What this build does with `[dev_thresholds]` in the config file now
    /// (the running service's choice at its start is in
    /// `service.detection.thresholds`).
    pub thresholds: ThresholdsReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentView {
    pub instance_name: String,
    pub instance_url: String,
    pub instance_id: String,
    pub device_id: String,
    pub device_name: String,
    pub device_fingerprint: String,
    pub member_id: String,
    pub member_key_fingerprint: String,
    pub endorsed: bool,
    /// The recipient manifest version and its number of allies, once
    /// bootstrapped.
    pub manifest_version: Option<u64>,
    pub allies: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxView {
    pub events: u64,
    pub event_bytes: u64,
    pub reports: u64,
    pub next_seq: u64,
}

/// Read `config`'s state directory and the service's report.
pub fn gather(config: &Config, now_ms: i64) -> Result<StatusView, GatherError> {
    let dir = StateDir::open(&config.state_dir)?;
    let mut view = StatusView {
        state_dir: dir.path().display().to_string(),
        enrollment: None,
        outbox: None,
        service_running: false,
        service: None,
        service_error: None,
        thresholds: crate::thresholds::build_use(config.dev_thresholds.as_ref()).report(),
    };
    let e = match dir.enrollment() {
        Ok(e) => e,
        Err(StateError::NotEnrolled) => return Ok(view),
        Err(e) => return Err(e.into()),
    };
    let key = state::load_device_key(&dir)?;
    let outbox = faro_core::Outbox::open(dir.path(), &e.instance_id, &e.device_id)?;
    let recipients = outbox.current_recipients(&e.member_sign_pubkey, &e.member_id)?;
    view.enrollment = Some(EnrollmentView {
        instance_name: e.instance_name.clone(),
        instance_url: e.instance_url.clone(),
        instance_id: e.instance_id.to_string(),
        device_id: e.device_id.to_string(),
        device_name: e.device_name.clone(),
        device_fingerprint: enroll::device_fingerprint(&key.public()),
        member_id: e.member_id.to_string(),
        member_key_fingerprint: enroll::member_fingerprint(&e.member_sign_pubkey),
        endorsed: dir.endorsement()?.is_some(),
        manifest_version: recipients.as_ref().map(|s| s.manifest_ref().version),
        allies: recipients.as_ref().map(|s| s.allies().len()),
    });
    let stats = outbox.stats()?;
    let head = outbox.head()?;
    view.outbox = Some(OutboxView {
        events: stats.events,
        event_bytes: stats.event_bytes,
        reports: stats.reports,
        next_seq: head.next_seq,
    });
    match read_status_file(&dir) {
        Ok(r) => {
            view.service_running = r
                .as_ref()
                .is_some_and(|r| r.is_fresh(now_ms) && process_alive(r.pid));
            view.service = r;
        }
        Err(e) => view.service_error = Some(e.to_string()),
    }
    Ok(view)
}

#[derive(Debug, thiserror::Error)]
pub enum GatherError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Outbox(#[from] faro_core::OutboxError),
}

/// `pid` is a running process (always assumed off Unix).
fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        if pid <= 0 {
            return false;
        }
        // SAFETY: signal 0 only checks that the process exists.
        let r = unsafe { libc::kill(pid, 0) };
        r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        if pid == 0 {
            return false;
        }
        // SAFETY: a process handle we close; the exit code goes to a local.
        unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                // Access denied still means it exists; anything else, not.
                return std::io::Error::last_os_error().raw_os_error() == Some(5);
            };
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code).is_ok();
            let _ = CloseHandle(h);
            !ok || code == STILL_ACTIVE.0 as u32
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

/// `then`, relative to `now`: `12 s ago`, `4 min ago`, `3 h ago`, `2 days
/// ago`.
pub fn ago(now_ms: i64, then_ms: i64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        i64::MIN..=0 => "just now".to_owned(),
        1..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=172_799 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

fn account(a: &str) -> &str {
    if a.is_empty() {
        "(unknown account)"
    } else {
        a
    }
}

fn permission(p: Option<WirePermissionState>) -> &'static str {
    match p {
        None => "unknown",
        Some(WirePermissionState::Granted) => "granted",
        Some(WirePermissionState::Denied) => "denied",
        Some(WirePermissionState::NotDetermined) => "not asked yet",
        Some(WirePermissionState::NotRequired) => "not needed",
    }
}

fn artifact(a: &ArtifactReport) -> String {
    let source = match a.source {
        ArtifactSource::Packaged => "packaged",
        ArtifactSource::UpdateChannel => "update channel",
    };
    if a.version.is_empty() {
        format!("{} ({source})", a.name)
    } else {
        format!("{} {} ({source})", a.name, a.version)
    }
}

const PAD: &str = "              ";

impl StatusView {
    /// The plain-text output, made at `now_ms`.
    pub fn text(&self, now_ms: i64) -> String {
        let mut o = String::new();
        let Some(e) = &self.enrollment else {
            let _ = writeln!(o, "Not enrolled. State directory: {}", self.state_dir);
            self.thresholds_text(&mut o);
            return o;
        };
        let _ = writeln!(o, "Instance:     {} ({})", e.instance_name, e.instance_url);
        let _ = writeln!(o, "Instance id:  {}", e.instance_id);
        let _ = writeln!(o, "Device:       {} \"{}\"", e.device_id, e.device_name);
        let _ = writeln!(o, "Fingerprint:  {}", e.device_fingerprint);
        let _ = writeln!(o, "Member:       {}", e.member_id);
        let _ = writeln!(
            o,
            "Member key:   {}  (compare with the member key your web app shows)",
            e.member_key_fingerprint
        );
        let _ = writeln!(
            o,
            "Endorsed:     {}",
            if e.endorsed {
                "yes"
            } else {
                "no (waiting for approval)"
            }
        );
        match (e.manifest_version, e.allies) {
            (Some(v), Some(n)) => {
                let _ = writeln!(o, "Recipients:   manifest v{v} (member + {n} allies)");
            }
            _ => {
                let _ = writeln!(o, "Recipients:   none yet (not bootstrapped)");
            }
        }
        if let Some(b) = &self.outbox {
            let _ = writeln!(
                o,
                "Outbox:       {} events ({} bytes), {} reports queued; next seq {}",
                b.events, b.event_bytes, b.reports, b.next_seq
            );
        }
        self.thresholds_text(&mut o);
        o.push('\n');
        self.service_text(&mut o, now_ms);
        o
    }

    fn thresholds_text(&self, o: &mut String) {
        if let Some(line) = crate::thresholds::status_line(&self.thresholds) {
            let _ = writeln!(o, "{line}");
        }
    }

    fn service_text(&self, o: &mut String, now: i64) {
        let Some(r) = &self.service else {
            match &self.service_error {
                Some(err) => {
                    let _ = writeln!(o, "Service:      status unreadable: {err}");
                }
                None => {
                    let _ = writeln!(
                        o,
                        "Service:      no status yet (the service has not run since it was enrolled)"
                    );
                }
            }
            return;
        };
        if self.service_running {
            let _ = writeln!(
                o,
                "Service:      {} since {} (version {}, pid {})",
                phase(r.phase),
                ago(now, r.started_ms),
                r.service_version,
                r.pid
            );
        } else {
            let _ = writeln!(
                o,
                "Service:      not running (last status {}, {})",
                ago(now, r.updated_ms),
                phase(r.phase)
            );
        }
        if let Some(log) = &r.log_file {
            let _ = writeln!(o, "Log:          {log}");
        }

        let target = r.capture.target_account.as_deref().map(account);
        let state = if self.service_running {
            r.capture.state
        } else {
            CaptureState::Stopped
        };
        let at_screen = r
            .sessions
            .iter()
            .find(|s| s.at_screen)
            .map(|s| account(&s.account));
        let capture = match state {
            CaptureState::Active => format!("active, from {}", target.unwrap_or("?")),
            CaptureState::Idle => format!(
                "paused: {} is idle",
                target.unwrap_or("the person at the screen")
            ),
            CaptureState::Locked => "paused: the screen is locked".to_owned(),
            CaptureState::Asleep => "paused: the computer is asleep".to_owned(),
            CaptureState::Paused => "paused by the member (allies were told)".to_owned(),
            CaptureState::LoginWindow => {
                "none: nobody is logged in at the screen (login window)".to_owned()
            }
            CaptureState::NoAgent => format!(
                "none: the agent of {} is not connected",
                at_screen.unwrap_or("the session at the screen")
            ),
            CaptureState::NotStarted => "not started".to_owned(),
            CaptureState::Stopped => "none: the service is not running".to_owned(),
        };
        let _ = writeln!(o, "Capture:      {capture}");
        let when = |t: Option<i64>| t.map_or_else(|| "never".to_owned(), |t| ago(now, t));
        let _ = writeln!(
            o,
            "Last capture: attempted {}, succeeded {}",
            when(r.capture.last_attempt_ms),
            when(r.capture.last_success_ms)
        );
        match &r.capture.last_failure {
            Some(f) => {
                let _ = writeln!(
                    o,
                    "Failures:     {} in a row; last {}: {}",
                    r.capture.consecutive_failures,
                    ago(now, f.at_ms),
                    f.reason
                );
            }
            None => {
                let _ = writeln!(o, "Failures:     none");
            }
        }

        if r.sessions.is_empty() {
            let _ = writeln!(o, "Agents:       none (no session)");
        }
        for (i, s) in r.sessions.iter().enumerate() {
            let mut parts = Vec::new();
            if s.at_screen {
                parts.push("at the screen".to_owned());
            }
            if s.agent_connected {
                match &s.agent_version {
                    Some(v) => parts.push(format!("agent connected ({v})")),
                    None => parts.push("agent connected".to_owned()),
                }
            } else {
                parts.push("no agent connected".to_owned());
            }
            if s.capture_target {
                parts.push("capture target".to_owned());
            }
            if s.unmonitored {
                parts.push("unmonitored (allies were told)".to_owned());
            }
            let label = if i == 0 { "Agents:       " } else { PAD };
            let _ = writeln!(o, "{label}{}: {}", account(&s.account), parts.join(", "));
        }

        let p = &r.permissions;
        if p.screen_recording.is_none() && p.accessibility.is_none() {
            let _ = writeln!(o, "Permissions:  not reported (no capture target yet)");
        } else {
            let acc = match p.accessibility {
                None => "unknown",
                Some(true) => "granted",
                Some(false) => "denied",
            };
            let _ = writeln!(
                o,
                "Permissions:  Screen Recording {}, Accessibility {} (for {})",
                permission(p.screen_recording),
                acc,
                p.account.as_deref().map_or("?", account)
            );
        }

        let d = &r.detection;
        let model = match (&d.model, &d.model_missing) {
            (Some(m), _) => artifact(m),
            (None, Some(why)) => format!("none: {why}"),
            (None, None) => "none".to_owned(),
        };
        let _ = writeln!(o, "Image model:  {model}");
        let domains = match (&d.domains, &d.domains_missing) {
            (Some(m), _) => artifact(m),
            (None, Some(why)) => format!("none: {why}"),
            (None, None) => "none".to_owned(),
        };
        let _ = writeln!(o, "Domain list:  {domains}");

        let u = &r.updates;
        let updates = if !u.enabled {
            format!(
                "off: {}",
                u.disabled_reason.as_deref().unwrap_or("no root of trust")
            )
        } else {
            let channel = u
                .channel
                .as_deref()
                .map_or_else(String::new, |c| format!(", channel {c}"));
            match (u.last_check_ms, &u.last_result) {
                (Some(t), Some(res)) => {
                    format!("on{channel}; last check {}: {res}", ago(now, t))
                }
                _ => format!("on{channel}; not checked yet"),
            }
        };
        let _ = writeln!(o, "Updates:      {updates}");

        let h = &r.health;
        let heartbeat = h.last_heartbeat.map_or("none sent yet".to_owned(), |s| {
            serde_json::to_value(s)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        });
        let acked = match (h.acked_through, h.last_seq) {
            (Some(a), Some(l)) => format!("acknowledged through seq {a} of {l}"),
            (None, Some(l)) => format!("none acknowledged yet of {l}"),
            _ => "none written yet".to_owned(),
        };
        let _ = writeln!(
            o,
            "Uploads:      last heartbeat {heartbeat}; events {acked}"
        );
        let mut warnings = Vec::new();
        if h.identity_mismatch {
            warnings
                .push("the instance's identity no longer matches; uploads are paused".to_owned());
        }
        if let Some(w) = &h.manifest_warning {
            warnings.push(format!("recipients: {w}"));
        }
        if let Some(e) = &h.last_error {
            warnings.push(format!("last error: {e}"));
        }
        for (i, w) in warnings.iter().enumerate() {
            let label = if i == 0 { "Warnings:     " } else { PAD };
            let _ = writeln!(o, "{label}{w}");
        }
    }
}

fn phase(p: ServicePhase) -> &'static str {
    match p {
        ServicePhase::Starting => "starting",
        ServicePhase::AwaitingEndorsement => "waiting for approval",
        ServicePhase::Running => "running",
        ServicePhase::ShuttingDown => "stopping",
        ServicePhase::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_ipc::status::{
        CaptureFailure, CaptureReport, DetectionReport, PermissionsReport, SessionReport,
        UpdatesReport,
    };

    fn view(report: StatusReport, running: bool) -> StatusView {
        StatusView {
            state_dir: "/state".into(),
            enrollment: Some(EnrollmentView {
                instance_name: "Home".into(),
                instance_url: "https://faro.example/".into(),
                instance_id: "inst_1".into(),
                device_id: "dev_1".into(),
                device_name: "Laptop".into(),
                device_fingerprint: "AAAA".into(),
                member_id: "usr_1".into(),
                member_key_fingerprint: "BBBB".into(),
                endorsed: true,
                manifest_version: Some(2),
                allies: Some(1),
            }),
            outbox: Some(OutboxView {
                events: 1,
                event_bytes: 10,
                reports: 0,
                next_seq: 5,
            }),
            service_running: running,
            service: Some(report),
            service_error: None,
            thresholds: ThresholdsReport::default(),
        }
    }

    fn report() -> StatusReport {
        StatusReport {
            service_version: "0.1.0-beta.1".into(),
            pid: 7,
            started_ms: 0,
            updated_ms: 100_000,
            phase: ServicePhase::Running,
            sessions: vec![
                SessionReport {
                    session: "uid:501".into(),
                    account: "alex".into(),
                    at_screen: true,
                    agent_connected: true,
                    agent_version: Some("0.1.0-beta.1".into()),
                    capture_target: true,
                    unmonitored: false,
                },
                SessionReport {
                    session: "uid:502".into(),
                    account: "guest".into(),
                    unmonitored: true,
                    ..SessionReport::default()
                },
            ],
            capture: CaptureReport {
                state: CaptureState::Active,
                target_account: Some("alex".into()),
                last_attempt_ms: Some(40_000),
                last_success_ms: None,
                consecutive_failures: 2,
                last_failure: Some(CaptureFailure {
                    at_ms: 40_000,
                    reason: "permission denied: screen_recording".into(),
                }),
                ..CaptureReport::default()
            },
            permissions: PermissionsReport {
                account: Some("alex".into()),
                screen_recording: Some(WirePermissionState::Denied),
                accessibility: Some(true),
            },
            detection: DetectionReport {
                model: Some(ArtifactReport {
                    name: "opennsfw".into(),
                    version: "1.0.0+int8".into(),
                    source: ArtifactSource::Packaged,
                }),
                domains_missing: Some("no domain list installed".into()),
                ..DetectionReport::default()
            },
            updates: UpdatesReport {
                enabled: true,
                channel: Some("stable".into()),
                last_check_ms: Some(0),
                last_result: Some("up to date".into()),
                ..UpdatesReport::default()
            },
            log_file: Some("/Library/Logs/Faro/faro-service.log".into()),
            ..StatusReport::default()
        }
    }

    #[test]
    fn running_service_text() {
        let t = view(report(), true).text(100_000);
        for want in [
            "Service:      running since 1 min ago (version 0.1.0-beta.1, pid 7)",
            "Log:          /Library/Logs/Faro/faro-service.log",
            "Capture:      active, from alex",
            "Last capture: attempted 1 min ago, succeeded never",
            "Failures:     2 in a row; last 1 min ago: permission denied: screen_recording",
            "Agents:       alex: at the screen, agent connected (0.1.0-beta.1), capture target",
            "              guest: no agent connected, unmonitored (allies were told)",
            "Permissions:  Screen Recording denied, Accessibility granted (for alex)",
            "Image model:  opennsfw 1.0.0+int8 (packaged)",
            "Domain list:  none: no domain list installed",
            "Updates:      on, channel stable; last check 1 min ago: up to date",
            "Uploads:      last heartbeat none sent yet; events none written yet",
        ] {
            assert!(t.contains(want), "missing {want:?} in\n{t}");
        }
        assert!(!t.contains("Warnings"), "{t}");
        assert!(!t.contains("Thresholds"), "{t}");
    }

    #[test]
    fn stale_or_missing_reports() {
        let t = view(report(), false).text(100_000 + 7_200_000);
        assert!(
            t.contains("Service:      not running (last status 2 h ago, running)"),
            "{t}"
        );
        assert!(
            t.contains("Capture:      none: the service is not running"),
            "{t}"
        );

        let mut r = report();
        r.capture.state = CaptureState::NoAgent;
        r.capture.target_account = None;
        let t = view(r, true).text(100_000);
        assert!(
            t.contains("none: the agent of alex is not connected"),
            "{t}"
        );

        let mut v = view(report(), false);
        v.service = None;
        assert!(v.text(0).contains("no status yet"));
        v.enrollment = None;
        assert!(v.text(0).starts_with("Not enrolled."));
        v.thresholds.state = faro_ipc::status::ThresholdsState::Ignored;
        assert!(v
            .text(0)
            .contains("\nThresholds:   default ([dev_thresholds] ignored"));
    }

    #[test]
    fn warnings_are_listed() {
        let mut r = report();
        r.health.identity_mismatch = true;
        r.health.last_error = Some("outbox: disk full".into());
        let t = view(r, true).text(100_000);
        assert!(
            t.contains("Warnings:     the instance's identity no longer matches"),
            "{t}"
        );
        assert!(
            t.contains(&format!("{PAD}last error: outbox: disk full")),
            "{t}"
        );
    }

    #[test]
    fn relative_times() {
        assert_eq!(ago(10_000, 20_000), "just now");
        assert_eq!(ago(5_000, 0), "5 s ago");
        assert_eq!(ago(3_600_000, 0), "1 h ago");
        assert_eq!(ago(3 * 86_400_000, 0), "3 days ago");
    }

    #[test]
    fn this_process_is_alive() {
        assert!(process_alive(std::process::id()));
        assert!(!process_alive(0));
    }
}
