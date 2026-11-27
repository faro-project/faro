//! The words of the status screen and the notification: what Faro is
//! doing, and what to do when something is wrong. The phone's version of
//! the desktop status menu (`faro_agent::status_menu`), from the same
//! [`MemberStatus`] view of the runtime's status. Pure functions, so the
//! text is tested here. State only: nothing here changes monitoring.

use crate::types::AndroidStatus;
use faro_ipc::status::{CaptureState, ServicePhase};
use faro_ipc::{MemberStatus, WirePermissionState};

/// Captures failing this many times in a row is shown as a problem (the
/// desktop menu's threshold).
pub const FAILING_AFTER: u32 = 3;

/// What the app knows about the device and its runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    NotEnrolled,
    /// Enrolled, the member hasn't approved it yet.
    AwaitingApproval {
        instance_name: String,
    },
    /// The member removed the device, or the account was deleted.
    Removed,
    /// Approved, but the runtime isn't running: `error` if starting it
    /// failed.
    NotRunning {
        error: Option<String>,
    },
    /// The running runtime's view.
    Running(MemberStatus),
}

fn instance(name: &str) -> String {
    if name.trim().is_empty() {
        "your Faro instance".to_owned()
    } else {
        format!("\u{201c}{name}\u{201d}")
    }
}

fn status(
    headline: &str,
    detail: Option<String>,
    enrolled: bool,
    active: bool,
    problem: Option<&str>,
) -> AndroidStatus {
    AndroidStatus {
        headline: headline.to_owned(),
        detail,
        enrolled,
        active,
        paused_until_ms: None,
        problem: problem.map(str::to_owned),
    }
}

/// The status for `seen`.
pub fn android_status(seen: &Seen) -> AndroidStatus {
    match seen {
        Seen::NotEnrolled => status(
            "Not enrolled",
            Some(
                "Faro monitors nothing on this phone yet. Create an enrollment code on the \
                 Computers page of your Faro web app, then open the link on this phone."
                    .into(),
            ),
            false,
            false,
            None,
        ),
        Seen::AwaitingApproval { instance_name } => status(
            "Waiting for approval in the web app",
            Some(format!(
                "This phone is enrolled with {}. Open the Computers page of the web app, \
                 check that it shows the same code this phone showed, and approve the phone. \
                 Monitoring starts then.",
                instance(instance_name)
            )),
            true,
            false,
            None,
        ),
        Seen::Removed => status(
            "This phone was removed",
            Some(
                "The phone was removed in the web app, so Faro sends nothing more. To \
                 monitor it again, enroll it with a new code."
                    .into(),
            ),
            true,
            false,
            Some("removed"),
        ),
        Seen::NotRunning { error: Some(e) } => status(
            "Faro couldn't start",
            Some(format!(
                "{e}. Faro tries again when the app restarts. If this lasts, tell whoever \
                 runs your instance."
            )),
            true,
            true,
            Some("start_failed"),
        ),
        Seen::NotRunning { error: None } => status("Starting\u{2026}", None, true, true, None),
        Seen::Running(m) => running(m),
    }
}

fn running(m: &MemberStatus) -> AndroidStatus {
    let name = instance(&m.instance_name);
    if m.phase == ServicePhase::AwaitingEndorsement {
        return android_status(&Seen::AwaitingApproval {
            instance_name: m.instance_name.clone(),
        });
    }
    let on = |headline: &str, detail: Option<String>, problem: Option<&str>| {
        status(headline, detail, true, true, problem)
    };
    if matches!(m.phase, ServicePhase::ShuttingDown | ServicePhase::Stopped)
        || m.capture == Some(CaptureState::Stopped)
    {
        on("Faro is stopping", None, None)
    } else if m.identity_mismatch {
        on(
            &format!("Faro stopped sending to {name}"),
            Some(format!(
                "{name} doesn't have the identity this phone was enrolled with, so Faro \
                 sends it nothing. Your allies will see that this phone stopped checking in. \
                 Tell whoever runs your instance."
            )),
            Some("identity_mismatch"),
        )
    } else if m.screen_recording == Some(WirePermissionState::Denied) {
        on(
            "Accessibility is off",
            Some(
                "Faro can't see the screen, and your allies are told. Open Settings \
                 \u{2192} Accessibility \u{2192} Faro and switch it on."
                    .into(),
            ),
            Some("accessibility_off"),
        )
    } else if m.consecutive_failures >= FAILING_AFTER {
        on(
            "Faro can't take screenshots",
            Some(
                "Screenshots keep failing on this phone, and your allies are told if this \
                 goes on. Restart the phone. If it still says so, tell whoever runs your \
                 instance."
                    .into(),
            ),
            Some("capture_failing"),
        )
    } else if m.unreachable_since_ms.is_some() {
        on(
            &format!("Can't reach {name}"),
            Some(format!(
                "Check that this phone is online. Faro keeps monitoring and keeps what it \
                 records on this phone, encrypted, and sends it once {name} answers. If this \
                 lasts, your allies see that this phone stopped checking in."
            )),
            Some("unreachable"),
        )
    } else if m.capture == Some(CaptureState::Paused) {
        let detail = if m.paused_until_ms.is_some() {
            "Monitoring is paused, and your allies were told. It starts again by itself."
        } else {
            "Monitoring is paused, and your allies were told."
        };
        AndroidStatus {
            paused_until_ms: m.paused_until_ms,
            ..on("Paused", Some(detail.into()), None)
        }
    } else if m.capture == Some(CaptureState::NotStarted) || m.phase == ServicePhase::Starting {
        on("Starting\u{2026}", None, None)
    } else {
        on("Monitoring", None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitoring() -> MemberStatus {
        MemberStatus {
            phase: ServicePhase::Running,
            instance_name: "Home".into(),
            capture: Some(CaptureState::Active),
            screen_recording: Some(WirePermissionState::Granted),
            ..MemberStatus::default()
        }
    }

    #[test]
    fn states() {
        let s = android_status(&Seen::Running(monitoring()));
        assert_eq!(s.headline, "Monitoring");
        assert!(s.enrolled && s.active && s.problem.is_none());

        let s = android_status(&Seen::Running(MemberStatus {
            screen_recording: Some(WirePermissionState::Denied),
            ..monitoring()
        }));
        assert_eq!(s.problem.as_deref(), Some("accessibility_off"));

        let s = android_status(&Seen::Running(MemberStatus {
            consecutive_failures: FAILING_AFTER,
            ..monitoring()
        }));
        assert_eq!(s.problem.as_deref(), Some("capture_failing"));

        let s = android_status(&Seen::Running(MemberStatus {
            unreachable_since_ms: Some(1),
            ..monitoring()
        }));
        assert_eq!(s.problem.as_deref(), Some("unreachable"));
        assert!(s.headline.contains("Home"));

        let s = android_status(&Seen::Running(MemberStatus {
            capture: Some(CaptureState::Paused),
            paused_until_ms: Some(42),
            ..monitoring()
        }));
        assert_eq!(
            (s.headline.as_str(), s.paused_until_ms),
            ("Paused", Some(42))
        );

        let s = android_status(&Seen::Running(MemberStatus {
            phase: ServicePhase::AwaitingEndorsement,
            ..monitoring()
        }));
        assert!(s.enrolled && !s.active);

        let s = android_status(&Seen::NotEnrolled);
        assert!(!s.enrolled && !s.active);
        let s = android_status(&Seen::Removed);
        assert_eq!(s.problem.as_deref(), Some("removed"));
        assert!(!s.active);
        let s = android_status(&Seen::NotRunning { error: None });
        assert!(s.active && s.problem.is_none());
    }
}
