//! Enrolling the computer from the agent, without Terminal (issue #62).
//!
//! Opening a `faro://enroll` link, or "Enroll this computer…" in the menu,
//! runs [`run_flow`] on a worker thread:
//!
//! 1. **Link.** From the link, or from a window with two fields (the link,
//!    or the instance address and the code).
//! 2. **Confirm.** The service looks the instance up (`Preview`); the person
//!    sees its name and address and the accounts that will be monitored,
//!    with the same sentences as `faro-service enroll`, and confirms.
//! 3. **Approve.** The agent creates an empty macOS authorization and sends
//!    it with `Enroll`. The service, as root, asks an administrator for
//!    their name and password in the system's own dialog, and enrolls only
//!    if they approve. The agent can't enroll by itself.
//! 4. **Result.** The device key's fingerprint to compare in the web app,
//!    and either "member key matched the link" or the member key's safety
//!    code, as the CLI shows; or what went wrong.
//!
//! The words on every screen come from the pure functions here, so they are
//! tested; the screens themselves are behind [`EnrollUi`] (AppKit in the
//! binary), and the authorization behind [`Authorizer`].

use faro_ipc::{EnrollDone, EnrollPreview, EnrollStatus, EnrollTarget, FailureKind};

/// A screen's title and text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    pub title: String,
    pub body: String,
}

impl Screen {
    fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Screen {
            title: title.into(),
            body: body.into(),
        }
    }
}

/// The words of the window that asks for the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasteScreen {
    pub title: String,
    pub body: String,
    pub first_label: String,
    pub first_placeholder: String,
    pub second_label: String,
    pub second_placeholder: String,
    pub ok: String,
    pub cancel: String,
}

/// Buttons of the confirm screen.
pub const ENROLL_BUTTON: &str = "Enroll";
pub const CANCEL_BUTTON: &str = "Cancel";

/// The window that asks for the link, or the address and the code.
pub fn paste_screen() -> PasteScreen {
    PasteScreen {
        title: "Enroll this computer".into(),
        body: "Paste the enrollment link from the Computers page of your Faro web app. \
               Or type your Faro address and the code shown there."
            .into(),
        first_label: "Enrollment link or Faro address".into(),
        first_placeholder: "faro://enroll?\u{2026}  or  faro.example.org".into(),
        second_label: "Code (not needed with a link)".into(),
        second_placeholder: "ABCD-1234".into(),
        ok: "Continue".into(),
        cancel: CANCEL_BUTTON.into(),
    }
}

/// Turn the two fields into a target, or say what is missing. A link in
/// the first field wins; an address without a scheme gets `https://`. The
/// service checks everything again.
pub fn target_from_fields(first: &str, second: &str) -> Result<EnrollTarget, Screen> {
    let first = first.trim();
    let second = second.trim();
    if first.is_empty() {
        return Err(Screen::new(
            "Paste the link first",
            "Copy the enrollment link from the Computers page of your Faro web app and \
             paste it into the first field.",
        ));
    }
    if first
        .get(..5)
        .is_some_and(|p| p.eq_ignore_ascii_case("faro:"))
    {
        return Ok(EnrollTarget::Link(first.to_owned()));
    }
    if second.is_empty() {
        return Err(Screen::new(
            "Type the code too",
            "With a Faro address, also type the code the web app shows next to it.",
        ));
    }
    let instance = if first.contains("://") {
        first.to_owned()
    } else {
        format!("https://{first}")
    };
    Ok(EnrollTarget::Manual {
        instance,
        code: second.to_owned(),
    })
}

/// What `faro-service enroll` prints about the accounts
/// (`faro_service::accounts::enrollment_notice`), one sentence per line.
pub fn accounts_notice(accounts: Option<&[String]>, guest_enabled: bool) -> Vec<String> {
    let mut out =
        vec!["Faro will monitor every account on this computer, including accounts created later."
            .to_owned()];
    if let Some(names) = accounts.filter(|a| !a.is_empty()) {
        out.push(format!("Accounts: {}", names.join(", ")));
    }
    if guest_enabled {
        out.push(
            "The guest account is turned on, so anyone can use this computer without a \
             password. Consider turning it off (System Settings > Users & Groups)."
                .to_owned(),
        );
    }
    out.push("Everyone who uses this computer is told it is monitored when they log in.".into());
    out
}

/// Confirm the instance before asking for approval.
pub fn confirm_screen(p: &EnrollPreview) -> Screen {
    let mut body = format!(
        "Address: {}\nThis computer will be called \u{201c}{}\u{201d}.\n\n",
        p.instance_url, p.device_name
    );
    body.push_str(&accounts_notice(p.accounts.as_deref(), p.guest_enabled).join("\n"));
    body.push_str(
        "\n\nOnly continue if this is your Faro instance. Next, an administrator of this \
         computer types their name and password to approve.",
    );
    Screen::new(
        format!("Enroll this computer with \u{201c}{}\u{201d}?", p.instance_name),
        body,
    )
}

/// After enrolling: what to check in the web app.
pub fn enrolled_screen(d: &EnrollDone) -> Screen {
    let member = if d.member_key_checked {
        "Your member key matched the link.".to_owned()
    } else {
        format!(
            "Also check that the web app shows this member key: {}. If it shows a different \
             one, don't approve, and remove this computer in the web app.",
            d.member_fingerprint
        )
    };
    Screen::new(
        "This computer is enrolled",
        format!(
            "Last step: approve it in your Faro web app, on the Computers page. Before you \
             approve, check that the web app shows this code for the new computer:\n\n{}\n\n\
             {member}\n\nMonitoring starts once you approve.",
            d.device_fingerprint
        ),
    )
}

/// The menu item on an enrolled computer.
pub fn already_enrolled_screen(s: &EnrollStatus) -> Screen {
    let with = match (&s.instance_name, &s.instance_url) {
        (Some(n), Some(u)) => format!(" with \u{201c}{n}\u{201d} ({u})"),
        (Some(n), None) => format!(" with \u{201c}{n}\u{201d}"),
        _ => String::new(),
    };
    let next = if s.endorsed {
        "It is approved and monitored."
    } else {
        "It is waiting for approval in your Faro web app, on the Computers page."
    };
    Screen::new(
        "This computer is already enrolled",
        format!("This computer is enrolled{with}. {next}"),
    )
}

/// The service didn't answer.
pub fn no_service_screen(detail: &str) -> Screen {
    with_detail(
        Screen::new(
            "Faro isn't answering",
            "The Faro service on this computer isn't answering. Restart the computer and \
             try again.",
        ),
        detail,
    )
}

/// Something went wrong before or while enrolling.
pub fn failure_screen(kind: FailureKind, detail: &str) -> Screen {
    let s = match kind {
        FailureKind::BadInput => Screen::new(
            "That link or code doesn't look right",
            "Copy the enrollment link again from the Computers page of your Faro web app, \
             or check the address and the code.",
        ),
        FailureKind::Unreachable => Screen::new(
            "Faro can't reach your instance",
            "Check that this computer is online and that the address is right, then try \
             again.",
        ),
        FailureKind::NotFaro => Screen::new(
            "That isn't a Faro instance this computer can use",
            "Check the address. If it is right, the instance may need a newer version of \
             Faro.",
        ),
        FailureKind::WrongCode => Screen::new(
            "The code didn't work",
            "Each code works once and expires. Make a new one on the Computers page of \
             your Faro web app and try again.",
        ),
        FailureKind::AlreadyEnrolled => Screen::new(
            "This computer is already enrolled",
            "Nothing was changed.",
        ),
        FailureKind::NotApproved => Screen::new(
            "Not approved",
            "An administrator of this computer has to type their name and password to \
             approve. Nothing was changed. Try again when one can.",
        ),
        FailureKind::InstanceChanged => Screen::new(
            "The instance changed",
            "The instance answered differently from the one you confirmed. Nothing was \
             changed. Try again and check the name.",
        ),
        FailureKind::MemberKeyMismatch => Screen::new(
            "Enrollment stopped to keep you safe",
            "The instance answered with a member key that doesn't match your link, so it \
             may be trying to read your reports. Nothing was saved on this computer. If \
             the computer shows up in your web app, remove it, and tell whoever runs your \
             instance.",
        ),
        FailureKind::Busy => Screen::new(
            "Enrollment is already in progress",
            "Finish the other enrollment first.",
        ),
        FailureKind::Unavailable => Screen::new(
            "This computer can't be enrolled from here",
            "Ask an administrator to enroll it in Terminal with:\nsudo \
             /Library/Faro/bin/faro-service enroll --link '\u{2026}'",
        ),
        FailureKind::Failed => Screen::new("Enrollment didn't work", "Please try again."),
    };
    with_detail(s, detail)
}

fn with_detail(mut s: Screen, detail: &str) -> Screen {
    let detail = detail.trim();
    if !detail.is_empty() {
        s.body.push_str("\n\nDetails: ");
        s.body.push_str(detail);
    }
    s
}

#[cfg(unix)]
pub use flow::{run_flow, Authorizer, EnrollUi, ANSWER_TIMEOUT, ENROLL_TIMEOUT};

#[cfg(unix)]
mod flow {
    use super::*;
    use crate::ServiceTrust;
    use faro_ipc::{
        EnrollClientConnection, EnrollRequest, EnrollResponse, IpcClient, IpcError,
        AUTHORIZATION_LEN,
    };
    use std::any::Any;
    use std::path::Path;
    use std::time::Duration;
    use tokio::net::UnixStream;

    /// How long `Status` and `Preview` may take (the service's network
    /// timeout is 30 s).
    pub const ANSWER_TIMEOUT: Duration = Duration::from_secs(90);
    /// How long `Enroll` may take: up to 5 minutes for an administrator,
    /// then the network.
    pub const ENROLL_TIMEOUT: Duration = Duration::from_secs(8 * 60);

    /// The screens. Every call blocks until the person answers.
    pub trait EnrollUi {
        /// The two fields, or `None` if cancelled.
        fn ask_target(&self, screen: &PasteScreen) -> Option<(String, String)>;
        /// `true` for `ok`.
        fn confirm(&self, screen: &Screen, ok: &str, cancel: &str) -> bool;
        /// A message; `problem` shows it as a warning.
        fn show(&self, screen: &Screen, problem: bool);
    }

    /// Creates the authorization sent with `Enroll`.
    pub trait Authorizer {
        /// The authorization's external form, and a value that keeps it
        /// alive: dropping it frees the authorization and destroys its
        /// rights.
        fn create(&self) -> Result<(Box<dyn Any>, [u8; AUTHORIZATION_LEN]), String>;
    }

    async fn ask(
        socket: &Path,
        trust: ServiceTrust,
        req: &EnrollRequest,
        timeout: Duration,
    ) -> Result<EnrollResponse, IpcError> {
        let verifier = trust.verifier();
        let mut conn: EnrollClientConnection<UnixStream> =
            IpcClient::connect_verified_typed(socket, &*verifier).await?;
        conn.send(req).await?;
        conn.recv_timeout(timeout, "the service's answer").await
    }

    /// Run the whole flow (see the module docs), blocking. `link` is the
    /// opened `faro:` link, or `None` from the menu. `socket` is the enroll
    /// socket (`faro_ipc::resolve_enroll_socket`), and `trust` who must be
    /// listening on it.
    pub fn run_flow(
        ui: &dyn EnrollUi,
        auth: &dyn Authorizer,
        socket: &Path,
        trust: ServiceTrust,
        link: Option<String>,
    ) {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                ui.show(&no_service_screen(&e.to_string()), true);
                return;
            }
        };
        let ask = |req: &EnrollRequest, timeout| rt.block_on(ask(socket, trust, req, timeout));
        let unexpected = |r: &EnrollResponse| {
            failure_screen(
                FailureKind::Failed,
                &format!("unexpected answer {}", r.kind()),
            )
        };

        let target = match link {
            Some(l) => EnrollTarget::Link(l),
            None => {
                match ask(&EnrollRequest::Status, ANSWER_TIMEOUT) {
                    Ok(EnrollResponse::Status(s)) if s.enrolled => {
                        ui.show(&already_enrolled_screen(&s), false);
                        return;
                    }
                    Ok(EnrollResponse::Status(_)) => {}
                    Ok(EnrollResponse::Failed { kind, detail }) => {
                        ui.show(&failure_screen(kind, &detail), true);
                        return;
                    }
                    Ok(other) => {
                        ui.show(&unexpected(&other), true);
                        return;
                    }
                    Err(e) => {
                        ui.show(&no_service_screen(&e.to_string()), true);
                        return;
                    }
                }
                let paste = paste_screen();
                loop {
                    let Some((first, second)) = ui.ask_target(&paste) else {
                        return;
                    };
                    match target_from_fields(&first, &second) {
                        Ok(t) => break t,
                        Err(screen) => ui.show(&screen, true),
                    }
                }
            }
        };

        let preview = match ask(&EnrollRequest::Preview(target.clone()), ANSWER_TIMEOUT) {
            Ok(EnrollResponse::Preview(p)) => p,
            Ok(EnrollResponse::Failed { kind, detail }) => {
                ui.show(&failure_screen(kind, &detail), true);
                return;
            }
            Ok(other) => {
                ui.show(&unexpected(&other), true);
                return;
            }
            Err(e) => {
                ui.show(&no_service_screen(&e.to_string()), true);
                return;
            }
        };
        if !ui.confirm(&confirm_screen(&preview), ENROLL_BUTTON, CANCEL_BUTTON) {
            return;
        }

        let (hold, authorization) = match auth.create() {
            Ok(a) => a,
            Err(e) => {
                ui.show(&failure_screen(FailureKind::Unavailable, &e), true);
                return;
            }
        };
        let req = EnrollRequest::Enroll {
            target,
            confirmed_instance: preview.instance_id.clone(),
            confirmed_identity: preview.identity_key,
            authorization,
        };
        let answer = ask(&req, ENROLL_TIMEOUT);
        // Free the authorization (destroying any right in it) as soon as
        // the service has answered.
        drop(hold);
        match answer {
            Ok(EnrollResponse::Enrolled(done)) => ui.show(&enrolled_screen(&done), false),
            Ok(EnrollResponse::Failed { kind, detail }) => {
                ui.show(&failure_screen(kind, &detail), true)
            }
            Ok(other) => ui.show(&unexpected(&other), true),
            Err(e) => ui.show(&no_service_screen(&e.to_string()), true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview() -> EnrollPreview {
        EnrollPreview {
            instance_name: "Sam's Faro".into(),
            instance_url: "https://faro.example.org/".into(),
            instance_id: "inst_a".into(),
            identity_key: [1; 32],
            device_name: "Laptop".into(),
            accounts: Some(vec!["alex".into(), "sam".into()]),
            guest_enabled: true,
            member_key_in_link: true,
        }
    }

    #[test]
    fn fields_become_a_target() {
        assert_eq!(
            target_from_fields(" faro://enroll?i=x&c=y ", "ignored"),
            Ok(EnrollTarget::Link("faro://enroll?i=x&c=y".into()))
        );
        assert_eq!(
            target_from_fields("FARO://enroll?i=x&c=y", ""),
            Ok(EnrollTarget::Link("FARO://enroll?i=x&c=y".into()))
        );
        assert_eq!(
            target_from_fields("faro.example.org", " abcd-1234 "),
            Ok(EnrollTarget::Manual {
                instance: "https://faro.example.org".into(),
                code: "abcd-1234".into()
            })
        );
        assert_eq!(
            target_from_fields("http://localhost:8080", "ABCD-1234"),
            Ok(EnrollTarget::Manual {
                instance: "http://localhost:8080".into(),
                code: "ABCD-1234".into()
            })
        );
        assert!(target_from_fields("", "ABCD-1234").is_err());
        assert!(target_from_fields("faro.example.org", " ").is_err());
    }

    #[test]
    fn confirm_names_the_instance_and_every_account() {
        let s = confirm_screen(&preview());
        assert_eq!(s.title, "Enroll this computer with \u{201c}Sam's Faro\u{201d}?");
        assert!(s.body.contains("Address: https://faro.example.org/"));
        assert!(s.body.contains("\u{201c}Laptop\u{201d}"));
        assert!(s.body.contains("every account on this computer"));
        assert!(s.body.contains("Accounts: alex, sam"));
        assert!(s.body.contains("guest account is turned on"));
        assert!(s.body.contains("administrator"));

        let mut p = preview();
        p.accounts = None;
        p.guest_enabled = false;
        let s = confirm_screen(&p);
        assert!(!s.body.contains("Accounts:") && !s.body.contains("guest"));
        assert!(s.body.contains("every account on this computer"));
    }

    #[test]
    fn result_shows_the_fingerprints_like_the_cli() {
        let mut d = EnrollDone {
            device_fingerprint: "0123456789abcdef".into(),
            member_fingerprint: "fedcba9876543210".into(),
            member_key_checked: true,
        };
        let s = enrolled_screen(&d);
        assert!(s.body.contains("0123456789abcdef"));
        assert!(s.body.contains("member key matched the link"));
        assert!(!s.body.contains("fedcba9876543210"));
        d.member_key_checked = false;
        let s = enrolled_screen(&d);
        assert!(s.body.contains("fedcba9876543210"));
        assert!(s.body.contains("don't approve"));
    }

    #[test]
    fn every_failure_has_words_and_keeps_the_detail() {
        use FailureKind::*;
        for kind in [
            BadInput,
            Unreachable,
            NotFaro,
            WrongCode,
            AlreadyEnrolled,
            NotApproved,
            InstanceChanged,
            MemberKeyMismatch,
            Busy,
            Unavailable,
            Failed,
        ] {
            let s = failure_screen(kind, "the detail");
            assert!(!s.title.is_empty() && !s.body.is_empty(), "{kind:?}");
            assert!(s.body.ends_with("Details: the detail"), "{kind:?}");
            assert!(!failure_screen(kind, " ").body.contains("Details"));
        }
        assert!(failure_screen(WrongCode, "").body.contains("new one"));
        assert!(failure_screen(NotApproved, "").body.contains("Nothing was changed"));
    }

    #[test]
    fn already_enrolled_says_with_what() {
        let s = already_enrolled_screen(&EnrollStatus {
            enrolled: true,
            instance_name: Some("Sam's Faro".into()),
            instance_url: Some("https://faro.example.org/".into()),
            endorsed: false,
        });
        assert!(s.body.contains("\u{201c}Sam's Faro\u{201d} (https://faro.example.org/)"));
        assert!(s.body.contains("waiting for approval"));
    }
}
