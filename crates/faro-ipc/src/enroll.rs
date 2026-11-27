//! Enrolling the computer from the agent (issue #62, ARCHITECTURE.md §3.8).
//!
//! The session agent can ask the service to enroll the computer, so a
//! member can open a `faro://enroll` link instead of using Terminal. This is
//! its own small protocol on its own socket, not part of the agent's
//! session protocol ([`AgentMsg`](crate::AgentMsg) /
//! [`ServiceMsg`](crate::ServiceMsg)): the service listens for it before the
//! computer is enrolled, when no agent socket exists yet.
//!
//! ```text
//! agent                                     service (root)
//!   │ Status ───────────────────────────────▶ │  enrolled? with what?
//!   │ Preview(target) ──────────────────────▶ │  parse, GET /.well-known/faro
//!   │ ◀────────────── Preview { name, identity key, accounts, … }
//!   │   (the person confirms the instance)
//!   │ Enroll { target, confirmed identity, authorization } ─▶
//!   │                                         │  discover again, compare,
//!   │                                         │  ask an administrator,
//!   │                                         │  enroll (the CLI's code)
//!   │ ◀────────────── Enrolled { fingerprints } | Failed { kind, detail }
//! ```
//!
//! One request per connection, answered once; the connection then closes.
//! The service keeps no state between `Preview` and `Enroll`: `Enroll`
//! carries what the person confirmed, and the service checks it against
//! what it discovers itself.
//!
//! **The agent cannot enroll by itself.** `authorization` is a macOS
//! `AuthorizationExternalForm` (32 bytes) with no rights in it; the service
//! asks Authorization Services for an administrator's approval with it, and
//! only an administrator's name and password, typed into the system's own
//! dialog, produce one.
//!
//! Every type here is bounded by [`WireMessage::validate`], and the one-time
//! code and the authorization bytes never appear in `Debug` output.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::connection::Connection;
use crate::endpoint::AccountId;
use crate::error::{IpcError, Result};
use crate::messages::WireMessage;

/// Size of a macOS `AuthorizationExternalForm`
/// (`kAuthorizationExternalFormLength`).
pub const AUTHORIZATION_LEN: usize = 32;

/// Longest link or instance address accepted (the service's own limits are
/// tighter; this only bounds the message).
pub const MAX_TARGET_LEN: usize = 4096;
/// Longest typed code accepted.
pub const MAX_CODE_LEN: usize = 64;
/// Longest name, address, id or fingerprint in a response.
pub const MAX_TEXT_LEN: usize = 2048;
/// Longest `Failed` detail.
pub const MAX_DETAIL_LEN: usize = 1024;
/// Most accounts listed in a preview.
pub const MAX_ACCOUNTS: usize = 256;
/// Longest account name in a preview.
pub const MAX_ACCOUNT_LEN: usize = 256;

/// The enroll endpoint for `account`, next to the agent endpoint
/// `agent_base`: `enroll.<uid>.sock` / `\\.\pipe\faro\enroll.<SID>` (a
/// privileged service binds one per account that only that account can
/// connect to), or `enroll.sock` / `\\.\pipe\faro\enroll` for `None` (a
/// development service running as the user). See [`crate::endpoint`].
pub fn enroll_socket_path(agent_base: &Path, account: Option<AccountId>) -> PathBuf {
    let ext = agent_base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let name = match account {
        Some(account) => format!("enroll.{account}{ext}"),
        None => format!("enroll{ext}"),
    };
    agent_base.with_file_name(name)
}

/// Where an agent running as `account` should connect: its own enroll
/// endpoint if the service has bound one, else the development service's.
/// As with [`resolve_agent_socket`](crate::resolve_agent_socket), who
/// listens there is checked when connecting.
pub fn resolve_enroll_socket(agent_base: &Path, account: AccountId) -> PathBuf {
    let own = enroll_socket_path(agent_base, Some(account));
    if crate::endpoint::endpoint_exists(&own) {
        own
    } else {
        enroll_socket_path(agent_base, None)
    }
}

/// What the person gave the agent: a whole link, or an instance address and
/// a code typed separately. The service parses both (with the CLI's
/// parsers); the agent never interprets them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollTarget {
    /// A `faro://enroll?i=…&c=…[&m=…]` link.
    Link(String),
    /// An instance address and the one-time code shown next to it.
    Manual { instance: String, code: String },
}

impl fmt::Debug for EnrollTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A link carries the one-time code, so neither form is printed.
        match self {
            EnrollTarget::Link(_) => f.write_str("Link(..)"),
            EnrollTarget::Manual { instance, .. } => f
                .debug_struct("Manual")
                .field("instance", &clip(instance, 80))
                .finish_non_exhaustive(),
        }
    }
}

/// From the agent to the service.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollRequest {
    /// Is this computer enrolled already?
    Status,
    /// Look the instance up and say what enrolling would do. Changes
    /// nothing and needs no approval.
    Preview(EnrollTarget),
    /// Enroll, if an administrator approves.
    Enroll {
        target: EnrollTarget,
        /// The instance id the person confirmed (from `Preview`).
        confirmed_instance: String,
        /// The identity key the person confirmed (from `Preview`). The
        /// service refuses if the instance now answers with another.
        confirmed_identity: [u8; 32],
        /// `AuthorizationExternalForm` of an authorization the agent created
        /// with no rights.
        authorization: [u8; AUTHORIZATION_LEN],
    },
    /// Windows only: an elevated administrator's helper
    /// (`faro-service approve-enroll`) asks the service to record that it
    /// approved the enrollment the agent will request with `request` as its
    /// `authorization`. The service checks the helper's own token. Appended
    /// last, so the encodings of the other variants are unchanged.
    ///
    /// `binding` is SHA-256 over a domain-separated encoding of the
    /// instance URL and name the administrator was shown and the `request`
    /// (see `faro_service::enroll_approval::approval_binding`). The service
    /// keeps it with the approval and on `Enroll` recomputes it from the
    /// instance it discovered, so an approval is good only for the target
    /// the approver saw.
    ApproveEnroll {
        request: [u8; AUTHORIZATION_LEN],
        binding: [u8; 32],
    },
}

impl fmt::Debug for EnrollRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollRequest::Status => f.write_str("Status"),
            EnrollRequest::Preview(t) => f.debug_tuple("Preview").field(t).finish(),
            EnrollRequest::Enroll {
                target,
                confirmed_instance,
                ..
            } => f
                .debug_struct("Enroll")
                .field("target", target)
                .field("confirmed_instance", &clip(confirmed_instance, 80))
                .finish_non_exhaustive(),
            // The request id is the secret the approval is redeemed with.
            EnrollRequest::ApproveEnroll { .. } => f.write_str("ApproveEnroll(..)"),
        }
    }
}

impl EnrollRequest {
    /// Variant name, safe to log.
    pub fn kind(&self) -> &'static str {
        match self {
            EnrollRequest::Status => "Status",
            EnrollRequest::Preview(_) => "Preview",
            EnrollRequest::Enroll { .. } => "Enroll",
            EnrollRequest::ApproveEnroll { .. } => "ApproveEnroll",
        }
    }
}

/// Whether the computer is enrolled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollStatus {
    pub enrolled: bool,
    /// The instance's name and address, when enrolled.
    pub instance_name: Option<String>,
    pub instance_url: Option<String>,
    /// The member has approved the computer in the web app.
    pub endorsed: bool,
}

/// What enrolling would do, for the person to confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollPreview {
    /// The instance's name (sanitized by the service).
    pub instance_name: String,
    /// Its address, normalized.
    pub instance_url: String,
    pub instance_id: String,
    /// The instance's identity key, which enrolling pins. Send it back in
    /// `Enroll` as `confirmed_identity`.
    pub identity_key: [u8; 32],
    /// The name this computer will have in the web app.
    pub device_name: String,
    /// The computer's accounts, every one of which is monitored. `None`
    /// when the service cannot list them.
    pub accounts: Option<Vec<String>>,
    /// The guest account is on.
    pub guest_enabled: bool,
    /// The link names the member's key (`m`), so the device will refuse
    /// any other.
    pub member_key_in_link: bool,
}

/// A finished enrollment. Activation continues in the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollDone {
    /// The device key's fingerprint, which the web app shows for the
    /// pending computer.
    pub device_fingerprint: String,
    /// The member key's fingerprint (`key_id`).
    pub member_fingerprint: String,
    /// The member key was checked against the link's `m`. If not, the
    /// person compares `member_fingerprint` with their web app.
    pub member_key_checked: bool,
}

/// Why a request failed, for the agent to pick its words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureKind {
    /// The link, address or code is malformed.
    BadInput,
    /// The instance could not be reached.
    Unreachable,
    /// Something answered, but not a Faro instance this client can use.
    NotFaro,
    /// The instance refused the code (unknown, used or expired).
    WrongCode,
    /// The computer is enrolled already.
    AlreadyEnrolled,
    /// No administrator approved (cancelled, wrong password, or timed out).
    NotApproved,
    /// The instance answers with another identity than the one confirmed.
    InstanceChanged,
    /// The instance answered with a member key other than the link's.
    MemberKeyMismatch,
    /// Another enrollment is in progress.
    Busy,
    /// Enrolling from the agent is not possible on this computer (no
    /// approval mechanism, or its rule is missing or altered).
    Unavailable,
    /// Anything else.
    Failed,
}

/// From the service to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollResponse {
    Status(EnrollStatus),
    Preview(EnrollPreview),
    Enrolled(EnrollDone),
    Failed {
        kind: FailureKind,
        detail: String,
    },
    /// The answer to `ApproveEnroll`: the approval was recorded. A refusal
    /// is `Failed { kind: NotApproved, .. }`. Appended last.
    Approved,
}

impl EnrollResponse {
    /// Variant name, safe to log.
    pub fn kind(&self) -> &'static str {
        match self {
            EnrollResponse::Status(_) => "Status",
            EnrollResponse::Preview(_) => "Preview",
            EnrollResponse::Enrolled(_) => "Enrolled",
            EnrollResponse::Failed { .. } => "Failed",
            EnrollResponse::Approved => "Approved",
        }
    }

    /// A `Failed` response, with `detail` cut to [`MAX_DETAIL_LEN`].
    pub fn failed(kind: FailureKind, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        EnrollResponse::Failed {
            kind,
            detail: clip(&detail, MAX_DETAIL_LEN),
        }
    }
}

/// The service's end of an enroll connection.
pub type EnrollServerConnection<S> = Connection<S, EnrollResponse, EnrollRequest>;
/// The agent's end of an enroll connection.
pub type EnrollClientConnection<S> = Connection<S, EnrollRequest, EnrollResponse>;

fn check_len(field: &'static str, s: &str, max: usize) -> Result<()> {
    if s.len() > max {
        return Err(IpcError::FieldTooLong {
            field,
            len: s.len(),
            max,
        });
    }
    Ok(())
}

/// At most `max` bytes of `s`, cut at a character boundary.
fn clip(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

impl EnrollTarget {
    fn validate(&self) -> Result<()> {
        match self {
            EnrollTarget::Link(l) => check_len("link", l, MAX_TARGET_LEN),
            EnrollTarget::Manual { instance, code } => {
                check_len("instance", instance, MAX_TARGET_LEN)?;
                check_len("code", code, MAX_CODE_LEN)
            }
        }
    }
}

impl WireMessage for EnrollRequest {
    fn validate(&self) -> Result<()> {
        match self {
            EnrollRequest::Status | EnrollRequest::ApproveEnroll { .. } => Ok(()),
            EnrollRequest::Preview(t) => t.validate(),
            EnrollRequest::Enroll {
                target,
                confirmed_instance,
                ..
            } => {
                target.validate()?;
                check_len("confirmed_instance", confirmed_instance, MAX_TEXT_LEN)
            }
        }
    }

    fn kind_name(&self) -> &'static str {
        self.kind()
    }
}

impl WireMessage for EnrollResponse {
    fn validate(&self) -> Result<()> {
        match self {
            EnrollResponse::Status(s) => {
                for (field, v) in [
                    ("instance_name", &s.instance_name),
                    ("instance_url", &s.instance_url),
                ] {
                    if let Some(v) = v {
                        check_len(field, v, MAX_TEXT_LEN)?;
                    }
                }
                Ok(())
            }
            EnrollResponse::Preview(p) => {
                check_len("instance_name", &p.instance_name, MAX_TEXT_LEN)?;
                check_len("instance_url", &p.instance_url, MAX_TEXT_LEN)?;
                check_len("instance_id", &p.instance_id, MAX_TEXT_LEN)?;
                check_len("device_name", &p.device_name, MAX_TEXT_LEN)?;
                if let Some(accounts) = &p.accounts {
                    if accounts.len() > MAX_ACCOUNTS {
                        return Err(IpcError::FieldTooLong {
                            field: "accounts",
                            len: accounts.len(),
                            max: MAX_ACCOUNTS,
                        });
                    }
                    for a in accounts {
                        check_len("account", a, MAX_ACCOUNT_LEN)?;
                    }
                }
                Ok(())
            }
            EnrollResponse::Enrolled(d) => {
                check_len("device_fingerprint", &d.device_fingerprint, MAX_TEXT_LEN)?;
                check_len("member_fingerprint", &d.member_fingerprint, MAX_TEXT_LEN)
            }
            EnrollResponse::Failed { detail, .. } => check_len("detail", detail, MAX_DETAIL_LEN),
            EnrollResponse::Approved => Ok(()),
        }
    }

    fn kind_name(&self) -> &'static str {
        self.kind()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    fn requests() -> Vec<EnrollRequest> {
        vec![
            EnrollRequest::Status,
            EnrollRequest::Preview(EnrollTarget::Link(
                "faro://enroll?i=https%3A%2F%2Fa.example&c=ABCD-1234".into(),
            )),
            EnrollRequest::Enroll {
                target: EnrollTarget::Manual {
                    instance: "https://a.example".into(),
                    code: "ABCD-1234".into(),
                },
                confirmed_instance: "inst_a".into(),
                confirmed_identity: [7; 32],
                authorization: [9; AUTHORIZATION_LEN],
            },
            EnrollRequest::ApproveEnroll {
                request: [9; AUTHORIZATION_LEN],
                binding: [5; 32],
            },
        ]
    }

    fn responses() -> Vec<EnrollResponse> {
        vec![
            EnrollResponse::Status(EnrollStatus {
                enrolled: true,
                instance_name: Some("Example".into()),
                instance_url: Some("https://a.example/".into()),
                endorsed: false,
            }),
            EnrollResponse::Preview(EnrollPreview {
                instance_name: "Example".into(),
                instance_url: "https://a.example/".into(),
                instance_id: "inst_a".into(),
                identity_key: [1; 32],
                device_name: "Laptop".into(),
                accounts: Some(vec!["alex".into(), "sam".into()]),
                guest_enabled: true,
                member_key_in_link: false,
            }),
            EnrollResponse::Enrolled(EnrollDone {
                device_fingerprint: "0123456789abcdef".into(),
                member_fingerprint: "fedcba9876543210".into(),
                member_key_checked: true,
            }),
            EnrollResponse::failed(FailureKind::WrongCode, "nope"),
            EnrollResponse::Approved,
        ]
    }

    #[test]
    fn round_trip() {
        for r in requests() {
            let bytes = encode(&r).unwrap();
            assert_eq!(decode::<EnrollRequest>(&bytes).unwrap(), r);
        }
        for r in responses() {
            let bytes = encode(&r).unwrap();
            assert_eq!(decode::<EnrollResponse>(&bytes).unwrap(), r);
        }
    }

    #[test]
    fn debug_hides_the_code_and_the_authorization() {
        for r in requests() {
            let d = format!("{r:?}");
            assert!(!d.contains("ABCD"), "{d}");
            assert!(!d.contains("9, 9"), "{d}");
        }
        let d = format!(
            "{:?}",
            EnrollTarget::Manual {
                instance: "https://a.example".into(),
                code: "SECRET99".into()
            }
        );
        assert!(d.contains("a.example") && !d.contains("SECRET"), "{d}");
    }

    #[test]
    fn oversized_fields_are_refused_both_ways() {
        let big = EnrollRequest::Preview(EnrollTarget::Link("x".repeat(MAX_TARGET_LEN + 1)));
        assert!(matches!(
            encode(&big),
            Err(IpcError::FieldTooLong { field: "link", .. })
        ));
        let code = EnrollRequest::Preview(EnrollTarget::Manual {
            instance: "a".into(),
            code: "c".repeat(MAX_CODE_LEN + 1),
        });
        assert!(encode(&code).is_err());
        let many = EnrollResponse::Preview(EnrollPreview {
            instance_name: "n".into(),
            instance_url: "u".into(),
            instance_id: "i".into(),
            identity_key: [0; 32],
            device_name: "d".into(),
            accounts: Some(vec!["a".into(); MAX_ACCOUNTS + 1]),
            guest_enabled: false,
            member_key_in_link: false,
        });
        assert!(encode(&many).is_err());
        // A peer that skips validation is refused on decode too.
        let raw = postcard::to_allocvec(&big).unwrap();
        let mut frame = crate::codec::MAGIC.to_vec();
        frame.extend_from_slice(&crate::codec::PROTOCOL_VERSION.to_be_bytes());
        frame.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        frame.extend_from_slice(&raw);
        assert!(matches!(
            decode::<EnrollRequest>(&frame),
            Err(IpcError::FieldTooLong { .. })
        ));
    }

    #[test]
    fn failed_detail_is_clipped() {
        let r = EnrollResponse::failed(FailureKind::Failed, "é".repeat(MAX_DETAIL_LEN));
        let EnrollResponse::Failed { detail, .. } = &r else {
            unreachable!()
        };
        assert!(detail.len() <= MAX_DETAIL_LEN);
        assert!(encode(&r).is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn socket_names() {
        let base = Path::new("/var/run/faro/agent.sock");
        assert_eq!(
            enroll_socket_path(base, Some(501)),
            Path::new("/var/run/faro/enroll.501.sock")
        );
        assert_eq!(
            enroll_socket_path(base, None),
            Path::new("/var/run/faro/enroll.sock")
        );
        assert_eq!(
            enroll_socket_path(Path::new("/run/faro/agent"), Some(1000)),
            Path::new("/run/faro/enroll.1000")
        );
        assert_eq!(
            resolve_enroll_socket(Path::new("/nonexistent-faro/agent.sock"), 501),
            Path::new("/nonexistent-faro/enroll.sock")
        );
    }

    #[cfg(windows)]
    #[test]
    fn pipe_names() {
        let sid: crate::Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        let base = Path::new(r"\\.\pipe\faro\agent");
        assert_eq!(
            enroll_socket_path(base, Some(sid)),
            Path::new(r"\\.\pipe\faro\enroll.S-1-5-21-1-2-3-1001")
        );
        assert_eq!(
            enroll_socket_path(base, None),
            Path::new(r"\\.\pipe\faro\enroll")
        );
        assert_eq!(
            resolve_enroll_socket(Path::new(r"\\.\pipe\faro-nonexistent-test\agent"), sid),
            Path::new(r"\\.\pipe\faro-nonexistent-test\enroll")
        );
    }
}
