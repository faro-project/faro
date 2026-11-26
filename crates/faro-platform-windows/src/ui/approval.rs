//! Administrator approval for enrolling, through UAC. The Windows
//! counterpart of macOS's Authorization Services flow (issue #62).
//!
//! Enrolling changes the machine-wide service, so an administrator of the
//! computer must approve it, and the unprivileged agent must never be able
//! to enroll by itself. The service runs as SYSTEM in session 0 and can't
//! show a UAC prompt, so the agent starts an **elevated helper** in the
//! person's session, and the **service** checks that helper's token
//! itself. The agent only carries a random request id; it decides nothing.
//!
//! # The contract
//!
//! ```text
//! agent (user)              helper (elevated admin)          service (SYSTEM)
//!   │ request = 32 random bytes
//!   │ ShellExecuteExW("runas", faro-service.exe,
//!   │   "approve-enroll --request <64 hex>")
//!   │    ── UAC: consent (admin) or credentials (standard user) ──
//!   │                        │ connect to the service's pipe ─▶ │ check the client:
//!   │                        │ ApproveEnroll { request }        │  token, session, image
//!   │                        │ ◀──────────── Approved | Refused │ record (request, session,
//!   │ ◀── exit code ──────── │                                  │   approver) for 5 min
//!   │ Enroll { …, authorization: request } ──────────────────▶ │ consume the record
//! ```
//!
//! **Agent** ([`ApprovalRequest::generate`], [`request_admin_approval`]):
//! after the person confirms the instance, generate a request, run
//! [`HELPER_PROGRAM`] elevated with [`ApprovalRequest::helper_arguments`],
//! wait for it, then send `EnrollRequest::Enroll` with the request bytes as
//! `authorization` (its 32 bytes, [`REQUEST_LEN`], are
//! `faro_ipc::AUTHORIZATION_LEN`). In `faro_agent::enroll::Authorizer`
//! terms, `create()` does both and returns the bytes. Declining the UAC
//! prompt is [`ApprovalError::Declined`].
//!
//! **Helper** (`faro-service.exe approve-enroll --request <hex>`; to be
//! written in `faro-service`): parse the arguments with
//! [`ApprovalRequest::parse_helper_arguments`] (exit
//! [`exit::BAD_ARGUMENTS`] if they don't parse), connect to the service's
//! enroll pipe, send the request id, and exit with [`exit::APPROVED`],
//! [`exit::REFUSED`] or [`exit::NO_SERVICE`]. It shows nothing and holds
//! no secret: it only *is* an elevated administrator process, which is
//! what the service checks. It is the service binary (not the agent) so
//! that the agent is never run elevated and the UAC prompt names the
//! program that makes the change.
//!
//! **Service** (the trust decision): on the approval request, using the
//! *pipe client's* token (`ImpersonateNamedPipeClient` +
//! `OpenThreadToken(TOKEN_QUERY | TOKEN_DUPLICATE)`, then `RevertToSelf`;
//! not a PID lookup, which can race):
//!
//! 1. [`check_approver_token`] must succeed: an enabled member of
//!    `BUILTIN\Administrators`, elevated (`TokenIsElevated`), integrity
//!    High or System. A filtered (UAC-limited) admin token fails, so the
//!    UAC prompt is the only way to get there.
//! 2. The client's session (`GetNamedPipeClientSessionId`, which must equal
//!    [`Approver::session_id`]) must have an agent connected, so an
//!    approval in one session doesn't serve another.
//! 3. Recommended, defense in depth: the client's image is
//!    `layout::SERVICE_PROGRAM` with a valid Faro Authenticode signature
//!    (`authenticode`). Not essential: any elevated administrator process
//!    could already run `faro-service enroll` itself.
//! 4. Record `(request, session, approver SID, now)`, keep it for
//!    [`APPROVAL_TTL`], at most a few at a time, and answer Approved.
//!
//! Then on `Enroll`: the `authorization` bytes must match a live record
//! *from the session of the agent that sends `Enroll`*; remove it at once
//! (one use), whatever the outcome, and log the approver's SID. No record:
//! `Failed { kind: NotApproved }`. Compare in constant time. A `--dev`
//! build's weaker pipe-client check (who may *send* `Enroll`) changes
//! nothing here: the approval still needs the elevated token.
//!
//! Unlike macOS (where the root service shows the prompt while it handles
//! `Enroll`), the approval comes *before* `Enroll`, so the service keeps
//! this one short-lived table. `Preview` and `Enroll` stay stateless.

use std::ffi::c_void;
use std::path::Path;
use std::time::Duration;

use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_CANCELLED, HANDLE, HLOCAL, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetSidSubAuthority,
    GetSidSubAuthorityCount, GetTokenInformation, SecurityIdentification, TokenElevation,
    TokenIntegrityLevel, TokenSessionId, TokenUser, WinBuiltinAdministratorsSid, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_USER,
};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{
    ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// The helper's program: the service binary.
pub const HELPER_PROGRAM: &str = crate::layout::SERVICE_PROGRAM;
/// The helper's subcommand.
pub const APPROVE_ENROLL_COMMAND: &str = "approve-enroll";
/// The flag before the request id.
pub const REQUEST_FLAG: &str = "--request";
/// Bytes in a request id (`faro_ipc::AUTHORIZATION_LEN`).
pub const REQUEST_LEN: usize = 32;
/// How long the service keeps an approval for `Enroll` to use.
pub const APPROVAL_TTL: Duration = Duration::from_secs(5 * 60);
/// How long the agent waits for the helper once UAC has started it.
pub const HELPER_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// The helper's exit codes.
pub mod exit {
    /// The service checked the helper and recorded the approval.
    pub const APPROVED: u32 = 0;
    /// The service refused (not an elevated administrator, wrong session…).
    pub const REFUSED: u32 = 10;
    /// The service didn't answer.
    pub const NO_SERVICE: u32 = 11;
    /// The arguments didn't parse.
    pub const BAD_ARGUMENTS: u32 = 12;
}

/// A request id: random, used once. Its bytes never appear in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalRequest([u8; REQUEST_LEN]);

impl std::fmt::Debug for ApprovalRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApprovalRequest(..)")
    }
}

impl ApprovalRequest {
    /// A new random request id (the system RNG).
    pub fn generate() -> windows::core::Result<Self> {
        let mut b = [0u8; REQUEST_LEN];
        // SAFETY: fills our buffer.
        unsafe { BCryptGenRandom(None, &mut b, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok()? };
        Ok(ApprovalRequest(b))
    }

    pub fn from_bytes(bytes: [u8; REQUEST_LEN]) -> Self {
        ApprovalRequest(bytes)
    }

    /// The bytes sent as `Enroll`'s `authorization`.
    pub fn bytes(&self) -> &[u8; REQUEST_LEN] {
        &self.0
    }

    /// The helper's command line after the program:
    /// `approve-enroll --request <64 lowercase hex digits>`.
    pub fn helper_arguments(&self) -> String {
        let hex: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        format!("{APPROVE_ENROLL_COMMAND} {REQUEST_FLAG} {hex}")
    }

    /// Parse the helper's arguments after the program name, exactly as
    /// [`helper_arguments`](Self::helper_arguments) writes them.
    pub fn parse_helper_arguments<S: AsRef<str>>(args: &[S]) -> Option<Self> {
        let [cmd, flag, hex] = args else {
            return None;
        };
        if cmd.as_ref() != APPROVE_ENROLL_COMMAND || flag.as_ref() != REQUEST_FLAG {
            return None;
        }
        let hex = hex.as_ref();
        if hex.len() != REQUEST_LEN * 2 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut b = [0u8; REQUEST_LEN];
        for (i, out) in b.iter_mut().enumerate() {
            *out = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(ApprovalRequest(b))
    }
}

/// Why no approval was recorded.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("the administrator approval was cancelled")]
    Declined,
    #[error("the Faro service refused the approval")]
    Refused,
    #[error("the Faro service didn't answer the approval")]
    NoService,
    #[error("the approval helper didn't understand its arguments")]
    BadArguments,
    #[error("the approval helper ended with code {0}")]
    Helper(u32),
    #[error("the approval helper didn't finish in time")]
    TimedOut,
    #[error("could not start the approval helper: {0}")]
    Launch(windows::core::Error),
}

/// Run `program` (normally [`HELPER_PROGRAM`]) elevated through UAC with
/// `request`'s arguments, and wait for it. `Ok` once the service has
/// recorded the approval. Blocks through the UAC prompt: never call it
/// from the UI thread.
pub fn request_admin_approval(
    program: &Path,
    request: &ApprovalRequest,
) -> Result<(), ApprovalError> {
    let file = HSTRING::from(program.as_os_str());
    let params = HSTRING::from(request.helper_arguments());
    // ShellExecuteEx may hand the work to shell extensions, which want COM.
    // SAFETY: balanced with CoUninitialize below when it succeeded.
    let com = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.is_ok();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: `info` and the strings it points to outlive the call.
    let launched = unsafe { ShellExecuteExW(&mut info) };
    if com {
        // SAFETY: balances the successful CoInitializeEx.
        unsafe { CoUninitialize() };
    }
    if let Err(e) = launched {
        return Err(if e.code() == ERROR_CANCELLED.to_hresult() {
            ApprovalError::Declined
        } else {
            ApprovalError::Launch(e)
        });
    }
    let process = info.hProcess;
    if process.is_invalid() {
        return Err(ApprovalError::Launch(windows::core::Error::from_thread()));
    }
    // SAFETY: our own process handle, closed below.
    let code = unsafe {
        let waited = WaitForSingleObject(process, HELPER_TIMEOUT.as_millis() as u32);
        let mut code = 0u32;
        let got = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
        match waited {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Err(ApprovalError::TimedOut),
            _ => return Err(ApprovalError::Launch(windows::core::Error::from_thread())),
        }
        got.map_err(ApprovalError::Launch)?;
        code
    };
    match code {
        exit::APPROVED => Ok(()),
        exit::REFUSED => Err(ApprovalError::Refused),
        exit::NO_SERVICE => Err(ApprovalError::NoService),
        exit::BAD_ARGUMENTS => Err(ApprovalError::BadArguments),
        other => Err(ApprovalError::Helper(other)),
    }
}

/// Who approved: from a token that passed [`check_approver_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    /// The token's session.
    pub session_id: u32,
    /// The approving account, as an SID string, for the service's log.
    pub user_sid: String,
    /// The mandatory integrity level's RID (0x3000 High, 0x4000 System).
    pub integrity_rid: u32,
}

/// Why a token can't approve.
#[derive(Debug, thiserror::Error)]
pub enum NotAnApprover {
    #[error("not a member of Administrators")]
    NotAdministrator,
    #[error("not elevated")]
    NotElevated,
    #[error("integrity level {0:#x} is below High")]
    IntegrityTooLow(u32),
    #[error("could not read the token: {0}")]
    Query(windows::core::Error),
}

/// `SECURITY_MANDATORY_HIGH_RID`.
const HIGH_RID: u32 = 0x3000;

/// Whether `token` belongs to an elevated administrator, the check the
/// service makes on the helper (see the module docs). `token` needs
/// `TOKEN_QUERY`, and `TOKEN_DUPLICATE` if it is a primary token.
///
/// # Safety
///
/// `token` must be a valid token handle for the duration of the call.
pub unsafe fn check_approver_token(token: HANDLE) -> Result<Approver, NotAnApprover> {
    // SAFETY: the caller's contract.
    unsafe {
        if !is_admin_member(token)? {
            return Err(NotAnApprover::NotAdministrator);
        }
        let mut elevation = TOKEN_ELEVATION::default();
        query_fixed(token, TokenElevation, &mut elevation)?;
        if elevation.TokenIsElevated == 0 {
            return Err(NotAnApprover::NotElevated);
        }
        let label = query_var(token, TokenIntegrityLevel)?;
        let sid = (*(label.as_ptr() as *const TOKEN_MANDATORY_LABEL))
            .Label
            .Sid;
        let count = *GetSidSubAuthorityCount(sid);
        let rid = if count == 0 {
            0
        } else {
            *GetSidSubAuthority(sid, u32::from(count) - 1)
        };
        if rid < HIGH_RID {
            return Err(NotAnApprover::IntegrityTooLow(rid));
        }
        let mut session_id = 0u32;
        query_fixed(token, TokenSessionId, &mut session_id)?;
        let user = query_var(token, TokenUser)?;
        let user_sid = sid_string((*(user.as_ptr() as *const TOKEN_USER)).User.Sid);
        Ok(Approver {
            session_id,
            user_sid,
            integrity_rid: rid,
        })
    }
}

/// Enabled membership in `BUILTIN\Administrators`. `CheckTokenMembership`
/// wants an impersonation token, so a primary token is duplicated.
unsafe fn is_admin_member(token: HANDLE) -> Result<bool, NotAnApprover> {
    // SAFETY: the buffers are ours and as large as declared; the duplicate
    // is closed.
    unsafe {
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut len = sid.len() as u32;
        let psid = PSID(sid.as_mut_ptr().cast());
        CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(psid), &mut len)
            .map_err(NotAnApprover::Query)?;
        let mut member = false.into();
        if CheckTokenMembership(Some(token), psid, &mut member).is_ok() {
            return Ok(member.as_bool());
        }
        let mut dup = HANDLE::default();
        DuplicateToken(token, SecurityIdentification, &mut dup).map_err(NotAnApprover::Query)?;
        let r = CheckTokenMembership(Some(dup), psid, &mut member);
        let _ = CloseHandle(dup);
        r.map_err(NotAnApprover::Query)?;
        Ok(member.as_bool())
    }
}

/// A fixed-size token information class.
unsafe fn query_fixed<T>(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
    out: &mut T,
) -> Result<(), NotAnApprover> {
    let mut len = 0u32;
    // SAFETY: `out` is a `T`, as large as declared.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some((out as *mut T).cast::<c_void>()),
            size_of::<T>() as u32,
            &mut len,
        )
    }
    .map_err(NotAnApprover::Query)
}

/// A variable-size token information class, in an 8-byte-aligned buffer.
unsafe fn query_var(
    token: HANDLE,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u64>, NotAnApprover> {
    // SAFETY: the first call only asks for the size; the second fills a
    // buffer at least that large.
    unsafe {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, class, None, 0, &mut len);
        if len == 0 {
            return Err(NotAnApprover::Query(windows::core::Error::from_thread()));
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr().cast()),
            (buf.len() * 8) as u32,
            &mut len,
        )
        .map_err(NotAnApprover::Query)?;
        Ok(buf)
    }
}

unsafe fn sid_string(sid: PSID) -> String {
    let mut s = PWSTR::null();
    // SAFETY: `sid` is valid (from the token buffer); the string is freed.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut s).is_err() {
            return String::new();
        }
        let out = s.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(s.0.cast())));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[test]
    fn arguments_round_trip_and_nothing_else_parses() {
        let r = ApprovalRequest::from_bytes(core::array::from_fn(|i| i as u8 * 7));
        let line = r.helper_arguments();
        assert!(line.starts_with("approve-enroll --request 00070e15"));
        let args: Vec<&str> = line.split(' ').collect();
        assert_eq!(
            ApprovalRequest::parse_helper_arguments(&args),
            Some(r.clone())
        );
        let hex = args[2];
        for bad in [
            vec!["approve-enroll", "--request"],
            vec!["enroll", "--request", hex],
            vec!["approve-enroll", "--req", hex],
            vec!["approve-enroll", "--request", &hex[1..]],
            vec!["approve-enroll", "--request", hex, "extra"],
        ] {
            assert_eq!(
                ApprovalRequest::parse_helper_arguments(&bad),
                None,
                "{bad:?}"
            );
        }
        let mut nonhex = hex.to_owned();
        nonhex.replace_range(0..1, "g");
        assert_eq!(
            ApprovalRequest::parse_helper_arguments(&["approve-enroll", "--request", &nonhex]),
            None
        );
        assert_eq!(format!("{r:?}"), "ApprovalRequest(..)");
    }

    #[test]
    fn requests_are_random() {
        let a = ApprovalRequest::generate().unwrap();
        let b = ApprovalRequest::generate().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn our_own_token_approves_only_when_elevated() {
        // SAFETY: our own process token, closed below.
        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut token,
            )
            .unwrap();
            let mut e = TOKEN_ELEVATION::default();
            query_fixed(token, TokenElevation, &mut e).unwrap();
            let r = check_approver_token(token);
            let _ = CloseHandle(token);
            if e.TokenIsElevated == 0 {
                assert!(
                    matches!(
                        r,
                        Err(NotAnApprover::NotAdministrator | NotAnApprover::NotElevated)
                    ),
                    "{r:?}"
                );
            } else {
                let a = r.unwrap();
                assert!(a.integrity_rid >= HIGH_RID);
                assert!(a.user_sid.starts_with("S-1-"));
            }
        }
    }
}
