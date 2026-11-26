//! Service-side Windows integration: Terminal Services sessions, launching
//! the session agent into them, and session-change events
//! (ARCHITECTURE.md §3.1, §3.3 "Windows").
//!
//! # Sessions
//!
//! Every logon on Windows, at the console or over RDP, and every account
//! switched away from with fast user switching, is a Terminal Services
//! (WTS) session with a numeric id. Session 0 is where services run and is
//! never interactive. [`enumerate_sessions`] lists the others that have a
//! user, through `WTSEnumerateSessionsW` and `WTSQuerySessionInformationW`;
//! [`WinServiceHost::list_sessions`] reduces them to
//! [`faro_platform::SessionInfo`] with ids of the form `wts:<id>`
//! ([`session_id`], [`parse_session_id`]).
//!
//! A *disconnected* session (switched away from, or an RDP client that went
//! away) still has a logged-on user whose programs keep running, so it is
//! listed (with `active: false`) and still gets an agent: a second account
//! left running in the background must not be a way around Faro.
//!
//! # Launching the agent
//!
//! The service runs as LocalSystem in session 0 and cannot show anything
//! to a user or capture their screen, so it starts `faro-agent.exe run` in
//! each user session ([`WinServiceHost::spawn_in_session`]):
//!
//! 1. `WTSQueryUserToken(session)`: the primary token of the user logged on
//!    there. It requires `SeTcbPrivilege`, which only LocalSystem holds, so
//!    any other caller gets [`PlatformError::PermissionDenied`]. For an
//!    administrator with UAC this is the **filtered** (non-elevated) token,
//!    so the agent never runs elevated.
//! 2. `DuplicateTokenEx` to a fresh primary token the service owns.
//! 3. `CreateEnvironmentBlock` from that token: the user's own environment
//!    (profile paths, `%LOCALAPPDATA%`), never the service's.
//! 4. `CreateProcessAsUserW` on desktop `winsta0\default` (the user's
//!    interactive desktop), with no inherited handles (nothing of the
//!    service's leaks into a process the user controls), no console window
//!    (`CREATE_NO_WINDOW`) and the program's directory as working directory.
//!
//! The program and its arguments default to [`layout::AGENT_PROGRAM`] and
//! `run`, and can be replaced ([`WinServiceHost::with_agent`]) for tests
//! and spike tools.
//!
//! The user owns the process it starts (its token's default DACL grants
//! them full access), so a user can always kill their agent. That is
//! expected: the service notices (the returned process handle is
//! signalled, and the agent's pipe closes), relaunches it and reports
//! `agent_restarted` (§3.7).
//!
//! # Session changes
//!
//! The SCM delivers `SERVICE_CONTROL_SESSIONCHANGE` to the service's control
//! handler ([`crate::scm`]); [`SessionEvent::from_raw`] decodes it.

use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use faro_platform::{AgentPid, PlatformError, Result as PlatformResult, ServiceHost};
use faro_platform::{SessionId, SessionInfo};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_TOKEN, ERROR_PRIVILEGE_NOT_HELD, HANDLE, WIN32_ERROR,
};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityIdentification, TokenPrimary, TOKEN_ADJUST_DEFAULT,
    TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::{
    WTSClientProtocolType, WTSDomainName, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSQueryUserToken, WTSUserName, WTS_CONNECTSTATE_CLASS,
    WTS_INFO_CLASS, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use crate::layout;

/// The session id format used in [`SessionId`]: `wts:<WTS session id>`.
pub fn session_id(wts_id: u32) -> SessionId {
    SessionId(format!("wts:{wts_id}"))
}

/// The WTS session id in a [`SessionId`] made by [`session_id`].
pub fn parse_session_id(id: &SessionId) -> Option<u32> {
    let n = id.0.strip_prefix("wts:")?;
    // Reject signs, spaces and leading zeros so the text form is canonical.
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0'))
    {
        return None;
    }
    n.parse().ok()
}

/// A WTS connection state (`WTS_CONNECTSTATE_CLASS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectState {
    /// A user is logged on and the session is attached to the console or a
    /// connected RDP client: it is at a screen.
    Active,
    /// Connected to a client, no user logged on yet (the logon screen).
    Connected,
    ConnectQuery,
    Shadow,
    /// A user is logged on but no screen is attached (switched away from,
    /// or the RDP client disconnected). Programs keep running.
    Disconnected,
    Idle,
    Listen,
    Reset,
    Down,
    Init,
    Other(i32),
}

impl ConnectState {
    fn from_raw(s: WTS_CONNECTSTATE_CLASS) -> Self {
        match s.0 {
            0 => Self::Active,
            1 => Self::Connected,
            2 => Self::ConnectQuery,
            3 => Self::Shadow,
            4 => Self::Disconnected,
            5 => Self::Idle,
            6 => Self::Listen,
            7 => Self::Reset,
            8 => Self::Down,
            9 => Self::Init,
            n => Self::Other(n),
        }
    }
}

/// How a session is attached (`WTSClientProtocolType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// The physical console (including a session switched away from).
    Console,
    /// Remote Desktop.
    Rdp,
    Other(u16),
}

/// One WTS session with a logged-on user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtsSession {
    pub id: u32,
    /// The account name (`alex`), without the domain.
    pub user: String,
    /// The account's domain: the computer name for local accounts, the
    /// domain (or `AzureAD`, `MicrosoftAccount`…) otherwise.
    pub domain: String,
    pub state: ConnectState,
    pub protocol: Protocol,
}

impl WtsSession {
    /// At a screen right now.
    pub fn active(&self) -> bool {
        self.state == ConnectState::Active
    }

    /// The [`SessionInfo`] for this session.
    pub fn to_session_info(&self) -> SessionInfo {
        SessionInfo {
            id: session_id(self.id),
            user: self.user.clone(),
            graphical: true,
            active: self.active(),
        }
    }
}

/// Which raw sessions are user sessions Faro serves: not session 0, with a
/// user name, and in a state where the user is logged on (active or
/// disconnected; the others are listeners, logon screens or teardown).
pub fn is_user_session(s: &WtsSession) -> bool {
    s.id != 0
        && !s.user.is_empty()
        && matches!(s.state, ConnectState::Active | ConnectState::Disconnected)
}

/// Every WTS session on this computer that has a logged-on user (see
/// [`is_user_session`]). Works without privilege.
pub fn enumerate_sessions() -> PlatformResult<Vec<WtsSession>> {
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: valid out pointers; the local server; version 1 is required.
    unsafe { WTSEnumerateSessionsW(None, 0, 1, &mut list, &mut count) }
        .map_err(|e| PlatformError::Os(format!("WTSEnumerateSessionsW: {e}")))?;
    // SAFETY: on success `list` points to `count` entries, freed below.
    let raw = unsafe { std::slice::from_raw_parts(list, count as usize) }.to_vec();
    // SAFETY: allocated by WTSEnumerateSessionsW, freed once, not used after.
    unsafe { WTSFreeMemory(list.cast()) };
    let mut out = Vec::new();
    for s in raw {
        // A session can end between enumeration and the queries; skip it.
        let Ok(user) = query_string(s.SessionId, WTSUserName) else {
            continue;
        };
        let domain = query_string(s.SessionId, WTSDomainName).unwrap_or_default();
        let protocol = match query_u16(s.SessionId, WTSClientProtocolType) {
            Some(0) => Protocol::Console,
            Some(2) => Protocol::Rdp,
            Some(n) => Protocol::Other(n),
            None => Protocol::Other(u16::MAX),
        };
        let session = WtsSession {
            id: s.SessionId,
            user,
            domain,
            state: ConnectState::from_raw(s.State),
            protocol,
        };
        if is_user_session(&session) {
            out.push(session);
        }
    }
    Ok(out)
}

/// `WTSQuerySessionInformationW` into an owned buffer.
fn query_raw(session: u32, class: WTS_INFO_CLASS) -> windows::core::Result<Vec<u8>> {
    let mut buf = PWSTR::null();
    let mut len = 0u32;
    // SAFETY: valid out pointers; the buffer is freed below.
    unsafe { WTSQuerySessionInformationW(None, session, class, &mut buf, &mut len) }?;
    // SAFETY: on success `buf` holds `len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buf.0.cast::<u8>(), len as usize) }.to_vec();
    // SAFETY: allocated by WTSQuerySessionInformationW, freed once.
    unsafe { WTSFreeMemory(buf.0.cast()) };
    Ok(bytes)
}

fn query_string(session: u32, class: WTS_INFO_CLASS) -> windows::core::Result<String> {
    let bytes = query_raw(session, class)?;
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

fn query_u16(session: u32, class: WTS_INFO_CLASS) -> Option<u16> {
    let bytes = query_raw(session, class).ok()?;
    Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
}

/// What a session change was (`WTS_*` event codes of
/// `SERVICE_CONTROL_SESSIONCHANGE` / `WM_WTSSESSION_CHANGE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionEventKind {
    /// `WTS_CONSOLE_CONNECT`: the session was attached to the console
    /// (a fast user switch *to* it, or the first logon).
    ConsoleConnect,
    /// `WTS_CONSOLE_DISCONNECT`: switched away from at the console.
    ConsoleDisconnect,
    /// `WTS_REMOTE_CONNECT`: an RDP client attached.
    RemoteConnect,
    /// `WTS_REMOTE_DISCONNECT`: the RDP client went away (the user stays
    /// logged on).
    RemoteDisconnect,
    /// `WTS_SESSION_LOGON`: a user logged on; start an agent.
    Logon,
    /// `WTS_SESSION_LOGOFF`: the user logged off; their agent's goodbye is
    /// expected.
    Logoff,
    /// `WTS_SESSION_LOCK`.
    Lock,
    /// `WTS_SESSION_UNLOCK`.
    Unlock,
    /// `WTS_SESSION_REMOTE_CONTROL`: remote control (shadowing) started or
    /// stopped.
    RemoteControl,
    /// `WTS_SESSION_CREATE`.
    Create,
    /// `WTS_SESSION_TERMINATE`.
    Terminate,
    Other(u32),
}

impl SessionEventKind {
    pub fn from_raw(code: u32) -> Self {
        match code {
            1 => Self::ConsoleConnect,
            2 => Self::ConsoleDisconnect,
            3 => Self::RemoteConnect,
            4 => Self::RemoteDisconnect,
            5 => Self::Logon,
            6 => Self::Logoff,
            7 => Self::Lock,
            8 => Self::Unlock,
            9 => Self::RemoteControl,
            10 => Self::Create,
            11 => Self::Terminate,
            n => Self::Other(n),
        }
    }
}

/// A session change and the WTS session it concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionEvent {
    pub kind: SessionEventKind,
    pub session: u32,
}

impl SessionEvent {
    /// Decode `SERVICE_CONTROL_SESSIONCHANGE`'s event type and data.
    ///
    /// # Safety
    /// `data` must be null or point to a `WTSSESSION_NOTIFICATION`, as the
    /// SCM passes to a `HandlerEx` for this control.
    pub unsafe fn from_raw(event_type: u32, data: *const core::ffi::c_void) -> Option<Self> {
        if data.is_null() {
            return None;
        }
        // SAFETY: per the contract. WTSSESSION_NOTIFICATION is
        // { DWORD cbSize; DWORD dwSessionId; }.
        let (cb, session) = unsafe {
            let p = data.cast::<u32>();
            (p.read_unaligned(), p.add(1).read_unaligned())
        };
        if cb < 8 {
            return None;
        }
        Some(SessionEvent {
            kind: SessionEventKind::from_raw(event_type),
            session,
        })
    }

    /// The [`SessionId`] this event concerns.
    pub fn session_id(&self) -> SessionId {
        session_id(self.session)
    }
}

/// A launched agent: its pid and a handle to the process, which is
/// signalled when it exits (wait on it to notice a killed agent at once).
#[derive(Debug)]
pub struct SpawnedAgent {
    pub pid: u32,
    pub process: OwnedHandle,
}

/// The Windows [`ServiceHost`].
#[derive(Debug, Clone)]
pub struct WinServiceHost {
    program: PathBuf,
    args: Vec<String>,
    service_args: Vec<String>,
}

impl Default for WinServiceHost {
    fn default() -> Self {
        Self::new()
    }
}

impl WinServiceHost {
    /// The production host: agents are `layout::AGENT_PROGRAM run`, and
    /// [`ServiceHost::install`] registers `layout::SERVICE_PROGRAM run`.
    pub fn new() -> Self {
        WinServiceHost {
            program: PathBuf::from(layout::AGENT_PROGRAM),
            args: vec!["run".into()],
            service_args: vec!["run".into()],
        }
    }

    /// Launch `program args…` as the agent instead (tests, spike tools).
    pub fn with_agent(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        WinServiceHost {
            program: program.into(),
            args,
            ..Self::new()
        }
    }

    /// The agent program this host launches.
    pub fn agent_program(&self) -> &Path {
        &self.program
    }

    /// Launch the agent in WTS session `session` and keep a handle to it.
    /// Needs LocalSystem (see the module docs).
    pub fn spawn_in_session(&self, session: u32) -> PlatformResult<SpawnedAgent> {
        spawn_as_session_user(session, &self.program, &self.args)
    }
}

impl ServiceHost for WinServiceHost {
    /// Register the service with the SCM ([`crate::scm::install_service`]:
    /// LocalSystem, automatic start, recovery actions, protective DACL).
    /// There is nothing to register for the agent: the service launches it
    /// into each session itself. Needs an elevated administrator.
    fn install(&self) -> PlatformResult<()> {
        crate::scm::install_service(Path::new(layout::SERVICE_PROGRAM), &self.service_args).map_err(
            |e| {
                if e.raw_os_error() == Some(5) {
                    PlatformError::PermissionDenied(
                        "installing the service needs an elevated administrator".into(),
                    )
                } else {
                    PlatformError::Os(format!("install service: {e}"))
                }
            },
        )
    }

    fn list_sessions(&self) -> PlatformResult<Vec<SessionInfo>> {
        Ok(enumerate_sessions()?
            .iter()
            .map(WtsSession::to_session_info)
            .collect())
    }

    /// Launch the agent in `session` (a `wts:<id>` id) and return its pid.
    /// The process handle is closed; use
    /// [`WinServiceHost::spawn_in_session`] to keep it.
    fn spawn_agent_in_session(&self, session: &SessionId) -> PlatformResult<AgentPid> {
        let id = parse_session_id(session).ok_or_else(|| {
            PlatformError::Unavailable(format!("not a Windows session id: {:?}", session.0))
        })?;
        self.spawn_in_session(id).map(|a| AgentPid(a.pid))
    }
}

/// A Win32 handle closed on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: we own the handle and close it once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// The primary token of the user logged on in `session`, duplicated so the
/// caller owns it.
fn session_user_token(session: u32) -> PlatformResult<Handle> {
    let mut raw = HANDLE::default();
    // SAFETY: valid out pointer.
    if let Err(e) = unsafe { WTSQueryUserToken(session, &mut raw) } {
        let code = WIN32_ERROR::from_error(&e);
        return Err(if code == Some(ERROR_PRIVILEGE_NOT_HELD) {
            PlatformError::PermissionDenied(
                "WTSQueryUserToken needs LocalSystem (SeTcbPrivilege); run as the Faro service"
                    .into(),
            )
        } else if code == Some(ERROR_NO_TOKEN) {
            PlatformError::Unavailable(format!("no user is logged on in session {session}"))
        } else {
            PlatformError::Os(format!("WTSQueryUserToken({session}): {e}"))
        });
    }
    let user = Handle(raw);
    let mut dup = HANDLE::default();
    // SAFETY: `user.0` is a valid token; `dup` is a valid out pointer.
    unsafe {
        DuplicateTokenEx(
            user.0,
            // What CreateProcessAsUserW and CreateEnvironmentBlock need.
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityIdentification,
            TokenPrimary,
            &mut dup,
        )
    }
    .map_err(|e| PlatformError::Os(format!("DuplicateTokenEx: {e}")))?;
    Ok(Handle(dup))
}

/// The SID (`S-1-5-21-…`) of the user logged on in `session`, for pipe
/// DACLs and for checking that a pipe client runs as that user. Needs
/// LocalSystem, like spawning.
pub fn session_user_sid(session: u32) -> PlatformResult<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    let token = session_user_token(session)?;
    let mut len = 0u32;
    // SAFETY: a size query.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
    // SAFETY: `buf` holds at least `len` bytes, 8-byte aligned.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(|e| PlatformError::Os(format!("GetTokenInformation: {e}")))?;
    // SAFETY: TokenUser filled a TOKEN_USER whose SID points into `buf`.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut s = PWSTR::null();
    // SAFETY: valid SID and out pointer; `s` is freed below.
    unsafe { ConvertSidToStringSidW(sid, &mut s) }
        .map_err(|e| PlatformError::Os(format!("ConvertSidToStringSidW: {e}")))?;
    // SAFETY: NUL-terminated string from ConvertSidToStringSidW.
    let out = unsafe { s.to_string() }.map_err(|e| PlatformError::Os(e.to_string()));
    // SAFETY: LocalAlloc'd by ConvertSidToStringSidW, freed once.
    unsafe {
        windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(s.0.cast())))
    };
    out
}

/// Quote one argument for the MSVC runtime's command-line parser (what
/// Rust's and C's `main` use): wrap in quotes when it is empty or contains
/// whitespace or a quote; double the backslashes that precede a quote or
/// the closing quote; escape quotes.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// The full command line: the quoted program, then the quoted arguments.
pub fn command_line(program: &Path, args: &[String]) -> String {
    let mut line = quote_arg(&program.to_string_lossy());
    for a in args {
        line.push(' ');
        line.push_str(&quote_arg(a));
    }
    line
}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn spawn_as_session_user(
    session: u32,
    program: &Path,
    args: &[String],
) -> PlatformResult<SpawnedAgent> {
    if !program.is_absolute() {
        // A relative program would be searched for on the PATH and in the
        // working directory: never for a process started by SYSTEM.
        return Err(PlatformError::Os(format!(
            "agent program must be an absolute path: {}",
            program.display()
        )));
    }
    let token = session_user_token(session)?;

    let mut env: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: valid token and out pointer; `false`: do not inherit the
    // service's environment.
    unsafe { CreateEnvironmentBlock(&mut env, Some(token.0), false) }
        .map_err(|e| PlatformError::Os(format!("CreateEnvironmentBlock: {e}")))?;
    struct Env(*mut core::ffi::c_void);
    impl Drop for Env {
        fn drop(&mut self) {
            // SAFETY: created by CreateEnvironmentBlock, destroyed once.
            let _ = unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
    let env = Env(env);

    let app: Vec<u16> = program.as_os_str().encode_wide().chain(Some(0)).collect();
    // CreateProcessW may write to the command-line buffer, so it is ours.
    let mut cmd = wide_str(&command_line(program, args));
    let dir: Option<Vec<u16>> = program
        .parent()
        .map(|d| d.as_os_str().encode_wide().chain(Some(0)).collect());
    let mut desktop = wide_str(r"winsta0\default");
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is to a NUL-terminated buffer that outlives the
    // call; `env` is a Unicode environment block (flagged as such); no
    // handles are inherited.
    unsafe {
        CreateProcessAsUserW(
            Some(token.0),
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmd.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            Some(env.0.cast_const()),
            dir.as_ref().map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
            &si,
            &mut pi,
        )
    }
    .map_err(|e| {
        PlatformError::Os(format!(
            "CreateProcessAsUserW({}) in session {session}: {e}",
            program.display()
        ))
    })?;
    drop(Handle(pi.hThread));
    // SAFETY: a fresh process handle we now own.
    let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess.0) };
    debug_assert!(!process.as_raw_handle().is_null());
    Ok(SpawnedAgent {
        pid: pi.dwProcessId,
        process,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_ids_round_trip() {
        assert_eq!(session_id(3).0, "wts:3");
        assert_eq!(parse_session_id(&session_id(3)), Some(3));
        assert_eq!(parse_session_id(&session_id(0)), Some(0));
        for bad in [
            "3",
            "uid:3",
            "wts:",
            "wts:-1",
            "wts:+1",
            "wts: 1",
            "wts:01",
            "wts:99999999999",
        ] {
            assert_eq!(parse_session_id(&SessionId(bad.into())), None, "{bad}");
        }
    }

    #[test]
    fn quoting_follows_msvc_rules() {
        assert_eq!(quote_arg("run"), "run");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_arg(r"C:\dir\"), r"C:\dir\");
        assert_eq!(quote_arg(r"C:\my dir\"), r#""C:\my dir\\""#);
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(
            command_line(Path::new(layout::AGENT_PROGRAM), &["run".into()]),
            r#""C:\Program Files\Faro\faro-agent.exe" run"#
        );
    }

    #[test]
    fn quoting_round_trips_through_the_msvc_rules() {
        // Parse each quoted argument back with a reference implementation
        // of the MSVC runtime's rules.
        for a in [
            "plain",
            "with space",
            r#"q"uote"#,
            r"trail\",
            r"sp ace\",
            "",
        ] {
            let ours = quote_arg(a);
            assert_eq!(
                parse_msvc(&format!("x {ours}")),
                vec!["x".to_string(), a.to_string()]
            );
        }
    }

    /// A reference parser for the MSVC rules (after argv[0]).
    fn parse_msvc(line: &str) -> Vec<String> {
        let mut args = Vec::new();
        let mut cur = String::new();
        let mut in_q = false;
        let mut have = false;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let mut n = 0;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        cur.push('"');
                        i += 1;
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                have = true;
                continue;
            }
            if c == '"' {
                in_q = !in_q;
                have = true;
            } else if (c == ' ' || c == '\t') && !in_q {
                if have {
                    args.push(std::mem::take(&mut cur));
                    have = false;
                }
            } else {
                cur.push(c);
                have = true;
            }
            i += 1;
        }
        if have {
            args.push(cur);
        }
        args
    }

    #[test]
    fn session_events_decode() {
        let n: [u32; 2] = [8, 7];
        // SAFETY: `n` has the WTSSESSION_NOTIFICATION layout.
        let e = unsafe { SessionEvent::from_raw(5, n.as_ptr().cast()) }.unwrap();
        assert_eq!(
            e,
            SessionEvent {
                kind: SessionEventKind::Logon,
                session: 7
            }
        );
        assert_eq!(e.session_id().0, "wts:7");
        // SAFETY: null is allowed.
        assert_eq!(unsafe { SessionEvent::from_raw(5, std::ptr::null()) }, None);
        let short: [u32; 2] = [4, 7];
        // SAFETY: valid layout, wrong size field.
        assert_eq!(
            unsafe { SessionEvent::from_raw(5, short.as_ptr().cast()) },
            None
        );
        for (code, kind) in [
            (1, SessionEventKind::ConsoleConnect),
            (2, SessionEventKind::ConsoleDisconnect),
            (3, SessionEventKind::RemoteConnect),
            (4, SessionEventKind::RemoteDisconnect),
            (6, SessionEventKind::Logoff),
            (7, SessionEventKind::Lock),
            (8, SessionEventKind::Unlock),
            (9, SessionEventKind::RemoteControl),
            (10, SessionEventKind::Create),
            (11, SessionEventKind::Terminate),
            (42, SessionEventKind::Other(42)),
        ] {
            assert_eq!(SessionEventKind::from_raw(code), kind);
        }
    }

    #[test]
    fn user_session_filter() {
        let s = |id, user: &str, state| WtsSession {
            id,
            user: user.into(),
            domain: "PC".into(),
            state,
            protocol: Protocol::Console,
        };
        assert!(is_user_session(&s(1, "alex", ConnectState::Active)));
        assert!(is_user_session(&s(2, "sam", ConnectState::Disconnected)));
        assert!(!is_user_session(&s(
            0,
            "SYSTEM",
            ConnectState::Disconnected
        )));
        assert!(!is_user_session(&s(3, "", ConnectState::Connected)));
        assert!(!is_user_session(&s(65536, "", ConnectState::Listen)));
        assert!(!is_user_session(&s(4, "x", ConnectState::Connected)));
        let info = s(2, "sam", ConnectState::Disconnected).to_session_info();
        assert_eq!(info.id.0, "wts:2");
        assert!(!info.active && info.graphical);
    }

    #[test]
    fn lists_this_session() {
        let host = WinServiceHost::new();
        let sessions = host.list_sessions().unwrap();
        eprintln!("{sessions:?}");
        let raw = enumerate_sessions().unwrap();
        // This test runs in some user's session (unless CI runs it as a
        // service in session 0); that session must be listed with its user.
        let mut mine = 0u32;
        // SAFETY: valid out pointer.
        let ok = unsafe {
            windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut mine,
            )
        }
        .is_ok();
        if !ok || mine == 0 {
            eprintln!("skipped: running in session 0");
            return;
        }
        let me = raw
            .iter()
            .find(|s| s.id == mine)
            .expect("own session listed");
        let user = std::env::var("USERNAME").unwrap();
        assert!(me.user.eq_ignore_ascii_case(&user), "{me:?} vs {user}");
        assert!(sessions.iter().any(|s| s.id == session_id(mine)));
    }

    #[test]
    fn spawning_needs_system() {
        let host = WinServiceHost::with_agent(
            r"C:\Windows\System32\cmd.exe",
            vec!["/c".into(), "exit".into()],
        );
        if crate::acl::running_as_system() {
            eprintln!("running as SYSTEM: spawn test runs in sessions_probe instead");
            return;
        }
        let mut mine = 0u32;
        // SAFETY: valid out pointer.
        let _ = unsafe {
            windows::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut mine,
            )
        };
        match host.spawn_agent_in_session(&session_id(mine)) {
            Err(PlatformError::PermissionDenied(m)) => assert!(m.contains("LocalSystem")),
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
        assert!(matches!(
            host.spawn_agent_in_session(&SessionId("uid:501".into())),
            Err(PlatformError::Unavailable(_))
        ));
        let rel = WinServiceHost::with_agent("faro-agent.exe", vec![]);
        assert!(matches!(
            rel.spawn_in_session(mine),
            Err(PlatformError::Os(_))
        ));
    }
}
