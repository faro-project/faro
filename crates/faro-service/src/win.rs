//! Windows plumbing shared by the service's modules: who we run as, which
//! session a process is in, which sessions have an agent, and the token of
//! a pipe client.
//!
//! The service runs as LocalSystem under the SCM and as an ordinary user
//! when a developer starts `faro-service run` by hand. [`is_system`] is the
//! Windows meaning of the Unix code's "euid is 0".

use faro_ipc::AccountId;
use std::collections::BTreeSet;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::{Mutex, OnceLock, PoisonError};
use tokio::sync::watch;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{RevertToSelf, TOKEN_DUPLICATE, TOKEN_QUERY};
use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{GetCurrentProcessId, GetCurrentThread, OpenThreadToken};

/// Whether this process is LocalSystem: the real service, which may start
/// agents in other sessions and bind a pipe per account.
pub fn is_system() -> bool {
    faro_platform_windows::acl::running_as_system()
}

/// The account this process runs as.
pub fn own_account() -> AccountId {
    // Reading our own token cannot fail in practice; a placeholder that no
    // peer can have keeps the signature simple.
    faro_ipc::current_account().unwrap_or(faro_ipc::Sid::LOCAL_SYSTEM)
}

/// The Terminal Services session this process is in.
pub fn own_session_id() -> Option<u32> {
    let mut id = 0u32;
    // SAFETY: a valid out pointer.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) }
        .ok()
        .map(|()| id)
}

/// The session a process is in, or `None` if it is gone or unreadable.
pub fn process_session_id(pid: u32) -> Option<u32> {
    let mut id = 0u32;
    // SAFETY: a valid out pointer.
    unsafe { ProcessIdToSessionId(pid, &mut id) }
        .ok()
        .map(|()| id)
}

// ---- directories -----------------------------------------------------------

/// Create `C:\ProgramData\Faro` and its `logs` directory and protect
/// them: the state directory SYSTEM and Administrators only, then the log
/// directory SYSTEM full and Administrators read (that order, since the
/// log directory is inside the state directory). Does nothing unless this
/// process is LocalSystem, and only once per process.
pub fn prepare_dirs() -> io::Result<()> {
    use faro_platform_windows::{acl, layout};
    static DONE: OnceLock<()> = OnceLock::new();
    if !is_system() || DONE.get().is_some() {
        return Ok(());
    }
    std::fs::create_dir_all(layout::DATA_DIR)?;
    acl::protect_state_dir(std::path::Path::new(layout::DATA_DIR))?;
    std::fs::create_dir_all(layout::LOG_DIR)?;
    acl::protect_log_dir(std::path::Path::new(layout::LOG_DIR))?;
    let _ = DONE.set(());
    Ok(())
}

// ---- session changes -------------------------------------------------------

fn changes() -> &'static watch::Sender<u64> {
    static CHANGES: OnceLock<watch::Sender<u64>> = OnceLock::new();
    CHANGES.get_or_init(|| watch::channel(0).0)
}

/// The SCM reported a session change (logon, logoff, connect, disconnect):
/// whoever lists sessions should do it now.
pub fn notify_session_change() {
    changes().send_modify(|n| *n = n.wrapping_add(1));
}

/// A feed that changes on every [`notify_session_change`].
pub fn session_changes() -> watch::Receiver<u64> {
    changes().subscribe()
}

// ---- which sessions have an agent -------------------------------------------

#[derive(Default)]
struct Presence {
    /// Sessions where the service started or found a running agent process.
    launched: BTreeSet<u32>,
    /// Sessions whose agent is connected to the agent pipe.
    connected: BTreeSet<u32>,
}

fn presence() -> &'static Mutex<Presence> {
    static P: OnceLock<Mutex<Presence>> = OnceLock::new();
    P.get_or_init(Mutex::default)
}

fn lock() -> std::sync::MutexGuard<'static, Presence> {
    presence().lock().unwrap_or_else(PoisonError::into_inner)
}

/// The launcher's view: these sessions have a live agent process.
pub fn set_launched_agents(sessions: BTreeSet<u32>) {
    lock().launched = sessions;
}

/// The agent source's view: these sessions have a connected agent.
pub fn set_connected_agents(sessions: BTreeSet<u32>) {
    lock().connected = sessions;
}

/// Whether an agent is known to run in `session`, either because the
/// service launched it there or because it is connected.
pub fn agent_in_session(session: u32) -> bool {
    let p = lock();
    p.launched.contains(&session) || p.connected.contains(&session)
}

// ---- pipe clients ----------------------------------------------------------

/// An owned token handle, closed on drop.
pub struct Token(OwnedHandle);

impl Token {
    /// The handle, for calls that take one. Valid while `self` lives.
    pub fn handle(&self) -> HANDLE {
        HANDLE(self.0.as_raw_handle())
    }
}

/// The token a pipe client opened the pipe with (`TOKEN_QUERY |
/// TOKEN_DUPLICATE`, impersonation at identification level), read from the
/// connection itself so a client exiting and its pid being reused cannot
/// change the answer.
///
/// Impersonation changes the calling thread's token, which is shared state
/// on a Tokio worker thread, so this runs start to finish with no `.await`
/// and reverts before returning. If reverting ever failed this thread would
/// go on running as the client; there is no safe way to continue, so the
/// process aborts (as `faro-ipc` does).
pub fn pipe_client_token(pipe: &impl AsRawHandle) -> io::Result<Token> {
    let h = HANDLE(pipe.as_raw_handle());
    // SAFETY: `h` is a valid, connected server pipe handle.
    unsafe { ImpersonateNamedPipeClient(h) }.map_err(io::Error::from)?;
    let mut token = HANDLE::default();
    // SAFETY: the current-thread pseudo handle is always valid; `token` is a
    // valid out pointer. OpenAsSelf: the access check uses the service's own
    // token, since an identification-level token cannot open objects.
    let opened = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            true,
            &mut token,
        )
    };
    // SAFETY: no preconditions.
    if unsafe { RevertToSelf() }.is_err() {
        std::process::abort();
    }
    opened.map_err(io::Error::from)?;
    // SAFETY: a fresh token handle we own.
    Ok(Token(unsafe {
        OwnedHandle::from_raw_handle(token.0 as RawHandle)
    }))
}
