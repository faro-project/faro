//! Named-pipe transport (Windows) — ARCHITECTURE.md §3.1, §9. The
//! counterpart of the Unix-socket `transport` module, with the same API
//! ([`IpcServer`], [`IpcClient`], [`BindOptions`]) over
//! `tokio::net::windows::named_pipe`, so the codec, [`Connection`] and
//! handshake are reused unchanged.
//!
//! Pipe names are carried as [`Path`]s (`\\.\pipe\faro\agent.<SID>`, see
//! [`crate::endpoint`]) so call sites are the same on both platforms.
//!
//! Security properties, in the order they are established. The Unix
//! transport's guarantees are kept, adapted to how pipes work:
//!
//! 1. **Nobody can squat on the name.** `\\.\pipe\` has no directories to
//!    secure (the Unix point 1); a name belongs to whoever creates its
//!    first instance. The server creates its first instance with
//!    `FILE_FLAG_FIRST_PIPE_INSTANCE`, which fails if *any* instance of the
//!    name already exists, whoever made it: a squatter, or a live service.
//!    That is reported as [`IpcError::AddrInUse`] and nothing is hijacked.
//!    Afterwards the server always holds at least one instance (it creates
//!    the next instance *before* handing a connected one out, see
//!    [`IpcServer::accept`]), so the name never lapses while it runs. Pipes
//!    leave nothing behind when their last handle closes, so there is no
//!    stale endpoint to replace (the Unix staging-and-rename dance exists
//!    for socket files, which outlive their listener).
//! 2. **The pipe never exists with loose permissions.** Its security
//!    descriptor is passed to `CreateNamedPipeW` itself, atomically, for
//!    every instance (the Unix staging directory's job):
//!    * owner: the server's own account (LocalSystem for the service);
//!    * DACL, protected from inheritance: LocalSystem, Administrators and
//!      the owner get full access; the **one account the pipe is for**
//!      ([`BindOptions::account`]) gets `FILE_GENERIC_READ | FILE_WRITE_DATA`
//!      and nothing else. Crucially, not `FILE_CREATE_PIPE_INSTANCE`
//!      (which is `FILE_APPEND_DATA`, part of `GENERIC_WRITE`): with it, the
//!      client account could create its *own* instances of the service's
//!      pipe, under the service's security descriptor, and have other
//!      agents connect to it. No other account gets an ACE, so nobody else
//!      can open the pipe at all. Administrators mirror Unix, where root can
//!      connect to any socket; the ACE only applies to an elevated token
//!      (in a non-elevated admin token the group is deny-only);
//!    * mandatory label: Medium, no-read-up and no-write-up, so a
//!      low-integrity or AppContainer process running as the user (a
//!      browser sandbox) can neither read from nor write to the service even
//!      though its account matches.
//!
//!    `PIPE_REJECT_REMOTE_CLIENTS` refuses connections over SMB, so the
//!    pipe is local-only like a Unix socket.
//! 3. **Every client is identified by the kernel** before a single byte is
//!    read and passed to a caller-supplied [`PeerVerifier`]: its pid
//!    (`GetNamedPipeClientProcessId`, for the Authenticode hook, see
//!    [`crate::peer`]), its session (`GetNamedPipeClientSessionId`) and its
//!    account, the user SID of the token it opened the pipe with. The SID is
//!    read by impersonating the client at identification level
//!    (`ImpersonateNamedPipeClient`, `OpenThreadToken`, `RevertToSelf`):
//!    the token comes from the connection, so unlike opening the process by
//!    pid it cannot be raced by the client exiting and its pid being reused.
//!    A rejected client's instance is closed immediately.
//!
//! # The agent's check of the server
//!
//! The agent should verify the *server* too ([`IpcClient::connect_verified`]
//! with [`AllowSystemService`](crate::AllowSystemService)), so it never
//! streams frames to an impostor that created the name while the service
//! was not running. The client reports the server's pid
//! (`GetNamedPipeServerProcessId`) and session, and as its account the
//! **owner of the pipe object** (`GetSecurityInfo`), not the user of the
//! server process's token: a standard user cannot open a LocalSystem
//! process's token (its DACL admits only SYSTEM and Administrators), so a
//! token check would fail for every real agent. The owner is as strong:
//! Windows sets it from the creator's token and lets a creator name only
//! its own user (or an owner group it holds) as owner, so a pipe owned by
//! `S-1-5-18` was made by LocalSystem or by an administrator holding
//! `SeRestorePrivilege`, both of whom already control the computer (the
//! Unix side trusts root the same way). And because client accounts lack
//! `FILE_CREATE_PIPE_INSTANCE` (point 2), every instance of a
//! LocalSystem-owned pipe was created by the service. The client opens the
//! pipe at `SECURITY_IDENTIFICATION` level, so even an impostor server can
//! only identify the agent's account, not act as it.
//!
//! A development service run as the user owns its pipe as that user, which
//! [`AllowSameUser`](crate::AllowSameUser) (the agent's
//! `--trust-same-uid-service`) accepts and `AllowSystemService` refuses.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_SEM_TIMEOUT, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, RevertToSelf, TokenUser,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
    GetNamedPipeServerSessionId, ImpersonateNamedPipeClient, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::connection::{AgentConnection, Connection, ServiceConnection};
use crate::error::{IpcError, Result};
use crate::messages::WireMessage;
use crate::peer::{PeerInfo, PeerVerifier};
use crate::sid::Sid;

/// Every pipe name starts with this: the local machine's pipe namespace.
/// Remote names (`\\server\pipe\…`) are refused on both sides.
pub const PIPE_PREFIX: &str = r"\\.\pipe\";

/// Longest pipe name Windows accepts, in UTF-16 units.
const MAX_PIPE_NAME_LEN: usize = 256;

/// What the pipe's own account gets: everything a client needs (read,
/// write, query its attributes and the security descriptor, wait on it)
/// and nothing that changes the pipe. `FILE_GENERIC_READ` includes
/// `READ_CONTROL`, which the agent needs to read the owner. Deliberately
/// missing: `FILE_APPEND_DATA` = `FILE_CREATE_PIPE_INSTANCE`,
/// `FILE_WRITE_ATTRIBUTES`, `WRITE_DAC`, `WRITE_OWNER`, `DELETE`.
const CLIENT_GRANTED_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;

/// What [`IpcClient`] asks for when it opens a pipe: a subset of
/// [`CLIENT_GRANTED_ACCESS`]. Not `GENERIC_WRITE`, which includes
/// `FILE_CREATE_PIPE_INSTANCE` and so would be refused.
const CLIENT_OPEN_ACCESS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// How long [`IpcClient`] retries while every instance of the pipe is busy
/// (`ERROR_PIPE_BUSY`). The server creates the next instance right after a
/// client connects, so this only covers a burst of clients.
const BUSY_RETRY_FOR: Duration = Duration::from_secs(2);
const BUSY_RETRY_EVERY: Duration = Duration::from_millis(10);

/// Who may connect to the pipe besides the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BindOptions {
    /// The one account the pipe is for, which gets read/write access. The
    /// LocalSystem service binds one pipe per session user with
    /// [`BindOptions::for_account`]. `None` means the account this process
    /// runs as (a development service run by the user, or tests).
    pub account: Option<Sid>,
}

impl BindOptions {
    /// A pipe that `account` (and the system) may connect to.
    pub fn for_account(account: Sid) -> Self {
        BindOptions {
            account: Some(account),
        }
    }
}

/// The SDDL for a pipe owned by `owner` that `account` may use. See the
/// module docs, point 2. SIDs are formatted from validated [`Sid`]s, so no
/// caller-controlled text reaches the SDDL parser.
fn pipe_sddl(owner: &Sid, account: &Sid) -> String {
    let full = FILE_ALL_ACCESS;
    let client = CLIENT_GRANTED_ACCESS;
    let system = Sid::LOCAL_SYSTEM;
    let admins = Sid::BUILTIN_ADMINISTRATORS;
    format!(
        "O:{owner}\
         D:P(A;;0x{full:x};;;{system})(A;;0x{full:x};;;{admins})(A;;0x{full:x};;;{owner})\
         (A;;0x{client:x};;;{account})\
         S:(ML;;NWNR;;;ME)"
    )
}

/// A security descriptor allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW`, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is a self-relative block of plain memory that is
// never written after creation; Windows only reads it.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: as above.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = wide_nul(sddl.as_ref());
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; `sd` is a valid out-pointer and
        // the size out-pointer may be null.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecurityDescriptor(sd))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated with LocalAlloc by the conversion above and
        // freed exactly once.
        unsafe { LocalFree(self.0) };
    }
}

/// A listening IPC endpoint (the service side).
///
/// Dropping it closes the listening instance. Connections already accepted
/// keep working, and the name exists until the last of them closes. Tokio
/// closes a pipe handle once its pending I/O has been cancelled, which the
/// runtime completes shortly after the drop, so binding the same name again
/// immediately can briefly fail with [`IpcError::AddrInUse`].
///
/// Unlike a Unix listener, a pipe has no backlog beyond its one waiting
/// instance: a client that arrives while the server is not in `accept` (and
/// the previous client took the waiting instance) gets `ERROR_PIPE_BUSY`,
/// which [`IpcClient`] retries for two seconds. Run `accept` in a loop.
pub struct IpcServer {
    name: PathBuf,
    sd: SecurityDescriptor,
    /// The instance waiting for the next client. Replaced (never left
    /// empty) each time a client connects; see [`IpcServer::accept`].
    listening: tokio::sync::Mutex<NamedPipeServer>,
    verifier: Arc<dyn PeerVerifier>,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl IpcServer {
    /// Bind with [`BindOptions::default`] (only our own account and the
    /// system may connect). Must be called from within a Tokio runtime.
    pub fn bind(name: impl AsRef<Path>, verifier: impl PeerVerifier + 'static) -> Result<Self> {
        Self::bind_with(name, BindOptions::default(), verifier)
    }

    /// Bind for an explicit account. See the module docs for the checks.
    pub fn bind_with(
        name: impl AsRef<Path>,
        options: BindOptions,
        verifier: impl PeerVerifier + 'static,
    ) -> Result<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(IpcError::NoRuntime);
        }
        let name = name.as_ref();
        validate_pipe_name(name)?;
        let owner = current_user_sid()?;
        let account = options.account.unwrap_or(owner);
        let sd = SecurityDescriptor::from_sddl(&pipe_sddl(&owner, &account))?;
        let first = create_instance(name, &sd, true).map_err(|e| {
            // With FILE_FLAG_FIRST_PIPE_INSTANCE, "access denied" means an
            // instance of the name exists already (whoever created it), and
            // "busy" that someone else's pipe of that name is at its
            // instance limit.
            match e.raw_os_error().map(|c| c as u32) {
                Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) => {
                    IpcError::AddrInUse(name.to_path_buf())
                }
                _ => IpcError::Io(e),
            }
        })?;
        Ok(IpcServer {
            name: name.to_path_buf(),
            sd,
            listening: tokio::sync::Mutex::new(first),
            verifier: Arc::new(verifier),
        })
    }

    /// The pipe name.
    pub fn path(&self) -> &Path {
        &self.name
    }

    /// Accept the next connection and verify its peer.
    ///
    /// A peer that fails verification is disconnected and reported as an
    /// error; callers running an accept loop should log it and continue
    /// rather than stop listening. Cancel-safe: dropping the future while
    /// it waits loses no connection. Concurrent calls are served one at a
    /// time.
    pub async fn accept(&self) -> Result<ServiceConnection<NamedPipeServer>> {
        self.accept_typed().await
    }

    /// [`accept`](Self::accept) for a connection carrying other message
    /// types (the enroll pipe's [`EnrollServerConnection`](crate::EnrollServerConnection)).
    pub async fn accept_typed<Out: WireMessage, In: WireMessage>(
        &self,
    ) -> Result<Connection<NamedPipeServer, Out, In>> {
        let connected = {
            let mut listening = self.listening.lock().await;
            loop {
                let r = listening.connect().await;
                // Create the next instance *before* releasing this one, so
                // the name always has an instance of ours and cannot be
                // taken over between two clients (module docs, point 1).
                let next = create_instance(&self.name, &self.sd, false)?;
                let current = std::mem::replace(&mut *listening, next);
                match r {
                    Ok(()) => break current,
                    // A client connected and closed again before we got to
                    // it (or something probed the name). Not an error for
                    // the accept loop; wait for the next one.
                    Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA as i32) => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let peer = client_credentials(&connected).map_err(IpcError::PeerCredentials)?;
        // On rejection `connected` is dropped here, closing the instance
        // without a byte exchanged.
        self.verifier.verify(&peer)?;
        Ok(Connection::with_peer(connected, Some(peer)))
    }
}

/// One instance of the pipe `name`, with our security descriptor.
fn create_instance(
    name: &Path,
    sd: &SecurityDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first)
        .reject_remote_clients(true)
        .pipe_mode(PipeMode::Byte)
        .access_inbound(true)
        .access_outbound(true);
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor lives
    // in `sd`, which outlives the call; CreateNamedPipeW copies it.
    unsafe {
        opts.create_with_security_attributes_raw(
            name.as_os_str(),
            (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

/// The agent side of the transport.
#[derive(Debug, Clone, Copy)]
pub struct IpcClient;

impl IpcClient {
    /// Connect without checking who is listening. Prefer
    /// [`connect_verified`](Self::connect_verified) in production.
    pub async fn connect(name: impl AsRef<Path>) -> Result<AgentConnection<NamedPipeClient>> {
        Self::connect_typed(name).await
    }

    /// [`connect`](Self::connect) for a connection carrying other message
    /// types (the enroll pipe's [`EnrollClientConnection`](crate::EnrollClientConnection)).
    pub async fn connect_typed<Out: WireMessage, In: WireMessage>(
        name: impl AsRef<Path>,
    ) -> Result<Connection<NamedPipeClient, Out, In>> {
        let name = name.as_ref();
        validate_pipe_name(name)?;
        let handle = open_client(name).await?;
        let peer =
            server_credentials_raw(handle.as_raw_handle()).map_err(IpcError::PeerCredentials)?;
        // SAFETY: `handle` is an open pipe client handle we own, opened with
        // FILE_FLAG_OVERLAPPED as tokio requires; ownership moves to tokio
        // (which closes it on error).
        let stream = unsafe { NamedPipeClient::from_raw_handle(handle.into_raw_handle())? };
        Ok(Connection::with_peer(stream, Some(peer)))
    }

    /// [`connect_verified`](Self::connect_verified) for other message types.
    pub async fn connect_verified_typed<Out: WireMessage, In: WireMessage>(
        name: impl AsRef<Path>,
        verifier: &dyn PeerVerifier,
    ) -> Result<Connection<NamedPipeClient, Out, In>> {
        let conn = Self::connect_typed(name).await?;
        let peer = conn
            .peer()
            .ok_or_else(|| IpcError::peer_rejected("server credentials unavailable"))?;
        verifier.verify(peer)?;
        Ok(conn)
    }

    /// Connect and require the listening process to pass `verifier`
    /// (typically [`AllowSystemService`](crate::AllowSystemService)). On
    /// rejection nothing has been sent.
    pub async fn connect_verified(
        name: impl AsRef<Path>,
        verifier: &dyn PeerVerifier,
    ) -> Result<AgentConnection<NamedPipeClient>> {
        Self::connect_verified_typed(name, verifier).await
    }
}

/// Open the client end, retrying briefly while every instance is busy.
async fn open_client(name: &Path) -> io::Result<OwnedHandle> {
    let wide = wide_nul(name.as_os_str());
    let deadline = Instant::now() + BUSY_RETRY_FOR;
    loop {
        // SAFETY: `wide` is NUL-terminated; no security attributes or
        // template. SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION lets the
        // server identify our account but not act as us.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_OPEN_ACCESS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            // SAFETY: a fresh handle we own.
            return Ok(unsafe { OwnedHandle::from_raw_handle(h as RawHandle) });
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && Instant::now() < deadline {
            tokio::time::sleep(BUSY_RETRY_EVERY).await;
            continue;
        }
        return Err(e);
    }
}

/// Who connected to a server instance: pid, session and account. See the
/// module docs, point 3.
pub fn client_credentials(pipe: &NamedPipeServer) -> io::Result<PeerInfo> {
    let h = pipe.as_raw_handle() as HANDLE;
    let mut pid = 0u32;
    // SAFETY: `h` is a valid, connected server handle; `pid` is a valid
    // out-pointer.
    if unsafe { GetNamedPipeClientProcessId(h, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut session = 0u32;
    // SAFETY: as above.
    if unsafe { GetNamedPipeClientSessionId(h, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = impersonated_client_sid(h)?;
    Ok(PeerInfo {
        uid: PeerInfo::NO_ID,
        gid: PeerInfo::NO_ID,
        pid: (pid != 0).then_some(pid),
        macos_audit_token: None,
        windows_sid: Some(sid),
        windows_session_id: Some(session),
    })
}

/// Who is serving the pipe a client handle is connected to: pid, session,
/// and the pipe object's owner. See the module docs, "The agent's check of
/// the server".
pub fn server_credentials(pipe: &NamedPipeClient) -> io::Result<PeerInfo> {
    server_credentials_raw(pipe.as_raw_handle())
}

fn server_credentials_raw(raw: RawHandle) -> io::Result<PeerInfo> {
    let h = raw as HANDLE;
    let mut pid = 0u32;
    // SAFETY: `h` is a valid client pipe handle; `pid` is a valid
    // out-pointer.
    if unsafe { GetNamedPipeServerProcessId(h, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut session = 0u32;
    // SAFETY: as above.
    if unsafe { GetNamedPipeServerSessionId(h, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let owner = object_owner(h)?;
    Ok(PeerInfo {
        uid: PeerInfo::NO_ID,
        gid: PeerInfo::NO_ID,
        pid: (pid != 0).then_some(pid),
        macos_audit_token: None,
        windows_sid: Some(owner),
        windows_session_id: Some(session),
    })
}

/// The user SID of the token the client opened the pipe with.
///
/// Impersonation changes the calling thread's token, which is shared state
/// on a Tokio worker thread, so this runs start to finish with no `.await`
/// and reverts before returning. If reverting ever failed, this thread
/// would go on running as the client, and there is no safe way to continue:
/// the process aborts.
fn impersonated_client_sid(pipe: HANDLE) -> io::Result<Sid> {
    // SAFETY: `pipe` is a valid, connected server handle.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the current-thread pseudo handle is always valid; `token` is a
    // valid out-pointer. OpenAsSelf: the access check uses the service's
    // own token, since an identification-level token cannot open objects.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let open_err = io::Error::last_os_error();
    // SAFETY: no preconditions.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        return Err(open_err);
    }
    // SAFETY: a fresh token handle we own.
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    token_user_sid(&token)
}

/// The account this process runs as: its process token's user.
pub(crate) fn current_user_sid() -> io::Result<Sid> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the current-process pseudo handle is always valid; `token` is
    // a valid out-pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh token handle we own.
    let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    token_user_sid(&token)
}

/// `GetTokenInformation(TokenUser)`, copied out into a [`Sid`].
fn token_user_sid(token: &OwnedHandle) -> io::Result<Sid> {
    let h = token.as_raw_handle() as HANDLE;
    let mut len = 0u32;
    // SAFETY: a size query: null buffer of length 0, valid `len`. It fails
    // with ERROR_INSUFFICIENT_BUFFER and reports the size.
    unsafe { GetTokenInformation(h, TokenUser, ptr::null_mut(), 0, &mut len) };
    if (len as usize) < size_of::<TOKEN_USER>() {
        return Err(io::Error::last_os_error());
    }
    // u64 storage keeps the TOKEN_USER (which holds a pointer) aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buf` has at least `len` writable bytes.
    if unsafe { GetTokenInformation(h, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success the buffer starts with a TOKEN_USER, suitably
    // aligned, whose SID points into the same buffer.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    // SAFETY: the SID pointer is valid while `buf` lives.
    unsafe { sid_from_ptr(user.User.Sid) }
}

/// The owner SID of a kernel object we hold a handle to (with
/// `READ_CONTROL`).
fn object_owner(h: HANDLE) -> io::Result<Sid> {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `h` is valid; out-pointers are valid, unused ones null.
    let rc = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let sd = SecurityDescriptor(sd);
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "pipe has no owner",
        ));
    }
    // SAFETY: `owner` points into `sd`, which is still alive.
    let sid = unsafe { sid_from_ptr(owner) };
    drop(sd);
    sid
}

/// Copy a SID out of Windows-owned memory.
///
/// # Safety
///
/// `psid` must point to a SID that stays valid for the call.
unsafe fn sid_from_ptr(psid: PSID) -> io::Result<Sid> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "malformed SID");
    // SAFETY: the caller guarantees `psid` is a readable SID.
    if psid.is_null() || unsafe { IsValidSid(psid) } == 0 {
        return Err(invalid());
    }
    // SAFETY: validated above.
    let len = unsafe { GetLengthSid(psid) } as usize;
    if len > Sid::MAX_LEN {
        return Err(invalid());
    }
    // SAFETY: GetLengthSid says the SID spans `len` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(psid.cast::<u8>(), len) };
    Sid::from_bytes(bytes).ok_or_else(invalid)
}

/// Does any instance of the pipe exist? Never connects to it (that would
/// use up a server instance): `WaitNamedPipeW` returns at once with
/// `ERROR_FILE_NOT_FOUND` when no instance exists and times out when all
/// are busy.
pub(crate) fn pipe_exists(name: &Path) -> bool {
    if validate_pipe_name(name).is_err() {
        return false;
    }
    let wide = wide_nul(name.as_os_str());
    // SAFETY: `wide` is NUL-terminated.
    if unsafe { WaitNamedPipeW(wide.as_ptr(), 1) } != 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32)
}

/// A local pipe name: `\\.\pipe\` and a non-empty rest, at most
/// [`MAX_PIPE_NAME_LEN`] UTF-16 units, no `/` (which Win32 would turn into
/// `\`) and no NUL.
fn validate_pipe_name(name: &Path) -> Result<()> {
    let invalid = |reason: &str| IpcError::InvalidSocketPath {
        path: name.to_path_buf(),
        reason: reason.to_owned(),
    };
    let s = name
        .to_str()
        .ok_or_else(|| invalid("pipe name is not valid Unicode"))?;
    let prefix_ok = s.len() > PIPE_PREFIX.len()
        && s.is_char_boundary(PIPE_PREFIX.len())
        && s[..PIPE_PREFIX.len()].eq_ignore_ascii_case(PIPE_PREFIX);
    if !prefix_ok {
        return Err(invalid(r"not a local pipe name (\\.\pipe\...)"));
    }
    if s.contains(['/', '\0']) {
        return Err(invalid("pipe name contains '/' or NUL"));
    }
    if s.encode_utf16().count() > MAX_PIPE_NAME_LEN {
        return Err(invalid("pipe name is longer than 256 characters"));
    }
    Ok(())
}

fn wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION};

    fn unique(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        PathBuf::from(format!(
            r"\\.\pipe\faro-ipc-unit\{tag}.{}.{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// The security descriptor of the object behind `h`, as SDDL.
    fn sddl_of(h: HANDLE) -> String {
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let what =
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        // SAFETY: valid handle and out-pointers.
        let rc = unsafe {
            GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                what,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "GetSecurityInfo");
        let sd = SecurityDescriptor(sd);
        let mut out: *mut u16 = ptr::null_mut();
        // SAFETY: `sd.0` is a valid descriptor; `out` a valid out-pointer.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.0,
                SDDL_REVISION_1,
                what,
                &mut out,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            ok, 0,
            "ConvertSecurityDescriptorToStringSecurityDescriptorW"
        );
        // SAFETY: a NUL-terminated string allocated by the call above.
        let s = unsafe {
            let len = (0..).take_while(|&i| *out.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
            LocalFree(out.cast());
            s
        };
        s
    }

    #[test]
    fn pipe_name_validation() {
        for ok in [
            r"\\.\pipe\faro\agent",
            r"\\.\PIPE\x",
            r"\\.\pipe\faro\agent.S-1-5-18",
        ] {
            assert!(validate_pipe_name(Path::new(ok)).is_ok(), "{ok}");
        }
        let long = format!(r"\\.\pipe\{}", "a".repeat(250));
        for bad in [
            "",
            r"\\.\pipe\",
            r"\\server\pipe\faro",
            r"\\?\pipe\faro",
            r"C:\faro\agent.sock",
            r"//./pipe/faro",
            r"\\.\pipe\faro/agent",
            long.as_str(),
        ] {
            assert!(
                matches!(
                    validate_pipe_name(Path::new(bad)),
                    Err(IpcError::InvalidSocketPath { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn sddl_shape() {
        let owner = Sid::LOCAL_SYSTEM;
        let user: Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(
            pipe_sddl(&owner, &user),
            "O:S-1-5-18D:P(A;;0x1f01ff;;;S-1-5-18)(A;;0x1f01ff;;;S-1-5-32-544)\
             (A;;0x1f01ff;;;S-1-5-18)(A;;0x12008b;;;S-1-5-21-1-2-3-1001)S:(ML;;NWNR;;;ME)"
        );
        // The client grant has no FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA).
        assert_eq!(CLIENT_GRANTED_ACCESS & 0x4, 0);
        assert_eq!(CLIENT_OPEN_ACCESS & !CLIENT_GRANTED_ACCESS, 0);
    }

    /// The descriptor Windows actually applied to the pipe, read back
    /// through a client handle.
    #[tokio::test]
    async fn applied_security_descriptor() {
        let me = current_user_sid().unwrap();
        let other: Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        let name = unique("sd");
        let _server =
            IpcServer::bind_with(&name, BindOptions::for_account(other), crate::AllowSameUser)
                .unwrap();
        let client = open_client(&name).await.unwrap();
        let sddl = sddl_of(client.as_raw_handle() as HANDLE);
        assert_eq!(object_owner(client.as_raw_handle() as HANDLE).unwrap(), me);
        assert!(sddl.contains("D:P"), "DACL is protected: {sddl}");
        // The other account's grant is exactly read + write-data.
        assert!(
            sddl.contains(&format!("(A;;0x12008b;;;{other})")),
            "client grant: {sddl}"
        );
        // Nobody else: only SYSTEM, Administrators, us and the account.
        let aces = sddl.matches("(A;").count();
        assert_eq!(aces, 4, "{sddl}");
        assert!(!sddl.contains(";;;WD)") && !sddl.contains(";;;AU)") && !sddl.contains(";;;AN)"));
        assert!(sddl.contains("(ML;;NWNR;;;ME)"), "label: {sddl}");

        let peer = server_credentials_raw(client.as_raw_handle()).unwrap();
        assert_eq!(peer.pid, Some(std::process::id()));
        assert_eq!(peer.windows_sid, Some(me));
        assert_eq!(peer.uid, PeerInfo::NO_ID);
    }

    #[test]
    fn bind_outside_runtime_is_an_error_not_a_panic() {
        let r = IpcServer::bind(unique("nort"), crate::AllowSameUser);
        assert!(matches!(r, Err(IpcError::NoRuntime)));
    }

    #[test]
    fn current_user_is_a_real_account() {
        // A local (S-1-5-21-…) or Entra ID (S-1-12-1-…) user, not a
        // service account.
        let me = current_user_sid().unwrap();
        assert_ne!(me, Sid::LOCAL_SYSTEM);
        assert!(me.sub_authorities().count() >= 4, "{me}");
    }
}
