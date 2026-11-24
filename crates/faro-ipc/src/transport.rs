//! Unix-domain-socket transport (macOS, Linux) — ARCHITECTURE.md §3.1, §9.
//!
//! Security properties, in the order they are established:
//!
//! 1. **The socket directory cannot be manipulated by others.** The parent
//!    directory (after resolving symlinks) must be owned by root or our
//!    effective uid and must not be group/world-writable; every ancestor must
//!    be owned by root or us and be either not group/world-writable or
//!    sticky (like `/tmp`). Otherwise another user could swap the socket for
//!    their own and impersonate the service.
//! 2. **The socket never exists with loose permissions.** It is bound inside
//!    a fresh private (0700) staging directory, chmod/chowned there, and then
//!    atomically `rename`d into place (which also replaces a stale socket
//!    from a previous run without an unlink/bind race). A live listener on
//!    the path is detected and refused rather than hijacked.
//! 3. **Every peer is identified by the kernel** (`SO_PEERCRED` on Linux;
//!    `getpeereid` + `LOCAL_PEERPID` + `LOCAL_PEERTOKEN` on macOS) and passed
//!    to a caller-supplied [`PeerVerifier`] before a single byte is read. A
//!    rejected peer's connection is closed immediately. Code-signature
//!    verification of the peer binary plugs in there (see [`crate::peer`]).
//!
//! The agent side should also verify the *server* (`connect_verified` with
//! [`AllowUids::root`](crate::AllowUids::root)) so it never streams frames
//! to an impostor.
//!
//! Linux credential code is written against `libc` but could not be compiled
//! on the macOS host this crate was developed on; it is small and mirrors
//! the standard `SO_PEERCRED` pattern.

use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::connection::{AgentConnection, Connection, ServiceConnection};
use crate::error::{IpcError, Result};
use crate::peer::{PeerInfo, PeerVerifier};

/// The per-account socket a root service binds for `uid`, next to `base`:
/// `agent.sock` becomes `agent.<uid>.sock`.
///
/// Every OS account is monitored (ARCHITECTURE.md §3.1), so agents of
/// several users connect to one service. Rather than open one socket to
/// everyone (this module refuses modes beyond owner/group), a root service
/// binds one `0600` socket per account, owned by that account; an agent
/// connects to its own ([`resolve_agent_socket`]). A non-root development
/// service binds `base` itself.
pub fn session_socket_path(base: &Path, uid: u32) -> PathBuf {
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".to_owned());
    let name = match base.extension() {
        Some(ext) => format!("{stem}.{uid}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{uid}"),
    };
    base.with_file_name(name)
}

/// Where an agent running as `uid` should connect: its per-account socket
/// ([`session_socket_path`]) if the service has bound one, else `base`
/// (a development service running as the user).
pub fn resolve_agent_socket(base: &Path, uid: u32) -> PathBuf {
    let own = session_socket_path(base, uid);
    match fs::symlink_metadata(&own) {
        Ok(md) if md.file_type().is_socket() => own,
        _ => base.to_path_buf(),
    }
}

/// Ownership and mode applied to the socket file before it becomes visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindOptions {
    /// Permission bits. Must include owner read/write (0o600) and may add
    /// group read/write (0o060); nothing else is allowed.
    pub mode: u32,
    /// Group to own the socket (needed with `0o660`, e.g. a `faro` group
    /// whose members are the monitored session users).
    pub group: Option<u32>,
    /// User to own the socket. Lets a root service create a per-session
    /// socket only that session's user can connect to with mode `0o600`.
    pub owner: Option<u32>,
}

impl Default for BindOptions {
    fn default() -> Self {
        BindOptions {
            mode: 0o600,
            group: None,
            owner: None,
        }
    }
}

impl BindOptions {
    /// `0o660` owned by `gid`.
    pub fn group_access(gid: u32) -> Self {
        BindOptions {
            mode: 0o660,
            group: Some(gid),
            owner: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.mode & !0o660 != 0 {
            return Err(IpcError::InvalidOptions(format!(
                "mode {:o} grants more than owner/group read-write",
                self.mode
            )));
        }
        if self.mode & 0o600 != 0o600 {
            return Err(IpcError::InvalidOptions(format!(
                "mode {:o} must include owner read-write",
                self.mode
            )));
        }
        Ok(())
    }
}

/// A listening IPC endpoint (the service side).
///
/// Dropping it removes the socket file, but only if the path still refers to
/// the socket this server created.
pub struct IpcServer {
    listener: UnixListener,
    path: PathBuf,
    /// (dev, ino) of our socket, to avoid deleting someone else's on drop.
    ident: (u64, u64),
    verifier: Arc<dyn PeerVerifier>,
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl IpcServer {
    /// Bind with [`BindOptions::default`] (mode `0o600`). Must be called
    /// from within a Tokio runtime.
    pub fn bind(path: impl AsRef<Path>, verifier: impl PeerVerifier + 'static) -> Result<Self> {
        Self::bind_with(path, BindOptions::default(), verifier)
    }

    /// Bind with explicit ownership/mode. See the module docs for the checks.
    pub fn bind_with(
        path: impl AsRef<Path>,
        options: BindOptions,
        verifier: impl PeerVerifier + 'static,
    ) -> Result<Self> {
        options.validate()?;
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(IpcError::NoRuntime);
        }
        let requested = path.as_ref();
        let invalid = |reason: &str| IpcError::InvalidSocketPath {
            path: requested.to_path_buf(),
            reason: reason.to_owned(),
        };
        let file_name = requested
            .file_name()
            .ok_or_else(|| invalid("path has no file name"))?;
        let parent = match requested.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        // Resolve symlinks once, check the real directory chain, and then
        // only ever use the resolved path.
        let parent = fs::canonicalize(parent)?;
        check_secure_dir(&parent)?;
        let path = parent.join(file_name);

        clear_stale_socket(&path)?;

        let staging = StagingDir::create(&parent)?;
        let staged = staging.path.join("s");
        let std_listener = std::os::unix::net::UnixListener::bind(&staged)?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(options.mode))?;
        if options.owner.is_some() || options.group.is_some() {
            std::os::unix::fs::chown(&staged, options.owner, options.group)?;
        }
        let md = fs::symlink_metadata(&staged)?;
        let ident = (md.dev(), md.ino());
        fs::rename(&staged, &path)?;
        drop(staging);

        std_listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(std_listener)?;
        Ok(IpcServer {
            listener,
            path,
            ident,
            verifier: Arc::new(verifier),
        })
    }

    /// The resolved socket path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accept the next connection and verify its peer.
    ///
    /// A peer that fails verification is disconnected and reported as an
    /// error; callers running an accept loop should log it and continue
    /// rather than stop listening.
    pub async fn accept(&self) -> Result<ServiceConnection<UnixStream>> {
        let (stream, _addr) = self.listener.accept().await?;
        let peer = peer_credentials(&stream).map_err(IpcError::PeerCredentials)?;
        // On rejection `stream` is dropped here, closing the connection
        // without a byte exchanged.
        self.verifier.verify(&peer)?;
        Ok(Connection::with_peer(stream, Some(peer)))
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        if let Ok(md) = fs::symlink_metadata(&self.path) {
            if md.file_type().is_socket() && (md.dev(), md.ino()) == self.ident {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// The agent side of the transport.
#[derive(Debug, Clone, Copy)]
pub struct IpcClient;

impl IpcClient {
    /// Connect without checking who is listening. Prefer
    /// [`connect_verified`](Self::connect_verified) in production.
    pub async fn connect(path: impl AsRef<Path>) -> Result<AgentConnection<UnixStream>> {
        let stream = UnixStream::connect(path.as_ref()).await?;
        let peer = peer_credentials(&stream).map_err(IpcError::PeerCredentials)?;
        Ok(Connection::with_peer(stream, Some(peer)))
    }

    /// Connect and require the listening process to pass `verifier`
    /// (typically [`AllowUids::root`](crate::AllowUids::root)).
    pub async fn connect_verified(
        path: impl AsRef<Path>,
        verifier: &dyn PeerVerifier,
    ) -> Result<AgentConnection<UnixStream>> {
        let conn = Self::connect(path).await?;
        // `connect` always records the peer; fail closed if that ever changes.
        let peer = conn
            .peer()
            .ok_or_else(|| IpcError::peer_rejected("server credentials unavailable"))?;
        verifier.verify(peer)?;
        Ok(conn)
    }
}

/// Read the kernel's view of who is on the other end of a Unix socket.
pub fn peer_credentials(sock: &impl AsRawFd) -> io::Result<PeerInfo> {
    os::peer_credentials(sock.as_raw_fd())
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The sticky bit. Its value is fixed by POSIX, so it is spelled out here
/// rather than taken from `libc`, whose `S_ISVTX` is `u16` on macOS but
/// `u32` on Linux (which makes any conversion lint-clean on only one of them).
const S_ISVTX: u32 = 0o1000;

/// See the module docs, point 1.
fn check_secure_dir(dir: &Path) -> Result<()> {
    let me = euid();
    let insecure = |p: &Path, reason: String| IpcError::InsecureSocketDir {
        path: p.to_path_buf(),
        reason,
    };
    let md = fs::metadata(dir)?;
    if !md.is_dir() {
        return Err(IpcError::InvalidSocketPath {
            path: dir.to_path_buf(),
            reason: "parent is not a directory".into(),
        });
    }
    if md.uid() != 0 && md.uid() != me {
        return Err(insecure(
            dir,
            format!("owned by uid {}, expected root or {me}", md.uid()),
        ));
    }
    if md.mode() & 0o022 != 0 {
        return Err(insecure(
            dir,
            format!("mode {:o} is group- or world-writable", md.mode() & 0o7777),
        ));
    }
    for anc in dir.ancestors().skip(1) {
        let md = fs::metadata(anc)?;
        if md.uid() != 0 && md.uid() != me {
            return Err(insecure(
                anc,
                format!("ancestor owned by uid {}, expected root or {me}", md.uid()),
            ));
        }
        let sticky = md.mode() & S_ISVTX != 0;
        if md.mode() & 0o022 != 0 && !sticky {
            return Err(insecure(
                anc,
                format!(
                    "ancestor mode {:o} is group- or world-writable without the sticky bit",
                    md.mode() & 0o7777
                ),
            ));
        }
    }
    Ok(())
}

/// See the module docs, point 2. Leaves a dead socket in place (the atomic
/// rename replaces it) but refuses to touch anything else.
fn clear_stale_socket(path: &Path) -> Result<()> {
    let md = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !md.file_type().is_socket() {
        return Err(IpcError::InvalidSocketPath {
            path: path.to_path_buf(),
            reason: "occupied by something that is not a socket; refusing to replace it".into(),
        });
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(IpcError::AddrInUse(path.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A private 0700 directory next to the final socket path, removed on drop.
struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn create(parent: &Path) -> Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let pid = std::process::id();
        for _ in 0..16 {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".faro-ipc-{pid}-{n}"));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(StagingDir { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(IpcError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create a unique socket staging directory",
        )))
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.path.join("s"));
        let _ = fs::remove_dir(&self.path);
    }
}

#[cfg(target_vendor = "apple")]
mod os {
    use super::*;

    pub fn peer_credentials(fd: RawFd) -> io::Result<PeerInfo> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: `fd` is a valid socket for the duration of the call; uid and
        // gid are valid out-pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut pid: libc::pid_t = 0;
        let pid = match getsockopt_local(fd, libc::LOCAL_PEERPID, &mut pid) {
            Ok(()) if pid > 0 => Some(pid as u32),
            _ => None,
        };

        let mut token = [0u32; 8];
        let macos_audit_token = match getsockopt_local(fd, libc::LOCAL_PEERTOKEN, &mut token) {
            Ok(()) => Some(token),
            Err(_) => None,
        };

        Ok(PeerInfo {
            uid,
            gid,
            pid,
            macos_audit_token,
        })
    }

    /// `getsockopt(fd, SOL_LOCAL, opt, out)` requiring the kernel to fill
    /// exactly `size_of::<T>()` bytes.
    fn getsockopt_local<T: Copy>(fd: RawFd, opt: libc::c_int, out: &mut T) -> io::Result<()> {
        let want = std::mem::size_of::<T>();
        let mut len = want as libc::socklen_t;
        // SAFETY: `out` points to `want` writable bytes and `len` says so;
        // T is plain old data (pid_t / [u32; 8]).
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                opt,
                (out as *mut T).cast::<c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned an unexpected option length",
            ));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod os {
    use super::*;

    pub fn peer_credentials(fd: RawFd) -> io::Result<PeerInfo> {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let want = std::mem::size_of::<libc::ucred>();
        let mut len = want as libc::socklen_t;
        // SAFETY: `cred` is a valid, writable ucred and `len` is its size.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast::<c_void>(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel returned an unexpected SO_PEERCRED length",
            ));
        }
        Ok(PeerInfo {
            uid: cred.uid,
            gid: cred.gid,
            pid: (cred.pid > 0).then_some(cred.pid as u32),
            macos_audit_token: None,
        })
    }
}

#[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
mod os {
    use super::*;

    /// Faro targets macOS, Linux and Windows only. Refusing is safer than
    /// guessing at another kernel's credential API.
    pub fn peer_credentials(_fd: RawFd) -> io::Result<PeerInfo> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer credentials are not implemented for this OS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_options_validation() {
        assert!(BindOptions::default().validate().is_ok());
        assert!(BindOptions::group_access(20).validate().is_ok());
        for mode in [0o666, 0o700, 0o602, 0o400, 0o000, 0o4600] {
            let o = BindOptions {
                mode,
                ..BindOptions::default()
            };
            assert!(o.validate().is_err(), "mode {mode:o} accepted");
        }
    }

    #[test]
    fn bind_outside_runtime_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let r = IpcServer::bind(dir.path().join("s.sock"), crate::AllowSameUid);
        assert!(matches!(r, Err(IpcError::NoRuntime)));
    }

    #[test]
    fn per_account_socket_names() {
        assert_eq!(
            session_socket_path(Path::new("/var/run/faro/agent.sock"), 501),
            Path::new("/var/run/faro/agent.501.sock")
        );
        assert_eq!(
            session_socket_path(Path::new("/run/faro/agent"), 1000),
            Path::new("/run/faro/agent.1000")
        );
        // Nothing bound for the account: fall back to the base path.
        let base = Path::new("/nonexistent-faro-dir/agent.sock");
        assert_eq!(resolve_agent_socket(base, 501), base);
    }
}
