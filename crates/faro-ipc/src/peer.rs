//! Who is on the other end of the socket or pipe, and whether we accept
//! them.
//!
//! # Code-signature hook
//!
//! ARCHITECTURE.md §3.1 requires the service to verify the *code signature*
//! of the connecting agent binary, not just its account. That check is
//! OS-specific (Security.framework on macOS, Authenticode on Windows, a
//! package-manager/IMA check on Linux) and belongs in the platform crates.
//! This crate exposes everything needed to do it and a place to plug it in:
//!
//! * [`PeerInfo::pid`] — the kernel-reported peer pid, and
//! * [`PeerInfo::macos_audit_token`] — on macOS, the peer's audit token.
//!   **Prefer the audit token**: a pid can be recycled between the
//!   credential read and the signature check, while an audit token pins the
//!   exact process instance (pass it to
//!   `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit, …)`).
//! * On Windows, [`PeerInfo::pid`] (from `GetNamedPipeClientProcessId`) is
//!   what `faro_platform_windows::authenticode::verify_process(pid, req)`
//!   takes. Windows has no audit-token equivalent for a pipe client, so the
//!   pid caveat applies: a client that hands its pipe handle to a child and
//!   exits leaves a pid that can be recycled. The account check does not
//!   have this problem ([`PeerInfo::windows_sid`] is read from the
//!   connection itself, not from the pid), so do it first; the signature
//!   check raises the bar on top of it.
//!
//! Implement [`PeerVerifier`] (or pass a closure) that first checks the
//! account and then calls the platform's signature check; the transport
//! invokes it on every accepted connection before any byte is read from the
//! peer.
//!
//! # Accounts on each platform
//!
//! | | account set | "the privileged service" | dev: "same account as me" |
//! |---|---|---|---|
//! | Unix | [`AllowUids`] | [`AllowUids::root`] / [`AllowSystemService`] | `AllowSameUid` / [`AllowSameUser`] |
//! | Windows | [`AllowSids`] | [`AllowSids::local_system`] / [`AllowSystemService`] | [`AllowSameUser`] |
//!
//! [`AllowSystemService`] and [`AllowSameUser`] exist on every platform, so
//! the agent can pick its service trust without `cfg`s. Each verifier fails
//! closed on a peer that carries the other platform's identity: on Windows
//! [`PeerInfo::uid`] is [`PeerInfo::NO_ID`], which [`AllowUids`] never
//! admits, and on Unix [`PeerInfo::windows_sid`] is `None`, which
//! [`AllowSids`] never admits.

use std::collections::BTreeSet;

use crate::error::{IpcError, Result};
use crate::sid::Sid;

/// Kernel-reported credentials of a socket or pipe peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    /// Effective uid of the peer process. [`PeerInfo::NO_ID`] on Windows.
    pub uid: u32,
    /// Effective gid of the peer process. [`PeerInfo::NO_ID`] on Windows.
    pub gid: u32,
    /// Peer pid, when the OS reports one. On Windows, from
    /// `GetNamedPipeClientProcessId` (server side) or
    /// `GetNamedPipeServerProcessId` (client side).
    pub pid: Option<u32>,
    /// macOS `audit_token_t` of the peer (`LOCAL_PEERTOKEN`); `None` on other
    /// platforms. Layout: `[auid, euid, egid, ruid, rgid, pid, asid, pidversion]`.
    pub macos_audit_token: Option<[u32; 8]>,
    /// Windows: the peer's account; `None` on other platforms.
    ///
    /// * Seen by the **service** (a client): the user SID of the token the
    ///   client opened the pipe with, read by impersonating the client at
    ///   identification level (`ImpersonateNamedPipeClient` +
    ///   `OpenThreadToken`). It comes from the connection, not from the pid,
    ///   so it cannot be raced by pid reuse.
    /// * Seen by the **agent** (the server): the owner of the pipe object.
    ///   See [`crate::named_pipe`] (Windows) for why that, and not the
    ///   server process's token, identifies the service.
    pub windows_sid: Option<Sid>,
    /// Windows: the peer's Terminal Services session id
    /// (`GetNamedPipeClientSessionId` / `GetNamedPipeServerSessionId`);
    /// `None` on other platforms. Services run in session 0; each logged-in
    /// user has their own. The service can require an agent's session to be
    /// the one it launched the agent into.
    pub windows_session_id: Option<u32>,
}

impl PeerInfo {
    /// The uid/gid recorded where the OS has none (Windows). `(uid_t)-1` is
    /// reserved by POSIX as "no id" and never belongs to a real account, and
    /// [`AllowUids`] refuses it even if it is in the set.
    pub const NO_ID: u32 = u32::MAX;
}

/// Decides whether a connected peer may talk to us.
///
/// Return [`IpcError::PeerRejected`] (see [`IpcError::peer_rejected`]) to
/// refuse; the transport then closes the connection without reading from or
/// writing to it.
pub trait PeerVerifier: Send + Sync {
    fn verify(&self, peer: &PeerInfo) -> Result<()>;
}

/// Closures are verifiers, which makes composing an account check with a
/// platform code-signature check a one-liner.
impl<F> PeerVerifier for F
where
    F: Fn(&PeerInfo) -> Result<()> + Send + Sync,
{
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        self(peer)
    }
}

/// Accept only peers running as our own effective uid.
///
/// Useful for development and tests, and for the agent verifying a
/// same-user helper. The production service runs as root and should use
/// [`AllowUids`] with the session user's uid instead. [`AllowSameUser`] is
/// the same check under a name that also exists on Windows.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowSameUid;

#[cfg(unix)]
impl PeerVerifier for AllowSameUid {
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        if peer.uid == me {
            Ok(())
        } else {
            Err(IpcError::peer_rejected(format!(
                "uid {} is not our uid {me}",
                peer.uid
            )))
        }
    }
}

/// Accept only peers whose uid is in an explicit set. Root is not implicitly
/// allowed, and [`PeerInfo::NO_ID`] (every Windows peer) never is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowUids(pub BTreeSet<u32>);

impl AllowUids {
    pub fn new(uids: impl IntoIterator<Item = u32>) -> Self {
        AllowUids(uids.into_iter().collect())
    }

    /// Only uid 0. What the agent should require of the service it connects
    /// to, so a same-user impostor listening on a stale path is refused.
    pub fn root() -> Self {
        Self::new([0])
    }
}

impl PeerVerifier for AllowUids {
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        if peer.uid != PeerInfo::NO_ID && self.0.contains(&peer.uid) {
            Ok(())
        } else {
            Err(IpcError::peer_rejected(format!(
                "uid {} is not in the allowed set",
                peer.uid
            )))
        }
    }
}

/// Accept only peers whose account SID is in an explicit set: the Windows
/// [`AllowUids`]. LocalSystem and Administrators are not implicitly allowed,
/// and a peer without a SID (every Unix peer) never is.
///
/// The service admits an agent with `AllowSids::new([session_user])`; the
/// agent requires [`AllowSids::local_system`] of the service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowSids(pub BTreeSet<Sid>);

impl AllowSids {
    pub fn new(sids: impl IntoIterator<Item = Sid>) -> Self {
        AllowSids(sids.into_iter().collect())
    }

    /// Only `S-1-5-18` (LocalSystem). What the agent should require of the
    /// service it connects to, so a same-user impostor that created the pipe
    /// name first is refused.
    pub fn local_system() -> Self {
        Self::new([Sid::LOCAL_SYSTEM])
    }
}

impl PeerVerifier for AllowSids {
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        match peer.windows_sid {
            Some(sid) if self.0.contains(&sid) => Ok(()),
            Some(sid) => Err(IpcError::peer_rejected(format!(
                "account {sid} is not in the allowed set"
            ))),
            None => Err(IpcError::peer_rejected("peer has no Windows account SID")),
        }
    }
}

/// Accept only the privileged system service: uid 0 on Unix
/// ([`AllowUids::root`]), LocalSystem on Windows
/// ([`AllowSids::local_system`]).
///
/// What a production agent requires of the endpoint it connects to. It
/// exists on every platform so faro-agent can choose its service trust
/// without `cfg`s.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowSystemService;

impl PeerVerifier for AllowSystemService {
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        if cfg!(windows) {
            AllowSids::local_system().verify(peer)
        } else {
            AllowUids::root().verify(peer)
        }
    }
}

/// Accept only peers running as the same account as this process: our
/// effective uid on Unix (`AllowSameUid`), our process token's user SID on
/// Windows.
///
/// For development and tests: a service run by hand as the user, with the
/// agent's `--trust-same-uid-service`. Never what production uses; a
/// same-account peer is exactly the impostor the production checks exist to
/// refuse.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowSameUser;

impl PeerVerifier for AllowSameUser {
    fn verify(&self, peer: &PeerInfo) -> Result<()> {
        #[cfg(unix)]
        {
            AllowSameUid.verify(peer)
        }
        #[cfg(windows)]
        {
            let me = crate::named_pipe::current_user_sid().map_err(|e| {
                IpcError::peer_rejected(format!("cannot read our own account: {e}"))
            })?;
            match peer.windows_sid {
                Some(sid) if sid == me => Ok(()),
                Some(sid) => Err(IpcError::peer_rejected(format!(
                    "account {sid} is not our account {me}"
                ))),
                None => Err(IpcError::peer_rejected("peer has no Windows account SID")),
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = peer;
            Err(IpcError::peer_rejected(
                "account checks are not implemented for this OS",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32) -> PeerInfo {
        PeerInfo {
            uid,
            gid: 20,
            pid: Some(1234),
            macos_audit_token: None,
            windows_sid: None,
            windows_session_id: None,
        }
    }

    fn win_peer(sid: Sid) -> PeerInfo {
        PeerInfo {
            uid: PeerInfo::NO_ID,
            gid: PeerInfo::NO_ID,
            pid: Some(1234),
            macos_audit_token: None,
            windows_sid: Some(sid),
            windows_session_id: Some(1),
        }
    }

    #[test]
    fn allow_uids_is_exact() {
        let v = AllowUids::new([501, 502]);
        assert!(v.verify(&peer(501)).is_ok());
        assert!(v.verify(&peer(502)).is_ok());
        assert!(matches!(v.verify(&peer(0)), Err(IpcError::PeerRejected(_))));
        assert!(AllowUids::default().verify(&peer(501)).is_err());
        assert!(AllowUids::root().verify(&peer(0)).is_ok());
        assert!(AllowUids::root().verify(&peer(1)).is_err());
    }

    #[test]
    fn no_id_is_never_a_uid() {
        let v = AllowUids::new([PeerInfo::NO_ID, 0]);
        assert!(v.verify(&peer(PeerInfo::NO_ID)).is_err());
        assert!(v.verify(&win_peer(Sid::LOCAL_SYSTEM)).is_err());
    }

    #[test]
    fn allow_sids_is_exact() {
        let user: Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        let other: Sid = "S-1-5-21-1-2-3-1002".parse().unwrap();
        let v = AllowSids::new([user]);
        assert!(v.verify(&win_peer(user)).is_ok());
        assert!(matches!(
            v.verify(&win_peer(other)),
            Err(IpcError::PeerRejected(_))
        ));
        // Neither the system nor administrators get in implicitly.
        assert!(v.verify(&win_peer(Sid::LOCAL_SYSTEM)).is_err());
        assert!(v.verify(&win_peer(Sid::BUILTIN_ADMINISTRATORS)).is_err());
        // A Unix-style peer has no SID.
        assert!(v.verify(&peer(0)).is_err());
        assert!(AllowSids::default().verify(&win_peer(user)).is_err());

        let sys = AllowSids::local_system();
        assert!(sys.verify(&win_peer(Sid::LOCAL_SYSTEM)).is_ok());
        assert!(sys.verify(&win_peer(user)).is_err());
        assert!(sys.verify(&win_peer(Sid::BUILTIN_ADMINISTRATORS)).is_err());
    }

    #[test]
    fn system_service_per_platform() {
        let user: Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert!(AllowSystemService.verify(&win_peer(user)).is_err());
        assert!(AllowSystemService.verify(&peer(501)).is_err());
        if cfg!(windows) {
            assert!(AllowSystemService
                .verify(&win_peer(Sid::LOCAL_SYSTEM))
                .is_ok());
            assert!(AllowSystemService.verify(&peer(0)).is_err());
        } else {
            assert!(AllowSystemService.verify(&peer(0)).is_ok());
            assert!(AllowSystemService
                .verify(&win_peer(Sid::LOCAL_SYSTEM))
                .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn allow_same_uid() {
        // SAFETY: no preconditions.
        let me = unsafe { libc::geteuid() };
        assert!(AllowSameUid.verify(&peer(me)).is_ok());
        assert!(AllowSameUid.verify(&peer(me.wrapping_add(1))).is_err());
        assert!(AllowSameUser.verify(&peer(me)).is_ok());
        assert!(AllowSameUser.verify(&peer(me.wrapping_add(1))).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn allow_same_user() {
        let me = crate::current_account().unwrap();
        assert!(AllowSameUser.verify(&win_peer(me)).is_ok());
        let other: Sid = "S-1-5-21-1-2-3-1002".parse().unwrap();
        assert!(AllowSameUser.verify(&win_peer(other)).is_err());
        assert!(AllowSameUser.verify(&peer(0)).is_err());
    }

    #[test]
    fn closures_compose() {
        let uid_ok = AllowUids::new([501]);
        let v = move |p: &PeerInfo| {
            uid_ok.verify(p)?;
            match p.pid {
                Some(_) => Ok(()),
                None => Err(IpcError::peer_rejected("no pid for signature check")),
            }
        };
        assert!(v.verify(&peer(501)).is_ok());
        let mut nopid = peer(501);
        nopid.pid = None;
        assert!(v.verify(&nopid).is_err());
        assert!(v.verify(&peer(502)).is_err());
    }
}
