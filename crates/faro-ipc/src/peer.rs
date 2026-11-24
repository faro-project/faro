//! Who is on the other end of the socket, and whether we accept them.
//!
//! # Code-signature hook
//!
//! ARCHITECTURE.md §3.1 requires the service to verify the *code signature*
//! of the connecting agent binary, not just its uid. That check is
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
//!
//! Implement [`PeerVerifier`] (or pass a closure) that first checks the uid
//! and then calls the platform's signature check; the transport invokes it
//! on every accepted connection before any byte is read from the peer.

use std::collections::BTreeSet;

use crate::error::{IpcError, Result};

/// Kernel-reported credentials of a socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerInfo {
    /// Effective uid of the peer process.
    pub uid: u32,
    /// Effective gid of the peer process.
    pub gid: u32,
    /// Peer pid, when the OS reports one.
    pub pid: Option<u32>,
    /// macOS `audit_token_t` of the peer (`LOCAL_PEERTOKEN`); `None` on other
    /// platforms. Layout: `[auid, euid, egid, ruid, rgid, pid, asid, pidversion]`.
    pub macos_audit_token: Option<[u32; 8]>,
}

/// Decides whether a connected peer may talk to us.
///
/// Return [`IpcError::PeerRejected`] (see [`IpcError::peer_rejected`]) to
/// refuse; the transport then closes the connection without reading from or
/// writing to it.
pub trait PeerVerifier: Send + Sync {
    fn verify(&self, peer: &PeerInfo) -> Result<()>;
}

/// Closures are verifiers, which makes composing a uid check with a
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
/// [`AllowUids`] with the session user's uid instead.
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
/// allowed.
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
        if self.0.contains(&peer.uid) {
            Ok(())
        } else {
            Err(IpcError::peer_rejected(format!(
                "uid {} is not in the allowed set",
                peer.uid
            )))
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

    #[cfg(unix)]
    #[test]
    fn allow_same_uid() {
        // SAFETY: no preconditions.
        let me = unsafe { libc::geteuid() };
        assert!(AllowSameUid.verify(&peer(me)).is_ok());
        assert!(AllowSameUid.verify(&peer(me.wrapping_add(1))).is_err());
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
