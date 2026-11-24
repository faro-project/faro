//! Verifying the connecting agent binary's code signature (ARCHITECTURE.md
//! §3.1: "peer-credential checks and verification of the connecting
//! binary's code signature").
//!
//! A uid check alone is not enough: every process the session user runs has
//! that uid, so without this check about twenty lines of user code can
//! connect, say `Hello`, and feed the service forged session state ("the
//! system is asleep") while the real agent is locked out. With it, only a
//! binary whose signature satisfies the configured **designated
//! requirement** (`ipc.agent_requirement`, for example
//! `anchor apple generic and identifier "org.faro.agent" and certificate
//! leaf[subject.OU] = "<TEAMID>"`) is accepted.
//!
//! The check runs in the `faro-ipc` [`PeerVerifier`](faro_ipc::PeerVerifier),
//! before a byte is read from the peer, and pins the exact process instance
//! through the kernel's **audit token** rather than the pid (a pid can be
//! recycled between the credential read and the check).
//!
//! macOS only: Authenticode (Windows) and IMA / package-manager checks
//! (Linux) are not implemented, so on those systems a configured
//! requirement rejects every peer rather than being silently ignored.

use faro_ipc::PeerInfo;

/// Why a peer's code signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeSignError {
    #[error("the designated requirement is not valid (OSStatus {0})")]
    BadRequirement(i32),
    #[error("the kernel did not report the peer's audit token")]
    NoAuditToken,
    #[error("cannot locate the peer's code (OSStatus {0})")]
    NoGuest(i32),
    #[error(
        "the peer's code signature is invalid or does not satisfy the requirement (OSStatus {0})"
    )]
    Rejected(i32),
    #[error("Core Foundation allocation failed")]
    Alloc,
    #[error("code-signature verification is not implemented on this operating system")]
    Unsupported,
}

/// Check that `requirement` parses as a designated requirement, so a typo
/// in the config fails at start rather than locking out every agent.
pub fn check_requirement(requirement: &str) -> Result<(), CodeSignError> {
    imp::check_requirement(requirement)
}

/// Verify that the process behind `peer` is validly signed and satisfies
/// `requirement`.
pub fn verify_peer(peer: &PeerInfo, requirement: &str) -> Result<(), CodeSignError> {
    imp::verify_peer(peer, requirement)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::CodeSignError;
    use faro_ipc::PeerInfo;
    use std::ffi::c_void;

    type CFTypeRef = *const c_void;
    type CFIndex = isize;
    type OSStatus = i32;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_SEC_CS_DEFAULT_FLAGS: u32 = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFTypeDictionaryKeyCallBacks: [usize; 6];
        static kCFTypeDictionaryValueCallBacks: [usize; 5];
        fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFTypeRef;
        fn CFStringCreateWithBytes(
            allocator: CFTypeRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: u32,
            is_external_representation: u8,
        ) -> CFTypeRef;
        fn CFDictionaryCreate(
            allocator: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFTypeRef;
        fn CFRelease(cf: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributeAudit: CFTypeRef;
        fn SecCodeCopyGuestWithAttributes(
            host: CFTypeRef,
            attributes: CFTypeRef,
            flags: u32,
            guest: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecRequirementCreateWithString(
            text: CFTypeRef,
            flags: u32,
            requirement: *mut CFTypeRef,
        ) -> OSStatus;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    }

    /// An owned Core Foundation reference, released on drop.
    struct Owned(CFTypeRef);

    impl Owned {
        fn new(r: CFTypeRef) -> Result<Owned, CodeSignError> {
            if r.is_null() {
                Err(CodeSignError::Alloc)
            } else {
                Ok(Owned(r))
            }
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a non-null reference we own (created by a
            // CF/Security "Create"/"Copy" function) and release exactly once.
            unsafe { CFRelease(self.0) }
        }
    }

    fn requirement(text: &str) -> Result<Owned, CodeSignError> {
        let len = CFIndex::try_from(text.len()).map_err(|_| CodeSignError::Alloc)?;
        // SAFETY: the pointer/length pair describes `text`, which outlives
        // the call; CF copies the bytes. A null allocator means the default.
        let s = Owned::new(unsafe {
            CFStringCreateWithBytes(
                std::ptr::null(),
                text.as_ptr(),
                len,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        })?;
        let mut req: CFTypeRef = std::ptr::null();
        // SAFETY: `s.0` is a valid CFString and `req` a valid out pointer.
        let status =
            unsafe { SecRequirementCreateWithString(s.0, K_SEC_CS_DEFAULT_FLAGS, &mut req) };
        if status != 0 || req.is_null() {
            return Err(CodeSignError::BadRequirement(status));
        }
        Ok(Owned(req))
    }

    pub(super) fn check_requirement(text: &str) -> Result<(), CodeSignError> {
        requirement(text).map(drop)
    }

    pub(super) fn verify_peer(peer: &PeerInfo, text: &str) -> Result<(), CodeSignError> {
        let token = peer.macos_audit_token.ok_or(CodeSignError::NoAuditToken)?;
        let req = requirement(text)?;
        // `audit_token_t` is `struct { unsigned int val[8]; }`.
        let mut bytes = [0u8; 32];
        for (chunk, v) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(token) {
            *chunk = v.to_ne_bytes();
        }
        // SAFETY: the pointer/length pair describes `bytes`; CF copies it.
        let data = Owned::new(unsafe {
            CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex)
        })?;
        // SAFETY: reading an immutable framework constant.
        let key = unsafe { kSecGuestAttributeAudit };
        let keys = [key];
        let values = [data.0];
        // SAFETY: `keys`/`values` hold one valid CF object each and outlive
        // the call (the dictionary retains them); the callbacks are the
        // framework's own CFType callbacks.
        let attrs = Owned::new(unsafe {
            CFDictionaryCreate(
                std::ptr::null(),
                keys.as_ptr(),
                values.as_ptr(),
                1,
                std::ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
                std::ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
            )
        })?;
        let mut guest: CFTypeRef = std::ptr::null();
        // SAFETY: a null host means "the system"; `attrs` is a valid
        // dictionary and `guest` a valid out pointer.
        let status = unsafe {
            SecCodeCopyGuestWithAttributes(
                std::ptr::null(),
                attrs.0,
                K_SEC_CS_DEFAULT_FLAGS,
                &mut guest,
            )
        };
        if status != 0 || guest.is_null() {
            return Err(CodeSignError::NoGuest(status));
        }
        let guest = Owned(guest);
        // SAFETY: `guest` is a valid SecCode and `req` a valid SecRequirement.
        let status = unsafe { SecCodeCheckValidity(guest.0, K_SEC_CS_DEFAULT_FLAGS, req.0) };
        if status != 0 {
            return Err(CodeSignError::Rejected(status));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::CodeSignError;
    use faro_ipc::PeerInfo;

    pub(super) fn check_requirement(_text: &str) -> Result<(), CodeSignError> {
        Err(CodeSignError::Unsupported)
    }

    pub(super) fn verify_peer(_peer: &PeerInfo, _text: &str) -> Result<(), CodeSignError> {
        Err(CodeSignError::Unsupported)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use faro_ipc::{BindOptions, IpcClient, IpcServer};
    use std::sync::{Arc, Mutex};

    /// The credentials of a real socket peer: this test process.
    async fn own_peer_info() -> PeerInfo {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("cs.sock");
        let seen = Arc::new(Mutex::new(None));
        let seen2 = seen.clone();
        let server = IpcServer::bind_with(
            &sock,
            BindOptions::default(),
            move |p: &PeerInfo| -> faro_ipc::Result<()> {
                *seen2.lock().unwrap() = Some(*p);
                Ok(())
            },
        )
        .unwrap();
        let (_c, s) = tokio::join!(IpcClient::connect(&sock), server.accept());
        s.unwrap();
        let p = seen.lock().unwrap().take();
        p.unwrap()
    }

    #[test]
    fn requirement_syntax_is_checked() {
        check_requirement("anchor apple generic").unwrap();
        assert!(matches!(
            check_requirement("this is not a requirement"),
            Err(CodeSignError::BadRequirement(_))
        ));
    }

    #[tokio::test]
    async fn peer_must_satisfy_the_requirement() {
        let peer = own_peer_info().await;
        assert!(peer.macos_audit_token.is_some());
        // The test binary is (at most) ad-hoc signed by the linker, so a
        // Developer ID team requirement must refuse it.
        let team = "anchor apple generic and certificate leaf[subject.OU] = \"ZZZZZZZZZZ\"";
        assert!(matches!(
            verify_peer(&peer, team),
            Err(CodeSignError::Rejected(_))
        ));
        // Without an audit token there is nothing to pin: refused.
        let no_token = PeerInfo {
            macos_audit_token: None,
            ..peer
        };
        assert_eq!(
            verify_peer(&no_token, "anchor apple generic"),
            Err(CodeSignError::NoAuditToken)
        );
        // On Apple silicon every binary carries at least a linker ad-hoc
        // signature, which satisfies the trivial requirement: the lookup by
        // audit token itself works.
        #[cfg(target_arch = "aarch64")]
        verify_peer(&peer, "always").unwrap();
    }
}
