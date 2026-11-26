//! Authenticode verification (STUB: implemented by the service-side work).
//!
//! The Windows counterpart of macOS's code-signing requirement
//! (`ipc.agent_requirement`): the service checks that the process at the
//! other end of an agent pipe runs an image signed by Faro's publisher, and
//! the updater checks a downloaded MSI the same way.
//!
//! Contract (other modules and crates code against this; keep it):

use std::path::{Path, PathBuf};

/// What a signature must satisfy. `subject` is matched against the leaf
/// signing certificate's subject Common Name exactly (for example
/// `"Faro Project"`); `thumbprints`, when non-empty, pins the leaf
/// certificate's SHA-256 thumbprint (lowercase hex), any one of which matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRequirement {
    pub subject: String,
    pub thumbprints: Vec<String>,
}

impl SignerRequirement {
    /// Parse the `ipc.agent_requirement` text on Windows:
    /// `subject="Faro Project"` optionally followed by
    /// `; sha256=<hex>[,<hex>...]`.
    pub fn parse(text: &str) -> Result<Self, AuthenticodeError> {
        let _ = text;
        Err(AuthenticodeError::Os("not implemented".into()))
    }
}

/// The verified signer of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub subject: String,
    pub thumbprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticodeError {
    #[error("invalid requirement: {0}")]
    Requirement(String),
    #[error("file is not signed")]
    Unsigned,
    #[error("signature is not trusted: {0}")]
    Untrusted(String),
    #[error("signer does not satisfy the requirement: {0}")]
    WrongSigner(String),
    #[error("os error: {0}")]
    Os(String),
}

/// Verify `path`'s Authenticode signature chains to a trusted root (with
/// revocation checks off-line tolerant) and its signer satisfies `req`.
pub fn verify_file(path: &Path, req: &SignerRequirement) -> Result<SignerInfo, AuthenticodeError> {
    let _ = (path, req);
    Err(AuthenticodeError::Os("not implemented".into()))
}

/// The full image path of process `pid` (`QueryFullProcessImageNameW`).
pub fn process_image_path(pid: u32) -> std::io::Result<PathBuf> {
    let _ = pid;
    Err(std::io::Error::other("not implemented"))
}

/// Verify the image of running process `pid`. Implementations open the
/// process first and re-check it is still alive after verifying, so a pid
/// reused in between is not accepted.
pub fn verify_process(pid: u32, req: &SignerRequirement) -> Result<SignerInfo, AuthenticodeError> {
    let path = process_image_path(pid).map_err(|e| AuthenticodeError::Os(e.to_string()))?;
    verify_file(&path, req)
}
