//! File and directory ACLs (STUB: implemented by the service-side work).
//!
//! Contract:

use std::path::Path;

/// Give `dir` a protected (non-inherited) DACL granting full control to
/// SYSTEM and Administrators only, applied to it and inherited by children.
pub fn protect_state_dir(dir: &Path) -> std::io::Result<()> {
    let _ = dir;
    Err(std::io::Error::other("not implemented"))
}

/// Give a log directory SYSTEM full control and Administrators read.
pub fn protect_log_dir(dir: &Path) -> std::io::Result<()> {
    let _ = dir;
    Err(std::io::Error::other("not implemented"))
}

/// Whether `path`'s DACL grants write to anyone but SYSTEM, Administrators
/// or TrustedInstaller (a tamper check on Faro's own files).
pub fn writable_by_others(path: &Path) -> std::io::Result<bool> {
    let _ = path;
    Err(std::io::Error::other("not implemented"))
}

/// Whether the current process token is LocalSystem.
pub fn running_as_system() -> bool {
    false
}

/// Whether the current process token is an elevated administrator.
pub fn running_elevated() -> bool {
    false
}
