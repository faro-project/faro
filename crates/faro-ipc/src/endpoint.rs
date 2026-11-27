//! Where the service listens, per account, on every platform.
//!
//! The service binds one endpoint per monitored account (ARCHITECTURE.md
//! §3.1: every OS account is monitored, and each account's agent may talk
//! only to its own endpoint). The naming is the same everywhere, only the
//! account id and the kind of endpoint differ:
//!
//! | | Unix | Windows |
//! |---|---|---|
//! | [`AccountId`] | uid (`u32`) | [`Sid`](crate::Sid) |
//! | base | `/var/run/faro/agent.sock` | `\\.\pipe\faro\agent` |
//! | per account | `/var/run/faro/agent.501.sock` | `\\.\pipe\faro\agent.S-1-5-21-…-1001` |
//! | enroll ([`enroll_socket_path`](crate::enroll_socket_path)) | `enroll.501.sock` | `enroll.S-1-5-21-…-1001` |
//!
//! On Windows the "path" is a named-pipe name carried in a [`PathBuf`], so
//! the call sites in faro-service and faro-agent stay free of `cfg`s.
//! `\\.\pipe\` is a flat namespace: the `faro\` part is just characters of
//! the name (Windows' own `\\.\pipe\Winsock2\…` pipes do the same), not a
//! directory, so there is no directory to secure. The squatting protection
//! that the Unix transport gets from its directory checks comes from the
//! pipe's first-instance flag and DACL instead ([`crate::named_pipe`]).

use std::io;
use std::path::{Path, PathBuf};

/// How the OS names an account: a uid on Unix.
#[cfg(not(windows))]
pub type AccountId = u32;
/// How the OS names an account: a SID on Windows.
#[cfg(windows)]
pub type AccountId = crate::sid::Sid;

/// The account this process runs as (effective uid on Unix, the process
/// token's user SID on Windows).
#[cfg(unix)]
pub fn current_account() -> io::Result<AccountId> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    Ok(unsafe { libc::geteuid() })
}

/// The account this process runs as (effective uid on Unix, the process
/// token's user SID on Windows).
#[cfg(windows)]
pub fn current_account() -> io::Result<AccountId> {
    crate::named_pipe::current_user_sid()
}

/// The per-account endpoint a privileged service binds for `account`, next
/// to `base`: `agent.sock` becomes `agent.<uid>.sock`, and
/// `\\.\pipe\faro\agent` becomes `\\.\pipe\faro\agent.<SID>`.
///
/// Every OS account is monitored (ARCHITECTURE.md §3.1), so agents of
/// several users connect to one service. Rather than open one endpoint to
/// everyone, a root/LocalSystem service binds one per account that only that
/// account (and the system) can connect to; an agent connects to its own
/// ([`resolve_agent_socket`]). A development service running as the user
/// binds `base` itself.
pub fn session_socket_path(base: &Path, account: AccountId) -> PathBuf {
    let stem = base
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "agent".to_owned());
    let name = match base.extension() {
        Some(ext) => format!("{stem}.{account}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{account}"),
    };
    base.with_file_name(name)
}

/// Where an agent running as `account` should connect: its per-account
/// endpoint ([`session_socket_path`]) if the service has bound one, else
/// `base` (a development service running as the user).
///
/// This only picks a name. Who listens there is checked when connecting
/// (`IpcClient::connect_verified`), so an impostor that creates the
/// per-account name first gains nothing.
pub fn resolve_agent_socket(base: &Path, account: AccountId) -> PathBuf {
    let own = session_socket_path(base, account);
    if endpoint_exists(&own) {
        own
    } else {
        base.to_path_buf()
    }
}

/// Is something listening-shaped at `path`: a socket file on Unix, a pipe
/// with at least one instance on Windows.
pub(crate) fn endpoint_exists(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        matches!(std::fs::symlink_metadata(path), Ok(md) if md.file_type().is_socket())
    }
    #[cfg(windows)]
    {
        crate::named_pipe::pipe_exists(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
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

    #[cfg(windows)]
    #[test]
    fn per_account_pipe_names() {
        let sid: crate::Sid = "S-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(
            session_socket_path(Path::new(r"\\.\pipe\faro\agent"), sid),
            Path::new(r"\\.\pipe\faro\agent.S-1-5-21-1-2-3-1001")
        );
        // Nothing bound for the account: fall back to the base name.
        let base = Path::new(r"\\.\pipe\faro-nonexistent-test\agent");
        assert_eq!(resolve_agent_socket(base, sid), base);
    }

    #[test]
    fn current_account_is_available() {
        current_account().unwrap();
    }
}
