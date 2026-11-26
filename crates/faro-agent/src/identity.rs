//! Who and when: the session identity sent in `Hello`, and the monotonic
//! clock stamped on captures.

/// `uid:<uid>` for the current (real) uid.
///
/// The agent runs as the session user, so its uid identifies the session on
/// macOS (one GUI session per user) and matches the ids
/// `MacServiceHost::list_sessions` produces. The service does not have to
/// take this on faith: it also sees the kernel's peer uid on the socket.
#[cfg(unix)]
pub fn default_session_id() -> String {
    format!("uid:{}", current_uid())
}

/// `wts:<WTS session id>` on Windows, exactly the form
/// `faro_platform_windows::service::session_id` gives the service's session listing (the service also sees
/// the pipe client's session and SID itself).
#[cfg(windows)]
pub fn default_session_id() -> String {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    let mut id = 0u32;
    // SAFETY: `id` is a valid out-pointer.
    match unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) } {
        Ok(()) => faro_platform_windows::service::session_id(id).0,
        Err(_) => "unknown".to_owned(),
    }
}

#[cfg(not(any(unix, windows)))]
pub fn default_session_id() -> String {
    "unknown".to_owned()
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The login name of the current user, from the user database.
///
/// Falls back to `uid:<uid>` if the account has no passwd entry (possible
/// with some directory services) or a non-UTF-8 name, so `Hello` is always
/// well-formed; the service keys sessions on the uid it sees anyway.
#[cfg(unix)]
pub fn login_name() -> String {
    passwd_name(current_uid()).unwrap_or_else(default_session_id)
}

#[cfg(not(unix))]
pub fn login_name() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(unix)]
fn passwd_name(uid: u32) -> Option<String> {
    use std::ffi::CStr;

    // Start with a typical size and grow on ERANGE, bounded so a broken
    // directory service cannot make us allocate without limit.
    const MAX_BUF: usize = 1 << 16;
    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: an all-zero passwd is a valid value for an out-parameter
        // (it is plain data: integers and null pointers).
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the duration of the call and
        // `buf.len()` is the true size of `buf`. getpwuid_r writes only into
        // `pwd`, `buf` and `result`.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < MAX_BUF {
            let grown = buf.len() * 2;
            buf.resize(grown, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
            return None;
        }
        // SAFETY: on success pw_name points to a NUL-terminated string inside
        // `buf`, which is alive until the end of this function.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) };
        return name
            .to_str()
            .ok()
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
    }
}

/// Monotonic milliseconds since boot, for `Frames::captured_at_mono_ms`.
///
/// Uses exactly the clock `faro_core::clock::SystemClock` reads (macOS
/// `CLOCK_MONOTONIC_RAW`, Linux `CLOCK_BOOTTIME`, else `CLOCK_MONOTONIC`)
/// so the service can compare the agent's stamps with its own. It is
/// duplicated rather than imported because `faro-core` links SQLite and the
/// crypto stack, neither of which belongs in the unprivileged agent.
///
/// Returns `None` only if the OS refuses to read the clock.
#[cfg(unix)]
pub fn mono_ms() -> Option<u64> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let id = libc::CLOCK_MONOTONIC_RAW;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let id = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android"
    )))]
    let id = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec and `id` is a clock
    // supported on this target; clock_gettime only writes into `ts`.
    if unsafe { libc::clock_gettime(id, &mut ts) } != 0 {
        return None;
    }
    let secs = u64::try_from(ts.tv_sec).ok()?;
    let nanos = u64::try_from(ts.tv_nsec).ok()?;
    secs.checked_mul(1000)?.checked_add(nanos / 1_000_000)
}

/// Windows: `GetTickCount64`, milliseconds since boot, sleep included (the
/// interrupt-time counter), so a stamp stays comparable across a suspend.
///
/// NOTE: `faro_core::clock::SystemClock` currently reads `Instant` since
/// *process* start on Windows, which is not this clock. The service only
/// compares the agent's stamps with each other today; if it ever needs to
/// compare them with its own clock, `SystemClock` must read this one.
#[cfg(windows)]
pub fn mono_ms() -> Option<u64> {
    // SAFETY: no preconditions.
    Some(unsafe { windows::Win32::System::SystemInformation::GetTickCount64() })
}

#[cfg(not(any(unix, windows)))]
pub fn mono_ms() -> Option<u64> {
    None
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn session_and_user_are_well_formed() {
        assert!(default_session_id().starts_with(if cfg!(windows) { "wts:" } else { "uid:" }));
        let user = login_name();
        assert!(!user.is_empty());
        assert!(user.len() <= faro_ipc::handshake::MAX_HELLO_FIELD_LEN);
    }

    #[test]
    fn mono_is_monotonic() {
        let a = mono_ms().unwrap();
        let b = mono_ms().unwrap();
        assert!(b >= a);
        assert!(a > 0);
    }
}
