//! `faro://` links: how the scheme is registered, and how a launched link
//! reaches the agent that is already running in the session.
//!
//! # Registration (the MSI's job)
//!
//! Per machine, under `HKEY_LOCAL_MACHINE`, so every account (including
//! accounts created later) gets it:
//!
//! ```text
//! HKLM\Software\Classes\faro
//!     (Default)      REG_SZ  "URL:Faro Protocol"          URL_SCHEME_DESCRIPTION
//!     URL Protocol   REG_SZ  ""                           URL_PROTOCOL_VALUE
//! HKLM\Software\Classes\faro\DefaultIcon
//!     (Default)      REG_SZ  "C:\Program Files\Faro\faro-agent.exe",0     URL_DEFAULT_ICON
//! HKLM\Software\Classes\faro\shell\open\command
//!     (Default)      REG_SZ  "C:\Program Files\Faro\faro-agent.exe" open-url "%1"   URL_OPEN_COMMAND
//! ```
//!
//! The constants below are the values; [`open_command`] builds the command
//! for another install directory. Browsers ask before they open an external
//! scheme, which is the person's first confirmation; Faro asks again.
//!
//! # Forwarding a link (`faro-agent.exe open-url <link>`)
//!
//! The shell starts a new `faro-agent.exe open-url "faro://…"` for each
//! link. That process must not start a second agent: it calls
//! [`forward_link`] and exits.
//!
//! 1. The running agent's UI holds the session-local mutex
//!    [`INSTANCE_MUTEX`] (`Local\` names are per session). No mutex: no
//!    agent UI in this session ([`ForwardError::NotRunning`]).
//! 2. It finds the agent's hidden window (class `FaroAgentUi`) among the
//!    session desktop's top-level windows, and accepts only a window owned
//!    by a process running the *same executable* as itself, so another
//!    program can't create a look-alike window to collect the link's
//!    one-time code. While the agent is still starting (the mutex exists,
//!    the window not yet), it waits up to the given time.
//! 3. It allows that process to take the foreground (it was started by a
//!    click, so it may), and sends the link as `WM_COPYDATA` (UTF-16, tagged
//!    [`COPYDATA_LINK`]). The agent checks it with [`is_faro_link`] and
//!    answers 1 if it took it; the enrollment flow then starts as from the
//!    menu, and still needs the person's confirmation and an
//!    administrator's approval.
//!
//! The agent never logs the link (it carries a one-time code).

use std::path::Path;
use std::time::{Duration, Instant};

use windows::core::{BOOL, HSTRING, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HWND, LPARAM, WPARAM,
};
use windows::Win32::System::DataExchange::COPYDATASTRUCT;
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
    REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentProcessId, OpenMutexW, OpenProcess,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    SYNCHRONIZATION_SYNCHRONIZE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AllowSetForegroundWindow, EnumWindows, GetClassNameW, GetWindowThreadProcessId,
    SendMessageTimeoutW, SMTO_ABORTIFHUNG, SMTO_BLOCK, WM_COPYDATA,
};

/// The agent's subcommand the scheme runs.
pub const OPEN_URL_COMMAND: &str = "open-url";
/// The scheme's key under `HKEY_LOCAL_MACHINE`.
pub const URL_SCHEME_KEY: &str = r"Software\Classes\faro";
/// The scheme key's default value.
pub const URL_SCHEME_DESCRIPTION: &str = "URL:Faro Protocol";
/// The empty value that marks the key as a URL scheme.
pub const URL_PROTOCOL_VALUE: &str = "URL Protocol";
/// `…\faro\DefaultIcon`'s default value.
pub const URL_DEFAULT_ICON: &str = r#""C:\Program Files\Faro\faro-agent.exe",0"#;
/// `…\faro\shell\open\command`'s default value.
pub const URL_OPEN_COMMAND: &str = r#""C:\Program Files\Faro\faro-agent.exe" open-url "%1""#;

/// Held by the agent UI of each session (`Local\` is per session).
pub const INSTANCE_MUTEX: &str = r"Local\FaroAgentUi";
/// `COPYDATASTRUCT::dwData` of a forwarded link ("FARO").
pub const COPYDATA_LINK: usize = 0x4641_524F;
/// The longest link accepted (as `faro_ipc::MAX_TARGET_LEN`).
pub const MAX_LINK_LEN: usize = 4096;
/// How long `open-url` waits for an agent that is still starting.
pub const FORWARD_WAIT: Duration = Duration::from_secs(15);

/// The open command for an agent installed at `agent_program`.
pub fn open_command(agent_program: &Path) -> String {
    format!("\"{}\" {OPEN_URL_COMMAND} \"%1\"", agent_program.display())
}

/// Whether `s` looks like a `faro:` link: the scheme (any case), bounded,
/// with no whitespace or control characters. The service parses and
/// checks it properly.
pub fn is_faro_link(s: &str) -> bool {
    s.len() <= MAX_LINK_LEN
        && s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("faro:"))
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Why a link couldn't be forwarded.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("that isn't a faro: link")]
    NotALink,
    #[error("Faro isn't running in this session")]
    NotRunning,
    #[error("Faro is starting but didn't answer in time")]
    NoWindow,
    #[error("Faro didn't accept the link")]
    Refused,
}

/// Forward `link` to the agent running in this session (see the module
/// docs), waiting up to `wait` for one that is still starting.
pub fn forward_link(link: &str, wait: Duration) -> Result<(), ForwardError> {
    if !is_faro_link(link) {
        return Err(ForwardError::NotALink);
    }
    // SAFETY: opening a named object by name; the handle is closed.
    match unsafe {
        OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            &HSTRING::from(INSTANCE_MUTEX),
        )
    } {
        // SAFETY: our own handle.
        Ok(h) => unsafe {
            let _ = CloseHandle(h);
        },
        Err(_) => return Err(ForwardError::NotRunning),
    }
    let deadline = Instant::now() + wait;
    let (hwnd, pid) = loop {
        if let Some(found) = find_agent_window() {
            break found;
        }
        if Instant::now() >= deadline {
            return Err(ForwardError::NoWindow);
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let units: Vec<u16> = link.encode_utf16().collect();
    let cds = COPYDATASTRUCT {
        dwData: COPYDATA_LINK,
        cbData: (units.len() * 2) as u32,
        lpData: units.as_ptr() as *mut _,
    };
    let mut answer = 0usize;
    // SAFETY: `cds` and `units` outlive the synchronous send; the system
    // copies the data into the receiver.
    let sent = unsafe {
        let _ = AllowSetForegroundWindow(pid);
        SendMessageTimeoutW(
            hwnd,
            WM_COPYDATA,
            WPARAM(0),
            LPARAM(&cds as *const COPYDATASTRUCT as isize),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            10_000,
            Some(&mut answer),
        )
    };
    if sent.0 != 0 && answer == 1 {
        Ok(())
    } else {
        Err(ForwardError::Refused)
    }
}

/// Take this session's instance mutex; `true` if no other UI had it. The
/// handle is kept open (leaked) for the life of the process.
pub(super) fn claim_instance() -> bool {
    // SAFETY: creating a named mutex; the handle is intentionally kept.
    unsafe {
        match CreateMutexW(None, false, &HSTRING::from(INSTANCE_MUTEX)) {
            Ok(_handle) => GetLastError() != ERROR_ALREADY_EXISTS,
            Err(e) => {
                tracing::warn!(error = %e, "could not create the session's instance mutex");
                true
            }
        }
    }
}

/// The full image path of a process (`None` if it can't be read).
fn image_of(pid: Option<u32>) -> Option<String> {
    // SAFETY: the handle is closed; the buffer is as long as the size
    // passed.
    unsafe {
        let (h, close) = match pid {
            Some(pid) => (
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?,
                true,
            ),
            None => (GetCurrentProcess(), false),
        };
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok =
            QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        if close {
            let _ = CloseHandle(h);
        }
        ok.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// The agent's window in this session: class `FaroAgentUi`, owned by
/// another process running the same executable as this one.
fn find_agent_window() -> Option<(HWND, u32)> {
    struct Search {
        me: u32,
        image: String,
        found: Option<(HWND, u32)>,
    }
    unsafe extern "system" fn each(hwnd: HWND, lp: LPARAM) -> BOOL {
        // SAFETY: `lp` is the `Search` passed to EnumWindows below.
        let s = unsafe { &mut *(lp.0 as *mut Search) };
        let mut class = [0u16; 64];
        // SAFETY: the buffer is ours.
        let n = unsafe { GetClassNameW(hwnd, &mut class) }.max(0) as usize;
        if String::from_utf16_lossy(&class[..n]) != "FaroAgentUi" {
            return true.into();
        }
        let mut pid = 0u32;
        // SAFETY: `pid` is ours.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == 0 || pid == s.me {
            return true.into();
        }
        let same = image_of(Some(pid)).is_some_and(|i| i.eq_ignore_ascii_case(&s.image));
        if !same {
            tracing::warn!(pid, "ignoring a Faro-like window from another program");
            return true.into();
        }
        s.found = Some((hwnd, pid));
        false.into()
    }
    let mut search = Search {
        // SAFETY: no preconditions.
        me: unsafe { GetCurrentProcessId() },
        image: image_of(None)?,
        found: None,
    };
    // SAFETY: `search` outlives the enumeration. EnumWindows "fails" when
    // the callback stops it early, which is how a match ends it.
    unsafe {
        let _ = EnumWindows(Some(each), LPARAM(&mut search as *mut Search as isize));
    }
    search.found
}

/// Register the scheme for the current account only
/// (`HKEY_CURRENT_USER\Software\Classes\faro`), to run `program open-url
/// "%1"`. For development builds and the `session_ui` example: the MSI
/// registers the packaged agent per machine, and a per-account entry
/// overrides it, so the packaged agent never calls this.
pub fn register_for_current_user(program: &Path) -> windows::core::Result<()> {
    let set = |key: HKEY, name: Option<&str>, value: &str| -> windows::core::Result<()> {
        let data: Vec<u8> = value
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let name = name.map(HSTRING::from);
        // SAFETY: `data` and `name` outlive the call.
        unsafe {
            RegSetValueExW(
                key,
                name.as_ref().map_or(windows::core::PCWSTR::null(), |n| {
                    windows::core::PCWSTR(n.as_ptr())
                }),
                None,
                REG_SZ,
                Some(&data),
            )
            .ok()
        }
    };
    let create = |sub: &str| -> windows::core::Result<HKEY> {
        let mut key = HKEY::default();
        // SAFETY: `key` is ours; closed by the caller.
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                &HSTRING::from(sub),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
            .ok()?;
        }
        Ok(key)
    };
    let close = |k: HKEY| {
        // SAFETY: a key we opened.
        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(k);
        }
    };
    let root = create(URL_SCHEME_KEY)?;
    let r = set(root, None, URL_SCHEME_DESCRIPTION).and(set(root, Some(URL_PROTOCOL_VALUE), ""));
    close(root);
    r?;
    let cmd = create(&format!(r"{URL_SCHEME_KEY}\shell\open\command"))?;
    let r = set(cmd, None, &open_command(program));
    close(cmd);
    r
}

/// Undo [`register_for_current_user`].
pub fn unregister_for_current_user() -> windows::core::Result<()> {
    // SAFETY: deleting our own per-account key.
    unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, &HSTRING::from(URL_SCHEME_KEY)).ok() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registered_command_is_the_packaged_agent() {
        assert_eq!(
            open_command(Path::new(crate::layout::AGENT_PROGRAM)),
            URL_OPEN_COMMAND
        );
        assert!(URL_DEFAULT_ICON.contains(crate::layout::AGENT_PROGRAM));
        assert!(URL_SCHEME_KEY.ends_with(crate::layout::URL_SCHEME));
    }

    #[test]
    fn only_faro_links_are_forwarded() {
        assert!(is_faro_link("faro://enroll?i=https%3A%2F%2Fx&c=AB-12"));
        assert!(is_faro_link("FARO://enroll"));
        assert!(!is_faro_link("https://faro.example.org"));
        assert!(!is_faro_link("faro://enroll?c=a b"));
        assert!(!is_faro_link("faro://enroll\n"));
        assert!(!is_faro_link(&format!(
            "faro://{}",
            "a".repeat(MAX_LINK_LEN)
        )));
        assert!(matches!(
            forward_link("https://x", Duration::ZERO),
            Err(ForwardError::NotALink)
        ));
    }

    #[test]
    fn this_process_has_an_image() {
        assert!(image_of(None).is_some_and(|p| p.to_ascii_lowercase().ends_with(".exe")));
    }
}
