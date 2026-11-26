//! Foreground application and window title.
//!
//! * The foreground window: `GetForegroundWindow`. It is `NULL` while the
//!   secure desktop has the input or focus is changing; we then report no
//!   app rather than guess.
//! * Its process: `GetWindowThreadProcessId`, then
//!   `QueryFullProcessImageNameW` on a `PROCESS_QUERY_LIMITED_INFORMATION`
//!   handle, which a standard user may open for any process in the session
//!   (including elevated ones). Store apps' windows belong to
//!   `ApplicationFrameHost.exe`; the app itself owns a child window of the
//!   frame, and we report that process instead.
//! * [`AppInfo`]: `id` is the executable's file name in lowercase
//!   (`chrome.exe`, as `faro-proto` documents), `name` its version
//!   resource's `FileDescription` ("Google Chrome"), falling back to the
//!   file stem. Version resources are read from disk, so names are cached
//!   per executable path.
//! * The title: `GetWindowTextW`. For another process's window this reads
//!   the title the window manager keeps and sends no message, so a hung app
//!   can't block the agent. It needs no permission on Windows, unlike macOS.
//!   Titles are sensitive: they are never logged (`debug` at most, and not
//!   here) and never appear in `Debug` output of this type.
//! * The browser tab: for a supported browser, the address field through UI
//!   Automation, reduced to `scheme://host/` ([`crate::browser`]).
//!
//! The process's image path is also what Authenticode and the tamper checks
//! look at; [`process_image_path`] is shared with [`crate::tamper`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use faro_platform::{AppInfo, BrowserContext, ForegroundInfo};
use windows::core::{BOOL, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

use crate::browser::{self, Browser};

/// Longest title we read, in UTF-16 units. Real titles are far shorter;
/// a longer one is cut.
const MAX_TITLE: usize = 1024;

/// Executable names cached before the cache is cleared.
const NAME_CACHE_MAX: usize = 256;

/// Store apps' frame host.
const FRAME_HOST: &str = "applicationframehost.exe";

/// The full Win32 path of process `pid`'s image, if it can be opened.
pub fn process_image_path(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    // SAFETY: plain open; the handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` UTF-16 units; `len` is updated in place.
    let r = unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
    };
    // SAFETY: opened above, closed once.
    let _ = unsafe { CloseHandle(h) };
    r.ok()?;
    let s = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
    (!s.is_empty()).then(|| PathBuf::from(s))
}

/// `chrome.exe` from `C:\…\chrome.exe`, lowercased.
pub fn exe_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    (!name.is_empty()).then_some(name)
}

/// The window's owning process id.
pub fn window_pid(hwnd: HWND) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: valid out-pointer; a stale hwnd gives 0.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    (pid != 0).then_some(pid)
}

/// The foreground window, if any.
pub fn foreground_window() -> Option<HWND> {
    // SAFETY: no preconditions.
    let h = unsafe { GetForegroundWindow() };
    (!h.0.is_null()).then_some(h)
}

struct ChildSearch {
    frame_pid: u32,
    found: Option<u32>,
}

unsafe extern "system" fn find_app_child(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the `&mut ChildSearch` passed by `store_app_pid`,
    // alive for the duration of EnumChildWindows.
    let s = unsafe { &mut *(data.0 as *mut ChildSearch) };
    match window_pid(hwnd) {
        Some(pid) if pid != s.frame_pid => {
            s.found = Some(pid);
            false.into()
        }
        _ => true.into(),
    }
}

/// The Store app hosted in an `ApplicationFrameHost` window.
fn store_app_pid(frame: HWND, frame_pid: u32) -> Option<u32> {
    let mut s = ChildSearch {
        frame_pid,
        found: None,
    };
    // SAFETY: the callback only touches `s` through the LPARAM.
    let _ = unsafe {
        EnumChildWindows(
            Some(frame),
            Some(find_app_child),
            LPARAM(&mut s as *mut ChildSearch as isize),
        )
    };
    s.found
}

/// The process that the user sees as owning `hwnd`, and its image path.
pub fn window_process(hwnd: HWND) -> Option<(u32, PathBuf)> {
    let pid = window_pid(hwnd)?;
    let path = process_image_path(pid)?;
    if exe_id(&path).as_deref() == Some(FRAME_HOST) {
        if let Some(app) = store_app_pid(hwnd, pid) {
            if let Some(p) = process_image_path(app) {
                return Some((app, p));
            }
        }
    }
    Some((pid, path))
}

/// A window's title, trimmed; `None` if it has none.
pub fn window_text(hwnd: HWND) -> Option<String> {
    let mut buf = vec![0u16; MAX_TITLE + 1];
    // SAFETY: `buf` is a valid writable slice.
    let n = unsafe { GetWindowTextW(hwnd, &mut buf) };
    let n = usize::try_from(n).ok()?.min(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]);
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// The `FileDescription` in an executable's version resource.
pub fn file_description(path: &Path) -> Option<String> {
    let wide = HSTRING::from(path.as_os_str());
    // SAFETY: a NUL-terminated path.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), None) };
    if size == 0 || size > 16 * 1024 * 1024 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    // SAFETY: `data` is `size` bytes, as passed.
    unsafe { GetFileVersionInfoW(PCWSTR(wide.as_ptr()), None, size, data.as_mut_ptr().cast()) }
        .ok()?;
    let query = |sub: &str| -> Option<(*const u8, u32)> {
        let sub = HSTRING::from(sub);
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: `data` is a version block filled above; on success `ptr`
        // points into it for `len` units.
        let ok = unsafe {
            VerQueryValueW(
                data.as_ptr().cast(),
                PCWSTR(sub.as_ptr()),
                &mut ptr,
                &mut len,
            )
        };
        (ok.as_bool() && !ptr.is_null() && len > 0).then_some((ptr as *const u8, len))
    };
    let mut langs: Vec<(u16, u16)> = Vec::new();
    if let Some((p, bytes)) = query(r"\VarFileInfo\Translation") {
        for i in 0..(bytes as usize / 4) {
            // SAFETY: the translation table holds `bytes / 4` pairs of u16
            // inside `data`; read unaligned to be safe.
            let (lang, cp) = unsafe {
                (
                    (p.add(i * 4) as *const u16).read_unaligned(),
                    (p.add(i * 4 + 2) as *const u16).read_unaligned(),
                )
            };
            langs.push((lang, cp));
        }
    }
    langs.extend([(0x0409, 0x04b0), (0x0409, 0x04e4), (0x0000, 0x04b0)]);
    for (lang, cp) in langs {
        let key = format!(r"\StringFileInfo\{lang:04x}{cp:04x}\FileDescription");
        if let Some((p, units)) = query(&key) {
            // SAFETY: a string value of `units` UTF-16 units (including the
            // terminator) inside `data`.
            let s = unsafe { std::slice::from_raw_parts(p as *const u16, units as usize) };
            let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
            let text = String::from_utf16_lossy(&s[..end]);
            let text = text.trim();
            if !text.is_empty() {
                return Some(text.to_owned());
            }
        }
    }
    None
}

/// Display name for an app: its description, else the file stem.
pub(crate) fn display_name(description: Option<String>, path: &Path) -> Option<String> {
    description.filter(|d| !d.trim().is_empty()).or_else(|| {
        path.file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
    })
}

/// [`ForegroundInfo`] for Windows.
#[derive(Default)]
pub struct WinForeground {
    names: Mutex<HashMap<PathBuf, Option<String>>>,
}

impl std::fmt::Debug for WinForeground {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinForeground").finish_non_exhaustive()
    }
}

impl WinForeground {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process id of the foreground app, if any.
    pub fn foreground_pid(&self) -> Option<u32> {
        window_process(foreground_window()?).map(|(pid, _)| pid)
    }

    fn app_name(&self, path: &Path) -> Option<String> {
        let mut names = self.names.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = names.get(path) {
            return n.clone();
        }
        if names.len() >= NAME_CACHE_MAX {
            names.clear();
        }
        let n = display_name(file_description(path), path);
        names.insert(path.to_owned(), n.clone());
        n
    }
}

impl ForegroundInfo for WinForeground {
    fn active_app(&self) -> Option<AppInfo> {
        let (_, path) = window_process(foreground_window()?)?;
        let id = exe_id(&path)?;
        let name = self.app_name(&path);
        Some(AppInfo { id, name })
    }

    fn window_title(&self) -> Option<String> {
        window_text(foreground_window()?)
    }

    /// See [`crate::browser`].
    fn browser(&self) -> Option<BrowserContext> {
        let hwnd = foreground_window()?;
        let (_, path) = window_process(hwnd)?;
        let b = Browser::from_exe_name(&exe_id(&path)?)?;
        let url = browser::tab_url(hwnd, b)?;
        Some(BrowserContext {
            url: Some(url),
            title: None,
            incognito: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_ids_are_lowercase_file_names() {
        assert_eq!(
            exe_id(Path::new(
                r"C:\Program Files\Google\Chrome\Application\Chrome.EXE"
            ))
            .as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(exe_id(Path::new(r"C:\")), None);
    }

    #[test]
    fn display_name_falls_back_to_the_stem() {
        let p = Path::new(r"C:\Tools\viewer.exe");
        assert_eq!(
            display_name(Some("Viewer Pro".into()), p).as_deref(),
            Some("Viewer Pro")
        );
        assert_eq!(
            display_name(Some("  ".into()), p).as_deref(),
            Some("viewer")
        );
        assert_eq!(display_name(None, p).as_deref(), Some("viewer"));
    }

    #[test]
    fn own_process_resolves() {
        let path = process_image_path(std::process::id()).expect("own image path");
        assert!(path.is_absolute());
        assert!(exe_id(&path).unwrap().ends_with(".exe"));
        assert_eq!(process_image_path(0), None);
        // Pids are multiples of 4 on Windows; this one can't exist.
        assert_eq!(process_image_path(0xFFFF_FFF1), None);
    }

    #[test]
    fn system_binaries_have_descriptions() {
        let windir = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let notepad = Path::new(&windir).join("System32").join("notepad.exe");
        if notepad.exists() {
            let d = file_description(&notepad).expect("notepad has a version resource");
            assert!(!d.is_empty());
        }
        assert_eq!(file_description(Path::new(r"C:\no\such\file.exe")), None);
    }

    #[test]
    fn smoke_foreground_does_not_panic() {
        let fg = WinForeground::new();
        if let Some(app) = fg.active_app() {
            assert!(!app.id.is_empty());
            // Cached the second time; same answer.
            assert!(fg.active_app().is_some());
        }
        if let Some(t) = fg.window_title() {
            assert!(!t.trim().is_empty());
        }
        if let Some(b) = fg.browser() {
            // No values in messages: this may be a real tab.
            let url = b.url.expect("a browser context always has a URL");
            assert!(browser::reduce_url(&url).as_deref() == Some(url.as_str()));
            assert!(b.title.is_none() && !b.incognito);
        }
        assert!(!format!("{fg:?}").contains("names"));
    }
}
