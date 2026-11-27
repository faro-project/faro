//! Windows that hide themselves from screen capture (ARCHITECTURE.md §3.7).
//!
//! An app can exclude a window from capture (`NSWindow.sharingType =
//! .none`). Captures, Faro's included, then show whatever is behind that
//! window, so a viewer that did this would be rated clean while showing
//! anything. The window server reports each window's state in the window
//! list (`CGWindowListCopyWindowInfo`, `kCGWindowSharingState`, where `0`
//! is `kCGWindowSharingNone`). When a large window of an app hides itself,
//! the agent raises `window_hidden_from_capture`, a tamper signal naming the
//! app.
//!
//! # What is read, and what is never read
//!
//! For every on-screen window: owner pid, owner name, layer, alpha, size and
//! sharing state. For the owner of a hidden window: its bundle id, display
//! name and executable path. Never the window's title (`kCGWindowName`) or
//! anything drawn in it. The signal carries the app's display name only.
//!
//! # When the reading counts
//!
//! A process without Screen Recording permission reads `0` for every
//! window but its own (checked on macOS 27: its own windows read their real
//! state, the menu bar reads `1`, every other window reads `0`). So:
//!
//! * nothing is read while Screen Recording is missing (the permission
//!   itself is reported by `PermissionRevoked`);
//! * a poll in which normal windows of two or more other apps all read `0`
//!   is treated as unreliable and skipped ([`looks_unreliable`]). With the
//!   permission, ordinary windows read `1`; a permission that has just been
//!   granted to a running process can still read `0` until it restarts.
//!   The cost: someone running two apps whose every window is hidden, with
//!   no other window on screen, isn't reported by this check.
//!
//! # Which windows count
//!
//! A hidden window counts when it is on screen, not fully transparent, and
//! at least [`MIN_STRIP_SIDE`] points on its shorter side, so thin strips
//! (toolbars, menus, call controls, the borders some screen-sharing tools
//! draw) are left out. An app is reported when its counting hidden windows
//! add up to [`MIN_HIDDEN_AREA`] (200 × 200 points), on any window layer,
//! for [`FIRE_AFTER_POLLS`] polls in a row. Each app is reported once, and
//! again only after it has had no hidden window for [`REARM_AFTER_POLLS`]
//! polls.
//!
//! # What is allowed
//!
//! Only a short list of macOS's own programs, each named by its exact
//! executable path ([`OS_PROGRAMS`]: the lock screen, the password prompt,
//! the Touch ID prompt, the screenshot toolbar), and only when the running
//! process is also an Apple platform binary whose code-signing identifier
//! is the one listed ([`live`'s `is_platform_binary`]: the kernel's
//! `CS_PLATFORM_BINARY` flag plus a Security.framework check of
//! `anchor apple and identifier "…"` against the live process). Being under
//! `/System` is not enough: Apple ships interpreters there (the Ruby, Tcl
//! and Tk frameworks, `osascript`, Script Editor, Shortcuts, WebKit
//! helpers) that run the member's own code, and any such program could
//! hide a window. Each hides its windows only if code the member wrote
//! tells it to, so none is on the list. Faro's own process is skipped.
//!
//! The list is the minimum found by inspection of a stock macOS 27 install,
//! not by watching which processes hold capture-excluded windows (reading
//! other apps' windows needs Screen Recording, and the lock screen and
//! password prompts are hard to provoke from a test). A program that is
//! missing from it is reported by name rather than hidden, which allies
//! can judge; add one when a real case turns up.
//!
//! No third-party app is allowed. Password managers, DRM video players and
//! screen-sharing tools may hide windows; one large enough to count is
//! reported with the app's name so allies can judge. A third-party allowlist
//! would have to check each app's code signature (team id), since a bundle
//! id can be copied by anyone.

use std::collections::HashMap;

use faro_platform::TamperSignal;

/// `kCGWindowSharingNone`.
pub const SHARING_NONE: i64 = 0;
/// Hidden windows thinner than this (points) never count.
pub const MIN_STRIP_SIDE: f64 = 64.0;
/// Total hidden area (square points) at which an app is reported.
pub const MIN_HIDDEN_AREA: f64 = 200.0 * 200.0;
/// Polls in a row an app must hide windows before it is reported, so a
/// window that flashes past during a transition doesn't count.
pub const FIRE_AFTER_POLLS: u32 = 2;
/// Polls without a hidden window before an app can be reported again (five
/// minutes at the agent's 2 s poll).
pub const REARM_AFTER_POLLS: u32 = 150;
/// Longest app name the signal carries, in characters.
pub const MAX_APP_LABEL: usize = 64;

/// Normal application windows live on layer 0.
const NORMAL_WINDOW_LAYER: i64 = 0;

/// macOS's own programs that keep windows out of captures: exact
/// executable path and the code-signing identifier it must have.
pub const OS_PROGRAMS: &[(&str, &str)] = &[
    // The lock screen and login window.
    (
        "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
        "com.apple.loginwindow",
    ),
    // Administrator password and Touch ID prompts from the Security
    // framework.
    (
        "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent",
        "com.apple.SecurityAgent",
    ),
    // The Touch ID / Apple Watch prompt of LocalAuthentication (the
    // `coreauthd` daemon itself has no windows).
    (
        "/System/Library/PrivateFrameworks/LocalAuthenticationUI.framework/Versions/A/XPCServices/LocalAuthenticationRemoteService.xpc/Contents/MacOS/LocalAuthenticationRemoteService",
        "com.apple.LocalAuthenticationRemoteService",
    ),
    // The screenshot and screen recording toolbar.
    (
        "/System/Library/CoreServices/screencaptureui.app/Contents/MacOS/screencaptureui",
        "com.apple.screencaptureui",
    ),
];

/// One on-screen window, as the window list describes it. No title.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowInfo {
    pub pid: i32,
    pub layer: i64,
    pub sharing: i64,
    pub alpha: f64,
    pub width: f64,
    pub height: f64,
    /// `kCGWindowOwnerName`: the owning app's name.
    pub owner_name: Option<String>,
}

/// The process that owns a hidden window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Process {
    pub bundle_id: Option<String>,
    pub exe_path: Option<String>,
    /// Display name (`localizedName`).
    pub name: Option<String>,
    /// The running process is an Apple platform binary with the
    /// code-signing identifier [`OS_PROGRAMS`] lists for its path (only
    /// checked for processes at a listed path).
    pub platform_verified: bool,
}

/// An app with enough hidden window area this poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenApp {
    /// Stable identity: bundle id, else executable path, else pid.
    pub key: String,
    /// What the signal says.
    pub name: String,
}

/// One poll's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// The window list can't be trusted this poll (see module docs).
    Unknown,
    /// Apps hiding windows, front to back (possibly none).
    Hidden(Vec<HiddenApp>),
}

fn visible(w: &WindowInfo) -> bool {
    w.pid > 0 && w.alpha > 0.0 && w.width.min(w.height) >= MIN_STRIP_SIDE
}

/// Whether normal windows of two or more other processes all read "not
/// shared", which is what a reader without Screen Recording sees.
pub fn looks_unreliable(windows: &[WindowInfo], own_pid: i32) -> bool {
    let mut pids: Vec<i32> = Vec::new();
    for w in windows {
        if w.layer != NORMAL_WINDOW_LAYER || w.pid == own_pid || !visible(w) {
            continue;
        }
        if w.sharing != SHARING_NONE {
            return false;
        }
        if !pids.contains(&w.pid) {
            pids.push(w.pid);
        }
    }
    pids.len() >= 2
}

/// Whether `p` is one of macOS's own programs that may keep windows out of
/// captures (see module docs): at a listed path, exactly, and verified as
/// an Apple platform binary.
pub fn is_allowed_os_process(p: &Process) -> bool {
    p.platform_verified
        && p.exe_path
            .as_deref()
            .is_some_and(|path| OS_PROGRAMS.iter().any(|(listed, _)| *listed == path))
}

/// Control characters removed, trimmed, at most [`MAX_APP_LABEL`]
/// characters.
pub fn app_label(name: &str) -> String {
    let cut: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_APP_LABEL)
        .collect();
    cut.trim_end().to_owned()
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(app_label).filter(|s| !s.is_empty())
}

fn hidden_app(pid: i32, p: &Process, owner_name: Option<&str>) -> HiddenApp {
    let key = p
        .bundle_id
        .clone()
        .or_else(|| p.exe_path.clone())
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| format!("pid:{pid}"));
    let exe_name = p
        .exe_path
        .as_deref()
        .and_then(|e| e.rsplit('/').next())
        .filter(|s| !s.is_empty());
    let name = non_empty(p.name.as_deref())
        .or_else(|| non_empty(owner_name))
        .or_else(|| non_empty(p.bundle_id.as_deref()))
        .or_else(|| non_empty(exe_name))
        .unwrap_or_else(|| "An unnamed app".to_owned());
    HiddenApp { key, name }
}

/// Apps hiding enough window area in `windows` (front to back), skipping
/// `own_pid` and macOS's own processes. `resolve` is only called for pids
/// that own a counting hidden window.
pub fn read(
    windows: &[WindowInfo],
    own_pid: i32,
    mut resolve: impl FnMut(i32) -> Process,
) -> Reading {
    if looks_unreliable(windows, own_pid) {
        return Reading::Unknown;
    }
    // Hidden area per pid, in front-to-back order of first appearance.
    let mut per_pid: Vec<(i32, f64, Option<&str>)> = Vec::new();
    for w in windows {
        if w.sharing != SHARING_NONE || w.pid == own_pid || !visible(w) {
            continue;
        }
        let area = w.width * w.height;
        match per_pid.iter_mut().find(|(pid, _, _)| *pid == w.pid) {
            Some(entry) => entry.1 += area,
            None => per_pid.push((w.pid, area, w.owner_name.as_deref())),
        }
    }
    // Several processes of one app (same bundle id) add up.
    let mut per_app: Vec<(HiddenApp, f64)> = Vec::new();
    for (pid, area, owner_name) in per_pid {
        let p = resolve(pid);
        if is_allowed_os_process(&p) {
            continue;
        }
        let app = hidden_app(pid, &p, owner_name);
        match per_app.iter_mut().find(|(a, _)| a.key == app.key) {
            Some(entry) => entry.1 += area,
            None => per_app.push((app, area)),
        }
    }
    Reading::Hidden(
        per_app
            .into_iter()
            .filter(|(_, area)| *area >= MIN_HIDDEN_AREA)
            .map(|(app, _)| app)
            .collect(),
    )
}

#[derive(Debug)]
struct AppState {
    seen: u32,
    absent: u32,
    reported: bool,
}

/// Turns readings into edge-triggered signals (see module docs).
#[derive(Debug, Default)]
pub struct HiddenWindowTracker {
    apps: HashMap<String, AppState>,
}

impl HiddenWindowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one poll's reading. An unknown reading changes nothing.
    pub fn observe(&mut self, reading: &Reading) -> Vec<TamperSignal> {
        let Reading::Hidden(apps) = reading else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for app in apps {
            let s = self.apps.entry(app.key.clone()).or_insert(AppState {
                seen: 0,
                absent: 0,
                reported: false,
            });
            s.seen = s.seen.saturating_add(1);
            s.absent = 0;
            if !s.reported && s.seen >= FIRE_AFTER_POLLS {
                s.reported = true;
                out.push(TamperSignal::WindowHiddenFromCapture {
                    app: app.name.clone(),
                });
            }
        }
        self.apps.retain(|key, s| {
            if apps.iter().any(|a| &a.key == key) {
                return true;
            }
            s.seen = 0;
            s.absent = s.absent.saturating_add(1);
            s.reported && s.absent < REARM_AFTER_POLLS
        });
        out
    }
}

pub use live::{on_screen_windows, read_now, resolve_process};

mod live {
    use super::*;
    use objc2::rc::autoreleasepool;
    use objc2_app_kit::NSRunningApplication;
    use objc2_core_foundation::{CFDictionary, CFString};
    use objc2_core_graphics::{
        kCGNullWindowID, kCGWindowAlpha, kCGWindowBounds, kCGWindowLayer, kCGWindowOwnerName,
        kCGWindowOwnerPID, kCGWindowSharingState, CGWindowListCopyWindowInfo, CGWindowListOption,
    };
    use std::ffi::c_void;
    use std::ptr;

    use crate::cf;

    /// Every on-screen window, front to back. Titles are not read.
    pub fn on_screen_windows() -> Vec<WindowInfo> {
        let options =
            CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements;
        let Some(list) = CGWindowListCopyWindowInfo(options, kCGNullWindowID) else {
            return Vec::new();
        };
        // SAFETY: the key constants are immutable framework statics.
        let keys = unsafe {
            [
                kCGWindowOwnerPID,
                kCGWindowLayer,
                kCGWindowSharingState,
                kCGWindowAlpha,
                kCGWindowBounds,
                kCGWindowOwnerName,
            ]
        };
        let [pid_k, layer_k, sharing_k, alpha_k, bounds_k, owner_k] = keys.map(|k| k.to_string());
        cf::as_type_array(&list)
            .iter()
            .filter_map(|item| {
                let d = item.downcast::<CFDictionary>().ok()?;
                let d = cf::as_plist_dict(&d);
                let bounds = cf::get_dict(d, &bounds_k)?;
                let bounds = cf::as_plist_dict(&bounds);
                Some(WindowInfo {
                    pid: i32::try_from(cf::get_i64(d, &pid_k)?).ok()?,
                    layer: cf::get_i64(d, &layer_k)?,
                    // A window without the key is treated as shared.
                    sharing: cf::get_i64(d, &sharing_k).unwrap_or(1),
                    alpha: cf::get_f64(d, &alpha_k).unwrap_or(1.0),
                    width: cf::get_f64(bounds, "Width")?,
                    height: cf::get_f64(bounds, "Height")?,
                    owner_name: cf::get_string(d, &owner_k),
                })
            })
            .collect()
    }

    fn exe_path(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: `buf` is a writable buffer of the size passed.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        let n = usize::try_from(n)
            .ok()
            .filter(|&n| n > 0 && n <= buf.len())?;
        buf.truncate(n);
        String::from_utf8(buf).ok()
    }

    type CFTypeRef = *const c_void;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecGuestAttributePid: CFTypeRef;
        fn SecCodeCopyGuestWithAttributes(
            host: CFTypeRef,
            attributes: CFTypeRef,
            flags: u32,
            guest: *mut CFTypeRef,
        ) -> i32;
        fn SecRequirementCreateWithString(
            text: CFTypeRef,
            flags: u32,
            requirement: *mut CFTypeRef,
        ) -> i32;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
        fn CFNumberCreate(alloc: CFTypeRef, the_type: isize, value: *const c_void) -> CFTypeRef;
        fn CFDictionaryCreate(
            alloc: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            count: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFTypeRef;
        fn CFRelease(cf: CFTypeRef);
    }

    extern "C" {
        fn csops(pid: i32, ops: u32, useraddr: *mut c_void, usersize: usize) -> i32;
    }

    const CS_OPS_STATUS: u32 = 0;
    /// `CS_PLATFORM_BINARY`: the kernel treats the code as part of the OS.
    const CS_PLATFORM_BINARY: u32 = 0x0400_0000;
    const K_CF_NUMBER_SINT32_TYPE: isize = 3;

    /// Whether `pid` is a platform binary (kernel flag) whose code
    /// satisfies `anchor apple and identifier "<identifier>"` (checked by
    /// Security.framework against the live process, so a copy of the file
    /// elsewhere, or a process that merely claims the bundle id, fails).
    pub fn is_platform_binary(pid: i32, identifier: &str) -> bool {
        let mut flags: u32 = 0;
        // SAFETY: `flags` is a writable u32 and the size passed is 4.
        let rc = unsafe { csops(pid, CS_OPS_STATUS, (&raw mut flags).cast(), 4) };
        if rc != 0 || flags & CS_PLATFORM_BINARY == 0 {
            return false;
        }
        if identifier.contains(['"', '\\']) {
            return false;
        }
        let text = CFString::from_str(&format!("anchor apple and identifier \"{identifier}\""));
        let mut req: CFTypeRef = ptr::null();
        // SAFETY: `text` is a valid CFString; `req` receives a +1 reference.
        let status = unsafe {
            SecRequirementCreateWithString((&*text as *const CFString).cast(), 0, &mut req)
        };
        if status != 0 || req.is_null() {
            return false;
        }
        let mut ok = false;
        // SAFETY: every object created below is released before returning;
        // the key and callbacks are immutable framework statics.
        unsafe {
            let num = CFNumberCreate(
                ptr::null(),
                K_CF_NUMBER_SINT32_TYPE,
                (&raw const pid).cast(),
            );
            if !num.is_null() {
                let keys = [kSecGuestAttributePid];
                let values = [num];
                let attrs = CFDictionaryCreate(
                    ptr::null(),
                    keys.as_ptr(),
                    values.as_ptr(),
                    1,
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                );
                if !attrs.is_null() {
                    let mut code: CFTypeRef = ptr::null();
                    if SecCodeCopyGuestWithAttributes(ptr::null(), attrs, 0, &mut code) == 0
                        && !code.is_null()
                    {
                        ok = SecCodeCheckValidity(code, 0, req) == 0;
                        CFRelease(code);
                    }
                    CFRelease(attrs);
                }
                CFRelease(num);
            }
            CFRelease(req);
        }
        ok
    }

    /// Bundle id, display name and executable path of `pid`, and whether it
    /// is a verified Apple platform binary (only checked at a listed path).
    /// Must run in an autorelease pool.
    pub fn resolve_process(pid: i32) -> Process {
        let app = NSRunningApplication::runningApplicationWithProcessIdentifier(pid);
        let exe_path = exe_path(pid);
        let platform_verified = exe_path.as_deref().is_some_and(|path| {
            OS_PROGRAMS
                .iter()
                .find(|(listed, _)| *listed == path)
                .is_some_and(|(_, id)| is_platform_binary(pid, id))
        });
        Process {
            platform_verified,
            bundle_id: app
                .as_ref()
                .and_then(|a| a.bundleIdentifier())
                .map(|s| s.to_string()),
            name: app
                .as_ref()
                .and_then(|a| a.localizedName())
                .map(|s| s.to_string()),
            exe_path,
        }
    }

    /// One live reading, skipping this process's own windows. The caller
    /// checks Screen Recording first (see module docs).
    pub fn read_now() -> Reading {
        let own = std::process::id() as i32;
        autoreleasepool(|_| read(&on_screen_windows(), own, resolve_process))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: i32 = 1;

    fn win(pid: i32, sharing: i64, w: f64, h: f64) -> WindowInfo {
        WindowInfo {
            pid,
            layer: 0,
            sharing,
            alpha: 1.0,
            width: w,
            height: h,
            owner_name: Some(format!("Owner {pid}")),
        }
    }

    fn third_party(pid: i32) -> Process {
        Process {
            bundle_id: Some(format!("com.example.app{pid}")),
            exe_path: Some(format!(
                "/Applications/App{pid}.app/Contents/MacOS/App{pid}"
            )),
            name: Some(format!("App {pid}")),
            platform_verified: false,
        }
    }

    fn os(bundle: &str, path: &str) -> Process {
        Process {
            bundle_id: Some(bundle.into()),
            exe_path: Some(path.into()),
            name: Some("System thing".into()),
            platform_verified: true,
        }
    }

    fn names(r: &Reading) -> Vec<String> {
        match r {
            Reading::Hidden(a) => a.iter().map(|a| a.name.clone()).collect(),
            Reading::Unknown => panic!("unexpected unknown reading"),
        }
    }

    #[test]
    fn large_hidden_window_of_an_app_is_found() {
        let ws = [win(10, 1, 800.0, 600.0), win(20, 0, 800.0, 600.0)];
        assert_eq!(names(&read(&ws, ME, third_party)), ["App 20"]);
    }

    #[test]
    fn shared_windows_strips_and_transparent_windows_dont_count() {
        let mut clear = win(30, 0, 800.0, 600.0);
        clear.alpha = 0.0;
        let ws = [
            win(10, 1, 800.0, 600.0),
            win(20, 2, 800.0, 600.0),
            // A 1000 x 50 toolbar: thin strip.
            win(40, 0, 1000.0, 50.0),
            clear,
            // Too small in total: 150 x 150.
            win(50, 0, 150.0, 150.0),
        ];
        assert_eq!(names(&read(&ws, ME, third_party)), Vec::<String>::new());
    }

    #[test]
    fn small_hidden_windows_add_up() {
        // Four 150 x 150 tiles: 90 000 square points.
        let ws = [
            win(10, 1, 800.0, 600.0),
            win(20, 0, 150.0, 150.0),
            win(20, 0, 150.0, 150.0),
            win(20, 0, 150.0, 150.0),
            win(20, 0, 150.0, 150.0),
        ];
        assert_eq!(names(&read(&ws, ME, third_party)), ["App 20"]);
    }

    #[test]
    fn processes_of_one_app_add_up() {
        let ws = [
            win(10, 1, 800.0, 600.0),
            win(20, 0, 150.0, 150.0),
            win(21, 0, 150.0, 150.0),
        ];
        let same = |_| third_party(20);
        assert_eq!(names(&read(&ws, ME, same)), ["App 20"]);
    }

    #[test]
    fn floating_layers_count() {
        let mut panel = win(20, 0, 800.0, 600.0);
        panel.layer = 3;
        let ws = [win(10, 1, 800.0, 600.0), panel];
        assert_eq!(names(&read(&ws, ME, third_party)), ["App 20"]);
    }

    #[test]
    fn own_windows_are_skipped() {
        let ws = [win(10, 1, 800.0, 600.0), win(ME, 0, 800.0, 600.0)];
        assert_eq!(names(&read(&ws, ME, third_party)), Vec::<String>::new());
    }

    #[test]
    fn resolve_is_only_called_for_hidden_owners() {
        let ws = [
            win(10, 1, 800.0, 600.0),
            win(20, 0, 800.0, 600.0),
            win(20, 0, 800.0, 600.0),
        ];
        let mut asked = Vec::new();
        let _ = read(&ws, ME, |pid| {
            asked.push(pid);
            third_party(pid)
        });
        assert_eq!(asked, [20]);
    }

    #[test]
    fn everything_unshared_is_unreliable() {
        // What a reader without Screen Recording sees.
        let ws = [
            win(10, 0, 800.0, 600.0),
            win(20, 0, 800.0, 600.0),
            win(ME, 1, 300.0, 200.0),
        ];
        assert!(looks_unreliable(&ws, ME));
        assert_eq!(read(&ws, ME, third_party), Reading::Unknown);
    }

    #[test]
    fn one_app_alone_hiding_everything_is_still_reported() {
        // The plain way around Faro: a full-screen hidden viewer and
        // nothing else on screen.
        let mut menu_bar = win(5, 1, 1710.0, 34.0);
        menu_bar.layer = 24;
        let ws = [
            menu_bar,
            win(20, 0, 1710.0, 1000.0),
            win(20, 0, 400.0, 300.0),
        ];
        assert_eq!(names(&read(&ws, ME, third_party)), ["App 20"]);
    }

    #[test]
    fn listed_os_programs_are_allowed() {
        for (path, id) in OS_PROGRAMS {
            let p = os(id, path);
            assert!(is_allowed_os_process(&p), "{p:?}");
        }
        let ws = [win(10, 1, 800.0, 600.0), win(20, 0, 800.0, 600.0)];
        let (path, id) = OS_PROGRAMS[0];
        let lock = |_| os(id, path);
        assert_eq!(names(&read(&ws, ME, lock)), Vec::<String>::new());
    }

    #[test]
    fn a_listed_path_without_platform_proof_is_refused() {
        for (path, id) in OS_PROGRAMS {
            let mut p = os(id, path);
            p.platform_verified = false;
            assert!(!is_allowed_os_process(&p), "{p:?}");
        }
    }

    #[test]
    fn apple_shipped_interpreters_and_other_system_paths_are_refused() {
        for path in [
            // Frameworks that carry interpreters.
            "/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/ruby",
            "/System/Library/Frameworks/Tcl.framework/Versions/8.5/tclsh8.5",
            "/System/Library/Frameworks/Tk.framework/Versions/8.5/Resources/Wish.app/Contents/MacOS/Wish",
            "/System/Library/Frameworks/Python.framework/Versions/2.7/bin/python2.7",
            "/System/Library/Frameworks/Python.framework/Versions/Current/Resources/Python.app/Contents/MacOS/Python",
            "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc",
            "/System/Library/Frameworks/OSAKit.framework/Versions/A/XPCServices/OSAKitUIHelper.xpc/Contents/MacOS/OSAKitUIHelper",
            "/System/Library/CoreServices/Applications/Directory Utility.app/Contents/MacOS/Directory Utility",
            "/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
            "/System/Applications/Automator.app/Contents/MacOS/Automator",
            "/System/Applications/Shortcuts.app/Contents/MacOS/Shortcuts",
            "/System/Library/CoreServices/Applications/Wish.app/Contents/MacOS/Wish",
            "/System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/runner",
            "/System/Library/CoreServices/System Events.app/Contents/MacOS/System Events",
            // Browsers (Safari lives in a system cryptex).
            "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari",
            "/System/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari",
            // Outside the allowed folders, or not exact.
            "/usr/bin/osascript",
            "/usr/bin/ruby",
            "/usr/bin/python3",
            "/usr/libexec/some-helper",
            "/usr/local/libexec/x",
            "/System/Volumes/Data/Users/alex/x",
            "/System/../Users/alex/x",
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow/../x",
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow2",
            "/Users/alex/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "/Applications/Viewer.app/Contents/MacOS/Viewer",
        ] {
            // Even carrying every claim a process can make about itself.
            let p = os("com.apple.loginwindow", path);
            assert!(!is_allowed_os_process(&p), "{p:?}");
            let p = os("", path);
            assert!(!is_allowed_os_process(&p), "{p:?}");
        }
        assert!(!is_allowed_os_process(&Process::default()));
        let mut no_path = os("com.apple.loginwindow", "");
        no_path.exe_path = None;
        assert!(!is_allowed_os_process(&no_path));
    }

    #[test]
    fn the_list_is_exact_system_paths() {
        for (path, id) in OS_PROGRAMS {
            assert!(
                path.starts_with("/System/") && !path.contains(".."),
                "{path}"
            );
            assert!(id.starts_with("com.apple."), "{id}");
        }
    }

    /// Needs a logged-in session (loginwindow runs in every one, including
    /// the GUI CI runners); skipped when `pgrep` finds none.
    #[test]
    fn live_platform_check_accepts_loginwindow_and_refuses_the_rest() {
        let out = std::process::Command::new("/usr/bin/pgrep")
            .args(["-x", "loginwindow"])
            .output();
        let pid = out.ok().and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()?
                .lines()
                .next()?
                .trim()
                .parse::<i32>()
                .ok()
        });
        if let Some(pid) = pid {
            let (path, id) = OS_PROGRAMS[0];
            assert!(live::is_platform_binary(pid, id));
            assert!(!live::is_platform_binary(pid, "com.apple.screencaptureui"));
            assert_eq!(live::resolve_process(pid).exe_path.as_deref(), Some(path));
        }
        // This test process is not an Apple program.
        let me = std::process::id() as i32;
        assert!(!live::is_platform_binary(me, "com.apple.loginwindow"));
        assert!(!live::resolve_process(me).platform_verified);
    }

    #[test]
    fn names_fall_back_and_are_cleaned() {
        let p = Process {
            bundle_id: Some("org.example.v".into()),
            exe_path: None,
            name: Some("  Viewer\u{7}\n".into()),
            ..Process::default()
        };
        assert_eq!(hidden_app(9, &p, None).name, "Viewer");
        assert_eq!(hidden_app(9, &p, None).key, "org.example.v");
        let p = Process {
            bundle_id: None,
            exe_path: Some("/Users/a/bin/viewer".into()),
            name: None,
            ..Process::default()
        };
        assert_eq!(hidden_app(9, &p, Some("")).name, "viewer");
        assert_eq!(hidden_app(9, &p, None).key, "/Users/a/bin/viewer");
        let a = hidden_app(9, &Process::default(), None);
        assert_eq!(
            (a.key.as_str(), a.name.as_str()),
            ("pid:9", "An unnamed app")
        );
        assert_eq!(app_label(&"x".repeat(200)).chars().count(), MAX_APP_LABEL);
    }

    fn hidden(names: &[&str]) -> Reading {
        Reading::Hidden(
            names
                .iter()
                .map(|n| HiddenApp {
                    key: n.to_string(),
                    name: n.to_string(),
                })
                .collect(),
        )
    }

    fn signal(app: &str) -> TamperSignal {
        TamperSignal::WindowHiddenFromCapture { app: app.into() }
    }

    #[test]
    fn reported_once_after_two_polls() {
        let mut t = HiddenWindowTracker::new();
        assert!(
            t.observe(&hidden(&["V"])).is_empty(),
            "one poll is not enough"
        );
        assert_eq!(t.observe(&hidden(&["V"])), [signal("V")]);
        for _ in 0..100 {
            assert!(t.observe(&hidden(&["V"])).is_empty(), "not every poll");
        }
    }

    #[test]
    fn a_flash_never_fires() {
        let mut t = HiddenWindowTracker::new();
        for _ in 0..10 {
            assert!(t.observe(&hidden(&["V"])).is_empty());
            assert!(t.observe(&hidden(&[])).is_empty());
        }
    }

    #[test]
    fn rearms_only_after_a_long_absence() {
        let mut t = HiddenWindowTracker::new();
        t.observe(&hidden(&["V"]));
        assert_eq!(t.observe(&hidden(&["V"])), [signal("V")]);
        for _ in 0..REARM_AFTER_POLLS - 1 {
            assert!(t.observe(&hidden(&[])).is_empty());
        }
        // Back before the re-arm: still silent.
        t.observe(&hidden(&["V"]));
        assert!(t.observe(&hidden(&["V"])).is_empty());
        for _ in 0..REARM_AFTER_POLLS {
            assert!(t.observe(&hidden(&[])).is_empty());
        }
        t.observe(&hidden(&["V"]));
        assert_eq!(t.observe(&hidden(&["V"])), [signal("V")]);
    }

    #[test]
    fn unknown_readings_change_nothing() {
        let mut t = HiddenWindowTracker::new();
        t.observe(&hidden(&["V"]));
        assert!(t.observe(&Reading::Unknown).is_empty());
        assert_eq!(t.observe(&hidden(&["V"])), [signal("V")]);
    }

    #[test]
    fn apps_are_tracked_separately() {
        let mut t = HiddenWindowTracker::new();
        t.observe(&hidden(&["A"]));
        assert_eq!(t.observe(&hidden(&["A", "B"])), [signal("A")]);
        assert_eq!(t.observe(&hidden(&["B"])), [signal("B")]);
    }
}
