//! Frontmost application and focused window title.
//!
//! # Why not just `NSWorkspace.frontmostApplication`?
//!
//! `NSWorkspace` caches the frontmost application and refreshes it from
//! notifications delivered on the **main** run loop. The session agent is a
//! background process whose capture loop runs on worker threads, and a
//! spike on macOS 27 confirmed that, off the main run loop, the property
//! keeps returning whichever app was frontmost at first use, indefinitely.
//! That would silently attribute hours of activity to the wrong app.
//!
//! Instead we query sources that are answered fresh on every call:
//!
//! 1. the on-screen window list (`CGWindowListCopyWindowInfo`, front to
//!    back), whose normal-layer owners are the likely frontmost apps;
//! 2. for each candidate pid, a *newly created* `NSRunningApplication`, whose
//!    `isActive` is read from LaunchServices at creation time;
//! 3. if no window owner is active (an app with no windows, such as Finder
//!    with all windows closed), the same fresh `isActive` check over
//!    `NSWorkspace.runningApplications`.
//!
//! When nothing reports itself active (for example during a fast user
//! switch) we return `None` rather than guess.
//!
//! The window list's owner pid and layer do not require Screen Recording
//! permission (only window *names* do), so this works before onboarding
//! finishes.
//!
//! # Window titles
//!
//! Read through the Accessibility API (`AXFocusedWindow` → `AXTitle`) only
//! when the member has granted Accessibility (`AXIsProcessTrusted`), which is
//! optional (§3.3). Each AX call is bounded by a short messaging timeout so a
//! hung app cannot stall the agent. Any app picks its own title, so it is
//! cut to [`MAX_TITLE_CHARS`] (the Windows agent's limit).
//!
//! # Browser tabs
//!
//! With the same permission, the active tab's URL in Safari, Chrome, Edge,
//! Brave and Arc, reduced to its scheme and host. See [`crate::browser`].
//!
//! # Autorelease pools
//!
//! AppKit returns many objects autoreleased (`runningApplications`,
//! `bundleIdentifier`, `localizedName`, ...). The agent calls these from a
//! long-lived worker thread that has no `NSAutoreleasePool` of its own, so
//! without an explicit pool every call's temporaries would accumulate in the
//! thread's implicit pool until the thread exits — measured at ~600 bytes
//! per `active_app()` call, i.e. tens of MB per day at the agent's tick
//! rate. Every public entry point therefore runs inside
//! [`autoreleasepool`], which drains those objects before returning (the
//! values we return are plain Rust data).

use faro_platform::{AppInfo, BrowserContext, ForegroundInfo};
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSRunningApplication, NSWorkspace};
use objc2_application_services::{AXError, AXIsProcessTrusted, AXUIElement};
use objc2_core_foundation::{CFRetained, CFString, CFType};
use objc2_core_graphics::{
    kCGNullWindowID, kCGWindowLayer, kCGWindowOwnerPID, CGWindowListCopyWindowInfo,
    CGWindowListOption,
};
use std::ptr::NonNull;

use crate::browser::{self, Browser};
use crate::cf;

/// How long one Accessibility request may block, in seconds.
pub(crate) const AX_TIMEOUT_SECS: f32 = 0.25;

/// Normal application windows live on layer 0; menus, the Dock, overlays and
/// the menu bar live above it.
const NORMAL_WINDOW_LAYER: i64 = 0;

/// Whether this process has Accessibility permission. Never prompts.
pub fn accessibility_trusted() -> bool {
    // SAFETY: AXIsProcessTrusted takes no arguments and has no preconditions.
    unsafe { AXIsProcessTrusted() }
}

/// [`ForegroundInfo`] for macOS. Stateless; every call queries the OS.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacForeground;

impl MacForeground {
    pub fn new() -> Self {
        MacForeground
    }

    /// Process id of the frontmost (active) application, if any.
    pub fn frontmost_pid(&self) -> Option<i32> {
        autoreleasepool(|_| frontmost_pid_now())
    }
}

/// See [`MacForeground::frontmost_pid`]. Must run inside an autorelease
/// pool (see the module docs).
fn frontmost_pid_now() -> Option<i32> {
    let candidates = layer0_owner_pids(&on_screen_windows());
    if let Some(pid) = pick_frontmost(&candidates, is_active_now) {
        return Some(pid);
    }
    let all: Vec<i32> = NSWorkspace::sharedWorkspace()
        .runningApplications()
        .iter()
        .map(|a| a.processIdentifier())
        .collect();
    pick_frontmost(&all, is_active_now)
}

/// See [`ForegroundInfo::active_app`]. Must run inside an autorelease pool.
fn active_app_now() -> Option<AppInfo> {
    let pid = frontmost_pid_now()?;
    let app = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)?;
    let id = app
        .bundleIdentifier()
        .map(|s| s.to_string())
        .or_else(|| {
            app.executableURL()
                .and_then(|u| u.lastPathComponent())
                .map(|s| s.to_string())
        })
        .filter(|s| !s.is_empty())?;
    let name = app
        .localizedName()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    Some(AppInfo { id, name })
}

impl ForegroundInfo for MacForeground {
    fn active_app(&self) -> Option<AppInfo> {
        autoreleasepool(|_| active_app_now())
    }

    fn window_title(&self) -> Option<String> {
        autoreleasepool(|_| {
            if !accessibility_trusted() {
                return None;
            }
            focused_window_title(frontmost_pid_now()?)
        })
    }

    /// See [`crate::browser`].
    fn browser(&self) -> Option<BrowserContext> {
        autoreleasepool(|_| {
            if !accessibility_trusted() {
                return None;
            }
            let pid = frontmost_pid_now()?;
            let app = NSRunningApplication::runningApplicationWithProcessIdentifier(pid)?;
            let browser = Browser::from_bundle_id(&app.bundleIdentifier()?.to_string())?;
            let url = browser::tab_url_now(pid, browser)?;
            Some(BrowserContext {
                url: Some(url),
                title: None,
                incognito: false,
            })
        })
    }
}

/// `isActive` on a freshly created `NSRunningApplication` (see module docs).
fn is_active_now(pid: i32) -> bool {
    NSRunningApplication::runningApplicationWithProcessIdentifier(pid).is_some_and(|a| a.isActive())
}

/// `(layer, owner pid)` for each on-screen window, front to back.
fn on_screen_windows() -> Vec<(i64, i32)> {
    let options =
        CGWindowListOption::OptionOnScreenOnly | CGWindowListOption::ExcludeDesktopElements;
    let Some(list) = CGWindowListCopyWindowInfo(options, kCGNullWindowID) else {
        return Vec::new();
    };
    // SAFETY: the key constants are immutable framework statics.
    let (layer_key, pid_key) = unsafe { (kCGWindowLayer, kCGWindowOwnerPID) };
    let (layer_key, pid_key) = (layer_key.to_string(), pid_key.to_string());
    cf::as_type_array(&list)
        .iter()
        .filter_map(|item| {
            let d = item
                .downcast::<objc2_core_foundation::CFDictionary>()
                .ok()?;
            let d = cf::as_plist_dict(&d);
            let layer = cf::get_i64(d, &layer_key)?;
            let pid = i32::try_from(cf::get_i64(d, &pid_key)?).ok()?;
            Some((layer, pid))
        })
        .collect()
}

/// Owners of normal-layer windows in front-to-back order, deduplicated,
/// ignoring invalid pids.
pub(crate) fn layer0_owner_pids(windows: &[(i64, i32)]) -> Vec<i32> {
    let mut out: Vec<i32> = Vec::new();
    for &(layer, pid) in windows {
        if layer == NORMAL_WINDOW_LAYER && pid > 0 && !out.contains(&pid) {
            out.push(pid);
        }
    }
    out
}

/// First candidate the OS reports as active.
pub(crate) fn pick_frontmost(candidates: &[i32], is_active: impl Fn(i32) -> bool) -> Option<i32> {
    candidates
        .iter()
        .copied()
        .filter(|&p| p > 0)
        .find(|&p| is_active(p))
}

/// Copy one AX attribute, adopting the +1 reference.
fn ax_copy(element: &AXUIElement, attribute: &str) -> Option<CFRetained<CFType>> {
    let attr = CFString::from_str(attribute);
    let mut out: *const CFType = std::ptr::null();
    // SAFETY: `out` is a valid out-pointer for the duration of the call.
    let err = unsafe { element.copy_attribute_value(&attr, NonNull::from(&mut out)) };
    if err != AXError::Success {
        return None;
    }
    // SAFETY: on success AXUIElementCopyAttributeValue stores a +1 (Copy
    // rule) reference, which `from_raw` adopts and releases on drop.
    NonNull::new(out.cast_mut()).map(|p| unsafe { CFRetained::from_raw(p) })
}

/// Longest title we report, in characters. Real titles are far shorter; a
/// longer one is cut (the service bounds it again, `faro_ipc::limits`).
pub const MAX_TITLE_CHARS: usize = 1024;

/// `raw` trimmed and cut to [`MAX_TITLE_CHARS`]; `None` if empty.
fn bound_title(raw: &str) -> Option<String> {
    let title = raw.trim();
    let end = title
        .char_indices()
        .nth(MAX_TITLE_CHARS)
        .map_or(title.len(), |(i, _)| i);
    let title = title[..end].trim_end();
    (!title.is_empty()).then(|| title.to_owned())
}

fn focused_window_title(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    // SAFETY: AXUIElementCreateApplication accepts any pid; for a positive
    // pid it returns a (possibly dead) element, never null.
    let app = unsafe { AXUIElement::new_application(pid) };
    // SAFETY: plain setter on a valid element. Bounds every later request on
    // this element (and elements derived from it) so a hung app cannot
    // block the agent's tick.
    let _ = unsafe { app.set_messaging_timeout(AX_TIMEOUT_SECS) };
    let window = ax_copy(&app, "AXFocusedWindow")?
        .downcast::<AXUIElement>()
        .ok()?;
    // SAFETY: as above, on the derived window element.
    let _ = unsafe { window.set_messaging_timeout(AX_TIMEOUT_SECS) };
    let title = ax_copy(&window, "AXTitle")?
        .downcast::<CFString>()
        .ok()?
        .to_string();
    bound_title(&title)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_are_trimmed_and_bounded() {
        assert_eq!(bound_title("  Inbox  ").as_deref(), Some("Inbox"));
        assert_eq!(bound_title("   "), None);
        let long = "é".repeat(MAX_TITLE_CHARS * 4);
        let cut = bound_title(&long).unwrap();
        assert_eq!(cut.chars().count(), MAX_TITLE_CHARS);
        assert!(long.starts_with(&cut));
    }

    #[test]
    fn layer0_owners_keep_order_and_dedupe() {
        let windows = [
            (25, 10),
            (0, 42),
            (0, 7),
            (0, 42),
            (0, -1),
            (3, 9),
            (0, 0),
            (0, 8),
        ];
        assert_eq!(layer0_owner_pids(&windows), vec![42, 7, 8]);
        assert!(layer0_owner_pids(&[]).is_empty());
        assert!(layer0_owner_pids(&[(24, 1), (25, 2)]).is_empty());
    }

    #[test]
    fn pick_first_active_candidate() {
        assert_eq!(pick_frontmost(&[1, 2, 3], |p| p >= 2), Some(2));
        assert_eq!(pick_frontmost(&[1, 2, 3], |_| false), None);
        assert_eq!(pick_frontmost(&[], |_| true), None);
        assert_eq!(
            pick_frontmost(&[-5, 0, 9], |_| true),
            Some(9),
            "invalid pids skipped"
        );
    }

    #[test]
    fn smoke_active_app_and_title_do_not_panic() {
        let fg = MacForeground::new();
        if let Some(app) = fg.active_app() {
            assert!(!app.id.is_empty());
        }
        if let Some(t) = fg.window_title() {
            assert!(!t.trim().is_empty());
        }
        let _ = accessibility_trusted();
    }

    #[test]
    fn smoke_browser_does_not_panic() {
        if let Some(b) = MacForeground::new().browser() {
            // No values in the messages: this may be a real tab.
            let url = b.url.expect("a browser context always has a URL");
            assert!(
                browser::reduce_url(&url).as_deref() == Some(url.as_str()),
                "the URL is already reduced"
            );
            assert!(b.title.is_none() && !b.incognito);
        }
    }

    #[test]
    fn title_for_bogus_pids_is_none() {
        assert_eq!(focused_window_title(0), None);
        assert_eq!(focused_window_title(-1), None);
        // A pid that cannot exist (pid_max on macOS is 99998).
        if accessibility_trusted() {
            assert_eq!(focused_window_title(999_999), None);
        }
    }
}
