//! # faro-platform-macos
//!
//! The macOS 13+ implementation of the `faro-platform` traits
//! (ARCHITECTURE.md §3.2, §3.3 "macOS").
//!
//! | Trait | Implementation | Runs in |
//! |---|---|---|
//! | `ScreenCapture` | [`MacScreenCapture`]: ScreenCaptureKit `SCScreenshotManager` (14+), `CGDisplayCreateImage` (13) | agent |
//! | `ForegroundInfo` | [`MacForeground`]: window list + fresh `NSRunningApplication`; titles and browser tab URLs ([`browser`]) via Accessibility | agent |
//! | `SessionState` | [`MacSession`]: CGEventSource idle, CGSession lock, display/system sleep | agent |
//! | `TamperSignals` | [`MacTamper`]: permission revocation, VM, VPN (edge-triggered) | agent |
//! | `ServiceHost` | [`MacServiceHost`]: launchd plists, `SMAppService`, console sessions | service |
//!
//! [`ui`] is the agent's menu-bar icon, monitoring notice (§12) and
//! enrollment screens; it has no `faro-platform` trait because only the
//! macOS agent binary drives it. [`authorization`] is how an administrator
//! approves enrolling the computer (Authorization Services).
//!
//! On every other OS this crate compiles to an empty library, so the
//! workspace builds everywhere and only macOS binaries depend on it for real.
//!
//! ## Privacy invariants
//!
//! Captured pixels only ever exist in memory: the OS image is drawn into a
//! zeroizing buffer and handed out as a [`faro_platform::Frame`]
//! (zeroize-on-drop, no `Clone`/`Serialize`). Nothing in this crate writes
//! images to disk, logs pixels, or uses the ScreenCaptureKit file-output
//! APIs.
//!
//! ## Deviations from ARCHITECTURE.md
//!
//! * macOS 13 uses `CGDisplayCreateImage` (resolved at runtime) rather than a
//!   single-frame `SCStream`. Both need the same Screen Recording permission;
//!   the stream route needs an Objective-C delegate class, a dispatch queue
//!   and start/stop choreography per capture to obtain one frame, for an OS
//!   version on which the synchronous API is still fully supported.
//! * The frontmost app does not come from `NSWorkspace.frontmostApplication`,
//!   which goes stale off the main run loop (see [`foreground`]).

#![cfg_attr(not(target_os = "macos"), allow(unused))]

#[cfg(target_os = "macos")]
pub mod authorization;
#[cfg(target_os = "macos")]
mod bridge;
#[cfg(target_os = "macos")]
pub mod browser;
#[cfg(target_os = "macos")]
pub mod capture;
#[cfg(target_os = "macos")]
mod cf;
#[cfg(target_os = "macos")]
pub mod convert;
#[cfg(target_os = "macos")]
pub mod foreground;
#[cfg(target_os = "macos")]
pub mod service;
#[cfg(target_os = "macos")]
pub mod session;
#[cfg(target_os = "macos")]
pub mod tamper;
#[cfg(target_os = "macos")]
pub mod ui;
#[cfg(target_os = "macos")]
pub mod update_job;

#[cfg(target_os = "macos")]
pub use bridge::{BridgeError, DEFAULT_TIMEOUT as CAPTURE_TIMEOUT};
#[cfg(target_os = "macos")]
pub use capture::{
    active_displays, request_screen_capture_access, screen_capture_permission, CaptureBackend,
    CaptureError, DisplayCapture, DisplayFailure, MacScreenCapture,
};
#[cfg(target_os = "macos")]
pub use foreground::{accessibility_trusted, MacForeground};
#[cfg(target_os = "macos")]
pub use service::{
    agent_plist, daemon_plist, pkg_agent_job, pkg_daemon_job, pkg_layout, LaunchdJob,
    MacServiceHost, PlistError, ProgramLocation, AGENT_LABEL, DAEMON_LABEL,
};
#[cfg(target_os = "macos")]
pub use session::MacSession;
#[cfg(target_os = "macos")]
pub use tamper::MacTamper;

/// Constructors for the macOS platform bundle.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, Default)]
pub struct MacPlatform;

#[cfg(target_os = "macos")]
impl MacPlatform {
    /// Everything the session agent needs. Construction never prompts for
    /// any permission; it samples the session and tamper baselines.
    pub fn agent_platform() -> faro_platform::AgentPlatform {
        faro_platform::AgentPlatform {
            capture: Box::new(MacScreenCapture::new()),
            foreground: Box::new(MacForeground::new()),
            session: Box::new(MacSession::new()),
            tamper: Box::new(MacTamper::new()),
        }
    }

    /// The service-side host integration.
    pub fn service_host() -> MacServiceHost {
        MacServiceHost::new()
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn components_are_send() {
        assert_send::<MacScreenCapture>();
        assert_send::<MacForeground>();
        assert_send::<MacSession>();
        assert_send::<MacTamper>();
        assert_send::<MacServiceHost>();
    }

    #[test]
    fn agent_platform_constructs_and_answers() {
        let mut p = MacPlatform::agent_platform();
        let _ = p.capture.permission_state();
        let _ = p.foreground.active_app();
        let _ = p.session.idle_secs();
        let _ = p.session.is_locked();
        let _ = p.tamper.poll();
    }
}
