//! # faro-platform-windows
//!
//! The Windows 10 22H2+ / 11 implementation of the `faro-platform` traits
//! (ARCHITECTURE.md §3.2, §3.3 "Windows").
//!
//! | Trait / concern | Module | Runs in |
//! |---|---|---|
//! | `ScreenCapture` | [`capture`]: DXGI Desktop Duplication, GDI fallback | agent |
//! | `ForegroundInfo` | [`foreground`]: `GetForegroundWindow`, `QueryFullProcessImageName`; tab URLs via UI Automation ([`browser`]) | agent |
//! | `SessionState` | [`session`]: `GetLastInputInfo`, lock / secure desktop, display and system sleep | agent |
//! | `TamperSignals` | [`tamper`]: VM, VPN, windows excluded from capture (edge-triggered) | agent |
//! | `ServiceHost` | [`service`]: WTS sessions, `WTSQueryUserToken` + `CreateProcessAsUser` | service |
//! | SCM integration | [`scm`]: service dispatcher, install with recovery actions and a protective DACL | service |
//! | File ACLs | [`acl`]: SYSTEM-only `%ProgramData%\Faro` | service |
//! | Code signing | [`authenticode`]: `WinVerifyTrust` + signer check of a file or a process image | service |
//! | Tray / notices / enrolling | [`ui`] | agent |
//!
//! On every other OS this crate compiles to an empty library, so the
//! workspace builds everywhere and only Windows binaries depend on it for real.
//!
//! ## Privacy invariants
//!
//! Captured pixels only ever exist in memory: the OS image is copied into a
//! zeroizing buffer and handed out as a [`faro_platform::Frame`]. Nothing in
//! this crate writes images to disk or logs pixels, window titles or URLs
//! (titles and URLs only at `debug`, and never in `Debug` output).

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
pub mod acl;
#[cfg(windows)]
pub mod authenticode;
#[cfg(windows)]
pub mod browser;
#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod foreground;
pub mod layout;
#[cfg(windows)]
pub mod scm;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod tamper;
#[cfg(windows)]
pub mod ui;

#[cfg(windows)]
pub use authenticode::{AuthenticodeError, SignerInfo, SignerRequirement};
#[cfg(windows)]
pub use scm::{ServiceContext, ServiceControl};
#[cfg(windows)]
pub use service::{SessionEvent, SessionEventKind, WinServiceHost};

// ---------------------------------------------------------------------------
// Agent side: the session agent's platform bundle.
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub use browser::Browser;
#[cfg(windows)]
pub use capture::{CaptureBackend, CaptureError, DisplayCapture, DisplayFailure, WinScreenCapture};
#[cfg(windows)]
pub use foreground::WinForeground;
#[cfg(windows)]
pub use session::WinSession;
#[cfg(windows)]
pub use tamper::WinTamper;

/// Constructors for the Windows platform bundle.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WinPlatform;

#[cfg(windows)]
impl WinPlatform {
    /// The service-side host integration (sessions, launching agents,
    /// installing the service).
    pub fn service_host() -> WinServiceHost {
        WinServiceHost::new()
    }

    /// Everything the session agent needs. Construction is cheap and opens
    /// nothing that is tied to the calling thread: DXGI duplications are
    /// opened on the first capture and the UI Automation client on the
    /// first browser read, both on the thread that drives the platform
    /// (the agent's dedicated platform thread). It registers the
    /// display-state callback and samples the session baseline.
    pub fn agent_platform() -> faro_platform::AgentPlatform {
        faro_platform::AgentPlatform {
            capture: Box::new(WinScreenCapture::new()),
            foreground: Box::new(WinForeground::new()),
            session: Box::new(WinSession::new()),
            tamper: Box::new(WinTamper::new()),
        }
    }
}

#[cfg(all(test, windows))]
mod agent_tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn agent_components_are_send() {
        assert_send::<WinScreenCapture>();
        assert_send::<WinForeground>();
        assert_send::<WinSession>();
        assert_send::<WinTamper>();
    }

    #[test]
    fn agent_platform_constructs_and_answers() {
        let mut p = WinPlatform::agent_platform();
        assert_eq!(
            p.capture.permission_state(),
            faro_platform::PermissionState::NotRequired
        );
        let _ = p.foreground.active_app();
        let _ = p.session.idle_secs();
        let _ = p.session.is_locked();
        let _ = p.session.poll_changes();
        let _ = p.tamper.poll();
    }

    #[test]
    fn agent_platform_runs_on_another_thread() {
        // The agent builds the bundle on one thread and drives it on its
        // platform thread.
        let mut p = WinPlatform::agent_platform();
        std::thread::spawn(move || {
            let _ = p.foreground.browser();
            let _ = p.capture.capture_all_displays();
        })
        .join()
        .unwrap();
    }
}
