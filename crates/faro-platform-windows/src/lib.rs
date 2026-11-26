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

// NOTE (merge): the agent-side work adds `WinPlatform` with
// `agent_platform()` too. Keep one struct definition; the impl blocks are
// separate so both can stay as they are.
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
}
