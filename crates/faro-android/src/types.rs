//! What Kotlin sees: the [`AndroidPlatform`] it implements, and the records,
//! enums and errors of [`crate::FaroAndroid`]. Kotlin names are UniFFI's
//! camelCase of these; error enums become `…Exception` classes.

use std::fmt;

/// The Android side of the platform, implemented in Kotlin (a foreign
/// trait). Rust calls it from its own worker threads, never the main
/// thread, one call at a time.
#[uniffi::export(with_foreign)]
pub trait AndroidPlatform: Send + Sync {
    /// One screenshot of the default display, already downscaled on the
    /// Kotlin side so the longest side is at most 768 px, as tightly packed
    /// RGBA8888 rows (`rgba.len() == width * height * 4`). Kotlin keeps no
    /// copy: it recycles its bitmaps and zeroes its own byte array once this
    /// returns.
    fn capture_screen(&self) -> Result<CapturedFrame, CaptureError>;
    /// Whether the accessibility service is enabled and connected.
    fn permission_state(&self) -> PermissionState;
    fn foreground_app(&self) -> Option<ForegroundApp>;
    /// The active browser tab's address, reduced by Kotlin to
    /// `scheme://host/` (never a path or query). Rust checks it again.
    fn browser(&self) -> Option<BrowserTab>;
    fn idle_secs(&self) -> u64;
    fn is_locked(&self) -> bool;
    fn display_asleep(&self) -> bool;
    /// Signals observed since the last call.
    fn poll_tamper(&self) -> Vec<AndroidTamper>;
    /// Show the monitoring notice (ARCHITECTURE.md §12).
    fn show_notice(&self, text: String);
}

/// A screenshot. Holds unblurred pixels: Rust moves `rgba` into a zeroizing
/// `faro_platform::Frame` as soon as it arrives, and `Debug` never prints
/// it.
#[derive(uniffi::Record)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

impl fmt::Debug for CapturedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field(
                "rgba",
                &format_args!("<{} bytes redacted>", self.rgba.len()),
            )
            .finish()
    }
}

/// Why [`AndroidPlatform::capture_screen`] returned no frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum CaptureError {
    /// The accessibility service isn't enabled or connected.
    #[error("the accessibility service is off")]
    PermissionDenied,
    /// A `FLAG_SECURE` window of `package` is in front.
    #[error("a secure window is in front")]
    SecureWindow { package: String },
    /// Rate limited, display off, the system's own secure window
    /// (`reason` = [`SYSTEM_WINDOW`]), or an internal error.
    #[error("capture unavailable: {reason}")]
    Unavailable { reason: String },
}

/// The [`CaptureError::Unavailable`] reason Kotlin gives when the window in
/// front is the system's own secure UI (the lock screen, a permission or
/// credential prompt). It is a skipped capture, never a failure that
/// counts towards `capture_failing`.
pub const SYSTEM_WINDOW: &str = "system window";

impl From<uniffi::UnexpectedUniFFICallbackError> for CaptureError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        CaptureError::Unavailable { reason: e.reason }
    }
}

/// The accessibility service's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PermissionState {
    Granted,
    Denied,
    NotDetermined,
}

/// The app in front.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ForegroundApp {
    pub package: String,
    pub label: Option<String>,
}

/// The active browser tab. `origin` is `scheme://host/` at most; never log
/// it.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct BrowserTab {
    pub browser_package: String,
    pub origin: String,
    pub incognito: bool,
}

impl fmt::Debug for BrowserTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserTab")
            .field("browser_package", &self.browser_package)
            .field("incognito", &self.incognito)
            .finish_non_exhaustive()
    }
}

/// Tamper and context signals the app observes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, uniffi::Enum)]
pub enum AndroidTamper {
    /// The accessibility service was turned off or lost its connection:
    /// `permission_revoked` (`accessibility_service`), urgent.
    AccessibilityDisabled,
    /// Device admin `onDisableRequested` / `onDisabled`:
    /// `permission_revoked` (`device_admin`), urgent.
    DeviceAdminDisableRequested,
    /// A `FLAG_SECURE` window of `app` (its package) is in front. Rust
    /// debounces it like a capture refused for it.
    SecureWindow { app: String },
    /// Context only (the daily report).
    BatteryOptimizationOn,
    /// Context only (the daily report).
    UsbDebuggingOn,
}

/// A change in the phone's session, as Kotlin learns it from broadcasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionEvent {
    Locked,
    Unlocked,
    DisplaySleep,
    DisplayWake,
}

/// What [`crate::FaroAndroid::preview_enrollment`] shows the member to
/// confirm.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrollPreview {
    /// The instance's name, from its discovery document (sanitized).
    pub instance_name: String,
    pub instance_url: String,
    /// The member key fingerprint the link names (`m`), if it names one:
    /// enrollment then refuses any other member key.
    pub member_fingerprint: Option<String>,
}

/// The enrolled device.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrolledDevice {
    pub device_id: String,
    /// The device key's fingerprint, which the member compares with the
    /// one the web app shows before approving.
    pub device_fingerprint: String,
}

/// The member's decision on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ApprovalState {
    /// Enrolled, waiting for the member to approve it in the web app.
    Pending,
    /// Approved: the recipients are known and the runtime can run.
    Active,
    /// The member removed the device (or the account was deleted). Final:
    /// enroll again with a new code.
    Refused,
}

/// For the status screen and the notification text. State only: nothing
/// here changes monitoring.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct AndroidStatus {
    /// One line ("Monitoring", "Accessibility is off", "Paused").
    pub headline: String,
    /// What it means and what to do.
    pub detail: Option<String>,
    pub enrolled: bool,
    /// Approved, so the runtime can run ([`ApprovalState::Active`]); not
    /// "capturing right now".
    pub active: bool,
    /// While paused: when the pause ends by itself, if it has an end (ms
    /// since the epoch).
    pub paused_until_ms: Option<i64>,
    /// A stable code for what is wrong, if anything, so the app can offer
    /// the fix: `accessibility_off`, `capture_failing`, `unreachable`,
    /// `identity_mismatch`, `removed`, `start_failed`.
    pub problem: Option<String>,
}

/// Why a call failed. Kotlin sees `FaroAndroidException.<Variant>` with the
/// message; the variant is what the app acts on.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FaroAndroidError {
    /// The link, code or device name is malformed, or the call isn't
    /// valid now (enroll before preview).
    #[error("{0}")]
    Invalid(String),
    /// Couldn't reach the instance, or it failed; try again later.
    #[error("{0}")]
    Network(String),
    /// The instance refused, isn't a Faro instance this app can use, or is
    /// too old to know Android.
    #[error("{0}")]
    Instance(String),
    /// Something the instance sent doesn't check out (a changed identity, a
    /// member key the link doesn't name, a forged endorsement). Nothing was
    /// trusted or stored.
    #[error("{0}")]
    Integrity(String),
    /// Not enrolled, already enrolled, or removed.
    #[error("{0}")]
    State(String),
    /// Local storage (the data directory) failed.
    #[error("{0}")]
    Storage(String),
}
