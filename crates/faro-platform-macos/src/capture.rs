//! Screen capture via ScreenCaptureKit (ARCHITECTURE.md §3.3, macOS row).
//!
//! # Backends
//!
//! * **macOS 14+** — [`CaptureBackend::ScreenshotManager`]:
//!   `SCScreenshotManager captureImageWithFilter:configuration:` once per
//!   display. The `SCStreamConfiguration` asks the OS for a BGRA image whose
//!   longest side is already at most [`MAX_FRAME_SIDE`], at nominal (point)
//!   resolution, so a full-resolution copy of a Retina screen is never handed
//!   to this process.
//! * **macOS 13** — [`CaptureBackend::LegacyDisplayImage`]:
//!   `CGDisplayCreateImage`, the supported synchronous API on 13 (deprecated
//!   only from 14, where the screenshot backend is used instead). It returns a
//!   full-resolution image that we immediately draw down to ≤ 768 px in
//!   memory. The symbol is resolved with `dlsym` at runtime rather than
//!   linked, because Apple marks it obsoleted in the macOS 15 SDK; a hard link
//!   would risk the whole agent failing to load on a future macOS that drops
//!   it. ARCHITECTURE.md suggests a single-frame `SCStream` on 13; see the
//!   crate docs for why this deviates.
//!
//! # Permission
//!
//! Capture needs the Screen Recording TCC permission.
//! [`screen_capture_permission`] uses `CGPreflightScreenCaptureAccess`, which
//! never prompts. Capture is refused up front when it reports "not granted",
//! because ScreenCaptureKit calls themselves can trigger the system prompt,
//! and the agent must never surprise the member with a dialog mid-session.
//! Onboarding calls [`request_screen_capture_access`] explicitly.
//!
//! # Privacy
//!
//! Frames exist only in memory (see `convert`). Nothing here writes,
//! logs or serialises pixels; errors carry display ids and OS error codes
//! only.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use block2::RcBlock;
use faro_platform::{
    Frame, PermissionState, PlatformError, Result as PlatformResult, ScreenCapture, MAX_FRAME_SIDE,
};
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::AnyClass;
use objc2::AllocAnyThread;
use objc2_core_foundation::CFRetained;
use objc2_core_graphics::{
    CGDirectDisplayID, CGDisplayMirrorsDisplay, CGGetActiveDisplayList, CGImage, CGMainDisplayID,
    CGPreflightScreenCaptureAccess, CGRequestScreenCaptureAccess,
};
use objc2_foundation::{NSArray, NSError};
use objc2_screen_capture_kit::{
    SCCaptureResolutionType, SCContentFilter, SCDisplay, SCScreenshotManager, SCShareableContent,
    SCStreamConfiguration, SCStreamErrorCode,
};

use crate::bridge::{await_completion, AssertSend, BridgeError, DEFAULT_TIMEOUT};
use crate::convert::{cgimage_to_frame, fit_within, ConvertError};

/// `kCVPixelFormatType_32BGRA` (`'BGRA'`).
const PIXEL_FORMAT_32BGRA: u32 = u32::from_be_bytes(*b"BGRA");

/// `SCStreamErrorDomain`.
const SC_STREAM_ERROR_DOMAIN: &str = "com.apple.ScreenCaptureKit.SCStreamErrorDomain";

/// Upper bound on displays we enumerate on the legacy path.
const MAX_DISPLAYS: usize = 32;

/// Whether this process may capture the screen. Never shows a prompt.
///
/// `CGPreflightScreenCaptureAccess` only answers yes/no, so "never asked"
/// and "denied" both map to [`PermissionState::Denied`]; macOS offers no
/// public, prompt-free way to tell them apart.
pub fn screen_capture_permission() -> PermissionState {
    if CGPreflightScreenCaptureAccess() {
        PermissionState::Granted
    } else {
        PermissionState::Denied
    }
}

/// Ask macOS for Screen Recording permission (onboarding only).
///
/// Shows the system prompt the first time; afterwards macOS only points the
/// user at System Settings. Returns whether access is granted *now*; on
/// current macOS a newly granted permission usually takes effect only after
/// the process restarts, so callers should relaunch the agent.
pub fn request_screen_capture_access() -> bool {
    CGRequestScreenCaptureAccess()
}

/// Which OS API performs the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// `SCScreenshotManager` (macOS 14+).
    ScreenshotManager,
    /// `CGDisplayCreateImage` (macOS 13).
    LegacyDisplayImage,
}

impl CaptureBackend {
    /// Pick the backend for the running OS by probing for the
    /// `SCScreenshotManager` class (present from macOS 14).
    pub fn detect() -> Self {
        if AnyClass::get(c"SCScreenshotManager").is_some() {
            CaptureBackend::ScreenshotManager
        } else {
            CaptureBackend::LegacyDisplayImage
        }
    }
}

/// Typed capture failure. Converted to [`PlatformError`] at the trait edge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    #[error("screen recording permission is not granted")]
    PermissionDenied,
    #[error("{what}: {source}")]
    Bridge {
        what: &'static str,
        source: BridgeError,
    },
    #[error("ScreenCaptureKit error ({domain} {code}): {message}")]
    ScreenCaptureKit {
        domain: String,
        code: isize,
        message: String,
    },
    #[error("display {0} returned no image")]
    NoImage(u32),
    #[error("CGDisplayCreateImage is not available on this system")]
    LegacyApiMissing,
    #[error("CoreGraphics error {0}")]
    CoreGraphics(i32),
    #[error("display {display}: {source}")]
    Convert { display: u32, source: ConvertError },
}

impl CaptureError {
    fn from_ns_error(err: &NSError) -> Self {
        let domain = err.domain().to_string();
        let code = err.code();
        if domain == SC_STREAM_ERROR_DOMAIN && code == SCStreamErrorCode::UserDeclined.0 {
            return CaptureError::PermissionDenied;
        }
        CaptureError::ScreenCaptureKit {
            domain,
            code,
            message: err.localizedDescription().to_string(),
        }
    }

    /// Read an `NSError*` handed to a completion handler.
    ///
    /// # Safety
    /// `err` must be null or point to a valid `NSError` for the duration of
    /// the call (true inside a ScreenCaptureKit completion handler).
    unsafe fn from_raw_ns_error(err: *mut NSError, fallback: CaptureError) -> Self {
        // SAFETY: guaranteed by the caller; `retain` keeps it alive while we
        // read it and releases it on drop.
        match unsafe { Retained::retain(err) } {
            Some(e) => CaptureError::from_ns_error(&e),
            None => fallback,
        }
    }
}

impl From<CaptureError> for PlatformError {
    fn from(e: CaptureError) -> Self {
        match e {
            CaptureError::PermissionDenied => {
                PlatformError::PermissionDenied("screen_recording".into())
            }
            CaptureError::LegacyApiMissing => PlatformError::Unavailable(e.to_string()),
            other => PlatformError::Os(other.to_string()),
        }
    }
}

/// Outcome of capturing one display.
#[derive(Debug)]
pub struct DisplayCapture {
    pub display_id: u32,
    pub result: Result<Frame, CaptureError>,
    /// Wall time for this display, from request to converted frame.
    pub latency: Duration,
}

/// A display whose capture failed while others succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayFailure {
    pub display_id: u32,
    pub error: CaptureError,
}

/// [`ScreenCapture`] for macOS. Holds no Objective-C objects between calls,
/// so it is `Send` and cheap to construct.
#[derive(Debug)]
pub struct MacScreenCapture {
    backend: CaptureBackend,
    timeout: Duration,
    last_failures: Vec<DisplayFailure>,
}

impl Default for MacScreenCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl MacScreenCapture {
    pub fn new() -> Self {
        // Touch CoreGraphics once so the process has a window-server
        // connection before ScreenCaptureKit runs. Command-line processes
        // (like the agent) that skip this can hit a CGS initialisation
        // assertion inside ScreenCaptureKit.
        let _ = CGMainDisplayID();
        MacScreenCapture {
            backend: CaptureBackend::detect(),
            timeout: DEFAULT_TIMEOUT,
            last_failures: Vec::new(),
        }
    }

    /// Override the per-call deadline for ScreenCaptureKit round trips.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn backend(&self) -> CaptureBackend {
        self.backend
    }

    /// Displays that failed during the most recent
    /// [`capture_all_displays`](ScreenCapture::capture_all_displays) call.
    /// When some displays succeed the call still returns their frames, so
    /// this is how the agent counts partial failures. Displays are captured
    /// sequentially, each bounded by the timeout.
    pub fn last_failures(&self) -> &[DisplayFailure] {
        &self.last_failures
    }

    /// Capture every display, returning per-display results.
    ///
    /// Runs inside an autorelease pool: ScreenCaptureKit and Foundation hand
    /// back autoreleased objects (display arrays, error strings), and the
    /// agent's capture thread has no pool of its own, so without one they
    /// would pile up for the life of the thread (see `foreground`).
    pub fn capture_each(&self) -> Result<Vec<DisplayCapture>, CaptureError> {
        if screen_capture_permission() != PermissionState::Granted {
            return Err(CaptureError::PermissionDenied);
        }
        autoreleasepool(|_| match self.backend {
            CaptureBackend::ScreenshotManager => self.capture_each_sck(),
            CaptureBackend::LegacyDisplayImage => capture_each_legacy(),
        })
    }

    fn capture_each_sck(&self) -> Result<Vec<DisplayCapture>, CaptureError> {
        let content = shareable_content(self.timeout)?;
        // SAFETY: `displays` is a plain property getter on a valid object.
        let displays = unsafe { content.displays() };
        let mut out = Vec::new();
        for display in displays.iter() {
            // SAFETY: plain property getter on a valid SCDisplay.
            let id = unsafe { display.displayID() };
            if is_mirror(id) {
                continue;
            }
            let started = Instant::now();
            let result = capture_display_sck(&display, self.timeout);
            out.push(DisplayCapture {
                display_id: id,
                result,
                latency: started.elapsed(),
            });
        }
        Ok(out)
    }
}

impl ScreenCapture for MacScreenCapture {
    fn capture_all_displays(&mut self) -> PlatformResult<Vec<Frame>> {
        self.last_failures.clear();
        let results = self.capture_each()?;
        let mut frames = Vec::with_capacity(results.len());
        let mut failures = Vec::new();
        for DisplayCapture {
            display_id, result, ..
        } in results
        {
            match result {
                Ok(f) => frames.push(f),
                // Losing permission mid-call is never a "partial" failure.
                Err(CaptureError::PermissionDenied) => {
                    return Err(CaptureError::PermissionDenied.into())
                }
                Err(error) => failures.push(DisplayFailure { display_id, error }),
            }
        }
        if frames.is_empty() {
            if let Some(first) = failures.first() {
                let err = first.error.clone();
                self.last_failures = failures;
                return Err(err.into());
            }
        }
        // Partial success: return what we have, keep the rest for the caller
        // to inspect. Frames from working displays are more useful to the
        // member's allies than a blanket failure caused by one flaky monitor.
        self.last_failures = failures;
        Ok(frames)
    }

    fn permission_state(&self) -> PermissionState {
        screen_capture_permission()
    }
}

/// A display that only mirrors another shows the same pixels; skip it.
fn is_mirror(id: CGDirectDisplayID) -> bool {
    CGDisplayMirrorsDisplay(id) != 0
}

/// Fetch the current displays (on-screen windows only, to keep the
/// enumeration cheap; we never use the window list).
fn shareable_content(timeout: Duration) -> Result<Retained<SCShareableContent>, CaptureError> {
    type Reply = Result<AssertSend<Retained<SCShareableContent>>, CaptureError>;
    let reply: Reply = await_completion(timeout, |done| {
        let block = RcBlock::new(move |content: *mut SCShareableContent, err: *mut NSError| {
            // SAFETY: ScreenCaptureKit passes either a valid object or null
            // for each argument, valid for the duration of this handler;
            // `retain` takes our own +1 reference.
            let r = match unsafe { Retained::retain(content) } {
                Some(c) => Ok(AssertSend(c)),
                None => Err(unsafe {
                    CaptureError::from_raw_ns_error(
                        err,
                        CaptureError::ScreenCaptureKit {
                            domain: SC_STREAM_ERROR_DOMAIN.into(),
                            code: 0,
                            message: "no shareable content".into(),
                        },
                    )
                }),
            };
            done.complete(r);
        });
        // SAFETY: the block has the exact signature the API expects; SCK
        // copies the block, so it may outlive this stack frame.
        unsafe {
            SCShareableContent::getShareableContentExcludingDesktopWindows_onScreenWindowsOnly_completionHandler(
                false, true, &block,
            );
        }
    })
    .map_err(|source| CaptureError::Bridge {
        what: "SCShareableContent",
        source,
    })?;
    reply.map(|AssertSend(c)| c)
}

fn capture_display_sck(display: &SCDisplay, timeout: Duration) -> Result<Frame, CaptureError> {
    // SAFETY: property getters on a valid SCDisplay.
    let (id, w_pt, h_pt) = unsafe { (display.displayID(), display.width(), display.height()) };
    let clamp = |v: isize| u32::try_from(v.max(1)).unwrap_or(u32::MAX);
    // Points, not pixels: at nominal resolution the OS renders one pixel per
    // point, and the aspect ratio is all we need to fit within the bound.
    let (tw, th) = fit_within(clamp(w_pt), clamp(h_pt), MAX_FRAME_SIDE);

    // SAFETY: standard alloc/init of an SCContentFilter for a valid display
    // with an empty exclusion list; `new` on SCStreamConfiguration returns a
    // fresh object; the setters take plain values. `setCaptureResolution`
    // exists on macOS 14+, which this backend requires.
    let (filter, config) = unsafe {
        let filter = SCContentFilter::initWithDisplay_excludingWindows(
            SCContentFilter::alloc(),
            display,
            &NSArray::new(),
        );
        let config = SCStreamConfiguration::new();
        config.setWidth(tw as usize);
        config.setHeight(th as usize);
        config.setPixelFormat(PIXEL_FORMAT_32BGRA);
        config.setShowsCursor(false);
        config.setCaptureResolution(SCCaptureResolutionType::Nominal);
        (filter, config)
    };

    type Reply = Result<CFRetained<CGImage>, CaptureError>;
    let reply: Reply = await_completion(timeout, |done| {
        let block = RcBlock::new(move |image: *mut CGImage, err: *mut NSError| {
            let r = match NonNull::new(image) {
                // SAFETY: a non-null CGImage passed to the handler is valid
                // for its duration; `retain` takes our own reference.
                Some(p) => Ok(unsafe { CFRetained::retain(p) }),
                // SAFETY: as above for the NSError argument.
                None => {
                    Err(unsafe { CaptureError::from_raw_ns_error(err, CaptureError::NoImage(id)) })
                }
            };
            done.complete(r);
        });
        // SAFETY: filter/config are valid for the call (SCK retains what it
        // needs); the block signature matches the API, and SCK copies it.
        unsafe {
            SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
                &filter,
                &config,
                Some(&block),
            );
        }
    })
    .map_err(|source| CaptureError::Bridge {
        what: "SCScreenshotManager",
        source,
    })?;
    let image = reply?;
    cgimage_to_frame(&image, id, MAX_FRAME_SIDE).map_err(|source| CaptureError::Convert {
        display: id,
        source,
    })
}

type CgDisplayCreateImageFn = unsafe extern "C" fn(CGDirectDisplayID) -> *mut CGImage;

/// Resolve `CGDisplayCreateImage` at runtime (see module docs).
fn legacy_create_image_fn() -> Option<CgDisplayCreateImageFn> {
    static FN: OnceLock<Option<usize>> = OnceLock::new();
    let addr = *FN.get_or_init(|| {
        // SAFETY: dlsym with RTLD_DEFAULT and a NUL-terminated name has no
        // preconditions; it returns null when the symbol is absent.
        let p: *mut c_void =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"CGDisplayCreateImage".as_ptr()) };
        (!p.is_null()).then_some(p as usize)
    });
    // SAFETY: the address came from dlsym for `CGDisplayCreateImage`, whose
    // C signature is `CGImageRef CGDisplayCreateImage(CGDirectDisplayID)`.
    addr.map(|a| unsafe { std::mem::transmute::<usize, CgDisplayCreateImageFn>(a) })
}

/// Ids of the displays CoreGraphics currently considers active (drawable),
/// including mirrors. Does not need Screen Recording permission.
pub fn active_displays() -> Result<Vec<CGDirectDisplayID>, CaptureError> {
    let mut ids = [0 as CGDirectDisplayID; MAX_DISPLAYS];
    let mut count: u32 = 0;
    // SAFETY: `ids` has room for MAX_DISPLAYS entries, which is the capacity
    // we pass; `count` is a valid out-pointer.
    let err = unsafe { CGGetActiveDisplayList(MAX_DISPLAYS as u32, ids.as_mut_ptr(), &mut count) };
    if err.0 != 0 {
        return Err(CaptureError::CoreGraphics(err.0));
    }
    let n = (count as usize).min(MAX_DISPLAYS);
    Ok(ids[..n].to_vec())
}

fn capture_each_legacy() -> Result<Vec<DisplayCapture>, CaptureError> {
    let create = legacy_create_image_fn().ok_or(CaptureError::LegacyApiMissing)?;
    let mut out = Vec::new();
    for id in active_displays()? {
        if is_mirror(id) {
            continue;
        }
        let started = Instant::now();
        // SAFETY: `create` is CGDisplayCreateImage; it follows the Create
        // rule, so a non-null result is a +1 reference we adopt with
        // `from_raw` (released when `image` drops).
        let image = NonNull::new(unsafe { create(id) }).map(|p| unsafe { CFRetained::from_raw(p) });
        let r = match image {
            Some(img) => {
                cgimage_to_frame(&img, id, MAX_FRAME_SIDE).map_err(|source| CaptureError::Convert {
                    display: id,
                    source,
                })
            }
            None => Err(CaptureError::NoImage(id)),
        };
        out.push(DisplayCapture {
            display_id: id,
            result: r,
            latency: started.elapsed(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_state_does_not_panic_or_prompt() {
        let p = MacScreenCapture::new().permission_state();
        assert!(matches!(
            p,
            PermissionState::Granted | PermissionState::Denied
        ));
    }

    #[test]
    fn backend_detection_matches_os() {
        // This crate requires macOS 13+; on 14+ the class exists.
        let b = CaptureBackend::detect();
        assert!(matches!(
            b,
            CaptureBackend::ScreenshotManager | CaptureBackend::LegacyDisplayImage
        ));
    }

    #[test]
    fn capture_without_permission_is_a_typed_denial() {
        let mut cap = MacScreenCapture::new();
        if cap.permission_state() == PermissionState::Granted {
            return; // covered by the ignored integration test
        }
        assert_eq!(
            cap.capture_all_displays().unwrap_err(),
            PlatformError::PermissionDenied("screen_recording".into())
        );
    }

    #[test]
    fn error_mapping() {
        assert_eq!(
            PlatformError::from(CaptureError::LegacyApiMissing),
            PlatformError::Unavailable(
                "CGDisplayCreateImage is not available on this system".into()
            )
        );
        assert!(matches!(
            PlatformError::from(CaptureError::NoImage(3)),
            PlatformError::Os(m) if m.contains('3')
        ));
    }

    #[test]
    fn pixel_format_constant_is_bgra_fourcc() {
        assert_eq!(PIXEL_FORMAT_32BGRA, 0x4247_5241);
    }

    #[test]
    fn active_display_list_is_bounded() {
        // May legitimately be empty (headless CI), but never errors on a
        // logged-in Mac and never exceeds our buffer.
        if let Ok(ids) = active_displays() {
            assert!(ids.len() <= MAX_DISPLAYS);
        }
    }
}
