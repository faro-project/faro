//! Screen capture: DXGI Desktop Duplication with a GDI fallback
//! (ARCHITECTURE.md §3.3, Windows row).
//!
//! # Backends
//!
//! * [`CaptureBackend::DesktopDuplication`]: one `IDXGIOutputDuplication`
//!   per output (monitor) of every adapter, each on a D3D11 device created on
//!   the adapter that drives it (hybrid-GPU laptops have outputs on two
//!   adapters). It shows no capture border, works per monitor at native
//!   resolution, and costs the GPU a copy. Duplications stay open between
//!   captures; nothing else is kept (see "Privacy").
//! * [`CaptureBackend::Gdi`]: `StretchBlt` from the screen DC, one monitor at
//!   a time, straight into a DIB section of the final (≤ 768 px) size with
//!   `HALFTONE` filtering, so the OS does the downscaling. Used for an output
//!   whose duplication can't be created or keeps failing: RDP sessions and
//!   some VMs (no duplication support), a desktop in a format we don't read
//!   (HDR, when `DuplicateOutput1` can't convert it), or the four-duplication
//!   limit per output taken by other apps (`DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`).
//!   Windows Graphics Capture (the other fallback ARCHITECTURE.md lists) draws
//!   a yellow border around the captured monitor and needs WinRT plumbing;
//!   GDI covers the same cases without either.
//!
//! # Downscaling early
//!
//! Desktop duplication hands back a full-resolution GPU texture. Rather than
//! read 33 MB of a 4K desktop back to the CPU, we copy it into a texture with
//! a mip chain, let the GPU generate the mips (`GenerateMips`), and read back
//! only the smallest level whose longest side is still at least
//! [`MAX_FRAME_SIDE`] ([`mip_level_for`]); a 4K screen reads back 1920×1080
//! → 960×540, about 2 MB. The CPU then box-filters that to ≤ 768 px
//! ([`Frame::downscale_to_max`]) and applies the monitor's rotation.
//!
//! # Duplication lifecycle
//!
//! `AcquireNextFrame` returns only when the desktop changed since the frame
//! last released. A capture every minute usually finds a change and gets a
//! frame at once. When nothing changed (`DXGI_ERROR_WAIT_TIMEOUT`), or the
//! duplication is invalid (`DXGI_ERROR_ACCESS_LOST` after a mode change, a
//! desktop switch or a full-screen app; `DXGI_ERROR_INVALID_CALL`), the
//! duplication is recreated and the fresh one's first frame that carries a
//! desktop image is used (the very first frame of a new duplication is
//! often black, with `LastPresentTime == 0`; we wait for the next one, up
//! to half a second, then fall back to GDI for that round). That keeps no
//! copy of the last image around just in case. The whole set of duplications is rebuilt when the
//! DXGI factory goes stale (`IsCurrent`: monitors added, removed or
//! rearranged).
//!
//! # When the screen is not ours
//!
//! While the secure desktop is up (UAC, Ctrl+Alt+Del, the lock and logon
//! screens), the session is locked, or the session isn't at a screen (fast
//! user switching away from it, a disconnected RDP client), capture fails
//! with [`CaptureError::SecureDesktop`], [`CaptureError::Locked`] or
//! [`CaptureError::Disconnected`], which become
//! [`PlatformError::Unavailable`]: an expected pause, never tamper. The
//! checks run before each capture and again after a failure, because the
//! desktop can switch mid-capture (that is what `ACCESS_LOST` usually means).
//!
//! # Display ids
//!
//! A frame's `display_id` is the number in the monitor's GDI device name
//! (`\\.\DISPLAY2` → 2), which both backends see, so a monitor keeps its id
//! when it moves between backends.
//!
//! # Privacy
//!
//! Frames exist only in memory. The read-back staging texture is mapped
//! read-write and overwritten with zeros after its pixels are copied into a
//! zeroizing buffer; the GDI DIB section (memory we own) is zeroed before it
//! is deleted. Textures are created per capture and released at its end. The
//! desktop texture itself belongs to DWM and the GPU mip texture to the
//! driver; we cannot zeroize memory we don't own, and we never copy it
//! anywhere else. Errors carry display ids and HRESULTs only. DRM-protected
//! content comes out black (`ProtectedContentMaskedOut`).

use std::time::{Duration, Instant};

use faro_platform::{
    Frame, PermissionState, PixelFormat, PlatformError, Result as PlatformResult, ScreenCapture,
    MAX_FRAME_SIDE,
};
use windows::core::{Interface, HRESULT};
use windows::Win32::Foundation::{HMODULE, LPARAM, RECT};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11ShaderResourceView,
    ID3D11Texture2D, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
    D3D11_CPU_ACCESS_WRITE, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ_WRITE, D3D11_RESOURCE_MISC_GENERATE_MIPS, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_B8G8R8A8_UNORM_SRGB, DXGI_MODE_ROTATION,
    DXGI_MODE_ROTATION_ROTATE180, DXGI_MODE_ROTATION_ROTATE270, DXGI_MODE_ROTATION_ROTATE90,
    DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutput5,
    IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_DENIED, DXGI_ERROR_ACCESS_LOST,
    DXGI_ERROR_INVALID_CALL, DXGI_ERROR_NOT_FOUND, DXGI_ERROR_SESSION_DISCONNECTED,
    DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};
use windows::Win32::Graphics::Gdi::{
    CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, EnumDisplayMonitors, GdiFlush,
    GetDC, GetMonitorInfoW, ReleaseDC, SelectObject, SetBrushOrgEx, SetStretchBltMode, StretchBlt,
    BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS, HALFTONE, HDC, HMONITOR,
    MONITORINFO, MONITORINFOEXW, SRCCOPY,
};
use zeroize::{Zeroize, Zeroizing};

use crate::session::{self, InputDesktop, WtsLock};

/// `E_ACCESSDENIED`: what `DuplicateOutput` returns on the secure desktop.
const E_ACCESSDENIED: HRESULT = HRESULT(0x8007_0005_u32 as i32);

/// How long a freshly created duplication may take to deliver a frame
/// with a desktop image, and how long each wait for one lasts.
const FIRST_FRAME_BUDGET: Duration = Duration::from_millis(500);
const FIRST_FRAME_POLL_MS: u32 = 100;

/// Upper bound on adapters and outputs we enumerate.
const MAX_ADAPTERS: u32 = 16;
const MAX_OUTPUTS: u32 = 16;

/// Which OS API captured a display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    /// DXGI Desktop Duplication.
    DesktopDuplication,
    /// `StretchBlt` from the screen DC.
    Gdi,
}

/// Typed capture failure. Converted to [`PlatformError`] at the trait edge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// The secure desktop (UAC, Ctrl+Alt+Del, lock or logon screen) or
    /// another desktop has the input.
    #[error("the secure desktop is showing")]
    SecureDesktop,
    #[error("the session is locked")]
    Locked,
    /// The session isn't at a screen (switched away from, or its remote
    /// client disconnected).
    #[error("the session is not connected to a display")]
    Disconnected,
    #[error("no displays are attached to the desktop")]
    NoDisplays,
    #[error("{what} failed (HRESULT {code:#010x})")]
    Dxgi { what: &'static str, code: u32 },
    #[error("desktop format {0} is not supported")]
    UnsupportedFormat(i32),
    #[error("{0} failed")]
    Gdi(&'static str),
    #[error("display {0} is not attached")]
    NoSuchDisplay(u32),
    #[error("display {0} delivered no desktop image in time")]
    NoImage(u32),
    #[error("display {display}: {message}")]
    Frame { display: u32, message: String },
}

impl CaptureError {
    fn dxgi(what: &'static str, e: &windows::core::Error) -> Self {
        CaptureError::Dxgi {
            what,
            code: e.code().0 as u32,
        }
    }

    /// Whether this means "the screen is not available right now".
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            CaptureError::SecureDesktop
                | CaptureError::Locked
                | CaptureError::Disconnected
                | CaptureError::NoDisplays
        )
    }
}

impl From<CaptureError> for PlatformError {
    fn from(e: CaptureError) -> Self {
        if e.is_unavailable() {
            PlatformError::Unavailable(e.to_string())
        } else {
            PlatformError::Os(e.to_string())
        }
    }
}

/// Outcome of capturing one display.
#[derive(Debug)]
pub struct DisplayCapture {
    pub display_id: u32,
    pub backend: CaptureBackend,
    pub result: Result<Frame, CaptureError>,
    /// Wall time for this display, from request to finished frame.
    pub latency: Duration,
}

/// A display whose capture failed while others succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayFailure {
    pub display_id: u32,
    pub error: CaptureError,
}

/// Why the screen can't be captured right now, if it can't (see module
/// docs). `None` means go ahead.
pub fn screen_unavailable() -> Option<CaptureError> {
    let wts = session::current_wts_session();
    if let Some(w) = wts {
        if w.is_disconnected() || !w.is_active() {
            return Some(CaptureError::Disconnected);
        }
        if w.lock == WtsLock::Locked {
            return Some(CaptureError::Locked);
        }
    }
    match session::input_desktop() {
        InputDesktop::Ours => None,
        InputDesktop::Other(_) | InputDesktop::Inaccessible => Some(CaptureError::SecureDesktop),
    }
}

/// `\\.\DISPLAY3` → 3. Falls back to a stable hash of the name for any
/// other form (virtual display drivers sometimes use their own).
pub fn display_id_from_device_name(name: &str) -> u32 {
    let name = name.trim_end_matches('\0');
    if let Some(n) = name
        .strip_prefix(r"\\.\DISPLAY")
        .and_then(|n| n.parse::<u32>().ok())
    {
        return n;
    }
    // FNV-1a, with the top bit set so it can't collide with a GDI number.
    let mut h: u32 = 0x811c_9dc5;
    for b in name.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h | 0x8000_0000
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}

/// Largest size, preserving aspect ratio, whose longest side is at most
/// `max_side`; never upscales, never rounds a side to zero.
pub fn fit_within(width: u32, height: u32, max_side: u32) -> (u32, u32) {
    let max_side = max_side.max(1);
    let (w, h) = (width.max(1), height.max(1));
    let longest = w.max(h);
    if longest <= max_side {
        return (w, h);
    }
    let scale = |side: u32| -> u32 {
        let v =
            (u64::from(side) * u64::from(max_side) + u64::from(longest) / 2) / u64::from(longest);
        (v as u32).clamp(1, max_side)
    };
    if w >= h {
        (max_side, scale(h))
    } else {
        (scale(w), max_side)
    }
}

/// The deepest mip level of a `width`×`height` texture whose longest side
/// is still at least `max_side` (level 0 when the texture is already
/// smaller than twice that, so no mips are needed).
pub fn mip_level_for(width: u32, height: u32, max_side: u32) -> u32 {
    let longest = width.max(height);
    let mut level = 0;
    while (longest >> (level + 1)) >= max_side.max(1) {
        level += 1;
    }
    level
}

/// Size of mip `level` of a `width`×`height` texture (D3D rounds down).
pub fn mip_size(width: u32, height: u32, level: u32) -> (u32, u32) {
    ((width >> level).max(1), (height >> level).max(1))
}

/// `(x, y, width, height)` of a desktop pixel → the source pixel it comes
/// from, in an image of the given source size.
type SourcePixel = fn(usize, usize, usize, usize) -> (usize, usize);

/// Rotate a tightly packed 4-byte-per-pixel image so it shows the desktop
/// upright. DXGI hands back a rotated monitor's image in the panel's
/// native orientation; `rotation` is the output's `DXGI_MODE_ROTATION`.
/// Returns the new buffer and size; the input is zeroized.
pub fn rotate_to_desktop(
    mut px: Zeroizing<Vec<u8>>,
    width: u32,
    height: u32,
    rotation: DXGI_MODE_ROTATION,
) -> (Zeroizing<Vec<u8>>, u32, u32) {
    let (w, h) = (width as usize, height as usize);
    let (nw, nh, map): (usize, usize, SourcePixel) = match rotation {
        // Desktop pixel (x, y) comes from source pixel (sx, sy).
        DXGI_MODE_ROTATION_ROTATE90 => (h, w, |x, y, _w, h| (y, h - 1 - x)),
        DXGI_MODE_ROTATION_ROTATE180 => (w, h, |x, y, w, h| (w - 1 - x, h - 1 - y)),
        DXGI_MODE_ROTATION_ROTATE270 => (h, w, |x, y, w, _h| (w - 1 - y, x)),
        _ => return (px, width, height),
    };
    let mut out = Zeroizing::new(vec![0u8; nw * nh * 4]);
    for y in 0..nh {
        for x in 0..nw {
            let (sx, sy) = map(x, y, w, h);
            let s = (sy * w + sx) * 4;
            let d = (y * nw + x) * 4;
            out[d..d + 4].copy_from_slice(&px[s..s + 4]);
        }
    }
    px.zeroize();
    (out, nw as u32, nh as u32)
}

/// Copy `rows` rows of `row_bytes` each out of a buffer with `pitch` bytes
/// per row into a tightly packed zeroizing buffer.
///
/// # Safety
/// `src` must be valid for reads of `pitch * (rows - 1) + row_bytes` bytes.
unsafe fn copy_rows(
    src: *const u8,
    pitch: usize,
    row_bytes: usize,
    rows: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; row_bytes * rows]);
    for r in 0..rows {
        // SAFETY: row `r` starts `r * pitch` bytes in and is `row_bytes`
        // long, inside the region the caller vouches for.
        let row = unsafe { std::slice::from_raw_parts(src.add(r * pitch), row_bytes) };
        out[r * row_bytes..(r + 1) * row_bytes].copy_from_slice(row);
    }
    out
}

/// Screens are opaque, but GDI leaves the alpha byte at 0 and some desktop
/// surfaces carry undefined alpha. The classifier wants opaque pixels.
fn force_opaque(px: &mut [u8]) {
    for p in px.as_chunks_mut::<4>().0 {
        p[3] = 255;
    }
}

fn finish_frame(
    px: Zeroizing<Vec<u8>>,
    width: u32,
    height: u32,
    rotation: DXGI_MODE_ROTATION,
    display_id: u32,
) -> Result<Frame, CaptureError> {
    let frame_err = |e: faro_platform::FrameError| CaptureError::Frame {
        display: display_id,
        message: e.to_string(),
    };
    // Downscale before rotating: rotation is a plain copy, cheaper small.
    let mut px = px;
    force_opaque(&mut px);
    let pixels = std::mem::take(&mut *px);
    let frame = Frame::new(width, height, PixelFormat::Bgra8, display_id, pixels)
        .map_err(frame_err)?
        .downscale_to_max(MAX_FRAME_SIDE);
    if !matches!(
        rotation,
        DXGI_MODE_ROTATION_ROTATE90 | DXGI_MODE_ROTATION_ROTATE180 | DXGI_MODE_ROTATION_ROTATE270
    ) {
        return Ok(frame);
    }
    let (w, h, fmt, id, pixels) = frame.into_parts();
    let (rotated, nw, nh) = rotate_to_desktop(pixels, w, h, rotation);
    let mut rotated = rotated;
    Frame::new(nw, nh, fmt, id, std::mem::take(&mut *rotated)).map_err(frame_err)
}

// ---------------------------------------------------------------------------
// Desktop duplication
// ---------------------------------------------------------------------------

/// One output (monitor) and its duplication.
struct DupOutput {
    display_id: u32,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    output: IDXGIOutput1,
    rotation: DXGI_MODE_ROTATION,
    dup: Option<IDXGIOutputDuplication>,
    /// Duplications opened for this output (diagnostics).
    opened: u64,
}

/// Every attached output of every adapter.
struct Dxgi {
    factory: IDXGIFactory1,
    outputs: Vec<DupOutput>,
}

/// The outcome of one acquire.
enum Acquire {
    /// A frame was read (or reading it failed).
    Frame(Result<Frame, CaptureError>),
    /// Nothing new since the last release (`DXGI_ERROR_WAIT_TIMEOUT`).
    Timeout,
    /// A frame without a desktop image (see [`DupOutput::fresh_frame`]).
    NoImage,
    /// The duplication is unusable (`ACCESS_LOST` and the like); it has
    /// been dropped.
    Stale(CaptureError),
}

impl Dxgi {
    fn new() -> Result<Self, CaptureError> {
        // SAFETY: plain factory creation.
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }
            .map_err(|e| CaptureError::dxgi("CreateDXGIFactory1", &e))?;
        let mut outputs = Vec::new();
        for a in 0..MAX_ADAPTERS {
            // SAFETY: enumeration by index; DXGI_ERROR_NOT_FOUND ends it.
            let adapter: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(a) } {
                Ok(ad) => ad,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => return Err(CaptureError::dxgi("EnumAdapters1", &e)),
            };
            let mut attached = Vec::new();
            for o in 0..MAX_OUTPUTS {
                // SAFETY: as above.
                let output = match unsafe { adapter.EnumOutputs(o) } {
                    Ok(out) => out,
                    Err(_) => break,
                };
                // SAFETY: plain getter.
                let Ok(desc) = (unsafe { output.GetDesc() }) else {
                    continue;
                };
                if !desc.AttachedToDesktop.as_bool() {
                    continue;
                }
                let Ok(output1) = output.cast::<IDXGIOutput1>() else {
                    continue;
                };
                attached.push((
                    display_id_from_device_name(&wide_to_string(&desc.DeviceName)),
                    desc.Rotation,
                    output1,
                ));
            }
            if attached.is_empty() {
                continue;
            }
            let (device, context) = create_device(&adapter)?;
            for (display_id, rotation, output) in attached {
                outputs.push(DupOutput {
                    display_id,
                    device: device.clone(),
                    context: context.clone(),
                    output,
                    rotation,
                    dup: None,
                    opened: 0,
                });
            }
        }
        Ok(Dxgi { factory, outputs })
    }

    /// The factory still describes the current monitor layout.
    fn is_current(&self) -> bool {
        // SAFETY: plain getter.
        unsafe { self.factory.IsCurrent() }.as_bool()
    }
}

/// A D3D11 device on `adapter`. Not single-threaded: the platform object
/// may move between threads (it is `Send`), though only one uses it at a
/// time.
fn create_device(
    adapter: &IDXGIAdapter1,
) -> Result<(ID3D11Device, ID3D11DeviceContext), CaptureError> {
    let mut device = None;
    let mut context = None;
    // SAFETY: out-pointers are valid; an explicit adapter requires
    // D3D_DRIVER_TYPE_UNKNOWN.
    unsafe {
        D3D11CreateDevice(
            adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
    }
    .map_err(|e| CaptureError::dxgi("D3D11CreateDevice", &e))?;
    match (device, context) {
        (Some(d), Some(c)) => Ok((d, c)),
        _ => Err(CaptureError::Dxgi {
            what: "D3D11CreateDevice",
            code: 0,
        }),
    }
}

/// Map a DXGI error from duplication or acquisition.
fn dup_error(what: &'static str, e: &windows::core::Error) -> CaptureError {
    let code = e.code();
    if code == DXGI_ERROR_ACCESS_DENIED || code == E_ACCESSDENIED {
        CaptureError::SecureDesktop
    } else if code == DXGI_ERROR_SESSION_DISCONNECTED {
        CaptureError::Disconnected
    } else {
        CaptureError::dxgi(what, e)
    }
}

fn is_recreate(e: &windows::core::Error) -> bool {
    let c = e.code();
    c == DXGI_ERROR_ACCESS_LOST || c == DXGI_ERROR_WAIT_TIMEOUT || c == DXGI_ERROR_INVALID_CALL
}

impl DupOutput {
    /// Create the duplication. `DuplicateOutput1` asks DWM for BGRA even on
    /// an HDR desktop; it needs a per-monitor-DPI-aware process, so plain
    /// `DuplicateOutput` is the fallback.
    fn duplicate(&mut self) -> Result<(), CaptureError> {
        self.dup = None;
        let formats = [DXGI_FORMAT_B8G8R8A8_UNORM];
        let via1 = self.output.cast::<IDXGIOutput5>().ok().and_then(|o5| {
            // SAFETY: valid device and format list.
            unsafe { o5.DuplicateOutput1(&self.device, 0, &formats) }.ok()
        });
        let dup = match via1 {
            Some(d) => d,
            // SAFETY: valid device.
            None => unsafe { self.output.DuplicateOutput(&self.device) }
                .map_err(|e| dup_error("DuplicateOutput", &e))?,
        };
        // SAFETY: plain getter.
        self.rotation = unsafe { dup.GetDesc() }.Rotation;
        self.dup = Some(dup);
        Ok(())
    }

    /// One capture. An open duplication with a new frame answers at once;
    /// otherwise (nothing changed, or the duplication went stale) a fresh
    /// duplication is opened and its first real frame used.
    fn capture(&mut self) -> Result<Frame, CaptureError> {
        if self.dup.is_some() {
            if let Acquire::Frame(r) = self.acquire(0, false) {
                return r;
            }
        }
        self.fresh_frame()
    }

    /// Open a new duplication and wait (bounded) for a frame that carries
    /// a desktop image. Measured on Windows 11: the very first frame of a
    /// new duplication often has `LastPresentTime == 0` and an all-black
    /// surface; DWM delivers the real image a few milliseconds later.
    fn fresh_frame(&mut self) -> Result<Frame, CaptureError> {
        self.duplicate()?;
        self.opened += 1;
        let deadline = Instant::now() + FIRST_FRAME_BUDGET;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                // A static desktop that DWM didn't re-present for us; the
                // caller falls back to GDI for this round.
                return Err(CaptureError::NoImage(self.display_id));
            }
            let wait = (left.as_millis() as u32).clamp(1, FIRST_FRAME_POLL_MS);
            match self.acquire(wait, true) {
                Acquire::Frame(r) => return r,
                Acquire::Timeout | Acquire::NoImage => continue,
                Acquire::Stale(e) => {
                    self.dup = None;
                    return Err(e);
                }
            }
        }
    }

    /// One `AcquireNextFrame`. With `need_image`, a frame whose desktop
    /// image was never presented (`LastPresentTime == 0`) is released
    /// unread.
    fn acquire(&mut self, timeout_ms: u32, need_image: bool) -> Acquire {
        let Some(dup) = self.dup.clone() else {
            return Acquire::Stale(CaptureError::Dxgi {
                what: "AcquireNextFrame",
                code: 0,
            });
        };
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        // SAFETY: valid out-pointers; a successful acquire is paired with
        // ReleaseFrame below.
        if let Err(e) = unsafe { dup.AcquireNextFrame(timeout_ms, &mut info, &mut resource) } {
            if e.code() == DXGI_ERROR_WAIT_TIMEOUT {
                return Acquire::Timeout;
            }
            self.dup = None;
            return Acquire::Stale(dup_error("AcquireNextFrame", &e));
        }
        let copied = if need_image && info.LastPresentTime == 0 {
            None
        } else {
            Some(
                resource
                    .ok_or(CaptureError::Dxgi {
                        what: "AcquireNextFrame",
                        code: 0,
                    })
                    .and_then(|r| {
                        r.cast::<ID3D11Texture2D>()
                            .map_err(|e| CaptureError::dxgi("IDXGIResource cast", &e))
                    })
                    .and_then(|tex| self.copy_down(&tex)),
            )
        };
        // Release as soon as our GPU copy is queued, so DWM isn't held up.
        // SAFETY: a frame is held.
        if let Err(e) = unsafe { dup.ReleaseFrame() } {
            if is_recreate(&e) {
                self.dup = None;
            }
        }
        match copied {
            None => Acquire::NoImage,
            Some(c) => Acquire::Frame(c.and_then(|staging| self.read_back(staging))),
        }
    }

    /// Queue the GPU work: desktop → (mips) → a small staging texture.
    fn copy_down(&self, desktop: &ID3D11Texture2D) -> Result<Staging, CaptureError> {
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: valid out-pointer.
        unsafe { desktop.GetDesc(&mut desc) };
        let format = desc.Format;
        if !is_supported_format(format) {
            return Err(CaptureError::UnsupportedFormat(format.0));
        }
        let level = mip_level_for(desc.Width, desc.Height, MAX_FRAME_SIDE);
        let (sw, sh) = mip_size(desc.Width, desc.Height, level);
        let staging = self.texture(&D3D11_TEXTURE2D_DESC {
            Width: sw,
            Height: sh,
            MipLevels: 1,
            ArraySize: 1,
            Format: format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: (D3D11_CPU_ACCESS_READ.0 | D3D11_CPU_ACCESS_WRITE.0) as u32,
            MiscFlags: 0,
        })?;
        if level == 0 {
            // SAFETY: same size and format family, both valid.
            unsafe { self.context.CopyResource(&staging, desktop) };
        } else {
            let mips = self.texture(&D3D11_TEXTURE2D_DESC {
                Width: desc.Width,
                Height: desc.Height,
                MipLevels: level + 1,
                ArraySize: 1,
                Format: format,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
                CPUAccessFlags: 0,
                MiscFlags: D3D11_RESOURCE_MISC_GENERATE_MIPS.0 as u32,
            })?;
            let mut srv: Option<ID3D11ShaderResourceView> = None;
            // SAFETY: `mips` has BIND_SHADER_RESOURCE; valid out-pointer.
            unsafe {
                self.device
                    .CreateShaderResourceView(&mips, None, Some(&mut srv))
            }
            .map_err(|e| CaptureError::dxgi("CreateShaderResourceView", &e))?;
            let srv = srv.ok_or(CaptureError::Dxgi {
                what: "CreateShaderResourceView",
                code: 0,
            })?;
            // SAFETY: subresource 0 of `mips` matches the desktop's size and
            // format; level `level` of `mips` matches `staging`.
            unsafe {
                self.context
                    .CopySubresourceRegion(&mips, 0, 0, 0, 0, desktop, 0, None);
                self.context.GenerateMips(&srv);
                self.context
                    .CopySubresourceRegion(&staging, 0, 0, 0, 0, &mips, level, None);
            }
        }
        Ok(Staging {
            texture: staging,
            width: sw,
            height: sh,
        })
    }

    fn texture(&self, desc: &D3D11_TEXTURE2D_DESC) -> Result<ID3D11Texture2D, CaptureError> {
        let mut tex = None;
        // SAFETY: valid descriptor and out-pointer.
        unsafe { self.device.CreateTexture2D(desc, None, Some(&mut tex)) }
            .map_err(|e| CaptureError::dxgi("CreateTexture2D", &e))?;
        tex.ok_or(CaptureError::Dxgi {
            what: "CreateTexture2D",
            code: 0,
        })
    }

    /// Map the staging texture, copy its pixels out, wipe it.
    fn read_back(&self, s: Staging) -> Result<Frame, CaptureError> {
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: staging texture with CPU read/write access; valid
        // out-pointer. Map waits for the queued copy to finish.
        unsafe {
            self.context
                .Map(&s.texture, 0, D3D11_MAP_READ_WRITE, 0, Some(&mut mapped))
        }
        .map_err(|e| CaptureError::dxgi("Map", &e))?;
        let row_bytes = s.width as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let rows = s.height as usize;
        let px = if mapped.pData.is_null() || pitch < row_bytes {
            None
        } else {
            let base = mapped.pData as *mut u8;
            // SAFETY: a mapped texture of `rows` rows, `pitch` bytes apart,
            // each at least `row_bytes` long.
            let px = unsafe { copy_rows(base, pitch, row_bytes, rows) };
            // SAFETY: as above; the mapping is writable (MAP_READ_WRITE).
            unsafe { std::ptr::write_bytes(base, 0, pitch * (rows - 1) + row_bytes) };
            Some(px)
        };
        // SAFETY: mapped above.
        unsafe { self.context.Unmap(&s.texture, 0) };
        let px = px.ok_or(CaptureError::Dxgi {
            what: "Map",
            code: 0,
        })?;
        finish_frame(px, s.width, s.height, self.rotation, self.display_id)
    }
}

struct Staging {
    texture: ID3D11Texture2D,
    width: u32,
    height: u32,
}

// ---------------------------------------------------------------------------
// GDI
// ---------------------------------------------------------------------------

/// A monitor as GDI sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monitor {
    pub display_id: u32,
    /// Position and size in virtual-screen coordinates (as this process
    /// sees them: DPI-virtualized unless the process is DPI aware).
    pub rect: (i32, i32, i32, i32),
    pub primary: bool,
}

unsafe extern "system" fn collect_monitor(
    hmon: HMONITOR,
    _hdc: HDC,
    _rect: *mut RECT,
    data: LPARAM,
) -> windows::core::BOOL {
    // SAFETY: `data` is the `&mut Vec<Monitor>` passed by `monitors`, alive
    // for the duration of EnumDisplayMonitors.
    let out = unsafe { &mut *(data.0 as *mut Vec<Monitor>) };
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    // SAFETY: `info` is a MONITORINFOEXW with cbSize set, as the call allows.
    if unsafe { GetMonitorInfoW(hmon, &mut info as *mut MONITORINFOEXW as *mut MONITORINFO) }
        .as_bool()
    {
        let r = info.monitorInfo.rcMonitor;
        out.push(Monitor {
            display_id: display_id_from_device_name(&wide_to_string(&info.szDevice)),
            rect: (r.left, r.top, r.right - r.left, r.bottom - r.top),
            primary: info.monitorInfo.dwFlags & 1 != 0,
        });
    }
    true.into()
}

/// Every monitor on the desktop, as GDI enumerates them. Needs no
/// permission and reads no pixels.
pub fn monitors() -> Vec<Monitor> {
    let mut out: Vec<Monitor> = Vec::new();
    // SAFETY: the callback only touches `out` through the LPARAM, which
    // outlives the call.
    let _ = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(collect_monitor),
            LPARAM(&mut out as *mut Vec<Monitor> as isize),
        )
    };
    out
}

/// Capture one monitor through GDI at ≤ [`MAX_FRAME_SIDE`].
pub fn capture_monitor_gdi(m: &Monitor) -> Result<Frame, CaptureError> {
    let (x, y, w, h) = m.rect;
    if w <= 0 || h <= 0 {
        return Err(CaptureError::NoSuchDisplay(m.display_id));
    }
    let (tw, th) = fit_within(w as u32, h as u32, MAX_FRAME_SIDE);
    // SAFETY: GetDC(None) is the screen DC, released below on every path.
    let screen = unsafe { GetDC(None) };
    if screen.is_invalid() {
        return Err(CaptureError::Gdi("GetDC"));
    }
    let result = gdi_blit(screen, (x, y, w, h), tw, th, m.display_id);
    // SAFETY: obtained with GetDC(None) above.
    unsafe { ReleaseDC(None, screen) };
    result
}

fn gdi_blit(
    screen: HDC,
    (x, y, w, h): (i32, i32, i32, i32),
    tw: u32,
    th: u32,
    display_id: u32,
) -> Result<Frame, CaptureError> {
    // SAFETY: a memory DC compatible with the screen; deleted below.
    let mem = unsafe { CreateCompatibleDC(Some(screen)) };
    if mem.is_invalid() {
        return Err(CaptureError::Gdi("CreateCompatibleDC"));
    }
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: tw as i32,
            // Negative: top-down rows, like every other frame.
            biHeight: -(th as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: valid BITMAPINFO for a 32-bpp top-down DIB; `bits` receives
    // a pointer to its tw*th*4 bytes, valid until the bitmap is deleted.
    let dib = unsafe { CreateDIBSection(Some(mem), &bmi, DIB_RGB_COLORS, &mut bits, None, 0) };
    let dib = match dib {
        Ok(d) if !bits.is_null() => d,
        _ => {
            // SAFETY: created above.
            let _ = unsafe { DeleteDC(mem) };
            return Err(CaptureError::Gdi("CreateDIBSection"));
        }
    };
    let len = tw as usize * th as usize * 4;
    // SAFETY: GDI calls on the DCs and bitmap created above.
    let ok = unsafe {
        let old = SelectObject(mem, dib.into());
        SetStretchBltMode(mem, HALFTONE);
        let _ = SetBrushOrgEx(mem, 0, 0, None);
        let ok = StretchBlt(
            mem,
            0,
            0,
            tw as i32,
            th as i32,
            Some(screen),
            x,
            y,
            w,
            h,
            SRCCOPY | CAPTUREBLT,
        )
        .as_bool();
        let _ = GdiFlush();
        SelectObject(mem, old);
        ok
    };
    let px = ok.then(|| {
        // SAFETY: the DIB's pixel memory is `len` bytes, ours until deleted.
        let src = unsafe { std::slice::from_raw_parts(bits as *const u8, len) };
        Zeroizing::new(src.to_vec())
    });
    // SAFETY: the DIB memory is ours: wipe it, then free bitmap and DC.
    unsafe {
        std::ptr::write_bytes(bits as *mut u8, 0, len);
        let _ = DeleteObject(dib.into());
        let _ = DeleteDC(mem);
    }
    let px = px.ok_or(CaptureError::Gdi("StretchBlt"))?;
    finish_frame(px, tw, th, DXGI_MODE_ROTATION(0), display_id)
}

// ---------------------------------------------------------------------------
// The trait implementation
// ---------------------------------------------------------------------------

/// [`ScreenCapture`] for Windows. Holds the open duplications between
/// calls; every D3D/DXGI object in it is free-threaded (the `windows` crate
/// marks them `Send`), so it can move to the agent's platform thread.
pub struct WinScreenCapture {
    dxgi: Option<Dxgi>,
    force_gdi: bool,
    last_failures: Vec<DisplayFailure>,
}

impl std::fmt::Debug for WinScreenCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinScreenCapture")
            .field(
                "duplicated_outputs",
                &self.dxgi.as_ref().map(|d| d.outputs.len()),
            )
            .field("force_gdi", &self.force_gdi)
            .field("last_failures", &self.last_failures)
            .finish()
    }
}

impl Default for WinScreenCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl WinScreenCapture {
    /// Cheap: nothing is opened until the first capture.
    pub fn new() -> Self {
        WinScreenCapture {
            dxgi: None,
            force_gdi: false,
            last_failures: Vec::new(),
        }
    }

    /// Never use desktop duplication (probes and tests of the fallback).
    pub fn gdi_only() -> Self {
        WinScreenCapture {
            force_gdi: true,
            ..Self::new()
        }
    }

    /// Displays that failed during the most recent
    /// [`capture_all_displays`](ScreenCapture::capture_all_displays) call
    /// while others succeeded.
    pub fn last_failures(&self) -> &[DisplayFailure] {
        &self.last_failures
    }

    /// Desktop duplications opened so far, over all outputs (the probe
    /// uses this to show how often a capture needed a fresh one). Resets
    /// when the set of outputs is rebuilt.
    pub fn duplications_opened(&self) -> u64 {
        self.dxgi
            .as_ref()
            .map_or(0, |d| d.outputs.iter().map(|o| o.opened).sum())
    }

    /// Capture every display, returning per-display results. An `Err` means
    /// nothing could be captured at all (the screen is unavailable).
    pub fn capture_each(&mut self) -> Result<Vec<DisplayCapture>, CaptureError> {
        if let Some(why) = screen_unavailable() {
            // Desktop switches invalidate duplications; start fresh after.
            self.dxgi = None;
            return Err(why);
        }
        let mut out = Vec::new();
        if !self.force_gdi {
            if self.dxgi.as_ref().is_some_and(|d| !d.is_current()) {
                self.dxgi = None;
            }
            if self.dxgi.is_none() {
                match Dxgi::new() {
                    Ok(d) => self.dxgi = Some(d),
                    Err(e) => tracing::debug!(error = %e, "desktop duplication unavailable"),
                }
            }
            if let Some(d) = self.dxgi.as_mut() {
                for o in &mut d.outputs {
                    let started = Instant::now();
                    let result = o.capture();
                    out.push(DisplayCapture {
                        display_id: o.display_id,
                        backend: CaptureBackend::DesktopDuplication,
                        result,
                        latency: started.elapsed(),
                    });
                }
            }
        }
        // A desktop switch mid-capture shows up as per-display failures;
        // if the screen went away, say so instead of reporting errors.
        if out.iter().any(|d| d.result.is_err()) {
            if let Some(why) = screen_unavailable() {
                self.dxgi = None;
                return Err(why);
            }
        }
        // GDI for every monitor duplication didn't deliver.
        let gdi_monitors: Vec<Monitor> = monitors()
            .into_iter()
            .filter(|m| {
                !out.iter()
                    .any(|d| d.display_id == m.display_id && d.result.is_ok())
            })
            .collect();
        for m in gdi_monitors {
            if let Some(failed) = out.iter().find(|d| d.display_id == m.display_id) {
                if let Err(e) = &failed.result {
                    tracing::debug!(display = m.display_id, error = %e, "falling back to GDI");
                }
            }
            let started = Instant::now();
            let result = capture_monitor_gdi(&m);
            let entry = DisplayCapture {
                display_id: m.display_id,
                backend: CaptureBackend::Gdi,
                result,
                latency: started.elapsed(),
            };
            match out.iter_mut().find(|d| d.display_id == m.display_id) {
                Some(slot) => *slot = entry,
                None => out.push(entry),
            }
        }
        if out.is_empty() {
            return Err(CaptureError::NoDisplays);
        }
        Ok(out)
    }
}

impl ScreenCapture for WinScreenCapture {
    fn capture_all_displays(&mut self) -> PlatformResult<Vec<Frame>> {
        self.last_failures.clear();
        let results = self.capture_each()?;
        let mut frames = Vec::with_capacity(results.len());
        let mut failures = Vec::new();
        for d in results {
            match d.result {
                Ok(f) => frames.push(f),
                Err(error) => failures.push(DisplayFailure {
                    display_id: d.display_id,
                    error,
                }),
            }
        }
        if frames.is_empty() {
            if let Some(first) = failures.first() {
                let err = first.error.clone();
                self.last_failures = failures;
                return Err(err.into());
            }
        }
        // Partial success: frames from working displays are more useful to
        // allies than a blanket failure caused by one flaky monitor.
        self.last_failures = failures;
        Ok(frames)
    }

    /// Desktop duplication and GDI need no permission.
    fn permission_state(&self) -> PermissionState {
        PermissionState::NotRequired
    }
}

/// The format of a desktop we can read directly.
pub fn is_supported_format(f: DXGI_FORMAT) -> bool {
    f == DXGI_FORMAT_B8G8R8A8_UNORM || f == DXGI_FORMAT_B8G8R8A8_UNORM_SRGB
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_ids_from_gdi_names() {
        assert_eq!(display_id_from_device_name(r"\\.\DISPLAY1"), 1);
        assert_eq!(display_id_from_device_name("\\\\.\\DISPLAY12\0\0"), 12);
        let odd = display_id_from_device_name(r"\\?\VIRTUAL#1");
        assert!(
            odd & 0x8000_0000 != 0,
            "hash ids can't collide with GDI numbers"
        );
        assert_eq!(odd, display_id_from_device_name(r"\\?\VIRTUAL#1"), "stable");
    }

    #[test]
    fn fit_keeps_aspect() {
        assert_eq!(fit_within(1920, 1080, 768), (768, 432));
        assert_eq!(fit_within(1080, 1920, 768), (432, 768));
        assert_eq!(fit_within(640, 480, 768), (640, 480));
        assert_eq!(fit_within(10000, 1, 768), (768, 1));
        assert_eq!(fit_within(0, 0, 768), (1, 1));
    }

    #[test]
    fn mip_levels_stay_at_or_above_the_target() {
        assert_eq!(mip_level_for(1366, 768, 768), 0);
        assert_eq!(mip_level_for(1920, 1080, 768), 1);
        assert_eq!(mip_size(1920, 1080, 1), (960, 540));
        assert_eq!(mip_level_for(2560, 1440, 768), 1);
        assert_eq!(mip_level_for(3840, 2160, 768), 2);
        assert_eq!(mip_size(3840, 2160, 2), (960, 540));
        assert_eq!(mip_level_for(7680, 4320, 768), 3);
        assert_eq!(mip_level_for(1535, 100, 768), 0);
        assert_eq!(mip_level_for(1536, 100, 768), 1);
        assert_eq!(mip_size(3, 1, 4), (1, 1));
        for (w, h) in [(1920, 1080), (3840, 2160), (5120, 1440), (1080, 1920)] {
            let (mw, mh) = mip_size(w, h, mip_level_for(w, h, 768));
            assert!(mw.max(mh) >= 768 && mw.max(mh) < 1536, "{w}x{h}");
        }
    }

    /// A 3×2 image whose pixels are numbered 0..6 in the first byte.
    fn numbered() -> Zeroizing<Vec<u8>> {
        Zeroizing::new((0u8..6).flat_map(|i| [i, 0, 0, 255]).collect())
    }

    fn firsts(px: &[u8]) -> Vec<u8> {
        px.as_chunks::<4>().0.iter().map(|p| p[0]).collect()
    }

    #[test]
    fn rotation_maps_pixels_upright() {
        // Source (3×2):   0 1 2
        //                 3 4 5
        let (px, w, h) = rotate_to_desktop(numbered(), 3, 2, DXGI_MODE_ROTATION(1));
        assert_eq!(
            (w, h, firsts(&px)),
            (3, 2, vec![0, 1, 2, 3, 4, 5]),
            "identity"
        );
        let (px, w, h) = rotate_to_desktop(numbered(), 3, 2, DXGI_MODE_ROTATION_ROTATE180);
        assert_eq!((w, h, firsts(&px)), (3, 2, vec![5, 4, 3, 2, 1, 0]));
        let (px, w, h) = rotate_to_desktop(numbered(), 3, 2, DXGI_MODE_ROTATION_ROTATE90);
        assert_eq!((w, h), (2, 3));
        assert_eq!(firsts(&px), vec![3, 0, 4, 1, 5, 2]);
        let (px, w, h) = rotate_to_desktop(numbered(), 3, 2, DXGI_MODE_ROTATION_ROTATE270);
        assert_eq!((w, h), (2, 3));
        assert_eq!(firsts(&px), vec![2, 5, 1, 4, 0, 3]);
        // 90 then 270 is the identity.
        let (a, w, h) = rotate_to_desktop(numbered(), 3, 2, DXGI_MODE_ROTATION_ROTATE90);
        let (b, _, _) = rotate_to_desktop(a, w, h, DXGI_MODE_ROTATION_ROTATE270);
        assert_eq!(firsts(&b), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn rows_are_unpadded() {
        // Two rows of 2 pixels with a 12-byte pitch (4 bytes of padding).
        let src: Vec<u8> = (0u8..24).collect();
        // SAFETY: 12 * 1 + 8 = 20 bytes ≤ 24.
        let out = unsafe { copy_rows(src.as_ptr(), 12, 8, 2) };
        assert_eq!(
            &out[..],
            &[0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 16, 17, 18, 19]
        );
    }

    #[test]
    fn frames_come_out_opaque_and_small() {
        let px = Zeroizing::new(vec![9u8; 1920 * 1080 * 4]);
        let f = finish_frame(px, 1920, 1080, DXGI_MODE_ROTATION_ROTATE90, 4).unwrap();
        assert_eq!((f.width(), f.height(), f.display_id()), (432, 768, 4));
        assert!(f
            .pixels()
            .as_chunks::<4>()
            .0
            .iter()
            .all(|p| p == &[9, 9, 9, 255]));
    }

    #[test]
    fn unavailable_maps_to_unavailable() {
        for e in [
            CaptureError::SecureDesktop,
            CaptureError::Locked,
            CaptureError::Disconnected,
            CaptureError::NoDisplays,
        ] {
            assert!(matches!(
                PlatformError::from(e),
                PlatformError::Unavailable(_)
            ));
        }
        assert!(matches!(
            PlatformError::from(CaptureError::Gdi("StretchBlt")),
            PlatformError::Os(_)
        ));
        assert!(is_supported_format(DXGI_FORMAT_B8G8R8A8_UNORM));
        assert!(
            !is_supported_format(DXGI_FORMAT(10)),
            "R16G16B16A16_FLOAT (HDR)"
        );
    }

    #[test]
    fn live_capture_smoke() {
        let mut cap = WinScreenCapture::new();
        assert_eq!(cap.permission_state(), PermissionState::NotRequired);
        match cap.capture_all_displays() {
            Ok(frames) => {
                for f in &frames {
                    assert!(f.width().max(f.height()) <= MAX_FRAME_SIDE);
                }
            }
            // A CI runner without an interactive desktop.
            Err(PlatformError::Unavailable(_)) => {}
            Err(e) => panic!("capture failed: {e}"),
        }
        let mut gdi = WinScreenCapture::gdi_only();
        if let Ok(frames) = gdi.capture_all_displays() {
            assert_eq!(frames.len(), monitors().len());
        }
    }
}
