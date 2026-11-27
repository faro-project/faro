//! The tray icon: the Faro lighthouse, `assets/brand/tray/faro-tray.ico`
//! (built by `assets/brand/make-tray-icons.swift`), compiled in. The file
//! holds one colour image for each display scale from 100% to 300% (16 to
//! 48 px); the one matching the small-icon size is used, and Windows scales
//! the nearest larger one for any other size. If none can be read, the
//! stock information icon stands in, so the tray icon is never missing.

use windows::Win32::UI::WindowsAndMessaging::{
    CreateIconFromResourceEx, GetSystemMetrics, LoadIconW, HICON, IDI_INFORMATION, LR_DEFAULTCOLOR,
    SM_CXSMICON,
};

/// The icon file, as `make-tray-icons.swift` writes it.
const TRAY_ICO: &[u8] = include_bytes!("../../../../assets/brand/tray/faro-tray.ico");

/// The icon for the tray, at the small-icon size.
pub(super) fn tray_icon() -> HICON {
    // SAFETY: a plain Win32 call with no arguments that can be invalid.
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) }.clamp(16, 256);
    match from_ico(TRAY_ICO, size) {
        Ok(icon) => icon,
        Err(e) => {
            tracing::warn!(error = %e, "could not load the tray icon");
            // SAFETY: loading a stock icon.
            unsafe { LoadIconW(None, IDI_INFORMATION) }.unwrap_or_default()
        }
    }
}

/// The image in `ico` that suits `size`, as an icon of that size.
fn from_ico(ico: &[u8], size: i32) -> Result<HICON, String> {
    let image = pick(ico, size)?;
    // SAFETY: `image` is one complete image (a PNG or a DIB) from the file,
    // which is what the call reads; it copies the bits into the icon.
    unsafe {
        CreateIconFromResourceEx(image, true, 0x0003_0000, size, size, LR_DEFAULTCOLOR)
            .map_err(|e| e.to_string())
    }
}

/// The bytes of the image in an `.ico` file whose width is `size`, else the
/// smallest wider one, else the widest. Every offset and length is checked
/// against the file.
fn pick(ico: &[u8], size: i32) -> Result<&[u8], String> {
    let u16_at = |at: usize| {
        ico.get(at..at + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
    };
    let u32_at = |at: usize| {
        ico.get(at..at + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    if u16_at(0) != Some(0) || u16_at(2) != Some(1) {
        return Err("not an icon file".into());
    }
    let count = usize::from(u16_at(4).unwrap_or(0));
    let mut best: Option<(i32, usize, usize)> = None;
    for i in 0..count {
        let entry = 6 + 16 * i;
        let width = match ico.get(entry) {
            Some(0) => 256, // 0 means 256
            Some(&w) => i32::from(w),
            None => return Err("the icon directory is cut short".into()),
        };
        let (Some(len), Some(offset)) = (u32_at(entry + 8), u32_at(entry + 12)) else {
            return Err("the icon directory is cut short".into());
        };
        let (len, offset) = (len as usize, offset as usize);
        if offset.checked_add(len).is_none_or(|end| end > ico.len()) {
            return Err(format!("image {i} lies outside the file"));
        }
        // Prefer the exact size, then the smallest larger one (scaled
        // down), then the largest smaller one (scaled up).
        let better = match best {
            None => true,
            Some((b, _, _)) => {
                if b >= size {
                    width >= size && width < b
                } else {
                    width > b
                }
            }
        };
        if better {
            best = Some((width, offset, len));
        }
    }
    let (_, offset, len) = best.ok_or("the icon file has no images")?;
    Ok(&ico[offset..offset + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG";

    fn width_of(image: &[u8]) -> u32 {
        // A PNG's IHDR width, big-endian, at byte 16.
        u32::from_be_bytes([image[16], image[17], image[18], image[19]])
    }

    #[test]
    fn every_display_scale_gets_its_own_image() {
        for size in [16, 20, 24, 32, 40, 48] {
            let image = pick(TRAY_ICO, size).unwrap();
            assert!(image.starts_with(PNG));
            assert_eq!(width_of(image), size as u32);
        }
    }

    #[test]
    fn other_sizes_scale_the_nearest_image() {
        // Down from the next larger one; up from the largest.
        assert_eq!(width_of(pick(TRAY_ICO, 28).unwrap()), 32);
        assert_eq!(width_of(pick(TRAY_ICO, 64).unwrap()), 48);
    }

    #[test]
    fn a_broken_file_is_refused() {
        assert!(pick(b"", 16).is_err());
        assert!(pick(b"\0\0\x02\0\x01\0", 16).is_err(), "a cursor file");
        // One entry whose image runs past the end.
        let mut bad = vec![0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0];
        bad.extend_from_slice(&1000u32.to_le_bytes());
        bad.extend_from_slice(&22u32.to_le_bytes());
        assert!(pick(&bad, 16).is_err());
    }

    #[test]
    fn the_tray_icon_is_created_at_every_scale() {
        for size in [16, 20, 24, 32, 40, 48] {
            let icon = from_ico(TRAY_ICO, size).unwrap();
            assert!(!icon.is_invalid());
        }
    }
}
