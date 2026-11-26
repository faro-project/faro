//! The tray icon: the executable's icon resource 1 if it has one, else an
//! eye drawn here (a white almond with a blue pupil on a blue disc, which
//! reads on both the light and the dark taskbar). Drawing it keeps the
//! crate free of binary assets; the packaged agent can embed a designed
//! icon as resource 1 instead.

use windows::core::PCWSTR;
use windows::Win32::Graphics::Gdi::{
    CreateBitmap, CreateDIBSection, DeleteObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS, HGDIOBJ,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateIconIndirect, GetSystemMetrics, LoadIconW, LoadImageW, HICON, ICONINFO, IDI_INFORMATION,
    IMAGE_ICON, LR_DEFAULTCOLOR, SM_CXSMICON,
};

/// The disc and the pupil.
const BLUE: (u8, u8, u8) = (0x1F, 0x5F, 0xAD);
const WHITE: (u8, u8, u8) = (0xFF, 0xFF, 0xFF);

/// The icon for the tray, at the small-icon size.
pub(super) fn tray_icon() -> HICON {
    // SAFETY: plain Win32 calls with valid arguments.
    unsafe {
        let size = GetSystemMetrics(SM_CXSMICON).clamp(16, 256);
        if let Ok(module) = GetModuleHandleW(None) {
            // MAKEINTRESOURCE(1).
            if let Ok(h) = LoadImageW(
                Some(module.into()),
                PCWSTR(std::ptr::without_provenance(1)),
                IMAGE_ICON,
                size,
                size,
                LR_DEFAULTCOLOR,
            ) {
                return HICON(h.0);
            }
        }
        match drawn(size) {
            Ok(icon) => icon,
            Err(e) => {
                tracing::warn!(error = %e, "could not draw the tray icon");
                LoadIconW(None, IDI_INFORMATION).unwrap_or_default()
            }
        }
    }
}

/// The eye as `size`×`size` BGRA pixels (non-premultiplied alpha), top row
/// first, antialiased by 4×4 supersampling.
pub(super) fn eye_pixels(size: usize) -> Vec<u32> {
    const SS: usize = 4;
    let mut out = Vec::with_capacity(size * size);
    for py in 0..size {
        for px in 0..size {
            let (mut a, mut r, mut g, mut b) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    // -1..1 across the icon.
                    let u = ((px * SS + sx) as f32 + 0.5) / (size * SS) as f32 * 2.0 - 1.0;
                    let v = ((py * SS + sy) as f32 + 0.5) / (size * SS) as f32 * 2.0 - 1.0;
                    if let Some(c) = eye_color(u, v) {
                        a += 1;
                        r += u32::from(c.0);
                        g += u32::from(c.1);
                        b += u32::from(c.2);
                    }
                }
            }
            if a == 0 {
                out.push(0);
                continue;
            }
            let alpha = a * 255 / (SS * SS) as u32;
            out.push((alpha << 24) | ((r / a) << 16) | ((g / a) << 8) | (b / a));
        }
    }
    out
}

/// The color at `(u, v)`, or `None` outside the disc.
fn eye_color(u: f32, v: f32) -> Option<(u8, u8, u8)> {
    let d2 = |cx: f32, cy: f32| (u - cx) * (u - cx) + (v - cy) * (v - cy);
    if d2(0.0, 0.0) > 0.96 * 0.96 {
        return None;
    }
    // The almond: inside two discs offset up and down.
    let almond = d2(0.0, 0.62) <= 0.97 * 0.97 && d2(0.0, -0.62) <= 0.97 * 0.97;
    if !almond {
        return Some(BLUE);
    }
    if d2(0.0, 0.0) <= 0.27 * 0.27 {
        return Some(BLUE);
    }
    Some(WHITE)
}

/// [`eye_pixels`] as an icon.
fn drawn(size: i32) -> windows::core::Result<HICON> {
    let pixels = eye_pixels(size as usize);
    let bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: size,
            biHeight: -size, // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    // SAFETY: the DIB section has room for `size * size` 32-bit pixels,
    // which is what is copied; both bitmaps are deleted once the icon
    // (which copies them) exists.
    unsafe {
        let mut bits = std::ptr::null_mut();
        let color = CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits, None, 0)?;
        std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u32>(), pixels.len());
        let mask = CreateBitmap(size, size, 1, 1, None);
        let info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: color,
        };
        let icon = CreateIconIndirect(&info);
        let _ = DeleteObject(HGDIOBJ(color.0));
        let _ = DeleteObject(HGDIOBJ(mask.0));
        icon
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_eye_has_a_pupil_and_transparent_corners() {
        let size = 32;
        let p = eye_pixels(size);
        assert_eq!(p.len(), size * size);
        assert_eq!(p[0], 0, "corner");
        let center = p[size / 2 * size + size / 2];
        assert_eq!(center >> 24, 0xFF);
        assert_eq!(center & 0xFF_FFFF, 0x1F5FAD, "pupil");
        // Between the pupil and the almond's tip: white.
        let white = p[size / 2 * size + size / 2 + 8];
        assert_eq!(white & 0xFF_FFFF, 0xFF_FFFF);
        // Above the almond: the disc.
        let top = p[4 * size + size / 2];
        assert_eq!(top & 0xFF_FFFF, 0x1F5FAD);
    }

    #[test]
    fn the_drawn_icon_is_created() {
        assert!(!drawn(16).unwrap().is_invalid());
    }
}
