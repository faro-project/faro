//! `CGImage` → [`Frame`] conversion, entirely in memory.
//!
//! Instead of reading the image's backing store directly (whose layout,
//! row padding, colour space and bit depth vary by display and macOS
//! version), we *draw* it into a bitmap context that wraps a buffer we own:
//! tightly packed 8-bit BGRA in sRGB, sized to at most [`MAX_FRAME_SIDE`].
//! That one step normalises layout, converts colour (wide-gamut and HDR
//! displays come out as plain sRGB for the classifier) and, when the OS has
//! not already scaled the capture, downsamples it with CoreGraphics'
//! high-quality filter.
//!
//! Privacy (§3.5): the only copy of unblurred pixels Faro owns is the
//! destination buffer, which is held in [`Zeroizing`] until it is moved into
//! a [`Frame`] (itself zeroize-on-drop), so every early-return path wipes it.
//! The OS-owned source image (an IOSurface or CG-allocated store) is released
//! as soon as the caller drops its `CFRetained<CGImage>`; we cannot zeroize
//! memory we do not own, and we never copy it anywhere else.

use faro_platform::{Frame, FrameError, PixelFormat, MAX_FRAME_SIDE};
use objc2_core_foundation::{CGPoint, CGRect, CGSize};
use objc2_core_graphics::{
    kCGColorSpaceSRGB, CGBitmapContextCreate, CGColorSpace, CGContext, CGImage, CGImageAlphaInfo,
    CGImageByteOrderInfo, CGInterpolationQuality,
};
use zeroize::Zeroizing;

/// Why an image could not be turned into a frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    #[error("image has zero width or height")]
    EmptyImage,
    #[error("image dimensions {0}x{1} are too large")]
    TooLarge(usize, usize),
    #[error("could not create the sRGB colour space")]
    ColorSpace,
    #[error("could not create a bitmap context")]
    Context,
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Bitmap layout matching [`PixelFormat::Bgra8`]: 32-bit little-endian
/// premultiplied ARGB, i.e. bytes B, G, R, A in memory. Screens are opaque,
/// so premultiplication is a no-op in practice (A = 255).
pub(crate) const BGRA_BITMAP_INFO: u32 =
    CGImageAlphaInfo::PremultipliedFirst.0 | CGImageByteOrderInfo::Order32Little.0;

/// Largest size, preserving aspect ratio, whose longest side is at most
/// `max_side`. Sizes already within bounds are returned unchanged (we never
/// upscale). Neither side is ever rounded down to zero.
pub fn fit_within(width: u32, height: u32, max_side: u32) -> (u32, u32) {
    let max_side = max_side.max(1);
    let (w, h) = (width.max(1), height.max(1));
    let longest = w.max(h);
    if longest <= max_side {
        return (w, h);
    }
    let scale = |side: u32| -> u32 {
        // Round-to-nearest in integer arithmetic; side <= longest so the
        // result is <= max_side.
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

/// Render `image` into a new BGRA [`Frame`] whose longest side is at most
/// `max_side` (clamped to [`MAX_FRAME_SIDE`]).
pub fn cgimage_to_frame(
    image: &CGImage,
    display_id: u32,
    max_side: u32,
) -> Result<Frame, ConvertError> {
    let src_w = CGImage::width(Some(image));
    let src_h = CGImage::height(Some(image));
    if src_w == 0 || src_h == 0 {
        return Err(ConvertError::EmptyImage);
    }
    let (Ok(w32), Ok(h32)) = (u32::try_from(src_w), u32::try_from(src_h)) else {
        return Err(ConvertError::TooLarge(src_w, src_h));
    };
    let (tw, th) = fit_within(w32, h32, max_side.min(MAX_FRAME_SIDE));
    let (tw_us, th_us) = (tw as usize, th as usize);
    let row_bytes = tw_us * 4;
    // At most 768 * 768 * 4 bytes, so this cannot overflow.
    let mut pixels = Zeroizing::new(vec![0u8; row_bytes * th_us]);

    // SAFETY: `kCGColorSpaceSRGB` is an immutable framework constant.
    let srgb = CGColorSpace::with_name(Some(unsafe { kCGColorSpaceSRGB }))
        .ok_or(ConvertError::ColorSpace)?;

    {
        // SAFETY: `pixels` is a live allocation of exactly
        // `row_bytes * th` bytes, matching the width/height/bytes-per-row we
        // pass (8 bits per component, 4 components). The context only
        // writes inside that region, and it is dropped at the end of this
        // block, before `pixels` is read or moved, so the raw pointer never
        // outlives the buffer.
        let ctx = unsafe {
            CGBitmapContextCreate(
                pixels.as_mut_ptr().cast(),
                tw_us,
                th_us,
                8,
                row_bytes,
                Some(&srgb),
                BGRA_BITMAP_INFO,
            )
        }
        .ok_or(ConvertError::Context)?;
        CGContext::set_interpolation_quality(Some(&ctx), CGInterpolationQuality::High);
        let rect = CGRect::new(
            CGPoint::new(0.0, 0.0),
            CGSize::new(f64::from(tw), f64::from(th)),
        );
        // Drawing a CGImage into a bitmap context stores the image's top row
        // at the start of the buffer, which is the Frame row order.
        CGContext::draw_image(Some(&ctx), rect, Some(image));
    }

    let owned = std::mem::take(&mut *pixels);
    Ok(Frame::new(tw, th, PixelFormat::Bgra8, display_id, owned)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use objc2_core_foundation::CFRetained;
    use objc2_core_graphics::{
        CGBitmapContextCreateImage, CGBitmapContextGetBytesPerRow, CGBitmapContextGetData,
    };

    /// Build a CGImage whose pixels are produced by `f(x, y) -> [b, g, r, a]`.
    pub(crate) fn make_image(
        w: usize,
        h: usize,
        f: impl Fn(usize, usize) -> [u8; 4],
    ) -> CFRetained<CGImage> {
        let srgb = CGColorSpace::with_name(Some(unsafe { kCGColorSpaceSRGB })).unwrap();
        // SAFETY (test): null data asks CG to allocate and own the buffer.
        let ctx = unsafe {
            CGBitmapContextCreate(
                std::ptr::null_mut(),
                w,
                h,
                8,
                0,
                Some(&srgb),
                BGRA_BITMAP_INFO,
            )
        }
        .unwrap();
        let data = CGBitmapContextGetData(Some(&ctx)).cast::<u8>();
        let bpr = CGBitmapContextGetBytesPerRow(Some(&ctx));
        assert!(!data.is_null());
        for y in 0..h {
            for x in 0..w {
                let px = f(x, y);
                for (c, v) in px.iter().enumerate() {
                    // SAFETY (test): (y, x, c) is within the CG-owned
                    // bpr * h buffer.
                    unsafe { *data.add(y * bpr + x * 4 + c) = *v };
                }
            }
        }
        CGBitmapContextCreateImage(Some(&ctx)).unwrap()
    }

    #[test]
    fn fit_within_preserves_aspect_and_bounds() {
        assert_eq!(fit_within(1920, 1080, 768), (768, 432));
        assert_eq!(fit_within(1080, 1920, 768), (432, 768));
        assert_eq!(fit_within(3024, 1964, 768), (768, 499));
        assert_eq!(fit_within(768, 768, 768), (768, 768));
        assert_eq!(fit_within(100, 50, 768), (100, 50), "never upscale");
    }

    #[test]
    fn fit_within_extremes() {
        // Extremely wide: the short side never collapses to 0.
        assert_eq!(fit_within(100_000, 1, 768), (768, 1));
        assert_eq!(fit_within(1, 100_000, 768), (1, 768));
        // Degenerate inputs are clamped rather than producing a 0 side.
        assert_eq!(fit_within(0, 0, 768), (1, 1));
        assert_eq!(fit_within(10, 10, 0), (1, 1));
        assert_eq!(fit_within(u32::MAX, u32::MAX, 768), (768, 768));
        for (w, h) in [(5120, 2880), (2560, 1600), (7, 13000), (769, 768)] {
            let (a, b) = fit_within(w, h, 768);
            assert!(a.max(b) <= 768 && a >= 1 && b >= 1, "{w}x{h} -> {a}x{b}");
        }
    }

    #[test]
    fn same_size_copy_is_exact_and_bgra_ordered() {
        let img = make_image(4, 3, |x, y| [x as u8 * 10, y as u8 * 20, 200, 255]);
        let f = cgimage_to_frame(&img, 7, 768).unwrap();
        assert_eq!((f.width(), f.height(), f.display_id()), (4, 3, 7));
        assert_eq!(f.format(), PixelFormat::Bgra8);
        assert_eq!(f.pixels().len(), 4 * 3 * 4);
        for y in 0..3 {
            for x in 0..4 {
                let o = (y * 4 + x) * 4;
                assert_eq!(
                    &f.pixels()[o..o + 4],
                    &[x as u8 * 10, y as u8 * 20, 200, 255]
                );
            }
        }
    }

    #[test]
    fn row_order_is_top_first() {
        // Top half blue (B=255), bottom half red (R=255), in BGRA.
        let img = make_image(8, 8, |_, y| {
            if y < 4 {
                [255, 0, 0, 255]
            } else {
                [0, 0, 255, 255]
            }
        });
        let f = cgimage_to_frame(&img, 1, 768).unwrap();
        assert_eq!(
            &f.pixels()[0..4],
            &[255, 0, 0, 255],
            "first row must be the image top"
        );
        let last = f.pixels().len() - 4;
        assert_eq!(&f.pixels()[last..], &[0, 0, 255, 255]);
    }

    #[test]
    fn large_images_are_downscaled_to_bound() {
        let img = make_image(2000, 1000, |_, _| [30, 60, 90, 255]);
        let f = cgimage_to_frame(&img, 1, MAX_FRAME_SIDE).unwrap();
        assert_eq!((f.width(), f.height()), (768, 384));
        // A solid colour stays (almost exactly) that colour after filtering.
        for px in f.pixels().as_chunks::<4>().0 {
            for (got, want) in px.iter().zip([30u8, 60, 90, 255]) {
                assert!(got.abs_diff(want) <= 1, "{px:?}");
            }
        }
    }

    #[test]
    fn requested_bound_is_clamped_to_max_frame_side() {
        let img = make_image(1600, 900, |_, _| [1, 2, 3, 255]);
        let f = cgimage_to_frame(&img, 1, 10_000).unwrap();
        assert!(f.width().max(f.height()) <= MAX_FRAME_SIDE);
    }
}
