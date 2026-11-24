//! The in-memory screen frame (ARCHITECTURE.md §3.5).
//!
//! **Invariant:** a [`Frame`] holds unblurred pixels, so it must never be
//! persisted, serialized, logged or cloned. The type enforces what it can:
//!
//! * no `Clone`, `Serialize` or pixel-printing `Debug`;
//! * the buffer is zeroized on drop (`ZeroizeOnDrop`), including the
//!   intermediate buffers produced by [`Frame::downscale_to_max`] and
//!   [`Frame::into_rgba8`];
//! * the only way out is a borrowed `&[u8]` view for classification and
//!   thumbnail blurring.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Longest side, in pixels, the agent downscales to before sending (§3.1).
pub const MAX_FRAME_SIDE: u32 = 768;

/// Byte layout of a frame's pixels. Always 4 bytes per pixel, tightly packed
/// (stride == width * 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PixelFormat {
    Rgba8,
    Bgra8,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("pixel buffer is {got} bytes, expected {expected}")]
    BadLength { expected: usize, got: usize },
    #[error("frame dimensions must be non-zero and at most 16384")]
    BadDimensions,
}

/// Raw, unblurred pixels of one display. See module docs for the invariant.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Frame {
    #[zeroize(skip)]
    width: u32,
    #[zeroize(skip)]
    height: u32,
    #[zeroize(skip)]
    format: PixelFormat,
    #[zeroize(skip)]
    display_id: u32,
    pixels: Vec<u8>,
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("format", &self.format)
            .field("display_id", &self.display_id)
            .field("pixels", &"<redacted>")
            .finish()
    }
}

impl Frame {
    /// Take ownership of a tightly packed 4-byte-per-pixel buffer. On error
    /// the buffer is zeroized before being dropped.
    pub fn new(
        width: u32,
        height: u32,
        format: PixelFormat,
        display_id: u32,
        mut pixels: Vec<u8>,
    ) -> Result<Self, FrameError> {
        if width == 0 || height == 0 || width > 16384 || height > 16384 {
            pixels.zeroize();
            return Err(FrameError::BadDimensions);
        }
        let expected = width as usize * height as usize * 4;
        if pixels.len() != expected {
            let got = pixels.len();
            pixels.zeroize();
            return Err(FrameError::BadLength { expected, got });
        }
        Ok(Frame {
            width,
            height,
            format,
            display_id,
            pixels,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn format(&self) -> PixelFormat {
        self.format
    }

    pub fn display_id(&self) -> u32 {
        self.display_id
    }

    /// Borrow the raw pixels. Never copy these anywhere persistent.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Move the pixel buffer out without copying it, for handing a frame to
    /// the IPC layer. The buffer stays zeroize-on-drop via [`Zeroizing`], so
    /// the unblurred pixels are still wiped wherever they end up being dropped.
    ///
    /// Returns `(width, height, format, display_id, pixels)`.
    ///
    /// [`Zeroizing`]: zeroize::Zeroizing
    pub fn into_parts(mut self) -> (u32, u32, PixelFormat, u32, zeroize::Zeroizing<Vec<u8>>) {
        // `self` is ZeroizeOnDrop; taking the Vec leaves an empty one behind,
        // so the drop of `self` at the end of this function has nothing to wipe.
        let pixels = zeroize::Zeroizing::new(std::mem::take(&mut self.pixels));
        (
            self.width,
            self.height,
            self.format,
            self.display_id,
            pixels,
        )
    }

    /// Convert to RGBA in place (swizzle), no extra allocation.
    pub fn into_rgba8(mut self) -> Frame {
        if self.format == PixelFormat::Bgra8 {
            for px in self.pixels.chunks_exact_mut(4) {
                px.swap(0, 2);
            }
            self.format = PixelFormat::Rgba8;
        }
        self
    }

    /// Box-filter downscale so the longest side is at most `max_side`.
    /// Returns `self` unchanged if it is already small enough. The source
    /// buffer is zeroized when it is dropped.
    pub fn downscale_to_max(self, max_side: u32) -> Frame {
        let max_side = max_side.max(1);
        let longest = self.width.max(self.height);
        if longest <= max_side {
            return self;
        }
        let scale = max_side as f64 / longest as f64;
        let nw = ((self.width as f64 * scale).round() as u32).max(1);
        let nh = ((self.height as f64 * scale).round() as u32).max(1);
        let mut out = vec![0u8; nw as usize * nh as usize * 4];
        let (sw, sh) = (self.width as usize, self.height as usize);
        for y in 0..nh as usize {
            let y0 = y * sh / nh as usize;
            let y1 = (((y + 1) * sh) / nh as usize).max(y0 + 1);
            for x in 0..nw as usize {
                let x0 = x * sw / nw as usize;
                let x1 = (((x + 1) * sw) / nw as usize).max(x0 + 1);
                let mut acc = [0u32; 4];
                for sy in y0..y1 {
                    let row = &self.pixels[(sy * sw + x0) * 4..(sy * sw + x1) * 4];
                    for px in row.chunks_exact(4) {
                        for c in 0..4 {
                            acc[c] += px[c] as u32;
                        }
                    }
                }
                let n = ((y1 - y0) * (x1 - x0)) as u32;
                let o = (y * nw as usize + x) * 4;
                for c in 0..4 {
                    out[o + c] = (acc[c] / n) as u8;
                }
            }
        }
        let f = Frame {
            width: nw,
            height: nh,
            format: self.format,
            display_id: self.display_id,
            pixels: out,
        };
        drop(self); // zeroizes the full-resolution buffer
        f
    }

    /// Explicitly destroy the frame now (equivalent to `drop`, but reads as
    /// intent at call sites: "zeroize the original frame buffer", §3.5).
    pub fn destroy(self) {
        drop(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(w: u32, h: u32, rgba: [u8; 4]) -> Frame {
        let px: Vec<u8> = (0..w * h).flat_map(|_| rgba).collect();
        Frame::new(w, h, PixelFormat::Rgba8, 0, px).unwrap()
    }

    #[test]
    fn rejects_bad_length() {
        assert!(matches!(
            Frame::new(2, 2, PixelFormat::Rgba8, 0, vec![0; 15]),
            Err(FrameError::BadLength { .. })
        ));
        assert!(matches!(
            Frame::new(0, 2, PixelFormat::Rgba8, 0, vec![]),
            Err(FrameError::BadDimensions)
        ));
    }

    #[test]
    fn downscale_keeps_aspect_and_color() {
        let f = solid(1920, 1080, [10, 20, 30, 255]).downscale_to_max(MAX_FRAME_SIDE);
        assert_eq!((f.width(), f.height()), (768, 432));
        assert!(f.pixels().chunks_exact(4).all(|p| p == [10, 20, 30, 255]));
    }

    #[test]
    fn small_frames_untouched() {
        let f = solid(100, 50, [1, 2, 3, 4]).downscale_to_max(768);
        assert_eq!((f.width(), f.height()), (100, 50));
    }

    #[test]
    fn bgra_swizzle() {
        let f = Frame::new(1, 1, PixelFormat::Bgra8, 0, vec![1, 2, 3, 4])
            .unwrap()
            .into_rgba8();
        assert_eq!(f.pixels(), &[3, 2, 1, 4]);
        assert_eq!(f.format(), PixelFormat::Rgba8);
    }

    #[test]
    fn zeroize_clears_pixels() {
        let mut f = solid(4, 4, [9, 9, 9, 9]);
        f.zeroize();
        assert!(f.pixels().iter().all(|&b| b == 0));
    }

    #[test]
    fn into_parts_moves_without_copy() {
        let f = solid(2, 2, [7, 8, 9, 10]);
        let ptr = f.pixels().as_ptr();
        let (w, h, fmt, d, px) = f.into_parts();
        assert_eq!((w, h, fmt, d), (2, 2, PixelFormat::Rgba8, 0));
        assert_eq!(px.as_ptr(), ptr, "buffer must be moved, not copied");
        assert_eq!(&px[..4], &[7, 8, 9, 10]);
    }

    #[test]
    fn debug_redacts() {
        let f = solid(1, 1, [1, 2, 3, 4]);
        assert!(format!("{f:?}").contains("<redacted>"));
    }
}
