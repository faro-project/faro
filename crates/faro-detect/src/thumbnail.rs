//! Irreversibly blurred, pixelated PNG thumbnails (§3.5).
//!
//! The thumbnail is the *only* image that ever leaves the device, so it has
//! to show the gist of the screen ("a video player with a person") without
//! recoverable detail. The transform, in order:
//!
//! 1. area-average resize to 320 px wide (aspect kept, height capped at
//!    320 px, so a very tall frame is fitted by height instead);
//! 2. separable Gaussian blur, σ = 12 px at that scale, radius 3σ, edges
//!    clamped (replicated);
//! 3. 8×8 block pixelation (each block becomes its mean);
//! 4. alpha dropped, PNG-encoded as 8-bit RGB.
//!
//! The PNG encoder only ever sees step-3 output. Every intermediate buffer
//! is a zeroize-on-drop scratch buffer allocated at its final size. The output
//! is labelled [`THUMBNAIL_TRANSFORM`] so a reader can tell which transform
//! produced it.

use crate::error::DetectError;
use crate::resample::{resample_rgb, PlanarRgb};
use crate::scratch::Scratch;
use faro_platform::Frame;
use faro_proto::body::BlurredThumbnail;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{ExtendedColorType, ImageEncoder};

/// Target width (and maximum height) of a thumbnail, in pixels.
pub const THUMBNAIL_SIDE: u32 = 320;
/// Gaussian σ in thumbnail pixels.
pub const BLUR_SIGMA: f32 = 12.0;
/// Pixelation block size in thumbnail pixels.
pub const PIXELATE_BLOCK: usize = 8;
/// Marker stored in [`BlurredThumbnail::transform`].
pub const THUMBNAIL_TRANSFORM: &str = "gauss12+pix8";

/// Output dimensions for a `w × h` frame: 320 wide with the aspect ratio
/// kept, unless that would be taller than 320, in which case 320 tall.
pub fn thumbnail_dims(w: u32, h: u32) -> (u32, u32) {
    let (w, h) = (u64::from(w.max(1)), u64::from(h.max(1)));
    let side = u64::from(THUMBNAIL_SIDE);
    let th = (h * side + w / 2) / w;
    if th <= side {
        (THUMBNAIL_SIDE, th.max(1) as u32)
    } else {
        let tw = ((w * side + h / 2) / h).clamp(1, side);
        (tw as u32, THUMBNAIL_SIDE)
    }
}

/// Normalised 1-D Gaussian kernel of radius `ceil(3σ)`.
fn gaussian_kernel(sigma: f32) -> Vec<f32> {
    let r = (3.0 * sigma).ceil() as i32;
    let two_s2 = 2.0 * sigma * sigma;
    let mut k: Vec<f32> = (-r..=r)
        .map(|i| (-((i * i) as f32) / two_s2).exp())
        .collect();
    let sum: f32 = k.iter().sum();
    k.iter_mut().for_each(|v| *v /= sum);
    k
}

/// Blur one `w × h` plane in place (horizontal then vertical), using `tmp`
/// (same length as the plane) and `pad` (length `max(w, h) + 2r`) as
/// scratch. Both passes are written as slice-wide `axpy`s over the kernel
/// taps so they vectorise; edge clamping is done by padding with the edge
/// value rather than branching per sample.
fn blur_plane(plane: &mut [f32], tmp: &mut [f32], pad: &mut [f32], w: usize, h: usize, k: &[f32]) {
    let r = k.len() / 2;

    // Horizontal: plane -> tmp.
    for y in 0..h {
        let row = &plane[y * w..(y + 1) * w];
        let p = &mut pad[..w + 2 * r];
        p[..r].fill(row[0]);
        p[r..r + w].copy_from_slice(row);
        p[r + w..].fill(row[w - 1]);
        let out = &mut tmp[y * w..(y + 1) * w];
        out.fill(0.0);
        for (i, &kv) in k.iter().enumerate() {
            for (o, &s) in out.iter_mut().zip(&p[i..i + w]) {
                *o += kv * s;
            }
        }
    }

    // Vertical: tmp -> plane, row-wide axpy with clamped source rows.
    for y in 0..h {
        let out = &mut plane[y * w..(y + 1) * w];
        out.fill(0.0);
        for (i, &kv) in k.iter().enumerate() {
            let sy = (y + i).saturating_sub(r).min(h - 1);
            let src = &tmp[sy * w..(sy + 1) * w];
            for (o, &s) in out.iter_mut().zip(src) {
                *o += kv * s;
            }
        }
    }
}

/// Replace each `block × block` tile of every plane with its mean and write
/// interleaved, rounded 8-bit RGB into `rgb`.
fn pixelate_into(img: &PlanarRgb, block: usize, rgb: &mut [u8]) {
    let (w, h) = (img.width, img.height);
    let n = img.plane_len();
    for by in (0..h).step_by(block) {
        let y1 = (by + block).min(h);
        for bx in (0..w).step_by(block) {
            let x1 = (bx + block).min(w);
            let count = ((y1 - by) * (x1 - bx)) as f32;
            let mut mean = [0u8; 3];
            for (c, m) in mean.iter_mut().enumerate() {
                let plane = &img.data[c * n..(c + 1) * n];
                let mut acc = 0f32;
                for y in by..y1 {
                    acc += plane[y * w + bx..y * w + x1].iter().sum::<f32>();
                }
                *m = (acc / count).round().clamp(0.0, 255.0) as u8;
            }
            for y in by..y1 {
                for x in bx..x1 {
                    let o = (y * w + x) * 3;
                    rgb[o..o + 3].copy_from_slice(&mean);
                }
            }
        }
    }
}

/// Build the blurred, pixelated PNG thumbnail for `frame`. Handles RGBA and
/// BGRA input; alpha is discarded.
pub fn blur_thumbnail(frame: &Frame) -> Result<BlurredThumbnail, DetectError> {
    let (tw, th) = thumbnail_dims(frame.width(), frame.height());
    let (w, h) = (tw as usize, th as usize);

    let mut img = resample_rgb(frame, w, h);
    let kernel = gaussian_kernel(BLUR_SIGMA);
    let r = kernel.len() / 2;
    {
        let n = img.plane_len();
        let mut tmp: Scratch<f32> = Scratch::zeroed(n);
        let mut pad: Scratch<f32> = Scratch::zeroed(w.max(h) + 2 * r);
        for c in 0..3 {
            blur_plane(
                &mut img.data[c * n..(c + 1) * n],
                &mut tmp,
                &mut pad,
                w,
                h,
                &kernel,
            );
        }
    }

    let mut rgb: Scratch<u8> = Scratch::zeroed(w * h * 3);
    pixelate_into(&img, PIXELATE_BLOCK, &mut rgb);
    drop(img);

    let mut png = Vec::new();
    PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::Adaptive)
        .write_image(&rgb, tw, th, ExtendedColorType::Rgb8)
        .map_err(|e| DetectError::Thumbnail(e.to_string()))?;

    Ok(BlurredThumbnail {
        width: tw,
        height: th,
        transform: THUMBNAIL_TRANSFORM.to_owned(),
        png,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_platform::PixelFormat;

    fn frame_from(w: u32, h: u32, f: PixelFormat, px: impl Fn(u32, u32) -> [u8; 4]) -> Frame {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&px(x, y));
            }
        }
        Frame::new(w, h, f, 0, v).unwrap()
    }

    fn decode(t: &BlurredThumbnail) -> image::RgbImage {
        let img = image::load_from_memory_with_format(&t.png, image::ImageFormat::Png).unwrap();
        assert_eq!((img.width(), img.height()), (t.width, t.height));
        img.to_rgb8()
    }

    fn variance(img: &image::RgbImage) -> f64 {
        let vals: Vec<f64> = img.as_raw().iter().map(|&v| f64::from(v)).collect();
        let mean = vals.iter().sum::<f64>() / vals.len() as f64;
        vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64
    }

    #[test]
    fn dims_keep_aspect_and_cap_height() {
        assert_eq!(thumbnail_dims(768, 480), (320, 200));
        assert_eq!(thumbnail_dims(1920, 1080), (320, 180));
        assert_eq!(thumbnail_dims(480, 768), (200, 320));
        assert_eq!(thumbnail_dims(100, 100), (320, 320));
        assert_eq!(thumbnail_dims(1, 1), (320, 320));
        assert_eq!(thumbnail_dims(3, 1000), (1, 320));
        assert_eq!(thumbnail_dims(16384, 1), (320, 1));
    }

    #[test]
    fn kernel_is_normalised_and_symmetric() {
        let k = gaussian_kernel(12.0);
        assert_eq!(k.len(), 73);
        assert!((k.iter().sum::<f32>() - 1.0).abs() < 1e-5);
        for i in 0..k.len() {
            assert!((k[i] - k[k.len() - 1 - i]).abs() < 1e-9);
        }
        assert!(k[36] > k[35] && k[35] > k[0]);
    }

    #[test]
    fn checkerboard_becomes_nearly_uniform() {
        // 1-px black/white checkerboard: maximal high-frequency content.
        let f = frame_from(768, 480, PixelFormat::Rgba8, |x, y| {
            if (x + y) % 2 == 0 {
                [0, 0, 0, 255]
            } else {
                [255, 255, 255, 255]
            }
        });
        let t = blur_thumbnail(&f).unwrap();
        assert_eq!(t.transform, THUMBNAIL_TRANSFORM);
        let img = decode(&t);
        assert!(variance(&img) < 1.0, "variance {}", variance(&img));
        let mean =
            img.as_raw().iter().map(|&v| f64::from(v)).sum::<f64>() / img.as_raw().len() as f64;
        assert!((mean - 127.5).abs() < 2.0);
    }

    #[test]
    fn coarse_checkerboard_is_also_destroyed() {
        // 16-px squares survive a plain resize to 320 px but not σ=12 blur.
        let f = frame_from(768, 480, PixelFormat::Rgba8, |x, y| {
            if (x / 16 + y / 16) % 2 == 0 {
                [0, 0, 0, 255]
            } else {
                [255, 255, 255, 255]
            }
        });
        let img = decode(&blur_thumbnail(&f).unwrap());
        // Input variance is 127.5² ≈ 16256; output must be a tiny fraction.
        assert!(variance(&img) < 50.0, "variance {}", variance(&img));
    }

    #[test]
    fn output_is_blocky() {
        let f = frame_from(640, 400, PixelFormat::Rgba8, |x, y| {
            [(x % 256) as u8, (y % 256) as u8, ((x * y) % 256) as u8, 255]
        });
        let img = decode(&blur_thumbnail(&f).unwrap());
        for by in (0..img.height()).step_by(8) {
            for bx in (0..img.width()).step_by(8) {
                let p0 = *img.get_pixel(bx, by);
                for y in by..(by + 8).min(img.height()) {
                    for x in bx..(bx + 8).min(img.width()) {
                        assert_eq!(*img.get_pixel(x, y), p0);
                    }
                }
            }
        }
    }

    #[test]
    fn large_scale_structure_survives() {
        // The gist should remain: left half dark, right half bright.
        let f = frame_from(768, 480, PixelFormat::Rgba8, |x, _| {
            if x < 384 {
                [20, 20, 20, 255]
            } else {
                [230, 230, 230, 255]
            }
        });
        let img = decode(&blur_thumbnail(&f).unwrap());
        assert!(img.get_pixel(5, 100)[0] < 40);
        assert!(img.get_pixel(314, 100)[0] > 210);
    }

    #[test]
    fn solid_colour_roundtrips_and_bgra_is_handled() {
        let rgba = frame_from(100, 50, PixelFormat::Rgba8, |_, _| [200, 100, 50, 7]);
        let bgra = frame_from(100, 50, PixelFormat::Bgra8, |_, _| [50, 100, 200, 7]);
        for f in [rgba, bgra] {
            let img = decode(&blur_thumbnail(&f).unwrap());
            assert!(img.pixels().all(|p| p.0 == [200, 100, 50]));
        }
    }

    #[test]
    fn small_and_odd_sizes_work() {
        for (w, h) in [
            (1, 1),
            (3, 1000),
            (1000, 3),
            (2, 2),
            (7, 13),
            (321, 1),
            (1, 321),
        ] {
            let f = frame_from(w, h, PixelFormat::Bgra8, |x, y| {
                [(x * 31) as u8, (y * 17) as u8, 9, 255]
            });
            let t = blur_thumbnail(&f).unwrap();
            assert_eq!((t.width, t.height), thumbnail_dims(w, h));
            assert!(t.width <= THUMBNAIL_SIDE && t.height <= THUMBNAIL_SIDE);
            decode(&t);
        }
    }

    /// Timing check for §3.4's CPU budget. Run with
    /// `cargo test --release -p faro-detect -- --ignored --nocapture timing`.
    #[test]
    #[ignore]
    fn timing_dhash_and_thumbnail_768x480() {
        use std::time::Instant;
        let f = frame_from(768, 480, PixelFormat::Bgra8, |x, y| {
            [(x * 7 + y) as u8, (x ^ y) as u8, (y * 3) as u8, 255]
        });
        let iters = 50;
        let _ = blur_thumbnail(&f).unwrap(); // warm up
        let t0 = Instant::now();
        let mut acc = 0u64;
        for _ in 0..iters {
            acc ^= crate::dhash::dhash(&f);
        }
        let dhash_ms = t0.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
        let t0 = Instant::now();
        let mut bytes = 0usize;
        for _ in 0..iters {
            bytes += blur_thumbnail(&f).unwrap().png.len();
        }
        let thumb_ms = t0.elapsed().as_secs_f64() * 1000.0 / f64::from(iters);
        println!(
            "dhash: {dhash_ms:.3} ms/frame, thumbnail: {thumb_ms:.3} ms/frame \
             (avg png {} bytes, {acc:x})",
            bytes / iters as usize
        );
        if !cfg!(debug_assertions) {
            assert!(dhash_ms < 20.0 && thumb_ms < 20.0);
        }
    }
}
