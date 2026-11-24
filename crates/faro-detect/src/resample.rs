//! Area-average resampling of a 4-byte-per-pixel frame into planar RGB `f32`.
//!
//! Shared by the thumbnail builder and the classifier preprocessor. Area
//! averaging (each output pixel is the coverage-weighted mean of the source
//! pixels under it) is alias-free when downscaling, which matters for both
//! users: aliasing would let fine detail survive into the thumbnail, and it
//! skews classifier inputs. Upscaling (tiny frames) degrades gracefully to a
//! blocky nearest-neighbour with blended edges.
//!
//! The filter is separable: a horizontal pass into a planar intermediate,
//! then a vertical pass written as row-wide `axpy`s, which the compiler
//! vectorises.

use crate::scratch::Scratch;
use faro_platform::{Frame, PixelFormat};

/// Planar RGB image with values in `[0, 255]`. Plane `c` occupies
/// `data[c * w * h .. (c + 1) * w * h]`, rows tightly packed.
pub(crate) struct PlanarRgb {
    pub width: usize,
    pub height: usize,
    pub data: Scratch<f32>,
}

impl PlanarRgb {
    pub(crate) fn plane_len(&self) -> usize {
        self.width * self.height
    }
}

/// One output sample's contributing source range and weights.
struct Taps {
    start: usize,
    weights: Vec<f32>,
}

/// Coverage weights for mapping `src` samples onto `dst` samples. Only
/// geometry, never pixel data, so plain `Vec`s are fine here.
fn area_taps(src: usize, dst: usize) -> Vec<Taps> {
    let scale = src as f64 / dst as f64;
    (0..dst)
        .map(|i| {
            let lo = i as f64 * scale;
            let hi = ((i + 1) as f64 * scale).min(src as f64);
            let first = (lo.floor() as usize).min(src - 1);
            let last = ((hi.ceil() as usize).max(first + 1)).min(src);
            let mut weights: Vec<f32> = (first..last)
                .map(|j| {
                    let a = lo.max(j as f64);
                    let b = hi.min((j + 1) as f64);
                    (b - a).max(0.0) as f32
                })
                .collect();
            let sum: f32 = weights.iter().sum();
            if sum > 0.0 {
                weights.iter_mut().for_each(|w| *w /= sum);
            } else {
                // Degenerate interval (cannot happen for src, dst >= 1, but
                // never divide by zero on a geometry corner case).
                weights.iter_mut().for_each(|w| *w = 0.0);
                if let Some(w) = weights.first_mut() {
                    *w = 1.0;
                }
            }
            Taps {
                start: first,
                weights,
            }
        })
        .collect()
}

/// Byte offsets of R, G, B within a pixel for the given format.
pub(crate) fn rgb_offsets(format: PixelFormat) -> [usize; 3] {
    match format {
        PixelFormat::Rgba8 => [0, 1, 2],
        PixelFormat::Bgra8 => [2, 1, 0],
    }
}

/// Resample `frame` to `dw × dh` planar RGB (alpha dropped). `dw`, `dh` are
/// clamped to at least 1.
pub(crate) fn resample_rgb(frame: &Frame, dw: usize, dh: usize) -> PlanarRgb {
    let (dw, dh) = (dw.max(1), dh.max(1));
    let (sw, sh) = (frame.width() as usize, frame.height() as usize);
    let px = frame.pixels();
    let offs = rgb_offsets(frame.format());

    let htaps = area_taps(sw, dw);
    let vtaps = area_taps(sh, dh);

    // Horizontal pass: sh rows × dw columns, planar.
    let mid_plane = sh * dw;
    let mut mid: Scratch<f32> = Scratch::zeroed(mid_plane * 3);
    for y in 0..sh {
        let row = &px[y * sw * 4..(y + 1) * sw * 4];
        for (x, t) in htaps.iter().enumerate() {
            let mut acc = [0f32; 3];
            for (k, &w) in t.weights.iter().enumerate() {
                let p = (t.start + k) * 4;
                for c in 0..3 {
                    acc[c] += w * f32::from(row[p + offs[c]]);
                }
            }
            for c in 0..3 {
                mid[c * mid_plane + y * dw + x] = acc[c];
            }
        }
    }

    // Vertical pass: row-wide axpy per tap.
    let out_plane = dw * dh;
    let mut out: Scratch<f32> = Scratch::zeroed(out_plane * 3);
    for c in 0..3 {
        let src = &mid[c * mid_plane..(c + 1) * mid_plane];
        let dst = &mut out[c * out_plane..(c + 1) * out_plane];
        for (y, t) in vtaps.iter().enumerate() {
            let drow = &mut dst[y * dw..(y + 1) * dw];
            for (k, &w) in t.weights.iter().enumerate() {
                let sy = t.start + k;
                let srow = &src[sy * dw..(sy + 1) * dw];
                for (d, &s) in drow.iter_mut().zip(srow) {
                    *d += w * s;
                }
            }
        }
    }

    PlanarRgb {
        width: dw,
        height: dh,
        data: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, f: PixelFormat, px: impl Fn(u32, u32) -> [u8; 4]) -> Frame {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&px(x, y));
            }
        }
        Frame::new(w, h, f, 0, v).unwrap()
    }

    #[test]
    fn taps_sum_to_one_and_stay_in_bounds() {
        for (s, d) in [
            (1, 1),
            (1, 320),
            (3, 1),
            (768, 320),
            (1000, 7),
            (7, 1000),
            (321, 320),
        ] {
            let taps = area_taps(s, d);
            assert_eq!(taps.len(), d);
            for t in &taps {
                let sum: f32 = t.weights.iter().sum();
                assert!((sum - 1.0).abs() < 1e-4, "{s}->{d}: {sum}");
                assert!(t.start + t.weights.len() <= s);
            }
        }
    }

    #[test]
    fn solid_colour_preserved_and_alpha_dropped() {
        let f = frame(37, 11, PixelFormat::Rgba8, |_, _| [10, 200, 30, 0]);
        let out = resample_rgb(&f, 8, 5);
        let n = out.plane_len();
        for (c, want) in [10.0f32, 200.0, 30.0].iter().enumerate() {
            assert!(out.data[c * n..(c + 1) * n]
                .iter()
                .all(|v| (v - want).abs() < 1e-3));
        }
    }

    #[test]
    fn bgra_is_swizzled() {
        let f = frame(4, 4, PixelFormat::Bgra8, |_, _| [1, 2, 3, 4]);
        let out = resample_rgb(&f, 2, 2);
        assert!((out.data[0] - 3.0).abs() < 1e-4); // R plane from byte 2
        assert!((out.data[4] - 2.0).abs() < 1e-4);
        assert!((out.data[8] - 1.0).abs() < 1e-4);
    }

    #[test]
    fn downscale_averages() {
        // Left half black, right half white: 2-wide output must be 0 / 255.
        let f = frame(10, 2, PixelFormat::Rgba8, |x, _| {
            if x < 5 {
                [0, 0, 0, 255]
            } else {
                [255, 255, 255, 255]
            }
        });
        let out = resample_rgb(&f, 2, 1);
        assert!(out.data[0].abs() < 1e-3);
        assert!((out.data[1] - 255.0).abs() < 1e-3);
        // 1-wide output is the mean.
        let out = resample_rgb(&f, 1, 1);
        assert!((out.data[0] - 127.5).abs() < 1e-3);
    }
}
