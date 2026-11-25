//! The synthetic test set: solid colours and UI-like windows, never a
//! real image. The harness tests use it, and `model-bench
//! --write-synthetic-set DIR` writes it so a real model's latency can be
//! measured without any real image. Its labels are the dominant colour's
//! (red is "explicit", green "neutral", blue "suggestive"), so a real
//! model's precision and recall on it mean nothing; only its latency does.

use crate::error::DetectError;
use std::path::Path;

/// Deterministic xorshift, for UI noise.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// An RGB image description.
struct Img {
    w: u32,
    h: u32,
    px: Vec<[u8; 3]>,
}

impl Img {
    fn solid(w: u32, h: u32, c: [u8; 3]) -> Self {
        Img {
            w,
            h,
            px: vec![c; (w * h) as usize],
        }
    }

    fn rect(&mut self, x0: u32, y0: u32, x1: u32, y1: u32, c: [u8; 3]) {
        for y in y0..y1.min(self.h) {
            for x in x0..x1.min(self.w) {
                self.px[(y * self.w + x) as usize] = c;
            }
        }
    }

    /// A window: `bg`, a toolbar, a sidebar, lines of "text" and a content
    /// panel of `accent` covering about `accent_frac` of the window, plus
    /// a little per-pixel noise.
    fn ui(bg: [u8; 3], accent: [u8; 3], accent_frac: f32, seed: u32) -> Self {
        let (w, h) = (160u32, 100u32);
        let mut img = Img::solid(w, h, bg);
        let mut rng = Rng(seed | 1);
        let shade = |c: [u8; 3], d: i32| c.map(|v| (i32::from(v) + d).clamp(0, 255) as u8);
        img.rect(0, 0, w, 10, shade(bg, -30)); // toolbar
        img.rect(0, 10, 24, h, shade(bg, -15)); // sidebar
        for line in 0..8 {
            let y = 16 + line * 10;
            let len = 30 + rng.below(90);
            img.rect(30, y, 30 + len, y + 3, shade(bg, -90)); // text
        }
        let side = ((accent_frac * (w * h) as f32).sqrt()) as u32;
        let (x0, y0) = (w - side.min(w), h - side.min(h));
        img.rect(x0, y0, w, h, accent);
        for p in &mut img.px {
            let n = rng.below(9) as i32 - 4;
            *p = shade(*p, n);
        }
        img
    }

    fn save(&self, path: &Path, color: image::ExtendedColorType) -> Result<(), DetectError> {
        let data: Vec<u8> = match color {
            image::ExtendedColorType::Rgb8 => self.px.iter().flatten().copied().collect(),
            image::ExtendedColorType::Rgba8 => self
                .px
                .iter()
                .flat_map(|&[r, g, b]| [r, g, b, 255])
                .collect(),
            image::ExtendedColorType::L8 => self.px.iter().map(|p| p[0]).collect(),
            other => unreachable!("{other:?}"),
        };
        let io = |source| DetectError::Io {
            path: path.to_owned(),
            source,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let mut out = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut out),
            &data,
            self.w,
            self.h,
            color,
        )
        .map_err(|e| DetectError::Bench(format!("encoding {}: {e}", path.display())))?;
        std::fs::write(path, out).map_err(io)
    }
}

/// Write the synthetic set into `root`: 6 explicit, 6 neutral and 3
/// suggestive images, all solid colours or UI-like windows. The labels are
/// the dominant colour's (red is "explicit"), not the content's.
pub fn write_synthetic_set(root: &Path) -> Result<(), DetectError> {
    use image::ExtendedColorType::{Rgb8, Rgba8, L8};
    let grey = [190, 190, 190];
    let red = [230, 20, 20];
    let blue = [40, 60, 210];
    let green = [40, 180, 60];
    let images: [(&str, Img, image::ExtendedColorType); 15] = [
        (
            "explicit/solid.png",
            Img::solid(96, 64, [220, 30, 30]),
            Rgba8,
        ),
        (
            "explicit/ui-red-panel.png",
            Img::ui(grey, red, 0.7, 1),
            Rgb8,
        ),
        // Larger than MAX_FRAME_SIDE: downscaled first, as in production.
        (
            "explicit/big/dark-red.png",
            Img::solid(1000, 600, [140, 25, 25]),
            Rgba8,
        ),
        (
            "explicit/magenta.png",
            Img::solid(64, 64, [200, 40, 170]),
            Rgba8,
        ),
        // Missed: a mostly grey window with a tiny red patch.
        (
            "explicit/ui-tiny-patch.png",
            Img::ui(grey, red, 0.01, 2),
            Rgba8,
        ),
        // Confused: more blue than red.
        (
            "explicit/violet.png",
            Img::solid(64, 64, [150, 30, 230]),
            Rgba8,
        ),
        ("neutral/grey.png", Img::solid(64, 64, [128, 128, 128]), L8),
        (
            "neutral/ui-light.png",
            Img::ui([235, 235, 235], green, 0.2, 3),
            Rgba8,
        ),
        (
            "neutral/ui-dark.png",
            Img::ui([40, 40, 40], [90, 90, 90], 0.3, 4),
            Rgb8,
        ),
        (
            "neutral/green.png",
            Img::solid(64, 64, [30, 200, 60]),
            Rgba8,
        ),
        (
            "neutral/white.png",
            Img::solid(64, 64, [255, 255, 255]),
            Rgba8,
        ),
        // False positive: orange reads as red.
        (
            "neutral/orange.png",
            Img::solid(64, 64, [230, 90, 40]),
            Rgba8,
        ),
        ("suggestive/blue.png", Img::solid(64, 64, blue), Rgba8),
        (
            "suggestive/ui-blue-panel.png",
            Img::ui(grey, blue, 0.7, 5),
            Rgba8,
        ),
        // Missed: just a grey window.
        (
            "suggestive/ui-plain.png",
            Img::ui([150, 150, 150], [150, 150, 150], 0.0, 6),
            Rgba8,
        ),
    ];
    for (rel, img, color) in images {
        img.save(&root.join(rel), color)?;
    }
    Ok(())
}
