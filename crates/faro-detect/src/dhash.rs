//! 64-bit difference hash (dHash) and the per-display deduper (§3.4).
//!
//! Most captures show the same thing as the previous one (a document being
//! read, a paused video). Running the classifier on them wastes CPU against
//! the "under 1% average CPU" budget, so the pipeline hashes every frame
//! and reuses the previous classification when the hash is close enough.
//!
//! dHash: convert to grayscale, area-average down to a 9×8 grid, and emit
//! one bit per horizontally adjacent pair (`left > right`), row-major, most
//! significant bit first. It is robust to scaling, brightness shifts and
//! compression noise, and a 64-bit hash reveals nothing usable about the
//! picture, so it may leave the device inside a
//! [`DetectionOutcome`](crate::DetectionOutcome).

use faro_platform::Frame;
use zeroize::Zeroize;

use crate::resample::rgb_offsets;

/// Default maximum Hamming distance at which two frames count as unchanged.
pub const DEFAULT_DEDUPE_THRESHOLD: u32 = 4;

/// Default number of displays the deduper remembers (least recently used
/// entries are evicted beyond this).
pub const DEFAULT_DEDUPE_CAPACITY: usize = 16;

const GRID_W: usize = 9;
const GRID_H: usize = 8;

/// Half-open source range covered by grid cell `i` of `n` over `len`
/// samples. Ranges never empty, so frames smaller than the grid still hash.
fn cell_range(i: usize, n: usize, len: usize) -> (usize, usize) {
    let lo = i * len / n;
    let hi = ((i + 1) * len / n).max(lo + 1).min(len);
    (lo, hi)
}

/// Compute the 64-bit dHash of a frame.
pub fn dhash(frame: &Frame) -> u64 {
    let (w, h) = (frame.width() as usize, frame.height() as usize);
    let px = frame.pixels();
    let [ro, go, bo] = rgb_offsets(frame.format());

    let xr: [(usize, usize); GRID_W] = std::array::from_fn(|i| cell_range(i, GRID_W, w));
    let yr: [(usize, usize); GRID_H] = std::array::from_fn(|i| cell_range(i, GRID_H, h));

    // A 9×8 grayscale thumbnail is still pixel-derived: zeroize it too.
    let mut sums = [0u64; GRID_W * GRID_H];
    let mut counts = [0u64; GRID_W * GRID_H];
    for (cy, &(y0, y1)) in yr.iter().enumerate() {
        for y in y0..y1 {
            let row = &px[y * w * 4..(y + 1) * w * 4];
            for (cx, &(x0, x1)) in xr.iter().enumerate() {
                let mut acc = 0u64;
                for p in row[x0 * 4..x1 * 4].as_chunks::<4>().0 {
                    // BT.601 luma, 8-bit fixed point.
                    acc += (77 * u64::from(p[ro]) + 150 * u64::from(p[go]) + 29 * u64::from(p[bo]))
                        >> 8;
                }
                sums[cy * GRID_W + cx] += acc;
                counts[cy * GRID_W + cx] += (x1 - x0) as u64;
            }
        }
    }

    let mut hash = 0u64;
    for cy in 0..GRID_H {
        for cx in 0..GRID_W - 1 {
            let (a, b) = (cy * GRID_W + cx, cy * GRID_W + cx + 1);
            // Compare means without division: sa/ca > sb/cb ⇔ sa·cb > sb·ca.
            let left = u128::from(sums[a]) * u128::from(counts[b]);
            let right = u128::from(sums[b]) * u128::from(counts[a]);
            hash = (hash << 1) | u64::from(left > right);
        }
    }
    sums.zeroize();
    hash
}

/// Number of differing bits between two hashes.
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Result of asking the [`Deduper`] about a new frame.
#[derive(Debug, Clone, PartialEq)]
pub enum DedupeDecision<T> {
    /// Close enough to the last classified frame on this display: reuse.
    Unchanged { previous: T, distance: u32 },
    /// No usable previous result: classify this frame.
    Changed,
}

#[derive(Debug)]
struct Entry<T> {
    display_id: u32,
    hash: u64,
    value: T,
    last_used: u64,
}

/// Remembers, per display, the hash of the last *classified* frame and its
/// result.
///
/// The reference hash is only replaced by [`Deduper::record`], i.e. when a
/// frame was actually classified, never on an `Unchanged` hit. Otherwise a
/// slow drift (each step within the threshold) could carry a stale result
/// arbitrarily far from what was classified, e.g. a page slowly scrolling
/// from harmless to explicit content.
#[derive(Debug)]
pub struct Deduper<T> {
    threshold: u32,
    capacity: usize,
    tick: u64,
    entries: Vec<Entry<T>>,
}

impl<T: Clone> Default for Deduper<T> {
    fn default() -> Self {
        Self::new(DEFAULT_DEDUPE_THRESHOLD)
    }
}

impl<T: Clone> Deduper<T> {
    pub fn new(threshold: u32) -> Self {
        Self::with_capacity(threshold, DEFAULT_DEDUPE_CAPACITY)
    }

    /// `capacity` bounds memory if a misbehaving agent invents display ids.
    pub fn with_capacity(threshold: u32, capacity: usize) -> Self {
        Deduper {
            threshold,
            capacity: capacity.max(1),
            tick: 0,
            entries: Vec::new(),
        }
    }

    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Is `hash` within the threshold of the last classified frame on
    /// `display_id`?
    pub fn check(&mut self, display_id: u32, hash: u64) -> DedupeDecision<T> {
        self.tick += 1;
        let tick = self.tick;
        let threshold = self.threshold;
        match self.entries.iter_mut().find(|e| e.display_id == display_id) {
            Some(e) => {
                let distance = hamming(e.hash, hash);
                if distance <= threshold {
                    e.last_used = tick;
                    DedupeDecision::Unchanged {
                        previous: e.value.clone(),
                        distance,
                    }
                } else {
                    DedupeDecision::Changed
                }
            }
            None => DedupeDecision::Changed,
        }
    }

    /// Store the result of classifying a frame with `hash` on `display_id`.
    pub fn record(&mut self, display_id: u32, hash: u64, value: T) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(e) = self.entries.iter_mut().find(|e| e.display_id == display_id) {
            e.hash = hash;
            e.value = value;
            e.last_used = tick;
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some(lru) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
            {
                self.entries.swap_remove(lru);
            }
        }
        self.entries.push(Entry {
            display_id,
            hash,
            value,
            last_used: tick,
        });
    }

    /// Forget one display (e.g. it was disconnected).
    pub fn forget(&mut self, display_id: u32) {
        self.entries.retain(|e| e.display_id != display_id);
    }

    /// Forget everything, e.g. after the classifier model changed so old
    /// results no longer apply.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_platform::PixelFormat;
    use proptest::prelude::*;

    fn frame_from(w: u32, h: u32, f: PixelFormat, px: impl Fn(u32, u32) -> [u8; 4]) -> Frame {
        let mut v = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&px(x, y));
            }
        }
        Frame::new(w, h, f, 0, v).unwrap()
    }

    fn gradient(w: u32, h: u32) -> Frame {
        frame_from(w, h, PixelFormat::Rgba8, |x, _| {
            let v = (255 - x * 255 / w.max(1)) as u8;
            [v, v, v, 255]
        })
    }

    #[test]
    fn uniform_frame_hashes_to_zero() {
        let f = frame_from(100, 60, PixelFormat::Rgba8, |_, _| [90, 90, 90, 255]);
        assert_eq!(dhash(&f), 0);
    }

    #[test]
    fn left_bright_gradient_sets_all_bits() {
        assert_eq!(dhash(&gradient(640, 400)), u64::MAX);
    }

    #[test]
    fn scale_invariant() {
        let a = dhash(&gradient(640, 400));
        let b = dhash(&gradient(320, 200));
        assert!(hamming(a, b) <= 2);
    }

    #[test]
    fn brightness_shift_invariant() {
        let pat = |x: u32, y: u32| ((x / 40 * 37 + y / 30 * 91) % 200) as u8;
        let a = frame_from(360, 240, PixelFormat::Rgba8, |x, y| {
            let v = pat(x, y);
            [v, v, v, 255]
        });
        let b = frame_from(360, 240, PixelFormat::Rgba8, |x, y| {
            let v = pat(x, y) + 40;
            [v, v, v, 255]
        });
        assert_eq!(dhash(&a), dhash(&b));
    }

    #[test]
    fn rgba_and_bgra_of_same_image_agree() {
        let px = |x: u32, y: u32| [(x * 7) as u8, (y * 3) as u8, (x * y) as u8, 255];
        let a = frame_from(50, 40, PixelFormat::Rgba8, px);
        let b = frame_from(50, 40, PixelFormat::Bgra8, |x, y| {
            let [r, g, b, a] = px(x, y);
            [b, g, r, a]
        });
        assert_eq!(dhash(&a), dhash(&b));
    }

    #[test]
    fn tiny_frames_do_not_panic() {
        for (w, h) in [(1, 1), (1, 100), (100, 1), (8, 7), (9, 8), (3, 1000)] {
            let f = frame_from(w, h, PixelFormat::Rgba8, |x, y| [(x ^ y) as u8; 4]);
            let _ = dhash(&f);
        }
    }

    #[test]
    fn different_content_differs() {
        let a = dhash(&gradient(200, 100));
        let b = dhash(&frame_from(200, 100, PixelFormat::Rgba8, |x, _| {
            let v = (x * 255 / 200) as u8;
            [v, v, v, 255]
        }));
        assert!(hamming(a, b) > 32);
    }

    #[test]
    fn hamming_basics() {
        assert_eq!(hamming(0, 0), 0);
        assert_eq!(hamming(0, u64::MAX), 64);
        assert_eq!(hamming(0b1010, 0b0110), 2);
    }

    #[test]
    fn deduper_threshold_is_inclusive() {
        let mut d = Deduper::new(4);
        assert_eq!(d.check(0, 0), DedupeDecision::Changed);
        d.record(0, 0, "first");
        assert_eq!(
            d.check(0, 0b1111),
            DedupeDecision::Unchanged {
                previous: "first",
                distance: 4
            }
        );
        assert_eq!(d.check(0, 0b11111), DedupeDecision::Changed);
    }

    #[test]
    fn deduper_is_per_display() {
        let mut d = Deduper::new(4);
        d.record(1, 0, 'a');
        d.record(2, u64::MAX, 'b');
        assert!(matches!(
            d.check(1, 0),
            DedupeDecision::Unchanged { previous: 'a', .. }
        ));
        assert!(matches!(
            d.check(2, u64::MAX),
            DedupeDecision::Unchanged { previous: 'b', .. }
        ));
        assert_eq!(d.check(3, 0), DedupeDecision::Changed);
        d.forget(1);
        assert_eq!(d.check(1, 0), DedupeDecision::Changed);
    }

    #[test]
    fn deduper_does_not_drift_on_hits() {
        // Each step is within the threshold of the previous frame, but the
        // reference stays the classified hash, so drift is caught.
        let mut d = Deduper::new(4);
        d.record(0, 0, ());
        let mut h = 0u64;
        let mut changed_at = None;
        for step in 0..10 {
            h = (h << 2) | 0b11; // two more bits each step
            if d.check(0, h) == DedupeDecision::Changed {
                changed_at = Some(step);
                break;
            }
        }
        assert_eq!(changed_at, Some(2), "drift beyond 4 bits must reclassify");
    }

    #[test]
    fn deduper_capacity_evicts_lru() {
        let mut d = Deduper::with_capacity(0, 2);
        d.record(1, 1, 1);
        d.record(2, 2, 2);
        let _ = d.check(1, 1); // touch 1
        d.record(3, 3, 3); // evicts 2
        assert_eq!(d.len(), 2);
        assert_eq!(d.check(2, 2), DedupeDecision::Changed);
        assert!(matches!(d.check(1, 1), DedupeDecision::Unchanged { .. }));
        assert!(matches!(d.check(3, 3), DedupeDecision::Unchanged { .. }));
        d.clear();
        assert!(d.is_empty());
    }

    proptest! {
        #[test]
        fn hamming_is_a_metric(a: u64, b: u64, c: u64) {
            prop_assert_eq!(hamming(a, a), 0);
            prop_assert_eq!(hamming(a, b), hamming(b, a));
            prop_assert!(hamming(a, c) <= hamming(a, b) + hamming(b, c));
        }

        #[test]
        fn dhash_never_panics(w in 1u32..40, h in 1u32..40, seed: u32) {
            let f = frame_from(w, h, PixelFormat::Bgra8, |x, y| {
                let v = x.wrapping_mul(2654435761).wrapping_add(y.wrapping_mul(seed | 1));
                v.to_le_bytes()
            });
            let _ = dhash(&f);
        }
    }
}
