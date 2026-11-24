//! The §10 test that no unblurred frames are kept.
//!
//! An instrumented global allocator (test builds only) checks, per thread:
//!
//! * every *watched* buffer (the frame's pixel buffer, registered by the
//!   test, and every [`Scratch`](crate::scratch::Scratch) buffer, which
//!   registers itself) is all zeroes at the moment it is freed, and is never
//!   moved by `realloc` (which would leave an unzeroized copy behind);
//! * no large (≥ 64 KiB) allocation made while armed is still alive when
//!   `process` returns, i.e. no frame-sized copy is retained anywhere.
//!
//! Soundness: the allocator only reads memory in `dealloc`, only for blocks
//! that were explicitly registered, and only the registered prefix. Every
//! registered prefix is a fully initialised buffer of plain integers/floats
//! (created with `vec![0; n]` or from a filled `Vec<u8>`) that is only ever
//! written with initialised values (including the volatile zeroing writes),
//! and the block is still allocated while `dealloc` runs. No uninitialised
//! or freed memory is ever read.

pub(crate) mod audit {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::{Cell, RefCell};

    const SLOTS: usize = 256;
    /// Allocations at least this large count as "frame-sized".
    pub(crate) const LARGE: usize = 64 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Report {
        pub watched: usize,
        pub freed_zeroed: usize,
        pub freed_dirty: usize,
        pub moved: usize,
        pub overflow: bool,
        pub large_allocs: usize,
        pub large_live: isize,
    }

    const EMPTY: Report = Report {
        watched: 0,
        freed_zeroed: 0,
        freed_dirty: 0,
        moved: 0,
        overflow: false,
        large_allocs: 0,
        large_live: 0,
    };

    struct State {
        armed: Cell<bool>,
        slots: RefCell<[(usize, usize); SLOTS]>,
        report: Cell<Report>,
    }

    thread_local! {
        // `const` init and no destructor: accessing this never allocates,
        // so it is safe to use from inside the allocator.
        static STATE: State = const {
            State {
                armed: Cell::new(false),
                slots: RefCell::new([(0, 0); SLOTS]),
                report: Cell::new(EMPTY),
            }
        };
    }

    fn update(f: impl FnOnce(&mut Report)) {
        let _ = STATE.try_with(|s| {
            let mut r = s.report.get();
            f(&mut r);
            s.report.set(r);
        });
    }

    fn armed() -> bool {
        STATE.try_with(|s| s.armed.get()).unwrap_or(false)
    }

    /// Start auditing on this thread.
    pub(crate) fn arm() {
        let _ = STATE.try_with(|s| {
            s.report.set(EMPTY);
            if let Ok(mut slots) = s.slots.try_borrow_mut() {
                *slots = [(0, 0); SLOTS];
            }
            s.armed.set(true);
        });
    }

    /// Stop auditing and return what was seen.
    pub(crate) fn disarm() -> Report {
        STATE
            .try_with(|s| {
                s.armed.set(false);
                if let Ok(mut slots) = s.slots.try_borrow_mut() {
                    *slots = [(0, 0); SLOTS];
                }
                s.report.get()
            })
            .unwrap_or(EMPTY)
    }

    /// Register a buffer whose first `len` bytes are initialised and must be
    /// zero when it is freed. No-op unless armed on this thread.
    pub(crate) fn watch(ptr: *const u8, len: usize) {
        if !armed() || len == 0 {
            return;
        }
        let _ = STATE.try_with(|s| {
            let stored = s.slots.try_borrow_mut().ok().and_then(|mut slots| {
                let slot = slots.iter_mut().find(|e| e.0 == 0)?;
                *slot = (ptr as usize, len);
                Some(())
            });
            let mut r = s.report.get();
            r.watched += 1;
            r.overflow |= stored.is_none();
            s.report.set(r);
        });
    }

    /// Remove `ptr` from the watch list, returning its registered length.
    fn take_slot(ptr: *mut u8) -> Option<usize> {
        STATE
            .try_with(|s| {
                let mut slots = s.slots.try_borrow_mut().ok()?;
                let slot = slots.iter_mut().find(|e| e.0 == ptr as usize)?;
                let len = slot.1;
                *slot = (0, 0);
                Some(len)
            })
            .ok()
            .flatten()
    }

    fn on_alloc(size: usize) {
        if armed() && size >= LARGE {
            update(|r| {
                r.large_allocs += 1;
                r.large_live += 1;
            });
        }
    }

    /// # Safety
    /// `ptr` must be a live allocation of at least `size` bytes.
    unsafe fn on_dealloc(ptr: *mut u8, size: usize) {
        if !armed() {
            return;
        }
        if size >= LARGE {
            update(|r| r.large_live -= 1);
        }
        if let Some(len) = take_slot(ptr) {
            // SAFETY: see module docs. `ptr` is still allocated, `len` is
            // at most the allocation size and those bytes are initialised.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, len.min(size)) };
            let zero = bytes.iter().all(|&b| b == 0);
            update(|r| {
                if zero {
                    r.freed_zeroed += 1;
                } else {
                    r.freed_dirty += 1;
                }
            });
        }
    }

    fn on_realloc(old: *mut u8, old_size: usize, new_size: usize) {
        if !armed() {
            return;
        }
        if take_slot(old).is_some() {
            update(|r| r.moved += 1);
        }
        if old_size >= LARGE {
            update(|r| r.large_live -= 1);
        }
        on_alloc(new_size);
    }

    pub(crate) struct AuditAlloc;

    // SAFETY: every method forwards to `System` with the caller's arguments;
    // the bookkeeping never allocates, never unwinds and only reads memory
    // as described in the module docs.
    unsafe impl GlobalAlloc for AuditAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(layout) };
            if !p.is_null() {
                on_alloc(layout.size());
            }
            p
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            let p = unsafe { System.alloc_zeroed(layout) };
            if !p.is_null() {
                on_alloc(layout.size());
            }
            p
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe {
                on_dealloc(ptr, layout.size());
                System.dealloc(ptr, layout);
            }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let p = unsafe { System.realloc(ptr, layout, new_size) };
            if !p.is_null() {
                on_realloc(ptr, layout.size(), new_size);
            }
            p
        }
    }

    #[global_allocator]
    static GLOBAL: AuditAlloc = AuditAlloc;
}

use crate::classifier::{Classifier, ImageScores, NullClassifier, ScriptedClassifier};
use crate::context::ContextSignals;
use crate::error::DetectError;
use crate::pipeline::{DetectionOutcome, Detector, DetectorConfig};
use crate::Rating;
use audit::Report;
use faro_platform::{Frame, PixelFormat};
use faro_proto::body::BrowserContext;
use std::collections::HashSet;

/// A distinctive byte pattern whose period (7) is coprime with the pixel
/// size (4), so every channel sees a high-frequency signal.
const PATTERN: [u8; 7] = [0xFA, 0x11, 0xC3, 0x5E, 0x92, 0x07, 0xBD];
const W: u32 = 640;
const H: u32 = 400;
/// Length of the pattern runs searched for in the output.
const RUN: usize = 12;

fn pattern_bytes() -> Vec<u8> {
    (0..(W * H * 4) as usize)
        .map(|i| PATTERN[i % PATTERN.len()])
        .collect()
}

/// Every `RUN`-byte window of a periodic stream (one period plus a window
/// is enough to see them all).
fn windows(stream: &[u8]) -> HashSet<Vec<u8>> {
    stream[..28 * 4 + RUN]
        .windows(RUN)
        .map(<[u8]>::to_vec)
        .collect()
}

fn contains_any(hay: &[u8], needles: &HashSet<Vec<u8>>) -> bool {
    hay.windows(RUN).any(|w| needles.contains(w))
}

/// Allocate the patterned frame (while armed), run `f` on it, and audit.
fn audited(
    f: impl FnOnce(Frame) -> Result<DetectionOutcome, DetectError>,
) -> (Result<DetectionOutcome, DetectError>, Report) {
    audit::arm();
    let pixels = pattern_bytes();
    audit::watch(pixels.as_ptr(), pixels.len());
    let frame = Frame::new(W, H, PixelFormat::Bgra8, 0, pixels).unwrap();
    let out = f(frame);
    (out, audit::disarm())
}

fn assert_clean_report(r: &Report, min_watched: usize) {
    assert!(!r.overflow, "{r:?}");
    assert_eq!(
        r.freed_dirty, 0,
        "a pixel-derived buffer was freed unzeroized: {r:?}"
    );
    assert_eq!(r.moved, 0, "a pixel-derived buffer was reallocated: {r:?}");
    assert_eq!(
        r.freed_zeroed, r.watched,
        "a pixel-derived buffer outlived process: {r:?}"
    );
    assert!(r.watched >= min_watched, "{r:?}");
    assert!(r.large_allocs >= 1, "the frame itself must be seen: {r:?}");
    assert_eq!(
        r.large_live, 0,
        "a frame-sized allocation survived process: {r:?}"
    );
}

#[test]
fn no_unblurred_frames_survive_a_high_rated_capture() {
    let classifier = ScriptedClassifier::new(ImageScores::new([("explicit", 0.99)]).unwrap());
    let mut d = Detector::new(&DetectorConfig::default(), Box::new(classifier), None).unwrap();
    let ctx = ContextSignals {
        window_title: Some("title".into()),
        browser: Some(BrowserContext {
            url: Some("https://example.test/".into()),
            title: None,
            incognito: false,
        }),
        ..Default::default()
    };

    let (out, report) = audited(|frame| d.process(frame, &ctx));
    let outcome = out.unwrap();
    assert_eq!(outcome.rating, Rating::High);
    // Frame + resample (2) + blur (2) + pixelated RGB.
    assert_clean_report(&report, 6);

    let thumb = outcome
        .thumbnail
        .as_ref()
        .expect("high rating has a thumbnail");
    let rgba = pattern_bytes();
    let rgb_in: Vec<u8> = rgba
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]]) // BGRA → RGB
        .collect();
    let mut needles = windows(&rgba);
    needles.extend(windows(&rgb_in));
    needles.extend(windows(
        &rgba
            .chunks_exact(4)
            .flat_map(|p| [p[0], p[1], p[2]])
            .collect::<Vec<_>>(),
    ));

    // 1. The serialized outcome (what would be encrypted and sent).
    let json = serde_json::to_vec(&outcome).unwrap();
    assert!(!contains_any(&json, &needles));
    // 2. The PNG bytes, recovered from the JSON's base64.
    let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let b64 = v["thumbnail"]["png"].as_str().unwrap();
    let png = faro_proto::encoding::b64_decode(b64).unwrap();
    assert_eq!(png, thumb.png);
    assert!(!contains_any(&png, &needles));
    // 3. The decoded thumbnail pixels.
    let img = image::load_from_memory_with_format(&png, image::ImageFormat::Png)
        .unwrap()
        .to_rgb8();
    assert_eq!((img.width(), img.height()), (thumb.width, thumb.height));
    assert!(!contains_any(img.as_raw(), &needles));

    // 4. The pixels are far from the input: the pattern's mean absolute
    //    deviation is ~76 per channel; the thumbnail is nearly uniform.
    let (tw, th) = (img.width() as usize, img.height() as usize);
    let mut mad = 0f64;
    for (i, p) in img.pixels().enumerate() {
        let (x, y) = (i % tw, i / tw);
        let sx = x * W as usize / tw;
        let sy = y * H as usize / th;
        let src = &rgb_in[(sy * W as usize + sx) * 3..][..3];
        for c in 0..3 {
            mad += (f64::from(p[c]) - f64::from(src[c])).abs();
        }
    }
    mad /= (tw * th * 3) as f64;
    assert!(mad > 50.0, "thumbnail too close to input: MAD {mad}");
    let mean = img.as_raw().iter().map(|&b| f64::from(b)).sum::<f64>() / img.as_raw().len() as f64;
    let var = img
        .as_raw()
        .iter()
        .map(|&b| (f64::from(b) - mean).powi(2))
        .sum::<f64>()
        / img.as_raw().len() as f64;
    assert!(var < 4.0, "thumbnail retains structure: variance {var}");
}

#[test]
fn frame_is_zeroized_on_clean_and_error_paths() {
    // Clean: no thumbnail is built, the frame is still zeroized and freed.
    let mut d = Detector::new(
        &DetectorConfig::default(),
        Box::new(NullClassifier::new()),
        None,
    )
    .unwrap();
    let (out, report) = audited(|frame| d.process(frame, &ContextSignals::default()));
    let o = out.unwrap();
    assert_eq!(o.rating, Rating::Clean);
    assert!(o.thumbnail.is_none());
    assert_clean_report(&report, 1);

    // Classifier error: the `?` path must still destroy the frame.
    let mut c = ScriptedClassifier::new(ImageScores::empty());
    c.push_error("boom");
    let mut d = Detector::new(&DetectorConfig::default(), Box::new(c), None).unwrap();
    let (out, report) = audited(|frame| d.process(frame, &ContextSignals::default()));
    assert!(out.is_err());
    assert_clean_report(&report, 1);
}

#[test]
fn preprocess_output_is_zeroized() {
    let mut info = NullClassifier::new().info().clone();
    info.input_size = crate::InputSize {
        width: 224,
        height: 224,
    };
    audit::arm();
    let pixels = pattern_bytes();
    audit::watch(pixels.as_ptr(), pixels.len());
    let frame = Frame::new(W, H, PixelFormat::Rgba8, 0, pixels).unwrap();
    let tensor = crate::classifier::preprocess(&frame, &info);
    assert_eq!(tensor.len(), 3 * 224 * 224);
    drop(tensor);
    drop(frame);
    let r = audit::disarm();
    assert_clean_report(&r, 3);
}

/// The audit must actually catch violations, or the tests above prove
/// nothing.
#[test]
fn audit_detects_violations() {
    audit::arm();
    let leaky = vec![7u8; 100];
    audit::watch(leaky.as_ptr(), leaky.len());
    drop(leaky); // freed without zeroizing
    let r = audit::disarm();
    assert_eq!((r.freed_dirty, r.freed_zeroed), (1, 0));

    audit::arm();
    let mut grows = Vec::with_capacity(4);
    grows.extend_from_slice(&[1u8; 4]);
    audit::watch(grows.as_ptr(), grows.len());
    grows.extend_from_slice(&[2u8; 4096]); // forces realloc
    let r = audit::disarm();
    assert_eq!(r.moved, 1);
    drop(grows);

    audit::arm();
    let kept = vec![0u8; audit::LARGE];
    let r = audit::disarm();
    assert_eq!(r.large_live, 1);
    drop(kept);

    audit::arm();
    let mut z = zeroize::Zeroizing::new(vec![9u8; 100]);
    audit::watch(z.as_ptr(), z.len());
    z[0] = 1;
    drop(z);
    let r = audit::disarm();
    assert_eq!((r.freed_dirty, r.freed_zeroed), (0, 1));
}
