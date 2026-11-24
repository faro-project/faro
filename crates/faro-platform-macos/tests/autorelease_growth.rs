//! Regression: the agent polls these APIs from a long-lived worker thread
//! that has no Objective-C autorelease pool. Before every entry point got
//! its own pool, `active_app()` left ~600 bytes of autoreleased AppKit
//! objects behind per call (tens of MB per day at the agent's tick rate).
//!
//! Measured with `malloc_zone_statistics` (bytes in use across all zones),
//! which is far less noisy than RSS. This file holds a single test so no
//! other test thread allocates while it measures.
#![cfg(target_os = "macos")]

use faro_platform::{ForegroundInfo, ScreenCapture, ServiceHost, TamperSignals};
use faro_platform_macos::{MacForeground, MacPlatform, MacScreenCapture, MacTamper};
use std::time::Instant;

fn bytes_in_use() -> i64 {
    // SAFETY: `malloc_statistics_t` is plain old data; zeroed is valid.
    let mut stats: libc::malloc_statistics_t = unsafe { std::mem::zeroed() };
    // SAFETY: a null zone means "all zones"; `stats` is a valid out-pointer.
    unsafe { libc::malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    i64::try_from(stats.size_in_use).unwrap_or(i64::MAX)
}

/// Bytes retained per call after a warm-up (caches, lazily created framework
/// singletons), corrected for background growth, as the minimum over several
/// measurement windows.
///
/// `malloc_zone_statistics` is process-wide. On CI runners the capture
/// frameworks' background threads (XPC, CoreGraphics) make the process grow
/// steadily *over time*, independent of our calls. Dividing that by the call
/// count blamed whichever API was slow (`capture_all_displays` measured
/// ~70 B/call once, `tamper.poll` 64 B/call in every window of another run),
/// while local runs measure 0. So each window is paired with a control of the
/// same wall-clock length in which nothing is called, and the control's
/// growth is subtracted. A real per-call leak scales with the number of calls
/// and survives the subtraction; time-based drift cancels out. The minimum
/// over windows then removes one-off transients.
fn growth_per_call(mut f: impl FnMut()) -> Measurement {
    const WARMUP: i64 = 100;
    const CALLS: i64 = 400;
    const WINDOWS: usize = 3;
    for _ in 0..WARMUP {
        f();
    }
    (0..WINDOWS)
        .map(|_| {
            let started = Instant::now();
            let before = bytes_in_use();
            for _ in 0..CALLS {
                f();
            }
            let raw = bytes_in_use() - before;
            let elapsed = started.elapsed();
            let control_before = bytes_in_use();
            std::thread::sleep(elapsed);
            let background = bytes_in_use() - control_before;
            Measurement {
                per_call: (raw - background) / CALLS,
                raw_per_call: raw / CALLS,
                background_per_call: background / CALLS,
            }
        })
        .min_by_key(|m| m.per_call)
        .unwrap_or(Measurement {
            per_call: i64::MAX,
            raw_per_call: i64::MAX,
            background_per_call: 0,
        })
}

/// One window's numbers, kept so failures (and `--nocapture` runs) show
/// whether growth came from the calls or from the background.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // raw/background are only read through Debug output.
struct Measurement {
    per_call: i64,
    raw_per_call: i64,
    background_per_call: i64,
}

/// The leak this test was written for retained ~624 B/call (`active_app`)
/// and ~264 B/call (`frontmost_pid`). 128 B/call still catches that class of
/// bug with a margin over residual noise after the background correction.
const MAX_RETAINED_PER_CALL: i64 = 128;

#[test]
fn polling_from_a_pool_less_thread_does_not_accumulate_memory() {
    // A fresh std thread has no autorelease pool, exactly like the agent's
    // tick loop.
    let report = std::thread::spawn(|| {
        let fg = MacForeground::new();
        let mut tamper = MacTamper::new();
        let mut capture = MacScreenCapture::new();
        let host = MacPlatform::service_host();
        vec![
            (
                "active_app",
                growth_per_call(|| {
                    let _ = fg.active_app();
                }),
            ),
            (
                "window_title",
                growth_per_call(|| {
                    let _ = fg.window_title();
                }),
            ),
            (
                "frontmost_pid",
                growth_per_call(|| {
                    let _ = fg.frontmost_pid();
                }),
            ),
            (
                "tamper.poll",
                growth_per_call(|| {
                    let _ = tamper.poll();
                }),
            ),
            (
                "capture_all_displays",
                growth_per_call(|| {
                    let _ = capture.capture_all_displays();
                }),
            ),
            (
                "list_sessions",
                growth_per_call(|| {
                    let _ = host.list_sessions();
                }),
            ),
        ]
    })
    .join()
    .expect("measurement thread");
    // Printed so CI logs show the measured numbers, not just pass/fail.
    eprintln!("bytes retained per call (background-corrected, min of windows): {report:?}");
    for (what, m) in report {
        // Before the fix: active_app ~624 B/call, frontmost_pid ~264 B/call.
        assert!(
            m.per_call < MAX_RETAINED_PER_CALL,
            "{what} retains {} bytes per call on a pool-less thread ({m:?})",
            m.per_call
        );
    }
}
