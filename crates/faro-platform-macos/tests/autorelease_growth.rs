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

fn bytes_in_use() -> i64 {
    // SAFETY: `malloc_statistics_t` is plain old data; zeroed is valid.
    let mut stats: libc::malloc_statistics_t = unsafe { std::mem::zeroed() };
    // SAFETY: a null zone means "all zones"; `stats` is a valid out-pointer.
    unsafe { libc::malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    i64::try_from(stats.size_in_use).unwrap_or(i64::MAX)
}

/// Bytes retained per call after a warm-up (caches, lazily created framework
/// singletons), as the **minimum over several measurement windows**.
///
/// `malloc_zone_statistics` is process-wide, and the capture frameworks
/// allocate on their own background threads (XPC, CoreGraphics), so a single
/// window can pick up unrelated transient allocations: on slow CI runners one
/// window occasionally measured ~70 B/call where local runs measure 0. A real
/// per-call leak grows by the same amount in *every* window, so the minimum
/// still catches it, while transient noise does not survive the minimum.
fn growth_per_call(mut f: impl FnMut()) -> i64 {
    const WARMUP: i64 = 100;
    const CALLS: i64 = 500;
    const WINDOWS: usize = 3;
    for _ in 0..WARMUP {
        f();
    }
    (0..WINDOWS)
        .map(|_| {
            let before = bytes_in_use();
            for _ in 0..CALLS {
                f();
            }
            (bytes_in_use() - before) / CALLS
        })
        .min()
        .unwrap_or(i64::MAX)
}

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
    eprintln!("bytes retained per call (min of windows): {report:?}");
    for (what, per_call) in report {
        // Before the fix: active_app ~624 B/call, frontmost_pid ~264 B/call.
        assert!(
            per_call < 64,
            "{what} retains {per_call} bytes per call on a pool-less thread"
        );
    }
}
