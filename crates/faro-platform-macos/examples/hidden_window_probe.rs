//! Lists the on-screen windows' capture state and what the agent would
//! report about them (ARCHITECTURE.md §3.7), for checking by hand:
//!
//! ```text
//! cargo run -p faro-platform-macos --example hidden_window_probe [--hide]
//! ```
//!
//! `--hide` first opens a 500 × 400 window of the probe's own with
//! `sharingType = .none`, and the probe's own windows are not skipped, so
//! the whole path (window list, decision, signal) can be seen working on
//! any Mac. A process always reads its own windows' real state; other
//! apps' windows read "not shared" unless the process running the probe
//! (the terminal app) has Screen Recording permission.
//!
//! Window titles are never read or printed.

#[cfg(target_os = "macos")]
fn main() {
    use faro_platform_macos::hidden_windows::{
        is_allowed_os_process, looks_unreliable, on_screen_windows, read, resolve_process,
        HiddenWindowTracker,
    };
    use faro_platform_macos::screen_capture_permission;
    use objc2::rc::autoreleasepool;
    use objc2::MainThreadMarker;
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSBackingStoreType, NSWindow,
        NSWindowSharingType, NSWindowStyleMask,
    };
    use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop};
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    let hide = std::env::args().any(|a| a == "--hide");
    let mtm = MainThreadMarker::new().expect("main runs on the main thread");
    let _window = hide.then(|| {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        let rect = NSRect::new(NSPoint::new(200.0, 200.0), NSSize::new(500.0, 400.0));
        // SAFETY: called on the main thread with a valid rect and style.
        let w = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc(),
                rect,
                NSWindowStyleMask::Titled,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        // SAFETY: we keep our own reference and never close the window.
        unsafe { w.setReleasedWhenClosed(false) };
        w.setTitle(&NSString::from_str("Hidden from capture (probe)"));
        w.setSharingType(NSWindowSharingType::None);
        app.finishLaunching();
        w.orderFrontRegardless();
        // Let the window server put the new window on screen.
        // SAFETY: an immutable framework static.
        let mode = unsafe { kCFRunLoopDefaultMode };
        CFRunLoop::run_in_mode(mode, 1.0, false);
        w
    });

    println!("screen recording: {:?}", screen_capture_permission());
    let own = std::process::id() as i32;
    autoreleasepool(|_| {
        let windows = on_screen_windows();
        for w in &windows {
            let p = resolve_process(w.pid);
            let note = if w.pid == own {
                " (this probe)"
            } else if is_allowed_os_process(&p) {
                " (macOS, allowed)"
            } else {
                ""
            };
            println!(
                "sharing={} layer={:>3} alpha={:.2} {:>5.0}x{:<5.0} {}{}",
                w.sharing,
                w.layer,
                w.alpha,
                w.width,
                w.height,
                w.owner_name.as_deref().unwrap_or("?"),
                note
            );
        }
        let report = |label: &str, windows: &[_], skip: i32| {
            let reading = read(windows, skip, resolve_process);
            let mut tracker = HiddenWindowTracker::new();
            tracker.observe(&reading);
            println!("{label}:");
            println!("  looks unreliable: {}", looks_unreliable(windows, skip));
            println!("  reading: {reading:?}");
            println!("  signals: {:?}", tracker.observe(&reading));
        };
        report("as the agent sees it", &windows, own);
        if hide {
            // Pid 0 is never a real owner, so nothing is skipped. Our own
            // windows read their real state even without Screen Recording.
            let mine: Vec<_> = windows.iter().filter(|w| w.pid == own).cloned().collect();
            report("this probe's own windows, not skipped", &mine, 0);
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("hidden_window_probe is macOS-only");
}
