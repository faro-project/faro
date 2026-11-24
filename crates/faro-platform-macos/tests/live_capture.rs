//! Live checks against the real OS.
//!
//! The capture test needs Screen Recording permission for the process that
//! runs `cargo test` (the terminal app), so it is `#[ignore]`d:
//!
//! ```text
//! cargo test -p faro-platform-macos --test live_capture -- --ignored
//! ```
#![cfg(target_os = "macos")]

use faro_platform::{PermissionState, PlatformError, ScreenCapture, MAX_FRAME_SIDE};
use faro_platform_macos::{active_displays, MacPlatform, MacScreenCapture};

#[test]
#[ignore = "needs Screen Recording permission for the terminal running the tests"]
fn captured_frames_are_bounded_and_not_blank() {
    let mut cap = MacScreenCapture::new();
    assert_eq!(
        cap.permission_state(),
        PermissionState::Granted,
        "grant Screen Recording to this terminal in System Settings > Privacy & Security"
    );
    let frames = cap
        .capture_all_displays()
        .expect("capture succeeds with permission");
    assert!(cap.last_failures().is_empty(), "{:?}", cap.last_failures());
    let displays = active_displays().expect("display list");
    assert!(!frames.is_empty(), "no frames for displays {displays:?}");
    for f in &frames {
        assert!(f.width() >= 1 && f.height() >= 1);
        assert!(
            f.width().max(f.height()) <= MAX_FRAME_SIDE,
            "{}x{} exceeds {MAX_FRAME_SIDE}",
            f.width(),
            f.height()
        );
        assert_eq!(
            f.pixels().len(),
            f.width() as usize * f.height() as usize * 4
        );
        assert!(
            f.pixels().iter().any(|&b| b != 0),
            "display {} frame is all zero",
            f.display_id()
        );
        assert!(displays.contains(&f.display_id()));
    }
}

#[test]
fn capture_respects_permission_state() {
    let mut p = MacPlatform::agent_platform();
    match p.capture.permission_state() {
        PermissionState::Granted => {
            // Covered by the ignored test; just make sure it doesn't panic.
            let _ = p.capture.capture_all_displays();
        }
        _ => assert_eq!(
            p.capture.capture_all_displays().unwrap_err(),
            PlatformError::PermissionDenied("screen_recording".into())
        ),
    }
}
