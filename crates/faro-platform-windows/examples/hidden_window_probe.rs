//! Lists the visible windows' capture affinity and what the agent would
//! report about them (ARCHITECTURE.md §3.7), for checking by hand:
//!
//! ```text
//! cargo run -p faro-platform-windows --example hidden_window_probe [--hide [--hold SECS]]
//! ```
//!
//! `--hide` first opens a 500 × 400 window of the probe's own with
//! `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, and reads the
//! probe's own windows without skipping them, so the whole path (window
//! list, decision, signal) can be seen working on any machine. With
//! `--hold SECS` the window stays up that long afterwards, so a second run
//! without `--hide` can check that another process's hidden window is seen.
//!
//! Window titles are never read or printed. Only windows that are hidden
//! from capture are listed by app; the rest are counted.

#[cfg(windows)]
fn main() {
    use faro_platform_windows::tamper::{
        is_allowed_os_process, on_screen_windows, read, resolve_process, system_root,
        HiddenWindowTracker,
    };
    use windows::core::w;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, PeekMessageW, RegisterClassW,
        SetWindowDisplayAffinity, ShowWindow, TranslateMessage, MSG, PM_REMOVE, SW_SHOWNOACTIVATE,
        WDA_EXCLUDEFROMCAPTURE, WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPEDWINDOW,
    };

    unsafe extern "system" fn wndproc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        // SAFETY: default handling of every message.
        unsafe { DefWindowProcW(h, m, w, l) }
    }

    let args: Vec<String> = std::env::args().collect();
    let hide = args.iter().any(|a| a == "--hide");
    let hold: u64 = args
        .iter()
        .position(|a| a == "--hold")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let own = std::process::id();
    if hide {
        // SAFETY: standard window class registration and creation with
        // valid, 'static strings; the window lives until the process exits.
        unsafe {
            let inst = GetModuleHandleW(None).expect("module handle");
            let class = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                hInstance: inst.into(),
                lpszClassName: w!("FaroHiddenWindowProbe"),
                ..Default::default()
            };
            RegisterClassW(&class);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("FaroHiddenWindowProbe"),
                w!("Hidden from capture (probe)"),
                WS_OVERLAPPEDWINDOW,
                200,
                200,
                500,
                400,
                None,
                None,
                Some(inst.into()),
                None,
            )
            .expect("create window");
            SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE).expect("set affinity");
            let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            // Let the window come up.
            let mut msg = MSG::default();
            for _ in 0..50 {
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    let root = system_root();
    let windows = on_screen_windows();
    let hidden: Vec<_> = windows.iter().filter(|w| w.is_hidden()).collect();
    println!(
        "{} visible top-level windows, {} hidden from capture",
        windows.len(),
        hidden.len()
    );
    for w in &hidden {
        let p = resolve_process(w.pid);
        let note = if w.pid == own {
            " (this probe)"
        } else if is_allowed_os_process(&p, &root) {
            " (Windows, allowed)"
        } else {
            ""
        };
        println!(
            "affinity={:#04x} {:>5}x{:<5} {}{}",
            w.affinity,
            w.width,
            w.height,
            p.name.as_deref().unwrap_or("?"),
            note
        );
    }
    let report = |label: &str, windows: &[_], skip: u32| {
        let reading = read(windows, skip, &root, resolve_process);
        let mut tracker = HiddenWindowTracker::new();
        tracker.observe(&reading);
        println!("{label}:");
        println!("  reading: {reading:?}");
        println!("  signals: {:?}", tracker.observe(&reading));
    };
    report("as the agent sees it", &windows, own);
    if hide {
        // Pid 0 is never a real owner, so nothing is skipped.
        let mine: Vec<_> = windows.iter().filter(|w| w.pid == own).cloned().collect();
        report("this probe's own windows, not skipped", &mine, 0);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(hold);
        let mut msg = MSG::default();
        while std::time::Instant::now() < until {
            // SAFETY: a plain message pump for this thread's window.
            unsafe {
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("hidden_window_probe is Windows-only");
}
