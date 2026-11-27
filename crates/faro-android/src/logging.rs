//! `tracing` to logcat (tag `faro`), on Android only; on other targets the
//! caller (a test) installs its own subscriber.
//!
//! What is logged is what faro-service and this crate log: states,
//! counters and error messages. Nothing logs pixels, browser addresses or
//! window titles (`SourceEvent`'s and `BrowserTab`'s `Debug` leave them
//! out, and Android gives no titles).

/// Install the logcat subscriber once per process (later calls do nothing).
/// `RUST_LOG`-style filtering isn't available in an app, so the level is
/// `info`.
pub fn init() {
    #[cfg(target_os = "android")]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
                .with_ansi(false)
                .without_time()
                .with_target(true)
                .with_writer(logcat::Logcat)
                .try_init();
        });
    }
}

#[cfg(target_os = "android")]
mod logcat {
    use std::ffi::CString;
    use std::io;
    use std::os::raw::{c_char, c_int};

    /// `ANDROID_LOG_INFO` (android/log.h). The level is in the text, so
    /// every line goes out at one priority.
    const ANDROID_LOG_INFO: c_int = 4;

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    /// One `tracing` event per writer, written as one logcat line.
    pub struct Logcat;

    pub struct Line(Vec<u8>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logcat {
        type Writer = Line;
        fn make_writer(&'a self) -> Line {
            Line(Vec::with_capacity(256))
        }
    }

    impl io::Write for Line {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Line {
        fn drop(&mut self) {
            let mut text = std::mem::take(&mut self.0);
            text.retain(|&b| b != 0);
            while text.last() == Some(&b'\n') {
                text.pop();
            }
            let Ok(text) = CString::new(text) else { return };
            // SAFETY: both pointers are valid NUL-terminated strings for the
            // duration of the call; liblog copies them.
            unsafe {
                __android_log_write(ANDROID_LOG_INFO, c"faro".as_ptr(), text.as_ptr());
            }
        }
    }
}
