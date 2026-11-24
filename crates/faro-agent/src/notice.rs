//! User-visible notices from the service (`ShowNotice`), e.g. the monthly
//! consent notice listing the member's current allies and the instance
//! operator (ARCHITECTURE.md §12).
//!
//! The agent hands them to a [`NoticeSink`]. On macOS the binary's sink
//! shows them in a window and keeps them in the menu-bar icon's menu
//! (`faro_platform_macos::ui`). Elsewhere, and in tests, the default
//! [`LogNotices`] only logs: there is no agent UI on other systems yet.

/// Something that can show a notice to the session user.
pub trait NoticeSink: Send {
    fn show(&mut self, title: &str, body: &str);
}

/// Logs notices. The title goes to `info` so it is visible in the unified
/// log; the body (which can name allies) only to `debug`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogNotices;

impl NoticeSink for LogNotices {
    fn show(&mut self, title: &str, body: &str) {
        tracing::info!(
            title,
            "service notice (no UI on this system; not shown on screen)"
        );
        tracing::debug!(title, body, "service notice body");
    }
}

impl<F> NoticeSink for F
where
    F: FnMut(&str, &str) + Send,
{
    fn show(&mut self, title: &str, body: &str) {
        self(title, body)
    }
}
