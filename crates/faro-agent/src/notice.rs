//! User-visible notices from the service (`ShowNotice`), e.g. the monthly
//! consent notice listing the member's current allies and the instance
//! operator (ARCHITECTURE.md §12).
//!
//! The tray UI will render these; until it exists the agent hands them to a
//! [`NoticeSink`], and the default one only logs. That is a stated gap, not a
//! fake UI: consent notices are not yet shown on screen.

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
            "service notice (no tray UI yet; not shown on screen)"
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
