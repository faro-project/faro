//! User-visible notices from the service (`ShowNotice`), e.g. the monthly
//! consent notice listing the member's current allies and the instance
//! operator (ARCHITECTURE.md §12), and the agent's own notice that Screen
//! Recording is off ([`SCREEN_RECORDING_OFF`]) and that an app hides a
//! window from it ([`window_hidden_notice`]).
//!
//! The agent hands them to a [`NoticeSink`]. On macOS the binary's sink
//! shows them in a window and keeps them in the menu-bar icon's menu
//! (`faro_platform_macos::ui`). Elsewhere, and in tests, the default
//! [`LogNotices`] only logs: there is no agent UI on other systems yet.

/// A notice with a button that opens a page of the system's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsNotice {
    pub title: &'static str,
    pub body: &'static str,
    /// The button that opens [`SettingsNotice::url`].
    pub open: &'static str,
    /// The button that only closes the notice.
    pub later: &'static str,
    pub url: &'static str,
}

/// Shown in a session where Faro has no Screen Recording permission
/// (ARCHITECTURE.md §3.7): once per agent run, and again if it goes off
/// after being granted. It is the member's side of the
/// `permission_revoked` alert their allies get.
pub const SCREEN_RECORDING_OFF: SettingsNotice = SettingsNotice {
    title: "Faro can't see the screen",
    body: "Screen Recording is off for Faro Agent, so Faro can't check this screen. \
           While it stays off, the member's allies are told that Faro can't see the screen.\n\n\
           To turn it on, open System Settings \u{2192} Privacy & Security \u{2192} \
           Screen & System Audio Recording and switch on Faro Agent. If Faro Agent is not in \
           the list, or it is on but Faro still can't see the screen (after Faro was \
           reinstalled, for example), remove it with the \u{2212} button if it is there, \
           then click + and add \"Faro Agent\" from the Faro folder on the startup disk.",
    open: "Open System Settings",
    later: "Later",
    url: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
};

/// The title and text shown when the agent reports
/// `window_hidden_from_capture` for `app` (ARCHITECTURE.md §3.7): the
/// member's side of the alert their allies get. The tracker in the
/// platform layer reports each app once, so this isn't shown on every poll.
pub fn window_hidden_notice(app: &str) -> (String, String) {
    (
        "Faro can't see one of your windows".to_owned(),
        format!(
            "\u{201c}{app}\u{201d} keeps one of its windows out of screenshots and screen \
             recordings, so Faro can't check what that window shows. The member's allies \
             are told which app it is.\n\n\
             If you don't need that window, close it. Some apps have a setting that hides \
             their windows from screen sharing; turning it off makes the window visible \
             to Faro again."
        ),
    )
}

/// Something that can show a notice to the session user.
pub trait NoticeSink: Send {
    fn show(&mut self, title: &str, body: &str);

    /// Show [`SCREEN_RECORDING_OFF`]. A UI adds the button that opens the
    /// settings page; by default only the title and the text are shown.
    fn screen_recording_off(&mut self) {
        self.show(SCREEN_RECORDING_OFF.title, SCREEN_RECORDING_OFF.body);
    }

    /// What the agent now knows of the service, for a status menu
    /// ([`crate::status_menu`]). Called when it changes. Without a menu
    /// there is nothing to show, so by default it is only logged.
    fn status(&mut self, seen: &crate::status_menu::Seen) {
        tracing::debug!(?seen, "service status");
    }
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
