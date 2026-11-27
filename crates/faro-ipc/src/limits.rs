//! Bounds on the text an agent sends (ARCHITECTURE.md §3.1, "Local IPC").
//!
//! The codec only caps a whole message ([`MAX_PAYLOAD_LEN`](crate::MAX_PAYLOAD_LEN),
//! sized for frames), so a single window title could otherwise be megabytes.
//! Any app the user runs picks its own window title, and the service copies
//! the title, app and browser context into `flag` bodies, which the instance
//! refuses over 1 MiB. The service therefore cuts every string an agent sends
//! to the limits here, on a character boundary, before using it; agents cut
//! their own titles too, so a long one does not cost a megabyte per message.
//!
//! Limits are in UTF-8 bytes. Each is well above what the field normally
//! holds: the title limit fits Windows' 1024 UTF-16 units (at most 3 bytes
//! each in UTF-8) and macOS's 1024 characters (at most 4 bytes each), and the
//! URL limit is the one the agents' own address-bar readers already apply.

use faro_proto::body::{AppInfo, BrowserContext};

/// A window or browser tab title.
pub const MAX_TITLE_BYTES: usize = 4096;
/// An app id (bundle id or executable name).
pub const MAX_APP_ID_BYTES: usize = 512;
/// An app's display name.
pub const MAX_APP_NAME_BYTES: usize = 512;
/// A browser URL. The host comes first, so a cut URL keeps it.
pub const MAX_URL_BYTES: usize = 8 * 1024;
/// Free text in a tamper signal from an agent (an app or browser name, a
/// permission name). Shown to allies, so it is also stripped of control
/// characters.
pub const MAX_TAMPER_TEXT_BYTES: usize = 256;

/// Cut `s` to at most `max` bytes on a character boundary. Returns whether
/// anything was cut.
pub fn clamp(s: &mut String, max: usize) -> bool {
    if s.len() <= max {
        return false;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    true
}

/// [`clamp`] for an optional string.
pub fn clamp_opt(s: &mut Option<String>, max: usize) -> bool {
    s.as_mut().is_some_and(|s| clamp(s, max))
}

/// `s` without control characters, cut to [`MAX_TAMPER_TEXT_BYTES`].
pub fn tamper_text(s: &str) -> String {
    let mut out: String = s.chars().filter(|c| !c.is_control()).collect();
    clamp(&mut out, MAX_TAMPER_TEXT_BYTES);
    out
}

/// Clamp an app's id and name. Returns whether anything was cut.
pub fn clamp_app(app: &mut AppInfo) -> bool {
    let id = clamp(&mut app.id, MAX_APP_ID_BYTES);
    let name = clamp_opt(&mut app.name, MAX_APP_NAME_BYTES);
    id || name
}

/// Clamp a browser context's URL and title. Returns whether anything was cut.
pub fn clamp_browser(b: &mut BrowserContext) -> bool {
    let url = clamp_opt(&mut b.url, MAX_URL_BYTES);
    let title = clamp_opt(&mut b.title, MAX_TITLE_BYTES);
    url || title
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_cuts_on_a_char_boundary() {
        let mut s = "é".repeat(10); // 2 bytes each
        assert!(clamp(&mut s, 5));
        assert_eq!(s, "éé");
        let mut short = "abc".to_owned();
        assert!(!clamp(&mut short, 3));
        assert_eq!(short, "abc");
        let mut emoji = "😀😀".to_owned(); // 4 bytes each
        assert!(clamp(&mut emoji, 3));
        assert_eq!(emoji, "");
    }

    #[test]
    fn app_and_browser_are_bounded() {
        let mut app = AppInfo {
            id: "x".repeat(10_000),
            name: Some("y".repeat(10_000)),
        };
        assert!(clamp_app(&mut app));
        assert_eq!(app.id.len(), MAX_APP_ID_BYTES);
        assert_eq!(app.name.as_deref().map(str::len), Some(MAX_APP_NAME_BYTES));
        let mut b = BrowserContext {
            url: Some(format!("https://example.com/{}", "a".repeat(100_000))),
            title: Some("t".repeat(100_000)),
            incognito: false,
        };
        assert!(clamp_browser(&mut b));
        assert_eq!(b.url.as_deref().map(str::len), Some(MAX_URL_BYTES));
        assert!(b
            .url
            .as_deref()
            .unwrap()
            .starts_with("https://example.com/"));
        assert_eq!(b.title.as_deref().map(str::len), Some(MAX_TITLE_BYTES));
    }

    #[test]
    fn tamper_text_strips_controls() {
        assert_eq!(tamper_text("Vie\u{1b}[31mwer\n"), "Vie[31mwer");
        assert_eq!(tamper_text(&"z".repeat(1000)).len(), MAX_TAMPER_TEXT_BYTES);
    }
}
