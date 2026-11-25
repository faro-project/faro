//! The active browser tab's URL, read through Accessibility
//! (ARCHITECTURE.md §3.3, the fallback until the browser extension exists).
//!
//! # Which browsers
//!
//! Safari, Chrome, Edge, Brave and Arc, identified by bundle id
//! ([`Browser::from_bundle_id`]), including their beta and preview builds.
//! Any other browser, or a missing Accessibility permission, gives no
//! browser context, as before.
//!
//! # How
//!
//! Only the Accessibility API, never AppleScript or Apple Events: those need
//! a separate Automation permission for each browser. Every request carries
//! the same short messaging timeout as window titles, the whole read has a
//! time and size budget, and a request that times out ends the read, so a
//! hung browser can't stall the agent.
//!
//! 1. From the focused element up to its window: the outermost `AXWebArea`
//!    above it is the page the member is using. Its `AXURL` is the page URL.
//!    This is a handful of requests.
//! 2. Otherwise, a bounded breadth-first walk of the focused window. It
//!    never enters a web area, so it never reads page content. The first
//!    web area with a web URL wins.
//! 3. Failing that, the address field's text. In Safari that is the field
//!    with the identifier `WEB_BROWSER_ADDRESS_AND_SEARCH_FIELD`. In the
//!    Chromium browsers it is the first text field whose text looks like an
//!    address. A focused address field is skipped: it holds what the member
//!    is typing, not the page they are on.
//!
//! Chromium builds its web accessibility tree only once an assistive app
//! asks for it, so in Chrome, Edge, Brave and Arc step 3 is often the one
//! that answers. We don't set `AXEnhancedUserInterface` or
//! `AXManualAccessibility` to force the tree on: that would change how the
//! member's browser behaves and costs it memory and CPU.
//!
//! # What leaves the agent
//!
//! Only `scheme://host/`, for `http` and `https` pages ([`reduce_url`]).
//! Domain categorization looks at the host only (`faro_detect`'s
//! `normalize_host`), and so does the report's top-domains list, so the
//! path, query, fragment, port and any user name or password are dropped
//! here. Other schemes (`file:`, `about:`, `chrome:`, `favorites:` and so
//! on) give no URL. The tab title is not sent either: the window title
//! already carries it.
//!
//! # Private windows
//!
//! `incognito` is always `false`. Neither Safari nor the Chromium browsers
//! mark a private window in a way Accessibility can read reliably: the only
//! hints are localized labels and window styling. The browser extension
//! will report private windows; until then, ARCHITECTURE.md §3.3 notes the
//! limit.

use std::collections::VecDeque;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use objc2::rc::autoreleasepool;
use objc2_application_services::{AXCopyMultipleAttributeOptions, AXError, AXUIElement};
use objc2_core_foundation::{CFArray, CFBoolean, CFRetained, CFString, CFType, CFURL};

use crate::cf;
use crate::foreground::AX_TIMEOUT_SECS;

/// Longest URL or address-field text we parse. Real URLs can be longer, but
/// the host is always near the start and nothing past this is kept anyway.
const MAX_URL_LEN: usize = 8 * 1024;

/// Total time one read may take. Each request is also bounded by
/// [`AX_TIMEOUT_SECS`].
const READ_BUDGET: Duration = Duration::from_millis(500);

/// Elements the window walk may visit, and how deep it may go.
const MAX_NODES: usize = 400;
const MAX_DEPTH: usize = 24;

/// Parents followed up from the focused element.
const MAX_PARENTS: usize = 64;

/// Safari's address field.
const SAFARI_ADDRESS_FIELD: &str = "WEB_BROWSER_ADDRESS_AND_SEARCH_FIELD";

/// A browser whose tab URL we read through Accessibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Safari,
    Chrome,
    Edge,
    Brave,
    Arc,
}

/// Bundle ids, compared ignoring ASCII case.
const BUNDLE_IDS: &[(&str, Browser)] = &[
    ("com.apple.Safari", Browser::Safari),
    ("com.apple.SafariTechnologyPreview", Browser::Safari),
    ("com.google.Chrome", Browser::Chrome),
    ("com.google.Chrome.beta", Browser::Chrome),
    ("com.google.Chrome.dev", Browser::Chrome),
    ("com.google.Chrome.canary", Browser::Chrome),
    ("com.microsoft.edgemac", Browser::Edge),
    ("com.microsoft.edgemac.Beta", Browser::Edge),
    ("com.microsoft.edgemac.Dev", Browser::Edge),
    ("com.microsoft.edgemac.Canary", Browser::Edge),
    ("com.brave.Browser", Browser::Brave),
    ("com.brave.Browser.beta", Browser::Brave),
    ("com.brave.Browser.nightly", Browser::Brave),
    ("company.thebrowser.Browser", Browser::Arc),
];

impl Browser {
    /// The browser with this bundle id, if it is one we support.
    pub fn from_bundle_id(id: &str) -> Option<Browser> {
        let id = id.trim();
        BUNDLE_IDS
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(id))
            .map(|&(_, b)| b)
    }

    /// Whether the browser is built on Chromium (its address field has no
    /// stable identifier).
    fn is_chromium(self) -> bool {
        !matches!(self, Browser::Safari)
    }
}

/// Reduce a page URL to what leaves the agent: `scheme://host/` for `http`
/// and `https`, `None` for anything else. The host comes out lowercased and,
/// for international names, in punycode, as domain lists store it.
pub fn reduce_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_URL_LEN {
        return None;
    }
    let url = url::Url::parse(raw).ok()?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = match url.host()? {
        url::Host::Domain(d) => d.trim_end_matches('.').to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => format!("[{ip}]"),
    };
    if host.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{host}/"))
}

/// Reduce an address field's text like [`reduce_url`]. Browsers often hide
/// the scheme (`example.com/page`), so text without one is read as
/// `https`. Text with spaces, or a single word without a dot, is a search,
/// not an address.
pub fn reduce_address_text(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() || t.len() > MAX_URL_LEN || t.chars().any(char::is_whitespace) {
        return None;
    }
    if has_scheme(t) {
        return reduce_url(t);
    }
    let reduced = reduce_url(&format!("https://{t}"))?;
    let host = reduced.strip_prefix("https://")?.trim_end_matches('/');
    let ip = host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok();
    (ip || host.contains('.')).then_some(reduced)
}

/// `scheme://…`, where the scheme has only the characters a scheme may.
fn has_scheme(t: &str) -> bool {
    t.split_once("://").is_some_and(|(s, _)| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}

/// The reduced URL of `browser`'s active tab in the app with `pid`, or
/// `None` if it can't be read (or Accessibility isn't granted).
///
/// [`MacForeground`](crate::MacForeground) calls this for the frontmost
/// app; the `browser_probe` example calls it for any pid.
pub fn tab_url(pid: i32, browser: Browser) -> Option<String> {
    autoreleasepool(|_| tab_url_now(pid, browser))
}

/// See [`tab_url`]. Must run inside an autorelease pool.
pub(crate) fn tab_url_now(pid: i32, browser: Browser) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    // SAFETY: AXUIElementCreateApplication accepts any pid; for a positive
    // pid it returns a (possibly dead) element, never null.
    let app = unsafe { AXUIElement::new_application(pid) };
    let mut ax = Ax {
        deadline: Instant::now() + READ_BUDGET,
    };
    // `Err(Stop)`: out of time, or the browser stopped answering.
    ax.read(&app, browser).unwrap_or_default()
}

/// The read ran out of time, or the browser stopped answering.
struct Stop;

/// What one element told us.
struct Node {
    role: Option<String>,
    children: Vec<CFRetained<AXUIElement>>,
}

struct Ax {
    deadline: Instant,
}

impl Ax {
    fn read(&mut self, app: &AXUIElement, browser: Browser) -> Result<Option<String>, Stop> {
        if let Some(focused) = self.element(app, "AXFocusedUIElement")? {
            if let Some(url) = self.page_above(focused)? {
                return Ok(Some(url));
            }
        }
        let Some(window) = self.element(app, "AXFocusedWindow")? else {
            return Ok(None);
        };
        self.walk(window, browser)
    }

    /// The reduced URL of the outermost web area above `element`, if it has
    /// a web URL.
    fn page_above(&mut self, element: CFRetained<AXUIElement>) -> Result<Option<String>, Stop> {
        let mut outermost = None;
        let mut current = Some(element);
        for _ in 0..MAX_PARENTS {
            let Some(el) = current.take() else { break };
            let values = self.copy_many(&el, &["AXRole", "AXParent"])?;
            let role = string_at(&values, 0);
            match role.as_deref() {
                Some("AXWebArea") => outermost = Some(el.clone()),
                Some("AXWindow") | Some("AXApplication") => break,
                _ => {}
            }
            current = values
                .get(1)
                .and_then(|v| v.clone().downcast::<AXUIElement>().ok());
        }
        match outermost {
            Some(area) => Ok(self.web_area_url(&area)?.as_deref().and_then(reduce_url)),
            None => Ok(None),
        }
    }

    /// Breadth-first over `window`: the first web area with a web URL, else
    /// the address field's text.
    fn walk(
        &mut self,
        window: CFRetained<AXUIElement>,
        browser: Browser,
    ) -> Result<Option<String>, Stop> {
        let mut address: Option<String> = None;
        let mut queue = VecDeque::from([(window, 0usize)]);
        let mut visited = 0usize;
        while let Some((el, depth)) = queue.pop_front() {
            visited += 1;
            if visited > MAX_NODES {
                break;
            }
            let node = self.node(&el)?;
            match node.role.as_deref() {
                Some("AXWebArea") => {
                    if let Some(url) = self.web_area_url(&el)?.as_deref().and_then(reduce_url) {
                        return Ok(Some(url));
                    }
                    // Never enter a web area: its children are the page.
                    continue;
                }
                Some("AXTextField" | "AXComboBox") => {
                    if address.is_none() {
                        address = self.address(&el, browser)?;
                    }
                    continue;
                }
                Some(role) if is_leaf(role) => continue,
                _ => {}
            }
            if depth < MAX_DEPTH {
                queue.extend(node.children.into_iter().map(|c| (c, depth + 1)));
            }
        }
        Ok(address)
    }

    /// The reduced address in a text field, if it is the browser's address
    /// field and not being edited.
    fn address(&mut self, field: &AXUIElement, browser: Browser) -> Result<Option<String>, Stop> {
        let values = self.copy_many(field, &["AXIdentifier", "AXFocused", "AXValue"])?;
        let focused = values
            .get(1)
            .and_then(|v| v.downcast_ref::<CFBoolean>().map(CFBoolean::as_bool))
            .unwrap_or(false);
        if focused {
            return Ok(None);
        }
        if !browser.is_chromium() && string_at(&values, 0).as_deref() != Some(SAFARI_ADDRESS_FIELD)
        {
            return Ok(None);
        }
        Ok(string_at(&values, 2)
            .as_deref()
            .and_then(reduce_address_text))
    }

    /// A web area's `AXURL`, unreduced.
    fn web_area_url(&mut self, area: &AXUIElement) -> Result<Option<String>, Stop> {
        let Some(v) = self.copy(area, "AXURL")? else {
            return Ok(None);
        };
        if let Some(u) = v.downcast_ref::<CFURL>() {
            let absolute = u.absolute_url();
            let u = absolute.as_deref().unwrap_or(u);
            return Ok(Some(u.string().to_string()));
        }
        // Some apps answer with a string.
        Ok(v.downcast_ref::<CFString>().map(ToString::to_string))
    }

    fn node(&mut self, el: &AXUIElement) -> Result<Node, Stop> {
        let values = self.copy_many(el, &["AXRole", "AXChildren"])?;
        let children = values
            .get(1)
            .and_then(|v| v.downcast_ref::<CFArray>().map(children_of))
            .unwrap_or_default();
        Ok(Node {
            role: string_at(&values, 0),
            children,
        })
    }

    fn element(
        &mut self,
        el: &AXUIElement,
        attribute: &str,
    ) -> Result<Option<CFRetained<AXUIElement>>, Stop> {
        Ok(self
            .copy(el, attribute)?
            .and_then(|v| v.downcast::<AXUIElement>().ok()))
    }

    /// One attribute. A missing attribute is `Ok(None)`; a request that
    /// timed out, or a spent budget, is `Err(Stop)`.
    fn copy(
        &mut self,
        el: &AXUIElement,
        attribute: &str,
    ) -> Result<Option<CFRetained<CFType>>, Stop> {
        self.before_request(el)?;
        let attr = CFString::from_str(attribute);
        let mut out: *const CFType = std::ptr::null();
        // SAFETY: `out` is a valid out-pointer for the duration of the call.
        let err = unsafe { el.copy_attribute_value(&attr, NonNull::from(&mut out)) };
        if err == AXError::CannotComplete {
            return Err(Stop);
        }
        if err != AXError::Success {
            return Ok(None);
        }
        // SAFETY: on success AXUIElementCopyAttributeValue stores a +1 (Copy
        // rule) reference, which `from_raw` adopts and releases on drop.
        Ok(NonNull::new(out.cast_mut()).map(|p| unsafe { CFRetained::from_raw(p) }))
    }

    /// Several attributes in one request. Each position holds the value, or
    /// an error placeholder that no type check accepts.
    fn copy_many(
        &mut self,
        el: &AXUIElement,
        attributes: &[&str],
    ) -> Result<Vec<CFRetained<CFType>>, Stop> {
        self.before_request(el)?;
        let names: Vec<CFRetained<CFString>> =
            attributes.iter().map(|a| CFString::from_str(a)).collect();
        let refs: Vec<&CFString> = names.iter().map(|n| &**n).collect();
        let names = CFArray::from_objects(&refs);
        let mut out: *const CFArray = std::ptr::null();
        // SAFETY: `names` is an array of CFStrings, as the call requires, and
        // `out` is a valid out-pointer for the duration of the call.
        let err = unsafe {
            el.copy_multiple_attribute_values(
                names.as_opaque(),
                AXCopyMultipleAttributeOptions::empty(),
                NonNull::from(&mut out),
            )
        };
        if err == AXError::CannotComplete {
            return Err(Stop);
        }
        if err != AXError::Success {
            return Ok(Vec::new());
        }
        let Some(p) = NonNull::new(out.cast_mut()) else {
            return Ok(Vec::new());
        };
        // SAFETY: on success the call stores a +1 (Copy rule) CFArray.
        let values: CFRetained<CFArray> = unsafe { CFRetained::from_raw(p) };
        Ok(cf::as_type_array(&values).iter().collect())
    }

    /// Spend the budget, and bound the coming request on `el`.
    fn before_request(&mut self, el: &AXUIElement) -> Result<(), Stop> {
        if Instant::now() >= self.deadline {
            return Err(Stop);
        }
        // SAFETY: plain setter on a valid element.
        let _ = unsafe { el.set_messaging_timeout(AX_TIMEOUT_SECS) };
        Ok(())
    }
}

fn string_at(values: &[CFRetained<CFType>], i: usize) -> Option<String> {
    values
        .get(i)?
        .downcast_ref::<CFString>()
        .map(ToString::to_string)
}

fn children_of(array: &CFArray) -> Vec<CFRetained<AXUIElement>> {
    cf::as_type_array(array)
        .iter()
        .filter_map(|c| c.downcast::<AXUIElement>().ok())
        .collect()
}

/// Roles whose children can't hold a web area or the address field.
fn is_leaf(role: &str) -> bool {
    matches!(
        role,
        "AXButton"
            | "AXRadioButton"
            | "AXCheckBox"
            | "AXPopUpButton"
            | "AXMenuButton"
            | "AXDisclosureTriangle"
            | "AXStaticText"
            | "AXImage"
            | "AXLink"
            | "AXTextArea"
            | "AXMenuBar"
            | "AXMenu"
            | "AXMenuItem"
            | "AXSlider"
            | "AXScrollBar"
            | "AXValueIndicator"
            | "AXProgressIndicator"
            | "AXBusyIndicator"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_browsers_by_bundle_id() {
        let cases = [
            ("com.apple.Safari", Some(Browser::Safari)),
            ("com.apple.SafariTechnologyPreview", Some(Browser::Safari)),
            ("com.google.Chrome", Some(Browser::Chrome)),
            ("com.google.Chrome.canary", Some(Browser::Chrome)),
            ("COM.GOOGLE.CHROME", Some(Browser::Chrome)),
            (" com.microsoft.edgemac ", Some(Browser::Edge)),
            ("com.brave.Browser", Some(Browser::Brave)),
            ("company.thebrowser.Browser", Some(Browser::Arc)),
            ("org.mozilla.firefox", None),
            ("org.torproject.torbrowser", None),
            ("com.vivaldi.Vivaldi", None),
            ("com.google.Chrome.app.abcdef", None),
            ("com.apple.Terminal", None),
            ("", None),
        ];
        for (id, want) in cases {
            assert_eq!(Browser::from_bundle_id(id), want, "{id}");
        }
        assert!(!Browser::Safari.is_chromium());
        assert!(Browser::Arc.is_chromium());
    }

    #[test]
    fn urls_reduce_to_scheme_and_host() {
        let cases = [
            (
                "https://example.com/a/b?q=secret#frag",
                Some("https://example.com/"),
            ),
            ("http://Example.COM", Some("http://example.com/")),
            (
                "https://user:pass@example.com:8443/x",
                Some("https://example.com/"),
            ),
            (
                "https://www.example.com./",
                Some("https://www.example.com/"),
            ),
            (
                "https://bücher.example/",
                Some("https://xn--bcher-kva.example/"),
            ),
            ("https://192.168.1.1/admin", Some("https://192.168.1.1/")),
            ("http://[::1]:8080/", Some("http://[::1]/")),
            ("  https://example.com  ", Some("https://example.com/")),
            ("file:///Users/sam/secret.pdf", None),
            ("about:blank", None),
            ("chrome://newtab/", None),
            ("favorites://", None),
            ("data:text/html,hi", None),
            ("blob:https://example.com/uuid", None),
            ("javascript:alert(1)", None),
            ("not a url", None),
            ("", None),
        ];
        for (raw, want) in cases {
            assert_eq!(reduce_url(raw).as_deref(), want, "{raw}");
        }
        assert_eq!(
            reduce_url(&format!("https://example.com/{}", "a".repeat(MAX_URL_LEN))),
            None
        );
    }

    #[test]
    fn address_text_reduces_like_a_url() {
        let cases = [
            ("example.com/page?q=1", Some("https://example.com/")),
            ("example.com", Some("https://example.com/")),
            ("http://example.com/x", Some("http://example.com/")),
            ("localhost:3000/x", None),
            ("10.0.0.1/router", Some("https://10.0.0.1/")),
            ("chrome://settings", None),
            ("example.com:8080/x", Some("https://example.com/")),
            ("a.com/?u=http://b.com", Some("https://a.com/")),
            ("faro", None),
            ("how to fix a bike", None),
            ("about:blank", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(reduce_address_text(text).as_deref(), want, "{text}");
        }
    }

    #[test]
    fn scheme_detection() {
        assert!(has_scheme("https://x"));
        assert!(has_scheme("chrome-extension://abc"));
        assert!(!has_scheme("a.com/?u=http://b.com"));
        assert!(!has_scheme("://x"));
        assert!(!has_scheme("1http://x"));
        assert!(!has_scheme("example.com"));
    }

    #[test]
    fn tab_url_for_bogus_pids_is_none() {
        assert_eq!(tab_url(0, Browser::Safari), None);
        assert_eq!(tab_url(-1, Browser::Chrome), None);
        // A pid that cannot exist (pid_max on macOS is 99998).
        if crate::accessibility_trusted() {
            assert_eq!(tab_url(999_999, Browser::Safari), None);
        }
    }
}
