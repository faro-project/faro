//! The active browser tab's URL, read through UI Automation
//! (ARCHITECTURE.md §3.3, the fallback until the browser extension exists).
//!
//! # Which browsers
//!
//! Edge, Chrome, Brave (Chromium) and Firefox with its forks LibreWolf,
//! Waterfox, Zen and Floorp, identified by executable name
//! ([`Browser::from_exe_name`]); beta, dev and nightly channels use the same
//! executable names. Any other browser gives no browser context.
//!
//! # How
//!
//! A UI Automation client in this process (`CUIAutomation8`, so the
//! connection and transaction timeouts can be set) reads the browser's
//! **address field** in the foreground window and nothing else:
//!
//! * Chromium: the `Edit` control of class `OmniboxViewViews`.
//! * Firefox and its forks: the control with automation id `urlbar-input`
//!   (a `ComboBox` in current builds, an `Edit` in older ones).
//!
//! The field is found with a bounded walk (toolbars first, depth-first;
//! everything else breadth-first) of the window's
//! control view ([`MAX_NODES`], [`MAX_DEPTH`], [`READ_BUDGET`]) that **never
//! enters a `Document`** (the page) or Chromium's render-widget pane. So it
//! never reads page content, never matches a text box on the page, and a
//! page can't plant an element that poses as the address field (Firefox
//! exposes DOM ids as automation ids, but only inside the document). Not
//! entering the page also matters for cost: Chromium builds its web
//! accessibility tree only when a client walks into it, which makes the
//! browser slower and hungrier for as long as the client keeps asking.
//!
//! Each expanded node's children come back in one cross-process call
//! (`FindAllBuildCache` over its children with a cache request for control
//! type, class name, automation id and focus), so a walk is one call per
//! container on the way to the field, typically 10 to 20. UIA's own connection and transaction timeouts
//! ([`UIA_TIMEOUT_MS`]) bound every call, and the walk stops when its total
//! budget is spent, so a hung browser can't stall the agent.
//!
//! An address field that has keyboard focus is skipped: it holds what the
//! member is typing, not the page they are on.
//!
//! # COM
//!
//! The automation object lives in a thread-local, created on first use on
//! whichever thread calls (the agent's dedicated platform thread). That
//! thread joins the multithreaded apartment, which is what Microsoft
//! recommends for UIA clients: calls into a hung provider then can't
//! re-enter or deadlock the caller's message loop, of which the platform
//! thread has none. If the thread already belongs to a single-threaded
//! apartment, it stays there and UIA works in it.
//!
//! # What leaves the agent
//!
//! Only `scheme://host/`, for `http` and `https` pages ([`reduce_url`],
//! [`reduce_address_text`], shared in behavior with the macOS
//! implementation). Domain categorization and the report's top domains use
//! only the host, so the path, query, fragment, port and credentials are
//! dropped here. The tab title is not sent: the window title carries it.
//!
//! # Private windows
//!
//! `incognito` is always `false`. Chromium's InPrivate/Incognito windows
//! and Firefox's private windows are only told apart by localized window
//! titles and styling, which a page title can imitate. The browser
//! extension will report private windows.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use windows::core::{Interface, BSTR};
use windows::Win32::Foundation::{HWND, RPC_E_CHANGED_MODE};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationCacheRequest,
    IUIAutomationCondition, IUIAutomationElement, IUIAutomationValuePattern, TreeScope_Children,
    UIA_AutomationIdPropertyId, UIA_ButtonControlTypeId, UIA_CheckBoxControlTypeId,
    UIA_ClassNamePropertyId, UIA_ComboBoxControlTypeId, UIA_ControlTypePropertyId,
    UIA_DocumentControlTypeId, UIA_EditControlTypeId, UIA_HasKeyboardFocusPropertyId,
    UIA_HyperlinkControlTypeId, UIA_ImageControlTypeId, UIA_MenuBarControlTypeId,
    UIA_MenuControlTypeId, UIA_MenuItemControlTypeId, UIA_ProgressBarControlTypeId,
    UIA_RadioButtonControlTypeId, UIA_ScrollBarControlTypeId, UIA_SeparatorControlTypeId,
    UIA_SliderControlTypeId, UIA_SplitButtonControlTypeId, UIA_TabItemControlTypeId,
    UIA_TextControlTypeId, UIA_ThumbControlTypeId, UIA_ToolBarControlTypeId,
    UIA_ToolTipControlTypeId, UIA_ValuePatternId, UIA_CONTROLTYPE_ID,
};

/// Longest URL or address-field text we parse. The host is always near the
/// start and nothing past it is kept anyway.
const MAX_URL_LEN: usize = 8 * 1024;

/// Total time one read may take.
pub const READ_BUDGET: Duration = Duration::from_millis(500);

/// UIA connection and transaction timeout for every call, in ms.
pub const UIA_TIMEOUT_MS: u32 = 250;

/// Elements the walk may visit, and how deep it may go.
pub const MAX_NODES: usize = 400;
pub const MAX_DEPTH: usize = 24;

/// Chromium's address field.
const CHROMIUM_OMNIBOX_CLASS: &str = "OmniboxViewViews";
/// Chromium's web-content host pane; its subtree is the page.
const CHROMIUM_RENDER_WIDGET_CLASS: &str = "Chrome_RenderWidgetHostHWND";
/// Firefox's address field.
const FIREFOX_URLBAR_ID: &str = "urlbar-input";

/// A browser whose address field we read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    Edge,
    Chrome,
    Brave,
    Firefox,
    LibreWolf,
    Waterfox,
    Zen,
    Floorp,
}

/// Executable names, compared ignoring ASCII case.
const EXE_NAMES: &[(&str, Browser)] = &[
    ("msedge.exe", Browser::Edge),
    ("chrome.exe", Browser::Chrome),
    ("brave.exe", Browser::Brave),
    ("firefox.exe", Browser::Firefox),
    ("librewolf.exe", Browser::LibreWolf),
    ("waterfox.exe", Browser::Waterfox),
    ("zen.exe", Browser::Zen),
    ("floorp.exe", Browser::Floorp),
];

impl Browser {
    /// The browser with this executable file name (`chrome.exe`), if we
    /// support it. A full path is accepted too; only its file name counts.
    pub fn from_exe_name(name: &str) -> Option<Browser> {
        let name = name.trim();
        let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
        EXE_NAMES
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(file))
            .map(|&(_, b)| b)
    }

    /// Built on Chromium (Edge, Chrome, Brave) rather than Gecko.
    pub fn is_chromium(self) -> bool {
        matches!(self, Browser::Edge | Browser::Chrome | Browser::Brave)
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

/// One element as the walk sees it (from the cache; no extra calls).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeInfo {
    pub control_type: i32,
    pub class_name: String,
    pub automation_id: String,
    pub has_focus: bool,
}

/// What to do with a node during the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    /// The browser's address field.
    Address,
    /// Don't look inside (the page, or a control that can't hold the field).
    Skip,
    /// Look at its children.
    Descend,
}

/// Classify a node for `browser` (pure, so the rules are testable).
pub fn classify(browser: Browser, n: &NodeInfo) -> Visit {
    let ct = UIA_CONTROLTYPE_ID(n.control_type);
    if ct == UIA_DocumentControlTypeId || n.class_name == CHROMIUM_RENDER_WIDGET_CLASS {
        return Visit::Skip;
    }
    if browser.is_chromium() {
        if ct == UIA_EditControlTypeId {
            return if n.class_name == CHROMIUM_OMNIBOX_CLASS {
                Visit::Address
            } else {
                Visit::Skip
            };
        }
    } else if ct == UIA_EditControlTypeId || ct == UIA_ComboBoxControlTypeId {
        // Firefox exposes its address field as a combo box (it has a
        // drop-down of suggestions); older builds as an edit.
        return if n.automation_id == FIREFOX_URLBAR_ID {
            Visit::Address
        } else {
            Visit::Skip
        };
    }
    if is_leaf(ct) {
        Visit::Skip
    } else {
        Visit::Descend
    }
}

/// Control types whose children can't hold the address field.
fn is_leaf(ct: UIA_CONTROLTYPE_ID) -> bool {
    [
        UIA_ButtonControlTypeId,
        UIA_CheckBoxControlTypeId,
        UIA_HyperlinkControlTypeId,
        UIA_ImageControlTypeId,
        UIA_MenuBarControlTypeId,
        UIA_MenuControlTypeId,
        UIA_MenuItemControlTypeId,
        UIA_ProgressBarControlTypeId,
        UIA_RadioButtonControlTypeId,
        UIA_ScrollBarControlTypeId,
        UIA_SeparatorControlTypeId,
        UIA_SliderControlTypeId,
        UIA_SplitButtonControlTypeId,
        UIA_TabItemControlTypeId,
        UIA_TextControlTypeId,
        UIA_ThumbControlTypeId,
        UIA_ToolTipControlTypeId,
    ]
    .contains(&ct)
}

/// COM for this thread, released when the thread exits.
struct ComApartment {
    initialized: bool,
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: paired with a successful CoInitializeEx on this thread.
            unsafe { CoUninitialize() };
        }
    }
}

/// The thread's UIA client. Field order matters: the automation objects
/// are released before COM is uninitialized.
struct Uia {
    automation: IUIAutomation,
    control_view: IUIAutomationCondition,
    cache: IUIAutomationCacheRequest,
    _com: ComApartment,
}

impl Uia {
    fn new() -> windows::core::Result<Uia> {
        // SAFETY: plain COM initialization of the calling thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        let com = ComApartment {
            initialized: hr.is_ok(),
        };
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            return Err(hr.into());
        }
        // SAFETY: standard in-process creation of the UIA client object.
        let automation: IUIAutomation =
            unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }?;
        if let Ok(a2) = automation.cast::<IUIAutomation2>() {
            // SAFETY: plain setters.
            unsafe {
                let _ = a2.SetConnectionTimeout(UIA_TIMEOUT_MS);
                let _ = a2.SetTransactionTimeout(UIA_TIMEOUT_MS);
            }
        }
        // SAFETY: plain getters/factories on a valid automation object.
        let (control_view, cache) = unsafe {
            let control_view = automation.ControlViewCondition()?;
            let cache = automation.CreateCacheRequest()?;
            for p in [
                UIA_ControlTypePropertyId,
                UIA_ClassNamePropertyId,
                UIA_AutomationIdPropertyId,
                UIA_HasKeyboardFocusPropertyId,
            ] {
                cache.AddProperty(p)?;
            }
            (control_view, cache)
        };
        Ok(Uia {
            automation,
            control_view,
            cache,
            _com: com,
        })
    }
}

/// How long after a failed setup the thread tries again.
const SETUP_RETRY: Duration = Duration::from_secs(60);

/// The thread's UIA client state.
enum Slot {
    Untried,
    Ready(Uia),
    /// Setup failed at this time; retried after [`SETUP_RETRY`].
    Failed(Instant),
}

thread_local! {
    static UIA: RefCell<Slot> = const { RefCell::new(Slot::Untried) };
}

/// Serializes client setup across threads: UIA's per-process
/// initialization is not safe to race (two threads setting up at once
/// intermittently get `E_FAIL` from the first tree call).
static SETUP: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_uia<R>(f: impl FnOnce(&Uia) -> Option<R>) -> Option<R> {
    UIA.with(|cell| {
        let mut slot = cell.borrow_mut();
        let retry = match &*slot {
            Slot::Untried => true,
            Slot::Failed(at) => at.elapsed() >= SETUP_RETRY,
            Slot::Ready(_) => false,
        };
        if retry {
            let _guard = SETUP.lock().unwrap_or_else(|e| e.into_inner());
            *slot = match Uia::new() {
                Ok(u) => Slot::Ready(u),
                Err(e) => {
                    tracing::debug!(code = e.code().0, "UI Automation unavailable");
                    Slot::Failed(Instant::now())
                }
            };
        }
        match &*slot {
            Slot::Ready(uia) => f(uia),
            _ => None,
        }
    })
}

fn node_info(el: &IUIAutomationElement) -> NodeInfo {
    // SAFETY: cached getters on an element built with our cache request;
    // they make no cross-process calls.
    unsafe {
        NodeInfo {
            control_type: el.CachedControlType().map(|c| c.0).unwrap_or(0),
            class_name: el
                .CachedClassName()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            automation_id: el
                .CachedAutomationId()
                .map(|s| s.to_string())
                .unwrap_or_default(),
            has_focus: el.CachedHasKeyboardFocus().is_ok_and(|b| b.as_bool()),
        }
    }
}

/// The address field of `browser`'s window `hwnd`, if found within budget.
/// `Err(())` if the budget ran out or the browser stopped answering.
fn find_address(
    uia: &Uia,
    hwnd: HWND,
    browser: Browser,
    deadline: Instant,
    mut on_node: impl FnMut(usize, &NodeInfo, Visit),
) -> Result<Option<(IUIAutomationElement, NodeInfo)>, ()> {
    // SAFETY: valid automation object and cache request; a stale hwnd only
    // makes the call fail.
    let root =
        unsafe { uia.automation.ElementFromHandleBuildCache(hwnd, &uia.cache) }.map_err(|_| ())?;
    // (element, depth, inside a toolbar)
    let mut queue = VecDeque::from([(root, 0usize, false)]);
    let mut visited = 0usize;
    while let Some((el, depth, in_toolbar)) = queue.pop_front() {
        visited += 1;
        if visited > MAX_NODES {
            break;
        }
        let info = node_info(&el);
        let visit = if visited == 1 {
            // The window itself is never the page or the field.
            Visit::Descend
        } else {
            classify(browser, &info)
        };
        on_node(depth, &info, visit);
        match visit {
            Visit::Address => return Ok(Some((el, info))),
            Visit::Skip => continue,
            Visit::Descend if depth >= MAX_DEPTH => continue,
            Visit::Descend => {}
        }
        if Instant::now() >= deadline {
            return Err(());
        }
        // All children with their cached properties in one call (a walker
        // would need one call per child).
        // SAFETY: valid element, condition and cache request.
        let Ok(children) =
            (unsafe { el.FindAllBuildCache(TreeScope_Children, &uia.control_view, &uia.cache) })
        else {
            continue;
        };
        // SAFETY: plain array accessors.
        let n = unsafe { children.Length() }.unwrap_or(0);
        let mut toolbar_first = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
        for i in 0..n {
            // SAFETY: `i` is within the array's length.
            if let Ok(c) = unsafe { children.GetElement(i) } {
                toolbar_first.push(c);
            }
        }
        // Both address fields live in a toolbar: walk toolbars depth-first
        // ahead of everything else, the rest breadth-first.
        for c in toolbar_first.into_iter().rev() {
            // SAFETY: cached getter.
            let is_toolbar =
                unsafe { c.CachedControlType() }.is_ok_and(|t| t == UIA_ToolBarControlTypeId);
            if in_toolbar || is_toolbar {
                queue.push_front((c, depth + 1, true));
            } else {
                queue.push_back((c, depth + 1, false));
            }
        }
    }
    Ok(None)
}

/// The reduced URL shown in `browser`'s top-level window `hwnd`, or `None`
/// if it can't be read. Sensitive: callers must not log it.
pub fn tab_url(hwnd: HWND, browser: Browser) -> Option<String> {
    if hwnd.0.is_null() {
        return None;
    }
    let deadline = Instant::now() + READ_BUDGET;
    with_uia(|uia| {
        let (field, info) = find_address(uia, hwnd, browser, deadline, |_, _, _| {})
            .ok()
            .flatten()?;
        if info.has_focus || Instant::now() >= deadline {
            return None;
        }
        // SAFETY: a valid element; the pattern call is bounded by the UIA
        // timeouts.
        let value: BSTR = unsafe {
            field
                .GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId)
                .ok()?
                .CurrentValue()
                .ok()?
        };
        reduce_address_text(&value.to_string())
    })
}

/// For the `browser_probe` example: walk `hwnd` as [`tab_url`] does and
/// report each visited node's depth, control type, class name, automation
/// id and decision. Never names or values (those can be titles or page
/// text). Returns whether the address field was found.
pub fn debug_walk(
    hwnd: HWND,
    browser: Browser,
    mut f: impl FnMut(usize, &NodeInfo, Visit),
) -> bool {
    let deadline = Instant::now() + READ_BUDGET * 4;
    with_uia(|uia| {
        find_address(uia, hwnd, browser, deadline, &mut f)
            .ok()
            .flatten()
            .map(|_| ())
    })
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_browsers_by_exe_name() {
        let cases = [
            ("msedge.exe", Some(Browser::Edge)),
            ("MSEDGE.EXE", Some(Browser::Edge)),
            ("chrome.exe", Some(Browser::Chrome)),
            (
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                Some(Browser::Chrome),
            ),
            ("brave.exe", Some(Browser::Brave)),
            ("firefox.exe", Some(Browser::Firefox)),
            ("librewolf.exe", Some(Browser::LibreWolf)),
            ("waterfox.exe", Some(Browser::Waterfox)),
            (" zen.exe ", Some(Browser::Zen)),
            ("floorp.exe", Some(Browser::Floorp)),
            ("opera.exe", None),
            ("vivaldi.exe", None),
            ("chrome_proxy.exe", None),
            ("msedgewebview2.exe", None),
            ("notepad.exe", None),
            ("", None),
        ];
        for (name, want) in cases {
            assert_eq!(Browser::from_exe_name(name), want, "{name}");
        }
        assert!(Browser::Brave.is_chromium());
        assert!(!Browser::LibreWolf.is_chromium());
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
                "https://bücher.example/",
                Some("https://xn--bcher-kva.example/"),
            ),
            ("https://192.168.1.1/admin", Some("https://192.168.1.1/")),
            ("http://[::1]:8080/", Some("http://[::1]/")),
            ("file:///C:/Users/sam/secret.pdf", None),
            ("about:blank", None),
            ("edge://settings", None),
            ("chrome://newtab/", None),
            ("javascript:alert(1)", None),
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
            ("edge://settings", None),
            ("a.com/?u=http://b.com", Some("https://a.com/")),
            ("faro", None),
            ("how to fix a bike", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(reduce_address_text(text).as_deref(), want, "{text}");
        }
        assert!(has_scheme("chrome-extension://abc"));
        assert!(!has_scheme("1http://x"));
    }

    fn node(ct: UIA_CONTROLTYPE_ID, class: &str, id: &str) -> NodeInfo {
        NodeInfo {
            control_type: ct.0,
            class_name: class.into(),
            automation_id: id.into(),
            has_focus: false,
        }
    }

    #[test]
    fn walk_rules_never_enter_the_page() {
        use Visit::*;
        let doc = node(UIA_DocumentControlTypeId, "", "");
        let rwh = node(
            windows::Win32::UI::Accessibility::UIA_PaneControlTypeId,
            CHROMIUM_RENDER_WIDGET_CLASS,
            "",
        );
        for b in [Browser::Chrome, Browser::Firefox] {
            assert_eq!(classify(b, &doc), Skip);
            assert_eq!(classify(b, &rwh), Skip);
        }
        let omnibox = node(UIA_EditControlTypeId, CHROMIUM_OMNIBOX_CLASS, "");
        let urlbar = node(UIA_EditControlTypeId, "", FIREFOX_URLBAR_ID);
        let other_edit = node(UIA_EditControlTypeId, "Textfield", "");
        assert_eq!(classify(Browser::Edge, &omnibox), Address);
        assert_eq!(classify(Browser::Edge, &urlbar), Skip);
        assert_eq!(classify(Browser::Edge, &other_edit), Skip);
        assert_eq!(classify(Browser::LibreWolf, &urlbar), Address);
        let urlbar_combo = node(
            UIA_ComboBoxControlTypeId,
            "urlbar-input textbox-input",
            FIREFOX_URLBAR_ID,
        );
        assert_eq!(classify(Browser::Firefox, &urlbar_combo), Address);
        assert_eq!(classify(Browser::Chrome, &urlbar_combo), Descend);
        let page_combo = node(UIA_ComboBoxControlTypeId, "", "search");
        assert_eq!(classify(Browser::Zen, &page_combo), Skip);
        assert_eq!(classify(Browser::LibreWolf, &omnibox), Skip);
        let pane = node(
            windows::Win32::UI::Accessibility::UIA_PaneControlTypeId,
            "BrowserRootView",
            "",
        );
        assert_eq!(classify(Browser::Chrome, &pane), Descend);
        let tab = node(UIA_TabItemControlTypeId, "Tab", "");
        assert_eq!(classify(Browser::Chrome, &tab), Skip);
    }

    #[test]
    fn tab_url_for_null_window_is_none() {
        assert_eq!(tab_url(HWND::default(), Browser::Chrome), None);
    }

    #[test]
    fn uia_sets_up_on_a_plain_thread() {
        // A fresh thread, as the agent's platform thread is.
        std::thread::spawn(|| {
            assert!(with_uia(|_| Some(())).is_some(), "UIA client created");
            // A second use reuses it.
            assert!(with_uia(|_| Some(())).is_some());
        })
        .join()
        .unwrap();
    }
}
