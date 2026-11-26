//! The agent's presence on screen in every session (ARCHITECTURE.md §12):
//! a menu-bar icon that is there for as long as the agent runs, and the
//! monitoring notice the service sends at login (`ShowNotice`).
//!
//! The agent runs in every account's session (§3.1), so this is what tells
//! everyone who uses the computer that it is monitored. It lives in the
//! agent rather than in the optional tray app because the agent is the
//! process that is always there: launchd starts it in every session, and
//! the service raises tamper when a session has none.
//!
//! # Threads
//!
//! AppKit runs on the main thread ([`SessionUi::run`]), so the agent's own
//! loop moves to a worker thread and reaches the UI through a
//! [`UiHandle`], which queues work on the main dispatch queue. The notice
//! is an `NSAlert` run modally from that queue: while it is open, later
//! notices wait behind it, and one that arrives anyway (the menu's "Show
//! the monitoring notice…") is shown again after it closes.
//!
//! The agent's own warnings, such as Screen Recording being off, are
//! another alert ([`UiHandle::show_settings_notice`]) whose first button
//! opens the System Settings pane that fixes it.
//!
//! # The status menu
//!
//! Under the first line, the menu says what Faro is doing (issue #89):
//! "Status: Monitoring", "Status: Screen Recording is off", "Status: Not
//! enrolled"… ([`UiHandle::set_status`]; the words come from
//! `faro_agent::status_menu`). Clicking the line explains it and what to
//! do. When something fixes it, an item below opens that (a System
//! Settings pane, the web app's Computers page). Then "Open Faro" (the
//! instance's web app), the monitoring notice, enrolling, "Report a
//! problem…" (how to run `faro-service diagnose`, with a button that
//! copies the command; it sends the service nothing) and "About Faro…"
//! (versions, the instance, and the third-party notices in
//! `/Library/Faro/notices`). Nothing on the menu stops monitoring, pauses
//! it or hides anything.
//!
//! # Enrolling
//!
//! The agent can also enroll the computer (issue #62). The bundle registers
//! the `faro` URL scheme, so opening a `faro://enroll` link reaches
//! `application:openURLs:`, and the menu has "Enroll this computer…". Both
//! call the handler set with [`SessionUi::on_enroll`], on the main thread;
//! the agent runs the flow on a worker thread of its own and shows each
//! screen through the blocking [`UiHandle::ask_enroll_target`],
//! [`UiHandle::confirm`] and [`UiHandle::message`], which run an `NSAlert`
//! on the main queue and wait for it. They must never be called from the
//! main thread (they return at once there instead of deadlocking).
//!
//! # Quitting
//!
//! As an `NSApplication`, the agent receives a Quit Apple Event at logout.
//! AppKit's default would exit at once, before the agent tells the service
//! `Goodbye`. Instead, `applicationShouldTerminate:` calls the `on_quit`
//! hook (the agent treats it like SIGTERM) and answers `TerminateLater`.
//! The agent thread then says goodbye and ends the process, which answers
//! the request.
//!
//! # The icon cannot be hidden
//!
//! The status item has no removal behavior, so it can't be dragged out of
//! the menu bar, and the menu has no Quit item. macOS 26 lets the user turn
//! menu-bar items off in System Settings; detecting that is a follow-up.

use std::cell::{Cell, OnceCell, RefCell};

use dispatch2::DispatchQueue;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, AnyThread, DefinedClass, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSAlertStyle, NSApplication,
    NSApplicationActivationPolicy, NSApplicationDelegate, NSApplicationTerminateReply,
    NSBitmapImageRep, NSFloatingWindowLevel, NSImage, NSMenu, NSMenuItem, NSModalResponse,
    NSPasteboard, NSPasteboardTypeString, NSStatusBar, NSStatusItem, NSTextField,
    NSVariableStatusItemLength, NSView, NSWorkspace,
};
use objc2_foundation::{
    ns_string, NSArray, NSBundle, NSData, NSNotification, NSObject, NSObjectProtocol, NSPoint,
    NSRect, NSSize, NSString, NSURL,
};

pub use objc2::MainThreadMarker;

/// The menu's first line and the icon's tooltip.
pub const MONITORED: &str = "This computer is monitored by Faro";

/// Shown by "Show the monitoring notice…" until the service has sent its
/// own notice, which names the instance and counts the allies.
pub const DEFAULT_NOTICE_BODY: &str = "Every account on this computer is monitored by Faro. \
     Screenshots are blurred on this computer and shared, encrypted, only with the member \
     and their allies. Switching to or creating another account does not turn monitoring off.";

/// The Faro mark in the menu bar, 18 pt square, at 1x and 2x: black on
/// transparent, drawn as a template image. Built from the brand SVG by
/// assets/brand/make-tray-icons.swift.
const MENU_BAR_ICON: [(&[u8], f64); 2] = [
    (
        include_bytes!("../../../assets/brand/tray/faro-menubar.png"),
        18.0,
    ),
    (
        include_bytes!("../../../assets/brand/tray/faro-menubar@2x.png"),
        36.0,
    ),
];
/// The menu-bar icon's size in points.
const MENU_BAR_ICON_POINTS: f64 = 18.0;

/// What the menu shows for "Show the monitoring notice…".
const SHOW_NOTICE: &str = "Show the monitoring notice\u{2026}";

/// What the menu shows for enrolling.
const ENROLL: &str = "Enroll this computer\u{2026}";

/// The menu item that opens the instance's web app.
pub const OPEN_FARO: &str = "Open Faro";

/// The menu item that shows the About window.
pub const ABOUT: &str = "About Faro\u{2026}";

/// The About window's button that shows the third-party notices.
pub const SHOW_NOTICES: &str = "Show Third-Party Notices";

/// The menu item that explains how to make a problem report.
pub const REPORT_PROBLEM: &str = "Report a problem\u{2026}";

/// The status line before the agent has told the UI anything.
const STATUS_STARTING: &str = "Connecting to the Faro service\u{2026}";

/// The status menu's items, once the menu exists.
struct StatusItems {
    status: Retained<NSMenuItem>,
    fix: Retained<NSMenuItem>,
    open: Retained<NSMenuItem>,
    report: Retained<NSMenuItem>,
}

/// The agent's bundle identifier: only the real bundle registers itself
/// with LaunchServices for `faro://` links.
const BUNDLE_ID: &str = "org.faro.agent";

/// Called on the main thread with a `faro:` link, or `None` from the menu.
type EnrollHandler = Box<dyn Fn(Option<String>)>;

struct Ivars {
    /// The latest notice: shown again from the menu.
    notice: RefCell<(String, String)>,
    /// A notice alert is open.
    showing: Cell<bool>,
    /// Show the notice again when the open alert closes.
    again: Cell<bool>,
    /// A settings notice ([`UiHandle::show_settings_notice`]) is open.
    settings_showing: Cell<bool>,
    on_quit: Box<dyn Fn()>,
    on_enroll: OnceCell<EnrollHandler>,
    status_item: OnceCell<Retained<NSStatusItem>>,
    /// The latest status ([`UiHandle::set_status`]).
    status: RefCell<StatusMenu>,
    /// The items that show it.
    items: OnceCell<StatusItems>,
}

define_class!(
    // SAFETY:
    // - NSObject has no subclassing requirements.
    // - `Delegate` does not implement `Drop`.
    #[unsafe(super = NSObject)]
    #[thread_kind = MainThreadOnly]
    #[name = "FaroSessionUi"]
    #[ivars = Ivars]
    struct Delegate;

    // SAFETY: NSObjectProtocol has no safety requirements.
    unsafe impl NSObjectProtocol for Delegate {}

    // SAFETY: NSApplicationDelegate has no safety requirements, and the
    // method signatures match the protocol.
    unsafe impl NSApplicationDelegate for Delegate {
        #[unsafe(method(applicationDidFinishLaunching:))]
        fn did_finish_launching(&self, _notification: &NSNotification) {
            self.install_status_item();
            if self.ivars().on_enroll.get().is_some() {
                register_url_scheme();
            }
        }

        #[unsafe(method(application:openURLs:))]
        fn open_urls(&self, _application: &NSApplication, urls: &NSArray<NSURL>) {
            // One enrollment at a time; the first `faro:` link wins.
            let link = urls.iter().find_map(|u| {
                let s = u.absoluteString()?.to_string();
                s.get(..5)
                    .is_some_and(|p| p.eq_ignore_ascii_case("faro:"))
                    .then_some(s)
            });
            if let (Some(link), Some(f)) = (link, self.ivars().on_enroll.get()) {
                f(Some(link));
            }
        }

        #[unsafe(method(applicationShouldTerminate:))]
        fn should_terminate(&self, _sender: &NSApplication) -> NSApplicationTerminateReply {
            (self.ivars().on_quit)();
            NSApplicationTerminateReply::TerminateLater
        }
    }

    impl Delegate {
        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(showNotice:))]
        fn show_notice_action(&self, _sender: Option<&AnyObject>) {
            self.present();
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(enroll:))]
        fn enroll_action(&self, _sender: Option<&AnyObject>) {
            if let Some(f) = self.ivars().on_enroll.get() {
                f(None);
            }
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(showStatus:))]
        fn show_status_action(&self, _sender: Option<&AnyObject>) {
            self.present_status();
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(fixProblem:))]
        fn fix_action(&self, _sender: Option<&AnyObject>) {
            let url = self.ivars().status.borrow().fix.as_ref().map(|f| f.url.clone());
            if let Some(url) = url {
                open_url(&url);
            }
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(openFaro:))]
        fn open_faro_action(&self, _sender: Option<&AnyObject>) {
            let url = self.ivars().status.borrow().web_app.clone();
            if let Some(url) = url {
                open_url(&url);
            }
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(reportProblem:))]
        fn report_action(&self, _sender: Option<&AnyObject>) {
            self.present_report();
        }

        // SAFETY: an action method: one object argument, no return value.
        #[unsafe(method(about:))]
        fn about_action(&self, _sender: Option<&AnyObject>) {
            self.present_about();
        }
    }
);

impl Delegate {
    fn new(mtm: MainThreadMarker, on_quit: Box<dyn Fn()>) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(Ivars {
            notice: RefCell::new((MONITORED.to_owned(), DEFAULT_NOTICE_BODY.to_owned())),
            showing: Cell::new(false),
            again: Cell::new(false),
            settings_showing: Cell::new(false),
            on_quit,
            on_enroll: OnceCell::new(),
            status_item: OnceCell::new(),
            status: RefCell::new(StatusMenu::starting()),
            items: OnceCell::new(),
        });
        // SAFETY: NSObject's `init` has this signature.
        unsafe { msg_send![super(this), init] }
    }

    fn install_status_item(&self) {
        let mtm = self.mtm();
        let monitored = NSString::from_str(MONITORED);
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        if let Some(button) = item.button(mtm) {
            match menu_bar_icon(&monitored) {
                Some(icon) => button.setImage(Some(&icon)),
                None => button.setTitle(ns_string!("Faro")),
            }
            button.setToolTip(Some(&monitored));
        }

        let menu = NSMenu::new(mtm);
        menu.setAutoenablesItems(false);
        let header = menu_item(mtm, MONITORED, None);
        header.setEnabled(false);
        menu.addItem(&header);
        menu.addItem(&NSMenuItem::separatorItem(mtm));
        // Every item's target is `self`, which implements its action. The
        // status item that holds the menu is kept in `self`, so the target
        // outlives the menu items' use of it.
        let targeted = |title: &str, action: Sel| {
            let i = menu_item(mtm, title, Some(action));
            // SAFETY: see above.
            unsafe { i.setTarget(Some(self.as_ref())) };
            i
        };
        let status = targeted(STATUS_STARTING, sel!(showStatus:));
        menu.addItem(&status);
        let fix = targeted("", sel!(fixProblem:));
        menu.addItem(&fix);
        menu.addItem(&NSMenuItem::separatorItem(mtm));
        let open = targeted(OPEN_FARO, sel!(openFaro:));
        menu.addItem(&open);
        menu.addItem(&targeted(SHOW_NOTICE, sel!(showNotice:)));
        if self.ivars().on_enroll.get().is_some() {
            menu.addItem(&targeted(ENROLL, sel!(enroll:)));
        }
        let report = targeted(REPORT_PROBLEM, sel!(reportProblem:));
        menu.addItem(&report);
        menu.addItem(&targeted(ABOUT, sel!(about:)));
        item.setMenu(Some(&menu));

        // Set once, from the one `applicationDidFinishLaunching:`.
        let _ = self.ivars().status_item.set(item);
        let _ = self.ivars().items.set(StatusItems {
            status,
            fix,
            open,
            report,
        });
        self.refresh_status();
    }

    /// Store `s` and show it in the menu.
    fn set_status(&self, s: StatusMenu) {
        *self.ivars().status.borrow_mut() = s;
        self.refresh_status();
    }

    /// Make the menu items show the stored status.
    fn refresh_status(&self) {
        let iv = self.ivars();
        let Some(items) = iv.items.get() else {
            return;
        };
        let s = iv.status.borrow();
        items
            .status
            .setTitle(&NSString::from_str(&format!("Status: {}", s.line)));
        match &s.fix {
            Some(f) => {
                items.fix.setTitle(&NSString::from_str(&f.label));
                items.fix.setHidden(false);
            }
            None => items.fix.setHidden(true),
        }
        items.open.setHidden(s.web_app.is_none());
        items.report.setHidden(s.report.is_none());
    }

    /// How to make a problem report, with a button that copies the
    /// command. It explains only; nothing is sent to the service.
    fn present_report(&self) {
        let Some(r) = self.ivars().status.borrow().report.clone() else {
            return;
        };
        let mtm = self.mtm();
        let a = alert(mtm, &r.title, &r.body, false);
        a.addButtonWithTitle(&NSString::from_str(&r.copy));
        a.addButtonWithTitle(ns_string!("OK"));
        if run_in_front(mtm, &a) {
            let board = NSPasteboard::generalPasteboard();
            board.clearContents();
            // SAFETY: `NSPasteboardTypeString` is an immutable constant
            // AppKit defines.
            let kind = unsafe { NSPasteboardTypeString };
            if !board.setString_forType(&NSString::from_str(&r.command), kind) {
                eprintln!("faro-agent: could not copy the command");
            }
        }
    }

    /// The status line and what to do, with the fix's button if there is
    /// one.
    fn present_status(&self) {
        let s = self.ivars().status.borrow().clone();
        let mtm = self.mtm();
        let a = alert(mtm, &s.line, &s.detail, s.problem);
        if let Some(f) = &s.fix {
            a.addButtonWithTitle(&NSString::from_str(f.label.trim_end_matches('\u{2026}')));
        }
        a.addButtonWithTitle(ns_string!("OK"));
        if run_in_front(mtm, &a) {
            if let Some(f) = &s.fix {
                open_url(&f.url);
            }
        }
    }

    /// Versions, the instance, and the third-party notices.
    fn present_about(&self) {
        let s = self.ivars().status.borrow().clone();
        let mtm = self.mtm();
        let a = alert(mtm, &s.about_title, &s.about_body, false);
        a.addButtonWithTitle(ns_string!("OK"));
        a.addButtonWithTitle(&NSString::from_str(SHOW_NOTICES));
        if run_modal_in_front(mtm, &a) == NSAlertSecondButtonReturn {
            open_url(&format!("file://{}/", crate::pkg_layout::NOTICES_DIR));
        }
    }

    fn set_notice(&self, title: String, body: String) {
        *self.ivars().notice.borrow_mut() = (title, body);
    }

    /// Show the latest notice, unless one is already open.
    fn present(&self) {
        let iv = self.ivars();
        if iv.showing.replace(true) {
            iv.again.set(true);
            return;
        }
        let mtm = self.mtm();
        loop {
            let (title, body) = iv.notice.borrow().clone();
            let alert = NSAlert::new(mtm);
            alert.setAlertStyle(NSAlertStyle::Informational);
            alert.setMessageText(&NSString::from_str(&title));
            alert.setInformativeText(&NSString::from_str(&body));
            alert.addButtonWithTitle(ns_string!("OK"));
            // An accessory app's alert would otherwise open behind the
            // frontmost app's windows.
            alert.window().setLevel(NSFloatingWindowLevel);
            // `activate` is macOS 14+; this one works on 13 as well.
            #[allow(deprecated)]
            NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
            alert.runModal();
            if !iv.again.replace(false) {
                break;
            }
        }
        iv.showing.set(false);
    }

    /// Show a warning whose first button opens `url`, unless one is
    /// already open (the agent sends each once anyway).
    fn present_settings(&self, n: &SettingsNotice) {
        let iv = self.ivars();
        if iv.settings_showing.replace(true) {
            return;
        }
        let mtm = self.mtm();
        let a = alert(mtm, &n.title, &n.body, true);
        a.addButtonWithTitle(&NSString::from_str(&n.open));
        a.addButtonWithTitle(&NSString::from_str(&n.later));
        if run_in_front(mtm, &a) {
            open_url(&n.url);
        }
        iv.settings_showing.set(false);
    }
}

/// Open a URL (here, a System Settings pane) with its default handler.
fn open_url(url: &str) {
    let opened = NSURL::URLWithString(&NSString::from_str(url))
        .is_some_and(|u| NSWorkspace::sharedWorkspace().openURL(&u));
    if !opened {
        eprintln!("faro-agent: could not open {url}");
    }
}

/// The menu-bar icon: the embedded PNGs as one template image, so macOS
/// draws it in the menu bar's colour and picks the 1x or 2x pixels. `None`
/// if a PNG doesn't decode (the caller then shows "Faro" as text).
fn menu_bar_icon(description: &NSString) -> Option<Retained<NSImage>> {
    let size = NSSize::new(MENU_BAR_ICON_POINTS, MENU_BAR_ICON_POINTS);
    let image = NSImage::initWithSize(NSImage::alloc(), size);
    for (png, pixels) in MENU_BAR_ICON {
        let rep = NSBitmapImageRep::imageRepWithData(&NSData::with_bytes(png))?;
        if rep.pixelsWide() as f64 != pixels {
            return None;
        }
        rep.setSize(size);
        image.addRepresentation(&rep);
    }
    image.setTemplate(true);
    image.setAccessibilityDescription(Some(description));
    Some(image)
}

fn menu_item(mtm: MainThreadMarker, title: &str, action: Option<Sel>) -> Retained<NSMenuItem> {
    // SAFETY: the action, if any, is implemented by the target set on it.
    unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(mtm),
            &NSString::from_str(title),
            action,
            ns_string!(""),
        )
    }
}

/// Register this bundle with LaunchServices, so `faro://` links open it.
/// The installer may not have registered an app outside /Applications for
/// every account; doing it at launch covers each account's first login.
/// Only the real bundle does it, never a development binary.
fn register_url_scheme() {
    let bundle = NSBundle::mainBundle();
    let is_agent = bundle
        .bundleIdentifier()
        .is_some_and(|id| id.to_string() == BUNDLE_ID);
    if !is_agent {
        return;
    }
    let url = bundle.bundleURL();
    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        fn LSRegisterURL(url: *const std::ffi::c_void, update: u8) -> i32;
    }
    // SAFETY: NSURL is toll-free bridged to CFURL, and `url` outlives the
    // call.
    let status = unsafe { LSRegisterURL(Retained::as_ptr(&url).cast(), 0) };
    if status != 0 {
        eprintln!("faro-agent: LSRegisterURL failed (OSStatus {status})");
    }
}

/// An alert in front of every window, as the notice is.
fn alert(mtm: MainThreadMarker, title: &str, body: &str, warning: bool) -> Retained<NSAlert> {
    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(if warning {
        NSAlertStyle::Warning
    } else {
        NSAlertStyle::Informational
    });
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(body));
    alert
}

/// Run `alert` in front of every window; `true` if its first button was
/// pressed.
fn run_in_front(mtm: MainThreadMarker, alert: &NSAlert) -> bool {
    run_modal_in_front(mtm, alert) == NSAlertFirstButtonReturn
}

/// Run `alert` in front of every window and return which button closed it.
fn run_modal_in_front(mtm: MainThreadMarker, alert: &NSAlert) -> NSModalResponse {
    alert.window().setLevel(NSFloatingWindowLevel);
    // `activate` is macOS 14+; this one works on 13 as well.
    #[allow(deprecated)]
    NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
    alert.runModal()
}

/// The words of a notice that offers to open a System Settings pane (see
/// [`UiHandle::show_settings_notice`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsNotice {
    pub title: String,
    pub body: String,
    /// The first button: opens `url`.
    pub open: String,
    /// The second button: only closes the notice.
    pub later: String,
    pub url: String,
}

/// A menu item that fixes a problem: its title and the URL it opens (a
/// System Settings pane, the web app's Computers page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusFix {
    pub label: String,
    pub url: String,
}

/// What the status menu shows (see [`UiHandle::set_status`]). The words
/// come from `faro_agent::status_menu`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMenu {
    /// The status line ("Monitoring").
    pub line: String,
    /// What it means and what to do, shown when the line is clicked.
    pub detail: String,
    /// Shown as a warning.
    pub problem: bool,
    /// The item that fixes it, if any.
    pub fix: Option<StatusFix>,
    /// "Open Faro" opens this; hidden without one.
    pub web_app: Option<String>,
    /// The About window.
    pub about_title: String,
    pub about_body: String,
    /// "Report a problem…"; hidden without one.
    pub report: Option<ReportProblem>,
}

/// The words of "Report a problem…": how to make a report, and the
/// command its first button copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportProblem {
    pub title: String,
    pub body: String,
    /// The button that copies `command` to the clipboard.
    pub copy: String,
    pub command: String,
}

impl StatusMenu {
    fn starting() -> Self {
        StatusMenu {
            line: STATUS_STARTING.to_owned(),
            detail: String::new(),
            problem: false,
            fix: None,
            web_app: None,
            about_title: "About Faro".to_owned(),
            about_body: String::new(),
            report: None,
        }
    }
}

/// The words of a two-field window (see [`UiHandle::ask_enroll_target`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoFields {
    pub title: String,
    pub body: String,
    pub first_label: String,
    pub first_placeholder: String,
    pub second_label: String,
    pub second_placeholder: String,
    pub ok: String,
    pub cancel: String,
}

fn two_field_alert(mtm: MainThreadMarker, t: &TwoFields) -> Option<(String, String)> {
    let alert = alert(mtm, &t.title, &t.body, false);
    alert.addButtonWithTitle(&NSString::from_str(&t.ok));
    alert.addButtonWithTitle(&NSString::from_str(&t.cancel));
    let rect = |x: f64, y: f64, w: f64, h: f64| NSRect::new(NSPoint::new(x, y), NSSize::new(w, h));
    let width = 340.0;
    let view = NSView::initWithFrame(NSView::alloc(mtm), rect(0.0, 0.0, width, 112.0));
    let label = |text: &str, y: f64| {
        let l = NSTextField::labelWithString(&NSString::from_str(text), mtm);
        l.setFrame(rect(0.0, y, width, 18.0));
        view.addSubview(&l);
    };
    let field = |placeholder: &str, y: f64| {
        let f = NSTextField::initWithFrame(NSTextField::alloc(mtm), rect(0.0, y, width, 24.0));
        f.setPlaceholderString(Some(&NSString::from_str(placeholder)));
        view.addSubview(&f);
        f
    };
    label(&t.first_label, 90.0);
    let first = field(&t.first_placeholder, 64.0);
    label(&t.second_label, 32.0);
    let second = field(&t.second_placeholder, 6.0);
    // SAFETY: both fields live in `view` for as long as the alert does.
    unsafe { first.setNextKeyView(Some(&second)) };
    alert.setAccessoryView(Some(&view));
    alert.window().setInitialFirstResponder(Some(&first));
    if !run_in_front(mtm, &alert) {
        return None;
    }
    Some((
        first.stringValue().to_string(),
        second.stringValue().to_string(),
    ))
}

/// Run `f` on the main thread and wait for it. `None` if called from the
/// main thread itself, which would deadlock.
fn on_main_and_wait<T: Send>(f: impl FnOnce(MainThreadMarker) -> T + Send) -> Option<T> {
    if MainThreadMarker::new().is_some() {
        return None;
    }
    let mut out = None;
    let slot = &mut out;
    DispatchQueue::main().exec_sync(move || {
        if let Some(mtm) = MainThreadMarker::new() {
            *slot = Some(f(mtm));
        }
    });
    out
}

thread_local! {
    /// The UI, on the main thread, for work queued by a [`UiHandle`].
    static UI: OnceCell<Retained<Delegate>> = const { OnceCell::new() };
}

/// The agent's AppKit UI. Create it and [`run`](Self::run) it on the main
/// thread; talk to it from other threads through a [`UiHandle`].
#[derive(Debug)]
pub struct SessionUi {
    app: Retained<NSApplication>,
}

impl SessionUi {
    /// Set up the application as an accessory (no Dock icon). The menu-bar
    /// icon appears once [`run`](Self::run) starts. `on_quit` is called
    /// when AppKit is asked to quit (see the module docs); the caller must
    /// then end the process.
    ///
    /// # Panics
    ///
    /// If called twice in one process.
    pub fn new(mtm: MainThreadMarker, on_quit: impl Fn() + 'static) -> Self {
        let app = NSApplication::sharedApplication(mtm);
        app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        let delegate = Delegate::new(mtm, Box::new(on_quit));
        app.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        UI.with(|ui| {
            assert!(ui.set(delegate).is_ok(), "SessionUi::new called twice");
        });
        SessionUi { app }
    }

    pub fn handle(&self) -> UiHandle {
        UiHandle { _private: () }
    }

    /// Offer enrollment: register for `faro://` links, add "Enroll this
    /// computer…" to the menu, and call `handler` on the main thread with
    /// the link (or `None` from the menu). Call before [`run`](Self::run);
    /// later calls are ignored.
    pub fn on_enroll(&self, handler: impl Fn(Option<String>) + 'static) {
        UI.with(|ui| {
            if let Some(ui) = ui.get() {
                let _ = ui.ivars().on_enroll.set(Box::new(handler));
            }
        });
    }

    /// Run AppKit's event loop. It does not return in normal operation: the
    /// agent thread ends the process.
    pub fn run(self) {
        self.app.run();
    }
}

/// Reaches the [`SessionUi`] from any thread.
#[derive(Debug, Clone, Copy)]
pub struct UiHandle {
    _private: (),
}

impl UiHandle {
    /// Ask for a link, or an address and a code (two fields). `None` if
    /// cancelled. Blocks; never call it from the main thread.
    pub fn ask_enroll_target(&self, text: &TwoFields) -> Option<(String, String)> {
        on_main_and_wait(|mtm| two_field_alert(mtm, text)).flatten()
    }

    /// Ask a yes-or-no question: `true` for `ok`. Blocks; never call it
    /// from the main thread.
    pub fn confirm(&self, title: &str, body: &str, ok: &str, cancel: &str) -> bool {
        on_main_and_wait(|mtm| {
            let a = alert(mtm, title, body, false);
            a.addButtonWithTitle(&NSString::from_str(ok));
            a.addButtonWithTitle(&NSString::from_str(cancel));
            run_in_front(mtm, &a)
        })
        .unwrap_or(false)
    }

    /// Show a message with one button. Blocks until it is closed; never
    /// call it from the main thread.
    pub fn message(&self, title: &str, body: &str, warning: bool) {
        on_main_and_wait(|mtm| {
            let a = alert(mtm, title, body, warning);
            a.addButtonWithTitle(ns_string!("OK"));
            run_in_front(mtm, &a);
        });
    }

    /// Show a warning with a button that opens a System Settings pane, for
    /// example Screen Recording when Faro doesn't have it. Doesn't block,
    /// and doesn't replace the monitoring notice in the menu.
    pub fn show_settings_notice(&self, notice: SettingsNotice) {
        DispatchQueue::main().exec_async(move || {
            UI.with(|ui| {
                if let Some(ui) = ui.get() {
                    ui.present_settings(&notice);
                }
            });
        });
    }

    /// Show `status` in the menu: the status line, the item that fixes a
    /// problem, "Open Faro" and the About window. Doesn't block, and never
    /// opens a window by itself.
    pub fn set_status(&self, status: StatusMenu) {
        DispatchQueue::main().exec_async(move || {
            UI.with(|ui| {
                if let Some(ui) = ui.get() {
                    ui.set_status(status);
                }
            });
        });
    }

    /// Show `title` and `body` in an alert now, and from the menu later.
    pub fn show_notice(&self, title: &str, body: &str) {
        let (title, body) = (title.to_owned(), body.to_owned());
        DispatchQueue::main().exec_async(move || {
            UI.with(|ui| {
                if let Some(ui) = ui.get() {
                    ui.set_notice(title, body);
                    ui.present();
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded PNGs decode at 18 and 36 pixels, so the menu bar shows
    /// the Faro mark rather than the "Faro" text fallback.
    #[test]
    fn the_menu_bar_icon_decodes() {
        let icon = menu_bar_icon(ns_string!("Faro")).expect("menu-bar icon");
        assert!(icon.isTemplate());
        assert_eq!(icon.representations().count(), 2);
    }
}
