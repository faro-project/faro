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
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadOnly};
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertStyle, NSApplication,
    NSApplicationActivationPolicy, NSApplicationDelegate, NSApplicationTerminateReply,
    NSFloatingWindowLevel, NSImage, NSMenu, NSMenuItem, NSStatusBar, NSStatusItem, NSTextField,
    NSVariableStatusItemLength, NSView,
};
use objc2_foundation::{
    ns_string, NSArray, NSBundle, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect,
    NSSize, NSString, NSURL,
};

pub use objc2::MainThreadMarker;

/// The menu's first line and the icon's tooltip.
pub const MONITORED: &str = "This computer is monitored by Faro";

/// Shown by "Show the monitoring notice…" until the service has sent its
/// own notice, which names the instance and counts the allies.
pub const DEFAULT_NOTICE_BODY: &str = "Every account on this computer is monitored by Faro. \
     Screenshots are blurred on this computer and shared, encrypted, only with the member \
     and their allies. Switching to or creating another account does not turn monitoring off.";

/// The SF Symbol in the menu bar.
const ICON_SYMBOL: &str = "eye";

/// What the menu shows for "Show the monitoring notice…".
const SHOW_NOTICE: &str = "Show the monitoring notice\u{2026}";

/// What the menu shows for enrolling.
const ENROLL: &str = "Enroll this computer\u{2026}";

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
    on_quit: Box<dyn Fn()>,
    on_enroll: OnceCell<EnrollHandler>,
    status_item: OnceCell<Retained<NSStatusItem>>,
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
    }
);

impl Delegate {
    fn new(mtm: MainThreadMarker, on_quit: Box<dyn Fn()>) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(Ivars {
            notice: RefCell::new((MONITORED.to_owned(), DEFAULT_NOTICE_BODY.to_owned())),
            showing: Cell::new(false),
            again: Cell::new(false),
            on_quit,
            on_enroll: OnceCell::new(),
            status_item: OnceCell::new(),
        });
        // SAFETY: NSObject's `init` has this signature.
        unsafe { msg_send![super(this), init] }
    }

    fn install_status_item(&self) {
        let mtm = self.mtm();
        let monitored = NSString::from_str(MONITORED);
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        if let Some(button) = item.button(mtm) {
            let icon = NSImage::imageWithSystemSymbolName_accessibilityDescription(
                &NSString::from_str(ICON_SYMBOL),
                Some(&monitored),
            );
            match icon {
                Some(icon) => {
                    icon.setTemplate(true);
                    button.setImage(Some(&icon));
                }
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
        let show = menu_item(mtm, SHOW_NOTICE, Some(sel!(showNotice:)));
        // SAFETY: `self` implements `showNotice:`, and the status item that
        // holds the menu is kept in `self`, so the target outlives the menu
        // item's use of it.
        unsafe { show.setTarget(Some(self.as_ref())) };
        menu.addItem(&show);
        if self.ivars().on_enroll.get().is_some() {
            let enroll = menu_item(mtm, ENROLL, Some(sel!(enroll:)));
            // SAFETY: as for `show`: `self` implements `enroll:` and
            // outlives the menu.
            unsafe { enroll.setTarget(Some(self.as_ref())) };
            menu.addItem(&enroll);
        }
        item.setMenu(Some(&menu));

        // Set once, from the one `applicationDidFinishLaunching:`.
        let _ = self.ivars().status_item.set(item);
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
    alert.window().setLevel(NSFloatingWindowLevel);
    // `activate` is macOS 14+; this one works on 13 as well.
    #[allow(deprecated)]
    NSApplication::sharedApplication(mtm).activateIgnoringOtherApps(true);
    alert.runModal() == NSAlertFirstButtonReturn
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
