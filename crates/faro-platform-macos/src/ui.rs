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
    NSAlert, NSAlertStyle, NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate,
    NSApplicationTerminateReply, NSFloatingWindowLevel, NSImage, NSMenu, NSMenuItem, NSStatusBar,
    NSStatusItem, NSVariableStatusItemLength,
};
use objc2_foundation::{ns_string, NSNotification, NSObject, NSObjectProtocol, NSString};

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

struct Ivars {
    /// The latest notice: shown again from the menu.
    notice: RefCell<(String, String)>,
    /// A notice alert is open.
    showing: Cell<bool>,
    /// Show the notice again when the open alert closes.
    again: Cell<bool>,
    on_quit: Box<dyn Fn()>,
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
    }
);

impl Delegate {
    fn new(mtm: MainThreadMarker, on_quit: Box<dyn Fn()>) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(Ivars {
            notice: RefCell::new((MONITORED.to_owned(), DEFAULT_NOTICE_BODY.to_owned())),
            showing: Cell::new(false),
            again: Cell::new(false),
            on_quit,
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
