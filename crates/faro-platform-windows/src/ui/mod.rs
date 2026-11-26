//! The agent's presence on screen in every session (ARCHITECTURE.md §12),
//! in plain Win32: a tray icon that is there for as long as the agent
//! runs, the monitoring notice the service sends at login (`ShowNotice`),
//! and enrolling without a terminal. The Windows counterpart of
//! `faro_platform_macos::ui`, with the same public API where the platforms
//! allow it, so `faro-agent`'s macOS paths (`run_with_ui`, `MacNotices`,
//! `offer_enrollment`, `MacEnrollUi`) can be reused by widening their
//! `cfg`s. The differences are listed at the end.
//!
//! The agent runs in every account's session (§3.1), so this is what tells
//! everyone who uses the computer that it is monitored.
//!
//! # Threads
//!
//! The UI lives on one thread: the one that calls [`SessionUi::new`] and
//! [`SessionUi::run`] (the process's main thread in `faro-agent`). It owns
//! a hidden top-level window whose message loop drives the tray icon, the
//! menu and every dialog. The agent's own loop runs on a worker thread and
//! reaches the UI through a [`UiHandle`] (`Send + Sync + Copy`), which
//! queues a closure and wakes the window with `PostMessageW`.
//!
//! Dialogs are modal (`DialogBoxIndirectParamW`), so while one is open the
//! window's messages are still dispatched by the dialog's own loop: the
//! tray menu keeps working, and work queued meanwhile runs. As on macOS, a
//! notice that arrives while one is open is shown again after it closes.
//!
//! # The tray icon
//!
//! `Shell_NotifyIconW` (`NOTIFYICON_VERSION_4`) with the tooltip
//! [`MONITORED`]. Explorer may not be ready when the agent starts at login,
//! and it forgets every icon when it restarts, so the icon is added again
//! on the `TaskbarCreated` broadcast and retried on a timer until it
//! sticks. That is why the window is a hidden *top-level* window and not a
//! message-only one: message-only windows get no broadcasts (neither
//! `TaskbarCreated` nor `WM_QUERYENDSESSION`/`WM_ENDSESSION`).
//!
//! The icon is the executable's icon resource 1 if it has one (the
//! packaged `faro-agent.exe` should), else an eye drawn at run time.
//!
//! # The status menu
//!
//! A click (left or right) opens the same menu as on macOS (issue #89):
//! [`MONITORED`] (disabled), "Status: …" ([`UiHandle::set_status`]; the
//! words come from `faro_agent::status_menu`), which explains itself when
//! clicked, the item that fixes the problem if there is one, "Open Faro",
//! "Show the monitoring notice…", "Enroll this computer…" (when
//! [`SessionUi::on_enroll`] was called), "Report a problem…" and "About
//! Faro…". Nothing on it stops, pauses or hides monitoring: there is no
//! Exit item. URLs opened from it must be `https:`, `http:` or
//! `ms-settings:`; anything else is refused, so a status the agent didn't
//! expect can never make the shell run a program.
//!
//! # The monitoring notice: a window, not a toast
//!
//! The notice ([`UiHandle::show_notice`]) is a topmost dialog with a
//! taskbar button, not a balloon or a toast. Toasts need an
//! AppUserModelID with a Start-menu shortcut for each account, and both
//! toasts and tray balloons (which Windows 10/11 turn into toasts) are
//! silently dropped by Focus assist / Do not disturb, by "Notifications"
//! being off, during presentations and full-screen games, and before
//! Explorer has finished starting at login; they also vanish after a few
//! seconds. A topmost window needs none of that, appears in every account
//! and on every Windows edition, and stays until it is closed. If Windows'
//! foreground lock stops it taking focus, it still shows on top and its
//! taskbar button flashes. It can be shown again from the menu.
//!
//! # Logging off
//!
//! At logoff Windows sends `WM_QUERYENDSESSION` (answered yes: monitoring
//! must not block logoff) and then `WM_ENDSESSION`, after which it may end
//! the process at any time. The window calls the `on_quit` hook (the agent
//! treats it like SIGTERM and says `Goodbye`), then waits up to
//! [`ENDSESSION_GRACE`] for the agent thread to end the process. `WM_CLOSE`
//! (for example `taskkill` without `/F`) is ignored: it is not how a
//! session ends, and the service watches for agents that disappear.
//! `faro-agent.exe` must be a GUI-subsystem binary for this
//! (`#![windows_subsystem = "windows"]`); a console binary also gets
//! `CTRL_LOGOFF_EVENT`, which the agent handles itself.
//!
//! # Enrolling
//!
//! Like on macOS, enrolling starts from a `faro://enroll` link or from the
//! menu, and calls the [`SessionUi::on_enroll`] handler on the UI thread.
//! The agent runs the flow on a worker thread and shows each screen with
//! the blocking [`UiHandle::ask_enroll_target`], [`UiHandle::confirm`] and
//! [`UiHandle::message`].
//!
//! Links reach the running agent through [`url`]: the MSI registers the
//! `faro` scheme to run `faro-agent.exe open-url "%1"`, and that short-lived
//! process forwards the link with [`url::forward_link`] to the agent
//! already running in the same session (found through a session-local
//! named mutex and its window), then exits.
//!
//! Administrator approval is [`approval`]: the agent starts an elevated
//! helper through UAC, and the *service* checks the helper's elevated
//! administrator token itself. The agent never decides.
//!
//! # Differences from macOS
//!
//! - [`MainThreadMarker`] is this crate's own type: Win32 has no special
//!   main thread, so the first thread that asks becomes the UI thread.
//! - [`SessionUi::try_new`] reports a window that can't be created;
//!   [`SessionUi::new`] panics instead, like macOS's `new` on a second call.
//! - [`UiHandle::show_settings_notice`]'s button opens an `ms-settings:` (or
//!   web) URL instead of a System Settings pane.
//! - [`SessionUi::run`] returns if the window is destroyed (it isn't, in
//!   normal operation).

mod dialog;
mod icon;
mod window;

pub mod approval;
pub mod url;

use std::collections::VecDeque;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, PostMessageW, TranslateMessage, MSG,
};

/// The menu's first line and the icon's tooltip.
pub const MONITORED: &str = "This computer is monitored by Faro";

/// Shown by "Show the monitoring notice…" until the service has sent its
/// own notice, which names the instance and counts the allies.
pub const DEFAULT_NOTICE_BODY: &str = "Every account on this computer is monitored by Faro. \
     Screenshots are blurred on this computer and shared, encrypted, only with the member \
     and their allies. Switching to or creating another account does not turn monitoring off.";

/// What the menu shows for "Show the monitoring notice…".
pub const SHOW_NOTICE: &str = "Show the monitoring notice\u{2026}";

/// What the menu shows for enrolling.
pub const ENROLL: &str = "Enroll this computer\u{2026}";

/// The menu item that opens the instance's web app.
pub const OPEN_FARO: &str = "Open Faro";

/// The menu item that shows the About window.
pub const ABOUT: &str = "About Faro\u{2026}";

/// The About window's button that shows the third-party notices.
pub const SHOW_NOTICES: &str = "Show Third-Party Notices";

/// The menu item that explains how to make a problem report.
pub const REPORT_PROBLEM: &str = "Report a problem\u{2026}";

/// The status line before the agent has told the UI anything.
pub const STATUS_STARTING: &str = "Connecting to the Faro service\u{2026}";

/// How long the UI thread holds on to `WM_ENDSESSION` after calling
/// `on_quit`, so the agent can say `Goodbye` before Windows ends the
/// process. Windows itself waits about 5 s before it offers to end a
/// program that hasn't answered.
pub const ENDSESSION_GRACE: Duration = Duration::from_secs(4);

/// The words of a notice that offers to open a page of the system's
/// settings (see [`UiHandle::show_settings_notice`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsNotice {
    pub title: String,
    pub body: String,
    /// The first button: opens `url`.
    pub open: String,
    /// The second button: only closes the notice.
    pub later: String,
    /// An `ms-settings:` or `https:` URL; any other scheme is refused.
    pub url: String,
}

/// A menu item that fixes a problem: its title and the URL it opens (an
/// `ms-settings:` page, the web app's Computers page).
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

/// The id of the thread that runs the UI (0 until one claims it).
static UI_THREAD: AtomicU32 = AtomicU32::new(0);
/// The hidden window, once [`SessionUi::new`] has made it (0 before).
static UI_HWND: AtomicIsize = AtomicIsize::new(0);

/// Work for the UI thread, queued by a [`UiHandle`].
type Job = Box<dyn FnOnce(&window::Ui) + Send>;
static JOBS: Mutex<VecDeque<Job>> = Mutex::new(VecDeque::new());

/// Queue `job` for the UI thread and wake it. Dropped (never run) if there
/// is no UI window.
fn enqueue(job: Job) {
    let hwnd = UI_HWND.load(Ordering::Acquire);
    if hwnd == 0 {
        return;
    }
    JOBS.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push_back(job);
    // SAFETY: posting a message has no memory-safety preconditions; a
    // stale handle only makes the call fail.
    let posted = unsafe {
        PostMessageW(
            Some(HWND(hwnd as *mut _)),
            window::WM_APP_JOBS,
            WPARAM(0),
            LPARAM(0),
        )
    };
    if let Err(e) = posted {
        tracing::warn!(error = %e, "could not wake the UI thread");
    }
}

/// Take the next queued job.
fn next_job() -> Option<Job> {
    JOBS.lock().unwrap_or_else(|e| e.into_inner()).pop_front()
}

fn current_thread() -> u32 {
    // SAFETY: no preconditions.
    unsafe { GetCurrentThreadId() }
}

fn on_ui_thread() -> bool {
    UI_THREAD.load(Ordering::Acquire) == current_thread()
}

/// Run `f` on the UI thread and wait for its result. `None` if called
/// from the UI thread itself (which would deadlock), or if there is no UI.
fn on_ui_and_wait<T: Send + 'static>(
    f: impl FnOnce(&window::Ui) -> T + Send + 'static,
) -> Option<T> {
    if on_ui_thread() || UI_HWND.load(Ordering::Acquire) == 0 {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    enqueue(Box::new(move |ui| {
        let _ = tx.send(f(ui));
    }));
    // A job dropped without running (no window) closes the channel.
    rx.recv().ok()
}

/// Proof that the current thread is the UI thread. Win32 has no special
/// main thread, so the first thread that calls [`MainThreadMarker::new`]
/// becomes the UI thread for the life of the process: call it first from
/// `main`. Not `Send`, like the macOS type of the same name.
#[derive(Debug, Clone, Copy)]
pub struct MainThreadMarker {
    _not_send: PhantomData<*const ()>,
}

impl MainThreadMarker {
    /// `Some` on the UI thread (claiming it if no thread has yet), `None`
    /// on every other thread.
    pub fn new() -> Option<Self> {
        let me = current_thread();
        match UI_THREAD.compare_exchange(0, me, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Some(MainThreadMarker {
                _not_send: PhantomData,
            }),
            Err(owner) if owner == me => Some(MainThreadMarker {
                _not_send: PhantomData,
            }),
            Err(_) => None,
        }
    }
}

/// The agent's Win32 UI. Create it and [`run`](Self::run) it on the UI
/// thread; talk to it from other threads through a [`UiHandle`].
#[derive(Debug)]
pub struct SessionUi {
    _not_send: PhantomData<*const ()>,
    first_in_session: bool,
}

impl SessionUi {
    /// Create the hidden window and the tray icon (retried until Explorer
    /// takes it). `on_quit` is called on the UI thread when the session
    /// ends (see the module docs); the caller must then end the process.
    ///
    /// # Panics
    ///
    /// If called twice in one process, or if the window can't be created
    /// (see [`try_new`](Self::try_new)).
    pub fn new(mtm: MainThreadMarker, on_quit: impl Fn() + 'static) -> Self {
        match Self::try_new(mtm, on_quit) {
            Ok(ui) => ui,
            Err(e) => panic!("could not create the agent's UI: {e}"),
        }
    }

    /// [`new`](Self::new), returning window-creation errors instead.
    ///
    /// # Panics
    ///
    /// If called twice in one process.
    pub fn try_new(
        _mtm: MainThreadMarker,
        on_quit: impl Fn() + 'static,
    ) -> windows::core::Result<Self> {
        assert!(
            UI_HWND.load(Ordering::Acquire) == 0,
            "SessionUi::new called twice"
        );
        let first_in_session = url::claim_instance();
        if !first_in_session {
            tracing::warn!("another Faro agent UI is already running in this session");
        }
        let hwnd = window::create(Box::new(on_quit))?;
        UI_HWND.store(hwnd.0 as isize, Ordering::Release);
        Ok(SessionUi {
            _not_send: PhantomData,
            first_in_session,
        })
    }

    /// Whether this is the only agent UI in the session (it created the
    /// session's instance mutex, [`url::INSTANCE_MUTEX`]). A second one
    /// still works, but `faro://` links go to whichever window
    /// [`url::forward_link`] finds first.
    pub fn is_first_in_session(&self) -> bool {
        self.first_in_session
    }

    pub fn handle(&self) -> UiHandle {
        UiHandle { _private: () }
    }

    /// Offer enrollment: add "Enroll this computer…" to the menu, accept
    /// forwarded `faro://` links, and call `handler` on the UI thread with
    /// the link (or `None` from the menu). Call before [`run`](Self::run);
    /// later calls are ignored.
    pub fn on_enroll(&self, handler: impl Fn(Option<String>) + 'static) {
        window::set_enroll_handler(Box::new(handler));
    }

    /// Run the message loop. It does not return in normal operation: the
    /// agent thread ends the process.
    pub fn run(self) {
        let mut msg = MSG::default();
        // SAFETY: the standard message loop; `msg` outlives every call.
        unsafe {
            while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

/// Reaches the [`SessionUi`] from any thread.
#[derive(Debug, Clone, Copy)]
pub struct UiHandle {
    _private: (),
}

impl UiHandle {
    /// Ask for a link, or an address and a code (two fields). `None` if
    /// cancelled. Blocks; never call it from the UI thread (it returns
    /// `None` at once there instead of deadlocking).
    pub fn ask_enroll_target(&self, text: &TwoFields) -> Option<(String, String)> {
        let text = text.clone();
        on_ui_and_wait(move |_| dialog::two_fields(&text)).flatten()
    }

    /// Ask a yes-or-no question: `true` for `ok`. Blocks; never call it
    /// from the UI thread.
    pub fn confirm(&self, title: &str, body: &str, ok: &str, cancel: &str) -> bool {
        let (title, body, ok, cancel) = (
            title.to_owned(),
            body.to_owned(),
            ok.to_owned(),
            cancel.to_owned(),
        );
        on_ui_and_wait(move |_| {
            dialog::alert(&title, &body, false, &[ok.as_str(), cancel.as_str()]) == Some(0)
        })
        .unwrap_or(false)
    }

    /// Show a message with one button. Blocks until it is closed; never
    /// call it from the UI thread.
    pub fn message(&self, title: &str, body: &str, warning: bool) {
        let (title, body) = (title.to_owned(), body.to_owned());
        on_ui_and_wait(move |_| {
            dialog::alert(&title, &body, warning, &["OK"]);
        });
    }

    /// Show a warning with a button that opens a settings page. Doesn't
    /// block, and doesn't replace the monitoring notice in the menu.
    pub fn show_settings_notice(&self, notice: SettingsNotice) {
        enqueue(Box::new(move |ui| ui.present_settings(&notice)));
    }

    /// Show `status` in the menu: the status line, the item that fixes a
    /// problem, "Open Faro" and the About window. Doesn't block, and never
    /// opens a window by itself.
    pub fn set_status(&self, status: StatusMenu) {
        enqueue(Box::new(move |ui| ui.set_status(status)));
    }

    /// Show `title` and `body` in a window now, and from the menu later.
    pub fn show_notice(&self, title: &str, body: &str) {
        let (title, body) = (title.to_owned(), body.to_owned());
        enqueue(Box::new(move |ui| {
            ui.set_notice(title, body);
            ui.present();
        }));
    }
}

/// Show a message without a [`SessionUi`], for a process that has none:
/// `faro-agent open-url` telling the person that Faro isn't running in
/// this session, for example. Blocks until it is closed; any thread.
pub fn show_message(title: &str, body: &str, warning: bool) {
    dialog::alert(title, body, warning, &["OK"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ui_thread_is_the_first_to_ask() {
        // Tests share one process; whichever thread asked first owns it.
        let here = MainThreadMarker::new().is_some();
        let again = MainThreadMarker::new().is_some();
        assert_eq!(here, again);
        let elsewhere = std::thread::spawn(|| MainThreadMarker::new().is_some())
            .join()
            .unwrap();
        assert!(!(here && elsewhere), "two UI threads");
    }

    #[test]
    fn blocking_calls_without_a_ui_return_at_once() {
        // No SessionUi in tests: nothing may hang.
        let h = UiHandle { _private: () };
        assert!(!h.confirm("t", "b", "ok", "cancel"));
        assert!(h
            .ask_enroll_target(&TwoFields {
                title: String::new(),
                body: String::new(),
                first_label: String::new(),
                first_placeholder: String::new(),
                second_label: String::new(),
                second_placeholder: String::new(),
                ok: String::new(),
                cancel: String::new(),
            })
            .is_none());
        h.set_status(StatusMenu::starting());
        h.show_notice("t", "b");
    }
}
