//! The hidden window: tray icon, menu, forwarded links, logoff, and the
//! UI thread's state. Everything here runs on the UI thread.

use std::cell::{Cell, OnceCell, RefCell};
use std::rc::Rc;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData, COPYDATASTRUCT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD,
    NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, CreateWindowExW, DefWindowProcW,
    DestroyMenu, KillTimer, PostMessageW, PostQuitMessage, RegisterClassExW,
    RegisterWindowMessageW, SetForegroundWindow, SetTimer, TrackPopupMenu, HICON, MF_GRAYED,
    MF_SEPARATOR, MF_STRING, MSGFLT_ALLOW, SW_SHOWNORMAL, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_COPYDATA, WM_DESTROY, WM_ENDSESSION,
    WM_NULL, WM_QUERYENDSESSION, WM_TIMER, WNDCLASSEXW, WS_EX_TOOLWINDOW, WS_POPUP,
};

use super::{
    dialog, icon, url, ReportProblem, SettingsNotice, StatusMenu, ABOUT, DEFAULT_NOTICE_BODY,
    ENDSESSION_GRACE, ENROLL, MONITORED, OPEN_FARO, REPORT_PROBLEM, SHOW_NOTICE, SHOW_NOTICES,
};

/// Wakes the window to run queued jobs.
pub(super) const WM_APP_JOBS: u32 = WM_APP + 1;
/// The tray icon's callback message.
const WM_APP_TRAY: u32 = WM_APP + 2;
/// `NIN_SELECT | NINF_KEY`: the icon chosen with the keyboard.
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
/// The window class, which [`url::forward_link`] looks for.
pub(super) const WINDOW_CLASS: PCWSTR = w!("FaroAgentUi");
/// The tray icon's id within the window.
const TRAY_ID: u32 = 1;
/// Retries adding the icon while Explorer isn't ready.
const RETRY_TIMER: usize = 1;
const RETRY_MS: u32 = 2000;

// Menu commands.
const ID_STATUS: u32 = 1;
const ID_FIX: u32 = 2;
const ID_OPEN: u32 = 3;
const ID_NOTICE: u32 = 4;
const ID_ENROLL: u32 = 5;
const ID_REPORT: u32 = 6;
const ID_ABOUT: u32 = 7;

/// Called on the UI thread with a `faro:` link, or `None` from the menu.
type EnrollHandler = Box<dyn Fn(Option<String>)>;

/// The UI thread's state.
pub(crate) struct Ui {
    hwnd: HWND,
    /// `TaskbarCreated`: Explorer (re)started.
    taskbar_created: u32,
    icon: HICON,
    icon_added: Cell<bool>,
    /// The latest notice: shown again from the menu.
    notice: RefCell<(String, String)>,
    /// A notice window is open.
    showing: Cell<bool>,
    /// Show the notice again when the open window closes.
    again: Cell<bool>,
    /// A settings notice is open.
    settings_showing: Cell<bool>,
    on_quit: Box<dyn Fn()>,
    on_enroll: OnceCell<EnrollHandler>,
    /// The latest status ([`super::UiHandle::set_status`]).
    status: RefCell<StatusMenu>,
}

thread_local! {
    static UI: OnceCell<Rc<Ui>> = const { OnceCell::new() };
}

fn current() -> Option<Rc<Ui>> {
    UI.with(|u| u.get().cloned())
}

/// Create the window and the tray icon on this thread.
pub(super) fn create(on_quit: Box<dyn Fn()>) -> windows::core::Result<HWND> {
    // SAFETY: plain Win32 calls; every pointer passed outlives its call,
    // and `wndproc` matches WNDPROC.
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: WINDOW_CLASS,
            ..Default::default()
        };
        if RegisterClassExW(&class) == 0 {
            return Err(windows::core::Error::from_thread());
        }
        // A hidden top-level window (not HWND_MESSAGE, which gets no
        // broadcasts); a tool window never shows in the taskbar.
        let hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            WINDOW_CLASS,
            w!("Faro"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        )?;
        let taskbar_created = RegisterWindowMessageW(w!("TaskbarCreated"));
        // Only needed if the agent ever ran elevated (UIPI filters the
        // broadcast then); harmless otherwise.
        let _ = ChangeWindowMessageFilterEx(hwnd, taskbar_created, MSGFLT_ALLOW, None);
        let ui = Rc::new(Ui {
            hwnd,
            taskbar_created,
            icon: icon::tray_icon(),
            icon_added: Cell::new(false),
            notice: RefCell::new((MONITORED.to_owned(), DEFAULT_NOTICE_BODY.to_owned())),
            showing: Cell::new(false),
            again: Cell::new(false),
            settings_showing: Cell::new(false),
            on_quit,
            on_enroll: OnceCell::new(),
            status: RefCell::new(StatusMenu::starting()),
        });
        UI.with(|u| {
            let _ = u.set(ui.clone());
        });
        ui.ensure_icon();
        Ok(hwnd)
    }
}

/// Set the enroll handler, once.
pub(super) fn set_enroll_handler(handler: EnrollHandler) {
    if let Some(ui) = current() {
        let _ = ui.on_enroll.set(handler);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let Some(ui) = current() else {
        // SAFETY: forwarding the message as received.
        return unsafe { DefWindowProcW(hwnd, msg, wp, lp) };
    };
    match msg {
        WM_APP_JOBS => {
            while let Some(job) = super::next_job() {
                job(&ui);
            }
            LRESULT(0)
        }
        WM_APP_TRAY => {
            // NOTIFYICON_VERSION_4: the event in LOWORD(lParam), the anchor
            // point in wParam.
            let event = (lp.0 & 0xffff) as u32;
            if matches!(event, WM_CONTEXTMENU | NIN_SELECT | NIN_KEYSELECT) {
                let x = (wp.0 & 0xffff) as u16 as i16 as i32;
                let y = ((wp.0 >> 16) & 0xffff) as u16 as i16 as i32;
                ui.show_menu(x, y);
            }
            LRESULT(0)
        }
        m if m == ui.taskbar_created => {
            tracing::info!("the taskbar was recreated; adding the tray icon again");
            ui.icon_added.set(false);
            ui.ensure_icon();
            LRESULT(0)
        }
        WM_TIMER if wp.0 == RETRY_TIMER => {
            ui.ensure_icon();
            LRESULT(0)
        }
        // SAFETY: for WM_COPYDATA, lParam points to a COPYDATASTRUCT that
        // is valid for the duration of the message.
        WM_COPYDATA => unsafe { ui.receive_link(lp) },
        // Monitoring never blocks logoff or shutdown.
        WM_QUERYENDSESSION => LRESULT(1),
        WM_ENDSESSION => {
            if wp.0 != 0 {
                tracing::info!("the session is ending");
                (ui.on_quit)();
                // Windows may end the process once this returns; give the
                // agent thread the time to say Goodbye and exit itself.
                std::thread::sleep(ENDSESSION_GRACE);
            }
            LRESULT(0)
        }
        // Not how a session ends (see the module docs).
        WM_CLOSE => LRESULT(0),
        WM_DESTROY => {
            ui.remove_icon();
            // SAFETY: no preconditions.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        // SAFETY: forwarding the message as received.
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

/// `&` starts a mnemonic in menu text; show it as itself.
fn menu_text(s: &str) -> HSTRING {
    HSTRING::from(s.replace('&', "&&"))
}

impl Ui {
    fn notify_data(&self) -> NOTIFYICONDATAW {
        let mut nid = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uID: TRAY_ID,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
            uCallbackMessage: WM_APP_TRAY,
            hIcon: self.icon,
            ..Default::default()
        };
        let tip: Vec<u16> = MONITORED.encode_utf16().collect();
        let n = tip.len().min(nid.szTip.len() - 1);
        nid.szTip[..n].copy_from_slice(&tip[..n]);
        nid
    }

    /// Add the icon if it isn't there; retry on a timer until it is.
    fn ensure_icon(&self) {
        if self.icon_added.get() {
            return;
        }
        let mut nid = self.notify_data();
        // SAFETY: `nid` is a valid, fully initialized NOTIFYICONDATAW.
        let added = unsafe {
            Shell_NotifyIconW(NIM_ADD, &nid).as_bool()
                // Still there from before (a TaskbarCreated after a DPI
                // change, for example).
                || Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool()
        };
        if added {
            nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            // SAFETY: as above.
            unsafe {
                if !Shell_NotifyIconW(NIM_SETVERSION, &nid).as_bool() {
                    tracing::warn!("the tray did not accept NOTIFYICON_VERSION_4");
                }
                let _ = KillTimer(Some(self.hwnd), RETRY_TIMER);
            }
            self.icon_added.set(true);
            tracing::info!("tray icon added");
        } else {
            tracing::info!("the tray isn't ready; retrying");
            // SAFETY: a timer on our own window.
            unsafe { SetTimer(Some(self.hwnd), RETRY_TIMER, RETRY_MS, None) };
        }
    }

    fn remove_icon(&self) {
        let nid = self.notify_data();
        // SAFETY: as in `ensure_icon`.
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
        }
        self.icon_added.set(false);
    }

    /// Build the menu from the current status, show it at `(x, y)` and run
    /// the chosen command.
    fn show_menu(&self, x: i32, y: i32) {
        let s = self.status.borrow().clone();
        // SAFETY: the menu is created, used and destroyed here; every
        // string outlives the call that copies it.
        let chosen = unsafe {
            let Ok(menu) = CreatePopupMenu() else {
                tracing::warn!("could not create the tray menu");
                return;
            };
            let add = |id: u32, text: &str| {
                let _ = AppendMenuW(menu, MF_STRING, id as usize, &menu_text(text));
            };
            let sep = || {
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, None);
            };
            let _ = AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, &menu_text(MONITORED));
            sep();
            add(ID_STATUS, &format!("Status: {}", s.line));
            if let Some(f) = &s.fix {
                add(ID_FIX, &f.label);
            }
            sep();
            if s.web_app.is_some() {
                add(ID_OPEN, OPEN_FARO);
            }
            add(ID_NOTICE, SHOW_NOTICE);
            if self.on_enroll.get().is_some() {
                add(ID_ENROLL, ENROLL);
            }
            if s.report.is_some() {
                add(ID_REPORT, REPORT_PROBLEM);
            }
            add(ID_ABOUT, ABOUT);
            // Without this the menu doesn't close when the person clicks
            // elsewhere (the documented TrackPopupMenu quirk).
            let _ = SetForegroundWindow(self.hwnd);
            let cmd = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
                x,
                y,
                None,
                self.hwnd,
                None,
            );
            let _ = PostMessageW(Some(self.hwnd), WM_NULL, WPARAM(0), LPARAM(0));
            let _ = DestroyMenu(menu);
            cmd.0 as u32
        };
        match chosen {
            ID_STATUS => self.present_status(),
            ID_FIX => {
                if let Some(f) = s.fix {
                    open_url(&f.url);
                }
            }
            ID_OPEN => {
                if let Some(u) = s.web_app {
                    open_url(&u);
                }
            }
            ID_NOTICE => self.present(),
            ID_ENROLL => self.enroll(None),
            ID_REPORT => self.present_report(),
            ID_ABOUT => self.present_about(),
            _ => {}
        }
    }

    fn enroll(&self, link: Option<String>) {
        match self.on_enroll.get() {
            Some(f) => f(link),
            None => tracing::info!("enrolling isn't offered here; ignoring"),
        }
    }

    /// A link forwarded by `faro-agent open-url` ([`url::forward_link`]).
    ///
    /// # Safety
    ///
    /// `lp` must be WM_COPYDATA's lParam.
    unsafe fn receive_link(&self, lp: LPARAM) -> LRESULT {
        // SAFETY: the caller's contract.
        let Some(cds) = (unsafe { (lp.0 as *const COPYDATASTRUCT).as_ref() }) else {
            return LRESULT(0);
        };
        let len = cds.cbData as usize;
        if cds.dwData != url::COPYDATA_LINK
            || cds.lpData.is_null()
            || len == 0
            || !len.is_multiple_of(2)
            || len > url::MAX_LINK_LEN * 2
        {
            return LRESULT(0);
        }
        // SAFETY: the system copied `cbData` bytes to `lpData` for us.
        let bytes = unsafe { std::slice::from_raw_parts(cds.lpData as *const u8, len) };
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let Ok(link) = String::from_utf16(&units) else {
            return LRESULT(0);
        };
        if !url::is_faro_link(&link) {
            tracing::info!("refused a forwarded link that isn't a faro: link");
            return LRESULT(0);
        }
        // The link carries a one-time code: never logged.
        tracing::info!("received a faro: link from another process");
        // Run the handler after answering, so the sender isn't held up.
        super::enqueue(Box::new(move |ui| ui.enroll(Some(link))));
        LRESULT(1)
    }

    pub(super) fn set_status(&self, s: StatusMenu) {
        *self.status.borrow_mut() = s;
    }

    pub(super) fn set_notice(&self, title: String, body: String) {
        *self.notice.borrow_mut() = (title, body);
    }

    /// Show the latest notice, unless one is already open.
    pub(super) fn present(&self) {
        if self.showing.replace(true) {
            self.again.set(true);
            return;
        }
        loop {
            let (title, body) = self.notice.borrow().clone();
            dialog::alert(&title, &body, false, &["OK"]);
            if !self.again.replace(false) {
                break;
            }
        }
        self.showing.set(false);
    }

    /// Show a warning whose first button opens its URL, unless one is
    /// already open (the agent sends each once anyway).
    pub(super) fn present_settings(&self, n: &SettingsNotice) {
        if self.settings_showing.replace(true) {
            return;
        }
        if dialog::alert(&n.title, &n.body, true, &[&n.open, &n.later]) == Some(0) {
            open_url(&n.url);
        }
        self.settings_showing.set(false);
    }

    /// The status line and what to do, with the fix's button if any.
    fn present_status(&self) {
        let s = self.status.borrow().clone();
        match &s.fix {
            Some(f) => {
                let label = f.label.trim_end_matches('\u{2026}');
                if dialog::alert(&s.line, &s.detail, s.problem, &[label, "OK"]) == Some(0) {
                    open_url(&f.url);
                }
            }
            None => {
                dialog::alert(&s.line, &s.detail, s.problem, &["OK"]);
            }
        }
    }

    /// How to make a problem report, with a button that copies the
    /// command. It explains only; nothing is sent to the service.
    fn present_report(&self) {
        let Some(ReportProblem {
            title,
            body,
            copy,
            command,
        }) = self.status.borrow().report.clone()
        else {
            return;
        };
        if dialog::alert(&title, &body, false, &[&copy, "OK"]) == Some(0)
            && !copy_to_clipboard(self.hwnd, &command)
        {
            tracing::warn!("could not copy the command");
        }
    }

    /// Versions, the instance, and the third-party notices.
    fn present_about(&self) {
        let s = self.status.borrow().clone();
        if dialog::alert(&s.about_title, &s.about_body, false, &["OK", SHOW_NOTICES]) == Some(1) {
            open_folder(crate::layout::NOTICES_DIR);
        }
    }
}

/// Whether the menu may open `url`: web pages and Settings pages only, so
/// nothing that reaches the menu can make the shell run a program.
pub(super) fn openable(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    ["https://", "http://", "ms-settings:"]
        .iter()
        .any(|p| lower.starts_with(p))
        && !url.chars().any(char::is_control)
}

/// Open a web page or a Settings page with its default handler.
fn open_url(url: &str) {
    if !openable(url) {
        tracing::warn!("refused to open a URL with an unexpected scheme");
        tracing::debug!(url, "refused URL");
        return;
    }
    shell_open(url);
}

/// Show a folder in File Explorer.
fn open_folder(path: &str) {
    shell_open(path);
}

fn shell_open(target: &str) {
    // SAFETY: the strings outlive the call.
    let r = unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            &HSTRING::from(target),
            None,
            None,
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute's documented success test.
    if r.0 as isize <= 32 {
        tracing::warn!(code = r.0 as isize, "could not open a link or folder");
        tracing::debug!(target, "could not open");
    }
}

/// Put `text` on the clipboard.
fn copy_to_clipboard(owner: HWND, text: &str) -> bool {
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    let bytes = wide.len() * 2;
    // SAFETY: the clipboard protocol: open, empty, hand over a movable
    // global block (owned by the system once SetClipboardData succeeds),
    // close. The block is `bytes` long, which the copy stays within.
    unsafe {
        if OpenClipboard(Some(owner)).is_err() {
            return false;
        }
        let ok = (|| {
            EmptyClipboard().ok()?;
            let mem = GlobalAlloc(GMEM_MOVEABLE, bytes).ok()?;
            let dst = GlobalLock(mem) as *mut u16;
            if dst.is_null() {
                let _ = GlobalFree(Some(mem));
                return None;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
            let _ = GlobalUnlock(mem);
            if SetClipboardData(u32::from(CF_UNICODETEXT.0), Some(HANDLE(mem.0))).is_err() {
                let _ = GlobalFree(Some(mem));
                return None;
            }
            Some(())
        })()
        .is_some();
        let _ = CloseClipboard();
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_web_and_settings_urls_open() {
        assert!(openable("https://faro.example.org/computers"));
        assert!(openable("HTTP://127.0.0.1:8080/"));
        assert!(openable("ms-settings:privacy-broadfilesystemaccess"));
        for bad in [
            "C:\\Windows\\System32\\calc.exe",
            "file:///C:/Windows/System32/calc.exe",
            "faro://enroll?i=x",
            "javascript:alert(1)",
            "https://faro.example.org/\n",
            "\\\\server\\share\\x.exe",
            "",
        ] {
            assert!(!openable(bad), "{bad:?}");
        }
    }

    #[test]
    fn menu_text_keeps_ampersands() {
        assert_eq!(menu_text("A & B").to_string(), "A && B");
    }
}
