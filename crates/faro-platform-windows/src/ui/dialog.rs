//! Modal dialogs built at run time: a heading, a body, optional text
//! fields and buttons with any labels (a `MessageBox` can't relabel its
//! buttons, and `TaskDialog` needs Common Controls 6, which needs an
//! application manifest).
//!
//! Each is `DialogBoxIndirectParamW` over an in-memory template with no
//! controls: the controls are created and laid out in `WM_INITDIALOG`, in
//! dialog units converted with `MapDialogRect`, so the layout follows the
//! dialog font and the DPI. The dialog manager still provides Tab, Enter
//! (the first button) and Esc (closes, choosing nothing).
//!
//! The window is topmost and has a taskbar button, so it is seen even when
//! Windows' foreground lock keeps it from taking focus. The body is a
//! read-only edit control, so fingerprints and codes in it can be selected
//! and copied.

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DeleteObject, DrawTextW, GetDC, GetMonitorInfoW, GetObjectW,
    MonitorFromPoint, ReleaseDC, SelectObject, DT_CALCRECT, DT_EDITCONTROL, DT_NOPREFIX,
    DT_SINGLELINE, DT_WORDBREAK, HFONT, HGDIOBJ, LOGFONTW, MONITORINFO, MONITOR_DEFAULTTOPRIMARY,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DialogBoxIndirectParamW, EndDialog, GetCursorPos,
    GetWindowLongPtrW, GetWindowLongW, GetWindowTextLengthW, GetWindowTextW, LoadIconW,
    MapDialogRect, SendMessageW, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos, DLGTEMPLATE,
    GWLP_USERDATA, GWL_EXSTYLE, GWL_STYLE, HMENU, HWND_TOPMOST, IDCANCEL, IDI_INFORMATION,
    IDI_WARNING, IDOK, STM_SETICON, SWP_SHOWWINDOW, WINDOW_EX_STYLE, WINDOW_STYLE, WM_COMMAND,
    WM_DESTROY, WM_GETFONT, WM_INITDIALOG, WM_SETFONT,
};

use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;

use super::TwoFields;

// Styles, as the template and CreateWindowExW want them.
const WS_POPUP: u32 = 0x8000_0000;
const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_CAPTION: u32 = 0x00C0_0000;
const WS_BORDER: u32 = 0x0080_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const WS_VSCROLL: u32 = 0x0020_0000;
const WS_TABSTOP: u32 = 0x0001_0000;
const DS_SETFONT: u32 = 0x40;
const DS_MODALFRAME: u32 = 0x80;
const WS_EX_DLGMODALFRAME: u32 = 0x1;
const WS_EX_TOPMOST: u32 = 0x8;
const WS_EX_APPWINDOW: u32 = 0x0004_0000;
const SS_ICON: u32 = 0x3;
const SS_NOPREFIX: u32 = 0x80;
const ES_MULTILINE: u32 = 0x4;
const ES_AUTOVSCROLL: u32 = 0x40;
const ES_AUTOHSCROLL: u32 = 0x80;
const ES_READONLY: u32 = 0x800;
const BS_PUSHBUTTON: u32 = 0x0;
const BS_DEFPUSHBUTTON: u32 = 0x1;
/// `EM_SETCUEBANNER`: the placeholder (shown with Common Controls 6 only;
/// ignored otherwise).
const EM_SETCUEBANNER: u32 = 0x1501;
const BN_CLICKED: usize = 0;

/// The caption of every dialog.
const CAPTION: &str = "Faro";
/// Buttons after the first get these ids (the first is IDOK).
const FIRST_EXTRA_BUTTON: i32 = 1000;
/// Fields get these ids.
const FIRST_FIELD: i32 = 2000;
/// The static controls' id.
const ID_STATIC: i32 = 0xFFFF;

/// What a dialog shows.
struct Spec<'a> {
    title: &'a str,
    body: &'a str,
    warning: bool,
    /// Label and placeholder of each field.
    fields: &'a [(&'a str, &'a str)],
    /// The first is the default (Enter).
    buttons: &'a [&'a str],
}

/// A dialog while it is open; `WM_INITDIALOG`'s parameter.
struct State<'a> {
    spec: &'a Spec<'a>,
    fields: Vec<HWND>,
    values: Vec<String>,
    heading_font: Option<HFONT>,
}

/// Show a message with `buttons` (the first is the default) and return the
/// index of the one pressed, or `None` if it was closed another way.
/// Blocks; any thread, but in the agent always the UI thread.
pub(super) fn alert(title: &str, body: &str, warning: bool, buttons: &[&str]) -> Option<usize> {
    run(&Spec {
        title,
        body,
        warning,
        fields: &[],
        buttons,
    })
    .0
}

/// The two-field window; `None` if cancelled.
pub(super) fn two_fields(t: &TwoFields) -> Option<(String, String)> {
    let fields = [
        (t.first_label.as_str(), t.first_placeholder.as_str()),
        (t.second_label.as_str(), t.second_placeholder.as_str()),
    ];
    let (pressed, mut values) = run(&Spec {
        title: &t.title,
        body: &t.body,
        warning: false,
        fields: &fields,
        buttons: &[&t.ok, &t.cancel],
    });
    if pressed != Some(0) || values.len() != 2 {
        return None;
    }
    let second = values.pop()?;
    let first = values.pop()?;
    Some((first, second))
}

/// An in-memory `DLGTEMPLATE` with no controls and the Segoe UI 9 font,
/// DWORD-aligned as `DialogBoxIndirectParamW` requires.
fn template() -> Vec<u32> {
    let style = DS_SETFONT | DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU;
    let ex = WS_EX_DLGMODALFRAME | WS_EX_TOPMOST | WS_EX_APPWINDOW;
    let mut words: Vec<u16> = vec![
        style as u16,
        (style >> 16) as u16,
        ex as u16,
        (ex >> 16) as u16,
        0,   // no controls
        0,   // x
        0,   // y
        200, // cx (resized in WM_INITDIALOG)
        100, // cy
        0,   // no menu
        0,   // the standard dialog class
    ];
    words.extend(CAPTION.encode_utf16().chain(Some(0)));
    words.push(9); // point size
    words.extend("Segoe UI".encode_utf16().chain(Some(0)));
    if !words.len().is_multiple_of(2) {
        words.push(0);
    }
    words
        .as_chunks::<2>()
        .0
        .iter()
        .map(|w| u32::from(w[0]) | (u32::from(w[1]) << 16))
        .collect()
}

fn run(spec: &Spec) -> (Option<usize>, Vec<String>) {
    let tpl = template();
    let mut state = State {
        spec,
        fields: Vec::new(),
        values: Vec::new(),
        heading_font: None,
    };
    // SAFETY: `tpl` is a valid template that outlives the modal call, and
    // `state` outlives it too (the dialog only uses it until EndDialog).
    let result = unsafe {
        let instance = GetModuleHandleW(None).ok();
        DialogBoxIndirectParamW(
            instance.map(Into::into),
            tpl.as_ptr().cast::<DLGTEMPLATE>(),
            None,
            Some(dialog_proc),
            LPARAM(&mut state as *mut State as isize),
        )
    };
    let pressed = match result {
        -1 => {
            tracing::warn!(
                error = %windows::core::Error::from_thread(),
                "could not show a dialog"
            );
            None
        }
        0 => None,
        n => Some(n as usize - 1),
    };
    (pressed, state.values)
}

/// The `State` stored on the dialog.
///
/// # Safety
///
/// Only between `WM_INITDIALOG` and the end of `run`.
unsafe fn state<'a>(hdlg: HWND) -> Option<&'a mut State<'a>> {
    // SAFETY: GWLP_USERDATA holds the pointer set in WM_INITDIALOG (or 0).
    unsafe { (GetWindowLongPtrW(hdlg, GWLP_USERDATA) as *mut State).as_mut() }
}

unsafe extern "system" fn dialog_proc(hdlg: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> isize {
    match msg {
        WM_INITDIALOG => {
            // SAFETY: `run` passes a `State` that outlives the dialog.
            unsafe {
                SetWindowLongPtrW(hdlg, GWLP_USERDATA, lp.0);
                if let Some(s) = state(hdlg) {
                    layout(hdlg, s);
                }
            }
            // Focus was set by `layout`.
            0
        }
        WM_COMMAND if (wp.0 >> 16) & 0xffff == BN_CLICKED => {
            let id = (wp.0 & 0xffff) as i32;
            let pressed = match id {
                x if x == IDOK.0 => Some(0),
                x if x == IDCANCEL.0 => None,
                x if (FIRST_EXTRA_BUTTON..FIRST_EXTRA_BUTTON + 16).contains(&x) => {
                    Some((x - FIRST_EXTRA_BUTTON) as usize)
                }
                _ => return 0,
            };
            // SAFETY: the state is live until EndDialog returns to `run`.
            unsafe {
                if let Some(s) = state(hdlg) {
                    s.values = s.fields.iter().map(|&f| text_of(f)).collect();
                }
                let _ = EndDialog(hdlg, pressed.map_or(0, |i| i as isize + 1));
            }
            1
        }
        WM_DESTROY => {
            // SAFETY: as above; the font was created for this dialog.
            unsafe {
                if let Some(f) = state(hdlg).and_then(|s| s.heading_font.take()) {
                    let _ = DeleteObject(HGDIOBJ(f.0));
                }
            }
            0
        }
        _ => 0,
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// An edit control wants CR LF.
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

fn text_of(hwnd: HWND) -> String {
    // SAFETY: the buffer is as long as the length passed.
    unsafe {
        let n = GetWindowTextLengthW(hwnd).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(hwnd, &mut buf).max(0) as usize;
        String::from_utf16_lossy(&buf[..got.min(n)])
    }
}

/// Create a child control.
///
/// # Safety
///
/// `parent` must be a live window.
unsafe fn child(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    style: u32,
    id: i32,
    r: RECT,
    font: HFONT,
) -> Option<HWND> {
    // SAFETY: the caller's contract; the strings outlive the call.
    unsafe {
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            &HSTRING::from(text),
            WINDOW_STYLE(WS_CHILD | WS_VISIBLE | style),
            r.left,
            r.top,
            r.right - r.left,
            r.bottom - r.top,
            Some(parent),
            Some(HMENU(id as isize as *mut _)),
            None,
            None,
        )
        .ok()?;
        SendMessageW(
            hwnd,
            WM_SETFONT,
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(0)),
        );
        Some(hwnd)
    }
}

/// Text size in pixels with `font`, wrapped at `width` (or on one line).
///
/// # Safety
///
/// `hwnd` must be a live window.
unsafe fn measure(hwnd: HWND, font: HFONT, text: &str, width: i32, wrap: bool) -> (i32, i32) {
    // SAFETY: the DC is released, and the old font restored, before
    // returning; the buffer is ours.
    unsafe {
        let dc = GetDC(Some(hwnd));
        let old = SelectObject(dc, HGDIOBJ(font.0));
        let mut buf: Vec<u16> = text.encode_utf16().collect();
        if buf.is_empty() {
            buf.push(u16::from(b' '));
        }
        let mut r = RECT {
            left: 0,
            top: 0,
            right: width,
            bottom: 0,
        };
        let flags = DT_CALCRECT
            | DT_NOPREFIX
            | if wrap {
                DT_WORDBREAK | DT_EDITCONTROL
            } else {
                DT_SINGLELINE
            };
        DrawTextW(dc, &mut buf, &mut r, flags);
        SelectObject(dc, old);
        ReleaseDC(Some(hwnd), dc);
        (r.right - r.left, r.bottom - r.top)
    }
}

/// Create the controls, size the dialog and center it on the monitor
/// under the cursor.
///
/// # Safety
///
/// `hdlg` must be the dialog in `WM_INITDIALOG`.
unsafe fn layout(hdlg: HWND, s: &mut State) {
    // SAFETY: the caller's contract; every handle used is live.
    unsafe {
        let spec = s.spec;
        // Dialog units to pixels.
        let dlu = |x: i32, y: i32| {
            let mut r = RECT {
                left: 0,
                top: 0,
                right: x,
                bottom: y,
            };
            let _ = MapDialogRect(hdlg, &mut r);
            (r.right, r.bottom)
        };
        let font = HFONT(SendMessageW(hdlg, WM_GETFONT, None, None).0 as *mut _);

        let mut lf = LOGFONTW::default();
        let heading_font = if GetObjectW(
            HGDIOBJ(font.0),
            size_of::<LOGFONTW>() as i32,
            Some((&mut lf as *mut LOGFONTW).cast()),
        ) != 0
        {
            lf.lfWeight = 600;
            lf.lfHeight = lf.lfHeight * 5 / 4;
            let f = CreateFontIndirectW(&lf);
            (!f.is_invalid()).then_some(f)
        } else {
            None
        };
        s.heading_font = heading_font;
        let heading = heading_font.unwrap_or(font);

        let (margin, _) = dlu(7, 0);
        let (_, vgap) = dlu(0, 7);
        let (_, small_gap) = dlu(0, 3);
        let (text_w, _) = dlu(250, 0);
        let (_, row_h) = dlu(0, 14);
        let (_, max_body_h) = dlu(0, 220);
        let icon_size = 32;

        let rect = |x: i32, y: i32, w: i32, h: i32| RECT {
            left: x,
            top: y,
            right: x + w,
            bottom: y + h,
        };

        // The icon.
        let icon = LoadIconW(
            None,
            if spec.warning {
                IDI_WARNING
            } else {
                IDI_INFORMATION
            },
        );
        if let (Ok(icon), Some(h)) = (
            icon,
            child(
                hdlg,
                w!("STATIC"),
                "",
                SS_ICON,
                ID_STATIC,
                rect(margin, margin, icon_size, icon_size),
                font,
            ),
        ) {
            SendMessageW(
                h,
                STM_SETICON,
                Some(WPARAM(icon.0 as usize)),
                Some(LPARAM(0)),
            );
        }
        let x = margin * 2 + icon_size;
        let mut y = margin;

        // The heading.
        let (_, h) = measure(hdlg, heading, spec.title, text_w, true);
        let _ = child(
            hdlg,
            w!("STATIC"),
            spec.title,
            SS_NOPREFIX,
            ID_STATIC,
            rect(x, y, text_w, h),
            heading,
        );
        y += h + vgap;

        // The body, scrolling if it is very long.
        if !spec.body.trim().is_empty() {
            let (_, h) = measure(hdlg, font, spec.body, text_w - 8, true);
            let (h, scroll) = if h + 8 > max_body_h {
                (max_body_h, WS_VSCROLL)
            } else {
                (h + 4, 0)
            };
            let _ = child(
                hdlg,
                w!("EDIT"),
                &crlf(spec.body),
                ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | scroll,
                ID_STATIC,
                rect(x, y, text_w, h),
                font,
            );
            y += h + vgap;
        }

        // The fields.
        for (i, (label, placeholder)) in spec.fields.iter().enumerate() {
            let (_, lh) = measure(hdlg, font, label, text_w, true);
            let _ = child(
                hdlg,
                w!("STATIC"),
                label,
                SS_NOPREFIX,
                ID_STATIC,
                rect(x, y, text_w, lh),
                font,
            );
            y += lh + small_gap;
            if let Some(f) = child(
                hdlg,
                w!("EDIT"),
                "",
                WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                FIRST_FIELD + i as i32,
                rect(x, y, text_w, row_h),
                font,
            ) {
                let cue = wide(placeholder);
                SendMessageW(
                    f,
                    EM_SETCUEBANNER,
                    Some(WPARAM(1)),
                    Some(LPARAM(cue.as_ptr() as isize)),
                );
                s.fields.push(f);
            }
            y += row_h + vgap;
        }

        // The buttons, right-aligned, the default first.
        let (min_w, _) = dlu(50, 0);
        let (pad, _) = dlu(16, 0);
        let (gap, _) = dlu(4, 0);
        let widths: Vec<i32> = spec
            .buttons
            .iter()
            .map(|b| (measure(hdlg, font, b, 0, false).0 + pad).max(min_w))
            .collect();
        let total: i32 = widths.iter().sum::<i32>() + gap * (widths.len() as i32 - 1).max(0);
        let content_right = x + text_w;
        let mut bx = content_right - total;
        let mut first_button = None;
        y += small_gap;
        for (i, (label, w)) in spec.buttons.iter().zip(&widths).enumerate() {
            let (id, style) = if i == 0 {
                (IDOK.0, BS_DEFPUSHBUTTON)
            } else {
                (FIRST_EXTRA_BUTTON + i as i32, BS_PUSHBUTTON)
            };
            let b = child(
                hdlg,
                w!("BUTTON"),
                label,
                style | WS_TABSTOP,
                id,
                rect(bx, y, *w, row_h),
                font,
            );
            if i == 0 {
                first_button = b;
            }
            bx += w + gap;
        }
        y += row_h + margin;

        // Size the dialog for that client area and center it.
        let mut frame = RECT {
            left: 0,
            top: 0,
            right: content_right + margin,
            bottom: y,
        };
        let style = WINDOW_STYLE(GetWindowLongW(hdlg, GWL_STYLE) as u32);
        let ex = WINDOW_EX_STYLE(GetWindowLongW(hdlg, GWL_EXSTYLE) as u32);
        let _ = AdjustWindowRectEx(&mut frame, style, false, ex);
        let (w, h) = (frame.right - frame.left, frame.bottom - frame.top);
        let mut cursor = POINT::default();
        let _ = GetCursorPos(&mut cursor);
        let mut info = MONITORINFO {
            cbSize: size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let work = if GetMonitorInfoW(
            MonitorFromPoint(cursor, MONITOR_DEFAULTTOPRIMARY),
            &mut info,
        )
        .as_bool()
        {
            info.rcWork
        } else {
            RECT {
                left: 0,
                top: 0,
                right: w,
                bottom: h,
            }
        };
        let left = work.left + ((work.right - work.left) - w).max(0) / 2;
        let top = work.top + ((work.bottom - work.top) - h).max(0) / 3;
        let _ = SetWindowPos(hdlg, Some(HWND_TOPMOST), left, top, w, h, SWP_SHOWWINDOW);
        let _ = SetForegroundWindow(hdlg);
        if let Some(f) = s.fields.first().copied().or(first_button) {
            let _ = SetFocus(Some(f));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_template_is_dword_aligned_and_names_the_font() {
        let t = template();
        let words: Vec<u16> = t
            .iter()
            .flat_map(|d| [*d as u16, (*d >> 16) as u16])
            .collect();
        // style has DS_SETFONT; no controls.
        assert_ne!(u32::from(words[0]) & DS_SETFONT, 0);
        assert_eq!(words[4], 0);
        let tail = String::from_utf16_lossy(&words[11..]);
        assert!(tail.starts_with("Faro\0\u{9}Segoe UI\0"), "{tail:?}");
    }

    #[test]
    fn bodies_get_crlf() {
        assert_eq!(crlf("a\nb\r\nc"), "a\r\nb\r\nc");
    }
}
