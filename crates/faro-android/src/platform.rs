//! The adapter from [`AndroidPlatform`] (Kotlin) to faro-platform's traits,
//! so `faro_service::InProcessFrameSource` can drive it like any other
//! [`AgentPlatform`].
//!
//! * **Frames** are checked strictly (non-zero dimensions, longest side at
//!   most [`MAX_FRAME_SIDE`], exactly `width * height * 4` bytes) and moved
//!   into a zeroizing [`Frame`] at once. A frame that fails a check is wiped
//!   and dropped, and the capture counts as failed.
//! * **Permission.** A capture refused for want of the accessibility
//!   service is `PlatformError::PermissionDenied`, and the permission is
//!   [`ACCESSIBILITY`], so the service's `permission_revoked` logic applies
//!   to it as to Screen Recording on a Mac.
//! * **Secure windows** (`FLAG_SECURE`). A refused capture is
//!   [`HIDDEN_FROM_CAPTURE`], which the service counts as failed but not
//!   towards `capture_failing`. The same app refusing two captures in a row
//!   (or reported by `poll_tamper` in between) gives one
//!   `window_hidden_from_capture`, again only after [`SECURE_QUIET_MS`]
//!   without one, as the macOS and Windows hidden-window rules do
//!   (ARCHITECTURE.md §3.7). The system's own UI ([`is_system_ui`]) is
//!   never reported, and its refusals are skipped captures.
//! * **Browser addresses** are reduced again to `scheme://host/`
//!   ([`reduce_origin`]); anything else is dropped.
//!
//! Nothing here logs pixels, addresses or titles. Android has no window
//! titles to give, and Faro reads none.

use crate::types::{
    AndroidPlatform, AndroidTamper, CaptureError, PermissionState as AndroidPermission,
    SessionEvent, SYSTEM_WINDOW,
};
use faro_platform::{
    AgentPlatform, AppInfo, BrowserContext, ForegroundInfo, Frame, PermissionState, PixelFormat,
    PlatformError, ScreenCapture, SessionChange, SessionState, TamperSignal, TamperSignals,
    MAX_FRAME_SIDE,
};
use faro_service::source::HIDDEN_FROM_CAPTURE;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;
use zeroize::Zeroize;

/// The permission Android captures need, as `permission_revoked` names it.
pub const ACCESSIBILITY: &str = "accessibility";
/// The device admin permission, as `permission_revoked` names it.
pub const DEVICE_ADMIN: &str = "device_admin";
/// An app is reported again only after this long without a secure window of
/// its in front (the desktop's quiet spell).
pub const SECURE_QUIET_MS: u64 = 5 * 60 * 1000;
/// Secure-window observations of one app in a row that make a report.
const SECURE_STREAK: u32 = 2;
/// Longest address text considered.
const MAX_ORIGIN_LEN: usize = 2048;
/// Longest app name in a signal.
const MAX_APP_NAME: usize = 100;

/// The system's own UI, which sets `FLAG_SECURE` for good reasons (the lock
/// screen, credential and permission prompts) and is never reported
/// (docs/ANDROID.md §8). No third-party app, and no browser, is ever on it.
/// Package names are unique on a device, so another app can't claim one of
/// these while the system's own is installed.
pub fn is_system_ui(package: &str) -> bool {
    matches!(
        package,
        "android"
            | "com.android.systemui"
            | "com.android.keyguard"
            | "com.android.permissioncontroller"
            | "com.google.android.permissioncontroller"
            | "com.android.settings"
    )
}

/// `scheme://host/` of an `http` or `https` address, lowercased (and in
/// punycode for international names), with any credentials, port, path,
/// query or fragment removed. `None` for anything else.
pub fn reduce_origin(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_ORIGIN_LEN {
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

/// The signal for a polled tamper observation. `SecureWindow` is not mapped
/// here: it goes through the debounce ([`Shared::observe_secure`]).
pub fn map_tamper(t: &AndroidTamper) -> Option<TamperSignal> {
    Some(match t {
        AndroidTamper::AccessibilityDisabled => TamperSignal::PermissionRevoked {
            permission: ACCESSIBILITY.into(),
            never_granted: false,
        },
        AndroidTamper::DeviceAdminDisableRequested => TamperSignal::PermissionRevoked {
            permission: DEVICE_ADMIN.into(),
            never_granted: false,
        },
        AndroidTamper::BatteryOptimizationOn => TamperSignal::BatteryOptimizationOn,
        AndroidTamper::UsbDebuggingOn => TamperSignal::UsbDebuggingOn,
        AndroidTamper::SecureWindow { .. } => return None,
    })
}

/// Printable, bounded text from Kotlin (an app name or a failure reason).
fn clean(s: &str, max: usize) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).take(max).collect();
    s.trim().to_owned()
}

/// Milliseconds on a monotonic clock.
pub type MonoClock = Arc<dyn Fn() -> u64 + Send + Sync>;

/// A monotonic clock starting now.
pub fn mono_clock() -> MonoClock {
    let start = Instant::now();
    Arc::new(move || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// The secure-window debounce (see the module docs).
#[derive(Default)]
struct SecureWindows {
    /// The app the latest observations saw, and how many in a row.
    streak: Option<(String, u32)>,
    /// Reported apps: when one was last seen.
    reported: HashMap<String, u64>,
}

impl SecureWindows {
    /// A secure window of `package` was seen. `Some(package)` when that is
    /// to be reported now.
    fn secure(&mut self, package: &str, now: u64) -> Option<String> {
        self.reported
            .retain(|_, seen| now.saturating_sub(*seen) < SECURE_QUIET_MS);
        let count = match &mut self.streak {
            Some((p, n)) if p == package => {
                *n = n.saturating_add(1);
                *n
            }
            _ => {
                self.streak = Some((package.to_owned(), 1));
                1
            }
        };
        if let Some(seen) = self.reported.get_mut(package) {
            *seen = now;
            return None;
        }
        if count >= SECURE_STREAK {
            self.reported.insert(package.to_owned(), now);
            return Some(package.to_owned());
        }
        None
    }

    /// Something other than a third-party secure window was seen in front.
    fn clear(&mut self) {
        self.streak = None;
    }
}

/// State shared by the adapter's parts and [`crate::FaroAndroid`].
pub struct Shared {
    platform: Arc<dyn AndroidPlatform>,
    mono: MonoClock,
    secure: Mutex<SecureWindows>,
    /// Signals waiting for the next tamper poll.
    pending: Mutex<Vec<TamperSignal>>,
    /// Session changes from `session_changed`, for the next poll.
    changes: Mutex<Vec<SessionChange>>,
    /// The app last seen in front, to name a secure window's app.
    foreground: Mutex<Option<crate::types::ForegroundApp>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    pub fn new(platform: Arc<dyn AndroidPlatform>, mono: MonoClock) -> Arc<Self> {
        Arc::new(Shared {
            platform,
            mono,
            secure: Mutex::default(),
            pending: Mutex::default(),
            changes: Mutex::default(),
            foreground: Mutex::default(),
        })
    }

    pub fn platform(&self) -> &Arc<dyn AndroidPlatform> {
        &self.platform
    }

    /// The [`AgentPlatform`] for `InProcessFrameSource`.
    pub fn agent_platform(self: &Arc<Self>) -> AgentPlatform {
        AgentPlatform {
            capture: Box::new(Capture(self.clone())),
            foreground: Box::new(Foreground(self.clone())),
            session: Box::new(Session(self.clone())),
            tamper: Box::new(Tamper(self.clone())),
        }
    }

    /// A secure window of `package` was seen in front (a refused capture,
    /// or `poll_tamper`). Queues `window_hidden_from_capture` when it is
    /// the second time in a row.
    pub fn observe_secure(&self, package: &str) {
        let package = clean(package, MAX_APP_NAME);
        if package.is_empty() || is_system_ui(&package) {
            lock(&self.secure).clear();
            return;
        }
        let now = (self.mono)();
        let Some(package) = lock(&self.secure).secure(&package, now) else {
            return;
        };
        let app = lock(&self.foreground)
            .as_ref()
            .filter(|f| f.package == package)
            .and_then(|f| f.label.as_deref().map(|l| clean(l, MAX_APP_NAME)))
            .filter(|l| !l.is_empty())
            .unwrap_or(package);
        tracing::warn!(%app, "a secure window keeps the screen from Faro");
        lock(&self.pending).push(TamperSignal::WindowHiddenFromCapture { app });
    }

    /// Queue a session change for the next poll.
    pub fn session_changed(&self, change: SessionEvent) {
        lock(&self.changes).push(match change {
            SessionEvent::Locked => SessionChange::Locked,
            SessionEvent::Unlocked => SessionChange::Unlocked,
            SessionEvent::DisplaySleep => SessionChange::DisplaySleep,
            SessionEvent::DisplayWake => SessionChange::DisplayWake,
        });
    }

    fn capture(&self) -> faro_platform::Result<Vec<Frame>> {
        match self.platform.capture_screen() {
            Ok(mut captured) => {
                let (w, h) = (captured.width, captured.height);
                let rgba = std::mem::take(&mut captured.rgba);
                let frame = checked_frame(w, h, rgba)?;
                lock(&self.secure).clear();
                Ok(vec![frame])
            }
            Err(CaptureError::PermissionDenied) => {
                Err(PlatformError::PermissionDenied(ACCESSIBILITY.into()))
            }
            Err(CaptureError::SecureWindow { package }) => {
                self.observe_secure(&package);
                Err(PlatformError::Unavailable(HIDDEN_FROM_CAPTURE.into()))
            }
            Err(CaptureError::Unavailable { reason }) if reason == SYSTEM_WINDOW => {
                lock(&self.secure).clear();
                Err(PlatformError::Unavailable(HIDDEN_FROM_CAPTURE.into()))
            }
            Err(CaptureError::Unavailable { reason }) => {
                let reason = clean(&reason, 200);
                Err(PlatformError::Unavailable(if reason.is_empty() {
                    "capture unavailable".into()
                } else {
                    reason
                }))
            }
        }
    }
}

/// `rgba` as a [`Frame`], or wiped and refused if it isn't exactly a
/// `width` × `height` RGBA frame no larger than [`MAX_FRAME_SIDE`].
pub fn checked_frame(width: u32, height: u32, mut rgba: Vec<u8>) -> faro_platform::Result<Frame> {
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4));
    let ok = width > 0
        && height > 0
        && width.max(height) <= MAX_FRAME_SIDE
        && expected == Some(rgba.len());
    if !ok {
        rgba.zeroize();
        tracing::warn!(
            width,
            height,
            "the platform returned an invalid frame; dropped"
        );
        return Err(PlatformError::Unavailable(
            "invalid frame from the platform".into(),
        ));
    }
    Frame::new(width, height, PixelFormat::Rgba8, 0, rgba)
        .map_err(|e| PlatformError::Unavailable(e.to_string()))
}

struct Capture(Arc<Shared>);

impl ScreenCapture for Capture {
    fn capture_all_displays(&mut self) -> faro_platform::Result<Vec<Frame>> {
        self.0.capture()
    }

    fn permission_state(&self) -> PermissionState {
        match self.0.platform.permission_state() {
            AndroidPermission::Granted => PermissionState::Granted,
            AndroidPermission::Denied => PermissionState::Denied,
            AndroidPermission::NotDetermined => PermissionState::NotDetermined,
        }
    }
}

struct Foreground(Arc<Shared>);

impl ForegroundInfo for Foreground {
    fn active_app(&self) -> Option<AppInfo> {
        let app = self.0.platform.foreground_app();
        *lock(&self.0.foreground) = app.clone();
        let app = app?;
        let id = clean(&app.package, MAX_APP_NAME);
        if id.is_empty() {
            return None;
        }
        Some(AppInfo {
            id,
            name: app
                .label
                .map(|l| clean(&l, MAX_APP_NAME))
                .filter(|l| !l.is_empty()),
        })
    }

    /// Android gives no window titles, and Faro reads none.
    fn window_title(&self) -> Option<String> {
        None
    }

    fn browser(&self) -> Option<BrowserContext> {
        let tab = self.0.platform.browser()?;
        let url = reduce_origin(&tab.origin);
        let ctx = BrowserContext {
            url,
            title: None,
            incognito: tab.incognito,
        };
        (ctx != BrowserContext::default()).then_some(ctx)
    }
}

struct Session(Arc<Shared>);

impl SessionState for Session {
    fn idle_secs(&self) -> u64 {
        self.0.platform.idle_secs()
    }

    fn is_locked(&self) -> bool {
        self.0.platform.is_locked()
    }

    fn display_asleep(&self) -> bool {
        self.0.platform.display_asleep()
    }

    fn poll_changes(&mut self) -> Vec<SessionChange> {
        std::mem::take(&mut *lock(&self.0.changes))
    }
}

struct Tamper(Arc<Shared>);

impl TamperSignals for Tamper {
    fn poll(&mut self) -> Vec<TamperSignal> {
        let mut out = Vec::new();
        for t in self.0.platform.poll_tamper() {
            match &t {
                AndroidTamper::SecureWindow { app } => self.0.observe_secure(app),
                other => out.extend(map_tamper(other)),
            }
        }
        let mut pending = std::mem::take(&mut *lock(&self.0.pending));
        pending.append(&mut out);
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BrowserTab, CapturedFrame, ForegroundApp};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Fake {
        captures: Mutex<VecDeque<Result<CapturedFrame, CaptureError>>>,
        tamper: Mutex<Vec<AndroidTamper>>,
        foreground: Mutex<Option<ForegroundApp>>,
        tab: Mutex<Option<BrowserTab>>,
    }

    impl AndroidPlatform for Fake {
        fn capture_screen(&self) -> Result<CapturedFrame, CaptureError> {
            lock(&self.captures)
                .pop_front()
                .unwrap_or(Err(CaptureError::Unavailable {
                    reason: "nothing scripted".into(),
                }))
        }
        fn permission_state(&self) -> AndroidPermission {
            AndroidPermission::Granted
        }
        fn foreground_app(&self) -> Option<ForegroundApp> {
            lock(&self.foreground).clone()
        }
        fn browser(&self) -> Option<BrowserTab> {
            lock(&self.tab).clone()
        }
        fn idle_secs(&self) -> u64 {
            0
        }
        fn is_locked(&self) -> bool {
            false
        }
        fn display_asleep(&self) -> bool {
            false
        }
        fn poll_tamper(&self) -> Vec<AndroidTamper> {
            std::mem::take(&mut *lock(&self.tamper))
        }
        fn show_notice(&self, _text: String) {}
    }

    struct Rig {
        fake: Arc<Fake>,
        now: Arc<AtomicU64>,
        p: AgentPlatform,
    }

    impl Rig {
        fn new() -> Rig {
            let fake = Arc::new(Fake::default());
            let now = Arc::new(AtomicU64::new(1_000));
            let n = now.clone();
            let shared = Shared::new(fake.clone(), Arc::new(move || n.load(Ordering::SeqCst)));
            let p = shared.agent_platform();
            Rig { fake, now, p }
        }
        fn script(&self, r: Result<CapturedFrame, CaptureError>) {
            lock(&self.fake.captures).push_back(r);
        }
        fn secure(&self, package: &str) {
            self.script(Err(CaptureError::SecureWindow {
                package: package.into(),
            }));
        }
        fn ok(&self) {
            self.script(Ok(frame(4, 2)));
        }
        fn capture(&mut self) -> faro_platform::Result<Vec<Frame>> {
            self.p.capture.capture_all_displays()
        }
        fn advance(&self, ms: u64) {
            self.now.fetch_add(ms, Ordering::SeqCst);
        }
        fn hidden(&mut self) -> Vec<String> {
            self.p
                .tamper
                .poll()
                .into_iter()
                .filter_map(|s| match s {
                    TamperSignal::WindowHiddenFromCapture { app } => Some(app),
                    _ => None,
                })
                .collect()
        }
    }

    fn frame(w: u32, h: u32) -> CapturedFrame {
        CapturedFrame {
            width: w,
            height: h,
            rgba: vec![7; (w * h * 4) as usize],
        }
    }

    fn is_hidden(r: &faro_platform::Result<Vec<Frame>>) -> bool {
        matches!(r, Err(PlatformError::Unavailable(m)) if m == HIDDEN_FROM_CAPTURE)
    }

    #[test]
    fn valid_frames_become_frames() {
        let mut r = Rig::new();
        r.ok();
        let frames = r.capture().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!((frames[0].width(), frames[0].height()), (4, 2));
        assert_eq!(frames[0].format(), PixelFormat::Rgba8);
        assert!(frames[0].pixels().iter().all(|&b| b == 7));
        // The largest frame allowed.
        r.script(Ok(frame(MAX_FRAME_SIDE, 432)));
        assert!(r.capture().is_ok());
    }

    #[test]
    fn invalid_frames_are_refused() {
        let mut r = Rig::new();
        let bad = [
            CapturedFrame {
                width: 0,
                height: 2,
                rgba: vec![],
            },
            CapturedFrame {
                width: 2,
                height: 0,
                rgba: vec![],
            },
            // Too large: longest side over 768.
            frame(MAX_FRAME_SIDE + 1, 10),
            frame(10, MAX_FRAME_SIDE + 1),
            // Wrong length (short, long, and RGB instead of RGBA).
            CapturedFrame {
                width: 2,
                height: 2,
                rgba: vec![0; 15],
            },
            CapturedFrame {
                width: 2,
                height: 2,
                rgba: vec![0; 17],
            },
            CapturedFrame {
                width: 2,
                height: 2,
                rgba: vec![0; 12],
            },
            // Overflowing dimensions.
            CapturedFrame {
                width: u32::MAX,
                height: u32::MAX,
                rgba: vec![0; 4],
            },
        ];
        for f in bad {
            let desc = format!("{f:?}");
            r.script(Ok(f));
            let got = r.capture();
            assert!(
                matches!(&got, Err(PlatformError::Unavailable(m)) if m.contains("invalid frame")),
                "{desc}: {got:?}"
            );
        }
    }

    #[test]
    fn checked_frame_wipes_what_it_refuses() {
        // The refused buffer is zeroized before it is dropped; the check
        // itself is what this pins down (the Vec is gone afterwards).
        assert!(checked_frame(2, 2, vec![9; 15]).is_err());
        assert!(checked_frame(2, 2, vec![9; 16]).is_ok());
    }

    #[test]
    fn debug_never_prints_pixels() {
        let f = CapturedFrame {
            width: 1,
            height: 1,
            rgba: vec![0xAB, 0xCD, 0xEF, 0x12],
        };
        let d = format!("{f:?}");
        assert!(d.contains("redacted"), "{d}");
        assert!(!d.contains("171") && !d.contains("205"), "{d}");
        let tab = BrowserTab {
            browser_package: "com.android.chrome".into(),
            origin: "https://secret.example/".into(),
            incognito: false,
        };
        assert!(!format!("{tab:?}").contains("secret"));
    }

    #[test]
    fn permission_denied_is_the_platforms_permission_error() {
        let mut r = Rig::new();
        r.script(Err(CaptureError::PermissionDenied));
        assert_eq!(
            r.capture().unwrap_err(),
            PlatformError::PermissionDenied(ACCESSIBILITY.into())
        );
    }

    #[test]
    fn a_secure_window_two_captures_in_a_row_is_reported_once() {
        let mut r = Rig::new();
        *lock(&r.fake.foreground) = Some(ForegroundApp {
            package: "org.thoughtcrime.securesms".into(),
            label: Some("Signal".into()),
        });
        // Learn the foreground (the source polls it).
        let _ = r.p.foreground.active_app();
        r.secure("org.thoughtcrime.securesms");
        assert!(is_hidden(&r.capture()));
        assert!(r.hidden().is_empty(), "one refused capture is not enough");
        r.secure("org.thoughtcrime.securesms");
        assert!(is_hidden(&r.capture()));
        assert_eq!(r.hidden(), vec!["Signal".to_owned()]);
        // Still there: no second report.
        for _ in 0..5 {
            r.advance(60_000);
            r.secure("org.thoughtcrime.securesms");
            assert!(is_hidden(&r.capture()));
        }
        assert!(r.hidden().is_empty());
    }

    #[test]
    fn a_working_capture_in_between_breaks_the_streak() {
        let mut r = Rig::new();
        for _ in 0..3 {
            r.secure("com.example.bank");
            let _ = r.capture();
            r.ok();
            r.capture().unwrap();
        }
        assert!(r.hidden().is_empty());
        // Two different apps in a row are not a streak either.
        r.secure("com.example.bank");
        let _ = r.capture();
        r.secure("com.example.vault");
        let _ = r.capture();
        assert!(r.hidden().is_empty());
        r.secure("com.example.vault");
        let _ = r.capture();
        assert_eq!(r.hidden(), vec!["com.example.vault".to_owned()]);
    }

    #[test]
    fn reported_again_only_after_a_quiet_spell() {
        let mut r = Rig::new();
        let twice = |r: &mut Rig| {
            for _ in 0..2 {
                r.secure("com.example.bank");
                let _ = r.capture();
            }
        };
        twice(&mut r);
        assert_eq!(r.hidden().len(), 1);
        // Gone for a minute, back: still within the quiet spell.
        r.ok();
        r.capture().unwrap();
        r.advance(60_000);
        twice(&mut r);
        assert!(r.hidden().is_empty());
        // Gone for longer than the quiet spell, back: reported again.
        r.ok();
        r.capture().unwrap();
        r.advance(SECURE_QUIET_MS + 1);
        twice(&mut r);
        assert_eq!(r.hidden(), vec!["com.example.bank".to_owned()]);
    }

    #[test]
    fn polled_secure_windows_count_as_observations() {
        let mut r = Rig::new();
        lock(&r.fake.tamper).push(AndroidTamper::SecureWindow {
            app: "com.example.bank".into(),
        });
        assert!(r.hidden().is_empty());
        r.secure("com.example.bank");
        let _ = r.capture();
        assert_eq!(r.hidden(), vec!["com.example.bank".to_owned()]);
    }

    #[test]
    fn the_systems_own_ui_is_never_reported_and_never_a_failure() {
        let mut r = Rig::new();
        for pkg in ["com.android.systemui", "android", "com.android.settings"] {
            for _ in 0..3 {
                r.secure(pkg);
                assert!(is_hidden(&r.capture()));
            }
        }
        for _ in 0..3 {
            r.script(Err(CaptureError::Unavailable {
                reason: SYSTEM_WINDOW.into(),
            }));
            assert!(is_hidden(&r.capture()), "a skipped capture");
        }
        assert!(r.hidden().is_empty());
        // Browsers are never exempt (private tabs set FLAG_SECURE).
        for _ in 0..2 {
            r.secure("com.android.chrome");
            let _ = r.capture();
        }
        assert_eq!(r.hidden(), vec!["com.android.chrome".to_owned()]);
    }

    #[test]
    fn other_failures_are_plain_failures() {
        let mut r = Rig::new();
        r.script(Err(CaptureError::Unavailable {
            reason: "rate limited\n".into(),
        }));
        assert_eq!(
            r.capture().unwrap_err(),
            PlatformError::Unavailable("rate limited".into())
        );
    }

    #[test]
    fn tamper_mapping() {
        let mut r = Rig::new();
        *lock(&r.fake.tamper) = vec![
            AndroidTamper::AccessibilityDisabled,
            AndroidTamper::DeviceAdminDisableRequested,
            AndroidTamper::BatteryOptimizationOn,
            AndroidTamper::UsbDebuggingOn,
        ];
        let got = r.p.tamper.poll();
        assert_eq!(
            got,
            vec![
                TamperSignal::PermissionRevoked {
                    permission: "accessibility".into(),
                    never_granted: false
                },
                TamperSignal::PermissionRevoked {
                    permission: "device_admin".into(),
                    never_granted: false
                },
                TamperSignal::BatteryOptimizationOn,
                TamperSignal::UsbDebuggingOn,
            ]
        );
        assert!(!got[0].is_context_only() && !got[1].is_context_only());
        assert!(got[2].is_context_only() && got[3].is_context_only());
        assert!(r.p.tamper.poll().is_empty(), "drained");
    }

    #[test]
    fn origins_are_reduced_to_scheme_and_host() {
        for (raw, want) in [
            ("https://example.com/", Some("https://example.com/")),
            ("https://Example.COM", Some("https://example.com/")),
            ("http://example.com./", Some("http://example.com/")),
            (
                "https://user:pw@example.com:8443/a/b?q=secret#frag",
                Some("https://example.com/"),
            ),
            (
                "https://bücher.example/x",
                Some("https://xn--bcher-kva.example/"),
            ),
            ("http://192.168.1.1:8080/admin", Some("http://192.168.1.1/")),
            ("https://[::1]/", Some("https://[::1]/")),
            ("  https://example.com/  ", Some("https://example.com/")),
            ("ftp://example.com/", None),
            ("javascript:alert(1)", None),
            ("file:///sdcard/x", None),
            ("example.com", None),
            ("", None),
        ] {
            assert_eq!(reduce_origin(raw).as_deref(), want, "{raw}");
        }
        assert_eq!(
            reduce_origin(&format!("https://e.com/{}", "a".repeat(3000))),
            None
        );
    }

    #[test]
    fn browser_context_carries_only_the_reduced_origin() {
        let r = Rig::new();
        *lock(&r.fake.tab) = Some(BrowserTab {
            browser_package: "com.android.chrome".into(),
            origin: "https://example.com/private/path?q=1".into(),
            incognito: false,
        });
        let b = r.p.foreground.browser().unwrap();
        assert_eq!(b.url.as_deref(), Some("https://example.com/"));
        assert_eq!(b.title, None);
        // An address that isn't one: only the private-mode flag survives.
        *lock(&r.fake.tab) = Some(BrowserTab {
            browser_package: "org.mozilla.firefox".into(),
            origin: "about:privatebrowsing".into(),
            incognito: true,
        });
        let b = r.p.foreground.browser().unwrap();
        assert_eq!((b.url, b.incognito), (None, true));
        *lock(&r.fake.tab) = Some(BrowserTab {
            browser_package: "org.mozilla.firefox".into(),
            origin: "about:blank".into(),
            incognito: false,
        });
        assert_eq!(r.p.foreground.browser(), None);
        assert_eq!(r.p.foreground.window_title(), None);
    }

    #[test]
    fn session_changes_are_drained_once() {
        let fake = Arc::new(Fake::default());
        let shared = Shared::new(fake, mono_clock());
        let mut p = shared.agent_platform();
        shared.session_changed(SessionEvent::Locked);
        shared.session_changed(SessionEvent::DisplaySleep);
        assert_eq!(
            p.session.poll_changes(),
            vec![SessionChange::Locked, SessionChange::DisplaySleep]
        );
        assert!(p.session.poll_changes().is_empty());
    }
}
