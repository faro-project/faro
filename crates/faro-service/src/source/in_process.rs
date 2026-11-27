//! An [`AgentPlatform`] driven inside the service process.
//!
//! Used with `faro_platform::synthetic::Script` by tests and the headless E2E
//! client, (development only) with the real macOS platform when the
//! service runs as the logged-in user, and in production on Android, where
//! one app process both captures and runs the service
//! (`crates/faro-android`). A root desktop service never uses it: it
//! cannot capture the user's graphical session (§3.1).
//!
//! What a platform needs from it beyond the [`AgentPlatform`] calls is set
//! here: the permission its captures need
//! ([`InProcessFrameSource::with_capture_permission`]), and where notices
//! go ([`InProcessFrameSource::with_notice`]; without one they are only
//! logged). A capture refused because a window keeps itself out of
//! captures ([`super::HIDDEN_FROM_CAPTURE`]) becomes
//! [`SourceEvent::CaptureHidden`].
//!
//! The platform calls are synchronous (and on macOS may block on
//! ScreenCaptureKit for up to its timeout), so they run on Tokio's blocking
//! pool, one at a time.

use super::{BoxFuture, FrameSource, SourceCommand, SourceEvent, SourceIo, HIDDEN_FROM_CAPTURE};
use faro_platform::{AgentPlatform, AppInfo, BrowserContext, PermissionState, PlatformError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// Shows a notice (`title`, `body`) to the person at the screen.
pub type NoticeFn = dyn Fn(&str, &str) + Send + Sync;

/// See the module docs.
pub struct InProcessFrameSource {
    platform: Arc<Mutex<AgentPlatform>>,
    poll_every: Duration,
    label: String,
    capture_permission: &'static str,
    notice: Option<Arc<NoticeFn>>,
}

impl InProcessFrameSource {
    /// Poll foreground, session, permission and tamper state every
    /// `poll_every` (the agent does the same on its own loop).
    pub fn new(platform: AgentPlatform, poll_every: Duration) -> Self {
        InProcessFrameSource {
            platform: Arc::new(Mutex::new(platform)),
            poll_every: poll_every.max(Duration::from_millis(1)),
            label: "in-process".into(),
            capture_permission: crate::runtime::SCREEN_RECORDING,
            notice: None,
        }
    }

    /// The permission this platform's captures need, as
    /// `permission_revoked` names it (default `screen_recording`).
    pub fn with_capture_permission(mut self, permission: &'static str) -> Self {
        self.capture_permission = permission;
        self
    }

    /// Show notices (the login notice and the monthly consent notice, §12)
    /// with `show`, called on Tokio's blocking pool.
    pub fn with_notice(mut self, show: impl Fn(&str, &str) + Send + Sync + 'static) -> Self {
        self.notice = Some(Arc::new(show));
        self
    }

    /// The `session` reported in [`SourceEvent::AgentConnected`].
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }
}

#[derive(Default, PartialEq)]
struct Seen {
    foreground: Option<(Option<AppInfo>, Option<String>)>,
    /// The tab last sent (`None`: none, or never sent).
    browser: Option<BrowserContext>,
    session: Option<(u64, bool, bool)>,
    permission: Option<PermissionState>,
}

/// What one poll observed.
struct Observed {
    foreground: (Option<AppInfo>, Option<String>),
    browser: Option<BrowserContext>,
    session: (u64, bool, bool),
    permission: PermissionState,
    changes: Vec<faro_platform::SessionChange>,
    tamper: Vec<faro_proto::body::TamperSignal>,
}

fn observe(p: &mut AgentPlatform) -> Observed {
    Observed {
        foreground: (p.foreground.active_app(), p.foreground.window_title()),
        browser: p.foreground.browser(),
        session: (
            p.session.idle_secs(),
            p.session.is_locked(),
            p.session.display_asleep(),
        ),
        permission: p.capture.permission_state(),
        changes: p.session.poll_changes(),
        tamper: p.tamper.poll(),
    }
}

impl FrameSource for InProcessFrameSource {
    fn name(&self) -> &'static str {
        "in-process"
    }

    fn capture_permission(&self) -> &'static str {
        self.capture_permission
    }

    fn run(self: Box<Self>, io: SourceIo) -> BoxFuture {
        Box::pin(async move {
            // No agent, so no status menu to feed.
            let SourceIo {
                mut commands,
                events,
                ..
            } = io;
            let platform = self.platform;
            let notice = self.notice;
            // One session that is always at the screen; it has no OS
            // account label.
            let connected = SourceEvent::AgentConnected {
                session: self.label.clone(),
                account: String::new(),
                agent_version: format!("in-process/{}", env!("CARGO_PKG_VERSION")),
            };
            let target = SourceEvent::CaptureTarget(Some(super::CaptureTarget {
                session: self.label.clone(),
                account: String::new(),
            }));
            for ev in [connected, target] {
                if events.send(ev).await.is_err() {
                    return;
                }
            }
            let mut seen = Seen::default();
            let mut tick = tokio::time::interval(self.poll_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    cmd = commands.recv() => match cmd {
                        None | Some(SourceCommand::Shutdown) => return,
                        Some(SourceCommand::ShowNotice { title, body, .. }) => match &notice {
                            Some(show) => {
                                let show = show.clone();
                                tracing::info!(%title, "showing a notice");
                                if tokio::task::spawn_blocking(move || show(&title, &body)).await.is_err() {
                                    tracing::error!("showing the notice panicked");
                                }
                            }
                            None => tracing::info!(%title, "notice (in-process source has no UI)"),
                        },
                        Some(SourceCommand::CaptureNow(_)) => {
                            let p = platform.clone();
                            let result = tokio::task::spawn_blocking(move || {
                                p.lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .capture
                                    .capture_all_displays()
                            })
                            .await;
                            let ev = match result {
                                Ok(Ok(frames)) if !frames.is_empty() => SourceEvent::Frames(frames),
                                Ok(Ok(_)) => SourceEvent::CaptureFailed { reason: "no displays".into() },
                                Ok(Err(PlatformError::Unavailable(m))) if m == HIDDEN_FROM_CAPTURE => SourceEvent::CaptureHidden,
                                Ok(Err(e)) => SourceEvent::CaptureFailed { reason: failure_reason(&e) },
                                Err(_) => SourceEvent::CaptureFailed { reason: "capture task panicked".into() },
                            };
                            if events.send(ev).await.is_err() {
                                return;
                            }
                        }
                    },
                    _ = tick.tick() => {
                        let p = platform.clone();
                        let Ok(obs) = tokio::task::spawn_blocking(move || {
                            observe(&mut p.lock().unwrap_or_else(PoisonError::into_inner))
                        })
                        .await else {
                            tracing::error!("platform poll panicked");
                            continue;
                        };
                        for ev in diff(&mut seen, obs) {
                            if events.send(ev).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        })
    }
}

fn diff(seen: &mut Seen, obs: Observed) -> Vec<SourceEvent> {
    let mut out = Vec::new();
    let app_changed = seen
        .foreground
        .as_ref()
        .map(|f| f.0.as_ref().map(|a| &a.id))
        != Some(obs.foreground.0.as_ref().map(|a| &a.id));
    if seen.foreground.as_ref() != Some(&obs.foreground) {
        out.push(SourceEvent::Foreground {
            app: obs.foreground.0.clone(),
            title: obs.foreground.1.clone(),
        });
        seen.foreground = Some(obs.foreground);
    }
    // After `Foreground`, as the agent does: the core drops the tab when
    // the app changes, so the new app's tab is sent again even if it is the
    // same. No tab goes out as an empty context, which clears it. URLs are
    // never logged.
    if seen.browser != obs.browser || (app_changed && obs.browser.is_some()) {
        out.push(SourceEvent::Browser(
            obs.browser.clone().unwrap_or_default(),
        ));
        seen.browser = obs.browser;
    }
    if seen.session != Some(obs.session) {
        let (idle_secs, locked, display_asleep) = obs.session;
        out.push(SourceEvent::Session {
            idle_secs,
            locked,
            display_asleep,
        });
        seen.session = Some(obs.session);
    }
    if seen.permission != Some(obs.permission) {
        out.push(SourceEvent::Permission {
            screen: obs.permission,
            accessibility: None,
        });
        seen.permission = Some(obs.permission);
    }
    out.extend(obs.changes.into_iter().map(SourceEvent::SessionChanged));
    out.extend(obs.tamper.into_iter().map(|signal| SourceEvent::Tamper {
        signal,
        account: None,
    }));
    out
}

/// A short diagnostic that never contains screen content.
fn failure_reason(e: &PlatformError) -> String {
    let s = match e {
        PlatformError::PermissionDenied(_) => "permission denied".to_owned(),
        PlatformError::Unavailable(m) | PlatformError::Os(m) => m.chars().take(200).collect(),
    };
    s.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_platform::synthetic::Script;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn drives_synthetic_platform() {
        let script = Script::new();
        let src = Box::new(InProcessFrameSource::new(
            script.platform(),
            Duration::from_millis(5),
        ));
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let (ev_tx, mut ev_rx) = mpsc::channel(16);
        let task = tokio::spawn(src.run(SourceIo::new(cmd_rx, ev_tx)));
        assert!(matches!(
            ev_rx.recv().await,
            Some(SourceEvent::AgentConnected { .. })
        ));
        assert!(matches!(
            ev_rx.recv().await,
            Some(SourceEvent::CaptureTarget(Some(_)))
        ));
        cmd_tx
            .send(SourceCommand::CaptureNow(faro_ipc::CaptureReason::Startup))
            .await
            .unwrap();
        let mut got_frames = false;
        let mut got_fg = false;
        while !(got_frames && got_fg) {
            match ev_rx.recv().await.unwrap() {
                SourceEvent::Frames(f) => {
                    assert_eq!(f.len(), 1);
                    got_frames = true;
                }
                SourceEvent::Foreground { app, .. } => {
                    assert_eq!(app.unwrap().id, "com.example.editor");
                    got_fg = true;
                }
                _ => {}
            }
        }
        script.with(|s| s.tamper.push(faro_proto::body::TamperSignal::VpnActive));
        loop {
            if let SourceEvent::Tamper { signal, .. } = ev_rx.recv().await.unwrap() {
                assert_eq!(signal, faro_proto::body::TamperSignal::VpnActive);
                break;
            }
        }
        script.with(|s| s.permission = PermissionState::Denied);
        cmd_tx
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        loop {
            if let SourceEvent::CaptureFailed { reason } = ev_rx.recv().await.unwrap() {
                assert_eq!(reason, "permission denied");
                break;
            }
        }
        cmd_tx.send(SourceCommand::Shutdown).await.unwrap();
        task.await.unwrap();
    }

    struct Hidden;

    impl faro_platform::ScreenCapture for Hidden {
        fn capture_all_displays(&mut self) -> faro_platform::Result<Vec<faro_platform::Frame>> {
            Err(PlatformError::Unavailable(HIDDEN_FROM_CAPTURE.into()))
        }
        fn permission_state(&self) -> PermissionState {
            PermissionState::Granted
        }
    }

    #[tokio::test]
    async fn notices_tabs_permission_and_hidden_captures() {
        let script = Script::new();
        script.with(|s| {
            s.browser = Some(BrowserContext {
                url: Some("https://example.test/".into()),
                title: None,
                incognito: false,
            })
        });
        let mut platform = script.platform();
        platform.capture = Box::new(Hidden);
        let shown = Arc::new(Mutex::new(Vec::new()));
        let s2 = shown.clone();
        let src = InProcessFrameSource::new(platform, Duration::from_millis(5))
            .with_capture_permission("accessibility_service")
            .with_notice(move |t, b| s2.lock().unwrap().push(format!("{t}|{b}")));
        assert_eq!(src.capture_permission(), "accessibility_service");
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let (ev_tx, mut ev_rx) = mpsc::channel(16);
        let task = tokio::spawn(Box::new(src).run(SourceIo::new(cmd_rx, ev_tx)));
        // The tab follows the foreground.
        loop {
            if let SourceEvent::Browser(b) = ev_rx.recv().await.unwrap() {
                assert_eq!(b.url.as_deref(), Some("https://example.test/"));
                break;
            }
        }
        // It went away: an empty context clears it.
        script.with(|s| s.browser = None);
        loop {
            if let SourceEvent::Browser(b) = ev_rx.recv().await.unwrap() {
                assert_eq!(b, BrowserContext::default());
                break;
            }
        }
        cmd_tx
            .send(SourceCommand::CaptureNow(
                faro_ipc::CaptureReason::Scheduled,
            ))
            .await
            .unwrap();
        loop {
            match ev_rx.recv().await.unwrap() {
                SourceEvent::CaptureHidden => break,
                SourceEvent::CaptureFailed { reason } => panic!("{reason}"),
                _ => {}
            }
        }
        cmd_tx
            .send(SourceCommand::ShowNotice {
                session: None,
                title: "Faro".into(),
                body: "This phone is monitored".into(),
            })
            .await
            .unwrap();
        cmd_tx.send(SourceCommand::Shutdown).await.unwrap();
        task.await.unwrap();
        assert_eq!(*shown.lock().unwrap(), vec!["Faro|This phone is monitored"]);
    }
}
