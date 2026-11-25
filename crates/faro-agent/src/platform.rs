//! A dedicated thread that owns the [`AgentPlatform`].
//!
//! The platform traits are synchronous and some calls can block for seconds
//! (a ScreenCaptureKit round trip is bounded at 5 s per display, and
//! `replayd` stalls while a TCC re-confirmation dialog is up). Running them
//! on their own thread keeps the async IPC loop responsive, so a slow
//! capture never delays a `Pong` and the service does not mistake a busy
//! agent for a hung one.
//!
//! One long-lived thread (rather than `spawn_blocking`) also keeps every OS
//! object the platform creates on a single thread, which is what the macOS
//! layer's autorelease-pool handling assumes.
//!
//! Requests are served strictly in order. Results come back on one-shot
//! channels; if the requester has gone away (the connection dropped) a
//! capture's frames are dropped on this thread, which zeroizes them.

use std::sync::mpsc;
use std::thread::JoinHandle;

use faro_ipc::{WireFrame, WireFrameError};
use faro_platform::{
    AgentPlatform, AppInfo, BrowserContext, PermissionState, PlatformError, SessionChange,
    TamperSignal,
};
use tokio::sync::oneshot;

use crate::frames::capture_to_wire;
use crate::identity::mono_ms;

/// Reports whether the session has granted the Accessibility permission
/// (macOS; used for window titles). Platforms without such a permission
/// pass no probe and report `accessibility: None`.
pub type AccessibilityProbe = Box<dyn Fn() -> bool + Send>;

/// One sample of everything the agent reports besides frames.
pub struct Observation {
    pub app: Option<AppInfo>,
    /// Sensitive; see the crate docs. Not printed by `Debug`.
    pub title: Option<String>,
    /// The active browser tab, already reduced by the platform. Sensitive:
    /// not printed by `Debug`.
    pub browser: Option<BrowserContext>,
    pub idle_secs: u64,
    pub locked: bool,
    pub display_asleep: bool,
    /// Session edges since the previous observation.
    pub changes: Vec<SessionChange>,
    /// Tamper/context signals since the previous observation (the platform
    /// edge-triggers them).
    pub tamper: Vec<TamperSignal>,
    pub permission: PermissionState,
    pub accessibility: Option<bool>,
}

impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observation")
            .field("app", &self.app)
            .field("title", &self.title.as_ref().map(|_| "<redacted>"))
            .field("browser", &self.browser.as_ref().map(|_| "<redacted>"))
            .field("idle_secs", &self.idle_secs)
            .field("locked", &self.locked)
            .field("display_asleep", &self.display_asleep)
            .field("changes", &self.changes)
            .field("tamper", &self.tamper)
            .field("permission", &self.permission)
            .field("accessibility", &self.accessibility)
            .finish()
    }
}

/// Why a capture produced no frames.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    #[error("capture failed: {0}")]
    Platform(#[from] PlatformError),
    #[error("platform produced an invalid frame: {0}")]
    InvalidFrame(#[from] WireFrameError),
    #[error("no displays were captured")]
    NoDisplays,
    #[error("monotonic clock unavailable")]
    Clock,
}

impl CaptureError {
    /// Whether the OS refused the capture permission.
    pub fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            CaptureError::Platform(PlatformError::PermissionDenied(_))
        )
    }
}

/// One capture of every display, ready to send.
#[derive(Debug)]
pub struct Capture {
    pub captured_at_mono_ms: u64,
    pub frames: Vec<WireFrame>,
}

/// The result of a capture request plus the permission state sampled right
/// after it, so a denial can be reported with the current state.
#[derive(Debug)]
pub struct CaptureOutcome {
    pub result: Result<Capture, CaptureError>,
    pub permission: PermissionState,
    pub accessibility: Option<bool>,
}

enum Request {
    Capture(oneshot::Sender<CaptureOutcome>),
    Observe(oneshot::Sender<Observation>),
}

/// The platform thread has exited (it panicked inside a platform call).
/// The agent cannot do its job without it and should exit, so the OS
/// relaunches it and the service logs `agent_restarted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the platform thread is gone")]
pub struct WorkerGone;

/// Handle to the platform thread. Dropping it lets the thread exit once its
/// current call returns.
#[derive(Debug)]
pub struct PlatformWorker {
    tx: mpsc::Sender<Request>,
    // Never joined: a capture stuck inside the OS must not block the agent
    // from exiting. The thread ends when `tx` is dropped.
    _thread: JoinHandle<()>,
}

impl PlatformWorker {
    pub fn spawn(
        platform: AgentPlatform,
        accessibility: Option<AccessibilityProbe>,
    ) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("faro-platform".into())
            .spawn(move || serve(platform, accessibility, rx))?;
        Ok(PlatformWorker {
            tx,
            _thread: thread,
        })
    }

    /// Ask for a capture of every display.
    pub fn capture(&self) -> Result<oneshot::Receiver<CaptureOutcome>, WorkerGone> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Request::Capture(tx)).map_err(|_| WorkerGone)?;
        Ok(rx)
    }

    /// Ask for a state observation.
    pub fn observe(&self) -> Result<oneshot::Receiver<Observation>, WorkerGone> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Request::Observe(tx)).map_err(|_| WorkerGone)?;
        Ok(rx)
    }
}

fn serve(
    mut p: AgentPlatform,
    accessibility: Option<AccessibilityProbe>,
    rx: mpsc::Receiver<Request>,
) {
    let accessibility = || accessibility.as_ref().map(|probe| probe());
    while let Ok(req) = rx.recv() {
        match req {
            Request::Capture(reply) => {
                let result = capture(&mut p);
                let outcome = CaptureOutcome {
                    result,
                    permission: p.capture.permission_state(),
                    accessibility: accessibility(),
                };
                // If the receiver is gone the outcome comes back and drops
                // here, zeroizing any frames.
                let _ = reply.send(outcome);
            }
            Request::Observe(reply) => {
                let obs = Observation {
                    app: p.foreground.active_app(),
                    title: p.foreground.window_title(),
                    browser: p.foreground.browser(),
                    idle_secs: p.session.idle_secs(),
                    locked: p.session.is_locked(),
                    display_asleep: p.session.display_asleep(),
                    changes: p.session.poll_changes(),
                    tamper: p.tamper.poll(),
                    permission: p.capture.permission_state(),
                    accessibility: accessibility(),
                };
                if let Err(lost) = reply.send(obs) {
                    // The requester vanished between asking and now. Session
                    // edges and tamper signals were drained from the
                    // platform and must not vanish with it.
                    tracing::warn!(
                        changes = lost.changes.len(),
                        tamper = lost.tamper.len(),
                        "observation requester went away; signals in it are lost"
                    );
                }
            }
        }
    }
}

fn capture(p: &mut AgentPlatform) -> Result<Capture, CaptureError> {
    let captured_at_mono_ms = mono_ms().ok_or(CaptureError::Clock)?;
    let frames = p.capture.capture_all_displays()?;
    if frames.is_empty() {
        return Err(CaptureError::NoDisplays);
    }
    let frames = capture_to_wire(frames)?;
    Ok(Capture {
        captured_at_mono_ms,
        frames,
    })
}

// Unix only: `identity::mono_ms` has no Windows source yet (it must be a
// since-boot clock shared with the service, not a per-process `Instant`),
// and there is no Windows agent for it to serve.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use faro_platform::synthetic::Script;

    #[tokio::test]
    async fn capture_and_observe_round_trip() {
        let script = Script::new();
        script.with(|s| {
            s.displays = 2;
            s.tamper.push(TamperSignal::VpnActive);
            s.browser = Some(BrowserContext {
                url: Some("https://example.test/".into()),
                title: None,
                incognito: false,
            });
        });
        let w = PlatformWorker::spawn(script.platform(), Some(Box::new(|| true))).unwrap();
        let out = w.capture().unwrap().await.unwrap();
        let cap = out.result.unwrap();
        assert_eq!(cap.frames.len(), 2);
        assert_eq!(out.permission, PermissionState::Granted);
        assert_eq!(out.accessibility, Some(true));

        let obs = w.observe().unwrap().await.unwrap();
        assert_eq!(obs.tamper, vec![TamperSignal::VpnActive]);
        assert!(obs.browser.is_some());
        let debug = format!("{obs:?}");
        assert!(!debug.contains("Untitled"), "title redacted");
        assert!(!debug.contains("example.test"), "URL redacted");
    }

    #[tokio::test]
    async fn denied_capture_reports_permission() {
        let script = Script::new();
        script.with(|s| s.permission = PermissionState::Denied);
        let w = PlatformWorker::spawn(script.platform(), None).unwrap();
        let out = w.capture().unwrap().await.unwrap();
        assert!(out.result.unwrap_err().is_permission_denied());
        assert_eq!(out.permission, PermissionState::Denied);
        assert_eq!(out.accessibility, None);
    }

    #[tokio::test]
    async fn zero_displays_is_an_error() {
        let script = Script::new();
        script.with(|s| s.displays = 0);
        let w = PlatformWorker::spawn(script.platform(), None).unwrap();
        let out = w.capture().unwrap().await.unwrap();
        assert_eq!(out.result.unwrap_err(), CaptureError::NoDisplays);
    }
}
