//! An [`AgentPlatform`] driven inside the service process.
//!
//! Used with `faro_platform::synthetic::Script` by tests and the headless E2E
//! client, and (development only) with the real macOS platform when the
//! service runs as the logged-in user. Production never uses it: a root
//! service cannot capture the user's graphical session (§3.1).
//!
//! The platform calls are synchronous (and on macOS may block on
//! ScreenCaptureKit for up to its timeout), so they run on Tokio's blocking
//! pool, one at a time.

use super::{BoxFuture, FrameSource, SourceCommand, SourceEvent, SourceIo};
use faro_platform::{AgentPlatform, AppInfo, PermissionState, PlatformError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// See the module docs.
pub struct InProcessFrameSource {
    platform: Arc<Mutex<AgentPlatform>>,
    poll_every: Duration,
    label: String,
}

impl InProcessFrameSource {
    /// Poll foreground, session, permission and tamper state every
    /// `poll_every` (the agent does the same on its own loop).
    pub fn new(platform: AgentPlatform, poll_every: Duration) -> Self {
        InProcessFrameSource {
            platform: Arc::new(Mutex::new(platform)),
            poll_every: poll_every.max(Duration::from_millis(1)),
            label: "in-process".into(),
        }
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
    session: Option<(u64, bool, bool)>,
    permission: Option<PermissionState>,
}

/// What one poll observed.
struct Observed {
    foreground: (Option<AppInfo>, Option<String>),
    session: (u64, bool, bool),
    permission: PermissionState,
    changes: Vec<faro_platform::SessionChange>,
    tamper: Vec<faro_proto::body::TamperSignal>,
}

fn observe(p: &mut AgentPlatform) -> Observed {
    Observed {
        foreground: (p.foreground.active_app(), p.foreground.window_title()),
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

    fn run(self: Box<Self>, io: SourceIo) -> BoxFuture {
        Box::pin(async move {
            let SourceIo {
                mut commands,
                events,
            } = io;
            let platform = self.platform;
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
                        Some(SourceCommand::ShowNotice { title, .. }) => {
                            tracing::info!(%title, "notice (in-process source has no UI)");
                        }
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
    if seen.foreground.as_ref() != Some(&obs.foreground) {
        out.push(SourceEvent::Foreground {
            app: obs.foreground.0.clone(),
            title: obs.foreground.1.clone(),
        });
        seen.foreground = Some(obs.foreground);
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
        let task = tokio::spawn(src.run(SourceIo {
            commands: cmd_rx,
            events: ev_tx,
        }));
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
}
