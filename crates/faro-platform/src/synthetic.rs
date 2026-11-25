//! Deterministic, OS-free implementations for tests and the headless E2E
//! client ("synthetic-capture mode", ARCHITECTURE.md §10).
//!
//! A [`Script`] is shared between the pieces so a test can change what the
//! "screen" shows, which app is frontmost, lock state, and inject tamper
//! signals, all from one handle.

use crate::{
    AgentPlatform, AppInfo, BrowserContext, ForegroundInfo, Frame, PermissionState, PixelFormat,
    PlatformError, Result, ScreenCapture, SessionChange, SessionState, TamperSignal, TamperSignals,
};
use std::sync::{Arc, Mutex};

/// What the synthetic screen currently shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scene {
    /// A flat colour.
    Solid([u8; 4]),
    /// A deterministic pattern seeded by the value; different seeds give
    /// different perceptual hashes.
    Pattern(u32),
}

#[derive(Debug)]
pub struct ScriptState {
    pub scene: Scene,
    pub width: u32,
    pub height: u32,
    pub displays: u32,
    pub permission: PermissionState,
    pub fail_capture: bool,
    pub app: Option<AppInfo>,
    pub title: Option<String>,
    /// What [`ForegroundInfo::browser`] returns. `None` by default.
    pub browser: Option<BrowserContext>,
    pub idle_secs: u64,
    pub locked: bool,
    pub display_asleep: bool,
    pub changes: Vec<SessionChange>,
    pub tamper: Vec<TamperSignal>,
}

impl Default for ScriptState {
    fn default() -> Self {
        ScriptState {
            scene: Scene::Solid([240, 240, 240, 255]),
            width: 1280,
            height: 800,
            displays: 1,
            permission: PermissionState::Granted,
            fail_capture: false,
            app: Some(AppInfo {
                id: "com.example.editor".into(),
                name: Some("Editor".into()),
            }),
            title: Some("Untitled".into()),
            browser: None,
            idle_secs: 0,
            locked: false,
            display_asleep: false,
            changes: Vec::new(),
            tamper: Vec::new(),
        }
    }
}

/// Shared, mutable script driving all synthetic components.
#[derive(Debug, Clone, Default)]
pub struct Script(pub Arc<Mutex<ScriptState>>);

impl Script {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut ScriptState) -> R) -> R {
        f(&mut self.0.lock().expect("synthetic script poisoned"))
    }

    /// Build a full [`AgentPlatform`] backed by this script.
    pub fn platform(&self) -> AgentPlatform {
        AgentPlatform {
            capture: Box::new(SyntheticCapture(self.clone())),
            foreground: Box::new(SyntheticForeground(self.clone())),
            session: Box::new(SyntheticSession(self.clone())),
            tamper: Box::new(SyntheticTamper(self.clone())),
        }
    }
}

fn render(scene: Scene, w: u32, h: u32, display: u32) -> Vec<u8> {
    let mut px = Vec::with_capacity(w as usize * h as usize * 4);
    match scene {
        Scene::Solid(c) => {
            for _ in 0..w * h {
                px.extend_from_slice(&c);
            }
        }
        Scene::Pattern(seed) => {
            for y in 0..h {
                for x in 0..w {
                    // Cheap integer hash → blocky pattern with structure at dHash scale.
                    let bx = x * 9 / w.max(1);
                    let by = y * 8 / h.max(1);
                    let mut v = seed
                        ^ (bx.wrapping_mul(0x9E37_79B9))
                        ^ (by.wrapping_mul(0x85EB_CA6B))
                        ^ display;
                    v ^= v >> 13;
                    v = v.wrapping_mul(0xC2B2_AE35);
                    v ^= v >> 16;
                    let g = (v & 0xFF) as u8;
                    px.extend_from_slice(&[g, g.wrapping_add(40), g.wrapping_add(80), 255]);
                }
            }
        }
    }
    px
}

pub struct SyntheticCapture(pub Script);

impl ScreenCapture for SyntheticCapture {
    fn capture_all_displays(&mut self) -> Result<Vec<Frame>> {
        let (scene, w, h, n, perm, fail) = self.0.with(|s| {
            (
                s.scene,
                s.width,
                s.height,
                s.displays,
                s.permission,
                s.fail_capture,
            )
        });
        if perm == PermissionState::Denied {
            return Err(PlatformError::PermissionDenied("synthetic".into()));
        }
        if fail {
            return Err(PlatformError::Os("synthetic capture failure".into()));
        }
        (0..n)
            .map(|d| {
                Frame::new(w, h, PixelFormat::Rgba8, d, render(scene, w, h, d))
                    .map(|f| f.downscale_to_max(crate::MAX_FRAME_SIDE))
                    .map_err(|e| PlatformError::Os(e.to_string()))
            })
            .collect()
    }

    fn permission_state(&self) -> PermissionState {
        self.0.with(|s| s.permission)
    }
}

pub struct SyntheticForeground(pub Script);

impl ForegroundInfo for SyntheticForeground {
    fn active_app(&self) -> Option<AppInfo> {
        self.0.with(|s| s.app.clone())
    }

    fn window_title(&self) -> Option<String> {
        self.0.with(|s| s.title.clone())
    }

    fn browser(&self) -> Option<BrowserContext> {
        self.0.with(|s| s.browser.clone())
    }
}

pub struct SyntheticSession(pub Script);

impl SessionState for SyntheticSession {
    fn idle_secs(&self) -> u64 {
        self.0.with(|s| s.idle_secs)
    }

    fn is_locked(&self) -> bool {
        self.0.with(|s| s.locked)
    }

    fn display_asleep(&self) -> bool {
        self.0.with(|s| s.display_asleep)
    }

    fn poll_changes(&mut self) -> Vec<SessionChange> {
        self.0.with(|s| std::mem::take(&mut s.changes))
    }
}

pub struct SyntheticTamper(pub Script);

impl TamperSignals for SyntheticTamper {
    fn poll(&mut self) -> Vec<TamperSignal> {
        self.0.with(|s| std::mem::take(&mut s.tamper))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_drives_capture() {
        let script = Script::new();
        let mut p = script.platform();
        let frames = p.capture.capture_all_displays().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].width(), 768);
        script.with(|s| s.permission = PermissionState::Denied);
        assert!(matches!(
            p.capture.capture_all_displays(),
            Err(PlatformError::PermissionDenied(_))
        ));
        assert_eq!(p.capture.permission_state(), PermissionState::Denied);
    }

    #[test]
    fn patterns_differ() {
        let a = render(Scene::Pattern(1), 64, 64, 0);
        let b = render(Scene::Pattern(2), 64, 64, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn tamper_and_changes_drain() {
        let script = Script::new();
        let mut p = script.platform();
        script.with(|s| {
            s.tamper.push(TamperSignal::VpnActive);
            s.changes.push(SessionChange::Locked);
        });
        assert_eq!(p.tamper.poll(), vec![TamperSignal::VpnActive]);
        assert!(p.tamper.poll().is_empty());
        assert_eq!(p.session.poll_changes(), vec![SessionChange::Locked]);
    }
}
