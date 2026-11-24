//! Plaintext event bodies. These are JSON-serialized and then encrypted; the
//! instance never sees them. Only the member's devices, the member and their
//! allies can read them.
//!
//! **Invariant (§3.5):** the only image type that can appear here is
//! [`BlurredThumbnail`]. There is deliberately no field, variant or setting
//! that can carry an unblurred frame.

use crate::encoding::b64;
use serde::{Deserialize, Serialize};

/// Outcome of the fusion/policy engine for one capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rating {
    Clean,
    Low,
    Medium,
    High,
}

/// Where a reason came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonSource {
    Image,
    Domain,
    Title,
    App,
    Ocr,
    Context,
}

/// One explainable reason, e.g. `image:explicit 0.93` or `domain:adult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub source: ReasonSource,
    pub label: String,
    /// Classifier score in `[0, 1]`, if the reason has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let src = serde_json::to_value(self.source)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        match self.score {
            Some(s) => write!(f, "{src}:{} {s:.2}", self.label),
            None => write!(f, "{src}:{}", self.label),
        }
    }
}

/// A heavily blurred and pixelated PNG thumbnail (~320 px wide, σ≈12 blur).
///
/// Can only be constructed by `faro-detect`'s thumbnail builder in practice;
/// this type carries already-blurred bytes and a marker of the transform used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlurredThumbnail {
    pub width: u32,
    pub height: u32,
    /// Describes the irreversible transform, e.g. `"gauss12+pix8"`.
    pub transform: String,
    #[serde(with = "b64")]
    pub png: Vec<u8>,
}

/// Foreground application info.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AppInfo {
    /// Bundle id / executable name, e.g. `com.google.Chrome` or `chrome.exe`.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Browser context reported by the extension or OS accessibility fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BrowserContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub incognito: bool,
}

/// Body of a `flag` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlagBody {
    pub rating: Rating,
    pub reasons: Vec<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<BlurredThumbnail>,
    /// True if this capture was taken during burst mode.
    #[serde(default)]
    pub burst: bool,
}

/// Tamper signals (§3.7). Context-only signals are listed here too; their
/// urgency is decided by the policy engine, not by the variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum TamperSignal {
    PermissionRevoked {
        permission: String,
    },
    AgentKilledRepeatedly {
        count: u32,
        window_secs: u64,
    },
    IntegrityFailure {
        component: String,
    },
    ClockManipulation {
        wall_delta_ms: i64,
        mono_delta_ms: i64,
    },
    WaylandTokenLost,
    CaptureFailing {
        consecutive_failures: u32,
    },
    // Context-only (urgency `none` by default):
    BrowserWithoutExtension {
        browser: String,
    },
    VpnActive,
    VirtualMachine,
    RemoteDesktop,
    UnmonitoredUserSession {
        user: String,
    },
}

impl TamperSignal {
    /// Whether this is a context signal (reported in the daily report) rather
    /// than an active tamper attempt.
    pub fn is_context_only(&self) -> bool {
        matches!(
            self,
            TamperSignal::BrowserWithoutExtension { .. }
                | TamperSignal::VpnActive
                | TamperSignal::VirtualMachine
                | TamperSignal::RemoteDesktop
                | TamperSignal::UnmonitoredUserSession { .. }
        )
    }
}

/// A single setting change that allies are told about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingChange {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<String>,
}

/// Why a device said goodbye.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoodbyeReason {
    Uninstalled,
    MovedInstance { new_instance_host: String },
    AccountDeleted,
}

/// The decrypted body of any event. `kind` in the header must match the variant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventBody {
    Capture {
        rating: crate::body::Rating,
        count: u32,
    },
    Flag(FlagBody),
    Tamper {
        signal: TamperSignal,
    },
    SettingsChange {
        changes: Vec<SettingChange>,
    },
    AgentRestarted {
        count_last_hour: u32,
    },
    Paused {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        until_ms: Option<i64>,
    },
    Resumed,
    Goodbye {
        reason: GoodbyeReason,
    },
    Boot {
        os: String,
        client_version: String,
    },
    Shutdown,
}

impl EventBody {
    pub fn kind(&self) -> crate::event::EventKind {
        use crate::event::EventKind as K;
        match self {
            EventBody::Capture { .. } => K::Capture,
            EventBody::Flag(_) => K::Flag,
            EventBody::Tamper { .. } => K::Tamper,
            EventBody::SettingsChange { .. } => K::SettingsChange,
            EventBody::AgentRestarted { .. } => K::AgentRestarted,
            EventBody::Paused { .. } => K::Paused,
            EventBody::Resumed => K::Resumed,
            EventBody::Goodbye { .. } => K::Goodbye,
            EventBody::Boot { .. } => K::Boot,
            EventBody::Shutdown => K::Shutdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_display() {
        let r = Reason {
            source: ReasonSource::Image,
            label: "explicit".into(),
            score: Some(0.934),
        };
        assert_eq!(r.to_string(), "image:explicit 0.93");
        let r = Reason {
            source: ReasonSource::Domain,
            label: "adult".into(),
            score: None,
        };
        assert_eq!(r.to_string(), "domain:adult");
    }

    #[test]
    fn body_json_tagged() {
        let b = EventBody::Tamper {
            signal: TamperSignal::PermissionRevoked {
                permission: "screen_recording".into(),
            },
        };
        let j = serde_json::to_value(&b).unwrap();
        assert_eq!(j["type"], "tamper");
        assert_eq!(j["signal"]["signal"], "permission_revoked");
        let back: EventBody = serde_json::from_value(j).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.kind(), crate::event::EventKind::Tamper);
    }

    #[test]
    fn rating_order() {
        assert!(
            Rating::High > Rating::Medium
                && Rating::Medium > Rating::Low
                && Rating::Low > Rating::Clean
        );
    }
}
