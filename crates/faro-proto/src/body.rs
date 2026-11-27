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
    /// A burst of blocked DNS lookups on an iPhone (`dns:adult ×6, 4 hosts,
    /// 3 min, screen on`). The label carries the whole explanation.
    Dns,
}

/// One explainable reason, e.g. `image:explicit 0.93` or `domain:adult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    pub source: ReasonSource,
    pub label: String,
    /// Classifier score in `[0, 1]`, if the reason has one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "finite_score"
    )]
    pub score: Option<f32>,
}

/// A score must be a finite `f32`. JSON numbers beyond its range (`1e39`)
/// would otherwise decode as infinity, which encodes as `null`: the score
/// would silently vanish the next time the body is written.
fn finite_score<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<f32>, D::Error> {
    match Option::<f32>::deserialize(d)? {
        Some(s) if !s.is_finite() => Err(serde::de::Error::custom(
            "reason score is not a finite 32-bit number",
        )),
        s => Ok(s),
    }
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
    /// The OS account whose session was captured (§3.6), as a short local
    /// label (see [`account_label`]). Only inside the encrypted body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// Longest OS-account label carried in an event body or report.
pub const MAX_ACCOUNT_LABEL: usize = 64;

/// The short local label for an OS account (ARCHITECTURE.md §3.6): the
/// account's short name with control characters removed, trimmed and cut
/// to [`MAX_ACCOUNT_LABEL`] characters. It travels only inside encrypted
/// bodies, so the instance never sees it.
pub fn account_label(name: &str) -> String {
    let cut: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_ACCOUNT_LABEL)
        .collect();
    // The cut can land just after a space, so trim again.
    cut.trim_end().to_owned()
}

/// Tamper signals (§3.7). Context-only signals are listed here too
/// ([`TamperSignal::is_context_only`]); they go to the daily report instead
/// of becoming `tamper` events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum TamperSignal {
    /// A permission Faro needs is off. `never_granted` means the service
    /// never saw it granted to this account on this enrollment (a new
    /// install, or a reinstall that dropped the grant) rather than saw it
    /// turned off (§3.7). Bodies without the field read as `false`.
    PermissionRevoked {
        permission: String,
        #[serde(default, skip_serializing_if = "is_false")]
        never_granted: bool,
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
    /// An interactive session of the OS account `user` has had no connected
    /// agent for 90 s (§3.1, §3.7). Every account on the computer is
    /// monitored, so this is active tamper, not context: switching to or
    /// creating another account must not be a way around Faro.
    UnmonitoredUserSession {
        user: String,
    },
    /// A large on-screen window of the app named `app` is excluded from
    /// screen capture (on macOS, `NSWindow.sharingType = .none`), so
    /// captures show what is behind it instead (§3.7). `app` is the app's
    /// display name, or its bundle id when it has none; never a window
    /// title.
    WindowHiddenFromCapture {
        app: String,
    },
    /// iPhone: Screen Time authorization is no longer approved, so the
    /// shields and `denyAppRemoval` are gone and Faro can be deleted
    /// (docs/IOS.md §10.2).
    ScreenTimeRevoked,
    /// iPhone: the DNS filter is off. `cause` says how, as far as the phone
    /// could tell.
    FilterOff {
        cause: FilterOffCause,
    },
    /// iPhone: Faro's ManagedSettings store was found cleared or changed
    /// while authorization still stands.
    SettingsCleared,
    // Context-only (reported in the daily report, never paged):
    BrowserWithoutExtension {
        browser: String,
    },
    VpnActive,
    VirtualMachine,
    RemoteDesktop,
    /// iPhone: connections to DNS-over-HTTPS resolvers were dropped.
    DohDropped,
    /// iPhone: another VPN is connected.
    OtherVpn,
    /// iPhone: the phone looks jailbroken.
    JailbreakSuspected,
}

/// Why an iPhone's DNS filter is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOffCause {
    /// The VPN was switched off.
    VpnDisconnected,
    /// Connect On Demand was turned off.
    OnDemandOff,
    /// Another VPN took over.
    OtherVpn,
    /// The Faro VPN profile was deleted.
    ProfileRemoved,
    /// The tunnel stopped reporting and nothing says why.
    Unknown,
}

/// One host in a [`EventBody::BlockedSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedHost {
    /// The host only, never a path or query.
    pub host: String,
    pub category: String,
    pub count: u32,
}

fn is_false(b: &bool) -> bool {
    !*b
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
                | TamperSignal::DohDropped
                | TamperSignal::OtherVpn
                | TamperSignal::JailbreakSuspected
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
        /// The OS account the signal came from, when it concerns one
        /// session rather than the whole computer (§3.6). See
        /// [`account_label`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    SettingsChange {
        changes: Vec<SettingChange>,
        /// Pending loosening (docs/IOS.md §9), all in ms since the epoch.
        /// When the member asked for the loosening.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested_at: Option<i64>,
        /// When it will apply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        takes_effect_at: Option<i64>,
        /// When the member cancelled it, if they did.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cancelled_at: Option<i64>,
        /// The delay that was in force, in seconds.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        delay_secs: Option<u64>,
    },
    /// iPhone: blocked DNS lookups in one bucket (docs/IOS.md §11). A
    /// `capture`-class event, so its header urgency is `none`.
    BlockedSummary {
        /// Start of the bucket, ms since the epoch.
        bucket_start: i64,
        bucket_secs: u64,
        /// Blocked lookups per category.
        by_category: std::collections::BTreeMap<String, u32>,
        /// The hosts listed (adult and gambling only).
        hosts: Vec<BlockedHost>,
        /// Blocked lookups of hosts not listed above.
        other_hosts: u32,
    },
    /// iPhone: how often a Screen Time shield was shown or closed in one
    /// bucket. Counts only, never app names. A `capture`-class event.
    ShieldSummary {
        /// Start of the bucket, ms since the epoch.
        bucket_start: i64,
        bucket_secs: u64,
        shown: u32,
        closed: u32,
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
    /// A `tamper` body that concerns the whole computer.
    pub fn tamper(signal: TamperSignal) -> Self {
        EventBody::Tamper {
            signal,
            account: None,
        }
    }

    /// A `settings_change` body with no pending-loosening fields.
    pub fn settings_change(changes: Vec<SettingChange>) -> Self {
        EventBody::SettingsChange {
            changes,
            requested_at: None,
            takes_effect_at: None,
            cancelled_at: None,
            delay_secs: None,
        }
    }

    pub fn kind(&self) -> crate::event::EventKind {
        use crate::event::EventKind as K;
        match self {
            EventBody::Capture { .. }
            | EventBody::BlockedSummary { .. }
            | EventBody::ShieldSummary { .. } => K::Capture,
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
                never_granted: false,
            },
            account: Some("alex".into()),
        };
        let j = serde_json::to_value(&b).unwrap();
        assert_eq!(j["type"], "tamper");
        assert_eq!(j["signal"]["signal"], "permission_revoked");
        assert_eq!(j["account"], "alex");
        let back: EventBody = serde_json::from_value(j).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.kind(), crate::event::EventKind::Tamper);
    }

    #[test]
    fn account_is_optional_on_the_wire() {
        // Bodies written before the field existed still parse, and a body
        // without an account does not carry the key.
        let old = r#"{"type":"tamper","signal":{"signal":"vpn_active"}}"#;
        let b: EventBody = serde_json::from_str(old).unwrap();
        assert_eq!(b, EventBody::tamper(TamperSignal::VpnActive));
        assert!(!serde_json::to_string(&b).unwrap().contains("account"));
    }

    #[test]
    fn never_granted_is_optional_on_the_wire() {
        // Bodies written before the field existed read as "turned off", and
        // a signal without it encodes exactly as before, so older readers
        // see the same JSON.
        let old = r#"{"signal":"permission_revoked","permission":"screen_recording"}"#;
        let s: TamperSignal = serde_json::from_str(old).unwrap();
        assert_eq!(
            s,
            TamperSignal::PermissionRevoked {
                permission: "screen_recording".into(),
                never_granted: false,
            }
        );
        assert_eq!(serde_json::to_string(&s).unwrap(), old);
        let missing = TamperSignal::PermissionRevoked {
            permission: "screen_recording".into(),
            never_granted: true,
        };
        let j = serde_json::to_value(&missing).unwrap();
        assert_eq!(j["signal"], "permission_revoked");
        assert_eq!(j["never_granted"], true);
        assert_eq!(serde_json::from_value::<TamperSignal>(j).unwrap(), missing);
        assert!(!missing.is_context_only());
    }

    #[test]
    fn unmonitored_session_is_active_tamper() {
        let s = TamperSignal::UnmonitoredUserSession {
            user: "guest".into(),
        };
        assert!(!s.is_context_only());
        assert!(TamperSignal::VpnActive.is_context_only());
    }

    #[test]
    fn hidden_window_is_active_tamper() {
        let s = TamperSignal::WindowHiddenFromCapture {
            app: "Viewer".into(),
        };
        assert!(!s.is_context_only());
        let j = serde_json::to_value(EventBody::tamper(s.clone())).unwrap();
        assert_eq!(j["signal"]["signal"], "window_hidden_from_capture");
        assert_eq!(j["signal"]["app"], "Viewer");
    }

    #[test]
    fn account_labels_are_short_and_clean() {
        assert_eq!(account_label("  alex \n"), "alex");
        assert_eq!(account_label("a\u{7}b"), "ab");
        assert_eq!(
            account_label(&"x".repeat(200)).chars().count(),
            MAX_ACCOUNT_LABEL
        );
    }

    #[test]
    fn reason_scores_must_be_finite() {
        // Found by the `report` fuzz target: 1E93 decoded as infinity and
        // re-encoded as `null`, dropping the score.
        let r = |score: &str| {
            serde_json::from_str::<Reason>(&format!(
                r#"{{"source":"image","label":"x","score":{score}}}"#
            ))
        };
        assert!(r("1E93").is_err());
        assert!(r("-1e39").is_err());
        assert_eq!(r("0.93").unwrap().score, Some(0.93));
        assert_eq!(r("null").unwrap().score, None);
        let missing: Reason = serde_json::from_str(r#"{"source":"app","label":"x"}"#).unwrap();
        assert_eq!(missing.score, None);
    }

    #[test]
    fn account_label_cut_never_leaves_trailing_space() {
        // Found by the `encoding` fuzz target: a space at the cut point
        // survived the trim, which ran before the cut.
        let name = format!("{}{}", "a".repeat(MAX_ACCOUNT_LABEL - 1), " b");
        let label = account_label(&name);
        assert_eq!(label, "a".repeat(MAX_ACCOUNT_LABEL - 1));
        assert_eq!(label.trim(), label);
    }

    #[test]
    fn rating_order() {
        assert!(
            Rating::High > Rating::Medium
                && Rating::Medium > Rating::Low
                && Rating::Low > Rating::Clean
        );
    }

    fn ios_signals() -> Vec<TamperSignal> {
        let mut v = vec![
            TamperSignal::ScreenTimeRevoked,
            TamperSignal::SettingsCleared,
        ];
        for cause in [
            FilterOffCause::VpnDisconnected,
            FilterOffCause::OnDemandOff,
            FilterOffCause::OtherVpn,
            FilterOffCause::ProfileRemoved,
            FilterOffCause::Unknown,
        ] {
            v.push(TamperSignal::FilterOff { cause });
        }
        v
    }

    #[test]
    fn ios_tamper_signals_round_trip_and_are_floored_urgent() {
        for signal in ios_signals() {
            assert!(!signal.is_context_only(), "{signal:?}");
            let b = EventBody::tamper(signal);
            let back: EventBody =
                serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
            assert_eq!(back, b);
            assert_eq!(b.kind(), crate::event::EventKind::Tamper);
            assert_eq!(
                b.kind().min_urgency(),
                crate::event::Urgency::Urgent,
                "{b:?}"
            );
        }
        let j = serde_json::to_value(TamperSignal::FilterOff {
            cause: FilterOffCause::ProfileRemoved,
        })
        .unwrap();
        assert_eq!(
            j,
            serde_json::json!({"signal": "filter_off", "cause": "profile_removed"})
        );
        let j = serde_json::to_value(TamperSignal::ScreenTimeRevoked).unwrap();
        assert_eq!(j, serde_json::json!({"signal": "screen_time_revoked"}));
        let j = serde_json::to_value(TamperSignal::SettingsCleared).unwrap();
        assert_eq!(j, serde_json::json!({"signal": "settings_cleared"}));
    }

    #[test]
    fn ios_context_signals_are_context_only() {
        for (s, name) in [
            (TamperSignal::DohDropped, "doh_dropped"),
            (TamperSignal::OtherVpn, "other_vpn"),
            (TamperSignal::JailbreakSuspected, "jailbreak_suspected"),
        ] {
            assert!(s.is_context_only());
            assert_eq!(
                serde_json::to_value(&s).unwrap(),
                serde_json::json!({ "signal": name })
            );
        }
    }

    #[test]
    fn summaries_round_trip_and_are_capture_class() {
        let b = EventBody::BlockedSummary {
            bucket_start: 1_700_000_000_000,
            bucket_secs: 300,
            by_category: [("adult".to_owned(), 6), ("gambling".to_owned(), 1)].into(),
            hosts: vec![BlockedHost {
                host: "example.test".into(),
                category: "adult".into(),
                count: 6,
            }],
            other_hosts: 1,
        };
        let s = EventBody::ShieldSummary {
            bucket_start: 1_700_000_000_000,
            bucket_secs: 300,
            shown: 4,
            closed: 3,
        };
        for body in [b, s] {
            let back: EventBody =
                serde_json::from_str(&serde_json::to_string(&body).unwrap()).unwrap();
            assert_eq!(back, body);
            assert_eq!(body.kind(), crate::event::EventKind::Capture);
            assert_eq!(body.kind().min_urgency(), crate::event::Urgency::None);
        }
        let j = serde_json::to_value(EventBody::ShieldSummary {
            bucket_start: 0,
            bucket_secs: 60,
            shown: 1,
            closed: 0,
        })
        .unwrap();
        assert_eq!(j["type"], "shield_summary");
    }

    #[test]
    fn dns_reason_round_trips() {
        let r = Reason {
            source: ReasonSource::Dns,
            label: "adult ×6, 4 hosts, 3 min, screen on".into(),
            score: None,
        };
        assert_eq!(r.to_string(), "dns:adult ×6, 4 hosts, 3 min, screen on");
        let back: Reason = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert_eq!(serde_json::to_value(&r).unwrap()["source"], "dns");
    }

    #[test]
    fn settings_change_gains_pending_fields_and_reads_old_json() {
        let old = r#"{"type":"settings_change","changes":[{"key":"k","old":"1","new":"2"}]}"#;
        let b: EventBody = serde_json::from_str(old).unwrap();
        assert_eq!(
            b,
            EventBody::settings_change(vec![SettingChange {
                key: "k".into(),
                old: Some("1".into()),
                new: Some("2".into()),
            }])
        );
        // Unset fields stay out of the JSON, so old readers see old bodies.
        assert_eq!(
            serde_json::to_value(&b).unwrap(),
            serde_json::from_str::<serde_json::Value>(old).unwrap()
        );
        let pending = EventBody::SettingsChange {
            changes: vec![],
            requested_at: Some(10),
            takes_effect_at: Some(20),
            cancelled_at: Some(15),
            delay_secs: Some(86_400),
        };
        let back: EventBody =
            serde_json::from_str(&serde_json::to_string(&pending).unwrap()).unwrap();
        assert_eq!(back, pending);
    }
}
