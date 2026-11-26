//! Urgency policy (ARCHITECTURE.md §5.4) and tamper-signal routing (§3.7).
//!
//! Urgency is the one piece of event metadata the instance can act on: it
//! decides whether allies are emailed immediately, in the hourly digest, or
//! only see the event in the daily report. Two rules keep it trustworthy:
//!
//! 1. Every event's urgency is raised to at least
//!    [`EventKind::min_urgency`](faro_proto::EventKind::min_urgency). The
//!    instance enforces the same floor, so a modified client gains nothing by
//!    signing a tamper event as `none`; we apply it here so the device and
//!    instance agree and the signed header is already correct.
//! 2. The member may set each rating's urgency anywhere from its **floor** up
//!    to `urgent`, never below the floor. A policy that silenced high-rated
//!    flags would let a member quietly disable the alerts their allies rely
//!    on.
//!
//! The default mapping is not the floor everywhere: `medium` flags are
//! `urgent` by default ([`UrgencyPolicy::MEDIUM_DEFAULT`], ARCHITECTURE.md
//! §14) but may be lowered to `normal` ([`UrgencyPolicy::MEDIUM_FLOOR`]).
//! Every change to the mapping, in either direction, is announced to allies
//! as a `settings_change` event ([`UrgencyPolicy::diff`]).
//!
//! A policy stored before `medium` defaulted to `urgent` keeps its value:
//! deserializing never fills in the defaults, so such a device stays at
//! `normal` until the member changes it. Only new devices start at the new
//! default (`faro_service::state::settings_in_effect`).

use faro_proto::body::{EventBody, Rating, SettingChange, TamperSignal};
use faro_proto::Urgency;
use serde::{Deserialize, Serialize};

/// How flag ratings map to urgency. Member-configurable within floors.
///
/// | Rating | Default | Floor |
/// |---|---|---|
/// | `low` | `none` | `none` |
/// | `medium` | `urgent` | `normal` |
/// | `high` | `urgent` | `urgent` |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPolicy", into = "RawPolicy")]
pub struct UrgencyPolicy {
    low: Urgency,
    medium: Urgency,
    high: Urgency,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct RawPolicy {
    low: Urgency,
    medium: Urgency,
    high: Urgency,
}

impl From<UrgencyPolicy> for RawPolicy {
    fn from(p: UrgencyPolicy) -> Self {
        RawPolicy {
            low: p.low,
            medium: p.medium,
            high: p.high,
        }
    }
}

impl TryFrom<RawPolicy> for UrgencyPolicy {
    type Error = PolicyError;
    fn try_from(r: RawPolicy) -> Result<Self, Self::Error> {
        UrgencyPolicy::new(r.low, r.medium, r.high)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("{rating} flags cannot be less urgent than {floor}")]
    BelowFloor {
        rating: &'static str,
        floor: Urgency,
    },
    #[error("a lower rating cannot be more urgent than a higher one")]
    NotMonotone,
}

impl Default for UrgencyPolicy {
    fn default() -> Self {
        UrgencyPolicy {
            low: Self::LOW_FLOOR,
            medium: Self::MEDIUM_DEFAULT,
            high: Self::HIGH_FLOOR,
        }
    }
}

impl UrgencyPolicy {
    /// The lowest urgency each rating may be given. `low` and `high` default
    /// to their floors; `medium` defaults to [`Self::MEDIUM_DEFAULT`].
    pub const LOW_FLOOR: Urgency = Urgency::None;
    pub const MEDIUM_FLOOR: Urgency = Urgency::Normal;
    pub const HIGH_FLOOR: Urgency = Urgency::Urgent;

    /// The urgency of `medium` flags on a new device. Deliberately above
    /// [`Self::MEDIUM_FLOOR`]: the member may lower it to `normal`, and
    /// allies are told when they do.
    pub const MEDIUM_DEFAULT: Urgency = Urgency::Urgent;

    /// Build a policy. Each level must be at least its floor (which is not
    /// always its default) and the mapping must be monotone
    /// (`low <= medium <= high`).
    pub fn new(low: Urgency, medium: Urgency, high: Urgency) -> Result<Self, PolicyError> {
        for (rating, value, floor) in [
            ("low", low, Self::LOW_FLOOR),
            ("medium", medium, Self::MEDIUM_FLOOR),
            ("high", high, Self::HIGH_FLOOR),
        ] {
            if value < floor {
                return Err(PolicyError::BelowFloor { rating, floor });
            }
        }
        if low > medium || medium > high {
            return Err(PolicyError::NotMonotone);
        }
        Ok(UrgencyPolicy { low, medium, high })
    }

    pub fn low(&self) -> Urgency {
        self.low
    }
    pub fn medium(&self) -> Urgency {
        self.medium
    }
    pub fn high(&self) -> Urgency {
        self.high
    }

    /// Urgency of a flag with this rating (before the kind floor).
    pub fn for_rating(&self, r: Rating) -> Urgency {
        match r {
            Rating::Clean => Urgency::None,
            Rating::Low => self.low,
            Rating::Medium => self.medium,
            Rating::High => self.high,
        }
    }

    /// The urgency the event carrying `body` should have, per §5.4, raised to
    /// the kind's floor.
    ///
    /// | Body | Urgency |
    /// |---|---|
    /// | `flag` | from the rating mapping |
    /// | `tamper`, `goodbye` | urgent |
    /// | `settings_change`, `paused`, `resumed` | normal |
    /// | `capture`, `agent_restarted`, `boot`, `shutdown` | none |
    ///
    /// A single `agent_restarted` is routine (updates, crashes); repeated
    /// kills are escalated separately as the `agent_killed_repeatedly` tamper
    /// signal.
    pub fn urgency_for(&self, body: &EventBody) -> Urgency {
        let base = match body {
            EventBody::Flag(f) => self.for_rating(f.rating),
            EventBody::Tamper { .. } | EventBody::Goodbye { .. } => Urgency::Urgent,
            EventBody::SettingsChange { .. } | EventBody::Paused { .. } | EventBody::Resumed => {
                Urgency::Normal
            }
            EventBody::Capture { .. }
            | EventBody::AgentRestarted { .. }
            | EventBody::Boot { .. }
            | EventBody::Shutdown => Urgency::None,
        };
        base.max(body.kind().min_urgency())
    }

    /// Setting changes between two policies, for a `settings_change` event.
    pub fn diff(&self, new: &UrgencyPolicy) -> Vec<SettingChange> {
        [
            ("urgency.low", self.low, new.low),
            ("urgency.medium", self.medium, new.medium),
            ("urgency.high", self.high, new.high),
        ]
        .into_iter()
        .filter(|(_, a, b)| a != b)
        .map(|(key, a, b)| SettingChange {
            key: key.into(),
            old: Some(a.as_str().into()),
            new: Some(b.as_str().into()),
        })
        .collect()
    }
}

/// Where a tamper signal goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalRoute {
    /// Emit a `tamper` event (always urgent).
    TamperEvent,
    /// Only list it in the daily report's `HealthSummary::context`.
    ReportContext,
}

/// Route a signal: context-only signals (browser without the extension, VPN,
/// VM, RDP) are informational and must not page allies, so
/// they never become `tamper` events, whose urgency is floored to urgent.
pub fn route_signal(signal: &TamperSignal) -> SignalRoute {
    if signal.is_context_only() {
        SignalRoute::ReportContext
    } else {
        SignalRoute::TamperEvent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::body::{FlagBody, GoodbyeReason};
    use faro_proto::EventKind;

    fn flag(r: Rating) -> EventBody {
        EventBody::Flag(FlagBody {
            rating: r,
            reasons: vec![],
            app: None,
            window_title: None,
            browser: None,
            thumbnail: None,
            burst: false,
            account: None,
        })
    }

    fn all_bodies() -> Vec<EventBody> {
        vec![
            EventBody::Capture {
                rating: Rating::Clean,
                count: 3,
            },
            flag(Rating::Clean),
            flag(Rating::Low),
            flag(Rating::Medium),
            flag(Rating::High),
            EventBody::Tamper {
                signal: TamperSignal::VpnActive,
                account: None,
            },
            EventBody::Tamper {
                signal: TamperSignal::WaylandTokenLost,
                account: None,
            },
            EventBody::SettingsChange { changes: vec![] },
            EventBody::AgentRestarted { count_last_hour: 9 },
            EventBody::Paused {
                reason: None,
                until_ms: None,
            },
            EventBody::Resumed,
            EventBody::Goodbye {
                reason: GoodbyeReason::Uninstalled,
            },
            EventBody::Boot {
                os: "macos".into(),
                client_version: "0.1.0".into(),
            },
            EventBody::Shutdown,
        ]
    }

    #[test]
    fn defaults_follow_table() {
        let p = UrgencyPolicy::default();
        assert_eq!(p.urgency_for(&flag(Rating::Clean)), Urgency::None);
        assert_eq!(p.urgency_for(&flag(Rating::Low)), Urgency::None);
        assert_eq!(p.urgency_for(&flag(Rating::Medium)), Urgency::Urgent);
        assert_eq!(p.urgency_for(&flag(Rating::High)), Urgency::Urgent);
        assert_eq!(
            p.urgency_for(&EventBody::SettingsChange { changes: vec![] }),
            Urgency::Normal
        );
        assert_eq!(p.urgency_for(&EventBody::Shutdown), Urgency::None);
    }

    #[test]
    fn medium_default_is_above_its_floor() {
        let p = UrgencyPolicy::default();
        assert_eq!(p.low(), UrgencyPolicy::LOW_FLOOR);
        assert_eq!(p.medium(), UrgencyPolicy::MEDIUM_DEFAULT);
        assert_eq!(p.high(), UrgencyPolicy::HIGH_FLOOR);
        assert!(UrgencyPolicy::MEDIUM_DEFAULT > UrgencyPolicy::MEDIUM_FLOOR);
        // The member may still lower medium flags to the floor...
        let lowered = UrgencyPolicy::new(
            UrgencyPolicy::LOW_FLOOR,
            UrgencyPolicy::MEDIUM_FLOOR,
            UrgencyPolicy::HIGH_FLOOR,
        )
        .unwrap();
        assert_eq!(lowered.urgency_for(&flag(Rating::Medium)), Urgency::Normal);
        // ...allies are told, with a `normal` settings change...
        let changes = p.diff(&lowered);
        assert_eq!(
            changes,
            vec![SettingChange {
                key: "urgency.medium".into(),
                old: Some("urgent".into()),
                new: Some("normal".into())
            }]
        );
        assert_eq!(
            p.urgency_for(&EventBody::SettingsChange { changes }),
            Urgency::Normal
        );
        // ...and it can't go below the floor.
        assert!(matches!(
            UrgencyPolicy::new(Urgency::None, Urgency::None, Urgency::Urgent),
            Err(PolicyError::BelowFloor {
                rating: "medium",
                ..
            })
        ));
    }

    #[test]
    fn stored_policy_keeps_its_medium() {
        // As written by a client from before `medium` defaulted to `urgent`.
        let old = r#"{"low":"none","medium":"normal","high":"urgent"}"#;
        let p: UrgencyPolicy = serde_json::from_str(old).unwrap();
        assert_eq!(p.medium(), Urgency::Normal);
        assert_ne!(p, UrgencyPolicy::default());
    }

    #[test]
    fn every_policy_respects_kind_floor() {
        let levels = [Urgency::None, Urgency::Normal, Urgency::Urgent];
        for low in levels {
            for medium in levels {
                for high in levels {
                    let Ok(p) = UrgencyPolicy::new(low, medium, high) else {
                        continue;
                    };
                    for b in all_bodies() {
                        let u = p.urgency_for(&b);
                        assert!(u >= b.kind().min_urgency(), "{b:?} -> {u}");
                    }
                    // Tamper (even with a context-only signal smuggled in) is urgent.
                    assert_eq!(
                        p.urgency_for(&EventBody::Tamper {
                            signal: TamperSignal::VpnActive,
                            account: None,
                        }),
                        Urgency::Urgent
                    );
                    assert_eq!(EventKind::Tamper.min_urgency(), Urgency::Urgent);
                }
            }
        }
    }

    #[test]
    fn member_can_raise_but_not_lower() {
        let p = UrgencyPolicy::new(Urgency::Normal, Urgency::Urgent, Urgency::Urgent).unwrap();
        assert_eq!(p.urgency_for(&flag(Rating::Medium)), Urgency::Urgent);
        assert_eq!(p.urgency_for(&flag(Rating::Low)), Urgency::Normal);
        assert!(matches!(
            UrgencyPolicy::new(Urgency::None, Urgency::None, Urgency::Urgent),
            Err(PolicyError::BelowFloor {
                rating: "medium",
                ..
            })
        ));
        assert!(matches!(
            UrgencyPolicy::new(Urgency::None, Urgency::Normal, Urgency::Normal),
            Err(PolicyError::BelowFloor { rating: "high", .. })
        ));
        assert_eq!(
            UrgencyPolicy::new(Urgency::Urgent, Urgency::Normal, Urgency::Urgent),
            Err(PolicyError::NotMonotone)
        );
    }

    #[test]
    fn serde_rejects_lowered_policy() {
        let ok = serde_json::to_string(&UrgencyPolicy::default()).unwrap();
        let back: UrgencyPolicy = serde_json::from_str(&ok).unwrap();
        assert_eq!(back, UrgencyPolicy::default());
        let bad = r#"{"low":"none","medium":"none","high":"none"}"#;
        assert!(serde_json::from_str::<UrgencyPolicy>(bad).is_err());
    }

    #[test]
    fn policy_diff() {
        let a = UrgencyPolicy::default();
        let b = UrgencyPolicy::new(Urgency::Normal, Urgency::Normal, Urgency::Urgent).unwrap();
        assert!(a.diff(&a).is_empty());
        assert_eq!(
            a.diff(&b),
            vec![
                SettingChange {
                    key: "urgency.low".into(),
                    old: Some("none".into()),
                    new: Some("normal".into())
                },
                SettingChange {
                    key: "urgency.medium".into(),
                    old: Some("urgent".into()),
                    new: Some("normal".into())
                }
            ]
        );
    }

    #[test]
    fn routing() {
        let context = [
            TamperSignal::BrowserWithoutExtension {
                browser: "firefox".into(),
            },
            TamperSignal::VpnActive,
            TamperSignal::VirtualMachine,
            TamperSignal::RemoteDesktop,
        ];
        for s in &context {
            assert_eq!(route_signal(s), SignalRoute::ReportContext, "{s:?}");
        }
        let tamper = [
            // Every OS account is monitored (§3.1): a session without an
            // agent is tamper, not context.
            TamperSignal::UnmonitoredUserSession {
                user: "guest".into(),
            },
            // A window hidden from capture shows things Faro can't see.
            TamperSignal::WindowHiddenFromCapture {
                app: "Viewer".into(),
            },
            TamperSignal::PermissionRevoked {
                permission: "screen".into(),
                never_granted: false,
            },
            TamperSignal::AgentKilledRepeatedly {
                count: 3,
                window_secs: 600,
            },
            TamperSignal::IntegrityFailure {
                component: "model".into(),
            },
            TamperSignal::ClockManipulation {
                wall_delta_ms: 1,
                mono_delta_ms: 2,
            },
            TamperSignal::WaylandTokenLost,
            TamperSignal::CaptureFailing {
                consecutive_failures: 5,
            },
        ];
        for s in &tamper {
            assert_eq!(route_signal(s), SignalRoute::TamperEvent, "{s:?}");
        }
    }
}
