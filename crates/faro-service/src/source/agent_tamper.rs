//! Which tamper signals the service takes from an agent (§3.1, §3.7).
//!
//! An agent is admitted by its uid and code signature, but what it sends is
//! still only its word: anything that gets that far can send any
//! [`TamperSignal`] on the wire, and each one forwarded becomes an urgent
//! event, an outbox row and ally notifications. So per connection:
//!
//! * **Allowlist.** Only the signals an agent observes in its own session
//!   are taken ([`from_agent`]): a permission revoked (`screen_recording` or
//!   `accessibility`, the macOS agent), a display that keeps failing to
//!   capture (`capture_failing`, the Windows agent's per-display check), a
//!   window hidden from capture, the Wayland portal token lost, and the
//!   context signals. The ones only the service can know are refused:
//!   `agent_killed_repeatedly` (the supervisor), `integrity_failure`,
//!   `clock_manipulation`, and `unmonitored_user_session` (whose free-text
//!   name could blame another account). A refusal is logged at debug, and
//!   the first one on a connection is reported as one
//!   `integrity_failure` ([`REFUSED_COMPONENT`]), since an agent that
//!   sends one is not the agent the service ships, or not behaving as it.
//! * **Fields.** Free text is stripped of control characters and cut to
//!   [`faro_ipc::limits::MAX_TAMPER_TEXT_BYTES`]; `never_granted` is the
//!   service's to decide.
//! * **Rate.** At most [`BURST`] signals, refilled at one per [`REFILL`]. A
//!   real agent reports edges, a handful an hour. Beyond that signals are
//!   dropped, with one warning per connection.
//!
//! The core then dedupes on the variant and account, not the text.

use faro_ipc::limits::tamper_text;
use faro_proto::body::TamperSignal;
use std::time::Duration;
use tokio::time::Instant;

/// Signals one connection may send at once.
pub const BURST: u32 = 10;
/// One more signal is allowed per this much time.
pub const REFILL: Duration = Duration::from_secs(6);
/// The `integrity_failure` component reported for an agent that sent a
/// signal only the service raises.
pub const REFUSED_COMPONENT: &str = "session agent: sent a signal only the service raises";

/// Permission names an agent may report revoked.
const AGENT_PERMISSIONS: &[&str] = &["screen_recording", "accessibility"];

/// `sig` as the service takes it from an agent, or `None` if an agent may
/// not originate it.
pub fn from_agent(sig: TamperSignal) -> Option<TamperSignal> {
    use TamperSignal as T;
    Some(match sig {
        T::PermissionRevoked { permission, .. } => {
            if !AGENT_PERMISSIONS.contains(&permission.as_str()) {
                return None;
            }
            T::PermissionRevoked {
                permission,
                never_granted: false,
            }
        }
        T::WindowHiddenFromCapture { app } => T::WindowHiddenFromCapture {
            app: tamper_text(&app),
        },
        T::BrowserWithoutExtension { browser } => T::BrowserWithoutExtension {
            browser: tamper_text(&browser),
        },
        s @ (T::CaptureFailing { .. }
        | T::WaylandTokenLost
        | T::VpnActive
        | T::VirtualMachine
        | T::RemoteDesktop) => s,
        T::AgentKilledRepeatedly { .. }
        | T::IntegrityFailure { .. }
        | T::ClockManipulation { .. }
        | T::UnmonitoredUserSession { .. }
        // No wire form (phones only); listed so a new variant is a choice.
        | T::ScreenTimeRevoked
        | T::FilterOff { .. }
        | T::SettingsCleared
        | T::DohDropped
        | T::OtherVpn
        | T::JailbreakSuspected
        | T::BatteryOptimizationOn
        | T::UsbDebuggingOn => return None,
    })
}

/// Per-connection state: the rate budget and what was already noted.
#[derive(Debug)]
pub struct TamperGate {
    tokens: u32,
    refilled_at: Instant,
    refusal_reported: bool,
    flood_warned: bool,
}

impl TamperGate {
    pub fn new(now: Instant) -> Self {
        TamperGate {
            tokens: BURST,
            refilled_at: now,
            refusal_reported: false,
            flood_warned: false,
        }
    }

    /// What to forward for `sig` from this connection, if anything.
    pub fn admit(&mut self, sig: TamperSignal, now: Instant) -> Option<TamperSignal> {
        let Some(sig) = from_agent(sig) else {
            // The variant only: its text is the agent's.
            tracing::debug!("agent sent a tamper signal only the service raises; refused");
            if std::mem::replace(&mut self.refusal_reported, true) {
                return None;
            }
            tracing::warn!("agent sent a tamper signal only the service raises");
            return Some(TamperSignal::IntegrityFailure {
                component: REFUSED_COMPONENT.to_owned(),
            });
        };
        self.refill(now);
        if self.tokens == 0 {
            tracing::debug!("agent tamper signal over the rate limit; dropped");
            if !std::mem::replace(&mut self.flood_warned, true) {
                tracing::warn!(
                    burst = BURST,
                    "agent is sending tamper signals faster than allowed; dropping the excess"
                );
            }
            return None;
        }
        self.tokens -= 1;
        Some(sig)
    }

    fn refill(&mut self, now: Instant) {
        let n = now.saturating_duration_since(self.refilled_at).as_millis() / REFILL.as_millis();
        if n == 0 {
            return;
        }
        let n = u32::try_from(n).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(n).min(BURST);
        self.refilled_at = if self.tokens == BURST {
            now
        } else {
            self.refilled_at + REFILL * n
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_ipc::limits::MAX_TAMPER_TEXT_BYTES;

    fn service_only() -> Vec<TamperSignal> {
        vec![
            TamperSignal::AgentKilledRepeatedly {
                count: 9,
                window_secs: 60,
            },
            TamperSignal::IntegrityFailure {
                component: "faro-service binary".into(),
            },
            TamperSignal::ClockManipulation {
                wall_delta_ms: 1,
                mono_delta_ms: 2,
            },
            TamperSignal::UnmonitoredUserSession {
                user: "someone-else".into(),
            },
            TamperSignal::PermissionRevoked {
                permission: "made_up".into(),
                never_granted: false,
            },
        ]
    }

    #[test]
    fn service_only_signals_are_refused() {
        for s in service_only() {
            assert_eq!(from_agent(s.clone()), None, "{s:?}");
        }
    }

    #[test]
    fn agent_signals_pass_with_bounded_fields() {
        for s in [
            TamperSignal::VpnActive,
            TamperSignal::VirtualMachine,
            TamperSignal::RemoteDesktop,
            TamperSignal::WaylandTokenLost,
            TamperSignal::CaptureFailing {
                consecutive_failures: 5,
            },
        ] {
            assert_eq!(from_agent(s.clone()), Some(s));
        }
        assert_eq!(
            from_agent(TamperSignal::PermissionRevoked {
                permission: "screen_recording".into(),
                never_granted: true,
            }),
            Some(TamperSignal::PermissionRevoked {
                permission: "screen_recording".into(),
                never_granted: false,
            }),
            "never_granted is the service's to decide"
        );
        let Some(TamperSignal::WindowHiddenFromCapture { app }) =
            from_agent(TamperSignal::WindowHiddenFromCapture {
                app: format!("Vie\nwer{}", "x".repeat(10_000)),
            })
        else {
            panic!("refused");
        };
        assert!(app.starts_with("Viewer"));
        assert_eq!(app.len(), MAX_TAMPER_TEXT_BYTES);
    }

    #[test]
    fn a_refusal_is_reported_once_per_connection() {
        let now = Instant::now();
        let mut g = TamperGate::new(now);
        let mut out = Vec::new();
        for s in service_only().into_iter().cycle().take(20) {
            out.extend(g.admit(s, now));
        }
        assert_eq!(
            out,
            vec![TamperSignal::IntegrityFailure {
                component: REFUSED_COMPONENT.into()
            }]
        );
    }

    #[test]
    fn signals_are_rate_limited() {
        let t0 = Instant::now();
        let mut g = TamperGate::new(t0);
        let sent = (0..100)
            .filter(|_| g.admit(TamperSignal::VpnActive, t0).is_some())
            .count();
        assert_eq!(sent, BURST as usize);
        assert!(g.admit(TamperSignal::VpnActive, t0 + REFILL / 2).is_none());
        assert!(g.admit(TamperSignal::VpnActive, t0 + REFILL).is_some());
        assert!(g.admit(TamperSignal::VpnActive, t0 + REFILL).is_none());
        // A long quiet spell refills to the burst, not beyond.
        let later = t0 + REFILL * 1000;
        let sent = (0..100)
            .filter(|_| g.admit(TamperSignal::VpnActive, later).is_some())
            .count();
        assert_eq!(sent, BURST as usize);
    }
}
