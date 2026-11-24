//! Session edges and tamper signals waiting to be delivered.
//!
//! Both are *events* (the platform drains them on every poll), unlike the
//! foreground/session/permission *state*, which is simply resent after a
//! reconnect. So they are queued until the service has them: a permission
//! revocation observed while the service was restarting must still arrive.
//!
//! The queue is bounded because the service could stay away for a long
//! time. Signals are edge-triggered, so reaching the bound takes a
//! pathological platform; if it happens, session edges are dropped before
//! tamper signals (a lost lock/unlock only blurs the timeline, a lost tamper
//! signal silences an alert), and the drop is logged.

use std::collections::VecDeque;

use faro_ipc::WireSessionChange;
use faro_platform::TamperSignal;

/// Upper bound on queued signals.
pub(crate) const MAX_PENDING: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Signal {
    Session(WireSessionChange),
    Tamper(TamperSignal),
}

#[derive(Debug, Default)]
pub(crate) struct Pending {
    queue: VecDeque<Signal>,
    dropped: u64,
}

impl Pending {
    pub(crate) fn push(&mut self, s: Signal) {
        if self.queue.len() >= MAX_PENDING {
            let victim = self
                .queue
                .iter()
                .position(|q| matches!(q, Signal::Session(_)))
                .unwrap_or(0);
            let what = match self.queue.remove(victim) {
                Some(Signal::Session(_)) => "session edge",
                _ => "tamper signal",
            };
            self.dropped += 1;
            tracing::warn!(
                dropped_total = self.dropped,
                "signal queue full while the service is unreachable; dropped the oldest {what}"
            );
        }
        self.queue.push_back(s);
    }

    pub(crate) fn front(&self) -> Option<&Signal> {
        self.queue.front()
    }

    pub(crate) fn pop_front(&mut self) {
        self.queue.pop_front();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_drops_session_edges_first() {
        let mut p = Pending::default();
        p.push(Signal::Tamper(TamperSignal::VpnActive));
        for _ in 1..MAX_PENDING {
            p.push(Signal::Session(WireSessionChange::Locked));
        }
        assert_eq!(p.len(), MAX_PENDING);
        p.push(Signal::Tamper(TamperSignal::RemoteDesktop));
        assert_eq!(p.len(), MAX_PENDING);
        // The oldest entry (a tamper signal) survived; a session edge went.
        assert_eq!(p.front(), Some(&Signal::Tamper(TamperSignal::VpnActive)));
        assert_eq!(p.dropped, 1);
    }

    #[test]
    fn overflow_of_only_tamper_drops_oldest() {
        let mut p = Pending::default();
        for i in 0..MAX_PENDING {
            p.push(Signal::Tamper(TamperSignal::CaptureFailing {
                consecutive_failures: i as u32,
            }));
        }
        p.push(Signal::Tamper(TamperSignal::VpnActive));
        assert_eq!(
            p.front(),
            Some(&Signal::Tamper(TamperSignal::CaptureFailing {
                consecutive_failures: 1
            }))
        );
    }
}
