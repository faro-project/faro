//! Agent supervision (ARCHITECTURE.md §3.1, §3.7).
//!
//! "If the agent is killed, the service relaunches it and logs
//! `agent_restarted`." Relaunching is the OS's job in production (launchd
//! `KeepAlive`, systemd `Restart=`, the Windows service) or `--spawn-agent`
//! in development; this module decides what the *log* says:
//!
//! * an agent that reconnects after an **unexpected** disconnect (crash,
//!   kill, hang) produces an `agent_restarted` event carrying the number of
//!   such disconnects in the last hour;
//! * `threshold` unexpected disconnects within `window` raise one
//!   `agent_killed_repeatedly` tamper signal, latched until the window
//!   empties again, so a kill loop pages allies once rather than every time.
//!
//! There is one agent per session (every OS account is monitored, §3.1).
//! Restarts are tracked per session, and the kill-loop window counts
//! unexpected disconnects of every session's agent together: killing the
//! agent in a second account is as much a way around Faro as in the first.
//!
//! Only departures the capture source *verified* as expected (the agent's
//! session ended: logout) are not counted. An agent
//! saying `Goodbye` while its user is still logged in counts like a kill,
//! since `launchctl bootout` or `pkill` make the real agent say goodbye too
//! (see `source::ipc`). An agent that leaves and stays away is caught
//! separately by the core's missing-agent timer.

use faro_proto::body::TamperSignal;
use std::collections::{BTreeSet, VecDeque};

const HOUR_MS: u64 = 3600 * 1000;

#[derive(Debug, Clone)]
pub struct Supervisor {
    threshold: u32,
    window_ms: u64,
    /// Monotonic times of unexpected disconnects within the last hour (or
    /// the window, whichever is longer).
    drops: VecDeque<u64>,
    /// Sessions whose agent disconnected unexpectedly and has not come back.
    restart_pending: BTreeSet<String>,
    latched: bool,
}

/// What a reconnect means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restarted {
    pub count_last_hour: u32,
}

impl Supervisor {
    pub fn new(threshold: u32, window_secs: u64) -> Self {
        Supervisor {
            threshold: threshold.max(2),
            window_ms: window_secs.saturating_mul(1000).max(1000),
            drops: VecDeque::new(),
            restart_pending: BTreeSet::new(),
            latched: false,
        }
    }

    fn trim(&mut self, now_ms: u64) {
        let keep = self.window_ms.max(HOUR_MS);
        while self
            .drops
            .front()
            .is_some_and(|&t| now_ms.saturating_sub(t) > keep)
        {
            self.drops.pop_front();
        }
    }

    fn in_window(&self, now_ms: u64, window: u64) -> u32 {
        let n = self
            .drops
            .iter()
            .filter(|&&t| now_ms.saturating_sub(t) <= window)
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// `session`'s agent connection dropped. Returns a tamper signal when
    /// this crosses the threshold.
    pub fn on_disconnect(
        &mut self,
        now_ms: u64,
        session: &str,
        expected: bool,
    ) -> Option<TamperSignal> {
        if expected {
            self.restart_pending.remove(session);
            return None;
        }
        self.trim(now_ms);
        self.drops.push_back(now_ms);
        self.restart_pending.insert(session.to_owned());
        let count = self.in_window(now_ms, self.window_ms);
        // Latched by `mark_reported`, once the signal has committed.
        if count >= self.threshold && !self.latched {
            return Some(TamperSignal::AgentKilledRepeatedly {
                count,
                window_secs: self.window_ms / 1000,
            });
        }
        None
    }

    /// The signal `on_disconnect` returned has been committed: not again
    /// until the drops fall below the threshold. Ignored if they already
    /// have.
    pub fn mark_reported(&mut self, now_ms: u64) {
        if self.in_window(now_ms, self.window_ms) >= self.threshold {
            self.latched = true;
        }
    }

    /// `session`'s agent connected. Returns `Some` if this is a restart
    /// after an unexpected disconnect.
    pub fn on_connect(&mut self, now_ms: u64, session: &str) -> Option<Restarted> {
        self.trim(now_ms);
        if self.in_window(now_ms, self.window_ms) < self.threshold {
            self.latched = false;
        }
        if self.restart_pending.remove(session) {
            Some(Restarted {
                count_last_hour: self.in_window(now_ms, HOUR_MS),
            })
        } else {
            None
        }
    }

    /// `session` ended (its user logged out) while its agent was away: its
    /// next agent, at the next login, is not a restart.
    pub fn forget(&mut self, session: &str) {
        self.restart_pending.remove(session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_restarts_and_latches_kill_signal() {
        let mut s = Supervisor::new(3, 600);
        assert_eq!(s.on_connect(0, "s"), None, "first connect is not a restart");
        assert_eq!(s.on_disconnect(1_000, "s", true), None);
        assert_eq!(s.on_connect(2_000, "s"), None, "goodbye is not a restart");

        assert_eq!(s.on_disconnect(10_000, "s", false), None);
        assert_eq!(
            s.on_connect(11_000, "s"),
            Some(Restarted { count_last_hour: 1 })
        );
        assert_eq!(s.on_disconnect(20_000, "s", false), None);
        s.on_connect(21_000, "s");
        let sig = s.on_disconnect(30_000, "s", false);
        assert_eq!(
            sig,
            Some(TamperSignal::AgentKilledRepeatedly {
                count: 3,
                window_secs: 600
            })
        );
        // Until the signal commits, the condition stands and is signalled again.
        s.on_connect(31_000, "s");
        assert!(s.on_disconnect(35_000, "s", false).is_some());
        s.mark_reported(35_000);
        s.on_connect(36_000, "s");
        assert_eq!(s.on_disconnect(40_000, "s", false), None, "latched");
        s.on_connect(41_000, "s");
        // After the window empties the latch re-arms.
        let later = 40_000 + 601_000;
        assert_eq!(s.on_connect(later, "s"), None);
        for i in 0..2 {
            assert_eq!(s.on_disconnect(later + i * 1000, "s", false), None);
            s.on_connect(later + i * 1000 + 500, "s");
        }
        assert!(s.on_disconnect(later + 5_000, "s", false).is_some());
    }

    #[test]
    fn restarts_are_per_session_and_kills_count_together() {
        let mut s = Supervisor::new(3, 600);
        s.on_connect(0, "a");
        s.on_connect(0, "b");
        assert_eq!(s.on_disconnect(1_000, "a", false), None);
        // b reconnecting is not a's restart.
        assert_eq!(s.on_connect(1_500, "b"), None);
        assert_eq!(s.on_disconnect(2_000, "b", false), None);
        assert!(
            s.on_disconnect(3_000, "b", false).is_some(),
            "three kills across two accounts"
        );
        assert_eq!(
            s.on_connect(4_000, "a"),
            Some(Restarted { count_last_hour: 3 })
        );
        // A session that ended while its agent was away starts fresh.
        s.forget("b");
        assert_eq!(s.on_connect(5_000, "b"), None);
    }

    #[test]
    fn hour_count_outlives_short_window() {
        let mut s = Supervisor::new(10, 60);
        for t in [0u64, 100_000, 200_000] {
            s.on_disconnect(t, "s", false);
            s.on_connect(t + 1, "s");
        }
        s.on_disconnect(300_000, "s", false);
        assert_eq!(
            s.on_connect(300_001, "s"),
            Some(Restarted { count_last_hour: 4 })
        );
    }
}
