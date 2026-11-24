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
//! Only departures the capture source *verified* as expected (the agent's
//! console session ended: logout, user switch) are not counted. An agent
//! saying `Goodbye` while its user is still logged in counts like a kill,
//! since `launchctl bootout` or `pkill` make the real agent say goodbye too
//! (see `source::ipc`). An agent that leaves and stays away is caught
//! separately by the core's missing-agent timer.

use faro_proto::body::TamperSignal;
use std::collections::VecDeque;

const HOUR_MS: u64 = 3600 * 1000;

#[derive(Debug, Clone)]
pub struct Supervisor {
    threshold: u32,
    window_ms: u64,
    /// Monotonic times of unexpected disconnects within the last hour (or
    /// the window, whichever is longer).
    drops: VecDeque<u64>,
    /// Set after an unexpected disconnect; cleared by the next connect.
    restart_pending: bool,
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
            restart_pending: false,
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

    /// The agent connection dropped. Returns a tamper signal when this
    /// crosses the threshold.
    pub fn on_disconnect(&mut self, now_ms: u64, expected: bool) -> Option<TamperSignal> {
        if expected {
            return None;
        }
        self.trim(now_ms);
        self.drops.push_back(now_ms);
        self.restart_pending = true;
        let count = self.in_window(now_ms, self.window_ms);
        if count >= self.threshold && !self.latched {
            self.latched = true;
            return Some(TamperSignal::AgentKilledRepeatedly {
                count,
                window_secs: self.window_ms / 1000,
            });
        }
        None
    }

    /// An agent connected. Returns `Some` if this is a restart after an
    /// unexpected disconnect.
    pub fn on_connect(&mut self, now_ms: u64) -> Option<Restarted> {
        self.trim(now_ms);
        if self.in_window(now_ms, self.window_ms) < self.threshold {
            self.latched = false;
        }
        if std::mem::take(&mut self.restart_pending) {
            Some(Restarted {
                count_last_hour: self.in_window(now_ms, HOUR_MS),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_restarts_and_latches_kill_signal() {
        let mut s = Supervisor::new(3, 600);
        assert_eq!(s.on_connect(0), None, "first connect is not a restart");
        assert_eq!(s.on_disconnect(1_000, true), None);
        assert_eq!(s.on_connect(2_000), None, "goodbye is not a restart");

        assert_eq!(s.on_disconnect(10_000, false), None);
        assert_eq!(s.on_connect(11_000), Some(Restarted { count_last_hour: 1 }));
        assert_eq!(s.on_disconnect(20_000, false), None);
        s.on_connect(21_000);
        let sig = s.on_disconnect(30_000, false);
        assert_eq!(
            sig,
            Some(TamperSignal::AgentKilledRepeatedly {
                count: 3,
                window_secs: 600
            })
        );
        s.on_connect(31_000);
        assert_eq!(s.on_disconnect(40_000, false), None, "latched");
        s.on_connect(41_000);
        // After the window empties the latch re-arms.
        let later = 40_000 + 601_000;
        assert_eq!(s.on_connect(later), None);
        for i in 0..2 {
            assert_eq!(s.on_disconnect(later + i * 1000, false), None);
            s.on_connect(later + i * 1000 + 500);
        }
        assert!(s.on_disconnect(later + 5_000, false).is_some());
    }

    #[test]
    fn hour_count_outlives_short_window() {
        let mut s = Supervisor::new(10, 60);
        for t in [0u64, 100_000, 200_000] {
            s.on_disconnect(t, false);
            s.on_connect(t + 1);
        }
        s.on_disconnect(300_000, false);
        assert_eq!(
            s.on_connect(300_001),
            Some(Restarted { count_last_hour: 4 })
        );
    }
}
