//! Exponential backoff with full jitter.
//!
//! Many devices of one instance go offline and come back together (an
//! instance reboot, a campus network blip). Without jitter they would all
//! retry in lock-step and hit the small self-hosted server at once; "full
//! jitter" (a uniform draw in `[0, cap]`) spreads them out.

use rand::Rng;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Backoff {
            initial: initial.max(Duration::from_millis(1)),
            max: max.max(initial),
            attempt: 0,
        }
    }

    /// The default for instance calls: 1 s doubling to 5 minutes.
    pub fn network() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(300))
    }

    /// The ceiling for the next delay (before jitter).
    pub fn current_cap(&self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt.min(20)).unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// The next delay: uniform in `[cap/2, cap]`. Keeping half the cap as a
    /// floor avoids immediate retries while still decorrelating devices.
    pub fn next_delay(&mut self) -> Duration {
        let cap = self.current_cap();
        self.attempt = self.attempt.saturating_add(1);
        let cap_ms = u64::try_from(cap.as_millis()).unwrap_or(u64::MAX).max(1);
        let lo = cap_ms / 2;
        Duration::from_millis(rand::thread_rng().gen_range(lo..=cap_ms))
    }

    /// Call after a success.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_caps_and_resets() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(1));
        let mut caps = Vec::new();
        for _ in 0..6 {
            caps.push(b.current_cap());
            let d = b.next_delay();
            assert!(d <= *caps.last().unwrap());
            assert!(d >= *caps.last().unwrap() / 2);
        }
        assert_eq!(caps[0], Duration::from_millis(100));
        assert_eq!(caps[1], Duration::from_millis(200));
        assert_eq!(caps[5], Duration::from_secs(1), "capped at max");
        b.reset();
        assert_eq!(b.current_cap(), Duration::from_millis(100));
        // Many attempts never overflow.
        for _ in 0..100 {
            b.next_delay();
        }
        assert_eq!(b.current_cap(), Duration::from_secs(1));
    }
}
