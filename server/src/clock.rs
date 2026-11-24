//! Wall-clock abstraction.
//!
//! Every expiry, skew check and liveness decision in the server goes through a
//! [`Clock`] rather than calling `SystemTime::now()` directly, so that tests
//! (and stage-B workers such as the liveness monitor) can drive time
//! deterministically with [`ManualClock`].

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of "now" in Unix milliseconds (UTC).
pub trait Clock: Send + Sync + std::fmt::Debug + 'static {
    fn now_ms(&self) -> i64;
}

/// The real system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        // A clock before 1970 is a misconfigured host; treat it as the epoch
        // rather than panicking, so expiry checks fail closed (everything
        // looks expired or not-yet-valid) instead of crashing the server.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to. Cheap to clone; clones share time.
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    pub fn new(start_ms: i64) -> Self {
        ManualClock(Arc::new(AtomicI64::new(start_ms)))
    }

    /// Start at the current system time.
    pub fn starting_now() -> Self {
        Self::new(SystemClock.now_ms())
    }

    pub fn set_ms(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }

    pub fn advance_ms(&self, delta: i64) {
        self.0.fetch_add(delta, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Shared handle used throughout the server.
pub type SharedClock = Arc<dyn Clock>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_is_shared_between_clones() {
        let a = ManualClock::new(1_000);
        let b = a.clone();
        a.advance_ms(500);
        assert_eq!(b.now_ms(), 1_500);
        b.set_ms(7);
        assert_eq!(a.now_ms(), 7);
    }

    #[test]
    fn system_clock_is_after_2025() {
        assert!(SystemClock.now_ms() > 1_735_689_600_000);
    }
}
