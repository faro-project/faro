//! Bridging Apple's asynchronous completion handlers to synchronous calls.
//!
//! ScreenCaptureKit only offers callback APIs (`getShareableContent…`,
//! `captureImageWithFilter…`) whose handlers run on private dispatch queues.
//! The platform traits are synchronous, so each call parks the calling
//! thread on a one-slot channel with a deadline.
//!
//! Why a timeout at all: `replayd` (the system capture daemon) can stall, for
//! example while a TCC re-confirmation dialog is on screen. Without a bound,
//! a stuck capture would wedge the agent's tick loop and the service would
//! only notice through missing heartbeats. With a bound, the caller gets a
//! typed error, counts it, and reports `CaptureFailing` (§3.7).
//!
//! If the handler fires after the deadline, its `try_send` fails because the
//! receiver is gone; the late value is simply dropped (and, for images,
//! released) on the OS queue.

use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::time::Duration;

/// Default deadline for one ScreenCaptureKit round trip.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a bridged call produced no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// The handler did not run before the deadline.
    #[error("completion handler did not fire within {0:?}")]
    TimedOut(Duration),
    /// The handler was dropped without ever running (the OS released the
    /// block without calling it).
    #[error("completion handler was dropped without being called")]
    Dropped,
}

/// A sending half handed to the callback. Only the first value is kept, which
/// protects against handlers that (contrary to their contract) fire twice.
#[derive(Debug)]
pub struct Completion<T> {
    tx: SyncSender<T>,
}

impl<T> Clone for Completion<T> {
    fn clone(&self) -> Self {
        Completion {
            tx: self.tx.clone(),
        }
    }
}

impl<T> Completion<T> {
    /// Deliver the result. Never blocks: a full slot (second call) or a
    /// departed receiver (deadline passed) drops `value`.
    pub fn complete(&self, value: T) {
        let _ = self.tx.try_send(value);
    }
}

/// Start an asynchronous operation and wait up to `timeout` for its first
/// completion.
///
/// `start` receives a [`Completion`] to move into the OS callback. It must
/// arrange for `complete` to be called at most once per logical result; extra
/// calls are ignored.
pub fn await_completion<T, F>(timeout: Duration, start: F) -> Result<T, BridgeError>
where
    F: FnOnce(Completion<T>),
{
    let (tx, rx) = mpsc::sync_channel(1);
    start(Completion { tx });
    match rx.recv_timeout(timeout) {
        Ok(v) => Ok(v),
        Err(RecvTimeoutError::Timeout) => Err(BridgeError::TimedOut(timeout)),
        Err(RecvTimeoutError::Disconnected) => Err(BridgeError::Dropped),
    }
}

/// Moves a value that is not `Send` by type, but is safe to hand to exactly
/// one other thread, across a channel.
///
/// Used for ScreenCaptureKit result objects (`SCShareableContent` and its
/// `SCDisplay`s), which the Objective-C bindings conservatively mark as
/// thread-unsafe. They are immutable snapshots produced on an OS queue and
/// consumed on ours; Objective-C retain/release is atomic, and ownership is
/// transferred, not shared.
pub(crate) struct AssertSend<T>(pub T);

// SAFETY: see the type docs. Only constructed for immutable ScreenCaptureKit
// snapshot objects that are transferred (not shared) to the waiting thread.
unsafe impl<T> Send for AssertSend<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn delivers_value_from_other_thread() {
        let v = await_completion(Duration::from_secs(2), |c| {
            thread::spawn(move || c.complete(42u32));
        });
        assert_eq!(v, Ok(42));
    }

    #[test]
    fn times_out_when_handler_never_fires() {
        let mut keep = None;
        let r: Result<u8, _> = await_completion(Duration::from_millis(30), |c| keep = Some(c));
        assert_eq!(r, Err(BridgeError::TimedOut(Duration::from_millis(30))));
        // A late completion after the deadline must not panic or block.
        if let Some(c) = keep {
            c.complete(1);
        }
    }

    #[test]
    fn dropped_handler_is_reported_not_hung() {
        let r: Result<u8, _> = await_completion(Duration::from_secs(5), drop);
        assert_eq!(r, Err(BridgeError::Dropped));
    }

    #[test]
    fn only_first_completion_counts() {
        let r = await_completion(Duration::from_secs(1), |c| {
            c.complete("first");
            c.complete("second");
            c.clone().complete("third");
        });
        assert_eq!(r, Ok("first"));
    }

    #[test]
    fn late_completion_from_thread_is_harmless() {
        // The thread completes only once the wait has timed out, however
        // slow the machine: a fixed sleep raced on a busy runner.
        let (go, go_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        let r: Result<u8, _> = await_completion(Duration::from_millis(10), |c| {
            thread::spawn(move || {
                let _ = go_rx.recv();
                c.complete(7);
                let _ = done_tx.send(());
            });
        });
        assert!(matches!(r, Err(BridgeError::TimedOut(_))));
        go.send(()).unwrap();
        done.recv().unwrap();
    }
}
