//! `faro-service goodbye`: tell allies that monitoring is ending on purpose
//! (ARCHITECTURE.md §3.7, PROTOCOL.md §3.3).
//!
//! The uninstaller stops the service, runs this, and only then removes the
//! files, so allies read "Faro was uninstalled from Laptop-X" (an urgent
//! `goodbye`) instead of a missed check-in hours later. Uninstalling is
//! always allowed (§12), but never silent.
//!
//! The order is chosen so the uninstaller can always either finish or back
//! out cleanly:
//!
//! 1. Take the state lock ([`StateDir::try_lock`]): the service must have
//!    stopped, since two writers would fork the chain.
//! 2. Confirm the instance identity and fetch the latest recipient manifest,
//!    so the goodbye reaches the member's current allies. If the instance
//!    can't be reached or refuses the device, **nothing has been written**
//!    ([`GoodbyeError::Unreachable`], [`GoodbyeError::Refused`]) and the
//!    uninstaller can restart the service as if nothing happened.
//! 3. Write the `goodbye` event (urgent; its kind floor makes it so anyway).
//! 4. Upload it, and anything still queued before it, until the deadline.
//!    A goodbye that was written but not delivered is
//!    [`GoodbyeOutcome::Queued`]: the uninstaller goes ahead (a service
//!    restarted after a goodbye would contradict it), and allies see the
//!    missed check-in instead.
//!
//! No heartbeat follows the goodbye: the instance treats any heartbeat as
//! the device being back (`goodbye_at` is cleared), which would re-arm the
//! liveness monitor for a device that is gone.

use super::net::{IdentityGate, ManifestRefresher, OutboxHandle, UploadStop, Uploader};
use super::status::StatusTx;
use crate::backoff::Backoff;
use crate::client::{ClientError, ClientOptions};
use crate::config::Config;
use crate::enroll::{self, EnrollError};
use crate::state::{self, StateDir, StateError, StateLock};
use faro_core::clock::{Clock, SystemClock};
use faro_core::{EventWriter, Outbox, OutboxError, PrunePolicy, WriterError};
use faro_proto::body::{EventBody, GoodbyeReason};
use faro_proto::Urgency;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use url::Url;

/// How often a busy state lock is retried while waiting for the service to
/// exit.
const LOCK_POLL: Duration = Duration::from_millis(250);

/// What [`say_goodbye`] needs besides the config.
#[derive(Clone)]
pub struct GoodbyeOptions {
    pub reason: GoodbyeReason,
    /// How long to keep trying to deliver the goodbye once it is written.
    pub deliver_within: Duration,
    /// How long to wait for a stopping service to release the state lock.
    pub lock_wait: Duration,
    /// Default: [`SystemClock`].
    pub clock: Option<Arc<dyn Clock>>,
    /// Talk to this base URL instead of the enrolled one (tests; the pinned
    /// identity is still enforced).
    pub base_url: Option<Url>,
}

impl GoodbyeOptions {
    pub fn new(reason: GoodbyeReason) -> Self {
        GoodbyeOptions {
            reason,
            deliver_within: Duration::from_secs(60),
            lock_wait: Duration::from_secs(30),
            clock: None,
            base_url: None,
        }
    }
}

/// How a goodbye ended. Every outcome lets the uninstaller go ahead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoodbyeOutcome {
    /// The instance acknowledged the goodbye (event `seq`).
    Delivered { seq: u64 },
    /// The goodbye is written but the instance did not acknowledge it in
    /// time. Allies will see a missed check-in instead.
    Queued { seq: u64, error: String },
    /// Never enrolled: no instance knows this device.
    NotEnrolled,
    /// Enrolled but never endorsed by the member: allies were never told
    /// about this device, and nothing can be sealed to them.
    NotActivated,
}

/// Why no goodbye was written. In every case the event chain is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum GoodbyeError {
    #[error("the Faro service is still running (it holds {path}); stop it first")]
    ServiceRunning { path: std::path::PathBuf },
    #[error("cannot reach the instance, so allies can't be told: {0}")]
    Unreachable(#[source] ClientError),
    #[error("the instance refused this device ({0}); if the member removed it in the web app, allies already know")]
    Refused(#[source] ClientError),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error("cannot build the goodbye event: {0}")]
    Writer(#[from] WriterError),
    /// The enrollment record can't produce an instance client.
    #[error(transparent)]
    Enroll(#[from] EnrollError),
}

/// A client error before anything was written.
fn before_write(e: ClientError) -> GoodbyeError {
    if e.is_transient() {
        GoodbyeError::Unreachable(e)
    } else {
        GoodbyeError::Refused(e)
    }
}

/// Write and deliver a `goodbye` event for this device. See the module docs
/// for the order of steps and what each failure leaves behind.
pub async fn say_goodbye(
    config: &Config,
    opts: GoodbyeOptions,
) -> Result<GoodbyeOutcome, GoodbyeError> {
    let dir = StateDir::open(&config.state_dir)?;
    let _lock = lock_within(&dir, opts.lock_wait).await?;
    let enrollment = match dir.enrollment() {
        Ok(e) => Arc::new(e),
        Err(StateError::NotEnrolled) => return Ok(GoodbyeOutcome::NotEnrolled),
        Err(e) => return Err(e.into()),
    };
    let outbox = Outbox::open(dir.path(), &enrollment.instance_id, &enrollment.device_id)?;
    if outbox.manifest_checkpoint()?.is_none() {
        return Ok(GoodbyeOutcome::NotActivated);
    }
    let head = outbox.head()?;
    let outbox = OutboxHandle::new(outbox);
    let key = state::load_device_key(&dir)?;
    let clock = opts
        .clock
        .clone()
        .unwrap_or_else(|| Arc::new(SystemClock::new()));
    let client = enroll::device_client(
        &enrollment,
        Arc::new(faro_crypto::SigningKey::from_bytes(&key.to_bytes())),
        clock.clone(),
        &ClientOptions {
            timeout: config.network.request_timeout(),
            ca_file: config.network.ca_file.clone(),
        },
        opts.base_url.clone(),
    )?;
    let (status, _status_rx) = StatusTx::new();
    let gate = IdentityGate::new_open();

    // ---- 2. reach the instance; nothing written yet ----------------------
    let refresher = ManifestRefresher {
        client: client.clone(),
        outbox: outbox.clone(),
        enrollment: enrollment.clone(),
        status: status.clone(),
        gate: gate.clone(),
    };
    refresher.check_identity().await.map_err(before_write)?;
    refresher.refresh().await.map_err(before_write)?;
    let recipients = outbox
        .recipients(&enrollment)
        .await?
        .ok_or(OutboxError::NotBootstrapped)?;

    // ---- 3. write ---------------------------------------------------------
    let writer = EventWriter::new(
        key,
        enrollment.instance_id.clone(),
        enrollment.device_id.clone(),
        head,
        clock.clone(),
    );
    let body = EventBody::Goodbye {
        reason: opts.reason.clone(),
    };
    let prepared = writer.prepare(&body, Urgency::Urgent, &recipients)?;
    let seq = prepared.event().header.seq;
    outbox.run(move |o| o.commit(&prepared)).await?;
    tracing::info!(seq, reason = ?opts.reason, "goodbye written");

    // ---- 4. deliver; from here on every path is an outcome ---------------
    let uploader = Uploader {
        client,
        outbox: outbox.clone(),
        clock,
        status,
        gate,
        prune: PrunePolicy::default(),
    };
    Ok(deliver(&uploader, &outbox, seq, opts.deliver_within).await)
}

/// Retry the state lock until `wait` has passed: `launchctl bootout` can
/// return while the service is still finishing its shutdown upload.
async fn lock_within(dir: &StateDir, wait: Duration) -> Result<StateLock, GoodbyeError> {
    let deadline = Instant::now() + wait;
    loop {
        match dir.try_lock() {
            Ok(l) => return Ok(l),
            Err(StateError::Busy { path }) => {
                if Instant::now() >= deadline {
                    return Err(GoodbyeError::ServiceRunning { path });
                }
                tokio::time::sleep(LOCK_POLL).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Upload until the instance has acknowledged `seq` or `within` runs out.
async fn deliver(
    uploader: &Uploader,
    outbox: &OutboxHandle,
    seq: u64,
    within: Duration,
) -> GoodbyeOutcome {
    let deadline = Instant::now() + within;
    let mut backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(10));
    loop {
        let error = match uploader.drain().await {
            Ok(()) => None,
            Err(UploadStop::Client(e)) => Some(e.to_string()),
            Err(UploadStop::Outbox(e)) => Some(e.to_string()),
            Err(UploadStop::Gated) => Some("the instance identity no longer matches".into()),
        };
        // Acknowledged even if a queued report then failed: the goodbye is
        // what matters here.
        match acked(outbox, seq).await {
            Ok(true) => return GoodbyeOutcome::Delivered { seq },
            Ok(false) => {}
            Err(e) => {
                return GoodbyeOutcome::Queued {
                    seq,
                    error: e.to_string(),
                }
            }
        }
        let error = error.unwrap_or_else(|| "the instance did not acknowledge it".into());
        let now = Instant::now();
        if now >= deadline {
            return GoodbyeOutcome::Queued { seq, error };
        }
        tracing::info!(%error, "goodbye not delivered yet; retrying");
        tokio::time::sleep(backoff.next_delay().min(deadline - now)).await;
    }
}

/// Whether nothing at or before `seq` is still pending.
async fn acked(outbox: &OutboxHandle, seq: u64) -> Result<bool, OutboxError> {
    let first = outbox.run(|o| o.pending(1)).await?;
    Ok(first.first().is_none_or(|e| e.header.seq > seq))
}
