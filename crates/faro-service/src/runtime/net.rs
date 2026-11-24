//! Everything that talks to the instance once the device is active:
//! uploading the outbox, heartbeats, and recipient-manifest refresh.
//!
//! All three work offline: the outbox keeps queueing (it is the durable
//! state), and each loop retries with jittered backoff until the instance is
//! reachable again.

use super::status::StatusTx;
use crate::backoff::Backoff;
use crate::client::{ClientError, InstanceClient};
use crate::state::Enrollment;
use faro_core::clock::Clock;
use faro_core::{ManifestDecision, Outbox, OutboxError, PrunePolicy, RecipientSet};
use faro_crypto::SigningKey;
use faro_proto::api::{DeviceState, EventResult, EventsBatchRequest, Heartbeat, HeartbeatResponse};
use faro_proto::Hash32;
use reqwest::StatusCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// Events per upload batch (the instance accepts up to 500).
pub const UPLOAD_BATCH: usize = 200;

/// The outbox, shared between the core and the network tasks. Every call
/// runs on Tokio's blocking pool: SQLite with `synchronous=FULL` fsyncs.
#[derive(Clone)]
pub struct OutboxHandle(Arc<Mutex<Outbox>>);

impl OutboxHandle {
    pub fn new(outbox: Outbox) -> Self {
        OutboxHandle(Arc::new(Mutex::new(outbox)))
    }

    pub async fn run<T, F>(&self, f: F) -> Result<T, OutboxError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Outbox) -> Result<T, OutboxError> + Send + 'static,
    {
        let inner = self.0.clone();
        tokio::task::spawn_blocking(move || {
            let mut g = inner.lock().unwrap_or_else(PoisonError::into_inner);
            f(&mut g)
        })
        .await
        .map_err(|_| OutboxError::Corrupt("outbox task panicked".into()))?
    }

    /// The recipient set of the stored checkpoint.
    pub async fn recipients(&self, e: &Enrollment) -> Result<Option<RecipientSet>, OutboxError> {
        let key = e.member_sign_pubkey;
        let member = e.member_id.clone();
        self.run(move |o| o.current_recipients(&key, &member)).await
    }
}

/// Shared by the network tasks: false while the instance's identity does
/// not match the pin, in which case no device call is made.
#[derive(Clone, Default)]
pub struct IdentityGate(Arc<AtomicBool>);

impl IdentityGate {
    pub fn new_open() -> Self {
        IdentityGate(Arc::new(AtomicBool::new(true)))
    }
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub fn set(&self, open: bool) {
        self.0.store(open, Ordering::Release);
    }
}

/// Drains the outbox to the instance.
pub struct Uploader {
    pub client: InstanceClient,
    pub outbox: OutboxHandle,
    pub clock: Arc<dyn Clock>,
    pub status: StatusTx,
    pub gate: IdentityGate,
    pub prune: PrunePolicy,
}

/// Why an upload pass stopped early.
#[derive(Debug)]
pub enum UploadStop {
    Client(ClientError),
    Outbox(OutboxError),
    /// The instance's identity no longer matches the pin.
    Gated,
}

impl Uploader {
    /// Upload everything pending: events in `seq` order, then reports.
    pub async fn drain(&self) -> Result<(), UploadStop> {
        if !self.gate.is_open() {
            return Err(UploadStop::Gated);
        }
        self.drain_events().await?;
        self.drain_reports().await
    }

    async fn drain_events(&self) -> Result<(), UploadStop> {
        let mut last_acked: Option<u64> = None;
        loop {
            let pending = self
                .outbox
                .run(|o| o.pending(UPLOAD_BATCH))
                .await
                .map_err(UploadStop::Outbox)?;
            let Some(first) = pending.first().map(|e| e.header.seq) else {
                return Ok(());
            };
            let n = pending.len();
            let resp = self
                .client
                .post_events(&EventsBatchRequest { events: pending })
                .await
                .map_err(UploadStop::Client)?;
            for r in &resp.results {
                if let EventResult::Rejected { seq, reason } = r {
                    if reason == "retry_later" {
                        continue;
                    }
                    tracing::warn!(seq, %reason, "instance rejected an event");
                }
            }
            let Some(acked) = resp.acked_through else {
                tracing::warn!(first, n, "instance acknowledged nothing; will retry later");
                return Ok(());
            };
            match self.outbox.run(move |o| o.ack_through(acked)).await {
                Ok(_) => {}
                Err(OutboxError::AckBeyondHead { acked, next_seq }) => {
                    // The instance claims events this device never wrote:
                    // keep everything and say so loudly.
                    tracing::error!(
                        acked,
                        next_seq,
                        "instance acknowledged beyond our chain head"
                    );
                    self.status.update(|s| {
                        s.last_error = Some(format!(
                            "instance acknowledged seq {acked} beyond the local head"
                        ));
                    });
                    return Ok(());
                }
                Err(e) => return Err(UploadStop::Outbox(e)),
            }
            self.status.update(|s| s.acked_through = Some(acked));
            if last_acked.is_some_and(|l| l >= acked) || acked < first {
                // No progress (e.g. the oldest pending event keeps being
                // rejected); try again on the next pass instead of spinning.
                return Ok(());
            }
            last_acked = Some(acked);
            if n < UPLOAD_BATCH {
                return Ok(());
            }
        }
    }

    async fn drain_reports(&self) -> Result<(), UploadStop> {
        let reports = self
            .outbox
            .run(|o| o.pending_reports())
            .await
            .map_err(UploadStop::Outbox)?;
        for r in reports {
            match self.client.post_report(&r.upload).await {
                Ok(acc) => {
                    let id = r.id;
                    self.outbox
                        .run(move |o| o.ack_report(id))
                        .await
                        .map_err(UploadStop::Outbox)?;
                    self.status.update(|s| s.reports_uploaded += 1);
                    tracing::info!(report = %acc.report_id, duplicate = acc.duplicate, "report uploaded");
                }
                Err(e) if is_permanent_report_error(&e) => {
                    // Retrying a report the instance will never accept would
                    // block every later one; drop it and record why.
                    tracing::error!(error = %e, period_start = r.upload.header.period_start_ms,
                        "instance permanently rejected a report; dropping it");
                    let id = r.id;
                    self.outbox
                        .run(move |o| o.ack_report(id))
                        .await
                        .map_err(UploadStop::Outbox)?;
                    self.status.update(|s| s.last_error = Some(e.to_string()));
                }
                Err(e) => return Err(UploadStop::Client(e)),
            }
        }
        Ok(())
    }

    /// Enforce offline retention (§3.6: ~30 days, oldest clean first).
    pub async fn prune(&self) {
        let now = self.clock.wall_ms();
        let policy = self.prune;
        match self.outbox.run(move |o| o.prune(now, policy)).await {
            Ok(out) if out.events_deleted > 0 || out.reports_deleted > 0 => {
                tracing::warn!(
                    events = out.events_deleted,
                    reports = out.reports_deleted,
                    "pruned unsent data from the outbox"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "outbox prune failed"),
        }
    }
}

fn is_permanent_report_error(e: &ClientError) -> bool {
    match e.status() {
        Some(s) => {
            s == StatusCode::BAD_REQUEST
                || s == StatusCode::CONFLICT
                || s == StatusCode::PAYLOAD_TOO_LARGE
                || s == StatusCode::UNPROCESSABLE_ENTITY
        }
        None => matches!(e, ClientError::Encode(_)),
    }
}

/// Builds, signs and sends heartbeats (PROTOCOL.md §7).
pub struct Heartbeater {
    pub client: InstanceClient,
    pub outbox: OutboxHandle,
    pub clock: Arc<dyn Clock>,
    pub key: Arc<SigningKey>,
    pub enrollment: Arc<Enrollment>,
    pub status: StatusTx,
    pub gate: IdentityGate,
}

impl Heartbeater {
    /// The heartbeat for `state`. `last_seq`/`last_hash` name the newest
    /// committed event: the outbox head's `prev_hash` *is* the chain hash of
    /// the event at `next_seq - 1`, which the instance compares with what it
    /// holds to detect forks.
    pub async fn build(&self, state: DeviceState) -> Result<Heartbeat, OutboxError> {
        let head = self.outbox.run(|o| o.head()).await?;
        let (last_seq, last_hash): (Option<u64>, Option<Hash32>) = match head.next_seq {
            0 => (None, None),
            n => (Some(n - 1), Some(head.prev_hash)),
        };
        Ok(Heartbeat {
            instance_id: self.enrollment.instance_id.clone(),
            device_id: self.enrollment.device_id.clone(),
            ts_ms: self.client.corrected_wall_ms(),
            mono_ms: self.clock.mono_ms(),
            boot_id: self.clock.boot_id(),
            state,
            last_seq,
            last_hash,
        })
    }

    /// Send one heartbeat. On success the instance's `acked_through` also
    /// prunes the outbox.
    pub async fn send(&self, state: DeviceState) -> Result<HeartbeatResponse, UploadStop> {
        if !self.gate.is_open() {
            return Err(UploadStop::Gated);
        }
        let hb = self.build(state).await.map_err(UploadStop::Outbox)?;
        let signed = self.key.sign_heartbeat(hb);
        let resp = self
            .client
            .heartbeat(&signed)
            .await
            .map_err(UploadStop::Client)?;
        if let Some(acked) = resp.acked_through {
            match self.outbox.run(move |o| o.ack_through(acked)).await {
                Ok(_) | Err(OutboxError::AckBeyondHead { .. }) => {}
                Err(e) => tracing::warn!(error = %e, "ack from heartbeat failed"),
            }
        }
        self.status.update(|s| {
            s.heartbeats_sent += 1;
            s.last_heartbeat_state = Some(state);
        });
        Ok(resp)
    }
}

/// Fetches the member's recipient manifest and advances the checkpoint, and
/// re-checks the pinned instance identity.
pub struct ManifestRefresher {
    pub client: InstanceClient,
    pub outbox: OutboxHandle,
    pub enrollment: Arc<Enrollment>,
    pub status: StatusTx,
    pub gate: IdentityGate,
}

impl ManifestRefresher {
    /// Re-check the instance identity against the pin. A mismatch closes
    /// the gate: no device calls until it matches again (events keep
    /// queueing locally, and the instance's liveness monitor will notice
    /// the silence, which is the visible outcome we want).
    pub async fn check_identity(&self) -> Result<(), ClientError> {
        match self
            .client
            .check_identity(
                &self.enrollment.instance_id,
                &self.enrollment.instance_identity_pubkey,
            )
            .await
        {
            Ok(_) => {
                if !self.gate.is_open() {
                    tracing::info!("instance identity matches the pin again");
                }
                self.gate.set(true);
                self.status.update(|s| s.identity_mismatch = false);
                Ok(())
            }
            Err(e @ ClientError::IdentityChanged { .. }) => {
                tracing::error!(error = %e, "instance identity does not match the pin; pausing uploads");
                self.gate.set(false);
                self.status.update(|s| s.identity_mismatch = true);
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    /// Fetch and judge the latest manifest. Refusals keep the current set
    /// (PROTOCOL.md §5.1) and are surfaced in the status (for the tray).
    pub async fn refresh(&self) -> Result<(), ClientError> {
        if !self.gate.is_open() {
            return Ok(());
        }
        let m = self
            .client
            .recipient_manifest(&self.enrollment.member_id)
            .await?;
        let key = self.enrollment.member_sign_pubkey;
        let member = self.enrollment.member_id.clone();
        match self
            .outbox
            .run(move |o| o.accept_manifest(&m, &key, &member))
            .await
        {
            Ok((set, ManifestDecision::Advanced(r))) => {
                tracing::info!(
                    version = r.version,
                    allies = set.allies().len(),
                    "accepted a newer recipient manifest"
                );
                self.status.update(|s| {
                    s.manifest = Some(r);
                    s.manifest_warning = None;
                });
            }
            Ok((set, ManifestDecision::Unchanged)) => {
                self.status.update(|s| {
                    s.manifest = Some(set.manifest_ref());
                    s.manifest_warning = None;
                });
            }
            Err(OutboxError::Manifest(e)) => {
                tracing::warn!(error = %e, "refused the instance's recipient manifest; keeping the current one");
                self.status
                    .update(|s| s.manifest_warning = Some(e.to_string()));
            }
            Err(e) => {
                tracing::error!(error = %e, "could not judge the recipient manifest");
                self.status.update(|s| s.last_error = Some(e.to_string()));
            }
        }
        Ok(())
    }
}

/// Run `f` every `every`, or when `poke` fires, until `stop` flips; with
/// jittered backoff after failures.
pub async fn periodic<F, Fut>(
    every: Duration,
    poke: Arc<tokio::sync::Notify>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    mut f: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut backoff = Backoff::new(Duration::from_secs(1), every.max(Duration::from_secs(1)));
    let mut wait = Duration::ZERO;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = poke.notified() => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        if *stop.borrow() {
            return;
        }
        if f().await {
            backoff.reset();
            wait = every;
        } else {
            wait = backoff.next_delay().min(every);
        }
    }
}
