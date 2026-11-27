//! Everything that talks to the instance once the device is active:
//! uploading the outbox, heartbeats, and recipient-manifest refresh.
//!
//! All three work offline: the outbox keeps queueing (it is the durable
//! state), and each loop retries with jittered backoff until the instance is
//! reachable again.

use super::core::Control;
use super::status::StatusTx;
use crate::backoff::Backoff;
use crate::client::{ClientError, InstanceClient};
use crate::state::Enrollment;
use faro_client::uplink::{self, EventsDrained, OutboxAccess, RefusedEvent, UplinkError};
use faro_core::clock::Clock;
use faro_core::outbox::PendingReport;
use faro_core::{ManifestDecision, Outbox, OutboxError, PrunePolicy, RecipientSet};
use faro_crypto::{ChainHead, SigningKey};
use faro_proto::api::{DeviceState, HeartbeatResponse};
use faro_proto::body::TamperSignal;
use faro_proto::SignedEvent;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

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

/// Uploads and heartbeats go through `faro_client::uplink`, shared with the
/// iOS core.
impl OutboxAccess for OutboxHandle {
    fn head(&self) -> impl Future<Output = Result<ChainHead, OutboxError>> + Send {
        self.run(|o| o.head())
    }
    fn pending(
        &self,
        limit: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<SignedEvent>, OutboxError>> + Send {
        self.run(move |o| o.pending_within(limit, max_bytes))
    }
    fn ack_through(&self, acked: u64) -> impl Future<Output = Result<u64, OutboxError>> + Send {
        self.run(move |o| o.ack_through(acked))
    }
    fn pending_reports(
        &self,
    ) -> impl Future<Output = Result<Vec<PendingReport>, OutboxError>> + Send {
        self.run(|o| o.pending_reports())
    }
    fn ack_report(&self, id: i64) -> impl Future<Output = Result<bool, OutboxError>> + Send {
        self.run(move |o| o.ack_report(id))
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
    /// Where an event the instance refused for good is reported, as a
    /// tamper signal (§3.7). `None` (the uninstaller): only logged.
    pub control: Option<mpsc::Sender<Control>>,
    /// Set by a `429`: no upload is tried before then.
    pub deferral: Deferral,
    /// The last event the instance refused for good.
    pub last_refused: Mutex<Option<RefusedEvent>>,
}

/// How long to wait after a `429` without a usable `Retry-After`.
const RATE_LIMITED_WAIT: Duration = Duration::from_secs(60);

/// Until when the instance asked us not to upload (`429`, `Retry-After`).
#[derive(Debug, Default)]
pub struct Deferral(Mutex<Option<Instant>>);

impl Deferral {
    /// Time left, if the instance asked us to wait.
    fn remaining(&self) -> Option<Duration> {
        let until = (*self.0.lock().unwrap_or_else(PoisonError::into_inner))?;
        let left = until.saturating_duration_since(Instant::now());
        (!left.is_zero()).then_some(left)
    }

    /// Remember a `429` answer, if `e` is one.
    fn note(&self, e: &ClientError) {
        if e.status() != Some(reqwest::StatusCode::TOO_MANY_REQUESTS) {
            return;
        }
        let wait = e.retry_after().unwrap_or(RATE_LIMITED_WAIT);
        tracing::info!(wait_secs = wait.as_secs(), "instance asked us to slow down");
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now() + wait);
    }
}

/// Why an upload pass stopped early.
#[derive(Debug)]
pub enum UploadStop {
    Client(ClientError),
    Outbox(OutboxError),
    /// The instance's identity no longer matches the pin.
    Gated,
    /// The instance answered `429`; this much of its wait is left.
    Deferred(Duration),
}

impl From<UplinkError> for UploadStop {
    fn from(e: UplinkError) -> Self {
        match e {
            UplinkError::Client(e) => UploadStop::Client(e),
            UplinkError::Outbox(e) => UploadStop::Outbox(e),
        }
    }
}

impl Uploader {
    /// Upload everything pending: events in `seq` order, then reports.
    pub async fn drain(&self) -> Result<(), UploadStop> {
        if !self.gate.is_open() {
            return Err(UploadStop::Gated);
        }
        if let Some(left) = self.deferral.remaining() {
            return Err(UploadStop::Deferred(left));
        }
        let r = match self.drain_events().await {
            Ok(()) => self.drain_reports().await,
            Err(e) => Err(e),
        };
        if let Err(UploadStop::Client(e)) = &r {
            self.deferral.note(e);
        }
        r
    }

    async fn drain_events(&self) -> Result<(), UploadStop> {
        let drained = uplink::drain_events(
            &self.client,
            &self.outbox,
            |acked| self.status.update(|s| s.acked_through = Some(acked)),
            |refused| self.refused(refused),
        )
        .await?;
        if let EventsDrained::AckBeyondHead { acked, .. } = drained {
            // The instance claims events this device never wrote: keep
            // everything and say so loudly (logged by `drain_events`).
            self.status.update(|s| {
                s.last_error = Some(format!(
                    "instance acknowledged seq {acked} beyond the local head"
                ));
            });
        }
        Ok(())
    }

    /// An event the instance will never take (logged by `drain_events`).
    /// When the instance raises no alert of its own for it (an oversized
    /// or malformed event), allies would otherwise see only the `chain_gap`
    /// the next event leaves, so it is reported as an `integrity_failure`
    /// naming the event's kind and the instance's reason.
    fn refused(&self, r: &RefusedEvent) {
        *self
            .last_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(r.clone());
        self.status.update(|s| {
            s.last_error = Some(format!(
                "the instance refused event {} ({}): {}",
                r.seq, r.kind, r.reason
            ));
        });
        if r.instance_alerted() {
            return;
        }
        let Some(control) = &self.control else {
            return;
        };
        let signal = TamperSignal::IntegrityFailure {
            component: format!(
                "upload: the instance refused a {} event ({})",
                r.kind, r.reason
            ),
        };
        if let Err(e) = control.try_send(Control::Tamper(signal)) {
            tracing::error!(error = %e, "cannot report the refused event");
        }
    }

    async fn drain_reports(&self) -> Result<(), UploadStop> {
        uplink::drain_reports(
            &self.client,
            &self.outbox,
            |_| self.status.update(|s| s.reports_uploaded += 1),
            |e| self.status.update(|s| s.last_error = Some(e.to_string())),
        )
        .await?;
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

/// A heartbeat failure that means the instance can't be reached. The
/// status menu shows it as "Can't reach …".
fn unreachable(e: &ClientError) -> bool {
    uplink::unreachable(e)
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
    /// Send one heartbeat. On success the instance's `acked_through` also
    /// prunes the outbox.
    pub async fn send(&self, state: DeviceState) -> Result<HeartbeatResponse, UploadStop> {
        if !self.gate.is_open() {
            return Err(UploadStop::Gated);
        }
        // A heartbeat says the device is recording. While it cannot commit
        // events it is not, and silence is what the instance alerts on.
        if self.status.read(|s| s.commit_failing) {
            tracing::error!(
                "not sending a heartbeat: the outbox has refused events for a long time"
            );
            return Err(UploadStop::Gated);
        }
        let answer = uplink::send_heartbeat(
            &self.client,
            &self.outbox,
            &self.key,
            &self.enrollment,
            self.clock.as_ref(),
            state,
        )
        .await;
        let now = self.clock.wall_ms();
        match &answer {
            Err(UplinkError::Client(e)) if unreachable(e) => self.status.update_if(|s| {
                let first = s.unreachable_since_ms.is_none();
                s.unreachable_since_ms.get_or_insert(now);
                first
            }),
            // An answer, even a refusal: the instance is there.
            Ok(_) | Err(UplinkError::Client(ClientError::Api { .. })) => self.status.update(|s| {
                s.last_contact_ms = Some(now);
                s.unreachable_since_ms = None;
            }),
            Err(_) => {}
        }
        let resp = answer?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: u16, retry_after: Option<Duration>) -> ClientError {
        ClientError::Api {
            status: reqwest::StatusCode::from_u16(status).unwrap(),
            code: "x".into(),
            message: String::new(),
            retry_after,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_429_defers_uploads_for_its_retry_after() {
        let d = Deferral::default();
        assert_eq!(d.remaining(), None);
        d.note(&api(503, Some(Duration::from_secs(30))));
        assert_eq!(d.remaining(), None, "only a 429 defers");
        d.note(&api(429, Some(Duration::from_secs(30))));
        assert_eq!(d.remaining(), Some(Duration::from_secs(30)));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(d.remaining(), None);
        d.note(&api(429, None));
        assert_eq!(d.remaining(), Some(RATE_LIMITED_WAIT));
    }
}
