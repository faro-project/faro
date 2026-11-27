//! Uploading the outbox and sending heartbeats (PROTOCOL.md §3, §7), the
//! parts every platform shares.
//!
//! How the outbox is reached is the platform's business: the desktop
//! service shares one connection between its tasks on Tokio's blocking
//! pool, the iOS core opens the app group's database from whichever process
//! runs. Both implement [`OutboxAccess`], and both upload and send
//! heartbeats through the functions here, so the batching, the
//! acknowledgement rules and the heartbeat's chain fields are the same
//! everywhere.

use crate::client::{ClientError, InstanceClient, ReportAccepted};
use crate::enroll::Enrollment;
use faro_core::outbox::PendingReport;
use faro_core::{Clock, OutboxError};
use faro_crypto::{ChainHead, SigningKey};
use faro_proto::api::{DeviceState, EventResult, EventsBatchRequest, Heartbeat, HeartbeatResponse};
use faro_proto::{EventKind, Hash32, SignedEvent};
use reqwest::StatusCode;
use std::future::Future;

/// Events per upload batch (the instance accepts up to 500).
pub const UPLOAD_BATCH: usize = 200;
/// Stored event bytes per upload batch. The instance reads at most 8 MiB
/// per batch request; half leaves room for the request's own framing.
pub const UPLOAD_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// The reason the instance gives for "try this event again later".
const RETRY_LATER: &str = "retry_later";
/// Longest refusal reason kept from the instance's answer.
const MAX_REASON: usize = 64;

/// The outbox operations uploads and heartbeats need.
pub trait OutboxAccess {
    /// The durable chain head.
    fn head(&self) -> impl Future<Output = Result<ChainHead, OutboxError>> + Send;
    /// Up to `limit` unacknowledged events, oldest first, adding up to at
    /// most `max_bytes` of stored JSON (but always at least the oldest
    /// one; `faro_core::Outbox::pending_within`).
    fn pending(
        &self,
        limit: usize,
        max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<SignedEvent>, OutboxError>> + Send;
    /// Drop events the instance holds (`seq <= acked`).
    fn ack_through(&self, acked: u64) -> impl Future<Output = Result<u64, OutboxError>> + Send;
    /// Reports awaiting upload, oldest first.
    fn pending_reports(
        &self,
    ) -> impl Future<Output = Result<Vec<PendingReport>, OutboxError>> + Send;
    /// Remove an uploaded (or permanently refused) report.
    fn ack_report(&self, id: i64) -> impl Future<Output = Result<bool, OutboxError>> + Send;
}

/// Why an upload or a heartbeat stopped.
#[derive(Debug, thiserror::Error)]
pub enum UplinkError {
    #[error(transparent)]
    Client(ClientError),
    #[error(transparent)]
    Outbox(OutboxError),
}

/// How [`drain_events`] ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventsDrained {
    /// Nothing is left, or the instance made no progress this pass (it
    /// asked to retry the oldest pending event later); the next pass tries
    /// again.
    Done,
    /// The instance acknowledged events this device never wrote. Everything
    /// is kept: the instance and the device disagree about the chain, which
    /// deserves attention rather than silent deletion.
    AckBeyondHead { acked: u64, next_seq: u64 },
}

/// An event the instance refused for good: it answered `rejected` with a
/// reason other than `retry_later`, so the same bytes will never be
/// accepted. [`drain_events`] drops it from the outbox once the caller has
/// been told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedEvent {
    pub seq: u64,
    pub kind: EventKind,
    /// The instance's reason, cut to its first word (`body_too_large`,
    /// `malformed`, `fork`, ...), at most 64 characters, no control
    /// characters: it comes from the instance.
    pub reason: String,
}

impl RefusedEvent {
    fn new(seq: u64, kind: EventKind, reason: &str) -> Self {
        let word = reason.split(':').next().unwrap_or_default();
        let reason: String = word
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_REASON)
            .collect();
        RefusedEvent { seq, kind, reason }
    }

    /// Whether the instance raises its own alert for this refusal (a fork,
    /// a bad signature, or a rewrite of an event it already holds,
    /// PROTOCOL.md §3.2). Otherwise (an oversized or malformed event) the
    /// device is the only one that can tell anybody: the instance stores
    /// the next event as a gap, and allies get a bare `chain_gap`.
    pub fn instance_alerted(&self) -> bool {
        matches!(
            self.reason.as_str(),
            "fork" | "bad_signature" | "conflicting_rewrite" | "late_event_in_recorded_gap"
        )
    }
}

/// Upload pending events in `seq` order, in batches of at most
/// [`UPLOAD_BATCH`] events and [`UPLOAD_BATCH_BYTES`].
///
/// The instance answers each event of a batch in order. Events it
/// `accepted` or already holds (`duplicate`) are dropped from the outbox.
/// One it refused for good is handed to `on_refused` and then dropped too,
/// so it can't hold up every later one. Everything from the first
/// `retry_later` (or an answer that doesn't match the batch) on is kept
/// for the next pass. The instance's `acked_through` doesn't decide what
/// is deleted: after a refused event it counts the gap as held. `on_acked`
/// is told each `acked_through` (the instance's head, for the status).
///
/// A `413` halves the batch and tries again. A `413` for one event alone,
/// and any other error (a `429` with its `Retry-After`, among them), ends
/// the pass with everything kept.
pub async fn drain_events<O: OutboxAccess>(
    client: &InstanceClient,
    outbox: &O,
    mut on_acked: impl FnMut(u64),
    mut on_refused: impl FnMut(&RefusedEvent),
) -> Result<EventsDrained, UplinkError> {
    let mut limit = UPLOAD_BATCH;
    loop {
        let pending = outbox
            .pending(limit, UPLOAD_BATCH_BYTES)
            .await
            .map_err(UplinkError::Outbox)?;
        let Some(first) = pending.first().map(|e| e.header.seq) else {
            return Ok(EventsDrained::Done);
        };
        let n = pending.len();
        let sent: Vec<(u64, EventKind)> = pending
            .iter()
            .map(|e| (e.header.seq, e.header.kind))
            .collect();
        let resp = match client
            .post_events(&EventsBatchRequest { events: pending })
            .await
        {
            Ok(r) => r,
            Err(e) if e.status() == Some(StatusCode::PAYLOAD_TOO_LARGE) && n > 1 => {
                limit = n / 2;
                tracing::warn!(
                    n,
                    limit,
                    "instance refused the batch as too large; halving it"
                );
                continue;
            }
            Err(e) => {
                if e.status() == Some(StatusCode::PAYLOAD_TOO_LARGE) {
                    tracing::error!(
                        seq = first,
                        kind = %sent[0].1,
                        "instance refuses this event alone as too large; it stays queued"
                    );
                }
                return Err(UplinkError::Client(e));
            }
        };
        if let Some(acked) = resp.acked_through {
            let head = outbox.head().await.map_err(UplinkError::Outbox)?;
            if acked >= head.next_seq {
                tracing::error!(
                    acked,
                    next_seq = head.next_seq,
                    "instance acknowledged beyond our chain head"
                );
                return Ok(EventsDrained::AckBeyondHead {
                    acked,
                    next_seq: head.next_seq,
                });
            }
        }
        // The leading run of events the instance settled, in batch order.
        let mut settled: Option<u64> = None;
        for (i, &(seq, kind)) in sent.iter().enumerate() {
            match resp.results.get(i) {
                Some(EventResult::Accepted { seq: s } | EventResult::Duplicate { seq: s })
                    if *s == seq =>
                {
                    settled = Some(seq);
                }
                Some(EventResult::Rejected { seq: s, reason })
                    if *s == seq && reason != RETRY_LATER =>
                {
                    let refused = RefusedEvent::new(seq, kind, reason);
                    tracing::error!(
                        seq,
                        kind = %kind,
                        reason = %refused.reason,
                        "instance refused an event for good; dropping it from the outbox"
                    );
                    on_refused(&refused);
                    settled = Some(seq);
                }
                Some(EventResult::Rejected { seq: s, .. }) if *s == seq => break,
                _ => {
                    tracing::warn!(
                        seq,
                        "instance's answers do not match the batch; keeping the rest"
                    );
                    break;
                }
            }
        }
        if let Some(acked) = resp.acked_through {
            on_acked(acked);
        }
        let Some(through) = settled else {
            tracing::info!(first, n, "instance settled nothing; will retry later");
            return Ok(EventsDrained::Done);
        };
        // The batch starts at the oldest pending event, so this drops
        // exactly the settled run.
        outbox
            .ack_through(through)
            .await
            .map_err(UplinkError::Outbox)?;
        // Each round drops at least one event, so this ends.
        if sent.last().is_none_or(|&(last, _)| last != through) {
            return Ok(EventsDrained::Done);
        }
    }
}

/// Upload pending reports, oldest first. A report the instance will never
/// accept ([`is_permanent_report_error`]) is dropped, so it can't block
/// every later one, and `on_dropped` is told why.
pub async fn drain_reports<O: OutboxAccess>(
    client: &InstanceClient,
    outbox: &O,
    mut on_uploaded: impl FnMut(&ReportAccepted),
    mut on_dropped: impl FnMut(&ClientError),
) -> Result<(), UplinkError> {
    let reports = outbox
        .pending_reports()
        .await
        .map_err(UplinkError::Outbox)?;
    for r in reports {
        match client.post_report(&r.upload).await {
            Ok(acc) => {
                outbox.ack_report(r.id).await.map_err(UplinkError::Outbox)?;
                on_uploaded(&acc);
                tracing::info!(report = %acc.report_id, duplicate = acc.duplicate, "report uploaded");
            }
            Err(e) if is_permanent_report_error(&e) => {
                tracing::error!(error = %e, period_start = r.upload.header.period_start_ms,
                    "instance permanently rejected a report; dropping it");
                outbox.ack_report(r.id).await.map_err(UplinkError::Outbox)?;
                on_dropped(&e);
            }
            Err(e) => return Err(UplinkError::Client(e)),
        }
    }
    Ok(())
}

/// A heartbeat failure that means the instance can't be reached: no
/// answer at all, or a server error (a proxy in front of a stopped
/// instance answers 502).
pub fn unreachable(e: &ClientError) -> bool {
    match e {
        ClientError::Transport(_) => true,
        ClientError::Api { status, .. } => status.is_server_error(),
        _ => false,
    }
}

/// The instance will never accept this report.
pub fn is_permanent_report_error(e: &ClientError) -> bool {
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

/// The heartbeat for `state` (PROTOCOL.md §7). `last_seq` and `last_hash`
/// name the newest committed event: the outbox head's `prev_hash` *is* the
/// chain hash of the event at `next_seq - 1`, which the instance compares
/// with what it holds to detect forks. `ts_ms` is the request clock
/// ([`InstanceClient::corrected_wall_ms`]).
pub fn heartbeat(
    enrollment: &Enrollment,
    head: ChainHead,
    ts_ms: i64,
    clock: &dyn Clock,
    state: DeviceState,
) -> Heartbeat {
    let (last_seq, last_hash): (Option<u64>, Option<Hash32>) = match head.next_seq {
        0 => (None, None),
        n => (Some(n - 1), Some(head.prev_hash)),
    };
    Heartbeat {
        instance_id: enrollment.instance_id.clone(),
        device_id: enrollment.device_id.clone(),
        ts_ms,
        mono_ms: clock.mono_ms(),
        boot_id: clock.boot_id(),
        state,
        last_seq,
        last_hash,
    }
}

/// Build, sign and send one heartbeat. On success the instance's
/// `acked_through` also prunes the outbox. The caller sees the client
/// error, if any, to judge reachability ([`unreachable`]).
pub async fn send_heartbeat<O: OutboxAccess>(
    client: &InstanceClient,
    outbox: &O,
    key: &SigningKey,
    enrollment: &Enrollment,
    clock: &dyn Clock,
    state: DeviceState,
) -> Result<HeartbeatResponse, UplinkError> {
    let head = outbox.head().await.map_err(UplinkError::Outbox)?;
    let hb = heartbeat(enrollment, head, client.corrected_wall_ms(), clock, state);
    let signed = key.sign_heartbeat(hb);
    let resp = client
        .heartbeat(&signed)
        .await
        .map_err(UplinkError::Client)?;
    if let Some(acked) = resp.acked_through {
        match outbox.ack_through(acked).await {
            Ok(_) | Err(OutboxError::AckBeyondHead { .. }) => {}
            Err(e) => tracing::warn!(error = %e, "ack from heartbeat failed"),
        }
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: u16) -> ClientError {
        ClientError::Api {
            status: StatusCode::from_u16(status).unwrap(),
            code: "x".into(),
            message: "y".into(),
            retry_after: None,
        }
    }

    #[test]
    fn server_errors_are_unreachable_and_refusals_are_not() {
        assert!(unreachable(&api(502)));
        assert!(unreachable(&api(503)));
        assert!(!unreachable(&api(403)));
        assert!(!unreachable(&api(401)));
        assert!(!unreachable(&ClientError::NoCredentials));
    }

    #[test]
    fn permanent_report_errors() {
        assert!(is_permanent_report_error(&api(400)));
        assert!(is_permanent_report_error(&api(409)));
        assert!(is_permanent_report_error(&api(413)));
        assert!(is_permanent_report_error(&api(422)));
        assert!(!is_permanent_report_error(&api(503)));
        assert!(!is_permanent_report_error(&api(401)));
    }
}
