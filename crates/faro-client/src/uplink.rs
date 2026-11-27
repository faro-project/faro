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
use faro_proto::{Hash32, SignedEvent};
use reqwest::StatusCode;
use std::future::Future;

/// Events per upload batch (the instance accepts up to 500).
pub const UPLOAD_BATCH: usize = 200;

/// The outbox operations uploads and heartbeats need.
pub trait OutboxAccess {
    /// The durable chain head.
    fn head(&self) -> impl Future<Output = Result<ChainHead, OutboxError>> + Send;
    /// Up to `limit` unacknowledged events, oldest first.
    fn pending(
        &self,
        limit: usize,
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
    /// Nothing is left, or the instance made no progress this pass (the
    /// oldest pending event keeps being refused, or it acknowledged
    /// nothing); the next pass tries again.
    Done,
    /// The instance acknowledged events this device never wrote. Everything
    /// is kept: the instance and the device disagree about the chain, which
    /// deserves attention rather than silent deletion.
    AckBeyondHead { acked: u64, next_seq: u64 },
}

/// Upload pending events in `seq` order, in batches of [`UPLOAD_BATCH`],
/// dropping each batch once the instance acknowledges it. `on_acked` is
/// told each new `acked_through`.
pub async fn drain_events<O: OutboxAccess>(
    client: &InstanceClient,
    outbox: &O,
    mut on_acked: impl FnMut(u64),
) -> Result<EventsDrained, UplinkError> {
    let mut last_acked: Option<u64> = None;
    loop {
        let pending = outbox
            .pending(UPLOAD_BATCH)
            .await
            .map_err(UplinkError::Outbox)?;
        let Some(first) = pending.first().map(|e| e.header.seq) else {
            return Ok(EventsDrained::Done);
        };
        let n = pending.len();
        let resp = client
            .post_events(&EventsBatchRequest { events: pending })
            .await
            .map_err(UplinkError::Client)?;
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
            return Ok(EventsDrained::Done);
        };
        match outbox.ack_through(acked).await {
            Ok(_) => {}
            Err(OutboxError::AckBeyondHead { acked, next_seq }) => {
                tracing::error!(
                    acked,
                    next_seq,
                    "instance acknowledged beyond our chain head"
                );
                return Ok(EventsDrained::AckBeyondHead { acked, next_seq });
            }
            Err(e) => return Err(UplinkError::Outbox(e)),
        }
        on_acked(acked);
        if last_acked.is_some_and(|l| l >= acked) || acked < first {
            // No progress (e.g. the oldest pending event keeps being
            // rejected); try again on the next pass instead of spinning.
            return Ok(EventsDrained::Done);
        }
        last_acked = Some(acked);
        if n < UPLOAD_BATCH {
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
