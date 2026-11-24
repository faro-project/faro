//! `POST /v1/events:batch`: the encrypted mailbox's front door (§3.6, §3.7, §5.4).
//!
//! For each event, **in order**, the instance checks it against the device's
//! verified chain head with [`faro_crypto::chain::verify_next`] (ids, body
//! commitments, device signature, then linkage) and decides:
//!
//! | Outcome | Stored? | Head moves? | Alert |
//! |---|---|---|---|
//! | Contiguous | yes | yes | only if urgency ≥ normal (source = device) |
//! | Gap (`seq` jumped) | yes | yes | urgent `chain_gap` + the above |
//! | Behind, identical header stored | no (`Duplicate`) | no | none |
//! | Behind, anything else | no (`Rejected`) | no | urgent `chain_gap` (conflicting rewrite) |
//! | Fork (`prev_hash` mismatch) | no (`Rejected`) | no | urgent `chain_gap` |
//! | Bad signature | no (`Rejected`) | no | urgent `invalid_signature` |
//! | Malformed / wrong ids | no (`Rejected`) | no | none |
//!
//! Alerts for rejected uploads carry a dedupe key, so a device retrying the
//! same bad event does not page its allies every minute.
//!
//! **Urgency floor.** The member controls the device, so a modified client
//! could sign a tamper event as `none`. The signed header is stored verbatim
//! (it must stay verifiable), and a separate `effective_urgency =
//! max(header.urgency, kind.min_urgency())` drives notifications.
//!
//! **Atomicity.** Each event is stored in its own transaction together with
//! its recipients, alerts and the chain-head update (a compare-and-set on the
//! previous head), so a crash never leaves a stored event without its head or
//! vice versa. Bodies go to the blob store first; if the transaction then
//! fails the blob is deleted (best effort; the stage-B retention worker
//! sweeps any orphan left by a crash).
//!
//! **`acked_through`** is the instance's verified head. After a gap the
//! missing range has been recorded as an alert and can never be filled (a
//! late event in it is `Behind`), so the device may prune up to the head.
//!
//! If an internal error interrupts a batch, that event and every later one
//! are answered `Rejected { reason: "retry_later" }` and nothing about them is
//! recorded, so the device simply retries from `acked_through + 1`.

use crate::blob::BlobId;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::devices::{self, DeviceRow};
use crate::db::repo::events::{self as ev_repo, BlobKind, NewEvent};
use crate::db::repo::liveness as liveness_repo;
use crate::db::to_i64;
use crate::device_auth::SignedJson;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use faro_crypto::chain::{verify_next, ChainError, ChainHead, Link};
use faro_proto::api::{EventResult, EventsBatchRequest, EventsBatchResponse, ServerAlertKind};
use faro_proto::{EventKind, SignedEvent, Urgency, UserId};

/// Events accepted per request.
pub const MAX_EVENTS_PER_BATCH: usize = 500;
/// Ciphertext bytes per event body (a blurred thumbnail is tens of KB).
pub const MAX_EVENT_BODY_BYTES: usize = 1024 * 1024;
/// Envelopes (recipients) per item: the member plus their allies.
pub const MAX_ENVELOPES: usize = 64;
/// Longest accepted `boot_id`.
pub const MAX_BOOT_ID_LEN: usize = 128;

const RETRY_LATER: &str = "retry_later";

/// `max(signed urgency, per-kind floor)`.
pub fn effective_urgency(ev: &SignedEvent) -> Urgency {
    ev.header.urgency.max(ev.header.kind.min_urgency())
}

fn rejected(seq: u64, reason: impl Into<String>) -> EventResult {
    EventResult::Rejected {
        seq,
        reason: reason.into(),
    }
}

/// The device's verified chain head, or genesis.
fn head_of(state: &AppState, dev: &DeviceRow) -> Result<ChainHead, AppError> {
    match (dev.last_seq, dev.last_hash) {
        (None, _) => Ok(ChainHead::genesis(state.instance_id(), &dev.id)),
        (Some(seq), Some(hash)) => Ok(ChainHead {
            next_seq: seq
                .checked_add(1)
                .ok_or_else(|| AppError::internal("chain head overflow"))?,
            prev_hash: hash,
        }),
        (Some(_), None) => Err(AppError::internal("device chain head is inconsistent")),
    }
}

/// `POST /v1/events:batch`
pub async fn post_batch(
    State(state): State<AppState>,
    SignedJson { device, body }: SignedJson<EventsBatchRequest>,
) -> AppResult<Json<EventsBatchResponse>> {
    if body.events.len() > MAX_EVENTS_PER_BATCH {
        return Err(AppError::bad_request(
            "batch_too_large",
            format!("at most {MAX_EVENTS_PER_BATCH} events per batch"),
        ));
    }
    // One ingest at a time per device in this process, and a fresh read of
    // the head under the lock.
    let _guard = state.lock_device(device.id().as_str()).await;
    let dev = devices::by_id(state.db().pool(), device.id())
        .await?
        .ok_or(AppError::Unauthorized)?;
    let mut head = head_of(&state, &dev)?;
    let mut last_seq = dev.last_seq;

    let mut results = Vec::with_capacity(body.events.len());
    let mut halted = false;
    for ev in body.events {
        let seq = ev.header.seq;
        if halted {
            results.push(rejected(seq, RETRY_LATER));
            continue;
        }
        match ingest_one(&state, &dev, &mut head, &mut last_seq, ev).await {
            Ok(r) => results.push(r),
            Err(e) => {
                tracing::error!(device = %dev.id, seq, error = %e, "event ingest failed");
                halted = true;
                results.push(rejected(seq, RETRY_LATER));
            }
        }
    }
    Ok(Json(EventsBatchResponse {
        results,
        acked_through: last_seq,
    }))
}

/// Process one event. `Err` means an internal failure (nothing was recorded).
async fn ingest_one(
    state: &AppState,
    dev: &DeviceRow,
    head: &mut ChainHead,
    last_seq: &mut Option<u64>,
    ev: SignedEvent,
) -> Result<EventResult, AppError> {
    let seq = ev.header.seq;
    if to_i64(seq).is_none() {
        return Ok(rejected(seq, "seq_out_of_range"));
    }
    if ev.header.boot_id.len() > MAX_BOOT_ID_LEN {
        return Ok(rejected(seq, "malformed: boot_id too long"));
    }
    if let Some(body) = &ev.body {
        if body.ciphertext.len() > MAX_EVENT_BODY_BYTES {
            return Ok(rejected(seq, "body_too_large"));
        }
        if body.envelopes.is_empty() || body.envelopes.len() > MAX_ENVELOPES {
            return Ok(rejected(seq, "malformed: bad envelope count"));
        }
    }

    let member = &dev.owner_user_id;
    let verdict = verify_next(
        head,
        state.instance_id(),
        &dev.id,
        &dev.sign_pubkey,
        &ev,
        true,
    );
    match verdict {
        Ok(link) => {
            store_event(state, dev, *last_seq, &ev, link).await?;
            head.advance(&ev.header);
            *last_seq = Some(seq);
            Ok(EventResult::Accepted { seq })
        }
        Err(ChainError::Behind { .. }) => {
            match ev_repo::stored_header_hash(state.db().pool(), &dev.id, seq).await? {
                Some(h) if h == ev.header.chain_hash() => Ok(EventResult::Duplicate { seq }),
                stored => {
                    let detail = if stored.is_some() {
                        "conflicting_rewrite"
                    } else {
                        "late_event_in_recorded_gap"
                    };
                    server_alert(
                        state,
                        member,
                        dev,
                        ServerAlertKind::ChainGap,
                        seq,
                        detail,
                        format!("behind:{}:{seq}", dev.id),
                    )
                    .await?;
                    Ok(rejected(seq, detail))
                }
            }
        }
        Err(ChainError::Fork { .. }) => {
            server_alert(
                state,
                member,
                dev,
                ServerAlertKind::ChainGap,
                seq,
                "fork",
                format!("fork:{}:{seq}", dev.id),
            )
            .await?;
            Ok(rejected(seq, "fork"))
        }
        Err(ChainError::BadSignature) => {
            server_alert(
                state,
                member,
                dev,
                ServerAlertKind::InvalidSignature,
                seq,
                "bad_event_signature",
                format!("badsig:{}:{seq}", dev.id),
            )
            .await?;
            Ok(rejected(seq, "bad_signature"))
        }
        Err(ChainError::WrongInstance) => Ok(rejected(seq, "wrong_instance")),
        Err(ChainError::WrongDevice) => Ok(rejected(seq, "wrong_device")),
        Err(ChainError::Shape(e)) => Ok(rejected(seq, format!("malformed: {e}"))),
    }
}

/// Record a server-raised alert about a rejected upload (deduplicated).
async fn server_alert(
    state: &AppState,
    member: &UserId,
    dev: &DeviceRow,
    kind: ServerAlertKind,
    seq: u64,
    detail: &str,
    dedupe_key: String,
) -> Result<(), AppError> {
    let created = alerts::insert(
        state.db().pool(),
        &NewAlert {
            member_id: member,
            device_id: Some(&dev.id),
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: kind.urgency(),
            event_seq: to_i64(seq),
            detail: Some(detail.to_owned()),
            dedupe_key: Some(dedupe_key),
            now_ms: state.now_ms(),
        },
    )
    .await?;
    if created {
        tracing::warn!(device = %dev.id, seq, kind = kind.as_str(), detail, "chain alert raised");
    }
    Ok(())
}

/// Store an authenticated, linked event with its blob, recipients, alerts and
/// the new chain head, atomically.
async fn store_event(
    state: &AppState,
    dev: &DeviceRow,
    expected_last_seq: Option<u64>,
    ev: &SignedEvent,
    link: Link,
) -> Result<(), AppError> {
    let h = &ev.header;
    let now = state.now_ms();
    let member = &dev.owner_user_id;

    // Ciphertext (plus wrapped keys) to the blob store first.
    let blob = match &ev.body {
        Some(body) => {
            let bytes = serde_json::to_vec(body)
                .map_err(|_| AppError::internal("cannot serialize event body"))?;
            let id = BlobId::new_random();
            let size = bytes.len();
            state.blobs().put(&id, bytes).await?;
            Some((id, size))
        }
        None => None,
    };

    let result = async {
        let header_json =
            serde_json::to_string(h).map_err(|_| AppError::internal("cannot serialize header"))?;
        let header_hash = h.chain_hash();
        let effective = effective_urgency(ev);
        let mut tx = state.db().begin_write().await?;
        if let Some((id, size)) = &blob {
            ev_repo::insert_blob(&mut *tx, id, BlobKind::EventBody, member, *size, now).await?;
        }
        ev_repo::insert_event(
            &mut *tx,
            &NewEvent {
                device_id: &dev.id,
                member_id: member,
                seq: h.seq,
                ts_ms: h.ts_ms,
                kind: h.kind.as_str(),
                urgency: h.urgency.as_str(),
                effective_urgency: effective.as_str(),
                header_json: &header_json,
                header_hash: &header_hash,
                sig_b64: &ev.sig.to_b64(),
                blob_id: blob.as_ref().map(|(id, _)| id),
                received_at_ms: now,
            },
        )
        .await?;
        if let Some(body) = &ev.body {
            for env in &body.envelopes {
                // Recipients are device-declared routing hints for the feed,
                // not access control; skip anything that is not an id.
                if env.recipient.is_well_formed() && env.key_id.len() <= 64 {
                    ev_repo::insert_recipient(
                        &mut *tx,
                        &dev.id,
                        h.seq,
                        &env.recipient,
                        &env.key_id,
                    )
                    .await?;
                }
            }
        }
        let seq_i64 = to_i64(h.seq);
        if let Link::Gap {
            missing_from,
            missing_to,
        } = link
        {
            let kind = ServerAlertKind::ChainGap;
            alerts::insert(
                &mut *tx,
                &NewAlert {
                    member_id: member,
                    device_id: Some(&dev.id),
                    source: AlertSource::Server,
                    kind: kind.as_str(),
                    urgency: kind.urgency(),
                    event_seq: seq_i64,
                    detail: Some(format!("missing {missing_from}..={missing_to}")),
                    dedupe_key: Some(format!("gap:{}:{missing_from}", dev.id)),
                    now_ms: now,
                },
            )
            .await?;
            tracing::warn!(device = %dev.id, missing_from, missing_to, "chain gap");
        }
        if effective >= Urgency::Normal {
            alerts::insert(
                &mut *tx,
                &NewAlert {
                    member_id: member,
                    device_id: Some(&dev.id),
                    source: AlertSource::Device,
                    kind: h.kind.as_str(),
                    urgency: effective,
                    event_seq: seq_i64,
                    detail: None,
                    dedupe_key: Some(format!("event:{}:{}", dev.id, h.seq)),
                    now_ms: now,
                },
            )
            .await?;
        }
        // An accepted goodbye retires the device for the liveness monitor:
        // the goodbye is itself the urgent alert, so its silence afterwards
        // is not reported again, and an episode it left open is closed.
        let goodbye = (h.kind == EventKind::Goodbye).then_some(now);
        if goodbye.is_some() {
            liveness_repo::close_open_episode(&mut tx, &dev.id, now).await?;
        }
        // Compare-and-set the head: if another process advanced it since we
        // verified, abort and let the device retry.
        if !devices::advance_head(
            &mut *tx,
            &dev.id,
            expected_last_seq,
            h.seq,
            &header_hash,
            goodbye,
        )
        .await?
        {
            return Err(AppError::Unavailable("chain_head_moved"));
        }
        tx.commit().await?;
        Ok(())
    }
    .await;

    if result.is_err() {
        if let Some((id, _)) = &blob {
            if let Err(e) = state.blobs().delete(id).await {
                tracing::warn!(error = %e, "could not delete orphaned event blob");
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::{genesis_hash, DeviceId, EventHeader, EventKind, Hash32, InstanceId};

    fn ev(kind: EventKind, urgency: Urgency) -> SignedEvent {
        let i = InstanceId::new("inst_x");
        let d = DeviceId::new("dev_x");
        SignedEvent {
            header: EventHeader {
                v: 1,
                prev_hash: genesis_hash(&i, &d),
                instance_id: i,
                device_id: d,
                seq: 0,
                ts_ms: 0,
                mono_ms: 0,
                boot_id: "b".into(),
                kind,
                urgency,
                body_hash: Hash32::ZERO,
                body_len: 0,
            },
            sig: faro_proto::Signature([0; 64]),
            body: None,
        }
    }

    #[test]
    fn urgency_is_floored_never_lowered() {
        for kind in EventKind::ALL {
            for u in [Urgency::None, Urgency::Normal, Urgency::Urgent] {
                let eff = effective_urgency(&ev(kind, u));
                assert!(eff >= u, "{kind} {u}");
                assert!(eff >= kind.min_urgency(), "{kind} {u}");
                assert_eq!(eff, u.max(kind.min_urgency()));
            }
        }
        assert_eq!(
            effective_urgency(&ev(EventKind::Tamper, Urgency::None)),
            Urgency::Urgent
        );
        assert_eq!(
            effective_urgency(&ev(EventKind::Flag, Urgency::Urgent)),
            Urgency::Urgent
        );
    }
}
