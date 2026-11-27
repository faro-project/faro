//! `POST /v1/reports`: encrypted daily/weekly reports (§6).
//!
//! Reports are built and encrypted **on the device**; the instance stores the
//! ciphertext (with its per-recipient envelopes) as an opaque blob and keeps
//! only the device-signed [`ReportHeader`] as metadata: which member and
//! device, which period, which chain range, and the body commitment.
//!
//! Checks, in order: header version and ids (the header must name this
//! instance, the authenticated device and that device's owner), period and
//! seq-range sanity, body commitment (`BLAKE3(nonce || ciphertext)` and
//! length), size limits, then the device signature over the header.
//!
//! Uploads are idempotent: re-sending the same signed header returns the
//! existing report id with `duplicate: true`, so a device that lost the
//! response can safely retry.
//!
//! A header that fails signature verification on an otherwise authenticated
//! request is suspicious (the transport was signed by the device key, the
//! report was not), so it raises a deduplicated urgent `invalid_signature`
//! alert as well as being rejected.

use crate::api::events::MAX_ENVELOPES;
use crate::blob::BlobId;
use crate::db::repo::alerts::{AlertSource, NewAlert};
use crate::db::repo::events::{self as ev_repo, BlobKind};
use crate::db::repo::is_unique_violation;
use crate::db::repo::reports::{self, NewReport};
use crate::db::to_i64;
use crate::device_auth::{AuthedDevice, SignedJson};
use crate::device_limits;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::tokens::new_hex_id;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use faro_proto::api::ServerAlertKind;
use faro_proto::report::{ReportHeader, ReportUpload, REPORT_HEADER_VERSION};
use faro_proto::{EncryptedItem, Hash32};
use serde::{Deserialize, Serialize};

/// Ciphertext bytes per report. Daily reports are 20-200 KB (§4.2); a week
/// with many flagged blurred thumbnails stays well below this.
pub const MAX_REPORT_BODY_BYTES: usize = 6 * 1024 * 1024;
/// Longest period one report may cover (weekly reports plus slack).
pub const MAX_REPORT_PERIOD_MS: i64 = 8 * 24 * 3600 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportAccepted {
    pub report_id: String,
    /// True if this exact signed report was already stored.
    pub duplicate: bool,
}

fn bad(code: &'static str, msg: &str) -> AppError {
    AppError::bad_request(code, msg)
}

/// Every check that needs no key.
fn check_shape(state: &AppState, device: &AuthedDevice, up: &ReportUpload) -> AppResult<()> {
    let h = &up.header;
    let row = device.row();
    if h.v != REPORT_HEADER_VERSION {
        return Err(bad(
            "unsupported_version",
            "unsupported report header version",
        ));
    }
    if &h.instance_id != state.instance_id()
        || h.device_id != row.id
        || h.member_id != row.owner_user_id
    {
        return Err(bad(
            "report_mismatch",
            "report must name this instance, the authenticated device and its member",
        ));
    }
    if h.period_end_ms < h.period_start_ms
        || h.period_end_ms - h.period_start_ms > MAX_REPORT_PERIOD_MS
    {
        return Err(bad("invalid_period", "report period is invalid"));
    }
    match (h.first_seq, h.last_seq) {
        (None, None) => {}
        (Some(a), Some(b)) if a <= b && to_i64(b).is_some() => {}
        _ => {
            return Err(bad(
                "invalid_seq_range",
                "first_seq/last_seq are inconsistent",
            ))
        }
    }
    check_body(h, &up.body)
}

fn check_body(h: &ReportHeader, body: &EncryptedItem) -> AppResult<()> {
    if body.alg != EncryptedItem::ALG {
        return Err(bad("unsupported_alg", "unsupported body algorithm"));
    }
    if body.ciphertext.len() > MAX_REPORT_BODY_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    if body.envelopes.is_empty() || body.envelopes.len() > MAX_ENVELOPES {
        return Err(bad("invalid_envelopes", "bad envelope count"));
    }
    if body.body_hash() != h.body_hash || body.ciphertext.len() as u64 != h.body_len {
        return Err(bad(
            "body_mismatch",
            "body_hash/body_len do not match the body",
        ));
    }
    Ok(())
}

/// `POST /v1/reports`
pub async fn post(
    State(state): State<AppState>,
    SignedJson { device, body: up }: SignedJson<ReportUpload>,
) -> AppResult<(StatusCode, Json<ReportAccepted>)> {
    device_limits::check_report(&state, device.row())?;
    check_shape(&state, &device, &up)?;
    let h = &up.header;
    let header_hash = Hash32::of(&h.signing_bytes());
    let row = device.row();

    if faro_crypto::verify_item(&row.sign_pubkey, h, &up.sig).is_err() {
        let kind = ServerAlertKind::InvalidSignature;
        let mut conn = state.db().pool().acquire().await?;
        device_limits::raise(
            &state,
            &mut conn,
            &NewAlert {
                member_id: &row.owner_user_id,
                device_id: Some(&row.id),
                source: AlertSource::Server,
                kind: kind.as_str(),
                urgency: kind.urgency(),
                event_seq: None,
                detail: Some("bad_report_signature".to_owned()),
                dedupe_key: Some(device_limits::interval_key(
                    &state,
                    "report-badsig",
                    &row.id,
                )),
                now_ms: state.now_ms(),
            },
        )
        .await?;
        tracing::warn!(device = %row.id, "report with invalid signature rejected");
        return Err(bad(
            "bad_signature",
            "report is not signed by this device's key",
        ));
    }

    if let Some(id) = reports::find_by_header(state.db().pool(), &row.id, &header_hash).await? {
        return Ok((
            StatusCode::OK,
            Json(ReportAccepted {
                report_id: id,
                duplicate: true,
            }),
        ));
    }

    if let Some(limit) = device_limits::quota_bytes(&state) {
        let used = ev_repo::device_stored_bytes(state.db().pool(), &row.id).await?;
        if used.saturating_add(up.body.ciphertext.len() as u64) > limit {
            crate::api::events::quota_alert(&state, row, "report").await?;
            return Err(AppError::QuotaExceeded);
        }
    }
    let bytes = serde_json::to_vec(&up.body)
        .map_err(|_| AppError::internal("cannot serialize report body"))?;
    let size = bytes.len();
    let blob_id = BlobId::new_random();
    state.blobs().put(&blob_id, bytes).await?;

    let report_id = new_hex_id();
    let stored = store(&state, &up, &report_id, &header_hash, &blob_id, size).await;
    match stored {
        Ok(()) => {
            tracing::info!(device = %row.id, report = %report_id, "report stored");
            Ok((
                StatusCode::CREATED,
                Json(ReportAccepted {
                    report_id,
                    duplicate: false,
                }),
            ))
        }
        Err(e) => {
            if let Err(de) = state.blobs().delete(&blob_id).await {
                tracing::warn!(error = %de, "could not delete orphaned report blob");
            }
            // Lost a race with a concurrent upload of the same report.
            if matches!(&e, AppError::Db(db) if is_unique_violation(db)) {
                if let Some(id) =
                    reports::find_by_header(state.db().pool(), &row.id, &header_hash).await?
                {
                    return Ok((
                        StatusCode::OK,
                        Json(ReportAccepted {
                            report_id: id,
                            duplicate: true,
                        }),
                    ));
                }
            }
            Err(e)
        }
    }
}

async fn store(
    state: &AppState,
    up: &ReportUpload,
    report_id: &str,
    header_hash: &Hash32,
    blob_id: &BlobId,
    size: usize,
) -> AppResult<()> {
    let h = &up.header;
    let now = state.now_ms();
    let header_json =
        serde_json::to_string(h).map_err(|_| AppError::internal("cannot serialize header"))?;
    let mut tx = state.db().begin_write().await?;
    ev_repo::insert_blob(&mut *tx, blob_id, BlobKind::Report, &h.member_id, size, now).await?;
    reports::insert(
        &mut *tx,
        &NewReport {
            id: report_id,
            member_id: &h.member_id,
            device_id: &h.device_id,
            period_start_ms: h.period_start_ms,
            period_end_ms: h.period_end_ms,
            first_seq: h.first_seq.and_then(to_i64),
            last_seq: h.last_seq.and_then(to_i64),
            header_json: &header_json,
            header_hash,
            sig_b64: &up.sig.to_b64(),
            blob_id,
            received_at_ms: now,
        },
    )
    .await?;
    for env in &up.body.envelopes {
        // Device-declared routing hints, not access control (see events).
        if env.recipient.is_well_formed() && env.key_id.len() <= 64 {
            reports::insert_recipient(&mut *tx, report_id, &env.recipient, &env.key_id).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
