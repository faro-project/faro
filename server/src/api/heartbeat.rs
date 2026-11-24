//! `POST /v1/heartbeat`: signed liveness pings (§3.7, §4.2).
//!
//! Heartbeats are deliberately *not* chain events (288 a day would bloat the
//! chain). The request is device-authenticated like every other device call,
//! and the [`Heartbeat`] payload carries its own device signature so the
//! stored liveness state ("asleep", "shutting down", last chain position) is
//! attributable to the device key rather than to whoever held the transport.
//!
//! The instance records **its own** receive time as `last_seen_at`; the
//! device's wall clock is never trusted for liveness. The liveness monitor
//! reads `last_seen_at`, `last_state` and the signed chain position:
//!
//! * `last_seq` ahead of the verified head starts `upload_behind_since`; if
//!   the head does not catch up within the grace period, the monitor raises
//!   an urgent `chain_gap` (`upload_stalled`, [`crate::liveness`]);
//! * `last_seq`/`last_hash` naming a position the instance already holds,
//!   with a different hash, means the device's chain is not the one it
//!   uploaded: an urgent `chain_gap` (`heartbeat_fork`) at once.
//!
//! Each heartbeat also closes the device's open missed-check-in episode, if
//! any ([`crate::liveness::check_in`]).
//!
//! Pending (not yet endorsed) devices may heartbeat: the member can then see
//! that a freshly enrolled device is alive while it waits for endorsement.

use crate::api::events::MAX_BOOT_ID_LEN;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::devices::{self, HeartbeatUpdate};
use crate::db::repo::events as ev_repo;
use crate::db::to_i64;
use crate::device_auth::SignedJson;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use faro_proto::api::{
    Heartbeat, HeartbeatResponse, ServerAlertKind, SignedHeartbeat, REQUEST_MAX_SKEW_MS,
};

/// Suggested interval between heartbeats (288 a day, §4.2).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 300;

fn valid_boot_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_BOOT_ID_LEN && !s.chars().any(char::is_control)
}

/// Structural checks that need no keys.
fn check_heartbeat(
    state: &AppState,
    device: &faro_proto::DeviceId,
    hb: &Heartbeat,
) -> AppResult<()> {
    if &hb.instance_id != state.instance_id() || &hb.device_id != device {
        return Err(AppError::bad_request(
            "heartbeat_mismatch",
            "heartbeat must name this instance and the authenticated device",
        ));
    }
    if !valid_boot_id(&hb.boot_id) {
        return Err(AppError::bad_request(
            "invalid_boot_id",
            "boot_id is malformed",
        ));
    }
    // The signed heartbeat time must be as fresh as the request itself, so an
    // old signed "sleeping" heartbeat cannot be replayed (by a device that
    // kept it) to explain away a later silence.
    if (hb.ts_ms - state.now_ms()).abs() > REQUEST_MAX_SKEW_MS {
        return Err(AppError::bad_request(
            "stale_heartbeat",
            "heartbeat timestamp is too far from server time",
        ));
    }
    Ok(())
}

/// If the heartbeat names a chain position the instance already holds, its
/// hash must be the stored one; otherwise the device holds a different chain
/// than it uploaded (rewritten history), which is raised once per position.
async fn check_reported_head(
    state: &AppState,
    dev: &devices::DeviceRow,
    hb: &Heartbeat,
) -> AppResult<()> {
    let (Some(seq), Some(claimed)) = (hb.last_seq, hb.last_hash) else {
        return Ok(());
    };
    if dev.last_seq.is_none_or(|held| seq > held) {
        return Ok(());
    }
    let Some(stored) = ev_repo::stored_header_hash(state.db().pool(), &dev.id, seq).await? else {
        // Pruned by retention, or inside a recorded gap: nothing to compare.
        return Ok(());
    };
    if stored == claimed {
        return Ok(());
    }
    let kind = ServerAlertKind::ChainGap;
    let created = alerts::insert(
        state.db().pool(),
        &NewAlert {
            member_id: &dev.owner_user_id,
            device_id: Some(&dev.id),
            source: AlertSource::Server,
            kind: kind.as_str(),
            urgency: kind.urgency(),
            event_seq: to_i64(seq),
            detail: Some("heartbeat_fork".to_owned()),
            dedupe_key: Some(format!("hbfork:{}:{seq}", dev.id)),
            now_ms: state.now_ms(),
        },
    )
    .await?;
    if created {
        tracing::warn!(device = %dev.id, seq, "heartbeat reports a different chain");
    }
    Ok(())
}

/// `POST /v1/heartbeat`
pub async fn post(
    State(state): State<AppState>,
    SignedJson { device, body }: SignedJson<SignedHeartbeat>,
) -> AppResult<Json<HeartbeatResponse>> {
    let hb = &body.heartbeat;
    check_heartbeat(&state, device.id(), hb)?;
    faro_crypto::verify_item(&device.row().sign_pubkey, hb, &body.sig).map_err(|_| {
        AppError::bad_request(
            "bad_heartbeat_signature",
            "heartbeat is not signed by this device's key",
        )
    })?;
    let reported_last_seq = match hb.last_seq {
        None => None,
        Some(s) => Some(to_i64(s).ok_or_else(|| {
            AppError::bad_request("seq_out_of_range", "last_seq is out of range")
        })?),
    };

    let now = state.now_ms();
    devices::record_heartbeat(
        state.db().pool(),
        device.id(),
        &HeartbeatUpdate {
            now_ms: now,
            state: hb.state.as_str(),
            boot_id: &hb.boot_id,
            reported_last_seq,
            reported_last_hash: hb.last_hash.map(|h| h.to_prefixed_hex()),
        },
    )
    .await?;
    check_reported_head(&state, device.row(), hb).await?;
    // A check-in ends any missed-check-in episode ("back online").
    crate::liveness::check_in(&state, device.id()).await?;

    Ok(Json(HeartbeatResponse {
        server_time_ms: now,
        next_in_secs: HEARTBEAT_INTERVAL_SECS,
        acked_through: device.row().last_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_ids() {
        assert!(valid_boot_id("3f2a-boot"));
        assert!(!valid_boot_id(""));
        assert!(!valid_boot_id("a\nb"));
        assert!(!valid_boot_id(&"x".repeat(MAX_BOOT_ID_LEN + 1)));
    }
}
