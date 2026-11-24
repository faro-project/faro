//! Device enrollment and endorsement (§3.8, §5.2 step 3, §7 "Member").
//!
//! 1. The member (signed in, member keys **and** a first recipient manifest
//!    stored) creates a one-time code: `POST /v1/me/enroll-codes` →
//!    `XXXX-XXXX`, valid 10 minutes.
//! 2. The device generates its Ed25519 key and calls `POST /v1/devices/enroll`
//!    with the code. It receives a device token and the member's signing key
//!    (which it pins). The device is `pending_endorsement`.
//! 3. The member's browser lists the pending device (`GET /v1/me/devices`),
//!    the member compares the key fingerprint with the one the device shows,
//!    and the browser signs a [`DeviceEndorsement`] with the member key:
//!    `POST /v1/devices/{id}/endorse`. The device becomes `active`.
//!    The endorsement's `min_manifest` must be the member's latest recipient
//!    manifest ([`ManifestRef`]) at that moment: it is the bootstrap anchor
//!    that stops an instance from starting a new device on an older,
//!    pre-removal manifest (PROTOCOL.md §5.1 "Bootstrapping"). The device
//!    reads it back from `GET /v1/devices/self`.
//!
//! Only the device's owner can endorse it. An instance admin cannot enroll or
//! endorse devices for anyone else (§12): codes are bound to the member who
//! created them, and endorsement requires the member's own signing key and
//! session.

use super::ApiJson;
use crate::auth::session::SessionUser;
use crate::db::repo::alerts::{self, AlertSource, NewAlert};
use crate::db::repo::devices::{self, DeviceRow, DeviceStatus};
use crate::db::repo::liveness as liveness_repo;
use crate::db::repo::{enroll_codes, is_unique_violation, manifests, member_keys};
use crate::device_auth::DeviceRequest;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::tokens::{new_enroll_code, new_token, normalize_enroll_code, TokenPurpose};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use faro_crypto::random_bytes;
use faro_proto::api::{EnrollRequest, EnrollResponse, Platform, ServerAlertKind};
use faro_proto::keys::{key_id, DeviceEndorsement, ManifestRef, Signed};
use faro_proto::{DeviceId, SignPublicKey, UserId};
use serde::{Deserialize, Serialize};

/// Enroll codes expire after 10 minutes.
pub const ENROLL_CODE_TTL_MS: i64 = 10 * 60 * 1000;
/// Unused, unexpired codes a member may hold at once.
pub const MAX_OUTSTANDING_CODES: i64 = 5;

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollCodeResponse {
    /// `XXXX-XXXX`, shown to the member once.
    pub code: String,
    pub expires_at_ms: i64,
    /// `faro://enroll?i=<instance url>&c=<code>` for a link or QR code.
    pub enroll_url: String,
}

/// `POST /v1/me/enroll-codes`
pub async fn create_enroll_code(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<(StatusCode, Json<EnrollCodeResponse>)> {
    s.require_member()?;
    let pool = state.db().pool();
    if member_keys::sign_pubkey(pool, &s.user.id).await?.is_none() {
        // Without a member key nothing could endorse the device.
        return Err(AppError::conflict(
            "member_keys_required",
            "set up your member keys before enrolling a device",
        ));
    }
    if manifests::latest(pool, &s.user.id).await?.is_none() {
        // A device needs a manifest to bootstrap from, and its endorsement
        // must anchor to one (PROTOCOL.md §5.1).
        return Err(AppError::conflict(
            "recipient_manifest_required",
            "sign your first recipient manifest before enrolling a device",
        ));
    }
    let now = state.now_ms();
    if enroll_codes::count_outstanding(pool, &s.user.id, now).await? >= MAX_OUTSTANDING_CODES {
        return Err(AppError::conflict(
            "too_many_codes",
            "too many unused enrollment codes; wait for them to expire",
        ));
    }
    let code = new_enroll_code();
    let normalized = normalize_enroll_code(&code)
        .ok_or_else(|| AppError::internal("generated enroll code failed to normalize"))?;
    let expires_at_ms = now + ENROLL_CODE_TTL_MS;
    enroll_codes::insert(
        pool,
        &state.hasher().hash(TokenPurpose::EnrollCode, &normalized),
        &s.user.id,
        now,
        expires_at_ms,
    )
    .await?;
    let enroll_url = format!(
        "faro://enroll?i={}&c={}",
        super::url_encode(&state.config().public_url),
        code
    );
    Ok((
        StatusCode::CREATED,
        Json(EnrollCodeResponse {
            code,
            expires_at_ms,
            enroll_url,
        }),
    ))
}

fn valid_device_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && !s.chars().any(char::is_control) && s.trim() == s
}

fn valid_client_version(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// `POST /v1/devices/enroll` (unauthenticated; rate-limited).
pub async fn enroll(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<EnrollRequest>,
) -> AppResult<(StatusCode, Json<EnrollResponse>)> {
    if !valid_device_name(&req.device_name) {
        return Err(AppError::bad_request(
            "invalid_device_name",
            "device name must be 1-64 printable characters",
        ));
    }
    if !valid_client_version(&req.client_version) {
        return Err(AppError::bad_request(
            "invalid_client_version",
            "client_version is malformed",
        ));
    }
    if faro_crypto::validate_sign_pubkey(&req.sign_pubkey).is_err() {
        return Err(AppError::bad_request(
            "invalid_sign_pubkey",
            "sign_pubkey is not a usable Ed25519 key",
        ));
    }
    // Malformed, unknown, used and expired codes are indistinguishable.
    let code = normalize_enroll_code(&req.enroll_code)
        .ok_or(AppError::AuthFailed("invalid_enroll_code"))?;
    let code_hash = state.hasher().hash(TokenPurpose::EnrollCode, &code);
    let now = state.now_ms();

    let mut tx = state.db().begin_write().await?;
    let member = enroll_codes::consume(&mut tx, &code_hash, now)
        .await?
        .ok_or(AppError::AuthFailed("invalid_enroll_code"))?;
    let member_sign_pubkey = member_keys::sign_pubkey(&mut *tx, &member)
        .await?
        .ok_or_else(|| AppError::conflict("member_keys_required", "the member has no keys"))?;
    if devices::sign_pubkey_in_use(&mut *tx, &req.sign_pubkey).await? {
        return Err(AppError::conflict(
            "device_key_in_use",
            "this device key is already enrolled",
        ));
    }
    let device_id = DeviceId::from_random(&random_bytes::<16>());
    let token = new_token();
    let insert = devices::insert(
        &mut *tx,
        &devices::NewDevice {
            id: &device_id,
            owner_user_id: &member,
            platform: req.platform,
            name: &req.device_name,
            client_version: &req.client_version,
            sign_pubkey: &req.sign_pubkey,
            token_hash: &state.hasher().hash(TokenPurpose::Device, &token),
            now_ms: now,
        },
    )
    .await;
    match insert {
        Ok(()) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::conflict(
                "device_key_in_use",
                "this device key is already enrolled",
            ))
        }
        Err(e) => return Err(e.into()),
    }
    enroll_codes::link_device(&mut *tx, &code_hash, &device_id).await?;
    tx.commit().await?;
    tracing::info!(device = %device_id, member = %member, "device enrolled; awaiting endorsement");

    Ok((
        StatusCode::CREATED,
        Json(EnrollResponse {
            instance_id: state.instance_id().clone(),
            device_id,
            device_token: token.as_str().to_owned(),
            member_id: member,
            member_sign_pubkey,
        }),
    ))
}

/// A device as shown to its owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub device_id: DeviceId,
    pub name: String,
    pub platform: Platform,
    pub status: String,
    pub sign_pubkey: SignPublicKey,
    /// Fingerprint the member compares with the one the device displays
    /// before endorsing, so the instance cannot slip in its own device key.
    pub key_id: String,
    pub enrolled_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
}

impl From<&DeviceRow> for DeviceSummary {
    fn from(d: &DeviceRow) -> Self {
        DeviceSummary {
            device_id: d.id.clone(),
            name: d.name.clone(),
            platform: d.platform,
            status: d.status.as_str().to_owned(),
            sign_pubkey: d.sign_pubkey,
            key_id: key_id(d.sign_pubkey.as_bytes()),
            enrolled_at_ms: d.enrolled_at_ms,
            last_seen_at_ms: d.last_seen_at_ms,
        }
    }
}

/// `GET /v1/me/devices`
pub async fn list_my_devices(
    State(state): State<AppState>,
    s: SessionUser,
) -> AppResult<Json<Vec<DeviceSummary>>> {
    let rows = devices::list_for_owner(state.db().pool(), &s.user.id).await?;
    Ok(Json(rows.iter().map(DeviceSummary::from).collect()))
}

/// `DELETE /v1/me/devices/{id}`: the member retires one of their devices (a
/// lost laptop, a replaced one, a pending enrollment they don't recognise).
///
/// The device's token and key stop authenticating at once, it drops out of
/// the device list and the liveness monitor, and any open missed-check-in
/// episode is closed. Retiring an **active** device stops its monitoring,
/// so it is never silent: an urgent, tamper-class `device_removed` alert
/// goes to the member and their allies in the same transaction. A pending
/// device was never monitored and is removed quietly.
pub async fn remove_device(
    State(state): State<AppState>,
    Path(id): Path<String>,
    s: SessionUser,
) -> AppResult<StatusCode> {
    s.require_member()?;
    let id = DeviceId::new(id);
    if !id.is_well_formed() {
        return Err(AppError::NotFound);
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    // Someone else's device is indistinguishable from a missing one.
    let device = devices::by_id(&mut *tx, &id)
        .await?
        .filter(|d| d.owner_user_id == s.user.id && d.status != DeviceStatus::Removed)
        .ok_or(AppError::NotFound)?;
    if !devices::remove(&mut *tx, &id, &s.user.id, now).await? {
        return Err(AppError::NotFound);
    }
    liveness_repo::close_open_episode(&mut tx, &id, now).await?;
    if device.status == DeviceStatus::Active {
        let kind = ServerAlertKind::DeviceRemoved;
        alerts::insert(
            &mut *tx,
            &NewAlert {
                member_id: &s.user.id,
                device_id: Some(&id),
                source: AlertSource::Server,
                kind: kind.as_str(),
                urgency: kind.urgency(),
                event_seq: None,
                detail: Some("removed_by_member".to_owned()),
                dedupe_key: Some(format!("devremoved:{id}")),
                now_ms: now,
            },
        )
        .await?;
    }
    tx.commit().await?;
    tracing::info!(device = %id, "device removed by its member");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EndorseResponse {
    pub device_id: DeviceId,
    pub status: String,
}

/// `POST /v1/devices/{id}/endorse`
pub async fn endorse(
    State(state): State<AppState>,
    Path(id): Path<String>,
    s: SessionUser,
    ApiJson(req): ApiJson<Signed<DeviceEndorsement>>,
) -> AppResult<Json<EndorseResponse>> {
    s.require_member()?;
    let id = DeviceId::new(id);
    if !id.is_well_formed() {
        return Err(AppError::NotFound);
    }
    let now = state.now_ms();
    let mut tx = state.db().begin_write().await?;
    // Someone else's device is indistinguishable from a missing one.
    let device = devices::by_id(&mut *tx, &id)
        .await?
        .filter(|d| d.owner_user_id == s.user.id)
        .ok_or(AppError::NotFound)?;
    match device.status {
        DeviceStatus::PendingEndorsement => {}
        DeviceStatus::Active => {
            return Err(AppError::conflict(
                "already_endorsed",
                "device is already active",
            ))
        }
        DeviceStatus::Removed => return Err(AppError::NotFound),
    }
    let e = &req.body;
    if &e.instance_id != state.instance_id()
        || e.member_id != s.user.id
        || e.device_id != device.id
        || e.device_sign_pubkey != device.sign_pubkey
    {
        return Err(AppError::bad_request(
            "endorsement_mismatch",
            "the endorsement must name this instance, your account, this device and its key",
        ));
    }
    let member_key = member_keys::sign_pubkey(&mut *tx, &s.user.id)
        .await?
        .ok_or_else(|| AppError::conflict("member_keys_required", "no member keys"))?;
    faro_crypto::verify_signed(&member_key, &req).map_err(|_| {
        AppError::bad_request(
            "bad_endorsement_signature",
            "endorsement is not signed by your member key",
        )
    })?;
    // The anchor must be the manifest that is current *now*, read in the
    // same write transaction that activates the device: an older one would
    // let the instance bootstrap the device below a removal, and a version
    // the instance does not hold could never be satisfied.
    let current = manifests::latest(&mut *tx, &s.user.id)
        .await?
        .map(|m| m.reference)
        .ok_or_else(|| {
            AppError::conflict(
                "recipient_manifest_required",
                "sign your first recipient manifest before endorsing a device",
            )
        })?;
    if e.min_manifest != current {
        return Err(AppError::conflict(
            "stale_min_manifest",
            format!(
                "min_manifest must be your current recipient manifest (version {})",
                current.version
            ),
        ));
    }
    let json = serde_json::to_string(&req)
        .map_err(|_| AppError::internal("cannot serialize endorsement"))?;
    if !devices::activate(&mut *tx, &device.id, &s.user.id, &json, now).await? {
        return Err(AppError::conflict(
            "already_endorsed",
            "device is no longer pending",
        ));
    }
    tx.commit().await?;
    tracing::info!(device = %device.id, "device endorsed");
    Ok(Json(EndorseResponse {
        device_id: device.id,
        status: DeviceStatus::Active.as_str().to_owned(),
    }))
}

/// `GET /v1/devices/self` response.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceSelf {
    pub device_id: DeviceId,
    pub member_id: UserId,
    pub status: String,
    /// The member's endorsement once active. The device verifies it against
    /// the member key it pinned at enrollment.
    pub endorsement: Option<Signed<DeviceEndorsement>>,
    /// The endorsement's bootstrap anchor, for convenience: a device must
    /// take it from the *verified* `endorsement`, never from this field.
    pub min_manifest: Option<ManifestRef>,
    pub acked_through: Option<u64>,
}

/// `GET /v1/devices/self` (device auth; pending allowed): lets a freshly
/// enrolled device poll until the member has endorsed it, then read the
/// stored endorsement (and with it the `min_manifest` anchor it needs before
/// accepting its first recipient manifest).
pub async fn device_self(DeviceRequest(d): DeviceRequest) -> AppResult<Json<DeviceSelf>> {
    let row = d.row();
    let endorsement: Option<Signed<DeviceEndorsement>> = row
        .member_sig
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|_| AppError::internal("stored endorsement does not parse"))?;
    Ok(Json(DeviceSelf {
        device_id: row.id.clone(),
        member_id: row.owner_user_id.clone(),
        status: row.status.as_str().to_owned(),
        min_manifest: endorsement.as_ref().map(|e| e.body.min_manifest),
        endorsement,
        acked_through: row.last_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names() {
        assert!(valid_device_name("Sam's MacBook Pro"));
        assert!(!valid_device_name(""));
        assert!(!valid_device_name(" padded "));
        assert!(!valid_device_name("tab\there"));
        assert!(!valid_device_name(&"x".repeat(65)));
    }

    #[test]
    fn client_versions() {
        assert!(valid_client_version("0.1.0"));
        assert!(valid_client_version("1.2.3-beta.1+abc"));
        assert!(!valid_client_version(""));
        assert!(!valid_client_version("1.0 beta"));
        assert!(!valid_client_version(&"1".repeat(33)));
    }
}
