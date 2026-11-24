//! Device request authentication (§4.5: "a device token **plus** an Ed25519
//! signature on every request").
//!
//! A device request carries:
//!
//! * `Authorization: Bearer <device_token>`: proves possession of the token
//!   issued at enrollment (stored hashed);
//! * `faro-device: dev_…`: must name the same device the token belongs to;
//! * `faro-timestamp: <unix ms>`: within ±[`REQUEST_MAX_SKEW_MS`] of server
//!   time, which bounds replay of a captured request to a few minutes;
//! * `faro-signature: <base64url>`: Ed25519 over
//!   [`request_signing_bytes`]`(method, path_and_query, device_id, ts, body)`
//!   with the device key the member endorsed.
//!
//! The token alone is not enough (a leaked token cannot forge requests) and
//! the key alone is not enough (a stolen key without the token is useless
//! against this instance). The body is read with a hard size limit *before*
//! any verification, so oversized bodies cost nothing.
//!
//! **Pending devices** (enrolled but not yet endorsed by the member key) may
//! only send heartbeats and fetch keys/status: they are not yet trusted to put
//! events into anyone's accountability record. Each request type declares
//! this through [`DeviceBody::ALLOW_PENDING`], so the policy is enforced here
//! once rather than in every handler.
//!
//! The signed `path_and_query` is the URL as the device sent it, so a reverse
//! proxy must forward paths unchanged.

use crate::db::repo::devices::{self, DeviceRow, DeviceStatus};
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens::{is_token_shaped, TokenPurpose};
use axum::body::Body;
use axum::extract::{FromRequest, OriginalUri, Request};
use axum::http::{header, HeaderMap, Method};
use faro_proto::api::{auth_headers, request_signing_bytes, REQUEST_MAX_SKEW_MS};
use faro_proto::{DeviceId, Signature};
use serde::de::DeserializeOwned;

/// An authenticated device.
#[derive(Debug, Clone)]
pub struct AuthedDevice(pub DeviceRow);

impl AuthedDevice {
    pub fn row(&self) -> &DeviceRow {
        &self.0
    }

    pub fn id(&self) -> &DeviceId {
        &self.0.id
    }

    pub fn is_active(&self) -> bool {
        self.0.status == DeviceStatus::Active
    }
}

/// A JSON request body a device may send, with its size limit and pending policy.
pub trait DeviceBody: DeserializeOwned {
    /// Maximum accepted body size in bytes.
    const MAX_BYTES: usize;
    /// Whether a device still awaiting endorsement may send it.
    const ALLOW_PENDING: bool;
}

impl DeviceBody for faro_proto::api::EventsBatchRequest {
    // Up to a few hundred events with small encrypted bodies (blurred
    // thumbnails are ~10-30 KB). Larger backlogs are uploaded in batches.
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    const ALLOW_PENDING: bool = false;
}

impl DeviceBody for faro_proto::api::SignedHeartbeat {
    const MAX_BYTES: usize = 4 * 1024;
    const ALLOW_PENDING: bool = true;
}

impl DeviceBody for faro_proto::report::ReportUpload {
    // Daily reports are 20-200 KB (§4.2); allow generous headroom for a week
    // with many flagged thumbnails.
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    const ALLOW_PENDING: bool = false;
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Verify the device credentials on a request whose body has already been
/// read (and size-limited).
pub async fn authenticate(
    state: &AppState,
    method: &Method,
    path_and_query: &str,
    headers: &HeaderMap,
    body: &[u8],
    allow_pending: bool,
) -> Result<AuthedDevice, AppError> {
    // Cheap syntactic checks first; no database work for garbage.
    let token = header_str(headers, header::AUTHORIZATION.as_str())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| is_token_shaped(t))
        .ok_or(AppError::Unauthorized)?;
    let claimed = header_str(headers, auth_headers::DEVICE)
        .map(DeviceId::new)
        .filter(DeviceId::is_well_formed)
        .ok_or(AppError::Unauthorized)?;
    let ts: i64 = header_str(headers, auth_headers::TIMESTAMP)
        .and_then(|v| v.trim().parse().ok())
        .ok_or(AppError::Unauthorized)?;
    let sig = header_str(headers, auth_headers::SIGNATURE)
        .and_then(|v| Signature::from_b64(v.trim()))
        .ok_or(AppError::Unauthorized)?;
    if (state.now_ms() - ts).abs() > REQUEST_MAX_SKEW_MS {
        return Err(AppError::AuthFailed("clock_skew"));
    }

    let device = devices::by_token_hash(
        state.db().pool(),
        &state.hasher().hash(TokenPurpose::Device, token),
    )
    .await?
    .ok_or(AppError::Unauthorized)?;
    // The token must belong to the device named in the header: device A's
    // token can never be used to act as device B.
    if device.id != claimed || device.status == DeviceStatus::Removed {
        return Err(AppError::Unauthorized);
    }
    let msg = request_signing_bytes(method.as_str(), path_and_query, &device.id, ts, body);
    faro_crypto::verify(&device.sign_pubkey, &msg, &sig).map_err(|_| AppError::Unauthorized)?;

    if device.status == DeviceStatus::PendingEndorsement && !allow_pending {
        return Err(AppError::Forbidden("device_pending_endorsement"));
    }
    Ok(AuthedDevice(device))
}

/// Split a request and read its body with a hard limit.
async fn read_limited(
    req: Request,
    max: usize,
) -> Result<(axum::http::request::Parts, axum::body::Bytes), AppError> {
    let (parts, body): (_, Body) = req.into_parts();
    if let Some(len) = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len > max as u64 {
            return Err(AppError::PayloadTooLarge);
        }
    }
    let bytes = axum::body::to_bytes(body, max)
        .await
        .map_err(|_| AppError::PayloadTooLarge)?;
    Ok((parts, bytes))
}

fn signed_path(parts: &axum::http::request::Parts) -> String {
    // Use the original URI in case this router is ever nested.
    let uri = parts
        .extensions
        .get::<OriginalUri>()
        .map(|o| &o.0)
        .unwrap_or(&parts.uri);
    uri.path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

/// Extractor: an authenticated device plus its parsed JSON body.
#[derive(Debug)]
pub struct SignedJson<T> {
    pub device: AuthedDevice,
    pub body: T,
}

impl<T: DeviceBody> FromRequest<AppState> for SignedJson<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, AppError> {
        let (parts, bytes) = read_limited(req, T::MAX_BYTES).await?;
        let path = signed_path(&parts);
        let device = authenticate(
            state,
            &parts.method,
            &path,
            &parts.headers,
            &bytes,
            T::ALLOW_PENDING,
        )
        .await?;
        // Parse only after authenticating, so unauthenticated callers cannot
        // make the server do JSON work on large bodies.
        let body = serde_json::from_slice(&bytes)
            .map_err(|e| AppError::bad_request("invalid_json", e.to_string()))?;
        Ok(SignedJson { device, body })
    }
}

/// Bodyless device requests (GETs) are at most this large.
const BODYLESS_MAX: usize = 1024;

/// Extractor: an authenticated device on a request without a JSON body.
/// Pending devices are allowed (used for key/status fetches).
#[derive(Debug)]
pub struct DeviceRequest(pub AuthedDevice);

impl FromRequest<AppState> for DeviceRequest {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, AppError> {
        let (parts, bytes) = read_limited(req, BODYLESS_MAX).await?;
        let path = signed_path(&parts);
        authenticate(state, &parts.method, &path, &parts.headers, &bytes, true)
            .await
            .map(DeviceRequest)
    }
}

/// Either a device (token + signature) or a browser session. Used by endpoints
/// both can call, such as the member key directory.
#[derive(Debug)]
pub enum DeviceOrSession {
    Device(AuthedDevice),
    Session(crate::auth::session::SessionUser),
}

impl FromRequest<AppState> for DeviceOrSession {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, AppError> {
        if req.headers().contains_key(header::AUTHORIZATION) {
            let DeviceRequest(d) = DeviceRequest::from_request(req, state).await?;
            return Ok(DeviceOrSession::Device(d));
        }
        crate::auth::session::from_headers(state, req.headers())
            .await?
            .map(DeviceOrSession::Session)
            .ok_or(AppError::Unauthorized)
    }
}
