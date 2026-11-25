//! HTTP client for the device's instance API (ARCHITECTURE.md §4.5).
//!
//! * **Authentication.** Every device call carries the bearer token *and*
//!   an Ed25519 request signature from [`faro_core::request::sign_request`]
//!   over the method, the exact path and query on the request line, the
//!   exact body bytes and a timestamp (PROTOCOL.md §6).
//! * **The instance is untrusted.** Every response body is read with a hard
//!   per-endpoint cap *before* parsing (the recipient manifest at 64 KiB,
//!   PROTOCOL.md §5.1), redirects are never followed (a redirect would carry
//!   the token to another origin and break the path signature), and nothing
//!   parsed here is trusted until the caller verifies its signatures.
//! * **Pinning.** [`InstanceClient::check_identity`] re-fetches
//!   `/.well-known/faro` and requires the instance id and identity key pinned
//!   at enrollment. TLS authenticates the host name; the pin catches a
//!   re-installed or substituted instance behind the same name.
//! * **Clock.** Requests are stamped with the device wall clock corrected by
//!   the offset observed in the instance's `Date` header when that offset is
//!   large. The instance's ±5 minute window is replay protection, not a
//!   judgement of the device; a member who sets the clock wrong must not be
//!   able to stop uploads that way. Clock manipulation itself is detected and
//!   reported separately (`ClockGuard`, heartbeats).

use crate::state::Enrollment;
use faro_core::clock::Clock;
use faro_core::request::sign_request;
use faro_crypto::SigningKey;
use faro_proto::api::{
    ApiError, EnrollRequest, EnrollResponse, EventsBatchRequest, EventsBatchResponse,
    HeartbeatResponse, SignedHeartbeat, SignedRecipientManifest, WellKnown, WELL_KNOWN_PATH,
};
use faro_proto::keys::{DeviceEndorsement, ManifestRef, Signed};
use faro_proto::report::ReportUpload;
use faro_proto::{DeviceId, InstanceId, SignPublicKey, UserId};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

/// Response size caps, per endpoint.
pub mod limits {
    pub const WELL_KNOWN: usize = 16 * 1024;
    pub const ENROLL: usize = 16 * 1024;
    pub const DEVICE_SELF: usize = 64 * 1024;
    /// PROTOCOL.md §5.1 "Fetch limits".
    pub const MANIFEST: usize = 64 * 1024;
    /// Up to 500 per-event results.
    pub const EVENTS_BATCH: usize = 256 * 1024;
    pub const HEARTBEAT: usize = 4 * 1024;
    pub const REPORT: usize = 16 * 1024;
    pub const ERROR_BODY: usize = 16 * 1024;
}

/// Clock offsets smaller than this are left uncorrected (`Date` has 1 s
/// resolution and the instance allows 5 minutes).
const CORRECT_OFFSET_ABOVE_MS: i64 = 60_000;

/// Longest error code / message echoed from the instance into logs.
const MAX_ECHO: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("could not build the HTTP client: {0}")]
    Build(String),
    #[error("cannot read CA file {path}: {reason}")]
    CaFile { path: String, reason: String },
    #[error("network error talking to the instance: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("instance returned HTTP {status} ({code}): {message}")]
    Api {
        status: StatusCode,
        code: String,
        message: String,
    },
    #[error("instance response is larger than the {limit}-byte limit")]
    TooLarge { limit: usize },
    #[error("instance response is not valid JSON for this endpoint: {0}")]
    Json(#[source] serde_json::Error),
    #[error("cannot serialize request: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("invalid URL: {0}")]
    Url(String),
    #[error("this call needs device credentials (the device is not enrolled)")]
    NoCredentials,
    #[error("instance identity changed: expected {expected_id} with key {expected_key}, got {got_id} with key {got_key}")]
    IdentityChanged {
        expected_id: InstanceId,
        expected_key: String,
        got_id: InstanceId,
        got_key: String,
    },
}

impl ClientError {
    /// Worth retrying later with backoff (network trouble, overload, server
    /// errors, clock skew that a `Date` header can fix).
    pub fn is_transient(&self) -> bool {
        match self {
            ClientError::Transport(_) => true,
            ClientError::Api { status, code, .. } => {
                status.is_server_error()
                    || *status == StatusCode::TOO_MANY_REQUESTS
                    || *status == StatusCode::REQUEST_TIMEOUT
                    || code == "clock_skew"
            }
            _ => false,
        }
    }

    /// The device is still waiting for its member's endorsement.
    pub fn is_pending_endorsement(&self) -> bool {
        matches!(self, ClientError::Api { status, code, .. }
            if *status == StatusCode::FORBIDDEN && code == "device_pending_endorsement")
    }

    pub fn status(&self) -> Option<StatusCode> {
        match self {
            ClientError::Api { status, .. } => Some(*status),
            ClientError::Transport(e) => e.status(),
            _ => None,
        }
    }
}

/// How the HTTP client is built.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub timeout: Duration,
    /// Extra PEM CA certificates to trust.
    pub ca_file: Option<std::path::PathBuf>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            timeout: Duration::from_secs(30),
            ca_file: None,
        }
    }
}

/// Token + key used to authenticate device calls.
pub struct DeviceCredentials {
    pub device_id: DeviceId,
    token: Zeroizing<String>,
    key: Arc<SigningKey>,
}

impl DeviceCredentials {
    pub fn new(device_id: DeviceId, token: &str, key: Arc<SigningKey>) -> Self {
        DeviceCredentials {
            device_id,
            token: Zeroizing::new(token.to_owned()),
            key,
        }
    }

    pub fn from_enrollment(e: &Enrollment, key: Arc<SigningKey>) -> Self {
        Self::new(e.device_id.clone(), &e.device_token, key)
    }
}

impl fmt::Debug for DeviceCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceCredentials")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("key", &self.key)
            .finish()
    }
}

/// `GET /v1/devices/self`, mirrored from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSelf {
    pub device_id: DeviceId,
    pub member_id: UserId,
    /// `pending_endorsement`, `active` or `removed`.
    pub status: String,
    pub endorsement: Option<Signed<DeviceEndorsement>>,
    /// Convenience copy; never used, the anchor comes from the *verified*
    /// endorsement.
    pub min_manifest: Option<ManifestRef>,
    pub acked_through: Option<u64>,
}

/// `POST /v1/reports` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportAccepted {
    pub report_id: String,
    pub duplicate: bool,
}

/// The instance API client. Cheap to clone.
#[derive(Clone)]
pub struct InstanceClient {
    http: reqwest::Client,
    base: Url,
    clock: Arc<dyn Clock>,
    device: Option<Arc<DeviceCredentials>>,
    offset_ms: Arc<AtomicI64>,
}

impl fmt::Debug for InstanceClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstanceClient")
            .field("base", &self.base.as_str())
            .field("device", &self.device.as_ref().map(|d| &d.device_id))
            .finish_non_exhaustive()
    }
}

impl InstanceClient {
    /// `base` must already be validated ([`crate::link::parse_instance_url`]).
    pub fn new(
        base: Url,
        clock: Arc<dyn Clock>,
        opts: &ClientOptions,
    ) -> Result<Self, ClientError> {
        let mut b = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(opts.timeout)
            .connect_timeout(opts.timeout.min(Duration::from_secs(15)))
            .user_agent(concat!("faro-service/", env!("CARGO_PKG_VERSION")))
            .https_only(base.scheme() == "https");
        if let Some(path) = &opts.ca_file {
            for cert in load_ca_file(path)? {
                b = b.add_root_certificate(cert);
            }
        }
        let http = b.build().map_err(|e| ClientError::Build(e.to_string()))?;
        Ok(InstanceClient {
            http,
            base,
            clock,
            device: None,
            offset_ms: Arc::new(AtomicI64::new(0)),
        })
    }

    /// Attach device credentials for authenticated calls.
    pub fn with_device(mut self, creds: DeviceCredentials) -> Self {
        self.device = Some(Arc::new(creds));
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    /// Wall-clock offset (`instance - device`, ms) applied to request
    /// timestamps; 0 unless the device clock is far off.
    pub fn clock_offset_ms(&self) -> i64 {
        self.offset_ms.load(Ordering::Relaxed)
    }

    /// The device wall clock corrected by [`Self::clock_offset_ms`].
    pub fn corrected_wall_ms(&self) -> i64 {
        self.clock.wall_ms().saturating_add(self.clock_offset_ms())
    }

    fn url(&self, path: &str) -> Result<Url, ClientError> {
        // `path` is a fixed API path starting with '/'; join it under the
        // base path so instances served under a prefix work.
        let rel = path.trim_start_matches('/');
        self.base
            .join(rel)
            .map_err(|e| ClientError::Url(e.to_string()))
    }

    /// One request. `authed` signs it with the device credentials.
    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        authed: bool,
        limit: usize,
    ) -> Result<T, ClientError> {
        let url = self.url(path)?;
        let body = body.unwrap_or_default();
        let mut req = self.http.request(method.clone(), url.clone());
        if !body.is_empty() || method == Method::POST || method == Method::PUT {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        if authed {
            let creds = self.device.as_ref().ok_or(ClientError::NoCredentials)?;
            let path_and_query = match url.query() {
                Some(q) => format!("{}?{q}", url.path()),
                None => url.path().to_owned(),
            };
            let headers = sign_request(
                &creds.key,
                &creds.device_id,
                method.as_str(),
                &path_and_query,
                &body,
                self.corrected_wall_ms(),
            );
            for (name, value) in headers {
                req = req.header(name, value);
            }
            req = req.bearer_auth(creds.token.as_str());
        }
        let resp = req
            .body(body)
            .send()
            .await
            .map_err(ClientError::Transport)?;
        self.observe_date(&resp);
        let status = resp.status();
        if !status.is_success() {
            let raw = read_limited(resp, limits::ERROR_BODY)
                .await
                .unwrap_or_default();
            let (code, message) = match serde_json::from_slice::<ApiError>(&raw) {
                Ok(e) => (truncate(e.error), truncate(e.message)),
                Err(_) => ("http_error".to_owned(), String::new()),
            };
            return Err(ClientError::Api {
                status,
                code,
                message,
            });
        }
        let raw = read_limited(resp, limit).await?;
        serde_json::from_slice(&raw).map_err(ClientError::Json)
    }

    fn observe_date(&self, resp: &reqwest::Response) {
        let Some(date) = resp
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| httpdate::parse_http_date(s).ok())
        else {
            return;
        };
        let Ok(d) = date.duration_since(std::time::UNIX_EPOCH) else {
            return;
        };
        let server_ms = i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        let offset = server_ms.saturating_sub(self.clock.wall_ms());
        let applied = if offset.abs() > CORRECT_OFFSET_ABOVE_MS {
            offset
        } else {
            0
        };
        let prev = self.offset_ms.swap(applied, Ordering::Relaxed);
        if prev == 0 && applied != 0 {
            tracing::warn!(
                offset_ms = applied,
                "device clock differs from the instance's; correcting request timestamps"
            );
        }
    }

    fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, ClientError> {
        serde_json::to_vec(v).map_err(ClientError::Encode)
    }

    /// `GET /.well-known/faro` (unauthenticated).
    pub async fn well_known(&self) -> Result<WellKnown, ClientError> {
        self.call(
            Method::GET,
            WELL_KNOWN_PATH,
            None,
            false,
            limits::WELL_KNOWN,
        )
        .await
    }

    /// Fetch `/.well-known/faro` and require the pinned identity.
    pub async fn check_identity(
        &self,
        instance_id: &InstanceId,
        identity_pubkey: &SignPublicKey,
    ) -> Result<WellKnown, ClientError> {
        let wk = self.well_known().await?;
        if &wk.instance_id != instance_id || &wk.identity_pubkey != identity_pubkey {
            return Err(ClientError::IdentityChanged {
                expected_id: instance_id.clone(),
                expected_key: identity_pubkey.to_b64(),
                got_id: InstanceId::new(truncate(wk.instance_id.into_string())),
                got_key: wk.identity_pubkey.to_b64(),
            });
        }
        Ok(wk)
    }

    /// `POST /v1/devices/enroll` (unauthenticated; the code is the credential).
    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, ClientError> {
        let body = Self::encode(req)?;
        self.call(
            Method::POST,
            "/v1/devices/enroll",
            Some(body),
            false,
            limits::ENROLL,
        )
        .await
    }

    /// `GET /v1/devices/self`.
    pub async fn device_self(&self) -> Result<DeviceSelf, ClientError> {
        self.call(
            Method::GET,
            "/v1/devices/self",
            None,
            true,
            limits::DEVICE_SELF,
        )
        .await
    }

    /// `GET /v1/members/{id}/recipient-manifest`, capped at 64 KiB.
    pub async fn recipient_manifest(
        &self,
        member: &UserId,
    ) -> Result<SignedRecipientManifest, ClientError> {
        if !member.is_well_formed() {
            return Err(ClientError::Url("malformed member id".into()));
        }
        let path = format!("/v1/members/{}/recipient-manifest", member.as_str());
        self.call(Method::GET, &path, None, true, limits::MANIFEST)
            .await
    }

    /// `POST /v1/events:batch`.
    pub async fn post_events(
        &self,
        batch: &EventsBatchRequest,
    ) -> Result<EventsBatchResponse, ClientError> {
        let body = Self::encode(batch)?;
        self.call(
            Method::POST,
            "/v1/events:batch",
            Some(body),
            true,
            limits::EVENTS_BATCH,
        )
        .await
    }

    /// `POST /v1/heartbeat`.
    pub async fn heartbeat(&self, hb: &SignedHeartbeat) -> Result<HeartbeatResponse, ClientError> {
        let body = Self::encode(hb)?;
        self.call(
            Method::POST,
            "/v1/heartbeat",
            Some(body),
            true,
            limits::HEARTBEAT,
        )
        .await
    }

    /// `POST /v1/reports`.
    pub async fn post_report(&self, up: &ReportUpload) -> Result<ReportAccepted, ClientError> {
        let body = Self::encode(up)?;
        self.call(
            Method::POST,
            "/v1/reports",
            Some(body),
            true,
            limits::REPORT,
        )
        .await
    }
}

/// Read a response body, refusing anything over `limit` bytes. The
/// `Content-Length` is checked first, then the running total per chunk, so
/// a hostile or broken instance can't make the service buffer more.
async fn read_limited(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, ClientError> {
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Err(ClientError::TooLarge { limit });
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(ClientError::Transport)? {
        if out.len() + chunk.len() > limit {
            return Err(ClientError::TooLarge { limit });
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_ECHO {
        let mut cut = MAX_ECHO;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s.retain(|c| !c.is_control());
    s
}

pub(crate) fn load_ca_file(path: &Path) -> Result<Vec<reqwest::Certificate>, ClientError> {
    let err = |reason: String| ClientError::CaFile {
        path: path.display().to_string(),
        reason,
    };
    let meta = std::fs::metadata(path).map_err(|e| err(e.to_string()))?;
    if meta.len() > 1024 * 1024 {
        return Err(err("larger than 1 MiB".into()));
    }
    let pem = std::fs::read(path).map_err(|e| err(e.to_string()))?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| err(e.to_string()))?;
    if certs.is_empty() {
        return Err(err("no certificates found".into()));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_classification() {
        let api = |status: u16, code: &str| ClientError::Api {
            status: StatusCode::from_u16(status).unwrap(),
            code: code.into(),
            message: String::new(),
        };
        assert!(api(503, "x").is_transient());
        assert!(api(429, "rate_limited").is_transient());
        assert!(api(401, "clock_skew").is_transient());
        assert!(!api(401, "unauthorized").is_transient());
        assert!(!api(400, "bad").is_transient());
        assert!(api(403, "device_pending_endorsement").is_pending_endorsement());
        assert!(!ClientError::TooLarge { limit: 1 }.is_transient());
    }

    #[test]
    fn echo_is_bounded_and_printable() {
        let s = truncate(format!("a\nb{}", "é".repeat(500)));
        assert!(s.len() <= MAX_ECHO);
        assert!(!s.contains('\n'));
    }

    #[test]
    fn joins_under_base_path() {
        let c = InstanceClient::new(
            crate::link::parse_instance_url("https://h.example/faro").unwrap(),
            Arc::new(faro_core::ManualClock::new(0, 0)),
            &ClientOptions::default(),
        )
        .unwrap();
        assert_eq!(
            c.url("/v1/events:batch").unwrap().as_str(),
            "https://h.example/faro/v1/events:batch"
        );
        assert_eq!(
            c.url(WELL_KNOWN_PATH).unwrap().as_str(),
            "https://h.example/faro/.well-known/faro"
        );
    }
}
