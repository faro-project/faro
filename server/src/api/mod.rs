//! HTTP handlers, one module per area of §4.5.

pub mod admin;
pub mod allies;
pub mod auth;
pub mod devices;
pub mod events;
pub mod feed;
pub mod heartbeat;
pub mod invites;
pub mod keys;
pub mod manifests;
pub mod prefs;
pub mod privacy;
pub mod reports;
pub mod setup;
pub mod well_known;

use crate::error::AppError;
use crate::state::AppState;
use axum::extract::{FromRequest, Request};
use axum::http::header;
use serde::de::DeserializeOwned;

/// Body limit for ordinary browser/API JSON requests.
pub const JSON_MAX_BYTES: usize = 64 * 1024;

/// JSON body extractor with our error format and size limit.
///
/// Requires `Content-Type: application/json`. Beyond correctness this is a
/// CSRF defence for cookie-authenticated endpoints: a cross-site HTML form can
/// only send form/text content types, and a cross-site `fetch` with JSON
/// triggers a CORS preflight that this server never approves.
#[derive(Debug)]
pub struct ApiJson<T>(pub T);

fn is_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

fn expected_json() -> AppError {
    AppError::bad_request("expected_json", "Content-Type must be application/json")
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes).map_err(|e| AppError::bad_request("invalid_json", e.to_string()))
}

impl<T: DeserializeOwned> FromRequest<AppState> for ApiJson<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &AppState) -> Result<Self, AppError> {
        if !is_json(&req) {
            return Err(expected_json());
        }
        let bytes = axum::body::to_bytes(req.into_body(), JSON_MAX_BYTES)
            .await
            .map_err(|_| AppError::PayloadTooLarge)?;
        parse_json(&bytes).map(ApiJson)
    }
}

/// Like [`ApiJson`], for endpoints whose body is optional (`DELETE`): an
/// empty body is `None`; a non-empty one must be `application/json` and
/// parse, exactly as for [`ApiJson`].
#[derive(Debug)]
pub struct OptionalApiJson<T>(pub Option<T>);

impl<T: DeserializeOwned> FromRequest<AppState> for OptionalApiJson<T> {
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &AppState) -> Result<Self, AppError> {
        let json = is_json(&req);
        let bytes = axum::body::to_bytes(req.into_body(), JSON_MAX_BYTES)
            .await
            .map_err(|_| AppError::PayloadTooLarge)?;
        if bytes.is_empty() {
            return Ok(OptionalApiJson(None));
        }
        if !json {
            return Err(expected_json());
        }
        parse_json(&bytes).map(|v| OptionalApiJson(Some(v)))
    }
}

/// Percent-encode a string for use as a URL query value (RFC 3986 unreserved
/// characters pass through).
pub(crate) fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn url_encode_reserved() {
        assert_eq!(
            super::url_encode("https://faro.example.org/x?y"),
            "https%3A%2F%2Ffaro.example.org%2Fx%3Fy"
        );
    }
}
