//! The uniform API error type.
//!
//! Every handler returns `Result<_, AppError>`; the response body is always a
//! [`faro_proto::api::ApiError`] (`{"error": "<code>", "message": "…"}`) so the
//! web app and devices can branch on a stable machine-readable `error` code.
//!
//! Internal errors are logged server-side with their cause and returned to the
//! client as a generic `internal` error: database or I/O error text can leak
//! schema details and is useless to a client. None of the wrapped errors carry
//! request secrets (sqlx never includes bound parameter values in its errors).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use faro_proto::api::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Malformed input. `code` is a stable snake_case identifier.
    #[error("{code}: {message}")]
    BadRequest { code: &'static str, message: String },
    /// Missing or invalid credentials. Deliberately says nothing about which
    /// check failed.
    #[error("unauthorized")]
    Unauthorized,
    /// Authentication failed for a reason the client must be able to act on
    /// without it helping an attacker (e.g. `clock_skew`: fix the clock).
    #[error("unauthorized: {0}")]
    AuthFailed(&'static str),
    /// Authenticated but not allowed. `code` explains why (stable).
    #[error("forbidden: {0}")]
    Forbidden(&'static str),
    /// Not found, or not visible to the caller (we deliberately do not
    /// distinguish, so ids belonging to other users cannot be probed).
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("{code}: {message}")]
    Conflict { code: &'static str, message: String },
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("rate limited")]
    TooManyRequests { retry_after_secs: u64 },
    #[error("service unavailable: {0}")]
    Unavailable(&'static str),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("blob store error: {0}")]
    Blob(#[from] crate::blob::BlobError),
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        AppError::BadRequest {
            code,
            message: message.into(),
        }
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        AppError::Conflict {
            code,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        AppError::Internal(message.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            AppError::Unauthorized | AppError::AuthFailed(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            AppError::Conflict { .. } => StatusCode::CONFLICT,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::TooManyRequests { .. } => StatusCode::TOO_MANY_REQUESTS,
            AppError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Db(_) | AppError::Blob(_) | AppError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// The wire body for this error.
    pub fn to_api_error(&self) -> ApiError {
        let (error, message): (&str, String) = match self {
            AppError::BadRequest { code, message } => (code, message.clone()),
            AppError::Unauthorized => ("unauthorized", "authentication required".into()),
            AppError::AuthFailed(code) => (code, "authentication failed".into()),
            AppError::Forbidden(code) => (code, "not allowed".into()),
            AppError::NotFound => ("not_found", "not found".into()),
            AppError::MethodNotAllowed => (
                "method_not_allowed",
                "method not allowed for this path".into(),
            ),
            AppError::Conflict { code, message } => (code, message.clone()),
            AppError::PayloadTooLarge => ("payload_too_large", "request body too large".into()),
            AppError::TooManyRequests { .. } => {
                ("rate_limited", "too many requests; slow down".into())
            }
            AppError::Unavailable(code) => (code, "temporarily unavailable".into()),
            AppError::Db(_) | AppError::Blob(_) | AppError::Internal(_) => {
                ("internal", "internal server error".into())
            }
        };
        ApiError {
            error: error.to_owned(),
            message,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        }
        let mut resp = (status, Json(self.to_api_error())).into_response();
        if let AppError::TooManyRequests { retry_after_secs } = self {
            if let Ok(v) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                resp.headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let e = AppError::internal("secret table layout");
        let body = e.to_api_error();
        assert_eq!(body.error, "internal");
        assert!(!body.message.contains("secret"));
        assert_eq!(e.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn rate_limit_sets_retry_after() {
        let r = AppError::TooManyRequests {
            retry_after_secs: 7,
        }
        .into_response();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[axum::http::header::RETRY_AFTER], "7");
    }
}
