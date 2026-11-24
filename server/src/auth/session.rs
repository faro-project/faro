//! Session cookies.
//!
//! * The cookie value is a random 256-bit token; only its keyed hash is
//!   stored, so a database leak cannot be replayed as live sessions.
//! * `HttpOnly` (no script access), `SameSite=Strict` (no cross-site sends:
//!   the main CSRF defence), `Secure` and the `__Host-` prefix unless `--dev`.
//! * State-changing endpoints additionally require a JSON body
//!   ([`crate::api::ApiJson`]), which a cross-site form cannot produce
//!   without a CORS preflight that we never approve.

use crate::db::repo::{sessions, users::User};
use crate::error::AppError;
use crate::state::AppState;
use crate::tokens::{is_token_shaped, new_token, TokenPurpose};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue};

/// Session lifetime.
pub const SESSION_TTL_MS: i64 = 30 * 24 * 3600 * 1000;

/// `last_seen_at` is refreshed at most this often, to avoid a write per request.
const TOUCH_INTERVAL_MS: i64 = 3600 * 1000;

const COOKIE_SECURE: &str = "__Host-faro_session";
const COOKIE_DEV: &str = "faro_session";

pub fn cookie_name(state: &AppState) -> &'static str {
    if state.config().secure_cookies() {
        COOKIE_SECURE
    } else {
        COOKIE_DEV
    }
}

fn cookie_attrs(state: &AppState) -> &'static str {
    if state.config().secure_cookies() {
        "; Path=/; HttpOnly; Secure; SameSite=Strict"
    } else {
        "; Path=/; HttpOnly; SameSite=Strict"
    }
}

/// Find a cookie by name in the request's `Cookie` headers.
pub fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

/// Create a session for `user` and return the `Set-Cookie` header value.
pub async fn create(state: &AppState, user: &User) -> Result<HeaderValue, AppError> {
    let token = new_token();
    let now = state.now_ms();
    sessions::insert(
        state.db().pool(),
        &state.hasher().hash(TokenPurpose::Session, &token),
        &user.id,
        now,
        now + SESSION_TTL_MS,
    )
    .await?;
    let cookie = format!(
        "{}={}{}; Max-Age={}",
        cookie_name(state),
        token.as_str(),
        cookie_attrs(state),
        SESSION_TTL_MS / 1000
    );
    HeaderValue::from_str(&cookie).map_err(|_| AppError::internal("unencodable cookie"))
}

/// `Set-Cookie` value that removes the session cookie.
pub fn clear_cookie(state: &AppState) -> HeaderValue {
    let cookie = format!(
        "{}=deleted{}; Max-Age=0",
        cookie_name(state),
        cookie_attrs(state)
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The authenticated browser user. Extracting it fails with 401 if there is
/// no valid session.
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub user: User,
    /// Keyed hash of the session id (for logout).
    pub session_hash: String,
}

impl SessionUser {
    /// Members are the people being held accountable: only they hold member
    /// keys and enroll devices.
    pub fn require_member(&self) -> Result<(), AppError> {
        if self.user.roles.member {
            Ok(())
        } else {
            Err(AppError::Forbidden("not_a_member"))
        }
    }

    /// Instance admins configure the instance and see aggregate metadata.
    /// The role grants nothing over any member's keys, devices, allies or
    /// content (§4.3, §12).
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.user.roles.admin {
            Ok(())
        } else {
            Err(AppError::Forbidden("not_an_admin"))
        }
    }
}

/// Resolve the session (if any) from request headers.
pub async fn from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<SessionUser>, AppError> {
    let Some(token) = read_cookie(headers, cookie_name(state)) else {
        return Ok(None);
    };
    if !is_token_shaped(token) {
        return Ok(None);
    }
    let hash = state.hasher().hash(TokenPurpose::Session, token);
    let now = state.now_ms();
    let Some(live) = sessions::lookup(state.db().pool(), &hash, now).await? else {
        return Ok(None);
    };
    if now - live.last_seen_at_ms > TOUCH_INTERVAL_MS {
        sessions::touch(state.db().pool(), &hash, now).await?;
    }
    Ok(Some(SessionUser {
        user: live.user,
        session_hash: hash,
    }))
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        from_headers(state, &parts.headers)
            .await?
            .ok_or(AppError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cookie_among_many() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; faro_session=abc ; b=2".parse().unwrap(),
        );
        h.append(header::COOKIE, "c=3".parse().unwrap());
        assert_eq!(read_cookie(&h, "faro_session"), Some("abc"));
        assert_eq!(read_cookie(&h, "c"), Some("3"));
        assert_eq!(read_cookie(&h, "faro"), None);
        assert_eq!(read_cookie(&HeaderMap::new(), "a"), None);
    }
}
