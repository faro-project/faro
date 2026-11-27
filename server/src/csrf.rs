//! Cross-site request defence for cookie-authenticated requests.
//!
//! `SameSite=Strict` is the main defence ([`crate::auth::session`]) and
//! JSON-only body extractors ([`crate::api::ApiJson`]) the second, but several
//! `POST`/`DELETE` routes take no body at all (`/admin/api/users/{id}/disable`,
//! `/v1/me/allies/{id}/approve`, ...), so a cross-site `<form>` post could
//! reach them if a browser ever sent the cookie. This middleware makes the
//! rule uniform, as a third layer: an unsafe-method request that carries the
//! session cookie must be provably same-origin.
//!
//! * `Sec-Fetch-Site` present: must be `same-origin`. `same-site` (a sibling
//!   subdomain) and `none` are refused too.
//! * Absent (older browsers): `Origin` must equal the instance's public
//!   origin; `Origin: null` or any other origin is refused.
//! * Both absent: allowed. Browsers send at least one of the two on every
//!   cross-site unsafe request, so a request with neither is a non-browser
//!   client (curl, a script), which is not a CSRF vector: an attacker's page
//!   cannot make a victim's browser omit both.
//!
//! Requests without the session cookie are not checked. Device routes
//! authenticate by signature headers (`device_auth`), never by cookie, so they
//! are untouched; with no cookie there is no ambient authority to abuse.
//! Behind the Vite dev proxy the browser talks to one origin
//! (`localhost:5173`), so `Sec-Fetch-Site` is `same-origin` there.

use crate::auth::session::{cookie_name, read_cookie};
use crate::error::AppError;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method};
use axum::middleware::Next;
use axum::response::Response;

const SEC_FETCH_SITE: &str = "sec-fetch-site";

/// `scheme://authority` of a validated public URL (path dropped).
fn origin_of(public_url: &str) -> &str {
    let after = public_url.find("://").map_or(0, |i| i + 3);
    let end = public_url[after..]
        .find('/')
        .map_or(public_url.len(), |i| after + i);
    &public_url[..end]
}

/// Whether the request may carry a session cookie.
fn same_origin(headers: &HeaderMap, public_url: &str) -> bool {
    if let Some(site) = headers.get(SEC_FETCH_SITE) {
        return site.as_bytes().eq_ignore_ascii_case(b"same-origin");
    }
    match headers.get(header::ORIGIN) {
        Some(origin) => origin
            .to_str()
            .is_ok_and(|o| o.eq_ignore_ascii_case(origin_of(public_url))),
        None => true,
    }
}

pub async fn require_same_origin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let unsafe_method = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if unsafe_method
        && read_cookie(req.headers(), cookie_name(&state)).is_some()
        && !same_origin(req.headers(), &state.config().public_url)
    {
        return Err(AppError::Forbidden("cross_site_request"));
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.parse().unwrap());
        }
        m
    }

    #[test]
    fn decisions() {
        let u = "https://faro.example.org/base";
        assert!(same_origin(&h(&[]), u));
        assert!(same_origin(&h(&[("sec-fetch-site", "same-origin")]), u));
        assert!(!same_origin(&h(&[("sec-fetch-site", "cross-site")]), u));
        assert!(!same_origin(&h(&[("sec-fetch-site", "same-site")]), u));
        assert!(!same_origin(&h(&[("sec-fetch-site", "none")]), u));
        assert!(same_origin(
            &h(&[("origin", "https://faro.example.org")]),
            u
        ));
        assert!(!same_origin(&h(&[("origin", "https://evil.example")]), u));
        assert!(!same_origin(&h(&[("origin", "null")]), u));
        // Sec-Fetch-Site wins over Origin.
        assert!(!same_origin(
            &h(&[
                ("sec-fetch-site", "cross-site"),
                ("origin", "https://faro.example.org")
            ]),
            u
        ));
    }
}
