//! Cross-site defence for cookie-authenticated requests (`faro_server::csrf`).

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;

/// A bodyless or form-encoded POST with the session cookie and extra headers.
async fn send(t: &TestApp, path: &str, session: &str, extra: &[(&str, &str)], form: bool) -> Resp {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, format!("{COOKIE}={session}"));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let body = if form {
        b = b.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        Body::from("x=1")
    } else {
        Body::empty()
    };
    t.send(b.body(body).unwrap()).await
}

#[tokio::test]
async fn cross_site_form_post_with_admin_cookie_is_refused() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let (member, _ms) = t.sign_in("pat@example.org").await;
    let path = format!("/admin/api/users/{member}/disable");

    for headers in [
        vec![("sec-fetch-site", "cross-site")],
        vec![("sec-fetch-site", "same-site")],
        vec![("origin", "https://evil.example")],
        vec![("origin", "null")],
    ] {
        let r = send(&t, &path, &admin_s, &headers, true).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{headers:?}");
        assert_eq!(r.error_code(), "cross_site_request");
        let r = send(&t, &path, &admin_s, &headers, false).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{headers:?}");
    }
    // Nothing happened: the user can still be disabled afterwards.
    let ok = send(
        &t,
        &path,
        &admin_s,
        &[("sec-fetch-site", "same-origin")],
        false,
    )
    .await;
    assert!(ok.status.is_success(), "{:?}", ok.body);
}

#[tokio::test]
async fn same_origin_and_non_browser_requests_pass() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let (m1, _) = t.sign_in("a@example.org").await;
    let (m2, _) = t.sign_in("b@example.org").await;
    let (m3, _) = t.sign_in("c@example.org").await;
    let origin = t.state.config().public_url.clone();
    let p1 = format!("/admin/api/users/{m1}/disable");
    let p2 = format!("/admin/api/users/{m2}/disable");
    let p3 = format!("/admin/api/users/{m3}/disable");
    // Fetch metadata.
    let same = [("sec-fetch-site", "same-origin")];
    let r = send(&t, &p1, &admin_s, &same, false).await;
    assert!(r.status.is_success(), "{:?}", r.body);
    // Older browser: Origin only.
    let r = send(&t, &p2, &admin_s, &[("origin", origin.as_str())], false).await;
    assert!(r.status.is_success(), "{:?}", r.body);
    // Neither header: a non-browser client.
    let r = send(&t, &p3, &admin_s, &[], false).await;
    assert!(r.status.is_success(), "{:?}", r.body);
}

#[tokio::test]
async fn device_routes_are_not_affected() {
    let t = TestApp::new().await;
    let (_m, _s, _keys, dev) = t.active_device().await;
    let mut req = dev.request(Method::POST, "/v1/heartbeat", b"{}", t.clock_ms());
    req.headers_mut()
        .insert("sec-fetch-site", "cross-site".parse().unwrap());
    let r = t.send(req).await;
    // Whatever the handler makes of this heartbeat, the CSRF layer is not it:
    // device requests carry a signature, not the session cookie.
    assert_ne!(r.error_code(), "cross_site_request", "{:?}", r.body);
}

#[tokio::test]
async fn accept_proposal_requires_a_json_body() {
    let t = TestApp::new().await;
    let (_a, s) = t.setup_admin("admin@example.org").await;
    let r = send(&t, "/v1/proposals/nope/accept", &s, &[], false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert_eq!(r.error_code(), "expected_json");
}
