//! First-run setup, magic-link sign-in, sessions, registration modes and the
//! HTTP security envelope.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;
use faro_proto::api::WellKnown;
use faro_server::config::RegistrationMode;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn well_known_describes_the_instance() {
    let t = TestApp::new().await;
    let r = t.get("/.well-known/faro", None).await;
    assert_eq!(r.status, StatusCode::OK);
    let wk: WellKnown = serde_json::from_value(r.body).unwrap();
    assert_eq!(&wk.instance_id, t.state.instance_id());
    assert!(wk.instance_id.is_well_formed());
    assert_eq!(wk.identity_pubkey, t.state.identity().public());
    assert_eq!(wk.name, "Faro");
    assert_eq!(wk.protocol, faro_proto::api::PROTOCOL_VERSION);
}

#[tokio::test]
async fn instance_id_and_identity_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let open = || async {
        faro_server::bootstrap::open(
            test_config(dir.path()),
            std::sync::Arc::new(faro_server::mailer::TestMailer::new()),
            std::sync::Arc::new(faro_server::clock::ManualClock::starting_now()),
        )
        .await
        .unwrap()
    };
    let a = open().await;
    let (id, pk) = (a.instance_id().clone(), a.identity().public());
    a.db().close().await;
    let b = open().await;
    assert_eq!(b.instance_id(), &id);
    assert_eq!(b.identity().public(), pk);
}

#[tokio::test]
async fn swapped_identity_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = test_config(dir.path());
    let open = |cfg| async {
        faro_server::bootstrap::open(
            cfg,
            std::sync::Arc::new(faro_server::mailer::TestMailer::new()),
            std::sync::Arc::new(faro_server::clock::ManualClock::starting_now()),
        )
        .await
    };
    let a = open(cfg.clone()).await.unwrap();
    a.db().close().await;
    std::fs::remove_file(cfg.data_dir.join("identity.key")).unwrap();
    assert!(matches!(
        open(cfg).await,
        Err(faro_server::bootstrap::BootstrapError::IdentityMismatch)
    ));
}

#[tokio::test]
async fn setup_token_is_single_use_and_only_before_an_admin_exists() {
    let t = TestApp::new().await;
    assert_eq!(t.get("/v1/setup", None).await.body["needs_setup"], true);

    let token = faro_server::bootstrap::issue_setup_token(&t.state)
        .await
        .unwrap()
        .unwrap();
    // Re-issuing invalidates the earlier token.
    let token2 = faro_server::bootstrap::issue_setup_token(&t.state)
        .await
        .unwrap()
        .unwrap();
    let body = |tok: &str, email: &str| json!({"setup_token": tok, "email": email, "display_name": "Admin"});
    let r = t
        .post("/v1/setup", body(&token, "admin@example.org"), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error_code(), "invalid_setup_token");

    // Invalid input does not burn the token.
    let r = t
        .post("/v1/setup", body(&token2, "not-an-email"), None)
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    let r = t
        .post("/v1/setup", body(&token2, "Admin@Example.org"), None)
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["user"]["email"], "admin@example.org");
    assert_eq!(r.body["user"]["roles"]["admin"], true);
    let cookie = session_from(&r.headers).unwrap();
    let set_cookie = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"));

    // Same token again: rejected (already set up).
    let r = t
        .post("/v1/setup", body(&token2, "evil@example.org"), None)
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "already_set_up");
    // And no further tokens can be minted.
    assert!(faro_server::bootstrap::issue_setup_token(&t.state)
        .await
        .unwrap()
        .is_none());
    assert_eq!(t.get("/v1/setup", None).await.body["needs_setup"], false);

    let me = t.get("/v1/me", Some(&cookie)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["user"]["email"], "admin@example.org");
    assert_eq!(me.body["has_member_keys"], false);
}

#[tokio::test]
async fn setup_tokens_expire_and_are_stored_hashed() {
    let t = TestApp::new().await;
    let token = faro_server::bootstrap::issue_setup_token(&t.state)
        .await
        .unwrap()
        .unwrap();
    // The plaintext appears nowhere in the database.
    let n = count_with(
        &t.state,
        "SELECT COUNT(*) FROM setup_tokens WHERE token_hash = $1",
        token.as_str(),
    )
    .await;
    assert_eq!(n, 0);
    t.clock
        .advance_ms(faro_server::bootstrap::SETUP_TOKEN_TTL_MS + 1);
    let r = t
        .post(
            "/v1/setup",
            json!({"setup_token": token.as_str(), "email": "a@example.org", "display_name": "A"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn magic_link_flow() {
    let t = TestApp::new().await;
    let (admin, _) = t.setup_admin("admin@example.org").await;

    let token = t.magic_link_token("admin@example.org").await;
    let email = t.mailer.sent().pop().unwrap();
    assert!(
        email.text.contains("/auth/verify#token="),
        "token is in the fragment"
    );

    let r = t
        .post(
            "/v1/auth/magic-link/verify",
            json!({ "token": token }),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["user"]["id"], admin.as_str());
    assert_eq!(r.body["created"], false);
    let cookie = session_from(&r.headers).unwrap();
    assert_eq!(t.get("/v1/me", Some(&cookie)).await.status, StatusCode::OK);

    // Single use.
    let r = t
        .post(
            "/v1/auth/magic-link/verify",
            json!({ "token": token }),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error_code(), "invalid_or_expired_link");

    // Logout kills the session server-side, not just the cookie.
    let r = t
        .call(Method::POST, "/v1/auth/logout", None, Some(&cookie))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert!(r.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    assert_eq!(
        t.get("/v1/me", Some(&cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn magic_links_expire_after_15_minutes() {
    let t = TestApp::new().await;
    t.setup_admin("admin@example.org").await;
    let token = t.magic_link_token("admin@example.org").await;
    t.clock.advance_ms(15 * 60 * 1000 + 1);
    let r = t
        .post(
            "/v1/auth/magic-link/verify",
            json!({ "token": token }),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sessions_expire_after_30_days() {
    let t = TestApp::new().await;
    let (_, cookie) = t.setup_admin("admin@example.org").await;
    t.clock.advance_ms(29 * 24 * 3600 * 1000);
    assert_eq!(t.get("/v1/me", Some(&cookie)).await.status, StatusCode::OK);
    t.clock.advance_ms(2 * 24 * 3600 * 1000);
    assert_eq!(
        t.get("/v1/me", Some(&cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn magic_link_response_does_not_reveal_accounts() {
    let t = TestApp::with_config(|c| c.registration.mode = RegistrationMode::InviteOnly).await;
    t.setup_admin("admin@example.org").await;
    let a = t
        .post(
            "/v1/auth/magic-link",
            json!({"email": "admin@example.org"}),
            None,
        )
        .await;
    let b = t
        .post(
            "/v1/auth/magic-link",
            json!({"email": "nobody@example.org"}),
            None,
        )
        .await;
    assert_eq!(a.status, b.status);
    assert_eq!(a.raw, b.raw);
    assert!(t
        .mailer
        .wait_for("admin@example.org", Duration::from_secs(5))
        .await
        .is_some());
    // Invite-only: no email, no account for strangers.
    assert!(t
        .mailer
        .wait_for("nobody@example.org", Duration::from_millis(100))
        .await
        .is_none());
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM users").await, 1);
}

#[tokio::test]
async fn open_registration_honours_the_domain_allowlist() {
    let t = TestApp::new().await; // open for example.org
    let (_, cookie) = t.sign_in("new@example.org").await;
    let me = t.get("/v1/me", Some(&cookie)).await;
    assert_eq!(me.body["user"]["roles"]["member"], true);
    assert_eq!(me.body["user"]["roles"]["admin"], false);

    let r = t
        .post(
            "/v1/auth/magic-link",
            json!({"email": "x@evil.example"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(t
        .mailer
        .wait_for("x@evil.example", Duration::from_millis(100))
        .await
        .is_none());
}

#[tokio::test]
async fn closed_registration_still_lets_existing_users_in() {
    let t = TestApp::with_config(|c| c.registration.mode = RegistrationMode::Closed).await;
    t.setup_admin("admin@example.org").await;
    t.magic_link_token("admin@example.org").await;
    t.post(
        "/v1/auth/magic-link",
        json!({"email": "new@example.org"}),
        None,
    )
    .await;
    assert!(t
        .mailer
        .wait_for("new@example.org", Duration::from_millis(100))
        .await
        .is_none());
}

#[tokio::test]
async fn garbage_and_forged_cookies_are_unauthorized() {
    let t = TestApp::new().await;
    for c in ["", "short", &"A".repeat(43), "../../etc"] {
        let r = t.get("/v1/me", Some(c)).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{c:?}");
        assert_eq!(r.error_code(), "unauthorized");
    }
}

#[tokio::test]
async fn json_endpoints_require_json_content_type() {
    let t = TestApp::new().await;
    // A cross-site HTML form can only send form/text bodies.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/auth/magic-link")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("email=a@example.org"))
        .unwrap();
    let r = t.send(req).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "expected_json");
}

#[tokio::test]
async fn oversized_json_is_rejected() {
    let t = TestApp::new().await;
    let big = "x".repeat(100 * 1024);
    let r = t
        .post("/v1/auth/magic-link", json!({ "email": big }), None)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn security_headers_and_uniform_errors() {
    let t = TestApp::new().await;
    let r = t.get("/v1/no/such/route", None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(r.error_code(), "not_found");
    // Unknown non-API paths go to the web app (its 404 page, or a note when
    // built without it); the security headers apply there too.
    let web = t.get("/no/such/route", None).await;
    assert_eq!(web.status, StatusCode::NOT_FOUND);
    for r in [&r, &web] {
        assert_eq!(r.headers["x-content-type-options"], "nosniff");
        assert_eq!(r.headers["referrer-policy"], "no-referrer");
        assert!(r.headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        // Dev mode: no HSTS.
        assert!(r.headers.get("strict-transport-security").is_none());
    }

    let r = t.call(Method::PUT, "/v1/me", None, None).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(r.error_code(), "method_not_allowed");
}

#[tokio::test]
async fn production_mode_sends_hsts_and_secure_host_cookies() {
    let t = TestApp::with_config(|c| {
        c.dev = false;
        c.public_url = "https://faro.example.org".into();
    })
    .await;
    let token = faro_server::bootstrap::issue_setup_token(&t.state)
        .await
        .unwrap()
        .unwrap();
    let r = t
        .post(
            "/v1/setup",
            json!({"setup_token": token.as_str(), "email": "a@example.org", "display_name": "A"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert!(r.headers.contains_key("strict-transport-security"));
    let c = r.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(c.starts_with("__Host-faro_session="), "{c}");
    assert!(c.contains("; Secure") && c.contains("HttpOnly") && c.contains("SameSite=Strict"));
}

#[tokio::test]
async fn unauthenticated_endpoints_are_rate_limited() {
    let t = TestApp::with_config(|c| c.rate_limit.unauthenticated_per_minute = 3).await;
    let body = json!({"enroll_code": "AAAA-AAAA", "sign_pubkey": faro_crypto::SigningKey::generate().public(),
                      "platform": "linux", "device_name": "x", "client_version": "0.1.0"});
    for _ in 0..3 {
        let r = t.post("/v1/devices/enroll", body.clone(), None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    let r = t.post("/v1/devices/enroll", body.clone(), None).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.error_code(), "rate_limited");
    assert!(r.headers.contains_key(header::RETRY_AFTER));
    // Buckets are per route: sign-in still works.
    let r = t
        .post(
            "/v1/auth/magic-link",
            json!({"email": "a@example.org"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    // And they refill.
    t.clock.advance_ms(60_000);
    let r = t.post("/v1/devices/enroll", body, None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn magic_links_are_limited_per_address() {
    let t = TestApp::with_config(|c| c.rate_limit.magic_links_per_email_per_hour = 2).await;
    t.setup_admin("admin@example.org").await;
    for _ in 0..4 {
        let r = t
            .post(
                "/v1/auth/magic-link",
                json!({"email": "admin@example.org"}),
                None,
            )
            .await;
        // Same answer whether or not the limit kicked in.
        assert_eq!(r.status, StatusCode::ACCEPTED);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let n = t
        .mailer
        .sent()
        .iter()
        .filter(|m| m.to == "admin@example.org")
        .count();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn people_can_change_their_own_display_name() {
    let t = TestApp::new().await;
    let (id, session) = t.setup_admin("sam@example.org").await;

    let r = t
        .call(
            Method::PATCH,
            "/v1/me",
            Some(json!({ "display_name": "  Sam Rivera  " })),
            Some(&session),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["user"]["display_name"], "Sam Rivera");
    assert_eq!(r.body["user"]["id"], id.as_str());
    let me = t.get("/v1/me", Some(&session)).await;
    assert_eq!(me.body["user"]["display_name"], "Sam Rivera");

    for bad in [
        json!(""),
        json!("   "),
        json!("x".repeat(65)),
        json!("tab\there"),
    ] {
        let r = t
            .call(
                Method::PATCH,
                "/v1/me",
                Some(json!({ "display_name": bad })),
                Some(&session),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(r.error_code(), "invalid_display_name");
    }
    // Only the name can change: roles and email are not editable here.
    let r = t
        .call(
            Method::PATCH,
            "/v1/me",
            Some(json!({ "email": "other@example.org" })),
            Some(&session),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // Signed out: no change.
    let r = t
        .call(
            Method::PATCH,
            "/v1/me",
            Some(json!({ "display_name": "Mallory" })),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}
