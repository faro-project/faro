//! Instance branding: the logo and the customization toggles, and the rules
//! for operator content (docs/SELF-HOSTING.md "Branding your instance").

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;
use image::{ImageBuffer, ImageFormat, Rgba, RgbaImage};
use serde_json::{json, Value};
use std::io::Cursor;

fn png(w: u32, h: u32) -> Vec<u8> {
    let img: RgbaImage = ImageBuffer::from_fn(w, h, |x, y| {
        Rgba([(x % 256) as u8, (y % 256) as u8, 90, 255])
    });
    let mut out = Cursor::new(Vec::new());
    img.write_to(&mut out, ImageFormat::Png).unwrap();
    out.into_inner()
}

async fn upload(t: &TestApp, session: Option<&str>, content_type: &str, body: Vec<u8>) -> Resp {
    let mut b = Request::builder()
        .method(Method::PUT)
        .uri("/admin/api/branding/logo")
        .header(header::CONTENT_TYPE, content_type);
    if let Some(s) = session {
        b = b.header(header::COOKIE, format!("{COOKIE}={s}"));
    }
    t.send(b.body(Body::from(body)).unwrap()).await
}

async fn patch(t: &TestApp, session: &str, body: Value) -> Resp {
    t.call(
        Method::PATCH,
        "/admin/api/branding",
        Some(body),
        Some(session),
    )
    .await
}

fn logo_path(id: &str) -> String {
    format!("/v1/branding/logo/{id}.png")
}

#[tokio::test]
async fn defaults_before_any_change() {
    let t = TestApp::new().await;
    let r = t.get("/v1/branding", None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.body,
        json!({
            "instance_name": "Faro",
            "show_name": true,
            "logo": null,
            "welcome": null,
            "support": null,
        })
    );
}

#[tokio::test]
async fn only_admins_change_branding() {
    let t = TestApp::new().await;
    t.setup_admin("admin@example.org").await;
    let (_m, ms) = t.sign_in("sam@example.org").await;
    for s in [None, Some(ms.as_str())] {
        let want = if s.is_some() {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(t.get("/admin/api/branding", s).await.status, want);
        let r = t
            .call(
                Method::PATCH,
                "/admin/api/branding",
                Some(json!({"show_name": false})),
                s,
            )
            .await;
        assert_eq!(r.status, want);
        assert_eq!(upload(&t, s, "image/png", png(8, 8)).await.status, want);
        let r = t
            .call(Method::DELETE, "/admin/api/branding/logo", None, s)
            .await;
        assert_eq!(r.status, want);
    }
    assert_eq!(t.get("/v1/branding", None).await.body["show_name"], true);
}

#[tokio::test]
async fn logo_upload_replace_and_remove() {
    let t = TestApp::new().await;
    let (_a, admin) = t.setup_admin("admin@example.org").await;

    let r = upload(&t, Some(&admin), "image/png", png(1024, 256)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["logo"]["width"], 512, "scaled down");
    assert_eq!(r.body["logo"]["height"], 128);
    let id1 = r.body["logo"]["id"].as_str().unwrap().to_owned();

    // Public, from this origin, as a PNG that can't be sniffed as anything
    // else, and cached for good: the URL changes with the logo.
    let pub_ = t.get("/v1/branding", None).await;
    assert_eq!(pub_.body["logo"]["id"], id1.as_str());
    let img = t.get(&logo_path(&id1), None).await;
    assert_eq!(img.status, StatusCode::OK);
    let h = &img.headers;
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(
        h[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("sandbox"));
    assert_eq!(h["cross-origin-resource-policy"], "same-origin");
    let back = image::load_from_memory(&img.raw).unwrap();
    assert_eq!((back.width(), back.height()), (512, 128));

    // Replacing it gives a new URL; the old one is gone.
    let r = upload(&t, Some(&admin), "image/png", png(40, 40)).await;
    let id2 = r.body["logo"]["id"].as_str().unwrap().to_owned();
    assert_ne!(id1, id2);
    assert_eq!(
        t.get(&logo_path(&id1), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(t.get(&logo_path(&id2), None).await.status, StatusCode::OK);

    // Switched off: still stored, but not shown.
    patch(&t, &admin, json!({"show_logo": false})).await;
    assert_eq!(t.get("/v1/branding", None).await.body["logo"], Value::Null);
    patch(&t, &admin, json!({"show_logo": true})).await;
    assert_eq!(
        t.get("/v1/branding", None).await.body["logo"]["id"],
        id2.as_str()
    );

    // Removed.
    let r = t
        .call(
            Method::DELETE,
            "/admin/api/branding/logo",
            None,
            Some(&admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["logo"], Value::Null);
    assert_eq!(t.get("/v1/branding", None).await.body["logo"], Value::Null);
    assert_eq!(
        t.get(&logo_path(&id2), None).await.status,
        StatusCode::NOT_FOUND
    );

    // Junk logo paths are a plain 404.
    for p in [
        "/v1/branding/logo/../../etc/passwd",
        "/v1/branding/logo/abc.png",
        "/v1/branding/logo/0123456789abcdef0123456789abcdef.svg",
    ] {
        assert_eq!(t.get(p, None).await.status, StatusCode::NOT_FOUND, "{p}");
    }
}

#[tokio::test]
async fn svg_and_unsafe_uploads_are_refused() {
    let t = TestApp::new().await;
    let (_a, admin) = t.setup_admin("admin@example.org").await;
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let cases: Vec<(&str, Vec<u8>, &str)> = vec![
        ("image/svg+xml", svg.to_vec(), "unsupported_logo_format"),
        // An SVG claiming to be a PNG is read by its bytes, not its label.
        ("image/png", svg.to_vec(), "unsupported_logo_format"),
        (
            "image/gif",
            b"GIF89a\x01\x00\x01\x00".to_vec(),
            "unsupported_logo_format",
        ),
        // Form posts can't send image types, so cross-site forms can't upload.
        (
            "multipart/form-data; boundary=x",
            png(8, 8),
            "unsupported_logo_format",
        ),
        ("text/plain", png(8, 8), "unsupported_logo_format"),
        (
            "image/png",
            b"\x89PNG\r\n\x1a\n\0\0\0\0junk".to_vec(),
            "unreadable_logo",
        ),
        ("image/png", vec![0; 1024 * 1024 + 1], "logo_too_large"),
    ];
    for (ct, body, code) in cases {
        let r = upload(&t, Some(&admin), ct, body).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{ct}");
        assert_eq!(r.error_code(), code, "{ct}");
    }
    assert_eq!(t.get("/v1/branding", None).await.body["logo"], Value::Null);
}

#[tokio::test]
async fn toggles_and_operator_text() {
    let t = TestApp::new().await;
    let (_a, admin) = t.setup_admin("admin@example.org").await;

    // A draft that is switched off is stored but not public.
    let r = patch(
        &t,
        &admin,
        json!({"welcome": "  Welcome to St. Mark's <b>group</b>  "}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.body["settings"]["welcome"],
        "Welcome to St. Mark's <b>group</b>"
    );
    assert_eq!(
        t.get("/v1/branding", None).await.body["welcome"],
        Value::Null
    );

    let r = patch(
        &t,
        &admin,
        json!({
            "welcome_enabled": true,
            "support_enabled": true,
            "support": "help@church.example",
            "show_name": false,
        }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let b = t.get("/v1/branding", None).await.body;
    // Plain text: sent as it was written, for the page to show as text.
    assert_eq!(b["welcome"], "Welcome to St. Mark's <b>group</b>");
    assert_eq!(
        b["support"],
        json!({"kind": "email", "value": "help@church.example"})
    );
    assert_eq!(b["show_name"], false);

    patch(
        &t,
        &admin,
        json!({"support": "https://church.example/help"}),
    )
    .await;
    assert_eq!(
        t.get("/v1/branding", None).await.body["support"],
        json!({"kind": "url", "value": "https://church.example/help"})
    );

    // Refused, and nothing changes.
    let long = "x".repeat(201);
    for (bad, code) in [
        (json!({"welcome": "two\nlines"}), "invalid_welcome"),
        (json!({"welcome": long}), "invalid_welcome"),
        (json!({"welcome": "abc \u{202E}gnp.exe"}), "invalid_welcome"),
        (json!({"welcome": ""}), "invalid_welcome"), // still switched on
        (
            json!({"support": "javascript:alert(1)"}),
            "invalid_support_contact",
        ),
        (
            json!({"support": "http://church.example"}),
            "invalid_support_contact",
        ),
        (
            json!({"support": "data:text/html,x"}),
            "invalid_support_contact",
        ),
        (json!({"support": ""}), "invalid_support_contact"), // still switched on
        (json!({"welcome_html": "<b>x</b>"}), "invalid_json"),
    ] {
        let r = patch(&t, &admin, bad.clone()).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(r.error_code(), code, "{bad}");
    }
    let b = t.get("/v1/branding", None).await.body;
    assert_eq!(b["welcome"], "Welcome to St. Mark's <b>group</b>");
    assert_eq!(b["support"]["value"], "https://church.example/help");

    // Switching off hides them again.
    patch(
        &t,
        &admin,
        json!({"welcome_enabled": false, "support_enabled": false}),
    )
    .await;
    let b = t.get("/v1/branding", None).await.body;
    assert_eq!(b["welcome"], Value::Null);
    assert_eq!(b["support"], Value::Null);
}

#[tokio::test]
async fn branding_stays_out_of_security_relevant_places_and_notifies_nobody() {
    let t = TestApp::new().await;
    let (_a, admin) = t.setup_admin("admin@example.org").await;
    let (_member, _ms, _keys, _dev) = t.active_device().await;
    let alerts_before = count(&t.state, "SELECT COUNT(*) FROM alerts").await;
    let notifications_before = count(&t.state, "SELECT COUNT(*) FROM notifications").await;
    let mail_before = t.mailer.sent().len();

    let marker = "OPERATOR-MARKER";
    let r = patch(
        &t,
        &admin,
        json!({
            "welcome_enabled": true,
            "welcome": marker,
            "support_enabled": true,
            "support": "operator-marker@church.example",
        }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    upload(&t, Some(&admin), "image/png", png(16, 16)).await;
    t.notify_now().await;

    // Nobody is told: no alert, no notification, no email.
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM alerts").await,
        alerts_before
    );
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM notifications").await,
        notifications_before
    );
    assert_eq!(t.mailer.sent().len(), mail_before);

    // Enrollment confirmation (`/.well-known/faro`) doesn't carry it.
    let wk = t.get("/.well-known/faro", None).await;
    let raw = String::from_utf8(wk.raw).unwrap();
    assert!(!raw.to_lowercase().contains("operator-marker"), "{raw}");
    assert!(!raw.contains("logo"), "{raw}");

    // Nor do emails.
    t.magic_link_token("new@example.org").await;
    for m in t.mail_to("new@example.org") {
        assert!(!m.text.to_lowercase().contains("operator-marker"));
        assert!(!m.subject.to_lowercase().contains("operator-marker"));
    }
}

#[tokio::test]
async fn branding_persists_in_the_database() {
    let t = TestApp::new().await;
    let (_a, admin) = t.setup_admin("admin@example.org").await;
    patch(&t, &admin, json!({"show_name": false})).await;
    let id = upload(&t, Some(&admin), "image/png", png(20, 10))
        .await
        .body["logo"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // A restart on the same data keeps it (and a backup of the database has
    // it: the logo is a column, not a separate file).
    let state2 = faro_server::bootstrap::open(
        t.state.config().clone(),
        std::sync::Arc::new(faro_server::mailer::TestMailer::new()),
        std::sync::Arc::new(t.clock.clone()),
    )
    .await
    .unwrap();
    let app2 = faro_server::router::build(state2);
    let resp = tower::ServiceExt::oneshot(
        app2,
        Request::get("/v1/branding").body(Body::empty()).unwrap(),
    )
    .await
    .unwrap();
    let raw = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let b: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(b["show_name"], false);
    assert_eq!(b["logo"]["id"], id.as_str());
}
