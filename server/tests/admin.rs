//! The admin console API (§4.3): configuration and aggregate metadata only,
//! plus the privacy notice generated from live settings.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::{EventKind, Urgency};
use serde_json::json;
use std::sync::Arc;

const ADMIN_GETS: [&str; 3] = [
    "/admin/api/overview",
    "/admin/api/users",
    "/admin/api/settings",
];

#[tokio::test]
async fn admin_endpoints_require_the_admin_role() {
    let t = TestApp::new().await;
    t.setup_admin("admin@example.org").await;
    let (_m, ms, _k, _d) = t.active_device().await;
    for p in ADMIN_GETS {
        assert_eq!(t.get(p, None).await.status, StatusCode::UNAUTHORIZED, "{p}");
        let r = t.get(p, Some(&ms)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{p}");
        assert_eq!(r.error_code(), "not_an_admin");
    }
    let r = t
        .call(
            Method::PATCH,
            "/admin/api/settings",
            Some(json!({"registration_mode": "closed"})),
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t.post("/admin/api/smtp-test", json!({}), Some(&ms)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = t
        .post(
            "/admin/api/invites",
            json!({"email": "x@example.org"}),
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn overview_and_user_list_expose_only_aggregates_and_account_metadata() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let ev = dev.next_event_to(
        EventKind::Flag,
        Urgency::Urgent,
        b"{\"title\":\"PRIVATE-CONTENT\"}",
        &[(pat.id.clone(), pat.keys.enc.public())],
    );
    t.post_events(&dev, &[ev]).await;
    t.heartbeat(&dev, faro_proto::api::DeviceState::Active)
        .await;

    let o = t.get("/admin/api/overview", Some(&admin_s)).await;
    assert_eq!(o.status, StatusCode::OK, "{:?}", o.body);
    let b = &o.body;
    assert_eq!(b["users"]["total"], 3);
    assert_eq!(b["users"]["admins"], 1);
    assert_eq!(b["users"]["allies"], 1);
    assert_eq!(b["devices"]["active"], 1);
    assert_eq!(b["last_seen"]["within_1h"], 1);
    assert_eq!(b["storage"]["blob_count"], 1);
    assert!(b["storage"]["blobs"].as_i64().unwrap() > 0);
    assert!(b["storage"]["database"].as_i64().unwrap() > 0);
    // No per-member anything: no ids, names, emails, device names, kinds.
    let raw = String::from_utf8(o.raw.clone()).unwrap();
    for leak in [
        member.as_str(),
        pat.id.as_str(),
        dev.id.as_str(),
        "sam",
        "pat@",
        "MacBook",
        "flag",
        "PRIVATE",
    ] {
        assert!(!raw.contains(leak), "overview leaks {leak:?}: {raw}");
    }

    // The account list is account metadata: no relationships, no content.
    let u = t.get("/admin/api/users", Some(&admin_s)).await;
    assert_eq!(u.status, StatusCode::OK);
    let rows = u.body.as_array().unwrap();
    assert_eq!(rows.len(), 3);
    let sam = rows
        .iter()
        .find(|r| r["email"] == "sam@example.org")
        .unwrap();
    assert_eq!(sam["device_count"], 1);
    let raw = String::from_utf8(u.raw.clone()).unwrap();
    for leak in [
        "MacBook",
        "flag",
        "PRIVATE",
        "ally_id",
        "enc_pubkey",
        "sign_pubkey",
    ] {
        assert!(!raw.contains(leak), "user list leaks {leak:?}");
    }

    // And the admin role opens no content route.
    assert_eq!(
        t.feed(&member, &admin_s).await.status,
        StatusCode::NOT_FOUND
    );
    let blob: String = sqlx::Row::try_get(
        &sqlx::query("SELECT id FROM blobs")
            .fetch_one(t.state.db().pool())
            .await
            .unwrap(),
        "id",
    )
    .unwrap();
    assert_eq!(
        t.get(&format!("/v1/blobs/{blob}"), Some(&admin_s))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&format!("/v1/members/{member}/keys"), Some(&admin_s))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn settings_patch_validates_applies_live_and_persists() {
    let t = TestApp::new().await; // open for example.org
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;

    // Invalid changes are refused and change nothing.
    for bad in [
        json!({"liveness_grace_secs": 60}),
        json!({"retention": {"blob_days": 0}}),
        json!({"allowed_email_domains": ["not a domain"]}),
        json!({"registration_mode": "anyone"}),
        json!({"bogus": 1}),
    ] {
        let r = t
            .call(
                Method::PATCH,
                "/admin/api/settings",
                Some(bad.clone()),
                Some(&admin_s),
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let s = t.get("/admin/api/settings", Some(&admin_s)).await;
    assert_eq!(s.body["registration"]["mode"], "open");
    assert_eq!(s.body["liveness"]["grace_secs"], 10800);

    // Close registration: takes effect on the very next sign-up attempt.
    let r = t
        .call(
            Method::PATCH,
            "/admin/api/settings",
            Some(json!({"registration_mode": "closed", "retention": {"blob_days": 14}})),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["registration"]["mode"], "closed");
    assert_eq!(r.body["retention"]["blob_days"], 14);
    assert_eq!(r.body["retention"]["alert_days"], 90, "untouched");
    t.post(
        "/v1/auth/magic-link",
        json!({"email": "new@example.org"}),
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(t.mail_to("new@example.org").is_empty());

    // The privacy notice follows the live settings.
    let n = t.get("/v1/privacy-notice", None).await;
    assert_eq!(n.status, StatusCode::OK);
    assert_eq!(n.body["retention"]["blob_days"], 14);
    assert_eq!(n.body["registration_mode"], "closed");
    assert!(n.body["text"].as_str().unwrap().contains("14 days"));

    // Persisted: a restart on the same data keeps the admin's choice.
    let cfg = t.state.config().clone();
    let state2 = faro_server::bootstrap::open(
        cfg,
        Arc::new(faro_server::mailer::TestMailer::new()),
        Arc::new(faro_server::clock::ManualClock::starting_now()),
    )
    .await
    .unwrap();
    assert_eq!(
        state2.settings().registration.mode,
        faro_server::config::RegistrationMode::Closed
    );
    assert_eq!(state2.settings().retention.blob_days, 14);
}

#[tokio::test]
async fn smtp_test_only_mails_the_calling_admin() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let r = t
        .post(
            "/admin/api/smtp-test",
            json!({"to": "victim@example.org"}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["ok"], true);
    assert_eq!(r.body["sent_to"], "admin@example.org");
    assert!(t.mail_to("victim@example.org").is_empty());
    assert_eq!(
        t.mail_to("admin@example.org")
            .iter()
            .filter(|m| m.subject.contains("test email"))
            .count(),
        1
    );
    t.mailer.set_failing(true);
    let r = t
        .post("/admin/api/smtp-test", json!({}), Some(&admin_s))
        .await;
    assert_eq!(r.body["ok"], false);
    assert_eq!(r.body["error"], "test_failure");
}

#[tokio::test]
async fn privacy_notice_is_public_and_states_the_tradeoffs() {
    let t = TestApp::with_config(|c| c.instance.name = "Grace Church Faro".into()).await;
    let n = t.get("/v1/privacy-notice", None).await;
    assert_eq!(n.status, StatusCode::OK);
    assert_eq!(n.body["instance_name"], "Grace Church Faro");
    let text = n.body["text"].as_str().unwrap();
    assert!(text.contains("Grace Church Faro"));
    assert!(text.contains("CANNOT see"));
    assert!(text.contains("urgent event happened"));
    assert!(text.contains("30 days"), "{text}");
    assert!(n.body["operator_cannot_see"].as_array().unwrap().len() >= 3);
}
