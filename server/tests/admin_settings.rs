//! Changing instance settings is never silent (§4.3, §8): written to the
//! admin log, told to the other admins, announced to every member's allies
//! when it weakens monitoring, and a shorter retention window never reaches
//! back to data that already arrived.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::{EventKind, Urgency};
use faro_server::retention;
use serde_json::{json, Value};

const DAY: i64 = 24 * 3600 * 1000;

async fn patch(t: &TestApp, session: &str, body: Value) -> Resp {
    t.call(
        Method::PATCH,
        "/admin/api/settings",
        Some(body),
        Some(session),
    )
    .await
}

async fn blob_count(t: &TestApp) -> i64 {
    count(&t.state, "SELECT COUNT(*) FROM blobs").await
}

fn weakened_alerts(alerts: &[faro_server::db::repo::alerts::AlertRow]) -> Vec<String> {
    alerts
        .iter()
        .filter(|a| a.kind == "member_settings_changed")
        .filter_map(|a| a.detail.clone())
        .collect()
}

#[tokio::test]
async fn a_settings_change_is_logged_and_told_to_the_other_admins() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let r = t
        .call(
            Method::PUT,
            &format!("/admin/api/users/{kim}/admin"),
            Some(json!({"admin": true})),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    let kim_mail_before = t.mail_to("kim@example.org").len();
    let admin_mail_before = t.mail_to("admin@example.org").len();

    let r = patch(
        &t,
        &admin_s,
        json!({"liveness_grace_secs": 7200, "retention": {"blob_days": 14}}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    // A patch that changes nothing writes nothing.
    let r = patch(&t, &admin_s, json!({"retention": {"blob_days": 14}})).await;
    assert_eq!(r.status, StatusCode::OK);

    let log = t.get("/admin/api/log", Some(&kim_s)).await;
    let entries: Vec<&Value> = log.body.as_array().unwrap().iter().collect();
    let e = entries
        .iter()
        .find(|e| e["action"] == "settings_changed")
        .expect("logged");
    assert_eq!(e["actor"]["email"], "admin@example.org");
    let detail = e["detail"].as_str().unwrap();
    assert!(detail.contains("retention.blob_days:30>14"), "{detail}");
    assert!(
        detail.contains("liveness.grace_secs:10800>7200"),
        "{detail}"
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["action"] == "settings_changed")
            .count(),
        1
    );

    t.notify_now().await;
    let mail = t.mail_to("kim@example.org");
    assert_eq!(mail.len(), kim_mail_before + 1, "the other admin is told");
    assert!(mail.last().unwrap().text.contains("blob_days"));
    assert_eq!(
        t.mail_to("admin@example.org").len(),
        admin_mail_before,
        "not the admin who did it"
    );
}

#[tokio::test]
async fn retention_has_a_floor_in_the_console() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    for field in ["event_header_days", "blob_days", "alert_days"] {
        let r = patch(&t, &admin_s, json!({"retention": {field: 6}})).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(r.error_code(), "invalid_settings");
    }
    assert_eq!(t.state.settings().retention.blob_days, 30);
    let r = patch(&t, &admin_s, json!({"retention": {"blob_days": 7}})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

#[tokio::test]
async fn weakening_monitoring_alerts_every_members_allies() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s, sam_keys, _dev) = t.active_device().await;
    let _pat = t
        .link_ally(&sam, &sam_keys, &sam_s, "pat@elsewhere.net")
        .await;

    // Shorter grace and longer retention weaken nothing.
    let r = patch(
        &t,
        &admin_s,
        json!({"liveness_grace_secs": 3600, "retention": {"blob_days": 60}}),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(weakened_alerts(&t.alerts(&sam).await).is_empty());

    // A longer grace period does.
    t.clock.advance_ms(1000);
    patch(&t, &admin_s, json!({"liveness_grace_secs": 86400})).await;
    // So does shorter retention.
    t.clock.advance_ms(1000);
    patch(&t, &admin_s, json!({"retention": {"alert_days": 7}})).await;
    let details = weakened_alerts(&t.alerts(&sam).await);
    assert_eq!(details.len(), 2, "{details:?}");
    assert!(details.contains(&"instance_weakened:liveness_grace_longer".to_owned()));
    assert!(details.contains(&"instance_weakened:alert_days".to_owned()));
}

#[tokio::test]
async fn shorter_instance_retention_does_not_reach_back() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s, sam_keys, mut dev) = t.active_device().await;
    let pat = t
        .link_ally(&sam, &sam_keys, &sam_s, "pat@elsewhere.net")
        .await;
    let to_pat = [(pat.id.clone(), pat.keys.enc.public())];

    // Day 0: a flag sealed to pat.
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, b"x", &to_pat);
    t.post_events(&dev, &[ev]).await;
    assert_eq!(blob_count(&t).await, 1);

    // Day 10: the admin cuts blob retention to 7 days.
    t.clock.advance_ms(10 * DAY);
    let r = patch(&t, &admin_s, json!({"retention": {"blob_days": 7}})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        s.blobs, 0,
        "the 10-day-old flag keeps the old 30-day window"
    );

    // Day 11: a new flag, under the 7-day window.
    t.clock.advance_ms(DAY);
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, b"y", &to_pat);
    t.post_events(&dev, &[ev]).await;
    assert_eq!(blob_count(&t).await, 2);

    // Day 19: the new one (8 days old) goes; the old one (19 days) stays.
    t.clock.advance_ms(8 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 1);
    assert_eq!(blob_count(&t).await, 1);

    // Day 31: the old window ends for the old one.
    t.clock.advance_ms(12 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 1);
    assert_eq!(blob_count(&t).await, 0);
}
