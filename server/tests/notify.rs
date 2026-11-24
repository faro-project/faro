//! The notifier (§5.4): content-free text, urgency routing, digests, the
//! tamper floor, quiet hours and delivery retries.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::{EventKind, Urgency};
use faro_server::mailer::MailError;
use faro_server::notify::policy::{MAX_ATTEMPTS, OUTAGE_RETRY_MS};
use serde_json::json;
use sqlx::Row;

const PLAINTEXT: &[u8] = b"{\"url\":\"https://very-secret.example/page\"}";

/// The words a notification must never contain: anything from the body,
/// and not even the event kind.
fn assert_content_free(text: &str) {
    for leak in [
        "very-secret",
        "secret",
        "flag",
        "tamper",
        "url",
        "goodbye",
        "settings",
    ] {
        assert!(
            !text.to_lowercase().contains(leak),
            "notification leaks {leak:?}: {text}"
        );
    }
}

async fn statuses(t: &TestApp) -> Vec<(String, String, String)> {
    sqlx::query(
        "SELECT u.email, n.status, n.mode FROM notifications n
         JOIN users u ON u.id = n.recipient_id ORDER BY u.email, n.created_at",
    )
    .fetch_all(t.state.db().pool())
    .await
    .unwrap()
    .iter()
    .map(|r| {
        (
            r.try_get("email").unwrap(),
            r.try_get("status").unwrap(),
            r.try_get("mode").unwrap(),
        )
    })
    .collect()
}

#[tokio::test]
async fn urgent_event_sends_an_immediate_content_free_email_to_member_and_allies() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    t.mailer.clear();
    let ev = dev.next_event_to(
        EventKind::Flag,
        Urgency::Urgent,
        PLAINTEXT,
        &[(pat.id.clone(), pat.keys.enc.public())],
    );
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;

    for to in [pat.email.as_str(), "sam@example.org"] {
        let mails = t.alert_mail_to(to);
        assert_eq!(mails.len(), 1, "{to}: {mails:?}");
        let m = &mails[0];
        assert_eq!(m.subject, "Urgent: new alert for sam");
        assert!(
            m.text
                .starts_with("Urgent: new alert for sam on Sam's MacBook. Open Faro to view."),
            "{}",
            m.text
        );
        assert_content_free(&m.text);
        assert_content_free(&m.subject);
    }
    // Sent once only: running again sends nothing new.
    t.notify_now().await;
    assert_eq!(t.alert_mail_to(&pat.email).len(), 1);
    // A stranger on the instance hears nothing.
    let (_, _) = t.sign_in("eve@example.org").await;
    t.notify_now().await;
    assert!(t
        .mail_to("eve@example.org")
        .iter()
        .all(|m| m.subject.starts_with("Sign in")));
}

#[tokio::test]
async fn normal_events_go_to_the_hourly_digest() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    t.mailer.clear();
    let evs = vec![
        dev.next_event(EventKind::SettingsChange, Urgency::Normal),
        dev.next_event(EventKind::Paused, Urgency::None), // floored to normal
        dev.next_event(EventKind::Flag, Urgency::Urgent),
    ];
    t.post_events(&dev, &evs).await;
    t.notify_now().await;
    // Only the urgent one went out immediately.
    assert_eq!(t.alert_mail_to(&pat.email).len(), 1);
    assert!(t.digests_to(&pat.email).is_empty());

    // Not before the oldest item has waited an hour.
    t.clock.advance_ms(59 * 60 * 1000);
    let early = faro_server::notify::send_digests(&t.state).await.unwrap();
    assert_eq!(early.sent, 0);
    t.clock.advance_ms(-59 * 60 * 1000);
    let s = t.digest_now().await;
    assert_eq!(s.sent, 2, "one digest per recipient: {s:?}");
    let d = t.digests_to(&pat.email);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].subject, "Faro digest: 2 new items");
    assert!(d[0].text.contains("- sam: 2 alerts"), "{}", d[0].text);
    assert_content_free(&d[0].text);
    // Nothing is sent twice.
    assert_eq!(t.digest_now().await.sent, 0);
}

#[tokio::test]
async fn tamper_alerts_cannot_be_turned_off_only_moved_to_digest() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;

    // The ally turns everything off.
    let r = t
        .call(
            Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({
                "member_id": member, "urgent": "off", "normal": "off", "none": "off"
            })),
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["urgent"], "off");
    assert_eq!(r.body["tamper_minimum"], "digest");
    t.mailer.clear();

    // A high flag is silenced; a tamper event (even signed `none`) and an
    // uninstall are not.
    let evs = vec![
        dev.next_event(EventKind::Flag, Urgency::Urgent),
        dev.next_event(EventKind::Tamper, Urgency::None),
        dev.next_event(EventKind::Goodbye, Urgency::Urgent),
    ];
    t.post_events(&dev, &evs).await;
    t.notify_now().await;
    assert!(t.alert_mail_to(&pat.email).is_empty(), "nothing immediate");
    let d = t.digest_now().await;
    assert!(d.sent >= 1);
    let digests = t.digests_to(&pat.email);
    assert_eq!(digests.len(), 1);
    assert!(
        digests[0].text.contains("- sam: 2 urgent alerts"),
        "{}",
        digests[0].text
    );
    let st = statuses(&t).await;
    let pat_rows: Vec<_> = st.iter().filter(|r| r.0 == pat.email).collect();
    assert_eq!(
        pat_rows.iter().filter(|r| r.1 == "suppressed").count(),
        1,
        "only the flag is suppressed: {pat_rows:?}"
    );
    // The member's own defaults are untouched: immediate for all three.
    assert_eq!(t.alert_mail_to("sam@example.org").len(), 3);

    // Server-raised chain gaps are tamper-class too.
    let mut skipped = dev.head;
    skipped.next_seq += 5;
    let gap = dev.event_at(skipped, EventKind::Capture, Urgency::None, b"x");
    t.post_events(&dev, &[gap]).await;
    t.mailer.clear();
    t.notify_now().await;
    assert!(t.alert_mail_to(&pat.email).is_empty());
    t.digest_now().await;
    assert_eq!(t.digests_to(&pat.email).len(), 1);
}

#[tokio::test]
async fn quiet_hours_defer_until_they_end() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    // Put the clock at 23:00 UTC and set quiet hours 22:00-07:00 UTC.
    let day = 24 * 3600 * 1000;
    let midnight = t.clock_ms() - t.clock_ms().rem_euclid(day);
    t.clock.set_ms(midnight + day + 23 * 3600 * 1000);
    let r = t
        .call(
            Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({
                "member_id": member,
                "quiet_hours": {"start_min": 1320, "end_min": 420, "tz_offset_min": 0}
            })),
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        r.body["urgent"], "immediate",
        "unchanged modes keep defaults"
    );
    t.mailer.clear();
    // Even a tamper alert waits for the end of quiet hours (it is never dropped).
    let ev = dev.next_event(EventKind::Tamper, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;
    assert!(t.alert_mail_to(&pat.email).is_empty());
    assert_eq!(
        t.alert_mail_to("sam@example.org").len(),
        1,
        "member has no quiet hours"
    );
    // 06:59 next morning: still quiet.
    t.clock
        .set_ms(midnight + 2 * day + 7 * 3600 * 1000 - 60_000);
    t.notify_now().await;
    assert!(t.alert_mail_to(&pat.email).is_empty());
    // 07:00: delivered.
    t.clock.set_ms(midnight + 2 * day + 7 * 3600 * 1000);
    t.notify_now().await;
    assert_eq!(t.alert_mail_to(&pat.email).len(), 1);

    // Invalid quiet hours are refused.
    let r = t
        .call(
            Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({
                "member_id": member,
                "quiet_hours": {"start_min": 1440, "end_min": 0, "tz_offset_min": 0}
            })),
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_quiet_hours");
}

#[tokio::test]
async fn failed_deliveries_retry_with_backoff_then_fail_and_admins_see_counts() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (_member, _ms, _mkeys, mut dev) = t.active_device().await;
    // The recipient's mailbox is temporarily unavailable (450/452): that is
    // about this message, so it is charged an attempt.
    t.mailer.fail_with(Some(MailError::RecipientDeferred));
    let ev = dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;
    let row =
        sqlx::query("SELECT attempts, status, last_error, next_attempt_at FROM notifications")
            .fetch_one(t.state.db().pool())
            .await
            .unwrap();
    assert_eq!(row.try_get::<i64, _>("attempts").unwrap(), 1);
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "pending");
    assert_eq!(
        row.try_get::<String, _>("last_error").unwrap(),
        "recipient_deferred"
    );
    let next: i64 = row.try_get("next_attempt_at").unwrap();
    assert_eq!(next, t.clock_ms() + 60_000, "first retry after a minute");

    // Not retried before the backoff elapses.
    t.notify_now().await;
    assert_eq!(
        count(&t.state, "SELECT MAX(attempts) FROM notifications").await,
        1
    );
    // Keep failing until it gives up.
    for _ in 1..MAX_ATTEMPTS {
        t.clock.advance_ms(7 * 3600 * 1000);
        t.notify_now().await;
    }
    let row = sqlx::query("SELECT attempts, status FROM notifications")
        .fetch_one(t.state.db().pool())
        .await
        .unwrap();
    assert_eq!(row.try_get::<i64, _>("attempts").unwrap(), MAX_ATTEMPTS);
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "failed");

    // Admins see counts, never recipients or text.
    let o = t.get("/admin/api/overview", Some(&admin_s)).await;
    assert_eq!(o.status, StatusCode::OK);
    assert_eq!(o.body["notifications"]["failed"], 1);
    assert!(!o.raw.windows(3).any(|w| w == b"sam"));

    // A recovered mailbox gets the next alert normally.
    t.mailer.fail_with(None);
    let ev = dev.next_event(EventKind::Goodbye, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;
    assert_eq!(t.alert_mail_to("sam@example.org").len(), 1);
}

async fn rows(t: &TestApp) -> Vec<(String, i64, Option<String>)> {
    // Notifications about device alerts only (linking an ally queues a
    // digest line about it too).
    sqlx::query(
        "SELECT n.status, n.attempts, n.last_error FROM notifications n
         JOIN alerts a ON a.id = n.alert_id WHERE a.source = 'device'
         ORDER BY n.created_at, n.id",
    )
    .fetch_all(t.state.db().pool())
    .await
    .unwrap()
    .iter()
    .map(|r| {
        (
            r.try_get("status").unwrap(),
            r.try_get("attempts").unwrap(),
            r.try_get("last_error").unwrap(),
        )
    })
    .collect()
}

#[tokio::test]
async fn an_smtp_outage_never_fails_alerts_and_they_go_out_once_fixed() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    // The app password expired: every AUTH is answered 535 5.7.8.
    t.mailer.fail_with(Some(MailError::Rejected));
    let evs = vec![
        dev.next_event(EventKind::Tamper, Urgency::Urgent),
        dev.next_event(EventKind::Flag, Urgency::Urgent),
    ];
    t.post_events(&dev, &evs).await;
    t.notify_now().await;
    let r = rows(&t).await;
    assert_eq!(r.len(), 4, "member and pat, two alerts each: {r:?}");
    for (status, attempts, err) in &r {
        assert_eq!(status, "pending");
        assert_eq!(*attempts, 0, "an outage is not charged to the rows");
        assert_eq!(err.as_deref(), Some("rejected"));
    }
    // A day of outage (far beyond MAX_ATTEMPTS backoffs), digests included.
    for _ in 0..(24 * 6) {
        t.clock.advance_ms(10 * 60 * 1000);
        t.notify_now().await;
        faro_server::notify::send_digests(&t.state).await.unwrap();
    }
    assert!(rows(&t)
        .await
        .iter()
        .all(|(status, attempts, _)| status == "pending" && *attempts == 0));
    assert!(t.alert_mail_to(&pat.email).is_empty());

    // The admin fixes the password: everything raised during the outage,
    // the tamper alert first of all, is delivered.
    t.mailer.fail_with(None);
    t.clock.advance_ms(OUTAGE_RETRY_MS);
    t.notify_now().await;
    assert_eq!(t.alert_mail_to("sam@example.org").len(), 2);
    assert_eq!(t.alert_mail_to(&pat.email).len(), 2);
    assert!(rows(&t).await.iter().all(|(status, ..)| status == "sent"));

    // A permanent rejection of one recipient fails that row alone, at once.
    t.mailer.fail_with(Some(MailError::RecipientRejected));
    let ev = dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;
    let r = rows(&t).await;
    let new: Vec<_> = r.iter().filter(|(s, ..)| s != "sent").collect();
    assert_eq!(new.len(), 2, "{r:?}");
    for (status, attempts, err) in new {
        assert_eq!((status.as_str(), *attempts), ("failed", 1));
        assert_eq!(err.as_deref(), Some("recipient_rejected"));
    }
}

#[tokio::test]
async fn prefs_are_only_for_people_linked_to_the_member() {
    let t = TestApp::new().await;
    let (member, ms, _mkeys, _dev) = t.active_device().await;
    let (_eve, eve_s) = t.sign_in("eve@example.org").await;
    let r = t
        .get(
            &format!("/v1/me/notification-prefs?member_id={member}"),
            Some(&eve_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .call(
            Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({"member_id": member, "urgent": "off"})),
            Some(&eve_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The member may tune their own copy; defaults are shown.
    let r = t
        .get(
            &format!("/v1/me/notification-prefs?member_id={member}"),
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        (
            r.body["urgent"].as_str(),
            r.body["normal"].as_str(),
            r.body["none"].as_str()
        ),
        (Some("immediate"), Some("digest"), Some("off"))
    );
    // Unknown modes are rejected by the schema.
    let r = t
        .call(
            Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({"member_id": member, "urgent": "never"})),
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reports_notify_only_when_opted_in() {
    let t = TestApp::new().await;
    let (member, ms, _mkeys, dev) = t.active_device().await;
    // Default: reports (urgency none) are not notified.
    upload_report(&t, &dev).await;
    t.notify_now().await;
    t.digest_now().await;
    assert!(t
        .mail_to("sam@example.org")
        .iter()
        .all(|m| m.subject.starts_with("Sign in")));
    // Opt in to a digest line for routine items.
    t.call(
        Method::PUT,
        "/v1/me/notification-prefs",
        Some(json!({"member_id": member, "none": "digest"})),
        Some(&ms),
    )
    .await;
    t.clock.advance_ms(1000);
    upload_report(&t, &dev).await;
    t.digest_now().await;
    let d = t.digests_to("sam@example.org");
    assert_eq!(d.len(), 1);
    assert!(d[0].text.contains("1 new report"), "{}", d[0].text);
}

async fn upload_report(t: &TestApp, dev: &TestDevice) {
    use faro_proto::report::{ReportHeader, ReportUpload};
    let body = faro_crypto::seal_item(
        b"report",
        b"aad",
        &[faro_crypto::Recipient {
            user_id: dev.member_id.clone(),
            pubkey: dev.member_enc,
        }],
    )
    .unwrap();
    let now = t.clock_ms();
    let header = ReportHeader {
        v: 1,
        instance_id: t.instance_id(),
        member_id: dev.member_id.clone(),
        device_id: dev.id.clone(),
        period_start_ms: now - 3600 * 1000,
        period_end_ms: now,
        first_seq: None,
        last_seq: None,
        body_hash: body.body_hash(),
        body_len: body.ciphertext.len() as u64,
    };
    let sig = dev.key.sign(&header);
    let r = t
        .device_post(dev, "/v1/reports", &ReportUpload { header, sig, body })
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

#[tokio::test]
async fn queued_alerts_are_dropped_for_removed_allies_and_disabled_users() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let lee = t.link_ally(&member, &mkeys, &ms, "lee@elsewhere.net").await;
    let ev = dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    // Fanned out (queued for sam, pat and lee) but not sent yet.
    faro_server::notify::dispatch(&t.state).await.unwrap();
    // pat is removed and lee's account is disabled before the sender runs.
    let r = t.remove_ally(&member, &mkeys, &ms, &pat.id).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    sqlx::query("UPDATE users SET disabled = 1 WHERE id = $1")
        .bind(lee.id.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();
    t.mailer.clear();
    // pat's row is suppressed by the removal itself, lee's at send time.
    let s = faro_server::notify::send_immediate(&t.state).await.unwrap();
    assert_eq!((s.sent, s.dropped), (1, 1), "{s:?}");
    assert!(t.alert_mail_to(&pat.email).is_empty());
    assert!(t.alert_mail_to(&lee.email).is_empty());
    assert_eq!(t.alert_mail_to("sam@example.org").len(), 1);
    let st = statuses(&t).await;
    for who in [&pat.email, &lee.email] {
        assert!(
            st.iter()
                .filter(|r| &r.0 == who && r.2 == "immediate")
                .all(|r| r.1 == "suppressed"),
            "{st:?}"
        );
    }
}
