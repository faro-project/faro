//! Floods and fairness (#194): per-device limits, coalesced alerts and
//! emails, round-robin dispatch and sending, and the storage quota. A modified
//! client must not be able to stall alerts for other members, and an honest
//! tamper alert behind a flood must still arrive.

mod common;

use axum::http::StatusCode;
use common::*;
use faro_proto::api::{EventResult, EventsBatchResponse};
use faro_proto::{EventKind, Urgency};
use faro_server::db::repo::alerts::{self, AlertSource, NewAlert};
use sqlx::Row;

fn batch(r: &Resp) -> EventsBatchResponse {
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body.clone()).expect("EventsBatchResponse")
}

#[tokio::test]
async fn event_floods_get_429_with_retry_after_and_store_nothing() {
    let t = TestApp::with_config(|c| c.device_limits.events_per_device_per_hour = 20).await;
    let (_m, _s, _k, mut dev) = t.active_device().await;

    let evs: Vec<_> = (0..15)
        .map(|_| dev.next_event(EventKind::Capture, Urgency::None))
        .collect();
    batch(&t.post_events(&dev, &evs).await);

    let more: Vec<_> = (0..15)
        .map(|_| dev.next_event(EventKind::Capture, Urgency::None))
        .collect();
    let r = t.post_events(&dev, &more).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{:?}", r.body);
    let wait: u64 = r.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!(wait >= 1);
    let stored = count_with(
        &t.state,
        "SELECT COUNT(*) FROM events WHERE device_id = $1",
        dev.id.as_str(),
    )
    .await;
    assert_eq!(stored, 15, "a refused batch stores nothing");

    // After the Retry-After the same batch goes through.
    t.clock
        .advance_ms(i64::try_from(wait).unwrap() * 1000 + 1000);
    let b = batch(&t.post_events(&dev, &more).await);
    assert!(b
        .results
        .iter()
        .all(|r| matches!(r, EventResult::Accepted { .. })));
}

#[tokio::test]
async fn bad_signature_floods_coalesce_to_one_counted_alert() {
    let t = TestApp::new().await;
    let (member, _s, _k, dev) = t.active_device().await;

    // 50 forged events with distinct seq values: one alert, not fifty.
    let evs: Vec<_> = (0..50)
        .map(|i| {
            let mut head = dev.head;
            head.next_seq += i;
            let mut ev = dev.event_at(head, EventKind::Capture, Urgency::None, b"x");
            ev.header.ts_ms += 1; // not covered by the signature check's inputs
            ev
        })
        .collect();
    let b = batch(&t.post_events(&dev, &evs).await);
    assert!(b
        .results
        .iter()
        .all(|r| matches!(r, EventResult::Rejected { .. })));
    let bad: Vec<_> = t
        .alerts(&member)
        .await
        .into_iter()
        .filter(|a| a.kind == "invalid_signature")
        .collect();
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert_eq!(
        bad[0].detail.as_deref(),
        Some("bad_event_signature;folded=49")
    );

    // The next interval is a fresh alert.
    t.clock.advance_ms(3_600_000);
    let ev = {
        let mut ev = dev.event_at(dev.head, EventKind::Capture, Urgency::None, b"x");
        ev.header.ts_ms += 1;
        ev
    };
    t.post_events(&dev, &[ev]).await;
    let n = t
        .alerts(&member)
        .await
        .iter()
        .filter(|a| a.kind == "invalid_signature")
        .count();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn an_honest_tamper_behind_an_alert_flood_is_folded_not_dropped() {
    let t = TestApp::with_config(|c| c.device_limits.alerts_per_device_per_hour = 5).await;
    let (member, _s, _k, mut dev) = t.active_device().await;
    let mut evs: Vec<_> = (0..20)
        .map(|_| dev.next_event(EventKind::Flag, Urgency::Urgent))
        .collect();
    evs.push(dev.next_event(EventKind::Tamper, Urgency::Urgent));
    let b = batch(&t.post_events(&dev, &evs).await);
    assert!(b
        .results
        .iter()
        .all(|r| matches!(r, EventResult::Accepted { .. })));

    let all = t.alerts(&member).await;
    let direct = all.iter().filter(|a| a.source == "device").count();
    assert_eq!(direct, 5, "{all:?}");
    let folded: Vec<_> = all
        .iter()
        .filter(|a| a.kind == "alerts_coalesced")
        .collect();
    assert_eq!(folded.len(), 1, "{all:?}");
    assert_eq!(folded[0].urgency, "urgent");
    // 21 alerts: 5 delivered one by one, 16 counted on the folded alert,
    // the tamper among them.
    assert_eq!(folded[0].detail.as_deref(), Some("coalesced;folded=16"));
    // The tamper event itself is stored and visible in the feed.
    assert!(stored_event(&t.state, &dev.id, 20).await.is_some());
}

#[tokio::test]
async fn one_coalesced_email_per_recipient_and_member_per_interval() {
    let t = TestApp::with_config(|c| c.device_limits.email_interval_secs = 60).await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    t.mailer.clear();

    let ev = dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.notify_now().await;
    assert_eq!(t.alert_mail_to(&pat.email).len(), 1);

    // Five more inside the interval: nothing goes out yet ...
    let evs: Vec<_> = (0..5)
        .map(|_| dev.next_event(EventKind::Flag, Urgency::Urgent))
        .collect();
    t.post_events(&dev, &evs).await;
    t.notify_now().await;
    let alert_mails = |to: &str| -> Vec<_> {
        t.mail_to(to)
            .into_iter()
            .filter(|m| m.subject.contains("alert"))
            .collect()
    };
    assert_eq!(alert_mails(&pat.email).len(), 1);

    // ... and afterwards they arrive as one email that counts them.
    t.clock.advance_ms(61_000);
    t.notify_now().await;
    let mails = alert_mails(&pat.email);
    assert_eq!(mails.len(), 2, "{mails:?}");
    assert_eq!(mails[1].subject, "Urgent: 5 new alerts for sam");
    // The member is told once as well, and nothing is left pending.
    let pending = count(
        &t.state,
        "SELECT COUNT(*) FROM notifications WHERE status = 'pending' AND mode = 'immediate'",
    )
    .await;
    assert_eq!(pending, 0);
}

fn server_alert<'a>(member: &'a faro_proto::UserId, key: String, now_ms: i64) -> NewAlert<'a> {
    NewAlert {
        member_id: member,
        device_id: None,
        source: AlertSource::Server,
        kind: "chain_gap",
        urgency: Urgency::Urgent,
        event_seq: None,
        detail: Some("x".into()),
        dedupe_key: Some(key),
        now_ms,
    }
}

/// Member A queues hundreds of alerts; member B raises one afterwards. B's
/// alert is fanned out in the first pass and emailed in the first send pass.
#[tokio::test]
async fn dispatch_and_send_are_fair_across_members() {
    let t = TestApp::new().await;
    let (sam, ms, mkeys, _dev) = t.active_device().await;
    let _pat = t.link_ally(&sam, &mkeys, &ms, "pat@elsewhere.net").await;
    let (kim, _ks) = t.sign_in("kim@example.org").await;

    let now = t.clock_ms();
    for i in 0..450 {
        alerts::insert(
            t.state.db().pool(),
            &server_alert(&sam, format!("flood:{i}"), now),
        )
        .await
        .unwrap();
    }
    t.clock.advance_ms(1000);
    alerts::insert(
        t.state.db().pool(),
        &server_alert(&kim, "kim:1".into(), t.clock_ms()),
    )
    .await
    .unwrap();

    // One fan-out pass handles 200 alerts: kim's comes with the first, not
    // after sam's 450.
    faro_server::notify::dispatch(&t.state).await.unwrap();
    let kim_dispatched = count_with(
        &t.state,
        "SELECT COUNT(*) FROM alerts WHERE member_id = $1 AND dispatched_at IS NOT NULL",
        kim.as_str(),
    )
    .await;
    assert_eq!(kim_dispatched, 1);
    let sam_left = count_with(
        &t.state,
        "SELECT COUNT(*) FROM alerts WHERE member_id = $1 AND dispatched_at IS NULL",
        sam.as_str(),
    )
    .await;
    assert!(sam_left > 0, "the flood is still being worked through");

    // Likewise for sending: sam has hundreds of queued emails, kim's goes
    // in the first batch of 100.
    t.mailer.clear();
    faro_server::notify::send_immediate(&t.state).await.unwrap();
    assert_eq!(
        t.mail_to("kim@example.org").len(),
        1,
        "kim's alert must not wait behind sam's backlog"
    );
    let row = sqlx::query("SELECT COUNT(*) FROM notifications WHERE status = 'pending'")
        .fetch_one(t.state.db().pool())
        .await
        .unwrap();
    assert!(row.get::<i64, _>(0) > 0);
}

#[tokio::test]
async fn over_quota_keeps_the_header_drops_the_body_and_alerts_allies() {
    let t = TestApp::with_config(|c| c.device_limits.storage_quota_mib = 1).await;
    let (member, _s, _k, mut dev) = t.active_device().await;
    let big = vec![b'a'; 700_000];

    let e0 = dev.event_at(dev.head, EventKind::Flag, Urgency::Normal, &big);
    dev.head.advance(&e0.header);
    let e1 = dev.event_at(dev.head, EventKind::Flag, Urgency::Normal, &big);
    dev.head.advance(&e1.header);
    let e2 = dev.next_event(EventKind::Tamper, Urgency::Urgent);
    let b = batch(&t.post_events(&dev, &[e0, e1, e2]).await);
    assert_eq!(b.acked_through, Some(2));
    assert!(b
        .results
        .iter()
        .all(|r| matches!(r, EventResult::Accepted { .. })));

    let (_, _, _, blob0) = stored_event(&t.state, &dev.id, 0).await.unwrap();
    let (_, _, _, blob1) = stored_event(&t.state, &dev.id, 1).await.unwrap();
    let (_, eff2, _, _) = stored_event(&t.state, &dev.id, 2).await.unwrap();
    assert!(blob0.is_some());
    assert!(blob1.is_none(), "over quota: header kept, body not stored");
    assert_eq!(eff2, "urgent", "the tamper event is stored regardless");

    let quota: Vec<_> = t
        .alerts(&member)
        .await
        .into_iter()
        .filter(|a| a.kind == "storage_quota")
        .collect();
    assert_eq!(quota.len(), 1, "surfaced to allies, not silent");
}
