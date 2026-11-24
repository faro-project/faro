//! Device ingest: `events:batch`, heartbeats and reports, with real signed,
//! hash-chained, encrypted events, plus adversarial device authentication.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_crypto::{seal_item, ChainHead, Recipient, SigningKey};
use faro_proto::api::{
    DeviceState, EventResult, EventsBatchResponse, Heartbeat, HeartbeatResponse,
    REQUEST_MAX_SKEW_MS,
};
use faro_proto::report::{ReportHeader, ReportUpload};
use faro_proto::{EncryptedItem, EventKind, Hash32, Urgency, UserId};
use faro_server::blob::BlobId;
use serde_json::json;

fn batch(r: &Resp) -> EventsBatchResponse {
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body.clone()).expect("EventsBatchResponse")
}

fn alerts_of<'a>(
    all: &'a [faro_server::db::repo::alerts::AlertRow],
    kind: &str,
) -> Vec<&'a faro_server::db::repo::alerts::AlertRow> {
    all.iter().filter(|a| a.kind == kind).collect()
}

#[tokio::test]
async fn contiguous_events_are_stored_as_ciphertext_only() {
    let t = TestApp::new().await;
    let (member, _s, keys, mut dev) = t.active_device().await;
    let evs: Vec<_> = (0..3)
        .map(|_| dev.next_event(EventKind::Capture, Urgency::None))
        .collect();
    let b = batch(&t.post_events(&dev, &evs).await);
    assert_eq!(
        b.results,
        (0..3)
            .map(|seq| EventResult::Accepted { seq })
            .collect::<Vec<_>>()
    );
    assert_eq!(b.acked_through, Some(2));

    // The stored body is the encrypted item, byte-for-byte openable by the
    // member and containing no plaintext.
    let (urgency, eff, header_json, blob_id) = stored_event(&t.state, &dev.id, 1).await.unwrap();
    assert_eq!((urgency.as_str(), eff.as_str()), ("none", "none"));
    let header: faro_proto::EventHeader = serde_json::from_str(&header_json).unwrap();
    assert_eq!(header, evs[1].header, "signed header stored verbatim");
    faro_crypto::verify_item(&dev.key.public(), &header, &evs[1].sig).unwrap();
    let raw = t
        .state
        .blobs()
        .get(&BlobId::parse(&blob_id.unwrap()).unwrap())
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("blurred"));
    let item: EncryptedItem = serde_json::from_slice(&raw).unwrap();
    let pt = faro_crypto::open_item(&item, &header.body_aad(), &member, &keys.enc).unwrap();
    assert_eq!(pt.as_slice(), b"{\"blurred\":true}");

    // Envelope recipients are indexed for the (stage-B) feed.
    assert_eq!(
        count_with(
            &t.state,
            "SELECT COUNT(*) FROM event_recipients WHERE recipient_id = $1",
            member.as_str()
        )
        .await,
        3
    );
    // Clean captures notify nobody.
    assert!(t.alerts(&member).await.is_empty());

    // Heartbeat and device status report the verified head.
    let me = t
        .device_call(&dev, Method::GET, "/v1/devices/self", b"")
        .await;
    assert_eq!(me.body["acked_through"], 2);
}

#[tokio::test]
async fn duplicates_gaps_forks_and_rewrites() {
    let t = TestApp::new().await;
    let (member, _s, _keys, mut dev) = t.active_device().await;
    let e0 = dev.next_event(EventKind::Boot, Urgency::None);
    let e1 = dev.next_event(EventKind::Capture, Urgency::None);
    batch(&t.post_events(&dev, &[e0.clone(), e1.clone()]).await);

    // Idempotent re-upload (the device lost our response).
    let b = batch(&t.post_events(&dev, &[e0.clone(), e1.clone()]).await);
    assert_eq!(
        b.results,
        vec![
            EventResult::Duplicate { seq: 0 },
            EventResult::Duplicate { seq: 1 }
        ]
    );
    assert_eq!(b.acked_through, Some(1));
    assert!(t.alerts(&member).await.is_empty());

    // Conflicting rewrite of an already-stored seq.
    let rewrite = dev.event_at(
        ChainHead {
            next_seq: 1,
            prev_hash: e0.header.chain_hash(),
        },
        EventKind::Capture,
        Urgency::None,
        b"different",
    );
    let b = batch(&t.post_events(&dev, &[rewrite]).await);
    assert_eq!(
        b.results,
        vec![EventResult::Rejected {
            seq: 1,
            reason: "conflicting_rewrite".into()
        }]
    );
    let gaps = t.alerts(&member).await;
    let gaps = alerts_of(&gaps, "chain_gap");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].urgency, "urgent");
    assert_eq!(gaps[0].source, "server");

    // Gap: seq 2 is deleted locally, seq 3 arrives.
    let _deleted = dev.next_event(EventKind::Flag, Urgency::Urgent);
    let e3 = dev.next_event(EventKind::Capture, Urgency::None);
    let b = batch(&t.post_events(&dev, &[e3]).await);
    assert_eq!(b.results, vec![EventResult::Accepted { seq: 3 }]);
    assert_eq!(b.acked_through, Some(3));
    let all = t.alerts(&member).await;
    let gap = alerts_of(&all, "chain_gap")
        .into_iter()
        .find(|a| a.detail.as_deref() == Some("missing 2..=2"))
        .expect("gap alert");
    assert_eq!(gap.urgency, "urgent");
    assert_eq!(gap.event_seq, Some(3));

    // The missing event showing up late cannot be slotted back in.
    let b = batch(&t.post_events(&dev, &[_deleted]).await);
    assert_eq!(
        b.results,
        vec![EventResult::Rejected {
            seq: 2,
            reason: "late_event_in_recorded_gap".into()
        }]
    );

    // Fork: right seq, wrong prev_hash. Rejected; head does not move.
    let fork = dev.event_at(
        ChainHead {
            next_seq: 4,
            prev_hash: Hash32::of(b"rewritten history"),
        },
        EventKind::Capture,
        Urgency::None,
        b"x",
    );
    let before = alerts_of(&t.alerts(&member).await, "chain_gap").len();
    let b = batch(&t.post_events(&dev, std::slice::from_ref(&fork)).await);
    assert_eq!(
        b.results,
        vec![EventResult::Rejected {
            seq: 4,
            reason: "fork".into()
        }]
    );
    assert_eq!(b.acked_through, Some(3));
    assert_eq!(
        alerts_of(&t.alerts(&member).await, "chain_gap").len(),
        before + 1
    );
    // Retrying the same fork does not page allies again.
    batch(&t.post_events(&dev, &[fork]).await);
    assert_eq!(
        alerts_of(&t.alerts(&member).await, "chain_gap").len(),
        before + 1
    );

    // The genuine continuation is still accepted.
    let e4 = dev.next_event(EventKind::Capture, Urgency::None);
    let b = batch(&t.post_events(&dev, &[e4]).await);
    assert_eq!(b.results, vec![EventResult::Accepted { seq: 4 }]);
}

#[tokio::test]
async fn urgency_is_floored_by_kind_but_header_is_kept_verbatim() {
    let t = TestApp::new().await;
    let (member, _s, _keys, mut dev) = t.active_device().await;
    // A modified client signs a tamper event as "none".
    let tamper = dev.next_event(EventKind::Tamper, Urgency::None);
    let settings = dev.next_event(EventKind::SettingsChange, Urgency::None);
    let flag = dev.next_event(EventKind::Flag, Urgency::None);
    let high = dev.next_event(EventKind::Flag, Urgency::Urgent);
    batch(&t.post_events(&dev, &[tamper, settings, flag, high]).await);

    let expect = [
        (0, "none", "urgent"),
        (1, "none", "normal"),
        (2, "none", "none"),
        (3, "urgent", "urgent"),
    ];
    for (seq, signed, effective) in expect {
        let (u, e, header_json, _) = stored_event(&t.state, &dev.id, seq).await.unwrap();
        assert_eq!((u.as_str(), e.as_str()), (signed, effective), "seq {seq}");
        let h: faro_proto::EventHeader = serde_json::from_str(&header_json).unwrap();
        assert_eq!(h.urgency.as_str(), signed, "header is not rewritten");
    }
    let alerts = t.alerts(&member).await;
    let mut device: Vec<_> = alerts
        .iter()
        .filter(|a| a.source == "device")
        .map(|a| (a.event_seq, a.kind.as_str(), a.urgency.as_str()))
        .collect();
    device.sort();
    assert_eq!(
        device,
        vec![
            (Some(0), "tamper", "urgent"),
            (Some(1), "settings_change", "normal"),
            (Some(3), "flag", "urgent"),
        ]
    );
}

#[tokio::test]
async fn bad_event_signatures_and_malformed_events_are_rejected() {
    let t = TestApp::new().await;
    let (member, _s, _keys, mut dev) = t.active_device().await;

    // Urgency downgraded in transit: signature no longer matches.
    let mut forged = dev.event_at(dev.head, EventKind::Tamper, Urgency::Urgent, b"x");
    forged.header.urgency = Urgency::None;
    // Body swapped for another valid ciphertext: commitment mismatch.
    let mut swapped = dev.event_at(dev.head, EventKind::Flag, Urgency::None, b"a");
    swapped.body = dev
        .event_at(dev.head, EventKind::Flag, Urgency::None, b"b")
        .body;
    // Signed for another instance.
    let mut other = dev.clone_for_instance("inst_other");
    let wrong_inst = other.next_event(EventKind::Boot, Urgency::None);
    // Header declares a body that is missing.
    let mut stripped = dev.event_at(dev.head, EventKind::Flag, Urgency::None, b"c");
    stripped.body = None;

    let b = batch(
        &t.post_events(&dev, &[forged.clone(), swapped, wrong_inst, stripped])
            .await,
    );
    let reasons: Vec<_> = b
        .results
        .iter()
        .map(|r| match r {
            EventResult::Rejected { reason, .. } => reason.clone(),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(reasons[0], "bad_signature");
    assert!(reasons[1].starts_with("malformed"), "{}", reasons[1]);
    assert_eq!(reasons[2], "wrong_instance");
    assert!(reasons[3].starts_with("malformed"), "{}", reasons[3]);
    assert_eq!(b.acked_through, None);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 0);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM blobs").await, 0);

    let alerts = t.alerts(&member).await;
    let sig = alerts_of(&alerts, "invalid_signature");
    assert_eq!(sig.len(), 1, "only the forged signature raises an alert");
    assert_eq!(sig[0].urgency, "urgent");
    // Retrying the forgery is deduplicated.
    batch(&t.post_events(&dev, &[forged]).await);
    assert_eq!(
        alerts_of(&t.alerts(&member).await, "invalid_signature").len(),
        1
    );

    // The genuine event at that position still goes through.
    let good = dev.next_event(EventKind::Boot, Urgency::None);
    let b = batch(&t.post_events(&dev, &[good]).await);
    assert_eq!(b.results, vec![EventResult::Accepted { seq: 0 }]);
}

#[tokio::test]
async fn results_follow_batch_order_and_limits_apply() {
    let t = TestApp::new().await;
    let (_m, _s, _keys, mut dev) = t.active_device().await;
    let e0 = dev.next_event(EventKind::Boot, Urgency::None);
    let e1 = dev.next_event(EventKind::Capture, Urgency::None);
    // Out of order within a batch: e1 first is a gap (0 missing), then e0 is
    // behind the head that e1 established.
    let b = batch(&t.post_events(&dev, &[e1, e0]).await);
    assert_eq!(b.results[0], EventResult::Accepted { seq: 1 });
    assert!(matches!(b.results[1], EventResult::Rejected { seq: 0, .. }));

    let too_many: Vec<_> = (0..501)
        .map(|_| dev.next_event(EventKind::Capture, Urgency::None))
        .collect();
    let r = t.post_events(&dev, &too_many).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "batch_too_large");
}

#[tokio::test]
async fn device_requests_need_fresh_timestamps_and_valid_signatures() {
    let t = TestApp::new().await;
    let (_m, _s, _keys, mut dev) = t.active_device().await;
    let ev = dev.next_event(EventKind::Boot, Urgency::None);
    let body = serde_json::to_vec(&json!({ "events": [ev] })).unwrap();
    let now = t.clock_ms();

    // Stale and future timestamps.
    for ts in [now - REQUEST_MAX_SKEW_MS - 1, now + REQUEST_MAX_SKEW_MS + 1] {
        let r = t
            .send(dev.request(Method::POST, "/v1/events:batch", &body, ts))
            .await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        assert_eq!(r.error_code(), "clock_skew");
    }
    // Wrong key.
    let other = SigningKey::generate();
    let r = t
        .send(dev.request_as(
            &dev.token,
            &dev.id,
            &other,
            Method::POST,
            "/v1/events:batch",
            &body,
            now,
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Signed for one path, sent to another.
    let mut req = dev.request(Method::POST, "/v1/heartbeat", &body, now);
    *req.uri_mut() = "/v1/events:batch".parse().unwrap();
    assert_eq!(t.send(req).await.status, StatusCode::UNAUTHORIZED);
    // Body changed after signing.
    let req = dev.request(Method::POST, "/v1/events:batch", &body, now);
    let (parts, _) = req.into_parts();
    let mut tampered = body.clone();
    tampered.push(b' ');
    let req = axum::http::Request::from_parts(parts, axum::body::Body::from(tampered));
    assert_eq!(t.send(req).await.status, StatusCode::UNAUTHORIZED);
    // Missing credentials altogether.
    let r = t
        .post("/v1/events:batch", json!({"events": []}), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A garbage token.
    let r = t
        .send(dev.request_as(
            &"A".repeat(43),
            &dev.id,
            &dev.key,
            Method::POST,
            "/v1/events:batch",
            &body,
            now,
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    // Nothing above was stored; the genuine request works.
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 0);
    let r = t
        .send(dev.request(
            Method::POST,
            "/v1/events:batch",
            &body,
            now - REQUEST_MAX_SKEW_MS + 1000,
        ))
        .await;
    assert_eq!(batch(&r).acked_through, Some(0));
}

#[tokio::test]
async fn one_devices_token_cannot_act_as_another_device() {
    let t = TestApp::new().await;
    let (member, s, keys, dev_a) = t.active_device().await;
    let code = t.enroll_code(&s).await;
    let mut dev_b = t.enroll(&code, &keys.enc).await;
    assert_eq!(t.endorse(&dev_b, &keys, &s).await.status, StatusCode::OK);

    let ev_b = dev_b.next_event(EventKind::Boot, Urgency::None);
    let body = serde_json::to_vec(&json!({ "events": [ev_b] })).unwrap();
    let now = t.clock_ms();
    // A's token, claiming to be B, signed with B's key.
    let r = t
        .send(dev_a.request_as(
            &dev_a.token,
            &dev_b.id,
            &dev_b.key,
            Method::POST,
            "/v1/events:batch",
            &body,
            now,
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A's token, claiming A, signed with B's key.
    let r = t
        .send(dev_a.request_as(
            &dev_a.token,
            &dev_a.id,
            &dev_b.key,
            Method::POST,
            "/v1/events:batch",
            &body,
            now,
        ))
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // A, properly authenticated, uploading B's events: rejected per event.
    let r = t
        .device_call(&dev_a, Method::POST, "/v1/events:batch", &body)
        .await;
    assert_eq!(
        batch(&r).results,
        vec![EventResult::Rejected {
            seq: 0,
            reason: "wrong_device".into()
        }]
    );
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 0);
    assert!(t.alerts(&member).await.is_empty());
    // B itself is fine.
    let r = t
        .device_call(&dev_b, Method::POST, "/v1/events:batch", &body)
        .await;
    assert_eq!(batch(&r).acked_through, Some(0));
}

#[tokio::test]
async fn oversized_device_bodies_are_refused_before_verification() {
    let t = TestApp::new().await;
    let (_m, _s, _keys, dev) = t.active_device().await;
    let body = vec![b'x'; 8 * 1024 * 1024 + 1];
    let r = t
        .device_call(&dev, Method::POST, "/v1/events:batch", &body)
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
    let r = t
        .device_call(&dev, Method::POST, "/v1/heartbeat", &vec![b'x'; 5000])
        .await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);
}

fn heartbeat(t: &TestApp, dev: &TestDevice, ts_ms: i64, last_seq: Option<u64>) -> Heartbeat {
    Heartbeat {
        instance_id: t.instance_id(),
        device_id: dev.id.clone(),
        ts_ms,
        mono_ms: 42,
        boot_id: "boot-7".into(),
        state: DeviceState::Sleeping,
        last_seq,
        last_hash: Some(dev.head.prev_hash),
    }
}

#[tokio::test]
async fn heartbeats_update_liveness() {
    let t = TestApp::new().await;
    let (_m, _s, _keys, mut dev) = t.active_device().await;
    let boot = dev.next_event(EventKind::Boot, Urgency::None);
    batch(&t.post_events(&dev, &[boot]).await);

    t.clock.advance_ms(1234);
    let hb = dev
        .key
        .sign_heartbeat(heartbeat(&t, &dev, t.clock_ms(), Some(5)));
    let r = t.device_post(&dev, "/v1/heartbeat", &hb).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let resp: HeartbeatResponse = serde_json::from_value(r.body).unwrap();
    assert_eq!(resp.server_time_ms, t.clock_ms());
    assert_eq!(resp.next_in_secs, 300);
    assert_eq!(resp.acked_through, Some(0));

    use sqlx::Row;
    let row = sqlx::query(
        "SELECT last_seen_at, last_state, last_boot_id, reported_last_seq FROM devices WHERE id = $1",
    )
    .bind(dev.id.as_str())
    .fetch_one(t.state.db().pool())
    .await
    .unwrap();
    assert_eq!(row.try_get::<i64, _>("last_seen_at").unwrap(), t.clock_ms());
    assert_eq!(row.try_get::<String, _>("last_state").unwrap(), "sleeping");
    assert_eq!(row.try_get::<String, _>("last_boot_id").unwrap(), "boot-7");
    assert_eq!(row.try_get::<i64, _>("reported_last_seq").unwrap(), 5);
}

#[tokio::test]
async fn bad_heartbeats_are_rejected() {
    let t = TestApp::new().await;
    let (_m, s, keys, dev) = t.active_device().await;
    let now = t.clock_ms();

    // Signed by another key (the request itself is genuinely from `dev`).
    let hb = SigningKey::generate().sign_heartbeat(heartbeat(&t, &dev, now, None));
    let r = t.device_post(&dev, "/v1/heartbeat", &hb).await;
    assert_eq!(r.error_code(), "bad_heartbeat_signature");

    // A heartbeat naming another device.
    let code = t.enroll_code(&s).await;
    let other = t.enroll(&code, &keys.enc).await;
    let hb = dev.key.sign_heartbeat(heartbeat(&t, &other, now, None));
    let r = t.device_post(&dev, "/v1/heartbeat", &hb).await;
    assert_eq!(r.error_code(), "heartbeat_mismatch");

    // An old signed heartbeat replayed inside a fresh request.
    let hb = dev
        .key
        .sign_heartbeat(heartbeat(&t, &dev, now - 3_600_000, None));
    let r = t.device_post(&dev, "/v1/heartbeat", &hb).await;
    assert_eq!(r.error_code(), "stale_heartbeat");

    use sqlx::Row;
    let seen: Option<i64> = sqlx::query("SELECT last_seen_at FROM devices WHERE id = $1")
        .bind(dev.id.as_str())
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get("last_seen_at")
        .unwrap();
    assert_eq!(seen, None, "no rejected heartbeat counted as liveness");
}

fn report(t: &TestApp, dev: &TestDevice, member: &UserId, keys: &MemberKeys) -> ReportUpload {
    let mut header = ReportHeader {
        v: 1,
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        period_start_ms: 1_800_000_000_000,
        period_end_ms: 1_800_000_000_000 + 24 * 3600 * 1000,
        first_seq: Some(0),
        last_seq: Some(10),
        body_hash: Hash32::ZERO,
        body_len: 0,
    };
    let body = seal_item(
        b"{\"daily\":\"report\"}",
        &header.body_aad(),
        &[Recipient {
            user_id: member.clone(),
            pubkey: keys.enc.public(),
        }],
    )
    .unwrap();
    header.body_hash = body.body_hash();
    header.body_len = body.ciphertext.len() as u64;
    ReportUpload {
        sig: dev.key.sign(&header),
        header,
        body,
    }
}

#[tokio::test]
async fn reports_are_verified_stored_and_idempotent() {
    let t = TestApp::new().await;
    let (member, _s, keys, dev) = t.active_device().await;
    let up = report(&t, &dev, &member, &keys);

    let r = t.device_post(&dev, "/v1/reports", &up).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let id = r.body["report_id"].as_str().unwrap().to_owned();
    assert_eq!(r.body["duplicate"], false);

    let r = t.device_post(&dev, "/v1/reports", &up).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["report_id"], id.as_str());
    assert_eq!(r.body["duplicate"], true);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM reports").await, 1);
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM blobs WHERE kind = 'report'").await,
        1
    );
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM report_recipients").await,
        1
    );

    // The stored blob is the ciphertext and opens for the member.
    use sqlx::Row;
    let blob_id: String = sqlx::query("SELECT blob_id FROM reports WHERE id = $1")
        .bind(&id)
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get("blob_id")
        .unwrap();
    let raw = t
        .state
        .blobs()
        .get(&BlobId::parse(&blob_id).unwrap())
        .await
        .unwrap();
    let item: EncryptedItem = serde_json::from_slice(&raw).unwrap();
    let pt = faro_crypto::open_item(&item, &up.header.body_aad(), &member, &keys.enc).unwrap();
    assert_eq!(pt.as_slice(), b"{\"daily\":\"report\"}");
}

#[tokio::test]
async fn bad_reports_are_rejected() {
    let t = TestApp::new().await;
    let (member, _s, keys, dev) = t.active_device().await;

    let mut wrong_member = report(&t, &dev, &UserId::new("usr_other"), &keys);
    wrong_member.sig = dev.key.sign(&wrong_member.header);
    let r = t.device_post(&dev, "/v1/reports", &wrong_member).await;
    assert_eq!(r.error_code(), "report_mismatch");

    let mut swapped = report(&t, &dev, &member, &keys);
    swapped.body = report(&t, &dev, &member, &keys).body;
    let r = t.device_post(&dev, "/v1/reports", &swapped).await;
    assert_eq!(r.error_code(), "body_mismatch");

    let mut backwards = report(&t, &dev, &member, &keys);
    backwards.header.period_end_ms = backwards.header.period_start_ms - 1;
    backwards.sig = dev.key.sign(&backwards.header);
    let r = t.device_post(&dev, "/v1/reports", &backwards).await;
    assert_eq!(r.error_code(), "invalid_period");

    let mut seqs = report(&t, &dev, &member, &keys);
    seqs.header.first_seq = Some(9);
    seqs.header.last_seq = Some(2);
    seqs.sig = dev.key.sign(&seqs.header);
    let r = t.device_post(&dev, "/v1/reports", &seqs).await;
    assert_eq!(r.error_code(), "invalid_seq_range");

    let mut forged = report(&t, &dev, &member, &keys);
    forged.sig = SigningKey::generate().sign(&forged.header);
    let r = t.device_post(&dev, "/v1/reports", &forged).await;
    assert_eq!(r.error_code(), "bad_signature");
    let alerts = t.alerts(&member).await;
    assert_eq!(alerts_of(&alerts, "invalid_signature").len(), 1);

    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM reports").await, 0);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM blobs").await, 0);
}

/// Helper for building events that claim a different instance.
trait CloneForInstance {
    fn clone_for_instance(&self, inst: &str) -> TestDevice;
}

impl CloneForInstance for TestDevice {
    fn clone_for_instance(&self, inst: &str) -> TestDevice {
        let instance_id = faro_proto::InstanceId::new(inst);
        TestDevice {
            key: SigningKey::from_bytes(&self.key.to_bytes()),
            id: self.id.clone(),
            token: self.token.clone(),
            member_id: self.member_id.clone(),
            head: ChainHead::genesis(&instance_id, &self.id),
            instance_id,
            member_enc: self.member_enc,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_uploads_store_each_event_exactly_once() {
    let t = TestApp::new().await;
    let (member, _s, _keys, mut dev) = t.active_device().await;
    let evs: Vec<_> = (0..20)
        .map(|_| dev.next_event(EventKind::Paused, Urgency::None))
        .collect();
    let body = serde_json::to_vec(&json!({ "events": evs })).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let app = t.app.clone();
        let req = dev.request(Method::POST, "/v1/events:batch", &body, t.clock_ms());
        tasks.push(tokio::spawn(async move {
            use tower::ServiceExt;
            let resp = app.oneshot(req).await.unwrap();
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap();
            serde_json::from_slice::<EventsBatchResponse>(&bytes).unwrap()
        }));
    }
    let mut accepted = vec![0u32; 20];
    for task in tasks {
        let b = task.await.unwrap();
        assert_eq!(b.acked_through, Some(19));
        for r in b.results {
            match r {
                EventResult::Accepted { seq } => accepted[seq as usize] += 1,
                EventResult::Duplicate { .. } => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert!(accepted.iter().all(|&n| n == 1), "{accepted:?}");
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 20);
    // One (normal-urgency) device alert per paused event, no chain alerts.
    let alerts = t.alerts(&member).await;
    assert_eq!(alerts.len(), 20);
    assert!(alerts
        .iter()
        .all(|a| a.source == "device" && a.urgency == "normal"));
}
