//! The retention worker (§8): windows, blob files, expired secrets, orphans
//! and per-member (shorter only) overrides.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::{EventKind, Urgency};
use faro_server::blob::BlobId;
use faro_server::retention;
use serde_json::json;
use sqlx::Row;

const DAY: i64 = 24 * 3600 * 1000;

async fn blob_ids(t: &TestApp) -> Vec<String> {
    sqlx::query("SELECT id FROM blobs ORDER BY id")
        .fetch_all(t.state.db().pool())
        .await
        .unwrap()
        .iter()
        .map(|r| r.try_get("id").unwrap())
        .collect()
}

fn blob_file(t: &TestApp, id: &str) -> std::path::PathBuf {
    t.state
        .config()
        .data_dir
        .join("blobs")
        .join(&id[..2])
        .join(&id[2..4])
        .join(id)
}

#[tokio::test]
async fn windows_delete_blobs_then_headers_then_alerts() {
    let t = TestApp::new().await;
    let (member, _s, _k, mut dev) = t.active_device().await;
    let evs = vec![
        dev.next_event(EventKind::Flag, Urgency::Urgent),
        dev.next_event(EventKind::Capture, Urgency::None),
    ];
    t.post_events(&dev, &evs).await;
    let ids = blob_ids(&t).await;
    assert_eq!(ids.len(), 2);
    assert!(ids.iter().all(|id| blob_file(&t, id).is_file()));
    let alerts_before = t.alerts(&member).await.len();
    assert!(alerts_before > 0);

    // Day 29: nothing is old enough.
    t.clock.advance_ms(29 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!((s.blobs, s.events, s.alerts), (0, 0, 0));

    // Day 31: ciphertext rows and files are gone; headers remain.
    t.clock.advance_ms(2 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 2);
    assert!(blob_ids(&t).await.is_empty());
    assert!(ids.iter().all(|id| !blob_file(&t, id).exists()));
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 2);
    assert_eq!(
        count(
            &t.state,
            "SELECT COUNT(*) FROM events WHERE blob_id IS NOT NULL"
        )
        .await,
        0
    );
    assert_eq!(t.alerts(&member).await.len(), alerts_before);

    // Day 91: headers, recipients and alerts are gone too.
    t.clock.advance_ms(60 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.events, 2);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM events").await, 0);
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM event_recipients").await,
        0
    );
    assert!(t.alerts(&member).await.is_empty());
    // The chain head survives in the device row, so the device continues.
    let next = dev.next_event(EventKind::Capture, Urgency::None);
    let r = t.post_events(&dev, &[next]).await;
    assert_eq!(r.body["results"][0]["status"], "accepted", "{:?}", r.body);
}

#[tokio::test]
async fn expired_secrets_are_swept() {
    let t = TestApp::new().await;
    let (_m, s, _k, _d) = t.active_device().await;
    t.enroll_code(&s).await;
    t.invite(&s, "pat@elsewhere.net").await;
    t.magic_link_token("eve@example.org").await;
    t.clock.advance_ms(31 * DAY);
    let r = retention::run_once(&t.state).await.unwrap();
    assert!(r.expired_secrets >= 4, "{r:?}");
    for sql in [
        "SELECT COUNT(*) FROM sessions",
        "SELECT COUNT(*) FROM magic_links",
        "SELECT COUNT(*) FROM enroll_codes",
        "SELECT COUNT(*) FROM invites",
    ] {
        assert_eq!(count(&t.state, sql).await, 0, "{sql}");
    }
    // The expired session no longer works anyway.
    assert_eq!(
        t.get("/v1/me", Some(&s)).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn orphan_blob_files_are_swept_after_a_grace_period() {
    let t = TestApp::new().await;
    let (_m, _s, _k, mut dev) = t.active_device().await;
    let ev = dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    // A file with no row: what a crash between write and commit leaves.
    let orphan = BlobId::new_random();
    t.state
        .blobs()
        .put(&orphan, b"orphan".to_vec())
        .await
        .unwrap();
    let kept = blob_ids(&t).await;

    // Young orphans are left alone (an upload may be mid-transaction).
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.orphan_files, 0);
    assert!(blob_file(&t, orphan.as_str()).exists());

    t.clock.advance_ms(2 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.orphan_files, 1);
    assert!(!blob_file(&t, orphan.as_str()).exists());
    // Referenced blobs are never touched by the sweep.
    assert!(kept.iter().all(|id| blob_file(&t, id).is_file()));
}

#[tokio::test]
async fn members_may_only_shorten_retention() {
    let t = TestApp::new().await;
    let (sam, sam_s, _k, mut sam_dev) = t.active_device().await;
    let (alex, alex_s) = t.sign_in("alex@example.org").await;
    let alex_keys = t.create_member_keys(&alex, &alex_s).await;
    let code = t.enroll_code(&alex_s).await;
    let mut alex_dev = t.enroll(&code, &alex_keys.enc).await;
    assert_eq!(
        t.endorse(&alex_dev, &alex_keys, &alex_s).await.status,
        StatusCode::OK
    );

    // Sam asks for 1 day (clamped up to the floor) and 365 (clamped down).
    let r = t
        .call(
            Method::PUT,
            "/v1/me/retention",
            Some(json!({"blob_days": 1, "event_header_days": 365})),
            Some(&sam_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["effective"]["blob_days"], retention::MIN_MEMBER_DAYS);
    assert_eq!(r.body["effective"]["event_header_days"], 90);
    assert_eq!(r.body["chosen"]["blob_days"], retention::MIN_MEMBER_DAYS);
    assert_eq!(r.body["instance"]["blob_days"], 30);

    let ev = sam_dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&sam_dev, &[ev]).await;
    let ev = alex_dev.next_event(EventKind::Flag, Urgency::Urgent);
    t.post_events(&alex_dev, &[ev]).await;
    t.clock.advance_ms(8 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 1, "only sam's shorter window applies");
    let owners: Vec<String> = sqlx::query("SELECT owner_member_id FROM blobs")
        .fetch_all(t.state.db().pool())
        .await
        .unwrap()
        .iter()
        .map(|r| r.try_get("owner_member_id").unwrap())
        .collect();
    assert_eq!(owners, vec![alex.as_str().to_owned()]);
    let _ = sam;

    // An ally-only account has no retention to set.
    let token = t.invite(&alex_s, "pat@elsewhere.net").await;
    let (_p, pat_s) = t.sign_in("pat@elsewhere.net").await;
    t.accept(&token, &pat_s, &AllyKeys::generate()).await;
    let r = t.get("/v1/me/retention", Some(&pat_s)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reports_go_with_their_blobs() {
    let t = TestApp::new().await;
    let (_m, _s, _k, dev) = t.active_device().await;
    use faro_proto::report::{ReportHeader, ReportUpload};
    let body = faro_crypto::seal_item(
        b"r",
        b"a",
        &[faro_crypto::Recipient {
            user_id: dev.member_id.clone(),
            pubkey: dev.member_enc,
        }],
    )
    .unwrap();
    let header = ReportHeader {
        v: 1,
        instance_id: t.instance_id(),
        member_id: dev.member_id.clone(),
        device_id: dev.id.clone(),
        period_start_ms: t.clock_ms() - DAY,
        period_end_ms: t.clock_ms(),
        first_seq: None,
        last_seq: None,
        body_hash: body.body_hash(),
        body_len: body.ciphertext.len() as u64,
    };
    let sig = dev.key.sign(&header);
    let r = t
        .device_post(&dev, "/v1/reports", &ReportUpload { header, sig, body })
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    t.clock.advance_ms(31 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!((s.reports, s.blobs), (1, 1));
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM reports").await, 0);
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM report_recipients").await,
        0
    );
}

#[tokio::test]
async fn a_shorter_window_never_deletes_what_was_sent_before_it() {
    let t = TestApp::new().await;
    let (sam, sam_s, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&sam, &mkeys, &sam_s, "pat@elsewhere.net").await;
    let to_pat = [(pat.id.clone(), pat.keys.enc.public())];
    // Day 0: an urgent flag sealed to pat.
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, b"x", &to_pat);
    t.post_events(&dev, &[ev]).await;
    let before = blob_ids(&t).await;
    assert_eq!(before.len(), 1);

    // Day 10: sam shortens blob retention to 7 days.
    t.clock.advance_ms(10 * DAY);
    let r = t
        .call(
            Method::PUT,
            "/v1/me/retention",
            Some(json!({"blob_days": 7})),
            Some(&sam_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 0, "the 10-day-old flag keeps the instance window");
    assert_eq!(blob_ids(&t).await, before);

    // Re-saving the same choice does not restart anything either.
    t.clock.advance_ms(DAY);
    let r = t
        .call(
            Method::PUT,
            "/v1/me/retention",
            Some(json!({"blob_days": 7})),
            Some(&sam_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // Day 11: a new flag, under the 7-day window.
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, b"y", &to_pat);
    t.post_events(&dev, &[ev]).await;
    let after: Vec<String> = blob_ids(&t)
        .await
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    assert_eq!(after.len(), 1);

    // Day 19: the new flag is 8 days old and goes; the old one (19 days)
    // stays until the instance window ends.
    t.clock.advance_ms(8 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 1);
    assert_eq!(blob_ids(&t).await, before);

    // Day 31: the instance window takes the old one.
    t.clock.advance_ms(12 * DAY);
    let s = retention::run_once(&t.state).await.unwrap();
    assert_eq!(s.blobs, 1);
    assert!(blob_ids(&t).await.is_empty());
}

#[tokio::test]
async fn open_liveness_episodes_survive_retention() {
    let t = TestApp::new().await;
    let started = t.clock_ms();
    let (_m, _s, _k, _dev) = t.active_device().await;
    let grace = i64::try_from(t.state.settings().liveness.grace_secs).unwrap() * 1000;
    t.clock.advance_ms(grace + 1);
    let s = faro_server::liveness::run_once(&t.state, started)
        .await
        .unwrap();
    assert_eq!(s.missed, 1);
    t.clock.advance_ms(200 * DAY);
    retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(
            &t.state,
            "SELECT COUNT(*) FROM liveness_episodes WHERE closed_at IS NULL"
        )
        .await,
        1,
        "a still-silent device stays reported"
    );
}
