//! Leave Faro's goodbye, who the phone reports to, and the clock check
//! against the instance, with the real instance (docs/IOS.md §10.2, §12).

mod support;

use faro_core::{Clock, ManualClock};
use faro_mobile::keys::{DEVICE_KEY, DEVICE_TOKEN};
use faro_mobile::{Context, FaroCore, FaroError, GoodbyeOutcome, HeartbeatState, Tamper};
use faro_proto::body::{EventBody, TamperSignal};
use faro_proto::EventKind;
use std::sync::Arc;
use support::{approved_phone, blocking, Phone, World};

fn integrity() -> Tamper {
    Tamper::IntegrityFailure {
        component: "test".into(),
    }
}

/// Point the stored enrollment at `url`, as if the instance moved or went
/// away (the only way to make it unreachable from here).
fn set_instance_url(phone: &Phone, url: &str) {
    let db = rusqlite::Connection::open(phone.dir.join(faro_core::outbox::OUTBOX_FILE)).unwrap();
    let raw: String = db
        .query_row(
            "SELECT value FROM mobile_state WHERE key = 'enrollment'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["instance_url"] = url.into();
    db.execute(
        "UPDATE mobile_state SET value = ?1 WHERE key = 'enrollment'",
        [v.to_string()],
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_says_goodbye_once_and_then_nothing_more() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, device_id) = approved_phone(&w, &phone).await;
    let c = core.clone();
    let outcome = blocking(move || {
        c.record_tamper(integrity()).unwrap();
        c.goodbye(10).unwrap()
    })
    .await;
    // Everything queued before it goes first, then the goodbye.
    assert_eq!(outcome, GoodbyeOutcome::Delivered { seq: 1 });
    assert_eq!(w.stored_seqs(&device_id).await, vec![0, 1]);

    // Nothing after it: an event or a heartbeat would tell the instance the
    // phone is back.
    let c = core.clone();
    let (status, hb, tamper, context, again) = blocking(move || {
        (
            c.status().unwrap(),
            c.heartbeat(HeartbeatState::Active),
            c.record_tamper(Tamper::ScreenTimeRevoked),
            c.record_context(Context::OtherVpn),
            c.goodbye(10).unwrap(),
        )
    })
    .await;
    assert!(status.leaving && status.goodbye_delivered);
    assert!(matches!(hb, Err(FaroError::Left)), "{hb:?}");
    assert!(matches!(tamper, Err(FaroError::Left)), "{tamper:?}");
    assert!(matches!(context, Err(FaroError::Left)), "{context:?}");
    assert_eq!(again, GoodbyeOutcome::Delivered { seq: 1 }, "never twice");
    assert_eq!(w.stored_seqs(&device_id).await, vec![0, 1]);

    // The keys are gone, and the instance holds the goodbye.
    assert_eq!(phone.keys.load(DEVICE_KEY.into()).unwrap(), None);
    assert_eq!(phone.keys.load(DEVICE_TOKEN.into()).unwrap(), None);
    let (kind, urgency, goodbye_at): (String, String, Option<i64>) = sqlx::query_as(
        "SELECT e.kind, e.urgency, d.goodbye_at FROM events e JOIN devices d ON d.id = e.device_id
          WHERE e.device_id = $1 AND e.seq = 1",
    )
    .bind(&device_id)
    .fetch_one(w.t.state.db().pool())
    .await
    .unwrap();
    assert_eq!(kind, EventKind::Goodbye.as_str());
    assert_eq!(urgency, "urgent");
    assert!(goodbye_at.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_instance_changes_nothing_until_a_retry_reaches_it() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, device_id) = approved_phone(&w, &phone).await;
    set_instance_url(&phone, "http://127.0.0.1:1/");
    let c = core.clone();
    let (out, status, tamper) = blocking(move || {
        (
            c.goodbye(1),
            c.status().unwrap(),
            c.record_tamper(integrity()),
        )
    })
    .await;
    assert!(matches!(out, Err(FaroError::Network { .. })), "{out:?}");
    assert!(!status.leaving, "nothing changed");
    assert_eq!(status.next_seq, 0, "nothing was written");
    assert_eq!(tamper.unwrap(), 0, "the phone still records");
    assert!(phone.keys.load(DEVICE_KEY.into()).unwrap().is_some());

    set_instance_url(&phone, &w.url());
    let c = core.clone();
    let out = blocking(move || c.goodbye(10).unwrap()).await;
    assert_eq!(out, GoodbyeOutcome::Delivered { seq: 1 });
    assert_eq!(w.stored_seqs(&device_id).await, vec![0, 1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_phone_the_member_removed_leaves_without_a_goodbye() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, device_id) = approved_phone(&w, &phone).await;
    let r =
        w.t.call(
            axum::http::Method::DELETE,
            &format!("/v1/me/devices/{device_id}"),
            None,
            Some(&w.member_session),
        )
        .await;
    assert!(r.status.is_success(), "{:?}", r.body);
    let c = core.clone();
    let (out, status) = blocking(move || (c.goodbye(5).unwrap(), c.status().unwrap())).await;
    assert_eq!(out, GoodbyeOutcome::AlreadyRetired);
    assert!(status.leaving && status.goodbye_delivered);
    assert_eq!(status.next_seq, 0, "nothing was written");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_before_approval_or_enrollment_has_nobody_to_tell() {
    let w = World::new().await;
    let phone = Phone::new();
    let core = phone.core();
    let c = core.clone();
    assert_eq!(
        blocking(move || c.goodbye(1).unwrap()).await,
        GoodbyeOutcome::NotEnrolled
    );
    let link = w.link(Some(&w.member_key_id())).await;
    let c = core.clone();
    let out = blocking(move || {
        let p = c.preview_enrollment(link.clone()).unwrap();
        c.enroll(link, support::DEVICE_NAME.into(), p.identity_fingerprint)
            .unwrap();
        (c.goodbye(1).unwrap(), c.heartbeat(HeartbeatState::Active))
    })
    .await;
    assert_eq!(out.0, GoodbyeOutcome::NotActivated);
    assert!(matches!(out.1, Err(FaroError::Left)), "{:?}", out.1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allies_come_from_the_manifest_the_member_signed() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let c = core.clone();
    let info = blocking(move || c.allies().unwrap()).await;
    let manifest = w.manifest().await;
    assert_eq!(info.manifest_version, manifest.body.version);
    assert_eq!(info.signed_at_ms, manifest.body.issued_at_ms);
    assert_eq!(info.member_fingerprint, w.member_key_id());
    assert_eq!(info.instance_url, w.url());
    assert!(!info.instance_name.is_empty());
    assert_eq!(info.allies.len(), 1);
    assert_eq!(info.allies[0].ally_id, w.ally.id.to_string());
    // The name the member signed (the harness signs format 2, as the web
    // app does).
    assert_eq!(manifest.body.format, 2);
    assert_eq!(
        info.allies[0].name.as_deref(),
        Some(support::server::ally_name(&w.ally.id).as_str())
    );
    // The code the member and the ally compared when the ally was approved.
    let code = faro_proto::keys::safety_code(
        w.member_keys.sign.public().as_bytes(),
        w.ally.keys.enc.public().as_bytes(),
    );
    assert_eq!(info.allies[0].safety_code, code);

    // The member re-signs, naming the ally differently (they renamed
    // themselves), with characters a name must not keep.
    let mut body = w.member_keys.next_manifest(&manifest, |_| {}).body;
    body.allies[0].name = Some("Alex\u{202e} \u{1b}Smith".into());
    let renamed = w.member_keys.sign.endorse(body);
    assert_eq!(
        w.t.put_manifest(&w.member_session, &renamed).await.status,
        axum::http::StatusCode::CREATED
    );
    let c = core.clone();
    let info = blocking(move || {
        c.upload_pending().unwrap();
        c.allies().unwrap()
    })
    .await;
    assert_eq!(info.manifest_version, renamed.body.version);
    assert_eq!(info.allies[0].name.as_deref(), Some("Alex Smith"));

    // A format 1 manifest names no one: count and codes only, as before.
    let v1 = w.member_keys.manifest_in(
        1,
        &renamed.body.instance_id,
        &w.member,
        renamed.body.version + 1,
        &[(w.ally.id.clone(), w.ally.keys.enc.public())],
        renamed.body.issued_at_ms + 1,
    );
    assert_eq!(
        w.t.put_manifest(&w.member_session, &v1).await.status,
        axum::http::StatusCode::CREATED
    );
    let c = core.clone();
    let info = blocking(move || {
        c.upload_pending().unwrap();
        c.allies().unwrap()
    })
    .await;
    assert_eq!(info.manifest_version, v1.body.version);
    assert_eq!(info.allies[0].name, None);
    assert_eq!(info.allies[0].safety_code, code);

    // The member removes the ally: the next upload adopts the new manifest.
    let v3 = w.remove_ally().await;
    let c = core.clone();
    let info = blocking(move || {
        c.upload_pending().unwrap();
        c.allies().unwrap()
    })
    .await;
    assert_eq!(info.manifest_version, v3.body.version);
    assert!(info.allies.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_off_the_instance_is_reported_once_per_skew() {
    let w = World::new().await;
    let clock = ManualClock::new(w.t.clock_ms(), 1_000);
    let phone = Phone::new();
    let core = FaroCore::with_options(
        phone.dir.clone(),
        phone.keys.clone(),
        Arc::new(clock.clone()) as Arc<dyn Clock>,
        faro_client::ClientOptions {
            product: "faro-ios-test",
            ..faro_client::ClientOptions::default()
        },
    )
    .unwrap();
    let (core, _) = support::approve(&w, core).await;
    let skews = |core: &Arc<FaroCore>| -> Vec<i64> {
        core.pending_events(100)
            .unwrap()
            .iter()
            .filter(|e| e.header.kind == EventKind::Tamper)
            .map(
                |e| match faro_core::open_event_body(e, &w.member, &w.member_keys.enc).unwrap() {
                    EventBody::Tamper {
                        signal: TamperSignal::ClockManipulation { wall_delta_ms, .. },
                        ..
                    } => wall_delta_ms,
                    other => panic!("{other:?}"),
                },
            )
            .collect()
    };

    // In range: nothing.
    let c = core.clone();
    blocking(move || c.heartbeat(HeartbeatState::Active).unwrap()).await;
    assert!(skews(&core).is_empty());

    // An hour ahead: one signal, however many heartbeats see it. The first
    // request after the jump is refused (`clock_skew`) and teaches the
    // client the instance's time from its `Date` header.
    clock.jump_wall(3_600_000);
    let c = core.clone();
    blocking(move || {
        let _ = c.heartbeat(HeartbeatState::Active);
        c.heartbeat(HeartbeatState::Active).unwrap();
        c.heartbeat(HeartbeatState::Active).unwrap();
    })
    .await;
    let s = skews(&core);
    assert_eq!(s.len(), 1, "{s:?}");
    assert!((3_590_000..3_610_000).contains(&s[0]), "{s:?}");

    // Back in range, then off again: a second signal.
    clock.jump_wall(-3_600_000);
    let c = core.clone();
    blocking(move || {
        let _ = c.heartbeat(HeartbeatState::Active);
        c.heartbeat(HeartbeatState::Active).unwrap();
    })
    .await;
    clock.jump_wall(-7_200_000);
    let c = core.clone();
    blocking(move || {
        let _ = c.heartbeat(HeartbeatState::Active);
        c.heartbeat(HeartbeatState::Active).unwrap();
    })
    .await;
    let s = skews(&core);
    assert_eq!(s.len(), 2, "{s:?}");
    assert!(s[1] < -7_000_000, "{s:?}");
}
