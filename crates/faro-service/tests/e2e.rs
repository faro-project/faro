//! End-to-end: the real instance (in-process `faro-server` over TCP), the
//! real service (`faro_service::Service` with a synthetic screen), and the
//! member's and ally's browsers simulated with faro-crypto
//! (ARCHITECTURE.md §10 "E2E"). See `e2e_support` for how the pieces are
//! wired and how time is driven.
//!
//! Every scenario starts from the same onboarding (§7): admin setup, the
//! member signs in by magic link and uploads keys and manifest v1, invites
//! an ally who accepts with their key, and approves them with an
//! endorsement and manifest v2. Then a device is enrolled with a code and
//! endorsed with `min_manifest = v2`.
//!
//! Not covered here: the server in Postgres mode (the harness is SQLite
//! only) and the Playwright-driven ally web app, which does not exist yet;
//! this suite plays the ally's browser with faro-crypto instead. The
//! instance's background workers are driven explicitly rather than run
//! (see `e2e_support`).

mod e2e_support;

use axum::http::StatusCode;
use e2e_support::*;
use faro_crypto::CryptoError;
use faro_platform::synthetic::Scene;
use faro_platform::PermissionState;
use faro_proto::body::{EventBody, GoodbyeReason, Rating, TamperSignal};
use faro_proto::{EventHeader, EventKind, Urgency};
use faro_service::{GoodbyeError, GoodbyeOutcome, Phase};
use std::time::Duration;

/// Inject a distinct active-tamper signal (the service suppresses an
/// identical signal repeated within a minute, so each call names its own
/// component).
fn integrity_failure(dev: &Device, component: &str) {
    let component = component.to_owned();
    dev.script.with(|s| {
        s.tamper.push(TamperSignal::IntegrityFailure { component });
    });
}

/// 1. Onboarding → enrollment → endorsement → bootstrap → a High flag with a
///    blurred thumbnail reaches the ally: urgent in the feed, a content-free
///    immediate email, and a body only the member and the ally can open,
///    with no raw pixels anywhere in it or in anything persisted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn happy_path_flag_reaches_the_ally_blurred_and_urgent() {
    let w = World::new().await;
    let v2 = w.manifest().await;
    assert_eq!(v2.body.version, 2);

    let mut dev = w.enroll_device().await;
    // A structured synthetic screen (blocks of distinct colours), so the
    // pixel probe below has distinctive runs to look for.
    dev.script.with(|s| s.scene = Scene::Pattern(0x00FA_120E));
    dev.start(explicit_classifier());
    dev.wait("awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    // Pending: it heartbeats but seals and uploads nothing.
    assert!(w.stored_seqs(&dev).await.is_empty());
    assert_eq!(dev.status().events_committed, 0);

    let anchor = w.endorse(&dev).await;
    assert_eq!(anchor, v2.body.reference());
    let st = dev
        .wait("bootstrapped", |s| {
            s.phase == Phase::Running && s.manifest.is_some()
        })
        .await;
    assert_eq!(st.manifest, Some(v2.body.reference()));
    assert!(dev.dir.endorsement().expect("read").is_some());

    // The start-up capture comes 1-3 s (device time) after start; the
    // scripted classifier makes it a High rating.
    dev.drive_until("a flag", |s| s.flags >= 1).await;
    dev.upload_all().await;

    // ---- the ally's feed: the flag, urgent --------------------------------
    let feed = w.feed_events(&w.ally.session).await;
    let flag = feed
        .iter()
        .find(|e| e.kind == EventKind::Flag)
        .expect("the flag is in the ally's feed")
        .clone();
    assert_eq!(flag.device_id, dev.enrollment.device_id);
    assert_eq!(flag.urgency, Urgency::Urgent, "effective urgency");
    let blob_id = flag.blob_id.clone().expect("a flag has a body");
    // The member sees exactly what allies see (§12 transparency).
    let member_feed = w.feed_events(&w.member_session).await;
    assert!(member_feed.iter().any(|e| e.seq == flag.seq));

    // ---- an immediate, content-free email to the ally ---------------------
    w.t.notify_now().await;
    let mails = w.t.alert_mail_to(ALLY_EMAIL);
    assert!(!mails.is_empty(), "the ally was emailed at once");
    for m in &mails {
        assert!(m.subject.starts_with("Urgent:"), "{:?}", m.subject);
        assert!(m.text.contains(&format!("on {DEVICE_NAME}")));
        assert_content_free(m, &[]);
    }

    // ---- the ally downloads and decrypts the body --------------------------
    let r = w.blob(&w.ally.session, &blob_id).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let item: faro_proto::EncryptedItem = serde_json::from_slice(&r.raw).expect("EncryptedItem");
    // Sealed to the member and exactly the manifest's ally.
    let mut expected = vec![w.member.clone(), w.ally.id.clone()];
    expected.sort();
    assert_eq!(envelope_recipients(&item), expected);
    // The ciphertext is the one the signed header commits to.
    let (_, effective, header_json, _) =
        server::stored_event(w.state(), &dev.enrollment.device_id, flag.seq as i64)
            .await
            .expect("stored event");
    assert_eq!(effective, "urgent");
    let header: EventHeader = serde_json::from_str(&header_json).expect("header");
    assert_eq!(header.body_hash, item.body_hash());
    assert_eq!(header.kind, EventKind::Flag);

    let plain = open_event(&item, &dev, flag.seq, &w.ally.id, &w.ally.keys.enc)
        .expect("the ally can open the flag");
    // The member can open it too; the AAD pins it to this seq.
    assert!(open_event(&item, &dev, flag.seq, &w.member, &w.member_keys.enc).is_ok());
    assert!(matches!(
        open_event(&item, &dev, flag.seq + 1, &w.ally.id, &w.ally.keys.enc),
        Err(CryptoError::Decrypt)
    ));

    // No unblurred pixels: neither the body JSON nor the downloaded blob
    // contains any 8-pixel run of the raw frame the device captured.
    let probe = PixelProbe::capture(&dev.script);
    assert!(!probe.found_in(&plain), "raw pixels in the decrypted body");
    assert!(!probe.found_in(&r.raw), "raw pixels in the blob");

    let body: EventBody = serde_json::from_slice(&plain).expect("EventBody JSON");
    let EventBody::Flag(f) = body else {
        panic!("expected a flag body, got {body:?}");
    };
    assert_eq!(f.rating, Rating::High);
    assert!(!f.reasons.is_empty());
    let thumb = f
        .thumbnail
        .expect("a High flag carries a blurred thumbnail");
    assert_eq!(thumb.transform, faro_detect::THUMBNAIL_TRANSFORM);
    assert!(!probe.found_in(&thumb.png), "raw pixels inside the PNG");
    let img = image::load_from_memory_with_format(&thumb.png, image::ImageFormat::Png)
        .expect("the thumbnail is a PNG");
    assert!(img.width() <= 320, "thumbnail is {} px wide", img.width());
    assert_eq!((img.width(), img.height()), (thumb.width, thumb.height));
    let thumb_bytes = img.to_rgba8().into_raw().len();
    assert!(
        thumb_bytes * 4 < probe.frame_bytes,
        "the thumbnail ({thumb_bytes} B) is a small fraction of the frame ({} B)",
        probe.frame_bytes
    );

    // ---- nothing persisted holds raw pixels --------------------------------
    dev.shutdown().await;
    probe.assert_absent_under(&dev.state_dir);
    probe.assert_absent_under(w.t.dir.path());
}

/// 2. The member removes the ally with manifest v3; the device refreshes,
///    and the next event has no envelope for the removed ally, who also
///    gets 404 for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removed_ally_gets_nothing_sealed_after_the_device_accepts_v3() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;

    // Before the removal: sealed to member + ally.
    integrity_failure(&dev, "e2e-before-removal");
    dev.wait("first tamper", |s| s.tamper_events >= 1).await;
    let before_seq = dev.upload_all().await;
    let before = w.event_item(&w.ally.session, &dev, before_seq).await;
    assert!(envelope_recipients(&before).contains(&w.ally.id));
    assert!(open_event(&before, &dev, before_seq, &w.ally.id, &w.ally.keys.enc).is_ok());

    // The member removes the ally (their browser signs v3 without them).
    let v3 = w.remove_ally().await;
    assert!(v3.body.allies.is_empty());
    dev.handle().refresh_manifest_now();
    let st = dev
        .wait("manifest v3", |s| s.manifest == Some(v3.body.reference()))
        .await;
    assert!(st.manifest_warning.is_none());

    integrity_failure(&dev, "e2e-after-removal");
    dev.wait("second tamper", |s| s.tamper_events >= 2).await;
    let after_seq = dev.upload_all().await;
    assert!(after_seq > before_seq);

    // Device side: the new body is wrapped to the member only.
    let after = w.event_item(&w.member_session, &dev, after_seq).await;
    assert_eq!(envelope_recipients(&after), vec![w.member.clone()]);
    assert!(matches!(
        open_event(&after, &dev, after_seq, &w.ally.id, &w.ally.keys.enc),
        Err(CryptoError::NoEnvelope)
    ));
    let body: EventBody = serde_json::from_slice(
        &open_event(&after, &dev, after_seq, &w.member, &w.member_keys.enc)
            .expect("the member opens it"),
    )
    .expect("EventBody");
    assert!(matches!(
        body,
        EventBody::Tamper { signal: TamperSignal::IntegrityFailure { ref component }, .. }
            if component == "e2e-after-removal"
    ));

    // Instance side: the removed ally can't fetch it (or the feed).
    let blob = w
        .feed_event(&w.member_session, &dev, after_seq)
        .await
        .blob_id
        .expect("body");
    let r = w.blob(&w.ally.session, &blob).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = w.t.feed(&w.member, &w.ally.session).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    dev.shutdown().await;
}

/// 3. Screen-recording permission revoked on the device → an urgent tamper
///    event → an urgent alert email to the ally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_permission_is_an_urgent_tamper_alert_for_the_ally() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    // One successful capture first: the service has seen the permission
    // granted (a revocation is a transition from granted).
    dev.drive_until("a capture", |s| s.captures >= 1).await;
    assert_eq!(dev.status().tamper_events, 0);
    w.t.notify_now().await;
    let mails_before = w.t.alert_mail_to(ALLY_EMAIL).len();

    dev.script.with(|s| s.permission = PermissionState::Denied);
    dev.wait("tamper event", |s| s.tamper_events >= 1).await;
    let seq = dev.upload_all().await;

    let ev = w.feed_event(&w.ally.session, &dev, seq).await;
    assert_eq!(ev.kind, EventKind::Tamper);
    assert_eq!(ev.urgency, Urgency::Urgent);
    let item = w.event_item(&w.ally.session, &dev, seq).await;
    let body: EventBody = serde_json::from_slice(
        &open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
    )
    .expect("EventBody");
    assert_eq!(
        body,
        EventBody::Tamper {
            signal: TamperSignal::PermissionRevoked {
                permission: "screen_recording".into()
            },
            account: None,
        }
    );
    let alerts = w.alerts().await;
    assert!(
        alerts
            .iter()
            .any(|(kind, urgency, _)| kind == "tamper" && urgency == "urgent"),
        "{alerts:?}"
    );

    w.t.notify_now().await;
    let mails = w.t.alert_mail_to(ALLY_EMAIL);
    assert!(
        mails.len() > mails_before,
        "an alert email went to the ally"
    );
    for m in &mails[mails_before..] {
        assert!(m.subject.starts_with("Urgent:"), "{:?}", m.subject);
        assert_content_free(m, &[]);
    }

    dev.shutdown().await;
}

/// 4. The instance goes down while the device records events: they queue
///    in the outbox, and once it is back they are all uploaded in order,
///    with no chain-gap (or any other chain) alert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_recorded_offline_arrive_in_order_without_a_gap() {
    let mut w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    let synced = dev.upload_all().await;

    w.stop_server().await;
    const OFFLINE: usize = 5;
    for i in 0..OFFLINE {
        integrity_failure(&dev, &format!("e2e-offline-{i}"));
    }
    let st = dev
        .wait("offline tamper events", |s| {
            s.tamper_events >= OFFLINE as u64
        })
        .await;
    let last = st.last_seq.expect("committed");
    assert!(last >= synced + OFFLINE as u64);
    // Urgent events poke the uploader at once; it can't reach the instance.
    dev.handle().upload_now();
    dev.handle().heartbeat_now();
    let st = dev.status();
    assert!(st.acked_through.is_some_and(|a| a < last), "{st:?}");
    let held = w.stored_seqs(&dev).await;
    assert_eq!(held.last().copied(), Some(synced as i64), "nothing arrived");

    w.start_server().await;
    dev.handle().upload_now();
    dev.wait("queue drained", |s| {
        s.acked_through.is_some_and(|a| a >= last)
    })
    .await;

    let held = w.stored_seqs(&dev).await;
    let expected: Vec<i64> = (0..=last as i64).collect();
    assert_eq!(held, expected, "a contiguous chain from genesis");
    // The offline events are the injected ones, in the order they happened.
    let mut seen = Vec::new();
    for seq in synced + 1..=last {
        let item = w.event_item(&w.ally.session, &dev, seq).await;
        let body: EventBody = serde_json::from_slice(
            &open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
        )
        .expect("EventBody");
        if let EventBody::Tamper {
            signal: TamperSignal::IntegrityFailure { component },
            ..
        } = body
        {
            seen.push(component);
        }
    }
    let injected: Vec<String> = (0..OFFLINE).map(|i| format!("e2e-offline-{i}")).collect();
    assert_eq!(seen, injected);
    let alerts = w.alerts().await;
    for bad in [
        "chain_gap",
        "invalid_signature",
        "missed_checkin",
        "upload_stalled",
    ] {
        assert!(
            alerts.iter().all(|(kind, _, _)| kind != bad),
            "unexpected {bad}: {alerts:?}"
        );
    }

    dev.shutdown().await;
}

/// 5. A malicious instance rolls the stored manifest back to v2 (re-adding
///    the removed ally) after the device accepted v3: the device refuses
///    it, warns, keeps sealing to v3, and still does after a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rolled_back_manifest_is_refused_and_the_removed_ally_stays_out() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    let v2 = w.manifest().await;
    let v3 = w.remove_ally().await;
    dev.handle().refresh_manifest_now();
    dev.wait("manifest v3", |s| s.manifest == Some(v3.body.reference()))
        .await;

    // The instance's operator edits SQLite: v3 disappears, so the
    // (genuinely member-signed) v2 that lists the ally is "latest" again.
    let deleted = sqlx::query("DELETE FROM member_manifests WHERE member_id = $1 AND version = $2")
        .bind(w.member.as_str())
        .bind(3i64)
        .execute(w.state().db().pool())
        .await
        .expect("edit the database")
        .rows_affected();
    assert_eq!(deleted, 1);
    assert_eq!(w.manifest().await.body.reference(), v2.body.reference());

    dev.handle().refresh_manifest_now();
    let st = dev
        .wait("rollback refused", |s| s.manifest_warning.is_some())
        .await;
    let warning = st.manifest_warning.clone().unwrap_or_default();
    assert!(warning.contains("rollback"), "{warning}");
    assert_eq!(st.manifest, Some(v3.body.reference()), "keeps v3");

    integrity_failure(&dev, "e2e-after-rollback");
    dev.wait("tamper", |s| s.tamper_events >= 1).await;
    let seq = dev.upload_all().await;
    let item = w.event_item(&w.member_session, &dev, seq).await;
    assert_eq!(envelope_recipients(&item), vec![w.member.clone()]);
    assert!(matches!(
        open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc),
        Err(CryptoError::NoEnvelope)
    ));

    // The checkpoint is durable: a restarted service, still served v2,
    // seals its boot event (and everything after) to v3.
    dev.shutdown().await;
    dev.start(quiet_classifier());
    let st = dev
        .wait("restarted with a manifest and a warning", |s| {
            s.phase == Phase::Running
                && s.manifest.is_some()
                && s.last_seq.is_some()
                && s.manifest_warning.is_some()
        })
        .await;
    assert_eq!(st.manifest, Some(v3.body.reference()));
    assert!(st.manifest_warning.is_some_and(|m| m.contains("rollback")));
    let boot_seq = dev.upload_all().await;
    // `boot` has urgency none, so it is not in the feed; the member's
    // browser can still fetch its body by id.
    let (_, _, header_json, blob) =
        server::stored_event(w.state(), &dev.enrollment.device_id, boot_seq as i64)
            .await
            .expect("boot event stored");
    let header: EventHeader = serde_json::from_str(&header_json).expect("header");
    assert_eq!(header.kind, EventKind::Boot);
    let r = w
        .blob(&w.member_session, &blob.expect("boot has a body"))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let item: faro_proto::EncryptedItem = serde_json::from_slice(&r.raw).expect("item");
    assert_eq!(envelope_recipients(&item), vec![w.member.clone()]);

    integrity_failure(&dev, "e2e-after-restart");
    dev.wait("tamper after restart", |s| s.tamper_events >= 1)
        .await;
    let seq = dev.upload_all().await;
    let item = w.event_item(&w.member_session, &dev, seq).await;
    assert_eq!(envelope_recipients(&item), vec![w.member.clone()]);
    assert!(open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc).is_err());

    dev.shutdown().await;
}

/// 6. The device goes silent (its connection to the instance is cut while
///    it keeps running) → once the server clock passes the liveness grace
///    period, an urgent missed check-in, emailed to the ally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_device_raises_a_missed_checkin_after_the_grace_period() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    dev.upload_all().await;
    let sent = dev.status().heartbeats_sent;
    dev.handle().heartbeat_now();
    dev.wait("an active heartbeat", |s| s.heartbeats_sent > sent)
        .await;
    let r = w.t.get("/v1/me/devices", Some(&w.member_session)).await;
    let listed = r.body.as_array().expect("devices")[0].clone();
    assert_eq!(listed["status"], "active");
    assert!(listed["last_seen_at_ms"].is_i64(), "{listed}");

    w.gate.cut();
    let sent = dev.status().heartbeats_sent;
    dev.handle().heartbeat_now();

    let grace_ms =
        i64::try_from(w.state().settings().liveness.grace_secs).expect("grace fits") * 1000;
    // Just inside the grace period: nothing.
    w.t.clock.advance_ms(grace_ms - 60_000);
    let s = faro_server::liveness::run_once(w.state(), w.started_ms)
        .await
        .expect("liveness pass");
    assert_eq!(s.missed, 0);
    assert!(w
        .alerts()
        .await
        .iter()
        .all(|(k, _, _)| k != "missed_checkin"));

    // Past it: one urgent missed check-in naming the last known state.
    w.t.clock.advance_ms(120_000);
    let s = faro_server::liveness::run_once(w.state(), w.started_ms)
        .await
        .expect("liveness pass");
    assert_eq!(s.missed, 1);
    let alerts = w.alerts().await;
    let missed: Vec<_> = alerts
        .iter()
        .filter(|(k, _, _)| k == "missed_checkin")
        .collect();
    assert_eq!(missed.len(), 1, "{alerts:?}");
    assert_eq!(missed[0].1, "urgent");
    let detail = missed[0].2.clone().unwrap_or_default();
    assert!(detail.starts_with("last_state=active;"), "{detail}");

    w.t.notify_now().await;
    let mails = w.t.alert_mail_to(ALLY_EMAIL);
    let last = mails.last().expect("the ally was emailed");
    assert!(last.subject.starts_with("Urgent:"), "{:?}", last.subject);
    assert_content_free(last, &["missed", "silent"]);

    // The device never got through while cut off.
    assert_eq!(dev.status().heartbeats_sent, sent);
    dev.shutdown().await;
}

/// 7. The enrollment link pins the member key (`m`): an instance answering
///    with any other "member" key (to sign manifests that add its own ally)
///    is refused before anything is persisted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_refuses_a_member_key_other_than_the_links() {
    let w = World::new().await;
    // Stand-in for a substituted key: the link names a key the instance's
    // answer (the genuine member key) does not match.
    let wrong = "0123456789abcdef".to_owned();
    assert_ne!(wrong, w.member_key_id());
    match w.try_enroll(Some(wrong.clone())).await {
        Err(faro_service::enroll::EnrollError::MemberKeyMismatch { expected, got }) => {
            assert_eq!(expected, wrong);
            assert_eq!(got, w.member_key_id());
        }
        Err(other) => panic!("unexpected error {other}"),
        Ok(_) => panic!("enrolled despite a member key mismatch"),
    }
    // The genuine key from the member's browser enrolls (and every other
    // scenario enrolls this way too).
    let dev = w.enroll_device().await;
    assert_eq!(
        faro_service::enroll::member_fingerprint(&dev.enrollment.member_sign_pubkey),
        w.member_key_id()
    );
}

/// 8. Screen recording revoked while the service was stopped (before a
///    reboot, say) is still an urgent tamper event at the next start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permission_revoked_while_stopped_is_tamper_at_next_start() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    dev.drive_until("a capture", |s| s.captures >= 1).await;
    dev.shutdown().await;

    dev.script.with(|s| s.permission = PermissionState::Denied);
    dev.start(quiet_classifier());
    dev.wait("tamper at start", |s| s.tamper_events >= 1).await;
    let seq = dev.upload_all().await;
    let ev = w.feed_event(&w.ally.session, &dev, seq).await;
    assert_eq!(ev.kind, EventKind::Tamper);
    assert_eq!(ev.urgency, Urgency::Urgent);
    let item = w.event_item(&w.ally.session, &dev, seq).await;
    let body: EventBody = serde_json::from_slice(
        &open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
    )
    .expect("EventBody");
    assert_eq!(
        body,
        EventBody::Tamper {
            signal: TamperSignal::PermissionRevoked {
                permission: "screen_recording".into()
            },
            account: None,
        }
    );
    dev.shutdown().await;
}

/// 9. Report-day rollover: crossing local midnight seals the finished day
///    `[start, midnight)` and starts the next period exactly at midnight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn midnight_rollover_seals_the_day_and_starts_the_next() {
    use faro_core::Clock;
    use faro_service::runtime::journal::{day_start, DAY_MS};
    const MIN: i64 = 60_000;

    let w = World::new().await;
    let mut dev = w.enroll_device().await;
    // Choose the report UTC offset so local midnight is about 75 s of
    // device time away (well inside the harness's drive budget).
    let now = dev.clock.wall_ms();
    let mut off_min = ((DAY_MS - 75_000 - now).rem_euclid(DAY_MS) + MIN / 2) / MIN;
    if off_min > 12 * 60 {
        off_min -= 24 * 60;
    }
    dev.utc_offset_minutes = i32::try_from(off_min).expect("offset fits");
    let midnight = day_start(now, dev.utc_offset_minutes) + DAY_MS;
    assert!(
        (30_000..=120_000).contains(&(midnight - now)),
        "{}",
        midnight - now
    );

    dev.start(quiet_classifier());
    dev.wait("awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    w.endorse(&dev).await;
    dev.wait("running", |s| {
        s.phase == Phase::Running && s.last_seq.is_some()
    })
    .await;
    // Most of the way in 1 s steps (quicker than the harness's 50 ms ones),
    // then the last stretch with the harness.
    while dev.clock.wall_ms() < midnight - 2_000 {
        dev.clock.advance(1_000);
        tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    }
    dev.drive_until("the day's report", |s| s.reports_queued >= 1)
        .await;
    assert!(dev.clock.wall_ms() >= midnight);
    // A little of the new day, then a partial report for it at shutdown.
    dev.clock.advance(5_000);
    dev.shutdown().await;

    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT period_start_ms, period_end_ms FROM reports WHERE device_id = $1 ORDER BY period_start_ms",
    )
    .bind(dev.enrollment.device_id.as_str())
    .fetch_all(w.t.state.db().pool())
    .await
    .expect("query reports");
    let periods: Vec<(i64, i64)> = rows
        .iter()
        .map(|r| {
            (
                r.try_get("period_start_ms").expect("start"),
                r.try_get("period_end_ms").expect("end"),
            )
        })
        .collect();
    assert_eq!(periods.len(), 2, "{periods:?}");
    assert!(periods[0].0 < midnight, "{periods:?}");
    assert_eq!(periods[0].1, midnight, "the day ends at midnight");
    assert_eq!(periods[1].0, midnight, "the next period starts at midnight");
    assert!(periods[1].1 > midnight);
}

/// 10. Uninstall (§3.7): with the service stopped, `goodbye` seals an urgent
///     `goodbye` to the ally, who is alerted by email. The device is retired:
///     its silence afterwards is not a missed check-in. While the service
///     runs, `goodbye` refuses (two writers would fork the chain).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uninstall_goodbye_alerts_the_ally_and_retires_the_device() {
    let w = World::new().await;
    let mut dev = w.active_device(quiet_classifier()).await;
    dev.upload_all().await;

    let refused = dev.goodbye(Duration::ZERO).await;
    assert!(
        matches!(refused, Err(GoodbyeError::ServiceRunning { .. })),
        "{refused:?}"
    );

    dev.shutdown().await;
    let before = w.stored_seqs(&dev).await;
    w.t.notify_now().await;
    let mails_before = w.t.alert_mail_to(ALLY_EMAIL).len();

    let seq = match dev.goodbye(Duration::from_secs(1)).await {
        Ok(GoodbyeOutcome::Delivered { seq }) => seq,
        other => panic!("goodbye not delivered: {other:?}"),
    };
    let stored = w.stored_seqs(&dev).await;
    assert_eq!(
        i64::try_from(seq).expect("seq fits"),
        *stored.last().expect("stored"),
        "the goodbye is the last event"
    );
    assert_eq!(stored.len(), before.len() + 1, "{before:?} -> {stored:?}");

    let ev = w.feed_event(&w.ally.session, &dev, seq).await;
    assert_eq!(ev.kind, EventKind::Goodbye);
    assert_eq!(ev.urgency, Urgency::Urgent);
    let item = w.event_item(&w.ally.session, &dev, seq).await;
    let body: EventBody = serde_json::from_slice(
        &open_event(&item, &dev, seq, &w.ally.id, &w.ally.keys.enc).expect("ally opens it"),
    )
    .expect("EventBody");
    assert_eq!(
        body,
        EventBody::Goodbye {
            reason: GoodbyeReason::Uninstalled
        }
    );
    let alerts = w.alerts().await;
    assert!(
        alerts
            .iter()
            .any(|(kind, urgency, _)| kind == "goodbye" && urgency == "urgent"),
        "{alerts:?}"
    );
    w.t.notify_now().await;
    let mails = w.t.alert_mail_to(ALLY_EMAIL);
    assert!(mails.len() > mails_before, "the ally was emailed");
    for m in &mails[mails_before..] {
        assert!(m.subject.starts_with("Urgent:"), "{:?}", m.subject);
        assert_content_free(m, &[]);
    }

    // Long past the grace period: the goodbye was the alert.
    let grace_ms =
        i64::try_from(w.state().settings().liveness.grace_secs).expect("grace fits") * 1000;
    w.t.clock.advance_ms(grace_ms + 3_600_000);
    let s = faro_server::liveness::run_once(w.state(), w.started_ms)
        .await
        .expect("liveness pass");
    assert_eq!(s.missed, 0, "a retired device is not judged");
}

/// 11. `goodbye` while the instance is unreachable writes nothing, so the
///     uninstaller can back out and restart the service with an unchanged
///     chain. A device its member never approved has nobody to tell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goodbye_writes_nothing_when_it_cannot_be_delivered() {
    let w = World::new().await;
    let pending = w.enroll_device().await;
    assert_eq!(
        pending.goodbye(Duration::ZERO).await.expect("goodbye"),
        GoodbyeOutcome::NotActivated
    );

    let mut dev = w.active_device(quiet_classifier()).await;
    dev.shutdown().await;
    let head = || {
        let o = faro_core::Outbox::open(
            dev.dir.path(),
            &dev.enrollment.instance_id,
            &dev.enrollment.device_id,
        )
        .expect("outbox");
        o.head().expect("head").next_seq
    };
    let next = head();

    w.gate.cut();
    let r = dev.goodbye(Duration::ZERO).await;
    assert!(matches!(r, Err(GoodbyeError::Unreachable(_))), "{r:?}");
    assert_eq!(head(), next, "nothing was written");

    // The service starts again on the same chain (the lock was released).
    dev.start(quiet_classifier());
    dev.wait("running again", |s| s.phase == Phase::Running)
        .await;
    dev.shutdown().await;
}
