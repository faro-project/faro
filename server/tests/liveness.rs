//! The liveness monitor and instance-uptime bookkeeping (§3.7), driven with
//! the manual clock.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::api::{DeviceState, Heartbeat};
use faro_proto::{EventKind, Hash32, Urgency};
use faro_server::db::repo::uptime;
use faro_server::liveness;
use faro_server::workers::UptimeRun;

const H: i64 = 3600 * 1000;

fn grace_ms(t: &TestApp) -> i64 {
    i64::try_from(t.state.settings().liveness.grace_secs).unwrap() * 1000
}

fn missed(
    alerts: &[faro_server::db::repo::alerts::AlertRow],
) -> Vec<&faro_server::db::repo::alerts::AlertRow> {
    alerts
        .iter()
        .filter(|a| a.kind == "missed_checkin" && a.urgency == "urgent")
        .collect()
}

#[tokio::test]
async fn silent_device_past_grace_raises_one_urgent_missed_checkin() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, _s, _k, dev) = t.active_device().await;
    t.clock.advance_ms(H);
    let r = t.heartbeat(&dev, DeviceState::Sleeping).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let last_seen = t.clock_ms();

    // Within the grace period: nothing.
    t.clock.advance_ms(grace_ms(&t));
    let s = liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(s.missed, 0);
    assert!(missed(&t.alerts(&member).await).is_empty());

    // Just past it: one urgent alert with the last known state.
    t.clock.advance_ms(1);
    let s = liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(s.missed, 1);
    let alerts = t.alerts(&member).await;
    let m = missed(&alerts);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].source, "server");
    assert_eq!(m[0].device_id.as_deref(), Some(dev.id.as_str()));
    assert_eq!(
        m[0].detail.as_deref(),
        Some(format!("last_state=sleeping;since_ms={last_seen}").as_str())
    );

    // Still silent an hour later: no repeat.
    t.clock.advance_ms(H);
    liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(missed(&t.alerts(&member).await).len(), 1);

    // It is urgent and immediate for the member, content-free.
    t.notify_now().await;
    let mails = t.alert_mail_to("sam@example.org");
    assert_eq!(mails.len(), 1);
    assert!(mails[0]
        .text
        .starts_with("Urgent: new alert for sam on Sam's MacBook."));

    // The device checks in: the episode closes with a normal "back online".
    let r = t.heartbeat(&dev, DeviceState::Active).await;
    assert_eq!(r.status, StatusCode::OK);
    let alerts = t.alerts(&member).await;
    let back: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind == "missed_checkin" && a.urgency == "normal")
        .collect();
    assert_eq!(back.len(), 1);
    assert!(back[0]
        .detail
        .as_deref()
        .unwrap()
        .starts_with("back_online;silent_ms="));
    // A second heartbeat does not re-announce it.
    t.heartbeat(&dev, DeviceState::Active).await;
    assert_eq!(t.alerts(&member).await.len(), alerts.len());

    // A new silence after recovery is a new episode.
    t.clock.advance_ms(grace_ms(&t) + 1);
    liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(missed(&t.alerts(&member).await).len(), 2);
}

#[tokio::test]
async fn silence_overlapping_instance_downtime_never_counts() {
    let t = TestApp::new().await;
    let (member, _s, _k, dev) = t.active_device().await;
    t.heartbeat(&dev, DeviceState::Active).await;
    let grace = grace_ms(&t);

    // The instance is down for 10 hours right after that heartbeat, then
    // restarts.
    t.clock.advance_ms(10 * H);
    let restarted = t.clock_ms();
    // Immediately, and all through one grace period of uptime: nothing,
    // although the device has been silent for far longer than the grace.
    for step in [0, H, 2 * H, grace - 1] {
        t.clock.set_ms(restarted + step);
        let s = liveness::run_once(&t.state, restarted).await.unwrap();
        assert_eq!(s.missed, 0, "at +{step} ms");
        assert_eq!(
            s.judged, 0,
            "nobody is judged during the post-restart grace"
        );
    }
    // At exactly one grace of uptime the device is judged, and the counted
    // silence (from the restart) is not yet longer than the grace.
    t.clock.set_ms(restarted + grace);
    let s = liveness::run_once(&t.state, restarted).await.unwrap();
    assert_eq!((s.judged, s.missed), (1, 0));
    assert!(missed(&t.alerts(&member).await).is_empty());

    // The device comes back during the grace period: never an alert.
    t.clock.set_ms(restarted + H);
    t.heartbeat(&dev, DeviceState::Active).await;
    t.clock.set_ms(restarted + grace + H / 2);
    liveness::run_once(&t.state, restarted).await.unwrap();
    assert!(missed(&t.alerts(&member).await).is_empty());

    // If it stays silent past a full grace *of uptime*, it is reported,
    // counting silence from its last heartbeat after the restart.
    t.clock.set_ms(restarted + H + grace + 1);
    let s = liveness::run_once(&t.state, restarted).await.unwrap();
    assert_eq!(s.missed, 1);
    let alerts = t.alerts(&member).await;
    assert!(missed(&alerts)[0]
        .detail
        .as_deref()
        .unwrap()
        .ends_with(&format!("since_ms={}", restarted + H)));
}

#[tokio::test]
async fn device_that_never_checked_in_is_judged_from_activation() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, session, keys, _dev) = t.active_device().await;
    // A second device that stays pending is never judged.
    let code = t.enroll_code(&session).await;
    let _pending = t.enroll(&code, &keys.enc).await;
    t.clock.advance_ms(grace_ms(&t) + 1);
    let s = liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(s.missed, 1, "only the active device");
    let alerts = t.alerts(&member).await;
    assert_eq!(
        missed(&alerts)[0]
            .detail
            .as_deref()
            .map(|d| d.starts_with("last_state=unknown")),
        Some(true)
    );
    assert_eq!(
        Urgency::parse(&missed(&alerts)[0].urgency),
        Some(Urgency::Urgent)
    );
}

#[tokio::test]
async fn uptime_rows_close_crashed_runs_at_their_last_alive_tick() {
    let t = TestApp::new().await;
    let first = UptimeRun::start(&t.state).await.unwrap();
    t.clock.advance_ms(30_000);
    first.tick(&t.state).await.unwrap();
    let last_alive = t.clock_ms();
    // Crash: no stop(). Some time later the next run starts.
    t.clock.advance_ms(5 * H);
    let second = UptimeRun::start(&t.state).await.unwrap();
    assert_eq!(second.started_at_ms(), t.clock_ms());
    let rows = uptime::list(t.state.db().pool()).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].stopped_at_ms, Some(last_alive));
    assert_eq!(rows[1].stopped_at_ms, None);
    // A clean stop records the stop time.
    t.clock.advance_ms(1000);
    second.stop(&t.state).await.unwrap();
    let rows = uptime::list(t.state.db().pool()).await.unwrap();
    assert_eq!(rows[1].stopped_at_ms, Some(t.clock_ms()));
}

#[tokio::test]
async fn admin_can_change_the_grace_period_live() {
    let t = TestApp::new().await;
    let (_a, admin_s) = t.setup_admin("admin@example.org").await;
    let run_started = t.clock_ms();
    let (member, _s, _k, dev) = t.active_device().await;
    t.heartbeat(&dev, DeviceState::Active).await;
    let r = t
        .call(
            axum::http::Method::PATCH,
            "/admin/api/settings",
            Some(serde_json::json!({"liveness_grace_secs": 3600})),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.clock.advance_ms(H + 1);
    let s = liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(s.missed, 1);
    assert_eq!(missed(&t.alerts(&member).await).len(), 1);
}

/// A heartbeat claiming a chain position.
async fn heartbeat_at(
    t: &TestApp,
    dev: &TestDevice,
    last_seq: Option<u64>,
    last_hash: Option<Hash32>,
) -> Resp {
    let hb = dev.key.sign_heartbeat(Heartbeat {
        instance_id: t.instance_id(),
        device_id: dev.id.clone(),
        ts_ms: t.clock_ms(),
        mono_ms: 1,
        boot_id: "boot-1".into(),
        state: DeviceState::Active,
        last_seq,
        last_hash,
    });
    t.device_post(dev, "/v1/heartbeat", &hb).await
}

fn urgent_alerts<'a>(
    alerts: &'a [faro_server::db::repo::alerts::AlertRow],
    kind: &str,
    prefix: &str,
) -> Vec<&'a faro_server::db::repo::alerts::AlertRow> {
    alerts
        .iter()
        .filter(|a| {
            a.kind == kind
                && a.urgency == "urgent"
                && a.detail.as_deref().is_some_and(|d| d.starts_with(prefix))
        })
        .collect()
}

#[tokio::test]
async fn a_host_suspend_is_instance_downtime_not_device_silence() {
    let t = TestApp::new().await;
    let run = UptimeRun::start(&t.state).await.unwrap();
    let (member, _s, _k, dev) = t.active_device().await;
    let grace = grace_ms(&t);
    // Four hours of normal operation: ticks, passes and heartbeats.
    for minute in 1..=240 {
        t.clock.advance_ms(60_000);
        run.tick(&t.state).await.unwrap();
        if minute % 5 == 0 {
            t.heartbeat(&dev, DeviceState::Active).await;
        }
        liveness::pass(&t.state, &run).await.unwrap();
    }
    let last_alive = t.clock_ms();
    // The host sleeps for eight hours. On resume the overdue liveness pass
    // fires before any device could reconnect.
    t.clock.advance_ms(8 * H);
    let resumed = t.clock_ms();
    let s = liveness::pass(&t.state, &run).await.unwrap();
    assert_eq!((s.judged, s.missed), (0, 0), "nobody is judged right after");
    assert!(missed(&t.alerts(&member).await).is_empty());
    // The uptime table shows the gap like any other downtime.
    run.tick(&t.state).await.unwrap();
    let rows = uptime::list(t.state.db().pool()).await.unwrap();
    let last_two: Vec<_> = rows.iter().rev().take(2).rev().collect();
    assert_eq!(last_two[0].stopped_at_ms, Some(last_alive));
    assert_eq!(last_two[1].started_at_ms, resumed);

    // If the device then really stays silent, it is reported one grace
    // period of uptime later, counting from the resume.
    let mut reported = None;
    for _ in 0..(grace / 60_000 + 2) {
        t.clock.advance_ms(60_000);
        run.tick(&t.state).await.unwrap();
        let s = liveness::pass(&t.state, &run).await.unwrap();
        if s.missed > 0 {
            reported = Some(t.clock_ms());
            break;
        }
    }
    assert!(reported.unwrap() > resumed + grace);
    let alerts = t.alerts(&member).await;
    assert!(missed(&alerts)[0]
        .detail
        .as_deref()
        .unwrap()
        .ends_with(&format!("since_ms={resumed}")));
}

#[tokio::test]
async fn a_wall_clock_jump_restarts_the_grace_period() {
    let t = TestApp::new().await;
    let run = UptimeRun::start(&t.state).await.unwrap();
    assert_eq!(run.observe(t.clock_ms() + 60_000), run.started_at_ms());
    let before = run.started_at_ms();
    // NTP corrects a stale boot clock by a day.
    let jumped = t.clock_ms() + 24 * H;
    assert_eq!(run.observe(jumped), jumped);
    assert!(jumped > before);
    // A small backwards step is taken as is and does not count as downtime.
    assert_eq!(run.observe(jumped - 1000), jumped);
    assert_eq!(run.observe(jumped + 60_000), jumped);
}

#[tokio::test]
async fn silence_before_endorsement_is_never_counted() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, session, keys, _dev) = t.active_device().await;
    let code = t.enroll_code(&session).await;
    let pending = t.enroll(&code, &keys.enc).await;
    // One heartbeat while pending, then nothing for five hours.
    assert_eq!(
        t.heartbeat(&pending, DeviceState::Active).await.status,
        StatusCode::OK
    );
    t.clock.advance_ms(5 * H);
    assert_eq!(
        t.endorse(&pending, &keys, &session).await.status,
        StatusCode::OK
    );
    let endorsed = t.clock_ms();
    t.clock.advance_ms(60_000);
    liveness::run_once(&t.state, run_started).await.unwrap();
    let alerts = t.alerts(&member).await;
    let about_new: Vec<_> = missed(&alerts)
        .into_iter()
        .filter(|a| a.device_id.as_deref() == Some(pending.id.as_str()))
        .collect();
    assert!(about_new.is_empty(), "{alerts:?}");
    // Silent for a full grace after endorsement: reported from endorsement.
    t.clock.set_ms(endorsed + grace_ms(&t) + 1);
    liveness::run_once(&t.state, run_started).await.unwrap();
    let alerts = t.alerts(&member).await;
    let about_new: Vec<_> = missed(&alerts)
        .into_iter()
        .filter(|a| a.device_id.as_deref() == Some(pending.id.as_str()))
        .collect();
    assert_eq!(about_new.len(), 1);
    assert!(about_new[0]
        .detail
        .as_deref()
        .unwrap()
        .ends_with(&format!("since_ms={endorsed}")));
}

#[tokio::test]
async fn a_device_that_heartbeats_but_stops_uploading_is_reported_once() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, _s, _k, mut dev) = t.active_device().await;
    let ev = dev.next_event(EventKind::Capture, Urgency::None);
    t.post_events(&dev, &[ev]).await;
    // Keeping up: claiming the held head is fine.
    assert_eq!(
        heartbeat_at(&t, &dev, Some(0), Some(dev.head.prev_hash))
            .await
            .status,
        StatusCode::OK
    );
    // Uploads are blocked from here on; heartbeats keep claiming seq 5.
    let behind_from = t.clock_ms() + 60_000;
    let steps = (grace_ms(&t) + 2 * H) / (5 * 60_000);
    for _ in 0..steps {
        t.clock.advance_ms(5 * 60_000);
        heartbeat_at(&t, &dev, Some(5), None).await;
        liveness::run_once(&t.state, run_started).await.unwrap();
    }
    let alerts = t.alerts(&member).await;
    let stalled = urgent_alerts(&alerts, "upload_stalled", "upload_stalled;");
    assert_eq!(stalled.len(), 1, "one alert per stall: {alerts:?}");
    assert!(stalled[0]
        .detail
        .as_deref()
        .unwrap()
        .starts_with("upload_stalled;reported_seq=5;held_seq=0;since_ms="));
    assert!(
        missed(&alerts).is_empty(),
        "it is heartbeating, so it is not missing"
    );
    let since: i64 = stalled[0]
        .detail
        .as_deref()
        .unwrap()
        .rsplit('=')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(since >= behind_from - 60_000 && since <= behind_from + 5 * 60_000);

    // The backlog arrives: the stall is over and a later short lag (normal
    // upload latency) raises nothing.
    let evs: Vec<_> = (0..5)
        .map(|_| dev.next_event(EventKind::Capture, Urgency::None))
        .collect();
    t.post_events(&dev, &evs).await;
    for _ in 0..steps {
        t.clock.advance_ms(5 * 60_000);
        heartbeat_at(&t, &dev, Some(dev.head.next_seq), None).await;
        let ev = dev.next_event(EventKind::Capture, Urgency::None);
        t.post_events(&dev, &[ev]).await;
        liveness::run_once(&t.state, run_started).await.unwrap();
    }
    let alerts = t.alerts(&member).await;
    assert_eq!(
        urgent_alerts(&alerts, "upload_stalled", "upload_stalled;").len(),
        1
    );
}

#[tokio::test]
async fn a_heartbeat_naming_a_different_chain_is_a_fork() {
    let t = TestApp::new().await;
    let (member, _s, _k, mut dev) = t.active_device().await;
    let evs = vec![
        dev.next_event(EventKind::Capture, Urgency::None),
        dev.next_event(EventKind::Capture, Urgency::None),
    ];
    t.post_events(&dev, &evs).await;
    // The right hash for the held head: nothing.
    heartbeat_at(&t, &dev, Some(1), Some(dev.head.prev_hash)).await;
    assert!(urgent_alerts(&t.alerts(&member).await, "chain_gap", "heartbeat_fork").is_empty());
    // A different one: the device holds a rewritten chain.
    for _ in 0..2 {
        let r = heartbeat_at(&t, &dev, Some(1), Some(Hash32::ZERO)).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    assert_eq!(
        urgent_alerts(&t.alerts(&member).await, "chain_gap", "heartbeat_fork").len(),
        1,
        "raised once per position"
    );
}

#[tokio::test]
async fn a_goodbye_retires_the_device_from_liveness() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, _s, _k, mut dev) = t.active_device().await;
    t.heartbeat(&dev, DeviceState::Active).await;
    let ev = dev.next_event(EventKind::Goodbye, Urgency::Urgent);
    t.post_events(&dev, &[ev]).await;
    t.clock.advance_ms(24 * H);
    liveness::run_once(&t.state, run_started).await.unwrap();
    let alerts = t.alerts(&member).await;
    assert!(
        missed(&alerts).is_empty(),
        "the goodbye was the alert: {alerts:?}"
    );
    // Heard from again: judged again.
    t.heartbeat(&dev, DeviceState::Active).await;
    t.clock.advance_ms(grace_ms(&t) + 1);
    liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(missed(&t.alerts(&member).await).len(), 1);
}

#[tokio::test]
async fn a_member_can_remove_a_device_and_allies_are_told() {
    let t = TestApp::new().await;
    let run_started = t.clock_ms();
    let (member, session, keys, dev) = t.active_device().await;
    // Silent: an episode opens.
    t.clock.advance_ms(grace_ms(&t) + 1);
    liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(missed(&t.alerts(&member).await).len(), 1);

    // Nobody else can remove it, and an unknown id is the same 404.
    let (_eve, eve_s) = t.sign_in("eve@example.org").await;
    let path = format!("/v1/me/devices/{}", dev.id);
    let r = t.call(Method::DELETE, &path, None, Some(&eve_s)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .call(
            Method::DELETE,
            "/v1/me/devices/dev_nope",
            None,
            Some(&session),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let r = t.call(Method::DELETE, &path, None, Some(&session)).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    // Its token and key no longer authenticate. The device itself (token
    // and signature) learns why, so its uninstaller knows allies were told.
    let r = t.heartbeat(&dev, DeviceState::Active).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "device_removed");
    // It is gone from the list, its episode is closed, and the removal is
    // an urgent alert.
    let l = t.get("/v1/me/devices", Some(&session)).await;
    assert_eq!(l.body, serde_json::json!([]));
    assert_eq!(
        count(
            &t.state,
            "SELECT COUNT(*) FROM liveness_episodes WHERE closed_at IS NULL"
        )
        .await,
        0
    );
    let alerts = t.alerts(&member).await;
    let removed: Vec<_> = alerts
        .iter()
        .filter(|a| a.kind == "device_removed")
        .collect();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].urgency, "urgent");
    // Not judged any more.
    t.clock.advance_ms(grace_ms(&t) * 3);
    let s = liveness::run_once(&t.state, run_started).await.unwrap();
    assert_eq!(s.judged, 0);
    // Twice is a 404.
    let r = t.call(Method::DELETE, &path, None, Some(&session)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // A pending device (never monitored) is removed quietly.
    let code = t.enroll_code(&session).await;
    let pending = t.enroll(&code, &keys.enc).await;
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/devices/{}", pending.id),
            None,
            Some(&session),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.alerts(&member)
            .await
            .iter()
            .filter(|a| a.kind == "device_removed")
            .count(),
        1
    );
}
