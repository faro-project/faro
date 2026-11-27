//! Enrollment, approval, the embedded runtime and urgent signals against the
//! real instance (docs/ANDROID.md §8, §10).

mod support;

use faro_android::{AndroidTamper, ApprovalState, FaroAndroidError, PermissionState};
use faro_proto::body::{EventBody, TamperSignal};
use faro_proto::{EventKind, Urgency};
use std::sync::Arc;
use support::{
    blocking, eventually, explicit, phone_core, phone_core_with, FakePhone, World, DEVICE_NAME,
};

/// Enroll a phone with a link naming the member key and approve it.
async fn approved(
    w: &World,
    dir: &std::path::Path,
    phone: Arc<FakePhone>,
    classifier: Option<fn() -> Box<dyn faro_detect::Classifier>>,
) -> (Arc<faro_android::FaroAndroid>, String) {
    let core = phone_core(dir, phone, classifier);
    let link = w.link(Some(&w.member_key_id())).await;
    let c = core.clone();
    let enrolled = blocking(move || {
        c.preview_enrollment(link.clone())?;
        c.enroll(link, DEVICE_NAME.into())
    })
    .await
    .expect("enrolled");
    w.endorse(&enrolled.device_id, &enrolled.device_fingerprint)
        .await;
    let c = core.clone();
    assert_eq!(
        blocking(move || c.poll_approval()).await.unwrap(),
        ApprovalState::Active
    );
    (core, enrolled.device_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolls_as_android_monitors_and_uploads_urgent_tamper() {
    support::init_logging();
    let w = World::new().await;
    let tmp = tempfile::tempdir().unwrap();
    let phone = FakePhone::new();
    let core = phone_core(tmp.path(), phone.clone(), Some(explicit));

    // Not enrolled yet.
    let s = core.status();
    assert!(!s.enrolled && !s.active, "{s:?}");
    assert!(matches!(core.start(), Err(FaroAndroidError::State(_))));

    // Preview: the instance, and the member key the link names.
    let link = w.link(Some(&w.member_key_id())).await;
    let (c, l) = (core.clone(), link.clone());
    let preview = blocking(move || c.preview_enrollment(l)).await.unwrap();
    assert_eq!(preview.instance_url, w.url());
    assert!(!preview.instance_name.is_empty());
    assert_eq!(preview.member_fingerprint, Some(w.member_key_id()));

    // Enroll: registered as `android`, waiting for approval.
    let c = core.clone();
    let enrolled = blocking(move || c.enroll(link, DEVICE_NAME.into()))
        .await
        .unwrap();
    let c = core.clone();
    assert_eq!(
        blocking(move || c.poll_approval()).await.unwrap(),
        ApprovalState::Pending
    );
    let s = core.status();
    assert!(s.enrolled && !s.active, "{s:?}");
    assert_eq!(s.headline, "Waiting for approval in the web app");

    // The member approves (checking platform and fingerprint).
    w.endorse(&enrolled.device_id, &enrolled.device_fingerprint)
        .await;
    let c = core.clone();
    assert_eq!(
        blocking(move || c.poll_approval()).await.unwrap(),
        ApprovalState::Active
    );
    assert!(core.status().active);

    // Start (twice: idempotent). Frames flow, are classified and flagged,
    // and the events upload.
    core.start().unwrap();
    core.start().unwrap();
    let dev = enrolled.device_id.clone();
    let events = eventually("a flag on the instance", async || {
        let ev = w.events(&dev).await;
        ev.iter().any(|e| e.1 == EventKind::Flag).then_some(ev)
    })
    .await;
    assert_eq!(
        w.stored_kinds(&dev).await.first().map(|k| k.1.as_str()),
        Some("boot"),
        "{events:?}"
    );
    assert!(phone.with(|s| s.captured) >= 1);
    let flag = events.iter().find(|e| e.1 == EventKind::Flag).unwrap();
    match &flag.3 {
        EventBody::Flag(f) => {
            // The reduced origin is the only address that reaches a body.
            let url = f.browser.as_ref().and_then(|b| b.url.as_deref());
            assert_eq!(
                f.app.as_ref().map(|a| a.id.as_str()),
                Some("com.android.chrome")
            );
            assert_eq!(f.window_title, None);
            assert_eq!(url, Some("https://example.org/"), "{f:?}");
        }
        other => panic!("not a flag body: {other:?}"),
    }
    let s = core.status();
    assert_eq!(s.headline, "Monitoring", "{s:?}");
    assert!(s.active && s.problem.is_none());
    // The login notice went to the phone (§12).
    eventually("the notice", async || {
        (!phone.with(|s| s.notices.is_empty())).then_some(())
    })
    .await;

    // The device admin disable request: recorded and uploaded before
    // `report_tamper_now` returns, as an urgent tamper event.
    let c = core.clone();
    blocking(move || c.report_tamper_now(AndroidTamper::DeviceAdminDisableRequested)).await;
    let events = w.events(&dev).await;
    let tamper: Vec<_> = events.iter().filter(|e| e.1 == EventKind::Tamper).collect();
    assert_eq!(tamper.len(), 1, "{events:?}");
    assert_eq!(tamper[0].2, Urgency::Urgent);
    assert!(
        matches!(
            &tamper[0].3,
            EventBody::Tamper { signal: TamperSignal::PermissionRevoked { permission, never_granted: false }, .. }
                if permission == "device_admin"
        ),
        "{:?}",
        tamper[0].3
    );
    let stored = w.stored_seqs(&dev).await;
    assert_eq!(
        stored,
        (0..stored.len() as i64).collect::<Vec<_>>(),
        "an unbroken chain"
    );
    let kinds = w.alert_kinds().await;
    assert!(
        !kinds
            .iter()
            .any(|k| k == "chain_gap" || k == "invalid_signature"),
        "{kinds:?}"
    );

    // Context signals are for the report, never events.
    phone.with(|s| {
        s.tamper.push(AndroidTamper::BatteryOptimizationOn);
        s.tamper.push(AndroidTamper::UsbDebuggingOn);
    });
    eventually("the context polled", async || {
        phone.with(|s| s.tamper.is_empty()).then_some(())
    })
    .await;

    // Graceful stop: a shutdown event reaches the instance. Stopping again
    // does nothing.
    core.stop();
    core.stop();
    eventually("the shutdown event", async || {
        w.stored_kinds(&dev)
            .await
            .iter()
            .any(|k| k.1 == "shutdown")
            .then_some(())
    })
    .await;
    let events = w.events(&dev).await;
    assert_eq!(
        events.iter().filter(|e| e.1 == EventKind::Tamper).count(),
        1,
        "context signals are not tamper events: {events:?}"
    );

    // Start again after the stop: the runtime comes back on the same chain.
    core.start().unwrap();
    eventually("a second boot", async || {
        (w.stored_kinds(&dev)
            .await
            .iter()
            .filter(|k| k.1 == "boot")
            .count()
            >= 2)
            .then_some(())
    })
    .await;
    core.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accessibility_turned_off_is_one_urgent_permission_revoked() {
    support::init_logging();
    let w = World::new().await;
    let tmp = tempfile::tempdir().unwrap();
    let phone = FakePhone::new();
    let (core, dev) = approved(&w, tmp.path(), phone.clone(), None).await;
    core.start().unwrap();
    eventually("the runtime running", async || {
        (core.service_status()?.phase == faro_service::Phase::Running).then_some(())
    })
    .await;
    // Granted seen first, then off: the permission flips and Kotlin also
    // reports the edge. One signal, not two.
    eventually("the permission seen granted", async || {
        core.service_status()?
            .permissions
            .screen_recording
            .is_some()
            .then_some(())
    })
    .await;
    phone.with(|s| {
        s.permission = PermissionState::Denied;
        s.tamper.push(AndroidTamper::AccessibilityDisabled);
    });
    let revoked = eventually("permission_revoked on the instance", async || {
        let ev = w.events(&dev).await;
        let t: Vec<_> = ev
            .into_iter()
            .filter(|e| e.1 == EventKind::Tamper)
            .collect();
        (!t.is_empty()).then_some(t)
    })
    .await;
    assert!(matches!(
        &revoked[0].3,
        EventBody::Tamper { signal: TamperSignal::PermissionRevoked { permission, .. }, .. }
            if permission == "accessibility_service"
    ));
    assert_eq!(revoked[0].2, Urgency::Urgent);
    let s = eventually("the status says so", async || {
        let s = core.status();
        (s.problem.as_deref() == Some("accessibility_off")).then_some(s)
    })
    .await;
    assert_eq!(s.headline, "Accessibility is off");
    // Give a duplicate the time to arrive; none does.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let c = core.clone();
    blocking(move || c.report_tamper_now(AndroidTamper::AccessibilityDisabled)).await;
    let n = w
        .events(&dev)
        .await
        .iter()
        .filter(|e| e.1 == EventKind::Tamper)
        .count();
    assert_eq!(n, 1, "one cause, one signal");
    core.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_instances_too_old_for_android() {
    support::init_logging();
    let w = World::new().await;
    // The real instance's discovery document, claiming an older version.
    let wk = w.t.get("/.well-known/faro", None).await.body;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let versions = Arc::new(std::sync::Mutex::new(rx));
    let app = axum::Router::new().route(
        "/.well-known/faro",
        axum::routing::get(move || {
            let mut wk = wk.clone();
            let v = versions.lock().unwrap().try_recv().unwrap_or_default();
            wk["server_version"] = v.into();
            async move { axum::Json(wk) }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let tmp = tempfile::tempdir().unwrap();
    let core = phone_core(tmp.path(), FakePhone::new(), None);
    let link = format!("http://{addr}/ ABCD-EFGH");
    for old in ["0.1.0-alpha.3", "0.0.9", "not a version", ""] {
        tx.send(old.to_owned()).unwrap();
        let (c, l) = (core.clone(), link.clone());
        let r = blocking(move || c.preview_enrollment(l)).await;
        match r {
            Err(FaroAndroidError::Instance(m)) => assert!(m.contains("too old"), "{m}"),
            other => panic!("{old}: {other:?}"),
        }
    }
    for ok in ["0.1.0-beta.1", "0.1.0", "1.2.3"] {
        tx.send(ok.to_owned()).unwrap();
        let (c, l) = (core.clone(), link.clone());
        let p = blocking(move || c.preview_enrollment(l)).await.unwrap();
        assert_eq!(p.member_fingerprint, None);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enroll_needs_the_preview_and_refuses_bad_input() {
    support::init_logging();
    let w = World::new().await;
    let tmp = tempfile::tempdir().unwrap();
    let core = phone_core(tmp.path(), FakePhone::new(), None);
    let link = w.link(None).await;
    let c = core.clone();
    let (no_preview, bad_link, bad_name) = blocking(move || {
        let a = c.enroll(link.clone(), DEVICE_NAME.into());
        let b = c.preview_enrollment("https://example.org/enroll".into());
        c.preview_enrollment(link.clone()).unwrap();
        let d = c.enroll(link, " padded ".into());
        (a, b, d)
    })
    .await;
    assert!(
        matches!(no_preview, Err(FaroAndroidError::Invalid(_))),
        "{no_preview:?}"
    );
    assert!(
        matches!(bad_link, Err(FaroAndroidError::Invalid(_))),
        "{bad_link:?}"
    );
    assert!(
        matches!(bad_name, Err(FaroAndroidError::Invalid(_))),
        "{bad_name:?}"
    );
    // A member key the link names but the instance doesn't have.
    let link = w.link(Some("0123456789abcdef")).await;
    let c = core.clone();
    let r = blocking(move || {
        c.preview_enrollment(link.clone())?;
        c.enroll(link, DEVICE_NAME.into())
    })
    .await;
    assert!(matches!(r, Err(FaroAndroidError::Integrity(_))), "{r:?}");
    assert!(!core.status().enrolled, "nothing is stored");
    // Enrolled once, not twice.
    let tmp2 = tempfile::tempdir().unwrap();
    let (core, _) = approved(&w, tmp2.path(), FakePhone::new(), None).await;
    let link = w.link(None).await;
    let c = core.clone();
    let again = blocking(move || {
        c.preview_enrollment(link.clone())?;
        c.enroll(link, DEVICE_NAME.into())
    })
    .await;
    assert!(
        matches!(again, Err(FaroAndroidError::State(_))),
        "{again:?}"
    );
}

/// An app built with the image model, whose model isn't in its data
/// directory (deleted, or never copied): an urgent `integrity_failure`.
/// A build without a model (the other tests) raises nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packaged_model_that_is_missing_is_an_urgent_integrity_failure() {
    support::init_logging();
    let w = World::new().await;
    let tmp = tempfile::tempdir().unwrap();
    let core = phone_core_with(tmp.path(), FakePhone::new(), None, true);
    let link = w.link(Some(&w.member_key_id())).await;
    let c = core.clone();
    let enrolled = blocking(move || {
        c.preview_enrollment(link.clone())?;
        c.enroll(link, DEVICE_NAME.into())
    })
    .await
    .expect("enrolled");
    w.endorse(&enrolled.device_id, &enrolled.device_fingerprint)
        .await;
    let c = core.clone();
    assert_eq!(
        blocking(move || c.poll_approval()).await.unwrap(),
        ApprovalState::Active
    );
    core.start().unwrap();
    let dev = enrolled.device_id.clone();
    let events = eventually("an integrity failure", async || {
        let ev = w.events(&dev).await;
        ev.iter().any(|e| e.1 == EventKind::Tamper).then_some(ev)
    })
    .await;
    let tamper = events.iter().find(|e| e.1 == EventKind::Tamper).unwrap();
    assert_eq!(tamper.2, Urgency::Urgent);
    assert!(
        matches!(
            &tamper.3,
            EventBody::Tamper {
                signal: TamperSignal::IntegrityFailure { .. },
                ..
            }
        ),
        "{:?}",
        tamper.3
    );
    core.stop();
}
