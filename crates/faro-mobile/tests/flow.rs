//! Enrollment, events, heartbeats and uploads against the real instance
//! (docs/IOS.md §10.1, §14).

mod support;

use faro_mobile::{
    Approval, BlockedHostRecord, BlockedSummaryRecord, Context, FaroError, FilterCause,
    HeartbeatState, KeyStore, KeyStoreError, MemoryKeyStore, PendingLoosening, SettingChangeRecord,
    ShieldSummaryRecord, Tamper,
};
use faro_proto::api::DeviceState;
use faro_proto::body::{EventBody, FilterOffCause, TamperSignal};
use faro_proto::EventKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use support::{approved_phone, blocking, Phone, World, DEVICE_NAME};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enrolls_waits_for_approval_then_records_and_uploads() {
    let w = World::new().await;
    let phone = Phone::new();
    let core = phone.core();

    // Preview: the instance's name and identity, and whether the link pins
    // the member key.
    let link = w.link(Some(&w.member_key_id())).await;
    let (c, l) = (core.clone(), link.clone());
    let preview = blocking(move || c.preview_enrollment(l)).await.unwrap();
    assert_eq!(preview.instance_id, w.t.instance_id().to_string());
    assert!(preview.link_names_member_key);
    assert!(!preview.name.is_empty());
    assert_eq!(
        preview.identity_fingerprint,
        faro_proto::keys::key_id(w.t.state.identity().public().as_bytes())
    );

    let c = core.clone();
    let fp = preview.identity_fingerprint.clone();
    let enrolled = blocking(move || c.enroll(link, DEVICE_NAME.into(), fp))
        .await
        .unwrap();
    assert_eq!(enrolled.member_fingerprint, w.member_key_id());

    // Pending: nothing can be recorded, a heartbeat is accepted.
    let c = core.clone();
    let (status, approval, tamper, hb) = blocking(move || {
        (
            c.status().unwrap(),
            c.poll_approval().unwrap(),
            c.record_tamper(Tamper::ScreenTimeRevoked),
            c.heartbeat(HeartbeatState::Active),
        )
    })
    .await;
    assert!(status.enrolled && !status.approved);
    assert_eq!(
        status.device_id.as_deref(),
        Some(enrolled.device_id.as_str())
    );
    assert_eq!(approval, Approval::Pending);
    assert!(matches!(tamper, Err(FaroError::NotApproved)), "{tamper:?}");
    let hb = hb.expect("heartbeats are allowed while pending");
    assert_eq!(hb.acked_through, None);

    // The member approves; the device bootstraps at the anchor.
    let anchor = w
        .endorse(&enrolled.device_id, &enrolled.device_fingerprint)
        .await;
    let c = core.clone();
    let (approval, status) =
        blocking(move || (c.poll_approval().unwrap(), c.status().unwrap())).await;
    assert_eq!(approval, Approval::Approved);
    assert!(status.approved);
    assert_eq!(status.manifest_version, Some(anchor.version));

    // Events: tamper (urgent), a settings change with a pending loosening
    // (normal), the filter's and the shields' summaries (capture-class);
    // context is kept for the report and is never an event.
    let c = core.clone();
    let seqs = blocking(move || {
        let s0 = c
            .record_tamper(Tamper::FilterOff {
                cause: FilterCause::ProfileRemoved,
            })
            .unwrap();
        let s1 = c
            .record_settings_change(
                vec![SettingChangeRecord {
                    key: "blocking.gambling".into(),
                    old_value: Some("on".into()),
                    new_value: Some("off".into()),
                }],
                Some(PendingLoosening {
                    requested_at_ms: Some(1_000),
                    takes_effect_at_ms: Some(86_401_000),
                    cancelled_at_ms: None,
                    delay_secs: Some(86_400),
                }),
            )
            .unwrap();
        let s2 = c
            .record_blocked_summary(BlockedSummaryRecord {
                bucket_start_ms: 1_800_000_000_000,
                bucket_secs: 300,
                by_category: [("adult".to_owned(), 6)].into(),
                hosts: vec![BlockedHostRecord {
                    host: "adult.example".into(),
                    category: "adult".into(),
                    count: 6,
                }],
                other_hosts: 0,
            })
            .unwrap();
        let s3 = c
            .record_shield_summary(ShieldSummaryRecord {
                bucket_start_ms: 1_800_000_000_000,
                bucket_secs: 300,
                shown: 2,
                closed: 1,
            })
            .unwrap();
        c.record_context(Context::DohDropped).unwrap();
        [s0, s1, s2, s3]
    })
    .await;
    assert_eq!(seqs, [0, 1, 2, 3]);
    let c = core.clone();
    let (pending, context) =
        blocking(move || (c.pending_events(10).unwrap(), c.context_since(0).unwrap())).await;
    let shape: Vec<_> = pending
        .iter()
        .map(|e| (e.header.kind, e.header.urgency))
        .collect();
    use faro_proto::Urgency as U;
    assert_eq!(
        shape,
        vec![
            (EventKind::Tamper, U::Urgent),
            (EventKind::SettingsChange, U::Normal),
            (EventKind::Capture, U::None),
            (EventKind::Capture, U::None),
        ]
    );
    assert_eq!(context.len(), 1);
    assert_eq!(context[0].signal, TamperSignal::DohDropped);

    // The bodies open for the member and the ally, as their web apps do.
    let open = |i: usize| faro_core::open_event_body(&pending[i], &w.member, &w.member_keys.enc);
    assert_eq!(
        open(0).unwrap(),
        EventBody::tamper(TamperSignal::FilterOff {
            cause: FilterOffCause::ProfileRemoved
        })
    );
    assert!(matches!(
        open(1).unwrap(),
        EventBody::SettingsChange {
            takes_effect_at: Some(86_401_000),
            delay_secs: Some(86_400),
            cancelled_at: None,
            ..
        }
    ));
    assert!(matches!(
        open(2).unwrap(),
        EventBody::BlockedSummary { ref hosts, .. } if hosts[0].host == "adult.example"
    ));
    assert!(matches!(
        open(3).unwrap(),
        EventBody::ShieldSummary {
            shown: 2,
            closed: 1,
            ..
        }
    ));
    for e in &pending {
        assert!(faro_core::open_event_body(e, &w.ally.id, &w.ally.keys.enc).is_ok());
    }

    assert!(core.has_pending().unwrap(), "recorded events wait");

    // Upload, then a heartbeat that names the head.
    let c = core.clone();
    let (up, hb) = blocking(move || {
        (
            c.upload_pending().unwrap(),
            c.heartbeat(HeartbeatState::Sleeping).unwrap(),
        )
    })
    .await;
    assert_eq!(up.acked_through, Some(3));
    assert_eq!(up.pending_events, 0);
    assert!(
        !core.has_pending().unwrap(),
        "nothing waits after the upload"
    );
    assert!(up.warnings.is_empty(), "{:?}", up.warnings);
    assert_eq!(hb.acked_through, Some(3));
    assert_eq!(w.stored_seqs(&enrolled.device_id).await, vec![0, 1, 2, 3]);
    let kinds = w.alert_kinds().await;
    assert!(
        !kinds
            .iter()
            .any(|k| k == "chain_gap" || k == "invalid_signature"),
        "{kinds:?}"
    );
    // The instance holds the heartbeat's state and the chain head it named.
    let (state, reported): (String, i64) =
        sqlx::query_as("SELECT last_state, reported_last_seq FROM devices WHERE id = $1")
            .bind(&enrolled.device_id)
            .fetch_one(w.t.state.db().pool())
            .await
            .unwrap();
    assert_eq!(state, DeviceState::Sleeping.as_str());
    assert_eq!(reported, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_a_member_key_the_link_does_not_name() {
    let w = World::new().await;
    let phone = Phone::new();
    let core = phone.core();
    let link = w.link(Some("0123456789abcdef")).await;
    let c = core.clone();
    let r = blocking(move || {
        let p = c.preview_enrollment(link.clone())?;
        c.enroll(link, DEVICE_NAME.into(), p.identity_fingerprint)
    })
    .await;
    assert!(matches!(r, Err(FaroError::Integrity { .. })), "{r:?}");
    let c = core.clone();
    let status = blocking(move || c.status().unwrap()).await;
    assert!(!status.enrolled, "nothing is stored");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_an_instance_identity_other_than_the_one_shown() {
    let w = World::new().await;
    let phone = Phone::new();
    let core = phone.core();
    let link = w.link(None).await;
    let c = core.clone();
    let r = blocking(move || c.enroll(link, DEVICE_NAME.into(), "00".repeat(8))).await;
    assert!(matches!(r, Err(FaroError::Integrity { .. })), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_bad_links_names_and_a_second_enrollment() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let link = w.link(None).await;
    let c = core.clone();
    let (bad_link, bad_name, again) = blocking(move || {
        (
            c.preview_enrollment("https://example.org/enroll".into()),
            c.enroll(link.clone(), " padded ".into(), String::new()),
            c.enroll(link, DEVICE_NAME.into(), String::new()),
        )
    })
    .await;
    assert!(matches!(bad_link, Err(FaroError::InvalidLink { .. })));
    assert!(matches!(bad_name, Err(FaroError::InvalidArgument { .. })));
    assert!(matches!(again, Err(FaroError::AlreadyEnrolled { .. })));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_bad_settings_and_summaries() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let c = core.clone();
    let summary = |host: &str, category: &str| BlockedSummaryRecord {
        bucket_start_ms: 0,
        bucket_secs: 300,
        by_category: Default::default(),
        hosts: vec![BlockedHostRecord {
            host: host.into(),
            category: category.into(),
            count: 1,
        }],
        other_hosts: 0,
    };
    let results = blocking(move || {
        vec![
            c.record_settings_change(vec![], None),
            c.record_settings_change(
                vec![SettingChangeRecord {
                    key: "has space".into(),
                    old_value: None,
                    new_value: None,
                }],
                None,
            ),
            c.record_settings_change(
                vec![SettingChangeRecord {
                    key: "k".into(),
                    old_value: Some("a\nb".into()),
                    new_value: None,
                }],
                None,
            ),
            // A summary carries host names only: no paths, ports or URLs.
            c.record_blocked_summary(summary("adult.example/path", "adult")),
            c.record_blocked_summary(summary("adult.example:443", "adult")),
            c.record_blocked_summary(summary("https://adult.example", "adult")),
            c.record_blocked_summary(summary("Adult.Example", "adult")),
            c.record_blocked_summary(summary("adult.example", "Adult Sites")),
            c.record_shield_summary(ShieldSummaryRecord {
                bucket_start_ms: 0,
                bucket_secs: 0,
                shown: 1,
                closed: 0,
            }),
        ]
    })
    .await;
    for r in results {
        assert!(matches!(r, Err(FaroError::InvalidArgument { .. })), "{r:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ally_removed_on_the_instance_is_dropped_at_the_next_upload() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let c = core.clone();
    blocking(move || {
        c.record_tamper(Tamper::IntegrityFailure {
            component: "test".into(),
        })
        .unwrap()
    })
    .await;
    let v3 = w.remove_ally().await;
    let c = core.clone();
    let (up, ev) = blocking(move || {
        let up = c.upload_pending().unwrap();
        c.record_tamper(Tamper::IntegrityFailure {
            component: "test".into(),
        })
        .unwrap();
        (up, c.pending_events(10).unwrap())
    })
    .await;
    assert_eq!(up.manifest_version, Some(v3.body.version));
    assert_eq!(ev.len(), 1);
    let item = ev[0].body.as_ref().expect("sealed body");
    assert!(item.envelopes.iter().all(|e| e.recipient != w.ally.id));
    assert!(faro_core::open_event_body(&ev[0], &w.ally.id, &w.ally.keys.enc).is_err());
    assert!(faro_core::open_event_body(&ev[0], &w.member, &w.member_keys.enc).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_removed_device_is_retired() {
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
    let hb = blocking(move || c.heartbeat(HeartbeatState::Active)).await;
    assert!(matches!(hb, Err(FaroError::Retired { .. })), "{hb:?}");
}

/// A key store that can be locked, as the Keychain is before the first
/// unlock after a reboot.
struct Lockable {
    inner: Arc<MemoryKeyStore>,
    locked: AtomicBool,
}

impl KeyStore for Lockable {
    fn load(&self, name: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        if self.locked.load(Ordering::SeqCst) {
            return Err(KeyStoreError::Locked {
                message: "before first unlock".into(),
            });
        }
        self.inner.load(name)
    }
    fn store(&self, name: String, value: Vec<u8>) -> Result<(), KeyStoreError> {
        self.inner.store(name, value)
    }
    fn delete(&self, name: String) -> Result<(), KeyStoreError> {
        self.inner.delete(name)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_locked_key_store_signs_nothing_until_unlocked() {
    let w = World::new().await;
    let keys = Arc::new(Lockable {
        inner: MemoryKeyStore::new(),
        locked: AtomicBool::new(false),
    });
    let phone = Phone::with_keys(keys.clone());
    let (core, _) = approved_phone(&w, &phone).await;
    keys.locked.store(true, Ordering::SeqCst);
    let tamper = Tamper::IntegrityFailure {
        component: "test".into(),
    };
    let (c, t) = (core.clone(), tamper.clone());
    let (locked, status) = blocking(move || (c.record_tamper(t), c.status().unwrap())).await;
    assert!(
        matches!(locked, Err(FaroError::KeysLocked { .. })),
        "{locked:?}"
    );
    assert_eq!(status.next_seq, 0, "nothing was appended");
    keys.locked.store(false, Ordering::SeqCst);
    let c = core.clone();
    assert_eq!(blocking(move || c.record_tamper(tamper)).await.unwrap(), 0);
}
