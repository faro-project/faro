//! Enrollment, events, heartbeats and uploads against the real instance
//! (docs/IOS.md §10.1, §14).

mod support;

use faro_mobile::{
    Approval, Context, FaroError, HeartbeatState, KeyStore, KeyStoreError, MemoryKeyStore,
    SettingChangeRecord, Tamper,
};
use faro_proto::api::DeviceState;
use faro_proto::body::{EventBody, TamperSignal};
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
            c.record_tamper(Tamper::PermissionRevoked {
                permission: "screen_time".into(),
                never_granted: false,
            }),
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

    // Events: tamper (urgent), a settings change (normal); context is kept
    // for the report and is never an event.
    let c = core.clone();
    let (s0, s1) = blocking(move || {
        let s0 = c
            .record_tamper(Tamper::PermissionRevoked {
                permission: "screen_time".into(),
                never_granted: false,
            })
            .unwrap();
        let s1 = c
            .record_settings_change(vec![SettingChangeRecord {
                key: "blocking.gambling".into(),
                old_value: Some("on".into()),
                new_value: Some("off".into()),
            }])
            .unwrap();
        c.record_context(Context::VpnActive).unwrap();
        (s0, s1)
    })
    .await;
    assert_eq!((s0, s1), (0, 1));
    let c = core.clone();
    let (pending, context) =
        blocking(move || (c.pending_events(10).unwrap(), c.context_since(0).unwrap())).await;
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].header.kind, EventKind::Tamper);
    assert_eq!(pending[0].header.urgency, faro_proto::Urgency::Urgent);
    assert_eq!(pending[1].header.kind, EventKind::SettingsChange);
    assert_eq!(context.len(), 1);
    assert_eq!(context[0].signal, TamperSignal::VpnActive);

    // The bodies open for the member and the ally, as their web apps do.
    let body = faro_core::open_event_body(&pending[0], &w.member, &w.member_keys.enc).unwrap();
    assert!(matches!(
        body,
        EventBody::Tamper {
            signal: TamperSignal::PermissionRevoked { .. },
            ..
        }
    ));
    assert!(faro_core::open_event_body(&pending[1], &w.ally.id, &w.ally.keys.enc).is_ok());

    // Upload, then a heartbeat that names the head.
    let c = core.clone();
    let (up, hb) = blocking(move || {
        (
            c.upload_pending().unwrap(),
            c.heartbeat(HeartbeatState::Sleeping).unwrap(),
        )
    })
    .await;
    assert_eq!(up.acked_through, Some(1));
    assert_eq!(up.pending_events, 0);
    assert!(up.warnings.is_empty(), "{:?}", up.warnings);
    assert_eq!(hb.acked_through, Some(1));
    assert_eq!(w.stored_seqs(&enrolled.device_id).await, vec![0, 1]);
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
    assert_eq!(reported, 1);
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
async fn rejects_context_as_tamper_and_bad_settings() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let c = core.clone();
    let (empty, bad_key, control) = blocking(move || {
        (
            c.record_settings_change(vec![]),
            c.record_settings_change(vec![SettingChangeRecord {
                key: "has space".into(),
                old_value: None,
                new_value: None,
            }]),
            c.record_settings_change(vec![SettingChangeRecord {
                key: "k".into(),
                old_value: Some("a\nb".into()),
                new_value: None,
            }]),
        )
    })
    .await;
    for r in [empty, bad_key, control] {
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
