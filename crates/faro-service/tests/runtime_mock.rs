//! The whole runtime, in-process, against a small mock instance.
//!
//! The mock is deliberately strict where the real instance is: it verifies
//! every device request signature, every event's chain link and signature,
//! and heartbeat signatures and chain positions. It is *not* faro-server;
//! the end-to-end test against the real in-process server lives elsewhere.
//! What this test pins down is the device side: enrollment, waiting for and
//! verifying the endorsement, bootstrapping from the anchor, capture →
//! detection → flag events sealed to exactly the manifest's recipients,
//! tamper routing, manifest refresh (advance and refusal), reports,
//! heartbeats, and graceful shutdown.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use faro_core::clock::Clock;
use faro_core::{open_event_body, open_report, ManualClock};
use faro_crypto::{ChainHead, EncryptionKeypair, SigningKey};
use faro_detect::{ImageScores, ScriptedClassifier};
use faro_ipc::status::{ArtifactSource, CaptureState, ServicePhase};
use faro_ipc::WirePermissionState;
use faro_platform::synthetic::Script;
use faro_proto::api::{
    auth_headers, request_signing_bytes, ApiError, DeviceState, EnrollRequest, EnrollResponse,
    EventResult, EventsBatchRequest, EventsBatchResponse, HeartbeatResponse, SignedHeartbeat,
    SignedRecipientManifest, WellKnown,
};
use faro_proto::body::{EventBody, TamperSignal};
use faro_proto::keys::{DeviceEndorsement, ManifestAlly, RecipientManifest, Signed};
use faro_proto::report::ReportUpload;
use faro_proto::{
    DeviceId, EventKind, InstanceId, SignPublicKey, Signature, SignedEvent, Urgency, UserId,
};
use faro_service::client::{ClientOptions, DeviceSelf, ReportAccepted};
use faro_service::enroll::{self, EnrollParams};
use faro_service::link::{parse_instance_url, EnrollCode};
use faro_service::state::StateDir;
use faro_service::{Config, InProcessFrameSource, Phase, Service, ServiceStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOKEN: &str = "device-token-0123456789abcdef";

struct Mock {
    instance_id: InstanceId,
    identity: SignPublicKey,
    member_id: UserId,
    member_sign: SignPublicKey,
    device_id: DeviceId,
    device_key: Option<SignPublicKey>,
    endorsement: Option<Signed<DeviceEndorsement>>,
    manifest: SignedRecipientManifest,
    head: Option<ChainHead>,
    events: Vec<SignedEvent>,
    heartbeats: Vec<SignedHeartbeat>,
    reports: Vec<ReportUpload>,
    auth_failures: Vec<String>,
}

type Shared = Arc<Mutex<Mock>>;

fn api_err(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ApiError {
            error: code.into(),
            message: code.into(),
        }),
    )
        .into_response()
}

/// Verify device auth exactly as faro-server's `device_auth` does.
fn authenticate(
    m: &mut Mock,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> bool {
    let h = |n: &str| {
        headers
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let ok = (|| {
        let token = h("authorization")?.strip_prefix("Bearer ")?.to_owned();
        let dev = h(auth_headers::DEVICE)?;
        let ts: i64 = h(auth_headers::TIMESTAMP)?.parse().ok()?;
        let sig = Signature::from_b64(&h(auth_headers::SIGNATURE)?)?;
        let pk = m.device_key?;
        if token != TOKEN || dev != m.device_id.as_str() {
            return None;
        }
        let pq = uri.path_and_query().map(|p| p.as_str().to_owned())?;
        let msg = request_signing_bytes(method.as_str(), &pq, &m.device_id, ts, body);
        faro_crypto::verify(&pk, &msg, &sig).ok()
    })()
    .is_some();
    if !ok {
        m.auth_failures.push(format!("{method} {uri}"));
    }
    ok
}

async fn well_known(State(s): State<Shared>) -> Json<WellKnown> {
    let m = s.lock().unwrap();
    Json(WellKnown {
        instance_id: m.instance_id.clone(),
        name: "Mock Instance".into(),
        identity_pubkey: m.identity,
        server_version: "0.0.0".into(),
        min_client_version: "0.1.0".into(),
        protocol: 1,
    })
}

async fn do_enroll(State(s): State<Shared>, Json(req): Json<EnrollRequest>) -> Response {
    let mut m = s.lock().unwrap();
    if req.enroll_code != "ABCD-1234" {
        return api_err(StatusCode::UNAUTHORIZED, "invalid_enroll_code");
    }
    m.device_key = Some(req.sign_pubkey);
    (
        StatusCode::CREATED,
        Json(EnrollResponse {
            instance_id: m.instance_id.clone(),
            device_id: m.device_id.clone(),
            device_token: TOKEN.into(),
            member_id: m.member_id.clone(),
            member_sign_pubkey: m.member_sign,
        }),
    )
        .into_response()
}

async fn device_self(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut m = s.lock().unwrap();
    if !authenticate(&mut m, &method, &uri, &headers, &body) {
        return api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    Json(DeviceSelf {
        device_id: m.device_id.clone(),
        member_id: m.member_id.clone(),
        status: if m.endorsement.is_some() {
            "active"
        } else {
            "pending_endorsement"
        }
        .into(),
        min_manifest: m.endorsement.as_ref().map(|e| e.body.min_manifest),
        endorsement: m.endorsement.clone(),
        acked_through: m.head.and_then(|h| h.next_seq.checked_sub(1)),
    })
    .into_response()
}

async fn manifest(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut m = s.lock().unwrap();
    if !authenticate(&mut m, &method, &uri, &headers, &body) {
        return api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if uri.path() != format!("/v1/members/{}/recipient-manifest", m.member_id) {
        return api_err(StatusCode::NOT_FOUND, "not_found");
    }
    Json(m.manifest.clone()).into_response()
}

async fn events(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut m = s.lock().unwrap();
    if !authenticate(&mut m, &method, &uri, &headers, &body) {
        return api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if m.endorsement.is_none() {
        return api_err(StatusCode::FORBIDDEN, "device_pending_endorsement");
    }
    let req: EventsBatchRequest = serde_json::from_slice(&body).unwrap();
    let pk = m.device_key.unwrap();
    let mut head = m
        .head
        .unwrap_or_else(|| ChainHead::genesis(&m.instance_id, &m.device_id));
    let mut results = Vec::new();
    for ev in req.events {
        let seq = ev.header.seq;
        match faro_crypto::verify_next(&head, &m.instance_id, &m.device_id, &pk, &ev, true) {
            Ok(faro_crypto::Link::Contiguous) => {
                head.advance(&ev.header);
                m.events.push(ev);
                results.push(EventResult::Accepted { seq });
            }
            Ok(link) => panic!("device produced a chain gap: {link:?}"),
            Err(faro_crypto::ChainError::Behind { .. }) => {
                results.push(EventResult::Duplicate { seq })
            }
            Err(e) => panic!("invalid event from device: {e}"),
        }
    }
    m.head = Some(head);
    Json(EventsBatchResponse {
        results,
        acked_through: head.next_seq.checked_sub(1),
    })
    .into_response()
}

async fn heartbeat(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut m = s.lock().unwrap();
    if !authenticate(&mut m, &method, &uri, &headers, &body) {
        return api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let hb: SignedHeartbeat = serde_json::from_slice(&body).unwrap();
    faro_crypto::verify_item(&m.device_key.unwrap(), &hb.heartbeat, &hb.sig)
        .expect("heartbeat signature");
    // PROTOCOL.md §7: last_hash is the chain hash of the event at last_seq.
    if let (Some(seq), Some(hash)) = (hb.heartbeat.last_seq, hb.heartbeat.last_hash) {
        if let Some(ev) = m.events.iter().find(|e| e.header.seq == seq) {
            assert_eq!(
                ev.header.chain_hash(),
                hash,
                "heartbeat names a different chain"
            );
        }
    }
    let acked = m.head.and_then(|h| h.next_seq.checked_sub(1));
    m.heartbeats.push(hb);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    Json(HeartbeatResponse {
        server_time_ms: now,
        next_in_secs: 300,
        acked_through: acked,
    })
    .into_response()
}

async fn reports(
    State(s): State<Shared>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut m = s.lock().unwrap();
    if !authenticate(&mut m, &method, &uri, &headers, &body) {
        return api_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let up: ReportUpload = serde_json::from_slice(&body).unwrap();
    m.reports.push(up);
    (
        StatusCode::CREATED,
        Json(ReportAccepted {
            report_id: format!("rep_{}", m.reports.len()),
            duplicate: false,
        }),
    )
        .into_response()
}

async fn wait_for(
    handle: &faro_service::ServiceHandle,
    what: &str,
    pred: impl FnMut(&ServiceStatus) -> bool,
) -> ServiceStatus {
    match tokio::time::timeout(Duration::from_secs(30), handle.wait_for(pred)).await {
        Ok(s) => s,
        Err(_) => panic!(
            "timed out waiting for {what}; status: {:?}",
            handle.status()
        ),
    }
}

fn manifest_doc(
    member: &SigningKey,
    inst: &InstanceId,
    mid: &UserId,
    version: u64,
    member_enc: &EncryptionKeypair,
    allies: &[(&UserId, &EncryptionKeypair)],
) -> SignedRecipientManifest {
    member.endorse(RecipientManifest {
        format: faro_proto::keys::MANIFEST_FORMAT_V2,
        instance_id: inst.clone(),
        member_id: mid.clone(),
        version,
        prev_hash: None,
        issued_at_ms: 1_000 + version as i64,
        member_enc_pubkey: member_enc.public(),
        allies: allies
            .iter()
            .map(|(id, k)| ManifestAlly {
                ally_id: (*id).clone(),
                enc_pubkey: k.public(),
                name: Some(format!("Ally {id}")),
            })
            .collect(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_lifecycle_against_mock_instance() {
    if std::env::var_os("FARO_TEST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("faro_service=debug,faro_core=debug")
            .with_test_writer()
            .try_init();
    }
    let instance_id = InstanceId::new("inst_mock");
    let member_id = UserId::new("usr_member");
    let ally_id = UserId::new("usr_ally");
    let member = SigningKey::generate();
    let member_enc = EncryptionKeypair::generate();
    let ally_enc = EncryptionKeypair::generate();
    let v1 = manifest_doc(
        &member,
        &instance_id,
        &member_id,
        1,
        &member_enc,
        &[(&ally_id, &ally_enc)],
    );

    let shared: Shared = Arc::new(Mutex::new(Mock {
        instance_id: instance_id.clone(),
        identity: SigningKey::generate().public(),
        member_id: member_id.clone(),
        member_sign: member.public(),
        device_id: DeviceId::new("dev_mock"),
        device_key: None,
        endorsement: None,
        manifest: v1.clone(),
        head: None,
        events: Vec::new(),
        heartbeats: Vec::new(),
        reports: Vec::new(),
        auth_failures: Vec::new(),
    }));
    let app = Router::new()
        .route("/.well-known/faro", get(well_known))
        .route("/v1/devices/enroll", post(do_enroll))
        .route("/v1/devices/self", get(device_self))
        .route("/v1/members/{id}/recipient-manifest", get(manifest))
        .route("/v1/events:batch", post(events))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/reports", post(reports))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = parse_instance_url(&format!("http://{addr}")).unwrap();

    // ---- enroll ---------------------------------------------------------
    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    let dir = StateDir::open(&state_dir).unwrap();
    let wall0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let clock = ManualClock::new(wall0, 5_000_000);
    let params = EnrollParams {
        instance: base.clone(),
        code: EnrollCode::parse("abcd 1234").unwrap(),
        device_name: "Test Laptop".into(),
        client: ClientOptions::default(),
        // No `m` in the link: the CLI would show the safety code instead.
        member_key: None,
    };
    let mut shown = None;
    let enrollment = enroll::enroll(&dir, Arc::new(clock.clone()), &params, |info| {
        shown = Some(info.name.clone());
        true
    })
    .await
    .unwrap();
    assert_eq!(shown.as_deref(), Some("Mock Instance"));
    assert_eq!(enrollment.member_sign_pubkey, member.public());
    // A second enrollment into the same state directory is refused.
    assert!(
        enroll::enroll(&dir, Arc::new(clock.clone()), &params, |_| true)
            .await
            .is_err()
    );

    // ---- run, pending endorsement -----------------------------------------
    let mut config = Config {
        state_dir: state_dir.clone(),
        ..Config::default()
    };
    config.network.endorsement_poll_secs = 1;
    config.network.upload_interval_secs = 1;
    let script = Script::new();
    let classifier = ScriptedClassifier::new(ImageScores::new([("explicit", 0.95f32)]).unwrap());
    let service = Service::builder(config)
        .clock(Arc::new(clock.clone()))
        .frame_source(InProcessFrameSource::new(
            script.platform(),
            Duration::from_millis(10),
        ))
        .classifier(Box::new(classifier))
        .tick_interval(Duration::from_millis(10))
        .scheduler_seed(7)
        .build()
        .unwrap();
    let handle = service.spawn();
    wait_for(&handle, "awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    // Pending devices heartbeat (PROTOCOL §7) but seal nothing.
    handle.heartbeat_now();
    wait_for(&handle, "pending heartbeat", |s| s.heartbeats_sent >= 1).await;
    assert!(shared.lock().unwrap().events.is_empty());

    // Time passes 40x faster than real time from here on.
    let ticker = {
        let clock = clock.clone();
        tokio::spawn(async move {
            loop {
                clock.advance(200);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };

    // ---- the member endorses ----------------------------------------------
    {
        let mut m = shared.lock().unwrap();
        let e = DeviceEndorsement {
            instance_id: instance_id.clone(),
            member_id: member_id.clone(),
            device_id: m.device_id.clone(),
            device_sign_pubkey: m.device_key.unwrap(),
            endorsed_at_ms: wall0,
            min_manifest: v1.body.reference(),
        };
        m.endorsement = Some(member.endorse(e));
    }
    wait_for(&handle, "running", |s| s.phase == Phase::Running).await;
    let st = wait_for(&handle, "a flag uploaded", |s| {
        s.flags >= 1 && s.acked_through.is_some_and(|a| Some(a) == s.last_seq)
    })
    .await;
    assert_eq!(st.manifest, Some(v1.body.reference()));
    assert!(
        dir.endorsement().unwrap().is_some(),
        "verified endorsement persisted"
    );

    {
        let m = shared.lock().unwrap();
        assert_eq!(m.events[0].header.kind, EventKind::Boot);
        let flag = m
            .events
            .iter()
            .find(|e| e.header.kind == EventKind::Flag)
            .expect("a flag event");
        assert_eq!(
            flag.header.urgency,
            Urgency::Urgent,
            "high flags are urgent"
        );
        // Sealed to the member and exactly the manifest's ally.
        for (who, key) in [(&ally_id, &ally_enc), (&member_id, &member_enc)] {
            match open_event_body(flag, who, key).unwrap() {
                EventBody::Flag(f) => {
                    assert_eq!(f.rating, faro_proto::body::Rating::High);
                    let t = f.thumbnail.expect("blurred thumbnail on a high flag");
                    assert_eq!(t.transform, faro_detect::THUMBNAIL_TRANSFORM);
                }
                other => panic!("unexpected body {other:?}"),
            }
        }
        assert_eq!(flag.body.as_ref().unwrap().envelopes.len(), 2);
        assert!(m.auth_failures.is_empty(), "{:?}", m.auth_failures);
    }

    // ---- status ----------------------------------------------------------
    let st = wait_for(&handle, "capture status", |s| {
        s.capture.last_success_ms.is_some() && s.capture.state == CaptureState::Active
    })
    .await;
    assert_eq!(st.capture.consecutive_failures, 0);
    assert!(st.capture.last_attempt_ms.is_some());
    assert_eq!(st.session_list.len(), 1, "{:?}", st.session_list);
    let session = &st.session_list[0];
    assert!(session.agent_connected && session.capture_target && session.at_screen);
    assert!(session
        .agent_version
        .as_deref()
        .is_some_and(|v| v.starts_with("in-process/")));
    assert_eq!(
        st.permissions.screen_recording,
        Some(WirePermissionState::Granted)
    );
    let model = st.detection.model.as_ref().expect("a model in the status");
    assert_eq!(model.source, ArtifactSource::Packaged);
    assert!(!st.updates.enabled, "no root of trust in this test");
    // The running service writes it to the state directory, where `status`
    // reads it.
    let view = wait_for_status_file(&state_dir, |v| {
        v.service_running
            && v.service
                .as_ref()
                .is_some_and(|r| r.capture.last_success_ms.is_some())
    })
    .await;
    let report = view.service.as_ref().unwrap();
    assert_eq!(report.phase, ServicePhase::Running);
    assert_eq!(report.pid, std::process::id());
    let text = view.text(clock.wall_ms());
    assert!(text.contains("Service:      running since"), "{text}");
    assert!(text.contains("Capture:      active"), "{text}");
    assert!(text.contains("Screen Recording granted"), "{text}");

    // ---- tamper vs context ------------------------------------------------
    script.with(|s| {
        s.tamper.push(TamperSignal::PermissionRevoked {
            permission: "screen_recording".into(),
            never_granted: false,
        });
        s.tamper.push(TamperSignal::VpnActive);
    });
    let st = wait_for(&handle, "tamper event", |s| s.tamper_events >= 1).await;
    assert_eq!(st.tamper_events, 1, "VPN is context, not tamper");
    handle.upload_now();
    wait_for(&handle, "tamper uploaded", |s| {
        s.acked_through.is_some() && s.acked_through >= s.last_seq
    })
    .await;

    // ---- manifest: removal accepted, rollback refused ---------------------
    let v2 = manifest_doc(&member, &instance_id, &member_id, 2, &member_enc, &[]);
    shared.lock().unwrap().manifest = v2.clone();
    handle.refresh_manifest_now();
    wait_for(&handle, "manifest v2", |s| {
        s.manifest == Some(v2.body.reference())
    })
    .await;
    let seq_after_removal = handle.status().last_seq.unwrap();
    // The instance now re-serves the pre-removal manifest.
    shared.lock().unwrap().manifest = v1.clone();
    handle.refresh_manifest_now();
    let st = wait_for(&handle, "rollback refused", |s| {
        s.manifest_warning.is_some()
    })
    .await;
    assert!(st.manifest_warning.unwrap().contains("rollback"));
    assert_eq!(handle.status().manifest, Some(v2.body.reference()));
    // New events are sealed to v2: the removed ally can no longer read them.
    script.with(|s| s.tamper.push(TamperSignal::WaylandTokenLost));
    wait_for(&handle, "second tamper", |s| s.tamper_events >= 2).await;
    handle.upload_now();
    let target = handle.status().last_seq;
    wait_for(&handle, "uploaded after removal", |s| {
        s.acked_through.is_some() && s.acked_through >= target
    })
    .await;
    {
        let m = shared.lock().unwrap();
        let after: Vec<_> = m
            .events
            .iter()
            .filter(|e| e.header.seq > seq_after_removal && e.header.kind == EventKind::Tamper)
            .collect();
        assert!(!after.is_empty());
        for ev in after {
            assert!(
                open_event_body(ev, &ally_id, &ally_enc).is_err(),
                "removed ally can't read"
            );
            assert!(open_event_body(ev, &member_id, &member_enc).is_ok());
        }
    }

    // ---- report -----------------------------------------------------------
    assert!(handle.close_report().await);
    wait_for(&handle, "report uploaded", |s| s.reports_uploaded >= 1).await;
    {
        let m = shared.lock().unwrap();
        let pk = m.device_key.unwrap();
        let r = open_report(&m.reports[0], &pk, &member_id, &member_enc).unwrap();
        assert!(r.counts.high >= 1);
        assert!(!r.flagged.is_empty());
        assert_eq!(r.health.context.len(), 1, "VPN listed as context");
        assert!(!r.health.tamper.is_empty());
        assert_eq!(r.device_name, "Test Laptop");
    }

    // ---- graceful shutdown ------------------------------------------------
    // Make sure the period since the report above is non-empty (an empty
    // period is skipped, not reported).
    ticker.abort();
    clock.advance(1_000);
    handle.shutdown().await.unwrap();
    let m = shared.lock().unwrap();
    assert_eq!(m.events.last().unwrap().header.kind, EventKind::Shutdown);
    assert_eq!(
        m.heartbeats.last().unwrap().heartbeat.state,
        DeviceState::ShuttingDown
    );
    assert_eq!(m.reports.len(), 2, "partial report at shutdown");
    assert!(m.auth_failures.is_empty(), "{:?}", m.auth_failures);
    // The last status says it stopped.
    let view =
        faro_service::status_view::gather(&status_config(&state_dir), clock.wall_ms()).unwrap();
    assert!(!view.service_running);
    let report = view.service.unwrap();
    assert_eq!(report.phase, ServicePhase::Stopped);
    assert_eq!(report.capture.state, CaptureState::Stopped);
}

/// Break (or repair) the service's outbox the way a full volume does: every
/// event insert fails, reads still work.
fn set_outbox_full(state_dir: &std::path::Path, full: bool) {
    let db = rusqlite::Connection::open(state_dir.join(faro_core::outbox::OUTBOX_FILE)).unwrap();
    db.busy_timeout(Duration::from_secs(10)).unwrap();
    db.execute_batch(if full {
        "CREATE TRIGGER IF NOT EXISTS test_full BEFORE INSERT ON events \
         BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;"
    } else {
        "DROP TRIGGER IF EXISTS test_full;"
    })
    .unwrap();
}

/// A failed outbox commit must not lose a flag or a tamper event (#188): they
/// wait in memory and commit once the outbox works again, and while it keeps
/// failing the service stops claiming to be alive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn events_survive_a_failing_outbox() {
    let instance_id = InstanceId::new("inst_mock");
    let member_id = UserId::new("usr_member");
    let member = SigningKey::generate();
    let member_enc = EncryptionKeypair::generate();
    let v1 = manifest_doc(&member, &instance_id, &member_id, 1, &member_enc, &[]);
    let shared: Shared = Arc::new(Mutex::new(Mock {
        instance_id: instance_id.clone(),
        identity: SigningKey::generate().public(),
        member_id: member_id.clone(),
        member_sign: member.public(),
        device_id: DeviceId::new("dev_mock"),
        device_key: None,
        endorsement: None,
        manifest: v1.clone(),
        head: None,
        events: Vec::new(),
        heartbeats: Vec::new(),
        reports: Vec::new(),
        auth_failures: Vec::new(),
    }));
    let app = Router::new()
        .route("/.well-known/faro", get(well_known))
        .route("/v1/devices/enroll", post(do_enroll))
        .route("/v1/devices/self", get(device_self))
        .route("/v1/members/{id}/recipient-manifest", get(manifest))
        .route("/v1/events:batch", post(events))
        .route("/v1/heartbeat", post(heartbeat))
        .route("/v1/reports", post(reports))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = parse_instance_url(&format!("http://{addr}")).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let state_dir = tmp.path().join("state");
    let dir = StateDir::open(&state_dir).unwrap();
    let wall0 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let clock = ManualClock::new(wall0, 5_000_000);
    let params = EnrollParams {
        instance: base.clone(),
        code: EnrollCode::parse("abcd 1234").unwrap(),
        device_name: "Test Laptop".into(),
        client: ClientOptions::default(),
        member_key: None,
    };
    enroll::enroll(&dir, Arc::new(clock.clone()), &params, |_| true)
        .await
        .unwrap();
    let mut config = Config {
        state_dir: state_dir.clone(),
        ..Config::default()
    };
    config.network.endorsement_poll_secs = 1;
    config.network.upload_interval_secs = 1;
    let script = Script::new();
    let classifier = ScriptedClassifier::new(ImageScores::new([("explicit", 0.95f32)]).unwrap());
    let service = Service::builder(config)
        .clock(Arc::new(clock.clone()))
        .frame_source(InProcessFrameSource::new(
            script.platform(),
            Duration::from_millis(10),
        ))
        .classifier(Box::new(classifier))
        .tick_interval(Duration::from_millis(10))
        .scheduler_seed(7)
        .build()
        .unwrap();
    let handle = service.spawn();
    wait_for(&handle, "awaiting endorsement", |s| {
        s.phase == Phase::AwaitingEndorsement
    })
    .await;
    {
        let mut m = shared.lock().unwrap();
        let e = DeviceEndorsement {
            instance_id: instance_id.clone(),
            member_id: member_id.clone(),
            device_id: m.device_id.clone(),
            device_sign_pubkey: m.device_key.unwrap(),
            endorsed_at_ms: wall0,
            min_manifest: v1.body.reference(),
        };
        m.endorsement = Some(member.endorse(e));
    }
    wait_for(&handle, "running", |s| s.phase == Phase::Running).await;
    // The boot event has committed; from here the volume is "full".
    wait_for(&handle, "boot committed", |s| s.last_seq.is_some()).await;
    set_outbox_full(&state_dir, true);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = handle.status();

    // A tamper event and (as time passes) flags, none of which can commit.
    script.with(|s| s.tamper.push(TamperSignal::WaylandTokenLost));
    let ticker = {
        let clock = clock.clone();
        tokio::spawn(async move {
            loop {
                clock.advance(200);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    wait_for(&handle, "tamper signalled", |s| s.tamper_events >= 1).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let st = handle.status();
    assert_eq!(st.last_seq, before.last_seq, "nothing could commit");
    assert_eq!(st.flags, before.flags);

    // Failing for a long time: heartbeats stop, so the instance's liveness
    // monitor sees silence instead of an `active` device.
    ticker.abort();
    clock.advance(16 * 60 * 1000);
    wait_for(&handle, "commit failure shown", |s| s.commit_failing).await;
    let sent = handle.status().heartbeats_sent;
    handle.heartbeat_now();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(handle.status().heartbeats_sent, sent, "no heartbeat");

    // Space is freed: the queued events commit, in order, and upload.
    set_outbox_full(&state_dir, false);
    wait_for(&handle, "queued events committed", |s| {
        !s.commit_failing && s.last_seq > before.last_seq
    })
    .await;
    handle.heartbeat_now();
    wait_for(&handle, "heartbeats resume", |s| s.heartbeats_sent > sent).await;
    handle.upload_now();
    wait_for(&handle, "uploaded", |s| {
        s.acked_through.is_some() && s.acked_through == s.last_seq
    })
    .await;
    let m = shared.lock().unwrap();
    let tamper = m
        .events
        .iter()
        .filter(|e| e.header.kind == EventKind::Tamper)
        .find_map(
            |e| match open_event_body(e, &member_id, &member_enc).unwrap() {
                EventBody::Tamper { signal, .. } => Some(signal),
                _ => None,
            },
        );
    assert_eq!(tamper, Some(TamperSignal::WaylandTokenLost));
    assert!(m.auth_failures.is_empty(), "{:?}", m.auth_failures);
    drop(m);
    handle.shutdown().await.unwrap();
}

fn status_config(state_dir: &std::path::Path) -> Config {
    Config {
        state_dir: state_dir.to_owned(),
        ..Config::default()
    }
}

async fn wait_for_status_file(
    state_dir: &std::path::Path,
    mut pred: impl FnMut(&faro_service::status_view::StatusView) -> bool,
) -> faro_service::status_view::StatusView {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        // The service's clock runs ahead of real time here, so its reports
        // always look fresh.
        let view = faro_service::status_view::gather(&status_config(state_dir), 0).unwrap();
        if pred(&view) {
            return view;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the status file: {view:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
