//! `uplink::drain_events` against a stub instance: what is deleted from the
//! outbox after a permanent refusal, a `retry_later`, a `413` and a `429`.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use faro_client::client::{ClientOptions, DeviceCredentials, InstanceClient};
use faro_client::link::parse_instance_url;
use faro_client::uplink::{self, EventsDrained, OutboxAccess, RefusedEvent, UplinkError};
use faro_core::clock::SystemClock;
use faro_core::outbox::PendingReport;
use faro_core::OutboxError;
use faro_crypto::{ChainHead, SigningKey};
use faro_proto::api::{ApiError, EventResult, EventsBatchRequest, EventsBatchResponse};
use faro_proto::{
    DeviceId, EventHeader, EventKind, Hash32, InstanceId, SignedEvent, Urgency,
    EVENT_HEADER_VERSION,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How the stub answers one batch.
type Script = dyn Fn(&[u64]) -> Response + Send + Sync;

#[derive(Clone)]
struct Stub {
    script: Arc<Script>,
    /// The seqs of every batch received, in order.
    batches: Arc<Mutex<Vec<Vec<u64>>>>,
}

async fn events(State(stub): State<Stub>, Json(req): Json<EventsBatchRequest>) -> Response {
    let seqs: Vec<u64> = req.events.iter().map(|e| e.header.seq).collect();
    stub.batches.lock().unwrap().push(seqs.clone());
    (stub.script)(&seqs)
}

fn answer(results: Vec<EventResult>, acked_through: Option<u64>) -> Response {
    Json(EventsBatchResponse {
        results,
        acked_through,
    })
    .into_response()
}

fn error(status: StatusCode, code: &str, headers: HeaderMap) -> Response {
    let body = Json(ApiError {
        error: code.into(),
        message: String::new(),
    });
    (status, headers, body).into_response()
}

/// Accept everything, up to the last seq.
fn accept_all(seqs: &[u64]) -> Response {
    answer(
        seqs.iter()
            .map(|&seq| EventResult::Accepted { seq })
            .collect(),
        seqs.last().copied(),
    )
}

async fn serve(
    script: impl Fn(&[u64]) -> Response + Send + Sync + 'static,
) -> (Stub, InstanceClient) {
    let stub = Stub {
        script: Arc::new(script),
        batches: Arc::default(),
    };
    let app = Router::new()
        .route("/v1/events:batch", post(events))
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base = parse_instance_url(&format!("http://{addr}")).unwrap();
    let client = InstanceClient::new(
        base,
        Arc::new(SystemClock::new()),
        &ClientOptions::default(),
    )
    .unwrap()
    .with_device(DeviceCredentials::new(
        DeviceId::new("dev_test"),
        "token",
        Arc::new(SigningKey::generate()),
    ));
    (stub, client)
}

/// An in-memory outbox holding seqs `0..n`.
struct Mem {
    events: Mutex<BTreeMap<u64, SignedEvent>>,
    next_seq: u64,
}

impl Mem {
    fn new(n: u64) -> Self {
        let key = SigningKey::generate();
        let events = (0..n)
            .map(|seq| {
                let header = EventHeader {
                    v: EVENT_HEADER_VERSION,
                    instance_id: InstanceId::new("ins_test"),
                    device_id: DeviceId::new("dev_test"),
                    seq,
                    prev_hash: Hash32::ZERO,
                    ts_ms: 1_000,
                    mono_ms: seq,
                    boot_id: "b".into(),
                    kind: EventKind::Flag,
                    urgency: Urgency::Urgent,
                    body_hash: Hash32::ZERO,
                    body_len: 0,
                };
                let sig = key.sign(&header);
                (
                    seq,
                    SignedEvent {
                        header,
                        sig,
                        body: None,
                    },
                )
            })
            .collect();
        Mem {
            events: Mutex::new(events),
            next_seq: n,
        }
    }

    fn left(&self) -> Vec<u64> {
        self.events.lock().unwrap().keys().copied().collect()
    }
}

impl OutboxAccess for Mem {
    fn head(&self) -> impl Future<Output = Result<ChainHead, OutboxError>> + Send {
        std::future::ready(Ok(ChainHead {
            next_seq: self.next_seq,
            prev_hash: Hash32::ZERO,
        }))
    }
    fn pending(
        &self,
        limit: usize,
        _max_bytes: usize,
    ) -> impl Future<Output = Result<Vec<SignedEvent>, OutboxError>> + Send {
        let evs = self.events.lock().unwrap();
        std::future::ready(Ok(evs.values().take(limit).cloned().collect()))
    }
    fn ack_through(&self, acked: u64) -> impl Future<Output = Result<u64, OutboxError>> + Send {
        let mut evs = self.events.lock().unwrap();
        let before = evs.len();
        evs.retain(|&seq, _| seq > acked);
        std::future::ready(Ok((before - evs.len()) as u64))
    }
    fn pending_reports(
        &self,
    ) -> impl Future<Output = Result<Vec<PendingReport>, OutboxError>> + Send {
        std::future::ready(Ok(Vec::new()))
    }
    fn ack_report(&self, _id: i64) -> impl Future<Output = Result<bool, OutboxError>> + Send {
        std::future::ready(Ok(false))
    }
}

async fn drain(
    client: &InstanceClient,
    outbox: &Mem,
) -> (Result<EventsDrained, UplinkError>, Vec<RefusedEvent>) {
    let mut refused = Vec::new();
    let r = uplink::drain_events(client, outbox, |_| {}, |r| refused.push(r.clone())).await;
    (r, refused)
}

/// The instance refuses seq 2 as too large and stores 3 and 4 after a gap.
/// The refusal is reported, not folded silently into the instance's
/// `acked_through`, and then dropped so it can't block later events.
#[tokio::test]
async fn a_permanent_refusal_is_reported_and_dropped() {
    let (stub, client) = serve(|seqs| {
        let results = seqs
            .iter()
            .map(|&seq| match seq {
                2 => EventResult::Rejected {
                    seq,
                    reason: "body_too_large".into(),
                },
                _ => EventResult::Accepted { seq },
            })
            .collect();
        answer(results, seqs.last().copied())
    })
    .await;
    let outbox = Mem::new(5);
    let (r, refused) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].seq, 2);
    assert_eq!(refused[0].kind, EventKind::Flag);
    assert_eq!(refused[0].reason, "body_too_large");
    assert!(!refused[0].instance_alerted());
    assert!(outbox.left().is_empty());
    assert_eq!(*stub.batches.lock().unwrap(), vec![vec![0, 1, 2, 3, 4]]);
}

/// The newest event refused: the instance's head stays below it, and the
/// device still settles it rather than resending it every pass.
#[tokio::test]
async fn a_refused_newest_event_is_not_resent_forever() {
    let (stub, client) = serve(|seqs| {
        let results = seqs
            .iter()
            .map(|&seq| match seq {
                2 => EventResult::Rejected {
                    seq,
                    reason: "malformed: body_hash/body_len do not match".into(),
                },
                _ => EventResult::Accepted { seq },
            })
            .collect();
        answer(results, Some(1))
    })
    .await;
    let outbox = Mem::new(3);
    let (r, refused) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert_eq!(refused.len(), 1);
    assert_eq!(
        refused[0].reason, "malformed",
        "cut to the reason's first word"
    );
    assert!(outbox.left().is_empty());
    let (r, refused) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert!(refused.is_empty());
    assert_eq!(
        stub.batches.lock().unwrap().len(),
        1,
        "nothing left to send"
    );
}

/// `retry_later` and everything after it stay queued, even when the
/// instance's `acked_through` says more.
#[tokio::test]
async fn retry_later_keeps_the_rest() {
    let (_stub, client) = serve(|seqs| {
        let results = seqs
            .iter()
            .map(|&seq| {
                if seq >= 2 {
                    EventResult::Rejected {
                        seq,
                        reason: "retry_later".into(),
                    }
                } else {
                    EventResult::Accepted { seq }
                }
            })
            .collect();
        answer(results, Some(3))
    })
    .await;
    let outbox = Mem::new(5);
    let (r, refused) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert!(refused.is_empty());
    assert_eq!(outbox.left(), vec![2, 3, 4]);
}

/// A `413` halves the batch until it fits; everything is delivered.
#[tokio::test]
async fn a_413_halves_the_batch() {
    let (stub, client) = serve(|seqs| {
        if seqs.len() > 2 {
            error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", HeaderMap::new())
        } else {
            accept_all(seqs)
        }
    })
    .await;
    let outbox = Mem::new(5);
    let (r, refused) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert!(refused.is_empty());
    assert!(outbox.left().is_empty());
    assert_eq!(
        *stub.batches.lock().unwrap(),
        vec![vec![0, 1, 2, 3, 4], vec![0, 1], vec![2, 3], vec![4]]
    );
}

/// One event alone still too large: the pass ends with it kept (the
/// instance's `upload_stalled` then tells allies), never silently dropped.
#[tokio::test]
async fn a_413_for_one_event_keeps_it() {
    let (stub, client) =
        serve(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "too_large", HeaderMap::new())).await;
    let outbox = Mem::new(2);
    let (r, refused) = drain(&client, &outbox).await;
    let Err(UplinkError::Client(e)) = r else {
        panic!("expected a client error, got {r:?}");
    };
    assert_eq!(e.status(), Some(reqwest::StatusCode::PAYLOAD_TOO_LARGE));
    assert!(refused.is_empty());
    assert_eq!(outbox.left(), vec![0, 1]);
    assert_eq!(*stub.batches.lock().unwrap(), vec![vec![0, 1], vec![0]]);
}

/// A `429` ends the pass with its `Retry-After` and nothing deleted.
#[tokio::test]
async fn a_429_carries_retry_after() {
    let (_stub, client) = serve(|_| {
        let mut h = HeaderMap::new();
        h.insert("retry-after", HeaderValue::from_static("7"));
        error(StatusCode::TOO_MANY_REQUESTS, "rate_limited", h)
    })
    .await;
    let outbox = Mem::new(3);
    let (r, _) = drain(&client, &outbox).await;
    let Err(UplinkError::Client(e)) = r else {
        panic!("expected a client error, got {r:?}");
    };
    assert_eq!(e.status(), Some(reqwest::StatusCode::TOO_MANY_REQUESTS));
    assert_eq!(e.retry_after(), Some(Duration::from_secs(7)));
    assert!(e.is_transient());
    assert_eq!(outbox.left(), vec![0, 1, 2]);
}

/// Answers that don't line up with the batch settle nothing past the
/// mismatch.
#[tokio::test]
async fn mismatched_answers_keep_the_rest() {
    let (_stub, client) = serve(|seqs| {
        let mut results: Vec<_> = seqs
            .iter()
            .map(|&seq| EventResult::Accepted { seq })
            .collect();
        results[1] = EventResult::Accepted { seq: 99 };
        answer(results, Some(0))
    })
    .await;
    let outbox = Mem::new(3);
    let (r, _) = drain(&client, &outbox).await;
    assert_eq!(r.unwrap(), EventsDrained::Done);
    assert_eq!(outbox.left(), vec![1, 2]);
}
