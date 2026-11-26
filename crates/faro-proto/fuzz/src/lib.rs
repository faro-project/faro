//! The checks behind the faro-proto fuzz targets, and the samples their
//! seed corpus is built from. The targets are one-line wrappers, so the
//! seeds can be tested here on a stable toolchain.
//!
//! Every decoder gets the same round-trip property: whatever decodes must
//! encode, decode back to an equal value, and encode to the same bytes
//! again ([`roundtrip`]). On top of that each target checks what the
//! decoded value promises (shape checks, canonical signing bytes).

use faro_proto::api::{
    request_signing_bytes, AllyKeyUpload, ApiError, DeviceEndorseRequest, DeviceState,
    EnrollRequest, EnrollResponse, EventResult, EventsBatchRequest, EventsBatchResponse, FeedItem,
    Heartbeat, HeartbeatResponse, MemberKeysResponse, Platform, ServerAlertKind, SignedHeartbeat,
    SignedRecipientManifest, UpdatesInfo, WellKnown,
};
use faro_proto::body::{
    account_label, AppInfo, BlurredThumbnail, BrowserContext, EventBody, FlagBody, GoodbyeReason,
    Rating, Reason, ReasonSource, SettingChange, TamperSignal, MAX_ACCOUNT_LABEL,
};
use faro_proto::encoding::{b64, b64_decode, b64_encode, b64_opt, Canonical};
use faro_proto::event::{EventHeader, EVENT_HEADER_VERSION};
use faro_proto::keys::{
    key_id, safety_code, AllyEndorsement, AllyKeyRewrap, DeviceEndorsement, KeyRewrap,
    ManifestAlly, ManifestRef, MemberEncKeyBinding, ProvenAllyKeyRewrap, RecipientManifest, Signed,
    MAX_MANIFEST_ALLIES,
};
use faro_proto::report::{
    ActivityState, CountedItem, DailyReport, FlaggedMoment, HealthSummary, RatingCounts,
    ReportHeader, ReportUpload, TamperRecord, TimelineSpan,
};
use faro_proto::{
    genesis_hash, DeviceId, EncPublicKey, EncryptedItem, Envelope, EventKind, Hash32, InstanceId,
    Nonce24, SignPublicKey, Signature, SignedEvent, Urgency, UserId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Decode `json` as `T`; if it decodes, it must encode, decode back to an
/// equal value and encode to the same bytes again.
pub fn roundtrip<T>(json: &[u8]) -> Option<T>
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    let value: T = serde_json::from_slice(json).ok()?;
    let encoded = serde_json::to_vec(&value).expect("a decoded value encodes");
    let back: T = match serde_json::from_slice(&encoded) {
        Ok(v) => v,
        Err(e) => panic!(
            "re-encoded value does not decode ({e}): {}",
            String::from_utf8_lossy(&encoded)
        ),
    };
    assert_eq!(back, value, "value changed through encode and decode");
    let again = serde_json::to_vec(&back).expect("encodes");
    assert_eq!(again, encoded, "encoding is not stable");
    Some(value)
}

/// The serde adapters for byte strings.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Bytes {
    #[serde(with = "b64")]
    pub v: Vec<u8>,
    #[serde(default, with = "b64_opt")]
    pub o: Option<Vec<u8>>,
}

macro_rules! fixed {
    ($t:ty, $data:expr, $s:expr) => {{
        let data: &[u8] = $data;
        let v = <$t>::from_slice(data);
        assert_eq!(v.is_some(), data.len() == <$t>::LEN);
        if let Some(v) = v {
            assert_eq!(v.as_bytes().as_slice(), data);
            assert_eq!(<$t>::from_b64(&v.to_b64()), Some(v));
        }
        if let Some(s) = $s {
            if let Some(v) = <$t>::from_b64(s) {
                assert_eq!(v.to_b64(), s, "base64 decoding is not canonical");
            }
        }
        roundtrip::<$t>(data);
    }};
}

macro_rules! ids {
    ($data:expr, $s:expr, $($t:ty),*) => {$(
        roundtrip::<$t>($data);
        let id = <$t>::new($s);
        if id.is_well_formed() {
            let rest = &$s[<$t>::PREFIX.len()..];
            assert!(!rest.is_empty() && rest.len() <= 64);
            assert!(!$s.contains('/') && !$s.contains(char::is_whitespace));
        }
    )*};
}

/// `encoding`: the byte-level helpers, ids, enum names and key ids.
pub fn encoding(data: &[u8]) {
    let s = std::str::from_utf8(data).ok();

    fixed!(SignPublicKey, data, s);
    fixed!(Signature, data, s);
    fixed!(EncPublicKey, data, s);
    fixed!(Nonce24, data, s);
    roundtrip::<Hash32>(data);
    roundtrip::<Bytes>(data);

    // Two splits of the same bytes into two fields encode the same only if
    // they are the same split: the length prefixes make the encoding
    // injective.
    if let [a, b, rest @ ..] = data {
        let (i, j) = (
            usize::from(*a) % (rest.len() + 1),
            usize::from(*b) % (rest.len() + 1),
        );
        let enc = |k: usize| {
            let (x, y) = rest.split_at(k);
            Canonical::new("faro/fuzz/v1").bytes(x).bytes(y).finish()
        };
        assert_eq!(enc(i) == enc(j), i == j, "canonical encoding is ambiguous");

        let (x, y) = rest.split_at(i);
        assert_eq!(safety_code(x, y), safety_code(y, x));
        let code = safety_code(x, y);
        assert_eq!(code.len(), 12 * 5 + 11);
        assert!(code
            .split(' ')
            .all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
    }
    let id = key_id(data);
    assert!(id.len() == 16 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));

    let Some(s) = s else { return };
    if let Ok(v) = b64_decode(s) {
        assert_eq!(b64_encode(&v), s, "base64 decoding is not canonical");
    }
    if let Some(h) = Hash32::from_prefixed_hex(s) {
        // Hex digits may come in either case; the encoding is lowercase.
        assert!(h.to_prefixed_hex().eq_ignore_ascii_case(s));
        assert_eq!(Hash32::from_prefixed_hex(&h.to_prefixed_hex()), Some(h));
    }
    ids!(data, s, InstanceId, DeviceId, UserId);
    if let Some(k) = EventKind::parse(s) {
        assert_eq!(k.as_str(), s);
    }
    if let Some(u) = Urgency::parse(s) {
        assert_eq!(u.as_str(), s);
    }
    if let Some(k) = ServerAlertKind::parse(s) {
        assert_eq!(k.as_str(), s);
    }
    if let Some(p) = Platform::parse(s) {
        assert_eq!(p.as_str(), s);
    }
    if let Some(d) = roundtrip::<DeviceState>(data) {
        assert_eq!(
            serde_json::to_string(&d).unwrap(),
            format!("\"{}\"", d.as_str())
        );
    }
    let label = account_label(s);
    assert!(label.chars().count() <= MAX_ACCOUNT_LABEL);
    assert!(!label.chars().any(char::is_control));
    assert_eq!(label.trim(), label.as_str());
    let _ = request_signing_bytes(s, s, &DeviceId::new(s), 0, data);
}

fn check_event(e: &SignedEvent) {
    let h = &e.header;
    let sb = h.signing_bytes();
    assert!(sb.starts_with(b"faro/event-header/v1\0"));
    assert_eq!(h.chain_hash(), Hash32::of(&sb));
    let _ = h.body_aad();
    assert_eq!(EventKind::parse(h.kind.as_str()), Some(h.kind));
    assert_eq!(Urgency::parse(h.urgency.as_str()), Some(h.urgency));
    if h.seq == 0 {
        let _ = genesis_hash(&h.instance_id, &h.device_id);
    }
    for body_expected in [true, false] {
        if e.check_shape(body_expected).is_err() {
            continue;
        }
        assert_eq!(h.v, EVENT_HEADER_VERSION);
        match &e.body {
            Some(b) => {
                assert_eq!(b.alg, EncryptedItem::ALG);
                assert_eq!(b.body_hash(), h.body_hash);
                assert_eq!(b.ciphertext.len() as u64, h.body_len);
            }
            None if body_expected => {
                assert_eq!((h.body_len, h.body_hash), (0, Hash32::ZERO));
            }
            None => {}
        }
    }
}

fn check_body(b: &EventBody) {
    let _ = b.kind().min_urgency();
    match b {
        EventBody::Flag(f) => {
            for r in &f.reasons {
                let _ = r.to_string();
            }
        }
        EventBody::Tamper { signal, .. } => {
            let _ = signal.is_context_only();
        }
        _ => {}
    }
}

/// `event`: event uploads (`POST /v1/events:batch`, one signed event) and
/// decrypted event bodies.
pub fn event(data: &[u8]) -> usize {
    let mut decoded = 0;
    if let Some(batch) = roundtrip::<EventsBatchRequest>(data) {
        decoded += 1;
        let events = &batch.events[..batch.events.len().min(32)];
        for (i, e) in events.iter().enumerate() {
            check_event(e);
            // Distinct headers never share signing bytes.
            for other in &events[..i] {
                if other.header != e.header {
                    assert_ne!(other.header.signing_bytes(), e.header.signing_bytes());
                }
            }
        }
    }
    if let Some(e) = roundtrip::<SignedEvent>(data) {
        decoded += 1;
        check_event(&e);
    }
    if let Some(b) = roundtrip::<EventBody>(data) {
        decoded += 1;
        check_body(&b);
    }
    decoded
}

fn check_report_header(h: &ReportHeader) {
    assert!(h.signing_bytes().starts_with(b"faro/report-header/v1\0"));
    let _ = h.body_aad();
}

/// `report`: report uploads (`POST /v1/reports`) and decrypted reports.
pub fn report(data: &[u8]) -> usize {
    let mut decoded = 0;
    if let Some(r) = roundtrip::<ReportUpload>(data) {
        decoded += 1;
        check_report_header(&r.header);
        let _ = r.body.body_hash();
    }
    if let Some(r) = roundtrip::<DailyReport>(data) {
        decoded += 1;
        let c = &r.counts;
        let sum = u64::from(c.clean) + u64::from(c.low) + u64::from(c.medium) + u64::from(c.high);
        assert_eq!(u64::from(c.total()), sum.min(u64::from(u32::MAX)));
        for f in &r.flagged {
            for reason in &f.reasons {
                let _ = reason.to_string();
            }
        }
        for t in r.health.tamper.iter().chain(&r.health.context) {
            let _ = t.signal.is_context_only();
        }
    }
    decoded
}

fn check_manifest(m: &RecipientManifest) {
    let sb = m.signing_bytes();
    assert!(sb.starts_with(b"faro/recipient-manifest/v1\0"));
    assert_eq!(m.hash(), Hash32::of(&sb));
    assert_eq!(m.reference().version, m.version);
    if m.validate().is_ok() {
        assert!(m.version >= 1 && m.allies.len() <= MAX_MANIFEST_ALLIES);
        assert!(m.allies.windows(2).all(|w| w[0].ally_id < w[1].ally_id));
        assert!(m.allies.iter().all(|a| a.ally_id != m.member_id));
    }
}

/// The API types `api` decodes, by selector byte.
pub const API_TYPES: &[&str] = &[
    "WellKnown",
    "UpdatesInfo",
    "EnrollRequest",
    "EnrollResponse",
    "MemberKeysResponse",
    "SignedRecipientManifest",
    "DeviceEndorseRequest",
    "Signed<AllyEndorsement>",
    "Signed<KeyRewrap>",
    "EventsBatchResponse",
    "SignedHeartbeat",
    "HeartbeatResponse",
    "FeedItem",
    "ApiError",
    "AllyKeyUpload",
    "ProvenAllyKeyRewrap",
];

/// `api`: the first byte picks one of [`API_TYPES`], the rest is its JSON.
/// Returns whether it decoded.
pub fn api(data: &[u8]) -> bool {
    let Some((&sel, json)) = data.split_first() else {
        return false;
    };
    match usize::from(sel) % API_TYPES.len() {
        0 => roundtrip::<WellKnown>(json).is_some(),
        1 => roundtrip::<UpdatesInfo>(json).is_some(),
        2 => roundtrip::<EnrollRequest>(json).is_some(),
        3 => roundtrip::<EnrollResponse>(json).is_some(),
        4 => roundtrip::<MemberKeysResponse>(json)
            .inspect(|r| {
                let _ = r.member_enc_key.body.signing_bytes();
                for a in &r.allies {
                    let _ = a.body.signing_bytes();
                }
            })
            .is_some(),
        5 => roundtrip::<SignedRecipientManifest>(json)
            .inspect(|m| check_manifest(&m.body))
            .is_some(),
        6 => roundtrip::<DeviceEndorseRequest>(json)
            .inspect(|d| {
                let _ = d.body.signing_bytes();
            })
            .is_some(),
        7 => roundtrip::<Signed<AllyEndorsement>>(json)
            .inspect(|a| {
                let _ = a.body.signing_bytes();
            })
            .is_some(),
        8 => roundtrip::<Signed<KeyRewrap>>(json)
            .inspect(|k| {
                let _ = k.body.signing_bytes();
            })
            .is_some(),
        9 => roundtrip::<EventsBatchResponse>(json).is_some(),
        10 => roundtrip::<SignedHeartbeat>(json)
            .inspect(|h| {
                let sb = h.heartbeat.signing_bytes();
                assert!(sb.starts_with(b"faro/heartbeat/v1\0"));
            })
            .is_some(),
        11 => roundtrip::<HeartbeatResponse>(json).is_some(),
        12 => roundtrip::<FeedItem>(json).is_some(),
        13 => roundtrip::<ApiError>(json).is_some(),
        14 => roundtrip::<AllyKeyUpload>(json).is_some(),
        _ => roundtrip::<ProvenAllyKeyRewrap>(json)
            .inspect(|r| {
                assert!(r
                    .body
                    .proof_bytes()
                    .starts_with(b"faro/ally-key-rewrap/v1\0"));
                let _ = r.body.proof(&[0; 32]);
            })
            .is_some(),
    }
}

// ---------------------------------------------------------------------------
// Samples for the seed corpus.

const T0: i64 = 1_800_000_000_000;

fn inst() -> InstanceId {
    InstanceId::new("inst_0123456789abcdef")
}
fn dev() -> DeviceId {
    DeviceId::new("dev_0123456789abcdef")
}
fn member() -> UserId {
    UserId::new("usr_member")
}
fn ally() -> UserId {
    UserId::new("usr_ally")
}

fn item(plaintext_len: usize) -> EncryptedItem {
    EncryptedItem {
        alg: EncryptedItem::ALG.into(),
        nonce: Nonce24([3; 24]),
        ciphertext: vec![0xab; plaintext_len + 16],
        envelopes: vec![
            Envelope {
                recipient: member(),
                key_id: key_id(&[1; 32]),
                wrapped_key: vec![4; 80],
            },
            Envelope {
                recipient: ally(),
                key_id: key_id(&[2; 32]),
                wrapped_key: vec![5; 80],
            },
        ],
    }
}

fn header(seq: u64, kind: EventKind, body: Option<&EncryptedItem>) -> EventHeader {
    EventHeader {
        v: EVENT_HEADER_VERSION,
        instance_id: inst(),
        device_id: dev(),
        seq,
        prev_hash: if seq == 0 {
            genesis_hash(&inst(), &dev())
        } else {
            Hash32::of(b"previous")
        },
        ts_ms: T0 + seq as i64 * 1000,
        mono_ms: 5000 + seq * 1000,
        boot_id: "boot-1".into(),
        kind,
        urgency: kind.min_urgency(),
        body_hash: body.map_or(Hash32::ZERO, EncryptedItem::body_hash),
        body_len: body.map_or(0, |b| b.ciphertext.len() as u64),
    }
}

fn event_sample(seq: u64, kind: EventKind, with_body: bool) -> SignedEvent {
    let body = with_body.then(|| item(40));
    SignedEvent {
        header: header(seq, kind, body.as_ref()),
        sig: Signature([7; 64]),
        body,
    }
}

fn reasons() -> Vec<Reason> {
    vec![
        Reason {
            source: ReasonSource::Image,
            label: "explicit".into(),
            score: Some(0.93),
        },
        Reason {
            source: ReasonSource::Domain,
            label: "adult".into(),
            score: None,
        },
    ]
}

fn thumbnail() -> BlurredThumbnail {
    BlurredThumbnail {
        width: 320,
        height: 200,
        transform: "gauss12+pix8".into(),
        png: vec![0x89, b'P', b'N', b'G'],
    }
}

fn bodies() -> Vec<EventBody> {
    vec![
        EventBody::Capture {
            rating: Rating::Clean,
            count: 12,
        },
        EventBody::Flag(FlagBody {
            rating: Rating::High,
            reasons: reasons(),
            app: Some(AppInfo {
                id: "com.google.Chrome".into(),
                name: Some("Chrome".into()),
            }),
            window_title: Some("title".into()),
            browser: Some(BrowserContext {
                url: Some("https://example.com/".into()),
                title: Some("Example".into()),
                incognito: true,
            }),
            thumbnail: Some(thumbnail()),
            burst: true,
            account: Some("alex".into()),
        }),
        EventBody::Tamper {
            signal: TamperSignal::ClockManipulation {
                wall_delta_ms: -60_000,
                mono_delta_ms: 5,
            },
            account: Some("alex".into()),
        },
        EventBody::tamper(TamperSignal::UnmonitoredUserSession {
            user: "guest".into(),
        }),
        EventBody::tamper(TamperSignal::WindowHiddenFromCapture {
            app: "Viewer".into(),
        }),
        EventBody::tamper(TamperSignal::VpnActive),
        EventBody::SettingsChange {
            changes: vec![SettingChange {
                key: "capture.interval".into(),
                old: Some("60".into()),
                new: None,
            }],
        },
        EventBody::AgentRestarted { count_last_hour: 3 },
        EventBody::Paused {
            reason: Some("meeting".into()),
            until_ms: Some(T0),
        },
        EventBody::Resumed,
        EventBody::Goodbye {
            reason: GoodbyeReason::MovedInstance {
                new_instance_host: "faro.example".into(),
            },
        },
        EventBody::Boot {
            os: "macOS 15.1".into(),
            client_version: "1.0.0".into(),
        },
        EventBody::Shutdown,
    ]
}

fn daily_report() -> DailyReport {
    let tamper = TamperRecord {
        seq: Some(4),
        ts_ms: T0 + 10,
        signal: TamperSignal::PermissionRevoked {
            permission: "screen_recording".into(),
            never_granted: true,
        },
        account: Some("alex".into()),
    };
    DailyReport {
        v: 1,
        device_id: dev(),
        device_name: "Laptop".into(),
        period_start_ms: T0,
        period_end_ms: T0 + 86_400_000,
        first_seq: Some(0),
        last_seq: Some(9),
        timeline: vec![
            TimelineSpan {
                start_ms: T0,
                end_ms: T0 + 1000,
                state: ActivityState::Active,
                account: Some("alex".into()),
            },
            TimelineSpan {
                start_ms: T0 + 1000,
                end_ms: T0 + 2000,
                state: ActivityState::Unmonitored,
                account: None,
            },
        ],
        counts: RatingCounts {
            clean: 10,
            low: 2,
            medium: 1,
            high: 1,
        },
        flagged: vec![FlaggedMoment {
            seq: 3,
            ts_ms: T0 + 500,
            rating: Rating::Medium,
            reasons: reasons(),
            app: Some(AppInfo::default()),
            thumbnail: Some(thumbnail()),
            member_note: Some("false positive".into()),
            account: Some("alex".into()),
        }],
        top_domains: Some(vec![CountedItem {
            name: "example.com".into(),
            count: 4,
        }]),
        top_apps: None,
        health: HealthSummary {
            tamper: vec![tamper],
            context: vec![TamperRecord {
                seq: None,
                ts_ms: T0,
                signal: TamperSignal::BrowserWithoutExtension {
                    browser: "firefox".into(),
                },
                account: None,
            }],
            agent_restarts: 1,
            capture_failures: 0,
            unmonitored_secs: 1,
        },
    }
}

fn report_upload() -> ReportUpload {
    let body = item(200);
    ReportUpload {
        header: ReportHeader {
            v: 1,
            instance_id: inst(),
            member_id: member(),
            device_id: dev(),
            period_start_ms: T0,
            period_end_ms: T0 + 86_400_000,
            first_seq: Some(0),
            last_seq: None,
            body_hash: body.body_hash(),
            body_len: body.ciphertext.len() as u64,
        },
        sig: Signature([8; 64]),
        body,
    }
}

fn manifest() -> RecipientManifest {
    RecipientManifest {
        instance_id: inst(),
        member_id: member(),
        version: 3,
        issued_at_ms: T0,
        member_enc_pubkey: EncPublicKey([1; 32]),
        allies: vec![
            ManifestAlly {
                ally_id: UserId::new("usr_a"),
                enc_pubkey: EncPublicKey([2; 32]),
            },
            ManifestAlly {
                ally_id: UserId::new("usr_b"),
                enc_pubkey: EncPublicKey([3; 32]),
            },
        ],
    }
}

fn signed<T>(body: T) -> Signed<T> {
    Signed {
        body,
        sig: Signature([9; 64]),
    }
}

fn json(v: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(v).expect("sample encodes")
}

fn with_selector(name: &str, v: &impl Serialize) -> Vec<u8> {
    let sel = API_TYPES
        .iter()
        .position(|t| *t == name)
        .expect("a listed API type") as u8;
    let mut out = vec![sel];
    out.extend(json(v));
    out
}

/// `(target, name, bytes)` for every seed.
pub fn seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut add = |target: &'static str, name: &str, bytes: Vec<u8>| {
        out.push((target, name.to_owned(), bytes));
    };

    // encoding
    let key = SignPublicKey([0x5a; 32]);
    add("encoding", "key-b64", key.to_b64().into_bytes());
    add("encoding", "key-json", json(&key));
    add("encoding", "key-raw", key.0.to_vec());
    add("encoding", "nonce-raw", vec![3; 24]);
    add("encoding", "sig-json", json(&Signature([1; 64])));
    add(
        "encoding",
        "hash-hex",
        Hash32::of(b"faro").to_prefixed_hex().into_bytes(),
    );
    add("encoding", "hash-json", json(&Hash32::of(b"faro")));
    add(
        "encoding",
        "bytes-json",
        json(&Bytes {
            v: b"hello".to_vec(),
            o: Some(vec![0, 255]),
        }),
    );
    for s in [
        "dev_abc-1_2",
        "usr_x",
        "tamper",
        "urgent",
        "macos",
        "  alex\n",
    ] {
        add("encoding", s.trim(), s.as_bytes().to_vec());
    }
    add("encoding", "state-json", json(&DeviceState::ShuttingDown));

    // event
    let events = vec![
        event_sample(0, EventKind::Boot, false),
        event_sample(1, EventKind::Flag, true),
        event_sample(2, EventKind::Tamper, true),
    ];
    for (i, e) in events.iter().enumerate() {
        add("event", &format!("event-{i}"), json(e));
    }
    add(
        "event",
        "batch",
        json(&EventsBatchRequest {
            events: events.clone(),
        }),
    );
    for (i, b) in bodies().iter().enumerate() {
        add("event", &format!("body-{i:02}-{}", b.kind()), json(b));
    }

    // report
    add("report", "upload", json(&report_upload()));
    add("report", "daily", json(&daily_report()));
    let mut huge = daily_report();
    huge.counts = RatingCounts {
        clean: u32::MAX,
        low: u32::MAX - 1,
        medium: 1,
        high: 0,
    };
    add("report", "daily-huge-counts", json(&huge));

    // api
    let api = |name: &str, v: &dyn erased::Json| (name.to_owned(), v.bytes(name));
    let samples = [
        api(
            "WellKnown",
            &WellKnown {
                instance_id: inst(),
                name: "Faro".into(),
                identity_pubkey: key,
                server_version: "1.0.0".into(),
                min_client_version: "1.0.0".into(),
                protocol: 1,
            },
        ),
        api(
            "UpdatesInfo",
            &UpdatesInfo {
                available: true,
                channel: "stable-1".into(),
            },
        ),
        api(
            "EnrollRequest",
            &EnrollRequest {
                enroll_code: "ABCD-EFGH".into(),
                sign_pubkey: key,
                platform: Platform::Macos,
                device_name: "Laptop".into(),
                client_version: "1.0.0".into(),
            },
        ),
        api(
            "EnrollResponse",
            &EnrollResponse {
                instance_id: inst(),
                device_id: dev(),
                device_token: "token".into(),
                member_id: member(),
                member_sign_pubkey: key,
            },
        ),
        api(
            "MemberKeysResponse",
            &MemberKeysResponse {
                member_id: member(),
                member_sign_pubkey: key,
                member_enc_key: signed(MemberEncKeyBinding {
                    instance_id: inst(),
                    member_id: member(),
                    member_enc_pubkey: EncPublicKey([1; 32]),
                    endorsed_at_ms: T0,
                }),
                allies: vec![signed(AllyEndorsement {
                    instance_id: inst(),
                    member_id: member(),
                    ally_id: ally(),
                    ally_enc_pubkey: EncPublicKey([2; 32]),
                    endorsed_at_ms: T0,
                })],
            },
        ),
        api("SignedRecipientManifest", &signed(manifest())),
        api(
            "DeviceEndorseRequest",
            &signed(DeviceEndorsement {
                instance_id: inst(),
                member_id: member(),
                device_id: dev(),
                device_sign_pubkey: key,
                endorsed_at_ms: T0,
                min_manifest: ManifestRef {
                    version: 3,
                    hash: manifest().hash(),
                },
            }),
        ),
        api(
            "Signed<AllyEndorsement>",
            &signed(AllyEndorsement {
                instance_id: inst(),
                member_id: member(),
                ally_id: ally(),
                ally_enc_pubkey: EncPublicKey([2; 32]),
                endorsed_at_ms: T0,
            }),
        ),
        api(
            "Signed<KeyRewrap>",
            &signed(KeyRewrap {
                instance_id: inst(),
                member_id: member(),
                sign_pubkey: key,
                issued_at_ms: T0,
                wrapped_sign_key: r#"{"v":1}"#.into(),
                wrapped_enc_key: r#"{"v":1}"#.into(),
                recovery_wrapped: r#"{"v":1}"#.into(),
            }),
        ),
        api(
            "EventsBatchResponse",
            &EventsBatchResponse {
                results: vec![
                    EventResult::Accepted { seq: 0 },
                    EventResult::Duplicate { seq: 1 },
                    EventResult::Rejected {
                        seq: 2,
                        reason: "chain".into(),
                    },
                ],
                acked_through: Some(1),
            },
        ),
        api(
            "SignedHeartbeat",
            &SignedHeartbeat {
                heartbeat: Heartbeat {
                    instance_id: inst(),
                    device_id: dev(),
                    ts_ms: T0,
                    mono_ms: 1,
                    boot_id: "boot-1".into(),
                    state: DeviceState::Active,
                    last_seq: Some(9),
                    last_hash: Some(Hash32::of(b"head")),
                },
                sig: Signature([6; 64]),
            },
        ),
        api(
            "HeartbeatResponse",
            &HeartbeatResponse {
                server_time_ms: T0,
                next_in_secs: 300,
                acked_through: None,
            },
        ),
        api(
            "FeedItem",
            &FeedItem::Alert {
                member_id: member(),
                device_id: Some(dev()),
                alert_id: "alr_1".into(),
                kind: ServerAlertKind::AllyDisabled,
                urgency: Urgency::Urgent,
                ts_ms: T0,
                detail: Some("usr_ally".into()),
            },
        ),
        api(
            "ApiError",
            &ApiError {
                error: "bad_request".into(),
                message: "nope".into(),
            },
        ),
        api(
            "AllyKeyUpload",
            &AllyKeyUpload {
                enc_pubkey: EncPublicKey([2; 32]),
                wrapped_privkey: serde_json::json!({"v": 1, "kdf": {"m": 65536, "t": 3}}),
            },
        ),
        api("ProvenAllyKeyRewrap", &{
            let body = AllyKeyRewrap {
                instance_id: inst(),
                ally_id: ally(),
                enc_pubkey: EncPublicKey([2; 32]),
                issued_at_ms: T0,
                wrapped_privkey: r#"{"v":1}"#.into(),
            };
            ProvenAllyKeyRewrap {
                proof: body.proof(&[7; 32]),
                body,
            }
        }),
    ];
    for (name, bytes) in samples {
        add("api", &name.replace(['<', '>'], "-"), bytes);
    }
    let feed = FeedItem::Event {
        member_id: member(),
        device_id: dev(),
        seq: 1,
        ts_ms: T0,
        kind: EventKind::Flag,
        urgency: Urgency::Normal,
        blob_id: None,
    };
    add("api", "FeedItem-event", with_selector("FeedItem", &feed));
    out
}

/// Object-safe JSON encoding for the sample table.
mod erased {
    pub trait Json {
        fn bytes(&self, name: &str) -> Vec<u8>;
    }
    impl<T: serde::Serialize> Json for T {
        fn bytes(&self, name: &str) -> Vec<u8> {
            super::with_selector(name, self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_seed_decodes() {
        for (target, name, bytes) in seeds() {
            let ok = match target {
                "encoding" => {
                    encoding(&bytes);
                    true
                }
                "event" => event(&bytes) > 0,
                "report" => report(&bytes) > 0,
                "api" => api(&bytes),
                _ => unreachable!(),
            };
            assert!(ok, "{target}/{name} does not decode");
        }
    }

    #[test]
    fn every_api_type_has_a_seed() {
        let seeds = seeds();
        for (i, _) in API_TYPES.iter().enumerate() {
            assert!(seeds
                .iter()
                .any(|(t, _, b)| *t == "api" && usize::from(b[0]) == i));
        }
    }
}
