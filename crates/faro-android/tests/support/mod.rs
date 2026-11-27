//! The instance for faro-android's tests, as faro-mobile's and faro-service's
//! end-to-end tests run it: the real `faro-server` application, built by the
//! server's own integration-test harness (`server/tests/common/mod.rs`,
//! compiled in unchanged), served over TCP on 127.0.0.1 so the runtime's
//! real reqwest client, request signing and response caps are exercised.
//! The member and the ally are simulated with faro-crypto through it. The
//! phone is a [`FakePhone`] behind [`FaroAndroid`].

#![allow(dead_code)] // Not every test binary uses every helper.

use faro_android::{
    AndroidOptions, AndroidPlatform, AndroidTamper, BrowserTab, CaptureError, CapturedFrame,
    FaroAndroid, ForegroundApp, PermissionState,
};
use faro_detect::{ImageScores, ScriptedClassifier};
use faro_proto::api::FeedItem;
use faro_proto::body::EventBody;
use faro_proto::keys::{DeviceEndorsement, ManifestRef};
use faro_proto::{body_aad, DeviceId, EncryptedItem, EventKind, SignPublicKey, Urgency, UserId};
use faro_server::api::feed::FeedResponse;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

#[path = "../../../../server/tests/common/mod.rs"]
pub mod server;

pub use server::{Ally, MemberKeys, TestApp};

pub const ADMIN_EMAIL: &str = "admin@example.org";
pub const MEMBER_EMAIL: &str = "sam@example.org";
pub const ALLY_EMAIL: &str = "alex@example.org";
pub const DEVICE_NAME: &str = "Phone-Sam";
/// Real-time limit for any single wait.
pub const TIMEOUT: Duration = Duration::from_secs(60);

pub fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the fake phone shows. Tests change it while the runtime runs.
pub struct PhoneState {
    /// Scripted capture results, used first; then `screen`.
    pub captures: VecDeque<Result<CapturedFrame, CaptureError>>,
    /// The screen when nothing is scripted: a small synthetic frame.
    pub screen: (u32, u32),
    pub permission: PermissionState,
    pub foreground: Option<ForegroundApp>,
    pub browser: Option<BrowserTab>,
    pub locked: bool,
    pub tamper: Vec<AndroidTamper>,
    /// Notices shown.
    pub notices: Vec<String>,
    /// Captures taken.
    pub captured: u32,
}

/// A phone for [`FaroAndroid`], scripted through [`PhoneState`].
pub struct FakePhone(pub Mutex<PhoneState>);

impl FakePhone {
    pub fn new() -> Arc<FakePhone> {
        Arc::new(FakePhone(Mutex::new(PhoneState {
            captures: VecDeque::new(),
            screen: (96, 64),
            permission: PermissionState::Granted,
            foreground: Some(ForegroundApp {
                package: "com.android.chrome".into(),
                label: Some("Chrome".into()),
            }),
            browser: Some(BrowserTab {
                browser_package: "com.android.chrome".into(),
                origin: "https://example.org/".into(),
                incognito: false,
            }),
            locked: false,
            tamper: Vec::new(),
            notices: Vec::new(),
            captured: 0,
        })))
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut PhoneState) -> T) -> T {
        f(&mut lock(&self.0))
    }
}

impl AndroidPlatform for FakePhone {
    fn capture_screen(&self) -> Result<CapturedFrame, CaptureError> {
        let mut s = lock(&self.0);
        s.captured += 1;
        if let Some(r) = s.captures.pop_front() {
            return r;
        }
        if s.permission != PermissionState::Granted {
            return Err(CaptureError::PermissionDenied);
        }
        let (w, h) = s.screen;
        let n = s.captured;
        // A gradient that changes with every capture, so dHash never
        // dedupes two.
        let rgba = (0..w * h)
            .flat_map(|i| {
                let v = ((i * 7 + n * 31) % 251) as u8;
                [v, v.wrapping_mul(3), v.wrapping_add(n as u8), 255]
            })
            .collect();
        Ok(CapturedFrame {
            width: w,
            height: h,
            rgba,
        })
    }
    fn permission_state(&self) -> PermissionState {
        lock(&self.0).permission
    }
    fn foreground_app(&self) -> Option<ForegroundApp> {
        lock(&self.0).foreground.clone()
    }
    fn browser(&self) -> Option<BrowserTab> {
        lock(&self.0).browser.clone()
    }
    fn idle_secs(&self) -> u64 {
        0
    }
    fn is_locked(&self) -> bool {
        lock(&self.0).locked
    }
    fn display_asleep(&self) -> bool {
        false
    }
    fn poll_tamper(&self) -> Vec<AndroidTamper> {
        std::mem::take(&mut lock(&self.0).tamper)
    }
    fn show_notice(&self, text: String) {
        lock(&self.0).notices.push(text);
    }
}

/// Every capture rates `high` (an explicit-content score).
pub fn explicit() -> Box<dyn faro_detect::Classifier> {
    let scores = ImageScores::new([("explicit", 0.95f32)]).expect("valid scores");
    Box::new(ScriptedClassifier::new(scores))
}

/// A phone's [`FaroAndroid`] on a fresh data directory, uploading every
/// second, with `classifier` (none: no image model, as on Android today).
pub fn phone_core(
    dir: &std::path::Path,
    phone: Arc<FakePhone>,
    classifier: Option<fn() -> Box<dyn faro_detect::Classifier>>,
) -> Arc<FaroAndroid> {
    let mut opts = AndroidOptions {
        poll_every: Duration::from_millis(50),
        tick: Duration::from_millis(50),
        configure: Some(Arc::new(|c: &mut faro_service::Config| {
            c.network.endorsement_poll_secs = 1;
            c.network.upload_interval_secs = 1;
        })),
        ..AndroidOptions::default()
    };
    opts.client.product = "faro-android-test";
    if let Some(c) = classifier {
        opts.classifier = Some(Arc::new(c));
    }
    FaroAndroid::with_options(dir.to_owned(), phone, opts).expect("faro opens")
}

/// The instance with an admin, a member with keys and an approved ally.
pub struct World {
    pub t: TestApp,
    pub addr: SocketAddr,
    pub member: UserId,
    pub member_session: String,
    pub member_keys: MemberKeys,
    pub ally: Ally,
}

impl World {
    pub async fn new() -> World {
        let t = TestApp::with_config(|_| {}).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let app = faro_server::router::build(t.state.clone());
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("server");
        });
        let _ = t.setup_admin(ADMIN_EMAIL).await;
        let (member, member_session) = t.sign_in(MEMBER_EMAIL).await;
        let member_keys = t.create_member_keys(&member, &member_session).await;
        let ally = t
            .link_ally(&member, &member_keys, &member_session, ALLY_EMAIL)
            .await;
        World {
            t,
            addr,
            member,
            member_session,
            member_keys,
            ally,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    pub fn member_key_id(&self) -> String {
        faro_proto::keys::key_id(self.member_keys.sign.public().as_bytes())
    }

    /// A fresh enrollment link, with `m` when `member_key` is set.
    pub async fn link(&self, member_key: Option<&str>) -> String {
        let code = self.t.enroll_code(&self.member_session).await;
        let i: String = url_encode(&self.url());
        match member_key {
            Some(m) => format!("faro://enroll?i={i}&c={code}&m={m}"),
            None => format!("faro://enroll?i={i}&c={code}"),
        }
    }

    /// The member's browser approves the pending device: it checks the
    /// platform and the key fingerprint the phone shows, and signs an
    /// endorsement anchored to the current manifest.
    pub async fn endorse(&self, device_id: &str, fingerprint: &str) -> ManifestRef {
        let r = self
            .t
            .get("/v1/me/devices", Some(&self.member_session))
            .await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        let listed = r
            .body
            .as_array()
            .expect("device list")
            .iter()
            .find(|d| d["device_id"] == device_id)
            .expect("the device is listed")
            .clone();
        assert_eq!(listed["status"], "pending_endorsement");
        assert_eq!(listed["name"], DEVICE_NAME);
        assert_eq!(listed["platform"], "android");
        assert_eq!(listed["key_id"], fingerprint);
        let device_key: SignPublicKey =
            serde_json::from_value(listed["sign_pubkey"].clone()).expect("sign_pubkey");
        let min_manifest = self
            .t
            .latest_manifest(&self.member, &self.member_session)
            .await
            .expect("member has a manifest")
            .body
            .reference();
        let e = self.member_keys.sign.endorse(DeviceEndorsement {
            instance_id: self.t.instance_id(),
            member_id: self.member.clone(),
            device_id: DeviceId::new(device_id),
            device_sign_pubkey: device_key,
            endorsed_at_ms: self.t.clock_ms(),
            min_manifest,
        });
        let r = self
            .t
            .post(
                &format!("/v1/devices/{device_id}/endorse"),
                serde_json::to_value(e).expect("endorsement json"),
                Some(&self.member_session),
            )
            .await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        min_manifest
    }

    /// The events of `device_id` the member's feed shows, opened with the
    /// member's key as the web app does: `(seq, kind, effective urgency,
    /// body)`.
    pub async fn events(&self, device_id: &str) -> Vec<(u64, EventKind, Urgency, EventBody)> {
        let r = self.t.feed(&self.member, &self.member_session).await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
        let page: FeedResponse = serde_json::from_value(r.body).expect("feed page");
        let mut out = Vec::new();
        for e in page.items {
            let FeedItem::Event {
                device_id: d,
                seq,
                kind,
                urgency,
                blob_id,
                ..
            } = e.item
            else {
                continue;
            };
            if d.as_str() != device_id {
                continue;
            }
            let Some(blob) = blob_id else { continue };
            let r = self
                .t
                .get(&format!("/v1/blobs/{blob}"), Some(&self.member_session))
                .await;
            assert_eq!(r.status, axum::http::StatusCode::OK);
            let item: EncryptedItem = serde_json::from_slice(&r.raw).expect("an EncryptedItem");
            let aad = body_aad(&self.t.instance_id(), &d, seq);
            let pt = faro_crypto::open_item(&item, &aad, &self.member, &self.member_keys.enc)
                .expect("the member can open it");
            let body: EventBody = serde_json::from_slice(&pt).expect("an event body");
            out.push((seq, kind, urgency, body));
        }
        out.sort_by_key(|e| e.0);
        out
    }

    /// Every `seq` the instance stored for `device_id`, ascending.
    pub async fn stored_seqs(&self, device_id: &str) -> Vec<i64> {
        use sqlx::Row;
        sqlx::query("SELECT seq FROM events WHERE device_id = $1 ORDER BY seq")
            .bind(device_id)
            .fetch_all(self.t.state.db().pool())
            .await
            .expect("query events")
            .iter()
            .map(|r| r.try_get::<i64, _>("seq").expect("seq column"))
            .collect()
    }

    /// Every event the instance stored for `device_id`, as `(seq, kind)`
    /// from its plaintext header, ascending (the feed shows only events of
    /// at least normal urgency).
    pub async fn stored_kinds(&self, device_id: &str) -> Vec<(i64, String)> {
        sqlx::query_as("SELECT seq, kind FROM events WHERE device_id = $1 ORDER BY seq")
            .bind(device_id)
            .fetch_all(self.t.state.db().pool())
            .await
            .expect("query events")
    }

    pub async fn alert_kinds(&self) -> Vec<String> {
        self.t
            .alerts(&self.member)
            .await
            .into_iter()
            .map(|a| a.kind)
            .collect()
    }
}

fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Run `f` (which blocks) on a blocking thread.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

/// Poll `check` until it returns `Some`, or panic after [`TIMEOUT`].
pub async fn eventually<T>(what: &str, mut check: impl AsyncFnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = check().await {
            return v;
        }
        assert!(start.elapsed() < TIMEOUT, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
