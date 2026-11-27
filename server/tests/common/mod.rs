//! Shared harness for the in-process integration tests.
//!
//! Builds the real router through [`faro_server::bootstrap::open`] (SQLite in
//! a temp dir, local-disk blobs, [`TestMailer`], [`ManualClock`]) and drives
//! it with `tower::ServiceExt::oneshot`. Devices are simulated with real
//! faro-crypto keys: every event is genuinely signed, hash-chained and
//! encrypted to the member's key.

#![allow(dead_code)] // Not every test binary uses every helper.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use faro_crypto::{seal_item, ChainHead, EncryptionKeypair, KdfParams, Recipient, SigningKey};
use faro_proto::api::{
    auth_headers, request_signing_bytes, EnrollResponse, SignedRecipientManifest,
};
use faro_proto::keys::{
    DeviceEndorsement, ManifestAlly, ManifestRef, MemberEncKeyBinding, RecipientManifest,
};
use faro_proto::{
    DeviceId, EventHeader, EventKind, Hash32, InstanceId, SignedEvent, Urgency, UserId,
    EVENT_HEADER_VERSION,
};
use faro_server::clock::ManualClock;
use faro_server::config::{Config, RegistrationMode};
use faro_server::mailer::TestMailer;
use faro_server::AppState;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

pub const COOKIE: &str = "faro_session";

pub struct TestApp {
    pub app: Router,
    pub state: AppState,
    pub mailer: TestMailer,
    pub clock: ManualClock,
    pub dir: tempfile::TempDir,
}

/// A config suitable for tests: dev mode, open registration for
/// `example.org`, generous rate limits (one test checks limiting explicitly).
pub fn test_config(dir: &std::path::Path) -> Config {
    let mut c = Config {
        data_dir: dir.join("data"),
        dev: true,
        ..Config::default()
    };
    c.registration.mode = RegistrationMode::Open;
    c.registration.allowed_email_domains = vec!["example.org".into()];
    c.rate_limit.unauthenticated_per_minute = 10_000;
    c.rate_limit.magic_links_per_email_per_hour = 10_000;
    c.validate().expect("test config validates");
    c
}

pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn error_code(&self) -> &str {
        self.body["error"].as_str().unwrap_or("")
    }
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    pub async fn with_config(tweak: impl FnOnce(&mut Config)) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = test_config(dir.path());
        tweak(&mut cfg);
        cfg.validate().expect("tweaked config validates");
        let mailer = TestMailer::new();
        let clock = ManualClock::starting_now();
        let state =
            faro_server::bootstrap::open(cfg, Arc::new(mailer.clone()), Arc::new(clock.clone()))
                .await
                .expect("bootstrap");
        let app = faro_server::router::build(state.clone());
        TestApp {
            app,
            state,
            mailer,
            clock,
            dir,
        }
    }

    pub fn instance_id(&self) -> InstanceId {
        self.state.instance_id().clone()
    }

    pub async fn send(&self, req: Request<Body>) -> Resp {
        let resp = self.app.clone().oneshot(req).await.expect("infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let raw = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body")
            .to_vec();
        let body = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        Resp {
            status,
            headers,
            body,
            raw,
        }
    }

    /// A JSON (or bodyless) request, optionally with a session cookie.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        session: Option<&str>,
    ) -> Resp {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(s) = session {
            b = b.header(header::COOKIE, format!("{COOKIE}={s}"));
        }
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&v).expect("json"))
            }
            None => Body::empty(),
        };
        self.send(b.body(body).expect("request")).await
    }

    pub async fn get(&self, path: &str, session: Option<&str>) -> Resp {
        self.call(Method::GET, path, None, session).await
    }

    pub async fn post(&self, path: &str, body: Value, session: Option<&str>) -> Resp {
        self.call(Method::POST, path, Some(body), session).await
    }

    /// Mint a setup token and create the first admin. Returns the session.
    pub async fn setup_admin(&self, email: &str) -> (UserId, String) {
        let token = faro_server::bootstrap::issue_setup_token(&self.state)
            .await
            .expect("db")
            .expect("no admin yet");
        let r = self
            .post(
                "/v1/setup",
                json!({"setup_token": token.as_str(), "email": email, "display_name": "Admin"}),
                None,
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let cookie = session_from(&r.headers).expect("setup sets a session cookie");
        (
            UserId::new(r.body["user"]["id"].as_str().expect("id")),
            cookie,
        )
    }

    /// Request a magic link and return the token from the emailed URL.
    pub async fn magic_link_token(&self, email: &str) -> String {
        let before = self.mailer.sent().len();
        let r = self
            .post("/v1/auth/magic-link", json!({ "email": email }), None)
            .await;
        assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
        // Sending is asynchronous; wait for a *new* message.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let sent = self.mailer.sent();
            if sent.len() > before {
                if let Some(m) = sent[before..].iter().rev().find(|m| m.to == email) {
                    return token_from_email(&m.text).expect("token in email");
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no email for {email}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Sign in (creating the account under open registration).
    pub async fn sign_in(&self, email: &str) -> (UserId, String) {
        let token = self.magic_link_token(email).await;
        let r = self
            .post(
                "/v1/auth/magic-link/verify",
                json!({ "token": token }),
                None,
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let cookie = session_from(&r.headers).expect("cookie");
        (
            UserId::new(r.body["user"]["id"].as_str().expect("id")),
            cookie,
        )
    }

    /// Generate member keys, upload them, and store the first (empty)
    /// recipient manifest, as the member's browser does at setup.
    pub async fn create_member_keys(&self, member: &UserId, session: &str) -> MemberKeys {
        let keys = self.create_member_keys_only(member, session).await;
        let m = keys.manifest(&self.instance_id(), member, 1, &[], self.clock_ms());
        let r = self.put_manifest(session, &m).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        keys
    }

    /// Generate member keys and upload them, without a recipient manifest.
    pub async fn create_member_keys_only(&self, member: &UserId, session: &str) -> MemberKeys {
        let keys = MemberKeys::generate(&self.instance_id(), member, self.clock_ms());
        let r = self
            .call(
                Method::PUT,
                "/v1/me/keys",
                Some(keys.put_body()),
                Some(session),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        keys
    }

    pub fn clock_ms(&self) -> i64 {
        use faro_server::clock::Clock;
        self.clock.now_ms()
    }

    pub async fn enroll_code(&self, session: &str) -> String {
        let r = self
            .post("/v1/me/enroll-codes", json!({}), Some(session))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        r.body["code"].as_str().expect("code").to_owned()
    }

    /// Enroll a fresh device with `code` (device stays pending).
    pub async fn enroll(&self, code: &str, member_enc: &EncryptionKeypair) -> TestDevice {
        self.enroll_as(code, member_enc, "macos", "Sam's MacBook")
            .await
    }

    /// Enroll a fresh device of any platform (device stays pending).
    pub async fn enroll_as(
        &self,
        code: &str,
        member_enc: &EncryptionKeypair,
        platform: &str,
        name: &str,
    ) -> TestDevice {
        let key = SigningKey::generate();
        let r = self
            .post(
                "/v1/devices/enroll",
                json!({
                    "enroll_code": code,
                    "sign_pubkey": key.public(),
                    "platform": platform,
                    "device_name": name,
                    "client_version": "0.1.0",
                }),
                None,
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let er: EnrollResponse = serde_json::from_value(r.body).expect("EnrollResponse");
        TestDevice::new(key, er, self.instance_id(), member_enc.public())
    }

    /// Endorse `dev`, anchored to the member's current manifest.
    pub async fn endorse(&self, dev: &TestDevice, member: &MemberKeys, session: &str) -> Resp {
        let min_manifest = self
            .latest_manifest(&dev.member_id, session)
            .await
            .expect("member has a manifest")
            .body
            .reference();
        self.endorse_anchored(dev, member, session, min_manifest)
            .await
    }

    /// Endorse `dev` with an explicit `min_manifest`.
    pub async fn endorse_anchored(
        &self,
        dev: &TestDevice,
        member: &MemberKeys,
        session: &str,
        min_manifest: ManifestRef,
    ) -> Resp {
        let e = member.sign.endorse(DeviceEndorsement {
            instance_id: self.instance_id(),
            member_id: dev.member_id.clone(),
            device_id: dev.id.clone(),
            device_sign_pubkey: dev.key.public(),
            endorsed_at_ms: self.clock_ms(),
            min_manifest,
        });
        self.post(
            &format!("/v1/devices/{}/endorse", dev.id),
            serde_json::to_value(e).expect("json"),
            Some(session),
        )
        .await
    }

    /// Admin + member keys + an active device, the common starting point.
    pub async fn active_device(&self) -> (UserId, String, MemberKeys, TestDevice) {
        let (member, session) = self.sign_in("sam@example.org").await;
        let keys = self.create_member_keys(&member, &session).await;
        let code = self.enroll_code(&session).await;
        let dev = self.enroll(&code, &keys.enc).await;
        let r = self.endorse(&dev, &keys, &session).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        (member, session, keys, dev)
    }

    /// Send a device-signed request (`ts` defaults to now).
    pub async fn device_call(
        &self,
        dev: &TestDevice,
        method: Method,
        path: &str,
        body: &[u8],
    ) -> Resp {
        let req = dev.request(method, path, body, self.clock_ms());
        self.send(req).await
    }

    pub async fn device_post<T: serde::Serialize>(
        &self,
        dev: &TestDevice,
        path: &str,
        v: &T,
    ) -> Resp {
        let bytes = serde_json::to_vec(v).expect("json");
        self.device_call(dev, Method::POST, path, &bytes).await
    }

    pub async fn post_events(&self, dev: &TestDevice, events: &[SignedEvent]) -> Resp {
        self.device_post(dev, "/v1/events:batch", &json!({ "events": events }))
            .await
    }

    pub async fn alerts(&self, member: &UserId) -> Vec<faro_server::db::repo::alerts::AlertRow> {
        faro_server::db::repo::alerts::list_for_member(self.state.db().pool(), member)
            .await
            .expect("alerts")
    }
}

/// Extract the session value from a `Set-Cookie` header.
pub fn session_from(h: &HeaderMap) -> Option<String> {
    h.get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let first = c.split(';').next()?;
            let (k, v) = first.split_once('=')?;
            (k.trim() == COOKIE).then(|| v.trim().to_owned())
        })
}

pub fn token_from_email(text: &str) -> Option<String> {
    let start = text.find("#token=")? + "#token=".len();
    let rest = &text[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

/// A member's root keys, generated as the browser would.
pub struct MemberKeys {
    pub sign: SigningKey,
    pub enc: EncryptionKeypair,
    pub binding: faro_proto::keys::Signed<MemberEncKeyBinding>,
}

impl MemberKeys {
    pub fn generate(instance: &InstanceId, member: &UserId, now_ms: i64) -> Self {
        let sign = SigningKey::generate();
        let enc = EncryptionKeypair::generate();
        let binding = sign.endorse(MemberEncKeyBinding {
            instance_id: instance.clone(),
            member_id: member.clone(),
            member_enc_pubkey: enc.public(),
            endorsed_at_ms: now_ms,
        });
        MemberKeys { sign, enc, binding }
    }

    /// Sign a recipient manifest (allies are sorted here, as a browser must).
    pub fn manifest(
        &self,
        instance: &InstanceId,
        member: &UserId,
        version: u64,
        allies: &[(UserId, faro_proto::EncPublicKey)],
        issued_at_ms: i64,
    ) -> SignedRecipientManifest {
        let mut allies: Vec<ManifestAlly> = allies
            .iter()
            .map(|(id, k)| ManifestAlly {
                ally_id: id.clone(),
                enc_pubkey: *k,
            })
            .collect();
        allies.sort_by(|a, b| a.ally_id.cmp(&b.ally_id));
        self.sign.endorse(RecipientManifest {
            instance_id: instance.clone(),
            member_id: member.clone(),
            version,
            issued_at_ms,
            member_enc_pubkey: self.enc.public(),
            allies,
        })
    }

    /// The manifest after `latest`: same allies, edited by `f`, next version.
    pub fn next_manifest(
        &self,
        latest: &SignedRecipientManifest,
        f: impl FnOnce(&mut Vec<(UserId, faro_proto::EncPublicKey)>),
    ) -> SignedRecipientManifest {
        let mut allies: Vec<(UserId, faro_proto::EncPublicKey)> = latest
            .body
            .allies
            .iter()
            .map(|a| (a.ally_id.clone(), a.enc_pubkey))
            .collect();
        f(&mut allies);
        self.manifest(
            &latest.body.instance_id,
            &latest.body.member_id,
            latest.body.version + 1,
            &allies,
            latest.body.issued_at_ms + 1,
        )
    }

    pub fn put_body(&self) -> Value {
        let p = KdfParams::insecure_for_tests();
        let ws =
            faro_crypto::wrap_secret(self.sign.to_bytes().as_slice(), b"pass", p).expect("wrap");
        let we =
            faro_crypto::wrap_secret(self.enc.secret_bytes().as_slice(), b"pass", p).expect("wrap");
        let wr = faro_crypto::wrap_secret(self.sign.to_bytes().as_slice(), b"RECOVERY", p)
            .expect("wrap");
        json!({
            "sign_pubkey": self.sign.public(),
            "enc_binding": self.binding,
            "wrapped_sign_key": ws,
            "wrapped_enc_key": we,
            "recovery_wrapped": { "sign": wr },
        })
    }
}

/// A simulated device: real key, real token, real hash chain.
pub struct TestDevice {
    pub key: SigningKey,
    pub id: DeviceId,
    pub token: String,
    pub member_id: UserId,
    pub instance_id: InstanceId,
    pub member_enc: faro_proto::EncPublicKey,
    pub head: ChainHead,
}

impl TestDevice {
    pub fn new(
        key: SigningKey,
        er: EnrollResponse,
        instance_id: InstanceId,
        member_enc: faro_proto::EncPublicKey,
    ) -> Self {
        TestDevice {
            head: ChainHead::genesis(&instance_id, &er.device_id),
            key,
            id: er.device_id,
            token: er.device_token,
            member_id: er.member_id,
            instance_id,
            member_enc,
        }
    }

    /// Build a request authenticated as this device.
    pub fn request(&self, method: Method, path: &str, body: &[u8], ts_ms: i64) -> Request<Body> {
        self.request_as(&self.token, &self.id, &self.key, method, path, body, ts_ms)
    }

    /// Build a request with arbitrary credentials (for adversarial tests).
    #[allow(clippy::too_many_arguments)]
    pub fn request_as(
        &self,
        token: &str,
        claimed: &DeviceId,
        key: &SigningKey,
        method: Method,
        path: &str,
        body: &[u8],
        ts_ms: i64,
    ) -> Request<Body> {
        let sig = key.sign_raw(&request_signing_bytes(
            method.as_str(),
            path,
            claimed,
            ts_ms,
            body,
        ));
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(auth_headers::DEVICE, claimed.as_str())
            .header(auth_headers::TIMESTAMP, ts_ms.to_string())
            .header(auth_headers::SIGNATURE, sig.to_b64());
        if !body.is_empty() {
            b = b.header(header::CONTENT_TYPE, "application/json");
        }
        b.body(Body::from(body.to_vec())).expect("request")
    }

    /// The next event in this device's chain, with a body encrypted to the
    /// member. Advances the local head.
    pub fn next_event(&mut self, kind: EventKind, urgency: Urgency) -> SignedEvent {
        let ev = self.event_at(self.head, kind, urgency, b"{\"blurred\":true}");
        self.head.advance(&ev.header);
        ev
    }

    /// Build (without advancing) an event linked to an arbitrary head.
    pub fn event_at(
        &self,
        head: ChainHead,
        kind: EventKind,
        urgency: Urgency,
        plaintext: &[u8],
    ) -> SignedEvent {
        let mut header = EventHeader {
            v: EVENT_HEADER_VERSION,
            instance_id: self.instance_id.clone(),
            device_id: self.id.clone(),
            seq: head.next_seq,
            prev_hash: head.prev_hash,
            ts_ms: 1_800_000_000_000 + i64::try_from(head.next_seq).unwrap_or(0),
            mono_ms: head.next_seq * 1000,
            boot_id: "boot-1".into(),
            kind,
            urgency,
            body_hash: Hash32::ZERO,
            body_len: 0,
        };
        let body = seal_item(
            plaintext,
            &header.body_aad(),
            &[Recipient {
                user_id: self.member_id.clone(),
                pubkey: self.member_enc,
            }],
        )
        .expect("seal");
        header.body_hash = body.body_hash();
        header.body_len = body.ciphertext.len() as u64;
        let sig = self.key.sign(&header);
        SignedEvent {
            header,
            sig,
            body: Some(body),
        }
    }
}

/// Fetch a stored event row's (urgency, effective_urgency, header_json, blob_id).
pub async fn stored_event(
    state: &AppState,
    dev: &DeviceId,
    seq: i64,
) -> Option<(String, String, String, Option<String>)> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT urgency, effective_urgency, header_json, blob_id FROM events
         WHERE device_id = $1 AND seq = $2",
    )
    .bind(dev.as_str())
    .bind(seq)
    .fetch_optional(state.db().pool())
    .await
    .expect("query")?;
    Some((
        row.try_get("urgency").expect("col"),
        row.try_get("effective_urgency").expect("col"),
        row.try_get("header_json").expect("col"),
        row.try_get("blob_id").expect("col"),
    ))
}

pub async fn count(state: &AppState, sql: &'static str) -> i64 {
    use sqlx::Row;
    sqlx::query(sql)
        .fetch_one(state.db().pool())
        .await
        .expect("count")
        .try_get::<i64, _>(0)
        .expect("col")
}

/// [`count`] with one bound text parameter (`$1`).
pub async fn count_with(state: &AppState, sql: &'static str, arg: &str) -> i64 {
    use sqlx::Row;
    sqlx::query(sql)
        .bind(arg)
        .fetch_one(state.db().pool())
        .await
        .expect("count")
        .try_get::<i64, _>(0)
        .expect("col")
}

// ----- Stage B helpers: allies, heartbeats, workers -------------------------

/// An ally's encryption key, generated as their browser would.
pub struct AllyKeys {
    pub enc: EncryptionKeypair,
}

impl AllyKeys {
    pub fn generate() -> Self {
        AllyKeys {
            enc: EncryptionKeypair::generate(),
        }
    }

    pub fn upload_body(&self) -> Value {
        let wrapped = faro_crypto::wrap_secret(
            self.enc.secret_bytes().as_slice(),
            b"ally-pass",
            KdfParams::insecure_for_tests(),
        )
        .expect("wrap");
        json!({ "enc_pubkey": self.enc.public(), "wrapped_privkey": wrapped })
    }
}

/// A linked ally as seen by tests.
pub struct Ally {
    pub id: UserId,
    pub session: String,
    pub keys: AllyKeys,
    pub email: String,
}

/// Poll the outbox for an email to `to` whose text contains `needle`.
pub async fn wait_for_mail(t: &TestApp, to: &str, needle: &str) -> faro_server::mailer::Email {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(m) = t
            .mailer
            .sent()
            .into_iter()
            .rev()
            .find(|m| m.to == to && m.text.contains(needle))
        {
            return m;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no email to {to} containing {needle:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

impl TestApp {
    /// Invite `email` as an ally of the session's member; returns the token
    /// taken from the emailed link.
    pub async fn invite(&self, member_session: &str, email: &str) -> String {
        let r = self
            .post(
                "/v1/me/invites",
                json!({ "email": email }),
                Some(member_session),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let url = r.body["invite_url"].as_str().expect("invite_url");
        let token = token_from_email(url).expect("invite token");
        // The same link is emailed (asynchronously).
        wait_for_mail(self, email, &format!("/invite#token={token}")).await;
        token
    }

    /// Accept an invite as the signed-in `session`.
    pub async fn accept(&self, token: &str, session: &str, keys: &AllyKeys) -> Resp {
        self.post(
            &format!("/v1/invites/{token}/accept"),
            keys.upload_body(),
            Some(session),
        )
        .await
    }

    /// The member signs an endorsement of the ally's key and the next
    /// manifest (current allies plus this one), and approves.
    pub async fn approve(
        &self,
        member: &UserId,
        member_keys: &MemberKeys,
        member_session: &str,
        ally: &UserId,
        ally_pub: faro_proto::EncPublicKey,
    ) -> Resp {
        let e = self.ally_endorsement(member, member_keys, ally, ally_pub);
        let manifest = match self.latest_manifest(member, member_session).await {
            Some(latest) => {
                member_keys.next_manifest(&latest, |a| a.push((ally.clone(), ally_pub)))
            }
            None => member_keys.manifest(
                &self.instance_id(),
                member,
                1,
                &[(ally.clone(), ally_pub)],
                self.clock_ms(),
            ),
        };
        self.approve_with(member_session, ally, &e, &manifest).await
    }

    pub fn ally_endorsement(
        &self,
        member: &UserId,
        member_keys: &MemberKeys,
        ally: &UserId,
        ally_pub: faro_proto::EncPublicKey,
    ) -> faro_proto::keys::Signed<faro_proto::keys::AllyEndorsement> {
        member_keys.sign.endorse(faro_proto::keys::AllyEndorsement {
            instance_id: self.instance_id(),
            member_id: member.clone(),
            ally_id: ally.clone(),
            ally_enc_pubkey: ally_pub,
            endorsed_at_ms: self.clock_ms(),
        })
    }

    /// `POST …/approve` with an explicit endorsement and manifest.
    pub async fn approve_with<E: serde::Serialize>(
        &self,
        member_session: &str,
        ally: &UserId,
        endorsement: &E,
        manifest: &SignedRecipientManifest,
    ) -> Resp {
        self.post(
            &format!("/v1/me/allies/{ally}/approve"),
            json!({ "endorsement": endorsement, "manifest": manifest }),
            Some(member_session),
        )
        .await
    }

    /// The member removes `ally`, signing the manifest without them.
    pub async fn remove_ally(
        &self,
        member: &UserId,
        member_keys: &MemberKeys,
        member_session: &str,
        ally: &UserId,
    ) -> Resp {
        let latest = self
            .latest_manifest(member, member_session)
            .await
            .expect("member has a manifest");
        let m = member_keys.next_manifest(&latest, |a| a.retain(|(id, _)| id != ally));
        self.call(
            Method::DELETE,
            &format!("/v1/me/allies/{ally}"),
            Some(json!({ "manifest": m })),
            Some(member_session),
        )
        .await
    }

    /// `PUT /v1/me/recipient-manifest`.
    pub async fn put_manifest(&self, session: &str, m: &SignedRecipientManifest) -> Resp {
        self.call(
            Method::PUT,
            "/v1/me/recipient-manifest",
            Some(serde_json::to_value(m).expect("json")),
            Some(session),
        )
        .await
    }

    /// The member's latest manifest as served to `session` (None on 404).
    pub async fn latest_manifest(
        &self,
        member: &UserId,
        session: &str,
    ) -> Option<SignedRecipientManifest> {
        let r = self
            .get(
                &format!("/v1/members/{member}/recipient-manifest"),
                Some(session),
            )
            .await;
        match r.status {
            StatusCode::OK => Some(serde_json::from_value(r.body).expect("manifest")),
            StatusCode::NOT_FOUND => None,
            s => panic!("unexpected {s}: {:?}", r.body),
        }
    }

    /// Invite → sign in → accept → approve. The ally ends up active.
    pub async fn link_ally(
        &self,
        member: &UserId,
        member_keys: &MemberKeys,
        member_session: &str,
        email: &str,
    ) -> Ally {
        let token = self.invite(member_session, email).await;
        let (id, session) = self.sign_in(email).await;
        let keys = AllyKeys::generate();
        let r = self.accept(&token, &session, &keys).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        let r = self
            .approve(member, member_keys, member_session, &id, keys.enc.public())
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        Ally {
            id,
            session,
            keys,
            email: email.to_owned(),
        }
    }

    /// Send a signed heartbeat stamped with the current clock.
    pub async fn heartbeat(&self, dev: &TestDevice, state: faro_proto::api::DeviceState) -> Resp {
        let hb = dev.key.sign_heartbeat(faro_proto::api::Heartbeat {
            instance_id: self.instance_id(),
            device_id: dev.id.clone(),
            ts_ms: self.clock_ms(),
            mono_ms: 1,
            boot_id: "boot-1".into(),
            state,
            last_seq: None,
            last_hash: None,
        });
        self.device_post(dev, "/v1/heartbeat", &hb).await
    }

    /// Feed page for `member` as `session`.
    pub async fn feed(&self, member: &UserId, session: &str) -> Resp {
        self.get(&format!("/v1/ally/feed?member_id={member}"), Some(session))
            .await
    }

    /// Run the notifier's fan-out and immediate sender once.
    pub async fn notify_now(&self) {
        faro_server::notify::dispatch(&self.state)
            .await
            .expect("dispatch");
        faro_server::notify::send_immediate(&self.state)
            .await
            .expect("send");
    }

    /// Let an hour pass, then run fan-out and the digest sender once.
    pub async fn digest_now(&self) -> faro_server::notify::SendSummary {
        faro_server::notify::dispatch(&self.state)
            .await
            .expect("dispatch");
        self.clock
            .advance_ms(i64::try_from(faro_server::notify::DIGEST_INTERVAL_SECS).unwrap() * 1000);
        faro_server::notify::dispatch(&self.state)
            .await
            .expect("dispatch");
        faro_server::notify::send_digests(&self.state)
            .await
            .expect("digest")
    }

    /// Immediate alert emails sent to `to`, oldest first.
    pub fn alert_mail_to(&self, to: &str) -> Vec<faro_server::mailer::Email> {
        self.mail_to(to)
            .into_iter()
            .filter(|m| m.subject.contains("alert for"))
            .collect()
    }

    /// Digest emails sent to `to`, oldest first.
    pub fn digests_to(&self, to: &str) -> Vec<faro_server::mailer::Email> {
        self.mail_to(to)
            .into_iter()
            .filter(|m| m.subject.contains(" digest: "))
            .collect()
    }

    /// Emails sent to `to`, oldest first.
    pub fn mail_to(&self, to: &str) -> Vec<faro_server::mailer::Email> {
        self.mailer
            .sent()
            .into_iter()
            .filter(|m| m.to == to)
            .collect()
    }
}

impl TestDevice {
    /// The next event, encrypted to the member **and** `extra` recipients
    /// (as a real device does after fetching the key directory).
    pub fn next_event_to(
        &mut self,
        kind: EventKind,
        urgency: Urgency,
        plaintext: &[u8],
        extra: &[(UserId, faro_proto::EncPublicKey)],
    ) -> SignedEvent {
        let head = self.head;
        let mut header = EventHeader {
            v: EVENT_HEADER_VERSION,
            instance_id: self.instance_id.clone(),
            device_id: self.id.clone(),
            seq: head.next_seq,
            prev_hash: head.prev_hash,
            ts_ms: 1_800_000_000_000 + i64::try_from(head.next_seq).unwrap_or(0),
            mono_ms: head.next_seq * 1000,
            boot_id: "boot-1".into(),
            kind,
            urgency,
            body_hash: Hash32::ZERO,
            body_len: 0,
        };
        let mut recipients = vec![Recipient {
            user_id: self.member_id.clone(),
            pubkey: self.member_enc,
        }];
        recipients.extend(extra.iter().map(|(u, k)| Recipient {
            user_id: u.clone(),
            pubkey: *k,
        }));
        let body = seal_item(plaintext, &header.body_aad(), &recipients).expect("seal");
        header.body_hash = body.body_hash();
        header.body_len = body.ciphertext.len() as u64;
        let sig = self.key.sign(&header);
        self.head.advance(&header);
        SignedEvent {
            header,
            sig,
            body: Some(body),
        }
    }
}
