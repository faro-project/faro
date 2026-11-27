//! The instance for `faro-mobile`'s tests, as faro-service's end-to-end
//! tests run it: the real `faro-server` application, built by the server's
//! own integration-test harness (`server/tests/common/mod.rs`, compiled in
//! unchanged), served over TCP on 127.0.0.1 so the core's real reqwest
//! client, request signing and response caps are exercised. The member and
//! the ally are simulated with faro-crypto through that harness.
//!
//! `FaroCore` blocks on its own runtime, so tests call it from a blocking
//! thread ([`blocking`]) while the server runs on the test's runtime.

#![allow(dead_code)] // Not every test binary uses every helper.

use faro_core::Clock;
use faro_mobile::{FaroCore, KeyStore, MemoryKeyStore};
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::{DeviceEndorsement, ManifestRef};
use faro_proto::{SignPublicKey, UserId};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[path = "../../../../server/tests/common/mod.rs"]
pub mod server;

pub use server::{Ally, MemberKeys, TestApp};

pub const ADMIN_EMAIL: &str = "admin@example.org";
pub const MEMBER_EMAIL: &str = "sam@example.org";
pub const ALLY_EMAIL: &str = "alex@example.org";
pub const DEVICE_NAME: &str = "iPhone-Sam";

/// Run `f` (which calls `FaroCore`) on a blocking thread.
pub async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.expect("blocking task")
}

/// The instance with an admin, a member with keys and an approved ally:
/// manifest v1 (member only) then v2 (member and ally).
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
        Self::with_config(|_| {}).await
    }

    pub async fn with_config(tweak: impl FnOnce(&mut faro_server::config::Config)) -> World {
        let t = TestApp::with_config(tweak).await;
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

    /// The member key fingerprint the member's browser puts in the link.
    pub fn member_key_id(&self) -> String {
        faro_proto::keys::key_id(self.member_keys.sign.public().as_bytes())
    }

    /// A fresh enrollment link, with `m` when `member_key` is set.
    pub async fn link(&self, member_key: Option<&str>) -> String {
        let code = self.t.enroll_code(&self.member_session).await;
        let i: String = url::form_urlencoded::byte_serialize(self.url().as_bytes()).collect();
        match member_key {
            Some(m) => format!("faro://enroll?i={i}&c={code}&m={m}"),
            None => format!("faro://enroll?i={i}&c={code}"),
        }
    }

    pub async fn manifest(&self) -> SignedRecipientManifest {
        self.t
            .latest_manifest(&self.member, &self.member_session)
            .await
            .expect("member has a manifest")
    }

    /// The member's browser approves the pending device `device_id`: it
    /// checks the key fingerprint the device shows and signs an
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
        assert_eq!(listed["platform"], "ios");
        assert_eq!(listed["key_id"], fingerprint);
        let device_key: SignPublicKey =
            serde_json::from_value(listed["sign_pubkey"].clone()).expect("sign_pubkey");
        let min_manifest = self.manifest().await.body.reference();
        let e = self.member_keys.sign.endorse(DeviceEndorsement {
            instance_id: self.t.instance_id(),
            member_id: self.member.clone(),
            device_id: faro_proto::DeviceId::new(device_id),
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

    /// The member removes the ally, signing the next manifest without them.
    pub async fn remove_ally(&self) -> SignedRecipientManifest {
        let r = self
            .t
            .remove_ally(
                &self.member,
                &self.member_keys,
                &self.member_session,
                &self.ally.id,
            )
            .await;
        assert_eq!(r.status, axum::http::StatusCode::NO_CONTENT, "{:?}", r.body);
        self.manifest().await
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

    /// Alert kinds raised for the member.
    pub async fn alert_kinds(&self) -> Vec<String> {
        self.t
            .alerts(&self.member)
            .await
            .into_iter()
            .map(|a| a.kind)
            .collect()
    }
}

/// A phone: a data directory (the app group container) and a key store.
pub struct Phone {
    _tmp: tempfile::TempDir,
    pub dir: PathBuf,
    pub keys: Arc<dyn KeyStore>,
}

impl Phone {
    pub fn new() -> Phone {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("group");
        Phone {
            _tmp: tmp,
            dir,
            keys: MemoryKeyStore::new(),
        }
    }

    /// A phone whose key store is `keys` (shared between "processes").
    pub fn with_keys(keys: Arc<dyn KeyStore>) -> Phone {
        let mut p = Phone::new();
        p.keys = keys;
        p
    }

    /// One process's core.
    pub fn core(&self) -> Arc<FaroCore> {
        core_at(&self.dir, self.keys.clone())
    }
}

pub fn core_at(dir: &Path, keys: Arc<dyn KeyStore>) -> Arc<FaroCore> {
    FaroCore::with_options(
        dir.to_owned(),
        keys,
        Arc::new(faro_core::SystemClock::new()) as Arc<dyn Clock>,
        faro_client::ClientOptions {
            product: "faro-ios-test",
            ..faro_client::ClientOptions::default()
        },
    )
    .expect("core opens")
}

/// Enroll `phone` with a link naming the member key, approve it, and
/// return its core and device id.
pub async fn approved_phone(w: &World, phone: &Phone) -> (Arc<FaroCore>, String) {
    approve(w, phone.core()).await
}

/// Enroll `core` with a link naming the member key, approve it, and
/// return it with its device id.
pub async fn approve(w: &World, core: Arc<FaroCore>) -> (Arc<FaroCore>, String) {
    let link = w.link(Some(&w.member_key_id())).await;
    let c = core.clone();
    let preview = blocking(move || c.preview_enrollment(link.clone()).map(|p| (p, link)))
        .await
        .expect("preview");
    let (preview, link) = preview;
    let c = core.clone();
    let enrolled =
        blocking(move || c.enroll(link, DEVICE_NAME.into(), preview.identity_fingerprint))
            .await
            .expect("enroll");
    w.endorse(&enrolled.device_id, &enrolled.device_fingerprint)
        .await;
    let c = core.clone();
    let approval = blocking(move || c.poll_approval()).await.expect("poll");
    assert_eq!(approval, faro_mobile::Approval::Approved);
    (core, enrolled.device_id)
}
