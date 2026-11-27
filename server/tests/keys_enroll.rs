//! Member keys, the key directory, enrollment codes and device endorsement,
//! including the boundaries an instance admin must not be able to cross (§12).

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_crypto::SigningKey;
use faro_proto::api::{DeviceState, Heartbeat, MemberKeysResponse};
use faro_proto::keys::{DeviceEndorsement, KeyRewrap, MemberEncKeyBinding};
use faro_proto::{EventKind, Urgency, UserId};
use serde_json::json;

#[tokio::test]
async fn member_keys_reject_a_bad_binding_signature() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = MemberKeys::generate(&t.instance_id(), &member, t.clock_ms());

    // Signed by a different key than the one being registered.
    let mut body = keys.put_body();
    body["sign_pubkey"] = json!(SigningKey::generate().public());
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "bad_binding_signature");

    // Signature tampered.
    let mut body = keys.put_body();
    let mut b = keys.binding.clone();
    b.body.endorsed_at_ms += 1;
    body["enc_binding"] = serde_json::to_value(&b).unwrap();
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
        .await;
    assert_eq!(r.error_code(), "bad_binding_signature");

    // Correctly signed, but naming someone else / another instance.
    for (inst, mem) in [
        (t.instance_id(), UserId::new("usr_someoneelse")),
        (faro_proto::InstanceId::new("inst_other"), member.clone()),
    ] {
        let bad = keys.sign.endorse(MemberEncKeyBinding {
            instance_id: inst,
            member_id: mem,
            member_enc_pubkey: keys.enc.public(),
            endorsed_at_ms: 1,
        });
        let mut body = keys.put_body();
        body["enc_binding"] = serde_json::to_value(&bad).unwrap();
        let r = t
            .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.error_code(), "binding_mismatch");
    }

    // Unusable keys are refused before anything is stored.
    let mut weak = [0u8; 32];
    weak[0] = 1; // the Ed25519 identity point (small order)
    let mut body = keys.put_body();
    body["sign_pubkey"] = json!(faro_proto::SignPublicKey(weak));
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
        .await;
    assert_eq!(r.error_code(), "invalid_sign_pubkey");
    let weak_enc = keys.sign.endorse(MemberEncKeyBinding {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        member_enc_pubkey: faro_proto::EncPublicKey([0; 32]),
        endorsed_at_ms: 1,
    });
    let mut body = keys.put_body();
    body["enc_binding"] = serde_json::to_value(&weak_enc).unwrap();
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
        .await;
    assert_eq!(r.error_code(), "invalid_enc_pubkey");

    // Opaque blobs must at least be bounded JSON objects.
    let mut body = keys.put_body();
    body["wrapped_sign_key"] = json!("plaintext-seed?");
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(body), Some(&s))
        .await;
    assert_eq!(r.error_code(), "invalid_wrapped_key");

    // Nothing was stored by any of the failures.
    assert_eq!(
        t.get("/v1/me/keys", Some(&s)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn member_keys_roundtrip_and_cannot_be_overwritten() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;

    let r = t.get("/v1/me/keys", Some(&s)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["sign_pubkey"], json!(keys.sign.public()));
    // The wrapped blob comes back intact and still unwraps client-side.
    let ws: faro_crypto::WrappedSecret =
        serde_json::from_value(r.body["wrapped_sign_key"].clone()).unwrap();
    let seed = faro_crypto::unwrap_secret(&ws, b"pass").unwrap();
    assert_eq!(seed.as_slice(), keys.sign.to_bytes().as_slice());
    assert_eq!(
        t.get("/v1/me", Some(&s)).await.body["has_member_keys"],
        true
    );

    let other = MemberKeys::generate(&t.instance_id(), &member, t.clock_ms());
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(other.put_body()), Some(&s))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "keys_already_set");
    assert_eq!(
        t.get("/v1/me/keys", Some(&s)).await.body["sign_pubkey"],
        json!(keys.sign.public())
    );
}

#[tokio::test]
async fn member_keys_require_a_session() {
    let t = TestApp::new().await;
    let keys = MemberKeys::generate(&t.instance_id(), &UserId::new("usr_x"), 0);
    let r = t
        .call(Method::PUT, "/v1/me/keys", Some(keys.put_body()), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_codes_need_member_keys_and_are_single_use() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let r = t.post("/v1/me/enroll-codes", json!({}), Some(&s)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "member_keys_required");

    // Keys alone are not enough: a device bootstraps from (and its
    // endorsement anchors to) the member's recipient manifest.
    let keys = t.create_member_keys_only(&member, &s).await;
    let r = t.post("/v1/me/enroll-codes", json!({}), Some(&s)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "recipient_manifest_required");
    let m = keys.manifest(&t.instance_id(), &member, 1, &[], t.clock_ms());
    assert_eq!(t.put_manifest(&s, &m).await.status, StatusCode::CREATED);

    let r = t.post("/v1/me/enroll-codes", json!({}), Some(&s)).await;
    assert_eq!(r.status, StatusCode::CREATED);
    let code = r.body["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 9);
    assert!(r.body["enroll_url"]
        .as_str()
        .unwrap()
        .starts_with("faro://enroll?i=http%3A%2F%2Flocalhost%3A8080&c="));

    // Typed sloppily (lowercase, no hyphen) still works: Crockford rules.
    let sloppy = code.replace('-', "").to_ascii_lowercase();
    let dev = t.enroll(&sloppy, &keys.enc).await;
    assert_eq!(dev.member_id, member);

    // Used codes are dead.
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code, "sign_pubkey": SigningKey::generate().public(),
                   "platform": "macos", "device_name": "Second", "client_version": "0.1.0"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.error_code(), "invalid_enroll_code");
}

#[tokio::test]
async fn enroll_codes_expire_after_10_minutes() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    t.clock.advance_ms(10 * 60 * 1000 + 1);
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code, "sign_pubkey": SigningKey::generate().public(),
                   "platform": "windows", "device_name": "PC", "client_version": "0.1.0"}),
            None,
        )
        .await;
    assert_eq!(r.error_code(), "invalid_enroll_code");
}

#[tokio::test]
async fn enrollment_validates_input_without_burning_the_code() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    let mut weak = [0u8; 32];
    weak[0] = 1; // small-order point
    for (field, value, err) in [
        ("device_name", json!(""), "invalid_device_name"),
        ("client_version", json!("1 0"), "invalid_client_version"),
        (
            "sign_pubkey",
            json!(faro_proto::SignPublicKey(weak)),
            "invalid_sign_pubkey",
        ),
    ] {
        let mut body = json!({"enroll_code": code, "sign_pubkey": SigningKey::generate().public(),
                              "platform": "linux", "device_name": "Box", "client_version": "0.1.0"});
        body[field] = value;
        let r = t.post("/v1/devices/enroll", body, None).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{field}");
        assert_eq!(r.error_code(), err);
    }
    // The code still works.
    let dev = t.enroll(&code, &keys.enc).await;

    // Re-enrolling the same device key with a new code is refused.
    let code2 = t.enroll_code(&s).await;
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code2, "sign_pubkey": dev.key.public(),
                   "platform": "linux", "device_name": "Box", "client_version": "0.1.0"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "device_key_in_use");
}

#[tokio::test]
async fn an_iphone_enrolls_and_is_listed_as_ios() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    let key = SigningKey::generate();
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code, "sign_pubkey": key.public(),
                   "platform": "ios", "device_name": "iPhone-X", "client_version": "0.1.0"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let list = t.get("/v1/me/devices", Some(&s)).await;
    assert_eq!(list.body[0]["platform"], "ios");
    assert_eq!(list.body[0]["name"], "iPhone-X");
    assert_eq!(list.body[0]["status"], "pending_endorsement");

    // An unknown platform is still refused.
    let code = t.enroll_code(&s).await;
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code, "sign_pubkey": SigningKey::generate().public(),
                   "platform": "plan9", "device_name": "Box", "client_version": "0.1.0"}),
            None,
        )
        .await;
    assert!(r.status.is_client_error(), "{:?}", r.body);
    let _ = keys;
}

#[tokio::test]
async fn an_android_phone_enrolls_and_is_listed_as_android() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    let key = SigningKey::generate();
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({"enroll_code": code, "sign_pubkey": key.public(),
                   "platform": "android", "device_name": "Pixel-8", "client_version": "0.1.0-beta.1"}),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let list = t.get("/v1/me/devices", Some(&s)).await;
    assert_eq!(list.body[0]["platform"], "android");
    assert_eq!(list.body[0]["name"], "Pixel-8");
    assert_eq!(list.body[0]["status"], "pending_endorsement");
    let _ = keys;
}

#[tokio::test]
async fn enroll_then_endorse() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    let mut dev = t.enroll(&code, &keys.enc).await;
    assert_eq!(dev.member_id, member);

    // The member sees the pending device with its key fingerprint.
    let list = t.get("/v1/me/devices", Some(&s)).await;
    assert_eq!(list.body[0]["status"], "pending_endorsement");
    assert_eq!(
        list.body[0]["key_id"],
        faro_proto::keys::key_id(dev.key.public().as_bytes())
    );

    // A pending device may heartbeat, fetch its status and fetch keys...
    let hb = dev.key.sign_heartbeat(Heartbeat {
        instance_id: t.instance_id(),
        device_id: dev.id.clone(),
        ts_ms: t.clock_ms(),
        mono_ms: 5,
        boot_id: "boot-1".into(),
        state: DeviceState::Active,
        last_seq: None,
        last_hash: None,
    });
    assert_eq!(
        t.device_post(&dev, "/v1/heartbeat", &hb).await.status,
        StatusCode::OK
    );
    let me = t
        .device_call(&dev, Method::GET, "/v1/devices/self", b"")
        .await;
    assert_eq!(me.body["status"], "pending_endorsement");
    let k = t
        .device_call(
            &dev,
            Method::GET,
            &format!("/v1/members/{member}/keys"),
            b"",
        )
        .await;
    assert_eq!(k.status, StatusCode::OK);
    // ...but not put anything into the accountability record.
    let ev = dev.next_event(EventKind::Boot, Urgency::None);
    let r = t.post_events(&dev, &[ev]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "device_pending_endorsement");

    // Endorsement for the wrong key is refused.
    let anchor = t
        .latest_manifest(&member, &s)
        .await
        .unwrap()
        .body
        .reference();
    let wrong = keys.sign.endorse(DeviceEndorsement {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        device_sign_pubkey: SigningKey::generate().public(),
        endorsed_at_ms: 1,
        min_manifest: anchor,
    });
    let r = t
        .post(
            &format!("/v1/devices/{}/endorse", dev.id),
            serde_json::to_value(wrong).unwrap(),
            Some(&s),
        )
        .await;
    assert_eq!(r.error_code(), "endorsement_mismatch");

    // Right content, wrong signer (e.g. the instance trying to vouch).
    let forged = SigningKey::generate().endorse(DeviceEndorsement {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        device_sign_pubkey: dev.key.public(),
        endorsed_at_ms: 1,
        min_manifest: anchor,
    });
    let r = t
        .post(
            &format!("/v1/devices/{}/endorse", dev.id),
            serde_json::to_value(forged).unwrap(),
            Some(&s),
        )
        .await;
    assert_eq!(r.error_code(), "bad_endorsement_signature");

    let r = t.endorse(&dev, &keys, &s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["status"], "active");
    let r = t.endorse(&dev, &keys, &s).await;
    assert_eq!(r.error_code(), "already_endorsed");

    // The device can now fetch and verify its endorsement.
    let me = t
        .device_call(&dev, Method::GET, "/v1/devices/self", b"")
        .await;
    assert_eq!(me.body["status"], "active");
    let e: faro_proto::keys::Signed<DeviceEndorsement> =
        serde_json::from_value(me.body["endorsement"].clone()).unwrap();
    faro_crypto::verify_signed(&keys.sign.public(), &e).unwrap();
    // ... including the bootstrap anchor it needs before its first manifest.
    assert_eq!(e.body.min_manifest, anchor);
    assert_eq!(me.body["min_manifest"], json!(anchor));

    let ev = dev.next_event(EventKind::Boot, Urgency::None);
    assert_eq!(t.post_events(&dev, &[ev]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn key_directory_serves_the_member_binding() {
    let t = TestApp::new().await;
    let (member, s, keys, dev) = t.active_device().await;
    let r = t
        .device_call(
            &dev,
            Method::GET,
            &format!("/v1/members/{member}/keys"),
            b"",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let mk: MemberKeysResponse = serde_json::from_value(r.body).unwrap();
    assert_eq!(mk.member_sign_pubkey, keys.sign.public());
    faro_crypto::verify_signed(&mk.member_sign_pubkey, &mk.member_enc_key).unwrap();
    assert!(mk.allies.is_empty(), "no allies until stage B links them");
    // The member can read their own directory too.
    let r = t.get(&format!("/v1/members/{member}/keys"), Some(&s)).await;
    assert_eq!(r.status, StatusCode::OK);
}

#[tokio::test]
async fn an_admin_cannot_endorse_or_read_another_members_devices_and_keys() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    // The admin is also a member with their own keys.
    let admin_keys = {
        let id = UserId::new(
            t.get("/v1/me", Some(&admin_s)).await.body["user"]["id"]
                .as_str()
                .unwrap(),
        );
        t.create_member_keys(&id, &admin_s).await
    };

    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    let code = t.enroll_code(&s).await;
    let dev = t.enroll(&code, &keys.enc).await;

    // Endorsing someone else's device: indistinguishable from a missing one,
    // whether signed with the admin's key or with anything else.
    let e = admin_keys.sign.endorse(DeviceEndorsement {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        device_sign_pubkey: dev.key.public(),
        endorsed_at_ms: 1,
        min_manifest: t
            .latest_manifest(&member, &s)
            .await
            .unwrap()
            .body
            .reference(),
    });
    let r = t
        .post(
            &format!("/v1/devices/{}/endorse", dev.id),
            serde_json::to_value(&e).unwrap(),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The device is still pending.
    assert_eq!(
        t.get("/v1/me/devices", Some(&s)).await.body[0]["status"],
        "pending_endorsement"
    );

    // Reading the member's key directory or listing their devices: nothing.
    let r = t
        .get(&format!("/v1/members/{member}/keys"), Some(&admin_s))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t.get("/v1/me/devices", Some(&admin_s)).await;
    assert_eq!(r.body, json!([]));

    // An admin's enroll code enrolls devices for the admin only.
    let admin_code = t.enroll_code(&admin_s).await;
    let admin_dev = t.enroll(&admin_code, &admin_keys.enc).await;
    assert_ne!(admin_dev.member_id, member);

    // Another member's device cannot read this member's keys either.
    let r = t
        .device_call(
            &admin_dev,
            Method::GET,
            &format!("/v1/members/{member}/keys"),
            b"",
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn too_many_outstanding_codes_are_refused() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    t.create_member_keys(&member, &s).await;
    for _ in 0..5 {
        t.enroll_code(&s).await;
    }
    let r = t.post("/v1/me/enroll-codes", json!({}), Some(&s)).await;
    assert_eq!(r.error_code(), "too_many_codes");
    t.clock.advance_ms(10 * 60 * 1000 + 1);
    t.enroll_code(&s).await;
}

/// A signed `PUT /v1/me/keys/wrapped` body re-wrapping `keys` under `pass`.
fn rewrap_body(
    t: &TestApp,
    member: &UserId,
    keys: &MemberKeys,
    signer: &SigningKey,
    pass: &[u8],
    issued_at_ms: i64,
) -> serde_json::Value {
    let p = faro_crypto::KdfParams::insecure_for_tests();
    let ws = faro_crypto::wrap_secret(keys.sign.to_bytes().as_slice(), pass, p).unwrap();
    let we = faro_crypto::wrap_secret(keys.enc.secret_bytes().as_slice(), pass, p).unwrap();
    let rewrap = KeyRewrap {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        sign_pubkey: keys.sign.public(),
        issued_at_ms,
        wrapped_sign_key: serde_json::to_string(&ws).unwrap(),
        wrapped_enc_key: serde_json::to_string(&we).unwrap(),
        recovery_wrapped: json!({ "sign": ws, "enc": we }).to_string(),
    };
    serde_json::to_value(signer.endorse(rewrap)).unwrap()
}

#[tokio::test]
async fn members_can_rewrap_their_keys_with_a_signed_request() {
    let t = TestApp::new().await;
    let (member, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys(&member, &s).await;
    t.clock.advance_ms(1_000);
    let now = t.clock_ms();

    let put = |body| t.call(Method::PUT, "/v1/me/keys/wrapped", Some(body), Some(&s));

    let r = put(rewrap_body(
        &t,
        &member,
        &keys,
        &keys.sign,
        b"new pass",
        now,
    ))
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let stored = t.get("/v1/me/keys", Some(&s)).await;
    let w: faro_crypto::WrappedSecret =
        serde_json::from_value(stored.body["wrapped_sign_key"].clone()).unwrap();
    assert_eq!(
        &**faro_crypto::unwrap_secret(&w, b"new pass").unwrap(),
        keys.sign.to_bytes().as_slice()
    );
    // The public keys and their binding are untouched.
    assert_eq!(stored.body["sign_pubkey"], json!(keys.sign.public()));

    // Replaying it, or an older request, can't restore an old passphrase.
    let r = put(rewrap_body(
        &t,
        &member,
        &keys,
        &keys.sign,
        b"new pass",
        now,
    ))
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "stale_request");
    let r = put(rewrap_body(
        &t,
        &member,
        &keys,
        &keys.sign,
        b"old",
        now - 10,
    ))
    .await;
    assert_eq!(r.error_code(), "stale_request");

    // Too far from the server's clock.
    let r = put(rewrap_body(
        &t,
        &member,
        &keys,
        &keys.sign,
        b"x",
        now + 10 * 60_000,
    ))
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "stale_request");

    // A session alone (any other key) can't do it.
    let other = SigningKey::generate();
    let r = put(rewrap_body(&t, &member, &keys, &other, b"x", now + 1)).await;
    assert_eq!(r.error_code(), "bad_rewrap_signature");

    // Changing a signed field breaks the signature.
    let mut body = rewrap_body(&t, &member, &keys, &keys.sign, b"x", now + 2);
    body["wrapped_enc_key"] = json!(body["wrapped_sign_key"].clone());
    let r = put(body).await;
    assert_eq!(r.error_code(), "bad_rewrap_signature");

    // Naming another member is refused before anything else.
    let mut body = rewrap_body(&t, &member, &keys, &keys.sign, b"x", now + 3);
    body["member_id"] = json!("usr_someoneelse");
    let r = put(body).await;
    assert_eq!(r.error_code(), "rewrap_mismatch");

    // The wrapped values must be JSON objects, even when properly signed.
    let rewrap = KeyRewrap {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        sign_pubkey: keys.sign.public(),
        issued_at_ms: now + 4,
        wrapped_sign_key: "\"just a string\"".into(),
        wrapped_enc_key: "{}".into(),
        recovery_wrapped: "{}".into(),
    };
    let r = put(serde_json::to_value(keys.sign.endorse(rewrap)).unwrap()).await;
    assert_eq!(r.error_code(), "invalid_wrapped_key");
}
