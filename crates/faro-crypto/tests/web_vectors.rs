//! Cross-implementation test vectors shared with the web app's TypeScript
//! port of this crate (`web/src/lib/crypto`).
//!
//! `tests/data/web-vectors.json` holds values produced by this crate:
//! canonical encodings, key ids, safety codes, signatures, sealed boxes,
//! encrypted items and passphrase-wrapped secrets. This test checks that the
//! file still matches the Rust implementation, and `npm test` in `web/`
//! checks the TypeScript port against the same file.
//!
//! The `from_web` section goes the other way: secrets the TypeScript code
//! wrapped and signatures it made, which this test opens and verifies.
//! `npm run vectors` in `web/` (re)writes that section.
//!
//! Regenerate the Rust-made part (keeping `from_web`) with
//! `FARO_BLESS=1 cargo test -p faro-crypto --test web_vectors`. Sealed boxes
//! and wrapped secrets are randomized, so blessing changes them; everything
//! else is deterministic.

use faro_crypto::{
    open_item, seal_item, seal_to, unwrap_secret, verify, verify_signed, wrap_secret,
    EncryptionKeypair, KdfParams, Recipient, SigningKey, WrappedSecret,
};
use faro_proto::encoding::{b64_decode, b64_encode};
use faro_proto::keys::{
    key_id, safety_code, AllyEndorsement, AllyKeyRewrap, DeviceEndorsement, KeyRewrap,
    ManifestAlly, ManifestRef, MemberEncKeyBinding, ProvenAllyKeyRewrap, RecipientManifest, Signed,
};
use faro_proto::{event, DeviceId, EncryptedItem, InstanceId, Signature, UserId};
use serde_json::{json, Value};
use std::path::PathBuf;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/web-vectors.json")
}

fn report_aad(instance: &str, device: &str, start: i64, end: i64) -> Vec<u8> {
    faro_proto::encoding::Canonical::new("faro/report-body/v1")
        .str(instance)
        .str(device)
        .i64(start)
        .i64(end)
        .finish()
}

const INSTANCE: &str = "inst_0123456789abcdef";
const MEMBER: &str = "usr_member01";
const ALLY_A: &str = "usr_ally_a";
const ALLY_B: &str = "usr_ally_b";
const DEVICE: &str = "dev_laptop01";

fn member_sign() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}
fn member_enc() -> EncryptionKeypair {
    EncryptionKeypair::from_secret_bytes(&[0x22; 32])
}
fn ally_a() -> EncryptionKeypair {
    EncryptionKeypair::from_secret_bytes(&[0x33; 32])
}
fn ally_b() -> EncryptionKeypair {
    EncryptionKeypair::from_secret_bytes(&[0x44; 32])
}
fn device_sign() -> SigningKey {
    SigningKey::from_bytes(&[0x55; 32])
}

fn manifest() -> RecipientManifest {
    RecipientManifest {
        instance_id: InstanceId::new(INSTANCE),
        member_id: UserId::new(MEMBER),
        version: 3,
        issued_at_ms: 1_790_000_000_123,
        member_enc_pubkey: member_enc().public(),
        allies: vec![
            ManifestAlly {
                ally_id: UserId::new(ALLY_A),
                enc_pubkey: ally_a().public(),
            },
            ManifestAlly {
                ally_id: UserId::new(ALLY_B),
                enc_pubkey: ally_b().public(),
            },
        ],
    }
}

fn device_endorsement() -> DeviceEndorsement {
    DeviceEndorsement {
        instance_id: InstanceId::new(INSTANCE),
        member_id: UserId::new(MEMBER),
        device_id: DeviceId::new(DEVICE),
        device_sign_pubkey: device_sign().public(),
        endorsed_at_ms: 1_790_000_100_000,
        min_manifest: manifest().reference(),
    }
}

fn ally_endorsement() -> AllyEndorsement {
    AllyEndorsement {
        instance_id: InstanceId::new(INSTANCE),
        member_id: UserId::new(MEMBER),
        ally_id: UserId::new(ALLY_A),
        ally_enc_pubkey: ally_a().public(),
        endorsed_at_ms: 1_790_000_200_000,
    }
}

fn member_binding() -> MemberEncKeyBinding {
    MemberEncKeyBinding {
        instance_id: InstanceId::new(INSTANCE),
        member_id: UserId::new(MEMBER),
        member_enc_pubkey: member_enc().public(),
        endorsed_at_ms: 1_790_000_000_000,
    }
}

fn key_rewrap() -> KeyRewrap {
    KeyRewrap {
        instance_id: InstanceId::new(INSTANCE),
        member_id: UserId::new(MEMBER),
        sign_pubkey: member_sign().public(),
        issued_at_ms: 1_790_000_300_000,
        wrapped_sign_key: r#"{"v":1,"note":"pässwörd ✓"}"#.into(),
        wrapped_enc_key: "{}".into(),
        recovery_wrapped: r#"{"sign":{},"enc":{}}"#.into(),
    }
}

fn ally_key_rewrap() -> AllyKeyRewrap {
    AllyKeyRewrap {
        instance_id: InstanceId::new(INSTANCE),
        ally_id: UserId::new(ALLY_A),
        enc_pubkey: ally_a().public(),
        issued_at_ms: 1_790_000_400_000,
        wrapped_privkey: r#"{"v":1,"note":"pässwörd ✓","recovery":{}}"#.into(),
    }
}

/// The challenge the ally key re-wrap vector is proven with.
const REWRAP_CHALLENGE: [u8; 32] = [0x55; 32];

const EVENT_PLAINTEXT: &str = r#"{"type":"flag","rating":"high","reasons":[{"source":"image","label":"explicit","score":0.93}],"app":{"id":"com.apple.Safari","name":"Safari"},"burst":false,"account":"sam"}"#;
const REPORT_PLAINTEXT: &str = r#"{"v":1,"device_id":"dev_laptop01","device_name":"Sam's MacBook","period_start_ms":1790000000000,"period_end_ms":1790086400000,"first_seq":10,"last_seq":42,"timeline":[{"start_ms":1790000000000,"end_ms":1790003600000,"state":"active"}],"counts":{"clean":30,"low":1,"medium":1,"high":0},"flagged":[],"health":{"tamper":[],"context":[],"agent_restarts":0,"capture_failures":0,"unmonitored_secs":0}}"#;

fn signed_json<T: serde::Serialize>(body: T, sig: Signature) -> Value {
    serde_json::to_value(Signed { body, sig }).unwrap()
}

/// The Rust-made part of the file.
fn generate() -> Value {
    let ms = member_sign();
    let m = manifest();
    let de = device_endorsement();
    let ae = ally_endorsement();
    let mb = member_binding();
    let kr = key_rewrap();
    let akr = ally_key_rewrap();
    let recips = |pairs: &[(&str, &EncryptionKeypair)]| -> Vec<Recipient> {
        pairs
            .iter()
            .map(|(id, k)| Recipient {
                user_id: UserId::new(*id),
                pubkey: k.public(),
            })
            .collect()
    };
    let event_aad = event::body_aad(&InstanceId::new(INSTANCE), &DeviceId::new(DEVICE), 17);
    let event_item = seal_item(
        EVENT_PLAINTEXT.as_bytes(),
        &event_aad,
        &recips(&[(MEMBER, &member_enc()), (ALLY_A, &ally_a())]),
    )
    .unwrap();
    let (start, end) = (1_790_000_000_000, 1_790_086_400_000);
    let report_item = seal_item(
        REPORT_PLAINTEXT.as_bytes(),
        &report_aad(INSTANCE, DEVICE, start, end),
        &recips(&[
            (MEMBER, &member_enc()),
            (ALLY_A, &ally_a()),
            (ALLY_B, &ally_b()),
        ]),
    )
    .unwrap();
    let ck = [0x77u8; 32];
    let wrapped_cheap = wrap_secret(&ck, "correct horse battery".as_bytes(), cheap()).unwrap();
    let wrapped_unicode = wrap_secret(&[0x99; 32], "pässwörd ✓".as_bytes(), cheap()).unwrap();
    let a = ally_a().public();
    let msg = b"faro test message";
    json!({
        "comment": "Generated by crates/faro-crypto/tests/web_vectors.rs; checked by that test and by web/src/lib/crypto/vectors.test.ts. Do not edit by hand.",
        "ids": { "instance": INSTANCE, "member": MEMBER, "ally_a": ALLY_A, "ally_b": ALLY_B, "device": DEVICE },
        "canonical": {
            "layout_hex": hex::encode(faro_proto::encoding::Canonical::new("t").u16(1).str("ab").u64(2).i64(-1).fixed(&[0xaa, 0xbb]).finish()),
            "event_body_aad_hex": hex::encode(&event_aad),
            "report_body_aad_hex": hex::encode(report_aad(INSTANCE, DEVICE, start, end)),
        },
        "keys": {
            "member_sign_seed": b64_encode(ms.to_bytes().as_slice()),
            "member_sign_pubkey": ms.public().to_b64(),
            "member_enc_secret": b64_encode(member_enc().secret_bytes().as_slice()),
            "member_enc_pubkey": member_enc().public().to_b64(),
            "ally_a_secret": b64_encode(ally_a().secret_bytes().as_slice()),
            "ally_a_pubkey": a.to_b64(),
            "ally_b_secret": b64_encode(ally_b().secret_bytes().as_slice()),
            "ally_b_pubkey": ally_b().public().to_b64(),
            "device_sign_pubkey": device_sign().public().to_b64(),
        },
        "key_id": [
            { "pubkey": a.to_b64(), "key_id": key_id(a.as_bytes()) },
            { "pubkey": ms.public().to_b64(), "key_id": key_id(ms.public().as_bytes()) },
        ],
        "safety_code": {
            "a": ms.public().to_b64(),
            "b": a.to_b64(),
            "code": safety_code(ms.public().as_bytes(), a.as_bytes()),
        },
        "ed25519": {
            "msg_hex": hex::encode(msg),
            "sig": ms.sign_raw(msg).to_b64(),
        },
        "sealed_box": {
            "recipient_secret": b64_encode(ally_a().secret_bytes().as_slice()),
            "plaintext_hex": hex::encode(ck),
            "sealed": b64_encode(&seal_to(&a, &ck).unwrap()),
        },
        "event_item": {
            "device_id": DEVICE,
            "seq": 17,
            "item": event_item,
            "plaintext": EVENT_PLAINTEXT,
        },
        "report_item": {
            "device_id": DEVICE,
            "period_start_ms": start,
            "period_end_ms": end,
            "item": report_item,
            "plaintext": REPORT_PLAINTEXT,
        },
        "wrapped": [
            { "passphrase": "correct horse battery", "plaintext_hex": hex::encode(ck), "wrapped": wrapped_cheap },
            { "passphrase": "pässwörd ✓", "plaintext_hex": hex::encode([0x99u8; 32]), "wrapped": wrapped_unicode },
        ],
        "manifest": {
            "signed": signed_json(m.clone(), ms.sign(&m)),
            "signing_bytes_hex": hex::encode(m.signing_bytes()),
            "hash": m.hash(),
        },
        "device_endorsement": {
            "signed": signed_json(de.clone(), ms.sign(&de)),
            "signing_bytes_hex": hex::encode(de.signing_bytes()),
        },
        "ally_endorsement": {
            "signed": signed_json(ae.clone(), ms.sign(&ae)),
            "signing_bytes_hex": hex::encode(ae.signing_bytes()),
        },
        "member_binding": {
            "signed": signed_json(mb.clone(), ms.sign(&mb)),
            "signing_bytes_hex": hex::encode(mb.signing_bytes()),
        },
        "key_rewrap": {
            "signed": signed_json(kr.clone(), ms.sign(&kr)),
            "signing_bytes_hex": hex::encode(kr.signing_bytes()),
        },
        "ally_key_rewrap": {
            "challenge_hex": hex::encode(REWRAP_CHALLENGE),
            "proven": ProvenAllyKeyRewrap { proof: akr.proof(&REWRAP_CHALLENGE), body: akr.clone() },
            "proof_bytes_hex": hex::encode(akr.proof_bytes()),
        },
    })
}

/// Cheap enough for a debug-build test, still a real Argon2id run.
fn cheap() -> KdfParams {
    KdfParams {
        m_cost_kib: 256,
        t_cost: 2,
        p_cost: 1,
    }
}

fn s<'a>(v: &'a Value, ptr: &str) -> &'a str {
    v.pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string at {ptr}"))
}

fn b(v: &Value, ptr: &str) -> Vec<u8> {
    b64_decode(s(v, ptr)).unwrap()
}

fn h(v: &Value, ptr: &str) -> Vec<u8> {
    hex::decode(s(v, ptr)).unwrap()
}

#[test]
fn web_vectors() {
    let file = path();
    let existing: Option<Value> = std::fs::read_to_string(&file)
        .ok()
        .map(|t| serde_json::from_str(&t).expect("web-vectors.json parses"));

    if std::env::var_os("FARO_BLESS").is_some() {
        let mut v = generate();
        v["from_web"] = existing
            .as_ref()
            .and_then(|e| e.get("from_web").cloned())
            .unwrap_or(json!(null));
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let v = std::fs::read_to_string(&file)
        .map(|t| serde_json::from_str::<Value>(&t).unwrap())
        .expect("tests/data/web-vectors.json exists (FARO_BLESS=1 writes it)");
    let fresh = generate();

    // Deterministic values match exactly.
    for ptr in [
        "/canonical",
        "/keys",
        "/key_id",
        "/safety_code",
        "/ed25519",
        "/manifest",
        "/device_endorsement",
        "/ally_endorsement",
        "/member_binding",
        "/key_rewrap",
        "/ally_key_rewrap",
    ] {
        assert_eq!(v.pointer(ptr), fresh.pointer(ptr), "{ptr} is stale");
    }

    // Randomized values still open.
    let ally = ally_a();
    assert_eq!(
        &**ally.unseal(&b(&v, "/sealed_box/sealed")).unwrap(),
        h(&v, "/sealed_box/plaintext_hex").as_slice()
    );
    let item: EncryptedItem = serde_json::from_value(v["event_item"]["item"].clone()).unwrap();
    let aad = h(&v, "/canonical/event_body_aad_hex");
    for (id, k) in [(MEMBER, member_enc()), (ALLY_A, ally_a())] {
        let pt = open_item(&item, &aad, &UserId::new(id), &k).unwrap();
        assert_eq!(&**pt, s(&v, "/event_item/plaintext").as_bytes());
    }
    let item: EncryptedItem = serde_json::from_value(v["report_item"]["item"].clone()).unwrap();
    let aad = h(&v, "/canonical/report_body_aad_hex");
    let pt = open_item(&item, &aad, &UserId::new(ALLY_B), &ally_b()).unwrap();
    assert_eq!(&**pt, s(&v, "/report_item/plaintext").as_bytes());
    for w in v["wrapped"].as_array().unwrap() {
        let ws: WrappedSecret = serde_json::from_value(w["wrapped"].clone()).unwrap();
        let pt = unwrap_secret(&ws, s(w, "/passphrase").as_bytes()).unwrap();
        assert_eq!(&**pt, h(w, "/plaintext_hex").as_slice());
    }

    // What the web app produced opens and verifies here.
    let Some(web) = v.get("from_web").filter(|w| !w.is_null()) else {
        panic!("from_web is missing: run `npm run vectors` in web/");
    };
    for w in web["wrapped"].as_array().unwrap() {
        // The web app adds fields to a WrappedSecret (an ally key's
        // `recovery` copy); serde must ignore them.
        let ws: WrappedSecret = serde_json::from_value(w["wrapped"].clone()).unwrap();
        let pt = unwrap_secret(&ws, s(w, "/passphrase").as_bytes()).unwrap();
        assert_eq!(&**pt, h(w, "/plaintext_hex").as_slice());
    }
    let pk = faro_proto::SignPublicKey::from_b64(s(web, "/sign_pubkey")).unwrap();
    let sig = Signature::from_b64(s(web, "/sig")).unwrap();
    verify(&pk, &h(web, "/msg_hex"), &sig).unwrap();
    let m: Signed<RecipientManifest> =
        serde_json::from_value(web["manifest"].clone()).expect("web manifest parses");
    m.body.validate().unwrap();
    verify_signed(&pk, &m).unwrap();
    let de: Signed<DeviceEndorsement> =
        serde_json::from_value(web["device_endorsement"].clone()).unwrap();
    verify_signed(&pk, &de).unwrap();
    assert_eq!(
        de.body.min_manifest,
        ManifestRef {
            version: m.body.version,
            hash: m.body.hash()
        }
    );
    let ae: Signed<AllyEndorsement> =
        serde_json::from_value(web["ally_endorsement"].clone()).unwrap();
    verify_signed(&pk, &ae).unwrap();
    let mb: Signed<MemberEncKeyBinding> =
        serde_json::from_value(web["member_binding"].clone()).unwrap();
    verify_signed(&pk, &mb).unwrap();
    let kr: Signed<KeyRewrap> = serde_json::from_value(web["key_rewrap"].clone()).unwrap();
    verify_signed(&pk, &kr).unwrap();
    let akr: ProvenAllyKeyRewrap =
        serde_json::from_value(web["ally_key_rewrap"]["proven"].clone()).unwrap();
    let challenge: [u8; 32] = h(web, "/ally_key_rewrap/challenge_hex").try_into().unwrap();
    assert_eq!(akr.proof, akr.body.proof(&challenge));
}
