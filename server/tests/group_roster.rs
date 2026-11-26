//! The group roster log, snapshots and epoch keys (docs/GROUPS.md §10.3,
//! §10.5, §19 "Phase C"): what the instance accepts and serves, and that it
//! stops serving a departed participant at once.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_crypto::roster::{apply_entry, new_epoch, open_epoch_key, seal_epoch_key};
use faro_crypto::{EncryptionKeypair, SigningKey};
use faro_proto::encoding::{b64_decode, b64_encode};
use faro_proto::keys::Signed;
use faro_proto::roster::{RosterChange, RosterEntry, RosterState};
use faro_proto::{Hash32, UserId};
use serde_json::{json, Value};

struct Person {
    id: UserId,
    s: String,
    email: String,
}

async fn person(t: &TestApp, name: &str) -> Person {
    let email = format!("{name}@example.org");
    let (id, s) = t.sign_in(&email).await;
    Person { id, s, email }
}

async fn group_by(t: &TestApp, f: &Person) -> String {
    let r = t
        .post("/v1/groups", json!({ "name": "Tuesday" }), Some(&f.s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

async fn join(t: &TestApp, by: &Person, gid: &str, p: &Person) {
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [p.email] }),
            Some(&by.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    wait_for_mail(t, &p.email, "/group-invite#token=").await;
    let token = token_from_email(r.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    let a = t
        .post(
            &format!("/v1/group-invites/{token}/accept"),
            json!({}),
            Some(&p.s),
        )
        .await;
    assert_eq!(a.status, StatusCode::CREATED, "{:?}", a.body);
}

/// An encryption key for someone with none (`PUT /v1/me/ally-key`).
async fn enc_key(t: &TestApp, p: &Person) -> EncryptionKeypair {
    let k = AllyKeys::generate();
    let r = t
        .call(
            Method::PUT,
            "/v1/me/ally-key",
            Some(k.upload_body()),
            Some(&p.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    k.enc
}

/// The roster as a client sees it: every entry replayed and verified.
async fn roster(t: &TestApp, gid: &str, as_: &Person) -> RosterState {
    let mut state = RosterState::new(t.instance_id(), gid.to_owned());
    let mut after: Option<u64> = None;
    loop {
        let path = match after {
            Some(a) => format!("/v1/groups/{gid}/roster?after_seq={a}"),
            None => format!("/v1/groups/{gid}/roster"),
        };
        let r = t.get(&path, Some(&as_.s)).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        for e in r.body["entries"].as_array().unwrap() {
            let signed: Signed<RosterEntry> = serde_json::from_value(e.clone()).unwrap();
            apply_entry(&mut state, &signed).unwrap();
            after = Some(signed.body.seq);
        }
        if !r.body["more"].as_bool().unwrap() {
            return state;
        }
    }
}

async fn pending(t: &TestApp, gid: &str, as_: &Person) -> Value {
    let r = t
        .get(&format!("/v1/groups/{gid}/roster/pending"), Some(&as_.s))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body
}

/// An entry extending `state` with `changes`, rotating if they need it.
fn entry(
    t: &TestApp,
    state: &RosterState,
    signer: &UserId,
    changes: Vec<RosterChange>,
) -> (RosterEntry, Option<[u8; 32]>) {
    let rotate = changes.iter().any(RosterChange::needs_rotation);
    let (key, epoch) = if rotate {
        let (k, r) = new_epoch(&t.instance_id(), &state.group_id, state.epoch + 1);
        (Some(*k), Some(r))
    } else {
        (None, None)
    };
    (
        RosterEntry {
            instance_id: t.instance_id(),
            group_id: state.group_id.clone(),
            seq: state.next_seq,
            prev_hash: state.head,
            at_ms: t.clock_ms(),
            signer: signer.clone(),
            changes,
            epoch,
        },
        key,
    )
}

/// Seal `key` to everyone in the roster after `e`.
fn sealed_for(state: &RosterState, e: &Signed<RosterEntry>, key: &[u8; 32]) -> Vec<Value> {
    let mut after = state.clone();
    apply_entry(&mut after, e).unwrap();
    after
        .members
        .values()
        .map(|m| {
            json!({
                "user_id": m.user_id,
                "sealed_key": b64_encode(&seal_epoch_key(key, &m.enc_pubkey).unwrap()),
            })
        })
        .collect()
}

async fn post_entry(
    t: &TestApp,
    gid: &str,
    by: &Person,
    e: &Signed<RosterEntry>,
    keys: Vec<Value>,
) -> Resp {
    t.post(
        &format!("/v1/groups/{gid}/roster"),
        json!({ "entry": e, "epoch_keys": keys }),
        Some(&by.s),
    )
    .await
}

/// What a facilitator's client does on opening the group: sign everything
/// pending, one entry per round, until nothing is left. Returns the keys of
/// the epochs it started.
async fn sign_pending(t: &TestApp, gid: &str, f: &Person, sk: &SigningKey) -> Vec<(u64, [u8; 32])> {
    let mut keys = Vec::new();
    for _ in 0..5 {
        let p = pending(t, gid, f).await;
        let changes: Vec<RosterChange> = serde_json::from_value(p["changes"].clone()).unwrap();
        if changes.is_empty() {
            break;
        }
        let state = roster(t, gid, f).await;
        let (e, key) = entry(t, &state, &f.id, changes);
        let signed = sk.endorse(e);
        let sealed = key
            .map(|k| sealed_for(&state, &signed, &k))
            .unwrap_or_default();
        let r = post_entry(t, gid, f, &signed, sealed).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        if let (Some(k), Some(rot)) = (key, signed.body.epoch) {
            keys.push((rot.epoch, k));
        }
    }
    keys
}

async fn my_epoch_key(t: &TestApp, gid: &str, p: &Person, epoch: Option<u64>) -> Resp {
    let path = match epoch {
        Some(n) => format!("/v1/groups/{gid}/epoch-key?epoch={n}"),
        None => format!("/v1/groups/{gid}/epoch-key"),
    };
    t.get(&path, Some(&p.s)).await
}

#[tokio::test]
async fn genesis_join_leave_and_epoch_keys() {
    let t = TestApp::new().await;
    let f = person(&t, "fac").await;
    let fk = t.create_member_keys(&f.id, &f.s).await;
    let gid = group_by(&t, &f).await;

    // Before the first entry: the creator's join is pending.
    let p = pending(&t, &gid, &f).await;
    assert!(p["head"].is_null());
    assert_eq!(p["changes"].as_array().unwrap().len(), 1);
    assert_eq!(p["changes"][0]["kind"], "join");
    assert_eq!(p["changes"][0]["role"], "facilitator");

    let keys = sign_pending(&t, &gid, &f, &fk.sign).await;
    assert_eq!(keys.len(), 1);
    let state = roster(&t, &gid, &f).await;
    assert_eq!(state.next_seq, 1);
    assert_eq!(state.epoch, 1);

    // The facilitator's epoch key opens against the signed commitment.
    let r = my_epoch_key(&t, &gid, &f, None).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let sealed = b64_decode(r.body["sealed_key"].as_str().unwrap()).unwrap();
    let k = open_epoch_key(
        &fk.enc,
        &sealed,
        &t.instance_id(),
        &gid,
        1,
        &state.epoch_key_check,
    )
    .unwrap();
    assert_eq!(*k, keys[0].1);

    // Someone with no keys joins: they can't be added until they make an
    // encryption key; then their join is pending, and signing it rotates.
    let a = person(&t, "ally").await;
    join(&t, &f, &gid, &a).await;
    let p = pending(&t, &gid, &f).await;
    assert_eq!(p["waiting_for_keys"][0], a.id.as_str());
    assert!(p["changes"].as_array().unwrap().is_empty());
    let ak = enc_key(&t, &a).await;
    let p = pending(&t, &gid, &f).await;
    assert_eq!(p["changes"][0]["kind"], "join");
    assert_eq!(
        p["posting_paused"], false,
        "a pending join doesn't pause posting"
    );
    let keys = sign_pending(&t, &gid, &f, &fk.sign).await;
    assert_eq!(keys[0].0, 2);
    let state = roster(&t, &gid, &a).await;
    assert_eq!(state.members.len(), 2);

    // The joiner gets the new epoch only.
    let r = my_epoch_key(&t, &gid, &a, None).await;
    assert_eq!(r.body["epoch"], 2);
    let sealed = b64_decode(r.body["sealed_key"].as_str().unwrap()).unwrap();
    open_epoch_key(
        &ak,
        &sealed,
        &t.instance_id(),
        &gid,
        2,
        &state.epoch_key_check,
    )
    .unwrap();
    assert_eq!(
        my_epoch_key(&t, &gid, &a, Some(1)).await.status,
        StatusCode::NOT_FOUND
    );

    // They leave: at once, nothing in the group is served to them, before
    // any facilitator has signed anything.
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/groups/{gid}/me"),
            None,
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    for path in [
        format!("/v1/groups/{gid}/roster"),
        format!("/v1/groups/{gid}/roster/pending"),
        format!("/v1/groups/{gid}/epoch-key"),
        format!("/v1/groups/{gid}/epoch-key?epoch=2"),
    ] {
        assert_eq!(
            t.get(&path, Some(&a.s)).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let p = pending(&t, &gid, &f).await;
    assert_eq!(p["posting_paused"], true);
    assert_eq!(p["changes"][0]["kind"], "leave");

    // A rotation that still seals to them is refused.
    let state = roster(&t, &gid, &f).await;
    let (e, key) = entry(&t, &state, &f.id, vec![]);
    let e = RosterEntry {
        epoch: Some(new_epoch(&t.instance_id(), &gid, 3).1),
        ..e
    };
    assert!(key.is_none());
    let signed = fk.sign.endorse(e);
    let r = post_entry(&t, &gid, &f, &signed, sealed_for(&state, &signed, &[1; 32])).await;
    assert_eq!(r.error_code(), "roster_still_lists_departed");

    let keys = sign_pending(&t, &gid, &f, &fk.sign).await;
    assert_eq!(keys[0].0, 3);
    let state = roster(&t, &gid, &f).await;
    assert_eq!(state.members.len(), 1);
    assert_eq!(pending(&t, &gid, &f).await["posting_paused"], false);
}

#[tokio::test]
async fn the_instance_refuses_bad_entries() {
    let t = TestApp::new().await;
    let f = person(&t, "fac").await;
    let fk = t.create_member_keys(&f.id, &f.s).await;
    let gid = group_by(&t, &f).await;
    let m = person(&t, "member").await;
    let mk = t.create_member_keys(&m.id, &m.s).await;
    join(&t, &f, &gid, &m).await;
    sign_pending(&t, &gid, &f, &fk.sign).await;
    let state = roster(&t, &gid, &f).await;
    assert_eq!(state.members.len(), 2);

    // A participant can't post, even a well-signed entry.
    let (e, _) = entry(
        &t,
        &state,
        &m.id,
        vec![RosterChange::Role {
            user_id: m.id.clone(),
            role: faro_proto::roster::GroupRole::Facilitator,
        }],
    );
    let r = post_entry(&t, &gid, &m, &mk.sign.endorse(e), vec![]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // Adding a reader the group doesn't have (as a compromised client or
    // instance would): refused.
    let evil = EncryptionKeypair::generate();
    let add = vec![RosterChange::Join {
        user_id: UserId::new("usr_evil"),
        role: faro_proto::roster::GroupRole::Participant,
        enc_pubkey: evil.public(),
        sign_pubkey: None,
    }];
    let (e, key) = entry(&t, &state, &f.id, add);
    let signed = fk.sign.endorse(e);
    let r = post_entry(
        &t,
        &gid,
        &f,
        &signed,
        sealed_for(&state, &signed, &key.unwrap()),
    )
    .await;
    assert_eq!(r.error_code(), "roster_not_participant");

    // A forged signature, a fork and a rollback.
    let role = vec![RosterChange::Role {
        user_id: m.id.clone(),
        role: faro_proto::roster::GroupRole::Facilitator,
    }];
    let (e, _) = entry(&t, &state, &f.id, role.clone());
    let r = post_entry(&t, &gid, &f, &mk.sign.endorse(e.clone()), vec![]).await;
    assert_eq!(r.error_code(), "invalid_roster_entry");
    let forked = RosterEntry {
        prev_hash: Hash32::ZERO,
        ..e.clone()
    };
    let r = post_entry(&t, &gid, &f, &fk.sign.endorse(forked), vec![]).await;
    assert_eq!(r.error_code(), "roster_conflict");
    let old = RosterEntry {
        seq: 0,
        ..e.clone()
    };
    let r = post_entry(&t, &gid, &f, &fk.sign.endorse(old), vec![]).await;
    assert_eq!(r.error_code(), "roster_conflict");
    // A role the group doesn't have.
    let r = post_entry(&t, &gid, &f, &fk.sign.endorse(e), vec![]).await;
    assert_eq!(r.error_code(), "roster_keys_mismatch");

    // A rotation must seal to everyone.
    let (e, key) = entry(&t, &state, &f.id, vec![]);
    assert!(key.is_none());
    let e = RosterEntry {
        epoch: Some(new_epoch(&t.instance_id(), &gid, state.epoch + 1).1),
        ..e
    };
    let signed = fk.sign.endorse(e);
    let mut sealed = sealed_for(&state, &signed, &[2; 32]);
    sealed.pop();
    let r = post_entry(&t, &gid, &f, &signed, sealed).await;
    assert_eq!(r.error_code(), "invalid_epoch_keys");
    let r = post_entry(&t, &gid, &f, &signed, sealed_for(&state, &signed, &[2; 32])).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // The same entry again is a conflict.
    let r = post_entry(&t, &gid, &f, &signed, sealed_for(&state, &signed, &[2; 32])).await;
    assert_eq!(r.error_code(), "roster_conflict");
}

#[tokio::test]
async fn snapshots_and_ally_only_facilitators() {
    let t = TestApp::new().await;
    let f = person(&t, "fac").await;
    let fk = t.create_member_keys(&f.id, &f.s).await;
    let gid = group_by(&t, &f).await;
    let a = person(&t, "ally").await;
    join(&t, &f, &gid, &a).await;
    let ak = enc_key(&t, &a).await;
    sign_pending(&t, &gid, &f, &fk.sign).await;

    // A snapshot at the head.
    let state = roster(&t, &gid, &f).await;
    let snap = fk
        .sign
        .endorse(state.snapshot(t.clock_ms(), f.id.clone()).unwrap());
    let r = t
        .post(
            &format!("/v1/groups/{gid}/roster/snapshot"),
            serde_json::to_value(&snap).unwrap(),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = t
        .get(&format!("/v1/groups/{gid}/roster/snapshot"), Some(&a.s))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let back: Signed<faro_proto::roster::RosterSnapshot> =
        serde_json::from_value(r.body.clone()).unwrap();
    assert_eq!(faro_crypto::roster::verify_snapshot(&back).unwrap(), state);
    assert_eq!(roster_page(&t, &gid, &a).await["latest_snapshot_seq"], 0);
    // One that isn't the head's roster is refused.
    let mut wrong = state.snapshot(t.clock_ms(), f.id.clone()).unwrap();
    wrong.members.retain(|m| m.user_id == f.id);
    let r = t
        .post(
            &format!("/v1/groups/{gid}/roster/snapshot"),
            serde_json::to_value(fk.sign.endorse(wrong)).unwrap(),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.error_code(), "roster_conflict");

    // The ally becomes a facilitator and makes a group signing key, sealed
    // to their encryption key; the role and the key go into the roster.
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/groups/{gid}/participants/{}/role", a.id),
            Some(json!({ "facilitator": true })),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let sk = SigningKey::generate();
    let body = json!({
        "sign_pubkey": sk.public(),
        "enc_pubkey": ak.public(),
        "sealed_seed": b64_encode(&faro_crypto::seal_to(&ak.public(), sk.to_bytes().as_slice()).unwrap()),
    });
    // Sealed to some other key: refused.
    let mut other = body.clone();
    other["enc_pubkey"] = json!(EncryptionKeypair::generate().public());
    let r = t
        .call(
            Method::PUT,
            "/v1/me/group-sign-key",
            Some(other),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.error_code(), "enc_key_mismatch");
    let r = t
        .call(
            Method::PUT,
            "/v1/me/group-sign-key",
            Some(body.clone()),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = t.get("/v1/me/group-sign-key", Some(&a.s)).await;
    let sealed = b64_decode(r.body["sealed_seed"].as_str().unwrap()).unwrap();
    assert_eq!(
        ak.unseal(&sealed).unwrap().as_slice(),
        sk.to_bytes().as_slice()
    );
    // Members use their member key.
    let r = t
        .call(Method::PUT, "/v1/me/group-sign-key", Some(body), Some(&f.s))
        .await;
    assert_eq!(r.error_code(), "has_member_keys");

    // Keys first (a key change rotates), then the role, in two rounds.
    let p = pending(&t, &gid, &f).await;
    assert_eq!(p["changes"][0]["kind"], "keys");
    sign_pending(&t, &gid, &f, &fk.sign).await;
    let state = roster(&t, &gid, &a).await;
    assert!(state.is_facilitator(&a.id));
    assert_eq!(state.member(&a.id).unwrap().sign_pubkey, Some(sk.public()));

    // Now the ally-only facilitator can sign: the original one leaves
    // (after stepping down is impossible as the last one, they are not).
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/groups/{gid}/me"),
            None,
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let a_as_f = Person {
        id: a.id.clone(),
        s: a.s.clone(),
        email: a.email.clone(),
    };
    let keys = sign_pending(&t, &gid, &a_as_f, &sk).await;
    assert_eq!(keys.len(), 1);
    let state = roster(&t, &gid, &a).await;
    assert_eq!(state.members.len(), 1);

    // An encryption key can be created once.
    let r = t
        .call(
            Method::PUT,
            "/v1/me/ally-key",
            Some(AllyKeys::generate().upload_body()),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.error_code(), "ally_key_exists");
}

async fn roster_page(t: &TestApp, gid: &str, p: &Person) -> Value {
    t.get(&format!("/v1/groups/{gid}/roster"), Some(&p.s))
        .await
        .body
}
