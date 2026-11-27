//! Roster helpers for the group tests: what a facilitator's browser does to
//! sign pending work, and what any participant's does to read the roster.

#![allow(dead_code)] // Not every test binary uses every helper.

use super::TestApp;
use faro_crypto::roster::{apply_entry, new_epoch, seal_epoch_key};
use faro_crypto::SigningKey;
use faro_proto::encoding::b64_encode;
use faro_proto::keys::Signed;
use faro_proto::roster::{RosterChange, RosterEntry, RosterState};
use faro_proto::UserId;
use serde_json::{json, Value};

/// The roster as a client sees it: every entry replayed and verified.
pub async fn roster(t: &TestApp, gid: &str, session: &str) -> RosterState {
    let mut state = RosterState::new(t.instance_id(), gid.to_owned());
    let mut after: Option<u64> = None;
    loop {
        let path = match after {
            Some(a) => format!("/v1/groups/{gid}/roster?after_seq={a}"),
            None => format!("/v1/groups/{gid}/roster"),
        };
        let r = t.get(&path, Some(session)).await;
        assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
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

pub async fn pending(t: &TestApp, gid: &str, session: &str) -> Value {
    let r = t
        .get(&format!("/v1/groups/{gid}/roster/pending"), Some(session))
        .await;
    assert_eq!(r.status, axum::http::StatusCode::OK, "{:?}", r.body);
    r.body
}

/// An entry extending `state` with `changes`, rotating if they need it.
pub fn entry(
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
pub fn sealed_for(state: &RosterState, e: &Signed<RosterEntry>, key: &[u8; 32]) -> Vec<Value> {
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

/// What a facilitator's client does on opening the group: sign everything
/// pending, one entry per round, until nothing is left. Returns the keys of
/// the epochs it started.
pub async fn sign_pending(
    t: &TestApp,
    gid: &str,
    f: (&UserId, &str),
    sk: &SigningKey,
) -> Vec<(u64, [u8; 32])> {
    let mut keys = Vec::new();
    for _ in 0..8 {
        let p = pending(t, gid, f.1).await;
        let changes: Vec<RosterChange> = serde_json::from_value(p["changes"].clone()).unwrap();
        if changes.is_empty() {
            break;
        }
        let state = roster(t, gid, f.1).await;
        let (e, key) = entry(t, &state, f.0, changes);
        let signed = sk.endorse(e);
        let sealed = key
            .map(|k| sealed_for(&state, &signed, &k))
            .unwrap_or_default();
        let r = t
            .post(
                &format!("/v1/groups/{gid}/roster"),
                json!({ "entry": signed, "epoch_keys": sealed }),
                Some(f.1),
            )
            .await;
        assert_eq!(r.status, axum::http::StatusCode::CREATED, "{:?}", r.body);
        if let (Some(k), Some(rot)) = (key, signed.body.epoch) {
            keys.push((rot.epoch, k));
        }
    }
    keys
}
