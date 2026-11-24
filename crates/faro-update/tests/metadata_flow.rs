//! End-to-end and adversarial tests for root / timestamp / targets
//! verification.

mod common;

use common::*;
use faro_crypto::SigningKey;
use faro_proto::encoding::b64_encode;
use faro_update::{
    Channel, Envelope, EnvelopeSignature, MetadataSigner, Role, RoleKeys, TargetKind, TrustedState,
    UpdateError, Updater, MAX_SIGNATURES,
};
use proptest::prelude::*;

// ---------------------------------------------------------------- happy path

#[test]
fn happy_path_end_to_end() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + 7 * DAY);

    let ts = up.verify_timestamp(&rel.timestamp, T0).unwrap();
    assert_eq!(ts.version, 1);
    let vt = up.verify_targets(&rel.targets, T0).unwrap();
    let pick = vt
        .select(
            &Channel::stable(),
            TargetKind::Client,
            "macos",
            "aarch64",
            None,
        )
        .unwrap();
    assert_eq!(pick.name, "client/macos/aarch64/faro.pkg");
    faro_update::verify_target_stream(&b"payload v1"[..], &pick, 1 << 20).unwrap();

    let st = up.state();
    assert_eq!(st.timestamp().unwrap().version, 1);
    assert_eq!(st.targets().unwrap().version, 1);
    assert_eq!(st.max_observed_ms(), T0);
}

#[test]
fn state_survives_serde_roundtrip_and_keeps_protections() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let r2 = release(&keys, 2, 2, T0 + 7 * DAY);
    up.verify_timestamp(&r2.timestamp, T0).unwrap();
    up.verify_targets(&r2.targets, T0).unwrap();

    let json = serde_json::to_string(up.state()).unwrap();
    let restored: TrustedState = serde_json::from_str(&json).unwrap();
    assert_eq!(&restored, up.state());
    let mut up2 = Updater::from_state(restored);

    // Rollback protection survived the restart.
    let r1 = release(&keys, 1, 1, T0 + 7 * DAY);
    assert!(matches!(
        up2.verify_timestamp(&r1.timestamp, T0),
        Err(UpdateError::Rollback {
            role: Role::Timestamp,
            ..
        })
    ));
    // Cached copies re-verify idempotently.
    up2.verify_timestamp(&r2.timestamp, T0).unwrap();
    up2.verify_targets(&r2.targets, T0).unwrap();
}

#[test]
fn targets_before_timestamp_is_refused() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    assert_eq!(
        up.verify_targets(&rel.targets, T0).unwrap_err(),
        UpdateError::NoTrustedTimestamp
    );
}

// ------------------------------------------------------------ thresholds

#[test]
fn root_threshold_not_met() {
    let keys = KeySet::new();
    let root = keys.root_meta(1, T0 + DAY);
    let one_sig = sign_root(&root, &[&keys.root[0]]);
    assert_eq!(
        Updater::bootstrap(&one_sig).unwrap_err(),
        UpdateError::ThresholdNotMet {
            role: Role::Root,
            valid: 1,
            threshold: 2
        }
    );
    let no_sig = sign_root(&root, &[]);
    assert!(matches!(
        Updater::bootstrap(&no_sig),
        Err(UpdateError::ThresholdNotMet { valid: 0, .. })
    ));
}

#[test]
fn duplicate_signatures_by_one_key_count_once() {
    let keys = KeySet::new();
    let root = keys.root_meta(1, T0 + DAY);
    let mut env: Envelope = serde_json::from_slice(&sign_root(&root, &[&keys.root[0]])).unwrap();
    let dup = env.signatures[0].clone();
    env.signatures.push(dup.clone());
    env.signatures.push(dup);
    assert!(matches!(
        Updater::bootstrap(&env.to_bytes()),
        Err(UpdateError::ThresholdNotMet {
            valid: 1,
            threshold: 2,
            ..
        })
    ));
}

#[test]
fn signature_by_key_of_wrong_role_does_not_count() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let targets = sign_targets(&simple_targets(1, T0 + DAY), &keys.targets);
    let ts = timestamp_for(1, T0 + DAY, &targets, 1);

    // Signed by the targets key, a root key, and an unknown key: all valid
    // Ed25519 signatures, none from the timestamp role.
    let outsider = SigningKey::generate();
    let env = MetadataSigner::new([&keys.targets, &keys.root[0], &keys.root[1], &outsider])
        .sign_to_bytes(&ts)
        .unwrap();
    assert!(matches!(
        up.verify_timestamp(&env, T0),
        Err(UpdateError::ThresholdNotMet {
            role: Role::Timestamp,
            valid: 0,
            ..
        })
    ));

    // Targets signed by the timestamp key, committed to by a valid timestamp.
    let bad_targets = sign_targets(&simple_targets(1, T0 + DAY), &keys.timestamp);
    let ts = sign_ts(
        &timestamp_for(1, T0 + DAY, &bad_targets, 1),
        &keys.timestamp,
    );
    up.verify_timestamp(&ts, T0).unwrap();
    assert!(matches!(
        up.verify_targets(&bad_targets, T0),
        Err(UpdateError::ThresholdNotMet {
            role: Role::Targets,
            ..
        })
    ));
}

#[test]
fn signature_entry_claiming_another_keys_id_does_not_count() {
    // An attacker labels their own signature with the timestamp key's id.
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let attacker = SigningKey::generate();
    let targets = sign_targets(&simple_targets(1, T0 + DAY), &keys.targets);
    let ts = timestamp_for(1, T0 + DAY, &targets, 1);
    let mut env = MetadataSigner::new([&attacker]).sign(&ts).unwrap();
    env.signatures[0].keyid = id(&keys.timestamp);
    assert!(matches!(
        up.verify_timestamp(&env.to_bytes(), T0),
        Err(UpdateError::ThresholdNotMet { valid: 0, .. })
    ));
}

#[test]
fn garbage_signature_entries_are_ignored() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    let mut env: Envelope = serde_json::from_slice(&rel.timestamp).unwrap();
    env.signatures.insert(
        0,
        EnvelopeSignature {
            keyid: "zz".into(),
            sig: "%%%".into(),
        },
    );
    env.signatures.push(EnvelopeSignature {
        keyid: id(&keys.timestamp),
        sig: b64_encode(b"short"),
    });
    up.verify_timestamp(&env.to_bytes(), T0).unwrap();
}

#[test]
fn signature_flood_is_rejected() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    let mut env: Envelope = serde_json::from_slice(&rel.timestamp).unwrap();
    for i in 0..MAX_SIGNATURES {
        env.signatures.push(EnvelopeSignature {
            keyid: format!("{i:016x}"),
            sig: String::new(),
        });
    }
    assert!(matches!(
        up.verify_timestamp(&env.to_bytes(), T0),
        Err(UpdateError::TooManySignatures { .. })
    ));
}

// ------------------------------------------------- payload type & tampering

#[test]
fn wrong_payload_type_rejected() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let targets = sign_targets(&simple_targets(1, T0 + DAY), &keys.targets);
    let ts = timestamp_for(1, T0 + DAY, &targets, 1);
    // Valid timestamp payload, signed by the timestamp key, but labelled as targets.
    let payload = serde_json::to_vec(&ts).unwrap();
    let env = Envelope::sign_raw(Role::Targets.payload_type(), &payload, &[&keys.timestamp]);
    assert!(matches!(
        up.verify_timestamp(&env.to_bytes(), T0),
        Err(UpdateError::WrongPayloadType { .. })
    ));
    // A targets envelope fed to verify_timestamp.
    assert!(matches!(
        up.verify_timestamp(&targets, T0),
        Err(UpdateError::WrongPayloadType { .. })
    ));
}

#[test]
fn tampered_payload_rejected() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    let mut env: Envelope = serde_json::from_slice(&rel.timestamp).unwrap();
    let mut ts: faro_update::Timestamp =
        serde_json::from_slice(&env.unverified_payload().unwrap()).unwrap();
    ts.expires_ms += 365 * DAY;
    env.payload = b64_encode(&serde_json::to_vec(&ts).unwrap());
    assert!(matches!(
        up.verify_timestamp(&env.to_bytes(), T0),
        Err(UpdateError::ThresholdNotMet { valid: 0, .. })
    ));
    assert!(up.state().timestamp().is_none());
}

#[test]
fn malformed_and_oversized_envelopes() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    assert!(matches!(
        up.verify_timestamp(b"{not json", T0),
        Err(UpdateError::MalformedEnvelope { .. })
    ));
    assert!(matches!(
        up.verify_timestamp(br#"{"payload_type":"application/vnd.faro.timestamp+json","payload":"!!","signatures":[]}"#, T0),
        Err(UpdateError::MalformedEnvelope { .. })
    ));
    let huge = vec![b'x'; 1 << 20];
    assert!(matches!(
        up.verify_timestamp(&huge, T0),
        Err(UpdateError::TooLarge { .. })
    ));
    assert!(matches!(
        up.update_root(&vec![b' '; 2 << 20]),
        Err(UpdateError::TooLarge { .. })
    ));
}

#[test]
fn signed_payload_with_unknown_fields_rejected() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let targets = sign_targets(&simple_targets(1, T0 + DAY), &keys.targets);
    let mut v = serde_json::to_value(timestamp_for(1, T0 + DAY, &targets, 1)).unwrap();
    v["consistent_snapshot"] = serde_json::Value::Bool(true);
    let env = sign_unchecked(Role::Timestamp, &v, &[&keys.timestamp]);
    assert!(matches!(
        up.verify_timestamp(&env, T0),
        Err(UpdateError::InvalidMetadata {
            role: Role::Timestamp,
            ..
        })
    ));
}

// --------------------------------------------------------------- root rules

#[test]
fn root_with_mismatched_key_id_rejected() {
    let keys = KeySet::new();
    let mut root = keys.root_meta(1, T0 + DAY);
    // Re-point the targets key id at an attacker key.
    let attacker = SigningKey::generate();
    root.keys.insert(id(&keys.targets), attacker.public());
    let bytes = sign_unchecked(Role::Root, &root, &keys.root_refs());
    assert!(matches!(
        Updater::bootstrap(&bytes),
        Err(UpdateError::InvalidMetadata {
            role: Role::Root,
            ..
        })
    ));
}

#[test]
fn root_with_bad_thresholds_rejected_and_signer_refuses() {
    let keys = KeySet::new();
    for mutate in [
        (|r: &mut faro_update::Root| r.roles.timestamp.threshold = 0) as fn(&mut faro_update::Root),
        |r| r.roles.root.threshold = 4,
        |r| r.roles.targets.keyids.push("0000000000000000".into()),
        |r| {
            let dup = r.roles.root.keyids[0].clone();
            r.roles.root.keyids.push(dup);
        },
        |r| r.version = 0,
    ] {
        let mut root = keys.root_meta(1, T0 + DAY);
        mutate(&mut root);
        assert!(MetadataSigner::new(keys.root_refs()).sign(&root).is_err());
        let bytes = sign_unchecked(Role::Root, &root, &keys.root_refs());
        assert!(
            Updater::bootstrap(&bytes).is_err(),
            "accepted invalid root {root:?}"
        );
    }
}

#[test]
fn root_rotation_one_two_three() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);

    // v2: rotate one root key and the timestamp key, threshold unchanged.
    let mut k2 = KeySet::new();
    k2.root[0] = SigningKey::from_bytes(&k1.root[0].to_bytes());
    k2.root[1] = SigningKey::from_bytes(&k1.root[1].to_bytes());
    k2.targets = SigningKey::from_bytes(&k1.targets.to_bytes());
    let root2 = k2.root_meta(2, T0 + 365 * DAY);
    // Signed by old threshold (k1 root 0,1 are shared) and new threshold.
    let r2 = sign_root(&root2, &[&k1.root[0], &k1.root[1], &k2.root[2]]);
    up.update_root(&r2).unwrap();
    assert_eq!(up.state().root().version, 2);

    // v3: completely new key set, 3-of-3 root.
    let mut k3 = KeySet::new();
    k3.root_threshold = 3;
    let root3 = k3.root_meta(3, T0 + 365 * DAY);
    let mut signers: Vec<&SigningKey> = k2.root_refs();
    signers.extend(k3.root_refs());
    up.update_root(&sign_root(&root3, &signers)).unwrap();
    assert_eq!(up.state().root().version, 3);

    // Old timestamp key no longer counts; new one does.
    let old = release(&k1, 1, 1, T0 + DAY);
    assert!(matches!(
        up.verify_timestamp(&old.timestamp, T0),
        Err(UpdateError::ThresholdNotMet { .. })
    ));
    let new = release(&k3, 1, 1, T0 + DAY);
    up.verify_timestamp(&new.timestamp, T0).unwrap();
    up.verify_targets(&new.targets, T0).unwrap();

    // A mirror replaying root v2 now is refused (v3's keys never signed it;
    // the same-keys rollback case is covered by
    // `rotation_version_must_be_exactly_next`).
    let before = up.state().clone();
    assert!(matches!(
        up.update_root(&r2),
        Err(UpdateError::ThresholdNotMet {
            role: Role::Root,
            ..
        })
    ));
    assert_eq!(up.state(), &before);
}

#[test]
fn rotation_requires_new_root_threshold() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let k2 = KeySet::new();
    let root2 = k2.root_meta(2, T0 + DAY);
    // Old threshold yes, new: only one of three.
    let bytes = sign_root(&root2, &[&k1.root[0], &k1.root[1], &k2.root[0]]);
    let before = up.state().clone();
    assert!(matches!(
        up.update_root(&bytes),
        Err(UpdateError::ThresholdNotMet {
            role: Role::Root,
            valid: 1,
            ..
        })
    ));
    assert_eq!(up.state(), &before);
}

#[test]
fn rotation_requires_old_root_threshold() {
    // Attacker holds one old root key and generates a fresh new root set.
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let k2 = KeySet::new();
    let root2 = k2.root_meta(2, T0 + DAY);
    let mut signers = vec![&k1.root[0]];
    signers.extend(k2.root_refs());
    assert!(matches!(
        up.update_root(&sign_root(&root2, &signers)),
        Err(UpdateError::ThresholdNotMet {
            role: Role::Root,
            valid: 1,
            ..
        })
    ));
    assert_eq!(up.state().root().version, 1);
}

#[test]
fn rotation_version_must_be_exactly_next() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let all = k1.root_refs();
    for (v, expect_skip) in [(3u64, true), (1, false), (u64::MAX, true)] {
        let r = k1.root_meta(v, T0 + DAY);
        let err = up.update_root(&sign_root(&r, &all)).unwrap_err();
        if expect_skip {
            assert_eq!(
                err,
                UpdateError::RootVersionSkip {
                    expected: 2,
                    offered: v
                }
            );
        } else {
            assert!(matches!(
                err,
                UpdateError::Rollback {
                    role: Role::Root,
                    ..
                }
            ));
        }
    }
    // Intermediate roots may be expired; freshness is checked later.
    let r2 = k1.root_meta(2, T0 - DAY);
    up.update_root(&sign_root(&r2, &all)).unwrap();
    let rel = release(&k1, 1, 1, T0 + DAY);
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, T0),
        Err(UpdateError::Expired {
            role: Role::Root,
            ..
        })
    ));
    let r3 = k1.root_meta(3, T0 + DAY);
    up.update_root(&sign_root(&r3, &all)).unwrap();
    up.verify_timestamp(&rel.timestamp, T0).unwrap();
}

#[test]
fn timestamp_key_compromise_is_recoverable_by_rotation() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let honest = release(&k1, 1, 1, T0 + DAY);
    up.verify_timestamp(&honest.timestamp, T0).unwrap();
    up.verify_targets(&honest.targets, T0).unwrap();
    // Attacker with the online timestamp key fast-forwards clients.
    let ff = timestamp_for(u64::MAX - 1, T0 + DAY, &honest.targets, 1);
    up.verify_timestamp(&sign_ts(&ff, &k1.timestamp), T0)
        .unwrap();
    // The legitimate v2 is now locked out...
    let next = release(&k1, 2, 2, T0 + DAY);
    assert!(matches!(
        up.verify_timestamp(&next.timestamp, T0),
        Err(UpdateError::Rollback { .. })
    ));
    // ...until the project rotates the timestamp key.
    let mut k2 = KeySet::new();
    k2.root = k1
        .root
        .iter()
        .map(|k| SigningKey::from_bytes(&k.to_bytes()))
        .collect();
    k2.targets = SigningKey::from_bytes(&k1.targets.to_bytes());
    up.update_root(&sign_root(&k2.root_meta(2, T0 + DAY), &k2.root_refs()))
        .unwrap();
    assert!(up.state().timestamp().is_none());
    // Targets key unchanged, so its rollback record is kept.
    assert_eq!(up.state().targets().map(|t| t.version), Some(1));
    let rel = release(&k2, 1, 2, T0 + DAY);
    up.verify_timestamp(&rel.timestamp, T0).unwrap();
    up.verify_targets(&rel.targets, T0).unwrap();
}

#[test]
fn rotation_keeping_online_keys_keeps_rollback_records() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let r5 = release(&k1, 5, 5, T0 + DAY);
    up.verify_timestamp(&r5.timestamp, T0).unwrap();
    up.verify_targets(&r5.targets, T0).unwrap();
    // Rotate only the root keys.
    let mut k2 = KeySet::new();
    k2.targets = SigningKey::from_bytes(&k1.targets.to_bytes());
    k2.timestamp = SigningKey::from_bytes(&k1.timestamp.to_bytes());
    let mut signers = k1.root_refs();
    signers.extend(k2.root_refs());
    up.update_root(&sign_root(&k2.root_meta(2, T0 + DAY), &signers))
        .unwrap();
    assert_eq!(up.state().timestamp().map(|t| t.version), Some(5));
    let old = release(&k1, 4, 4, T0 + DAY);
    assert!(matches!(
        up.verify_timestamp(&old.timestamp, T0),
        Err(UpdateError::Rollback { .. })
    ));
}

// ----------------------------------------------------------------- expiry

#[test]
fn expired_timestamp_targets_and_root() {
    let keys = KeySet::new();

    // Timestamp expired.
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0);
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, T0),
        Err(UpdateError::Expired {
            role: Role::Timestamp,
            ..
        })
    ));

    // Targets expired while the timestamp is fresh.
    let mut up = updater(&keys);
    let targets = sign_targets(&simple_targets(1, T0 - 1), &keys.targets);
    let ts = sign_ts(&timestamp_for(1, T0 + DAY, &targets, 1), &keys.timestamp);
    up.verify_timestamp(&ts, T0).unwrap();
    assert!(matches!(
        up.verify_targets(&targets, T0),
        Err(UpdateError::Expired {
            role: Role::Targets,
            ..
        })
    ));

    // Timestamp expired between verifying it and verifying targets.
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + 10);
    up.verify_timestamp(&rel.timestamp, T0).unwrap();
    assert!(matches!(
        up.verify_targets(&rel.targets, T0 + 10),
        Err(UpdateError::Expired {
            role: Role::Timestamp,
            ..
        })
    ));

    // Root expired (bootstrap itself tolerates that, by design).
    let root = keys.root_meta(1, T0 - 1);
    let mut up = Updater::bootstrap(&sign_root(&root, &keys.root_refs())).unwrap();
    let rel = release(&keys, 1, 1, T0 + DAY);
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, T0),
        Err(UpdateError::Expired {
            role: Role::Root,
            ..
        })
    ));
}

#[test]
fn clock_rolled_back_after_seeing_later_time() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    up.verify_timestamp(&rel.timestamp, T0).unwrap();

    // Two days later the mirror still serves v1 (a freeze); it's expired.
    let later = T0 + 2 * DAY;
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, later),
        Err(UpdateError::Expired {
            role: Role::Timestamp,
            ..
        })
    ));
    // The mark is pinned at the (signed) expiry, not at the raw clock.
    assert_eq!(up.state().max_observed_ms(), T0 + DAY);

    // The clock is wound back to T0: the frozen timestamp stays expired,
    // and so do its targets.
    let err = up.verify_timestamp(&rel.timestamp, T0).unwrap_err();
    assert_eq!(
        err,
        UpdateError::Expired {
            role: Role::Timestamp,
            expires_ms: T0 + DAY,
            now_ms: T0 + DAY
        }
    );
    assert!(matches!(
        up.verify_targets(&rel.targets, T0),
        Err(UpdateError::Expired { .. })
    ));
    // Survives persistence (the state is persisted after errors too, as
    // the docs require, because the rejection is what raised the mark).
    let st: TrustedState =
        serde_json::from_str(&serde_json::to_string(up.state()).unwrap()).unwrap();
    let mut up2 = Updater::from_state(st);
    assert!(up2.verify_timestamp(&rel.timestamp, T0).is_err());
    // The admin escape hatch restores the raw clock.
    let mut st = up2.into_state();
    st.clear_observed_time();
    let mut up3 = Updater::from_state(st);
    up3.verify_timestamp(&rel.timestamp, T0).unwrap();
}

#[test]
fn far_future_clock_cannot_block_updates_beyond_next_timestamp() {
    // Regression: the mark used to be raised to the raw clock, so a single
    // update check with the clock set to ~2100 made every later document
    // look expired for decades.
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let r1 = release(&keys, 1, 1, T0 + 7 * DAY);
    let far = T0 + 30_000 * DAY;
    assert!(matches!(
        up.verify_timestamp(&r1.timestamp, far),
        Err(UpdateError::Expired { .. })
    ));
    assert_eq!(up.state().max_observed_ms(), T0 + 7 * DAY);
    // Clock corrected: r1 itself stays dead (it *was* seen past expiry, and
    // the rollback guarantee holds) ...
    assert!(matches!(
        up.verify_timestamp(&r1.timestamp, T0),
        Err(UpdateError::Expired {
            role: Role::Timestamp,
            ..
        })
    ));
    // ... but the project's next timestamp, expiring later, is accepted.
    let r2 = release(&keys, 2, 2, T0 + 8 * DAY);
    up.verify_timestamp(&r2.timestamp, T0).unwrap();
    up.verify_targets(&r2.targets, T0).unwrap();
}

#[test]
fn far_future_clock_during_targets_is_capped_by_timestamp_expiry() {
    // Targets live for weeks, timestamps for a day. A far-future clock while
    // verifying targets must not pin the mark at the targets' expiry.
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let targets = sign_targets(&simple_targets(1, T0 + 30 * DAY), &keys.targets);
    let ts = sign_ts(&timestamp_for(1, T0 + DAY, &targets, 1), &keys.timestamp);
    up.verify_timestamp(&ts, T0).unwrap();
    assert!(up.verify_targets(&targets, T0 + 30_000 * DAY).is_err());
    assert_eq!(up.state().max_observed_ms(), T0 + DAY);
    // The next day's timestamp for the same targets works with a sane clock.
    let ts2 = sign_ts(
        &timestamp_for(2, T0 + 2 * DAY, &targets, 1),
        &keys.timestamp,
    );
    up.verify_timestamp(&ts2, T0).unwrap();
    up.verify_targets(&targets, T0).unwrap();
}

#[test]
fn root_seen_expired_stays_expired_after_clock_rollback() {
    let keys = KeySet::new();
    let root = keys.root_meta(1, T0 + DAY);
    let mut up = Updater::bootstrap(&sign_root(&root, &keys.root_refs())).unwrap();
    let rel = release(&keys, 1, 1, T0 + 10 * DAY);
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, T0 + 2 * DAY),
        Err(UpdateError::Expired {
            role: Role::Root,
            ..
        })
    ));
    assert!(matches!(
        up.verify_timestamp(&rel.timestamp, T0),
        Err(UpdateError::Expired {
            role: Role::Root,
            ..
        })
    ));
}

#[test]
fn unauthenticated_input_does_not_advance_observed_time() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let rel = release(&keys, 1, 1, T0 + DAY);
    let attacker = SigningKey::generate();
    let forged = sign_ts(&timestamp_for(1, T0 + DAY, &rel.targets, 1), &attacker);
    assert!(up.verify_timestamp(&forged, T0 + 100 * DAY).is_err());
    assert_eq!(up.state().max_observed_ms(), i64::MIN);
    up.verify_timestamp(&rel.timestamp, T0).unwrap();
}

// ---------------------------------------------------------------- rollback

#[test]
fn timestamp_rollback_and_equivocation() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let r2 = release(&keys, 2, 2, T0 + DAY);
    up.verify_timestamp(&r2.timestamp, T0).unwrap();

    let r1 = release(&keys, 1, 1, T0 + DAY);
    assert_eq!(
        up.verify_timestamp(&r1.timestamp, T0).unwrap_err(),
        UpdateError::Rollback {
            role: Role::Timestamp,
            trusted: 2,
            offered: 1
        }
    );
    // Same version, different content (longer expiry).
    let r2b = release(&keys, 2, 2, T0 + 2 * DAY);
    assert_eq!(
        up.verify_timestamp(&r2b.timestamp, T0).unwrap_err(),
        UpdateError::Equivocation {
            role: Role::Timestamp,
            version: 2
        }
    );
    // Same content re-signed with signatures re-ordered / duplicated is fine.
    let mut env: Envelope = serde_json::from_slice(&r2.timestamp).unwrap();
    let s = env.signatures[0].clone();
    env.signatures.push(s);
    up.verify_timestamp(&env.to_bytes(), T0).unwrap();
}

#[test]
fn targets_rollback_via_timestamp_and_directly() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let r3 = release(&keys, 3, 3, T0 + DAY);
    up.verify_timestamp(&r3.timestamp, T0).unwrap();
    up.verify_targets(&r3.targets, T0).unwrap();

    // A newer timestamp that commits to older targets.
    let old_targets = sign_targets(&simple_targets(2, T0 + DAY), &keys.targets);
    let ts4 = sign_ts(
        &timestamp_for(4, T0 + DAY, &old_targets, 2),
        &keys.timestamp,
    );
    assert_eq!(
        up.verify_timestamp(&ts4, T0).unwrap_err(),
        UpdateError::Rollback {
            role: Role::Targets,
            trusted: 3,
            offered: 2
        }
    );
    // A newer timestamp committing to a *different* targets v3.
    let other3 = sign_targets(&simple_targets(3, T0 + 2 * DAY), &keys.targets);
    let ts5 = sign_ts(&timestamp_for(5, T0 + DAY, &other3, 3), &keys.timestamp);
    assert_eq!(
        up.verify_timestamp(&ts5, T0).unwrap_err(),
        UpdateError::Equivocation {
            role: Role::Targets,
            version: 3
        }
    );
}

#[test]
fn malicious_mirror_replays_old_validly_signed_metadata() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    // Every release the project ever made is still within its expiry, so
    // the mirror has a full archive of genuinely signed, fresh documents.
    let archive: Vec<Release> = (1..=5)
        .map(|v| release(&keys, v, v, T0 + 30 * DAY))
        .collect();
    up.verify_timestamp(&archive[4].timestamp, T0).unwrap();
    up.verify_targets(&archive[4].targets, T0).unwrap();
    let snapshot = up.state().clone();

    for old in &archive[..4] {
        assert!(matches!(
            up.verify_timestamp(&old.timestamp, T0 + 1),
            Err(UpdateError::Rollback {
                role: Role::Timestamp,
                ..
            })
        ));
        // Old targets with the current timestamp: mix-and-match.
        assert!(matches!(
            up.verify_targets(&old.targets, T0 + 1),
            Err(UpdateError::TimestampMismatch(_))
        ));
    }
    // Nothing the mirror did changed what we trust (observed time aside).
    assert_eq!(up.state().timestamp(), snapshot.timestamp());
    assert_eq!(up.state().targets(), snapshot.targets());
    assert_eq!(up.state().root(), snapshot.root());
}

#[test]
fn mix_and_match_rejected() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let a = release(&keys, 1, 1, T0 + DAY);
    up.verify_timestamp(&a.timestamp, T0).unwrap();

    // Validly signed targets with the same version but different contents.
    let mut t = simple_targets(1, T0 + DAY);
    t.expires_ms += 1;
    let b_targets = sign_targets(&t, &keys.targets);
    assert!(matches!(
        up.verify_targets(&b_targets, T0),
        Err(UpdateError::TimestampMismatch(_))
    ));
    // Same length, one byte changed.
    let mut flipped = a.targets.clone();
    let i = flipped.len() / 2;
    flipped[i] ^= 0x01;
    assert!(matches!(
        up.verify_targets(&flipped, T0),
        Err(UpdateError::TimestampMismatch(_))
    ));
    // Timestamp commits to the right bytes but the wrong version number.
    let ts = sign_ts(&timestamp_for(2, T0 + DAY, &a.targets, 7), &keys.timestamp);
    up.verify_timestamp(&ts, T0).unwrap();
    assert!(matches!(
        up.verify_targets(&a.targets, T0),
        Err(UpdateError::TimestampMismatch(_))
    ));
}

#[test]
fn invalid_targets_contents_rejected_even_when_signed() {
    let keys = KeySet::new();
    let mut up = updater(&keys);
    let mut t = simple_targets(1, T0 + DAY);
    let f = t.targets.values().next().unwrap().clone();
    t.targets.insert("../../etc/evil".into(), f);
    let bytes = sign_unchecked(Role::Targets, &t, &[&keys.targets]);
    let ts = sign_ts(&timestamp_for(1, T0 + DAY, &bytes, 1), &keys.timestamp);
    up.verify_timestamp(&ts, T0).unwrap();
    assert!(matches!(
        up.verify_targets(&bytes, T0),
        Err(UpdateError::InvalidMetadata {
            role: Role::Targets,
            ..
        })
    ));
}

#[test]
fn adding_an_online_key_keeps_rollback_records() {
    // Regression: any change to a role's key set (even a pure addition)
    // used to discard its rollback records, letting a mirror replay an
    // older, still-unexpired timestamp right after a routine rotation.
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let archive: Vec<Release> = (1..=9).map(|v| release(&k1, v, v, T0 + 30 * DAY)).collect();
    up.verify_timestamp(&archive[8].timestamp, T0).unwrap();
    up.verify_targets(&archive[8].targets, T0).unwrap();

    let extra_ts = SigningKey::generate();
    let extra_targets = SigningKey::generate();
    let mut root2 = k1.root_meta(2, T0 + 365 * DAY);
    root2.keys.insert(id(&extra_ts), extra_ts.public());
    root2
        .keys
        .insert(id(&extra_targets), extra_targets.public());
    root2.roles.timestamp = RoleKeys::new(ids(&[&k1.timestamp, &extra_ts]), 1);
    root2.roles.targets = RoleKeys::new(ids(&[&k1.targets, &extra_targets]), 2);
    up.update_root(&sign_root(&root2, &k1.root_refs())).unwrap();
    assert_eq!(up.state().timestamp().map(|t| t.version), Some(9));
    assert_eq!(up.state().targets().map(|t| t.version), Some(9));

    assert!(matches!(
        up.verify_timestamp(&archive[3].timestamp, T0),
        Err(UpdateError::Rollback {
            role: Role::Timestamp,
            trusted: 9,
            offered: 4
        })
    ));
    assert_eq!(up.state().timestamp().map(|t| t.version), Some(9));

    // Lowering a threshold is not a revocation either.
    let mut root3 = root2.clone();
    root3.version = 3;
    root3.roles.targets.threshold = 1;
    up.update_root(&sign_root(&root3, &k1.root_refs())).unwrap();
    assert_eq!(up.state().targets().map(|t| t.version), Some(9));
    assert_eq!(up.state().timestamp().map(|t| t.version), Some(9));

    // Removing the original timestamp key *is* a revocation: the timestamp
    // record (only) is reset so the remaining key can take over.
    let mut root4 = root3.clone();
    root4.version = 4;
    root4.roles.timestamp = RoleKeys::new(ids(&[&extra_ts]), 1);
    up.update_root(&sign_root(&root4, &k1.root_refs())).unwrap();
    assert!(up.state().timestamp().is_none());
    assert_eq!(up.state().targets().map(|t| t.version), Some(9));
}

#[test]
fn role_keys_order_does_not_matter_for_rotation_detection() {
    let k1 = KeySet::new();
    let mut up = updater(&k1);
    let r = release(&k1, 3, 3, T0 + DAY);
    up.verify_timestamp(&r.timestamp, T0).unwrap();
    let mut root2 = k1.root_meta(2, T0 + DAY);
    root2.roles.root.keyids.reverse();
    root2.roles.timestamp = RoleKeys::new(root2.roles.timestamp.keyids.clone(), 1);
    up.update_root(&sign_root(&root2, &k1.root_refs())).unwrap();
    assert_eq!(up.state().timestamp().map(|t| t.version), Some(3));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Any single-byte corruption of a signed timestamp either is rejected
    /// or (e.g. whitespace in the JSON wrapper) yields exactly the original
    /// timestamp. Corruption can never change what is accepted.
    #[test]
    fn corrupted_timestamp_never_changes_meaning(idx in any::<prop::sample::Index>(), xor in 1u8..=255) {
        let keys = KeySet::new();
        let rel = release(&keys, 1, 1, T0 + DAY);
        let mut good = updater(&keys);
        let expected = good.verify_timestamp(&rel.timestamp, T0).unwrap();
        let mut bytes = rel.timestamp.clone();
        let i = idx.index(bytes.len());
        bytes[i] ^= xor;
        let mut up = updater(&keys);
        if let Ok(got) = up.verify_timestamp(&bytes, T0) {
            prop_assert_eq!(got, expected);
        }
    }

    /// Arbitrary bytes never panic any entry point.
    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let keys = KeySet::new();
        let mut up = updater(&keys);
        let _ = up.update_root(&data);
        let _ = up.verify_timestamp(&data, T0);
        let _ = Updater::bootstrap(&data);
    }

    /// Arbitrary bytes that a genuine timestamp commits to get past the
    /// length/hash gate and reach the targets *envelope* parser, which must
    /// reject them cleanly.
    #[test]
    fn committed_arbitrary_targets_bytes_are_rejected(
        data in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        let keys = KeySet::new();
        let mut up = updater(&keys);
        let ts = sign_ts(&timestamp_for(1, T0 + DAY, &data, 1), &keys.timestamp);
        up.verify_timestamp(&ts, T0).unwrap();
        prop_assert!(up.verify_targets(&data, T0).is_err());
        prop_assert!(up.state().targets().is_none());
    }

    /// Arbitrary *payload* bytes, genuinely signed by the targets key and
    /// committed to by the timestamp, reach the targets payload parser and
    /// are rejected as invalid metadata.
    #[test]
    fn signed_arbitrary_targets_payload_is_rejected(
        payload in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let keys = KeySet::new();
        let mut up = updater(&keys);
        let env = Envelope::sign_raw(Role::Targets.payload_type(), &payload, &[&keys.targets])
            .to_bytes();
        let ts = sign_ts(&timestamp_for(1, T0 + DAY, &env, 1), &keys.timestamp);
        up.verify_timestamp(&ts, T0).unwrap();
        let res = up.verify_targets(&env, T0);
        prop_assert!(
            matches!(res, Err(UpdateError::InvalidMetadata { role: Role::Targets, .. })),
            "unexpected result: {:?}",
            res.map(|_| ())
        );
        prop_assert!(up.state().targets().is_none());
    }

    /// Single-byte corruptions of a *valid* targets payload, re-signed by
    /// the targets key, exercise the parser and validator deep inside the
    /// JSON structure. Whatever is accepted must still be committed by the
    /// timestamp's version and be a valid listing.
    #[test]
    fn signed_mutated_targets_payload_never_panics(
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let keys = KeySet::new();
        let mut up = updater(&keys);
        let mut payload = serde_json::to_vec(&simple_targets(1, T0 + DAY)).unwrap();
        let i = idx.index(payload.len());
        payload[i] ^= xor;
        let env = Envelope::sign_raw(Role::Targets.payload_type(), &payload, &[&keys.targets])
            .to_bytes();
        let ts = sign_ts(&timestamp_for(1, T0 + DAY, &env, 1), &keys.timestamp);
        up.verify_timestamp(&ts, T0).unwrap();
        if let Ok(vt) = up.verify_targets(&env, T0) {
            prop_assert_eq!(vt.targets().version, 1);
            prop_assert!(vt.targets().expires_ms > T0);
        }
    }
}
