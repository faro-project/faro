//! Recipient manifests (PROTOCOL.md §5.1), adversarially: version rules,
//! ally-set rules for PUT / approve / remove, the enrollment anchor, who may
//! read and write a manifest, and the alerts that go with ally and settings
//! changes.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::api::SignedRecipientManifest;
use faro_proto::keys::{ManifestAlly, ManifestRef, RecipientManifest};
use faro_proto::{EncPublicKey, Hash32, InstanceId, UserId};
use serde_json::json;

/// A member with keys and the first (empty) manifest.
async fn member(t: &TestApp, email: &str) -> (UserId, String, MemberKeys) {
    let (id, s) = t.sign_in(email).await;
    let keys = t.create_member_keys(&id, &s).await;
    (id, s, keys)
}

/// Invite → sign in → accept: a pending ally of the session's member.
async fn pending_ally(t: &TestApp, member_session: &str, email: &str) -> Ally {
    let token = t.invite(member_session, email).await;
    let (id, session) = t.sign_in(email).await;
    let keys = AllyKeys::generate();
    let r = t.accept(&token, &session, &keys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    Ally {
        id,
        session,
        keys,
        email: email.to_owned(),
    }
}

async fn device_manifest(t: &TestApp, d: &TestDevice) -> Resp {
    let path = format!("/v1/members/{}/recipient-manifest", d.member_id);
    t.device_call(d, Method::GET, &path, b"").await
}

async fn latest(t: &TestApp, member: &UserId, s: &str) -> SignedRecipientManifest {
    t.latest_manifest(member, s).await.expect("a manifest")
}

async fn versions(t: &TestApp, member: &UserId) -> i64 {
    count_with(
        &t.state,
        "SELECT COUNT(*) FROM member_manifests WHERE member_id = $1",
        member.as_str(),
    )
    .await
}

async fn link_state(t: &TestApp, member_s: &str, ally: &UserId) -> Option<String> {
    let l = t.get("/v1/me/allies", Some(member_s)).await;
    l.body["allies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["ally_id"] == ally.as_str())
        .map(|a| a["state"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn versions_must_advance_by_exactly_one() {
    let t = TestApp::new().await;
    let (m, s) = t.sign_in("sam@example.org").await;
    let keys = t.create_member_keys_only(&m, &s).await;
    let inst = t.instance_id();
    let now = t.clock_ms();
    assert!(t.latest_manifest(&m, &s).await.is_none(), "404 before any");
    let l = t.get("/v1/me/allies", Some(&s)).await;
    assert_eq!(l.body["manifest"], json!(null));

    // The first version is 1: not 0 (structurally invalid), not 2.
    let r = t
        .put_manifest(&s, &keys.manifest(&inst, &m, 0, &[], now))
        .await;
    assert_eq!(r.error_code(), "invalid_manifest");
    let r = t
        .put_manifest(&s, &keys.manifest(&inst, &m, 2, &[], now))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "manifest_version_mismatch");

    let v1 = keys.manifest(&inst, &m, 1, &[], now);
    let r = t.put_manifest(&s, &v1).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r1: ManifestRef = serde_json::from_value(r.body).unwrap();
    assert_eq!(r1, v1.body.reference());
    assert_eq!(latest(&t, &m, &s).await, v1);

    // Replaying the same version (identical, or a different document:
    // equivocation) and skipping ahead are refused.
    for bad in [
        v1.clone(),
        keys.manifest(&inst, &m, 1, &[], now + 1),
        keys.manifest(&inst, &m, 3, &[], now),
        keys.manifest(&inst, &m, u64::MAX, &[], now),
    ] {
        let r = t.put_manifest(&s, &bad).await;
        assert_eq!(r.error_code(), "manifest_version_mismatch", "{bad:?}");
    }

    let v2 = keys.next_manifest(&v1, |_| {});
    assert_eq!(t.put_manifest(&s, &v2).await.status, StatusCode::CREATED);
    // Rollback to an older version, re-signed or not.
    for bad in [v1.clone(), keys.manifest(&inst, &m, 1, &[], now + 5)] {
        let r = t.put_manifest(&s, &bad).await;
        assert_eq!(r.error_code(), "manifest_version_mismatch");
    }
    assert_eq!(latest(&t, &m, &s).await, v2);
    // History is kept.
    assert_eq!(versions(&t, &m).await, 2);
    let l = t.get("/v1/me/allies", Some(&s)).await;
    assert_eq!(l.body["manifest"]["current"], json!(v2.body.reference()));
    assert_eq!(l.body["manifest"]["needs_update"], false);
}

#[tokio::test]
async fn signatures_identity_and_keys_are_checked() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let inst = t.instance_id();
    let v1 = latest(&t, &m, &s).await;
    let next = keys.next_manifest(&v1, |_| {});

    // Signed by another key (e.g. one the instance substituted).
    let forger = MemberKeys::generate(&inst, &m, 0);
    let forged = forger.sign.endorse(next.body.clone());
    assert_eq!(
        t.put_manifest(&s, &forged).await.error_code(),
        "bad_manifest_signature"
    );
    // A genuine signature over a tampered body.
    let mut tampered = next.clone();
    tampered.body.issued_at_ms += 1;
    assert_eq!(
        t.put_manifest(&s, &tampered).await.error_code(),
        "bad_manifest_signature"
    );

    // Genuinely signed, but naming another instance or member.
    let mut other_inst = next.body.clone();
    other_inst.instance_id = InstanceId::new("inst_other");
    let mut other_member = next.body.clone();
    other_member.member_id = UserId::new("usr_someoneelse");
    for body in [other_inst, other_member] {
        let r = t.put_manifest(&s, &keys.sign.endorse(body)).await;
        assert_eq!(r.error_code(), "manifest_mismatch");
    }

    // The member key must be the registered one, and no key may be weak.
    let mut wrong_key = next.body.clone();
    wrong_key.member_enc_pubkey = AllyKeys::generate().enc.public();
    let r = t.put_manifest(&s, &keys.sign.endorse(wrong_key)).await;
    assert_eq!(r.error_code(), "manifest_member_key_mismatch");
    let mut weak = next.body.clone();
    weak.member_enc_pubkey = EncPublicKey([0; 32]);
    let r = t.put_manifest(&s, &keys.sign.endorse(weak)).await;
    assert_eq!(r.error_code(), "weak_manifest_key");
    let mut weak_ally = next.body.clone();
    weak_ally.allies = vec![ManifestAlly {
        ally_id: UserId::new("usr_x"),
        enc_pubkey: EncPublicKey([0; 32]),
    }];
    let r = t.put_manifest(&s, &keys.sign.endorse(weak_ally)).await;
    assert_eq!(r.error_code(), "weak_manifest_key");

    // Structure is checked before anything else: unsorted / self-listing /
    // oversized documents are refused even when correctly signed.
    let ally = |id: &str| ManifestAlly {
        ally_id: UserId::new(id),
        enc_pubkey: AllyKeys::generate().enc.public(),
    };
    for allies in [
        vec![ally("usr_b"), ally("usr_a")],
        vec![ally("usr_a"), ally("usr_a")],
        vec![ManifestAlly {
            ally_id: m.clone(),
            enc_pubkey: keys.enc.public(),
        }],
        (0..33).map(|i| ally(&format!("usr_{i:03}"))).collect(),
        vec![ally("dev_notauser")],
    ] {
        let body = RecipientManifest {
            allies,
            ..next.body.clone()
        };
        let r = t.put_manifest(&s, &keys.sign.endorse(body)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST);
        assert_eq!(r.error_code(), "invalid_manifest");
    }
    // A bad document after a good one changes nothing.
    assert_eq!(latest(&t, &m, &s).await, v1);
    assert_eq!(versions(&t, &m).await, 1);
}

#[tokio::test]
async fn put_cannot_add_an_ally_or_silently_drop_one() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let pat = pending_ally(&t, &s, "pat@elsewhere.net").await;

    // A pending ally cannot be added by an ordinary upload.
    let v1 = latest(&t, &m, &s).await;
    let add = keys.next_manifest(&v1, |a| a.push((pat.id.clone(), pat.keys.enc.public())));
    let r = t.put_manifest(&s, &add).await;
    assert_eq!(r.error_code(), "manifest_adds_ally");
    // Nor an arbitrary user who is not linked at all.
    let stranger = keys.next_manifest(&v1, |a| {
        a.push((
            UserId::new("usr_stranger"),
            AllyKeys::generate().enc.public(),
        ))
    });
    assert_eq!(
        t.put_manifest(&s, &stranger).await.error_code(),
        "manifest_adds_ally"
    );
    assert_eq!(
        link_state(&t, &s, &pat.id).await.as_deref(),
        Some("pending")
    );

    // Once approved, an ordinary upload must keep the ally, with the stored
    // key: dropping them needs DELETE (which tells everyone).
    let r = t
        .approve(&m, &keys, &s, &pat.id, pat.keys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v2 = latest(&t, &m, &s).await;
    let drop = keys.next_manifest(&v2, |a| a.clear());
    let r = t.put_manifest(&s, &drop).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "use_ally_removal");
    let swapped = keys.next_manifest(&v2, |a| a[0].1 = AllyKeys::generate().enc.public());
    let r = t.put_manifest(&s, &swapped).await;
    assert_eq!(r.error_code(), "manifest_key_mismatch");
    // Re-signing the same set is fine.
    let same = keys.next_manifest(&v2, |_| {});
    assert_eq!(t.put_manifest(&s, &same).await.status, StatusCode::CREATED);
    assert_eq!(latest(&t, &m, &s).await.body.version, 3);
}

#[tokio::test]
async fn approve_needs_exactly_the_previous_set_plus_this_ally() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let lee = t.link_ally(&m, &keys, &s, "lee@elsewhere.net").await;
    let pat = pending_ally(&t, &s, "pat@elsewhere.net").await;
    let kim = pending_ally(&t, &s, "kim@elsewhere.net").await;
    let v2 = latest(&t, &m, &s).await;
    let e = t.ally_endorsement(&m, &keys, &pat.id, pat.keys.enc.public());
    let pat_entry = (pat.id.clone(), pat.keys.enc.public());

    let cases = [
        // The ally is missing.
        (keys.next_manifest(&v2, |_| {}), "manifest_set_mismatch"),
        // Two allies at once.
        (
            keys.next_manifest(&v2, |a| {
                a.push(pat_entry.clone());
                a.push((kim.id.clone(), kim.keys.enc.public()));
            }),
            "manifest_set_mismatch",
        ),
        // The ally with a key other than their stored one.
        (
            keys.next_manifest(&v2, |a| {
                a.push((pat.id.clone(), AllyKeys::generate().enc.public()))
            }),
            "manifest_set_mismatch",
        ),
        // Sneaking an existing ally out while adding.
        (
            keys.next_manifest(&v2, |a| *a = vec![pat_entry.clone()]),
            "manifest_set_mismatch",
        ),
        // Right set, stale version (a replay of the current one).
        (
            keys.manifest(
                &t.instance_id(),
                &m,
                v2.body.version,
                &[(lee.id.clone(), lee.keys.enc.public()), pat_entry.clone()],
                t.clock_ms(),
            ),
            "manifest_version_mismatch",
        ),
        // Right set, signed by someone else.
        (
            MemberKeys::generate(&t.instance_id(), &m, 0)
                .next_manifest(&v2, |a| a.push(pat_entry.clone())),
            "bad_manifest_signature",
        ),
    ];
    for (manifest, code) in cases {
        let r = t.approve_with(&s, &pat.id, &e, &manifest).await;
        assert_eq!(r.error_code(), code, "{:?}", manifest.body);
        // Atomic: nothing was activated or stored.
        assert_eq!(
            link_state(&t, &s, &pat.id).await.as_deref(),
            Some("pending")
        );
        assert_eq!(latest(&t, &m, &s).await, v2);
    }

    // The right manifest works, and the endorsement still has to match.
    let good = keys.next_manifest(&v2, |a| a.push(pat_entry.clone()));
    let wrong_e = t.ally_endorsement(&m, &keys, &kim.id, kim.keys.enc.public());
    let r = t.approve_with(&s, &pat.id, &wrong_e, &good).await;
    assert_eq!(r.error_code(), "endorsement_mismatch");
    let r = t.approve_with(&s, &pat.id, &e, &good).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["manifest"], json!(good.body.reference()));
    assert_eq!(latest(&t, &m, &s).await, good);
    assert_eq!(link_state(&t, &s, &pat.id).await.as_deref(), Some("active"));

    // `ally_added` goes to the member and the existing ally (lee), but not
    // to pat, who gets a notice of their own instead.
    let added = t
        .alerts(&m)
        .await
        .into_iter()
        .filter(|a| a.kind == "ally_added")
        .collect::<Vec<_>>();
    assert_eq!(added.len(), 2, "lee's and pat's approvals");
    let for_pat = added
        .iter()
        .find(|a| a.detail.as_deref() == Some(format!("added:{}", pat.id).as_str()))
        .expect("an ally_added alert for pat");
    assert_eq!(for_pat.urgency, "normal");
    assert_eq!(for_pat.source, "server");
    wait_for_mail(&t, &pat.email, "approved you as their ally").await;
    faro_server::notify::dispatch(&t.state).await.unwrap();
    let about_pat = |u: UserId| {
        let st = t.state.clone();
        let pat = pat.id.clone();
        async move {
            sqlx::query(
                "SELECT COUNT(*) AS n FROM notifications n JOIN alerts a ON a.id = n.alert_id
                 WHERE a.detail = $1 AND n.recipient_id = $2",
            )
            .bind(format!("added:{pat}"))
            .bind(u.as_str())
            .fetch_one(st.db().pool())
            .await
            .map(|r| sqlx::Row::get::<i64, _>(&r, "n"))
            .unwrap()
        }
    };
    assert_eq!(about_pat(m.clone()).await, 1);
    assert_eq!(about_pat(lee.id.clone()).await, 1);
    assert_eq!(about_pat(pat.id.clone()).await, 0);
}

#[tokio::test]
async fn remove_needs_exactly_the_previous_set_minus_this_ally() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let lee = t.link_ally(&m, &keys, &s, "lee@elsewhere.net").await;
    let pat = t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    let v3 = latest(&t, &m, &s).await;
    let delete = |manifest: Option<SignedRecipientManifest>| {
        let path = format!("/v1/me/allies/{}", pat.id);
        let s = s.clone();
        let t = &t;
        async move {
            t.call(
                Method::DELETE,
                &path,
                manifest.map(|m| json!({ "manifest": m })),
                Some(&s),
            )
            .await
        }
    };

    let r = delete(None).await;
    assert_eq!(r.error_code(), "manifest_required");
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/allies/{}", pat.id),
            Some(json!({})),
            Some(&s),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_json");
    for (manifest, code) in [
        // Still lists pat.
        (keys.next_manifest(&v3, |_| {}), "manifest_set_mismatch"),
        // Drops lee too.
        (
            keys.next_manifest(&v3, |a| a.clear()),
            "manifest_set_mismatch",
        ),
        // Drops lee instead of pat.
        (
            keys.next_manifest(&v3, |a| a.retain(|(id, _)| id != &lee.id)),
            "manifest_set_mismatch",
        ),
        // Right set, stale version.
        (
            keys.manifest(
                &t.instance_id(),
                &m,
                v3.body.version,
                &[(lee.id.clone(), lee.keys.enc.public())],
                1,
            ),
            "manifest_version_mismatch",
        ),
    ] {
        let r = delete(Some(manifest)).await;
        assert_eq!(r.error_code(), code);
        assert_eq!(link_state(&t, &s, &pat.id).await.as_deref(), Some("active"));
        assert_eq!(latest(&t, &m, &s).await, v3);
    }
    // Right: link and manifest change together.
    let good = keys.next_manifest(&v3, |a| a.retain(|(id, _)| id != &pat.id));
    assert_eq!(
        delete(Some(good.clone())).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(link_state(&t, &s, &pat.id).await, None);
    assert_eq!(latest(&t, &m, &s).await, good);

    // A pending link was never in a manifest: removed without one, and a
    // manifest is refused rather than stored.
    let kim = pending_ally(&t, &s, "kim@elsewhere.net").await;
    let next = keys.next_manifest(&good, |_| {});
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/allies/{}", kim.id),
            Some(json!({ "manifest": next })),
            Some(&s),
        )
        .await;
    assert_eq!(r.error_code(), "manifest_not_needed");
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/allies/{}", kim.id),
            None,
            Some(&s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(latest(&t, &m, &s).await, good);
}

#[tokio::test]
async fn a_departed_ally_blocks_further_changes_until_the_member_resigns() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let lee = t.link_ally(&m, &keys, &s, "lee@elsewhere.net").await;
    let pat = t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    let kim = pending_ally(&t, &s, "kim@elsewhere.net").await;

    // pat leaves: access ends now, the manifest still lists them.
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/ally/members/{m}"),
            None,
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(t.feed(&m, &pat.session).await.status, StatusCode::NOT_FOUND);
    let l = t.get("/v1/me/allies", Some(&s)).await;
    assert_eq!(l.body["manifest"]["needs_update"], true);
    assert_eq!(l.body["manifest"]["departed"], json!([pat.id]));

    // Approving or removing someone else would sign a manifest that still
    // lists pat: refused until the member drops pat.
    let r = t
        .approve(&m, &keys, &s, &kim.id, kim.keys.enc.public())
        .await;
    assert_eq!(r.error_code(), "ally_not_active");
    let r = t.remove_ally(&m, &keys, &s, &lee.id).await;
    assert_eq!(r.error_code(), "ally_not_active");
    // Keeping pat in an ordinary upload is refused too.
    let v = latest(&t, &m, &s).await;
    let r = t.put_manifest(&s, &keys.next_manifest(&v, |_| {})).await;
    assert_eq!(r.error_code(), "ally_not_active");

    // Dropping pat is an allowed ordinary upload; then everything works.
    let fixed = keys.next_manifest(&v, |a| a.retain(|(id, _)| id != &pat.id));
    assert_eq!(t.put_manifest(&s, &fixed).await.status, StatusCode::CREATED);
    let r = t
        .approve(&m, &keys, &s, &kim.id, kim.keys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t.remove_ally(&m, &keys, &s, &lee.id).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let ids: Vec<UserId> = latest(&t, &m, &s)
        .await
        .body
        .allies
        .into_iter()
        .map(|a| a.ally_id)
        .collect();
    assert_eq!(ids, vec![kim.id]);
}

#[tokio::test]
async fn members_without_a_manifest_start_from_their_active_links() {
    // Links approved before manifests existed: the first manifest must list
    // exactly those allies.
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let pat = t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    sqlx::query("DELETE FROM member_manifests")
        .execute(t.state.db().pool())
        .await
        .unwrap();
    let inst = t.instance_id();
    let r = t
        .put_manifest(&s, &keys.manifest(&inst, &m, 1, &[], t.clock_ms()))
        .await;
    assert_eq!(r.error_code(), "use_ally_removal");
    let v1 = keys.manifest(
        &inst,
        &m,
        1,
        &[(pat.id.clone(), pat.keys.enc.public())],
        t.clock_ms(),
    );
    assert_eq!(t.put_manifest(&s, &v1).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn endorsement_must_anchor_to_the_current_manifest() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let v1 = latest(&t, &m, &s).await;
    let code = t.enroll_code(&s).await;
    let dev = t.enroll(&code, &keys.enc).await;

    // The pending device can already fetch the manifest it will bootstrap
    // from, and it verifies under the member key it pinned.
    let r = device_manifest(&t, &dev).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let fetched: SignedRecipientManifest = serde_json::from_value(r.body).unwrap();
    assert_eq!(fetched, v1);
    faro_crypto::verify_signed(&keys.sign.public(), &fetched).unwrap();

    // The member approves an ally after the device enrolled: v2.
    t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    let v2 = latest(&t, &m, &s).await.body.reference();

    for stale in [
        // A pre-change anchor (would let the device bootstrap below v2).
        v1.body.reference(),
        // The right version with another document's hash.
        ManifestRef {
            version: v2.version,
            hash: Hash32::ZERO,
        },
        // A version that does not exist (yet).
        ManifestRef {
            version: v2.version + 1,
            hash: v2.hash,
        },
    ] {
        let r = t.endorse_anchored(&dev, &keys, &s, stale).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        assert_eq!(r.error_code(), "stale_min_manifest");
    }
    let me = t
        .device_call(&dev, Method::GET, "/v1/devices/self", b"")
        .await;
    assert_eq!(me.body["status"], "pending_endorsement");
    assert_eq!(me.body["endorsement"], json!(null));

    let r = t.endorse_anchored(&dev, &keys, &s, v2).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let me = t
        .device_call(&dev, Method::GET, "/v1/devices/self", b"")
        .await;
    let e: faro_proto::keys::Signed<faro_proto::keys::DeviceEndorsement> =
        serde_json::from_value(me.body["endorsement"].clone()).unwrap();
    faro_crypto::verify_signed(&keys.sign.public(), &e).unwrap();
    assert_eq!(e.body.min_manifest, v2);
    // The device's first manifest is at the anchor.
    let first: SignedRecipientManifest =
        serde_json::from_value(device_manifest(&t, &dev).await.body).unwrap();
    assert_eq!(first.body.reference(), v2);
}

#[tokio::test]
async fn nobody_else_can_read_or_write_a_members_manifest() {
    let t = TestApp::new().await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let admin_keys = t.create_member_keys(&admin, &admin_s).await;
    let (m, s, keys, _dev) = t.active_device().await;
    let (alex, alex_s, alex_keys) = member(&t, "alex@example.org").await;
    let pat = t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    let path = format!("/v1/members/{m}/recipient-manifest");
    let mine = latest(&t, &m, &s).await;

    // Reading: an admin, another member, the member's own ally, another
    // member's device and an anonymous caller all get nothing.
    for session in [&admin_s, &alex_s, &pat.session] {
        let r = t.get(&path, Some(session)).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND);
    }
    assert_eq!(t.get(&path, None).await.status, StatusCode::UNAUTHORIZED);
    let code = t.enroll_code(&alex_s).await;
    let alex_dev = t.enroll(&code, &alex_keys.enc).await;
    let r = t.device_call(&alex_dev, Method::GET, &path, b"").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .get(
            "/v1/members/usr_doesnotexist/recipient-manifest",
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "same as a denial");

    // Writing: PUT only ever concerns the caller. The member's genuinely
    // signed next manifest, replayed by the admin or another member, fails
    // against their own key; one they sign themselves names the wrong member.
    let next = keys.next_manifest(&mine, |a| a.clear());
    for session in [&admin_s, &alex_s] {
        let r = t.put_manifest(session, &next).await;
        assert_eq!(r.error_code(), "bad_manifest_signature");
    }
    for (k, session) in [(&admin_keys, &admin_s), (&alex_keys, &alex_s)] {
        let body = RecipientManifest {
            member_enc_pubkey: k.enc.public(),
            ..next.body.clone()
        };
        let r = t.put_manifest(session, &k.sign.endorse(body)).await;
        assert_eq!(r.error_code(), "manifest_mismatch");
    }
    // An ally-only account cannot upload at all.
    let r = t.put_manifest(&pat.session, &next).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(latest(&t, &m, &s).await, mine);
    let _ = alex;
}

#[tokio::test]
async fn shortening_retention_tells_the_allies() {
    let t = TestApp::new().await;
    let (m, s, keys) = member(&t, "sam@example.org").await;
    let pat = t.link_ally(&m, &keys, &s, "pat@elsewhere.net").await;
    let changed = |t: &TestApp| {
        let st = t.state.clone();
        let m = m.clone();
        async move {
            count_with(
                &st,
                "SELECT COUNT(*) FROM alerts WHERE member_id = $1
                 AND kind = 'member_settings_changed'",
                m.as_str(),
            )
            .await
        }
    };
    let put =
        |body: serde_json::Value| t.call(Method::PUT, "/v1/me/retention", Some(body), Some(&s));

    let r = put(json!({"blob_days": 10})).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(changed(&t).await, 1);
    let a = t
        .alerts(&m)
        .await
        .into_iter()
        .find(|a| a.kind == "member_settings_changed")
        .unwrap();
    assert_eq!(a.urgency, "normal");
    assert_eq!(a.source, "server");
    assert_eq!(a.detail.as_deref(), Some("retention_shortened:blob_days"));
    // Same value again, or longer: nothing to tell.
    put(json!({"blob_days": 10})).await;
    put(json!({"blob_days": 20})).await;
    put(json!({})).await;
    assert_eq!(changed(&t).await, 1);
    // Shorter again (from the instance default for alerts too).
    put(json!({"blob_days": 8, "alert_days": 30})).await;
    assert_eq!(changed(&t).await, 2);

    // It reaches the ally (normal → digest) and shows in their feed.
    t.mailer.clear();
    t.digest_now().await;
    assert_eq!(t.digests_to(&pat.email).len(), 1);
    let f = t.feed(&m, &pat.session).await;
    assert!(f.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["kind"] == "member_settings_changed"));
}
