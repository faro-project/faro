//! Ally invites, links, the key directory, the feed and blob access, end to
//! end with real keys: invite → accept → approve → device encrypts to the
//! ally → ally reads the feed and decrypts the blob.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::api::{FeedItem, MemberKeysResponse, SignedRecipientManifest, REQUEST_MAX_SKEW_MS};
use faro_proto::encoding::b64_decode;
use faro_proto::keys::{AllyKeyRewrap, ProvenAllyKeyRewrap};
use faro_proto::{EncryptedItem, EventKind, Urgency, UserId};
use faro_server::api::feed::FeedResponse;
use faro_server::config::RegistrationMode;
use serde_json::json;

const SECRET: &[u8] = b"{\"reason\":\"a very private flagged moment\"}";

async fn directory(t: &TestApp, dev: &TestDevice) -> MemberKeysResponse {
    let r = t
        .device_call(
            dev,
            Method::GET,
            &format!("/v1/members/{}/keys", dev.member_id),
            b"",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body).unwrap()
}

/// The manifest as the member's device fetches it.
async fn manifest_for(t: &TestApp, dev: &TestDevice) -> SignedRecipientManifest {
    let r = t
        .device_call(
            dev,
            Method::GET,
            &format!("/v1/members/{}/recipient-manifest", dev.member_id),
            b"",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body).unwrap()
}

fn feed_of(r: &Resp) -> FeedResponse {
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body.clone()).unwrap()
}

#[tokio::test]
async fn full_flow_invite_accept_approve_encrypt_read_decrypt() {
    let t = TestApp::new().await; // open registration for example.org only
    let (member, ms, mkeys, mut dev) = t.active_device().await;

    // 1. Invite an ally whose domain could not self-register.
    let email = "pat@elsewhere.net";
    let token = t.invite(&ms, email).await;
    let info = t.get(&format!("/v1/invites/{token}"), None).await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["inviter_display_name"], "sam");
    assert_eq!(info.body["instance_name"], "Faro");
    assert_eq!(info.body["email"], email);

    // 2. The invite lets that address sign in; the account is ally-only.
    let (ally, ally_s) = t.sign_in(email).await;
    let me = t.get("/v1/me", Some(&ally_s)).await;
    assert_eq!(me.body["user"]["roles"]["ally"], true);
    assert_eq!(me.body["user"]["roles"]["member"], false);

    // 3. Accept with a fresh key: the link is pending and not yet in the
    //    directory devices encrypt to.
    let akeys = AllyKeys::generate();
    let r = t.accept(&token, &ally_s, &akeys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["state"], "pending");
    wait_for_mail(&t, "sam@example.org", "accepted your invitation").await;
    let allies = t.get("/v1/me/allies", Some(&ms)).await;
    assert_eq!(allies.status, StatusCode::OK);
    let a = &allies.body["allies"][0];
    assert_eq!(a["state"], "pending");
    assert_eq!(a["ally_id"], ally.as_str());
    assert_eq!(a["ally_enc_pubkey"], json!(akeys.enc.public()));
    assert_eq!(a["member_sign_pubkey"], json!(mkeys.sign.public()));
    // Both sides can compute the same safety code from these inputs.
    let from_member = faro_proto::keys::safety_code(
        mkeys.sign.public().as_bytes(),
        akeys.enc.public().as_bytes(),
    );
    let mine = t.get("/v1/ally/members", Some(&ally_s)).await;
    assert_eq!(mine.body[0]["state"], "pending");
    let spk: faro_proto::SignPublicKey =
        serde_json::from_value(mine.body[0]["member_sign_pubkey"].clone()).unwrap();
    assert_eq!(
        faro_proto::keys::safety_code(akeys.enc.public().as_bytes(), spk.as_bytes()),
        from_member
    );
    assert!(directory(&t, &dev).await.allies.is_empty());
    // A pending ally has no feed access yet.
    assert_eq!(t.feed(&member, &ally_s).await.status, StatusCode::NOT_FOUND);

    // 4. Approve: the next recipient manifest (stored atomically with the
    //    activation) lists the ally with their key, and the directory carries
    //    the member-signed endorsement.
    let r = t
        .approve(&member, &mkeys, &ms, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["manifest"]["version"], 2);
    let m = manifest_for(&t, &dev).await;
    faro_crypto::verify_signed(&mkeys.sign.public(), &m).unwrap();
    assert_eq!(m.body.version, 2);
    assert_eq!(m.body.allies.len(), 1);
    assert_eq!(m.body.allies[0].ally_id, ally);
    assert_eq!(m.body.allies[0].enc_pubkey, akeys.enc.public());
    assert_eq!(m.body.member_enc_pubkey, mkeys.enc.public());
    let dir = directory(&t, &dev).await;
    assert_eq!(dir.allies.len(), 1);
    assert_eq!(dir.allies[0].body.ally_enc_pubkey, akeys.enc.public());
    faro_crypto::verify_signed(&dir.member_sign_pubkey, &dir.allies[0]).unwrap();

    // 5. The device encrypts an urgent flag to member + the manifest allies.
    let ev = dev.next_event_to(
        EventKind::Flag,
        Urgency::Urgent,
        SECRET,
        &[(ally.clone(), m.body.allies[0].enc_pubkey)],
    );
    let r = t.post_events(&dev, std::slice::from_ref(&ev)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    // A clean capture (urgency none) stays out of the feed.
    let clean = dev.next_event(EventKind::Capture, Urgency::None);
    t.post_events(&dev, &[clean]).await;

    // 6. The ally's feed shows the flag, metadata only (next to the
    //    `ally_added` alert about their own approval).
    let f = feed_of(&t.feed(&member, &ally_s).await);
    let events: Vec<_> = f
        .items
        .iter()
        .filter(|e| matches!(e.item, FeedItem::Event { .. }))
        .collect();
    assert_eq!(events.len(), 1, "{:?}", f.items);
    assert!(f.items.iter().any(|e| matches!(
        &e.item,
        FeedItem::Alert { kind, detail, .. }
            if kind.as_str() == "ally_added"
                && detail.as_deref() == Some(format!("added:{ally}").as_str())
    )));
    let FeedItem::Event {
        seq,
        kind,
        urgency,
        blob_id,
        ..
    } = &events[0].item
    else {
        unreachable!()
    };
    assert_eq!(
        (*seq, *kind, *urgency),
        (0, EventKind::Flag, Urgency::Urgent)
    );
    let blob_id = blob_id.clone().expect("event has a body");
    // The member sees exactly the same feed.
    assert_eq!(feed_of(&t.feed(&member, &ms).await).items, f.items);

    // 7. The ally downloads the ciphertext and decrypts it locally.
    let b = t.get(&format!("/v1/blobs/{blob_id}"), Some(&ally_s)).await;
    assert_eq!(b.status, StatusCode::OK);
    assert_eq!(b.headers["content-type"], "application/json");
    assert!(!String::from_utf8_lossy(&b.raw).contains("private"));
    let item: EncryptedItem = serde_json::from_slice(&b.raw).unwrap();
    let pt = faro_crypto::open_item(&item, &ev.header.body_aad(), &ally, &akeys.enc).unwrap();
    assert_eq!(pt.as_slice(), SECRET);

    // 8. Nobody else gets the feed or the blob: not a stranger, not the
    //    admin, not even with the right id.
    let (_, eve_s) = t.sign_in("eve@example.org").await;
    assert_eq!(t.feed(&member, &eve_s).await.status, StatusCode::NOT_FOUND);
    let r = t.get(&format!("/v1/blobs/{blob_id}"), Some(&eve_s)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let missing = t
        .get(&format!("/v1/blobs/{}", "0".repeat(32)), Some(&eve_s))
        .await;
    assert_eq!(missing.body, r.body, "denial looks exactly like absence");
    let r = t.get(&format!("/v1/blobs/{blob_id}"), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn removing_an_ally_revokes_access_and_tells_them() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let lee = t.link_ally(&member, &mkeys, &ms, "lee@elsewhere.net").await;
    let ev = dev.next_event_to(
        EventKind::Flag,
        Urgency::Urgent,
        SECRET,
        &[
            (pat.id.clone(), pat.keys.enc.public()),
            (lee.id.clone(), lee.keys.enc.public()),
        ],
    );
    t.post_events(&dev, &[ev]).await;
    let f = feed_of(&t.feed(&member, &pat.session).await);
    let blob_id = f
        .items
        .iter()
        .find_map(|e| match &e.item {
            FeedItem::Event { blob_id, .. } => Some(blob_id.clone()),
            _ => None,
        })
        .expect("the flag is in the feed");
    let blob = format!("/v1/blobs/{}", blob_id.clone().unwrap());
    assert_eq!(
        t.get(&blob, Some(&pat.session)).await.status,
        StatusCode::OK
    );

    // Removing an approved ally needs the next manifest without them.
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/allies/{}", pat.id),
            None,
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "manifest_required");
    let r = t.remove_ally(&member, &mkeys, &ms, &pat.id).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    // Access ends at once, although pat was an envelope recipient.
    assert_eq!(
        t.feed(&member, &pat.session).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&blob, Some(&pat.session)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&blob, Some(&lee.session)).await.status,
        StatusCode::OK
    );
    // Devices stop encrypting to pat: the manifest stored with the removal
    // lists lee only.
    let m = manifest_for(&t, &dev).await;
    assert_eq!(m.body.version, 4);
    assert_eq!(
        m.body.allies.iter().map(|a| &a.ally_id).collect::<Vec<_>>(),
        vec![&lee.id]
    );
    let dir = directory(&t, &dev).await;
    assert_eq!(dir.allies.len(), 1);
    assert_eq!(dir.allies[0].body.ally_id, lee.id);

    // The removal is a normal alert in the feed of everyone still entitled.
    let f = feed_of(&t.feed(&member, &lee.session).await);
    let removed = f
        .items
        .iter()
        .find_map(|e| match &e.item {
            FeedItem::Alert {
                kind,
                urgency,
                detail,
                ..
            } if kind.as_str() == "ally_removed" => Some((*urgency, detail.clone())),
            _ => None,
        })
        .expect("ally_removed in the feed");
    assert_eq!(removed.0, Urgency::Normal);
    assert_eq!(
        removed.1.as_deref(),
        Some(format!("removed:{}", pat.id).as_str())
    );

    // Notifications: normal → digest. The removed ally is told although no
    // longer an ally; the remaining ally and the member are told too.
    t.mailer.clear();
    t.digest_now().await;
    let to_pat = t.digests_to(&pat.email);
    assert_eq!(to_pat.len(), 1, "{to_pat:?}");
    assert!(to_pat[0].text.contains("You are no longer an ally for sam"));
    assert!(!to_pat[0].text.contains("private"));
    // pat's earlier (undelivered) urgent item about sam was dropped, so the
    // digest names nothing but the removal.
    assert!(!to_pat[0].text.contains("urgent"));
    assert_eq!(t.digests_to(&lee.email).len(), 1);
    assert_eq!(t.digests_to("sam@example.org").len(), 1);
    // The member cannot remove the same ally twice.
    let r = t.remove_ally(&member, &mkeys, &ms, &pat.id).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert_eq!(
        manifest_for(&t, &dev).await.body.version,
        4,
        "nothing stored"
    );
}

#[tokio::test]
async fn an_ally_can_leave_and_the_member_is_told() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, _dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/ally/members/{member}"),
            None,
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(
        t.feed(&member, &pat.session).await.status,
        StatusCode::NOT_FOUND
    );
    let alerts = t.alerts(&member).await;
    let a = alerts.iter().find(|a| a.kind == "ally_removed").unwrap();
    assert_eq!(
        a.detail.as_deref(),
        Some(format!("left:{}", pat.id).as_str())
    );
    // The member is told that devices keep encrypting to pat until they
    // sign a manifest without them.
    let notice = wait_for_mail(&t, "sam@example.org", "keep encrypting new items to them").await;
    assert!(notice.subject.contains("is no longer your ally"));
    t.mailer.clear();
    t.digest_now().await;
    assert_eq!(t.digests_to("sam@example.org").len(), 1);
    assert!(
        t.digests_to(&pat.email).is_empty(),
        "the leaver is not re-told"
    );
    // The ally list says the manifest needs updating.
    let l = t.get("/v1/me/allies", Some(&ms)).await;
    assert_eq!(l.body["allies"], json!([]));
    assert_eq!(l.body["manifest"]["needs_update"], true);
    assert_eq!(l.body["manifest"]["departed"], json!([pat.id]));
    assert_eq!(l.body["manifest"]["current"]["version"], 2);
    // The stored manifest still lists pat (only the member can sign), but
    // pat's access is gone regardless.
    let latest = t.latest_manifest(&member, &ms).await.unwrap();
    assert_eq!(latest.body.allies[0].ally_id, pat.id);
    // The member signs the update; the warning clears.
    let next = mkeys.next_manifest(&latest, |a| a.clear());
    assert_eq!(t.put_manifest(&ms, &next).await.status, StatusCode::CREATED);
    let l = t.get("/v1/me/allies", Some(&ms)).await;
    assert_eq!(l.body["manifest"]["needs_update"], false);
    assert_eq!(l.body["manifest"]["departed"], json!([]));
    // Re-inviting works.
    let token = t.invite(&ms, &pat.email).await;
    let r = t.accept(&token, &pat.session, &pat.keys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

/// The blob of the newest event in `member`'s feed, as the member sees it.
async fn newest_event_blob(t: &TestApp, member: &UserId, session: &str) -> String {
    let f = feed_of(&t.feed(member, session).await);
    let id = f
        .items
        .iter()
        .rev()
        .find_map(|e| match &e.item {
            FeedItem::Event { blob_id, .. } => blob_id.clone(),
            _ => None,
        })
        .expect("an event with a body");
    format!("/v1/blobs/{id}")
}

#[tokio::test]
async fn re_approved_ally_cannot_read_items_sealed_while_they_were_not_an_ally() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let to_pat = [(pat.id.clone(), pat.keys.enc.public())];

    // Sealed to pat while pat is an ally: readable.
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &to_pat);
    t.post_events(&dev, &[ev]).await;
    let during = newest_event_blob(&t, &member, &ms).await;
    assert_eq!(
        t.get(&during, Some(&pat.session)).await.status,
        StatusCode::OK
    );
    // Not sealed to pat: never readable, active link or not.
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &[]);
    t.post_events(&dev, &[ev]).await;
    let not_sealed = newest_event_blob(&t, &member, &ms).await;
    assert_eq!(
        t.get(&not_sealed, Some(&pat.session)).await.status,
        StatusCode::NOT_FOUND
    );

    // pat leaves; the device has not seen a new manifest yet and keeps
    // sealing to pat (PROTOCOL §5.1: removal is forward-only).
    t.clock.advance_ms(1);
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/ally/members/{member}"),
            None,
            Some(&pat.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    t.clock.advance_ms(1);
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &to_pat);
    t.post_events(&dev, &[ev]).await;
    let gap = newest_event_blob(&t, &member, &ms).await;
    assert_eq!(
        t.get(&gap, Some(&pat.session)).await.status,
        StatusCode::NOT_FOUND
    );

    // Three weeks later the member drops pat from the manifest, re-invites
    // and approves them again.
    t.clock.advance_ms(21 * 24 * 3600 * 1000);
    let latest = t.latest_manifest(&member, &ms).await.unwrap();
    let next = mkeys.next_manifest(&latest, |a| a.clear());
    assert_eq!(t.put_manifest(&ms, &next).await.status, StatusCode::CREATED);
    let token = t.invite(&ms, &pat.email).await;
    let r = t.accept(&token, &pat.session, &pat.keys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = t
        .approve(&member, &mkeys, &ms, &pat.id, pat.keys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    // The item sealed during the gap stays closed to pat; the one from the
    // earlier link (which pat could already decrypt) is readable again.
    assert_eq!(
        t.get(&gap, Some(&pat.session)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&during, Some(&pat.session)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        t.get(&not_sealed, Some(&pat.session)).await.status,
        StatusCode::NOT_FOUND
    );
    // New items sealed to pat are readable.
    t.clock.advance_ms(1);
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &to_pat);
    t.post_events(&dev, &[ev]).await;
    let after = newest_event_blob(&t, &member, &ms).await;
    assert_eq!(
        t.get(&after, Some(&pat.session)).await.status,
        StatusCode::OK
    );
    // The member reads everything.
    for b in [&during, &not_sealed, &gap, &after] {
        assert_eq!(t.get(b, Some(&ms)).await.status, StatusCode::OK);
    }
}

#[tokio::test]
async fn approval_must_be_signed_by_the_member_over_the_stored_key() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, dev) = t.active_device().await;
    let token = t.invite(&ms, "pat@elsewhere.net").await;
    let (ally, ally_s) = t.sign_in("pat@elsewhere.net").await;
    let akeys = AllyKeys::generate();
    assert_eq!(
        t.accept(&token, &ally_s, &akeys).await.status,
        StatusCode::CREATED
    );

    // A key the instance (or anyone) swapped in: not the stored key.
    let other = AllyKeys::generate();
    let r = t
        .approve(&member, &mkeys, &ms, &ally, other.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "endorsement_mismatch");

    // Signed by a key that is not the member's.
    let forger = MemberKeys::generate(&t.instance_id(), &member, t.clock_ms());
    let r = t
        .approve(&member, &forger, &ms, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.error_code(), "bad_endorsement_signature");

    // A correctly signed endorsement with a tampered body.
    let good_manifest = mkeys.manifest(
        &t.instance_id(),
        &member,
        2,
        &[(ally.clone(), akeys.enc.public())],
        t.clock_ms(),
    );
    let mut e = mkeys.sign.endorse(faro_proto::keys::AllyEndorsement {
        instance_id: t.instance_id(),
        member_id: member.clone(),
        ally_id: ally.clone(),
        ally_enc_pubkey: akeys.enc.public(),
        endorsed_at_ms: 1,
    });
    e.body.endorsed_at_ms = 2;
    let r = t.approve_with(&ms, &ally, &e, &good_manifest).await;
    assert_eq!(r.error_code(), "bad_endorsement_signature");
    // The old body shape (a bare endorsement, no manifest) is refused.
    let r = t
        .post(
            &format!("/v1/me/allies/{ally}/approve"),
            serde_json::to_value(t.ally_endorsement(&member, &mkeys, &ally, akeys.enc.public()))
                .unwrap(),
            Some(&ms),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_json");

    // Naming another member or instance.
    for (m, i) in [
        (UserId::new("usr_someoneelse"), t.instance_id()),
        (member.clone(), faro_proto::InstanceId::new("inst_other")),
    ] {
        let e = mkeys.sign.endorse(faro_proto::keys::AllyEndorsement {
            instance_id: i,
            member_id: m,
            ally_id: ally.clone(),
            ally_enc_pubkey: akeys.enc.public(),
            endorsed_at_ms: 1,
        });
        let r = t.approve_with(&ms, &ally, &e, &good_manifest).await;
        assert_eq!(r.error_code(), "endorsement_mismatch");
    }
    // Nothing above activated the link or stored a manifest.
    assert!(directory(&t, &dev).await.allies.is_empty());
    assert_eq!(manifest_for(&t, &dev).await.body.version, 1);

    // Another member cannot approve this link (it is not theirs).
    let (other_m, other_s) = t.sign_in("alex@example.org").await;
    let other_keys = t.create_member_keys(&other_m, &other_s).await;
    let r = t
        .approve(&other_m, &other_keys, &other_s, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // The real approval works exactly once.
    let r = t
        .approve(&member, &mkeys, &ms, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .approve(&member, &mkeys, &ms, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.error_code(), "already_active");
}

#[tokio::test]
async fn admins_cannot_create_links_or_approve_for_anyone() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (member, ms, mkeys, dev) = t.active_device().await;
    let token = t.invite(&ms, "pat@elsewhere.net").await;
    let (ally, ally_s) = t.sign_in("pat@elsewhere.net").await;
    let akeys = AllyKeys::generate();
    t.accept(&token, &ally_s, &akeys).await;

    // The admin's own approve call only ever concerns the admin's own links.
    let admin_keys = t.create_member_keys(&_admin, &admin_s).await;
    let r = t
        .approve(&member, &admin_keys, &admin_s, &ally, akeys.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An admin can't read the member's ally list, feed or blobs.
    assert!(t.get("/v1/me/allies", Some(&admin_s)).await.body["allies"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        t.feed(&member, &admin_s).await.status,
        StatusCode::NOT_FOUND
    );
    // An admin can't accept an invite addressed to someone else.
    let token2 = t.invite(&ms, "lee@elsewhere.net").await;
    let r = t.accept(&token2, &admin_s, &AllyKeys::generate()).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "invite_email_mismatch");
    assert!(directory(&t, &dev).await.allies.is_empty());

    // An admin without the member role cannot invite at all.
    let t2 = TestApp::new().await;
    let (_a, s2) = t2.setup_admin("admin@example.org").await;
    sqlx::query("UPDATE users SET is_member = 0")
        .execute(t2.state.db().pool())
        .await
        .unwrap();
    let r = t2
        .post(
            "/v1/me/invites",
            json!({"email": "x@example.org"}),
            Some(&s2),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let _ = mkeys;
}

#[tokio::test]
async fn invite_rules_and_adversarial_accepts() {
    let t = TestApp::new().await;
    let (member, ms, _mkeys, _dev) = t.active_device().await;

    // Garbage, unknown and self invites.
    let r = t
        .post(
            "/v1/me/invites",
            json!({"email": "sam@example.org"}),
            Some(&ms),
        )
        .await;
    assert_eq!(r.error_code(), "cannot_invite_self");
    let r = t
        .post(
            "/v1/me/invites",
            json!({"email": "not-an-email"}),
            Some(&ms),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_email");
    for bad in ["short", &"A".repeat(43)] {
        assert_eq!(
            t.get(&format!("/v1/invites/{bad}"), None).await.status,
            StatusCode::NOT_FOUND
        );
    }

    let token = t.invite(&ms, "pat@elsewhere.net").await;
    // The token is stored hashed only.
    assert_eq!(
        count_with(
            &t.state,
            "SELECT COUNT(*) FROM invites WHERE token_hash = $1",
            &token
        )
        .await,
        0
    );
    let (_ally, ally_s) = t.sign_in("pat@elsewhere.net").await;

    // Weak keys and junk wrapped keys are refused without burning the invite.
    let r = t
        .post(
            &format!("/v1/invites/{token}/accept"),
            json!({"enc_pubkey": faro_proto::EncPublicKey([0; 32]), "wrapped_privkey": {}}),
            Some(&ally_s),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_enc_pubkey");
    let r = t
        .post(
            &format!("/v1/invites/{token}/accept"),
            json!({"enc_pubkey": AllyKeys::generate().enc.public(), "wrapped_privkey": "x"}),
            Some(&ally_s),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_wrapped_key");
    // Accept needs a session.
    let r = t
        .post(
            &format!("/v1/invites/{token}/accept"),
            AllyKeys::generate().upload_body(),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);

    let keys = AllyKeys::generate();
    assert_eq!(
        t.accept(&token, &ally_s, &keys).await.status,
        StatusCode::CREATED
    );
    // Single use.
    assert_eq!(
        t.accept(&token, &ally_s, &keys).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get(&format!("/v1/invites/{token}"), None).await.status,
        StatusCode::NOT_FOUND
    );
    // An existing link blocks a second invite.
    let r = t
        .post(
            "/v1/me/invites",
            json!({"email": "pat@elsewhere.net"}),
            Some(&ms),
        )
        .await;
    assert_eq!(r.error_code(), "already_linked");

    // One key per ally: a second member's invite must reuse it.
    let (m2, s2) = t.sign_in("alex@example.org").await;
    t.create_member_keys(&m2, &s2).await;
    let token2 = t.invite(&s2, "pat@elsewhere.net").await;
    let r = t.accept(&token2, &ally_s, &AllyKeys::generate()).await;
    assert_eq!(r.error_code(), "ally_key_mismatch");
    let k = t.get("/v1/me/ally-key", Some(&ally_s)).await;
    assert_eq!(k.body["enc_pubkey"], json!(keys.enc.public()));
    assert!(k.body["wrapped_privkey"].is_object());
    assert_eq!(
        t.accept(&token2, &ally_s, &keys).await.status,
        StatusCode::CREATED
    );
    let members = t.get("/v1/ally/members", Some(&ally_s)).await;
    assert_eq!(members.body.as_array().unwrap().len(), 2);
    let _ = member;
}

#[tokio::test]
async fn invites_expire_after_seven_days() {
    let t = TestApp::new().await;
    let (_m, ms, _k, _d) = t.active_device().await;
    let token = t.invite(&ms, "pat@elsewhere.net").await;
    t.clock
        .advance_ms(faro_server::api::invites::INVITE_TTL_MS + 1);
    assert_eq!(
        t.get(&format!("/v1/invites/{token}"), None).await.status,
        StatusCode::NOT_FOUND
    );
    // And no longer lets the address create an account.
    t.post(
        "/v1/auth/magic-link",
        json!({"email": "pat@elsewhere.net"}),
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!t
        .mailer
        .sent()
        .iter()
        .any(|m| m.to == "pat@elsewhere.net" && m.text.contains("/auth/verify")));
}

#[tokio::test]
async fn invite_only_mode_admits_invited_addresses_only() {
    let t = TestApp::with_config(|c| {
        c.registration.mode = RegistrationMode::InviteOnly;
        c.registration.allowed_email_domains.clear();
    })
    .await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let keys = t.create_member_keys(&admin, &admin_s).await;
    // Uninvited: no sign-in email.
    t.post(
        "/v1/auth/magic-link",
        json!({"email": "pat@elsewhere.net"}),
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(t.mail_to("pat@elsewhere.net").is_empty());
    // Invited: in.
    let pat = t
        .link_ally(&admin, &keys, &admin_s, "pat@elsewhere.net")
        .await;
    let me = t.get("/v1/me", Some(&pat.session)).await;
    assert_eq!(me.body["user"]["roles"]["ally"], true);

    // Admin member invite: the invitee becomes a member by signing in.
    let r = t
        .post(
            "/admin/api/invites",
            json!({"email": "newmember@example.org"}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    wait_for_mail(&t, "newmember@example.org", "/invite#token=").await;
    let (_nm, nms) = t.sign_in("newmember@example.org").await;
    let me = t.get("/v1/me", Some(&nms)).await;
    assert_eq!(me.body["user"]["roles"]["member"], true);
    assert_eq!(me.body["user"]["roles"]["admin"], false);
}

#[tokio::test]
async fn closed_mode_invites_do_not_create_accounts() {
    let t = TestApp::with_config(|c| {
        c.registration.mode = RegistrationMode::Closed;
    })
    .await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    t.create_member_keys(&admin, &admin_s).await;
    t.invite(&admin_s, "pat@elsewhere.net").await;
    t.post(
        "/v1/auth/magic-link",
        json!({"email": "pat@elsewhere.net"}),
        None,
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!t
        .mail_to("pat@elsewhere.net")
        .iter()
        .any(|m| m.text.contains("/auth/verify")));
}

#[tokio::test]
async fn feed_pages_never_skip_items_sharing_a_millisecond() {
    let t = TestApp::new().await;
    let (member, ms, _k, mut dev) = t.active_device().await;
    // The manual clock does not move: all 25 events share one receive time.
    let evs: Vec<_> = (0..25)
        .map(|_| dev.next_event(EventKind::SettingsChange, Urgency::Normal))
        .collect();
    t.post_events(&dev, &evs).await;
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let path = match &cursor {
            Some(c) => format!("/v1/ally/feed?member_id={member}&limit=7&cursor={c}"),
            None => format!("/v1/ally/feed?member_id={member}&limit=7"),
        };
        let f = feed_of(&t.get(&path, Some(&ms)).await);
        for e in &f.items {
            if let FeedItem::Event { seq, .. } = e.item {
                seen.push(seq);
            }
        }
        cursor = f.next_cursor.clone();
        if !f.has_more {
            break;
        }
    }
    assert_eq!(seen, (0..25).collect::<Vec<u64>>());
    // Polling with the last cursor returns nothing new.
    let f = feed_of(
        &t.get(
            &format!(
                "/v1/ally/feed?member_id={member}&cursor={}",
                cursor.unwrap()
            ),
            Some(&ms),
        )
        .await,
    );
    assert!(f.items.is_empty());
    let r = t
        .get(
            &format!("/v1/ally/feed?member_id={member}&cursor=junk"),
            Some(&ms),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_cursor");
    // since_ms filters by receive time.
    let f = feed_of(
        &t.get(
            &format!("/v1/ally/feed?member_id={member}&since_ms={}", t.clock_ms()),
            Some(&ms),
        )
        .await,
    );
    assert!(f.items.is_empty());
}

#[tokio::test]
async fn the_feed_says_which_devices_are_iphones_to_those_who_can_read_it() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut mac) = t.active_device().await;
    let code = t.enroll_code(&ms).await;
    let mut phone = t.enroll_as(&code, &mkeys.enc, "ios", "iPhone-X").await;
    assert_eq!(t.endorse(&phone, &mkeys, &ms).await.status, StatusCode::OK);
    // A third device that never sends anything stays out of the map.
    let code = t.enroll_code(&ms).await;
    let quiet = t.enroll_as(&code, &mkeys.enc, "windows", "Desk").await;
    assert_eq!(t.endorse(&quiet, &mkeys, &ms).await.status, StatusCode::OK);

    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let bye = phone.next_event(EventKind::Goodbye, Urgency::Urgent);
    let flag = mac.next_event(EventKind::SettingsChange, Urgency::Normal);
    t.post_events(&phone, &[bye]).await;
    t.post_events(&mac, &[flag]).await;

    let want = |f: &FeedResponse| {
        let mut m = std::collections::BTreeMap::new();
        m.insert(phone.id.to_string(), faro_proto::api::Platform::Ios);
        m.insert(mac.id.to_string(), faro_proto::api::Platform::Macos);
        assert_eq!(f.device_platforms, m);
    };
    // The ally and the member both get it.
    want(&feed_of(&t.feed(&member, &pat.session).await));
    want(&feed_of(&t.feed(&member, &ms).await));

    // Someone who is not an ally gets a 404, and so no map.
    let (_stranger, ss) = t.sign_in("stranger@example.org").await;
    let r = t.feed(&member, &ss).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{:?}", r.body);
    assert!(r.body.get("device_platforms").is_none());
    // Neither does a removed ally.
    let r = t.remove_ally(&member, &mkeys, &ms, &pat.id).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let r = t.feed(&member, &pat.session).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{:?}", r.body);
    assert!(r.body.get("device_platforms").is_none());
}

/// Ask for a re-wrap challenge as `session` and open it with `keys`.
async fn open_challenge(t: &TestApp, session: &str, keys: &AllyKeys) -> (i64, [u8; 32]) {
    let r = t
        .post("/v1/me/ally-key/challenge", json!({}), Some(session))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["enc_pubkey"], json!(keys.enc.public()));
    let sealed = b64_decode(r.body["sealed_challenge"].as_str().unwrap()).unwrap();
    let opened = keys.enc.unseal(&sealed).expect("sealed to the ally key");
    let challenge = <[u8; 32]>::try_from(opened.as_slice()).expect("32 bytes");
    (r.body["issued_at_ms"].as_i64().unwrap(), challenge)
}

/// An ally's wrapped key as the web app stores it: the secret under `pass`,
/// plus a `recovery` copy under `recovery`.
fn ally_wrapped(keys: &AllyKeys, pass: &[u8], recovery: &[u8]) -> serde_json::Value {
    let p = faro_crypto::KdfParams::insecure_for_tests();
    let secret = keys.enc.secret_bytes();
    let mut w = json!(faro_crypto::wrap_secret(secret.as_slice(), pass, p).unwrap());
    w["recovery"] = json!(faro_crypto::wrap_secret(secret.as_slice(), recovery, p).unwrap());
    w
}

/// A `PUT /v1/me/ally-key/wrapped` body, proven with `challenge`.
fn ally_rewrap_body(
    t: &TestApp,
    ally: &Ally,
    issued_at_ms: i64,
    challenge: &[u8; 32],
    wrapped: &serde_json::Value,
) -> serde_json::Value {
    let body = AllyKeyRewrap {
        instance_id: t.instance_id(),
        ally_id: ally.id.clone(),
        enc_pubkey: ally.keys.enc.public(),
        issued_at_ms,
        wrapped_privkey: wrapped.to_string(),
    };
    let proof = body.proof(challenge);
    serde_json::to_value(ProvenAllyKeyRewrap { body, proof }).unwrap()
}

#[tokio::test]
async fn allies_can_rewrap_their_key_by_answering_a_sealed_challenge() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let to_pat = [(pat.id.clone(), pat.keys.enc.public())];
    let ev = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &to_pat);
    t.post_events(&dev, std::slice::from_ref(&ev)).await;
    let before_blob = newest_event_blob(&t, &member, &ms).await;
    let before_key = t.get("/v1/me/ally-key", Some(&pat.session)).await;
    let before_allies = t.get("/v1/me/allies", Some(&ms)).await;
    t.notify_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mails = t.mailer.sent().len();
    let alerts = t.alerts(&member).await.len();

    let put = |body| {
        t.call(
            Method::PUT,
            "/v1/me/ally-key/wrapped",
            Some(body),
            Some(&pat.session),
        )
    };
    let junk = ally_wrapped(&pat.keys, b"x", b"y");

    // A session alone can't do it: the proof needs the opened challenge.
    let (at, challenge) = open_challenge(&t, &pat.session, &pat.keys).await;
    let r = put(ally_rewrap_body(&t, &pat, at, &[7; 32], &junk)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "bad_rewrap_proof");
    // Sending the challenge itself instead of a proof doesn't work either.
    let mut b = ally_rewrap_body(&t, &pat, at, &challenge, &junk);
    b["proof"] = json!(faro_proto::Hash32(challenge));
    assert_eq!(put(b).await.error_code(), "bad_rewrap_proof");
    // The proof covers the wrapped key and the time.
    let mut b = ally_rewrap_body(&t, &pat, at, &challenge, &junk);
    b["wrapped_privkey"] = json!(ally_wrapped(&pat.keys, b"z", b"y").to_string());
    assert_eq!(put(b).await.error_code(), "bad_rewrap_proof");
    let r = put(ally_rewrap_body(&t, &pat, at - 1, &challenge, &junk)).await;
    assert_eq!(r.error_code(), "bad_rewrap_proof");

    // The public key can never change, even with a good proof.
    let mut b = ally_rewrap_body(&t, &pat, at, &challenge, &junk);
    b["enc_pubkey"] = json!(AllyKeys::generate().enc.public());
    let r = put(b).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "ally_key_mismatch");

    // Only for this instance and this account.
    let mut b = ally_rewrap_body(&t, &pat, at, &challenge, &junk);
    b["ally_id"] = json!("usr_someoneelse");
    assert_eq!(put(b).await.error_code(), "rewrap_mismatch");

    // The wrapped key must be a JSON object of at most 8 KiB.
    let r = put(ally_rewrap_body(&t, &pat, at, &challenge, &json!("text"))).await;
    assert_eq!(r.error_code(), "invalid_wrapped_key");
    let big = json!({ "pad": "x".repeat(9000) });
    let r = put(ally_rewrap_body(&t, &pat, at, &challenge, &big)).await;
    assert_eq!(r.error_code(), "invalid_wrapped_key");

    // The real thing: stored as given, the key itself untouched.
    t.clock.advance_ms(1_000);
    let new = ally_wrapped(&pat.keys, b"new ally pass", b"NEW-RECOVERY");
    let r = put(ally_rewrap_body(&t, &pat, at, &challenge, &new)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let k = t.get("/v1/me/ally-key", Some(&pat.session)).await;
    assert_eq!(k.body["wrapped_privkey"], new);
    for f in ["enc_pubkey", "key_id", "created_at_ms"] {
        assert_eq!(k.body[f], before_key.body[f], "{f}");
    }
    let w: faro_crypto::WrappedSecret =
        serde_json::from_value(k.body["wrapped_privkey"].clone()).unwrap();
    assert_eq!(
        &**faro_crypto::unwrap_secret(&w, b"new ally pass").unwrap(),
        pat.keys.enc.secret_bytes().as_slice()
    );

    // The challenge was good for one change: replaying it can't restore
    // the old passphrase.
    let old = before_key.body["wrapped_privkey"].clone();
    let r = put(ally_rewrap_body(&t, &pat, at, &challenge, &old)).await;
    assert_eq!(r.error_code(), "bad_rewrap_proof");
    let k = t.get("/v1/me/ally-key", Some(&pat.session)).await;
    assert_eq!(k.body["wrapped_privkey"], new);

    // Challenges expire.
    let (at, challenge) = open_challenge(&t, &pat.session, &pat.keys).await;
    t.clock.advance_ms(REQUEST_MAX_SKEW_MS + 1);
    let r = put(ally_rewrap_body(&t, &pat, at, &challenge, &junk)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "stale_request");

    // Nobody is told, and nothing the member sees changed: the same key and
    // so the same safety code, and the same endorsement for devices.
    t.notify_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(t.mailer.sent().len(), mails, "{:?}", t.mailer.sent());
    assert_eq!(t.alerts(&member).await.len(), alerts);
    assert_eq!(
        t.get("/v1/me/allies", Some(&ms)).await.body,
        before_allies.body
    );
    let dir = directory(&t, &dev).await;
    assert_eq!(dir.allies.len(), 1);
    assert_eq!(dir.allies[0].body.ally_enc_pubkey, pat.keys.enc.public());

    // pat still reads what was sealed before, and what is sealed after.
    t.clock.advance_ms(1);
    let ev2 = dev.next_event_to(EventKind::Flag, Urgency::Urgent, SECRET, &to_pat);
    t.post_events(&dev, std::slice::from_ref(&ev2)).await;
    let after_blob = newest_event_blob(&t, &member, &ms).await;
    for (blob, ev) in [(&before_blob, &ev), (&after_blob, &ev2)] {
        let b = t.get(blob, Some(&pat.session)).await;
        assert_eq!(b.status, StatusCode::OK);
        let item: EncryptedItem = serde_json::from_slice(&b.raw).unwrap();
        let pt =
            faro_crypto::open_item(&item, &ev.header.body_aad(), &pat.id, &pat.keys.enc).unwrap();
        assert_eq!(pt.as_slice(), SECRET);
    }
}

#[tokio::test]
async fn rewrapping_needs_an_ally_key() {
    let t = TestApp::new().await;
    let (member, ms, _mkeys, _dev) = t.active_device().await;
    let r = t
        .post("/v1/me/ally-key/challenge", json!({}), Some(&ms))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let not_an_ally = Ally {
        id: member,
        session: ms.clone(),
        keys: AllyKeys::generate(),
        email: "sam@example.org".into(),
    };
    let wrapped = ally_wrapped(&not_an_ally.keys, b"x", b"y");
    let body = ally_rewrap_body(&t, &not_an_ally, t.clock_ms(), &[0; 32], &wrapped);
    let r = t
        .call(
            Method::PUT,
            "/v1/me/ally-key/wrapped",
            Some(body),
            Some(&ms),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "ally_key_required");
    let r = t.post("/v1/me/ally-key/challenge", json!({}), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}
