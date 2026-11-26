//! Reach out and signed, encrypted notes (docs/GROUPS.md §8.3, §10.2, §14;
//! PROTOCOL.md §9): a signed reach out that recipients verify and open
//! while the instance can't; forged and misdirected messages refused;
//! ally-only senders' unverifiable reach outs; the 3-an-hour limit; quiet
//! hours and the per-person bypass; answers; audiences; notes on proposals
//! and join requests, and who may read them.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_crypto::{
    open_group_message, seal_group_message, verify_group_message, EncryptionKeypair, SigningKey,
};
use faro_proto::group::{GroupMessage, GroupMessageKind, MessageRecipient, SealedGroupMessage};
use faro_proto::{EncPublicKey, Hash32, SignPublicKey, UserId};
use serde_json::{json, Value};

const HOUR: i64 = 3600 * 1000;
const DAY: i64 = 24 * HOUR;
const NAME: &str = "Tuesday Recovery Zebra";
const SECRET: &str = "Rough night, can someone call me? Narwhal";

struct P {
    id: UserId,
    s: String,
    email: String,
    keys: Option<MemberKeys>,
}

impl P {
    fn mk(&self) -> &MemberKeys {
        self.keys.as_ref().expect("member keys")
    }
}

async fn person(t: &TestApp, name: &str, member_keys: bool) -> P {
    let email = format!("{name}@example.org");
    let (id, s) = t.sign_in(&email).await;
    let keys = if member_keys {
        Some(t.create_member_keys(&id, &s).await)
    } else {
        None
    };
    P { id, s, email, keys }
}

async fn group_by(t: &TestApp, f: &P) -> String {
    let r = t
        .post(
            "/v1/groups",
            json!({ "name": NAME, "description": "d" }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

async fn join(t: &TestApp, by: &P, gid: &str, p: &P) {
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [p.email] }),
            Some(&by.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let tok = token_from_email(r.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    let a = t
        .post(
            &format!("/v1/group-invites/{tok}/accept"),
            json!({}),
            Some(&p.s),
        )
        .await;
    assert_eq!(a.status, StatusCode::CREATED, "{:?}", a.body);
}

/// The recipients the instance offers, as the composer loads them.
async fn recipients(t: &TestApp, s: &str, query: &str) -> Value {
    let r = t
        .get(&format!("/v1/me/message-recipients?{query}"), Some(s))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{query}: {:?}", r.body);
    r.body
}

/// Seal and sign as the author's browser does, to the recipients the
/// instance offered (those with a key).
fn compose(
    t: &TestApp,
    author: &P,
    offered: &Value,
    kind: GroupMessageKind,
    group: Option<&str>,
    text: Option<&str>,
) -> SealedGroupMessage {
    let mut rs: Vec<MessageRecipient> = offered["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| !r["enc_pubkey"].is_null())
        .map(|r| MessageRecipient {
            user_id: UserId::new(r["user_id"].as_str().unwrap()),
            enc_pubkey: EncPublicKey::from_b64(r["enc_pubkey"].as_str().unwrap()).unwrap(),
        })
        .collect();
    rs.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    let k = author.mk();
    seal_group_message(
        &k.sign,
        &k.enc.public(),
        message(t, author, kind, group, rs),
        text.map(|s| format!("{{\"text\":{}}}", serde_json::to_string(s).unwrap()))
            .as_deref()
            .map(str::as_bytes),
    )
    .unwrap()
}

fn message(
    t: &TestApp,
    author: &P,
    kind: GroupMessageKind,
    group: Option<&str>,
    recipients: Vec<MessageRecipient>,
) -> GroupMessage {
    GroupMessage {
        instance_id: t.instance_id(),
        group_id: group.map(str::to_owned),
        item_id: hex::encode(faro_crypto::random_bytes::<16>()),
        kind,
        author_id: author.id.clone(),
        issued_at_ms: t.clock_ms(),
        recipients,
        body_hash: Hash32::ZERO,
    }
}

/// Reach-out emails to `to` (other mail, such as an approval, arrives
/// asynchronously).
fn reach_mail(t: &TestApp, to: &str) -> Vec<faro_server::mailer::Email> {
    t.mail_to(to)
        .into_iter()
        .filter(|m| m.subject.contains("is reaching out"))
        .collect()
}

async fn reach_out(t: &TestApp, s: &str, body: Value) -> Resp {
    t.post("/v1/me/reach-outs", body, Some(s)).await
}

async fn mine(t: &TestApp, s: &str) -> Value {
    let r = t.get("/v1/me/reach-outs", Some(s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body
}

/// What a recipient's browser does: fetch, verify against the author's
/// key, open with its own key.
async fn read(t: &TestApp, s: &str, id: &str, me: &UserId, key: &EncryptionKeypair) -> String {
    let r = t.get(&format!("/v1/group-messages/{id}"), Some(s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let pk = SignPublicKey::from_b64(r.body["author"]["sign_pubkey"].as_str().unwrap()).unwrap();
    let sealed: SealedGroupMessage = serde_json::from_value(json!({
        "message": r.body["message"],
        "body": r.body["body"],
    }))
    .unwrap();
    verify_group_message(&pk, &sealed).expect("verifies");
    let pt = open_group_message(&sealed, me, key).unwrap().unwrap();
    let v: Value = serde_json::from_slice(&pt).unwrap();
    v["text"].as_str().unwrap().to_owned()
}

/// Sam (a member) with two allies, Jo and Kim.
struct World {
    t: TestApp,
    sam: P,
    jo: Ally,
    kim: Ally,
}

async fn world() -> World {
    let t = TestApp::new().await;
    let sam = person(&t, "sam", true).await;
    let jo = t
        .link_ally(&sam.id, sam.mk(), &sam.s, "jo@example.org")
        .await;
    let kim = t
        .link_ally(&sam.id, sam.mk(), &sam.s, "kim@example.org")
        .await;
    t.mailer.clear();
    World { t, sam, jo, kim }
}

#[tokio::test]
async fn a_signed_reach_out_to_my_allies_is_read_only_by_them() {
    let w = world().await;
    let t = &w.t;
    let offered = recipients(t, &w.sam.s, "audience=allies").await;
    assert_eq!(offered["can_sign"], true);
    assert_eq!(offered["recipients"].as_array().unwrap().len(), 2);
    assert!(offered["recipients"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["sender_ally"] == true && r["source"] == "ally_key"));
    let m = compose(
        t,
        &w.sam,
        &offered,
        GroupMessageKind::ReachOut,
        None,
        Some(SECRET),
    );
    let r = reach_out(t, &w.sam.s, json!({ "audience": "allies", "message": m })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["signed"], true);
    assert_eq!(r.body["recipients"].as_array().unwrap().len(), 2);
    let mid = r.body["message_id"].as_str().unwrap().to_owned();
    assert_eq!(mid, m.message.body.item_id);

    // The instance stored ciphertext only.
    let stored: String = sqlx::query_scalar(
        "SELECT COALESCE(body_json, '') || message_json FROM group_messages WHERE id = $1",
    )
    .bind(&mid)
    .fetch_one(t.state.db().pool())
    .await
    .unwrap();
    assert!(!stored.contains("Narwhal"));

    // Each ally reads it in their browser; so does Sam.
    let inc = mine(t, &w.jo.session).await;
    let ro = &inc["incoming"][0];
    assert!(ro["from"]["display_name"].as_str().is_some());
    assert_eq!(ro["signed"], true);
    assert_eq!(ro["message_id"], mid.as_str());
    assert_eq!(
        read(t, &w.jo.session, &mid, &w.jo.id, &w.jo.keys.enc).await,
        SECRET
    );
    assert_eq!(
        read(t, &w.kim.session, &mid, &w.kim.id, &w.kim.keys.enc).await,
        SECRET
    );
    assert_eq!(
        read(t, &w.sam.s, &mid, &w.sam.id, &w.sam.mk().enc).await,
        SECRET
    );
    // Anyone else: 404.
    let (_, other) = t.sign_in("zed@example.org").await;
    let r = t
        .get(&format!("/v1/group-messages/{mid}"), Some(&other))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    assert!(mine(t, &other).await["incoming"]
        .as_array()
        .unwrap()
        .is_empty());

    // An urgent, immediate, content-free email to each ally.
    t.notify_now().await;
    for email in [&w.jo.email, &w.kim.email] {
        let mail = reach_mail(t, email);
        assert_eq!(mail.len(), 1, "{mail:?}");
        assert!(mail[0].subject.contains("is reaching out"), "{mail:?}");
        assert!(mail[0].text.contains("Open Faro to see."));
        assert!(!mail[0].text.contains("Narwhal") && !mail[0].subject.contains("Narwhal"));
    }
    assert!(reach_mail(t, &w.sam.email).is_empty());
}

#[tokio::test]
async fn forged_and_misdirected_messages_are_refused() {
    let w = world().await;
    let t = &w.t;
    let offered = recipients(t, &w.sam.s, "audience=allies").await;
    let good = compose(
        t,
        &w.sam,
        &offered,
        GroupMessageKind::ReachOut,
        None,
        Some("x"),
    );

    // Signed with a key that isn't Sam's (what an operator could do).
    let mallory = SigningKey::generate();
    let forged = seal_group_message(
        &mallory,
        &w.sam.mk().enc.public(),
        good.message.body.clone(),
        Some(b"{\"text\":\"forged\"}"),
    )
    .unwrap();
    let r = reach_out(t, &w.sam.s, json!({ "message": forged })).await;
    assert_eq!(r.error_code(), "bad_signature", "{:?}", r.body);

    // An edited header no longer verifies.
    let mut edited = good.clone();
    edited.message.body.issued_at_ms += 1;
    let r = reach_out(t, &w.sam.s, json!({ "message": edited })).await;
    assert_eq!(r.error_code(), "bad_signature", "{:?}", r.body);

    // Someone else's message, or a message as someone else.
    let r = reach_out(
        t,
        &w.jo.session,
        json!({ "audience": "people", "user_ids": [w.sam.id], "message": good }),
    )
    .await;
    assert_eq!(r.error_code(), "invalid_message", "{:?}", r.body);

    // Sealed to someone it can't go to.
    let zed = person(t, "zed", true).await;
    let mut rs = good.message.body.recipients.clone();
    rs.push(MessageRecipient {
        user_id: zed.id.clone(),
        enc_pubkey: zed.mk().enc.public(),
    });
    rs.sort_by(|a, b| a.user_id.cmp(&b.user_id));
    let k = w.sam.mk();
    let wide = seal_group_message(
        &k.sign,
        &k.enc.public(),
        message(t, &w.sam, GroupMessageKind::ReachOut, None, rs),
        Some(b"{\"text\":\"x\"}"),
    )
    .unwrap();
    let r = reach_out(t, &w.sam.s, json!({ "message": wide })).await;
    assert_eq!(r.error_code(), "invalid_message", "{:?}", r.body);

    // Sealed to a key that isn't the recipient's.
    let mut rs = good.message.body.recipients.clone();
    rs[0].enc_pubkey = EncryptionKeypair::generate().public();
    let swapped = seal_group_message(
        &k.sign,
        &k.enc.public(),
        message(t, &w.sam, GroupMessageKind::ReachOut, None, rs),
        None,
    )
    .unwrap();
    let r = reach_out(t, &w.sam.s, json!({ "message": swapped })).await;
    assert_eq!(r.error_code(), "stale_recipient_key", "{:?}", r.body);

    // The wrong kind, a group that isn't the reach out's, an old message.
    let note = compose(
        t,
        &w.sam,
        &offered,
        GroupMessageKind::JoinRequestNote,
        Some("0123456789abcdef0123456789abcdef"),
        None,
    );
    let r = reach_out(t, &w.sam.s, json!({ "message": note })).await;
    assert_eq!(r.error_code(), "invalid_message", "{:?}", r.body);
    t.clock.advance_ms(10 * 60 * 1000);
    let r = reach_out(t, &w.sam.s, json!({ "message": good })).await;
    assert_eq!(r.error_code(), "clock_skew", "{:?}", r.body);

    // Nothing was sent.
    assert!(mine(t, &w.jo.session).await["incoming"]
        .as_array()
        .unwrap()
        .is_empty());
    // And the same id can't be used twice.
    let fresh = compose(
        t,
        &w.sam,
        &offered,
        GroupMessageKind::ReachOut,
        None,
        Some("x"),
    );
    let r = reach_out(t, &w.sam.s, json!({ "message": fresh })).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = reach_out(t, &w.sam.s, json!({ "message": fresh })).await;
    assert_eq!(r.error_code(), "message_exists", "{:?}", r.body);
}

#[tokio::test]
async fn three_reach_outs_an_hour() {
    let w = world().await;
    let t = &w.t;
    for _ in 0..3 {
        let r = reach_out(t, &w.sam.s, json!({})).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        assert_eq!(r.body["signed"], false);
        t.clock.advance_ms(60_000);
    }
    let r = reach_out(t, &w.sam.s, json!({})).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS, "{:?}", r.body);
    let retry: u64 = r.headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!(retry > 3000 && retry <= 3600, "{retry}");
    t.clock.advance_ms(HOUR - 2 * 60_000);
    let (_, s) = t.sign_in(&w.sam.email).await;
    let r = reach_out(t, &s, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        mine(t, &w.jo.session).await["incoming"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn quiet_hours_hold_reach_outs_unless_the_sender_is_let_through() {
    let w = world().await;
    let t = &w.t;
    // 23:00 UTC; Jo and Kim are quiet 22:00-07:00.
    let midnight = t.clock_ms() - t.clock_ms().rem_euclid(DAY);
    t.clock.set_ms(midnight + DAY + 23 * HOUR);
    let jo = t.sign_in(&w.jo.email).await.1;
    let kim = t.sign_in(&w.kim.email).await.1;
    let sam = t.sign_in(&w.sam.email).await.1;
    for (who, s) in [(&w.jo.id, &jo), (&w.kim.id, &kim)] {
        let r = t
            .call(
                Method::PUT,
                "/v1/me/notification-prefs",
                Some(json!({
                    "member_id": who,
                    "quiet_hours": {"start_min": 1320, "end_min": 420, "tz_offset_min": 0}
                })),
                Some(s),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
    // Jo lets Sam's reach outs through.
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/quiet-hours-bypass/{}", w.sam.id),
            None,
            Some(&jo),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let settings = t.get("/v1/me/reach-out-settings", Some(&jo)).await;
    assert_eq!(settings.body[0]["user_id"], w.sam.id.as_str());
    assert_eq!(settings.body[0]["quiet_hours_bypass"], true);
    assert_eq!(settings.body[0]["mode"], "immediate");

    t.mailer.clear();
    let r = reach_out(t, &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    t.notify_now().await;
    assert_eq!(reach_mail(t, &w.jo.email).len(), 1, "let through");
    assert!(
        reach_mail(t, &w.kim.email).is_empty(),
        "held for quiet hours"
    );
    assert_eq!(
        mine(t, &jo).await["incoming"][0]["quiet_hours_bypass"],
        true
    );
    assert_eq!(
        mine(t, &kim).await["incoming"][0]["quiet_hours_bypass"],
        false
    );
    // 07:00: Kim's arrives.
    t.clock.set_ms(midnight + 2 * DAY + 7 * HOUR);
    t.notify_now().await;
    assert_eq!(reach_mail(t, &w.kim.email).len(), 1);

    // Kim switches Sam's reach outs off (not tamper-class: it holds), Jo
    // takes the bypass back.
    let kim = t.sign_in(&w.kim.email).await.1;
    let jo = t.sign_in(&w.jo.email).await.1;
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/reach-out-prefs/{}", w.sam.id),
            Some(json!({ "mode": "off" })),
            Some(&kim),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let r = t
        .call(
            Method::DELETE,
            &format!("/v1/me/quiet-hours-bypass/{}", w.sam.id),
            None,
            Some(&jo),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    t.clock.set_ms(midnight + 2 * DAY + 23 * HOUR);
    t.mailer.clear();
    let sam = t.sign_in(&w.sam.email).await.1;
    let r = reach_out(t, &sam, json!({})).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    t.notify_now().await;
    assert!(reach_mail(t, &w.jo.email).is_empty(), "quiet again");
    t.clock.set_ms(midnight + 3 * DAY + 8 * HOUR);
    t.notify_now().await;
    assert_eq!(reach_mail(t, &w.jo.email).len(), 1);
    assert!(reach_mail(t, &w.kim.email).is_empty(), "switched off");
    // Still in Faro.
    let kim = t.sign_in(&w.kim.email).await.1;
    assert_eq!(mine(t, &kim).await["incoming"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn answers_reach_the_sender_and_the_others_see_someone_did() {
    let w = world().await;
    let t = &w.t;
    let r = reach_out(t, &w.sam.s, json!({})).await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    let r = t
        .post(
            &format!("/v1/reach-outs/{id}/answer"),
            json!({ "answer": "call" }),
            Some(&w.jo.session),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["my_answer"], "call");
    let kim = mine(t, &w.kim.session).await;
    assert_eq!(kim["incoming"][0]["others_answered"]["call"], 1);
    assert!(kim["incoming"][0]["my_answer"].is_null());
    let out = mine(t, &w.sam.s).await;
    let rs = out["outgoing"][0]["recipients"].as_array().unwrap();
    assert!(rs
        .iter()
        .any(|r| r["user_id"] == w.jo.id.as_str() && r["answer"] == "call"));
    assert!(rs
        .iter()
        .any(|r| r["user_id"] == w.kim.id.as_str() && r["answer"].is_null()));
    // Changing the answer is quiet; strangers and the sender can't answer.
    let r = t
        .post(
            &format!("/v1/reach-outs/{id}/answer"),
            json!({ "answer": "here" }),
            Some(&w.jo.session),
        )
        .await;
    assert_eq!(r.body["my_answer"], "here");
    let r = t
        .post(
            &format!("/v1/reach-outs/{id}/answer"),
            json!({ "answer": "here" }),
            Some(&w.sam.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Sam is told once, in the digest (a normal notice), naming Jo.
    t.notify_now().await;
    let s = t.digest_now().await;
    assert!(s.sent >= 1, "{s:?}");
    let mail = t.mail_to(&w.sam.email);
    let answered: Vec<_> = mail
        .iter()
        .filter(|m| m.text.contains("answered on"))
        .collect();
    assert_eq!(answered.len(), 1, "{mail:?}");
}

#[tokio::test]
async fn ally_only_senders_reach_out_unverified_and_groups_bound_audiences() {
    let t = TestApp::new().await;
    let fay = person(&t, "fay", true).await;
    let gid = group_by(&t, &fay).await;
    let al = person(&t, "al", false).await;
    let bea = person(&t, "bea", true).await;
    join(&t, &fay, &gid, &al).await;
    join(&t, &fay, &gid, &bea).await;
    let outsider = person(&t, "out", true).await;

    // Al has no member keys: he can't sign, so content-free only.
    let offered = recipients(&t, &al.s, &format!("audience=facilitators&group_id={gid}")).await;
    assert_eq!(offered["can_sign"], false);
    assert_eq!(offered["recipients"][0]["user_id"], fay.id.as_str());
    assert_eq!(offered["recipients"][0]["sender_ally"], false);
    let r = reach_out(
        &t,
        &al.s,
        json!({ "audience": "facilitators", "group_id": gid }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["signed"], false);
    assert!(r.body["message_id"].is_null());
    let inc = mine(&t, &fay.s).await;
    assert_eq!(inc["incoming"][0]["signed"], false);
    assert_eq!(inc["incoming"][0]["group_name"], NAME);
    // A message from someone without member keys is refused.
    let msg = compose(
        &t,
        &bea,
        &offered,
        GroupMessageKind::ReachOut,
        Some(&gid),
        None,
    );
    let mut forged = msg.clone();
    forged.message.body.author_id = al.id.clone();
    let r = reach_out(
        &t,
        &al.s,
        json!({ "audience": "facilitators", "group_id": gid, "message": forged }),
    )
    .await;
    assert_eq!(r.error_code(), "member_keys_required", "{:?}", r.body);
    // No allies: nobody to reach with "my allies".
    let r = reach_out(&t, &al.s, json!({})).await;
    assert_eq!(r.error_code(), "no_recipients", "{:?}", r.body);

    // Named people: in the group only, at most 32, not yourself.
    let offered = recipients(
        &t,
        &bea.s,
        &format!(
            "audience=people&group_id={gid}&user_ids={},{}",
            fay.id, al.id
        ),
    )
    .await;
    let names = offered["recipients"].as_array().unwrap();
    assert_eq!(names.len(), 2);
    assert!(
        names
            .iter()
            .any(|r| r["user_id"] == al.id.as_str() && r["enc_pubkey"].is_null()),
        "no key yet"
    );
    let m = compose(
        &t,
        &bea,
        &offered,
        GroupMessageKind::ReachOut,
        Some(&gid),
        Some("hello"),
    );
    assert_eq!(m.message.body.recipients.len(), 1, "sealed only to Fay");
    let r = reach_out(
        &t,
        &bea.s,
        json!({ "audience": "people", "group_id": gid, "user_ids": [fay.id, al.id], "message": m }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        r.body["recipients"].as_array().unwrap().len(),
        2,
        "Al is still told"
    );
    let r = t
        .get(
            &format!(
                "/v1/me/message-recipients?audience=people&group_id={gid}&user_ids={}",
                outsider.id
            ),
            Some(&bea.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .get(
            &format!(
                "/v1/me/message-recipients?audience=people&group_id={gid}&user_ids={}",
                bea.id
            ),
            Some(&bea.s),
        )
        .await;
    assert_eq!(r.error_code(), "cannot_reach_self");
    let many: Vec<String> = (0..33).map(|i| format!("usr_{i:03}")).collect();
    let r = reach_out(
        &t,
        &bea.s,
        json!({ "audience": "people", "group_id": gid, "user_ids": many }),
    )
    .await;
    assert_eq!(r.error_code(), "invalid_recipients");
    // Outside any group, named people must be linked to the sender.
    let r = reach_out(
        &t,
        &bea.s,
        json!({ "audience": "people", "user_ids": [fay.id] }),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // An outsider can't reach a group's facilitators.
    let r = reach_out(
        &t,
        &outsider.s,
        json!({ "audience": "facilitators", "group_id": gid }),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // There's no whole-group audience.
    let r = reach_out(&t, &bea.s, json!({ "audience": "group", "group_id": gid })).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn proposal_notes_are_for_the_recipient_only() {
    let t = TestApp::new().await;
    let fay = person(&t, "fay", true).await;
    let gid = group_by(&t, &fay).await;
    let ann = person(&t, "ann", true).await;
    let ben = person(&t, "ben", true).await;
    let cat = person(&t, "cat", true).await;
    join(&t, &fay, &gid, &ann).await;
    join(&t, &fay, &gid, &ben).await;
    join(&t, &fay, &gid, &cat).await;

    let offered = recipients(
        &t,
        &ann.s,
        &format!("for=proposal_note&group_id={gid}&user_ids={}", ben.id),
    )
    .await;
    let note = compose(
        &t,
        &ann,
        &offered,
        GroupMessageKind::ProposalNote,
        Some(&gid),
        Some("We met at the retreat. Narwhal"),
    );
    let r = t
        .post(
            &format!("/v1/groups/{gid}/proposals"),
            json!({ "to": ben.id, "kind": "request", "note": note }),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let nid = note.message.body.item_id.clone();
    assert_eq!(r.body["note_id"], nid.as_str());
    let inc = t.get("/v1/me/proposals", Some(&ben.s)).await;
    assert_eq!(inc.body["incoming"][0]["note_id"], nid.as_str());
    let text = read(&t, &ben.s, &nid, &ben.id, &ben.mk().enc).await;
    assert!(text.contains("retreat"));
    // The facilitator can't see it.
    let r = t
        .get(&format!("/v1/group-messages/{nid}"), Some(&fay.s))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // A note sealed to someone else, or for another group, is refused.
    let wrong = compose(
        &t,
        &ann,
        &offered,
        GroupMessageKind::ProposalNote,
        Some(&gid),
        Some("x"),
    );
    let r = t
        .post(
            &format!("/v1/groups/{gid}/proposals"),
            json!({ "to": fay.id, "kind": "request", "note": wrong }),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.error_code(), "invalid_message", "{:?}", r.body);
    let r = t.get("/v1/me/proposals", Some(&ann.s)).await;
    assert_eq!(
        r.body["outgoing"].as_array().unwrap().len(),
        1,
        "nothing half-made"
    );

    // Cat blocked Ann: her proposal is hidden from Cat, and so is its note.
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/proposal-blocks/{}", ann.id),
            None,
            Some(&cat.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let offered = recipients(
        &t,
        &ann.s,
        &format!("for=proposal_note&group_id={gid}&user_ids={}", cat.id),
    )
    .await;
    let note = compose(
        &t,
        &ann,
        &offered,
        GroupMessageKind::ProposalNote,
        Some(&gid),
        Some("again"),
    );
    let r = t
        .post(
            &format!("/v1/groups/{gid}/proposals"),
            json!({ "to": cat.id, "kind": "request", "note": note }),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let hidden = note.message.body.item_id.clone();
    let r = t
        .get(&format!("/v1/group-messages/{hidden}"), Some(&cat.s))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .get(&format!("/v1/group-messages/{hidden}"), Some(&ann.s))
        .await;
    assert_eq!(r.status, StatusCode::OK);

    // Purging Ann's proposals takes their notes with them.
    sqlx::query("DELETE FROM alliance_proposals")
        .execute(t.state.db().pool())
        .await
        .unwrap();
    t.clock.advance_ms(2 * HOUR);
    faro_server::retention::run_once(&t.state).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM group_messages")
        .fetch_one(t.state.db().pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn join_request_notes_go_to_the_facilitators() {
    let t = TestApp::new().await;
    let fay = person(&t, "fay", true).await;
    let gid = group_by(&t, &fay).await;
    let r = t
        .call(
            Method::PATCH,
            &format!("/v1/groups/{gid}"),
            Some(json!({ "listed": true })),
            Some(&fay.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let pia = person(&t, "pia", true).await;
    let offered = recipients(&t, &pia.s, &format!("for=join_request_note&group_id={gid}")).await;
    assert_eq!(offered["recipients"][0]["user_id"], fay.id.as_str());
    let note = compose(
        &t,
        &pia,
        &offered,
        GroupMessageKind::JoinRequestNote,
        Some(&gid),
        Some("I'm new to the church."),
    );
    let r = t
        .post(
            &format!("/v1/groups/{gid}/join-requests"),
            json!({ "note": note }),
            Some(&pia.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let list = t
        .get(&format!("/v1/groups/{gid}/join-requests"), Some(&fay.s))
        .await;
    let nid = list.body["items"][0]["note_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let text = read(&t, &fay.s, &nid, &fay.id, &fay.mk().enc).await;
    assert_eq!(text, "I'm new to the church.");
    let r = t
        .get(&format!("/v1/group-messages/{nid}"), Some(&pia.s))
        .await;
    assert_eq!(r.status, StatusCode::OK, "the author reads their own");
    // Unlisted groups have no recipients; strangers can't read the note.
    let other = person(&t, "oz", true).await;
    let r = t
        .get(&format!("/v1/group-messages/{nid}"), Some(&other.s))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = t
        .call(
            Method::PATCH,
            &format!("/v1/groups/{gid}"),
            Some(json!({ "listed": false })),
            Some(&fay.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .get(
            &format!("/v1/me/message-recipients?for=join_request_note&group_id={gid}"),
            Some(&other.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}
