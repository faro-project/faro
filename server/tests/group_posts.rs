//! Check-ins and replies, whole-group posts sealed with the epoch key, and
//! whole-group reach outs (docs/GROUPS.md §8.3, §8.6, §10.5, §18, §19;
//! PROTOCOL.md §11): who is served what, that the instance can read and
//! forge nothing, that a check-in never notifies, that posting waits while
//! roster work is pending, and what retention keeps.

mod common;

use axum::http::StatusCode;
use common::roster::{roster, sign_pending};
use common::*;
use faro_crypto::roster::open_epoch_key;
use faro_crypto::{
    open_group_message, open_group_message_with_epoch, seal_group_message,
    seal_group_message_to_epoch, verify_group_message, EncryptionKeypair,
};
use faro_proto::encoding::b64_decode;
use faro_proto::group::{
    CheckInText, GroupMessage, GroupMessageKind, MessageRecipient, SealedGroupMessage,
};
use faro_proto::{EncPublicKey, Hash32, SignPublicKey, UserId};
use serde_json::{json, Value};

const DAY: i64 = 24 * 3600 * 1000;
const SECRET: &str = "I slipped on Tuesday. Narwhal";

struct P {
    id: UserId,
    s: String,
    email: String,
    keys: MemberKeys,
}

async fn person(t: &TestApp, name: &str) -> P {
    let email = format!("{name}@example.org");
    let (id, s) = t.sign_in(&email).await;
    let keys = t.create_member_keys(&id, &s).await;
    P { id, s, email, keys }
}

async fn group_by(t: &TestApp, f: &P) -> String {
    let r = t
        .post("/v1/groups", json!({ "name": "Tuesday" }), Some(&f.s))
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

/// A group of `f` (a facilitator) and `others`, with the roster signed.
/// Returns the group id and the current epoch's key.
async fn signed_group(t: &TestApp, f: &P, others: &[&P]) -> (String, u64, [u8; 32]) {
    let gid = group_by(t, f).await;
    for p in others {
        join(t, f, &gid, p).await;
    }
    let keys = sign_pending(t, &gid, (&f.id, &f.s), &f.keys.sign).await;
    let (epoch, key) = *keys.last().expect("an epoch");
    (gid, epoch, key)
}

async fn recipients(t: &TestApp, s: &str, query: &str) -> Value {
    let r = t
        .get(&format!("/v1/me/message-recipients?{query}"), Some(s))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{query}: {:?}", r.body);
    r.body
}

fn header(
    t: &TestApp,
    author: &P,
    kind: GroupMessageKind,
    gid: &str,
    recipients: Vec<MessageRecipient>,
) -> GroupMessage {
    GroupMessage {
        instance_id: t.instance_id(),
        group_id: Some(gid.to_owned()),
        item_id: hex::encode(faro_crypto::random_bytes::<16>()),
        kind,
        author_id: author.id.clone(),
        issued_at_ms: t.clock_ms(),
        recipients,
        body_hash: Hash32::ZERO,
        epoch: None,
        parent_id: None,
    }
}

fn offered(v: &Value) -> Vec<MessageRecipient> {
    let mut rs: Vec<MessageRecipient> = v["recipients"]
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
    rs
}

fn check_in_json(secret: &str) -> Vec<u8> {
    serde_json::to_vec(&CheckInText {
        scale: 2,
        went_well: None,
        was_hard: Some(secret.to_owned()),
        ask: Some("A call on Sunday".into()),
    })
    .unwrap()
}

/// A check-in sealed to the recipients the instance offered (and to the author).
async fn check_in_to(t: &TestApp, author: &P, gid: &str, query: &str) -> SealedGroupMessage {
    let o = recipients(
        t,
        &author.s,
        &format!("for=check_in&group_id={gid}&{query}"),
    )
    .await;
    seal_group_message(
        &author.keys.sign,
        &author.keys.enc.public(),
        header(t, author, GroupMessageKind::CheckIn, gid, offered(&o)),
        Some(&check_in_json(SECRET)),
    )
    .unwrap()
}

/// A check-in to the whole group, sealed with `epoch`'s key.
fn check_in_to_group(
    t: &TestApp,
    author: &P,
    gid: &str,
    epoch: u64,
    key: &[u8; 32],
) -> SealedGroupMessage {
    let mut h = header(t, author, GroupMessageKind::CheckIn, gid, vec![]);
    h.epoch = Some(epoch);
    seal_group_message_to_epoch(&author.keys.sign, key, h, Some(&check_in_json(SECRET))).unwrap()
}

async fn post(
    t: &TestApp,
    s: &str,
    gid: &str,
    audience: Option<&str>,
    m: &SealedGroupMessage,
) -> Resp {
    let mut body = json!({ "message": m });
    if let Some(a) = audience {
        body["audience"] = json!(a);
    }
    t.post(&format!("/v1/groups/{gid}/posts"), body, Some(s))
        .await
}

async fn feed(t: &TestApp, s: &str, gid: &str) -> Vec<Value> {
    let r = t.get(&format!("/v1/groups/{gid}/posts"), Some(s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body["items"].as_array().unwrap().clone()
}

/// What a browser does with a served post: verify against the author's
/// signing key as the instance gave it.
fn verified(item: &Value) -> SealedGroupMessage {
    let pk = SignPublicKey::from_b64(item["author"]["sign_pubkey"].as_str().unwrap()).unwrap();
    let sealed: SealedGroupMessage = serde_json::from_value(json!({
        "message": item["message"],
        "body": item["body"],
    }))
    .unwrap();
    verify_group_message(&pk, &sealed).expect("verifies");
    sealed
}

fn open_person(item: &Value, me: &UserId, key: &EncryptionKeypair) -> CheckInText {
    let pt = open_group_message(&verified(item), me, key)
        .unwrap()
        .unwrap();
    serde_json::from_slice(&pt).unwrap()
}

fn open_epoch(item: &Value, key: &[u8; 32]) -> CheckInText {
    let pt = open_group_message_with_epoch(&verified(item), key)
        .unwrap()
        .unwrap();
    serde_json::from_slice(&pt).unwrap()
}

#[tokio::test]
async fn check_ins_go_to_chosen_people_and_never_notify() {
    let t = TestApp::new().await;
    let f = person(&t, "fay").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "ben").await;
    let c = person(&t, "cat").await;
    let (gid, _, _) = signed_group(&t, &f, &[&a, &b, &c]).await;
    // Ann is Ben's ally (and in the group): "my allies in this group".
    let ann_ally = t.link_ally(&b.id, &b.keys, &b.s, &a.email).await;
    let (other_gid, _, _) = signed_group(&t, &f, &[&a]).await;
    let out = person(&t, "out").await;
    // Let what the setup caused (joins, the ally link) settle first.
    t.notify_now().await;
    t.mailer.clear();
    let before = [
        count(&t.state, "SELECT COUNT(*) FROM alerts").await,
        count(&t.state, "SELECT COUNT(*) FROM notifications").await,
        count(&t.state, "SELECT COUNT(*) FROM group_notices").await,
    ];

    // Ben's check-in to his allies: the default audience.
    let o = recipients(
        &t,
        &b.s,
        &format!("for=check_in&group_id={gid}&audience=allies"),
    )
    .await;
    assert_eq!(o["recipients"].as_array().unwrap().len(), 1);
    assert_eq!(o["recipients"][0]["user_id"], a.id.as_str());
    let m = check_in_to(&t, &b, &gid, "audience=allies").await;
    let r = post(&t, &b.s, &gid, None, &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["kind"], "check_in");
    let ben_post = r.body["id"].as_str().unwrap().to_owned();

    // Ann reads it with her ally key; Ben has his own copy; nobody else sees it.
    let items = feed(&t, &a.s, &gid).await;
    assert_eq!(items.len(), 1);
    let ci = open_person(&items[0], &a.id, &ann_ally.keys.enc);
    assert_eq!(ci.scale, 2);
    assert_eq!(ci.was_hard.as_deref(), Some(SECRET));
    assert_eq!(feed(&t, &b.s, &gid).await.len(), 1);
    assert_eq!(
        open_person(&feed(&t, &b.s, &gid).await[0], &b.id, &b.keys.enc).scale,
        2
    );
    for p in [&c, &f] {
        assert!(feed(&t, &p.s, &gid).await.is_empty(), "{}", p.email);
    }

    // The instance holds ciphertext only.
    let stored: String = sqlx::query_scalar(
        "SELECT COALESCE(body_json, '') || message_json FROM group_posts WHERE id = $1",
    )
    .bind(&ben_post)
    .fetch_one(t.state.db().pool())
    .await
    .unwrap();
    assert!(!stored.contains("Narwhal"));

    // Cat's check-in to the facilitators reaches Fay only.
    let m = check_in_to(&t, &c, &gid, "audience=facilitators").await;
    let r = post(&t, &c.s, &gid, Some("facilitators"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(feed(&t, &f.s, &gid).await.len(), 1);
    assert_eq!(
        open_person(&feed(&t, &f.s, &gid).await[0], &f.id, &f.keys.enc).scale,
        2
    );
    assert_eq!(feed(&t, &a.s, &gid).await.len(), 1, "only Ben's");

    // A check-in to named people: Ann writes to Fay and Cat.
    let q = format!("audience=people&user_ids={},{}", f.id, c.id);
    let m = check_in_to(&t, &a, &gid, &q).await;
    let r = post(&t, &a.s, &gid, Some("people"), &m).await;
    // (the request names them too)
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "user_ids are required: {:?}",
        r.body
    );
    let body = json!({ "audience": "people", "user_ids": [f.id, c.id], "message": m });
    let r = t
        .post(&format!("/v1/groups/{gid}/posts"), body, Some(&a.s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(feed(&t, &c.s, &gid).await.len(), 2);
    assert_eq!(feed(&t, &b.s, &gid).await.len(), 1, "Ben isn't named");

    // Bad posts: a signature from another key, another group, someone who
    // isn't in the group, and a message that isn't a check-in.
    let mut forged = check_in_to(&t, &c, &gid, "audience=facilitators").await;
    forged.message.sig = f.keys.sign.sign(&forged.message.body);
    let r = post(&t, &c.s, &gid, Some("facilitators"), &forged).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "bad_signature");
    let m = check_in_to(&t, &c, &gid, "audience=facilitators").await;
    let r = post(&t, &c.s, &other_gid, Some("facilitators"), &m).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "Cat isn't in that group");
    let r = post(&t, &a.s, &other_gid, Some("facilitators"), &m).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "it names another group");
    let mut note = header(
        &t,
        &c,
        GroupMessageKind::ReachOut,
        &gid,
        offered(
            &recipients(
                &t,
                &c.s,
                &format!("for=check_in&group_id={gid}&audience=facilitators"),
            )
            .await,
        ),
    );
    note.kind = GroupMessageKind::ReachOut;
    let m = seal_group_message(
        &c.keys.sign,
        &c.keys.enc.public(),
        note,
        Some(b"{\"text\":\"x\"}"),
    )
    .unwrap();
    let r = post(&t, &c.s, &gid, Some("facilitators"), &m).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // An outsider can't read the feed at all.
    let r = t
        .get(&format!("/v1/groups/{gid}/posts"), Some(&out.s))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // Nothing above notified anybody: no alert, notice or email.
    t.notify_now().await;
    assert_eq!(
        [
            count(&t.state, "SELECT COUNT(*) FROM alerts").await,
            count(&t.state, "SELECT COUNT(*) FROM notifications").await,
            count(&t.state, "SELECT COUNT(*) FROM group_notices").await,
        ],
        before
    );
    assert!(t.mailer.sent().is_empty(), "{:?}", t.mailer.sent());
}

#[tokio::test]
async fn replies_are_private_to_the_checkins_author() {
    let t = TestApp::new().await;
    let f = person(&t, "fay").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "ben").await;
    let (gid, epoch, key) = signed_group(&t, &f, &[&a, &b]).await;

    // Ann checks in to the whole group; Ben answers privately.
    let m = check_in_to_group(&t, &a, &gid, epoch, &key);
    let r = post(&t, &a.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let parent = r.body["id"].as_str().unwrap().to_owned();

    let o = recipients(
        &t,
        &b.s,
        &format!("for=check_in_reply&group_id={gid}&user_ids={}", a.id),
    )
    .await;
    let reply = |author: &P, to: Vec<MessageRecipient>, parent: &str| {
        let mut h = header(&t, author, GroupMessageKind::CheckInReply, &gid, to);
        h.parent_id = Some(parent.to_owned());
        seal_group_message(
            &author.keys.sign,
            &author.keys.enc.public(),
            h,
            Some(b"{\"text\":\"Proud of you. Calling Sunday. Quokka\"}"),
        )
        .unwrap()
    };
    let m = reply(&b, offered(&o), &parent);
    let r = post(&t, &b.s, &gid, None, &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["kind"], "check_in_reply");
    assert_eq!(r.body["parent_id"], parent.as_str());

    // Ann has the check-in and the reply; Ben has the check-in (whole
    // group) and his reply; Fay has only the check-in.
    let by_kind = |items: &[Value], k: &str| items.iter().filter(|i| i["kind"] == k).count();
    let (ia, ib, iff) = (
        feed(&t, &a.s, &gid).await,
        feed(&t, &b.s, &gid).await,
        feed(&t, &f.s, &gid).await,
    );
    assert_eq!(
        (by_kind(&ia, "check_in"), by_kind(&ia, "check_in_reply")),
        (1, 1)
    );
    assert_eq!(
        (by_kind(&ib, "check_in"), by_kind(&ib, "check_in_reply")),
        (1, 1)
    );
    assert_eq!(
        (by_kind(&iff, "check_in"), by_kind(&iff, "check_in_reply")),
        (1, 0)
    );
    let ann_reply = ia.iter().find(|i| i["kind"] == "check_in_reply").unwrap();
    let pt = open_group_message(&verified(ann_reply), &a.id, &a.keys.enc)
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(pt.to_vec()).unwrap().contains("Quokka"));

    // One reply each; not to yourself; not to something you can't see; not
    // to the wrong person.
    let r = post(&t, &b.s, &gid, None, &reply(&b, offered(&o), &parent)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "already_replied");
    let to_ben = recipients(
        &t,
        &a.s,
        &format!("for=check_in_reply&group_id={gid}&user_ids={}", b.id),
    )
    .await;
    let r = post(&t, &a.s, &gid, None, &reply(&a, offered(&to_ben), &parent)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    assert_eq!(r.error_code(), "cannot_reply_to_self");
    let fa = recipients(
        &t,
        &f.s,
        &format!("for=check_in_reply&group_id={gid}&user_ids={}", b.id),
    )
    .await;
    // Fay replies to Ann's check-in but seals it to Ben: refused.
    let r = post(&t, &f.s, &gid, None, &reply(&f, offered(&fa), &parent)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    // A check-in Fay can't see can't be replied to.
    let m = check_in_to(&t, &b, &gid, "audience=facilitators").await;
    let r = post(&t, &b.s, &gid, Some("facilitators"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let ben_post = r.body["id"].as_str().unwrap().to_owned();
    let r = post(
        &t,
        &a.s,
        &gid,
        None,
        &reply(&a, offered(&to_ben), &ben_post),
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn whole_group_posts_use_the_epoch_key_and_follow_the_roster() {
    let t = TestApp::new().await;
    let f = person(&t, "fay").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "ben").await;
    let c = person(&t, "cat").await;
    let (gid, epoch, key) = signed_group(&t, &f, &[&a, &b, &c]).await;

    // One envelope, whatever the size; every participant reads it with
    // their own sealed copy of the epoch key.
    let m = check_in_to_group(&t, &a, &gid, epoch, &key);
    assert_eq!(m.body.as_ref().unwrap().envelopes.len(), 1);
    let r = post(&t, &a.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["epoch"], epoch);
    let state = roster(&t, &gid, &c.s).await;
    let mine = t
        .get(
            &format!("/v1/groups/{gid}/epoch-key?epoch={epoch}"),
            Some(&c.s),
        )
        .await;
    let opened = open_epoch_key(
        &c.keys.enc,
        &b64_decode(mine.body["sealed_key"].as_str().unwrap()).unwrap(),
        &t.instance_id(),
        &gid,
        epoch,
        &state.epoch_key_check,
    )
    .unwrap();
    for p in [&f, &b, &c, &a] {
        let items = feed(&t, &p.s, &gid).await;
        assert_eq!(items.len(), 1, "{}", p.email);
        assert_eq!(open_epoch(&items[0], &opened).scale, 2);
    }

    // The key must be the group's current one, and a whole-group post names
    // nobody.
    let stale = check_in_to_group(&t, &a, &gid, epoch + 1, &key);
    let r = post(&t, &a.s, &gid, Some("group"), &stale).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "stale_epoch");
    let to_people = check_in_to_group(&t, &a, &gid, epoch, &key);
    let r = post(&t, &a.s, &gid, Some("facilitators"), &to_people).await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "an epoch message to named people"
    );
    let named = check_in_to(&t, &a, &gid, "audience=facilitators").await;
    let r = post(&t, &a.s, &gid, Some("group"), &named).await;
    assert_eq!(
        r.status,
        StatusCode::BAD_REQUEST,
        "people-sealed to the whole group"
    );

    // Cat leaves. Her feed closes at once; whole-group posting waits for a
    // facilitator, while posts to named people carry on.
    let r = t
        .call(
            axum::http::Method::DELETE,
            &format!("/v1/groups/{gid}/me"),
            None,
            Some(&c.s),
        )
        .await;
    assert!(r.status.is_success(), "{:?}", r.body);
    let r = t.get(&format!("/v1/groups/{gid}/posts"), Some(&c.s)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let m = check_in_to_group(&t, &b, &gid, epoch, &key);
    let r = post(&t, &b.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "posting_paused");
    let m = check_in_to(&t, &b, &gid, "audience=facilitators").await;
    assert_eq!(
        post(&t, &b.s, &gid, Some("facilitators"), &m).await.status,
        StatusCode::CREATED
    );

    // A facilitator's client signs the departure and rotates. A joiner
    // after that sees what is posted from then on, not what came before.
    t.clock.advance_ms(1000);
    let d = person(&t, "dan").await;
    join(&t, &f, &gid, &d).await;
    let keys = sign_pending(&t, &gid, (&f.id, &f.s), &f.keys.sign).await;
    let (epoch2, key2) = *keys.last().unwrap();
    assert!(epoch2 > epoch);
    t.clock.advance_ms(1000);
    let m = check_in_to_group(&t, &b, &gid, epoch2, &key2);
    let r = post(&t, &b.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let latest = r.body["id"].as_str().unwrap().to_owned();
    // The old key doesn't open the new post, and Cat still can't ask.
    let items = feed(&t, &d.s, &gid).await;
    assert_eq!(items.len(), 1, "Dan sees only what came after he joined");
    assert_eq!(items[0]["id"], latest.as_str());
    assert!(open_group_message_with_epoch(&verified(&items[0]), &key).is_err());
    assert_eq!(open_epoch(&items[0], &key2).scale, 2);
    let r = t.get(&format!("/v1/groups/{gid}/posts"), Some(&c.s)).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The earlier whole-group post is still there for those who were in.
    assert_eq!(feed(&t, &a.s, &gid).await.len(), 2);
}

/// Active participants without keys, as the scale of a larger group needs.
async fn seed_participants(t: &TestApp, gid: &str, n: usize, prefix: &str) -> Vec<UserId> {
    let now = t.clock_ms();
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!("usr_{prefix}{i:05}");
        sqlx::query(
            "INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(format!("{prefix}{i}@example.org"))
        .bind(format!("Person {i}"))
        .bind(now)
        .execute(t.state.db().pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO group_participants (id, group_id, user_id, role, state, joined_via, joined_at)
             VALUES ($1, $2, $3, 'participant', 'active', 'invite', $4)",
        )
        .bind(format!("gp_{prefix}{i:05}"))
        .bind(gid)
        .bind(&id)
        .bind(now)
        .execute(t.state.db().pool())
        .await
        .unwrap();
        ids.push(UserId::new(id));
    }
    ids
}

fn reach_mail(t: &TestApp, to: &str) -> usize {
    t.mail_to(to)
        .into_iter()
        .filter(|m| m.subject.contains("is reaching out"))
        .count()
}

#[tokio::test]
async fn whole_group_reach_outs_only_in_groups_of_32_or_fewer() {
    let t = TestApp::new().await;
    let f = person(&t, "fay").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "ben").await;
    let (gid, epoch, key) = signed_group(&t, &f, &[&a, &b]).await;
    let out = person(&t, "out").await;
    t.mailer.clear();

    // Ann reaches out to the whole group with a message sealed with the
    // epoch key: one envelope, an urgent notice to everyone else.
    let mut h = header(&t, &a, GroupMessageKind::ReachOut, &gid, vec![]);
    h.epoch = Some(epoch);
    let m = seal_group_message_to_epoch(
        &a.keys.sign,
        &key,
        h,
        Some(b"{\"text\":\"Rough night. Narwhal\"}"),
    )
    .unwrap();
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid, "message": m }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["audience"], "group");
    assert_eq!(r.body["recipients"].as_array().unwrap().len(), 2);
    let mid = r.body["message_id"].as_str().unwrap().to_owned();
    t.notify_now().await;
    assert_eq!(reach_mail(&t, &f.email), 1);
    assert_eq!(reach_mail(&t, &b.email), 1);
    assert_eq!(reach_mail(&t, &a.email), 0);

    // Ben reads it with the epoch key; someone outside can't.
    let v = t
        .get(&format!("/v1/group-messages/{mid}"), Some(&b.s))
        .await;
    assert_eq!(v.status, StatusCode::OK, "{:?}", v.body);
    let pt = open_group_message_with_epoch(&verified(&v.body), &key)
        .unwrap()
        .unwrap();
    assert!(String::from_utf8(pt.to_vec()).unwrap().contains("Narwhal"));
    let v = t
        .get(&format!("/v1/group-messages/{mid}"), Some(&out.s))
        .await;
    assert_eq!(v.status, StatusCode::NOT_FOUND);
    let inc = t.get("/v1/me/reach-outs", Some(&b.s)).await;
    assert_eq!(inc.body["incoming"][0]["audience"], "group");

    // The message has to match the audience, and the epoch has to be current.
    for (aud, m, code) in [
        (
            "group",
            {
                let o =
                    recipients(&t, &a.s, &format!("group_id={gid}&audience=facilitators")).await;
                seal_group_message(
                    &a.keys.sign,
                    &a.keys.enc.public(),
                    header(&t, &a, GroupMessageKind::ReachOut, &gid, offered(&o)),
                    None,
                )
                .unwrap()
            },
            "invalid_message",
        ),
        (
            "group",
            {
                let mut h = header(&t, &a, GroupMessageKind::ReachOut, &gid, vec![]);
                h.epoch = Some(epoch + 1);
                seal_group_message_to_epoch(&a.keys.sign, &key, h, None).unwrap()
            },
            "stale_epoch",
        ),
        (
            "facilitators",
            {
                let mut h = header(&t, &a, GroupMessageKind::ReachOut, &gid, vec![]);
                h.epoch = Some(epoch);
                seal_group_message_to_epoch(&a.keys.sign, &key, h, None).unwrap()
            },
            "invalid_message",
        ),
    ] {
        t.clock.advance_ms(60_000);
        let r = t
            .post(
                "/v1/me/reach-outs",
                json!({ "audience": aud, "group_id": gid, "message": m }),
                Some(&a.s),
            )
            .await;
        assert_eq!(r.error_code(), code, "{aud}: {:?}", r.body);
    }
    // Content-free and unsigned works too, and someone outside gets 404.
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid }),
            Some(&b.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid }),
            Some(&out.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // 32 people is the largest group that can be reached whole; 33 is not.
    seed_participants(&t, &gid, 29, "x").await;
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "32 people: {:?}", r.body);
    assert_eq!(r.body["recipients"].as_array().unwrap().len(), 31);
    seed_participants(&t, &gid, 1, "y").await;
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.error_code(), "group_too_large");
    // A check-in to the whole group has no such limit.
    let m = check_in_to_group(&t, &a, &gid, epoch, &key);
    let r = post(&t, &a.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
}

#[tokio::test]
async fn check_ins_follow_blob_retention_and_unused_epoch_keys_are_pruned() {
    let t = TestApp::new().await;
    let f = person(&t, "fay").await;
    let a = person(&t, "ann").await;
    let c = person(&t, "cat").await;
    let (gid, epoch, key) = signed_group(&t, &f, &[&a, &c]).await;
    let m = check_in_to_group(&t, &a, &gid, epoch, &key);
    let r = post(&t, &a.s, &gid, Some("group"), &m).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // Cat leaves and a facilitator rotates: two epochs have keys stored.
    let r = t
        .call(
            axum::http::Method::DELETE,
            &format!("/v1/groups/{gid}/me"),
            None,
            Some(&c.s),
        )
        .await;
    assert!(r.status.is_success());
    let keys = sign_pending(&t, &gid, (&f.id, &f.s), &f.keys.sign).await;
    let epoch2 = keys.last().unwrap().0;
    let epoch_keys = |e: u64| {
        let p = t.state.db().pool().clone();
        let g = gid.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM group_epoch_keys WHERE group_id = $1 AND epoch = $2",
            )
            .bind(g)
            .bind(e as i64)
            .fetch_one(&p)
            .await
            .unwrap()
        }
    };
    assert_eq!(epoch_keys(epoch).await, 3);
    assert_eq!(epoch_keys(epoch2).await, 2);

    // A pass while the post is young keeps the old key: a stored post uses it.
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(epoch_keys(epoch).await, 3);
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM group_posts").await, 1);

    // Past the blob window the post goes, and then the key nothing uses.
    t.clock.advance_ms(31 * DAY);
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(count(&t.state, "SELECT COUNT(*) FROM group_posts").await, 0);
    assert_eq!(epoch_keys(epoch).await, 0);
    assert_eq!(epoch_keys(epoch2).await, 2, "the current epoch is kept");
}
