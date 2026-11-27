//! Alliance proposals in groups (docs/GROUPS.md §7): requests, offers and
//! partnerships end to end with real keys; the invariant that no route but
//! the member's own approval activates a link; decline privacy (the
//! sender's responses are byte-identical for declined, expired and void
//! proposals); the rules and limits; voiding on leave, removal, archive,
//! disable and deletion hold; blocks; and who may see or act on what.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::UserId;
use faro_server::db::repo::{allies as allies_repo, users};
use serde_json::{json, Value};
use sqlx::Row;

const DAY: i64 = 24 * 3600 * 1000;
const NAME: &str = "Tuesday Recovery Zebra";
const DESC: &str = "SecretDescriptionQuokka for the Tuesday men";

struct P {
    id: UserId,
    s: String,
    email: String,
    keys: Option<MemberKeys>,
    ally: AllyKeys,
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
    P {
        id,
        s,
        email,
        keys,
        ally: AllyKeys::generate(),
    }
}

async fn group_by(t: &TestApp, f: &P) -> String {
    let r = t
        .post(
            "/v1/groups",
            json!({ "name": NAME, "description": DESC }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

/// `by` invites `p` by address and `p` accepts.
async fn join(t: &TestApp, by: &P, gid: &str, p: &P) {
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [p.email] }),
            Some(&by.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    wait_for_mail(t, &p.email, "/group-invite#token=").await;
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

struct World {
    t: TestApp,
    admin_s: String,
    gid: String,
    /// The facilitator.
    f: P,
    a: P,
    b: P,
    c: P,
    d: P,
    e: P,
}

/// An admin, and a group made by `f` with `a`…`e` in it, everyone with
/// member keys.
async fn world() -> World {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let f = person(&t, "fay", true).await;
    let gid = group_by(&t, &f).await;
    let mut ps = Vec::new();
    for n in ["ann", "ben", "cat", "dan", "eve"] {
        let p = person(&t, n, true).await;
        join(&t, &f, &gid, &p).await;
        ps.push(p);
    }
    let mut ps = ps.into_iter();
    let mut next = || ps.next().unwrap();
    World {
        a: next(),
        b: next(),
        c: next(),
        d: next(),
        e: next(),
        t,
        admin_s,
        gid,
        f,
    }
}

async fn propose(t: &TestApp, gid: &str, from: &P, to: &P, kind: &str) -> Resp {
    t.post(
        &format!("/v1/groups/{gid}/proposals"),
        json!({ "to": to.id, "kind": kind }),
        Some(&from.s),
    )
    .await
}

/// Propose, sending `from`'s ally key too (offers and partnerships before
/// they have one).
async fn propose_with_key(t: &TestApp, gid: &str, from: &P, to: &P, kind: &str) -> Resp {
    t.post(
        &format!("/v1/groups/{gid}/proposals"),
        json!({ "to": to.id, "kind": kind, "ally_key": from.ally.upload_body() }),
        Some(&from.s),
    )
    .await
}

fn id_of(r: &Resp) -> String {
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

async fn accept(t: &TestApp, p: &P, id: &str, with_key: bool) -> Resp {
    let body = if with_key {
        json!({ "ally_key": p.ally.upload_body() })
    } else {
        json!({})
    };
    t.post(&format!("/v1/proposals/{id}/accept"), body, Some(&p.s))
        .await
}

async fn decline(t: &TestApp, p: &P, id: &str) -> Resp {
    t.call(
        Method::POST,
        &format!("/v1/proposals/{id}/decline"),
        None,
        Some(&p.s),
    )
    .await
}

async fn withdraw(t: &TestApp, p: &P, id: &str) -> Resp {
    t.call(
        Method::DELETE,
        &format!("/v1/proposals/{id}"),
        None,
        Some(&p.s),
    )
    .await
}

async fn del(t: &TestApp, path: &str, s: &str) -> Resp {
    t.call(Method::DELETE, path, None, Some(s)).await
}

async fn mine(t: &TestApp, p: &P) -> Value {
    let r = t.get("/v1/me/proposals", Some(&p.s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body
}

fn find<'a>(list: &'a Value, side: &str, id: &str) -> Option<&'a Value> {
    list[side]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == id)
}

async fn n(t: &TestApp, sql: &'static str) -> i64 {
    sqlx::query(sql)
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get("n")
        .unwrap()
}

async fn active_links(t: &TestApp) -> i64 {
    n(
        t,
        "SELECT COUNT(*) AS n FROM ally_links WHERE state = 'active'",
    )
    .await
}

/// `(member, ally, state, origin_group_id)` of every live link.
async fn links(t: &TestApp) -> Vec<(String, String, String, Option<String>)> {
    sqlx::query(
        "SELECT member_id, ally_id, state, origin_group_id FROM ally_links
         WHERE state <> 'removed' ORDER BY created_at, id",
    )
    .fetch_all(t.state.db().pool())
    .await
    .unwrap()
    .iter()
    .map(|r| {
        (
            r.try_get("member_id").unwrap(),
            r.try_get("ally_id").unwrap(),
            r.try_get("state").unwrap(),
            r.try_get("origin_group_id").unwrap(),
        )
    })
    .collect()
}

/// Group notices of `kind` to `to` (written whether or not they're emailed
/// yet).
async fn notices(t: &TestApp, kind: &str, to: &UserId) -> i64 {
    sqlx::query("SELECT COUNT(*) AS n FROM group_notices WHERE kind = $1 AND recipient_id = $2")
        .bind(kind)
        .bind(to.as_str())
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get("n")
        .unwrap()
}

async fn deliver_all(t: &TestApp) {
    t.notify_now().await;
    t.digest_now().await;
}

/// Let time pass, keeping everyone signed in (sessions last 30 days).
async fn advance(t: &TestApp, ms: i64) {
    t.clock.advance_ms(ms);
    sqlx::query("UPDATE sessions SET expires_at = expires_at + $1")
        .bind(ms)
        .execute(t.state.db().pool())
        .await
        .unwrap();
}

async fn fake_user(t: &TestApp, n: usize) -> UserId {
    let id = UserId::from_random(&faro_crypto::random_bytes::<16>());
    users::insert(
        t.state.db().pool(),
        &users::User {
            id: id.clone(),
            email: format!("fake{n}@example.org"),
            display_name: format!("Fake {n:03}"),
            roles: users::Roles::default(),
            disabled: false,
            created_at_ms: 0,
            deletion: None,
        },
    )
    .await
    .unwrap();
    id
}

// ---- The three kinds, end to end ----------------------------------------------

#[tokio::test]
async fn a_request_accepted_is_a_pending_link_until_the_member_approves() {
    let w = world().await;
    let t = &w.t;
    let (a, b) = (&w.a, &w.b);
    let r = propose(t, &w.gid, a, b, "request").await;
    let id = id_of(&r);
    assert_eq!(r.body["state"], "open");
    assert_eq!(r.body["kind"], "request");
    assert_eq!(r.body["to"]["user_id"], b.id.as_str());
    assert_eq!(r.body["group_name"], NAME);
    assert_eq!(r.body["expires_at_ms"], t.clock_ms() + 14 * DAY);
    assert_eq!(notices(t, "alliance_requested", &b.id).await, 1);
    // Emailed in B's digest, naming A and not the group.
    deliver_all(t).await;
    let to_b = t.mail_to(&b.email);
    assert!(
        to_b.iter()
            .any(|m| m.text.contains("ann asked you to be their ally on")),
        "{to_b:?}"
    );

    let theirs = mine(t, b).await;
    let p = find(&theirs, "incoming", &id).expect("listed for B");
    assert_eq!(p["state"], "open");
    assert_eq!(p["from"]["user_id"], a.id.as_str());
    assert!(find(&theirs, "outgoing", &id).is_none());

    // B has no ally key yet: accepting needs one.
    let r = accept(t, b, &id, false).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.error_code(), "ally_key_required");
    let r = accept(t, b, &id, true).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["proposal"]["state"], "accepted");
    let started = r.body["links"].as_array().unwrap();
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["member_id"], a.id.as_str());
    assert_eq!(started[0]["ally_id"], b.id.as_str());
    assert_eq!(started[0]["state"], "pending");
    assert_eq!(
        started[0]["ally_key_id"],
        faro_proto::keys::key_id(b.ally.enc.public().as_bytes())
    );
    assert_eq!(
        links(t).await,
        vec![(
            a.id.to_string(),
            b.id.to_string(),
            "pending".to_owned(),
            Some(w.gid.clone())
        )]
    );
    assert_eq!(notices(t, "alliance_accepted", &a.id).await, 1);
    let out = mine(t, a).await;
    let p = find(&out, "outgoing", &id).unwrap();
    assert_eq!(p["state"], "accepted");
    assert!(p["accepted_at_ms"].is_i64());
    // Answered: no second answer.
    assert_eq!(decline(t, b, &id).await.error_code(), "proposal_closed");
    assert_eq!(
        accept(t, b, &id, true).await.error_code(),
        "proposal_closed"
    );

    // A sees B in their allies, pending, and approves after comparing
    // codes: only now is the link active.
    let r = t.get("/v1/me/allies", Some(&a.s)).await;
    assert_eq!(r.body["allies"][0]["state"], "pending");
    assert_eq!(r.body["allies"][0]["origin_group_id"], w.gid.as_str());
    let r = t.get("/v1/ally/members", Some(&b.s)).await;
    assert_eq!(r.body[0]["origin_group_id"], w.gid.as_str());
    assert_eq!(active_links(t).await, 0);
    let r = t
        .approve(&a.id, a.mk(), &a.s, &b.id, b.ally.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(active_links(t).await, 1);
    assert_eq!(links(t).await[0].3.as_deref(), Some(w.gid.as_str()));

    // The emails name the people, never the group.
    deliver_all(t).await;
    let to_a = t.mail_to(&a.email);
    assert!(
        to_a.iter().any(|m| m.text.contains("ben accepted on")),
        "{to_a:?}"
    );
    for m in t.mailer.sent() {
        for secret in [NAME, DESC, "Zebra", "Quokka", "Tuesday"] {
            assert!(!m.subject.contains(secret), "{m:?}");
            assert!(!m.text.contains(secret), "{m:?}");
        }
    }
}

#[tokio::test]
async fn an_offer_uses_the_current_key_and_a_partnership_starts_both_links() {
    let w = world().await;
    let t = &w.t;
    let (a, b, c, d) = (&w.a, &w.b, &w.c, &w.d);

    // B offers to be A's ally. B has no ally key: the offer carries one.
    let r = propose(t, &w.gid, b, a, "offer").await;
    assert_eq!(r.error_code(), "ally_key_required", "{:?}", r.body);
    let r = propose_with_key(t, &w.gid, b, a, "offer").await;
    let offer = id_of(&r);
    assert_eq!(notices(t, "alliance_offered", &a.id).await, 1);
    // A request doesn't take the sender's ally key.
    let r = propose_with_key(t, &w.gid, a, c, "request").await;
    assert_eq!(r.error_code(), "ally_key_not_needed");

    let r = accept(t, a, &offer, true).await;
    assert_eq!(r.error_code(), "ally_key_not_needed", "{:?}", r.body);
    let r = accept(t, a, &offer, false).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let started = &r.body["links"][0];
    assert_eq!(started["member_id"], a.id.as_str());
    assert_eq!(started["ally_id"], b.id.as_str());
    assert_eq!(active_links(t).await, 0);
    let r = t
        .approve(&a.id, a.mk(), &a.s, &b.id, b.ally.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(active_links(t).await, 1);

    // C and D partner up: C sends their ally key, D accepts with theirs.
    let r = propose_with_key(t, &w.gid, c, d, "partnership").await;
    let pid = id_of(&r);
    assert_eq!(notices(t, "alliance_partnership", &d.id).await, 1);
    let r = accept(t, d, &pid, true).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["links"].as_array().unwrap().len(), 2);
    let pending: Vec<_> = links(t)
        .await
        .into_iter()
        .filter(|l| l.2 == "pending")
        .collect();
    assert_eq!(pending.len(), 2, "{pending:?}");
    assert!(pending
        .iter()
        .all(|l| l.3.as_deref() == Some(w.gid.as_str())));
    // Each side approves only their own; neither activates the other.
    let r = t
        .approve(&d.id, d.mk(), &d.s, &c.id, c.ally.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(active_links(t).await, 2);
    assert!(allies_repo::is_active(t.state.db().pool(), &d.id, &c.id)
        .await
        .unwrap());
    assert!(!allies_repo::is_active(t.state.db().pool(), &c.id, &d.id)
        .await
        .unwrap());
    let r = t
        .approve(&c.id, c.mk(), &c.s, &d.id, d.ally.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(active_links(t).await, 3);
}

// ---- The invariant ---------------------------------------------------------------

/// GROUPS.md principle 2 and §19: no route other than
/// `POST /v1/me/allies/{ally_id}/approve` moves an `ally_links` row to
/// `active`. Every proposal route, and the group leave, remove and archive
/// routes, is exercised, and the links are checked after each.
#[tokio::test]
async fn no_route_but_approve_activates_a_link() {
    let w = world().await;
    let t = &w.t;
    let (f, a, b, c, d, e) = (&w.f, &w.a, &w.b, &w.c, &w.d, &w.e);
    let g = &w.gid;
    let mut steps = 0;
    macro_rules! still_none {
        () => {
            steps += 1;
            assert_eq!(
                active_links(t).await,
                0,
                "a link became active at step {steps}"
            );
        };
    }

    let req = id_of(&propose(t, g, a, b, "request").await);
    still_none!();
    let off = id_of(&propose_with_key(t, g, c, a, "offer").await);
    still_none!();
    let par = id_of(&propose_with_key(t, g, d, e, "partnership").await);
    still_none!();
    let dec = id_of(&propose(t, g, b, c, "request").await);
    still_none!();
    let wd = id_of(&propose(t, g, e, f, "request").await);
    still_none!();
    mine(t, a).await;
    still_none!();
    assert_eq!(accept(t, b, &req, true).await.status, StatusCode::CREATED);
    still_none!();
    assert_eq!(accept(t, a, &off, false).await.status, StatusCode::CREATED);
    still_none!();
    assert_eq!(accept(t, e, &par, true).await.status, StatusCode::CREATED);
    still_none!();
    assert_eq!(decline(t, c, &dec).await.status, StatusCode::NO_CONTENT);
    still_none!();
    assert_eq!(withdraw(t, e, &wd).await.status, StatusCode::NO_CONTENT);
    still_none!();
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/proposal-blocks/{}", b.id),
            None,
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    still_none!();
    t.get("/v1/me/proposal-blocks", Some(&f.s)).await;
    still_none!();
    del(t, &format!("/v1/me/proposal-blocks/{}", b.id), &f.s).await;
    still_none!();
    // Retries and answers that must fail change nothing either.
    accept(t, b, &req, true).await;
    accept(t, f, &req, true).await;
    still_none!();
    assert_eq!(links(t).await.len(), 4, "{:?}", links(t).await);

    // The member approves one link: exactly that one is active.
    let r = t
        .approve(&a.id, a.mk(), &a.s, &b.id, b.ally.enc.public())
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(active_links(t).await, 1);
    assert!(allies_repo::is_active(t.state.db().pool(), &a.id, &b.id)
        .await
        .unwrap());

    // Leaving, removal and archiving leave every link as it was.
    let before = links(t).await;
    let r = del(t, &format!("/v1/groups/{g}/me"), &b.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = del(t, &format!("/v1/groups/{g}/participants/{}", c.id), &f.s).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let r = del(t, &format!("/v1/groups/{g}"), &f.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(links(t).await, before);
    assert_eq!(active_links(t).await, 1);
}

/// The same invariant, in the source: the only SQL that sets a link
/// `active` is `allies::activate`, and only the approve handler calls it.
#[test]
fn only_approve_calls_the_one_statement_that_activates_a_link() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![root.clone()];
    let mut sets = Vec::new();
    let mut calls = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let rel = path.strip_prefix(&root).unwrap().display().to_string();
            let flat: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
            for needle in [
                "ally_links SET state = 'active'",
                "UPDATE ally_links SET state = $",
            ] {
                if flat.contains(needle) {
                    sets.push(rel.clone());
                }
            }
            if flat.contains("allies::activate(") {
                calls.push(rel.clone());
            }
            if flat.contains("INSERT INTO ally_links") {
                assert!(
                    flat.contains("VALUES ($1, $2, $3, 'pending'"),
                    "{rel}: links are only ever inserted pending"
                );
            }
        }
    }
    assert_eq!(sets, vec!["db/repo/allies.rs".to_owned()]);
    assert_eq!(calls, vec!["api/allies.rs".to_owned()]);
}

// ---- Decline privacy -------------------------------------------------------------

/// The sender's view with the parts that name the proposal and the other
/// person taken out.
fn sender_bytes(p: &Value) -> Vec<u8> {
    let mut p = p.clone();
    let o = p.as_object_mut().unwrap();
    o.remove("id");
    o.remove("to");
    serde_json::to_vec(&p).unwrap()
}

#[tokio::test]
async fn declined_expired_void_and_hidden_look_the_same_to_the_sender() {
    let w = world().await;
    let t = &w.t;
    let (f, a, b, c, d, e) = (&w.f, &w.a, &w.b, &w.c, &w.d, &w.e);
    let g = &w.gid;
    // F has blocked A: A's proposal to F is hidden from F.
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/proposal-blocks/{}", a.id),
            None,
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let mut ids = Vec::new();
    let mut created = Vec::new();
    for to in [b, c, d, e, f] {
        let r = propose(t, g, a, to, "request").await;
        created.push(sender_bytes(&r.body));
        ids.push(id_of(&r));
    }
    // Even the creation responses are the same, hidden one included.
    assert!(created.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(notices(t, "alliance_requested", &f.id).await, 0);
    assert!(mine(t, f).await["incoming"].as_array().unwrap().is_empty());

    advance(t, DAY).await;
    // B declines; C leaves the group (void); E blocks A (void); D does
    // nothing (it will expire).
    assert_eq!(decline(t, b, &ids[0]).await.status, StatusCode::NO_CONTENT);
    let r = del(t, &format!("/v1/groups/{g}/me"), &c.s).await;
    assert_eq!(r.status, StatusCode::OK);
    let r = t
        .call(
            Method::PUT,
            &format!("/v1/me/proposal-blocks/{}", a.id),
            None,
            Some(&e.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);

    let check = |list: &Value, state: &str| {
        let views: Vec<Vec<u8>> = ids
            .iter()
            .map(|id| sender_bytes(find(list, "outgoing", id).unwrap()))
            .collect();
        assert!(
            views.windows(2).all(|w| w[0] == w[1]),
            "{:?}",
            views
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(find(list, "outgoing", &ids[0]).unwrap()["state"], state);
    };
    // Before the expiry, all still look open: a decline isn't visible early.
    check(&mine(t, a).await, "open");

    // After it, all look "not accepted", with the same ask-again date.
    advance(t, 14 * DAY).await;
    let list = mine(t, a).await;
    check(&list, "not_accepted");
    let p = find(&list, "outgoing", &ids[0]).unwrap();
    assert_eq!(
        p["ask_again_at_ms"],
        p["expires_at_ms"].as_i64().unwrap() + 30 * DAY
    );
    assert!(p["accepted_at_ms"].is_null() && p["withdrawn_at_ms"].is_null());

    // Asking again and withdrawing answer the same, byte for byte (C left,
    // so a new proposal to C is refused for that reason instead).
    let mut again = Vec::new();
    let mut gone = Vec::new();
    for (i, to) in [b, c, d, e, f].into_iter().enumerate() {
        if i != 1 {
            let r = propose(t, g, a, to, "request").await;
            assert_eq!(r.status, StatusCode::CONFLICT);
            again.push(r.raw);
        }
        let r = withdraw(t, a, &ids[i]).await;
        assert_eq!(r.status, StatusCode::CONFLICT);
        gone.push(r.raw);
    }
    assert!(again.windows(2).all(|w| w[0] == w[1]));
    assert!(gone.windows(2).all(|w| w[0] == w[1]));

    // The recipients see their own story.
    let state_for = |list: &Value, id: &str| find(list, "incoming", id).unwrap()["state"].clone();
    assert_eq!(state_for(&mine(t, b).await, &ids[0]), "declined");
    assert_eq!(state_for(&mine(t, c).await, &ids[1]), "void");
    assert_eq!(state_for(&mine(t, d).await, &ids[2]), "expired");
    assert_eq!(state_for(&mine(t, e).await, &ids[3]), "void");
    assert!(find(&mine(t, f).await, "incoming", &ids[4]).is_none());

    // No declines, expiries or voids were notified to A.
    assert_eq!(notices(t, "alliance_accepted", &a.id).await, 0);
    let before = t.mail_to(&a.email).len();
    deliver_all(t).await;
    assert_eq!(
        t.mail_to(&a.email).len(),
        before,
        "{:?}",
        t.mail_to(&a.email)
    );
}

// ---- Rules -------------------------------------------------------------------------

#[tokio::test]
async fn one_open_per_direction_no_duplicates_and_the_cool_down() {
    let w = world().await;
    let t = &w.t;
    let (a, b, c) = (&w.a, &w.b, &w.c);
    let g = &w.gid;
    let r = propose(t, g, a, a, "request").await;
    assert_eq!(r.error_code(), "cannot_propose_to_self");

    let req = id_of(&propose(t, g, a, b, "request").await);
    // The same direction again, or a partnership covering it: refused.
    assert_eq!(
        propose(t, g, a, b, "request").await.error_code(),
        "already_proposed"
    );
    assert_eq!(
        propose_with_key(t, g, a, b, "partnership")
            .await
            .error_code(),
        "already_proposed"
    );
    // B offering to be A's ally is the same link: B is pointed at A's
    // request instead.
    assert_eq!(
        propose_with_key(t, g, b, a, "offer").await.error_code(),
        "proposal_waiting"
    );
    // The other direction is a different link; and while B asks A to be
    // their ally, A offering the same is pointed back at it.
    let other = id_of(&propose(t, g, b, a, "request").await);
    assert_eq!(
        propose_with_key(t, g, a, b, "offer").await.error_code(),
        "proposal_waiting"
    );
    assert_eq!(withdraw(t, b, &other).await.status, StatusCode::NO_CONTENT);
    let off = id_of(&propose_with_key(t, g, a, b, "offer").await);
    assert_eq!(withdraw(t, a, &off).await.status, StatusCode::NO_CONTENT);

    // B declines A's request: A still sees it open, and can't ask again.
    assert_eq!(decline(t, b, &req).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        propose(t, g, a, b, "request").await.error_code(),
        "already_proposed"
    );
    advance(t, 14 * DAY).await;
    assert_eq!(
        propose(t, g, a, b, "request").await.error_code(),
        "proposal_cooldown"
    );
    // Another kind isn't held back by the cool-down.
    let off = id_of(&propose_with_key(t, g, a, b, "offer").await);
    assert_eq!(withdraw(t, a, &off).await.status, StatusCode::NO_CONTENT);
    advance(t, 30 * DAY).await;
    let again = id_of(&propose(t, g, a, b, "request").await);
    assert!(find(&mine(t, b).await, "incoming", &again).is_some());

    // Withdrawing after a decline doesn't get around the cool-down: the
    // next one is hidden from the recipient.
    assert_eq!(decline(t, b, &again).await.status, StatusCode::NO_CONTENT);
    let notified = notices(t, "alliance_requested", &b.id).await;
    assert_eq!(withdraw(t, a, &again).await.status, StatusCode::NO_CONTENT);
    let list = mine(t, a).await;
    assert_eq!(
        find(&list, "outgoing", &again).unwrap()["state"],
        "withdrawn"
    );
    let sneaky = id_of(&propose(t, g, a, b, "request").await);
    assert_eq!(
        find(&mine(t, a).await, "outgoing", &sneaky).unwrap()["state"],
        "open"
    );
    assert!(find(&mine(t, b).await, "incoming", &sneaky).is_none());
    assert_eq!(notices(t, "alliance_requested", &b.id).await, notified);
    // B still sees their decline as a decline.
    assert_eq!(
        find(&mine(t, b).await, "incoming", &again).unwrap()["state"],
        "declined"
    );
    // A hidden proposal can't be answered.
    assert_eq!(
        accept(t, b, &sneaky, true).await.status,
        StatusCode::NOT_FOUND
    );

    // A withdrawal of an open proposal: the recipient sees "withdrawn".
    let w2 = id_of(&propose(t, g, c, b, "request").await);
    assert_eq!(withdraw(t, c, &w2).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        find(&mine(t, b).await, "incoming", &w2).unwrap()["state"],
        "withdrawn"
    );
    assert_eq!(
        accept(t, b, &w2, true).await.error_code(),
        "proposal_closed"
    );

    // No duplicates of a live link.
    let r = id_of(&propose(t, g, c, &w.d, "request").await);
    assert_eq!(accept(t, &w.d, &r, true).await.status, StatusCode::CREATED);
    assert_eq!(
        propose(t, g, c, &w.d, "request").await.error_code(),
        "already_linked"
    );
    assert_eq!(
        propose_with_key(t, g, &w.d, c, "offer").await.error_code(),
        "already_linked"
    );
}

#[tokio::test]
async fn proposals_expire_after_14_days() {
    let w = world().await;
    let t = &w.t;
    let id = id_of(&propose(t, &w.gid, &w.a, &w.b, "request").await);
    advance(t, 14 * DAY).await;
    assert_eq!(
        accept(t, &w.b, &id, true).await.error_code(),
        "proposal_closed"
    );
    assert_eq!(decline(t, &w.b, &id).await.error_code(), "proposal_closed");
    assert_eq!(withdraw(t, &w.a, &id).await.error_code(), "proposal_closed");
    // The retention pass marks it and, 90 days on, forgets it.
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        n(t, "SELECT COUNT(*) AS n FROM alliance_proposals WHERE state = 'not_accepted' AND decided_at IS NULL").await,
        1
    );
    advance(t, 91 * DAY).await;
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        n(t, "SELECT COUNT(*) AS n FROM alliance_proposals").await,
        0
    );
}

#[tokio::test]
async fn ten_proposals_a_day_and_keys_each_side_needs() {
    let w = world().await;
    let t = &w.t;
    let (a, b) = (&w.a, &w.b);
    for _ in 0..10 {
        let id = id_of(&propose(t, &w.gid, a, b, "request").await);
        assert_eq!(withdraw(t, a, &id).await.status, StatusCode::NO_CONTENT);
    }
    let r = propose(t, &w.gid, a, b, "request").await;
    assert_eq!(r.error_code(), "too_many_proposals", "{:?}", r.body);
    advance(t, DAY + 1).await;
    id_of(&propose(t, &w.gid, a, b, "request").await);

    // Someone without member keys can't ask for an ally, and can't be
    // offered one.
    let nokeys = person(t, "zed", false).await;
    join(t, &w.f, &w.gid, &nokeys).await;
    assert_eq!(
        propose(t, &w.gid, &nokeys, b, "request").await.error_code(),
        "member_keys_required"
    );
    assert_eq!(
        propose_with_key(t, &w.gid, b, &nokeys, "offer")
            .await
            .error_code(),
        "cannot_propose"
    );
    assert_eq!(
        propose_with_key(t, &w.gid, b, &nokeys, "partnership")
            .await
            .error_code(),
        "cannot_propose"
    );
    // But they can be asked to be an ally.
    let id = id_of(&propose(t, &w.gid, &w.c, &nokeys, "request").await);
    assert_eq!(
        accept(t, &nokeys, &id, true).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn proposals_share_the_live_invite_limit_and_allies_are_checked_on_accepting() {
    let w = world().await;
    let t = &w.t;
    let (a, b, c) = (&w.a, &w.b, &w.c);
    // 18 email invitations and 2 proposals make 20.
    for i in 0..18 {
        let r = t
            .post(
                "/v1/me/invites",
                json!({ "email": format!("x{i}@example.org") }),
                Some(&a.s),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    }
    let first = id_of(&propose(t, &w.gid, a, b, "request").await);
    id_of(&propose(t, &w.gid, a, c, "request").await);
    assert_eq!(
        propose(t, &w.gid, a, &w.d, "request").await.error_code(),
        "too_many_invites"
    );
    let r = t
        .post(
            "/v1/me/invites",
            json!({ "email": "one-more@example.org" }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.error_code(), "too_many_invites");
    assert_eq!(withdraw(t, a, &first).await.status, StatusCode::NO_CONTENT);
    let r = t
        .post(
            "/v1/me/invites",
            json!({ "email": "one-more@example.org" }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // D asks E to be their ally; meanwhile D fills up to 32 allies.
    let (d, e) = (&w.d, &w.e);
    let req = id_of(&propose(t, &w.gid, d, e, "request").await);
    // And B offers to be D's ally.
    let off = id_of(&propose_with_key(t, &w.gid, b, d, "offer").await);
    for i in 0..32 {
        let ally = fake_user(t, i).await;
        allies_repo::insert_pending(t.state.db().pool(), &d.id, &ally, None, 0)
            .await
            .unwrap();
    }
    let before = links(t).await.len();
    // Only the person accepting is told; nothing is created.
    let r = accept(t, e, &req, true).await;
    assert_eq!(r.error_code(), "too_many_allies", "{:?}", r.body);
    let r = accept(t, d, &off, false).await;
    assert_eq!(r.error_code(), "too_many_allies", "{:?}", r.body);
    assert_eq!(links(t).await.len(), before);
    // Both stay open, and D's own request reads as open, nothing more.
    assert_eq!(
        find(&mine(t, d).await, "outgoing", &req).unwrap()["state"],
        "open"
    );
    assert_eq!(
        find(&mine(t, e).await, "incoming", &req).unwrap()["state"],
        "open"
    );
    // D can't ask for a 33rd.
    assert_eq!(
        propose(t, &w.gid, d, &w.c, "request").await.error_code(),
        "too_many_allies"
    );
}

// ---- Voiding ------------------------------------------------------------------------

#[tokio::test]
async fn leave_remove_archive_disable_and_deletion_void_open_proposals_only() {
    let w = world().await;
    let t = &w.t;
    let (f, a, b, c, d, e) = (&w.f, &w.a, &w.b, &w.c, &w.d, &w.e);
    let g = &w.gid;
    // A pending link and an active one formed in the group stay throughout.
    let p1 = id_of(&propose(t, g, a, b, "request").await);
    accept(t, b, &p1, true).await;
    let p2 = id_of(&propose(t, g, c, d, "request").await);
    accept(t, d, &p2, true).await;
    t.approve(&c.id, c.mk(), &c.s, &d.id, d.ally.enc.public())
        .await;
    let kept = links(t).await;
    assert_eq!(kept.len(), 2);

    let state = |list: Value, id: &str| find(&list, "incoming", id).unwrap()["state"].clone();

    // Leaving: proposals to and from the leaver in this group.
    let to_b = id_of(&propose(t, g, e, b, "request").await);
    let from_b = id_of(&propose(t, g, b, e, "request").await);
    let unrelated = id_of(&propose(t, g, e, f, "request").await);
    del(t, &format!("/v1/groups/{g}/me"), &b.s).await;
    assert_eq!(state(mine(t, b).await, &to_b), "void");
    assert_eq!(state(mine(t, e).await, &from_b), "void");
    assert_eq!(state(mine(t, f).await, &unrelated), "open");
    assert_eq!(
        accept(t, b, &to_b, true).await.error_code(),
        "proposal_closed"
    );

    // Removal.
    let to_c = id_of(&propose(t, g, e, c, "request").await);
    let r = del(t, &format!("/v1/groups/{g}/participants/{}", c.id), &f.s).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(state(mine(t, c).await, &to_c), "void");

    // Admin disable.
    let to_d = id_of(&propose(t, g, e, d, "request").await);
    let r = t
        .post(
            &format!("/admin/api/users/{}/disable", d.id),
            json!({}),
            Some(&w.admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let state_of = |id: &str| {
        let id = id.to_owned();
        async move {
            sqlx::query("SELECT state FROM alliance_proposals WHERE id = $1")
                .bind(id)
                .fetch_one(t.state.db().pool())
                .await
                .unwrap()
                .try_get::<String, _>("state")
                .unwrap()
        }
    };
    assert_eq!(state_of(&to_d).await, "void");
    // A disabled person receives nothing new: it's hidden.
    let hidden = id_of(&propose_with_key(t, g, e, d, "offer").await);
    assert_eq!(state_of(&hidden).await, "not_accepted");

    // Deletion hold: open proposals end, and the person can't send more.
    let to_a = id_of(&propose(t, g, e, a, "request").await);
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": a.email })),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(state_of(&to_a).await, "void");
    assert_eq!(
        propose(t, g, a, e, "request").await.error_code(),
        "account_deleting"
    );

    // Archive: everything open in the group.
    let last = id_of(&propose(t, g, f, e, "request").await);
    assert_eq!(state(mine(t, e).await, &last), "open");
    let r = del(t, &format!("/v1/groups/{g}"), &f.s).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(state(mine(t, e).await, &last), "void");
    assert_eq!(
        n(
            t,
            "SELECT COUNT(*) AS n FROM alliance_proposals WHERE state = 'open'"
        )
        .await,
        0
    );
    // An archived group takes no proposals.
    assert_eq!(
        propose(t, g, f, e, "partnership").await.error_code(),
        "group_archived"
    );

    // The links are exactly as they were (principle 4).
    assert_eq!(links(t).await, kept);
}

// ---- Blocks ---------------------------------------------------------------------

#[tokio::test]
async fn blocks_are_private_and_hide_proposals_silently() {
    let w = world().await;
    let t = &w.t;
    let (a, b) = (&w.a, &w.b);
    let g = &w.gid;
    let open = id_of(&propose(t, g, a, b, "request").await);
    assert_eq!(block(t, b, a).await.status, StatusCode::NO_CONTENT);
    assert_eq!(
        block(t, b, a).await.status,
        StatusCode::NO_CONTENT,
        "idempotent"
    );
    assert_eq!(block(t, b, b).await.error_code(), "cannot_block_self");
    let r = t
        .call(
            Method::PUT,
            "/v1/me/proposal-blocks/0123456789abcdef0123456789abcdef",
            None,
            Some(&b.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // The open proposal ended quietly; A's view is unchanged.
    assert_eq!(
        find(&mine(t, b).await, "incoming", &open).unwrap()["state"],
        "void"
    );
    assert_eq!(
        find(&mine(t, a).await, "outgoing", &open).unwrap()["state"],
        "open"
    );
    // New ones from A are accepted as usual, and never reach B.
    let off = id_of(&propose_with_key(t, g, a, b, "offer").await);
    assert_eq!(off.len(), 32);
    assert!(find(&mine(t, b).await, "incoming", &off).is_none());
    assert_eq!(notices(t, "alliance_offered", &b.id).await, 0);
    // B can still propose to A.
    id_of(&propose(t, g, b, a, "request").await);

    // Only B sees the block.
    let r = t.get("/v1/me/proposal-blocks", Some(&b.s)).await;
    assert_eq!(r.body.as_array().unwrap().len(), 1);
    assert_eq!(r.body[0]["user_id"], a.id.as_str());
    let r = t.get("/v1/me/proposal-blocks", Some(&a.s)).await;
    assert!(r.body.as_array().unwrap().is_empty());

    // Unblocked: A's next proposal (after the hidden offer's cool-down)
    // reaches B again.
    let r = del(t, &format!("/v1/me/proposal-blocks/{}", a.id), &b.s).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let partner = id_of(&propose(t, g, a, &w.c, "request").await);
    assert!(find(&mine(t, &w.c).await, "incoming", &partner).is_some());
    advance(t, 44 * DAY + 1).await;
    let off2 = id_of(&propose_with_key(t, g, a, b, "offer").await);
    assert!(find(&mine(t, b).await, "incoming", &off2).is_some());
}

// ---- Who may see and act ------------------------------------------------------------

#[tokio::test]
async fn only_the_two_people_see_or_act_on_a_proposal() {
    let w = world().await;
    let t = &w.t;
    let (f, a, b) = (&w.f, &w.a, &w.b);
    let g = &w.gid;
    let id = id_of(&propose(t, g, a, b, "request").await);
    // The facilitator and an admin see nothing and can't act.
    for p in [f, &w.c] {
        assert!(find(&mine(t, p).await, "incoming", &id).is_none());
        assert!(find(&mine(t, p).await, "outgoing", &id).is_none());
        assert_eq!(accept(t, p, &id, true).await.status, StatusCode::NOT_FOUND);
        assert_eq!(decline(t, p, &id).await.status, StatusCode::NOT_FOUND);
        assert_eq!(withdraw(t, p, &id).await.status, StatusCode::NOT_FOUND);
    }
    for (path, method) in [
        (format!("/v1/proposals/{id}/accept"), Method::POST),
        (format!("/v1/proposals/{id}/decline"), Method::POST),
        (format!("/v1/proposals/{id}"), Method::DELETE),
    ] {
        // Accept takes a JSON body (`{}` is enough).
        let body = path.ends_with("/accept").then(|| json!({}));
        let r = t
            .call(method.clone(), &path, body.clone(), Some(&w.admin_s))
            .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
        let r = t.call(method, &path, body, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    // The sender can't answer their own; the recipient can't withdraw it.
    assert_eq!(accept(t, a, &id, true).await.status, StatusCode::NOT_FOUND);
    assert_eq!(decline(t, a, &id).await.status, StatusCode::NOT_FOUND);
    assert_eq!(withdraw(t, b, &id).await.status, StatusCode::NOT_FOUND);

    // Only participants propose, and only to participants: anyone else is
    // a 404, so groups and people can't be probed.
    let stranger = person(t, "sly", true).await;
    assert_eq!(
        propose(t, g, &stranger, b, "request").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        propose(t, g, a, &stranger, "request").await.status,
        StatusCode::NOT_FOUND
    );
    let r = t
        .post(
            &format!("/v1/groups/{g}/proposals"),
            json!({ "to": b.id, "kind": "request" }),
            Some(&w.admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // No notes yet (#123), nor anything else unknown.
    let r = t
        .post(
            &format!("/v1/groups/{g}/proposals"),
            json!({ "to": w.c.id, "kind": "request", "note": "hi" }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_purge_removes_proposals_and_blocks() {
    let w = world().await;
    let t = &w.t;
    let (a, b) = (&w.a, &w.b);
    id_of(&propose(t, &w.gid, a, b, "request").await);
    id_of(&propose(t, &w.gid, b, a, "request").await);
    t.call(
        Method::PUT,
        &format!("/v1/me/proposal-blocks/{}", b.id),
        None,
        Some(&a.s),
    )
    .await;
    t.call(
        Method::PUT,
        &format!("/v1/me/proposal-blocks/{}", a.id),
        None,
        Some(&w.c.s),
    )
    .await;
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": a.email })),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    deliver_all(t).await;
    advance(t, 8 * DAY).await;
    deliver_all(t).await;
    assert!(faro_server::deletion::purge(&t.state, &a.id).await.unwrap());
    assert_eq!(
        n(t, "SELECT COUNT(*) AS n FROM alliance_proposals").await,
        0
    );
    assert_eq!(n(t, "SELECT COUNT(*) AS n FROM proposal_blocks").await, 0);
}

async fn block(t: &TestApp, who: &P, whom: &P) -> Resp {
    t.call(
        Method::PUT,
        &format!("/v1/me/proposal-blocks/{}", whom.id),
        None,
        Some(&who.s),
    )
    .await
}
