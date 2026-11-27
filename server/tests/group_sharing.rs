//! Opt-in sharing with a group and pairing suggestions (docs/GROUPS.md
//! §8.2, §8.5): the status dot comes only from liveness metadata and only
//! for people who chose to show it; allies are shown only where both are in
//! the group; turning sharing off tells nobody; nobody (facilitators
//! included) ever gets a count of who has or hasn't shared; and a
//! suggestion is not a proposal and doesn't reveal who acted on it.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::api::DeviceState;
use faro_proto::UserId;
use serde_json::{json, Value};

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
    gid: String,
    f: P,
    ann: P,
    ben: P,
    cat: P,
}

async fn world() -> World {
    let t = TestApp::new().await;
    t.setup_admin("admin@example.org").await;
    let f = person(&t, "fay").await;
    let r = t
        .post("/v1/groups", json!({ "name": "Tuesday" }), Some(&f.s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let gid = r.body["id"].as_str().unwrap().to_owned();
    let ann = person(&t, "ann").await;
    let ben = person(&t, "ben").await;
    let cat = person(&t, "cat").await;
    for p in [&ann, &ben, &cat] {
        join(&t, &f, &gid, p).await;
    }
    World {
        t,
        gid,
        f,
        ann,
        ben,
        cat,
    }
}

async fn set_sharing(w: &World, p: &P, status: bool, allies: bool) -> Resp {
    w.t.call(
        Method::PUT,
        &format!("/v1/groups/{}/me/sharing", w.gid),
        Some(json!({ "share_status": status, "share_allies": allies })),
        Some(&p.s),
    )
    .await
}

/// The dot `viewer` sees beside `of`.
async fn dot(w: &World, viewer: &P, of: &P) -> String {
    let r =
        w.t.get(
            &format!("/v1/groups/{}/participants", w.gid),
            Some(&viewer.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["user_id"] == json!(of.id))
        .expect("on the roster")["status"]
        .as_str()
        .expect("a status")
        .to_owned()
}

/// Enroll and endorse a computer for `p`.
async fn computer(w: &World, p: &P) -> TestDevice {
    let code = w.t.enroll_code(&p.s).await;
    let dev = w.t.enroll(&code, &p.keys.enc).await;
    let r = w.t.endorse(&dev, &p.keys, &p.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    dev
}

async fn dismiss(w: &World, p: &P, id: &str) -> Resp {
    w.t.post(
        &format!("/v1/groups/{}/me/suggestions/{id}/dismiss", w.gid),
        json!({}),
        Some(&p.s),
    )
    .await
}

async fn notices(w: &World) -> (i64, i64) {
    (
        count(&w.t.state, "SELECT COUNT(*) FROM group_notices").await,
        count(&w.t.state, "SELECT COUNT(*) FROM notifications").await,
    )
}

#[tokio::test]
async fn everything_is_off_until_chosen_and_the_dot_reads_liveness_only() {
    let w = world().await;
    let g =
        w.t.get(&format!("/v1/groups/{}", w.gid), Some(&w.ann.s))
            .await;
    assert_eq!(g.body["my_sharing"]["share_status"], json!(false));
    assert_eq!(g.body["my_sharing"]["share_allies"], json!(false));
    for p in [&w.ann, &w.ben, &w.cat] {
        assert_eq!(dot(&w, &w.f, p).await, "not_shared");
    }

    let ann_dev = computer(&w, &w.ann).await;
    let _cat_dev = computer(&w, &w.cat).await;

    // Hidden until chosen, whatever the computers are doing.
    w.t.heartbeat(&ann_dev, DeviceState::Paused).await;
    assert_eq!(dot(&w, &w.f, &w.ann).await, "not_shared");

    let r = set_sharing(&w, &w.ann, true, false).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["audience"], json!(4));
    set_sharing(&w, &w.ben, true, false).await;
    set_sharing(&w, &w.cat, true, false).await;
    assert_eq!(dot(&w, &w.f, &w.ann).await, "paused");
    assert_eq!(dot(&w, &w.ben, &w.ann).await, "paused");
    assert_eq!(dot(&w, &w.f, &w.ben).await, "no_computer");
    // Never heard from.
    assert_eq!(dot(&w, &w.f, &w.cat).await, "not_checked_in");

    w.t.clock.advance_ms(1000);
    w.t.heartbeat(&ann_dev, DeviceState::Active).await;
    assert_eq!(dot(&w, &w.f, &w.ann).await, "monitoring_on");

    // Silent for longer than the grace period.
    let grace = i64::try_from(w.t.state.settings().liveness.grace_secs).unwrap() * 1000;
    w.t.clock.advance_ms(grace + 1);
    assert_eq!(dot(&w, &w.f, &w.ann).await, "not_checked_in");
}

#[tokio::test]
async fn turning_sharing_off_tells_nobody_and_reads_not_shared() {
    let w = world().await;
    let dev = computer(&w, &w.ann).await;
    w.t.heartbeat(&dev, DeviceState::Active).await;
    let before = notices(&w).await;

    set_sharing(&w, &w.ann, true, true).await;
    assert_eq!(dot(&w, &w.ben, &w.ann).await, "monitoring_on");
    let off = set_sharing(&w, &w.ann, false, false).await;
    assert_eq!(off.status, StatusCode::OK);
    assert_eq!(dot(&w, &w.ben, &w.ann).await, "not_shared");
    assert_eq!(dot(&w, &w.f, &w.ann).await, "not_shared");

    // Not a single notice or notification, and the history is unchanged.
    w.t.notify_now().await;
    assert_eq!(notices(&w).await, before);
    let h =
        w.t.get(&format!("/v1/groups/{}/history", w.gid), Some(&w.f.s))
            .await;
    assert!(!h.body.to_string().contains("shar"), "{:?}", h.body);

    // A non-participant can't set anything.
    let outsider = person(&w.t, "zed").await;
    let r = set_sharing(&w, &outsider, true, true).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn allies_show_only_when_shared_and_only_inside_the_group() {
    let w = world().await;
    // ann supports ben (both in the group) and zed (not in it); cat
    // supports ann.
    w.t.link_ally(&w.ann.id, &w.ann.keys, &w.ann.s, &w.ben.email)
        .await;
    w.t.link_ally(&w.ann.id, &w.ann.keys, &w.ann.s, "zed@example.org")
        .await;
    w.t.link_ally(&w.cat.id, &w.cat.keys, &w.cat.s, &w.ann.email)
        .await;
    let path = format!("/v1/groups/{}/participants/{}/allies", w.gid, w.ann.id);

    let r = w.t.get(&path, Some(&w.f.s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body, json!({ "shared": false, "allies": [] }));

    set_sharing(&w, &w.ann, false, true).await;
    let r = w.t.get(&path, Some(&w.ben.s)).await;
    assert_eq!(r.body["shared"], json!(true));
    let allies = r.body["allies"].as_array().unwrap();
    assert_eq!(allies.len(), 2, "{:?}", r.body);
    assert!(allies
        .iter()
        .any(|a| a["user_id"] == json!(w.ben.id) && a["side"] == "ally"));
    assert!(allies
        .iter()
        .any(|a| a["user_id"] == json!(w.cat.id) && a["side"] == "supports"));
    assert!(!r.body.to_string().contains("zed"));

    // Turned off again: nothing.
    set_sharing(&w, &w.ann, false, false).await;
    let r = w.t.get(&path, Some(&w.ben.s)).await;
    assert_eq!(r.body, json!({ "shared": false, "allies": [] }));

    // Someone who left is no longer shown.
    set_sharing(&w, &w.ann, false, true).await;
    let r =
        w.t.call(
            Method::DELETE,
            &format!("/v1/groups/{}/me", w.gid),
            None,
            Some(&w.ben.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = w.t.get(&path, Some(&w.f.s)).await;
    assert_eq!(r.body["allies"].as_array().unwrap().len(), 1);

    // People outside the group learn nothing.
    let outsider = person(&w.t, "ivy").await;
    assert_eq!(
        w.t.get(&path, Some(&outsider.s)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn nobody_gets_a_count_of_who_has_shared() {
    let w = world().await;
    let admin = w.t.sign_in("admin@example.org").await.1;
    let group_view = || async {
        w.t.get(&format!("/v1/groups/{}", w.gid), Some(&w.f.s))
            .await
            .body
    };
    let roster = || async {
        w.t.get(&format!("/v1/groups/{}/participants", w.gid), Some(&w.f.s))
            .await
            .body
    };
    let admin_groups = || async { w.t.get("/admin/api/groups", Some(&admin)).await.body };
    let mine = || async { w.t.get("/v1/groups", Some(&w.f.s)).await.body };

    let (g0, a0, m0) = (group_view().await, admin_groups().await, mine().await);
    let r0 = roster().await;

    for p in [&w.ann, &w.ben] {
        set_sharing(&w, p, true, true).await;
    }

    // The same bytes for everything that isn't a person's own line.
    assert_eq!(group_view().await, g0);
    assert_eq!(admin_groups().await, a0);
    assert_eq!(mine().await, m0);
    // The roster has the same shape, no summary field anywhere, and the
    // person who hasn't shared looks as they always did.
    let r1 = roster().await;
    let keys = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&r0), keys(&r1));
    assert_eq!(dot(&w, &w.f, &w.cat).await, "not_shared");
    for body in [&g0, &r1, &a0, &m0] {
        let text = body.to_string();
        for needle in ["shared_count", "sharing_count", "opted", "not_shared_count"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
    }
    // The only sharing field in a group's view is the caller's own.
    assert_eq!(
        keys(&g0["my_sharing"]),
        vec!["share_allies".to_owned(), "share_status".to_owned()]
    );
}

#[tokio::test]
async fn suggestions_are_cards_for_two_people_not_proposals() {
    let w = world().await;
    let sug = format!("/v1/groups/{}/suggestions", w.gid);
    let mine = format!("/v1/groups/{}/me/suggestions", w.gid);
    let before = (
        notices(&w).await,
        count(&w.t.state, "SELECT COUNT(*) FROM alliance_proposals").await,
        count(&w.t.state, "SELECT COUNT(*) FROM ally_links").await,
    );

    // Only facilitators post; the people must be in the group.
    let pair = json!([{ "a": w.ann.id, "b": w.ben.id }]);
    let r = w.t.post(&sug, pair.clone(), Some(&w.ann.s)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);
    let outsider = person(&w.t, "zed").await;
    let r =
        w.t.post(
            &sug,
            json!([{ "a": w.ann.id, "b": outsider.id }]),
            Some(&w.f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    let r =
        w.t.post(
            &sug,
            json!([{ "a": w.ann.id, "b": w.ann.id }]),
            Some(&w.f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        w.t.post(&sug, pair.clone(), Some(&outsider.s)).await.status,
        StatusCode::NOT_FOUND
    );

    let r = w.t.post(&sug, pair.clone(), Some(&w.f.s)).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["posted"], json!(1));

    // Each person sees only their own card.
    let ann = w.t.get(&mine, Some(&w.ann.s)).await;
    assert_eq!(ann.body.as_array().unwrap().len(), 1);
    assert_eq!(ann.body[0]["other"]["user_id"], json!(w.ben.id));
    let ben = w.t.get(&mine, Some(&w.ben.s)).await;
    assert_eq!(ben.body[0]["other"]["user_id"], json!(w.ann.id));
    for p in [&w.cat, &w.f] {
        let r = w.t.get(&mine, Some(&p.s)).await;
        assert_eq!(r.body, json!([]), "someone else's card");
    }
    assert_eq!(
        w.t.get(&mine, Some(&outsider.s)).await.status,
        StatusCode::NOT_FOUND
    );

    // Posting created nothing else: no proposal, no link, no notice.
    assert_eq!(
        (
            notices(&w).await,
            count(&w.t.state, "SELECT COUNT(*) FROM alliance_proposals").await,
            count(&w.t.state, "SELECT COUNT(*) FROM ally_links").await,
        ),
        before
    );

    // The facilitator's list is the same bytes whatever people do.
    let posted0 = w.t.get(&sug, Some(&w.f.s)).await;
    assert_eq!(posted0.body.as_array().unwrap().len(), 1);
    let id = ann.body[0]["id"].as_str().unwrap().to_owned();
    // Not theirs: 404, and ann's card is untouched.
    assert_eq!(dismiss(&w, &w.cat, &id).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        w.t.get(&mine, Some(&w.ann.s))
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        dismiss(&w, &w.ann, &id).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(w.t.get(&mine, Some(&w.ann.s)).await.body, json!([]));
    assert_eq!(
        w.t.get(&mine, Some(&w.ben.s))
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(w.t.get(&sug, Some(&w.f.s)).await.body, posted0.body);

    // Acting through the ordinary route is also invisible to the
    // facilitator, and posting the pair again (either way round) looks the
    // same.
    let p =
        w.t.post(
            &format!("/v1/groups/{}/proposals", w.gid),
            json!({ "to": w.ann.id, "kind": "request" }),
            Some(&w.ben.s),
        )
        .await;
    assert_eq!(p.status, StatusCode::CREATED, "{:?}", p.body);
    assert_eq!(
        dismiss(&w, &w.ben, &id).await.status,
        StatusCode::NO_CONTENT
    );
    let again =
        w.t.post(
            &sug,
            json!([{ "a": w.ben.id, "b": w.ann.id }]),
            Some(&w.f.s),
        )
        .await;
    assert_eq!(again.body["posted"], json!(0));
    assert_eq!(w.t.get(&sug, Some(&w.f.s)).await.body, posted0.body);
    assert!(!posted0.body.to_string().contains("dismiss"));

    // A list at once, and withdrawing one.
    let r =
        w.t.post(
            &sug,
            json!([{ "a": w.ann.id, "b": w.cat.id }, { "a": w.ben.id, "b": w.cat.id }]),
            Some(&w.f.s),
        )
        .await;
    assert_eq!(r.body["posted"], json!(2));
    assert_eq!(
        w.t.get(&mine, Some(&w.cat.s))
            .await
            .body
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let sid = w.t.get(&sug, Some(&w.f.s)).await.body[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let d =
        w.t.call(
            Method::DELETE,
            &format!("{sug}/{sid}"),
            None,
            Some(&w.ann.s),
        )
        .await;
    assert_eq!(d.status, StatusCode::FORBIDDEN);
    let d =
        w.t.call(Method::DELETE, &format!("{sug}/{sid}"), None, Some(&w.f.s))
            .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn purging_an_account_removes_its_suggestions() {
    let w = world().await;
    w.t.post(
        &format!("/v1/groups/{}/suggestions", w.gid),
        json!([{ "a": w.ann.id, "b": w.ben.id }]),
        Some(&w.f.s),
    )
    .await;
    assert_eq!(
        count(&w.t.state, "SELECT COUNT(*) FROM pairing_suggestions").await,
        1
    );
    let mut conn = w.t.state.db().pool().acquire().await.unwrap();
    faro_server::db::repo::deletion::delete_rows(&mut conn, &w.ann.id, &w.ann.email, 0)
        .await
        .unwrap();
    assert_eq!(
        count(&w.t.state, "SELECT COUNT(*) FROM pairing_suggestions").await,
        0
    );
}
