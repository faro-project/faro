//! Groups (docs/GROUPS.md, phase A server core): the authorization matrix,
//! roles and limits, invitations, the lifecycle (archive, retention, account
//! purge), the admin console, and the rule that no email ever names a group.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::UserId;
use faro_server::config::RegistrationMode;
use faro_server::db::repo::groups as repo;
use faro_server::db::repo::users;
use faro_server::deletion;
use serde_json::{json, Value};
use sqlx::Row;

const DAY: i64 = 24 * 3600 * 1000;
const NAME: &str = "Tuesday Recovery Zebra";
const DESC: &str = "SecretDescriptionQuokka for the Tuesday men";

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

/// A group created by `f`, named [`NAME`].
async fn group_by(t: &TestApp, f: &Person) -> String {
    let r = t
        .post(
            "/v1/groups",
            json!({ "name": NAME, "description": DESC }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["my_role"], "facilitator");
    r.body["id"].as_str().unwrap().to_owned()
}

/// The invite URL's token.
fn token_of(r: &Resp, i: usize) -> String {
    token_from_email(r.body["invites"][i]["invite_url"].as_str().unwrap()).unwrap()
}

async fn invite(t: &TestApp, by: &Person, gid: &str, emails: &[&str]) -> Resp {
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": emails }),
            Some(&by.s),
        )
        .await;
    if r.status == StatusCode::CREATED {
        // The emails go out asynchronously: wait for them, so a sign-in link
        // requested next can't be confused with one.
        for i in r.body["invites"].as_array().unwrap() {
            let inv = i["invited"].as_str().unwrap();
            if inv.contains('@') {
                wait_for_mail(t, inv, "/group-invite#token=").await;
            }
        }
    }
    r
}

/// Invite `p` by address and have them accept.
async fn join(t: &TestApp, by: &Person, gid: &str, p: &Person) {
    let r = invite(t, by, gid, &[&p.email]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let a = accept(t, p, &token_of(&r, 0)).await;
    assert_eq!(a.status, StatusCode::CREATED, "{:?}", a.body);
}

async fn accept(t: &TestApp, p: &Person, token: &str) -> Resp {
    t.post(
        &format!("/v1/group-invites/{token}/accept"),
        json!({}),
        Some(&p.s),
    )
    .await
}

async fn del(t: &TestApp, path: &str, s: &str) -> Resp {
    t.call(Method::DELETE, path, None, Some(s)).await
}

async fn patch(t: &TestApp, path: &str, body: Value, s: &str) -> Resp {
    t.call(Method::PATCH, path, Some(body), Some(s)).await
}

async fn put(t: &TestApp, path: &str, body: Value, s: &str) -> Resp {
    t.call(Method::PUT, path, Some(body), Some(s)).await
}

/// An account with no session, added straight to the database.
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

async fn add_fake(t: &TestApp, gid: &str, n: usize, role: repo::Role) -> UserId {
    let id = fake_user(t, n).await;
    repo::add_participant(
        t.state.db().pool(),
        gid,
        &id,
        role,
        None,
        repo::JoinedVia::Invite,
        t.clock_ms() + n as i64,
    )
    .await
    .unwrap();
    id
}

async fn admin_patch_groups(t: &TestApp, admin_s: &str, body: Value) {
    let r = patch(t, "/admin/api/settings", json!({ "groups": body }), admin_s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

async fn count(t: &TestApp, sql: &'static str) -> i64 {
    sqlx::query(sql)
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

// ---- Basics ------------------------------------------------------------------

#[tokio::test]
async fn create_get_and_list() {
    let t = TestApp::new().await;
    let sam = person(&t, "sam").await;
    let gid = group_by(&t, &sam).await;

    let g = t.get(&format!("/v1/groups/{gid}"), Some(&sam.s)).await;
    assert_eq!(g.status, StatusCode::OK, "{:?}", g.body);
    assert_eq!(g.body["name"], NAME);
    assert_eq!(g.body["description"], DESC);
    assert_eq!(g.body["participant_count"], 1);
    assert_eq!(g.body["facilitators"][0]["display_name"], "sam");
    assert_eq!(g.body["can_invite"], true);
    assert_eq!(g.body["who_can_invite"], "facilitators");
    assert_eq!(g.body["listed"], false);
    assert!(g.body["max_participants"].is_null());

    let l = t.get("/v1/groups", Some(&sam.s)).await;
    assert_eq!(l.body.as_array().unwrap().len(), 1);
    assert_eq!(l.body[0]["id"], gid);

    // The creator's join is in the history.
    let h = t
        .get(&format!("/v1/groups/{gid}/history"), Some(&sam.s))
        .await;
    assert_eq!(h.body["items"][0]["kind"], "joined");
    assert_eq!(h.body["items"][0]["subject"]["display_name"], "sam");

    // Bad names and unknown fields.
    for body in [
        json!({ "name": "  " }),
        json!({ "name": "x".repeat(101) }),
        json!({ "name": "ok", "description": "y".repeat(1001) }),
        json!({ "name": "ok", "listed": true }),
    ] {
        let r = t.post("/v1/groups", body, Some(&sam.s)).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{:?}", r.body);
    }
    assert_eq!(
        t.post("/v1/groups", json!({ "name": "x" }), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn patch_details() {
    let t = TestApp::new().await;
    let sam = person(&t, "sam").await;
    let gid = group_by(&t, &sam).await;
    let path = format!("/v1/groups/{gid}");
    t.clock.advance_ms(1000);

    let r = patch(
        &t,
        &path,
        json!({ "name": "Thursdays", "description": "", "max_participants": 5 }),
        &sam.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["name"], "Thursdays");
    assert_eq!(r.body["description"], "");
    assert_eq!(r.body["max_participants"], 5);
    // null removes the limit.
    let r = patch(&t, &path, json!({ "max_participants": null }), &sam.s).await;
    assert!(r.body["max_participants"].is_null(), "{:?}", r.body);
    // Below the current size, and out of range.
    assert_eq!(
        patch(&t, &path, json!({ "max_participants": 0 }), &sam.s)
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    // The group may not widen who can invite beyond the instance.
    let r = patch(
        &t,
        &path,
        json!({ "who_can_invite": "participants" }),
        &sam.s,
    )
    .await;
    assert_eq!(r.error_code(), "not_allowed_by_instance");
    // Meeting and listing fields are not part of this route yet.
    let r = patch(&t, &path, json!({ "meeting": {} }), &sam.s).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // The rename is in the history.
    let h = t.get(&format!("{path}/history"), Some(&sam.s)).await;
    assert_eq!(h.body["items"][0]["kind"], "renamed");
}

// ---- The authorization matrix ------------------------------------------------

#[tokio::test]
async fn authorization_matrix() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let fac = person(&t, "fac").await;
    let part = person(&t, "part").await;
    let ex = person(&t, "ex").await;
    let out = person(&t, "out").await;
    let victim = person(&t, "victim").await;
    let gid = group_by(&t, &fac).await;
    join(&t, &fac, &gid, &part).await;
    join(&t, &fac, &gid, &ex).await;
    join(&t, &fac, &gid, &victim).await;
    assert_eq!(
        del(&t, &format!("/v1/groups/{gid}/me"), &ex.s).await.status,
        StatusCode::OK
    );

    let g = format!("/v1/groups/{gid}");
    // (method, path, body, who may: facilitator, participant)
    let reads = [
        g.clone(),
        format!("{g}/participants"),
        format!("{g}/history"),
        format!("{g}/invites"),
    ];
    for path in &reads {
        for (who, s, want) in [
            ("facilitator", Some(&fac.s), StatusCode::OK),
            ("participant", Some(&part.s), StatusCode::OK),
            ("ex-participant", Some(&ex.s), StatusCode::NOT_FOUND),
            ("non-participant", Some(&out.s), StatusCode::NOT_FOUND),
            ("admin", Some(&admin_s), StatusCode::NOT_FOUND),
            ("signed out", None, StatusCode::UNAUTHORIZED),
        ] {
            let r = t.call(Method::GET, path, None, s.map(String::as_str)).await;
            assert_eq!(r.status, want, "{who} GET {path}: {:?}", r.body);
        }
    }

    // Facilitator-only actions: a participant gets 403, everyone else 404.
    let outsiders = [
        ("ex-participant", &ex.s),
        ("non-participant", &out.s),
        ("admin", &admin_s),
    ];
    let victim_path = format!("{g}/participants/{}", victim.id);
    let actions: Vec<(&str, String, Option<Value>)> = vec![
        ("PATCH", g.clone(), Some(json!({ "name": "x" }))),
        ("DELETE", g.clone(), None),
        ("DELETE", victim_path.clone(), None),
        (
            "PUT",
            format!("{victim_path}/role"),
            Some(json!({ "facilitator": true })),
        ),
    ];
    for (m, path, body) in &actions {
        let m: Method = m.parse().unwrap();
        let r = t.call(m.clone(), path, body.clone(), Some(&part.s)).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "participant {m} {path}");
        assert_eq!(r.error_code(), "not_a_facilitator");
        for (who, s) in outsiders {
            let r = t.call(m.clone(), path, body.clone(), Some(s)).await;
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{who} {m} {path}");
        }
    }
    // Leaving, inviting, and the facilitator offer are for participants only.
    for (who, s) in outsiders {
        for (m, path, body) in [
            (Method::DELETE, format!("{g}/me"), None),
            (
                Method::POST,
                format!("{g}/invites"),
                Some(json!({ "emails": ["new@example.org"] })),
            ),
            (Method::POST, format!("{g}/facilitator-offer/accept"), None),
        ] {
            let r = t.call(m.clone(), &path, body, Some(s)).await;
            assert_eq!(r.status, StatusCode::NOT_FOUND, "{who} {m} {path}");
        }
    }
    // A participant may not invite while only facilitators can.
    let r = invite(&t, &part, &gid, &["new@example.org"]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN, "{:?}", r.body);

    // The facilitator can do all of it.
    let r = put(
        &t,
        &format!("{victim_path}/role"),
        json!({ "facilitator": true }),
        &fac.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = put(
        &t,
        &format!("{victim_path}/role"),
        json!({ "facilitator": false }),
        &fac.s,
    )
    .await;
    assert_eq!(r.body["role"], "participant");
    assert_eq!(
        del(&t, &victim_path, &fac.s).await.status,
        StatusCode::NO_CONTENT
    );
    // The removed person is now an ex-participant.
    assert_eq!(
        t.get(&g, Some(&victim.s)).await.status,
        StatusCode::NOT_FOUND
    );
    // A facilitator can't remove themself (they leave).
    let r = del(&t, &format!("{g}/participants/{}", fac.id), &fac.s).await;
    assert_eq!(r.error_code(), "use_leave");
    // Unknown ids behave like missing groups.
    assert_eq!(
        t.get("/v1/groups/nope", Some(&fac.s)).await.status,
        StatusCode::NOT_FOUND
    );
}

// ---- Roles and limits --------------------------------------------------------

#[tokio::test]
async fn facilitator_rules() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    let g = format!("/v1/groups/{gid}");

    // The only facilitator can neither leave nor step down.
    let r = del(&t, &format!("{g}/me"), &a.s).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "last_facilitator");
    let r = put(
        &t,
        &format!("{g}/participants/{}/role", a.id),
        json!({ "facilitator": false }),
        &a.s,
    )
    .await;
    assert_eq!(r.error_code(), "last_facilitator");

    // Make bob one; now ann may leave, and bob becomes the only one.
    put(
        &t,
        &format!("{g}/participants/{}/role", b.id),
        json!({ "facilitator": true }),
        &a.s,
    )
    .await;
    let r = del(&t, &format!("{g}/me"), &a.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["group_archived"], false);

    // The last participant leaving archives the group.
    let r = del(&t, &format!("{g}/me"), &b.s).await;
    assert_eq!(r.body["group_archived"], true, "{:?}", r.body);
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM accountability_groups WHERE archived_at IS NOT NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn at_most_32_facilitators() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    for n in 1..32 {
        add_fake(&t, &gid, n, repo::Role::Facilitator).await;
    }
    let extra = add_fake(&t, &gid, 99, repo::Role::Participant).await;
    let r = put(
        &t,
        &format!("/v1/groups/{gid}/participants/{extra}/role"),
        json!({ "facilitator": true }),
        &a.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.error_code(), "too_many_facilitators");
}

#[tokio::test]
async fn participant_and_group_limits() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;
    let g = format!("/v1/groups/{gid}");

    // A limit below the current size is refused; at the size, the group is full.
    patch(&t, &g, json!({ "max_participants": 2 }), &a.s).await;
    let r = invite(&t, &a, &gid, &[&b.email]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let tok_b = token_of(&r, 0);
    // Cat's invitation is made before the group fills.
    let r = invite(&t, &a, &gid, &[&c.email]).await;
    let tok_c = token_of(&r, 0);
    assert_eq!(accept(&t, &b, &tok_b).await.status, StatusCode::CREATED);
    let r = accept(&t, &c, &tok_c).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.error_code(), "group_full");
    // Invites are refused too: "This group is full".
    let r = invite(&t, &a, &gid, &["new@example.org"]).await;
    assert_eq!(r.error_code(), "group_full");
    let r = patch(&t, &g, json!({ "max_participants": 1 }), &a.s).await;
    assert_eq!(r.error_code(), "limit_below_size");
    // Raising it lets cat in (the invitation is still good).
    patch(&t, &g, json!({ "max_participants": null }), &a.s).await;
    assert_eq!(accept(&t, &c, &tok_c).await.status, StatusCode::CREATED);

    // Groups per user.
    admin_patch_groups(&t, &admin_s, json!({ "max_groups_per_user": 2 })).await;
    let r = t
        .post("/v1/groups", json!({ "name": "second" }), Some(&a.s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);
    let r = t
        .post("/v1/groups", json!({ "name": "third" }), Some(&a.s))
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
    assert_eq!(r.error_code(), "too_many_groups");
    // Accepting an invitation counts too.
    let d = person(&t, "dan").await;
    t.post("/v1/groups", json!({ "name": "dans" }), Some(&d.s))
        .await;
    let other = t
        .get("/v1/groups", Some(&a.s))
        .await
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "second")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    join(&t, &a, &other, &d).await; // dan: 2 groups now
    let r = invite(&t, &a, &gid, &[&d.email]).await;
    let r = accept(&t, &d, &token_of(&r, 0)).await;
    assert_eq!(r.error_code(), "too_many_groups", "{:?}", r.body);
}

#[tokio::test]
async fn who_can_create_and_groups_off() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;

    admin_patch_groups(&t, &admin_s, json!({ "who_can_create": "admins" })).await;
    let r = t
        .post("/v1/groups", json!({ "name": "no" }), Some(&a.s))
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "group_creation_restricted");
    let r = t
        .post("/v1/groups", json!({ "name": "yes" }), Some(&admin_s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED);

    // Off: existing groups are read-only.
    admin_patch_groups(&t, &admin_s, json!({ "enabled": false })).await;
    let g = format!("/v1/groups/{gid}");
    let r = t.get(&g, Some(&a.s)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["groups_disabled"], true);
    for r in [
        t.post("/v1/groups", json!({ "name": "no" }), Some(&admin_s))
            .await,
        patch(&t, &g, json!({ "name": "no" }), &a.s).await,
        invite(&t, &a, &gid, &["x@example.org"]).await,
        del(&t, &g, &a.s).await,
    ] {
        assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
        assert_eq!(r.error_code(), "groups_disabled");
    }
    assert_eq!(t.get("/v1/groups", Some(&a.s)).await.status, StatusCode::OK);
    // The setting validates.
    let r = patch(
        &t,
        "/admin/api/settings",
        json!({ "groups": { "max_groups_per_user": 0 } }),
        &admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let s = t.get("/admin/api/settings", Some(&admin_s)).await;
    assert_eq!(s.body["groups"]["enabled"], false);
    assert_eq!(s.body["groups"]["who_can_list"], "facilitators");
}

#[tokio::test]
async fn who_can_invite_is_instance_then_group() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    let g = format!("/v1/groups/{gid}");

    admin_patch_groups(&t, &admin_s, json!({ "who_can_invite": "participants" })).await;
    let v = t.get(&g, Some(&b.s)).await;
    assert_eq!(v.body["can_invite"], true);
    let r = invite(&t, &b, &gid, &["new@example.org"]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    // The group narrows it back to facilitators.
    patch(&t, &g, json!({ "who_can_invite": "facilitators" }), &a.s).await;
    let r = invite(&t, &b, &gid, &["other@example.org"]).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // And the instance narrowing wins over a group that said participants.
    patch(&t, &g, json!({ "who_can_invite": "participants" }), &a.s).await;
    admin_patch_groups(&t, &admin_s, json!({ "who_can_invite": "facilitators" })).await;
    let v = t.get(&g, Some(&b.s)).await;
    assert_eq!(v.body["who_can_invite"], "facilitators");
    assert_eq!(v.body["can_invite"], false);
}

// ---- Invitations -------------------------------------------------------------

#[tokio::test]
async fn invite_flow_binding_and_single_use() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;

    // By address and by user id; already-in-group and repeats are skipped.
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({
                "emails": [b.email, "Bob@Example.org", a.email, "new@example.org"],
                "user_ids": [c.id, a.id, "nonsense"]
            }),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["invites"].as_array().unwrap().len(), 3);
    assert_eq!(r.body["skipped"], 4);
    let tok_b = token_of(&r, 0);

    // The link shows the invited person who invited them and the group, only
    // to them.
    let info = t
        .get(&format!("/v1/group-invites/{tok_b}"), Some(&b.s))
        .await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["group_name"], NAME);
    assert_eq!(info.body["inviter_display_name"], "ann");
    for s in [Some(&c.s), Some(&a.s), None] {
        let r = t
            .call(
                Method::GET,
                &format!("/v1/group-invites/{tok_b}"),
                None,
                s.map(String::as_str),
            )
            .await;
        assert!(
            r.status == StatusCode::NOT_FOUND || r.status == StatusCode::UNAUTHORIZED,
            "{:?}",
            r.status
        );
    }
    // Someone else with the link can't accept or decline it.
    assert_eq!(
        accept(&t, &c, &tok_b).await.status,
        StatusCode::NOT_FOUND,
        "bound to the address"
    );
    let r = t
        .post(
            &format!("/v1/group-invites/{tok_b}/decline"),
            json!({}),
            Some(&c.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    // Bob sees it in-app too, and can accept by that reference.
    let mine = t.get("/v1/me/group-invites", Some(&b.s)).await;
    assert_eq!(mine.body.as_array().unwrap().len(), 1);
    let by_ref = mine.body[0]["invite_ref"].as_str().unwrap().to_owned();
    t.clock.advance_ms(1000);
    let r = accept(&t, &b, &by_ref).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["my_role"], "participant");
    assert_eq!(r.body["participant_count"], 2);
    // Single use.
    assert_eq!(accept(&t, &b, &tok_b).await.status, StatusCode::NOT_FOUND);

    // Cat (invited by user id) declines; the inviter sees "not_accepted".
    let mine = t.get("/v1/me/group-invites", Some(&c.s)).await;
    let r = t
        .post(
            &format!(
                "/v1/group-invites/{}/decline",
                mine.body[0]["invite_ref"].as_str().unwrap()
            ),
            json!({}),
            Some(&c.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{:?}", r.body);
    let list = t
        .get(&format!("/v1/groups/{gid}/invites"), Some(&a.s))
        .await;
    let states: Vec<_> = list
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["invited"].as_str().unwrap().to_owned(),
                i["state"].clone(),
            )
        })
        .collect();
    assert!(
        states.contains(&(b.email.clone(), json!("accepted"))),
        "{states:?}"
    );
    assert!(
        states.contains(&("cat".to_owned(), json!("not_accepted"))),
        "{states:?}"
    );
    assert!(
        states.contains(&("new@example.org".to_owned(), json!("pending"))),
        "{states:?}"
    );

    // The history shows the join, so nobody is added unseen.
    let h = t
        .get(&format!("/v1/groups/{gid}/history"), Some(&b.s))
        .await;
    assert_eq!(h.body["items"][0]["kind"], "joined");
    assert_eq!(h.body["items"][0]["subject"]["display_name"], "bob");
    assert_eq!(h.body["items"][0]["actor"]["display_name"], "ann");
}

#[tokio::test]
async fn invites_expire_and_die_with_their_inviter() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let d = person(&t, "dan").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    put(
        &t,
        &format!("/v1/groups/{gid}/participants/{}/role", b.id),
        json!({ "facilitator": true }),
        &a.s,
    )
    .await;
    let r = invite(&t, &a, &gid, &[&c.email]).await;
    let tok_c = token_of(&r, 0);
    let r = invite(&t, &b, &gid, &[&d.email]).await;
    let tok_d = token_of(&r, 0);

    // Bob leaves: his open invitations are void.
    del(&t, &format!("/v1/groups/{gid}/me"), &b.s).await;
    assert_eq!(accept(&t, &d, &tok_d).await.status, StatusCode::NOT_FOUND);

    // 8 days later ann's invitation has expired too.
    t.clock.advance_ms(8 * DAY);
    assert_eq!(accept(&t, &c, &tok_c).await.status, StatusCode::NOT_FOUND);
    let list = t
        .get(&format!("/v1/groups/{gid}/invites"), Some(&a.s))
        .await;
    assert!(list
        .body
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["state"] != "pending"));
}

#[tokio::test]
async fn group_invite_lets_a_new_address_sign_up_under_invite_only() {
    let t = TestApp::with_config(|c| c.registration.mode = RegistrationMode::InviteOnly).await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let r = t
        .post("/v1/groups", json!({ "name": NAME }), Some(&admin_s))
        .await;
    let gid = r.body["id"].as_str().unwrap().to_owned();
    let admin = Person {
        id: UserId::new("x"),
        s: admin_s.clone(),
        email: "admin@example.org".into(),
    };

    // Without an invite the address can't register.
    let r = t
        .post(
            "/v1/auth/magic-link",
            json!({ "email": "newbie@elsewhere.net" }),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    assert!(t.mail_to("newbie@elsewhere.net").is_empty());

    let r = invite(&t, &admin, &gid, &["newbie@elsewhere.net"]).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let tok = token_of(&r, 0);
    let (id, s) = t.sign_in("newbie@elsewhere.net").await;
    let me = Person {
        id,
        s,
        email: "newbie@elsewhere.net".into(),
    };
    assert_eq!(accept(&t, &me, &tok).await.status, StatusCode::CREATED);

    // Switched off by the admin: another invitation no longer opens signup.
    admin_patch_groups(&t, &admin_s, json!({ "invites_create_accounts": false })).await;
    invite(&t, &admin, &gid, &["other@elsewhere.net"]).await;
    t.post(
        "/v1/auth/magic-link",
        json!({ "email": "other@elsewhere.net" }),
        None,
    )
    .await;
    assert!(t
        .mail_to("other@elsewhere.net")
        .iter()
        .all(|m| !m.text.contains("#token=") || m.subject.contains("invited")));
    // (the only mail to them is the invitation, never a sign-in link)
    assert!(t
        .mail_to("other@elsewhere.net")
        .iter()
        .all(|m| m.subject.contains("invited you to join a group")));
}

#[tokio::test]
async fn roster_pages_and_search() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    for n in 1..=150 {
        add_fake(&t, &gid, n, repo::Role::Participant).await;
    }
    let p = format!("/v1/groups/{gid}/participants");
    let first = t.get(&p, Some(&a.s)).await;
    assert_eq!(first.body["items"].as_array().unwrap().len(), 100);
    let cursor = first.body["next_cursor"].as_str().unwrap().to_owned();
    let second = t.get(&format!("{p}?cursor={cursor}"), Some(&a.s)).await;
    assert_eq!(second.body["items"].as_array().unwrap().len(), 51);
    assert!(second.body["next_cursor"].is_null());
    // No emails in the roster.
    assert!(!String::from_utf8_lossy(&first.raw).contains("@example.org"));
    // Search by display name.
    let q = t.get(&format!("{p}?q=fake%20042"), Some(&a.s)).await;
    assert_eq!(q.body["items"].as_array().unwrap().len(), 1);
    let q = t.get(&format!("{p}?q=100%25"), Some(&a.s)).await;
    assert_eq!(q.body["items"].as_array().unwrap().len(), 0, "% is literal");
    assert_eq!(
        t.get(&format!("{p}?cursor=junk"), Some(&a.s)).await.status,
        StatusCode::BAD_REQUEST
    );
    // History pages too.
    let h = t
        .get(&format!("/v1/groups/{gid}/history"), Some(&a.s))
        .await;
    assert_eq!(h.status, StatusCode::OK);
    assert_eq!(h.body["items"].as_array().unwrap().len(), 1);
}

// ---- Lifecycle ---------------------------------------------------------------

#[tokio::test]
async fn archive_is_read_only_then_deleted_and_never_touches_allies() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;

    // An alliance formed in the group (what the proposals work will create).
    sqlx::query(
        "INSERT INTO ally_links (id, member_id, ally_id, state, created_at, origin_group_id)
         VALUES ('link1', $1, $2, 'pending', 1, $3)",
    )
    .bind(a.id.as_str())
    .bind(b.id.as_str())
    .bind(&gid)
    .execute(t.state.db().pool())
    .await
    .unwrap();
    let alerts_before = count(&t, "SELECT COUNT(*) AS n FROM alerts").await;

    // Bob leaves and rejoins: alliances are not touched.
    del(&t, &format!("/v1/groups/{gid}/me"), &b.s).await;
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM ally_links WHERE state = 'pending'"
        )
        .await,
        1
    );
    join(&t, &a, &gid, &b).await;

    let g = format!("/v1/groups/{gid}");
    let r = del(&t, &g, &a.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let delete_after = r.body["delete_after_ms"].as_i64().unwrap();
    assert_eq!(
        delete_after,
        r.body["archived_at_ms"].as_i64().unwrap() + 30 * DAY
    );

    // Read-only: reads work, everything else is refused, for everyone.
    for s in [&a.s, &b.s] {
        let v = t.get(&g, Some(s)).await;
        assert_eq!(v.status, StatusCode::OK);
        assert_eq!(v.body["archived_at_ms"], r.body["archived_at_ms"]);
        assert_eq!(v.body["listed"], false);
        assert_eq!(v.body["can_invite"], false);
    }
    for r in [
        patch(&t, &g, json!({ "name": "x" }), &a.s).await,
        invite(&t, &a, &gid, &["x@example.org"]).await,
        del(&t, &g, &a.s).await,
        del(&t, &format!("{g}/me"), &b.s).await,
        del(&t, &format!("{g}/participants/{}", b.id), &a.s).await,
    ] {
        assert_eq!(r.status, StatusCode::CONFLICT, "{:?}", r.body);
        assert_eq!(r.error_code(), "group_archived");
    }
    let l = t.get("/v1/groups", Some(&b.s)).await;
    assert_eq!(l.body[0]["delete_after_ms"], delete_after);
    // An archived group doesn't count against the per-user limit.
    assert_eq!(
        repo::count_live_groups_of(t.state.db().pool(), &b.id)
            .await
            .unwrap(),
        0
    );

    // Retention: not before 30 days, then the group goes with its rows.
    t.clock.advance_ms(29 * DAY);
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM accountability_groups").await,
        1
    );
    t.clock.advance_ms(2 * DAY);
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM accountability_groups").await,
        0
    );
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_participants").await,
        0
    );
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_history").await,
        0
    );
    assert!(repo::by_id(t.state.db().pool(), &gid)
        .await
        .unwrap()
        .is_none());

    // The alliance outlived the group; only its label went.
    let link = sqlx::query("SELECT state, origin_group_id FROM ally_links WHERE id = 'link1'")
        .fetch_one(t.state.db().pool())
        .await
        .unwrap();
    assert_eq!(link.try_get::<String, _>("state").unwrap(), "pending");
    assert!(link
        .try_get::<Option<String>, _>("origin_group_id")
        .unwrap()
        .is_none());
    // No alert was raised about any of it.
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM alerts").await,
        alerts_before
    );
}

#[tokio::test]
async fn purged_last_facilitator_offers_the_role_to_the_earliest_participant() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;
    t.clock.advance_ms(1000);
    join(&t, &a, &gid, &b).await;
    t.clock.advance_ms(1000);
    join(&t, &a, &gid, &c).await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;

    // Ann deletes her account; after the hold and the notices, she is purged.
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": a.email })),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    t.clock.advance_ms(7 * DAY + 1000);
    deliver_all(&t).await;
    assert_eq!(deletion::run_once(&t.state).await.unwrap().purged, 1);

    // Bob joined first: he is offered the role. Cat is not.
    let g = format!("/v1/groups/{gid}");
    let v = t.get(&g, Some(&b.s)).await;
    assert_eq!(v.status, StatusCode::OK, "{:?}", v.body);
    assert_eq!(v.body["no_facilitator"], true);
    assert!(v.body["facilitator_offer_until_ms"].as_i64().unwrap() > t.clock_ms());
    assert_eq!(
        t.get(&g, Some(&c.s)).await.body["facilitator_offer_until_ms"],
        Value::Null
    );
    assert_eq!(
        t.post(
            &format!("{g}/facilitator-offer/accept"),
            json!({}),
            Some(&c.s)
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    // Admins see the flag.
    let list = t.get("/admin/api/groups", Some(&admin_s)).await;
    assert_eq!(list.body[0]["no_facilitator"], true);
    assert_eq!(list.body[0]["facilitators"].as_array().unwrap().len(), 0);
    // Nobody can invite, edit or remove meanwhile.
    assert_eq!(
        patch(&t, &g, json!({ "name": "x" }), &c.s).await.status,
        StatusCode::FORBIDDEN
    );
    // History: ann's entries stay, without her ("Someone").
    let h = t.get(&format!("{g}/history"), Some(&c.s)).await;
    let items = h.body["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["kind"] == "joined" && i["subject"].is_null()),
        "{items:?}"
    );

    // Bob takes it.
    let r = t
        .post(
            &format!("{g}/facilitator-offer/accept"),
            json!({}),
            Some(&b.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["my_role"], "facilitator");
    assert_eq!(r.body["no_facilitator"], false);
    assert!(r.body["facilitator_offer_until_ms"].is_null());
}

#[tokio::test]
async fn an_unaccepted_offer_ends_after_14_days_and_the_group_goes_on() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    sqlx::query("UPDATE accountability_groups SET listed = 1 WHERE id = $1")
        .bind(&gid)
        .execute(t.state.db().pool())
        .await
        .unwrap();
    t.post("/v1/me/deletion/cancel", json!({}), Some(&a.s))
        .await;
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": a.email })),
            Some(&a.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    t.clock.advance_ms(7 * DAY + 1000);
    deliver_all(&t).await;
    assert_eq!(deletion::run_once(&t.state).await.unwrap().purged, 1);
    let g = format!("/v1/groups/{gid}");
    // Unlisted without a facilitator.
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM accountability_groups WHERE listed = 1"
        )
        .await,
        0
    );
    assert!(t.get(&g, Some(&b.s)).await.body["facilitator_offer_until_ms"].is_i64());

    t.clock.advance_ms(15 * DAY);
    faro_server::retention::run_once(&t.state).await.unwrap();
    let v = t.get(&g, Some(&b.s)).await;
    assert_eq!(v.status, StatusCode::OK);
    assert!(v.body["facilitator_offer_until_ms"].is_null());
    assert_eq!(v.body["no_facilitator"], true);
    assert_eq!(
        t.post(
            &format!("{g}/facilitator-offer/accept"),
            json!({}),
            Some(&b.s)
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_purged_sole_participant_archives_the_group() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    t.call(
        Method::DELETE,
        "/v1/me",
        Some(json!({ "confirm_email": a.email })),
        Some(&a.s),
    )
    .await;
    t.clock.advance_ms(7 * DAY + 1000);
    deliver_all(&t).await;
    assert_eq!(deletion::run_once(&t.state).await.unwrap().purged, 1);
    let row =
        sqlx::query("SELECT archived_at, created_by FROM accountability_groups WHERE id = $1")
            .bind(&gid)
            .fetch_one(t.state.db().pool())
            .await
            .unwrap();
    assert!(row
        .try_get::<Option<i64>, _>("archived_at")
        .unwrap()
        .is_some());
    assert!(row
        .try_get::<Option<String>, _>("created_by")
        .unwrap()
        .is_none());
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_participants").await,
        0
    );
}

// ---- Admin -------------------------------------------------------------------

#[tokio::test]
async fn admin_sees_metadata_and_can_archive() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;

    // Not an admin: no console.
    assert_eq!(
        t.get("/admin/api/groups", Some(&a.s)).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        del(&t, &format!("/admin/api/groups/{gid}"), &a.s)
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let list = t.get("/admin/api/groups", Some(&admin_s)).await;
    assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
    let row = &list.body[0];
    assert_eq!(row["name"], NAME);
    assert_eq!(row["participant_count"], 2);
    assert_eq!(row["facilitators"][0]["display_name"], "ann");
    assert_eq!(row["no_facilitator"], false);
    assert_eq!(row["listed"], false);
    // Metadata only: no description, no roster, no member names beyond the
    // facilitators, no email addresses.
    let raw = String::from_utf8_lossy(&list.raw).to_string();
    assert!(
        !raw.contains(DESC) && !raw.contains("bob") && !raw.contains("@example.org"),
        "{raw}"
    );
    // And the admin role grants nothing inside the group.
    assert_eq!(
        t.get(&format!("/v1/groups/{gid}"), Some(&admin_s))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    // Archive: logged, and everyone in it is told.
    t.mailer.clear();
    let r = del(&t, &format!("/admin/api/groups/{gid}"), &admin_s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(
        del(&t, &format!("/admin/api/groups/{gid}"), &admin_s)
            .await
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        del(&t, "/admin/api/groups/nope", &admin_s).await.status,
        StatusCode::NOT_FOUND
    );
    let log = t.get("/admin/api/log", Some(&admin_s)).await;
    assert_eq!(log.body[0]["action"], "group_archived");
    assert_eq!(log.body[0]["group_id"], gid);
    assert_eq!(log.body[0]["actor"]["email"], "admin@example.org");
    assert!(log.body[0]["user"].is_null());
    assert_eq!(
        t.get(&format!("/v1/groups/{gid}"), Some(&b.s)).await.body["archived_at_ms"],
        r.body["archived_at_ms"]
    );
    deliver_all(&t).await;
    for p in [&a, &b] {
        let m = t.mail_to(&p.email);
        assert_eq!(m.len(), 1, "{}: {m:?}", p.email);
        assert!(m[0].text.contains("was closed"), "{}", m[0].text);
    }
    let list = t.get("/admin/api/groups", Some(&admin_s)).await;
    assert!(list.body[0]["archived_at_ms"].is_i64());
}

// ---- Notices and emails ------------------------------------------------------

#[tokio::test]
async fn facilitators_are_told_of_joins_and_leaves_but_not_by_name() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    del(&t, &format!("/v1/groups/{gid}/me"), &b.s).await;
    join(&t, &a, &gid, &c).await;
    del(&t, &format!("/v1/groups/{gid}/participants/{}", c.id), &a.s).await;
    t.mailer.clear();
    deliver_all(&t).await;

    let ann = t.mail_to(&a.email);
    // One digest, with a line each for: bob joined, bob left, cat joined.
    assert_eq!(ann.len(), 1, "{ann:?}");
    assert_eq!(
        ann[0]
            .text
            .matches("Someone joined a group you facilitate")
            .count(),
        2,
        "{}",
        ann[0].text
    );
    assert_eq!(
        ann[0]
            .text
            .matches("Someone left a group you facilitate")
            .count(),
        1,
        "{}",
        ann[0].text
    );
    // The removed person is told; the one who left isn't (they did it).
    let cat = t.mail_to(&c.email);
    assert_eq!(cat.len(), 1);
    assert!(cat[0].text.contains("You were removed from a group"));
    assert!(t.mail_to(&b.email).is_empty());
}

#[tokio::test]
async fn large_groups_get_one_daily_summary() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    for n in 1..=33 {
        add_fake(&t, &gid, n, repo::Role::Participant).await;
    }
    t.mailer.clear();
    // Three people join the 34-person group: one summary, due after midnight.
    for n in ["x1", "x2", "x3"] {
        let p = person(&t, n).await;
        join(&t, &a, &gid, &p).await;
    }
    t.mailer.clear();
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM group_notices WHERE summary = 1"
        )
        .await,
        1
    );
    t.clock.advance_ms(2 * DAY);
    deliver_all(&t).await;
    let m = t.mail_to(&a.email);
    assert_eq!(m.len(), 1, "{m:?}");
    assert!(
        m[0].text
            .contains("People joined or left a group you facilitate"),
        "{}",
        m[0].text
    );
}

#[tokio::test]
async fn no_email_ever_names_the_group() {
    let t = TestApp::with_config(|c| c.registration.mode = RegistrationMode::InviteOnly).await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let admin = Person {
        id: UserId::new("x"),
        s: admin_s.clone(),
        email: "admin@example.org".into(),
    };
    admin_patch_groups(&t, &admin_s, json!({ "who_can_invite": "participants" })).await;
    let gid = {
        let r = t
            .post(
                "/v1/groups",
                json!({ "name": NAME, "description": DESC }),
                Some(&admin_s),
            )
            .await;
        r.body["id"].as_str().unwrap().to_owned()
    };
    // A brand-new address, an existing account (by address and by id), join,
    // leave, removal, a purge that offers the role, and an archive.
    let r = invite(&t, &admin, &gid, &["stranger@elsewhere.net"]).await;
    let tok = token_of(&r, 0);
    let (sid, ss) = t.sign_in("stranger@elsewhere.net").await;
    let stranger = Person {
        id: sid,
        s: ss,
        email: "stranger@elsewhere.net".into(),
    };
    accept(&t, &stranger, &tok).await;
    let sue = person_at(&t, &admin, &gid, "sue@elsewhere.net").await;
    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "user_ids": [stranger.id] }),
            Some(&stranger.s),
        )
        .await;
    assert_eq!(
        r.status,
        StatusCode::CREATED,
        "participants may invite here: {:?}",
        r.body
    );
    del(&t, &format!("/v1/groups/{gid}/me"), &sue.s).await;
    del(
        &t,
        &format!("/v1/groups/{gid}/participants/{}", stranger.id),
        &admin_s,
    )
    .await;
    deliver_all(&t).await;

    // The admin deletes their account while the last facilitator, with the
    // group having one more participant: the role is offered.
    let eve = person_at(&t, &admin, &gid, "eve@elsewhere.net").await;
    del(&t, &format!("/admin/api/groups/{gid}"), &admin_s).await;
    deliver_all(&t).await;
    let _ = eve;

    let sent = t.mailer.sent();
    assert!(sent.len() >= 6, "{} emails", sent.len());
    let mut kinds = std::collections::BTreeSet::new();
    for m in &sent {
        for secret in [NAME, DESC, "Zebra", "Quokka", "Tuesday"] {
            assert!(
                !m.subject.contains(secret),
                "subject names the group: {m:?}"
            );
            assert!(!m.text.contains(secret), "text names the group: {m:?}");
        }
        kinds.insert(m.subject.split(" on ").next().unwrap_or("").to_owned());
    }
    // The invitation does say who invited and which instance.
    let inv = t.mail_to("stranger@elsewhere.net");
    assert!(
        inv.iter().any(|m| m.subject
            == format!(
                "Admin invited you to join a group on {}",
                t.state.config().instance.name
            )),
        "{inv:?}"
    );
    assert!(kinds.len() >= 4, "{kinds:?}");
}

/// Invite `email` (new address), sign them in, and have them accept.
async fn person_at(t: &TestApp, by: &Person, gid: &str, email: &str) -> Person {
    let r = invite(t, by, gid, &[email]).await;
    let tok = token_of(&r, 0);
    let (id, s) = t.sign_in(email).await;
    let p = Person {
        id,
        s,
        email: email.to_owned(),
    };
    accept(t, &p, &tok).await;
    p
}

#[tokio::test]
async fn offer_email_never_names_the_group() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    join(&t, &a, &gid, &b).await;
    t.call(
        Method::DELETE,
        "/v1/me",
        Some(json!({ "confirm_email": a.email })),
        Some(&a.s),
    )
    .await;
    t.clock.advance_ms(7 * DAY + 1000);
    deliver_all(&t).await;
    t.mailer.clear();
    assert_eq!(deletion::run_once(&t.state).await.unwrap().purged, 1);
    deliver_all(&t).await;
    let m = t.mail_to(&b.email);
    assert!(
        m.iter()
            .any(|m| m.text.contains("offered to facilitate a group")),
        "{m:?}"
    );
    for m in t.mailer.sent() {
        assert!(!m.text.contains("Zebra") && !m.subject.contains("Zebra"));
    }
}
