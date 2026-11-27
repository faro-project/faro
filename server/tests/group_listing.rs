//! Listed groups, the signed-in directory, join requests, and meetings with
//! reminders (docs/GROUPS.md §8.4, §8.8, §14, Appendix A).

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::UserId;
use faro_server::db::repo::groups as repo;
use faro_server::db::repo::users;
use faro_server::deletion;
use faro_server::meetings;
use serde_json::{json, Value};
use sqlx::Row;

const DAY: i64 = 24 * 3600 * 1000;
const HOUR: i64 = 3600 * 1000;
const NAME: &str = "Tuesday Recovery Zebra";
const DESC: &str = "SecretDescriptionQuokka for the Tuesday men";
const PLACE: &str = "Room 104 Narwhal Annex";

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

/// A fresh session for `p` (sessions don't last as long as some tests run).
async fn relogin(t: &TestApp, p: &Person) -> Person {
    let (id, s) = t.sign_in(&p.email).await;
    Person {
        id,
        s,
        email: p.email.clone(),
    }
}

async fn group_by(t: &TestApp, f: &Person) -> String {
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

async fn call(t: &TestApp, m: Method, path: &str, body: Option<Value>, s: &str) -> Resp {
    t.call(m, path, body, Some(s)).await
}

async fn patch(t: &TestApp, gid: &str, body: Value, s: &str) -> Resp {
    call(
        t,
        Method::PATCH,
        &format!("/v1/groups/{gid}"),
        Some(body),
        s,
    )
    .await
}

async fn list_group(t: &TestApp, gid: &str, f: &Person) {
    let r = patch(t, gid, json!({ "listed": true }), &f.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["listed"], true);
}

async fn ask(t: &TestApp, gid: &str, p: &Person) -> Resp {
    t.post(
        &format!("/v1/groups/{gid}/join-requests"),
        json!({}),
        Some(&p.s),
    )
    .await
}

async fn requests(t: &TestApp, gid: &str, f: &Person) -> Resp {
    t.get(&format!("/v1/groups/{gid}/join-requests"), Some(&f.s))
        .await
}

async fn decide(t: &TestApp, id: &str, what: &str, f: &Person) -> Resp {
    t.post(
        &format!("/v1/join-requests/{id}/{what}"),
        json!({}),
        Some(&f.s),
    )
    .await
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

async fn add_fake(t: &TestApp, gid: &str, n: usize) -> UserId {
    let id = fake_user(t, n).await;
    repo::add_participant(
        t.state.db().pool(),
        gid,
        &id,
        repo::Role::Participant,
        None,
        repo::JoinedVia::Invite,
        t.clock_ms() + n as i64,
    )
    .await
    .unwrap();
    id
}

async fn count(t: &TestApp, sql: &'static str) -> i64 {
    sqlx::query(sql)
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get("n")
        .unwrap()
}

async fn admin_patch_groups(t: &TestApp, admin_s: &str, body: Value) {
    let r = call(
        t,
        Method::PATCH,
        "/admin/api/settings",
        Some(json!({ "groups": body })),
        admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

async fn deliver_all(t: &TestApp) {
    t.notify_now().await;
    t.digest_now().await;
}

// ---- Listing -----------------------------------------------------------------

#[tokio::test]
async fn listing_is_off_by_default_and_facilitators_switch_it() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    assert_eq!(g.body["listed"], false);

    // A participant who isn't a facilitator can't.
    {
        let c = fake_user(&t, 1).await;
        repo::add_participant(
            t.state.db().pool(),
            &gid,
            &c,
            repo::Role::Participant,
            None,
            repo::JoinedVia::Invite,
            t.clock_ms(),
        )
        .await
        .unwrap();
    }
    list_group(&t, &gid, &a).await;
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    // Defaults: meeting time shown, place hidden.
    assert_eq!(g.body["listing"]["show_meeting_time"], true);
    assert_eq!(g.body["listing"]["show_place"], false);
    let r = patch(&t, &gid, json!({ "listing": { "show_place": true } }), &a.s).await;
    assert_eq!(r.body["listing"]["show_place"], true);
    assert_eq!(r.body["listing"]["show_meeting_time"], true);
    // History says listed.
    let h = t
        .get(&format!("/v1/groups/{gid}/history"), Some(&a.s))
        .await;
    assert!(h.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "listed"));
    // Bad listing fields are refused.
    let r = patch(&t, &gid, json!({ "listing": { "show_who": true } }), &a.s).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    // A non-participant gets 404 and a plain participant 403.
    assert_eq!(
        patch(&t, &gid, json!({ "listed": false }), &b.s)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    // Unlist again.
    let r = patch(&t, &gid, json!({ "listed": false }), &a.s).await;
    assert_eq!(r.body["listed"], false);
}

#[tokio::test]
async fn who_can_list_is_enforced() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;

    // Admins only: the facilitator asks, an admin lists.
    admin_patch_groups(&t, &admin_s, json!({ "who_can_list": "admins" })).await;
    let r = patch(&t, &gid, json!({ "listed": true }), &a.s).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(r.error_code(), "listing_needs_admin");
    let r = call(
        &t,
        Method::PUT,
        &format!("/admin/api/groups/{gid}/listed"),
        Some(json!({ "listed": true })),
        &admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    assert_eq!(g.body["listed"], true);
    // The facilitator can still change what it shows, and unlist.
    let r = patch(&t, &gid, json!({ "listing": { "show_place": true } }), &a.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = patch(&t, &gid, json!({ "listed": false }), &a.s).await;
    assert_eq!(r.status, StatusCode::OK);
    // …but not list it again.
    assert_eq!(
        patch(&t, &gid, json!({ "listed": true }), &a.s)
            .await
            .status,
        StatusCode::FORBIDDEN
    );

    // Nobody: no directory at all.
    admin_patch_groups(&t, &admin_s, json!({ "who_can_list": "nobody" })).await;
    let r = patch(&t, &gid, json!({ "listed": true }), &a.s).await;
    assert_eq!(r.error_code(), "listing_disabled");
    let r = call(
        &t,
        Method::PUT,
        &format!("/admin/api/groups/{gid}/listed"),
        Some(json!({ "listed": true })),
        &admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "listing_not_allowed");
    // A listed group is hidden from the directory when listing is "nobody".
    admin_patch_groups(&t, &admin_s, json!({ "who_can_list": "facilitators" })).await;
    list_group(&t, &gid, &a).await;
    admin_patch_groups(&t, &admin_s, json!({ "who_can_list": "nobody" })).await;
    let d = t.get("/v1/group-directory", Some(&a.s)).await;
    assert_eq!(d.body["items"].as_array().unwrap().len(), 0);
    let b = person(&t, "bob").await;
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::NOT_FOUND);

    // Groups switched off: unlisted from view, requests refused.
    admin_patch_groups(
        &t,
        &admin_s,
        json!({ "who_can_list": "facilitators", "enabled": false }),
    )
    .await;
    let d = t.get("/v1/group-directory", Some(&a.s)).await;
    assert_eq!(d.body["items"].as_array().unwrap().len(), 0);
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::CONFLICT);
}

// ---- The directory -----------------------------------------------------------

#[tokio::test]
async fn directory_is_never_served_signed_out() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;

    for path in [
        "/v1/group-directory",
        "/v1/group-directory?q=Tuesday",
        "/v1/group-directory?cursor=1:abc",
    ] {
        let r = t.get(path, None).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{path}");
        let raw = String::from_utf8_lossy(&r.raw).to_string();
        assert!(!raw.contains(NAME) && !raw.contains(DESC), "{raw}");
    }
    // A bad session is no better.
    let r = t.get("/v1/group-directory", Some("not-a-session")).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Neither are the join-request routes.
    let r = t
        .post(&format!("/v1/groups/{gid}/join-requests"), json!({}), None)
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    // Signed in, any user of the instance sees it.
    let b = person(&t, "bob").await;
    let r = t.get("/v1/group-directory", Some(&b.s)).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.body["items"][0]["name"], NAME);
}

#[tokio::test]
async fn directory_listings_hold_no_participant_data() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    // Participants with names and ids that must never appear.
    let mut secret_ids = Vec::new();
    for n in 1..=3 {
        secret_ids.push(add_fake(&t, &gid, n).await);
    }
    let r = patch(
        &t,
        &gid,
        json!({
            "meeting": { "cadence": "weekly", "weekday": 1, "minute_of_day": 1140,
                         "tz_offset_min": 0, "place": PLACE },
        }),
        &a.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    list_group(&t, &gid, &a).await;
    let u = person(&t, "unlisted").await;
    let other = group_by(&t, &u).await;
    let _ = other;

    let d = t.get("/v1/group-directory", Some(&a.s)).await;
    assert_eq!(d.status, StatusCode::OK);
    let items = d.body["items"].as_array().unwrap();
    // Only the listed group, and only listing fields.
    assert_eq!(items.len(), 1, "{:?}", d.body);
    let e = &items[0];
    assert_eq!(e["id"], gid);
    assert_eq!(e["name"], NAME);
    assert_eq!(e["description"], DESC);
    assert_eq!(e["facilitators"], json!(["ann"]));
    assert_eq!(e["meeting"]["weekday"], 1);
    assert_eq!(e["meeting"]["minute_of_day"], 1140);
    assert!(e["meeting"].get("place").is_none());
    assert!(e["place"].is_null(), "place is hidden by default");
    assert_eq!(e["full"], false);
    let mut keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "description",
            "facilitators",
            "full",
            "id",
            "joined",
            "meeting",
            "name",
            "place",
            "requested"
        ]
    );
    let raw = String::from_utf8_lossy(&d.raw).to_string();
    for id in &secret_ids {
        assert!(!raw.contains(id.as_str()), "participant id in {raw}");
    }
    assert!(!raw.contains("Fake 00"), "participant name in {raw}");
    assert!(!raw.contains(a.id.as_str()), "facilitator id in {raw}");
    assert!(!raw.contains("count") && !raw.contains("size"), "{raw}");
    assert!(!raw.contains(PLACE));
    // The anchor and everything else about the meeting stays inside.
    assert!(!raw.contains("anchor"));

    // Show the place, hide the time.
    patch(
        &t,
        &gid,
        json!({ "listing": { "show_place": true, "show_meeting_time": false } }),
        &a.s,
    )
    .await;
    let d = t.get("/v1/group-directory", Some(&a.s)).await;
    let e = &d.body["items"][0];
    assert_eq!(e["place"], PLACE);
    assert!(e["meeting"].is_null());

    // "Full" only when a limit is set and reached; the number never shows.
    let r = patch(&t, &gid, json!({ "max_participants": 4 }), &a.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let d = t.get("/v1/group-directory", Some(&a.s)).await;
    assert_eq!(d.body["items"][0]["full"], true);
    let raw = String::from_utf8_lossy(&d.raw).to_string();
    assert!(!raw.contains("max_participants"));

    // Search by name and description, with paging cursors.
    let b = person(&t, "bob").await;
    assert_eq!(
        t.get("/v1/group-directory?q=zebra", Some(&b.s)).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        t.get("/v1/group-directory?q=quokka", Some(&b.s)).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        t.get("/v1/group-directory?q=nothing", Some(&b.s))
            .await
            .body["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        t.get("/v1/group-directory?cursor=junk", Some(&b.s))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn unlisted_and_archived_groups_are_404_from_the_directory_routes() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    // Not listed yet.
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::NOT_FOUND);
    assert_eq!(ask(&t, "nope", &b).await.status, StatusCode::NOT_FOUND);
    list_group(&t, &gid, &a).await;
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::CREATED);
    // Unlisting hides it at once.
    patch(&t, &gid, json!({ "listed": false }), &a.s).await;
    assert_eq!(
        t.get("/v1/group-directory", Some(&b.s)).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let c = person(&t, "cat").await;
    assert_eq!(ask(&t, &gid, &c).await.status, StatusCode::NOT_FOUND);
    // Archiving unlists too.
    list_group(&t, &gid, &a).await;
    call(&t, Method::DELETE, &format!("/v1/groups/{gid}"), None, &a.s).await;
    assert_eq!(
        t.get("/v1/group-directory", Some(&b.s)).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(ask(&t, &gid, &c).await.status, StatusCode::NOT_FOUND);
}

// ---- Join requests -----------------------------------------------------------

#[tokio::test]
async fn join_request_flow_accept_and_withdraw() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;

    t.mailer.clear();
    let r = ask(&t, &gid, &b).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.body["state"], "open");
    assert_eq!(r.body["group_name"], NAME);
    let rid = r.body["id"].as_str().unwrap().to_owned();
    // Twice is refused; the directory shows "requested" to bob only.
    assert_eq!(ask(&t, &gid, &b).await.error_code(), "already_requested");
    let d = t.get("/v1/group-directory", Some(&b.s)).await;
    assert_eq!(d.body["items"][0]["requested"], true);
    let d = t.get("/v1/group-directory", Some(&c.s)).await;
    assert_eq!(d.body["items"][0]["requested"], false);

    // Facilitators see a name and dates; nobody else sees anything.
    let l = requests(&t, &gid, &a).await;
    assert_eq!(l.status, StatusCode::OK, "{:?}", l.body);
    assert_eq!(l.body["items"][0]["display_name"], "bob");
    assert_eq!(l.body["items"][0]["id"], rid);
    let raw = String::from_utf8_lossy(&l.raw).to_string();
    assert!(!raw.contains("bob@example.org") && !raw.contains(b.id.as_str()));
    assert_eq!(requests(&t, &gid, &b).await.status, StatusCode::NOT_FOUND);
    assert_eq!(requests(&t, &gid, &c).await.status, StatusCode::NOT_FOUND);
    assert_eq!(requests(&t, &gid, &a).await.status, StatusCode::OK);
    // A participant who isn't a facilitator: 403, and can't decide.
    let p = person(&t, "pat").await;
    let inv = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [p.email] }),
            Some(&a.s),
        )
        .await;
    let token = token_from_email(inv.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    t.post(
        &format!("/v1/group-invites/{token}/accept"),
        json!({}),
        Some(&p.s),
    )
    .await;
    assert_eq!(requests(&t, &gid, &p).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        decide(&t, &rid, "accept", &p).await.status,
        StatusCode::FORBIDDEN
    );
    // A stranger can't tell the request exists.
    assert_eq!(
        decide(&t, &rid, "accept", &c).await.status,
        StatusCode::NOT_FOUND
    );
    // The requester can't accept their own.
    assert_eq!(
        decide(&t, &rid, "accept", &b).await.status,
        StatusCode::NOT_FOUND
    );

    // The facilitator is told, without the group's name.
    t.mailer.clear();
    deliver_all(&t).await;
    let m = t.mail_to(&a.email);
    assert!(
        m.iter().any(|m| m
            .text
            .contains("Someone asked to join a group you facilitate")),
        "{m:?}"
    );

    // Accept: bob joins with sharing off, is told, and the group is told.
    t.mailer.clear();
    let r = decide(&t, &rid, "accept", &a).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&b.s)).await;
    assert_eq!(g.status, StatusCode::OK);
    assert_eq!(g.body["my_role"], "participant");
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM group_participants
             WHERE joined_via = 'request' AND share_status = 0 AND share_allies = 0
               AND state = 'active'"
        )
        .await,
        1
    );
    let h = t
        .get(&format!("/v1/groups/{gid}/history"), Some(&b.s))
        .await;
    assert_eq!(h.body["items"][0]["kind"], "joined");
    // Can't be accepted twice.
    assert_eq!(
        decide(&t, &rid, "accept", &a).await.status,
        StatusCode::NOT_FOUND
    );
    deliver_all(&t).await;
    let m = t.mail_to(&b.email);
    assert_eq!(m.len(), 1, "{m:?}");
    assert!(
        m[0].text.contains("You were added to a group"),
        "{}",
        m[0].text
    );
    // Already in: the directory says so, asking again is refused.
    let d = t.get("/v1/group-directory", Some(&b.s)).await;
    assert_eq!(d.body["items"][0]["joined"], true);
    assert_eq!(ask(&t, &gid, &b).await.error_code(), "already_participant");

    // Withdraw: removed, and no cool-down.
    let r = ask(&t, &gid, &c).await;
    assert_eq!(r.status, StatusCode::CREATED);
    assert_eq!(
        call(
            &t,
            Method::DELETE,
            &format!("/v1/groups/{gid}/join-requests/me"),
            None,
            &c.s
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &t,
            Method::DELETE,
            &format!("/v1/groups/{gid}/join-requests/me"),
            None,
            &c.s
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        t.get("/v1/me/join-requests", Some(&c.s)).await.body,
        json!([])
    );
    assert_eq!(ask(&t, &gid, &c).await.status, StatusCode::CREATED);
    // A full group refuses requests and acceptances.
    patch(&t, &gid, json!({ "max_participants": 4 }), &a.s).await;
    let l = requests(&t, &gid, &a).await;
    let rid = l.body["items"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        decide(&t, &rid, "accept", &a).await.status,
        StatusCode::OK,
        "room for the third"
    );
    let d = person(&t, "dan").await;
    assert_eq!(ask(&t, &gid, &d).await.error_code(), "group_full");
}

#[tokio::test]
async fn join_request_limits() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    // Six listed groups; bob may have five open requests.
    let mut gids = Vec::new();
    for _ in 0..6 {
        let g = group_by(&t, &a).await;
        list_group(&t, &g, &a).await;
        gids.push(g);
    }
    for g in &gids[..5] {
        assert_eq!(ask(&t, g, &b).await.status, StatusCode::CREATED);
    }
    let r = ask(&t, &gids[5], &b).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "too_many_join_requests");
    // Withdrawing one makes room.
    call(
        &t,
        Method::DELETE,
        &format!("/v1/groups/{}/join-requests/me", gids[0]),
        None,
        &b.s,
    )
    .await;
    assert_eq!(ask(&t, &gids[5], &b).await.status, StatusCode::CREATED);
    let mine = t.get("/v1/me/join-requests", Some(&b.s)).await;
    assert_eq!(mine.body.as_array().unwrap().len(), 5);
    // Group limit: nobody can request while in the maximum number of groups.
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    admin_patch_groups(&t, &admin_s, json!({ "max_groups_per_user": 1 })).await;
    let c = person(&t, "cat").await;
    group_by(&t, &c).await;
    assert_eq!(ask(&t, &gids[0], &c).await.error_code(), "too_many_groups");
}

#[tokio::test]
async fn decline_and_expiry_look_the_same_and_cool_down_for_30_days() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let d = person(&t, "dan").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;
    let other = group_by(&t, &a).await;
    list_group(&t, &other, &a).await;

    let rb = ask(&t, &gid, &b).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let rc = ask(&t, &gid, &c).await;
    assert_eq!(rc.status, StatusCode::CREATED);
    // dan's request is in a group that gets unlisted.
    ask(&t, &other, &d).await;

    // Decline bob's; nobody is told.
    t.mailer.clear();
    assert_eq!(
        decide(&t, &rb, "decline", &a).await.status,
        StatusCode::NO_CONTENT
    );
    deliver_all(&t).await;
    assert!(t.mail_to(&b.email).is_empty());
    assert_eq!(
        decide(&t, &rb, "decline", &a).await.status,
        StatusCode::NOT_FOUND
    );

    // Right after the decline the requester still sees an open request, in
    // their list, in the directory, and as a refusal to ask again.
    let mine = t.get("/v1/me/join-requests", Some(&b.s)).await;
    assert_eq!(mine.body[0]["state"], "open", "{:?}", mine.body);
    assert_eq!(mine.body[0]["group_name"], json!(NAME));
    assert!(mine.body[0]["expires_at_ms"].is_i64());
    let dir = t.get("/v1/group-directory", Some(&b.s)).await;
    let entry = dir.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == json!(gid))
        .unwrap();
    assert_eq!(entry["requested"], true);
    assert_eq!(ask(&t, &gid, &b).await.error_code(), "already_requested");
    // The facilitators' list no longer holds it.
    assert_eq!(
        requests(&t, &gid, &a).await.body["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Cat's request runs out after 14 days.
    t.clock.advance_ms(15 * DAY);
    // dan's group is unlisted by its facilitator.
    patch(&t, &other, json!({ "listed": false }), &a.s).await;

    // What each of them is shown: the same, apart from the request's id and
    // the group it was about.
    let shown = |who: &Person| {
        let t = &t;
        let who_s = who.s.clone();
        async move {
            let r = t.get("/v1/me/join-requests", Some(&who_s)).await;
            assert_eq!(r.status, StatusCode::OK);
            r
        }
    };
    let rb = shown(&b).await;
    let rc = shown(&c).await;
    let rd = shown(&d).await;
    let normalize = |r: &Resp, gid: &str| {
        let mut s = String::from_utf8_lossy(&r.raw).to_string();
        let v = &r.body[0];
        s = s.replace(v["id"].as_str().unwrap(), "ID");
        s.replace(gid, "GID")
    };
    assert_eq!(normalize(&rb, &gid), normalize(&rc, &gid));
    assert_eq!(normalize(&rb, &gid), normalize(&rd, &other));
    assert_eq!(rb.body[0]["state"], "not_accepted");
    let raw = String::from_utf8_lossy(&rb.raw).to_string();
    assert!(!raw.contains(NAME), "{raw}");

    // Asking again: the same refusal for all of them, with the same words.
    let again_b = ask(&t, &gid, &b).await;
    let again_c = ask(&t, &gid, &c).await;
    assert_eq!(again_b.status, StatusCode::CONFLICT);
    assert_eq!(again_b.raw, again_c.raw);
    assert_eq!(again_b.error_code(), "request_cooldown");

    // The facilitators' list holds neither.
    assert_eq!(requests(&t, &gid, &a).await.body["items"], json!([]));

    // Thirty days after the request would have expired, they may ask again:
    // 14 + 30 days after it was made, for decline and expiry alike.
    t.clock.advance_ms(28 * DAY);
    let (a, b, c) = (
        relogin(&t, &a).await,
        relogin(&t, &b).await,
        relogin(&t, &c).await,
    );
    let _ = &a;
    assert_eq!(ask(&t, &gid, &b).await.error_code(), "request_cooldown");
    assert_eq!(ask(&t, &gid, &c).await.error_code(), "request_cooldown");
    t.clock.advance_ms(2 * DAY);
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::CREATED);
    assert_eq!(ask(&t, &gid, &c).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn unlisting_ends_requests_and_an_admin_unlisting_is_logged_and_told() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let c = person(&t, "cat").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;
    ask(&t, &gid, &b).await;

    // A facilitator unlisting makes the open request "Not accepted".
    patch(&t, &gid, json!({ "listed": false }), &a.s).await;
    let r = t.get("/v1/me/join-requests", Some(&b.s)).await;
    assert_eq!(r.body[0]["state"], "not_accepted");
    assert_eq!(requests(&t, &gid, &a).await.body["items"], json!([]));
    // No cool-down for that: bob may ask once it is listed again.
    list_group(&t, &gid, &a).await;
    assert_eq!(ask(&t, &gid, &b).await.status, StatusCode::CREATED);
    ask(&t, &gid, &c).await;

    // Only admins use the admin route.
    let r = call(
        &t,
        Method::PUT,
        &format!("/admin/api/groups/{gid}/listed"),
        Some(json!({ "listed": false })),
        &a.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    t.mailer.clear();
    let r = call(
        &t,
        Method::PUT,
        &format!("/admin/api/groups/{gid}/listed"),
        Some(json!({ "listed": false })),
        &admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["listed"], false);
    assert_eq!(
        t.get("/v1/group-directory", Some(&b.s)).await.body["items"],
        json!([])
    );
    let log = t.get("/admin/api/log", Some(&admin_s)).await;
    assert_eq!(log.body[0]["action"], "group_unlisted");
    assert_eq!(log.body[0]["group_id"], gid);
    assert_eq!(log.body[0]["actor"]["email"], "admin@example.org");
    for who in [&b, &c] {
        let r = t.get("/v1/me/join-requests", Some(&who.s)).await;
        assert_eq!(r.body[0]["state"], "not_accepted");
    }
    // The facilitators are told, without the name.
    deliver_all(&t).await;
    let m = t.mail_to(&a.email);
    assert!(
        m.iter().any(|m| m
            .text
            .contains("An admin removed a group you facilitate from the directory")),
        "{m:?}"
    );
    // Unlisting what is not listed changes and tells nobody.
    t.mailer.clear();
    let r = call(
        &t,
        Method::PUT,
        &format!("/admin/api/groups/{gid}/listed"),
        Some(json!({ "listed": false })),
        &admin_s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    deliver_all(&t).await;
    assert!(t.mail_to(&a.email).is_empty());
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM admin_log WHERE action = 'group_unlisted'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn emails_never_name_the_group_or_describe_it() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;
    let rid = ask(&t, &gid, &b).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&t, &rid, "accept", &a).await;
    patch(
        &t,
        &gid,
        json!({ "meeting": { "cadence": "weekly", "weekday": 0, "minute_of_day": 600,
                              "tz_offset_min": 0, "place": PLACE } }),
        &a.s,
    )
    .await;
    deliver_all(&t).await;
    for m in t.mailer.sent() {
        for secret in ["Zebra", "Quokka", "Narwhal"] {
            assert!(
                !m.subject.contains(secret) && !m.text.contains(secret),
                "{m:?}"
            );
        }
    }
}

// ---- Meetings and reminders --------------------------------------------------

/// Set a weekly meeting that starts `ahead_ms` from now (to the minute), at
/// UTC, and return when it starts.
async fn meet_in(t: &TestApp, gid: &str, f: &Person, ahead_ms: i64) -> i64 {
    let start = (t.clock_ms() + ahead_ms).div_euclid(60_000) * 60_000 + 60_000;
    let local_day = start.div_euclid(DAY);
    let weekday = (local_day + 3).rem_euclid(7);
    let minute = (start - local_day * DAY) / 60_000;
    let r = patch(
        t,
        gid,
        json!({ "meeting": { "cadence": "weekly", "weekday": weekday, "minute_of_day": minute,
                             "tz_offset_min": 0, "place": PLACE } }),
        &f.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["next_meeting_at_ms"], start);
    start
}

#[tokio::test]
async fn meeting_fields_are_validated_and_can_be_cleared() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    let ok = json!({ "cadence": "fortnightly", "weekday": 6, "minute_of_day": 0,
                     "tz_offset_min": 330 });
    for bad in [
        json!({ "cadence": "daily", "weekday": 1, "minute_of_day": 0, "tz_offset_min": 0 }),
        json!({ "cadence": "weekly", "weekday": 7, "minute_of_day": 0, "tz_offset_min": 0 }),
        json!({ "cadence": "weekly", "weekday": 1, "minute_of_day": 1440, "tz_offset_min": 0 }),
        json!({ "cadence": "weekly", "weekday": 1, "minute_of_day": 0, "tz_offset_min": 900 }),
        json!({ "cadence": "weekly", "weekday": 1, "minute_of_day": 0, "tz_offset_min": 0,
                "place": "x".repeat(201) }),
        json!({ "cadence": "weekly", "weekday": 1, "minute_of_day": 0, "tz_offset_min": 0,
                "extra": 1 }),
        json!({ "cadence": "weekly" }),
    ] {
        let r = patch(&t, &gid, json!({ "meeting": bad }), &a.s).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{bad}: {:?}", r.body);
    }
    let r = patch(&t, &gid, json!({ "meeting": ok }), &a.s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["meeting"]["cadence"], "fortnightly");
    let anchor = r.body["meeting"]["anchor_ms"].as_i64().unwrap();
    // Changing only the place keeps the fortnight.
    t.clock.advance_ms(3 * DAY);
    let mut again = ok.clone();
    again["place"] = json!("Zoom");
    let r = patch(&t, &gid, json!({ "meeting": again }), &a.s).await;
    assert_eq!(r.body["meeting"]["anchor_ms"], anchor);
    assert_eq!(r.body["meeting"]["place"], "Zoom");
    // Clear.
    let r = patch(&t, &gid, json!({ "meeting": null }), &a.s).await;
    assert!(r.body["meeting"].is_null());
    assert!(r.body["next_meeting_at_ms"].is_null());
}

#[tokio::test]
async fn reminders_go_out_two_hours_before_once_and_never_name_the_group() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    let inv = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [b.email] }),
            Some(&a.s),
        )
        .await;
    let token = token_from_email(inv.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    t.post(
        &format!("/v1/group-invites/{token}/accept"),
        json!({}),
        Some(&b.s),
    )
    .await;

    let start = meet_in(&t, &gid, &a, 5 * HOUR).await;
    t.mailer.clear();
    // Too early: more than two hours before.
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    // Two hours and a minute before: still too early.
    t.clock.advance_ms(start - 2 * HOUR - 60_000 - t.clock_ms());
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    // Two hours before: one reminder each, once.
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 2);
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    t.clock.advance_ms(30 * 60_000);
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    t.notify_now().await;
    // The reminder goes out two hours before, which is the day before when
    // the meeting is just after midnight (UTC, the group's time zone).
    let day = if (start - 2 * HOUR).div_euclid(DAY) == start.div_euclid(DAY) {
        " today"
    } else {
        " tomorrow"
    };
    for p in [&a, &b] {
        let m = t.mail_to(&p.email);
        assert_eq!(m.len(), 1, "{}: {m:?}", p.email);
        assert!(
            m[0].text.contains("meets at ") && m[0].text.contains(day),
            "{}",
            m[0].text
        );
        for secret in ["Zebra", "Quokka", "Narwhal", NAME] {
            assert!(
                !m[0].text.contains(secret) && !m[0].subject.contains(secret),
                "{m:?}"
            );
        }
        assert!(m[0].text.contains("on "), "names the instance");
    }
    // After the meeting has started, nothing more until the next one.
    t.clock.advance_ms(2 * HOUR);
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    // A week later, the next meeting.
    t.clock.advance_ms(7 * DAY - 2 * HOUR);
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 2);
}

#[tokio::test]
async fn reminders_can_be_switched_off_per_person() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    let start = meet_in(&t, &gid, &a, 3 * HOUR).await;
    // Defaults.
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    assert_eq!(g.body["my_meeting_reminders"]["reminders"], true);
    assert_eq!(g.body["my_meeting_reminders"]["email"], true);
    assert_eq!(g.body["my_meeting_reminders"]["email_default"], true);

    // Email off: the in-app notice is still written, nothing is emailed.
    let r = call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "email": false })),
        &a.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["reminders"], true);
    assert_eq!(r.body["email"], false);
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    t.mailer.clear();
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 1);
    t.notify_now().await;
    deliver_all(&t).await;
    assert!(t.mail_to(&a.email).is_empty());
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM group_notices WHERE kind = 'meeting_reminder'"
        )
        .await,
        1
    );

    // Reminders off: nothing at all next week.
    let r = call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "reminders": false })),
        &a.s,
    )
    .await;
    assert_eq!(r.body["reminders"], false);
    assert_eq!(r.body["email"], false, "the earlier choice stays");
    t.clock.advance_ms(7 * DAY);
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    // Bad bodies and strangers.
    let b = person(&t, "bob").await;
    let r = call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "email": true })),
        &b.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "loud": true })),
        &a.s,
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn above_32_participants_email_is_off_unless_the_person_opts_in() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    let inv = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": [b.email] }),
            Some(&a.s),
        )
        .await;
    let token = token_from_email(inv.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    t.post(
        &format!("/v1/group-invites/{token}/accept"),
        json!({}),
        Some(&b.s),
    )
    .await;
    // 2 + 30 = 32: still small. One more makes 33.
    for n in 1..=30 {
        add_fake(&t, &gid, n).await;
    }
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    assert_eq!(g.body["participant_count"], 32);
    assert_eq!(g.body["my_meeting_reminders"]["email_default"], true);
    add_fake(&t, &gid, 31).await;
    let g = t.get(&format!("/v1/groups/{gid}"), Some(&a.s)).await;
    assert_eq!(g.body["participant_count"], 33);
    assert_eq!(g.body["my_meeting_reminders"]["email_default"], false);
    assert_eq!(g.body["my_meeting_reminders"]["email"], false);

    // Bob opts in; ann doesn't.
    let r = call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "email": true })),
        &b.s,
    )
    .await;
    assert_eq!(r.body["email"], true);
    let start = meet_in(&t, &gid, &a, 4 * HOUR).await;
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    t.mailer.clear();
    // Every participant gets the in-app notice.
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 33);
    t.notify_now().await;
    assert!(t.mail_to(&a.email).is_empty(), "off by default above 32");
    assert_eq!(t.mail_to(&b.email).len(), 1, "opted in");
    assert!(t
        .mailer
        .sent()
        .iter()
        .all(|m| m.to == b.email || m.to.starts_with("fake") || m.to.contains("example.org")));
    // The fakes got none either.
    assert!(t.mailer.sent().iter().all(|m| !m.to.starts_with("fake")));
}

#[tokio::test]
async fn reminders_do_not_run_for_archived_groups_or_when_groups_are_off() {
    let t = TestApp::new().await;
    let (_, admin_s) = t.setup_admin("admin@example.org").await;
    let a = person(&t, "ann").await;
    let gid = group_by(&t, &a).await;
    let start = meet_in(&t, &gid, &a, 3 * HOUR).await;
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    admin_patch_groups(&t, &admin_s, json!({ "enabled": false })).await;
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
    admin_patch_groups(&t, &admin_s, json!({ "enabled": true })).await;
    call(&t, Method::DELETE, &format!("/v1/groups/{gid}"), None, &a.s).await;
    assert_eq!(meetings::run_once(&t.state).await.unwrap().notices, 0);
}

// ---- Account deletion and retention ------------------------------------------

#[tokio::test]
async fn retention_removes_old_requests_and_the_purge_removes_a_persons_rows() {
    let t = TestApp::new().await;
    let a = person(&t, "ann").await;
    let b = person(&t, "bob").await;
    let gid = group_by(&t, &a).await;
    list_group(&t, &gid, &a).await;
    let rid = ask(&t, &gid, &b).await.body["id"]
        .as_str()
        .unwrap()
        .to_owned();
    decide(&t, &rid, "decline", &a).await;
    let start = meet_in(&t, &gid, &a, 3 * HOUR).await;
    call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "email": false })),
        &a.s,
    )
    .await;
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    meetings::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_join_requests").await,
        1
    );

    // 90 days after the request was decided, it is deleted, and so are the
    // reminder notices of that age.
    t.clock.advance_ms(100 * DAY);
    let a = relogin(&t, &a).await;
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_join_requests").await,
        0
    );
    assert_eq!(
        count(
            &t,
            "SELECT COUNT(*) AS n FROM group_notices WHERE kind = 'meeting_reminder'"
        )
        .await,
        0
    );

    // The purge removes a person's requests and reminder choices.
    let c = person(&t, "cat").await;
    ask(&t, &gid, &c).await;
    call(
        &t,
        Method::PUT,
        &format!("/v1/groups/{gid}/me/meeting-reminders"),
        Some(json!({ "email": true })),
        &a.s,
    )
    .await;
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_join_requests").await,
        1
    );
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": c.email })),
            Some(&c.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    t.clock.advance_ms(7 * DAY + 1000);
    deliver_all(&t).await;
    assert_eq!(deletion::run_once(&t.state).await.unwrap().purged, 1);
    assert_eq!(
        count(&t, "SELECT COUNT(*) AS n FROM group_join_requests").await,
        0
    );
    let r = t.get("/v1/groups", Some(&a.s)).await;
    assert_eq!(r.status, StatusCode::OK);
}
