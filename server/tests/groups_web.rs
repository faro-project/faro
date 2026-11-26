//! The server additions the groups web pages need (docs/GROUPS.md §8.1,
//! §8.7): the roster says how each person is linked to the viewer and sorts
//! linked people first across pages, a facilitator can look people up by
//! name to invite, the leave dialog's "my allies here" list, the group view's
//! two `who_can_invite` values, and the invitation's facilitators and
//! meeting.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::UserId;
use faro_server::db::repo::groups as repo;
use faro_server::db::repo::users;
use serde_json::{json, Value};

const NAME: &str = "Tuesday Recovery Zebra";

struct Person {
    id: UserId,
    s: String,
    email: String,
    keys: MemberKeys,
    ally_keys: AllyKeys,
}

async fn person(t: &TestApp, name: &str) -> Person {
    let email = format!("{name}@example.org");
    let (id, s) = t.sign_in(&email).await;
    let keys = t.create_member_keys(&id, &s).await;
    Person {
        id,
        s,
        email,
        keys,
        ally_keys: AllyKeys::generate(),
    }
}

async fn group_by(t: &TestApp, f: &Person) -> String {
    let r = t
        .post(
            "/v1/groups",
            json!({ "name": NAME, "description": "For the Tuesday men" }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

/// Add `p` straight to the group (no invitation needed for these tests).
async fn add(t: &TestApp, gid: &str, p: &UserId, n: i64) {
    repo::add_participant(
        t.state.db().pool(),
        gid,
        p,
        repo::Role::Participant,
        None,
        repo::JoinedVia::Invite,
        t.clock_ms() + n,
    )
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

/// `ally` accepts `member`'s invitation; `approve` also has the member
/// approve (otherwise the link waits).
async fn link(t: &TestApp, member: &Person, ally: &Person, approve: bool) {
    let token = t.invite(&member.s, &ally.email).await;
    let keys = &ally.ally_keys;
    let r = t.accept(&token, &ally.s, keys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    if approve {
        let r = t
            .approve(
                &member.id,
                &member.keys,
                &member.s,
                &ally.id,
                keys.enc.public(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
}

fn names(items: &Value) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["display_name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_roster_says_how_you_are_linked_and_sorts_linked_people_first() {
    let t = TestApp::new().await;
    let ann = person(&t, "ann").await;
    let gid = group_by(&t, &ann).await;
    let bob = person(&t, "bob").await; // ann's ally
    let cat = person(&t, "cat").await; // ann is cat's ally
    let dan = person(&t, "dan").await; // waiting for safety codes
    let eve = person(&t, "eve").await; // partners
    for (n, p) in [&bob, &cat, &dan, &eve].iter().enumerate() {
        add(&t, &gid, &p.id, n as i64 + 1).await;
    }
    link(&t, &ann, &bob, true).await;
    link(&t, &cat, &ann, true).await;
    link(&t, &ann, &dan, false).await;
    link(&t, &ann, &eve, true).await;
    link(&t, &eve, &ann, true).await;
    // Later joiners, enough for a second page, who sort behind the linked.
    for n in 1..=130usize {
        let f = fake_user(&t, n).await;
        add(&t, &gid, &f, 100 + n as i64).await;
    }
    let late = person(&t, "zed").await; // joined last, but ann's ally
    add(&t, &gid, &late.id, 1000).await;
    link(&t, &ann, &late, true).await;

    let p = format!("/v1/groups/{gid}/participants");
    let first = t.get(&p, Some(&ann.s)).await;
    assert_eq!(first.status, StatusCode::OK);
    let items = first.body["items"].as_array().unwrap();
    let rels: Vec<(String, Option<String>)> = items
        .iter()
        .take(6)
        .map(|i| {
            (
                i["display_name"].as_str().unwrap().to_owned(),
                i["relationship"].as_str().map(str::to_owned),
            )
        })
        .collect();
    let rel = |who: &Person| {
        rels.iter()
            .position(|(n, _)| n == &t_name(&who.email))
            .unwrap_or_else(|| panic!("{} is not in the first six: {rels:?}", who.email))
    };
    assert_eq!(rels[0].1.as_deref(), Some("partners"), "{rels:?}");
    assert_eq!(rel(&eve), 0);
    // Her allies (bob, then zed who joined last), then the person she is
    // an ally of, then the link waiting for a safety code.
    assert_eq!(rels[1].1.as_deref(), Some("your_ally"));
    assert_eq!(rels[2].1.as_deref(), Some("your_ally"));
    assert_eq!(rels[3].1.as_deref(), Some("their_ally"));
    assert_eq!(rel(&cat), 3);
    assert_eq!(rels[4].1.as_deref(), Some("waiting"));
    assert_eq!(rel(&dan), 4);
    // Everyone else, including ann herself: none.
    assert!(rels[5].1.is_none(), "{rels:?}");
    assert!(items[5..].iter().all(|i| i["relationship"].is_null()));
    // The order holds across pages: nobody with a link shows up later.
    let cursor = first.body["next_cursor"].as_str().unwrap();
    let second = t.get(&format!("{p}?cursor={cursor}"), Some(&ann.s)).await;
    assert!(second.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|i| i["relationship"].is_null()));
    let total = items.len() + second.body["items"].as_array().unwrap().len();
    assert_eq!(total, 1 + 4 + 130 + 1);
    assert!(second.body["next_cursor"].is_null());
    // A search keeps the order too.
    let q = t.get(&format!("{p}?q=e"), Some(&ann.s)).await;
    assert_eq!(
        q.body["items"][0]["relationship"], "partners",
        "{:?}",
        q.body
    );

    // Each person sees their own side: bob sees ann as "their ally".
    let from_bob = t.get(&p, Some(&bob.s)).await;
    let ann_line = from_bob.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["user_id"] == ann.id.as_str())
        .unwrap();
    assert_eq!(ann_line["relationship"], "their_ally");
    // A stranger sees no roster at all.
    let stranger = person(&t, "stan").await;
    assert_eq!(
        t.get(&p, Some(&stranger.s)).await.status,
        StatusCode::NOT_FOUND
    );
    let _ = names(&first.body["items"]);
}

/// The display name a fresh account gets (the part of the address before
/// the `@`, as the roster shows it).
fn t_name(email: &str) -> String {
    email.split('@').next().unwrap().to_owned()
}

#[tokio::test]
async fn my_allies_in_this_group_is_a_short_list_for_participants_only() {
    let t = TestApp::new().await;
    let ann = person(&t, "ann").await;
    let gid = group_by(&t, &ann).await;
    let bob = person(&t, "bob").await;
    let cat = person(&t, "cat").await;
    let dan = person(&t, "dan").await; // in the group, no link
    let outsider = person(&t, "olga").await; // linked, but not in the group
    for (n, p) in [&bob, &cat, &dan].iter().enumerate() {
        add(&t, &gid, &p.id, n as i64 + 1).await;
    }
    link(&t, &ann, &bob, true).await;
    link(&t, &cat, &ann, true).await;
    link(&t, &ann, &outsider, true).await;
    for n in 1..=150usize {
        let f = fake_user(&t, n).await;
        add(&t, &gid, &f, 100 + n as i64).await;
    }
    let path = format!("/v1/groups/{gid}/me/allies");
    let r = t.get(&path, Some(&ann.s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let list = r.body.as_array().unwrap();
    assert_eq!(list.len(), 2, "{list:?}");
    assert_eq!(list[0]["relationship"], "your_ally");
    assert_eq!(list[0]["display_name"], "bob");
    assert_eq!(list[1]["relationship"], "their_ally");
    assert!(!String::from_utf8_lossy(&r.raw).contains("@example.org"));
    // Bob sees only his own alliance with ann.
    let r = t.get(&path, Some(&bob.s)).await;
    assert_eq!(names(&r.body), vec!["ann"]);
    // Someone outside the group learns nothing, not even that it exists.
    assert_eq!(
        t.get(&path, Some(&outsider.s)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn facilitators_search_users_by_name_only() {
    let t = TestApp::new().await;
    let ann = person(&t, "ann").await;
    let bob = person(&t, "bob").await;
    let gid = group_by(&t, &ann).await;
    add(&t, &gid, &bob.id, 1).await;
    let inside = fake_user(&t, 1).await;
    add(&t, &gid, &inside, 2).await;
    for n in 2..=4usize {
        fake_user(&t, n).await;
    }
    let path = |q: &str| format!("/v1/groups/{gid}/user-search?q={q}");

    let r = t.get(&path("fake"), Some(&ann.s)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(names(&r.body), vec!["Fake 002", "Fake 003", "Fake 004"]);
    for i in r.body.as_array().unwrap() {
        let keys: Vec<_> = i.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 2, "only an id and a name: {keys:?}");
    }
    assert!(!String::from_utf8_lossy(&r.raw).contains("@"));
    // Not by address: an address with an account looks the same as one
    // without.
    for q in ["fake3%40example.org", "example.org", "fake3@", "bob%40"] {
        let r = t.get(&path(q), Some(&ann.s)).await;
        assert_eq!(r.body, json!([]), "{q}");
    }
    // Not people already in the group, and not one letter.
    assert!(t.get(&path("bob"), Some(&ann.s)).await.body == json!([]));
    assert_eq!(t.get(&path("f"), Some(&ann.s)).await.body, json!([]));
    assert_eq!(t.get(&path("%25%25"), Some(&ann.s)).await.body, json!([]));
    // Participants and strangers can't use it.
    assert_eq!(
        t.get(&path("fake"), Some(&bob.s)).await.status,
        StatusCode::FORBIDDEN
    );
    let stranger = person(&t, "stan").await;
    assert_eq!(
        t.get(&path("fake"), Some(&stranger.s)).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_group_view_has_the_groups_own_invite_setting_and_the_instances() {
    let t = TestApp::new().await;
    let ann = person(&t, "ann").await;
    let gid = group_by(&t, &ann).await;
    let g = format!("/v1/groups/{gid}");
    let v = t.get(&g, Some(&ann.s)).await;
    assert!(v.body["group_who_can_invite"].is_null(), "{:?}", v.body);
    assert_eq!(v.body["instance_who_can_invite"], "facilitators");
    let r = t
        .call(
            Method::PATCH,
            &g,
            Some(json!({ "who_can_invite": "facilitators" })),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["group_who_can_invite"], "facilitators");
    assert_eq!(r.body["instance_who_can_invite"], "facilitators");
}

#[tokio::test]
async fn the_invitation_names_the_facilitators_and_the_meeting_but_not_the_roster() {
    let t = TestApp::new().await;
    let ann = person(&t, "ann").await;
    let bob = person(&t, "bob").await; // an ordinary participant
    let gid = group_by(&t, &ann).await;
    add(&t, &gid, &bob.id, 1).await;
    let r = t
        .call(
            Method::PATCH,
            &format!("/v1/groups/{gid}"),
            Some(json!({ "meeting": {
                "cadence": "weekly", "weekday": 1, "minute_of_day": 1140,
                "tz_offset_min": 0, "place": "Room 104"
            } })),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    let r = t
        .post(
            &format!("/v1/groups/{gid}/invites"),
            json!({ "emails": ["newcomer@example.org"] }),
            Some(&ann.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    wait_for_mail(&t, "newcomer@example.org", "/group-invite#token=").await;
    let token = token_from_email(r.body["invites"][0]["invite_url"].as_str().unwrap()).unwrap();
    let (_, s) = t.sign_in("newcomer@example.org").await;

    let info = t.get(&format!("/v1/group-invites/{token}"), Some(&s)).await;
    assert_eq!(info.status, StatusCode::OK, "{:?}", info.body);
    assert_eq!(info.body["facilitators"], json!(["ann"]));
    assert_eq!(info.body["meeting"]["weekday"], 1);
    assert_eq!(info.body["meeting"]["place"], "Room 104");
    let raw = String::from_utf8_lossy(&info.raw);
    assert!(
        !raw.contains("bob") && !raw.contains("@example.org"),
        "{raw}"
    );
    // The in-app list carries the same.
    let list = t.get("/v1/me/group-invites", Some(&s)).await;
    assert_eq!(list.body[0]["facilitators"], json!(["ann"]));
    assert!(list.body[0]["meeting"].is_object());
}
