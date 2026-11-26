//! Granting and revoking the admin role (§4.3): never your own, never the
//! last admin's, always told to the person and every other admin, and
//! never a way to see content.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_proto::UserId;
use serde_json::{json, Value};

async fn set_admin(t: &TestApp, session: &str, user: &UserId, admin: bool) -> Resp {
    t.call(
        Method::PUT,
        &format!("/admin/api/users/{user}/admin"),
        Some(json!({ "admin": admin })),
        Some(session),
    )
    .await
}

async fn log(t: &TestApp, session: &str) -> Vec<Value> {
    let r = t.get("/admin/api/log", Some(session)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body.as_array().expect("array").clone()
}

fn instance(t: &TestApp) -> String {
    t.state.config().instance.name.clone()
}

/// The only email to `to`, which must exist.
fn only_mail(t: &TestApp, to: &str) -> faro_server::mailer::Email {
    let m = t.mail_to(to);
    assert_eq!(m.len(), 1, "{to}: {m:?}");
    m.into_iter().next().expect("one")
}

#[tokio::test]
async fn granting_tells_the_person_and_every_other_admin() {
    let t = TestApp::new().await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let (sam, sam_s) = t.sign_in("sam@example.org").await;
    let name = instance(&t);

    // Not an admin yet: no console.
    assert_eq!(
        t.get("/admin/api/overview", Some(&kim_s)).await.status,
        StatusCode::FORBIDDEN
    );
    let r = set_admin(&t, &admin_s, &kim, true).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["admin"], true);
    // kim and the admin who granted it.
    assert_eq!(r.body["told"], 2);
    // At once, in the session kim already has.
    assert_eq!(
        t.get("/admin/api/overview", Some(&kim_s)).await.status,
        StatusCode::OK
    );

    t.notify_now().await;
    t.mailer.clear();
    t.clock.advance_ms(1000);
    let r = set_admin(&t, &kim_s, &sam, true).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["told"], 3);
    t.notify_now().await;

    let m = only_mail(&t, "sam@example.org");
    assert_eq!(m.subject, format!("You are now an admin of {name}"));
    assert!(m.text.starts_with("kim made you an admin"), "{}", m.text);
    assert!(
        m.text.contains("no access to anyone's reports"),
        "{}",
        m.text
    );
    let m = only_mail(&t, "admin@example.org");
    assert_eq!(m.subject, format!("sam is now an admin of {name}"));
    assert!(
        m.text
            .starts_with("kim made sam (sam@example.org) an admin"),
        "{}",
        m.text
    );
    assert!(m.text.contains("/admin/people"), "{}", m.text);
    let m = only_mail(&t, "kim@example.org");
    assert!(
        m.text
            .starts_with("You made sam (sam@example.org) an admin"),
        "{}",
        m.text
    );

    // The console shows both, newest first, with who did it.
    let entries = log(&t, &sam_s).await;
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["action"], "admin_granted");
    assert_eq!(entries[0]["user"]["id"], sam.as_str());
    assert_eq!(entries[0]["actor"]["id"], kim.as_str());
    assert_eq!(entries[0]["via"], "console");
    assert_eq!(entries[1]["user"]["id"], kim.as_str());
    assert_eq!(entries[1]["actor"]["id"], admin.as_str());
    let users = t.get("/admin/api/users", Some(&admin_s)).await;
    let admins = users.body.as_array().expect("array").iter();
    assert_eq!(admins.filter(|u| u["roles"]["admin"] == true).count(), 3);

    // Mail is only sent once.
    t.mailer.clear();
    t.notify_now().await;
    assert!(t.mailer.sent().is_empty());
}

#[tokio::test]
async fn revoking_is_told_and_takes_effect_at_once() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let (_sam, _) = t.sign_in("sam@example.org").await;
    let name = instance(&t);
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.status,
        StatusCode::OK
    );
    t.notify_now().await;
    t.mailer.clear();
    t.clock.advance_ms(1000);

    let r = set_admin(&t, &admin_s, &kim, false).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["admin"], false);
    // kim keeps their session, without the console.
    assert_eq!(t.get("/v1/me", Some(&kim_s)).await.status, StatusCode::OK);
    assert_eq!(
        t.get("/admin/api/overview", Some(&kim_s)).await.status,
        StatusCode::FORBIDDEN
    );
    t.notify_now().await;
    let m = only_mail(&t, "kim@example.org");
    assert_eq!(m.subject, format!("You are no longer an admin of {name}"));
    assert!(
        m.text.starts_with("Admin removed your admin role"),
        "{}",
        m.text
    );
    assert!(m.text.contains("You can still sign in"), "{}", m.text);
    let m = only_mail(&t, "admin@example.org");
    assert!(
        m.text
            .starts_with("You removed the admin role from kim (kim@example.org)"),
        "{}",
        m.text
    );
    // Nobody else hears about it.
    assert!(t.mail_to("sam@example.org").is_empty());
    assert_eq!(log(&t, &admin_s).await[0]["action"], "admin_revoked");
}

#[tokio::test]
async fn the_rules() {
    let t = TestApp::new().await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let (sam, _) = t.sign_in("sam@example.org").await;

    // Only admins, and only with a JSON body (the CSRF defence).
    assert_eq!(
        set_admin(&t, &kim_s, &sam, true).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        t.get("/admin/api/log", Some(&kim_s)).await.status,
        StatusCode::FORBIDDEN
    );
    let r = t
        .call(
            Method::PUT,
            &format!("/admin/api/users/{sam}/admin"),
            None,
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.error_code(), "expected_json", "{:?}", r.body);
    let nobody = UserId::new("usr_nobody");
    assert_eq!(
        set_admin(&t, &admin_s, &nobody, true).await.status,
        StatusCode::NOT_FOUND
    );

    // Never your own role.
    let r = set_admin(&t, &admin_s, &admin, false).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "cannot_change_own_role");

    // Nothing to change.
    assert_eq!(
        set_admin(&t, &admin_s, &sam, false).await.error_code(),
        "not_admin"
    );
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.status,
        StatusCode::OK
    );
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.error_code(),
        "already_admin"
    );

    // Never the last enabled admin who isn't being deleted: once the first
    // admin is deleting their account, kim is that admin.
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": "admin@example.org" })),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = set_admin(&t, &admin_s, &kim, false).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "last_admin");
    // And the account being deleted can't be changed.
    let r = set_admin(&t, &kim_s, &admin, false).await;
    assert_eq!(r.error_code(), "account_deleting", "{:?}", r.body);
    assert_eq!(
        t.post("/v1/me/deletion/cancel", json!({}), Some(&admin_s))
            .await
            .status,
        StatusCode::OK
    );

    // Not granted to a disabled account. A disabled admin's role can be
    // revoked, and they hear nothing: a disabled account hears only that
    // it was disabled.
    let r = t
        .post(
            &format!("/admin/api/users/{sam}/disable"),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = set_admin(&t, &admin_s, &sam, true).await;
    assert_eq!(r.error_code(), "account_disabled", "{:?}", r.body);
    let r = t
        .post(
            &format!("/admin/api/users/{kim}/disable"),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    t.mailer.clear();
    let r = set_admin(&t, &admin_s, &kim, false).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["told"], 1);
    t.notify_now().await;
    assert!(t.mail_to("kim@example.org").is_empty());
    assert_eq!(t.mail_to("admin@example.org").len(), 1);
}

#[tokio::test]
async fn the_role_reaches_no_content_and_no_ally() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s, sam_keys, _dev) = t.active_device().await;
    let pat = t
        .link_ally(&sam, &sam_keys, &sam_s, "pat@elsewhere.net")
        .await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let alerts_before = t.alerts(&sam).await.len();
    t.notify_now().await;
    t.mailer.clear();

    assert_eq!(
        set_admin(&t, &admin_s, &sam, true).await.status,
        StatusCode::OK
    );
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.status,
        StatusCode::OK
    );
    t.notify_now().await;
    // Not an alert: sam's feed and allies see nothing of it.
    assert_eq!(t.alerts(&sam).await.len(), alerts_before);
    assert!(t.mail_to(&pat.email).is_empty());
    // A new admin still can't open anyone's feed.
    assert_ne!(t.feed(&sam, &kim_s).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_command_line_grants_the_role_when_nobody_can() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, _) = t.sign_in("kim@example.org").await;
    let (sam, _) = t.sign_in("sam@example.org").await;
    let (_lee, lee_s) = t.sign_in("lee@example.org").await;
    let name = instance(&t);
    t.mailer.clear();

    let out = faro_server::cli::admin_grant(&t.state, " Kim@Example.org ", false, None)
        .await
        .expect("granted");
    assert!(out.starts_with("kim@example.org is now an admin"), "{out}");
    t.notify_now().await;
    let m = only_mail(&t, "kim@example.org");
    assert_eq!(m.subject, format!("You are now an admin of {name}"));
    assert!(
        m.text.starts_with(&format!(
            "Someone with access to the server made you an admin of {name} from the server's \
             command line."
        )),
        "{}",
        m.text
    );
    let m = only_mail(&t, "admin@example.org");
    assert!(
        m.text
            .starts_with("Someone with access to the server made kim (kim@example.org)"),
        "{}",
        m.text
    );
    let entry = &log(&t, &admin_s).await[0];
    assert_eq!(entry["user"]["id"], kim.as_str());
    assert_eq!(entry["actor"], Value::Null);
    assert_eq!(entry["via"], "command_line");

    // Again: nothing changes.
    let out = faro_server::cli::admin_grant(&t.state, "kim@example.org", false, None)
        .await
        .expect("no-op");
    assert!(out.contains("already an admin"), "{out}");
    assert_eq!(log(&t, &admin_s).await.len(), 1);

    // No such account.
    let e = faro_server::cli::admin_grant(&t.state, "nobody@example.org", false, None)
        .await
        .expect_err("no account");
    assert!(e.to_string().contains("sign in once"), "{e}");
    let e = faro_server::cli::admin_grant(&t.state, "not an address", false, None)
        .await
        .expect_err("not an address");
    assert!(e.to_string().contains("not an email address"), "{e}");

    // Disabled, or being deleted.
    t.clock.advance_ms(1000);
    let r = t
        .post(
            &format!("/admin/api/users/{sam}/disable"),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let e = faro_server::cli::admin_grant(&t.state, "sam@example.org", false, None)
        .await
        .expect_err("disabled");
    assert!(e.to_string().contains("is disabled"), "{e}");
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": "lee@example.org" })),
            Some(&lee_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let e = faro_server::cli::admin_grant(&t.state, "lee@example.org", false, None)
        .await
        .expect_err("deleting");
    assert!(e.to_string().contains("being deleted"), "{e}");
    // Only the grant and disabling sam: the refusals logged nothing.
    let entries = log(&t, &admin_s).await;
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert_eq!(entries[0]["action"], "account_disabled");
}

#[tokio::test]
async fn the_log_forgets_deleted_accounts() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let (sam, _) = t.sign_in("sam@example.org").await;
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.status,
        StatusCode::OK
    );
    t.clock.advance_ms(1000);
    assert_eq!(
        set_admin(&t, &kim_s, &sam, true).await.status,
        StatusCode::OK
    );
    // kim deletes their account, and the purge runs once the hold has
    // passed and every notice is out.
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": "kim@example.org" })),
            Some(&kim_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    t.clock
        .advance_ms(faro_server::api::account::HOLD_MS + 1000);
    t.notify_now().await;
    t.digest_now().await;
    let s = faro_server::deletion::run_once(&t.state)
        .await
        .expect("purge");
    assert_eq!(s.purged, 1, "{s:?}");

    let entries = log(&t, &admin_s).await;
    assert_eq!(entries.len(), 2, "{entries:?}");
    // kim granted sam the role: the entry stays, without kim.
    assert_eq!(entries[0]["user"]["id"], sam.as_str());
    assert_eq!(entries[0]["actor"], Value::Null);
    assert_eq!(entries[0]["via"], "console");
    // kim was granted the role: the entry no longer names them.
    assert_eq!(entries[1]["user"], Value::Null);
    assert_eq!(
        count_with(
            &t.state,
            "SELECT COUNT(*) AS n FROM admin_log WHERE user_id = $1 OR actor_id = $1",
            kim.as_str()
        )
        .await,
        0
    );
}

#[tokio::test]
async fn the_command_line_can_create_the_admin_account() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let name = instance(&t);
    t.mailer.clear();

    // Without --create, an unknown address is still refused.
    let e = faro_server::cli::admin_grant(&t.state, "new@example.org", false, None)
        .await
        .expect_err("no account");
    assert!(e.to_string().contains("--create"), "{e}");
    assert!(log(&t, &admin_s).await.is_empty());

    let out = faro_server::cli::admin_grant(&t.state, " New@Example.org ", true, Some("Noor"))
        .await
        .expect("created");
    assert!(
        out.starts_with("Created an account for new@example.org (Noor)"),
        "{out}"
    );
    let users = t.get("/admin/api/users", Some(&admin_s)).await;
    let row = users
        .body
        .as_array()
        .expect("array")
        .iter()
        .find(|u| u["email"] == "new@example.org")
        .expect("created")
        .clone();
    assert_eq!(row["display_name"], "Noor");
    assert_eq!(
        row["roles"],
        json!({ "admin": true, "member": true, "ally": false })
    );
    assert_eq!(row["last_login_at_ms"], Value::Null);
    assert_eq!(row["disabled"], false);
    let new = UserId::new(row["id"].as_str().expect("id"));

    // Logged as two entries, from the command line.
    let entries = log(&t, &admin_s).await;
    let mut actions: Vec<&str> = entries
        .iter()
        .map(|e| e["action"].as_str().expect("action"))
        .collect();
    actions.sort_unstable();
    assert_eq!(actions, ["account_created", "admin_granted"]);
    for e in &entries {
        assert_eq!(e["user"]["id"], new.as_str());
        assert_eq!(e["actor"], Value::Null);
        assert_eq!(e["via"], "command_line");
    }

    // The person gets a welcome saying how to sign in, and the usual role
    // notice. The other admin gets the role notice.
    t.notify_now().await;
    let mut m = t.mail_to("new@example.org");
    m.sort_by(|a, b| a.subject.cmp(&b.subject));
    assert_eq!(m.len(), 2, "{m:?}");
    assert_eq!(
        m[0].subject,
        format!("A Faro account was created for you on {name}")
    );
    assert!(
        m[0].text.contains("Faro emails you a sign-in link"),
        "{}",
        m[0].text
    );
    assert!(m[0].text.contains("/signin"), "{}", m[0].text);
    assert_eq!(m[1].subject, format!("You are now an admin of {name}"));
    let m = only_mail(&t, "admin@example.org");
    assert_eq!(m.subject, format!("Noor is now an admin of {name}"));

    // The person signs in with an email link like anyone else, and sets up
    // keys as a member.
    let (id, s) = t.sign_in("new@example.org").await;
    assert_eq!(id, new);
    let me = t.get("/v1/me", Some(&s)).await;
    assert_eq!(me.body["user"]["roles"]["admin"], true);
    assert_eq!(me.body["has_member_keys"], false);
    assert_eq!(
        t.get("/admin/api/overview", Some(&s)).await.status,
        StatusCode::OK
    );
    t.create_member_keys(&id, &s).await;

    // Running it again changes nothing.
    t.mailer.clear();
    let out = faro_server::cli::admin_grant(&t.state, "new@example.org", true, Some("Other"))
        .await
        .expect("no-op");
    assert!(out.contains("already an admin"), "{out}");
    assert!(out.contains("--name was not used"), "{out}");
    assert_eq!(log(&t, &admin_s).await.len(), 2);
    t.notify_now().await;
    assert!(t.mailer.sent().is_empty());

    // An existing account is granted, not created again; the name defaults
    // like a sign-up's.
    let (kim, _) = t.sign_in("kim@example.org").await;
    t.clock.advance_ms(1000);
    let out = faro_server::cli::admin_grant(&t.state, "kim@example.org", true, None)
        .await
        .expect("granted");
    assert!(out.starts_with("kim@example.org is now an admin"), "{out}");
    assert_eq!(log(&t, &admin_s).await[0]["user"]["id"], kim.as_str());
    let out = faro_server::cli::admin_grant(&t.state, "zed@example.org", true, None)
        .await
        .expect("created");
    assert!(out.contains("(zed)"), "{out}");
    let e = faro_server::cli::admin_grant(&t.state, "x@example.org", true, Some("  "))
        .await
        .expect_err("bad name");
    assert!(e.to_string().contains("--name"), "{e}");
}

#[tokio::test]
async fn create_still_refuses_disabled_and_deleting_accounts() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, _) = t.sign_in("sam@example.org").await;
    let (_lee, lee_s) = t.sign_in("lee@example.org").await;
    let r = t
        .post(
            &format!("/admin/api/users/{sam}/disable"),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let e = faro_server::cli::admin_grant(&t.state, "sam@example.org", true, None)
        .await
        .expect_err("disabled");
    assert!(e.to_string().contains("is disabled"), "{e}");
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": "lee@example.org" })),
            Some(&lee_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let e = faro_server::cli::admin_grant(&t.state, "lee@example.org", true, None)
        .await
        .expect_err("deleting");
    assert!(e.to_string().contains("being deleted"), "{e}");
    // Nothing was created or logged, beyond disabling sam.
    let entries = log(&t, &admin_s).await;
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["action"], "account_disabled");
    assert_eq!(count(&t.state, "SELECT COUNT(*) AS n FROM users").await, 3);
}

/// The admin log is kept: retention prunes the emails' delivery rows, never
/// the entries.
#[tokio::test]
async fn retention_keeps_the_admin_log() {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, _) = t.sign_in("kim@example.org").await;
    assert_eq!(
        set_admin(&t, &admin_s, &kim, true).await.status,
        StatusCode::OK
    );
    t.notify_now().await;
    let before = log(&t, &admin_s).await;
    assert_eq!(before.len(), 1);

    // Years pass; retention runs.
    t.clock.advance_ms(5 * 366 * 24 * 3600 * 1000);
    faro_server::retention::run_once(&t.state)
        .await
        .expect("retention");
    assert_eq!(
        count(
            &t.state,
            "SELECT COUNT(*) AS n FROM notifications WHERE admin_log_id IS NOT NULL"
        )
        .await,
        0,
        "delivery rows are pruned"
    );
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    assert_eq!(log(&t, &admin_s).await, before);
}
