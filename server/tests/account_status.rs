//! Disabling and re-enabling accounts (§4.3): admins are users like any
//! other, and disabling is never silent. The person, their allies, and the
//! members they are an ally for (with those members' other allies) are told.

mod common;

use axum::http::StatusCode;
use common::*;
use faro_proto::{EventKind, Urgency, UserId};
use serde_json::json;

/// Emails to `to` whose subject contains `needle`.
fn mails(t: &TestApp, to: &str, needle: &str) -> Vec<faro_server::mailer::Email> {
    t.mail_to(to)
        .into_iter()
        .filter(|m| m.subject.contains(needle))
        .collect()
}

async fn set_status(t: &TestApp, admin: &str, user: &UserId, action: &str) -> Resp {
    t.post(
        &format!("/admin/api/users/{user}/{action}"),
        json!({}),
        Some(admin),
    )
    .await
}

/// sam (a member with allies pat and lee) is also an ally for jo, whose
/// other ally is kim.
struct World {
    t: TestApp,
    admin_s: String,
    sam: UserId,
    sam_s: String,
    dev: TestDevice,
    pat: Ally,
    lee: Ally,
    jo: UserId,
    kim: Ally,
}

async fn world() -> World {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s, sam_keys, dev) = t.active_device().await;
    let pat = t
        .link_ally(&sam, &sam_keys, &sam_s, "pat@elsewhere.net")
        .await;
    let lee = t
        .link_ally(&sam, &sam_keys, &sam_s, "lee@elsewhere.net")
        .await;
    let (jo, jo_s) = t.sign_in("jo@example.org").await;
    let jo_keys = t.create_member_keys(&jo, &jo_s).await;
    t.link_ally(&jo, &jo_keys, &jo_s, "sam@example.org").await;
    let kim = t.link_ally(&jo, &jo_keys, &jo_s, "kim@elsewhere.net").await;
    t.mailer.clear();
    World {
        t,
        admin_s,
        sam,
        sam_s,
        dev,
        pat,
        lee,
        jo,
        kim,
    }
}

#[tokio::test]
async fn disabling_tells_the_person_and_every_accountability_partner() {
    let mut w = world().await;
    let t = &w.t;
    let r = set_status(t, &w.admin_s, &w.sam, "disable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["disabled"], true);

    // Signed out everywhere, and can't sign in.
    assert_eq!(
        t.get("/v1/me", Some(&w.sam_s)).await.status,
        StatusCode::UNAUTHORIZED
    );

    t.notify_now().await;

    // sam is told, although disabled, in words.
    let own = mails(t, "sam@example.org", "Your account on");
    assert_eq!(own.len(), 1, "{:?}", t.mail_to("sam@example.org"));
    assert!(own[0].subject.ends_with("was disabled"));
    assert!(own[0].text.contains("can no longer sign in"));
    assert!(own[0].text.contains("still monitored"));
    // ... and only that: not the "your ally" alert raised on jo.
    assert_eq!(t.mail_to("sam@example.org").len(), 1);

    // sam's allies.
    for ally in [&w.pat, &w.lee] {
        let m = mails(t, &ally.email, "sam's account on");
        assert_eq!(m.len(), 1, "{}: {:?}", ally.email, t.mail_to(&ally.email));
        assert!(m[0].text.contains("still receive alerts"));
    }
    // The member sam is an ally for, and that member's other ally.
    let jo_mail = mails(t, "jo@example.org", "Your ally sam's account on");
    assert_eq!(jo_mail.len(), 1, "{:?}", t.mail_to("jo@example.org"));
    assert!(jo_mail[0].text.contains("can no longer sign in"));
    let kim_mail = mails(t, &w.kim.email, "sam's account on");
    assert_eq!(kim_mail.len(), 1, "{:?}", t.mail_to(&w.kim.email));
    assert!(kim_mail[0].text.contains("also an ally for jo"));

    // The admin learns nothing new by email.
    assert!(t.mail_to("admin@example.org").is_empty());

    // Disabling stops sign-in, not monitoring: sam's device still uploads
    // and sam's allies are still alerted.
    t.mailer.clear();
    let ev = w.dev.next_event(EventKind::Flag, Urgency::Urgent);
    let r = t.post_events(&w.dev, &[ev]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    assert_eq!(t.alert_mail_to(&w.pat.email).len(), 1);
    // ... but sam hears nothing else while disabled.
    assert!(t.mail_to("sam@example.org").is_empty());
    let _ = &w.jo;
}

#[tokio::test]
async fn account_status_alerts_cannot_be_switched_off() {
    let w = world().await;
    let t = &w.t;
    // pat turns urgent alerts about sam off entirely.
    let r = t
        .call(
            axum::http::Method::PUT,
            "/v1/me/notification-prefs",
            Some(json!({ "member_id": w.sam, "urgent": "off", "normal": "off" })),
            Some(&w.pat.session),
        )
        .await;
    assert!(r.status.is_success(), "{:?}", r.body);
    set_status(t, &w.admin_s, &w.sam, "disable").await;
    t.notify_now().await;
    // Not immediate any more, but floored to the digest, never dropped.
    assert!(mails(t, &w.pat.email, "sam's account on").is_empty());
    t.digest_now().await;
    let d = t.digests_to(&w.pat.email);
    assert_eq!(d.len(), 1, "{:?}", t.mail_to(&w.pat.email));
    assert!(d[0].text.contains("sam's account on"), "{}", d[0].text);
}

#[tokio::test]
async fn re_enabling_tells_the_same_people() {
    let w = world().await;
    let t = &w.t;
    set_status(t, &w.admin_s, &w.sam, "disable").await;
    t.notify_now().await;
    t.mailer.clear();

    let r = set_status(t, &w.admin_s, &w.sam, "enable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["disabled"], false);
    // Normal urgency: allies get it in their digest by default; sam (the
    // member) too. Run the digest to collect everything.
    t.notify_now().await;
    t.digest_now().await;
    let text = |to: &str| {
        t.mail_to(to)
            .iter()
            .map(|m| format!("{}\n{}", m.subject, m.text))
            .collect::<String>()
    };
    assert!(text("sam@example.org").contains("Your account on"));
    assert!(text("sam@example.org").contains("re-enabled"));
    assert!(text(&w.pat.email).contains("sam's account on"));
    assert!(text(&w.lee.email).contains("re-enabled"));
    assert!(text("jo@example.org").contains("Your ally sam's account on"));
    assert!(text(&w.kim.email).contains("sam's account on"));
    // sam can sign in again.
    let (_, s) = t.sign_in("sam@example.org").await;
    assert_eq!(t.get("/v1/me", Some(&s)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admins_are_users_too_but_never_disable_themselves() {
    let t = TestApp::new().await;
    let (a1, a1_s) = t.setup_admin("admin@example.org").await;
    // A second admin (there is no API for granting the role yet).
    let (a2, a2_s) = t.sign_in("second@example.org").await;
    sqlx::query("UPDATE users SET is_admin = 1 WHERE id = $1")
        .bind(a2.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();

    // Nobody disables their own account.
    let r = set_status(&t, &a1_s, &a1, "disable").await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.error_code(), "cannot_disable_self");

    // One admin can disable another, who is told like anyone else.
    t.mailer.clear();
    let r = set_status(&t, &a2_s, &a1, "disable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    assert_eq!(mails(&t, "admin@example.org", "Your account on").len(), 1);
    assert_eq!(
        t.get("/admin/api/users", Some(&a1_s)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Repeats are refused rather than notifying again.
    let r = set_status(&t, &a2_s, &a1, "disable").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "already_disabled");
    let r = set_status(&t, &a2_s, &a2, "enable").await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "not_disabled");

    // Unknown accounts.
    let r = set_status(&t, &a2_s, &UserId::new("usr_nobody"), "disable").await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn only_admins_can_change_account_status() {
    let t = TestApp::new().await;
    let (admin, _admin_s) = t.setup_admin("admin@example.org").await;
    let (member, ms) = t.sign_in("sam@example.org").await;
    for target in [&admin, &member] {
        for action in ["disable", "enable"] {
            let r = set_status(&t, &ms, target, action).await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{action}");
            let r = t
                .post(
                    &format!("/admin/api/users/{target}/{action}"),
                    json!({}),
                    None,
                )
                .await;
            assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{action}");
        }
    }
}

/// Make `user` an admin, as `admin` does in the console.
async fn grant_admin(t: &TestApp, admin: &str, user: &UserId) {
    let r = t
        .call(
            axum::http::Method::PUT,
            &format!("/admin/api/users/{user}/admin"),
            Some(json!({ "admin": true })),
            Some(admin),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
}

async fn admin_log(t: &TestApp, session: &str) -> Vec<serde_json::Value> {
    let r = t.get("/admin/api/log", Some(session)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body.as_array().expect("array").clone()
}

#[tokio::test]
async fn disabling_and_enabling_are_logged_and_told_to_the_other_admins() {
    let t = TestApp::new().await;
    let name = t.state.config().instance.name.clone();
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (kim, kim_s) = t.sign_in("kim@example.org").await;
    let (lee, _lee_s) = t.sign_in("lee@example.org").await;
    let (sam, _sam_s) = t.sign_in("sam@example.org").await;
    grant_admin(&t, &admin_s, &kim).await;
    grant_admin(&t, &admin_s, &lee).await;
    t.notify_now().await;
    t.mailer.clear();
    t.clock.advance_ms(1000);

    // Admin disables sam: kim and lee are told at once, in words; Admin,
    // who did it, is not.
    let r = set_status(&t, &admin_s, &sam, "disable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    for to in ["kim@example.org", "lee@example.org"] {
        let m = mails(&t, to, "sam's account on");
        assert_eq!(m.len(), 1, "{to}: {:?}", t.mail_to(to));
        assert_eq!(
            m[0].subject,
            format!("sam's account on {name} was disabled")
        );
        assert!(
            m[0].text
                .starts_with("Admin disabled the Faro account of sam (sam@example.org)"),
            "{}",
            m[0].text
        );
        assert!(m[0].text.contains("keep reporting"), "{}", m[0].text);
        assert!(m[0].text.contains("/admin/people"), "{}", m[0].text);
    }
    assert!(t.mail_to("admin@example.org").is_empty());
    // sam hears only their own notice, not the admin log.
    let sam_mail = t.mail_to("sam@example.org");
    assert_eq!(sam_mail.len(), 1, "{sam_mail:?}");
    assert!(sam_mail[0].subject.starts_with("Your account on"));

    let entries = admin_log(&t, &kim_s).await;
    assert_eq!(entries[0]["action"], "account_disabled");
    assert_eq!(entries[0]["user"]["id"], sam.as_str());
    assert_eq!(entries[0]["actor"]["id"], admin.as_str());
    assert_eq!(entries[0]["via"], "console");
    let n = entries.len();

    // Refusals are not logged.
    let r = set_status(&t, &admin_s, &sam, "disable").await;
    assert_eq!(r.error_code(), "already_disabled");
    let r = set_status(&t, &admin_s, &admin, "disable").await;
    assert_eq!(r.error_code(), "cannot_disable_self");
    assert_eq!(admin_log(&t, &kim_s).await.len(), n);

    // kim disables lee, an admin: admin is told; lee, now disabled, only
    // hears their own notice; kim, who did it, nothing.
    t.mailer.clear();
    t.clock.advance_ms(1000);
    let r = set_status(&t, &kim_s, &lee, "disable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    let m = mails(&t, "admin@example.org", "lee's account on");
    assert_eq!(m.len(), 1, "{:?}", t.mail_to("admin@example.org"));
    assert!(
        m[0].text
            .starts_with("kim disabled the Faro account of lee (lee@example.org)"),
        "{}",
        m[0].text
    );
    assert!(t.mail_to("kim@example.org").is_empty());
    let lee_mail = t.mail_to("lee@example.org");
    assert_eq!(lee_mail.len(), 1, "{lee_mail:?}");
    assert!(lee_mail[0].subject.starts_with("Your account on"));

    // kim re-enables sam: admin is told at once (lee is disabled).
    t.mailer.clear();
    t.clock.advance_ms(1000);
    let r = set_status(&t, &kim_s, &sam, "enable").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    t.notify_now().await;
    let m = mails(&t, "admin@example.org", "sam's account on");
    assert_eq!(m.len(), 1, "{:?}", t.mail_to("admin@example.org"));
    assert_eq!(
        m[0].subject,
        format!("sam's account on {name} was re-enabled")
    );
    assert!(
        m[0].text
            .starts_with("kim re-enabled the Faro account of sam (sam@example.org)"),
        "{}",
        m[0].text
    );
    assert!(t.mail_to("kim@example.org").is_empty());
    assert!(t.mail_to("lee@example.org").is_empty());

    let entries = admin_log(&t, &admin_s).await;
    assert_eq!(entries.len(), n + 2, "{entries:?}");
    assert_eq!(entries[0]["action"], "account_enabled");
    assert_eq!(entries[0]["user"]["id"], sam.as_str());
    assert_eq!(entries[0]["actor"]["id"], kim.as_str());
    assert_eq!(entries[1]["action"], "account_disabled");
    assert_eq!(entries[1]["user"]["id"], lee.as_str());
    assert_eq!(entries[1]["actor"]["id"], kim.as_str());

    // Mail is only sent once.
    t.mailer.clear();
    t.notify_now().await;
    assert!(t.mail_to("admin@example.org").is_empty());
}
