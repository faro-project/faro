//! Deleting an account (§12): a 7-day hold during which nothing changes
//! but the notices, a cancel that tells the same people, and a purge that
//! leaves nothing about the person behind, once everyone has been told.

mod common;

use axum::http::{Method, StatusCode};
use common::*;
use faro_crypto::{seal_item, Recipient};
use faro_proto::api::DeviceState;
use faro_proto::report::{ReportHeader, ReportUpload};
use faro_proto::{EventKind, Hash32, Urgency, UserId};
use faro_server::db::repo::deletion::{Clears, EMAIL_COLUMNS, USER_COLUMNS};
use faro_server::deletion;
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet};

const MIN: i64 = 60 * 1000;
const DAY: i64 = 24 * 3600 * 1000;
const HOLD: i64 = 7 * DAY;
const SAM: &str = "sam@example.org";

/// Emails to `to` whose subject contains `needle` (digests included: their
/// lines repeat the subjects).
fn told(t: &TestApp, to: &str, needle: &str) -> usize {
    t.mail_to(to)
        .iter()
        .filter(|m| m.subject.contains(needle) || m.text.contains(needle))
        .count()
}

async fn request_deletion(t: &TestApp, session: &str, email: &str) -> Resp {
    t.call(
        Method::DELETE,
        "/v1/me",
        Some(json!({ "confirm_email": email })),
        Some(session),
    )
    .await
}

async fn cancel(t: &TestApp, session: &str) -> Resp {
    t.post("/v1/me/deletion/cancel", json!({}), Some(session))
        .await
}

/// Send everything queued, immediate and digest.
async fn deliver_all(t: &TestApp) {
    t.notify_now().await;
    t.digest_now().await;
}

async fn purge_pass(t: &TestApp) -> deletion::PurgeSummary {
    deletion::run_once(&t.state).await.expect("purge pass")
}

fn report(t: &TestApp, dev: &TestDevice, member: &UserId, keys: &MemberKeys) -> ReportUpload {
    let mut header = ReportHeader {
        v: 1,
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        period_start_ms: 1_800_000_000_000,
        period_end_ms: 1_800_000_000_000 + DAY,
        first_seq: Some(0),
        last_seq: Some(1),
        body_hash: Hash32::ZERO,
        body_len: 0,
    };
    let body = seal_item(
        b"{\"daily\":\"report\"}",
        &header.body_aad(),
        &[Recipient {
            user_id: member.clone(),
            pubkey: keys.enc.public(),
        }],
    )
    .unwrap();
    header.body_hash = body.body_hash();
    header.body_len = body.ciphertext.len() as u64;
    ReportUpload {
        sig: dev.key.sign(&header),
        header,
        body,
    }
}

/// sam: a member with an active device (events, a report, blobs), a
/// pending device, allies pat and lee, notification preferences, a
/// shorter retention window, an open ally invitation and an unused enroll
/// code; also an ally for jo, whose other ally is kim.
struct World {
    t: TestApp,
    admin_s: String,
    sam: UserId,
    sam_s: String,
    /// sam's second session (signed in to accept jo's invitation).
    sam_other_s: String,
    keys: MemberKeys,
    dev: TestDevice,
    pending: TestDevice,
    code: String,
    invite_token: String,
    pat: Ally,
    lee: Ally,
    jo: UserId,
    jo_s: String,
    kim: Ally,
}

async fn world() -> World {
    let t = TestApp::new().await;
    let (_admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s, keys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&sam, &keys, &sam_s, "pat@elsewhere.net").await;
    let lee = t.link_ally(&sam, &keys, &sam_s, "lee@elsewhere.net").await;
    let (jo, jo_s) = t.sign_in("jo@example.org").await;
    let jo_keys = t.create_member_keys(&jo, &jo_s).await;
    let sam_as_ally = t.link_ally(&jo, &jo_keys, &jo_s, SAM).await;
    let kim = t.link_ally(&jo, &jo_keys, &jo_s, "kim@elsewhere.net").await;

    let evs = vec![
        dev.next_event(EventKind::Flag, Urgency::Urgent),
        dev.next_event(EventKind::Capture, Urgency::None),
    ];
    let r = t.post_events(&dev, &evs).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let r = t
        .device_post(&dev, "/v1/reports", &report(&t, &dev, &sam, &keys))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        t.heartbeat(&dev, DeviceState::Active).await.status,
        StatusCode::OK
    );
    let prefs =
        |member: &UserId| json!({ "member_id": member, "urgent": "immediate", "normal": "digest" });
    for (s, m) in [
        (&sam_s, &sam),
        (&pat.session, &sam),
        (&sam_as_ally.session, &jo),
    ] {
        let r = t
            .call(
                Method::PUT,
                "/v1/me/notification-prefs",
                Some(prefs(m)),
                Some(s),
            )
            .await;
        assert!(r.status.is_success(), "{:?}", r.body);
    }
    let r = t
        .call(
            Method::PUT,
            "/v1/me/retention",
            Some(json!({ "event_header_days": null, "blob_days": 10, "alert_days": null })),
            Some(&sam_s),
        )
        .await;
    assert!(r.status.is_success(), "{:?}", r.body);
    let invite_token = t.invite(&sam_s, "new@elsewhere.net").await;
    let pending_code = t.enroll_code(&sam_s).await;
    let pending = t.enroll(&pending_code, &keys.enc).await;
    // Flush what the setup queued (this takes an hour), then sign in again:
    // deleting needs a recent sign-in.
    t.notify_now().await;
    t.digest_now().await;
    let old_session = sam_s;
    let (_, sam_s) = t.sign_in(SAM).await;
    let _ = old_session;
    // Codes last 10 minutes.
    let code = t.enroll_code(&sam_s).await;
    t.mailer.clear();
    World {
        t,
        admin_s,
        sam,
        sam_s,
        sam_other_s: sam_as_ally.session,
        keys,
        dev,
        pending,
        code,
        invite_token,
        pat,
        lee,
        jo,
        jo_s,
        kim,
    }
}

/// Rows naming `user` in each listed column, and in the email columns.
async fn rows_naming(t: &TestApp, user: &UserId, email: &str) -> BTreeMap<String, i64> {
    let mut out = BTreeMap::new();
    let cols = USER_COLUMNS
        .iter()
        .map(|(t, c, _)| (*t, *c, user.as_str()))
        .chain(EMAIL_COLUMNS.iter().map(|(t, c)| (*t, *c, email)));
    for (table, col, value) in cols {
        // SQL-SAFE (test): table and column names are the crate's own
        // constants; the value is bound.
        let sql = sqlx::AssertSqlSafe(format!(
            "SELECT COUNT(*) AS n FROM {table} WHERE {col} = $1"
        ));
        let n: i64 = sqlx::query(sql)
            .bind(value)
            .fetch_one(t.state.db().pool())
            .await
            .unwrap()
            .try_get("n")
            .unwrap();
        out.insert(format!("{table}.{col}"), n);
    }
    out
}

fn assert_nothing_left(rows: &BTreeMap<String, i64>) {
    let left: Vec<_> = rows.iter().filter(|(_, n)| **n > 0).collect();
    assert!(left.is_empty(), "rows still naming the user: {left:?}");
}

async fn user_exists(t: &TestApp, user: &UserId) -> bool {
    count_with(
        &t.state,
        "SELECT COUNT(*) FROM users WHERE id = $1",
        user.as_str(),
    )
    .await
        == 1
}

async fn tables(t: &TestApp) -> Vec<String> {
    sqlx::query(
        "SELECT name FROM sqlite_master WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%' AND name <> '_sqlx_migrations' ORDER BY name",
    )
    .fetch_all(t.state.db().pool())
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get("name").unwrap())
    .collect()
}

async fn columns_of(t: &TestApp, table: &str) -> Vec<String> {
    sqlx::query("SELECT name FROM pragma_table_info($1) ORDER BY cid")
        .bind(table)
        .fetch_all(t.state.db().pool())
        .await
        .unwrap()
        .iter()
        .map(|r| r.try_get("name").unwrap())
        .collect()
}

/// Every row of every table as text. `null_if` lists columns to show as
/// NULL where they hold `user` (the purge sets exactly those to NULL).
async fn snapshot(t: &TestApp, user: &UserId) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for table in tables(t).await {
        let exprs: Vec<String> = columns_of(t, &table)
            .await
            .into_iter()
            .map(|c| {
                let set_null = USER_COLUMNS
                    .iter()
                    .any(|(tt, cc, k)| *tt == table && *cc == c && *k == Clears::SetNull);
                if set_null {
                    format!("quote(CASE WHEN {c} = $1 THEN NULL ELSE {c} END)")
                } else {
                    format!("quote({c})")
                }
            })
            .collect();
        // SQL-SAFE (test): names come from the schema itself.
        let sql = sqlx::AssertSqlSafe(format!(
            "SELECT {} AS r FROM {table} WHERE $1 = $1",
            exprs.join(" || '|' || ")
        ));
        let rows: BTreeSet<String> = sqlx::query(sql)
            .bind(user.as_str())
            .fetch_all(t.state.db().pool())
            .await
            .unwrap()
            .iter()
            .map(|r| r.try_get("r").unwrap())
            .collect();
        out.insert(table, rows);
    }
    out
}

/// Ids of everything the user owns, for recognising rows about them.
async fn owned_ids(t: &TestApp, user: &UserId) -> Vec<String> {
    let mut ids = vec![user.as_str().to_owned()];
    for sql in [
        "SELECT id FROM devices WHERE owner_user_id = $1",
        "SELECT id FROM alerts WHERE member_id = $1",
        "SELECT id FROM reports WHERE member_id = $1",
        "SELECT id FROM blobs WHERE owner_member_id = $1",
    ] {
        for r in sqlx::query(sql)
            .bind(user.as_str())
            .fetch_all(t.state.db().pool())
            .await
            .unwrap()
        {
            ids.push(r.try_get("id").unwrap());
        }
    }
    ids
}

fn blob_file(t: &TestApp, id: &str) -> std::path::PathBuf {
    t.state
        .config()
        .data_dir
        .join("blobs")
        .join(&id[..2])
        .join(&id[2..4])
        .join(id)
}

#[tokio::test]
async fn requesting_tells_everyone_and_otherwise_changes_nothing() {
    let mut w = world().await;
    let t = &w.t;
    let now = t.clock_ms();
    // The address is compared after normalising.
    let r = request_deletion(t, &w.sam_s, " Sam@Example.ORG").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 2, "members": 1 }));
    assert_eq!(r.body["deletion"]["requested_at_ms"], now);
    assert_eq!(r.body["deletion"]["purge_after_ms"], now + HOLD);
    assert_eq!(
        request_deletion(t, &w.sam_s, SAM).await.error_code(),
        "already_deleting"
    );

    // This session stays (to cancel); every other one ends.
    let me = t.get("/v1/me", Some(&w.sam_s)).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["deletion"]["purge_after_ms"], now + HOLD);
    assert_eq!(
        t.get("/v1/me", Some(&w.sam_other_s)).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A code made before the request can't add a computer now (and stays
    // unused).
    let r = t
        .post(
            "/v1/devices/enroll",
            json!({
                "enroll_code": w.code,
                "sign_pubkey": faro_crypto::SigningKey::generate().public(),
                "platform": "macos",
                "device_name": "Another Mac",
                "client_version": "0.1.0",
            }),
            None,
        )
        .await;
    assert_eq!(r.error_code(), "account_deleting", "{:?}", r.body);
    assert_eq!(
        count(
            &t.state,
            "SELECT COUNT(*) FROM enroll_codes WHERE used_at IS NULL"
        )
        .await,
        1
    );

    deliver_all(t).await;
    let date = faro_server::notify::utc_date(now + HOLD);
    assert_eq!(told(t, SAM, &format!("will be deleted on {date}")), 1);
    for ally in [&w.pat, &w.lee] {
        assert_eq!(
            told(t, &ally.email, "sam is deleting their Faro account"),
            1,
            "{:?}",
            t.mail_to(&ally.email)
        );
    }
    assert_eq!(
        told(
            t,
            "jo@example.org",
            "Your ally sam is deleting their Faro account"
        ),
        1,
        "{:?}",
        t.mail_to("jo@example.org")
    );
    assert_eq!(
        told(t, &w.kim.email, "sam, also an ally for jo, is deleting"),
        1
    );
    // sam is told once, about their own account only.
    assert_eq!(t.mail_to(SAM).len(), 1, "{:?}", t.mail_to(SAM));
    assert!(t.mail_to("admin@example.org").is_empty());

    // Monitoring goes on: the device uploads, allies are alerted, and they
    // can still read sam's feed.
    t.mailer.clear();
    let ev = w.dev.next_event_to(
        EventKind::Flag,
        Urgency::Urgent,
        b"{\"blurred\":true}",
        &[(w.pat.id.clone(), w.pat.keys.enc.public())],
    );
    assert_eq!(t.post_events(&w.dev, &[ev]).await.status, StatusCode::OK);
    assert_eq!(
        t.heartbeat(&w.dev, DeviceState::Active).await.status,
        StatusCode::OK
    );
    t.notify_now().await;
    assert_eq!(t.alert_mail_to(&w.pat.email).len(), 1);
    let feed = t.feed(&w.sam, &w.pat.session).await;
    assert_eq!(feed.status, StatusCode::OK, "{:?}", feed.body);
    assert!(!feed.body["items"].as_array().unwrap().is_empty());
    let blob =
        sqlx::query("SELECT blob_id FROM events WHERE device_id = $1 ORDER BY seq DESC LIMIT 1")
            .bind(w.dev.id.as_str())
            .fetch_one(t.state.db().pool())
            .await
            .unwrap()
            .try_get::<String, _>("blob_id")
            .unwrap();
    assert_eq!(
        t.get(&format!("/v1/blobs/{blob}"), Some(&w.pat.session))
            .await
            .status,
        StatusCode::OK
    );
    // Signing in still works, and says a deletion is pending.
    let (_, again) = t.sign_in(SAM).await;
    let me = t.get("/v1/me", Some(&again)).await;
    assert_eq!(me.body["deletion"]["purge_after_ms"], now + HOLD);

    // What the purge would have to undo is refused.
    let r = t
        .post(
            "/v1/me/invites",
            json!({ "email": "x@elsewhere.net" }),
            Some(&w.sam_s),
        )
        .await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::CONFLICT, "account_deleting")
    );
    let r = t
        .post("/v1/me/enroll-codes", json!({}), Some(&w.sam_s))
        .await;
    assert_eq!(r.error_code(), "account_deleting");
    let r = t.endorse(&w.pending, &w.keys, &w.sam_s).await;
    assert_eq!(r.error_code(), "account_deleting", "{:?}", r.body);
    // sam's open invitation can't be used either.
    assert_eq!(
        t.get(&format!("/v1/invites/{}", w.invite_token), None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let (_, new_s) = t.sign_in("new@elsewhere.net").await;
    let r = t
        .accept(&w.invite_token, &new_s, &AllyKeys::generate())
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{:?}", r.body);
    // Nor can an admin change who can sign in meanwhile.
    for action in ["disable", "enable"] {
        let r = t
            .post(
                &format!("/admin/api/users/{}/{action}", w.sam),
                json!({}),
                Some(&w.admin_s),
            )
            .await;
        assert_eq!(r.error_code(), "account_deleting", "{action}");
    }
    let users = t.get("/admin/api/users", Some(&w.admin_s)).await;
    let row = users
        .body
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["id"] == w.sam.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["deletion_purge_after_ms"], now + HOLD);

    // Nothing was removed.
    let rows = rows_naming(t, &w.sam, SAM).await;
    assert_eq!(rows["devices.owner_user_id"], 2);
    assert_eq!(rows["ally_links.member_id"], 2);
    assert_eq!(rows["ally_links.ally_id"], 1);
    assert!(rows["blobs.owner_member_id"] >= 3);
    let _ = (&w.jo, &w.jo_s);
}

#[tokio::test]
async fn deletion_notices_cannot_be_switched_off() {
    let w = world().await;
    let t = &w.t;
    for (s, member) in [(&w.pat.session, &w.sam), (&w.kim.session, &w.jo)] {
        let r = t
            .call(
                Method::PUT,
                "/v1/me/notification-prefs",
                Some(json!({ "member_id": member, "urgent": "off", "normal": "off" })),
                Some(s),
            )
            .await;
        assert!(r.status.is_success(), "{:?}", r.body);
    }
    let r = request_deletion(t, &w.sam_s, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED);
    t.notify_now().await;
    // Not immediate any more, but floored to the digest.
    assert_eq!(told(t, &w.pat.email, "sam is deleting"), 0);
    t.digest_now().await;
    let d = t.digests_to(&w.pat.email);
    assert_eq!(d.len(), 1, "{:?}", t.mail_to(&w.pat.email));
    assert!(d[0].text.contains("sam is deleting their Faro account"));
    let d = t.digests_to(&w.kim.email);
    assert_eq!(d.len(), 1, "{:?}", t.mail_to(&w.kim.email));
    assert!(d[0].text.contains("sam, also an ally for jo, is deleting"));

    // The same for the cancellation.
    t.mailer.clear();
    assert_eq!(cancel(t, &w.sam_s).await.status, StatusCode::OK);
    deliver_all(t).await;
    assert_eq!(
        told(t, &w.pat.email, "sam cancelled the deletion"),
        1,
        "{:?}",
        t.mail_to(&w.pat.email)
    );
    assert_eq!(
        told(t, &w.kim.email, "sam, also an ally for jo, cancelled"),
        1
    );
}

#[tokio::test]
async fn cancelling_tells_the_same_people_and_keeps_everything() {
    let mut w = world().await;
    let t = &w.t;
    let requested = t.clock_ms();
    assert_eq!(
        request_deletion(t, &w.sam_s, SAM).await.status,
        StatusCode::ACCEPTED
    );
    deliver_all(t).await;
    t.mailer.clear();
    let before = rows_naming(t, &w.sam, SAM).await;

    let r = cancel(t, &w.sam_s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 2, "members": 1 }));
    assert_eq!(r.body["requested_at_ms"], requested);
    let cancelled = r.body["cancelled_at_ms"].as_i64().unwrap();
    assert_eq!(
        t.get("/v1/me", Some(&w.sam_s)).await.body["deletion"],
        Value::Null
    );
    assert_eq!(cancel(t, &w.sam_s).await.error_code(), "not_deleting");

    deliver_all(t).await;
    let (req, can) = (
        faro_server::notify::utc_time(requested),
        faro_server::notify::utc_time(cancelled),
    );
    let own = t
        .mail_to(SAM)
        .into_iter()
        .find(|m| m.text.contains("You cancelled the deletion"))
        .expect("sam is told");
    assert!(
        own.text.contains(&req) && own.text.contains(&can),
        "{}",
        own.text
    );
    for ally in [&w.pat, &w.lee] {
        assert_eq!(told(t, &ally.email, "sam cancelled the deletion"), 1);
    }
    assert_eq!(
        told(t, "jo@example.org", "Your ally sam cancelled the deletion"),
        1
    );
    assert_eq!(
        told(t, &w.kim.email, "sam, also an ally for jo, cancelled"),
        1
    );

    // Nothing is purged, ever, and the computers are never refused. (Only
    // the notices were added.)
    t.clock.advance_ms(HOLD + DAY);
    assert_eq!(purge_pass(t).await, deletion::PurgeSummary::default());
    let content = |rows: BTreeMap<String, i64>| -> BTreeMap<String, i64> {
        rows.into_iter()
            .filter(|(k, _)| !k.starts_with("alerts.") && !k.starts_with("notifications."))
            .collect()
    };
    assert_eq!(content(rows_naming(t, &w.sam, SAM).await), content(before));
    let ev = w.dev.next_event(EventKind::Flag, Urgency::Normal);
    assert_eq!(t.post_events(&w.dev, &[ev]).await.status, StatusCode::OK);
    assert_eq!(
        t.heartbeat(&w.dev, DeviceState::Active).await.status,
        StatusCode::OK
    );
    // What was blocked works again.
    let r = t
        .post("/v1/me/enroll-codes", json!({}), Some(&w.sam_s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    // A later request starts a new hold and a new notice.
    t.mailer.clear();
    let (_, fresh) = t.sign_in(SAM).await;
    let now = t.clock_ms();
    let r = request_deletion(t, &fresh, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["deletion"]["purge_after_ms"], now + HOLD);
    t.notify_now().await;
    let date = faro_server::notify::utc_date(now + HOLD);
    assert_eq!(told(t, SAM, &format!("will be deleted on {date}")), 1);
}

#[tokio::test]
async fn the_purge_waits_for_mail_to_work() {
    let w = world().await;
    let t = &w.t;
    t.mailer.set_failing(true);
    assert_eq!(
        request_deletion(t, &w.sam_s, SAM).await.status,
        StatusCode::ACCEPTED
    );
    deliver_all(t).await;
    t.clock.advance_ms(HOLD + MIN);
    deliver_all(t).await;
    let s = purge_pass(t).await;
    assert_eq!((s.purged, s.waiting), (0, 1));
    assert!(user_exists(t, &w.sam).await);
    // Still monitored while it waits.
    assert_eq!(
        t.heartbeat(&w.dev, DeviceState::Active).await.status,
        StatusCode::OK
    );
    let o = t.get("/admin/api/overview", Some(&w.admin_s)).await;
    assert_eq!(o.body["deletions"], json!({ "pending": 1, "overdue": 0 }));

    let doctor = faro_server::doctor::run(t.state.config(), false).await;
    let c = doctor.get("deletions").expect("doctor checks deletions");
    assert_eq!(c.level, faro_server::doctor::Level::Ok, "{}", c.detail);

    // A week past the hold, the admin is told it is held up, in the console
    // and by `doctor` (which reads the real clock: move the hold back).
    t.clock.advance_ms(HOLD);
    let o = t.get("/admin/api/overview", Some(&w.admin_s)).await;
    assert_eq!(o.body["deletions"], json!({ "pending": 1, "overdue": 1 }));
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let held = sqlx::query("SELECT deletion_purge_after FROM users WHERE id = $1")
        .bind(w.sam.as_str())
        .fetch_one(t.state.db().pool())
        .await
        .unwrap()
        .try_get::<i64, _>("deletion_purge_after")
        .unwrap();
    sqlx::query("UPDATE users SET deletion_purge_after = $1 WHERE id = $2")
        .bind(real_now - HOLD - DAY)
        .bind(w.sam.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();
    let doctor = faro_server::doctor::run(t.state.config(), false).await;
    let c = doctor.get("deletions").unwrap();
    assert_eq!(c.level, faro_server::doctor::Level::Warn, "{}", c.detail);
    assert!(c.detail.contains("1 account deletion"), "{}", c.detail);
    sqlx::query("UPDATE users SET deletion_purge_after = $1 WHERE id = $2")
        .bind(held)
        .bind(w.sam.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();

    // Once mail works the notices go out, and then the purge runs.
    t.mailer.set_failing(false);
    assert_eq!(purge_pass(t).await.purged, 0);
    deliver_all(t).await;
    assert!(told(t, &w.pat.email, "sam is deleting their Faro account") >= 1);
    assert_eq!(purge_pass(t).await.purged, 1);
    assert!(!user_exists(t, &w.sam).await);
    let o = t.get("/admin/api/overview", Some(&w.admin_s)).await;
    assert_eq!(o.body["deletions"], json!({ "pending": 0, "overdue": 0 }));
}

#[tokio::test]
async fn the_purge_leaves_nothing_about_the_person_and_nothing_else_changes() {
    let mut w = world().await;
    let t = &w.t;
    assert_eq!(
        request_deletion(t, &w.sam_s, SAM).await.status,
        StatusCode::ACCEPTED
    );
    deliver_all(t).await;
    // Not before the hold has passed.
    assert_eq!(purge_pass(t).await.purged, 0);
    t.clock.advance_ms(HOLD);

    let ids = owned_ids(t, &w.sam).await;
    let blobs: Vec<String> = sqlx::query("SELECT id FROM blobs WHERE owner_member_id = $1")
        .bind(w.sam.as_str())
        .fetch_all(t.state.db().pool())
        .await
        .unwrap()
        .iter()
        .map(|r| r.try_get("id").unwrap())
        .collect();
    assert!(blobs.len() >= 3, "events and a report");
    assert!(blobs.iter().all(|b| blob_file(t, b).is_file()));
    let before = snapshot(t, &w.sam).await;

    assert_eq!(purge_pass(t).await.purged, 1);

    // Every table is empty for sam, and the files are gone.
    assert!(!user_exists(t, &w.sam).await);
    assert_nothing_left(&rows_naming(t, &w.sam, SAM).await);
    assert!(blobs.iter().all(|b| !blob_file(t, b).exists()));

    // Nobody else's data changed, except the documented NULLs.
    let after = snapshot(t, &w.sam).await;
    for (table, rows) in &after {
        if table == "deleted_device_tokens" {
            continue;
        }
        let was = &before[table];
        let added: Vec<_> = rows.difference(was).collect();
        assert!(added.is_empty(), "{table}: rows changed: {added:?}");
        for gone in was.difference(rows) {
            assert!(
                ids.iter().any(|id| gone.contains(id.as_str())) || gone.contains(SAM),
                "{table}: a row not about sam was deleted: {gone}"
            );
        }
    }

    // sam's computers are refused, from the token alone, and are not
    // reported missing.
    for dev in [&w.dev, &w.pending] {
        let r = t.heartbeat(dev, DeviceState::Active).await;
        assert_eq!(
            (r.status, r.error_code()),
            (StatusCode::FORBIDDEN, "account_deleted")
        );
        let r = t
            .device_call(dev, Method::GET, "/v1/devices/self", b"")
            .await;
        assert_eq!(r.error_code(), "account_deleted");
    }
    let ev = w.dev.next_event(EventKind::Flag, Urgency::Urgent);
    assert_eq!(
        t.post_events(&w.dev, &[ev]).await.error_code(),
        "account_deleted"
    );
    let r = t
        .device_post(&w.dev, "/v1/reports", &report(t, &w.dev, &w.sam, &w.keys))
        .await;
    assert_eq!(r.error_code(), "account_deleted");
    let grace = i64::try_from(t.state.settings().liveness.grace_secs).unwrap() * 1000;
    t.clock.advance_ms(grace * 2);
    let s = faro_server::liveness::run_once(&t.state, t.clock_ms() - grace * 3)
        .await
        .unwrap();
    assert_eq!(s.judged, 0);
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM deleted_device_tokens").await,
        2
    );

    // jo is asked to re-sign without sam, as after a leave.
    let l = t.get("/v1/me/allies", Some(&w.jo_s)).await;
    assert_eq!(l.body["manifest"]["needs_update"], true);
    assert_eq!(l.body["manifest"]["departed"], json!([w.sam]));
    // Tombstones last a year.
    t.clock.advance_ms(366 * DAY);
    faro_server::retention::run_once(&t.state).await.unwrap();
    assert_eq!(
        count(&t.state, "SELECT COUNT(*) FROM deleted_device_tokens").await,
        0
    );
    // The address can sign up again (open registration), as a new account.
    let (again, _) = t.sign_in(SAM).await;
    assert_ne!(again, w.sam);
    let _ = (&w.lee, &w.kim);
}

#[tokio::test]
async fn an_ally_deleting_their_account() {
    let w = world().await;
    let t = &w.t;
    // max invited pat too; pat accepted but max has not approved yet.
    let (_max, max_s) = t.sign_in("max@example.org").await;
    let max_keys = t.create_member_keys(&_max, &max_s).await;
    let token = t.invite(&max_s, &w.pat.email).await;
    let r = t.accept(&token, &w.pat.session, &w.pat.keys).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let (_, pat_s) = t.sign_in(&w.pat.email).await;
    t.mailer.clear();

    let r = request_deletion(t, &pat_s, &w.pat.email).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 0, "members": 1 }));
    deliver_all(t).await;
    assert_eq!(told(t, &w.pat.email, "will be deleted on"), 1);
    assert_eq!(
        told(t, SAM, "Your ally pat is deleting their Faro account"),
        1,
        "{:?}",
        t.mail_to(SAM)
    );
    assert_eq!(
        told(t, &w.lee.email, "pat, also an ally for sam, is deleting"),
        1
    );
    assert!(t.mail_to("max@example.org").is_empty());
    let l = t.get("/v1/me/allies", Some(&w.sam_s)).await;
    let pat_row = l.body["allies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["ally_id"] == w.pat.id.as_str())
        .unwrap()
        .clone();
    assert!(pat_row["deletion_purge_after_ms"].is_i64());

    // max can't approve someone on the way out.
    let r = t
        .approve(&_max, &max_keys, &max_s, &w.pat.id, w.pat.keys.enc.public())
        .await;
    assert_eq!(r.error_code(), "ally_deleting", "{:?}", r.body);
    // pat is still sam's ally during the hold.
    assert_eq!(t.feed(&w.sam, &pat_s).await.status, StatusCode::OK);

    t.clock.advance_ms(HOLD);
    assert_eq!(purge_pass(t).await.purged, 1);
    assert_nothing_left(&rows_naming(t, &w.pat.id, &w.pat.email).await);
    assert_eq!(
        t.feed(&w.sam, &pat_s).await.status,
        StatusCode::UNAUTHORIZED
    );
    // sam's list asks for a manifest without pat, and takes one.
    let l = t.get("/v1/me/allies", Some(&w.sam_s)).await;
    assert_eq!(l.body["manifest"]["needs_update"], true);
    assert_eq!(l.body["manifest"]["departed"], json!([w.pat.id]));
    let latest = t.latest_manifest(&w.sam, &w.sam_s).await.unwrap();
    let next = w
        .keys
        .next_manifest(&latest, |a| a.retain(|(id, _)| *id != w.pat.id));
    assert_eq!(
        t.put_manifest(&w.sam_s, &next).await.status,
        StatusCode::CREATED
    );
    let l = t.get("/v1/me/allies", Some(&w.sam_s)).await;
    assert_eq!(l.body["manifest"]["needs_update"], false);
    // sam's account and devices are untouched.
    assert_eq!(
        t.heartbeat(&w.dev, DeviceState::Active).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn deleting_needs_a_fresh_sign_in_the_address_and_another_admin() {
    let t = TestApp::new().await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let r = t
        .call(
            Method::DELETE,
            "/v1/me",
            Some(json!({ "confirm_email": "admin@example.org" })),
            None,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = request_deletion(&t, &admin_s, "admin@example.org").await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::CONFLICT, "last_admin")
    );

    let (sam, sam_s) = t.sign_in(SAM).await;
    let r = request_deletion(&t, &sam_s, "someone@example.org").await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::BAD_REQUEST, "confirmation_mismatch")
    );
    let r = t
        .call(Method::DELETE, "/v1/me", Some(json!({})), Some(&sam_s))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    t.clock.advance_ms(10 * MIN + 1);
    let r = request_deletion(&t, &sam_s, SAM).await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::FORBIDDEN, "reauth_required")
    );
    let me = t.get("/v1/me", Some(&sam_s)).await;
    assert!(me.body["session_started_at_ms"].as_i64().unwrap() < t.clock_ms() - 10 * MIN);
    let (_, fresh) = t.sign_in(SAM).await;
    let r = request_deletion(&t, &fresh, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    // Cancelling needs only a session, however old.
    t.clock.advance_ms(DAY);
    assert_eq!(cancel(&t, &fresh).await.status, StatusCode::OK);

    // With a second admin, either may leave, but not both.
    sqlx::query("UPDATE users SET is_admin = 1 WHERE id = $1")
        .bind(sam.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();
    let (_, admin_fresh) = t.sign_in("admin@example.org").await;
    let r = request_deletion(&t, &admin_fresh, "admin@example.org").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let (_, sam_fresh) = t.sign_in(SAM).await;
    let r = request_deletion(&t, &sam_fresh, SAM).await;
    assert_eq!(r.error_code(), "last_admin");
    // ... and the one staying can't be disabled either.
    let r = t
        .post(
            &format!("/admin/api/users/{sam}/disable"),
            json!({}),
            Some(&admin_fresh),
        )
        .await;
    assert_eq!(r.error_code(), "last_admin");
    let _ = admin;
}

#[tokio::test]
async fn a_purge_interrupted_halfway_finishes_on_the_next_pass() {
    let w = world().await;
    let t = &w.t;
    assert_eq!(
        request_deletion(t, &w.sam_s, SAM).await.status,
        StatusCode::ACCEPTED
    );
    deliver_all(t).await;
    t.clock.advance_ms(HOLD);
    // Not due yet: nothing happens.
    let (other_id, _) = t.sign_in("other@example.org").await;
    assert!(!deletion::stop_and_purge_content(&t.state, &other_id)
        .await
        .unwrap());

    // The first stages run, then the process "crashes".
    assert!(deletion::stop_and_purge_content(&t.state, &w.sam)
        .await
        .unwrap());
    assert!(user_exists(t, &w.sam).await);
    let rows = rows_naming(t, &w.sam, SAM).await;
    assert_eq!(rows["blobs.owner_member_id"], 0);
    assert_eq!(rows["events.member_id"], 0);
    assert_eq!(
        rows["ally_links.member_id"], 0,
        "removed links are retention's"
    );
    let r = t.heartbeat(&w.dev, DeviceState::Active).await;
    assert_eq!(r.error_code(), "account_deleted");
    // From here on it can't be cancelled.
    assert_eq!(
        cancel(t, &w.sam_s).await.error_code(),
        "deletion_in_progress"
    );
    // Running the first stages again is harmless.
    assert!(deletion::stop_and_purge_content(&t.state, &w.sam)
        .await
        .unwrap());

    assert_eq!(purge_pass(t).await.purged, 1);
    assert!(!user_exists(t, &w.sam).await);
    assert_nothing_left(&rows_naming(t, &w.sam, SAM).await);
}

/// The guard against a future migration adding a reference to `users`
/// that the purge doesn't clear: every foreign key to `users` must be in
/// [`USER_COLUMNS`], and every listed column must exist.
#[tokio::test]
async fn every_reference_to_users_is_purged() {
    let t = TestApp::new().await;
    let fks: BTreeSet<(String, String)> = sqlx::query(
        "SELECT m.name AS t, p.\"from\" AS c
         FROM sqlite_master m JOIN pragma_foreign_key_list(m.name) p
         WHERE m.type = 'table' AND p.\"table\" = 'users'",
    )
    .fetch_all(t.state.db().pool())
    .await
    .unwrap()
    .iter()
    .map(|r| (r.try_get("t").unwrap(), r.try_get("c").unwrap()))
    .collect();
    assert!(fks.len() > 15, "{fks:?}");
    let listed: BTreeSet<(String, String)> = USER_COLUMNS
        .iter()
        .map(|(t, c, _)| ((*t).to_owned(), (*c).to_owned()))
        .collect();
    let missing: Vec<_> = fks.difference(&listed).collect();
    assert!(
        missing.is_empty(),
        "references to users the account-deletion purge does not clear \
         (add them to db::repo::deletion::USER_COLUMNS and PURGE_BY_ID): {missing:?}"
    );
    for (table, col) in listed.iter().chain(
        EMAIL_COLUMNS
            .iter()
            .map(|(t, c)| ((*t).to_owned(), (*c).to_owned()))
            .collect::<Vec<_>>()
            .iter(),
    ) {
        assert!(
            columns_of(&t, table).await.contains(col),
            "{table}.{col} does not exist"
        );
    }
}

// ---- Deletion an admin asks for (#41) -------------------------------------

async fn admin_delete(t: &TestApp, session: &str, user: &UserId, email: &str) -> Resp {
    t.call(
        Method::DELETE,
        &format!("/admin/api/users/{user}"),
        Some(json!({ "confirm_email": email })),
        Some(session),
    )
    .await
}

async fn admin_cancel(t: &TestApp, session: &str, user: &UserId) -> Resp {
    t.post(
        &format!("/admin/api/users/{user}/deletion/cancel"),
        json!({}),
        Some(session),
    )
    .await
}

async fn admin_log(t: &TestApp, session: &str) -> Vec<Value> {
    let r = t.get("/admin/api/log", Some(session)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    r.body.as_array().expect("array").clone()
}

async fn admin_row(t: &TestApp, session: &str, user: &UserId) -> Value {
    let r = t.get("/admin/api/users", Some(session)).await;
    r.body
        .as_array()
        .expect("array")
        .iter()
        .find(|u| u["id"] == user.as_str())
        .expect("listed")
        .clone()
}

async fn make_admin(t: &TestApp, user: &UserId) {
    sqlx::query("UPDATE users SET is_admin = 1 WHERE id = $1")
        .bind(user.as_str())
        .execute(t.state.db().pool())
        .await
        .unwrap();
}

/// Emails to `to` whose subject or text contains `needle` (a digest's
/// text repeats each notice's subject).
fn subjects(t: &TestApp, to: &str, needle: &str) -> Vec<faro_server::mailer::Email> {
    t.mail_to(to)
        .into_iter()
        .filter(|m| m.subject.contains(needle) || m.text.contains(needle))
        .collect()
}

const BY_ADMIN: &str = "being deleted by the instance administrator";

#[tokio::test]
async fn an_admin_deleting_an_account_tells_everyone_who_asked() {
    let w = world().await;
    let t = &w.t;
    let (admin, admin_s) = t.sign_in("admin@example.org").await;
    t.mailer.clear();
    let now = t.clock_ms();

    let r = admin_delete(t, &admin_s, &w.sam, " Sam@Example.ORG").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 2, "members": 1 }));
    assert_eq!(r.body["deletion"]["purge_after_ms"], now + HOLD);
    assert_eq!(r.body["deletion"]["by_admin"], true);
    assert_eq!(
        admin_delete(t, &admin_s, &w.sam, SAM).await.error_code(),
        "already_deleting"
    );

    // sam keeps every session, sees who asked, and can cancel.
    for s in [&w.sam_s, &w.sam_other_s] {
        let me = t.get("/v1/me", Some(s)).await;
        assert_eq!(me.status, StatusCode::OK);
        assert_eq!(me.body["deletion"]["by_admin"], true);
    }
    let row = admin_row(t, &admin_s, &w.sam).await;
    assert_eq!(row["deletion_purge_after_ms"], now + HOLD);
    assert_eq!(row["deletion_by_admin"], true);
    // The hold is the same as when the person asks.
    let r = t
        .post("/v1/me/enroll-codes", json!({}), Some(&w.sam_s))
        .await;
    assert_eq!(r.error_code(), "account_deleting");

    deliver_all(t).await;
    let date = faro_server::notify::utc_date(now + HOLD);
    let own = subjects(t, SAM, BY_ADMIN);
    assert_eq!(own.len(), 1, "{:?}", t.mail_to(SAM));
    assert!(
        own[0].text.contains(&format!("On {date}")),
        "{}",
        own[0].text
    );
    assert!(
        own[0].text.contains("sign in before") && own[0].text.contains("Cancel deletion"),
        "{}",
        own[0].text
    );
    for ally in [&w.pat, &w.lee] {
        let needle = format!("sam's Faro account on Faro is {BY_ADMIN}");
        assert_eq!(
            told(t, &ally.email, &needle),
            1,
            "{:?}",
            t.mail_to(&ally.email)
        );
    }
    let needle = format!("Your ally sam's Faro account is {BY_ADMIN}");
    assert_eq!(
        told(t, "jo@example.org", &needle),
        1,
        "{:?}",
        t.mail_to("jo@example.org")
    );
    let needle = format!("of sam, also an ally for jo, is {BY_ADMIN}");
    assert_eq!(
        told(t, &w.kim.email, &needle),
        1,
        "{:?}",
        t.mail_to(&w.kim.email)
    );
    // Nobody is told sam asked.
    for to in [SAM, &w.pat.email, "jo@example.org", &w.kim.email] {
        assert_eq!(told(t, to, "is deleting their"), 0, "{to}");
        assert_eq!(told(t, to, "You asked"), 0, "{to}");
    }
    // The admin is emailed from the admin log, which says who asked.
    let m = t.mail_to("admin@example.org");
    assert_eq!(m.len(), 1, "{m:?}");
    assert_eq!(m[0].subject, "sam's account on Faro is being deleted");
    assert!(
        m[0].text
            .starts_with("You asked for the Faro account of sam (sam@example.org)"),
        "{}",
        m[0].text
    );
    let log = admin_log(t, &admin_s).await;
    assert_eq!(log[0]["action"], "deletion_requested");
    assert_eq!(log[0]["user"]["id"], w.sam.as_str());
    assert_eq!(log[0]["actor"]["id"], admin.as_str());
    assert_eq!(log[0]["via"], "console");

    // The purge is the same too.
    t.clock.advance_ms(HOLD);
    assert_eq!(purge_pass(t).await.purged, 1);
    assert!(!user_exists(t, &w.sam).await);
    assert_nothing_left(&rows_naming(t, &w.sam, SAM).await);
    let r = t.heartbeat(&w.dev, DeviceState::Active).await;
    assert_eq!(r.error_code(), "account_deleted");
    // The log keeps the entry, without naming sam.
    let log = admin_log(t, &admin_s).await;
    assert_eq!(log[0]["action"], "deletion_requested");
    assert_eq!(log[0]["user"], Value::Null);
    assert_eq!(log[0]["actor"]["id"], admin.as_str());
}

#[tokio::test]
async fn the_person_or_any_admin_can_cancel_and_the_same_people_are_told() {
    let w = world().await;
    let t = &w.t;
    let (admin, admin_s) = t.sign_in("admin@example.org").await;
    let (ann, ann_s) = t.sign_in("ann@example.org").await;
    make_admin(t, &ann).await;
    t.mailer.clear();

    // The person cancels.
    let requested = t.clock_ms();
    let r = admin_delete(t, &admin_s, &w.sam, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    deliver_all(t).await;
    t.mailer.clear();
    let r = cancel(t, &w.sam_s).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 2, "members": 1 }));
    let cancelled = r.body["cancelled_at_ms"].as_i64().unwrap();
    deliver_all(t).await;
    let own = subjects(t, SAM, "You cancelled the deletion");
    assert_eq!(own.len(), 1, "{:?}", t.mail_to(SAM));
    let (req, can) = (
        faro_server::notify::utc_time(requested),
        faro_server::notify::utc_time(cancelled),
    );
    assert!(
        own[0]
            .text
            .contains(&format!("On {req}, the instance administrator asked")),
        "{}",
        own[0].text
    );
    assert!(
        own[0].text.contains(&format!("You cancelled it on {can}")),
        "{}",
        own[0].text
    );
    // (pat and lee get normal alerts in the digest.)
    for ally in [&w.pat, &w.lee] {
        let needle = "The deletion of sam's Faro account was cancelled";
        assert_eq!(
            told(t, &ally.email, needle),
            1,
            "{:?}",
            t.mail_to(&ally.email)
        );
        assert_eq!(told(t, &ally.email, "sam cancelled it on"), 1);
    }
    let needle = "The deletion of your ally sam's Faro account was cancelled";
    assert_eq!(
        told(t, "jo@example.org", needle),
        1,
        "{:?}",
        t.mail_to("jo@example.org")
    );
    assert_eq!(
        told(
            t,
            &w.kim.email,
            "of sam, also an ally for jo, was cancelled"
        ),
        1
    );
    // Both admins hear it from the log.
    for to in ["admin@example.org", "ann@example.org"] {
        let m = subjects(t, to, "The deletion of sam's account");
        assert_eq!(m.len(), 1, "{to}: {:?}", t.mail_to(to));
        assert!(
            m[0].text
                .starts_with("sam (sam@example.org) cancelled the deletion of their Faro account"),
            "{}",
            m[0].text
        );
    }
    let log = admin_log(t, &admin_s).await;
    assert_eq!(log[0]["action"], "deletion_cancelled");
    assert_eq!(log[0]["actor"]["id"], w.sam.as_str());
    assert_eq!(log[0]["user"]["id"], w.sam.as_str());
    let row = admin_row(t, &admin_s, &w.sam).await;
    assert_eq!(row["deletion_by_admin"], false);

    // Another admin cancels (the one who asked could too).
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    let r = admin_delete(t, &admin_s, &w.sam, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    deliver_all(t).await;
    t.mailer.clear();
    let r = admin_cancel(t, &ann_s, &w.sam).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["told"], json!({ "allies": 2, "members": 1 }));
    assert_eq!(
        admin_cancel(t, &ann_s, &w.sam).await.error_code(),
        "not_deleting"
    );
    assert_eq!(
        t.get("/v1/me", Some(&w.sam_s)).await.body["deletion"],
        Value::Null
    );
    deliver_all(t).await;
    let own = subjects(t, SAM, "The deletion of your Faro account");
    assert_eq!(own.len(), 1, "{:?}", t.mail_to(SAM));
    assert!(
        own[0]
            .text
            .contains("The instance administrator cancelled it on"),
        "{}",
        own[0].text
    );
    assert_eq!(
        told(t, &w.pat.email, "The instance administrator cancelled it"),
        1
    );
    let m = subjects(t, "admin@example.org", "was cancelled");
    assert_eq!(m.len(), 1, "{:?}", t.mail_to("admin@example.org"));
    assert!(
        m[0].text
            .starts_with("ann cancelled the deletion of the Faro account of sam"),
        "{}",
        m[0].text
    );
    let log = admin_log(t, &admin_s).await;
    assert_eq!(log[0]["action"], "deletion_cancelled");
    assert_eq!(log[0]["actor"]["id"], ann.as_str());
    assert_eq!(log[1]["action"], "deletion_requested");
    assert_eq!(log[1]["actor"]["id"], admin.as_str());

    // A deletion the person asked for is theirs alone to cancel, and isn't
    // in the admin log.
    let (_, fresh) = t.sign_in(SAM).await;
    assert_eq!(
        request_deletion(t, &fresh, SAM).await.status,
        StatusCode::ACCEPTED
    );
    let r = admin_cancel(t, &admin_s, &w.sam).await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::CONFLICT, "not_admin_deletion")
    );
    let row = admin_row(t, &admin_s, &w.sam).await;
    assert_eq!(row["deletion_by_admin"], false);
    assert_eq!(admin_log(t, &admin_s).await.len(), log.len());

    // Once the purge starts, nobody can cancel.
    assert_eq!(cancel(t, &fresh).await.status, StatusCode::OK);
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    assert_eq!(
        admin_delete(t, &admin_s, &w.sam, SAM).await.status,
        StatusCode::ACCEPTED
    );
    t.clock.advance_ms(HOLD);
    assert!(deletion::stop_and_purge_content(&t.state, &w.sam)
        .await
        .unwrap());
    assert_eq!(
        admin_cancel(t, &admin_s, &w.sam).await.error_code(),
        "deletion_in_progress"
    );
    assert_eq!(cancel(t, &fresh).await.error_code(), "deletion_in_progress");
}

#[tokio::test]
async fn a_disabled_account_can_be_deleted_and_the_person_is_still_told() {
    let w = world().await;
    let t = &w.t;
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    let r = t
        .post(
            &format!("/admin/api/users/{}/disable", w.sam),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    deliver_all(t).await;
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    t.mailer.clear();

    let r = admin_delete(t, &admin_s, &w.sam, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    deliver_all(t).await;
    // sam can't sign in, so the email says who to ask instead.
    let own = subjects(t, SAM, BY_ADMIN);
    assert_eq!(own.len(), 1, "{:?}", t.mail_to(SAM));
    assert!(
        own[0]
            .text
            .contains("Your account is disabled, so you can't sign in"),
        "{}",
        own[0].text
    );
    assert!(!own[0].text.contains("sign in before"), "{}", own[0].text);
    let needle = format!("sam's Faro account on Faro is {BY_ADMIN}");
    assert_eq!(told(t, &w.pat.email, &needle), 1);
    // Still disabled, and it can't be re-enabled meanwhile: the admin
    // cancels instead.
    let r = t
        .post(
            &format!("/admin/api/users/{}/enable", w.sam),
            json!({}),
            Some(&admin_s),
        )
        .await;
    assert_eq!(r.error_code(), "account_deleting");
    let row = admin_row(t, &admin_s, &w.sam).await;
    assert_eq!(row["disabled"], true);
    assert_eq!(row["deletion_by_admin"], true);

    // The cancellation reaches sam too.
    t.mailer.clear();
    assert_eq!(
        admin_cancel(t, &admin_s, &w.sam).await.status,
        StatusCode::OK
    );
    deliver_all(t).await;
    let needle = "The deletion of your Faro account on Faro was cancelled";
    assert_eq!(told(t, SAM, needle), 1, "{:?}", t.mail_to(SAM));
    assert_eq!(admin_row(t, &admin_s, &w.sam).await["disabled"], true);

    // Asked again, the purge goes ahead with sam still disabled.
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    assert_eq!(
        admin_delete(t, &admin_s, &w.sam, SAM).await.status,
        StatusCode::ACCEPTED
    );
    deliver_all(t).await;
    t.clock.advance_ms(HOLD);
    assert_eq!(purge_pass(t).await.purged, 1);
    assert!(!user_exists(t, &w.sam).await);
    assert_nothing_left(&rows_naming(t, &w.sam, SAM).await);
}

#[tokio::test]
async fn admin_deletion_needs_a_fresh_sign_in_the_address_and_another_admin() {
    let t = TestApp::new().await;
    let (admin, admin_s) = t.setup_admin("admin@example.org").await;
    let (sam, sam_s) = t.sign_in(SAM).await;

    // Admins only, and never their own account here.
    let r = admin_delete(&t, &sam_s, &admin, "admin@example.org").await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let r = admin_delete(&t, &admin_s, &admin, "admin@example.org").await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::BAD_REQUEST, "cannot_delete_self")
    );
    let r = admin_delete(&t, &admin_s, &UserId::new("usr_nobody"), SAM).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
    let r = admin_delete(&t, &admin_s, &sam, "admin@example.org").await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::BAD_REQUEST, "confirmation_mismatch")
    );
    let path = format!("/admin/api/users/{sam}");
    let r = t
        .call(Method::DELETE, &path, Some(json!({})), Some(&admin_s))
        .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    t.clock.advance_ms(10 * MIN + 1);
    let r = admin_delete(&t, &admin_s, &sam, SAM).await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::FORBIDDEN, "reauth_required")
    );
    // Cancelling needs only a session.
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    assert_eq!(
        admin_delete(&t, &admin_s, &sam, SAM).await.status,
        StatusCode::ACCEPTED
    );
    t.clock.advance_ms(DAY);
    assert_eq!(
        admin_cancel(&t, &admin_s, &sam).await.status,
        StatusCode::OK
    );
    assert_eq!(admin_log(&t, &admin_s).await.len(), 2);

    // Another admin can be deleted, but never the last one who stays.
    make_admin(&t, &sam).await;
    let (_, admin_s) = t.sign_in("admin@example.org").await;
    let r = request_deletion(&t, &admin_s, "admin@example.org").await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
    let r = admin_delete(&t, &admin_s, &sam, SAM).await;
    assert_eq!(
        (r.status, r.error_code()),
        (StatusCode::CONFLICT, "last_admin")
    );
    assert_eq!(cancel(&t, &admin_s).await.status, StatusCode::OK);
    let r = admin_delete(&t, &admin_s, &sam, SAM).await;
    assert_eq!(r.status, StatusCode::ACCEPTED, "{:?}", r.body);
}
