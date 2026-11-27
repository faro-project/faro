//! A group of 1,000 participants (docs/GROUPS.md §10.5, §19 "Scale"): the
//! signed roster's paging, a snapshot that fits the 8 MiB cap, the
//! participants list's paging, whole-group posting that costs one envelope,
//! no whole-group reach out, and the notifier sending one meeting reminder
//! to everyone. Timings are printed (`cargo test --test group_scale --
//! --nocapture`) and bounded loosely: the point is that nothing grows
//! faster than the group.

mod common;

use axum::http::StatusCode;
use common::roster::{entry, pending, roster, sealed_for};
use common::*;
use faro_crypto::roster::{apply_entry, verify_snapshot};
use faro_crypto::{seal_group_message_to_epoch, EncryptionKeypair, SigningKey};
use faro_proto::group::{GroupMessage, GroupMessageKind};
use faro_proto::keys::Signed;
use faro_proto::roster::{RosterChange, MAX_ROSTER_SNAPSHOT_BYTES};
use faro_proto::{Hash32, UserId};
use faro_server::meetings;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Instant;

const PEOPLE: usize = 1000;
const HOUR: i64 = 3600 * 1000;
const DAY: i64 = 24 * HOUR;

struct Fac {
    id: UserId,
    s: String,
    keys: MemberKeys,
}

/// `n` active participants with real public keys, as the instance holds
/// them for members (their private halves are never needed here).
async fn seed(t: &TestApp, gid: &str, n: usize) -> Vec<UserId> {
    let now = t.clock_ms();
    let pool = t.state.db().pool();
    let mut tx = pool.begin().await.unwrap();
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!("usr_scale{i:05}");
        let sign = SigningKey::generate().public();
        let enc = EncryptionKeypair::generate().public();
        sqlx::query(
            "INSERT INTO users (id, email, display_name, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&id)
        .bind(format!("scale{i}@example.org"))
        .bind(format!("Person {i}"))
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO member_keys (user_id, sign_pubkey, enc_pubkey, enc_binding_json,
                                      wrapped_sign_key, wrapped_enc_key, recovery_wrapped,
                                      created_at, updated_at)
             VALUES ($1, $2, $3, '{}', '{}', '{}', '{}', $4, $4)",
        )
        .bind(&id)
        .bind(sign.to_b64())
        .bind(enc.to_b64())
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO group_participants (id, group_id, user_id, role, state, joined_via, joined_at)
             VALUES ($1, $2, $3, 'participant', 'active', 'invite', $4)",
        )
        .bind(format!("0scale{i:05}"))
        .bind(gid)
        .bind(&id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        ids.push(UserId::new(id));
    }
    tx.commit().await.unwrap();
    ids
}

/// A facilitator's client signing everything pending: first the creator,
/// then a hundred one-person entries (so the log needs two pages), then the
/// rest in entries of 256 changes (the most one entry may carry). Returns
/// the last epoch's key.
async fn sign_everything(t: &TestApp, gid: &str, f: &Fac) -> (u64, [u8; 32]) {
    let mut last = None;
    let mut entries = 0;
    loop {
        let p = pending(t, gid, &f.s).await;
        let mut changes: Vec<RosterChange> = serde_json::from_value(p["changes"].clone()).unwrap();
        if changes.is_empty() {
            break;
        }
        let state = roster(t, gid, &f.s).await;
        let take = if state.next_seq == 0 {
            // The first entry is the creator's, alone.
            changes.retain(|c| c.user_id() == &f.id);
            1
        } else if state.next_seq <= 100 {
            1
        } else {
            256
        };
        changes.truncate(take);
        let (e, key) = entry(t, &state, &f.id, changes);
        let signed = f.keys.sign.endorse(e);
        let sealed = key.map(|k| sealed_for(&state, &signed, &k)).unwrap();
        let r = t
            .post(
                &format!("/v1/groups/{gid}/roster"),
                json!({ "entry": signed, "epoch_keys": sealed }),
                Some(&f.s),
            )
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        last = Some((signed.body.epoch.unwrap().epoch, key.unwrap()));
        entries += 1;
        assert!(entries < 200);
    }
    last.expect("signed something")
}

async fn meeting_in(t: &TestApp, gid: &str, f: &Fac, ahead_ms: i64) -> i64 {
    let start = (t.clock_ms() + ahead_ms).div_euclid(60_000) * 60_000 + 60_000;
    let local_day = start.div_euclid(DAY);
    let weekday = (local_day + 3).rem_euclid(7);
    let minute = (start - local_day * DAY) / 60_000;
    let r = t
        .call(
            axum::http::Method::PATCH,
            &format!("/v1/groups/{gid}"),
            Some(
                json!({ "meeting": { "cadence": "weekly", "weekday": weekday,
                                       "minute_of_day": minute, "tz_offset_min": 0 } }),
            ),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["next_meeting_at_ms"], start);
    start
}

async fn make_group(t: &TestApp, f: &Fac, name: &str) -> String {
    let r = t
        .post("/v1/groups", json!({ "name": name }), Some(&f.s))
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    r.body["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_group_of_a_thousand() {
    let t = TestApp::new().await;
    let (id, s) = t.sign_in("fay@example.org").await;
    let keys = t.create_member_keys(&id, &s).await;
    let f = Fac { id, s, keys };
    let gid = make_group(&t, &f, "Big").await;
    seed(&t, &gid, PEOPLE).await;

    // ---- The signed roster -------------------------------------------------
    let started = Instant::now();
    let (epoch, key) = sign_everything(&t, &gid, &f).await;
    eprintln!("scale: signed the roster in {:?}", started.elapsed());

    // The log pages 100 entries at a time; a client replays all of it and
    // ends with the same roster of 1,001 people.
    let first = t.get(&format!("/v1/groups/{gid}/roster"), Some(&f.s)).await;
    assert_eq!(first.body["entries"].as_array().unwrap().len(), 100);
    assert_eq!(first.body["more"], true);
    let started = Instant::now();
    let state = roster(&t, &gid, &f.s).await;
    eprintln!(
        "scale: fetched and verified {} log entries in {:?}",
        state.next_seq,
        started.elapsed()
    );
    assert!(state.next_seq > 100, "the log needs more than one page");
    assert_eq!(state.members.len(), PEOPLE + 1);
    assert_eq!(state.epoch, epoch);
    let last_page = t
        .get(&format!("/v1/groups/{gid}/roster?after_seq=99"), Some(&f.s))
        .await;
    assert_eq!(last_page.body["more"], false);
    assert_eq!(pending(&t, &gid, &f.s).await["posting_paused"], false);

    // A snapshot at the head: far inside the 8 MiB cap clients enforce, and
    // it replaces the whole log for a new joiner.
    let snap = f
        .keys
        .sign
        .endorse(state.snapshot(t.clock_ms(), f.id.clone()).unwrap());
    let size = serde_json::to_vec(&snap).unwrap().len();
    eprintln!(
        "scale: snapshot of {} people is {size} bytes ({:.1}% of the {MAX_ROSTER_SNAPSHOT_BYTES}-byte cap)",
        state.members.len(),
        100.0 * size as f64 / MAX_ROSTER_SNAPSHOT_BYTES as f64
    );
    assert!(size < MAX_ROSTER_SNAPSHOT_BYTES / 10);
    let r = t
        .post(
            &format!("/v1/groups/{gid}/roster/snapshot"),
            serde_json::to_value(&snap).unwrap(),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let started = Instant::now();
    let r = t
        .get(&format!("/v1/groups/{gid}/roster/snapshot"), Some(&f.s))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    let back: Signed<faro_proto::roster::RosterSnapshot> = serde_json::from_value(r.body).unwrap();
    assert_eq!(verify_snapshot(&back).unwrap(), state);
    eprintln!(
        "scale: snapshot fetched and verified in {:?}",
        started.elapsed()
    );
    // Snapshot plus the entries after it are what a joiner needs.
    let mut from_snapshot = verify_snapshot(&back).unwrap();
    let after = t
        .get(
            &format!("/v1/groups/{gid}/roster?after_seq={}", state.next_seq - 1),
            Some(&f.s),
        )
        .await;
    for e in after.body["entries"].as_array().unwrap() {
        apply_entry(
            &mut from_snapshot,
            &serde_json::from_value(e.clone()).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(from_snapshot, state);

    // The participants list pages 100 at a time with no gaps or repeats.
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/groups/{gid}/participants?cursor={}", urlenc(c)),
            None => format!("/v1/groups/{gid}/participants"),
        };
        let r = t.get(&path, Some(&f.s)).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let items = r.body["items"].as_array().unwrap();
        assert!(items.len() <= 100);
        for i in items {
            assert!(seen.insert(i["user_id"].as_str().unwrap().to_owned()));
        }
        pages += 1;
        match r.body["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
    }
    assert_eq!((seen.len(), pages), (PEOPLE + 1, 11));

    // ---- Posting to the whole group: one envelope -----------------------------
    let mut h = GroupMessage {
        instance_id: t.instance_id(),
        group_id: Some(gid.clone()),
        item_id: hex::encode(faro_crypto::random_bytes::<16>()),
        kind: GroupMessageKind::CheckIn,
        author_id: f.id.clone(),
        issued_at_ms: t.clock_ms(),
        recipients: vec![],
        body_hash: Hash32::ZERO,
        epoch: Some(epoch),
        parent_id: None,
    };
    h.epoch = Some(epoch);
    let m = seal_group_message_to_epoch(&f.keys.sign, &key, h, Some(br#"{"scale":4}"#)).unwrap();
    assert_eq!(m.body.as_ref().unwrap().envelopes.len(), 1);
    let r = t
        .post(
            &format!("/v1/groups/{gid}/posts"),
            json!({ "audience": "group", "message": m }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let stored: String =
        sqlx::query_scalar("SELECT COALESCE(body_json, '') || message_json FROM group_posts")
            .fetch_one(t.state.db().pool())
            .await
            .unwrap();
    assert!(stored.len() < 2000, "a check-in costs the same at any size");
    // ... but an urgent reach out to a thousand people isn't offered.
    let r = t
        .post(
            "/v1/me/reach-outs",
            json!({ "audience": "group", "group_id": gid }),
            Some(&f.s),
        )
        .await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.error_code(), "group_too_large");

    // ---- One meeting reminder ---------------------------------------------------
    // In a group this size, email is off unless a person turns it on: the
    // reminder is an in-app notice for everyone and costs no mail.
    let start = meeting_in(&t, &gid, &f, 5 * HOUR).await;
    t.clock.advance_ms(start - 2 * HOUR - t.clock_ms());
    t.mailer.clear();
    let started = Instant::now();
    let n = meetings::run_once(&t.state).await.unwrap().notices;
    let wrote = started.elapsed();
    assert_eq!(n, (PEOPLE + 1) as u64);
    let started = Instant::now();
    drain_notifier(&t, 0).await;
    eprintln!(
        "scale: reminder to {n} people: notices written in {wrote:?}, notifier drained in {:?}, \
         {} emails (email is off by default above 32)",
        started.elapsed(),
        t.mailer.sent().len()
    );
    assert!(t.mailer.sent().is_empty());
    assert!(wrote.as_secs() < 60);

    // Everyone who turned email on: the notifier sends a thousand emails.
    sqlx::query(
        "INSERT INTO group_meeting_prefs (group_id, user_id, reminders, email)
         SELECT $1, user_id, 1, 1 FROM group_participants WHERE group_id = $1",
    )
    .bind(&gid)
    .execute(t.state.db().pool())
    .await
    .unwrap();
    t.clock.advance_ms(7 * DAY);
    t.mailer.clear();
    let started = Instant::now();
    let n = meetings::run_once(&t.state).await.unwrap().notices;
    let wrote = started.elapsed();
    assert_eq!(n, (PEOPLE + 1) as u64);
    let started = Instant::now();
    drain_notifier(&t, PEOPLE + 1).await;
    let sent = started.elapsed();
    let mails = t.mailer.sent();
    let per_s = mails.len() as f64 / sent.as_secs_f64();
    eprintln!(
        "scale: reminder with email on for {n} people: notices in {wrote:?}, {} emails sent in \
         {sent:?} ({per_s:.0} a second)",
        mails.len()
    );
    assert_eq!(mails.len(), PEOPLE + 1);
    assert!(
        mails.iter().all(|m| !m.text.contains("Big")),
        "never names the group"
    );
    assert!(sent.as_secs() < 120);
}

fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Run the notifier until it has nothing due. With `expect_mail`, until
/// that many emails were sent.
async fn drain_notifier(t: &TestApp, expect_mail: usize) {
    for _ in 0..200 {
        faro_server::notify::dispatch(&t.state).await.unwrap();
        faro_server::notify::send_immediate(&t.state).await.unwrap();
        if t.mailer.sent().len() >= expect_mail {
            let due: Value = json!(
                count(
                    &t.state,
                    "SELECT COUNT(*) FROM notifications WHERE status = 'pending'"
                )
                .await
            );
            if due == 0 {
                return;
            }
        }
    }
    panic!("the notifier didn't finish");
}
