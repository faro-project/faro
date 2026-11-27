//! The feed carries what a reader needs to check it without trusting the
//! instance (PROTOCOL.md §3.5): each event's and report's device-signed
//! header and signature, the member-signed endorsement of each device, and
//! `GET /v1/ally/chain` for the headers in between.

mod common;

use axum::http::StatusCode;
use common::*;
use faro_crypto::{seal_item, verify_item, verify_signed, Recipient};
use faro_proto::api::FeedItem;
use faro_proto::report::{ReportHeader, ReportUpload};
use faro_proto::{genesis_hash, EventKind, Hash32, Urgency};
use faro_server::api::feed::{ChainResponse, FeedResponse};

const FLAG: &[u8] = b"{\"type\":\"flag\"}";

fn ok<T: serde::de::DeserializeOwned>(r: &Resp) -> T {
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    serde_json::from_value(r.body.clone()).unwrap()
}

#[tokio::test]
async fn feed_items_carry_signed_headers_and_endorsements() {
    let t = TestApp::new().await;
    let (member, ms, mkeys, mut dev) = t.active_device().await;
    let pat = t.link_ally(&member, &mkeys, &ms, "pat@elsewhere.net").await;
    let to_pat = [(pat.id.clone(), pat.keys.enc.public())];

    // seq 0: urgent flag (in the feed); 1: boot (urgency none, not in the
    // feed); 2: tamper (in the feed).
    let e0 = dev.next_event_to(EventKind::Flag, Urgency::Urgent, FLAG, &to_pat);
    let e1 = dev.next_event(EventKind::Boot, Urgency::None);
    let e2 = dev.next_event_to(EventKind::Tamper, Urgency::None, FLAG, &to_pat);
    let r = t
        .post_events(&dev, &[e0.clone(), e1.clone(), e2.clone()])
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    // A daily report over the same events.
    let mut rh = ReportHeader {
        v: 1,
        instance_id: t.instance_id(),
        member_id: member.clone(),
        device_id: dev.id.clone(),
        period_start_ms: 1_800_000_000_000,
        period_end_ms: 1_800_000_000_000 + 24 * 3600 * 1000,
        first_seq: Some(0),
        last_seq: Some(2),
        body_hash: Hash32::ZERO,
        body_len: 0,
    };
    let body = seal_item(
        b"{}",
        &rh.body_aad(),
        &[Recipient {
            user_id: member.clone(),
            pubkey: mkeys.enc.public(),
        }],
    )
    .unwrap();
    rh.body_hash = body.body_hash();
    rh.body_len = body.ciphertext.len() as u64;
    let up = ReportUpload {
        sig: dev.key.sign(&rh),
        header: rh.clone(),
        body,
    };
    let r = t.device_post(&dev, "/v1/reports", &up).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    let f: FeedResponse = ok(&t.feed(&member, &pat.session).await);

    // The endorsement is the member's, for this device and key.
    let e = &f.device_endorsements[dev.id.as_str()];
    verify_signed(&mkeys.sign.public(), e).unwrap();
    assert_eq!(e.body.device_id, dev.id);
    assert_eq!(e.body.member_id, member);
    assert_eq!(e.body.device_sign_pubkey, dev.key.public());

    // Every event and report carries the header the device signed.
    let pk = e.body.device_sign_pubkey;
    let mut seqs = Vec::new();
    let mut reports = 0;
    for entry in &f.items {
        match &entry.item {
            FeedItem::Event {
                seq,
                urgency,
                header,
                sig,
                ..
            } => {
                let (h, sig) = (header.as_deref().unwrap(), sig.unwrap());
                verify_item(&pk, h, &sig).unwrap();
                assert_eq!(h.seq, *seq);
                // The tamper event was signed `none`: the feed shows the
                // floor, the header what the device said.
                if h.kind == EventKind::Tamper {
                    assert_eq!((h.urgency, *urgency), (Urgency::None, Urgency::Urgent));
                }
                let want = [&e0, &e1, &e2][*seq as usize];
                assert_eq!(h, &want.header);
                seqs.push(*seq);
            }
            FeedItem::Report { header, sig, .. } => {
                let (h, sig) = (header.as_deref().unwrap(), sig.unwrap());
                verify_item(&pk, h, &sig).unwrap();
                assert_eq!(h, &rh);
                reports += 1;
            }
            FeedItem::Alert { .. } => {}
        }
    }
    seqs.sort_unstable();
    assert_eq!(seqs, [0, 2], "the boot (urgency none) isn't in the feed");
    assert_eq!(reports, 1);

    // The JSON shape the browser reads.
    let raw = t.feed(&member, &pat.session).await.body;
    let ev = raw["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["type"] == "event")
        .unwrap();
    assert!(ev["header"]["prev_hash"]
        .as_str()
        .unwrap()
        .starts_with("b3:"));
    assert_eq!(ev["sig"].as_str().unwrap().len(), 86);
    assert!(raw["device_endorsements"][dev.id.as_str()]["sig"].is_string());

    // The chain has every header, the boot included, linked.
    let path = format!(
        "/v1/ally/chain?member_id={member}&device_id={}",
        dev.id.as_str()
    );
    let c: ChainResponse = ok(&t.get(&path, Some(&pat.session)).await);
    assert!(!c.has_more);
    let hs: Vec<_> = c.links.iter().map(|l| &l.header).collect();
    assert_eq!(hs, [&e0.header, &e1.header, &e2.header]);
    assert_eq!(hs[0].prev_hash, genesis_hash(&t.instance_id(), &dev.id));
    for w in hs.windows(2) {
        assert_eq!(w[1].prev_hash, w[0].chain_hash());
    }
    for l in &c.links {
        verify_item(&pk, &l.header, &l.sig).unwrap();
    }
    // The member reads the same chain.
    let mine: ChainResponse = ok(&t.get(&path, Some(&ms)).await);
    assert_eq!(mine.links, c.links);

    // Paging by seq.
    let p: ChainResponse = ok(&t
        .get(&format!("{path}&from_seq=1&limit=1"), Some(&pat.session))
        .await);
    assert_eq!(p.links.len(), 1);
    assert_eq!(p.links[0].header.seq, 1);
    assert!(p.has_more);

    // Nobody else reads it, and a device of someone else's gives nothing.
    let (_, eve) = t.sign_in("eve@example.org").await;
    assert_eq!(t.get(&path, Some(&eve)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(t.get(&path, None).await.status, StatusCode::UNAUTHORIZED);
    let other: ChainResponse = ok(&t
        .get(
            &format!("/v1/ally/chain?member_id={}&device_id={}", pat.id, dev.id),
            Some(&pat.session),
        )
        .await);
    assert!(other.links.is_empty());
}

#[test]
fn a_feed_item_from_an_older_instance_still_parses() {
    let old = serde_json::json!({
        "type": "event", "member_id": "usr_a", "device_id": "dev_a", "seq": 3,
        "ts_ms": 1, "kind": "flag", "urgency": "urgent", "blob_id": null
    });
    let FeedItem::Event { header, sig, .. } = serde_json::from_value(old).unwrap() else {
        panic!("an event");
    };
    assert!(header.is_none() && sig.is_none());
}
