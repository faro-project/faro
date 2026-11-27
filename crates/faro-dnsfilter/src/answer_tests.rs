//! Upstream answers: alias targets (CNAME, DNAME, SVCB and HTTPS), the
//! session's forwarding (ids, truncated answers over TCP, failover,
//! timeouts) and fragmented replies.
//!
//! Fragments are reassembled here by [`reassemble`], written apart from
//! the builder, and the reassembled datagram's checksums checked with the
//! tests' own byte-wise sum.

use crate::dns::{self, qtype, DnsError};
use crate::packet::{self, build_udp, build_udp_fragments, parse_udp, BuildError};
use crate::session::{Skipped, Step, MAX_PENDING, MAX_UPSTREAMS, TCP_TIMEOUT_MS, UDP_TIMEOUT_MS};
use crate::tests::{categorizer, query};
use crate::*;
use faro_detect::Category;
use std::net::{IpAddr, SocketAddr};

const T0: i64 = 1_800_000_000_000;
const CLIENT: &str = "10.0.0.2:53000";
const UPSTREAM: &str = "192.168.1.1:53";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// A name in wire form, uncompressed.
fn wire(name: &str) -> Vec<u8> {
    let mut w = vec![];
    for l in name.split('.').filter(|l| !l.is_empty()) {
        w.push(l.len() as u8);
        w.extend_from_slice(l.as_bytes());
    }
    w.push(0);
    w
}

/// One record: owner (wire form, possibly a pointer), type, rdata.
fn rr(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut r = owner.to_vec();
    r.extend_from_slice(&rtype.to_be_bytes());
    r.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(rdata);
    r
}

/// The response to `q` (a DNS query message) with these answer records:
/// `QR`, `RD` and `RA` set, the question copied.
fn response(q: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
    let parsed = dns::parse_query(q).unwrap();
    let mut m = q[..2].to_vec();
    m.extend_from_slice(&[0x81, 0x80, 0, 1]);
    m.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(parsed.question_bytes());
    for a in answers {
        m.extend_from_slice(a);
    }
    m
}

/// A query for `name`, id 0x7777, as a message.
fn ask(name: &str) -> Vec<u8> {
    let labels: Vec<&[u8]> = name.split('.').map(str::as_bytes).collect();
    query(0x0100, 1, &labels)
}

const A: &[u8] = &[93, 184, 216, 34];
/// A pointer to the question's name (offset 12).
const PTR_Q: &[u8] = &[0xc0, 0x0c];

fn engine(config: FilterConfig) -> Engine {
    Engine::new(Filter::new(categorizer(), &config).unwrap())
}

fn check(e: &mut Engine, asked: &str, answer: &[u8]) -> AnswerCheck {
    let m = ask(asked);
    let q = dns::parse_query(&m).unwrap();
    e.check_answer(&q.name, answer, T0, true)
}

// ---- answer_targets and Engine::check_answer ----

#[test]
fn a_plain_answer_passes_and_counts_nothing() {
    let mut e = engine(FilterConfig::default());
    let q = ask("www.wikipedia.org");
    let a = response(&q, &[rr(PTR_Q, qtype::A, A)]);
    assert_eq!(check(&mut e, "www.wikipedia.org", &a), AnswerCheck::Pass);
    // An allowed chain passes too.
    let a = response(
        &q,
        &[
            rr(PTR_Q, qtype::CNAME, &wire("dyna.wikimedia.org")),
            rr(&wire("dyna.wikimedia.org"), qtype::A, A),
        ],
    );
    assert_eq!(check(&mut e, "www.wikipedia.org", &a), AnswerCheck::Pass);
    // No records, NXDOMAIN, NODATA: nothing to point anywhere.
    let mut nx = response(&q, &[]);
    nx[3] |= 3;
    assert_eq!(check(&mut e, "www.wikipedia.org", &nx), AnswerCheck::Pass);
    assert!(e.counters().is_empty());
}

#[test]
fn a_blocked_cname_target_is_blocked_and_counted_as_the_target() {
    let mut e = engine(FilterConfig::default());
    let q = ask("innocent.test");
    let a = response(
        &q,
        &[
            rr(PTR_Q, qtype::CNAME, &wire("cdn.porn.test")),
            rr(&wire("cdn.porn.test"), qtype::A, A),
        ],
    );
    let AnswerCheck::Blocked { category, burst } = check(&mut e, "innocent.test", &a) else {
        panic!("not blocked");
    };
    assert_eq!(category, BlockCategory::Bundle(Category::Adult));
    assert!(burst.is_none());
    let s = e.counters().summaries();
    assert_eq!(s[0].by_category["adult"], 1);
    assert_eq!(s[0].hosts.len(), 1);
    assert_eq!(s[0].hosts[0].host, "cdn.porn.test");
    let json = serde_json::to_string(e.counters()).unwrap();
    assert!(!json.contains("innocent"), "{json}");
}

#[test]
fn every_link_of_a_chain_is_checked() {
    let mut e = engine(FilterConfig::default());
    let q = ask("a.test");
    // a.test → b.test → c.xxx → d.test: the third link is adult.
    let a = response(
        &q,
        &[
            rr(PTR_Q, qtype::CNAME, &wire("b.test")),
            rr(&wire("b.test"), qtype::CNAME, &wire("c.xxx")),
            rr(&wire("c.xxx"), qtype::CNAME, &wire("d.test")),
            rr(&wire("d.test"), qtype::A, A),
        ],
    );
    assert!(matches!(
        check(&mut e, "a.test", &a),
        AnswerCheck::Blocked { .. }
    ));
    assert_eq!(e.counters().summaries()[0].hosts[0].host, "c.xxx");
}

#[test]
fn always_blocked_and_member_listed_targets() {
    let mut e = engine(FilterConfig {
        block: vec!["news.test".into()],
        ..Default::default()
    });
    let q = ask("innocent.test");
    for (target, cat) in [
        ("mask.icloud.com", BlockCategory::PrivateRelay),
        ("x.dns.google", BlockCategory::EncryptedDns),
        ("www.news.test", BlockCategory::MemberList),
    ] {
        let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire(target))]);
        assert_eq!(
            check(&mut e, "innocent.test", &a),
            AnswerCheck::Blocked {
                category: cat,
                burst: None
            },
            "{target}"
        );
    }
}

#[test]
fn dname_svcb_and_https_targets() {
    let mut e = engine(FilterConfig::default());
    let q = ask("x.innocent.test");
    let blocked = |e: &mut Engine, a: &[u8]| {
        matches!(check(e, "x.innocent.test", a), AnswerCheck::Blocked { .. })
    };
    let a = response(
        &q,
        &[rr(&wire("innocent.test"), qtype::DNAME, &wire("porn.test"))],
    );
    assert!(blocked(&mut e, &a));
    // HTTPS in AliasMode (priority 0) and ServiceMode, with parameters
    // after the target.
    for prio in [0u8, 1] {
        let mut rdata = vec![0, prio];
        rdata.extend(wire("svc.porn.test"));
        rdata.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'2']); // alpn=h2
        for t in [qtype::HTTPS, qtype::SVCB] {
            let a = response(&q, &[rr(PTR_Q, t, &rdata)]);
            assert!(blocked(&mut e, &a), "type {t} priority {prio}");
        }
    }
    // "." as the target means the owner: nothing new to check.
    let a = response(&q, &[rr(PTR_Q, qtype::HTTPS, &[0, 1, 0, 0, 1, 0, 0])]);
    assert_eq!(check(&mut e, "x.innocent.test", &a), AnswerCheck::Pass);
    // Other types carry no target, whatever their data looks like.
    let a = response(&q, &[rr(PTR_Q, 16, &wire("porn.test"))]); // TXT
    assert_eq!(check(&mut e, "x.innocent.test", &a), AnswerCheck::Pass);
}

#[test]
fn compressed_targets_are_followed_backwards() {
    let mut e = engine(FilterConfig::default());
    // Ask an allowed name that shares a suffix with a blocked one, and
    // compress the target onto it. The question www.a.test is at offset
    // 12: `3 www` at 12, `1 a` at 16, `4 test` at 18, the zero at 23.
    let q = ask("www.a.test");
    // Target "porn" + pointer to "test" at offset 20 → porn.test.
    let mut target = vec![4, b'p', b'o', b'r', b'n', 0xc0, 18];
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &target)]);
    let AnswerCheck::Blocked { .. } = check(&mut e, "www.a.test", &a) else {
        panic!("compressed target not followed");
    };
    // Uppercase in a target is lowercased.
    target[1] = b'P';
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &target)]);
    assert!(matches!(
        check(&mut e, "www.a.test", &a),
        AnswerCheck::Blocked { .. }
    ));
    // A pointer to an allowed name passes: "cdn" + pointer to "a.test".
    let a = response(
        &q,
        &[rr(PTR_Q, qtype::CNAME, &[3, b'c', b'd', b'n', 0xc0, 16])],
    );
    assert_eq!(check(&mut e, "www.a.test", &a), AnswerCheck::Pass);
}

#[test]
fn unreadable_answers_are_refused() {
    let mut e = engine(FilterConfig::default());
    let q = ask("www.a.test");
    let unreadable = |e: &mut Engine, a: &[u8]| match check(e, "www.a.test", a) {
        AnswerCheck::Unreadable(err) => err,
        other => panic!("{other:?}"),
    };
    let base = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire("b.test"))]);
    // Every truncation of the answer records.
    for cut in q.len()..base.len() {
        assert!(
            matches!(
                check(&mut e, "www.a.test", &base[..cut]),
                AnswerCheck::Unreadable(_)
            ),
            "cut at {cut}"
        );
    }
    // A pointer to itself, forward, and into the same run (a loop).
    let at = base.len() - wire("b.test").len();
    for ptr in [at as u8, (at + 2) as u8, 0xff] {
        let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &[0xc0, ptr])]);
        assert_eq!(unreadable(&mut e, &a), DnsError::BadPointer, "{ptr}");
    }
    let looped = response(&q, &[rr(PTR_Q, qtype::CNAME, &[1, b'x', 0xc0, at as u8])]);
    assert_eq!(unreadable(&mut e, &looped), DnsError::BadPointer);
    // Data longer or shorter than the name.
    let mut long = wire("b.test");
    long.push(0);
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &long)]);
    assert_eq!(unreadable(&mut e, &a), DnsError::BadRecord);
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire("b.test")[..3])]);
    assert_eq!(unreadable(&mut e, &a), DnsError::Truncated);
    // A target with bytes no host name has, and a short SVCB record.
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire("sp ace.test"))]);
    assert!(matches!(unreadable(&mut e, &a), DnsError::LabelByte(b' ')));
    let a = response(&q, &[rr(PTR_Q, qtype::HTTPS, &[0])]);
    assert_eq!(unreadable(&mut e, &a), DnsError::BadRecord);
    // A query is not an answer.
    assert_eq!(unreadable(&mut e, &q), DnsError::NotAResponse);
    assert!(e.counters().is_empty());
}

#[test]
fn the_instance_host_is_never_refused() {
    let mut e = engine(FilterConfig {
        instance_host: Some("faro.example.org".into()),
        ..Default::default()
    });
    let q = ask("faro.example.org");
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire("porn.test"))]);
    assert_eq!(check(&mut e, "faro.example.org", &a), AnswerCheck::Pass);
    assert_eq!(check(&mut e, "faro.example.org", &q), AnswerCheck::Pass);
    // Its subdomains are checked like any name.
    let q = ask("x.faro.example.org");
    let a = response(&q, &[rr(PTR_Q, qtype::CNAME, &wire("porn.test"))]);
    assert!(matches!(
        check(&mut e, "x.faro.example.org", &a),
        AnswerCheck::Blocked { .. }
    ));
}

// ---- fragments ----

/// Put fragments back together, independently of the builder: check each
/// is a well-formed fragment of one datagram no larger than `mtu`, then
/// return the datagram as one unfragmented packet.
pub(crate) fn reassemble(frags: &[Vec<u8>], mtu: usize) -> Vec<u8> {
    assert!(!frags.is_empty());
    if frags.len() == 1 {
        assert!(frags[0].len() <= mtu);
        return frags[0].clone();
    }
    let v6 = frags[0][0] >> 4 == 6;
    let mut data = vec![];
    let mut ident = None;
    for (i, f) in frags.iter().enumerate() {
        assert!(f.len() <= mtu, "fragment {i} is {} bytes", f.len());
        let last = i == frags.len() - 1;
        let (offset, more, id, body) = if v6 {
            assert_eq!(f[6], 44, "next header: fragment");
            assert_eq!(usize::from(u16::from_be_bytes([f[4], f[5]])), f.len() - 40);
            assert_eq!(f[40], 17, "fragment's next header: UDP");
            let field = u16::from_be_bytes([f[42], f[43]]);
            let id = u32::from_be_bytes([f[44], f[45], f[46], f[47]]);
            (usize::from(field >> 3) * 8, field & 1 == 1, id, &f[48..])
        } else {
            assert_eq!(f[0], 0x45);
            assert_eq!(usize::from(u16::from_be_bytes([f[2], f[3]])), f.len());
            assert_eq!(naive_sum(&[&f[..20]]), 0xffff, "IPv4 header checksum");
            let field = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(field & 0x4000, 0, "no DF on a fragment");
            let id = u32::from(u16::from_be_bytes([f[4], f[5]]));
            (
                usize::from(field & 0x1fff) * 8,
                field & 0x2000 != 0,
                id,
                &f[20..],
            )
        };
        assert_eq!(offset, data.len(), "fragment {i} out of place");
        assert_eq!(more, !last, "MF/M flag of fragment {i}");
        if !last {
            assert_eq!(body.len() % 8, 0);
        }
        assert_eq!(*ident.get_or_insert(id), id, "one identification");
        data.extend_from_slice(body);
    }
    // Rebuild as one packet from the first fragment's addresses.
    let f = &frags[0];
    let mut p;
    if v6 {
        p = f[..40].to_vec();
        p[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
        p[6] = 17;
    } else {
        p = f[..20].to_vec();
        p[2..4].copy_from_slice(&((20 + data.len()) as u16).to_be_bytes());
        // As an atomic datagram: no id, DF, a fresh header checksum.
        p[4..8].copy_from_slice(&[0, 0, 0x40, 0]);
        p[10..12].copy_from_slice(&[0, 0]);
        let sum = !naive_sum(&[&p]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
    }
    p.extend_from_slice(&data);
    p
}

fn naive_sum(parts: &[&[u8]]) -> u16 {
    let mut s: u64 = 0;
    for part in parts {
        for (i, b) in part.iter().enumerate() {
            s += if i % 2 == 0 {
                u64::from(*b) << 8
            } else {
                u64::from(*b)
            };
        }
    }
    while s > 0xffff {
        s = (s >> 16) + (s & 0xffff);
    }
    s as u16
}

/// The UDP checksum of an unfragmented packet sums to 0xffff.
fn udp_ok(p: &[u8]) -> bool {
    if p[0] >> 4 == 4 {
        let udp = &p[20..];
        let len = (udp.len() as u16).to_be_bytes();
        let pseudo = [&p[12..20], &[0, 17], &len[..]].concat();
        naive_sum(&[&pseudo, udp]) == 0xffff
    } else {
        let udp = &p[40..];
        let len = (udp.len() as u32).to_be_bytes();
        let pseudo = [&p[8..40], &len[..], &[0, 0, 0, 17]].concat();
        naive_sum(&[&pseudo, udp]) == 0xffff
    }
}

#[test]
fn fragments_reassemble_to_the_datagram() {
    let pairs = [
        (addr("198.18.0.53:53"), addr(CLIENT)),
        (addr("[2001:2::53]:53"), addr("[2001:2::1]:5353")),
    ];
    for (src, dst) in pairs {
        for len in [0usize, 100, 1400, 1472, 1473, 1500, 3000, 4096, 9000, 65507] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            for mtu in [1280usize, 1500, 9000] {
                let frags = build_udp_fragments(src, dst, &payload, mtu, 0x1234_5678).unwrap();
                let whole = build_udp(src, dst, &payload);
                let Ok(whole) = whole else {
                    assert_eq!(whole, Err(BuildError::TooLarge));
                    continue;
                };
                if whole.len() <= mtu {
                    assert_eq!(frags, vec![whole], "fits: one packet as build_udp makes it");
                    continue;
                }
                assert!(frags.len() > 1);
                let p = reassemble(&frags, mtu);
                assert!(udp_ok(&p), "{src} {len} {mtu}");
                let d = parse_udp(&p).unwrap();
                assert_eq!((d.src, d.dst), (src, dst));
                assert_eq!(d.payload, &payload[..]);
            }
        }
    }
}

#[test]
fn fragment_limits() {
    let v4 = (addr("198.18.0.53:53"), addr(CLIENT));
    let v6 = (addr("[2001:2::53]:53"), addr("[2001:2::1]:5353"));
    let big = vec![0u8; 3000];
    assert_eq!(
        build_udp_fragments(v4.0, v4.1, &big, 575, 1),
        Err(BuildError::MtuTooSmall)
    );
    assert_eq!(
        build_udp_fragments(v6.0, v6.1, &big, 1279, 1),
        Err(BuildError::MtuTooSmall)
    );
    // A small datagram never needs the MTU check.
    assert_eq!(
        build_udp_fragments(v4.0, v4.1, &[1, 2], 100, 1)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        build_udp_fragments(v4.0, v6.1, &[], 1500, 1),
        Err(BuildError::MixedFamilies)
    );
    assert_eq!(
        build_udp_fragments(v4.0, v4.1, &vec![0; packet::MAX_PAYLOAD_V4 + 1], 1500, 1),
        Err(BuildError::TooLarge)
    );
    // IPv4 carries the low 16 bits of the identification.
    let f = build_udp_fragments(v4.0, v4.1, &big, 1500, 0xabcd_1234).unwrap();
    assert_eq!(&f[0][4..6], &[0x12, 0x34]);
}

// ---- the session ----

fn session(config: FilterConfig) -> Session {
    let mut s = Session::new(engine(config), 42);
    s.set_upstreams([addr(UPSTREAM)]);
    s
}

/// The client's query for `name` as a packet to the tunnel.
fn packet_for(name: &str) -> Vec<u8> {
    build_udp(addr(CLIENT), addr("198.18.0.53:53"), &ask(name)).unwrap()
}

/// Send `name` through the session; return the upstream id and payload.
fn forward(s: &mut Session, name: &str, now: i64) -> (u16, Vec<u8>) {
    match s.packet(&packet_for(name), now, true) {
        Step::Send { server, payload } => {
            assert_eq!(Some(server), s.preferred_upstream());
            (u16::from_be_bytes([payload[0], payload[1]]), payload)
        }
        other => panic!("not forwarded: {other:?}"),
    }
}

/// The answer to an upstream payload, with these records.
fn upstream_answer(payload: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
    response(payload, answers)
}

fn single_reply(step: Step) -> Vec<u8> {
    match step {
        Step::Reply(mut p) if p.len() == 1 => p.remove(0),
        other => panic!("not one reply: {other:?}"),
    }
}

fn rcode(reply: &[u8]) -> u8 {
    reply[28 + 3] & 0x0f
}

#[test]
fn forwarded_queries_get_ids_of_their_own_and_answers_get_theirs_back() {
    let mut s = session(FilterConfig::default());
    let (id, payload) = forward(&mut s, "www.wikipedia.org", T0);
    let asked = ask("www.wikipedia.org");
    assert_eq!(&payload[2..], &asked[2..], "only the id changes");
    let answer = upstream_answer(&payload, &[rr(PTR_Q, qtype::A, A)]);
    let reply = single_reply(s.answer(addr(UPSTREAM), &answer, false, T0 + 5, true));
    let d = parse_udp(&reply).unwrap();
    assert_eq!((d.src, d.dst), (addr("198.18.0.53:53"), addr(CLIENT)));
    assert_eq!(&d.payload[..2], &asked[..2], "the client's id");
    assert_eq!(&d.payload[2..], &answer[2..]);
    assert!(udp_ok(&reply));
    assert_eq!(s.pending(), 0);
    // A second copy of the answer is no longer expected.
    assert_eq!(
        s.answer(addr(UPSTREAM), &answer, false, T0 + 6, true),
        Step::Nothing(Skipped::NotPending)
    );
    let _ = id;
}

#[test]
fn two_clients_with_the_same_id_get_their_own_answers() {
    let mut s = session(FilterConfig::default());
    let (id1, p1) = forward(&mut s, "one.test", T0);
    let (id2, p2) = forward(&mut s, "two.test", T0);
    assert_ne!(id1, id2);
    // Answered in the other order, each goes back with its own question
    // and the id the client used.
    for (p, name) in [(p2, "two.test"), (p1, "one.test")] {
        let r = single_reply(s.answer(addr(UPSTREAM), &upstream_answer(&p, &[]), false, T0, true));
        let back = parse_udp(&r).unwrap().payload;
        assert_eq!(back, &response(&ask(name), &[])[..]);
    }
}

#[test]
fn stray_and_forged_answers_are_ignored() {
    let mut s = session(FilterConfig::default());
    let (id, payload) = forward(&mut s, "www.a.test", T0);
    let good = upstream_answer(&payload, &[rr(PTR_Q, qtype::A, A)]);
    let skip = |s: &mut Session, from: &str, a: &[u8]| s.answer(addr(from), a, false, T0, true);
    assert_eq!(
        skip(&mut s, "192.168.1.2:53", &good),
        Step::Nothing(Skipped::WrongServer)
    );
    let mut other_id = good.clone();
    other_id[0] ^= 0xff;
    assert_eq!(
        skip(&mut s, UPSTREAM, &other_id),
        Step::Nothing(Skipped::NotPending)
    );
    let other_q = upstream_answer(
        &{
            let mut q = ask("www.b.test");
            q[..2].copy_from_slice(&id.to_be_bytes());
            q
        },
        &[],
    );
    assert_eq!(
        skip(&mut s, UPSTREAM, &other_q),
        Step::Nothing(Skipped::WrongQuestion)
    );
    // The case of the question must match too (DNS 0x20).
    let mut upper = good.clone();
    upper[13] = b'W';
    assert_eq!(
        skip(&mut s, UPSTREAM, &upper),
        Step::Nothing(Skipped::WrongQuestion)
    );
    assert_eq!(
        skip(&mut s, UPSTREAM, &payload),
        Step::Nothing(Skipped::NotPending)
    );
    assert_eq!(
        skip(&mut s, UPSTREAM, &good[..1]),
        Step::Nothing(Skipped::NotPending)
    );
    assert_eq!(s.pending(), 1, "still waiting for the real answer");
    assert!(matches!(skip(&mut s, UPSTREAM, &good), Step::Reply(_)));
}

#[test]
fn a_blocked_alias_gets_nxdomain_and_an_unreadable_answer_servfail() {
    let mut s = session(FilterConfig::default());
    let (_, payload) = forward(&mut s, "innocent.test", T0);
    let a = upstream_answer(&payload, &[rr(PTR_Q, qtype::CNAME, &wire("x.porn.test"))]);
    let reply = single_reply(s.answer(addr(UPSTREAM), &a, false, T0, true));
    // Exactly the NXDOMAIN a blocked name gets.
    let direct = parse_packet(&packet_for("innocent.test"))
        .unwrap()
        .nxdomain_packet()
        .unwrap();
    assert_eq!(reply, direct);
    assert_eq!(rcode(&reply), 3);
    assert_eq!(
        s.engine().counters().summaries()[0].hosts[0].host,
        "x.porn.test"
    );

    let (_, payload) = forward(&mut s, "innocent.test", T0);
    let a = upstream_answer(&payload, &[rr(PTR_Q, qtype::CNAME, &[0xc0, 0xff])]);
    let reply = single_reply(s.answer(addr(UPSTREAM), &a, false, T0, true));
    assert_eq!(rcode(&reply), 2);
    assert_eq!(&reply[28..30], &[0x77, 0x77]);
}

#[test]
fn a_truncated_answer_is_fetched_again_over_tcp() {
    let mut s = session(FilterConfig::default());
    let (id, payload) = forward(&mut s, "big.test", T0);
    let mut tc = upstream_answer(&payload, &[]);
    tc[2] |= 0x02;
    let Step::SendTcp {
        server,
        id: tcp_id,
        payload: again,
    } = s.answer(addr(UPSTREAM), &tc, false, T0, true)
    else {
        panic!("not retried over TCP");
    };
    assert_eq!((server, tcp_id, &again), (addr(UPSTREAM), id, &payload));
    // The truncated copy again, over UDP, is ignored while TCP runs.
    assert_eq!(
        s.answer(addr(UPSTREAM), &tc, false, T0, true),
        Step::Nothing(Skipped::AwaitingTcp)
    );
    // The whole answer: 60 A records, larger than the tunnel's MTU.
    let records: Vec<Vec<u8>> = (0..60)
        .map(|i| {
            rr(
                PTR_Q,
                16,
                &[vec![30u8], vec![b'a' + (i % 26) as u8; 30]].concat(),
            )
        })
        .collect();
    let full = upstream_answer(&payload, &records);
    assert!(full.len() > tunnel::MTU);
    let Step::Reply(frags) = s.answer(addr(UPSTREAM), &full, true, T0 + TCP_TIMEOUT_MS - 1, true)
    else {
        panic!("no reply");
    };
    assert!(frags.len() > 1);
    let p = reassemble(&frags, tunnel::MTU);
    assert!(udp_ok(&p));
    let d = parse_udp(&p).unwrap();
    assert_eq!(&d.payload[..2], &[0x77, 0x77]);
    assert_eq!(&d.payload[2..], &full[2..]);
    assert_eq!(s.pending(), 0);
}

#[test]
fn a_failed_fetch_gets_servfail() {
    let mut s = session(FilterConfig::default());
    let (id, payload) = forward(&mut s, "big.test", T0);
    let mut tc = upstream_answer(&payload, &[]);
    tc[2] |= 0x02;
    assert!(matches!(
        s.answer(addr(UPSTREAM), &tc, false, T0, true),
        Step::SendTcp { .. }
    ));
    let reply = single_reply(s.failed(id, T0 + 1));
    assert_eq!(rcode(&reply), 2);
    assert_eq!(s.failed(id, T0 + 2), Step::Nothing(Skipped::NotPending));
}

#[test]
fn without_an_upstream_allowed_names_fail_fast_and_blocked_ones_still_get_nxdomain() {
    let mut s = Session::new(engine(FilterConfig::default()), 1);
    let reply = single_reply(s.packet(&packet_for("www.a.test"), T0, true));
    assert_eq!(rcode(&reply), 2);
    let reply = single_reply(s.packet(&packet_for("porn.test"), T0, true));
    assert_eq!(rcode(&reply), 3);
    assert_eq!(s.pending(), 0);
}

#[test]
fn upstreams_are_checked() {
    let mut s = Session::new(engine(FilterConfig::default()), 1);
    let kept = s
        .set_upstreams(
            [
                "198.18.0.53:53",
                "[2001:2::53]:53",
                "198.18.0.1:53",
                "0.0.0.0:53",
                "127.0.0.1:53",
                "[::1]:53",
                "224.0.0.251:53",
                "255.255.255.255:53",
                "192.168.1.1:0",
                "192.168.1.1:53",
                "[::ffff:192.168.1.1]:53",
                "[fe80::1%4]:53",
                "8.8.8.8:53",
            ]
            .map(addr),
        )
        .to_vec();
    assert_eq!(
        kept,
        vec![
            addr("192.168.1.1:53"),
            addr("[fe80::1%4]:53"),
            addr("8.8.8.8:53")
        ]
    );
    let many: Vec<SocketAddr> = (1..=20).map(|i| addr(&format!("10.0.0.{i}:53"))).collect();
    assert_eq!(s.set_upstreams(many).len(), MAX_UPSTREAMS);
    assert!(s.set_upstreams([]).is_empty());
    assert!(tunnel::is_own_addr(IpAddr::V4(tunnel::DNS_V4)));
}

#[test]
fn overdue_queries_are_given_up_and_the_next_resolver_preferred() {
    let mut s = session(FilterConfig::default());
    s.set_upstreams([addr(UPSTREAM), addr("192.168.1.2:53")]);
    let (_, p) = forward(&mut s, "a.test", T0);
    assert_eq!(s.preferred_upstream(), Some(addr(UPSTREAM)));
    // Still in time.
    assert_eq!(s.expire(T0 + UDP_TIMEOUT_MS), 0);
    assert_eq!(s.expire(T0 + UDP_TIMEOUT_MS + 1), 1);
    assert_eq!(s.preferred_upstream(), Some(addr("192.168.1.2:53")));
    // Its answer is too late.
    let a = upstream_answer(&p, &[]);
    assert_eq!(
        s.answer(addr(UPSTREAM), &a, false, T0 + UDP_TIMEOUT_MS + 2, true),
        Step::Nothing(Skipped::NotPending)
    );
    // The next query goes to the new preferred one; a clock set back far
    // counts as time passing.
    match s.packet(&packet_for("b.test"), T0, true) {
        Step::Send { server, .. } => assert_eq!(server, addr("192.168.1.2:53")),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.expire(T0 - UDP_TIMEOUT_MS - 1), 1);
}

#[test]
fn queries_in_flight_are_bounded() {
    let mut s = session(FilterConfig::default());
    let mut ids = std::collections::HashSet::new();
    for i in 0..MAX_PENDING + 10 {
        let (id, _) = forward(&mut s, &format!("h{i}.test"), T0 + i as i64 / 1000);
        ids.insert(id);
        assert!(s.pending() <= MAX_PENDING);
    }
    assert_eq!(s.pending(), MAX_PENDING);
    assert!(ids.len() >= MAX_PENDING, "ids in flight are never reused");
    // A query larger than any real one is answered, not held.
    let mut big = ask("big.test");
    big.resize(session::MAX_QUERY + 1, 0);
    let p = build_udp(addr(CLIENT), addr("198.18.0.53:53"), &big).unwrap();
    let reply = single_reply(s.packet(&p, T0, true));
    assert_eq!(rcode(&reply), 2);
    big.truncate(session::MAX_QUERY);
    let p = build_udp(addr(CLIENT), addr("198.18.0.53:53"), &big).unwrap();
    assert!(matches!(s.packet(&p, T0, true), Step::Send { .. }));
}

#[test]
fn the_session_shows_no_query_in_its_debug_output() {
    let mut s = session(FilterConfig::default());
    let (_, payload) = forward(&mut s, "secretmarker.test", T0);
    let shown = format!("{s:?}");
    assert!(!shown.contains("secretmarker"), "{shown}");
    let step = Step::Send {
        server: addr(UPSTREAM),
        payload,
    };
    assert!(!format!("{step:?}").contains("secretmarker"));
}
