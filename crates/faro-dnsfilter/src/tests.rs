//! Packet fixtures, malformed input, checksums, the decision rules,
//! counters and bursts.
//!
//! The packets below were laid out by hand and their checksums computed by
//! a separate program (a short Perl script, itself checked against the
//! well-known IPv4 header example whose checksum is `b861`), not by this
//! crate. [`naive_sum`] is a second, byte-wise implementation that the
//! property tests check every built packet with.

use crate::burst::{
    registrable_domain, BURST_COOLDOWN_SECS, BURST_MIN_LOOKUPS, BURST_WINDOW_SECS, MAX_BURST_EVENTS,
};
use crate::counters::{BUCKET_SECS, MAX_BUCKETS, MAX_HOSTS_PER_BUCKET, MAX_HOSTS_TOTAL};
use crate::dns::{qtype, DnsError};
use crate::packet::{build_udp, checksum, parse_udp, PacketError};
use crate::*;
use faro_detect::{Category, DomainCategorizer, DomainCategorizerBuilder};
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

pub(crate) fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `www.Example.com` A from 10.0.0.2:53000 to 198.18.0.53:53, RD and AD
/// set, with an EDNS OPT record (4096 bytes).
pub(crate) const V4_QUERY: &str = "
    45000048 12340000 40119828 0a000002 c6120035
    cf080035 003459ab
    abcd0120 00010000 00000001
    03777777 07457861 6d706c65 03636f6d 00 0001 0001
    00 0029 1000 00 00 0000 0000";

/// The `NXDOMAIN` for [`V4_QUERY`]: RD and RA set, AD dropped, the question
/// echoed with its case.
const V4_NXDOMAIN: &str = "
    4500003d 00004000 40116a67 c6120035 0a000002
    0035cf08 0029e987
    abcd8183 00010000 00000000
    03777777 07457861 6d706c65 03636f6d 00 0001 0001";

/// An upstream answer to [`V4_QUERY`] (`93.184.216.34`), wrapped. Its odd
/// length exercises the checksum's padding byte.
const V4_ANSWER_DNS: &str = "
    abcd8180 00010001 00000000
    03777777 07457861 6d706c65 03636f6d 00 0001 0001
    c00c 0001 0001 0000012c 0004 5db8d822";
const V4_ANSWER_PACKET: &str = "
    4500004d 00004000 40116a57 c6120035 0a000002
    0035cf08 0039cf72
    abcd8180 00010001 00000000
    03777777 07457861 6d706c65 03636f6d 00 0001 0001
    c00c 0001 0001 0000012c 0004 5db8d822";

/// `mask.icloud.com` HTTPS from [fd00::2]:54321 to [fd00::53]:53, RD and CD
/// set.
pub(crate) const V6_QUERY: &str = "
    60000000 00291140
    fd000000 00000000 00000000 00000002
    fd000000 00000000 00000000 00000053
    d4310035 00294cab
    12340110 00010000 00000000
    046d6173 6b066963 6c6f7564 03636f6d 00 0041 0001";

const V6_NXDOMAIN: &str = "
    60000000 00291140
    fd000000 00000000 00000000 00000053
    fd000000 00000000 00000000 00000002
    0035d431 0029cc27
    12348193 00010000 00000000
    046d6173 6b066963 6c6f7564 03636f6d 00 0041 0001";

pub(crate) fn categorizer() -> DomainCategorizer {
    let mut b = DomainCategorizerBuilder::new();
    b.add_source(
        "0.0.0.0 example.com\n0.0.0.0 porn.test\n0.0.0.0 cdn.adult.test\nxxx\n",
        Category::Adult,
    )
    .unwrap();
    b.add_source("casino.test\nbet.co.uk\n", Category::Gambling)
        .unwrap();
    b.add_domain("gore.test", Category::Violence).unwrap();
    b.build().unwrap()
}

fn filter(config: &FilterConfig) -> Filter {
    Filter::new(categorizer(), config).unwrap()
}

fn engine() -> Engine {
    Engine::new(filter(&FilterConfig::default()))
}

/// The Internet checksum, byte by byte: high bytes at even offsets, low
/// bytes at odd ones, folded at the end. Written separately from
/// [`checksum`] so the two can check each other. Every part but the last
/// must have an even length (pseudo-headers do).
fn naive_sum(parts: &[&[u8]]) -> u16 {
    let mut hi: u64 = 0;
    let mut lo: u64 = 0;
    for part in parts {
        for (i, b) in part.iter().enumerate() {
            if i % 2 == 0 {
                hi += u64::from(*b);
            } else {
                lo += u64::from(*b);
            }
        }
    }
    let mut s = (hi << 8) + lo;
    while s > 0xffff {
        s = (s >> 16) + (s & 0xffff);
    }
    s as u16
}

/// Check every checksum of a built packet independently: the IPv4 header
/// and the UDP datagram with its pseudo-header must each sum to `0xffff`.
fn assert_checksums(p: &[u8]) {
    if p[0] >> 4 == 4 {
        let ihl = usize::from(p[0] & 0x0f) * 4;
        assert_eq!(naive_sum(&[&p[..ihl]]), 0xffff, "IPv4 header checksum");
        let udp = &p[ihl..];
        let len = (udp.len() as u16).to_be_bytes();
        let pseudo = [&p[12..20], &[0, 17], &len[..]].concat();
        assert_eq!(naive_sum(&[&pseudo, udp]), 0xffff, "UDP checksum (v4)");
        assert_ne!(&udp[6..8], &[0, 0]);
    } else {
        let udp = &p[40..];
        let len = (udp.len() as u32).to_be_bytes();
        let pseudo = [&p[8..40], &len[..], &[0, 0, 0, 17]].concat();
        assert_eq!(naive_sum(&[&pseudo, udp]), 0xffff, "UDP checksum (v6)");
        assert_ne!(&udp[6..8], &[0, 0]);
    }
}

// ---- checksums ----

#[test]
fn checksum_known_answer() {
    // The IPv4 header from the usual worked example, checksum b861.
    let h = hex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7");
    assert_eq!(checksum::finish(checksum::add(0, &h)), 0xb861);
    assert_eq!(
        naive_sum(&[&hex("4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7")]),
        0xffff
    );
    // Odd length: the last byte is padded with zero.
    assert_eq!(checksum::add(0, &[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
}

#[test]
fn fixtures_have_correct_checksums() {
    for f in [
        V4_QUERY,
        V4_NXDOMAIN,
        V4_ANSWER_PACKET,
        V6_QUERY,
        V6_NXDOMAIN,
    ] {
        assert_checksums(&hex(f));
    }
}

// ---- fixtures ----

#[test]
fn v4_query_parses() {
    let p = hex(V4_QUERY);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.client, "10.0.0.2:53000".parse().unwrap());
    assert_eq!(q.server, "198.18.0.53:53".parse().unwrap());
    assert_eq!(q.dns.id, 0xabcd);
    assert_eq!(q.dns.name.as_str(), "www.example.com");
    assert_eq!(q.dns.qtype, qtype::A);
    assert_eq!(q.dns.qclass, 1);
    assert_eq!(q.upstream_payload(), &p[28..]);
}

#[test]
fn v4_blocked_gets_the_expected_nxdomain() {
    let mut e = engine();
    let p = hex(V4_QUERY);
    let h = e.handle_packet(&p, 1_000, true);
    assert_eq!(h.action, Action::Reply(hex(V4_NXDOMAIN)));
    assert!(h.burst.is_none());
}

#[test]
fn v6_always_blocked_gets_the_expected_nxdomain() {
    let mut e = engine();
    let p = hex(V6_QUERY);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.client, "[fd00::2]:54321".parse().unwrap());
    assert_eq!(q.dns.name.as_str(), "mask.icloud.com");
    assert_eq!(q.dns.qtype, qtype::HTTPS);
    let h = e.handle_packet(&p, 1_000, true);
    assert_eq!(h.action, Action::Reply(hex(V6_NXDOMAIN)));
    let s = e.counters().summaries();
    assert_eq!(s[0].by_category["private_relay"], 1);
    assert!(s[0].hosts.is_empty());
}

#[test]
fn allowed_is_forwarded_and_the_answer_wrapped() {
    let mut e = Engine::new(
        Filter::new(
            DomainCategorizerBuilder::new().build().unwrap(),
            &FilterConfig::default(),
        )
        .unwrap(),
    );
    let p = hex(V4_QUERY);
    let h = e.handle_packet(&p, 1_000, true);
    let Action::Forward { payload, reply_to } = h.action else {
        panic!("not forwarded: {:?}", h.action);
    };
    assert_eq!(payload, &p[28..]);
    assert_eq!(reply_to.id(), 0xabcd);
    let wrapped = reply_to.wrap(&hex(V4_ANSWER_DNS)).unwrap();
    assert_eq!(wrapped, hex(V4_ANSWER_PACKET));
    assert!(e.counters().is_empty());
}

#[test]
fn wrap_refuses_what_is_not_the_answer() {
    let p = hex(V4_QUERY);
    let r = parse_packet(&p).unwrap().reply_to();
    let mut answer = hex(V4_ANSWER_DNS);
    assert!(r.wrap(&answer[..11]).is_err());
    answer[1] ^= 1; // another id
    assert_eq!(r.wrap(&answer), Err(WrapError::NotTheResponse));
    answer[1] ^= 1;
    answer[2] &= 0x7f; // QR clear: a query
    assert_eq!(r.wrap(&answer), Err(WrapError::NotTheResponse));
    let mut big = hex(V4_ANSWER_DNS);
    big.resize(packet::MAX_PAYLOAD_V4 + 1, 0);
    assert_eq!(r.wrap(&big), Err(WrapError::Build(BuildError::TooLarge)));
    big.truncate(packet::MAX_PAYLOAD_V4);
    let w = r.wrap(&big).unwrap();
    assert_eq!(w.len(), 65535);
    assert_checksums(&w);
}

#[test]
fn v6_wrap_of_the_largest_payload() {
    let p = hex(V6_QUERY);
    let r = parse_packet(&p).unwrap().reply_to();
    let mut big = hex(V6_NXDOMAIN)[48..].to_vec();
    big.resize(packet::MAX_PAYLOAD_V6, 0xa5);
    let w = r.wrap(&big).unwrap();
    assert_eq!(w.len(), 40 + 65535);
    assert_checksums(&w);
    big.push(0);
    assert_eq!(r.wrap(&big), Err(WrapError::Build(BuildError::TooLarge)));
}

#[test]
fn trailing_bytes_after_the_ip_packet_are_ignored() {
    let mut p = hex(V4_QUERY);
    p.extend_from_slice(&[0xde, 0xad]);
    assert_eq!(
        parse_packet(&p).unwrap().dns.name.as_str(),
        "www.example.com"
    );
    let mut p = hex(V6_QUERY);
    p.push(0);
    assert_eq!(
        parse_packet(&p).unwrap().dns.name.as_str(),
        "mask.icloud.com"
    );
}

#[test]
fn ipv4_options_are_skipped() {
    // IHL 6: four bytes of options (NOP NOP NOP EOL).
    let base = hex(V4_QUERY);
    let mut p = vec![0x46, 0x00, 0x00, 0x4c];
    p.extend_from_slice(&base[4..20]);
    p.extend_from_slice(&[1, 1, 1, 0]);
    p.extend_from_slice(&base[20..]);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.dns.name.as_str(), "www.example.com");
    // The reply carries no options.
    let r = q.nxdomain_packet().unwrap();
    assert_eq!(r, hex(V4_NXDOMAIN));
}

// ---- malformed packets ----

fn reject(p: &[u8]) -> Reject {
    let mut e = engine();
    match e.handle_packet(p, 0, true).action {
        Action::Drop(r) => r,
        other => panic!("not dropped: {other:?}"),
    }
}

#[test]
fn every_truncation_is_dropped() {
    for f in [V4_QUERY, V6_QUERY] {
        let p = hex(f);
        for n in 0..p.len() {
            let _ = reject(&p[..n]);
        }
    }
}

#[test]
fn bad_ip_headers() {
    let base = hex(V4_QUERY);
    let set = |i: usize, v: u8| {
        let mut p = base.clone();
        p[i] = v;
        p
    };
    assert_eq!(reject(&[]), Reject::Packet(PacketError::Empty));
    assert_eq!(
        reject(&set(0, 0x55)),
        Reject::Packet(PacketError::BadVersion(5))
    );
    assert_eq!(
        reject(&set(0, 0x44)),
        Reject::Packet(PacketError::BadHeaderLength)
    );
    assert_eq!(
        reject(&set(0, 0x4f)),
        Reject::Packet(PacketError::BadUdpLength)
    );
    assert_eq!(
        reject(&set(3, 0x49)),
        Reject::Packet(PacketError::Truncated)
    );
    assert_eq!(
        reject(&set(3, 0x10)),
        Reject::Packet(PacketError::BadHeaderLength)
    );
    assert_eq!(reject(&set(6, 0x20)), Reject::Packet(PacketError::Fragment)); // MF
    assert_eq!(reject(&set(7, 0x01)), Reject::Packet(PacketError::Fragment)); // offset
    let df = set(6, 0x40); // Don't Fragment is fine
    assert!(parse_packet(&df).is_ok());
    assert_eq!(reject(&set(9, 6)), Reject::Packet(PacketError::Tcp));
    assert_eq!(reject(&set(9, 1)), Reject::Packet(PacketError::NotUdp(1)));

    let v6 = hex(V6_QUERY);
    let mut p = v6.clone();
    p[6] = 0; // hop-by-hop options header
    assert_eq!(reject(&p), Reject::Packet(PacketError::NotUdp(0)));
    let mut p = v6.clone();
    p[6] = 6;
    assert_eq!(reject(&p), Reject::Packet(PacketError::Tcp));
    let mut p = v6.clone();
    p[5] = 0x2a; // payload length past the end
    assert_eq!(reject(&p), Reject::Packet(PacketError::Truncated));
    let mut p = v6;
    p[4] = 0;
    p[5] = 0; // jumbogram marker
    assert_eq!(reject(&p), Reject::Packet(PacketError::Truncated));
}

#[test]
fn bad_udp_headers() {
    let base = hex(V4_QUERY);
    let set = |i: usize, v: u8| {
        let mut p = base.clone();
        p[i] = v;
        p
    };
    assert_eq!(
        reject(&set(25, 7)),
        Reject::Packet(PacketError::BadUdpLength)
    );
    assert_eq!(
        reject(&set(25, 0x35)),
        Reject::Packet(PacketError::BadUdpLength)
    );
    let mut p = set(20, 0);
    p[21] = 0;
    assert_eq!(reject(&p), Reject::Packet(PacketError::ZeroSourcePort));
    assert_eq!(reject(&set(23, 54)), Reject::NotDnsPort(54));
    let mut p = set(22, 0x01);
    p[23] = 0xbb;
    assert_eq!(reject(&p), Reject::NotDnsPort(443));
    // A shorter UDP length cuts the DNS message: here, inside the OPT
    // record, which is not parsed, so the query still parses.
    let p = set(25, 0x30);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.upstream_payload().len(), 0x30 - 8);
}

/// A v4 packet around a DNS message, with correct lengths.
pub(crate) fn v4_packet(dns: &[u8]) -> Vec<u8> {
    build_udp(
        "10.0.0.2:53000".parse().unwrap(),
        "198.18.0.53:53".parse().unwrap(),
        dns,
    )
    .unwrap()
}

/// A DNS query for `labels` with the given header fields.
pub(crate) fn query(flags: u16, qdcount: u16, labels: &[&[u8]]) -> Vec<u8> {
    let mut m = vec![0x77, 0x77];
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&qdcount.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for l in labels {
        m.push(l.len() as u8);
        m.extend_from_slice(l);
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn dns_reject(dns: &[u8]) -> DnsError {
    match reject(&v4_packet(dns)) {
        Reject::Dns(e) => e,
        other => panic!("not a DNS rejection: {other:?}"),
    }
}

#[test]
fn bad_dns_messages() {
    let ok = query(0x0100, 1, &[b"porn", b"test"]);
    assert!(parse_packet(&v4_packet(&ok)).is_ok());
    assert_eq!(dns_reject(&ok[..11]), DnsError::Truncated);
    assert_eq!(dns_reject(&ok[..ok.len() - 1]), DnsError::Truncated);
    assert_eq!(dns_reject(&query(0x8100, 1, &[b"a"])), DnsError::NotAQuery);
    assert_eq!(dns_reject(&query(0x1100, 1, &[b"a"])), DnsError::Opcode(2));
    assert_eq!(dns_reject(&query(0x2800, 1, &[b"a"])), DnsError::Opcode(5));
    assert_eq!(
        dns_reject(&query(0x0100, 0, &[b"a"])),
        DnsError::QuestionCount(0)
    );
    assert_eq!(
        dns_reject(&query(0x0100, 2, &[b"a"])),
        DnsError::QuestionCount(2)
    );
    for bad in [
        b"sp ace".as_slice(),
        b"do.t",
        b"caf\xc3\xa9",
        b"star*",
        b"\0",
    ] {
        let e = dns_reject(&query(0x0100, 1, &[bad, b"test"]));
        assert!(matches!(e, DnsError::LabelByte(_)), "{bad:?}: {e:?}");
    }
}

#[test]
fn compression_pointers_and_loops() {
    let mut header = query(0x0100, 1, &[]);
    header.truncate(12);
    // A pointer to itself: the classic loop.
    let mut m = header.clone();
    m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    assert_eq!(dns_reject(&m), DnsError::CompressionPointer);
    // A label, then a pointer back to it.
    let mut m = header.clone();
    m.extend_from_slice(&[1, b'a', 0xc0, 0x0c, 0, 1, 0, 1]);
    assert_eq!(dns_reject(&m), DnsError::CompressionPointer);
    // Into the header, and forward.
    for target in [0x00u8, 0x02, 0x20, 0xff] {
        let mut m = header.clone();
        m.extend_from_slice(&[0xc0, target, 0, 1, 0, 1]);
        assert_eq!(dns_reject(&m), DnsError::CompressionPointer);
    }
    // The reserved and extended label types.
    for t in [0x40u8, 0x41, 0x80, 0xbf] {
        let mut m = header.clone();
        m.extend_from_slice(&[t, 0, 0, 1, 0, 1]);
        assert_eq!(dns_reject(&m), DnsError::LabelType);
    }
}

#[test]
fn label_and_name_limits() {
    let l63 = [b'a'; 63];
    let l64 = [b'a'; 64];
    // A 64-byte label's length byte is 0x40, a reserved label type.
    assert_eq!(
        dns_reject(&query(0x0100, 1, &[&l64, b"test"])),
        DnsError::LabelType
    );
    assert!(parse_packet(&v4_packet(&query(0x0100, 1, &[&l63, b"test"]))).is_ok());
    // 255 bytes on the wire: 63 + 63 + 63 + 61 with their length bytes and
    // the final zero. The longest a name can be, 253 with dots.
    let l61 = [b'b'; 61];
    let longest = query(0x0100, 1, &[&l63, &l63, &l63, &l61]);
    let p = v4_packet(&longest);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.dns.name.len(), 253);
    let l62 = [b'b'; 62];
    assert_eq!(
        dns_reject(&query(0x0100, 1, &[&l63, &l63, &l63, &l62])),
        DnsError::NameTooLong
    );
    let many: Vec<&[u8]> = vec![b"a"; 200];
    assert_eq!(dns_reject(&query(0x0100, 1, &many)), DnsError::NameTooLong);
    // The root, as a priming query asks it.
    let root = query(0x0000, 1, &[]);
    let p = v4_packet(&root);
    let q = parse_packet(&p).unwrap();
    assert!(q.dns.name.is_empty());
    assert!(matches!(
        engine().handle_packet(&p, 0, true).action,
        Action::Forward { .. }
    ));
}

#[test]
fn names_are_lowercased_and_punycode_kept() {
    let m = query(0x0100, 1, &[b"XN--Bcher-KVA", b"Example", b"_Svc"]);
    let p = v4_packet(&m);
    let q = parse_packet(&p).unwrap();
    assert_eq!(q.dns.name.as_str(), "xn--bcher-kva.example._svc");
    // The reply echoes the question as it was asked.
    let r = q.nxdomain_packet().unwrap();
    assert_eq!(&r[28 + 12..], &m[12..]);
}

#[test]
fn tcp_to_the_tunnel_gets_no_answer() {
    let mut p = hex(V4_QUERY);
    p[9] = 6;
    assert_eq!(reject(&p), Reject::Packet(PacketError::Tcp));
}

// ---- the decision ----

fn blocked(f: &Filter, name: &str) -> Option<(BlockCategory, BlockReason)> {
    match f.decide(name, qtype::A) {
        Verdict::Allow => None,
        Verdict::Block { category, reason } => Some((category, reason)),
    }
}

#[test]
fn parent_domain_matching() {
    let f = filter(&FilterConfig::default());
    let adult = Some((
        BlockCategory::Bundle(Category::Adult),
        BlockReason::Category,
    ));
    assert_eq!(blocked(&f, "example.com"), adult);
    assert_eq!(blocked(&f, "www.example.com"), adult);
    assert_eq!(blocked(&f, "a.b.c.example.com"), adult);
    assert_eq!(blocked(&f, "anything.xxx"), adult);
    assert_eq!(blocked(&f, "cdn.adult.test"), adult);
    assert_eq!(blocked(&f, "x.cdn.adult.test"), adult);
    assert_eq!(
        blocked(&f, "adult.test"),
        None,
        "a parent of an entry is not blocked"
    );
    assert_eq!(blocked(&f, "notexample.com"), None);
    assert_eq!(blocked(&f, "example.com.evil.test"), None);
    assert_eq!(blocked(&f, "example.co"), None);
    assert_eq!(blocked(&f, "com"), None);
    assert_eq!(blocked(&f, ""), None);
    // Case and a trailing dot don't matter.
    assert_eq!(blocked(&f, "WWW.Example.COM."), adult);
}

#[test]
fn categories_adult_always_on_others_opt_in() {
    let f = filter(&FilterConfig::default());
    assert_eq!(f.blocked_categories(), vec![Category::Adult]);
    assert_eq!(blocked(&f, "casino.test"), None);
    assert_eq!(blocked(&f, "gore.test"), None);
    let f = filter(&FilterConfig {
        categories: [Category::Gambling].into(),
        ..Default::default()
    });
    assert_eq!(
        f.blocked_categories(),
        vec![Category::Adult, Category::Gambling]
    );
    assert_eq!(
        blocked(&f, "www.casino.test"),
        Some((
            BlockCategory::Bundle(Category::Gambling),
            BlockReason::Category
        ))
    );
    assert!(blocked(&f, "porn.test").is_some());
    assert_eq!(blocked(&f, "gore.test"), None);
}

#[test]
fn always_blocked_whatever_the_member_picks() {
    let everything_allowed = FilterConfig {
        allow: ALWAYS_BLOCKED.iter().map(|(n, _)| n.to_string()).collect(),
        instance_host: Some("faro.example.org".into()),
        ..Default::default()
    };
    let f = filter(&everything_allowed);
    for (name, _) in ALWAYS_BLOCKED {
        for n in [name.to_string(), format!("sub.{name}"), name.to_uppercase()] {
            let (_, reason) = blocked(&f, &n).unwrap_or_else(|| panic!("{n} allowed"));
            assert_eq!(reason, BlockReason::AlwaysBlocked);
        }
    }
    let relay = |n| blocked(&f, n).map(|b| b.0);
    assert_eq!(relay("mask.icloud.com"), Some(BlockCategory::PrivateRelay));
    assert_eq!(
        relay("mask-h2.icloud.com"),
        Some(BlockCategory::PrivateRelay)
    );
    assert_eq!(relay("dns.google"), Some(BlockCategory::EncryptedDns));
    assert_eq!(
        relay("mozilla.cloudflare-dns.com"),
        Some(BlockCategory::EncryptedDns)
    );
    assert_eq!(
        relay("_dns.resolver.arpa"),
        Some(BlockCategory::EncryptedDns)
    );
    for fine in [
        "icloud.com",
        "www.icloud.com",
        "google.com",
        "quad9.net",
        "dns.google.evil.test",
        "mask.icloud.com.evil.test",
        "nomask.icloud.com",
    ] {
        assert_eq!(blocked(&f, fine), None, "{fine}");
    }
}

#[test]
fn always_blocked_list_is_well_formed() {
    let mut seen = std::collections::HashSet::new();
    for (name, _) in ALWAYS_BLOCKED {
        assert_eq!(filter::normalize_entry(name).as_deref(), Some(*name));
        assert!(seen.insert(*name), "{name} twice");
    }
}

#[test]
fn instance_host_always_allowed() {
    let host = "porn.test";
    let f = filter(&FilterConfig {
        instance_host: Some("Porn.Test.".into()),
        block: vec![host.into()],
        ..Default::default()
    });
    assert_eq!(blocked(&f, host), None);
    // Only the host itself.
    assert!(blocked(&f, "x.porn.test").is_some());
    // Never over an always-blocked name.
    let f = filter(&FilterConfig {
        instance_host: Some("dns.google".into()),
        ..Default::default()
    });
    assert!(blocked(&f, "dns.google").is_some());
}

#[test]
fn member_lists() {
    let f = filter(&FilterConfig {
        allow: vec!["example.com".into(), "*.ok.test".into()],
        block: vec![
            "ads.example.com".into(),
            "porn.test".into(),
            "news.test".into(),
        ],
        ..Default::default()
    });
    // The allow list lifts a category block, for subdomains too.
    assert_eq!(blocked(&f, "example.com"), None);
    assert_eq!(blocked(&f, "www.example.com"), None);
    // The block list wins over the allow list.
    assert_eq!(
        blocked(&f, "x.ads.example.com"),
        Some((
            BlockCategory::Bundle(Category::Adult),
            BlockReason::MemberBlockList
        ))
    );
    // A listed name the bundle doesn't know is counted as the member's.
    assert_eq!(
        blocked(&f, "www.news.test"),
        Some((BlockCategory::MemberList, BlockReason::MemberBlockList))
    );
    // A listed name the bundle knows keeps its category.
    assert_eq!(
        blocked(&f, "porn.test"),
        Some((
            BlockCategory::Bundle(Category::Adult),
            BlockReason::MemberBlockList
        ))
    );
    assert_eq!(blocked(&f, "ok.test"), None);
    assert_eq!(blocked(&f, "news.test.evil"), None);
}

#[test]
fn bad_configs_are_refused() {
    let c = categorizer();
    let with = |cfg: FilterConfig| Filter::new(c.clone(), &cfg).map(|_| ());
    assert!(matches!(
        with(FilterConfig {
            block: vec!["a b.test".into()],
            ..Default::default()
        }),
        Err(ConfigError::BadName(_))
    ));
    assert!(matches!(
        with(FilterConfig {
            allow: vec!["".into()],
            ..Default::default()
        }),
        Err(ConfigError::BadName(_))
    ));
    assert!(matches!(
        with(FilterConfig {
            instance_host: Some("https://x.test/".into()),
            ..Default::default()
        }),
        Err(ConfigError::BadName(_))
    ));
    assert_eq!(
        with(FilterConfig {
            block: vec!["a.test".into(); filter::MAX_LIST_ENTRIES + 1],
            ..Default::default()
        }),
        Err(ConfigError::TooManyEntries)
    );
    assert_eq!(
        with(FilterConfig {
            categories: [Category::Custom(200)].into(),
            ..Default::default()
        }),
        Err(ConfigError::BadCategory(Category::Custom(200)))
    );
    // The config round-trips through JSON, and an empty object is the
    // default.
    let cfg = FilterConfig {
        categories: [Category::Gambling].into(),
        block: vec!["a.test".into()],
        allow: vec![],
        instance_host: Some("faro.example.org".into()),
    };
    let json = serde_json::to_string(&cfg).unwrap();
    assert_eq!(serde_json::from_str::<FilterConfig>(&json).unwrap(), cfg);
    assert_eq!(
        serde_json::from_str::<FilterConfig>("{}").unwrap(),
        FilterConfig::default()
    );
}

#[test]
fn a_new_filter_shares_the_bundle() {
    let f = filter(&FilterConfig::default());
    let g = Filter::new(Arc::clone(f.categorizer()), &FilterConfig::default()).unwrap();
    assert!(Arc::ptr_eq(f.categorizer(), g.categorizer()));
    let mut e = Engine::new(f);
    let p = hex(V4_QUERY);
    e.handle_packet(&p, 0, true);
    e.set_filter(
        Filter::new(
            Arc::clone(g.categorizer()),
            &FilterConfig {
                allow: vec!["example.com".into()],
                ..Default::default()
            },
        )
        .unwrap(),
    );
    assert!(matches!(
        e.handle_packet(&p, 0, true).action,
        Action::Forward { .. }
    ));
    assert_eq!(e.counters().summaries()[0].by_category["adult"], 1);
}

// ---- resolvers ----

#[test]
fn resolver_list() {
    let mut seen = std::collections::HashSet::new();
    for ip in RESOLVER_ADDRS {
        assert!(seen.insert(*ip), "{ip} twice");
        assert!(
            !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast(),
            "{ip}"
        );
        if let IpAddr::V4(v4) = ip {
            assert!(!v4.is_private() && !v4.is_link_local(), "{ip}");
        }
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "9.9.9.9",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "::ffff:8.8.4.4",
    ] {
        assert!(is_resolver_addr(ip.parse().unwrap()), "{ip}");
    }
    for ip in ["8.8.8.9", "198.18.0.53", "2606:4700:4700::1234"] {
        assert!(!is_resolver_addr(ip.parse().unwrap()), "{ip}");
    }
    let v4 = resolvers::resolver_v4().count();
    let v6 = resolvers::resolver_v6().count();
    assert_eq!(v4 + v6, RESOLVER_ADDRS.len());
    assert!(v4 > 10 && v6 > 10);
}

#[test]
fn plain_dns_to_a_routed_resolver_is_filtered_and_answered_from_it() {
    let google: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let client: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    let dns = query(0x0100, 1, &[b"porn", b"test"]);
    let p = build_udp(client, google, &dns).unwrap();
    let mut e = engine();
    let Action::Reply(r) = e.handle_packet(&p, 0, true).action else {
        panic!("not answered");
    };
    let d = parse_udp(&r).unwrap();
    assert_eq!((d.src, d.dst), (google, client));
    // DoH, DoT and DoQ to it are dropped.
    for (port, proto) in [(443u16, 6u8), (853, 6), (443, 17), (853, 17)] {
        let mut p = build_udp(client, SocketAddr::new(google.ip(), port), &dns).unwrap();
        p[9] = proto;
        assert!(matches!(
            e.handle_packet(&p, 0, true).action,
            Action::Drop(_)
        ));
    }
}

// ---- counters ----

const T0: i64 = 1_800_000_000_000; // a multiple of 10 minutes

#[test]
fn counters_buckets_and_hosts() {
    let mut c = Counters::new();
    let adult = BlockCategory::Bundle(Category::Adult);
    let gambling = BlockCategory::Bundle(Category::Gambling);
    c.record(T0, "a.porn.test", adult);
    c.record(T0 + 1, "a.porn.test", adult);
    c.record(T0 + 2, "casino.test", gambling);
    c.record(
        T0 + 3,
        "gore.test",
        BlockCategory::Bundle(Category::Violence),
    );
    c.record(T0 + 4, "dns.google", BlockCategory::EncryptedDns);
    c.record(T0 + 5, "news.test", BlockCategory::MemberList);
    c.record(T0 + 600_000, "b.porn.test", adult);
    let s = c.summaries();
    assert_eq!(s.len(), 2);
    assert_eq!(s[0].bucket_start, T0);
    assert_eq!(s[0].bucket_secs, BUCKET_SECS);
    assert_eq!(
        s[0].by_category,
        [
            ("adult", 2),
            ("gambling", 1),
            ("violence", 1),
            ("encrypted_dns", 1),
            ("member_list", 1)
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    );
    // Only adult and gambling hosts are itemised.
    assert_eq!(
        s[0].hosts,
        vec![
            HostCount {
                host: "a.porn.test".into(),
                category: "adult".into(),
                count: 2
            },
            HostCount {
                host: "casino.test".into(),
                category: "gambling".into(),
                count: 1
            },
        ]
    );
    assert_eq!(s[1].bucket_start, T0 + 600_000);

    // Only ended buckets are taken.
    let closed = c.take_closed(T0 + 600_000 + 5);
    assert_eq!(closed, vec![s[0].clone()]);
    assert_eq!(c.len(), 1);
    assert!(c.take_closed(T0 + 600_000 + 599_999).is_empty());
    assert_eq!(c.take_closed(T0 + 1_200_000).len(), 1);
    assert!(c.is_empty());
}

#[test]
fn counters_are_bounded() {
    let mut c = Counters::new();
    let adult = BlockCategory::Bundle(Category::Adult);
    for i in 0..MAX_HOSTS_PER_BUCKET + 10 {
        c.record(T0, &format!("h{i}.porn.test"), adult);
    }
    // A host already itemised still counts as itself.
    c.record(T0, "h0.porn.test", adult);
    let s = &c.summaries()[0];
    assert_eq!(s.hosts.len(), MAX_HOSTS_PER_BUCKET);
    assert_eq!(s.other_hosts, 10);
    assert_eq!(s.by_category["adult"], (MAX_HOSTS_PER_BUCKET + 11) as u32);
    assert_eq!(
        s.hosts
            .iter()
            .find(|h| h.host == "h0.porn.test")
            .unwrap()
            .count,
        2
    );

    let mut c = Counters::new();
    for i in 0..(MAX_BUCKETS as i64 + 5) {
        c.record(T0 + i * 600_000, "x.porn.test", adult);
    }
    assert_eq!(c.len(), MAX_BUCKETS);
    assert_eq!(c.summaries()[0].bucket_start, T0 + 5 * 600_000);
    // A bucket older than all of them doesn't push a newer one out.
    c.record(T0, "x.porn.test", adult);
    assert_eq!(c.summaries()[0].bucket_start, T0 + 5 * 600_000);
    // A clock before 1970.
    let mut c = Counters::new();
    c.record(i64::MIN, "x.porn.test", adult);
    assert_eq!(c.summaries()[0].bucket_start, 0);
}

#[test]
fn counters_cap_hosts_across_buckets() {
    let mut c = Counters::new();
    let adult = BlockCategory::Bundle(Category::Adult);
    let full = MAX_HOSTS_TOTAL / MAX_HOSTS_PER_BUCKET;
    for b in 0..=full as i64 {
        for h in 0..MAX_HOSTS_PER_BUCKET {
            c.record(T0 + b * 600_000, &format!("h{h}.porn.test"), adult);
        }
    }
    let s = c.summaries();
    assert_eq!(
        s.iter().map(|b| b.hosts.len()).sum::<usize>(),
        MAX_HOSTS_TOTAL
    );
    let last = s.last().unwrap();
    assert!(last.hosts.is_empty());
    assert_eq!(last.other_hosts, MAX_HOSTS_PER_BUCKET as u32);
    assert_eq!(last.by_category["adult"], MAX_HOSTS_PER_BUCKET as u32);
    // Handing buckets over frees room.
    c.take_closed(T0 + 600_000);
    c.record(T0 + full as i64 * 600_000, "new.porn.test", adult);
    assert_eq!(c.summaries().last().unwrap().hosts.len(), 1);
    // Saved counters over the total are refused: give the last bucket a
    // full list of hosts too.
    let mut big = Counters::new();
    for b in 0..=full as i64 {
        for h in 0..MAX_HOSTS_PER_BUCKET {
            big.record(T0 + b * 600_000, &format!("h{h}.porn.test"), adult);
        }
    }
    let mut list = serde_json::to_value(&big).unwrap();
    assert!(serde_json::from_value::<Counters>(list.clone()).is_ok());
    list[full]["hosts"] = list[0]["hosts"].clone();
    assert!(serde_json::from_value::<Counters>(list).is_err());
}

#[test]
fn counters_json_round_trip_and_checks() {
    let mut c = Counters::new();
    c.record(T0, "a.porn.test", BlockCategory::Bundle(Category::Adult));
    c.record(T0, "dns.google", BlockCategory::EncryptedDns);
    let json = serde_json::to_string(&c).unwrap();
    assert_eq!(
        json,
        format!(
            r#"[{{"bucket_start":{T0},"bucket_secs":600,"by_category":{{"adult":1,"encrypted_dns":1}},"hosts":[{{"host":"a.porn.test","category":"adult","count":1}}],"other_hosts":0}}]"#
        )
    );
    assert_eq!(serde_json::from_str::<Counters>(&json).unwrap(), c);
    assert_eq!(
        serde_json::from_str::<Counters>("[]").unwrap(),
        Counters::new()
    );

    let bad = |s: String| serde_json::from_str::<Counters>(&s).is_err();
    let bucket = |start: i64, secs: u32, hosts: &str| {
        format!(
            r#"{{"bucket_start":{start},"bucket_secs":{secs},"by_category":{{}},"hosts":[{hosts}],"other_hosts":0}}"#
        )
    };
    assert!(bad(format!("[{}]", bucket(T0 + 1, 600, ""))));
    assert!(bad(format!("[{}]", bucket(-600_000, 600, ""))));
    assert!(bad(format!("[{}]", bucket(T0, 60, ""))));
    assert!(bad(format!(
        "[{},{}]",
        bucket(T0, 600, ""),
        bucket(T0, 600, "")
    )));
    let host = |h: &str, c: &str| format!(r#"{{"host":"{h}","category":"{c}","count":1}}"#);
    assert!(bad(format!(
        "[{}]",
        bucket(T0, 600, &host("a.test", "violence"))
    )));
    assert!(bad(format!(
        "[{}]",
        bucket(T0, 600, &host("A.test", "adult"))
    )));
    assert!(bad(format!("[{}]", bucket(T0, 600, &host("a b", "adult")))));
    let two = format!("{},{}", host("a.test", "adult"), host("a.test", "adult"));
    assert!(bad(format!("[{}]", bucket(T0, 600, &two))));
    let many: Vec<String> = (0..=MAX_HOSTS_PER_BUCKET)
        .map(|i| host(&format!("h{i}.test"), "adult"))
        .collect();
    assert!(bad(format!("[{}]", bucket(T0, 600, &many.join(",")))));
    let buckets: Vec<String> = (0..=MAX_BUCKETS as i64)
        .map(|i| bucket(T0 + i * 600_000, 600, ""))
        .collect();
    assert!(bad(format!("[{}]", buckets.join(","))));
    let long_cat = "x".repeat(65);
    assert!(bad(format!(
        r#"[{{"bucket_start":{T0},"bucket_secs":600,"by_category":{{"{long_cat}":1}},"hosts":[],"other_hosts":0}}]"#
    )));
}

#[test]
fn engine_starts_from_saved_counters() {
    let mut c = Counters::new();
    c.record(T0, "a.porn.test", BlockCategory::Bundle(Category::Adult));
    let mut e = Engine::with_counters(filter(&FilterConfig::default()), c);
    e.handle_packet(&hex(V4_QUERY), T0 + 1, false);
    let s = e.take_closed(T0 + 600_000);
    assert_eq!(s[0].by_category["adult"], 2);
}

// ---- bursts ----

const ADULT: BlockCategory = BlockCategory::Bundle(Category::Adult);

#[test]
fn registrable_domains() {
    for (name, want) in [
        ("example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("com", "com"),
        ("", ""),
        ("x.example.co.uk", "example.co.uk"),
        ("example.co.uk", "example.co.uk"),
        ("co.uk", "co.uk"),
        ("a.b.c.com.au", "c.com.au"),
        ("x.example.co", "example.co"),
        ("x.co.example", "co.example"),
    ] {
        assert_eq!(registrable_domain(name), want, "{name}");
    }
}

#[test]
fn closed_buckets_can_be_read_then_forgotten() {
    let mut c = Counters::new();
    c.record(T0 + 1, "a.test", ADULT);
    c.record(T0 + 600_001, "b.test", ADULT);
    c.record(T0 + 1_200_001, "c.test", ADULT);
    // Reading removes nothing, and the open bucket is never offered.
    let now = T0 + 1_200_100;
    let closed = c.closed(now);
    assert_eq!(closed.len(), 2);
    assert_eq!(c.closed(now).len(), 2);
    assert_eq!(c.len(), 3);
    // Forgetting through the last one read keeps the open bucket.
    c.forget_through(closed[1].bucket_start);
    assert_eq!(c.len(), 1);
    assert_eq!(c.summaries()[0].bucket_start, T0 + 1_200_000);
    c.forget_through(i64::MAX);
    assert!(c.is_empty());
}

#[test]
fn lower_burst_thresholds_make_a_burst_sooner() {
    use crate::burst::BurstThresholds;
    let t = BurstThresholds {
        min_lookups: 2,
        min_domains: 1,
        cooldown_secs: 30,
    };
    let mut b = BurstDetector::with_thresholds(t);
    assert!(b.observe(T0, "a.one.test", ADULT, true).is_none());
    let c = b.observe(T0 + 1_000, "a.one.test", ADULT, true).unwrap();
    assert_eq!((c.lookups, c.domains), (2, 1));
    // The shorter cooldown ends after 30 s.
    assert!(b.observe(T0 + 2_000, "a.one.test", ADULT, true).is_none());
    assert!(b.observe(T0 + 32_000, "a.one.test", ADULT, true).is_none());
    assert!(b.observe(T0 + 33_000, "a.one.test", ADULT, true).is_some());
    // The defaults are the constants.
    let d = BurstThresholds::default();
    assert_eq!(
        (d.min_lookups, d.min_domains, d.cooldown_secs),
        (BURST_MIN_LOOKUPS, 3, BURST_COOLDOWN_SECS)
    );
}

#[test]
fn burst_needs_six_lookups_across_three_domains() {
    let mut b = BurstDetector::new();
    let hosts = [
        "a.one.test",
        "b.one.test",
        "two.test",
        "www.two.test",
        "three.co.uk",
        "a.one.test",
    ];
    for (i, h) in hosts.iter().enumerate() {
        let r = b.observe(T0 + i as i64 * 30_000, h, ADULT, true);
        if i + 1 < BURST_MIN_LOOKUPS {
            assert!(r.is_none());
        } else {
            let c = r.unwrap();
            assert_eq!(c.lookups, 6);
            assert_eq!(c.hosts, 5);
            assert_eq!(c.domains, 3);
            assert_eq!(c.span_secs, 150);
            assert_eq!(c.label(), "adult ×6, 5 hosts, 3 min, screen on");
            assert_eq!(c.to_string(), "dns:adult ×6, 5 hosts, 3 min, screen on");
            assert_eq!(b.held(), 0);
        }
    }
}

#[test]
fn no_burst_without_three_domains_screen_or_time() {
    // Two domains only, however many lookups.
    let mut b = BurstDetector::new();
    for i in 0..40 {
        let h = if i % 2 == 0 { "a.one.test" } else { "two.test" };
        assert!(b.observe(T0 + i, h, ADULT, true).is_none());
    }
    // Screen off: nothing counts.
    let mut b = BurstDetector::new();
    for i in 0..20 {
        assert!(b
            .observe(T0 + i, &format!("h{i}.test"), ADULT, false)
            .is_none());
    }
    assert_eq!(b.held(), 0);
    // Spread over more than the window.
    let mut b = BurstDetector::new();
    let step = BURST_WINDOW_SECS * 1000 / 5 + 1;
    for i in 0..20 {
        assert!(b
            .observe(T0 + i * step, &format!("h{i}.test"), ADULT, true)
            .is_none());
    }
    // Another category.
    let mut b = BurstDetector::new();
    for i in 0..20 {
        let g = BlockCategory::Bundle(Category::Gambling);
        assert!(b.observe(T0 + i, &format!("h{i}.test"), g, true).is_none());
        assert!(b
            .observe(
                T0 + i,
                &format!("h{i}.test"),
                BlockCategory::EncryptedDns,
                true
            )
            .is_none());
    }
    assert_eq!(b.held(), 0);
}

#[test]
fn burst_cooldown_and_clock_changes() {
    let mut b = BurstDetector::new();
    let burst = |b: &mut BurstDetector, at: i64| {
        (0..6)
            .filter_map(|i| b.observe(at + i, &format!("h{i}.test"), ADULT, true))
            .count()
    };
    assert_eq!(burst(&mut b, T0), 1);
    assert_eq!(burst(&mut b, T0 + 1_000), 0, "quiet during the cooldown");
    assert_eq!(b.held(), 0, "nothing held while quiet");
    assert_eq!(burst(&mut b, T0 + BURST_COOLDOWN_SECS * 1000 + 10), 1);
    // A clock set back further than the cooldown starts over.
    assert_eq!(burst(&mut b, T0 - 10 * BURST_COOLDOWN_SECS * 1000), 1);
    // A clock set back a little clears the window.
    let mut b = BurstDetector::new();
    for i in 0..5 {
        b.observe(T0 + 100_000 + i, &format!("h{i}.test"), ADULT, true);
    }
    assert!(b.observe(T0, "h9.test", ADULT, true).is_none());
    assert_eq!(b.held(), 1);
    // Bounded.
    let mut b = BurstDetector::new();
    for i in 0..1000 {
        b.observe(T0 + i, "one.test", ADULT, true);
    }
    assert_eq!(b.held(), MAX_BURST_EVENTS);
    // Extreme times don't overflow.
    let mut b = BurstDetector::new();
    assert_eq!(burst(&mut b, i64::MAX - 10), 1);
    let mut b = BurstDetector::new();
    assert_eq!(burst(&mut b, i64::MIN), 1);
}

#[test]
fn engine_reports_bursts_from_packets() {
    let mut e = engine();
    let names: [&[&[u8]]; 6] = [
        &[b"a", b"porn", b"test"],
        &[b"b", b"porn", b"test"],
        &[b"example", b"com"],
        &[b"www", b"example", b"com"],
        &[b"cdn", b"adult", b"test"],
        &[b"x", b"xxx"],
    ];
    let mut bursts = vec![];
    for (i, n) in names.iter().enumerate() {
        let p = v4_packet(&query(0x0100, 1, n));
        let h = e.handle_packet(&p, T0 + i as i64 * 1000, true);
        assert!(matches!(h.action, Action::Reply(_)));
        bursts.extend(h.burst);
    }
    assert_eq!(bursts.len(), 1);
    assert_eq!(
        bursts[0].to_string(),
        "dns:adult ×6, 6 hosts, 1 min, screen on"
    );
    assert_eq!(bursts[0].domains, 4);
}

// ---- properties ----

fn any_addr_pair() -> impl Strategy<Value = (SocketAddr, SocketAddr)> {
    prop_oneof![
        (
            any::<[u8; 4]>(),
            any::<[u8; 4]>(),
            1..=u16::MAX,
            any::<u16>()
        )
            .prop_map(|(a, b, p, q)| (
                SocketAddr::new(Ipv4Addr::from(a).into(), p),
                SocketAddr::new(Ipv4Addr::from(b).into(), q)
            )),
        (
            any::<[u8; 16]>(),
            any::<[u8; 16]>(),
            1..=u16::MAX,
            any::<u16>()
        )
            .prop_map(|(a, b, p, q)| (
                SocketAddr::new(Ipv6Addr::from(a).into(), p),
                SocketAddr::new(Ipv6Addr::from(b).into(), q)
            )),
    ]
}

proptest! {
    #[test]
    fn built_packets_have_independently_correct_checksums(
        (src, dst) in any_addr_pair(),
        payload in proptest::collection::vec(any::<u8>(), 0..1500),
    ) {
        let p = build_udp(src, dst, &payload).unwrap();
        assert_checksums(&p);
        let d = parse_udp(&p).unwrap();
        prop_assert_eq!(d.src, src);
        prop_assert_eq!(d.dst, dst);
        prop_assert_eq!(d.payload, &payload[..]);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let mut e = engine();
        let _ = e.handle_packet(&bytes, T0, true);
        let _ = dns::parse_query(&bytes);
        let _ = parse_udp(&bytes);
    }

    #[test]
    fn mutated_fixtures_never_panic_and_replies_are_well_formed(
        v6 in any::<bool>(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
        cut in any::<usize>(),
    ) {
        let mut p = hex(if v6 { V6_QUERY } else { V4_QUERY });
        for (i, x) in flips {
            let i = i % p.len();
            p[i] ^= x;
        }
        p.truncate(cut % (p.len() + 1));
        let mut e = engine();
        let h = e.handle_packet(&p, T0, true);
        if let Action::Reply(r) = &h.action {
            assert_checksums(r);
            let q = parse_packet(&p).unwrap();
            let d = parse_udp(r).unwrap();
            prop_assert_eq!(d.src, q.server);
            prop_assert_eq!(d.dst, q.client);
            prop_assert_eq!(&d.payload[..2], &q.dns.id.to_be_bytes()[..]);
        }
        if let Action::Forward { payload, reply_to } = &h.action {
            prop_assert!(p.windows(payload.len()).any(|w| w == *payload));
            let mut answer = payload.to_vec();
            answer[2] |= 0x80;
            let w = reply_to.wrap(&answer).unwrap();
            assert_checksums(&w);
        }
    }
}
