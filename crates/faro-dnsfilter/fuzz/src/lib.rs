//! The checks behind the faro-dnsfilter fuzz targets, and their seed
//! corpus. The targets are one-line wrappers, so the seeds can be tested
//! here on a stable toolchain.
//!
//! Every packet the crate builds is checked against this file's own reading
//! of it (headers, lengths, addresses and a byte-wise checksum), not against
//! the crate's parser, so a bug shared by the builder and the parser still
//! shows.

use faro_detect::{Category, DomainCategorizerBuilder};
use faro_dnsfilter::{
    dns, parse_packet, Action, Counters, Engine, Filter, FilterConfig, Verdict, WrapError,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

/// The filter every target uses: a small bundle with adult and gambling
/// names, gambling blocked, one allow and one block entry.
fn filter() -> &'static Filter {
    static F: OnceLock<Filter> = OnceLock::new();
    F.get_or_init(|| {
        let mut b = DomainCategorizerBuilder::new();
        b.add_source("example.com\nporn.test\nxxx\n", Category::Adult)
            .expect("adult list");
        b.add_source("casino.test\nbet.co.uk\n", Category::Gambling)
            .expect("gambling list");
        let config = FilterConfig {
            categories: [Category::Gambling].into(),
            allow: vec!["ok.porn.test".into()],
            block: vec!["news.test".into()],
            instance_host: Some("faro.example.org".into()),
        };
        Filter::new(b.build().expect("bundle"), &config).expect("filter")
    })
}

/// The one's-complement sum, byte by byte.
fn sum(parts: &[&[u8]]) -> u16 {
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

/// Check that `p` is exactly one UDP datagram from `src` to `dst` carrying
/// `payload`, with correct lengths and checksums.
pub fn check_built(p: &[u8], src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
    let (udp, pseudo) = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            assert_eq!(p.len(), 28 + payload.len(), "IPv4 packet length");
            assert_eq!(p[0], 0x45);
            assert_eq!(usize::from(u16::from_be_bytes([p[2], p[3]])), p.len());
            assert_eq!(p[6] & 0x3f, 0, "no fragment bits");
            assert_eq!(p[7], 0);
            assert_eq!(p[9], 17);
            assert_eq!(sum(&[&p[..20]]), 0xffff, "IPv4 header checksum");
            assert_eq!(Ipv4Addr::from(<[u8; 4]>::try_from(&p[12..16]).unwrap()), s);
            assert_eq!(Ipv4Addr::from(<[u8; 4]>::try_from(&p[16..20]).unwrap()), d);
            let len = ((p.len() - 20) as u16).to_be_bytes();
            (&p[20..], [&p[12..20], &[0, 17], &len[..]].concat())
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            assert_eq!(p.len(), 48 + payload.len(), "IPv6 packet length");
            assert_eq!(p[0], 0x60);
            assert_eq!(usize::from(u16::from_be_bytes([p[4], p[5]])), p.len() - 40);
            assert_eq!(p[6], 17);
            assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()), s);
            assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()), d);
            let len = ((p.len() - 40) as u32).to_be_bytes();
            (&p[40..], [&p[8..40], &len[..], &[0, 0, 0, 17]].concat())
        }
        _ => panic!("mixed address families"),
    };
    assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), src.port());
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), dst.port());
    assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
    assert_ne!(&udp[6..8], &[0, 0], "UDP checksum present");
    assert_eq!(sum(&[&pseudo, udp]), 0xffff, "UDP checksum");
    assert_eq!(&udp[8..], payload);
}

fn check_name(name: &str) {
    assert!(name.len() <= dns::MAX_NAME);
    if name.is_empty() {
        return;
    }
    for label in name.split('.') {
        assert!(
            !label.is_empty() && label.len() <= dns::MAX_LABEL,
            "{name:?}"
        );
        assert!(label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'));
    }
}

/// The `packet` target: one packet from the tunnel through the engine.
/// Returns whether it was answered or forwarded.
pub fn packet(data: &[u8]) -> bool {
    let mut e = Engine::new(filter().clone());
    let h = e.handle_packet(data, 1_800_000_000_000, true);
    let parsed = parse_packet(data);
    match (h.action, parsed) {
        (Action::Reply(r), Ok(q)) => {
            check_name(q.dns.name.as_str());
            assert!(matches!(
                filter().decide(q.dns.name.as_str(), q.dns.qtype),
                Verdict::Block { .. }
            ));
            let msg = q.upstream_payload();
            // The question on the wire: the name's length bytes and labels
            // (its dotted length plus two, or one for the root), type, class.
            let n = q.dns.name.len();
            let question = if n == 0 { 1 } else { n + 2 } + 4;
            let flags = u16::from_be_bytes([msg[2], msg[3]]);
            let reply_flags = 0x8000 | (flags & 0x0110) | 0x0080 | 3;
            let mut expect = msg[..2].to_vec();
            expect.extend_from_slice(&reply_flags.to_be_bytes());
            expect.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
            expect.extend_from_slice(&msg[12..12 + question]);
            check_built(&r, q.server, q.client, &expect);
            assert!(!e.counters().is_empty(), "a blocked lookup is counted");
            true
        }
        (Action::Forward { payload, reply_to }, Ok(q)) => {
            check_name(q.dns.name.as_str());
            assert_eq!(
                filter().decide(q.dns.name.as_str(), q.dns.qtype),
                Verdict::Allow
            );
            assert_eq!(payload, q.upstream_payload());
            assert!(
                e.counters().is_empty(),
                "an allowed lookup is never counted"
            );
            assert!(h.burst.is_none());
            let mut answer = payload.to_vec();
            answer[2] |= 0x80;
            let w = reply_to
                .wrap(&answer)
                .expect("a query echoed as an answer wraps");
            check_built(&w, q.server, q.client, &answer);
            true
        }
        (Action::Drop(_), Err(_)) => {
            assert!(e.counters().is_empty());
            false
        }
        (action, parsed) => panic!("{action:?} for {parsed:?}"),
    }
}

/// The `response` target: an arbitrary upstream answer wrapped for one of
/// two fixed queries (the first byte picks IPv4 or IPv6).
pub fn response(data: &[u8]) -> bool {
    let Some((&pick, answer)) = data.split_first() else {
        return false;
    };
    let query = hex(if pick & 1 == 0 { V4_QUERY } else { V6_QUERY });
    let q = parse_packet(&query).expect("fixture parses");
    let r = q.reply_to();
    match r.wrap(answer) {
        Ok(w) => {
            check_built(&w, q.server, q.client, answer);
            true
        }
        Err(WrapError::NotTheResponse) => {
            let ok = answer.len() >= 12
                && u16::from_be_bytes([answer[0], answer[1]]) == r.id()
                && answer[2] & 0x80 != 0;
            assert!(!ok, "a real response was refused");
            false
        }
        Err(WrapError::Build(_)) => {
            assert!(answer.len() > 65535 - 48);
            false
        }
    }
}

/// The `state` target: what the tunnel loads from the app group. The first
/// byte picks saved counters (even) or a filter config (odd). Whatever
/// loads must round-trip.
pub fn state(data: &[u8]) -> bool {
    let Some((&pick, json)) = data.split_first() else {
        return false;
    };
    if pick & 1 == 0 {
        let Ok(c) = serde_json::from_slice::<Counters>(json) else {
            return false;
        };
        let encoded = serde_json::to_vec(&c).expect("counters encode");
        let back: Counters = serde_json::from_slice(&encoded).expect("counters decode again");
        assert_eq!(back, c);
        assert_eq!(serde_json::to_vec(&back).expect("encode"), encoded);
        true
    } else {
        let Ok(config) = serde_json::from_slice::<FilterConfig>(json) else {
            return false;
        };
        let encoded = serde_json::to_vec(&config).expect("config encodes");
        let back: FilterConfig = serde_json::from_slice(&encoded).expect("config decodes again");
        assert_eq!(back, config);
        let Ok(f) = Filter::new(filter().categorizer().clone(), &config) else {
            return false;
        };
        for name in config.block.iter().chain(&config.allow) {
            let _ = f.decide(name, 1);
        }
        // Nothing the member picks lifts the always-blocked list.
        assert!(f.decide("mask.icloud.com", 1).is_blocked());
        assert!(f.decide("dns.google", 1).is_blocked());
        true
    }
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// `www.Example.com` A over IPv4, with an EDNS OPT record.
const V4_QUERY: &str = "
    45000048 12340000 40119828 0a000002 c6120035
    cf080035 003459ab
    abcd0120 00010000 00000001
    03777777 07457861 6d706c65 03636f6d 00 0001 0001
    00 0029 1000 00 00 0000 0000";

/// `mask.icloud.com` HTTPS over IPv6.
const V6_QUERY: &str = "
    60000000 00291140
    fd000000 00000000 00000000 00000002
    fd000000 00000000 00000000 00000053
    d4310035 00294cab
    12340110 00010000 00000000
    046d6173 6b066963 6c6f7564 03636f6d 00 0041 0001";

fn v4(dns: &[u8]) -> Vec<u8> {
    faro_dnsfilter::packet::build_udp(
        "10.0.0.2:53000".parse().expect("addr"),
        "198.18.0.53:53".parse().expect("addr"),
        dns,
    )
    .expect("small packet")
}

fn v6(dns: &[u8]) -> Vec<u8> {
    faro_dnsfilter::packet::build_udp(
        "[fd00::2]:54321".parse().expect("addr"),
        "[fd00::53]:53".parse().expect("addr"),
        dns,
    )
    .expect("small packet")
}

fn query(name: &str, qtype: u16) -> Vec<u8> {
    let mut m = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.').filter(|l| !l.is_empty()) {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&[0, 1]);
    m
}

/// The seed corpus: `(target, name, bytes)`.
pub fn seeds() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut out = vec![];
    let mut add =
        |t: &'static str, name: &str, bytes: Vec<u8>| out.push((t, name.to_owned(), bytes));

    add("packet", "v4-blocked", hex(V4_QUERY));
    add("packet", "v6-always-blocked", hex(V6_QUERY));
    for (name, n) in [
        ("allowed", "www.wikipedia.org"),
        ("adult-sub", "a.b.porn.test"),
        ("gambling", "www.bet.co.uk"),
        ("allow-list", "ok.porn.test"),
        ("block-list", "x.news.test"),
        ("instance", "faro.example.org"),
        ("doh", "dns.google"),
        ("ddr", "_dns.resolver.arpa"),
        ("punycode", "xn--bcher-kva.example"),
        ("root", ""),
    ] {
        add("packet", &format!("v4-{name}"), v4(&query(n, 1)));
        add("packet", &format!("v6-{name}"), v6(&query(n, 28)));
    }
    let mut pointer = query("", 1);
    pointer.truncate(12);
    pointer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
    add("packet", "pointer-loop", v4(&pointer));
    let mut two = query("a.test", 1);
    two[5] = 2;
    add("packet", "two-questions", v4(&two));
    let mut tcp = hex(V4_QUERY);
    tcp[9] = 6;
    add("packet", "tcp", tcp);

    let answer = hex("abcd8180 00010001 00000000
         03777777 07457861 6d706c65 03636f6d 00 0001 0001
         c00c 0001 0001 0000012c 0004 5db8d822");
    add("response", "v4", [&[0u8][..], &answer].concat());
    let mut v6_answer = answer.clone();
    v6_answer[0] = 0x12;
    v6_answer[1] = 0x34;
    add("response", "v6", [&[1u8][..], &v6_answer].concat());

    let mut c = Counters::new();
    c.record(
        1_800_000_000_000,
        "a.porn.test",
        faro_dnsfilter::BlockCategory::Bundle(Category::Adult),
    );
    c.record(
        1_800_000_000_000,
        "dns.google",
        faro_dnsfilter::BlockCategory::EncryptedDns,
    );
    let counters = serde_json::to_vec(&c).expect("counters encode");
    add("state", "counters", [&[0u8][..], &counters].concat());
    let config = br#"{"categories":["gambling"],"block":["news.test"],"allow":["ok.test"],"instance_host":"faro.example.org"}"#;
    add("state", "config", [&[1u8][..], config].concat());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_seed_reaches_its_checks() {
        for (target, name, bytes) in seeds() {
            let reached = match target {
                "packet" => packet(&bytes),
                "response" => response(&bytes),
                "state" => state(&bytes),
                _ => unreachable!(),
            };
            let expect_drop = ["pointer-loop", "two-questions", "tcp"].contains(&name.as_str());
            assert_eq!(reached, !expect_drop, "{target}/{name}");
        }
    }

    /// Random multi-byte mutations of the seeds, from a fixed generator:
    /// a stand-in for libFuzzer where there is no nightly toolchain.
    /// `FARO_FUZZ_ITERS` sets the number of inputs (10 000 by default).
    #[test]
    fn random_mutations_pass_the_checks() {
        let iters: u64 = std::env::var("FARO_FUZZ_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);
        let seeds = seeds();
        let mut x: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (mut answered, mut total) = (0u64, 0u64);
        for _ in 0..iters {
            let (target, _, seed) = &seeds[(next() % seeds.len() as u64) as usize];
            let mut b = seed.clone();
            for _ in 0..=next() % 4 {
                if b.is_empty() {
                    break;
                }
                let i = (next() % b.len() as u64) as usize;
                match next() % 4 {
                    0 => b[i] = next() as u8,
                    1 => b[i] ^= 1 << (next() % 8),
                    2 => b.truncate(i),
                    _ => b.insert(i, next() as u8),
                }
            }
            let ok = match *target {
                "packet" => packet(&b),
                "response" => response(&b),
                _ => state(&b),
            };
            total += 1;
            answered += u64::from(ok);
        }
        assert!(answered > 0 && answered < total);
    }

    #[test]
    fn mutations_of_the_seeds_pass_the_checks() {
        // A few thousand single-byte changes and truncations, so the checks
        // themselves are exercised on stable too.
        for (target, _, bytes) in seeds() {
            for i in 0..bytes.len() {
                for x in [0x01u8, 0x80, 0xff] {
                    let mut b = bytes.clone();
                    b[i] ^= x;
                    match target {
                        "packet" => {
                            packet(&b);
                            packet(&b[..i]);
                        }
                        "response" => {
                            response(&b);
                        }
                        _ => {
                            state(&b);
                        }
                    }
                }
            }
        }
    }
}
