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
    dns, parse_packet, tunnel, Action, Counters, Engine, Filter, FilterConfig, Session, Step,
    Verdict, WrapError,
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

/// The allowed name the `answer` target asks about.
pub const ANSWER_QUESTION: &str = "www.Wikipedia.org";

/// The names an answer's records point to, read by this file's own parser:
/// CNAME and DNAME targets, and SVCB and HTTPS targets other than the root.
/// Pointers may go anywhere earlier in the message, at most 64 of them per
/// name. `None` if it doesn't parse, or a name has a byte no host name has.
fn targets(msg: &[u8]) -> Option<Vec<String>> {
    fn u16_at(m: &[u8], i: usize) -> Option<usize> {
        Some(usize::from(u16::from_be_bytes([
            *m.get(i)?,
            *m.get(i + 1)?,
        ])))
    }
    fn skip(m: &[u8], mut i: usize) -> Option<usize> {
        loop {
            let l = *m.get(i)?;
            if l >= 0xc0 {
                m.get(i + 1)?;
                return Some(i + 2);
            }
            if l > 63 {
                return None;
            }
            i += 1 + usize::from(l);
            if i > m.len() {
                return None;
            }
            if l == 0 {
                return Some(i);
            }
        }
    }
    fn name(m: &[u8], mut i: usize) -> Option<String> {
        let mut labels: Vec<String> = vec![];
        let mut hops = 0;
        loop {
            let l = *m.get(i)?;
            if l >= 0xc0 {
                let to = (usize::from(l & 0x3f) << 8) | usize::from(*m.get(i + 1)?);
                hops += 1;
                if hops > 64 || to >= i {
                    return None;
                }
                i = to;
                continue;
            }
            if l > 63 {
                return None;
            }
            if l == 0 {
                return Some(labels.join("."));
            }
            let raw = m.get(i + 1..i + 1 + usize::from(l))?;
            if !raw
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return None;
            }
            labels.push(String::from_utf8(raw.to_ascii_lowercase()).ok()?);
            i += 1 + usize::from(l);
        }
    }
    let mut i = 12;
    for _ in 0..u16_at(msg, 4)? {
        i = skip(msg, i)? + 4;
    }
    let mut out = vec![];
    for _ in 0..u16_at(msg, 6)? {
        i = skip(msg, i)?;
        let rtype = u16_at(msg, i)?;
        let len = u16_at(msg, i + 8)?;
        let data = i + 10;
        msg.get(data..data + len)?;
        let record = msg.get(..data + len)?;
        match rtype {
            5 | 39 => out.push(name(record, data)?),
            64 | 65 => {
                let t = name(record, data + 2)?;
                if !t.is_empty() {
                    out.push(t);
                }
            }
            _ => {}
        }
        i = data + len;
    }
    Some(out)
}

/// Put fragments back together, by this file's own reading of them, into
/// the UDP payload they carry, checking each fragment's headers and the
/// UDP checksum of the whole.
fn reassemble(frags: &[Vec<u8>], src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    if let [one] = frags {
        let skip = if src.is_ipv4() { 28 } else { 48 };
        check_built(one, src, dst, &one[skip..]);
        return one[skip..].to_vec();
    }
    let v6 = src.is_ipv6();
    let mut udp = vec![];
    for (i, f) in frags.iter().enumerate() {
        assert!(f.len() <= tunnel::MTU, "fragment over the MTU");
        let last = i + 1 == frags.len();
        let (offset, more, body) = if v6 {
            assert_eq!(f[6], 44);
            assert_eq!(f[40], 17);
            assert_eq!(usize::from(u16::from_be_bytes([f[4], f[5]])), f.len() - 40);
            let field = u16::from_be_bytes([f[42], f[43]]);
            (usize::from(field >> 3) * 8, field & 1 == 1, &f[48..])
        } else {
            assert_eq!(f[0], 0x45);
            assert_eq!(sum(&[&f[..20]]), 0xffff);
            assert_eq!(usize::from(u16::from_be_bytes([f[2], f[3]])), f.len());
            let field = u16::from_be_bytes([f[6], f[7]]);
            (
                usize::from(field & 0x1fff) * 8,
                field & 0x2000 != 0,
                &f[20..],
            )
        };
        assert_eq!(offset, udp.len());
        assert_eq!(more, !last);
        assert!(last || body.len() % 8 == 0);
        udp.extend_from_slice(body);
    }
    let pseudo = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let len = (udp.len() as u16).to_be_bytes();
            [&s.octets()[..], &d.octets(), &[0, 17], &len].concat()
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let len = (udp.len() as u32).to_be_bytes();
            [&s.octets()[..], &d.octets(), &len, &[0, 0, 0, 17]].concat()
        }
        _ => panic!("mixed families"),
    };
    assert_eq!(sum(&[&pseudo, &udp]), 0xffff, "UDP checksum of the whole");
    assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), src.port());
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), dst.port());
    assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
    udp[8..].to_vec()
}

/// The `answer` target: an upstream answer to an allowed query, through a
/// [`Session`], the way the tunnel hands it over. The first byte picks
/// IPv4 or IPv6 (bit 0) and whether it came over TCP (bit 1). The rest is
/// the answer's header after the id (10 bytes, with `QR` forced on and one
/// question), then everything after the question, which is the query's.
///
/// An answer that passes must point to no blocked name and come back with
/// only its id changed. One turned into `NXDOMAIN` must point to a blocked
/// name, and only blocked names are ever counted. A truncated UDP answer
/// must be fetched again over TCP, never passed on.
pub fn answer(data: &[u8]) -> bool {
    let Some((&pick, rest)) = data.split_first() else {
        return false;
    };
    let (head, tail) = rest.split_at(rest.len().min(10));
    let (client, server): (SocketAddr, SocketAddr) = if pick & 1 == 0 {
        (
            "10.0.0.2:53000".parse().expect("addr"),
            "198.18.0.53:53".parse().expect("addr"),
        )
    } else {
        (
            "[2001:2::1]:54321".parse().expect("addr"),
            "[2001:2::53]:53".parse().expect("addr"),
        )
    };
    let over_tcp = pick & 2 != 0;
    let upstream: SocketAddr = "192.168.1.1:53".parse().expect("addr");
    let mut s = Session::new(Engine::new(filter().clone()), 0x5eed);
    s.set_upstreams([upstream]);
    let q = query(ANSWER_QUESTION, 1);
    let packet = faro_dnsfilter::packet::build_udp(client, server, &q).expect("small");
    let now = 1_800_000_000_000;
    let Step::Send { payload, .. } = s.packet(&packet, now, true) else {
        panic!("the allowed query was not forwarded");
    };
    let mut msg = payload[..2].to_vec();
    msg.extend_from_slice(head);
    msg.resize(12, 0);
    msg[2] |= 0x80;
    msg[4..6].copy_from_slice(&[0, 1]);
    msg.extend_from_slice(&q[12..]);
    msg.extend_from_slice(tail);

    let step = s.answer(upstream, &msg, over_tcp, now, true);
    let counted: Vec<String> = s
        .engine()
        .counters()
        .summaries()
        .into_iter()
        .flat_map(|b| b.hosts.into_iter().map(|h| h.host))
        .collect();
    for h in &counted {
        assert!(
            filter().decide(h, 1).is_blocked(),
            "{h} counted but not blocked"
        );
        assert!(!h.contains("wikipedia"), "the allowed name was counted");
    }
    let found = targets(&msg);
    let blocked_target = found
        .as_ref()
        .map(|t| t.iter().any(|n| filter().decide(n, 5).is_blocked()));
    match step {
        Step::Reply(frags) => {
            let back = reassemble(&frags, server, client);
            assert_eq!(&back[..2], &q[..2], "the client's id");
            let rcode = back.get(3).map(|b| b & 0x0f);
            if back[2..] == msg[2..] {
                assert!(
                    over_tcp || !dns::is_truncated(&msg),
                    "a truncated answer passed"
                );
                assert_ne!(blocked_target, Some(true), "a blocked alias passed");
                assert!(s.engine().counters().is_empty());
            } else {
                assert_eq!(back.len(), q.len(), "an error reply is the question only");
                assert_eq!(&back[12..], &q[12..]);
                match rcode {
                    Some(3) => {
                        assert_ne!(
                            blocked_target,
                            Some(false),
                            "NXDOMAIN without a blocked alias"
                        );
                        assert!(!s.engine().counters().is_empty());
                    }
                    Some(2) => assert!(s.engine().counters().is_empty()),
                    other => panic!("rcode {other:?}"),
                }
            }
            assert_eq!(s.pending(), 0);
            true
        }
        Step::SendTcp {
            server: to,
            payload: again,
            ..
        } => {
            assert!(!over_tcp && dns::is_truncated(&msg));
            assert_eq!(to, upstream);
            assert_eq!(again, payload);
            assert!(s.engine().counters().is_empty());
            true
        }
        Step::Nothing(_) => {
            assert!(s.engine().counters().is_empty());
            assert_eq!(s.pending(), 1);
            false
        }
        Step::Send { .. } => panic!("an answer sent something upstream"),
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

    // Answers to ANSWER_QUESTION: the header after the id, then records.
    // The question's labels are at 12 (www), 16 (Wikipedia) and 26 (org).
    let wire = |n: &str| {
        let mut w = vec![];
        for l in n.split('.') {
            w.push(l.len() as u8);
            w.extend_from_slice(l.as_bytes());
        }
        w.push(0);
        w
    };
    let rr = |rtype: u16, rdata: &[u8]| {
        let mut r = vec![0xc0, 0x0c];
        r.extend_from_slice(&rtype.to_be_bytes());
        r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(rdata);
        r
    };
    let https = |target: &str| [&[0u8, 0][..], &wire(target), &[0, 1, 0, 0]].concat();
    for (name, pick, tc, records) in [
        ("a", 0u8, false, vec![rr(1, &[93, 184, 216, 34])]),
        (
            "cname-allowed",
            1,
            false,
            vec![rr(5, &wire("dyna.wikimedia.org"))],
        ),
        (
            "cname-blocked",
            0,
            false,
            vec![rr(5, &wire("cdn.porn.test"))],
        ),
        (
            "cname-compressed",
            0,
            false,
            vec![rr(5, &[3, b'c', b'd', b'n', 0xc0, 16])],
        ),
        ("cname-loop", 0, false, vec![rr(5, &[1, b'x', 0xc0, 47])]),
        ("dname-blocked", 1, false, vec![rr(39, &wire("x.xxx"))]),
        (
            "https-blocked",
            0,
            false,
            vec![rr(65, &https("svc.casino.test"))],
        ),
        ("https-self", 1, false, vec![rr(65, &https(""))]),
        (
            "member-blocked",
            0,
            false,
            vec![rr(5, &wire("www.news.test"))],
        ),
        ("truncated", 0, true, vec![]),
        ("truncated-tcp", 2, true, vec![rr(5, &wire("ok.test"))]),
        (
            "chain",
            3,
            false,
            vec![rr(5, &wire("b.test")), rr(5, &wire("mask.icloud.com"))],
        ),
    ] {
        let flags: u16 = 0x8180 | if tc { 0x0200 } else { 0 };
        let mut head = flags.to_be_bytes().to_vec();
        head.extend_from_slice(&[0, 1, 0, records.len() as u8, 0, 0, 0, 0]);
        let body = [&[pick][..], &head, &records.concat()].concat();
        add("answer", &format!("answer-{name}"), body);
    }

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
                "answer" => answer(&bytes),
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
                "answer" => answer(&b),
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
                        "answer" => {
                            answer(&b);
                            answer(&b[..i]);
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
