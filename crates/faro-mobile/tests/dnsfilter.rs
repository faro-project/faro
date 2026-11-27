//! `DnsFilter`, the packet tunnel's filter, through the API Swift sees:
//! the packaged domain list, the member's choices, upstreams, answers and
//! saved counters (docs/IOS.md §7).

use faro_detect::attribution::Attribution;
use faro_detect::{
    Category, DomainCategorizerBuilder, DomainSource, DomainsBundleInfo, DomainsManifest,
    DOMAINS_MANIFEST_FORMAT,
};
use faro_dnsfilter::packet::{build_udp, parse_udp};
use faro_dnsfilter::RESOLVER_ADDRS;
use faro_mobile::dnsfilter::tunnel_network;
use faro_mobile::{DnsFilter, DnsStep};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const T0: i64 = 1_800_000_000_000;

/// Write a packaged list (`domains.bin` and its manifest) listing
/// `adult` as adult, and return the manifest's path.
fn packaged(dir: &Path, version: &str, adult: &str) -> PathBuf {
    let mut b = DomainCategorizerBuilder::new();
    b.add_domain(adult, Category::Adult).unwrap();
    let bytes = b.build().unwrap().to_bytes();
    std::fs::write(dir.join("domains.bin"), &bytes).unwrap();
    let m = DomainsManifest {
        format: DOMAINS_MANIFEST_FORMAT.into(),
        notice: "Compiled from the lists below.".into(),
        version: version.into(),
        bundle: DomainsBundleInfo {
            file: "domains.bin".into(),
            bytes: bytes.len() as u64,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
        },
        domains: 1,
        unapproved_included: false,
        sources: vec![DomainSource {
            name: "adult-list".into(),
            category: Category::Adult,
            format: "domains".into(),
            license: "MIT".into(),
            approved: true,
            origin: "https://example.org/list.txt".into(),
            homepage: None,
            blake3: "0".repeat(64),
            attribution: Some(Attribution {
                author: "Test Authors".into(),
                copyright: vec!["Copyright 2026 Test Authors".into()],
                source_url: "https://example.org/list".into(),
                license_url: "https://example.org/list/LICENSE".into(),
                changes: "None.".into(),
            }),
            lines: 1,
            domains: 1,
            skipped: 0,
        }],
        license_texts: [(
            "MIT".to_owned(),
            "Permission is hereby granted (test).".to_owned(),
        )]
        .into(),
    };
    let path = dir.join("domains.manifest.json");
    std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
    path
}

fn query(name: &str) -> Vec<u8> {
    let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn client() -> SocketAddr {
    "10.0.0.2:53000".parse().unwrap()
}

fn packet(name: &str) -> Vec<u8> {
    build_udp(client(), "198.18.0.53:53".parse().unwrap(), &query(name)).unwrap()
}

fn rcode(step: &DnsStep) -> u8 {
    match step {
        DnsStep::Reply { packets } => parse_udp(&packets[0]).unwrap().payload[3] & 0x0f,
        other => panic!("not a reply: {other:?}"),
    }
}

/// Answer an upstream payload with one CNAME to `target` (or no records).
fn answer(payload: &[u8], cname: Option<&str>) -> Vec<u8> {
    let mut a = payload.to_vec();
    a[2] |= 0x80;
    if let Some(t) = cname {
        a[7] = 1;
        a.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
        let mut rdata = vec![];
        for l in t.split('.') {
            rdata.push(l.len() as u8);
            rdata.extend_from_slice(l.as_bytes());
        }
        rdata.push(0);
        a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        a.extend_from_slice(&rdata);
    }
    a
}

#[test]
fn filters_with_the_packaged_list_and_forwards_to_the_network_resolver() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), "1.2.0", "porn.test");
    let f = DnsFilter::new(Some(manifest.display().to_string()), None, None).unwrap();
    let s = f.status();
    assert_eq!(s.domains_version.as_deref(), Some("1.2.0"));
    assert_eq!(s.domains_source, "packaged");
    assert_eq!(s.domains_error, None);
    assert_eq!(s.blocked_categories, vec!["adult"]);

    // No resolver yet: allowed names fail fast, blocked ones are blocked.
    assert_eq!(rcode(&f.handle_packet(packet("www.a.test"), T0, true)), 2);
    assert_eq!(rcode(&f.handle_packet(packet("x.porn.test"), T0, true)), 3);

    let kept = f.set_upstreams(vec!["192.168.1.1".into(), "198.18.0.53".into()]);
    assert_eq!(kept.len(), 1);
    let DnsStep::Send { server, payload } = f.handle_packet(packet("www.a.test"), T0, true) else {
        panic!("not forwarded");
    };
    assert_eq!(server, "192.168.1.1:53");
    assert_eq!(server, kept[0].key);
    let back = f.handle_answer(server.clone(), answer(&payload, None), false, T0, true);
    assert_eq!(rcode(&back), 0);
    let DnsStep::Reply { packets } = back else {
        unreachable!()
    };
    let d = parse_udp(&packets[0]).unwrap();
    assert_eq!(d.dst, client());
    assert_eq!(&d.payload[..2], &[0x12, 0x34]);

    // An allowed name aliased to a blocked one is blocked.
    let DnsStep::Send { server, payload } = f.handle_packet(packet("www.a.test"), T0, true) else {
        panic!("not forwarded");
    };
    let back = f.handle_answer(
        server,
        answer(&payload, Some("cdn.porn.test")),
        false,
        T0,
        true,
    );
    assert_eq!(rcode(&back), 3);
    let json = f.counters_json();
    assert!(
        json.contains("cdn.porn.test") && !json.contains("a.test\""),
        "{json}"
    );

    // An answer from elsewhere, or naming no server, is ignored.
    let DnsStep::Send { payload, .. } = f.handle_packet(packet("b.test"), T0, true) else {
        panic!("not forwarded");
    };
    let a = answer(&payload, None);
    assert_eq!(
        f.handle_answer("192.168.1.9:53".into(), a.clone(), false, T0, true),
        DnsStep::Nothing
    );
    assert_eq!(
        f.handle_answer("nonsense".into(), a, false, T0, true),
        DnsStep::Nothing
    );
    assert_eq!(f.status().pending, 1);
}

#[test]
fn a_truncated_answer_asks_for_tcp_and_a_failed_fetch_gets_servfail() {
    let f = DnsFilter::new(None, None, None).unwrap();
    f.set_upstreams(vec!["192.168.1.1".into()]);
    let DnsStep::Send { server, payload } = f.handle_packet(packet("big.test"), T0, true) else {
        panic!("not forwarded");
    };
    let mut tc = answer(&payload, None);
    tc[2] |= 0x02;
    let DnsStep::SendTcp {
        id, payload: again, ..
    } = f.handle_answer(server, tc, false, T0, true)
    else {
        panic!("not over TCP");
    };
    assert_eq!(again, payload);
    assert_eq!(rcode(&f.upstream_failed(id, T0)), 2);
}

#[test]
fn without_a_packaged_list_it_still_blocks_what_it_can() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), "1.0.0", "porn.test");
    std::fs::write(dir.path().join("domains.bin"), b"changed").unwrap();
    for path in [Some(manifest.display().to_string()), None] {
        let f = DnsFilter::new(path, Some(r#"{"block":["news.test"]}"#.into()), None).unwrap();
        let s = f.status();
        assert_eq!(s.domains_source, "none");
        assert!(s.domains_error.is_some());
        assert_eq!(s.domains_version, None);
        assert_eq!(
            rcode(&f.handle_packet(packet("mask.icloud.com"), T0, true)),
            3
        );
        assert_eq!(
            rcode(&f.handle_packet(packet("www.news.test"), T0, true)),
            3
        );
        // Not listed anywhere it can read.
        assert_eq!(rcode(&f.handle_packet(packet("porn.test"), T0, true)), 2);
    }
}

#[test]
fn the_members_choices_and_the_instance_host() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), "1.0.0", "porn.test");
    let path = Some(manifest.display().to_string());
    // A config that doesn't parse, or that the filter refuses, leaves the
    // defaults in place.
    for bad in [r#"{"block": 7}"#, r#"{"block":["not a name"]}"#] {
        let f = DnsFilter::new(path.clone(), Some(bad.into()), None).unwrap();
        assert!(f.status().config_error.is_some(), "{bad}");
        assert_eq!(rcode(&f.handle_packet(packet("porn.test"), T0, true)), 3);
    }
    let f = DnsFilter::new(path, None, None).unwrap();
    assert!(f.set_config(r#"{"block":[1]}"#.into()).is_err());
    assert!(f.set_config(r#"{"allow":["*"]}"#.into()).is_err());
    f.set_config(r#"{"block":["news.test"],"allow":["ok.porn.test"]}"#.into())
        .unwrap();
    assert_eq!(f.status().config_error, None);
    assert_eq!(rcode(&f.handle_packet(packet("news.test"), T0, true)), 3);
    // Allowed: no upstream, so SERVFAIL rather than NXDOMAIN.
    assert_eq!(rcode(&f.handle_packet(packet("ok.porn.test"), T0, true)), 2);
    // The instance host is always allowed, and keeps the member's lists.
    f.set_instance_host(Some("porn.test".into()));
    assert_eq!(rcode(&f.handle_packet(packet("porn.test"), T0, true)), 2);
    assert_eq!(rcode(&f.handle_packet(packet("news.test"), T0, true)), 3);
    f.set_instance_host(None);
    assert_eq!(rcode(&f.handle_packet(packet("porn.test"), T0, true)), 3);
}

#[test]
fn upstream_addresses_as_the_system_reports_them() {
    let f = DnsFilter::new(None, None, None).unwrap();
    let kept = f.set_upstreams(
        [
            "192.168.1.1",
            " 10.0.0.1 ",
            "fe80::1%4",
            "[2001:db8::1]:5353",
            "198.18.0.53",
            "2001:2::53",
            "::1",
            "0.0.0.0",
            "fe80::1%en0",
            "garbage",
        ]
        .map(String::from)
        .to_vec(),
    );
    let keys: Vec<&str> = kept.iter().map(|u| u.key.as_str()).collect();
    assert_eq!(
        keys,
        vec![
            "192.168.1.1:53",
            "10.0.0.1:53",
            "[fe80::1%4]:53",
            "[2001:db8::1]:5353"
        ]
    );
    assert_eq!(
        (kept[2].host.as_str(), kept[2].port, kept[2].scope_id),
        ("fe80::1", 53, 4)
    );
    assert_eq!(f.upstreams(), kept);
    assert_eq!(f.status().upstreams, 4);
    assert!(f.set_upstreams(vec![]).is_empty());
}

#[test]
fn counters_survive_a_restart_and_only_hold_blocked_names() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), "1.0.0", "porn.test");
    let path = Some(manifest.display().to_string());
    let f = DnsFilter::new(path.clone(), None, None).unwrap();
    f.set_upstreams(vec!["192.168.1.1".into()]);
    f.handle_packet(packet("a.porn.test"), T0, true);
    f.handle_packet(packet("allowedmarker.test"), T0, true);
    let saved = f.counters_json();
    assert!(!saved.contains("allowedmarker"));
    let again = DnsFilter::new(path.clone(), None, Some(saved.clone())).unwrap();
    assert_eq!(again.counters_json(), saved);
    assert_eq!(again.status().counter_buckets, 1);
    // Saved counters that don't load are left behind.
    let fresh = DnsFilter::new(path, None, Some("{not json".into())).unwrap();
    assert_eq!(fresh.status().counter_buckets, 0);
}

#[test]
fn the_tunnel_routes_only_its_dns_address_and_the_resolver_list() {
    let n = tunnel_network();
    assert_eq!(n.ipv4_dns, "198.18.0.53");
    assert_eq!(n.ipv6_dns, "2001:2::53");
    assert_eq!(n.ipv4_address, "198.18.0.1");
    assert_eq!(n.ipv6_address, "2001:2::1");
    assert_eq!(n.mtu, 1500);
    assert_eq!(n.ipv4_routes[0], n.ipv4_dns);
    assert_eq!(n.ipv6_routes[0], n.ipv6_dns);
    let mut routed: Vec<String> = n.ipv4_routes[1..]
        .iter()
        .chain(&n.ipv6_routes[1..])
        .cloned()
        .collect();
    let mut listed: Vec<String> = RESOLVER_ADDRS.iter().map(ToString::to_string).collect();
    routed.sort();
    listed.sort();
    assert_eq!(routed, listed, "nothing but the resolver list");
}
