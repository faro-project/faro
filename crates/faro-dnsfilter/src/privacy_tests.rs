//! The IOS.md §7.5 test that allowed lookups are never recorded.
//!
//! Every allowed name carries a marker label (`allowedmarker`) that no
//! blocked name has. After a mix of allowed and blocked lookups runs
//! through the [`Engine`] the way the tunnel runs it, the marker must appear
//! nowhere the engine keeps or hands over: not in the counters (as values
//! or as JSON), not in the burst detector, not in the engine's `Debug`
//! output, and not in what a forwarded query keeps (its [`ReplyTo`]).
//! The blocked names must all be there, so the test would notice counters
//! that recorded nothing at all.

use crate::tests::{categorizer, query, v4_packet};
use crate::*;
use proptest::prelude::*;

const MARKER: &str = "allowedmarker";

/// A lookup: `true` for an allowed name, with its labels.
fn lookup() -> impl Strategy<Value = (bool, Vec<String>)> {
    let label = "[a-z0-9][a-z0-9-]{0,10}";
    prop_oneof![
        // Allowed: random labels, the marker, then a domain the bundle
        // doesn't list.
        (
            proptest::collection::vec(label, 0..3),
            prop::sample::select(vec!["net", "org", "co.uk", "test"])
        )
            .prop_map(|(mut ls, tld)| {
                ls.push(MARKER.to_owned());
                ls.extend(tld.split('.').map(str::to_owned));
                (true, ls)
            }),
        // Blocked: a subdomain of a listed adult or gambling domain.
        (
            proptest::collection::vec(label, 0..3),
            prop::sample::select(vec!["porn.test", "example.com", "casino.test", "bet.co.uk"])
        )
            .prop_map(|(mut ls, d)| {
                ls.extend(d.split('.').map(str::to_owned));
                (false, ls)
            }),
    ]
}

fn run(lookups: &[(bool, Vec<String>)]) -> (Engine, Vec<ReplyTo>) {
    let config = FilterConfig {
        categories: [faro_detect::Category::Gambling].into(),
        ..Default::default()
    };
    let mut e = Engine::new(Filter::new(categorizer(), &config).unwrap());
    let mut kept = vec![];
    for (i, (allowed, labels)) in lookups.iter().enumerate() {
        let ls: Vec<&[u8]> = labels.iter().map(|l| l.as_bytes()).collect();
        let p = v4_packet(&query(0x0100, 1, &ls));
        // Screen on, all within a minute, so the burst detector sees
        // everything it may.
        let h = e.handle_packet(&p, 1_800_000_000_000 + i as i64 * 100, true);
        match h.action {
            Action::Forward { reply_to, .. } => {
                assert!(*allowed, "blocked name forwarded: {labels:?}");
                kept.push(reply_to);
            }
            Action::Reply(_) => assert!(!*allowed, "allowed name blocked: {labels:?}"),
            Action::Drop(r) => panic!("dropped {labels:?}: {r}"),
        }
    }
    (e, kept)
}

fn assert_no_marker(e: &Engine, kept: &[ReplyTo], blocked: &[String]) {
    let json = serde_json::to_string(e.counters()).unwrap();
    let debug = format!("{e:?} {kept:?}");
    assert!(
        !json.contains(MARKER),
        "an allowed name reached the counters: {json}"
    );
    assert!(!debug.contains(MARKER), "an allowed name is held: {debug}");
    let summaries = e.counters().summaries();
    let mut listed = 0u32;
    for s in &summaries {
        for h in &s.hosts {
            assert!(!h.host.contains(MARKER));
            assert!(blocked.contains(&h.host), "{} was never blocked", h.host);
            listed += h.count;
        }
        listed += s.other_hosts;
    }
    let counted: u32 = summaries.iter().flat_map(|s| s.by_category.values()).sum();
    // Every blocked lookup here is adult or gambling, so every one is
    // counted and itemised, and nothing else is.
    assert_eq!(counted as usize, blocked.len());
    assert_eq!(listed as usize, blocked.len());
}

#[test]
fn only_allowed_lookups_leave_nothing() {
    let lookups: Vec<_> = (0..500)
        .map(|i| {
            (
                true,
                vec![format!("h{i}"), MARKER.to_owned(), "net".to_owned()],
            )
        })
        .collect();
    let (e, kept) = run(&lookups);
    assert!(e.counters().is_empty());
    assert_no_marker(&e, &kept, &[]);
}

#[test]
fn allowed_names_never_reach_the_counters_or_the_burst_detector() {
    // A burst's worth of blocked lookups between allowed ones, so the
    // detector holds and then clears names.
    let mut lookups = vec![];
    let mut blocked = vec![];
    for i in 0..12 {
        lookups.push((
            true,
            vec![format!("a{i}"), MARKER.to_owned(), "org".to_owned()],
        ));
        let domain = ["porn.test", "example.com", "x.xxx"][i % 3];
        let name = format!("h{i}.{domain}");
        blocked.push(name.clone());
        lookups.push((false, name.split('.').map(str::to_owned).collect()));
    }
    let (e, kept) = run(&lookups);
    assert_no_marker(&e, &kept, &blocked);
}

proptest! {
    #[test]
    fn any_mix_of_lookups(lookups in proptest::collection::vec(lookup(), 1..80)) {
        let blocked: Vec<String> = lookups
            .iter()
            .filter(|(allowed, _)| !allowed)
            .map(|(_, ls)| ls.join("."))
            .collect();
        let (e, kept) = run(&lookups);
        assert_no_marker(&e, &kept, &blocked);
    }
}

/// The same through a [`Session`], with every allowed query answered by
/// upstream: half the answers alias the allowed name to another allowed
/// name with the marker, half to a blocked one. Only the blocked targets
/// are counted, and once every answer is back the session holds nothing
/// with the marker either.
#[test]
fn answers_and_their_aliases_leave_no_allowed_name() {
    let upstream: std::net::SocketAddr = "192.168.1.1:53".parse().unwrap();
    let filter = Filter::new(categorizer(), &FilterConfig::default()).unwrap();
    let mut s = Session::new(Engine::new(filter), 7);
    s.set_upstreams([upstream]);
    let mut blocked = vec![];
    for i in 0..40 {
        let labels = [format!("h{i}"), MARKER.to_owned(), "net".to_owned()];
        let ls: Vec<&[u8]> = labels.iter().map(|l| l.as_bytes()).collect();
        let p = v4_packet(&query(0x0100, 1, &ls));
        let now = 1_800_000_000_000 + i;
        let Step::Send { payload, .. } = s.packet(&p, now, true) else {
            panic!("not forwarded");
        };
        let target = if i % 2 == 0 {
            format!("cdn{i}.{MARKER}.org")
        } else {
            let t = format!("c{i}.porn.test");
            blocked.push(t.clone());
            t
        };
        let mut answer = payload.clone();
        answer[2] |= 0x80;
        answer[7] = 1; // one answer record
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
        let mut rdata = vec![];
        for l in target.split('.') {
            rdata.push(l.len() as u8);
            rdata.extend_from_slice(l.as_bytes());
        }
        rdata.push(0);
        answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answer.extend_from_slice(&rdata);
        let rcode = match s.answer(upstream, &answer, false, now, true) {
            Step::Reply(p) => p[0][28 + 3] & 0x0f,
            other => panic!("no reply: {other:?}"),
        };
        assert_eq!(rcode, if i % 2 == 0 { 0 } else { 3 });
    }
    assert_eq!(s.pending(), 0);
    let shown = format!("{s:?}");
    assert!(!shown.contains(MARKER), "an allowed name is held: {shown}");
    let json = serde_json::to_string(s.engine().counters()).unwrap();
    assert!(!json.contains(MARKER), "{json}");
    let mut hosts: Vec<String> = s
        .engine()
        .counters()
        .summaries()
        .into_iter()
        .flat_map(|b| b.hosts.into_iter().map(|h| h.host))
        .collect();
    hosts.sort();
    blocked.sort();
    assert_eq!(hosts, blocked);
}
