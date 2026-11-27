//! Measure the DNS filter against a real domain bundle: heap held in the
//! steady state, allocations and time per query, and the counters at their
//! bound. See docs/DEVELOPMENT.md "The DNS filter".
//!
//! ```sh
//! # Build the bundle first ("The domain category bundle"), then:
//! cargo run --release -p faro-dnsfilter --example dnsfilter-measure -- \
//!     target/domains/domains.manifest.json target/domains/sources
//! ```
//!
//! The blocked names are drawn from the downloaded source lists (with a
//! random subdomain on half of them), the allowed ones are made up under
//! common TLDs. A project tool, never part of a shipped client. It counts
//! heap with a wrapping global allocator, which needs `unsafe`; the library
//! itself has none.

use faro_dnsfilter::counters::{MAX_BUCKETS, MAX_HOSTS_PER_BUCKET, MAX_HOSTS_TOTAL};
use faro_dnsfilter::packet::build_udp;
use faro_dnsfilter::{Action, BlockCategory, Counters, Engine, Filter, FilterConfig};
use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards every call to the system allocator unchanged and only
// updates counters on the side.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size() as isize, Relaxed) + layout.size() as isize;
            PEAK.fetch_max(live, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size() as isize, Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            let delta = new_size as isize - layout.size() as isize;
            let live = LIVE.fetch_add(delta, Relaxed) + delta;
            PEAK.fetch_max(live, Relaxed);
            ALLOCS.fetch_add(1, Relaxed);
        }
        p
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn live() -> isize {
    LIVE.load(Relaxed)
}

fn kib(b: isize) -> String {
    format!("{:.1} KiB", b as f64 / 1024.0)
}

/// A small deterministic generator (xorshift), so runs are comparable.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn label(&mut self) -> String {
        let len = 3 + (self.next() % 10) as usize;
        (0..len)
            .map(|_| (b'a' + (self.next() % 26) as u8) as char)
            .collect()
    }
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for l in name.split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    // An EDNS OPT record, as iOS sends.
    m.extend_from_slice(&[0, 0, 0x29, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    m
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    sorted[((sorted.len() - 1) as f64 * p) as usize]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let manifest: PathBuf = args
        .next()
        .map_or_else(|| "target/domains/domains.manifest.json".into(), Into::into);
    let sources: PathBuf = args
        .next()
        .map_or_else(|| "target/domains/sources".into(), Into::into);

    // Blocked names from the source lists, read before measuring.
    let mut listed = vec![];
    for entry in std::fs::read_dir(&sources)? {
        let text = std::fs::read_to_string(entry?.path())?;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let mut t = line.split_whitespace();
            if let (Some("0.0.0.0"), Some(h)) = (t.next(), t.next()) {
                if h != "0.0.0.0" && h.len() < 200 {
                    listed.push(h.to_ascii_lowercase());
                }
            }
        }
    }

    // The steady state: the bundle and the filter.
    let before = live();
    let started = Instant::now();
    let loaded = faro_detect::load_domains(&manifest)?;
    let load_time = started.elapsed();
    let after_load = live();
    let domains = loaded.categorizer.len();
    let version = loaded.manifest.version.clone();
    let bundle_bytes = loaded.manifest.bundle.bytes;
    drop(loaded.manifest);
    let config = FilterConfig {
        categories: [faro_detect::Category::Gambling].into(),
        instance_host: Some("faro.example.org".into()),
        ..Default::default()
    };
    let filter = Filter::new(loaded.categorizer, &config)?;
    let mut engine = Engine::new(filter);
    let steady = live() - before;

    // The queries: half blocked, half allowed.
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let n = 20_000;
    let tlds = ["com", "net", "org", "io", "co.uk", "de"];
    let mut names = Vec::with_capacity(n);
    for i in 0..n {
        let name = if i % 2 == 0 {
            let h = &listed[(rng.next() % listed.len() as u64) as usize];
            if rng.next().is_multiple_of(2) {
                format!("{}.{h}", rng.label())
            } else {
                h.clone()
            }
        } else {
            let tld = tlds[(rng.next() % tlds.len() as u64) as usize];
            format!("{}.{}.{tld}", rng.label(), rng.label())
        };
        names.push(name);
    }
    let client: SocketAddr = "172.16.0.2:50000".parse()?;
    let server: SocketAddr = "198.18.0.53:53".parse()?;
    let packets: Vec<Vec<u8>> = names
        .iter()
        .enumerate()
        .map(|(i, name)| build_udp(client, server, &dns_query(i as u16, name)))
        .collect::<Result<_, _>>()?;

    // Warm up, then time each packet.
    let t0 = 1_800_000_000_000i64;
    for p in &packets {
        std::hint::black_box(engine.handle_packet(p, t0, false));
    }
    let filter = engine.filter().clone();
    drop(engine);
    let mut engine = Engine::new(filter);
    // Screen on, so the burst detector does its share too.
    let (mut blocked, mut allowed) = (Vec::with_capacity(n), Vec::with_capacity(n));
    let mut bursts = 0;
    let base = live();
    PEAK.store(base, Relaxed);
    let allocs_before = ALLOCS.load(Relaxed);
    for (i, p) in packets.iter().enumerate() {
        let s = Instant::now();
        let h = engine.handle_packet(p, t0 + i as i64, true);
        let ns = s.elapsed().as_nanos();
        bursts += usize::from(h.burst.is_some());
        match h.action {
            Action::Reply(r) => {
                blocked.push(ns);
                std::hint::black_box(r);
            }
            Action::Forward { .. } => allowed.push(ns),
            Action::Drop(r) => panic!("dropped {}: {r}", names[i]),
        }
    }
    let allocs = ALLOCS.load(Relaxed) - allocs_before;
    let peak_during = PEAK.load(Relaxed) - base;

    // Decide only, without packets.
    let f = engine.filter().clone();
    let s = Instant::now();
    for name in &names {
        std::hint::black_box(f.decide(name, 1));
    }
    let decide_ns = s.elapsed().as_nanos() / n as u128;

    // The counters at their bound: every bucket full of the longest hosts.
    let before_counters = live();
    let mut c = Counters::new();
    let long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    for b in 0..MAX_BUCKETS as i64 {
        for h in 0..MAX_HOSTS_PER_BUCKET {
            let host = format!("{h:03}{}", &long[3..]);
            c.record(
                t0 + b * 600_000,
                &host,
                BlockCategory::Bundle(faro_detect::Category::Adult),
            );
        }
    }
    let counters_max = live() - before_counters;
    let json_max = serde_json::to_vec(&c)?.len();

    blocked.sort_unstable();
    allowed.sort_unstable();
    let mean = |v: &[u128]| v.iter().sum::<u128>() / v.len() as u128;
    println!("bundle {version}: {domains} domains, {bundle_bytes} bytes, loaded in {load_time:?}");
    println!(
        "heap after load_domains (bundle and manifest): {}",
        kib(after_load - before)
    );
    println!(
        "steady-state heap (bundle + filter + engine): {}",
        kib(steady)
    );
    println!(
        "queries: {n} ({} blocked, {} allowed)",
        blocked.len(),
        allowed.len()
    );
    println!(
        "handle_packet, blocked: mean {} ns, p50 {} ns, p99 {} ns",
        mean(&blocked),
        percentile(&blocked, 0.5),
        percentile(&blocked, 0.99)
    );
    println!(
        "handle_packet, allowed: mean {} ns, p50 {} ns, p99 {} ns",
        mean(&allowed),
        percentile(&allowed, 0.5),
        percentile(&allowed, 0.99)
    );
    println!("Filter::decide alone: mean {decide_ns} ns");
    println!(
        "allocations per query: {:.2}; bursts: {bursts}",
        allocs as f64 / n as f64
    );
    println!(
        "peak heap growth during the run (one bucket of counters, the burst window, one reply): {}",
        kib(peak_during)
    );
    println!(
        "counters at their bound ({MAX_BUCKETS} buckets, {MAX_HOSTS_TOTAL} hosts of 253 bytes): {} heap, {} KiB as JSON",
        kib(counters_max),
        json_max / 1024
    );
    Ok(())
}
