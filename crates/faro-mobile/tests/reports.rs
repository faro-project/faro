//! What allies see of an iPhone beyond single events (docs/IOS.md §7.5,
//! §11): blocked and shield summaries without double counting, burst flags,
//! development thresholds, and the daily report with its iPhone section.

mod support;

use faro_core::{open_event_body, Outbox};
use faro_detect::attribution::Attribution;
use faro_detect::{
    Category, DomainCategorizerBuilder, DomainSource, DomainsBundleInfo, DomainsManifest,
    DOMAINS_MANIFEST_FORMAT,
};
use faro_dnsfilter::packet::build_udp;
use faro_mobile::{
    BlockedHostRecord, BlockedSummaryRecord, DnsFilter, FaroError, PendingLoosening,
    SettingChangeRecord, Tamper,
};
use faro_proto::body::{EventBody, ReasonSource};
use faro_proto::report::DailyReport;
use faro_proto::{DeviceId, EventKind, Urgency};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use support::{approved_phone, blocking, Phone, World};

const T0: i64 = 1_800_000_000_000; // a multiple of 10 minutes
const BUCKET: i64 = 600_000;
const DAY: i64 = 86_400_000;

fn summary(start: i64, host: &str, n: u32) -> BlockedSummaryRecord {
    BlockedSummaryRecord {
        bucket_start_ms: start,
        bucket_secs: 600,
        by_category: [("adult".to_owned(), n)].into(),
        hosts: vec![BlockedHostRecord {
            host: host.into(),
            category: "adult".into(),
            count: n,
        }],
        other_hosts: 0,
    }
}

/// A packaged domain list that calls each of `adult` adult.
fn packaged(dir: &Path, adult: &[&str]) -> PathBuf {
    let mut b = DomainCategorizerBuilder::new();
    for d in adult {
        b.add_domain(d, Category::Adult).unwrap();
    }
    let bytes = b.build().unwrap().to_bytes();
    std::fs::write(dir.join("domains.bin"), &bytes).unwrap();
    let m = DomainsManifest {
        format: DOMAINS_MANIFEST_FORMAT.into(),
        notice: "Compiled from the lists below.".into(),
        version: "1.0.0".into(),
        bundle: DomainsBundleInfo {
            file: "domains.bin".into(),
            bytes: bytes.len() as u64,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
        },
        domains: adult.len(),
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
            lines: adult.len(),
            domains: adult.len(),
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

fn packet(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let client: SocketAddr = "10.0.0.2:53000".parse().unwrap();
    build_udp(client, "198.18.0.53:53".parse().unwrap(), &q).unwrap()
}

fn open(e: &faro_proto::SignedEvent, w: &World) -> EventBody {
    open_event_body(e, &w.member, &w.member_keys.enc).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bucket_is_recorded_once_across_flushes_processes_and_restarts() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    // A second process on the same app group.
    let other = phone.core();

    // The tunnel's saved counters: two ended buckets and an open one.
    let counters = serde_json::to_string(&[
        bucket(T0, "a.example", 3),
        bucket(T0 + BUCKET, "b.example", 2),
        bucket(T0 + 2 * BUCKET, "c.example", 1),
    ])
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), &["a.example"])
        .to_string_lossy()
        .into_owned();
    let now = T0 + 2 * BUCKET + 5_000;
    let make =
        |json: &str| DnsFilter::new(Some(manifest.clone()), None, Some(json.to_owned())).unwrap();

    let f1 = make(&counters);
    let (c, f) = (core.clone(), f1.clone());
    let n = blocking(move || f.flush_summaries(c, now).unwrap()).await;
    assert_eq!(n, 2, "the open bucket waits");
    assert_eq!(
        f1.status().counter_buckets,
        1,
        "recorded buckets are dropped"
    );

    // Flushed again: nothing new.
    let (c, f) = (core.clone(), f1.clone());
    assert_eq!(
        blocking(move || f.flush_summaries(c, now).unwrap()).await,
        0
    );

    // The tunnel died before saving its counters: a restart offers the same
    // buckets again, through another process's core, and none is repeated.
    let f2 = make(&counters);
    let (c, f) = (other.clone(), f2.clone());
    assert_eq!(
        blocking(move || f.flush_summaries(c, now).unwrap()).await,
        0
    );
    assert_eq!(f2.status().counter_buckets, 1);

    // The next bucket closes and is recorded.
    let (c, f) = (core.clone(), f2.clone());
    let later = now + BUCKET;
    assert_eq!(
        blocking(move || f.flush_summaries(c, later).unwrap()).await,
        1
    );

    let c = core.clone();
    let pending = blocking(move || c.pending_events(10).unwrap()).await;
    assert_eq!(pending.len(), 3);
    for e in &pending {
        assert_eq!(
            (e.header.kind, e.header.urgency),
            (EventKind::Capture, Urgency::None)
        );
    }
    let starts: Vec<i64> = pending
        .iter()
        .map(|e| match open(e, &w) {
            EventBody::BlockedSummary { bucket_start, .. } => bucket_start,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(starts, [T0, T0 + BUCKET, T0 + 2 * BUCKET]);
}

fn bucket(start: i64, host: &str, n: u32) -> faro_dnsfilter::BlockedSummary {
    faro_dnsfilter::BlockedSummary {
        bucket_start: start,
        bucket_secs: 600,
        by_category: [("adult".to_owned(), n)].into(),
        hosts: vec![faro_dnsfilter::HostCount {
            host: host.into(),
            category: "adult".into(),
            count: n,
        }],
        other_hosts: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_record_leaves_the_bucket_for_the_next_flush() {
    let w = World::new().await;
    let phone = Phone::new();
    let core = phone.core(); // not enrolled: nothing can be recorded
    let c = core.clone();
    let r = blocking(move || c.record_blocked_summary_once(summary(T0, "a.example", 1))).await;
    assert!(matches!(r, Err(FaroError::NotEnrolled)), "{r:?}");
    let _ = w;
    // Enrolled and approved later, the same bucket is accepted: the failed
    // attempt did not mark it as reported.
    let w2 = World::new().await;
    let phone2 = Phone::new();
    let (core2, _) = approved_phone(&w2, &phone2).await;
    let c = core2.clone();
    let first = blocking(move || c.record_blocked_summary_once(summary(T0, "a.example", 1))).await;
    assert_eq!(first.unwrap(), Some(0));
    let c = core2.clone();
    let again = blocking(move || c.record_blocked_summary_once(summary(T0, "a.example", 1))).await;
    assert_eq!(again.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shield_totals_report_only_what_is_new() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let other = phone.core();

    let c = core.clone();
    let seqs = blocking(move || {
        vec![
            c.record_shield_totals(2, 1).unwrap(),
            // Nothing new, from this process or another.
            c.record_shield_totals(2, 1).unwrap(),
            other.record_shield_totals(2, 1).unwrap(),
            c.record_shield_totals(5, 1).unwrap(),
            // The counter files started over (a reinstall): the totals are new.
            c.record_shield_totals(1, 0).unwrap(),
        ]
    })
    .await;
    assert_eq!(seqs, [Some(0), None, None, Some(1), Some(2)]);

    let c = core.clone();
    let pending = blocking(move || c.pending_events(10).unwrap()).await;
    let counts: Vec<(u32, u32)> = pending
        .iter()
        .map(|e| {
            assert_eq!(
                (e.header.kind, e.header.urgency),
                (EventKind::Capture, Urgency::None)
            );
            match open(e, &w) {
                EventBody::ShieldSummary {
                    shown,
                    closed,
                    bucket_secs,
                    ..
                } => {
                    assert!((1..=86_400).contains(&bucket_secs));
                    (shown, closed)
                }
                other => panic!("{other:?}"),
            }
        })
        .collect();
    assert_eq!(counts, [(2, 1), (3, 0), (1, 0)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bursts_become_medium_flags_with_the_dns_reason() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), &["a.one.test", "b.two.test", "c.three.test"])
        .to_string_lossy()
        .into_owned();
    let f = DnsFilter::new(Some(manifest), None, None).unwrap();
    let names = [
        "a.one.test",
        "b.two.test",
        "c.three.test",
        "a.one.test",
        "b.two.test",
        "c.three.test",
    ];
    // Five lookups are no burst; the sixth is. Allowed names count for
    // nothing.
    let f2 = f.clone();
    for (i, n) in names.iter().enumerate() {
        f2.handle_packet(packet(n), T0 + i as i64 * 30_000, true);
        f2.handle_packet(packet("allowed.example"), T0 + i as i64 * 30_000, true);
    }
    let (c, f3) = (core.clone(), f.clone());
    let recorded = blocking(move || {
        (
            f3.flush_bursts(c.clone()).unwrap(),
            f3.flush_bursts(c).unwrap(),
        )
    })
    .await;
    assert_eq!(recorded, (1, 0), "once, then nothing left");

    let c = core.clone();
    let pending = blocking(move || c.pending_events(10).unwrap()).await;
    assert_eq!(pending.len(), 1);
    // Rated medium, which the default policy maps to urgent.
    assert_eq!(
        (pending[0].header.kind, pending[0].header.urgency),
        (EventKind::Flag, Urgency::Urgent)
    );
    let EventBody::Flag(flag) = open(&pending[0], &w) else {
        panic!("not a flag");
    };
    assert_eq!(flag.rating, faro_proto::body::Rating::Medium);
    assert!(flag.burst);
    assert_eq!(flag.reasons.len(), 1);
    assert_eq!(flag.reasons[0].source, ReasonSource::Dns);
    assert_eq!(
        flag.reasons[0].label,
        "dns:adult ×6, 3 hosts, 3 min, screen on"
    );
    // Counts only: no host, and nothing about the allowed name.
    let json = serde_json::to_string(&flag).unwrap();
    for leak in ["one.test", "two.test", "three.test", "allowed"] {
        assert!(!json.contains(leak), "{json}");
    }
    // The ally opens it too.
    assert!(open_event_body(&pending[0], &w.ally.id, &w.ally.keys.enc).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_waits_while_the_keys_are_locked() {
    // An unenrolled core can't record: the burst stays in the filter.
    let phone = Phone::new();
    let core = phone.core();
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), &["a.one.test", "b.two.test", "c.three.test"])
        .to_string_lossy()
        .into_owned();
    let f = DnsFilter::new(Some(manifest), None, None).unwrap();
    for (i, n) in ["a.one.test", "b.two.test", "c.three.test"]
        .iter()
        .cycle()
        .take(6)
        .enumerate()
    {
        f.handle_packet(packet(n), T0 + i as i64 * 1000, true);
    }
    let (c, f2) = (core, f.clone());
    let r = blocking(move || f2.flush_bursts(c)).await;
    assert!(matches!(r, Err(FaroError::NotEnrolled)), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn development_thresholds_only_ever_lower_and_only_in_a_dev_build() {
    let f = DnsFilter::new(None, None, None).unwrap();
    assert_eq!(f.status().thresholds, "default");
    // Raising, or anything unknown, is refused in every build.
    for bad in [
        r#"{"min_lookups": 7}"#,
        r#"{"cooldown_secs": 601}"#,
        r#"{"min_domains": 0}"#,
        r#"{"window_secs": 10}"#,
        "not json",
    ] {
        let r = f.set_dev_thresholds(Some(bad.into()));
        assert!(
            matches!(r, Err(FaroError::InvalidArgument { .. })),
            "{bad}: {r:?}"
        );
    }
    let lowered = r#"{"min_lookups": 2, "min_domains": 1, "cooldown_secs": 30}"#;
    let said = f.set_dev_thresholds(Some(lowered.into())).unwrap();
    if cfg!(feature = "dev") {
        assert_eq!(
            said,
            "LOWERED FOR TESTING (min_lookups 2, min_domains 1, cooldown_secs 30)"
        );
    } else {
        assert_eq!(said, "ignored (release build)");
    }
    assert_eq!(f.status().thresholds, said);
    assert_eq!(f.set_dev_thresholds(None).unwrap(), "default");
}

#[cfg(feature = "dev")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lowered_thresholds_make_a_two_lookup_burst() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = packaged(dir.path(), &["a.one.test"])
        .to_string_lossy()
        .into_owned();
    let f = DnsFilter::new(Some(manifest), None, None).unwrap();
    f.set_dev_thresholds(Some(r#"{"min_lookups": 2, "min_domains": 1}"#.into()))
        .unwrap();
    f.handle_packet(packet("a.one.test"), T0, true);
    f.handle_packet(packet("a.one.test"), T0 + 1000, true);
    assert_eq!(f.status().thresholds.starts_with("LOWERED"), true);
    // A burst is waiting: a core that can't record shows it is there.
    let phone = Phone::new();
    let core = phone.core();
    let r = blocking(move || f.flush_bursts(core)).await;
    assert!(matches!(r, Err(FaroError::NotEnrolled)), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daily_report_carries_the_iphone_section_and_uploads() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, device_id) = approved_phone(&w, &phone).await;

    let c = core.clone();
    // The real clock stamps protection samples and loosenings, so nothing
    // here falls in the past day: build the report for the day that holds
    // the real time instead, by asking at the start of the next one.
    let now_real = faro_now();
    let tomorrow = (now_real / DAY + 1) * DAY + 3_600_000;
    blocking(move || {
        c.record_blocked_summary(summary(now_real / BUCKET * BUCKET, "a.example", 3))
            .unwrap();
        c.record_shield_totals(4, 2).unwrap();
        c.record_shield_totals(6, 2).unwrap();
        c.record_protection_sample(None, true).unwrap();
        c.record_tamper(Tamper::ScreenTimeRevoked).unwrap();
        c.record_settings_change(
            vec![SettingChangeRecord {
                key: "blocking.gambling".into(),
                old_value: Some("on".into()),
                new_value: Some("off".into()),
            }],
            Some(PendingLoosening {
                requested_at_ms: Some(now_real),
                takes_effect_at_ms: Some(now_real + DAY),
                cancelled_at_ms: None,
                delay_secs: Some(86_400),
            }),
        )
        .unwrap();
        // A tightening carries no pending loosening and is not listed.
        c.record_settings_change(
            vec![SettingChangeRecord {
                key: "blocking.adult".into(),
                old_value: Some("off".into()),
                new_value: Some("on".into()),
            }],
            None,
        )
        .unwrap();
    })
    .await;

    let c = core.clone();
    let (queued, again) = blocking(move || {
        (
            c.queue_daily_report(tomorrow, 0).unwrap(),
            c.queue_daily_report(tomorrow + 1000, 0).unwrap(),
        )
    })
    .await;
    assert!(queued && !again, "a day is queued once");

    // What is queued opens for the member and the ally, and is the iPhone's.
    let (dir, instance) = (phone.dir.clone(), w.t.instance_id());
    let dev = DeviceId::new(&device_id);
    let report = blocking(move || {
        let o = Outbox::open(&dir, &instance, &dev).unwrap();
        let mut reports = o.pending_reports().unwrap();
        assert_eq!(reports.len(), 1);
        reports.remove(0).upload
    })
    .await;
    let h = &report.header;
    let body =
        faro_crypto::open_item(&report.body, &h.body_aad(), &w.member, &w.member_keys.enc).unwrap();
    assert!(
        faro_crypto::open_item(&report.body, &h.body_aad(), &w.ally.id, &w.ally.keys.enc).is_ok()
    );
    let r: DailyReport = serde_json::from_slice(&body).unwrap();
    assert_eq!(r.device_name, support::DEVICE_NAME);
    assert_eq!(
        (r.period_start_ms, r.period_end_ms),
        (tomorrow / DAY * DAY - DAY, tomorrow / DAY * DAY)
    );
    let ios = r.ios.expect("an iPhone report has the section");
    assert_eq!(ios.blocked.len(), 1);
    assert_eq!(ios.blocked[0].by_category["adult"], 3);
    assert_eq!(ios.blocked[0].hosts[0].host, "a.example");
    assert_eq!(ios.shields.len(), 1);
    assert_eq!((ios.shields[0].shown, ios.shields[0].closed), (6, 2));
    assert_eq!(ios.protection.len(), 1);
    assert_eq!(
        (ios.protection[0].screen_time, ios.protection[0].filter),
        (None, true)
    );
    assert_eq!(ios.loosenings.len(), 1);
    assert!(ios.loosenings[0]
        .text
        .starts_with("Asked for (after a delay of 24 hours): blocking.gambling: on → off"));
    assert_eq!(r.health.tamper.len(), 1);
    assert!(r.timeline.is_empty(), "an iPhone has no activity timeline");
    assert!(r.first_seq.is_some());

    // It uploads, and the instance accepts it.
    let c = core.clone();
    let up = blocking(move || c.upload_pending().unwrap()).await;
    assert_eq!(up.reports_uploaded, 1, "{:?}", up.warnings);
}

fn faro_now() -> i64 {
    use faro_core::Clock;
    faro_core::SystemClock::new().wall_ms()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_report_for_a_day_before_enrollment() {
    let w = World::new().await;
    let phone = Phone::new();
    let (core, _) = approved_phone(&w, &phone).await;
    let now = faro_now();
    // The day that just ended began before this device existed.
    let c = core.clone();
    assert!(!blocking(move || c.queue_daily_report(now - DAY, 0).unwrap()).await);
}
