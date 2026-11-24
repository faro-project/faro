//! Daily report building and sealing (ARCHITECTURE.md §6).
//!
//! Reports are built **on the device** from what the service observed during
//! a period, then encrypted to the member and their verified allies. The
//! instance only ever sees the signed [`ReportHeader`] (period, chain range,
//! ciphertext commitment).
//!
//! Privacy defaults: top domains and top apps are only *collected* when the
//! member opted in; with the option off the builder does not even keep the
//! counts in memory.

use crate::recipients::RecipientSet;
use crate::urgency::{route_signal, SignalRoute};
use faro_crypto::Zeroizing;
use faro_crypto::{open_item, seal_item, verify_item, CryptoError, EncryptionKeypair, SigningKey};
use faro_proto::body::{AppInfo, FlagBody, Rating, TamperSignal};
use faro_proto::report::{
    ActivityState, CountedItem, DailyReport, FlaggedMoment, HealthSummary, RatingCounts,
    ReportHeader, ReportUpload, TamperRecord, TimelineSpan,
};
use faro_proto::{DeviceId, EncryptedItem, Hash32, InstanceId, SignPublicKey, UserId};
use std::collections::HashMap;

/// `DailyReport::v` / `ReportHeader::v` written by this crate.
pub const REPORT_VERSION: u16 = 1;
/// How many entries the optional top-domain / top-app lists carry.
pub const TOP_N: usize = 10;
/// At most this many flagged moments keep their blurred thumbnail in the
/// report (highest rating first, then earliest). Medium/high flags were
/// already delivered individually with their thumbnails; this keeps a busy
/// day's report within the 20–200 KB budget of §4.2.
pub const MAX_REPORT_THUMBNAILS: usize = 24;
/// Cap on tamper records kept per report, so a flapping signal cannot grow
/// the report without bound. Each one was also sent as its own urgent event.
pub const MAX_TAMPER_RECORDS: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("report period is empty or inverted ({start}..{end})")]
    BadPeriod { start: i64, end: i64 },
    #[error("recipient set is for {got_instance}/{got_member}, report is for {instance}/{member}")]
    RecipientMismatch {
        instance: InstanceId,
        member: UserId,
        got_instance: InstanceId,
        got_member: UserId,
    },
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("report header signature is invalid")]
    BadSignature,
    #[error("report body does not match the header commitment")]
    BodyMismatch,
    #[error("decrypted report does not match its header")]
    HeaderMismatch,
    #[error("unsupported report version {0}")]
    Version(u16),
}

/// What the member opted in to sharing (§6: off by default).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportOptions {
    pub share_top_domains: bool,
    pub share_top_apps: bool,
}

/// Accumulates one period's observations. See module docs.
#[derive(Debug, Clone)]
pub struct ReportBuilder {
    device_id: DeviceId,
    device_name: String,
    start_ms: i64,
    end_ms: i64,
    opts: ReportOptions,
    /// `(ts, seq-of-record, state)`; the record index breaks ties so the
    /// latest call wins for equal timestamps.
    transitions: Vec<(i64, u64, ActivityState)>,
    counts: RatingCounts,
    flagged: Vec<FlaggedMoment>,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    tamper: Vec<TamperRecord>,
    context: Vec<TamperRecord>,
    agent_restarts: u32,
    capture_failures: u32,
    domains: HashMap<String, u32>,
    apps: HashMap<String, u32>,
}

impl ReportBuilder {
    /// Start a report for `[period_start_ms, period_end_ms)`.
    pub fn new(
        device_id: DeviceId,
        device_name: impl Into<String>,
        period_start_ms: i64,
        period_end_ms: i64,
        opts: ReportOptions,
    ) -> Result<Self, ReportError> {
        if period_end_ms <= period_start_ms {
            return Err(ReportError::BadPeriod {
                start: period_start_ms,
                end: period_end_ms,
            });
        }
        Ok(ReportBuilder {
            device_id,
            device_name: device_name.into(),
            start_ms: period_start_ms,
            end_ms: period_end_ms,
            opts,
            transitions: Vec::new(),
            counts: RatingCounts::default(),
            flagged: Vec::new(),
            first_seq: None,
            last_seq: None,
            tamper: Vec::new(),
            context: Vec::new(),
            agent_restarts: 0,
            capture_failures: 0,
            domains: HashMap::new(),
            apps: HashMap::new(),
        })
    }

    pub fn period(&self) -> (i64, i64) {
        (self.start_ms, self.end_ms)
    }

    fn in_period(&self, ts: i64) -> bool {
        ts >= self.start_ms && ts < self.end_ms
    }

    /// Note that chain event `seq` belongs to this period (widens the
    /// report's `first_seq..=last_seq`).
    pub fn record_seq(&mut self, seq: u64) {
        self.first_seq = Some(self.first_seq.map_or(seq, |f| f.min(seq)));
        self.last_seq = Some(self.last_seq.map_or(seq, |l| l.max(seq)));
    }

    /// Count one capture result. Every capture, flagged or not, should be
    /// recorded here; [`ReportBuilder::record_flag`] does not count.
    /// Returns `false` (and ignores it) if `ts_ms` is outside the period.
    pub fn record_capture(&mut self, ts_ms: i64, rating: Rating) -> bool {
        if !self.in_period(ts_ms) {
            return false;
        }
        self.counts.add(rating);
        true
    }

    /// Add a flagged moment carried by chain event `seq`.
    pub fn record_flag(&mut self, seq: u64, ts_ms: i64, flag: &FlagBody) -> bool {
        if !self.in_period(ts_ms) {
            return false;
        }
        self.record_seq(seq);
        self.flagged.push(FlaggedMoment {
            seq,
            ts_ms,
            rating: flag.rating,
            reasons: flag.reasons.clone(),
            app: flag.app.clone(),
            thumbnail: flag.thumbnail.clone(),
            member_note: None,
        });
        true
    }

    /// From `ts_ms` on, the device was in `state`. Calls may arrive in any
    /// order; for equal timestamps the later call wins. A transition before
    /// the period start sets the state the period opens with.
    pub fn record_state(&mut self, ts_ms: i64, state: ActivityState) {
        if ts_ms >= self.end_ms {
            return;
        }
        let ord = self.transitions.len() as u64;
        self.transitions.push((ts_ms, ord, state));
    }

    /// Record an active tamper signal (also sent as an urgent event).
    pub fn record_tamper(&mut self, rec: TamperRecord) -> bool {
        if !self.in_period(rec.ts_ms) {
            return false;
        }
        if self.tamper.len() >= MAX_TAMPER_RECORDS {
            tracing::warn!("tamper record cap reached; dropping from report");
            return false;
        }
        if let Some(seq) = rec.seq {
            self.record_seq(seq);
        }
        self.tamper.push(rec);
        true
    }

    /// Record a context signal (VPN, VM, RDP, ...). Repeats of an identical
    /// signal are collapsed to the first occurrence: these are polled
    /// conditions, and allies need to know *that* it happened, not how often
    /// the poller saw it.
    pub fn record_context(&mut self, rec: TamperRecord) -> bool {
        if !self.in_period(rec.ts_ms) || self.context.iter().any(|c| c.signal == rec.signal) {
            return false;
        }
        self.context.push(rec);
        true
    }

    /// Route `signal` with [`route_signal`] and record it accordingly.
    pub fn record_signal(&mut self, seq: Option<u64>, ts_ms: i64, signal: TamperSignal) -> bool {
        let rec = TamperRecord { seq, ts_ms, signal };
        match route_signal(&rec.signal) {
            SignalRoute::TamperEvent => self.record_tamper(rec),
            SignalRoute::ReportContext => self.record_context(rec),
        }
    }

    pub fn record_agent_restart(&mut self) {
        self.agent_restarts = self.agent_restarts.saturating_add(1);
    }

    pub fn record_capture_failure(&mut self) {
        self.capture_failures = self.capture_failures.saturating_add(1);
    }

    /// Count a visit to `domain`. A no-op unless the member opted in.
    pub fn record_domain(&mut self, domain: &str) {
        if !self.opts.share_top_domains {
            return;
        }
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() || d.len() > 253 {
            return;
        }
        let c = self.domains.entry(d).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// Count time in `app`. A no-op unless the member opted in.
    pub fn record_app(&mut self, app: &AppInfo) {
        if !self.opts.share_top_apps {
            return;
        }
        let name = app
            .name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(&app.id)
            .trim()
            .to_owned();
        if name.is_empty() {
            return;
        }
        let c = self.apps.entry(name).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// The merged, contiguous timeline covering exactly the period.
    ///
    /// Time before the first recorded state is shown as [`ActivityState::Off`]:
    /// Faro was not running, and the instance's heartbeat history tells
    /// allies whether the machine was really off.
    pub fn timeline(&self) -> Vec<TimelineSpan> {
        build_timeline(self.start_ms, self.end_ms, &self.transitions)
    }

    /// Produce the report.
    pub fn finish(mut self) -> DailyReport {
        let timeline = self.timeline();
        let unmonitored_ms: i64 = timeline
            .iter()
            .filter(|s| s.state == ActivityState::Unmonitored)
            .map(|s| s.end_ms - s.start_ms)
            .sum();

        self.flagged.sort_by_key(|f| (f.ts_ms, f.seq));
        let mut by_priority: Vec<usize> = (0..self.flagged.len())
            .filter(|&i| self.flagged[i].thumbnail.is_some())
            .collect();
        by_priority.sort_by_key(|&i| {
            let f = &self.flagged[i];
            (std::cmp::Reverse(f.rating), f.ts_ms, f.seq)
        });
        for &i in by_priority.iter().skip(MAX_REPORT_THUMBNAILS) {
            self.flagged[i].thumbnail = None;
        }
        self.tamper.sort_by_key(|t| t.ts_ms);
        self.context.sort_by_key(|t| t.ts_ms);

        DailyReport {
            v: REPORT_VERSION,
            device_id: self.device_id,
            device_name: self.device_name,
            period_start_ms: self.start_ms,
            period_end_ms: self.end_ms,
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            timeline,
            counts: self.counts,
            flagged: self.flagged,
            top_domains: self.opts.share_top_domains.then(|| top_n(self.domains)),
            top_apps: self.opts.share_top_apps.then(|| top_n(self.apps)),
            health: HealthSummary {
                tamper: self.tamper,
                context: self.context,
                agent_restarts: self.agent_restarts,
                capture_failures: self.capture_failures,
                unmonitored_secs: u64::try_from(unmonitored_ms / 1000).unwrap_or(0),
            },
        }
    }
}

fn top_n(m: HashMap<String, u32>) -> Vec<CountedItem> {
    let mut v: Vec<CountedItem> = m
        .into_iter()
        .map(|(name, count)| CountedItem { name, count })
        .collect();
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(TOP_N);
    v
}

/// Turn point transitions into spans covering `[start, end)` exactly:
/// sorted, non-overlapping, contiguous, no empty spans, adjacent spans differ.
fn build_timeline(
    start: i64,
    end: i64,
    transitions: &[(i64, u64, ActivityState)],
) -> Vec<TimelineSpan> {
    let mut t: Vec<&(i64, u64, ActivityState)> = transitions.iter().collect();
    t.sort_by_key(|(ts, ord, _)| (*ts, *ord));
    let mut cur_state = t
        .iter()
        .rev()
        .find(|(ts, _, _)| *ts <= start)
        .map_or(ActivityState::Off, |(_, _, s)| *s);
    let mut cur_start = start;
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        let ts = t[i].0;
        // The last transition at this timestamp wins.
        let mut j = i;
        while j + 1 < t.len() && t[j + 1].0 == ts {
            j += 1;
        }
        let state = t[j].2;
        i = j + 1;
        if ts <= start || ts >= end || state == cur_state {
            continue;
        }
        out.push(TimelineSpan {
            start_ms: cur_start,
            end_ms: ts,
            state: cur_state,
        });
        cur_start = ts;
        cur_state = state;
    }
    out.push(TimelineSpan {
        start_ms: cur_start,
        end_ms: end,
        state: cur_state,
    });
    out
}

/// Encrypt `report` to the member and their verified allies and sign the
/// header with the device key.
///
/// The ciphertext's AAD is [`ReportHeader::body_aad`] (instance, device,
/// period), so the instance cannot move a report body onto another header.
pub fn seal_report(
    report: &DailyReport,
    instance_id: &InstanceId,
    member_id: &UserId,
    recipients: &RecipientSet,
    device_key: &SigningKey,
) -> Result<ReportUpload, ReportError> {
    if recipients.instance_id() != instance_id || recipients.member_id() != member_id {
        return Err(ReportError::RecipientMismatch {
            instance: instance_id.clone(),
            member: member_id.clone(),
            got_instance: recipients.instance_id().clone(),
            got_member: recipients.member_id().clone(),
        });
    }
    let mut header = ReportHeader {
        v: REPORT_VERSION,
        instance_id: instance_id.clone(),
        member_id: member_id.clone(),
        device_id: report.device_id.clone(),
        period_start_ms: report.period_start_ms,
        period_end_ms: report.period_end_ms,
        first_seq: report.first_seq,
        last_seq: report.last_seq,
        body_hash: Hash32::ZERO,
        body_len: 0,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(report)?);
    let body = seal_item(&plaintext, &header.body_aad(), &recipients.recipients())?;
    header.body_hash = body.body_hash();
    header.body_len = body.ciphertext.len() as u64;
    let sig = device_key.sign(&header);
    Ok(ReportUpload { header, sig, body })
}

/// Verify and decrypt a report as recipient `me` (member tray view, tests;
/// the ally web app implements the same steps in TypeScript).
pub fn open_report(
    upload: &ReportUpload,
    device_pubkey: &SignPublicKey,
    me: &UserId,
    keypair: &EncryptionKeypair,
) -> Result<DailyReport, ReportError> {
    let h = &upload.header;
    if h.v != REPORT_VERSION {
        return Err(ReportError::Version(h.v));
    }
    verify_item(device_pubkey, h, &upload.sig).map_err(|_| ReportError::BadSignature)?;
    let body: &EncryptedItem = &upload.body;
    if body.alg != EncryptedItem::ALG
        || body.body_hash() != h.body_hash
        || body.ciphertext.len() as u64 != h.body_len
    {
        return Err(ReportError::BodyMismatch);
    }
    let pt = open_item(body, &h.body_aad(), me, keypair)?;
    let report: DailyReport = serde_json::from_slice(&pt)?;
    if report.device_id != h.device_id
        || report.period_start_ms != h.period_start_ms
        || report.period_end_ms != h.period_end_ms
        || report.first_seq != h.first_seq
        || report.last_seq != h.last_seq
    {
        return Err(ReportError::HeaderMismatch);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recipients::tests::Fixture;
    use faro_proto::body::{BlurredThumbnail, Reason, ReasonSource};
    use proptest::prelude::*;

    const DAY: i64 = 86_400_000;
    const T0: i64 = 1_800_000_000_000;

    fn builder(opts: ReportOptions) -> ReportBuilder {
        ReportBuilder::new(DeviceId::new("dev_test"), "Laptop-X", T0, T0 + DAY, opts).unwrap()
    }

    fn flag(r: Rating, thumb: bool) -> FlagBody {
        FlagBody {
            rating: r,
            reasons: vec![Reason {
                source: ReasonSource::Domain,
                label: "adult".into(),
                score: None,
            }],
            app: Some(AppInfo {
                id: "com.example.browser".into(),
                name: Some("Browser".into()),
            }),
            window_title: Some("never in report".into()),
            browser: None,
            thumbnail: thumb.then(|| BlurredThumbnail {
                width: 320,
                height: 200,
                transform: "gauss12+pix8".into(),
                png: vec![1, 2, 3],
            }),
            burst: false,
        }
    }

    #[test]
    fn rejects_bad_period() {
        let d = DeviceId::new("dev_x");
        assert!(ReportBuilder::new(d.clone(), "x", 5, 5, ReportOptions::default()).is_err());
        assert!(ReportBuilder::new(d, "x", 6, 5, ReportOptions::default()).is_err());
    }

    #[test]
    fn timeline_basic() {
        let mut b = builder(ReportOptions::default());
        b.record_state(T0 - 1000, ActivityState::Active);
        b.record_state(T0 + 1000, ActivityState::Active); // no-op (same state)
        b.record_state(T0 + 5000, ActivityState::Locked);
        b.record_state(T0 + 3000, ActivityState::Idle); // out of order
        b.record_state(T0 + 9000, ActivityState::Active);
        b.record_state(T0 + 9000, ActivityState::Unmonitored); // same ts: later wins
        b.record_state(T0 + 12_000, ActivityState::Active);
        b.record_state(T0 + DAY + 5, ActivityState::Off); // beyond end: ignored
        let tl = b.clone().finish();
        let spans: Vec<_> = tl
            .timeline
            .iter()
            .map(|s| (s.start_ms - T0, s.end_ms - T0, s.state))
            .collect();
        assert_eq!(
            spans,
            vec![
                (0, 3000, ActivityState::Active),
                (3000, 5000, ActivityState::Idle),
                (5000, 9000, ActivityState::Locked),
                (9000, 12_000, ActivityState::Unmonitored),
                (12_000, DAY, ActivityState::Active),
            ]
        );
        assert_eq!(tl.health.unmonitored_secs, 3);
    }

    #[test]
    fn timeline_without_states_is_off() {
        let r = builder(ReportOptions::default()).finish();
        assert_eq!(
            r.timeline,
            vec![TimelineSpan {
                start_ms: T0,
                end_ms: T0 + DAY,
                state: ActivityState::Off
            }]
        );
    }

    #[test]
    fn counts_flags_and_seq_range() {
        let mut b = builder(ReportOptions::default());
        assert!(b.record_capture(T0, Rating::Clean));
        assert!(b.record_capture(T0 + 1, Rating::High));
        assert!(
            !b.record_capture(T0 + DAY, Rating::High),
            "end is exclusive"
        );
        assert!(!b.record_capture(T0 - 1, Rating::High));
        assert!(b.record_flag(7, T0 + 1, &flag(Rating::High, true)));
        assert!(!b.record_flag(99, T0 - 1, &flag(Rating::High, true)));
        b.record_seq(3);
        b.record_agent_restart();
        b.record_capture_failure();
        b.record_capture_failure();
        let r = b.finish();
        assert_eq!(r.counts.total(), 2);
        assert_eq!(r.counts.high, 1);
        assert_eq!(r.flagged.len(), 1);
        assert_eq!((r.first_seq, r.last_seq), (Some(3), Some(7)));
        assert_eq!(r.health.agent_restarts, 1);
        assert_eq!(r.health.capture_failures, 2);
        // Window titles never reach the report.
        assert!(!serde_json::to_string(&r)
            .unwrap()
            .contains("never in report"));
        // Opt-in lists are absent by default.
        assert!(r.top_domains.is_none() && r.top_apps.is_none());
    }

    #[test]
    fn signals_are_routed_and_context_deduped() {
        let mut b = builder(ReportOptions::default());
        b.record_signal(Some(4), T0 + 10, TamperSignal::WaylandTokenLost);
        b.record_signal(None, T0 + 20, TamperSignal::VpnActive);
        b.record_signal(None, T0 + 30, TamperSignal::VpnActive);
        b.record_signal(None, T0 + 40, TamperSignal::VirtualMachine);
        let r = b.finish();
        assert_eq!(r.health.tamper.len(), 1);
        assert_eq!(r.health.tamper[0].signal, TamperSignal::WaylandTokenLost);
        assert_eq!(r.health.context.len(), 2);
        assert_eq!(r.health.context[0].ts_ms, T0 + 20);
        assert_eq!(r.last_seq, Some(4));
    }

    #[test]
    fn top_lists_only_when_opted_in() {
        let mut off = builder(ReportOptions::default());
        off.record_domain("example.com");
        off.record_app(&AppInfo {
            id: "x".into(),
            name: None,
        });
        assert!(
            off.domains.is_empty() && off.apps.is_empty(),
            "not even kept in memory"
        );

        let mut b = builder(ReportOptions {
            share_top_domains: true,
            share_top_apps: true,
        });
        for i in 0..15 {
            for _ in 0..(i + 1) {
                b.record_domain(&format!("Site{i}.Example.COM."));
            }
        }
        b.record_domain("  ");
        b.record_app(&AppInfo {
            id: "com.a".into(),
            name: Some("Alpha".into()),
        });
        b.record_app(&AppInfo {
            id: "com.b".into(),
            name: None,
        });
        b.record_app(&AppInfo {
            id: "com.b".into(),
            name: Some(" ".into()),
        });
        let r = b.finish();
        let d = r.top_domains.unwrap();
        assert_eq!(d.len(), TOP_N);
        assert_eq!(d[0].name, "site14.example.com");
        assert_eq!(d[0].count, 15);
        assert!(d.windows(2).all(|w| w[0].count >= w[1].count));
        let a = r.top_apps.unwrap();
        assert_eq!(
            a[0],
            CountedItem {
                name: "com.b".into(),
                count: 2
            }
        );
        assert_eq!(
            a[1],
            CountedItem {
                name: "Alpha".into(),
                count: 1
            }
        );
    }

    #[test]
    fn thumbnails_capped_by_priority() {
        let mut b = builder(ReportOptions::default());
        for i in 0..40u64 {
            let r = if i % 2 == 0 {
                Rating::Medium
            } else {
                Rating::High
            };
            b.record_flag(i, T0 + i as i64, &flag(r, true));
        }
        let r = b.finish();
        assert_eq!(r.flagged.len(), 40, "moments are never dropped");
        let with: Vec<_> = r.flagged.iter().filter(|f| f.thumbnail.is_some()).collect();
        assert_eq!(with.len(), MAX_REPORT_THUMBNAILS);
        // All 20 high ones keep theirs, then the 4 earliest medium ones.
        assert_eq!(with.iter().filter(|f| f.rating == Rating::High).count(), 20);
        let meds: Vec<u64> = with
            .iter()
            .filter(|f| f.rating == Rating::Medium)
            .map(|f| f.seq)
            .collect();
        assert_eq!(meds, vec![0, 2, 4, 6]);
    }

    #[test]
    fn seal_open_roundtrip_for_member_and_allies() {
        let f = Fixture::new(2);
        let set = f.set();
        let dev_key = SigningKey::generate();
        let mut b = builder(ReportOptions::default());
        b.record_state(T0, ActivityState::Active);
        b.record_capture(T0 + 5, Rating::Medium);
        b.record_flag(1, T0 + 5, &flag(Rating::Medium, true));
        let report = b.finish();
        let up = seal_report(&report, &f.inst, &f.member, &set, &dev_key).unwrap();
        assert_eq!(up.body.envelopes.len(), 3);
        // The instance-visible JSON carries no plaintext.
        let wire = serde_json::to_string(&up).unwrap();
        assert!(!wire.contains("adult") && !wire.contains("Laptop-X"));

        let got = open_report(&up, &dev_key.public(), &f.member, &f.member_enc).unwrap();
        assert_eq!(got, report);
        for (id, k) in &f.allies {
            assert_eq!(open_report(&up, &dev_key.public(), id, k).unwrap(), report);
        }
        let eve = EncryptionKeypair::generate();
        assert!(open_report(&up, &dev_key.public(), &UserId::new("usr_eve"), &eve).is_err());

        // Tampering with the header breaks the signature.
        let mut t = up.clone();
        t.header.period_end_ms += 1;
        assert!(matches!(
            open_report(&t, &dev_key.public(), &f.member, &f.member_enc),
            Err(ReportError::BadSignature)
        ));
        // Another device's key does not verify.
        assert!(matches!(
            open_report(
                &up,
                &SigningKey::generate().public(),
                &f.member,
                &f.member_enc
            ),
            Err(ReportError::BadSignature)
        ));
        // Swapping in another report's body is caught by the commitment.
        let other = seal_report(&report, &f.inst, &f.member, &set, &dev_key).unwrap();
        let mut t = up.clone();
        t.body = other.body;
        assert!(matches!(
            open_report(&t, &dev_key.public(), &f.member, &f.member_enc),
            Err(ReportError::BodyMismatch)
        ));
    }

    #[test]
    fn seal_rejects_mismatched_recipients() {
        let f = Fixture::new(0);
        let r = builder(ReportOptions::default()).finish();
        assert!(matches!(
            seal_report(
                &r,
                &f.inst,
                &UserId::new("usr_x"),
                &f.set(),
                &SigningKey::generate()
            ),
            Err(ReportError::RecipientMismatch { .. })
        ));
        assert!(matches!(
            seal_report(
                &r,
                &InstanceId::new("inst_x"),
                &f.member,
                &f.set(),
                &SigningKey::generate()
            ),
            Err(ReportError::RecipientMismatch { .. })
        ));
    }

    fn state() -> impl Strategy<Value = ActivityState> {
        prop_oneof![
            Just(ActivityState::Active),
            Just(ActivityState::Idle),
            Just(ActivityState::Locked),
            Just(ActivityState::Asleep),
            Just(ActivityState::Paused),
            Just(ActivityState::Off),
            Just(ActivityState::Unmonitored),
        ]
    }

    proptest! {
        #[test]
        fn timeline_invariants(
            start in -1_000i64..1_000,
            len in 1i64..10_000,
            trans in proptest::collection::vec((-2_000i64..12_000, state()), 0..60),
        ) {
            let end = start + len;
            let mut b = ReportBuilder::new(DeviceId::new("dev_p"), "p", start, end, ReportOptions::default()).unwrap();
            for (ts, s) in &trans {
                b.record_state(*ts, *s);
            }
            let tl = b.timeline();
            prop_assert!(!tl.is_empty());
            prop_assert_eq!(tl[0].start_ms, start);
            prop_assert_eq!(tl.last().unwrap().end_ms, end);
            for s in &tl {
                prop_assert!(s.start_ms < s.end_ms, "empty span");
                prop_assert!(s.start_ms >= start && s.end_ms <= end);
            }
            for w in tl.windows(2) {
                prop_assert_eq!(w[0].end_ms, w[1].start_ms, "gap or overlap");
                prop_assert_ne!(w[0].state, w[1].state, "unmerged");
            }
            // Oracle: at any instant, the state is that of the last recorded
            // transition at or before it (later calls win ties), else Off.
            let oracle = |t: i64| -> ActivityState {
                trans.iter().enumerate()
                    .filter(|(_, (ts, _))| *ts <= t)
                    .max_by_key(|(i, (ts, _))| (*ts, *i))
                    .map_or(ActivityState::Off, |(_, (_, s))| *s)
            };
            let state_at = |t: i64| tl.iter().find(|s| s.start_ms <= t && t < s.end_ms).map(|s| s.state);
            let mut probes: Vec<i64> = trans.iter().flat_map(|(ts, _)| [*ts - 1, *ts]).collect();
            probes.extend([start, end - 1]);
            for t in probes.into_iter().filter(|t| *t >= start && *t < end) {
                prop_assert_eq!(state_at(t), Some(oracle(t)), "at {}", t);
            }
        }
    }
}
