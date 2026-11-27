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
use faro_proto::body::{AppInfo, BlockedHost, FlagBody, Rating, TamperSignal};
use faro_proto::keys::ManifestRef;
use faro_proto::report::{
    ActivityState, BlockedDay, CountedItem, DailyReport, FlaggedMoment, HealthSummary, IosReport,
    LooseningRecord, ProtectionSpan, RatingCounts, ReportHeader, ReportUpload, ShieldDay,
    TamperRecord, TimelineSpan,
};
use faro_proto::{DeviceId, EncryptedItem, Hash32, InstanceId, SignPublicKey, UserId};
use std::collections::{BTreeMap, HashMap};

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

/// One recorded state change: `(ts, record index, state, account)`.
type Transition = (i64, u64, ActivityState, Option<String>);

/// Accumulates one period's observations. See module docs.
#[derive(Debug, Clone)]
pub struct ReportBuilder {
    device_id: DeviceId,
    device_name: String,
    start_ms: i64,
    end_ms: i64,
    opts: ReportOptions,
    /// The record index breaks ties so the latest call wins for equal
    /// timestamps.
    transitions: Vec<Transition>,
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
    ios: Option<IosReport>,
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
            ios: None,
        })
    }

    /// Add the iPhone section (docs/IOS.md §11), built by
    /// [`IosReportBuilder`] for the same period.
    pub fn set_ios(&mut self, ios: IosReport) {
        self.ios = Some(ios);
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
            account: flag.account.clone(),
        });
        true
    }

    /// From `ts_ms` on, the device was in `state`. Calls may arrive in any
    /// order; for equal timestamps the later call wins. A transition before
    /// the period start sets the state the period opens with.
    pub fn record_state(&mut self, ts_ms: i64, state: ActivityState) {
        self.record_account_state(ts_ms, state, None);
    }

    /// Like [`record_state`](Self::record_state), with the OS account at the
    /// screen (§3.6). The same state under another account starts a new
    /// span, so the timeline can be grouped by account.
    pub fn record_account_state(
        &mut self,
        ts_ms: i64,
        state: ActivityState,
        account: Option<String>,
    ) {
        if ts_ms >= self.end_ms {
            return;
        }
        let ord = self.transitions.len() as u64;
        self.transitions.push((ts_ms, ord, state, account));
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
        if !self.in_period(rec.ts_ms)
            || self
                .context
                .iter()
                .any(|c| c.signal == rec.signal && c.account == rec.account)
        {
            return false;
        }
        self.context.push(rec);
        true
    }

    /// Route `signal` with [`route_signal`] and record it accordingly.
    /// `account` is the OS account it came from, if it concerns one session.
    pub fn record_signal(
        &mut self,
        seq: Option<u64>,
        ts_ms: i64,
        signal: TamperSignal,
        account: Option<String>,
    ) -> bool {
        let rec = TamperRecord {
            seq,
            ts_ms,
            signal,
            account,
        };
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
        // An iPhone blocks; it has no activity timeline. Its protection
        // timeline is in the iPhone section, and an `off` span here would
        // claim the phone was off.
        let timeline = if self.ios.is_some() {
            Vec::new()
        } else {
            self.timeline()
        };
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
            ios: self.ios,
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

const DAY_MS: i64 = 86_400_000;
/// A protection sample the tunnel records every 10 minutes covers at most
/// this long: if the next one is later, the time between is not claimed.
pub const PROTECTION_SAMPLE_COVER_MS: i64 = 25 * 60 * 1000;
/// Most hosts listed for one day. Lookups of the rest still count in the
/// day's categories and in `other_hosts`.
pub const MAX_REPORT_HOSTS_PER_DAY: usize = 500;
/// Cap on loosening lines kept per report.
pub const MAX_REPORT_LOOSENINGS: usize = 100;

/// Builds the iPhone section of a report (docs/IOS.md §11) from what the
/// device logged: the same blocked and shield summaries it sent as events,
/// protection samples from the tunnel, and loosenings. Pure: no clock, no
/// storage.
///
/// "Day" is the report's own day: entries start at the period's start and
/// step a day at a time, so a normal daily report has one entry of each.
#[derive(Debug, Clone)]
pub struct IosReportBuilder {
    start_ms: i64,
    end_ms: i64,
    samples: Vec<(i64, Option<bool>, bool)>,
    blocked: BTreeMap<i64, DayBlocked>,
    shields: BTreeMap<i64, (u32, u32)>,
    loosenings: Vec<LooseningRecord>,
}

#[derive(Debug, Clone, Default)]
struct DayBlocked {
    by_category: BTreeMap<String, u32>,
    hosts: BTreeMap<(String, String), u32>,
    other_hosts: u32,
}

impl IosReportBuilder {
    pub fn new(period_start_ms: i64, period_end_ms: i64) -> Self {
        IosReportBuilder {
            start_ms: period_start_ms,
            end_ms: period_end_ms,
            samples: Vec::new(),
            blocked: BTreeMap::new(),
            shields: BTreeMap::new(),
            loosenings: Vec::new(),
        }
    }

    fn in_period(&self, ts: i64) -> bool {
        ts >= self.start_ms && ts < self.end_ms
    }

    fn day_of(&self, ts: i64) -> i64 {
        self.start_ms + (ts - self.start_ms).div_euclid(DAY_MS) * DAY_MS
    }

    /// Add one blocked-lookup bucket (a `blocked_summary` body), filed under
    /// the day its bucket starts in. Returns whether it is in the period.
    pub fn record_blocked(
        &mut self,
        bucket_start: i64,
        by_category: &BTreeMap<String, u32>,
        hosts: &[BlockedHost],
        other_hosts: u32,
    ) -> bool {
        if !self.in_period(bucket_start) {
            return false;
        }
        let day = self.day_of(bucket_start);
        let d = self.blocked.entry(day).or_default();
        for (c, n) in by_category {
            let e = d.by_category.entry(c.clone()).or_insert(0);
            *e = e.saturating_add(*n);
        }
        d.other_hosts = d.other_hosts.saturating_add(other_hosts);
        for h in hosts {
            let e = d
                .hosts
                .entry((h.category.clone(), h.host.clone()))
                .or_insert(0);
            *e = e.saturating_add(h.count);
        }
        true
    }

    /// Add one shield bucket (a `shield_summary` body).
    pub fn record_shield(&mut self, bucket_start: i64, shown: u32, closed: u32) -> bool {
        if !self.in_period(bucket_start) {
            return false;
        }
        let e = self.shields.entry(self.day_of(bucket_start)).or_default();
        e.0 = e.0.saturating_add(shown);
        e.1 = e.1.saturating_add(closed);
        true
    }

    /// A protection sample: at `ts_ms` the filter was `filter` and Screen
    /// Time `screen_time` (`None` when not known). Samples before the period
    /// count too (the last one before it says how the period opened).
    pub fn record_protection(&mut self, ts_ms: i64, screen_time: Option<bool>, filter: bool) {
        if ts_ms < self.end_ms {
            self.samples.push((ts_ms, screen_time, filter));
        }
    }

    /// A loosening asked for, applied or cancelled, in words.
    pub fn record_loosening(&mut self, ts_ms: i64, text: &str) -> bool {
        if !self.in_period(ts_ms) || self.loosenings.len() >= MAX_REPORT_LOOSENINGS {
            return false;
        }
        self.loosenings.push(LooseningRecord {
            ts_ms,
            text: text.to_owned(),
        });
        true
    }

    /// The protection timeline. Each sample runs to the next one, but a
    /// sample that says the filter is on claims at most
    /// [`PROTECTION_SAMPLE_COVER_MS`]: after that the tunnel simply didn't
    /// say, and the report doesn't pretend it did. A sample that says it is
    /// off runs until the next, whatever the gap: that is the state it was
    /// left in. Spans are clipped to the period and merged.
    fn spans(&mut self) -> Vec<ProtectionSpan> {
        self.samples.sort_by_key(|s| s.0);
        let mut out: Vec<ProtectionSpan> = Vec::new();
        for (i, &(ts, screen_time, filter)) in self.samples.iter().enumerate() {
            let next = self.samples.get(i + 1).map(|s| s.0);
            let mut end = next.unwrap_or(self.end_ms).min(self.end_ms);
            if filter {
                end = end.min(ts.saturating_add(PROTECTION_SAMPLE_COVER_MS));
            }
            let start = ts.max(self.start_ms);
            if end <= start {
                continue;
            }
            match out.last_mut() {
                Some(l)
                    if l.end_ms == start && l.screen_time == screen_time && l.filter == filter =>
                {
                    l.end_ms = end;
                }
                _ => out.push(ProtectionSpan {
                    start_ms: start,
                    end_ms: end,
                    screen_time,
                    filter,
                }),
            }
        }
        out
    }

    pub fn finish(mut self) -> IosReport {
        let protection = self.spans();
        let blocked = self
            .blocked
            .into_iter()
            .map(|(day_start_ms, d)| {
                let mut hosts: Vec<BlockedHost> = d
                    .hosts
                    .into_iter()
                    .map(|((category, host), count)| BlockedHost {
                        host,
                        category,
                        count,
                    })
                    .collect();
                let mut other_hosts = d.other_hosts;
                if hosts.len() > MAX_REPORT_HOSTS_PER_DAY {
                    hosts.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.host.cmp(&b.host)));
                    for h in hosts.split_off(MAX_REPORT_HOSTS_PER_DAY) {
                        other_hosts = other_hosts.saturating_add(h.count);
                    }
                }
                hosts.sort_by(|a, b| {
                    (a.category.as_str(), b.count, a.host.as_str()).cmp(&(
                        b.category.as_str(),
                        a.count,
                        b.host.as_str(),
                    ))
                });
                BlockedDay {
                    day_start_ms,
                    by_category: d.by_category,
                    hosts,
                    other_hosts,
                }
            })
            .collect();
        let shields = self
            .shields
            .into_iter()
            .map(|(day_start_ms, (shown, closed))| ShieldDay {
                day_start_ms,
                shown,
                closed,
            })
            .collect();
        self.loosenings.sort_by_key(|l| l.ts_ms);
        IosReport {
            protection,
            blocked,
            shields,
            loosenings: self.loosenings,
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
/// sorted, non-overlapping, contiguous, no empty spans, adjacent spans differ
/// in state or account.
fn build_timeline(start: i64, end: i64, transitions: &[Transition]) -> Vec<TimelineSpan> {
    let mut t: Vec<&Transition> = transitions.iter().collect();
    t.sort_by_key(|(ts, ord, _, _)| (*ts, *ord));
    let (mut cur_state, mut cur_account) = t
        .iter()
        .rev()
        .find(|(ts, _, _, _)| *ts <= start)
        .map_or((ActivityState::Off, None), |(_, _, s, a)| (*s, a.clone()));
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
        let (state, account) = (t[j].2, &t[j].3);
        i = j + 1;
        if ts <= start || ts >= end || (state == cur_state && *account == cur_account) {
            continue;
        }
        out.push(TimelineSpan {
            start_ms: cur_start,
            end_ms: ts,
            state: cur_state,
            account: cur_account,
        });
        cur_start = ts;
        cur_state = state;
        cur_account = account.clone();
    }
    out.push(TimelineSpan {
        start_ms: cur_start,
        end_ms: end,
        state: cur_state,
        account: cur_account,
    });
    out
}

/// A report sealed by [`seal_report`], waiting to be queued with
/// [`Outbox::add_report`](crate::outbox::Outbox::add_report).
///
/// It carries the recipient manifest the body was sealed to, so the outbox
/// can refuse a report sealed to a set that is no longer the device's
/// checkpoint (for example one that still includes a removed ally). The
/// wire `ReportHeader` does not carry that ref yet, which is why it travels
/// alongside rather than inside the upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReport {
    upload: ReportUpload,
    manifest: ManifestRef,
}

impl SealedReport {
    /// The signed, encrypted upload.
    pub fn upload(&self) -> &ReportUpload {
        &self.upload
    }
    /// The recipient manifest the body was sealed to.
    pub fn manifest_ref(&self) -> ManifestRef {
        self.manifest
    }
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
) -> Result<SealedReport, ReportError> {
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
    Ok(SealedReport {
        upload: ReportUpload { header, sig, body },
        manifest: recipients.manifest_ref(),
    })
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
            account: None,
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
                state: ActivityState::Off,
                account: None,
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
    fn timeline_spans_carry_the_account() {
        let mut b = builder(ReportOptions::default());
        b.record_account_state(T0, ActivityState::Active, Some("alex".into()));
        b.record_account_state(T0 + 10, ActivityState::Active, Some("alex".into()));
        // Fast user switching: same state, another account.
        b.record_account_state(T0 + 20, ActivityState::Active, Some("guest".into()));
        b.record_state(T0 + 30, ActivityState::Off);
        let tl = b.timeline();
        let got: Vec<_> = tl
            .iter()
            .map(|s| (s.start_ms - T0, s.state, s.account.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                (0, ActivityState::Active, Some("alex")),
                (20, ActivityState::Active, Some("guest")),
                (30, ActivityState::Off, None),
            ]
        );
    }

    #[test]
    fn context_is_deduped_per_account() {
        let mut b = builder(ReportOptions::default());
        b.record_signal(None, T0 + 1, TamperSignal::VpnActive, Some("a".into()));
        b.record_signal(None, T0 + 2, TamperSignal::VpnActive, Some("a".into()));
        b.record_signal(None, T0 + 3, TamperSignal::VpnActive, Some("b".into()));
        let unmonitored = TamperSignal::UnmonitoredUserSession { user: "b".into() };
        b.record_signal(Some(9), T0 + 4, unmonitored.clone(), Some("b".into()));
        let r = b.finish();
        assert_eq!(r.health.context.len(), 2);
        assert_eq!(r.health.tamper.len(), 1);
        assert_eq!(r.health.tamper[0].signal, unmonitored);
        assert_eq!(r.health.tamper[0].account.as_deref(), Some("b"));
    }

    #[test]
    fn signals_are_routed_and_context_deduped() {
        let mut b = builder(ReportOptions::default());
        b.record_signal(Some(4), T0 + 10, TamperSignal::WaylandTokenLost, None);
        b.record_signal(None, T0 + 20, TamperSignal::VpnActive, None);
        b.record_signal(None, T0 + 30, TamperSignal::VpnActive, None);
        b.record_signal(None, T0 + 40, TamperSignal::VirtualMachine, None);
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
        let sealed = seal_report(&report, &f.inst, &f.member, &set, &dev_key).unwrap();
        assert_eq!(sealed.manifest_ref(), set.manifest_ref());
        let up = sealed.upload().clone();
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
        t.body = other.upload().body.clone();
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

    fn host(h: &str, c: &str, n: u32) -> BlockedHost {
        BlockedHost {
            host: h.into(),
            category: c.into(),
            count: n,
        }
    }

    #[test]
    fn ios_section_sums_buckets_per_day_and_lists_hosts() {
        let mut b = IosReportBuilder::new(T0, T0 + 2 * DAY);
        let cats = |a: u32, g: u32| -> BTreeMap<String, u32> {
            [("adult".to_owned(), a), ("gambling".to_owned(), g)].into()
        };
        assert!(b.record_blocked(
            T0 + 600_000,
            &cats(3, 1),
            &[host("a.test", "adult", 2), host("b.test", "adult", 1)],
            1
        ));
        assert!(b.record_blocked(
            T0 + 1_200_000,
            &cats(2, 0),
            &[host("a.test", "adult", 2), host("g.test", "gambling", 1)],
            0
        ));
        assert!(b.record_blocked(T0 + DAY + 5, &cats(1, 0), &[host("a.test", "adult", 1)], 0));
        assert!(!b.record_blocked(T0 - 1, &cats(9, 9), &[], 0), "before");
        assert!(
            !b.record_blocked(T0 + 2 * DAY, &cats(9, 9), &[], 0),
            "after"
        );
        assert!(b.record_shield(T0 + 5, 2, 1));
        assert!(b.record_shield(T0 + 700_000, 1, 1));
        assert!(!b.record_shield(T0 + 3 * DAY, 1, 1));
        assert!(b.record_loosening(T0 + 9, "Gambling will be unblocked"));
        let r = b.finish();
        assert_eq!(r.blocked.len(), 2);
        assert_eq!(r.blocked[0].day_start_ms, T0);
        assert_eq!(r.blocked[0].by_category["adult"], 5);
        assert_eq!(r.blocked[0].other_hosts, 1);
        let listed: Vec<(&str, u32)> = r.blocked[0]
            .hosts
            .iter()
            .map(|h| (h.host.as_str(), h.count))
            .collect();
        assert_eq!(listed, [("a.test", 4), ("b.test", 1), ("g.test", 1)]);
        assert_eq!(r.blocked[1].day_start_ms, T0 + DAY);
        assert_eq!(
            r.shields,
            [ShieldDay {
                day_start_ms: T0,
                shown: 3,
                closed: 2
            }]
        );
        assert_eq!(r.loosenings.len(), 1);
    }

    #[test]
    fn ios_hosts_over_the_cap_fold_into_other_hosts() {
        let mut b = IosReportBuilder::new(T0, T0 + DAY);
        let hosts: Vec<_> = (0..MAX_REPORT_HOSTS_PER_DAY + 3)
            .map(|i| host(&format!("h{i:04}.test"), "adult", 1))
            .collect();
        b.record_blocked(T0, &BTreeMap::new(), &hosts, 2);
        let d = &b.finish().blocked[0];
        assert_eq!(d.hosts.len(), MAX_REPORT_HOSTS_PER_DAY);
        assert_eq!(d.other_hosts, 5);
    }

    #[test]
    fn ios_protection_samples_become_spans_without_claiming_gaps() {
        let m = 60_000;
        let mut b = IosReportBuilder::new(T0, T0 + DAY);
        // Before the period: the filter was off and stays off until T0+10m.
        b.record_protection(T0 - 5 * m, Some(true), false);
        b.record_protection(T0 + 10 * m, Some(true), true);
        b.record_protection(T0 + 20 * m, Some(true), true);
        // Silence for hours: the last "on" claims only its cover time.
        b.record_protection(T0 + 5 * 3600 * 1000, None, true);
        b.record_protection(T0 + 5 * 3600 * 1000 + 10 * m, None, false);
        let r = b.finish().protection;
        let s = |a: i64, e: i64, st: Option<bool>, f: bool| ProtectionSpan {
            start_ms: a,
            end_ms: e,
            screen_time: st,
            filter: f,
        };
        let h5 = 5 * 3600 * 1000;
        assert_eq!(
            r,
            [
                s(T0, T0 + 10 * m, Some(true), false),
                s(T0 + 10 * m, T0 + 20 * m + 25 * m, Some(true), true),
                s(T0 + h5, T0 + h5 + 10 * m, None, true),
                s(T0 + h5 + 10 * m, T0 + DAY, None, false),
            ]
        );
    }

    #[test]
    fn the_ios_section_rides_in_the_report_and_older_reports_still_parse() {
        let mut rb = builder(ReportOptions::default());
        let mut ib = IosReportBuilder::new(T0, T0 + DAY);
        ib.record_shield(T0, 1, 0);
        rb.set_ios(ib.finish());
        let r = rb.finish();
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["ios"]["shields"][0]["shown"], 1);
        assert!(
            json["ios"].get("loosenings").is_none(),
            "left out when empty"
        );
        // A report without the section (any platform before this) parses.
        let mut old = json.clone();
        old.as_object_mut().unwrap().remove("ios");
        let back: DailyReport = serde_json::from_value(old).unwrap();
        assert!(back.ios.is_none());
        assert!(serde_json::to_value(&back).unwrap().get("ios").is_none());
    }

    /// The iPhone report and event bodies, as the device writes them. The web
    /// app's tests read the same file (`web/src/lib/feed/ios.test.ts`), so
    /// the shapes can't drift apart. After changing a shape, rewrite it with
    /// `FARO_UPDATE_FIXTURES=1 cargo test -p faro-core ios_fixture`.
    #[test]
    fn ios_fixture_is_what_the_device_writes() {
        use faro_proto::body::{
            EventBody, FilterOffCause, Reason, ReasonSource, SettingChange, TamperSignal,
        };
        use faro_proto::report::TamperRecord;
        let m = 60_000;
        let mut ib = IosReportBuilder::new(T0, T0 + DAY);
        ib.record_protection(T0, Some(true), true);
        ib.record_protection(T0 + 10 * m, Some(true), true);
        ib.record_protection(T0 + 20 * m, None, false);
        ib.record_blocked(
            T0 + 10 * m,
            &[("adult".to_owned(), 5), ("gambling".to_owned(), 2)].into(),
            &[
                host("a.example", "adult", 4),
                host("b.example", "adult", 1),
                host("casino.example", "gambling", 2),
            ],
            3,
        );
        ib.record_blocked(
            T0 + 20 * m,
            &[("adult".to_owned(), 1), ("encrypted_dns".to_owned(), 1)].into(),
            &[host("a.example", "adult", 1)],
            0,
        );
        ib.record_shield(T0 + 15 * m, 3, 2);
        ib.record_loosening(
            T0 + 30 * m,
            "Asked for (after a delay of 24 hours): blocking.gambling: on → off",
        );
        let dns_flag = FlagBody {
            rating: Rating::Medium,
            reasons: vec![Reason {
                source: ReasonSource::Dns,
                label: "dns:adult ×6, 4 hosts, 3 min, screen on".into(),
                score: None,
            }],
            app: None,
            window_title: None,
            browser: None,
            thumbnail: None,
            burst: true,
            account: None,
        };
        let mut rb = builder(ReportOptions::default());
        rb.record_flag(7, T0 + 12 * m, &dns_flag);
        rb.record_tamper(TamperRecord {
            seq: Some(9),
            ts_ms: T0 + 20 * m,
            signal: TamperSignal::FilterOff {
                cause: FilterOffCause::VpnDisconnected,
            },
            account: None,
        });
        rb.record_context(TamperRecord {
            seq: None,
            ts_ms: T0 + 40 * m,
            signal: TamperSignal::DohDropped,
            account: None,
        });
        rb.record_seq(11);
        rb.set_ios(ib.finish());
        let report = serde_json::to_value(rb.finish()).unwrap();
        let events = serde_json::json!([
            serde_json::to_value(EventBody::BlockedSummary {
                bucket_start: T0 + 10 * m,
                bucket_secs: 600,
                by_category: [("adult".to_owned(), 5), ("gambling".to_owned(), 2)].into(),
                hosts: vec![
                    host("a.example", "adult", 4),
                    host("b.example", "adult", 1),
                    host("casino.example", "gambling", 2)
                ],
                other_hosts: 3,
            })
            .unwrap(),
            serde_json::to_value(EventBody::ShieldSummary {
                bucket_start: T0 + 5 * m,
                bucket_secs: 600,
                shown: 3,
                closed: 2,
            })
            .unwrap(),
            serde_json::to_value(EventBody::Flag(dns_flag)).unwrap(),
            serde_json::to_value(EventBody::SettingsChange {
                changes: vec![SettingChange {
                    key: "blocking.gambling".into(),
                    old: Some("on".into()),
                    new: Some("off".into()),
                }],
                requested_at: Some(T0),
                takes_effect_at: Some(T0 + DAY),
                cancelled_at: None,
                delay_secs: Some(86_400),
            })
            .unwrap(),
        ]);
        let fixture = serde_json::json!({ "report": report, "events": events });

        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ios-reports.json");
        if std::env::var_os("FARO_UPDATE_FIXTURES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let text = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
            std::fs::write(&path, text).unwrap();
        }
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect(
                "tests/data/ios-reports.json is missing: FARO_UPDATE_FIXTURES=1 cargo test -p faro-core ios_fixture",
            ))
            .unwrap();
        assert_eq!(
            on_disk, fixture,
            "the iPhone fixture is out of date: FARO_UPDATE_FIXTURES=1 cargo test -p faro-core ios_fixture"
        );
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
