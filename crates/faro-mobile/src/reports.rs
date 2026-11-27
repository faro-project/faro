//! What allies see of an iPhone beyond single events (docs/IOS.md §7.5,
//! §11): summaries without double counting, burst flags, and the daily
//! report with its iPhone section, all built on the device.
//!
//! ## Where the numbers come from
//!
//! * **Blocked lookups.** The packet tunnel counts blocked lookups in
//!   10-minute buckets (`faro_dnsfilter::Counters`) and, when a bucket has
//!   ended, [`DnsFilter::flush_summaries`](crate::DnsFilter) hands it to
//!   [`FaroCore::record_blocked_summary_once`]. A bucket is reported once
//!   however often it is offered: its start is recorded in a ledger in the
//!   database (inside one immediate transaction, so two processes can't both
//!   win) before the event is appended, and released again if the append
//!   fails. A crash between the two can lose a bucket, never repeat one.
//! * **Shield counts.** The shield extensions only ever add to two counter
//!   files in the app group (`shield_shown`, `shield_closed`). Whoever
//!   flushes passes the files' current totals to
//!   [`FaroCore::record_shield_totals`], which swaps the stored baseline for
//!   them in one transaction and reports the difference. A process that
//!   comes second sees no difference. The count says how often, never which
//!   app.
//! * **Bursts.** `blocked_burst` candidates become `flag` events rated
//!   `medium` with one `dns` reason ([`FaroCore::record_burst_flag`]). The
//!   header urgency is the member's policy for `medium` (urgent by default,
//!   ARCHITECTURE.md §14), floored like any flag. The reason holds counts,
//!   never hosts.
//! * **The daily report.** Every fact above is also logged here, with the
//!   tunnel's protection samples and any loosenings, in
//!   `mobile_report_log`. [`FaroCore::queue_daily_report`] builds the last
//!   complete day from it with `faro_core::ReportBuilder` and
//!   `IosReportBuilder`, seals it to the verified recipients and queues it
//!   for upload. The log is on the device only, and is dropped after a few
//!   days.

use crate::core::{lock, FaroCore};
use crate::error::FaroError;
use crate::store::{BLOCKED_REPORTED, REPORT_QUEUED_THROUGH, SHIELD_BASELINE};
use crate::types::{BlockedSummaryRecord, PendingLoosening};
use faro_core::urgency::UrgencyPolicy;
use faro_core::{seal_report, IosReportBuilder, OutboxError, ReportBuilder, ReportOptions};
use faro_dnsfilter::BurstCandidate;
use faro_proto::body::{
    BlockedHost, EventBody, FlagBody, Rating, Reason, ReasonSource, SettingChange,
};
use faro_proto::report::TamperRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DAY_MS: i64 = 86_400_000;
/// Bucket starts remembered as reported: two days of 10-minute buckets,
/// and then some.
const MAX_REPORTED_BUCKETS: usize = 300;
/// How long facts are kept after the day they belong to.
const KEEP_FACTS_MS: i64 = 3 * DAY_MS;
/// The longest stretch one shield event may claim.
const MAX_SHIELD_SPAN_SECS: i64 = 86_400;

/// What the daily report is built from. Only counts and the words the
/// events already carry; nothing the events don't.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Fact {
    Blocked {
        seq: u64,
        by_category: BTreeMap<String, u32>,
        hosts: Vec<BlockedHost>,
        other_hosts: u32,
    },
    Shield {
        seq: u64,
        shown: u32,
        closed: u32,
    },
    Protection {
        screen_time: Option<bool>,
        filter: bool,
    },
    Flag {
        seq: u64,
        rating: Rating,
        reasons: Vec<Reason>,
    },
    Loosening {
        text: String,
    },
    Tamper {
        record: TamperRecord,
    },
}

/// The shield counters' totals when they were last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ShieldBaseline {
    shown: u64,
    closed: u64,
    at_ms: i64,
}

/// What a flush hands back for the shields.
struct ShieldClaim {
    shown: u64,
    closed: u64,
    from_ms: i64,
    previous: Option<ShieldBaseline>,
}

fn delta(total: u64, baseline: u64) -> u64 {
    // A total below the baseline means the counter file started over.
    if total >= baseline {
        total - baseline
    } else {
        total
    }
}

fn sat32(n: u64) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

impl FaroCore {
    /// Log a fact for the daily report. Best effort: the event it mirrors
    /// is already in the chain, and a full report is not worth failing for.
    pub(crate) fn log_fact(&self, ts_ms: i64, fact: &Fact) {
        let result = serde_json::to_string(fact)
            .map_err(FaroError::storage)
            .and_then(|json| lock(&self.store).add_fact(ts_ms, &json));
        if let Err(e) = result {
            tracing::warn!("report log: {e}");
        }
    }

    /// Mirror a summary event into the report log.
    pub(crate) fn log_summary(&self, body: &EventBody, seq: u64) {
        match body {
            EventBody::BlockedSummary {
                bucket_start,
                by_category,
                hosts,
                other_hosts,
                ..
            } => self.log_fact(
                *bucket_start,
                &Fact::Blocked {
                    seq,
                    by_category: by_category.clone(),
                    hosts: hosts.clone(),
                    other_hosts: *other_hosts,
                },
            ),
            EventBody::ShieldSummary {
                bucket_start,
                shown,
                closed,
                ..
            } => self.log_fact(
                *bucket_start,
                &Fact::Shield {
                    seq,
                    shown: *shown,
                    closed: *closed,
                },
            ),
            _ => {}
        }
    }

    /// Mirror a tamper event into the report log.
    pub(crate) fn log_tamper(&self, record: TamperRecord) {
        self.log_fact(record.ts_ms, &Fact::Tamper { record });
    }

    /// Mirror a pending loosening (asked for, applied or cancelled) into the
    /// report log, in words.
    pub(crate) fn log_loosening(&self, changes: &[SettingChange], p: &PendingLoosening) {
        let now = self.clock.wall_ms();
        let what = changes
            .iter()
            .map(|c| {
                format!(
                    "{}: {} → {}",
                    c.key.replace('_', " "),
                    c.old.as_deref().unwrap_or("unset"),
                    c.new.as_deref().unwrap_or("unset")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let text = if p.cancelled_at_ms.is_some() {
            format!("Cancelled before it took effect: {what}")
        } else if p.takes_effect_at_ms.is_some_and(|t| t <= now) {
            format!("Took effect: {what}")
        } else {
            let delay = p
                .delay_secs
                .map(|s| format!(" (after a delay of {} hours)", s / 3600))
                .unwrap_or_default();
            format!("Asked for{delay}: {what}")
        };
        self.log_fact(now, &Fact::Loosening { text });
    }

    /// Record a burst of blocked lookups as a `flag` event rated `medium`
    /// with the one reason `dns:adult ×6, 4 hosts, 3 min, screen on`. Counts
    /// only; the hosts are in the summaries, not here. Returns its `seq`.
    pub fn record_burst_flag(&self, burst: &BurstCandidate) -> Result<u64, FaroError> {
        let reasons = vec![Reason {
            source: ReasonSource::Dns,
            label: burst.to_string(),
            score: None,
        }];
        let body = EventBody::Flag(FlagBody {
            rating: Rating::Medium,
            reasons: reasons.clone(),
            app: None,
            window_title: None,
            browser: None,
            thumbnail: None,
            burst: true,
            account: None,
        });
        let urgency = UrgencyPolicy::default().urgency_for(&body);
        let seq = self.append(&body, urgency)?;
        self.log_fact(
            self.clock.wall_ms(),
            &Fact::Flag {
                seq,
                rating: Rating::Medium,
                reasons,
            },
        );
        Ok(seq)
    }

    fn build_and_queue(&self, start_ms: i64, end_ms: i64) -> Result<bool, FaroError> {
        let e = self.enrollment_record()?;
        let facts = lock(&self.store).facts_between(start_ms - DAY_MS, end_ms)?;
        let mut rb = ReportBuilder::new(
            e.device_id.clone(),
            e.device_name.clone(),
            start_ms,
            end_ms,
            ReportOptions::default(),
        )
        .map_err(|e| FaroError::invalid(e.to_string()))?;
        let mut ib = IosReportBuilder::new(start_ms, end_ms);
        for (ts, json) in facts {
            let Ok(fact) = serde_json::from_str::<Fact>(&json) else {
                continue;
            };
            match fact {
                Fact::Blocked {
                    seq,
                    by_category,
                    hosts,
                    other_hosts,
                } => {
                    if ib.record_blocked(ts, &by_category, &hosts, other_hosts) {
                        rb.record_seq(seq);
                    }
                }
                Fact::Shield { seq, shown, closed } => {
                    if ib.record_shield(ts, shown, closed) {
                        rb.record_seq(seq);
                    }
                }
                Fact::Protection {
                    screen_time,
                    filter,
                } => {
                    ib.record_protection(ts, screen_time, filter);
                }
                Fact::Flag {
                    seq,
                    rating,
                    reasons,
                } => {
                    rb.record_flag(
                        seq,
                        ts,
                        &FlagBody {
                            rating,
                            reasons,
                            app: None,
                            window_title: None,
                            browser: None,
                            thumbnail: None,
                            burst: true,
                            account: None,
                        },
                    );
                }
                Fact::Loosening { text } => {
                    ib.record_loosening(ts, &text);
                }
                Fact::Tamper { record } => {
                    rb.record_tamper(record);
                }
            }
        }
        for rec in self.context_since(start_ms)? {
            rb.record_context(rec);
        }
        rb.set_ios(ib.finish());
        let report = rb.finish();
        let key = self.device_key()?;
        let mut queued = false;
        for _ in 0..2 {
            let set = self
                .with_outbox_raw(&e, |o| {
                    o.current_recipients(&e.member_sign_pubkey, &e.member_id)
                })?
                .ok_or(FaroError::NotApproved)?;
            let sealed = seal_report(&report, &e.instance_id, &e.member_id, &set, &key)
                .map_err(|err| FaroError::storage(err.to_string()))?;
            match self.with_outbox_raw(&e, |o| o.add_report(&sealed)) {
                Ok(_) => {
                    queued = true;
                    break;
                }
                // The recipients changed while sealing: seal again.
                Err(OutboxError::StaleRecipients { .. }) => {}
                Err(err) => return Err(err.into()),
            }
        }
        if !queued {
            return Err(FaroError::storage("the recipients kept changing"));
        }
        lock(&self.store).prune_facts(start_ms - KEEP_FACTS_MS)?;
        Ok(true)
    }
}

#[uniffi::export]
impl FaroCore {
    /// Record one 10-minute bucket of blocked lookups, once. A bucket whose
    /// start was reported before (by this process or another, before or
    /// after a restart) is skipped and `None` is returned; otherwise the
    /// `seq` of its `blocked_summary` event. Fails like
    /// [`FaroCore::record_blocked_summary`], and then the bucket is not
    /// marked, so the next flush tries it again.
    pub fn record_blocked_summary_once(
        &self,
        summary: BlockedSummaryRecord,
    ) -> Result<Option<u64>, FaroError> {
        let start = summary.bucket_start_ms;
        let first = lock(&self.store).update(BLOCKED_REPORTED, |old: Option<Vec<i64>>| {
            let mut seen = old.unwrap_or_default();
            if seen.contains(&start) {
                return (None, false);
            }
            seen.push(start);
            seen.sort_unstable();
            if seen.len() > MAX_REPORTED_BUCKETS {
                seen.drain(..seen.len() - MAX_REPORTED_BUCKETS);
            }
            (Some(seen), true)
        })?;
        if !first {
            return Ok(None);
        }
        match self.record_blocked_summary(summary) {
            Ok(seq) => Ok(Some(seq)),
            Err(e) => {
                let released =
                    lock(&self.store).update(BLOCKED_REPORTED, |old: Option<Vec<i64>>| {
                        let mut seen = old.unwrap_or_default();
                        seen.retain(|s| *s != start);
                        (Some(seen), ())
                    });
                if let Err(e) = released {
                    tracing::warn!("could not release bucket {start}: {e}");
                }
                Err(e)
            }
        }
    }

    /// Record how often the shields were shown and closed since the last
    /// call, from the counters' current totals (`shield_shown` and
    /// `shield_closed` in the app group). Returns the event's `seq`, or
    /// `None` if nothing changed. The event covers the time since the last
    /// call (at most a day).
    pub fn record_shield_totals(
        &self,
        shown_total: u64,
        closed_total: u64,
    ) -> Result<Option<u64>, FaroError> {
        let now = self.clock.wall_ms();
        let claim = lock(&self.store).update(SHIELD_BASELINE, |old: Option<ShieldBaseline>| {
            let (shown, closed, from_ms) = match old {
                Some(b) => (
                    delta(shown_total, b.shown),
                    delta(closed_total, b.closed),
                    b.at_ms,
                ),
                None => (shown_total, closed_total, now),
            };
            (
                Some(ShieldBaseline {
                    shown: shown_total,
                    closed: closed_total,
                    at_ms: now,
                }),
                ShieldClaim {
                    shown,
                    closed,
                    from_ms,
                    previous: old,
                },
            )
        })?;
        if claim.shown == 0 && claim.closed == 0 {
            return Ok(None);
        }
        let secs = ((now - claim.from_ms) / 1000).clamp(1, MAX_SHIELD_SPAN_SECS);
        let record = crate::types::ShieldSummaryRecord {
            bucket_start_ms: now - secs * 1000,
            bucket_secs: secs as u64,
            shown: sat32(claim.shown),
            closed: sat32(claim.closed),
        };
        match self.record_shield_summary(record) {
            Ok(seq) => Ok(Some(seq)),
            Err(e) => {
                // Put the baseline back, so the counts are tried again.
                let back = claim.previous.unwrap_or(ShieldBaseline {
                    shown: 0,
                    closed: 0,
                    at_ms: claim.from_ms,
                });
                let restored = lock(&self.store)
                    .update(SHIELD_BASELINE, |_: Option<ShieldBaseline>| {
                        (Some(back), ())
                    });
                if let Err(e) = restored {
                    tracing::warn!("could not restore the shield baseline: {e}");
                }
                Err(e)
            }
        }
    }

    /// Note what the phone's protection looks like now, for the report's
    /// protection timeline. `filter_on` is whether the DNS filter is
    /// running; `screen_time_on` whether Screen Time protection stands, or
    /// `None` when the caller can't tell (the report then says so rather
    /// than guessing). Call it from the tunnel at each flush, and with
    /// `filter_on` false when the tunnel stops.
    pub fn record_protection_sample(
        &self,
        screen_time_on: Option<bool>,
        filter_on: bool,
    ) -> Result<(), FaroError> {
        if lock(&self.store)
            .get::<faro_client::enroll::Enrollment>(crate::store::ENROLLMENT)?
            .is_none()
        {
            return Ok(());
        }
        self.log_fact(
            self.clock.wall_ms(),
            &Fact::Protection {
                screen_time: screen_time_on,
                filter: filter_on,
            },
        );
        Ok(())
    }

    /// Build, seal and queue the report for the last complete local day,
    /// once. `utc_offset_secs` is the phone's offset from UTC now, which
    /// puts the day boundaries at local midnight (a day that is 23 or 25
    /// hours long is off by the hour; the report states its own period).
    /// Returns whether a report was queued: `false` if that day was done
    /// already (by either process), or the device was enrolled after it.
    /// Fails with `NotApproved` until the member has approved the device,
    /// and the day is then tried again at the next call.
    pub fn queue_daily_report(&self, now_ms: i64, utc_offset_secs: i32) -> Result<bool, FaroError> {
        let off = i64::from(utc_offset_secs) * 1000;
        let end = (now_ms + off).div_euclid(DAY_MS) * DAY_MS - off;
        let start = end - DAY_MS;
        if self.enrollment_record()?.enrolled_at_ms >= end {
            return Ok(false);
        }
        let previous = lock(&self.store).update(REPORT_QUEUED_THROUGH, |old: Option<i64>| {
            if old.is_some_and(|o| o >= end) {
                (None, Err(()))
            } else {
                (Some(end), Ok(old))
            }
        })?;
        let Ok(previous) = previous else {
            return Ok(false);
        };
        let result = self.build_and_queue(start, end);
        if result.is_err() {
            let back = previous.unwrap_or(0);
            let restored =
                lock(&self.store).update(REPORT_QUEUED_THROUGH, |_: Option<i64>| (Some(back), ()));
            if let Err(e) = restored {
                tracing::warn!("could not release the report for {end}: {e}");
            }
        }
        result
    }
}
