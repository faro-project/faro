//! Daily (or weekly) reports, built **on the device** (§6) and uploaded encrypted.

use crate::body::{AppInfo, BlockedHost, BlurredThumbnail, Rating, Reason, TamperSignal};
use crate::encoding::{Canonical, Hash32, Signature};
use crate::event::EncryptedItem;
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const TAG_REPORT_HEADER: &str = "faro/report-header/v1";

/// Current [`ReportHeader::v`].
pub const REPORT_HEADER_VERSION: u16 = 1;

/// What the device was doing during a stretch of the timeline. Gaps in
/// monitoring are always explained by one of these states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityState {
    Active,
    Idle,
    Locked,
    Asleep,
    Paused,
    Off,
    /// Monitoring should have been running but was not (agent down, permission
    /// missing, capture failing). Always paired with a tamper/health entry.
    Unmonitored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineSpan {
    pub start_ms: i64,
    pub end_ms: i64,
    pub state: ActivityState,
    /// The OS account at the screen during this span (§3.6), so reports can
    /// group the timeline by account. `None` while nobody is (asleep, off,
    /// at the login window) or when the source does not know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatingCounts {
    pub clean: u32,
    pub low: u32,
    pub medium: u32,
    pub high: u32,
}

impl RatingCounts {
    pub fn add(&mut self, r: Rating) {
        let n = match r {
            Rating::Clean => &mut self.clean,
            Rating::Low => &mut self.low,
            Rating::Medium => &mut self.medium,
            Rating::High => &mut self.high,
        };
        *n = n.saturating_add(1);
    }

    /// All captures, saturating at `u32::MAX`. A decrypted report comes from
    /// a device the member controls, so its counts can be anything.
    pub fn total(&self) -> u32 {
        self.clean
            .saturating_add(self.low)
            .saturating_add(self.medium)
            .saturating_add(self.high)
    }
}

/// A flagged moment, referenced by the event seq that carried it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlaggedMoment {
    pub seq: u64,
    pub ts_ms: i64,
    pub rating: Rating,
    pub reasons: Vec<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<AppInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<BlurredThumbnail>,
    /// The member's own "false positive" note, visible to allies (§3.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_note: Option<String>,
    /// The OS account whose session was captured (§3.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthSummary {
    pub tamper: Vec<TamperRecord>,
    pub context: Vec<TamperRecord>,
    pub agent_restarts: u32,
    pub capture_failures: u32,
    /// Seconds the device was on and unlocked but not monitored.
    pub unmonitored_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperRecord {
    pub seq: Option<u64>,
    pub ts_ms: i64,
    pub signal: TamperSignal,
    /// The OS account the signal came from, if it concerns one session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountedItem {
    pub name: String,
    pub count: u32,
}

/// A stretch of time during which the iPhone's two layers were in one
/// state (docs/IOS.md §11). Time with no span is time the device did not
/// say (the phone was off, or Faro was not running).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionSpan {
    pub start_ms: i64,
    pub end_ms: i64,
    /// Whether Screen Time protection was on. `None` when the device could
    /// not tell (the tunnel can't always read the authorization).
    pub screen_time: Option<bool>,
    /// Whether the DNS filter was running.
    pub filter: bool,
}

/// Blocked lookups on one day, from the DNS filter's summaries. Adult and
/// gambling hosts are listed (the host only, never a path); everything else
/// is a count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedDay {
    pub day_start_ms: i64,
    pub by_category: BTreeMap<String, u32>,
    pub hosts: Vec<BlockedHost>,
    pub other_hosts: u32,
}

/// How often a Screen Time shield was shown or closed on one day. Counts
/// only, never app names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldDay {
    pub day_start_ms: i64,
    pub shown: u32,
    pub closed: u32,
}

/// A loosening that was asked for, applied or cancelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LooseningRecord {
    pub ts_ms: i64,
    pub text: String,
}

/// The iPhone part of a daily report (docs/IOS.md §11): present only in an
/// iPhone's report, which has no screen checks. Built on the device from
/// the same facts as the `blocked_summary`, `shield_summary` and
/// `settings_change` events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IosReport {
    /// When each layer was on, in order.
    pub protection: Vec<ProtectionSpan>,
    /// Blocked lookups, one entry per day with any.
    pub blocked: Vec<BlockedDay>,
    /// Blocked apps opened, one entry per day with any.
    pub shields: Vec<ShieldDay>,
    /// Loosenings asked for, applied or cancelled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub loosenings: Vec<LooseningRecord>,
}

/// The decrypted daily report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DailyReport {
    pub v: u16,
    pub device_id: DeviceId,
    pub device_name: String,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    /// Chain range this report summarizes (inclusive). `None` if no events.
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub timeline: Vec<TimelineSpan>,
    pub counts: RatingCounts,
    pub flagged: Vec<FlaggedMoment>,
    /// Off by default; the member opts in (§6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_domains: Option<Vec<CountedItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_apps: Option<Vec<CountedItem>>,
    /// iPhone only (docs/IOS.md §11). Older reports and other platforms
    /// leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ios: Option<IosReport>,
    pub health: HealthSummary,
}

/// Plaintext, device-signed metadata for an uploaded report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportHeader {
    pub v: u16,
    pub instance_id: InstanceId,
    pub member_id: UserId,
    pub device_id: DeviceId,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub body_hash: Hash32,
    pub body_len: u64,
}

impl ReportHeader {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let opt = |v: Option<u64>| v.map(|x| x.wrapping_add(1)).unwrap_or(0);
        Canonical::new(TAG_REPORT_HEADER)
            .u16(self.v)
            .str(self.instance_id.as_str())
            .str(self.member_id.as_str())
            .str(self.device_id.as_str())
            .i64(self.period_start_ms)
            .i64(self.period_end_ms)
            // Option<u64> encoded as 0 = None, n+1 = Some(n).
            .u64(opt(self.first_seq))
            .u64(opt(self.last_seq))
            .fixed(self.body_hash.as_bytes())
            .u64(self.body_len)
            .finish()
    }

    /// AAD for the report ciphertext.
    pub fn body_aad(&self) -> Vec<u8> {
        Canonical::new("faro/report-body/v1")
            .str(self.instance_id.as_str())
            .str(self.device_id.as_str())
            .i64(self.period_start_ms)
            .i64(self.period_end_ms)
            .finish()
    }
}

/// `POST /v1/reports` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportUpload {
    pub header: ReportHeader,
    pub sig: Signature,
    pub body: EncryptedItem,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_saturate_instead_of_overflowing() {
        // Counts in a decrypted report are whatever the device wrote; adding
        // them up used to overflow (a panic in debug builds, a wrong total
        // in release).
        let mut c: RatingCounts =
            serde_json::from_str(r#"{"clean":4294967295,"low":1,"medium":0,"high":2}"#).unwrap();
        assert_eq!(c.total(), u32::MAX);
        c.add(Rating::Clean);
        assert_eq!(c.clean, u32::MAX);
        c.add(Rating::Medium);
        assert_eq!((c.medium, c.total()), (1, u32::MAX));
    }
}
