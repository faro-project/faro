//! Daily (or weekly) reports, built **on the device** (§6) and uploaded encrypted.

use crate::body::{AppInfo, BlurredThumbnail, Rating, Reason, TamperSignal};
use crate::encoding::{Canonical, Hash32, Signature};
use crate::event::EncryptedItem;
use crate::ids::{DeviceId, InstanceId, UserId};
use serde::{Deserialize, Serialize};

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
        match r {
            Rating::Clean => self.clean += 1,
            Rating::Low => self.low += 1,
            Rating::Medium => self.medium += 1,
            Rating::High => self.high += 1,
        }
    }

    pub fn total(&self) -> u32 {
        self.clean + self.low + self.medium + self.high
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountedItem {
    pub name: String,
    pub count: u32,
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
