//! Member-controlled settings and change tracking (ARCHITECTURE.md §3.4,
//! §3.7, §5.4, §6, §8).
//!
//! Every setting that affects what allies see is listed here, and every
//! change becomes a `settings_change` event (urgency `normal`) so allies are
//! told: a member cannot quietly lengthen the capture interval, lower alert
//! urgency, or change what the report shares.

use crate::scheduler::{MEAN_DEFAULT_SECS, MEAN_MAX_SECS, MEAN_MIN_SECS, SETTING_CAPTURE_MEAN};
use crate::urgency::UrgencyPolicy;
use faro_proto::body::{EventBody, SettingChange};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("capture mean {0}s is outside the allowed {MEAN_MIN_SECS}..={MEAN_MAX_SECS}s")]
    MeanOutOfRange(u32),
    #[error("retention override must be at least 1 day")]
    RetentionZero,
}

/// The member's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSettings", into = "RawSettings")]
pub struct MemberSettings {
    capture_mean_secs: u32,
    urgency: UrgencyPolicy,
    share_top_domains: bool,
    share_top_apps: bool,
    retention_days_override: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawSettings {
    capture_mean_secs: u32,
    urgency: UrgencyPolicy,
    #[serde(default)]
    share_top_domains: bool,
    #[serde(default)]
    share_top_apps: bool,
    #[serde(default)]
    retention_days_override: Option<u32>,
}

impl From<MemberSettings> for RawSettings {
    fn from(s: MemberSettings) -> Self {
        RawSettings {
            capture_mean_secs: s.capture_mean_secs,
            urgency: s.urgency,
            share_top_domains: s.share_top_domains,
            share_top_apps: s.share_top_apps,
            retention_days_override: s.retention_days_override,
        }
    }
}

impl TryFrom<RawSettings> for MemberSettings {
    type Error = SettingsError;
    fn try_from(r: RawSettings) -> Result<Self, Self::Error> {
        MemberSettings::new(
            r.capture_mean_secs,
            r.urgency,
            r.share_top_domains,
            r.share_top_apps,
            r.retention_days_override,
        )
    }
}

impl Default for MemberSettings {
    /// Defaults: 60 s mean, default urgency mapping, top lists off (§6),
    /// instance retention.
    fn default() -> Self {
        MemberSettings {
            capture_mean_secs: MEAN_DEFAULT_SECS,
            urgency: UrgencyPolicy::default(),
            share_top_domains: false,
            share_top_apps: false,
            retention_days_override: None,
        }
    }
}

const KEY_TOP_DOMAINS: &str = "share_top_domains";
const KEY_TOP_APPS: &str = "share_top_apps";
const KEY_RETENTION: &str = "retention_days_override";

impl MemberSettings {
    pub fn new(
        capture_mean_secs: u32,
        urgency: UrgencyPolicy,
        share_top_domains: bool,
        share_top_apps: bool,
        retention_days_override: Option<u32>,
    ) -> Result<Self, SettingsError> {
        if !(MEAN_MIN_SECS..=MEAN_MAX_SECS).contains(&capture_mean_secs) {
            return Err(SettingsError::MeanOutOfRange(capture_mean_secs));
        }
        if retention_days_override == Some(0) {
            return Err(SettingsError::RetentionZero);
        }
        Ok(MemberSettings {
            capture_mean_secs,
            urgency,
            share_top_domains,
            share_top_apps,
            retention_days_override,
        })
    }

    pub fn capture_mean_secs(&self) -> u32 {
        self.capture_mean_secs
    }
    pub fn urgency(&self) -> &UrgencyPolicy {
        &self.urgency
    }
    pub fn share_top_domains(&self) -> bool {
        self.share_top_domains
    }
    pub fn share_top_apps(&self) -> bool {
        self.share_top_apps
    }
    pub fn retention_days_override(&self) -> Option<u32> {
        self.retention_days_override
    }

    /// Retention actually applied: members may choose **shorter** retention
    /// than the instance, never longer (§8).
    pub fn effective_retention_days(&self, instance_days: u32) -> u32 {
        self.retention_days_override
            .map_or(instance_days, |d| d.min(instance_days))
    }

    pub fn report_options(&self) -> crate::report::ReportOptions {
        crate::report::ReportOptions {
            share_top_domains: self.share_top_domains,
            share_top_apps: self.share_top_apps,
        }
    }

    /// Every difference between `old` and `new`, in a stable order.
    pub fn diff(old: &MemberSettings, new: &MemberSettings) -> Vec<SettingChange> {
        let mut out = Vec::new();
        if old.capture_mean_secs != new.capture_mean_secs {
            out.push(SettingChange {
                key: SETTING_CAPTURE_MEAN.into(),
                old: Some(old.capture_mean_secs.to_string()),
                new: Some(new.capture_mean_secs.to_string()),
            });
        }
        out.extend(old.urgency.diff(&new.urgency));
        for (key, a, b) in [
            (
                KEY_TOP_DOMAINS,
                old.share_top_domains,
                new.share_top_domains,
            ),
            (KEY_TOP_APPS, old.share_top_apps, new.share_top_apps),
        ] {
            if a != b {
                out.push(SettingChange {
                    key: key.into(),
                    old: Some(a.to_string()),
                    new: Some(b.to_string()),
                });
            }
        }
        if old.retention_days_override != new.retention_days_override {
            out.push(SettingChange {
                key: KEY_RETENTION.into(),
                old: old.retention_days_override.map(|d| d.to_string()),
                new: new.retention_days_override.map(|d| d.to_string()),
            });
        }
        out
    }

    /// The `settings_change` body for a transition, or `None` if nothing changed.
    pub fn change_event(old: &MemberSettings, new: &MemberSettings) -> Option<EventBody> {
        let changes = Self::diff(old, new);
        (!changes.is_empty()).then_some(EventBody::SettingsChange { changes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_proto::Urgency;

    #[test]
    fn defaults_are_private() {
        let s = MemberSettings::default();
        assert_eq!(s.capture_mean_secs(), 60);
        assert!(!s.share_top_domains() && !s.share_top_apps());
        assert_eq!(s.report_options(), crate::report::ReportOptions::default());
    }

    #[test]
    fn validation() {
        let p = UrgencyPolicy::default();
        assert_eq!(
            MemberSettings::new(10, p, false, false, None),
            Err(SettingsError::MeanOutOfRange(10))
        );
        assert_eq!(
            MemberSettings::new(60, p, false, false, Some(0)),
            Err(SettingsError::RetentionZero)
        );
        let bad = r#"{"capture_mean_secs":1000,"urgency":{"low":"none","medium":"normal","high":"urgent"}}"#;
        assert!(serde_json::from_str::<MemberSettings>(bad).is_err());
        let good = r#"{"capture_mean_secs":90,"urgency":{"low":"none","medium":"normal","high":"urgent"}}"#;
        let s: MemberSettings = serde_json::from_str(good).unwrap();
        assert_eq!(s.capture_mean_secs(), 90);
        let back: MemberSettings =
            serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn diff_lists_every_change() {
        let a = MemberSettings::default();
        assert!(MemberSettings::diff(&a, &a).is_empty());
        assert!(MemberSettings::change_event(&a, &a).is_none());
        let b = MemberSettings::new(
            300,
            UrgencyPolicy::new(Urgency::Normal, Urgency::Urgent, Urgency::Urgent).unwrap(),
            true,
            true,
            Some(7),
        )
        .unwrap();
        let d = MemberSettings::diff(&a, &b);
        let keys: Vec<&str> = d.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "capture_mean_secs",
                "urgency.low",
                "urgency.medium",
                "share_top_domains",
                "share_top_apps",
                "retention_days_override"
            ]
        );
        assert_eq!(d[5].old, None);
        assert_eq!(d[5].new.as_deref(), Some("7"));
        let ev = MemberSettings::change_event(&a, &b).unwrap();
        assert_eq!(ev.kind(), faro_proto::EventKind::SettingsChange);
        // And the reverse direction is reported too.
        assert_eq!(MemberSettings::diff(&b, &a).len(), 6);
    }

    #[test]
    fn retention_only_shortens() {
        let s = MemberSettings::new(60, UrgencyPolicy::default(), false, false, Some(10)).unwrap();
        assert_eq!(s.effective_retention_days(30), 10);
        let s = MemberSettings::new(60, UrgencyPolicy::default(), false, false, Some(90)).unwrap();
        assert_eq!(s.effective_retention_days(30), 30);
        assert_eq!(MemberSettings::default().effective_retention_days(30), 30);
    }
}
