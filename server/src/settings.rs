//! Admin-editable instance settings (§4.3, §8): registration mode and domain
//! allowlist, retention windows, the liveness grace period and the update
//! channel.
//!
//! **Precedence.** `faro.toml` / `FARO_*` provide the initial values. Once an
//! admin changes a setting through `PATCH /admin/api/settings`, the changed
//! fields are stored in `instance.settings_json` and take precedence over the
//! config file from then on (the web console is the primary admin interface
//! for non-expert operators; silently reverting their change on the next
//! restart would be worse). Fields never changed in the console keep
//! following the config file. `faro-server doctor` prints the effective
//! values.
//!
//! Settings are read on every request that needs them through
//! [`crate::AppState::settings`], so a change takes effect immediately
//! without a restart.

use crate::config::{
    Config, ConfigError, LivenessConfig, RegistrationConfig, RegistrationMode, RetentionConfig,
};
use serde::{Deserialize, Serialize};

/// The effective, validated settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceSettings {
    pub registration: RegistrationConfig,
    pub retention: RetentionConfig,
    pub liveness: LivenessConfig,
    pub updates: UpdateSettings,
}

/// The admin-editable part of [`crate::config::UpdatesConfig`]. Where
/// updates come from (root of trust, upstream) stays in the config file:
/// it is a deployment decision, not a console one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateSettings {
    /// `stable`, `beta`, ... or the pin `stable-1`.
    pub channel: String,
}

/// What an admin has overridden (persisted as `instance.settings_json`).
/// Every field is optional so that untouched settings keep following the
/// config file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoredSettings {
    pub registration_mode: Option<RegistrationMode>,
    pub allowed_email_domains: Option<Vec<String>>,
    pub retention_event_header_days: Option<u32>,
    pub retention_blob_days: Option<u32>,
    pub retention_alert_days: Option<u32>,
    pub liveness_grace_secs: Option<u64>,
    pub update_channel: Option<String>,
}

/// `PATCH /admin/api/settings` body: any subset of fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SettingsPatch {
    pub registration_mode: Option<RegistrationMode>,
    pub allowed_email_domains: Option<Vec<String>>,
    pub retention: Option<RetentionPatch>,
    pub liveness_grace_secs: Option<u64>,
    pub update_channel: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionPatch {
    pub event_header_days: Option<u32>,
    pub blob_days: Option<u32>,
    pub alert_days: Option<u32>,
}

/// Upper bound on any retention window an admin can set (ten years): beyond
/// this is almost certainly a typo, and huge values risk overflow in cutoff
/// arithmetic.
pub const MAX_RETENTION_DAYS: u32 = 3650;
/// Upper bound on the liveness grace period (7 days).
pub const MAX_GRACE_SECS: u64 = 7 * 24 * 3600;

impl StoredSettings {
    /// Parse the stored JSON. An empty or `{}` column means "no overrides".
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        if s.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        // Serializing a struct of Options and Vec<String> cannot fail.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_owned())
    }

    /// Fold a patch into the overrides.
    pub fn apply(&mut self, p: &SettingsPatch) {
        if let Some(m) = p.registration_mode {
            self.registration_mode = Some(m);
        }
        if let Some(d) = &p.allowed_email_domains {
            self.allowed_email_domains = Some(d.clone());
        }
        if let Some(r) = &p.retention {
            if let Some(v) = r.event_header_days {
                self.retention_event_header_days = Some(v);
            }
            if let Some(v) = r.blob_days {
                self.retention_blob_days = Some(v);
            }
            if let Some(v) = r.alert_days {
                self.retention_alert_days = Some(v);
            }
        }
        if let Some(g) = p.liveness_grace_secs {
            self.liveness_grace_secs = Some(g);
        }
        if let Some(c) = &p.update_channel {
            self.update_channel = Some(c.clone());
        }
    }
}

impl InstanceSettings {
    /// The config file's values alone.
    pub fn from_config(c: &Config) -> Self {
        InstanceSettings {
            registration: c.registration.clone(),
            retention: c.retention.clone(),
            liveness: c.liveness.clone(),
            updates: UpdateSettings {
                channel: c.updates.channel.clone(),
            },
        }
    }

    /// Config values overridden by `stored`, validated with the same rules as
    /// the config file (so an admin cannot store a setting that would make
    /// the next startup fail).
    pub fn resolve(config: &Config, stored: &StoredSettings) -> Result<Self, ConfigError> {
        let mut c = config.clone();
        if let Some(m) = stored.registration_mode {
            c.registration.mode = m;
        }
        if let Some(d) = &stored.allowed_email_domains {
            c.registration.allowed_email_domains = d.clone();
        }
        if let Some(v) = stored.retention_event_header_days {
            c.retention.event_header_days = v;
        }
        if let Some(v) = stored.retention_blob_days {
            c.retention.blob_days = v;
        }
        if let Some(v) = stored.retention_alert_days {
            c.retention.alert_days = v;
        }
        if let Some(g) = stored.liveness_grace_secs {
            c.liveness.grace_secs = g;
        }
        if let Some(ch) = &stored.update_channel {
            c.updates.channel = ch.clone();
        }
        c.validate()?;
        let r = &c.retention;
        if r.event_header_days > MAX_RETENTION_DAYS
            || r.blob_days > MAX_RETENTION_DAYS
            || r.alert_days > MAX_RETENTION_DAYS
        {
            return Err(ConfigError::Invalid(format!(
                "retention periods must be at most {MAX_RETENTION_DAYS} days"
            )));
        }
        if c.liveness.grace_secs > MAX_GRACE_SECS {
            return Err(ConfigError::Invalid(format!(
                "liveness grace must be at most {MAX_GRACE_SECS} seconds"
            )));
        }
        Ok(Self::from_config(&c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config {
            dev: true,
            ..Config::default()
        };
        c.validate().unwrap();
        c
    }

    #[test]
    fn untouched_fields_follow_config() {
        let mut c = cfg();
        let s = InstanceSettings::resolve(&c, &StoredSettings::default()).unwrap();
        assert_eq!(s, InstanceSettings::from_config(&c));
        c.retention.blob_days = 7;
        let mut stored = StoredSettings::default();
        stored.apply(&SettingsPatch {
            retention: Some(RetentionPatch {
                alert_days: Some(30),
                ..RetentionPatch::default()
            }),
            ..SettingsPatch::default()
        });
        let s = InstanceSettings::resolve(&c, &stored).unwrap();
        assert_eq!(s.retention.blob_days, 7, "from config");
        assert_eq!(s.retention.alert_days, 30, "from override");
    }

    #[test]
    fn overrides_are_validated_like_config() {
        let c = cfg();
        let bad = [
            StoredSettings {
                registration_mode: Some(RegistrationMode::Open),
                ..StoredSettings::default()
            },
            StoredSettings {
                retention_blob_days: Some(0),
                ..StoredSettings::default()
            },
            StoredSettings {
                retention_alert_days: Some(MAX_RETENTION_DAYS + 1),
                ..StoredSettings::default()
            },
            StoredSettings {
                liveness_grace_secs: Some(60),
                ..StoredSettings::default()
            },
            StoredSettings {
                liveness_grace_secs: Some(MAX_GRACE_SECS + 1),
                ..StoredSettings::default()
            },
            StoredSettings {
                update_channel: Some("Stable".into()),
                ..StoredSettings::default()
            },
            StoredSettings {
                update_channel: Some("stable-2".into()),
                ..StoredSettings::default()
            },
            StoredSettings {
                allowed_email_domains: Some(vec!["not a domain".into()]),
                registration_mode: Some(RegistrationMode::Open),
                ..StoredSettings::default()
            },
        ];
        for b in bad {
            assert!(InstanceSettings::resolve(&c, &b).is_err(), "{b:?}");
        }
        let ok = StoredSettings {
            registration_mode: Some(RegistrationMode::Open),
            allowed_email_domains: Some(vec!["@College.EDU".into()]),
            ..StoredSettings::default()
        };
        let s = InstanceSettings::resolve(&c, &ok).unwrap();
        assert_eq!(s.registration.allowed_email_domains, vec!["college.edu"]);
        assert_eq!(s.updates.channel, "stable", "from config");
        let pin = StoredSettings {
            update_channel: Some(" stable-1 ".into()),
            ..StoredSettings::default()
        };
        let s = InstanceSettings::resolve(&c, &pin).unwrap();
        assert_eq!(s.updates.channel, "stable-1");
    }

    #[test]
    fn stored_json_roundtrip() {
        assert_eq!(
            StoredSettings::from_json("").unwrap(),
            StoredSettings::default()
        );
        assert_eq!(
            StoredSettings::from_json("{}").unwrap(),
            StoredSettings::default()
        );
        let s = StoredSettings {
            registration_mode: Some(RegistrationMode::Closed),
            liveness_grace_secs: Some(7200),
            ..StoredSettings::default()
        };
        assert_eq!(StoredSettings::from_json(&s.to_json()).unwrap(), s);
        assert!(StoredSettings::from_json("{\"bogus\":1}").is_err());
    }
}
