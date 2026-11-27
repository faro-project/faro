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
    /// Groups (GROUPS.md §13). Not in the config file: console only.
    #[serde(default)]
    pub groups: GroupSettings,
    /// Longer windows that still apply to older data after an admin
    /// shortened retention (see [`RetentionBefore`]).
    #[serde(default)]
    pub retention_before: RetentionBefore,
}

/// A window an admin shortened: data received **before** `since` keeps the
/// old, longer `days`; only data received from then on follows the new
/// window (§8). Shortening instance retention is never retroactive, as with
/// a member's own choice ([`crate::retention`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowBefore {
    pub days: u32,
    /// When the shorter window took effect (Unix ms).
    pub since: i64,
}

/// [`WindowBefore`] per retention window.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionBefore {
    pub event_header: Option<WindowBefore>,
    pub blob: Option<WindowBefore>,
    pub alert: Option<WindowBefore>,
}

impl RetentionBefore {
    /// After retention goes from `old` to `new` at `now_ms`: a window that
    /// got shorter keeps the longest window older data was promised
    /// (`old`, or what `self` already kept it for); one that is no
    /// shorter than that drops the rule; the others stay as they were.
    pub fn after_change(
        self,
        old: &RetentionConfig,
        new: &RetentionConfig,
        now_ms: i64,
    ) -> RetentionBefore {
        let pick = |before: Option<WindowBefore>, o: u32, n: u32| match before {
            _ if n < o => Some(WindowBefore {
                days: before.map_or(o, |b| b.days.max(o)),
                since: now_ms,
            }),
            Some(b) if n >= b.days => None,
            b => b,
        };
        RetentionBefore {
            event_header: pick(
                self.event_header,
                old.event_header_days,
                new.event_header_days,
            ),
            blob: pick(self.blob, old.blob_days, new.blob_days),
            alert: pick(self.alert, old.alert_days, new.alert_days),
        }
    }
}

/// The shortest retention window an admin can set in the console. Below
/// this, a flagged report or alert could be gone before an ally opens it
/// (§4.3 and §8), for every member. The same floor members have
/// ([`crate::retention::MIN_MEMBER_DAYS`]). The config file is not held to
/// it: it is the operator's own deployment decision.
pub const MIN_INSTANCE_RETENTION_DAYS: u32 = crate::retention::MIN_MEMBER_DAYS;

/// What differs between `old` and `new`, as `path:old>new` entries joined by
/// `;` (for the admin log). Setting names and values only; the
/// [`RetentionBefore`] bookkeeping is left out.
pub fn describe_changes(old: &InstanceSettings, new: &InstanceSettings) -> String {
    fn walk(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<String>) {
        match (a, b) {
            (serde_json::Value::Object(x), serde_json::Value::Object(y)) => {
                for (k, av) in x {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    if let Some(bv) = y.get(k) {
                        walk(&p, av, bv, out);
                    }
                }
            }
            _ if a != b => out.push(format!("{path}:{a}>{b}")),
            _ => {}
        }
    }
    let (Ok(mut a), Ok(mut b)) = (serde_json::to_value(old), serde_json::to_value(new)) else {
        return String::new();
    };
    for v in [&mut a, &mut b] {
        if let Some(o) = v.as_object_mut() {
            o.remove("retention_before");
        }
    }
    let mut out = Vec::new();
    walk("", &a, &b, &mut out);
    out.join(";")
}

/// Which settings in `old` and `new` weaken monitoring for members: setting
/// names (`liveness_grace_longer`, then the retention windows that got
/// shorter), empty when nothing does. Told to every member's allies.
pub fn weakened(old: &InstanceSettings, new: &InstanceSettings) -> Vec<&'static str> {
    let mut out = Vec::new();
    if new.liveness.grace_secs > old.liveness.grace_secs {
        out.push("liveness_grace_longer");
    }
    out.extend(crate::retention::shortened(&old.retention, &new.retention));
    out
}

/// Who may create groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhoCanCreateGroups {
    Anyone,
    Admins,
}

/// Who may list a group in the directory (the directory itself is built
/// separately; this is stored for it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhoCanListGroups {
    Facilitators,
    Admins,
    Nobody,
}

/// Who may invite people into a group. A group's facilitators may narrow
/// this for their group (never widen it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WhoCanInvite {
    Facilitators,
    Participants,
}

impl WhoCanInvite {
    pub fn as_str(self) -> &'static str {
        match self {
            WhoCanInvite::Facilitators => "facilitators",
            WhoCanInvite::Participants => "participants",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "facilitators" => Some(Self::Facilitators),
            "participants" => Some(Self::Participants),
            _ => None,
        }
    }

    /// The narrower of two settings.
    pub fn narrowest(self, other: WhoCanInvite) -> WhoCanInvite {
        if self == WhoCanInvite::Facilitators || other == WhoCanInvite::Facilitators {
            WhoCanInvite::Facilitators
        } else {
            WhoCanInvite::Participants
        }
    }
}

/// Instance-wide group settings (GROUPS.md §13). There is deliberately no
/// instance-wide group size limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Off hides the feature: existing groups become read-only and unlisted.
    pub enabled: bool,
    pub who_can_create: WhoCanCreateGroups,
    pub who_can_list: WhoCanListGroups,
    pub who_can_invite: WhoCanInvite,
    /// Under `invite-only` registration, whether a group invite lets a new
    /// address sign up (as an ally invite does).
    pub invites_create_accounts: bool,
    pub max_groups_per_user: u32,
}

impl Default for GroupSettings {
    fn default() -> Self {
        GroupSettings {
            enabled: true,
            who_can_create: WhoCanCreateGroups::Anyone,
            who_can_list: WhoCanListGroups::Facilitators,
            who_can_invite: WhoCanInvite::Facilitators,
            invites_create_accounts: true,
            max_groups_per_user: 10,
        }
    }
}

/// Upper bound on `max_groups_per_user`.
pub const MAX_GROUPS_PER_USER_LIMIT: u32 = 1000;

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
    pub groups_enabled: Option<bool>,
    pub groups_who_can_create: Option<WhoCanCreateGroups>,
    pub groups_who_can_list: Option<WhoCanListGroups>,
    pub groups_who_can_invite: Option<WhoCanInvite>,
    pub groups_invites_create_accounts: Option<bool>,
    pub groups_max_per_user: Option<u32>,
    /// Longer windows still applying to data received before a shortening.
    pub retention_before: Option<RetentionBefore>,
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
    pub groups: Option<GroupSettingsPatch>,
}

impl SettingsPatch {
    /// Retention windows in the patch below [`MIN_INSTANCE_RETENTION_DAYS`].
    /// Checked on the patch only, so a value stored before the floor existed
    /// never stops the server from starting.
    pub fn below_retention_floor(&self) -> bool {
        self.retention.as_ref().is_some_and(|r| {
            [r.event_header_days, r.blob_days, r.alert_days]
                .into_iter()
                .flatten()
                .any(|d| d < MIN_INSTANCE_RETENTION_DAYS)
        })
    }
}

/// Any subset of [`GroupSettings`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupSettingsPatch {
    pub enabled: Option<bool>,
    pub who_can_create: Option<WhoCanCreateGroups>,
    pub who_can_list: Option<WhoCanListGroups>,
    pub who_can_invite: Option<WhoCanInvite>,
    pub invites_create_accounts: Option<bool>,
    pub max_groups_per_user: Option<u32>,
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
        if let Some(g) = &p.groups {
            if let Some(v) = g.enabled {
                self.groups_enabled = Some(v);
            }
            if let Some(v) = g.who_can_create {
                self.groups_who_can_create = Some(v);
            }
            if let Some(v) = g.who_can_list {
                self.groups_who_can_list = Some(v);
            }
            if let Some(v) = g.who_can_invite {
                self.groups_who_can_invite = Some(v);
            }
            if let Some(v) = g.invites_create_accounts {
                self.groups_invites_create_accounts = Some(v);
            }
            if let Some(v) = g.max_groups_per_user {
                self.groups_max_per_user = Some(v);
            }
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
            groups: GroupSettings::default(),
            retention_before: RetentionBefore::default(),
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
        let mut out = Self::from_config(&c);
        out.retention_before = stored.retention_before.unwrap_or_default();
        let g = &mut out.groups;
        if let Some(v) = stored.groups_enabled {
            g.enabled = v;
        }
        if let Some(v) = stored.groups_who_can_create {
            g.who_can_create = v;
        }
        if let Some(v) = stored.groups_who_can_list {
            g.who_can_list = v;
        }
        if let Some(v) = stored.groups_who_can_invite {
            g.who_can_invite = v;
        }
        if let Some(v) = stored.groups_invites_create_accounts {
            g.invites_create_accounts = v;
        }
        if let Some(v) = stored.groups_max_per_user {
            if v == 0 || v > MAX_GROUPS_PER_USER_LIMIT {
                return Err(ConfigError::Invalid(format!(
                    "groups per user must be between 1 and {MAX_GROUPS_PER_USER_LIMIT}"
                )));
            }
            g.max_groups_per_user = v;
        }
        Ok(out)
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

    fn windows(e: u32, b: u32, a: u32) -> RetentionConfig {
        RetentionConfig {
            event_header_days: e,
            blob_days: b,
            alert_days: a,
        }
    }

    #[test]
    fn shortening_remembers_the_longest_window_older_data_was_promised() {
        let none = RetentionBefore::default();
        let a = none.after_change(&windows(90, 30, 90), &windows(90, 14, 90), 10);
        assert_eq!(
            a.blob,
            Some(WindowBefore {
                days: 30,
                since: 10
            })
        );
        assert_eq!((a.event_header, a.alert), (None, None));
        // Shortened again: older data still keeps 30; the new `since` is later.
        let b = a.after_change(&windows(90, 14, 90), &windows(90, 7, 90), 20);
        assert_eq!(
            b.blob,
            Some(WindowBefore {
                days: 30,
                since: 20
            })
        );
        // Raised, but still below what older data keeps: the rule stays.
        let c = b.after_change(&windows(90, 7, 90), &windows(90, 20, 90), 30);
        assert_eq!(c.blob, b.blob);
        // Raised to at least that: nothing to protect any more.
        let d = c.after_change(&windows(90, 20, 90), &windows(90, 45, 90), 40);
        assert_eq!(d.blob, None);
    }

    #[test]
    fn weakened_names_what_got_weaker() {
        let c = cfg();
        let old = InstanceSettings::from_config(&c);
        let mut new = old.clone();
        assert!(weakened(&old, &new).is_empty());
        new.liveness.grace_secs += 1;
        new.retention.alert_days -= 1;
        assert_eq!(
            weakened(&old, &new),
            vec!["liveness_grace_longer", "alert_days"]
        );
        assert!(
            weakened(&new, &old).is_empty(),
            "the other way is not weaker"
        );
        assert_eq!(
            describe_changes(&old, &new),
            format!(
                "liveness.grace_secs:{}>{};retention.alert_days:90>89",
                old.liveness.grace_secs, new.liveness.grace_secs
            )
        );
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
