//! Development-only burst thresholds (docs/DEVELOPMENT.md, "lower only").
//!
//! Testing the whole flag path on an iPhone (a burst, a `flag` event, the
//! ally's feed, the alert) means looking up six blocked names across three
//! domains within three minutes with the screen on, and then waiting out a
//! ten-minute cooldown before trying again. A development build can ease
//! that with a `dev_thresholds.json` in the app group container, such as
//! `{"min_lookups": 2, "min_domains": 1, "cooldown_secs": 30}`.
//!
//! The rule is the desktop's ([`BUILD_ALLOWS_DEV_THRESHOLDS`] below, and
//! `faro-service`'s `[dev_thresholds]`): **lower only, development builds
//! only.**
//!
//! * Each value must be at least 1 and at most its default, so a section can
//!   make a burst more likely, never less. `min_domains` can't exceed
//!   `min_lookups`. The window isn't settable: shortening it would make a
//!   burst less likely, and widening it is not a lowering.
//! * Only a build with the `dev` feature applies anything. A release build
//!   parses and ignores the section, and says so ([`DevThresholdsUse`]).
//!   The decision is made at compile time, never by configuration, and
//!   [`burst_thresholds`] checks the feature again before it applies
//!   anything, so even a forged [`DevThresholdsUse::Lowered`] does nothing
//!   in a release build.
//! * Flags themselves aren't marked: the event format has no field for it.
//!   The tunnel logs `DEVELOPMENT THRESHOLDS` at start and the filter's
//!   status says `lowered`, so check them before trusting a flag.

use crate::burst::{BurstThresholds, BURST_COOLDOWN_SECS, BURST_MIN_DOMAINS, BURST_MIN_LOOKUPS};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Whether this build may lower the burst thresholds: only with the `dev`
/// feature.
pub const BUILD_ALLOWS_DEV_THRESHOLDS: bool = cfg!(feature = "dev");

/// The `dev_thresholds.json` section. Unset values keep their defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DevBurstThresholds {
    /// Fewest blocked lookups in the window (default 6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_lookups: Option<usize>,
    /// Fewest registrable domains among them (default 3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_domains: Option<usize>,
    /// Quiet time after a burst, in seconds (default 600).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_secs: Option<i64>,
}

impl DevBurstThresholds {
    fn apply_to(&self, mut t: BurstThresholds) -> BurstThresholds {
        if let Some(v) = self.min_lookups {
            t.min_lookups = v;
        }
        if let Some(v) = self.min_domains {
            t.min_domains = v;
        }
        if let Some(v) = self.cooldown_secs {
            t.cooldown_secs = v;
        }
        t
    }

    /// Each value lowers its threshold (at least 1, at most the default),
    /// and `min_domains` stays within `min_lookups`.
    pub fn validate(&self) -> Result<(), String> {
        let check = |name: &str, v: Option<i64>, default: i64| match v {
            Some(v) if v < 1 || v > default => Err(format!(
                "{name} must be at least 1 and at most its default {default}, got {v}"
            )),
            _ => Ok(()),
        };
        let as_i64 = |v: Option<usize>| v.map(|v| i64::try_from(v).unwrap_or(i64::MAX));
        check(
            "min_lookups",
            as_i64(self.min_lookups),
            BURST_MIN_LOOKUPS as i64,
        )?;
        check(
            "min_domains",
            as_i64(self.min_domains),
            BURST_MIN_DOMAINS as i64,
        )?;
        check("cooldown_secs", self.cooldown_secs, BURST_COOLDOWN_SECS)?;
        let t = self.apply_to(BurstThresholds::default());
        if t.min_domains > t.min_lookups {
            return Err("min_domains can't be more than min_lookups".into());
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        *self == DevBurstThresholds::default()
    }
}

impl fmt::Display for DevBurstThresholds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.apply_to(BurstThresholds::default());
        write!(
            f,
            "min_lookups {}, min_domains {}, cooldown_secs {}",
            t.min_lookups, t.min_domains, t.cooldown_secs
        )
    }
}

/// What a build does with a `dev_thresholds.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevThresholdsUse {
    /// No section (or an empty one): the default thresholds.
    Default,
    /// A development build: these thresholds are lowered.
    Lowered(DevBurstThresholds),
    /// A release build: the section is ignored.
    Ignored(DevBurstThresholds),
}

/// What a build does with `section`. Only a development build lowers
/// anything.
pub fn use_for(section: Option<&DevBurstThresholds>, dev_build: bool) -> DevThresholdsUse {
    match section {
        Some(t) if !t.is_empty() && dev_build => DevThresholdsUse::Lowered(*t),
        Some(t) if !t.is_empty() => DevThresholdsUse::Ignored(*t),
        _ => DevThresholdsUse::Default,
    }
}

/// What this build does with `section`.
pub fn build_use(section: Option<&DevBurstThresholds>) -> DevThresholdsUse {
    use_for(section, BUILD_ALLOWS_DEV_THRESHOLDS)
}

/// The thresholds for `u`: the defaults, lowered only for
/// [`DevThresholdsUse::Lowered`] in a `dev` build.
pub fn burst_thresholds(u: &DevThresholdsUse) -> BurstThresholds {
    let mut t = BurstThresholds::default();
    if let DevThresholdsUse::Lowered(d) = u {
        // The second guard: a release build never applies them, whatever
        // it is handed.
        if cfg!(feature = "dev") {
            t = d.apply_to(t);
        }
    }
    t
}

impl fmt::Display for DevThresholdsUse {
    /// For the status and the log: `default`, `LOWERED FOR TESTING (...)` or
    /// `ignored (release build)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevThresholdsUse::Default => f.write_str("default"),
            DevThresholdsUse::Lowered(t) => write!(f, "LOWERED FOR TESTING ({t})"),
            DevThresholdsUse::Ignored(_) => f.write_str("ignored (release build)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(l: Option<usize>, d: Option<usize>, c: Option<i64>) -> DevBurstThresholds {
        DevBurstThresholds {
            min_lookups: l,
            min_domains: d,
            cooldown_secs: c,
        }
    }

    #[test]
    fn values_can_only_lower() {
        assert!(section(Some(2), Some(1), Some(30)).validate().is_ok());
        assert!(section(Some(6), Some(3), Some(600)).validate().is_ok());
        assert!(section(None, None, None).validate().is_ok());
        for bad in [
            section(Some(7), None, None),
            section(Some(0), None, None),
            section(None, Some(4), None),
            section(None, Some(0), None),
            section(None, None, Some(601)),
            section(None, None, Some(0)),
            section(None, None, Some(-5)),
            // 4 domains can't come from 2 lookups.
            section(Some(2), Some(3), None),
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_section_rejects_unknown_fields_and_a_window() {
        let ok: Result<DevBurstThresholds, _> = serde_json::from_str(r#"{"min_lookups":3}"#);
        assert_eq!(ok.unwrap().min_lookups, Some(3));
        for j in [r#"{"window_secs":10}"#, r#"{"min_lookups":-1}"#] {
            assert!(
                serde_json::from_str::<DevBurstThresholds>(j).is_err(),
                "{j}"
            );
        }
    }

    #[test]
    fn a_release_build_never_lowers_the_thresholds() {
        let s = section(Some(2), Some(1), Some(30));
        // `use_for` with a release build ignores the section ...
        assert_eq!(use_for(Some(&s), false), DevThresholdsUse::Ignored(s));
        assert_eq!(
            burst_thresholds(&use_for(Some(&s), false)),
            BurstThresholds::default()
        );
        // ... and so does a build without the feature, even when handed a
        // forged `Lowered`.
        if !BUILD_ALLOWS_DEV_THRESHOLDS {
            assert_eq!(
                burst_thresholds(&DevThresholdsUse::Lowered(s)),
                BurstThresholds::default()
            );
            assert_eq!(build_use(Some(&s)), DevThresholdsUse::Ignored(s));
        }
    }

    #[cfg(feature = "dev")]
    #[test]
    fn a_dev_build_lowers_the_thresholds() {
        let s = section(Some(2), Some(1), Some(30));
        assert_eq!(build_use(Some(&s)), DevThresholdsUse::Lowered(s));
        let t = burst_thresholds(&build_use(Some(&s)));
        assert_eq!((t.min_lookups, t.min_domains, t.cooldown_secs), (2, 1, 30));
        assert!(DevThresholdsUse::Lowered(s)
            .to_string()
            .starts_with("LOWERED FOR TESTING"));
    }

    #[test]
    fn nothing_set_is_the_default() {
        assert_eq!(build_use(None), DevThresholdsUse::Default);
        assert_eq!(
            build_use(Some(&DevBurstThresholds::default())),
            DevThresholdsUse::Default
        );
    }
}
