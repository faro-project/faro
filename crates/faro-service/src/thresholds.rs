//! Development-only detection thresholds (`[dev_thresholds]` in
//! `service.toml`).
//!
//! Testing the whole flag path (a flagged frame, an encrypted event, the
//! ally's feed with a blurred thumbnail, the email) needs a screen the
//! model rates at least `medium`. OpenNSFW rates an ordinary swimwear photo
//! around 0.06–0.15, far below the default `explicit_medium` of 0.60, so
//! without this the only way to see a flag is explicit content.
//!
//! A service built with the `dev` feature reads `[dev_thresholds]` and
//! lowers `explicit_high`, `explicit_medium` and `any_low` to the values
//! given. Every value must be in (0, 1] and at most its default, so the
//! section can only lower thresholds, never raise them.
//!
//! **A release build never lowers a threshold.** It parses the section (so
//! a leftover section doesn't stop the service) but ignores it, and says so
//! in the log at start and in `faro-service status`. The decision is made
//! at compile time ([`BUILD_ALLOWS_DEV_THRESHOLDS`]), never by
//! configuration, and [`detector_config`] checks the feature again before
//! it applies anything, so even a forged [`DevThresholdsUse::Lowered`] does
//! nothing in a release build. `installers/macos/check-pkg.sh` checks that
//! a release package's service ignores the section.

use faro_detect::{DetectorConfig, PolicyConfig};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Whether this build may lower the detection thresholds: only with the
/// `dev` feature.
pub const BUILD_ALLOWS_DEV_THRESHOLDS: bool = cfg!(feature = "dev");

/// The `[dev_thresholds]` section. Unset values keep their defaults.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DevThresholds {
    /// An explicit label at or above this rates `high` (default 0.85).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_high: Option<f32>,
    /// An explicit label at or above this rates `medium` (default 0.60).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_medium: Option<f32>,
    /// Any concerning label at or above this rates `low` (default 0.40).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_low: Option<f32>,
}

impl DevThresholds {
    /// `policy` with the values set here.
    fn apply_to(&self, mut policy: PolicyConfig) -> PolicyConfig {
        if let Some(v) = self.explicit_high {
            policy.explicit_high = v;
        }
        if let Some(v) = self.explicit_medium {
            policy.explicit_medium = v;
        }
        if let Some(v) = self.any_low {
            policy.any_low = v;
        }
        policy
    }

    /// Each value lowers its threshold (in (0, 1], at most the default),
    /// and the policy they make is valid (`any_low <= explicit_medium <=
    /// explicit_high`).
    pub fn validate(&self) -> Result<(), String> {
        let d = PolicyConfig::default();
        let fields = [
            ("explicit_high", self.explicit_high, d.explicit_high),
            ("explicit_medium", self.explicit_medium, d.explicit_medium),
            ("any_low", self.any_low, d.any_low),
        ];
        for (name, value, default) in fields {
            let Some(v) = value else { continue };
            if !v.is_finite() || v <= 0.0 || v > default {
                return Err(format!(
                    "{name} must be above 0 and at most its default {default}, got {v}"
                ));
            }
        }
        self.apply_to(d).validate().map_err(|e| e.to_string())
    }

    fn is_empty(&self) -> bool {
        *self == DevThresholds::default()
    }
}

impl fmt::Display for DevThresholds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = self.apply_to(PolicyConfig::default());
        write!(
            f,
            "explicit_high {}, explicit_medium {}, any_low {}",
            p.explicit_high, p.explicit_medium, p.any_low
        )
    }
}

/// What this service does with `[dev_thresholds]`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DevThresholdsUse {
    /// No section (or an empty one): the default thresholds.
    Default,
    /// A development build: these thresholds are lowered.
    Lowered(DevThresholds),
    /// A release build: the section is ignored.
    Ignored(DevThresholds),
}

/// What a build does with `section`. Only a development build lowers
/// anything.
pub fn use_for(section: Option<&DevThresholds>, dev_build: bool) -> DevThresholdsUse {
    match section {
        Some(t) if !t.is_empty() && dev_build => DevThresholdsUse::Lowered(*t),
        Some(t) if !t.is_empty() => DevThresholdsUse::Ignored(*t),
        _ => DevThresholdsUse::Default,
    }
}

/// What this build does with `section`.
pub fn build_use(section: Option<&DevThresholds>) -> DevThresholdsUse {
    use_for(section, BUILD_ALLOWS_DEV_THRESHOLDS)
}

/// The detector configuration for `u`: the defaults, with the thresholds
/// lowered only for [`DevThresholdsUse::Lowered`] in a `dev` build.
pub fn detector_config(u: &DevThresholdsUse) -> DetectorConfig {
    let mut c = DetectorConfig::default();
    if let DevThresholdsUse::Lowered(t) = u {
        // The second guard: a release build never applies them, whatever
        // it is handed.
        if cfg!(feature = "dev") {
            c.policy = t.apply_to(c.policy);
        }
    }
    c
}

impl DevThresholdsUse {
    /// Log what the service does with the section, once at start.
    pub fn log(&self) {
        match self {
            DevThresholdsUse::Default => {}
            DevThresholdsUse::Lowered(t) => tracing::warn!(
                "DEVELOPMENT THRESHOLDS: [dev_thresholds] lowers the detection thresholds \
                 ({t}). Flags from this service are made with them, not with the defaults. \
                 Never use this build to monitor anyone."
            ),
            DevThresholdsUse::Ignored(_) => tracing::warn!(
                "service.toml has a [dev_thresholds] section; this is not a development \
                 build, so it is ignored and the default thresholds apply"
            ),
        }
    }

    /// The line `faro-service status` prints, if any.
    pub fn status_line(&self) -> Option<String> {
        match self {
            DevThresholdsUse::Default => None,
            DevThresholdsUse::Lowered(t) => Some(format!(
                "Thresholds:   LOWERED FOR TESTING ({t}); flags are made with these \
                 [dev_thresholds], not the defaults"
            )),
            DevThresholdsUse::Ignored(_) => Some(
                "Thresholds:   default ([dev_thresholds] ignored: not a development build)"
                    .to_owned(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SWIMWEAR: DevThresholds = DevThresholds {
        explicit_high: Some(0.5),
        explicit_medium: Some(0.05),
        any_low: Some(0.03),
    };

    #[test]
    fn only_a_dev_build_lowers_the_thresholds() {
        assert_eq!(use_for(None, true), DevThresholdsUse::Default);
        assert_eq!(use_for(None, false), DevThresholdsUse::Default);
        let empty = DevThresholds::default();
        assert_eq!(use_for(Some(&empty), true), DevThresholdsUse::Default);
        assert_eq!(
            use_for(Some(&SWIMWEAR), true),
            DevThresholdsUse::Lowered(SWIMWEAR)
        );
        assert_eq!(
            use_for(Some(&SWIMWEAR), false),
            DevThresholdsUse::Ignored(SWIMWEAR)
        );
        assert_eq!(
            build_use(Some(&SWIMWEAR)),
            use_for(Some(&SWIMWEAR), cfg!(feature = "dev"))
        );
        assert_eq!(
            detector_config(&DevThresholdsUse::Default),
            DetectorConfig::default()
        );
        assert_eq!(
            detector_config(&DevThresholdsUse::Ignored(SWIMWEAR)),
            DetectorConfig::default()
        );
        assert!(use_for(Some(&SWIMWEAR), false)
            .status_line()
            .unwrap()
            .contains("ignored"));
        assert!(use_for(Some(&SWIMWEAR), true)
            .status_line()
            .unwrap()
            .contains("LOWERED"));
        assert_eq!(DevThresholdsUse::Default.status_line(), None);
    }

    /// The guarantee for release builds: without the `dev` feature no
    /// threshold is lowered, not even from a forged `Lowered`.
    #[cfg(not(feature = "dev"))]
    #[test]
    fn a_release_build_never_lowers_the_thresholds() {
        assert!(!BUILD_ALLOWS_DEV_THRESHOLDS);
        assert_eq!(
            build_use(Some(&SWIMWEAR)),
            DevThresholdsUse::Ignored(SWIMWEAR)
        );
        assert_eq!(
            detector_config(&DevThresholdsUse::Lowered(SWIMWEAR)),
            DetectorConfig::default()
        );
        let cfg = crate::Config::from_toml_str(
            "[dev_thresholds]\nexplicit_high = 0.5\nexplicit_medium = 0.05\nany_low = 0.03",
        )
        .expect("a release build accepts the section, and ignores it");
        assert_eq!(
            detector_config(&build_use(cfg.dev_thresholds.as_ref())),
            DetectorConfig::default()
        );
        // Not even invalid values stop a release service: they are ignored.
        crate::Config::from_toml_str("[dev_thresholds]\nexplicit_medium = 2.0").unwrap();
    }

    /// Run with `--features dev`.
    #[cfg(feature = "dev")]
    #[test]
    fn a_dev_build_lowers_the_thresholds() {
        use faro_detect::{ImageScores, PolicyEngine};
        use faro_proto::body::Rating;
        assert!(BUILD_ALLOWS_DEV_THRESHOLDS);
        let cfg = crate::Config::from_toml_str(
            "[dev_thresholds]\nexplicit_high = 0.5\nexplicit_medium = 0.05\nany_low = 0.03",
        )
        .unwrap();
        let u = build_use(cfg.dev_thresholds.as_ref());
        assert_eq!(u, DevThresholdsUse::Lowered(SWIMWEAR));
        let policy = detector_config(&u).policy;
        assert_eq!(policy.explicit_high, 0.5);
        assert_eq!(policy.explicit_medium, 0.05);
        assert_eq!(policy.any_low, 0.03);
        let d = PolicyConfig::default();
        assert_eq!(policy.suggestive_medium, d.suggestive_medium);
        assert_eq!(policy.corroboration_min_score, d.corroboration_min_score);
        // A swimwear photo's score now flags `medium`; by default it is clean.
        let swimwear = ImageScores::new([("nsfw", 0.10f32)]).unwrap();
        let lowered = PolicyEngine::new(policy).unwrap().fuse(&swimwear, &[]);
        assert_eq!(lowered.rating, Rating::Medium);
        let default = PolicyEngine::default().fuse(&swimwear, &[]);
        assert_eq!(default.rating, Rating::Clean);

        // Only lower, and only a valid policy.
        for bad in [
            "explicit_medium = 0.7",
            "explicit_high = 0.9",
            "any_low = 0.0",
            "any_low = -0.1",
            "explicit_medium = nan",
            "explicit_medium = 0.05", // below the default any_low 0.40
            "explicit_high = 0.2\nexplicit_medium = 0.3\nany_low = 0.1",
            "suggestive_medium = 0.1",
        ] {
            assert!(
                crate::Config::from_toml_str(&format!("[dev_thresholds]\n{bad}")).is_err(),
                "{bad}"
            );
        }
        crate::Config::from_toml_str("[dev_thresholds]\nany_low = 0.1").unwrap();
    }

    #[test]
    fn validation() {
        SWIMWEAR.validate().unwrap();
        DevThresholds::default().validate().unwrap();
        let raise = DevThresholds {
            explicit_medium: Some(0.7),
            ..DevThresholds::default()
        };
        assert!(raise.validate().is_err(), "thresholds can only be lowered");
        let order = DevThresholds {
            explicit_medium: Some(0.05),
            ..DevThresholds::default()
        };
        assert!(order.validate().is_err(), "any_low 0.40 > explicit_medium");
        assert_eq!(
            SWIMWEAR.to_string(),
            "explicit_high 0.5, explicit_medium 0.05, any_low 0.03"
        );
    }
}
