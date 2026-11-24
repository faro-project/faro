//! Fusion / policy engine (§3.5): image scores + context findings → rating,
//! reasons and a borderline flag.
//!
//! The engine is a small, explainable rules table rather than a learned
//! model, so every rating can be justified to the member and their allies
//! by its reasons (`image:explicit 0.93`, `domain:adult`).
//!
//! ## Default rules (all thresholds configurable via [`PolicyConfig`])
//!
//! | Signal | Rating |
//! |---|---|
//! | explicit label ≥ 0.85 | high |
//! | explicit ≥ 0.60, or suggestive ≥ 0.85 | medium |
//! | any concerning label (explicit, suggestive, other) ≥ 0.40 | low |
//! | domain `adult` alone | medium |
//! | domain `adult` **and** explicit/suggestive ≥ 0.40 | high |
//! | other domain categories (gambling, violence, proxy_vpn, custom) | low |
//! | title keyword alone | low |
//! | app category | low |
//! | incognito / browser without extension | clean (configurable, **never above low**) |
//!
//! The final rating is the strongest individual contribution. Ratings are
//! never added up (three weak signals do not make a strong one), so a rating
//! is always fully explained by its top reason.
//!
//! **Incognito decision.** Private browsing has plenty of legitimate uses
//! (banking, gift shopping), and §5.4 classifies context signals as urgency
//! `none`. So incognito and "browser without extension" are always recorded
//! as `context:` reasons (allies see them in the daily report) but rate
//! `clean` by default, and configuration can raise them to `low` at most:
//! they can never by themselves produce a `medium`/`high` flag or an urgent
//! notification.
//!
//! **Invariants** (tested): every non-clean rating has at least one reason;
//! reasons are sorted strongest first; scores never leave `[0, 1]`.
//!
//! **Borderline** means some score sits within `borderline_margin` *below* a
//! threshold whose crossing would raise the overall rating. The scheduler
//! uses it to enter burst mode (§3.4), so a threshold that could not change
//! the outcome does not count.

use crate::classifier::ImageScores;
use crate::context::ContextFinding;
use crate::domains::Category;
use crate::error::DetectError;
use faro_proto::body::{Rating, Reason, ReasonSource};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;

/// Tunable policy. See the module docs for what the defaults mean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Classifier labels treated as explicit.
    pub explicit_labels: Vec<String>,
    /// Classifier labels treated as suggestive.
    pub suggestive_labels: Vec<String>,
    /// Other concerning labels (only ever rate `low` from the image alone).
    /// Labels in none of the three lists (e.g. `neutral`) are ignored.
    pub other_labels: Vec<String>,

    pub explicit_high: f32,
    pub explicit_medium: f32,
    pub suggestive_medium: f32,
    pub any_low: f32,

    /// Rating of a domain category on its own.
    pub domain_ratings: BTreeMap<Category, Rating>,
    /// Rating for categories missing from `domain_ratings`.
    pub default_domain_rating: Rating,
    /// Rating when a domain category is corroborated by an explicit or
    /// suggestive image score ≥ `corroboration_min_score`.
    pub domain_corroborated_ratings: BTreeMap<Category, Rating>,
    pub corroboration_min_score: f32,

    pub title_keyword_rating: Rating,
    pub app_rating: Rating,
    /// At most `low`.
    pub incognito_rating: Rating,
    /// At most `low`.
    pub browser_without_extension_rating: Rating,

    pub borderline_margin: f32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        let s = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        PolicyConfig {
            // Covers the common open NSFW model label sets.
            explicit_labels: s(&["explicit", "porn", "hentai", "nsfw"]),
            suggestive_labels: s(&["suggestive", "sexy"]),
            other_labels: s(&["gambling", "violence", "gore"]),
            explicit_high: 0.85,
            explicit_medium: 0.60,
            suggestive_medium: 0.85,
            any_low: 0.40,
            domain_ratings: BTreeMap::from([
                (Category::Adult, Rating::Medium),
                (Category::Gambling, Rating::Low),
                (Category::Violence, Rating::Low),
                (Category::ProxyVpn, Rating::Low),
            ]),
            default_domain_rating: Rating::Low,
            domain_corroborated_ratings: BTreeMap::from([(Category::Adult, Rating::High)]),
            corroboration_min_score: 0.40,
            title_keyword_rating: Rating::Low,
            app_rating: Rating::Low,
            incognito_rating: Rating::Clean,
            browser_without_extension_rating: Rating::Clean,
            borderline_margin: 0.10,
        }
    }
}

impl PolicyConfig {
    pub fn validate(&self) -> Result<(), DetectError> {
        let unit = [
            ("explicit_high", self.explicit_high),
            ("explicit_medium", self.explicit_medium),
            ("suggestive_medium", self.suggestive_medium),
            ("any_low", self.any_low),
            ("corroboration_min_score", self.corroboration_min_score),
        ];
        for (name, v) in unit {
            if !v.is_finite() || !(0.0..=1.0).contains(&v) || v == 0.0 {
                return Err(DetectError::Config(format!(
                    "{name} must be in (0, 1], got {v}"
                )));
            }
        }
        if !(self.any_low <= self.explicit_medium && self.explicit_medium <= self.explicit_high) {
            return Err(DetectError::Config(
                "need any_low <= explicit_medium <= explicit_high".into(),
            ));
        }
        if self.any_low > self.suggestive_medium {
            return Err(DetectError::Config(
                "need any_low <= suggestive_medium".into(),
            ));
        }
        if !self.borderline_margin.is_finite() || !(0.0..=0.5).contains(&self.borderline_margin) {
            return Err(DetectError::Config(
                "borderline_margin must be in [0, 0.5]".into(),
            ));
        }
        if self.incognito_rating > Rating::Low
            || self.browser_without_extension_rating > Rating::Low
        {
            return Err(DetectError::Config(
                "incognito / browser-without-extension may not rate above low".into(),
            ));
        }
        let lists = [
            &self.explicit_labels,
            &self.suggestive_labels,
            &self.other_labels,
        ];
        for (i, a) in lists.iter().enumerate() {
            for b in &lists[i + 1..] {
                if let Some(l) = a.iter().find(|l| b.contains(l)) {
                    return Err(DetectError::Config(format!("label {l:?} is in two lists")));
                }
            }
        }
        let cats = self
            .domain_ratings
            .keys()
            .chain(self.domain_corroborated_ratings.keys());
        for c in cats {
            if c.bit().is_none() {
                return Err(DetectError::Config(format!("invalid category {c}")));
            }
        }
        Ok(())
    }
}

/// Output of [`PolicyEngine::fuse`].
#[derive(Debug, Clone, PartialEq)]
pub struct FusionResult {
    pub rating: Rating,
    /// Strongest first.
    pub reasons: Vec<Reason>,
    pub borderline: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LabelKind {
    Explicit,
    Suggestive,
    Other,
}

/// The rules engine. Cheap to clone; holds only the validated config.
#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    cfg: PolicyConfig,
}

/// A reason plus the rating it contributes, for ordering.
struct Contribution {
    reason: Reason,
    strength: Rating,
}

/// A threshold a score sits below, and the rating crossing it would give.
struct NearMiss {
    score: f32,
    threshold: f32,
    would_be: Rating,
}

impl PolicyEngine {
    pub fn new(cfg: PolicyConfig) -> Result<Self, DetectError> {
        cfg.validate()?;
        Ok(PolicyEngine { cfg })
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.cfg
    }

    fn kind(&self, label: &str) -> Option<LabelKind> {
        let has = |v: &[String]| v.iter().any(|l| l == label);
        if has(&self.cfg.explicit_labels) {
            Some(LabelKind::Explicit)
        } else if has(&self.cfg.suggestive_labels) {
            Some(LabelKind::Suggestive)
        } else if has(&self.cfg.other_labels) {
            Some(LabelKind::Other)
        } else {
            None
        }
    }

    /// Combine image scores and context findings into a rating.
    pub fn fuse(&self, scores: &ImageScores, findings: &[ContextFinding]) -> FusionResult {
        let c = &self.cfg;
        let mut contributions: Vec<Contribution> = Vec::new();
        let mut near: Vec<NearMiss> = Vec::new();
        let mut max_sexual = 0f32;

        for (label, score) in scores.iter() {
            let Some(kind) = self.kind(label) else {
                continue;
            };
            let ladder: &[(f32, Rating)] = match kind {
                LabelKind::Explicit => &[
                    (c.explicit_high, Rating::High),
                    (c.explicit_medium, Rating::Medium),
                    (c.any_low, Rating::Low),
                ],
                LabelKind::Suggestive => &[
                    (c.suggestive_medium, Rating::Medium),
                    (c.any_low, Rating::Low),
                ],
                LabelKind::Other => &[(c.any_low, Rating::Low)],
            };
            if kind != LabelKind::Other {
                max_sexual = max_sexual.max(score);
            }
            let strength = ladder
                .iter()
                .find(|(t, _)| score >= *t)
                .map_or(Rating::Clean, |&(_, r)| r);
            near.extend(ladder.iter().map(|&(threshold, would_be)| NearMiss {
                score,
                threshold,
                would_be,
            }));
            if strength > Rating::Clean {
                contributions.push(Contribution {
                    reason: Reason {
                        source: ReasonSource::Image,
                        label: label.to_owned(),
                        score: Some(score),
                    },
                    strength,
                });
            }
        }

        for f in findings {
            let (source, label, strength) = match f {
                ContextFinding::Domain { category, label } => {
                    let mut r = c
                        .domain_ratings
                        .get(category)
                        .copied()
                        .unwrap_or(c.default_domain_rating);
                    if let Some(&boosted) = c.domain_corroborated_ratings.get(category) {
                        if max_sexual >= c.corroboration_min_score {
                            r = r.max(boosted);
                        }
                        near.push(NearMiss {
                            score: max_sexual,
                            threshold: c.corroboration_min_score,
                            would_be: boosted,
                        });
                    }
                    (ReasonSource::Domain, label.clone(), r)
                }
                ContextFinding::TitleKeyword(k) => {
                    (ReasonSource::Title, k.clone(), c.title_keyword_rating)
                }
                ContextFinding::App(cat) => (ReasonSource::App, cat.clone(), c.app_rating),
                ContextFinding::Incognito => (
                    ReasonSource::Context,
                    "incognito".to_owned(),
                    c.incognito_rating.min(Rating::Low),
                ),
                ContextFinding::BrowserWithoutExtension => (
                    ReasonSource::Context,
                    "browser_without_extension".to_owned(),
                    c.browser_without_extension_rating.min(Rating::Low),
                ),
            };
            contributions.push(Contribution {
                reason: Reason {
                    source,
                    label,
                    score: None,
                },
                strength,
            });
        }

        let rating = contributions
            .iter()
            .map(|x| x.strength)
            .max()
            .unwrap_or(Rating::Clean);
        let borderline = near.iter().any(|n| {
            n.would_be > rating
                && n.score < n.threshold
                && n.score >= n.threshold - c.borderline_margin
        });

        contributions.sort_by(|a, b| {
            b.strength
                .cmp(&a.strength)
                .then_with(|| {
                    // Scored reasons before unscored, higher score first.
                    let sa = a.reason.score.unwrap_or(-1.0);
                    let sb = b.reason.score.unwrap_or(-1.0);
                    sb.partial_cmp(&sa).unwrap_or(Ordering::Equal)
                })
                .then_with(|| a.reason.label.cmp(&b.reason.label))
        });

        FusionResult {
            rating,
            reasons: contributions.into_iter().map(|x| x.reason).collect(),
            borderline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn s(v: &[(&str, f32)]) -> ImageScores {
        ImageScores::new(v.iter().map(|&(l, s)| (l, s))).unwrap()
    }

    fn adult() -> ContextFinding {
        ContextFinding::Domain {
            category: Category::Adult,
            label: "adult".into(),
        }
    }

    fn fuse(scores: &[(&str, f32)], f: &[ContextFinding]) -> FusionResult {
        PolicyEngine::default().fuse(&s(scores), f)
    }

    #[test]
    fn image_ladder() {
        assert_eq!(fuse(&[("explicit", 0.93)], &[]).rating, Rating::High);
        assert_eq!(fuse(&[("explicit", 0.85)], &[]).rating, Rating::High);
        assert_eq!(fuse(&[("explicit", 0.70)], &[]).rating, Rating::Medium);
        assert_eq!(fuse(&[("explicit", 0.60)], &[]).rating, Rating::Medium);
        assert_eq!(fuse(&[("explicit", 0.45)], &[]).rating, Rating::Low);
        assert_eq!(fuse(&[("explicit", 0.10)], &[]).rating, Rating::Clean);
        assert_eq!(fuse(&[("suggestive", 0.90)], &[]).rating, Rating::Medium);
        assert_eq!(fuse(&[("suggestive", 0.84)], &[]).rating, Rating::Low);
        assert_eq!(fuse(&[("gambling", 0.99)], &[]).rating, Rating::Low);
        assert_eq!(fuse(&[("neutral", 0.99)], &[]).rating, Rating::Clean);
        assert!(fuse(&[("neutral", 0.99)], &[]).reasons.is_empty());
        assert_eq!(fuse(&[], &[]).rating, Rating::Clean);
    }

    #[test]
    fn domain_rules() {
        assert_eq!(fuse(&[], &[adult()]).rating, Rating::Medium);
        assert_eq!(
            fuse(&[("suggestive", 0.40)], &[adult()]).rating,
            Rating::High
        );
        assert_eq!(
            fuse(&[("explicit", 0.39)], &[adult()]).rating,
            Rating::Medium
        );
        // "Other" labels do not corroborate adult domains.
        assert_eq!(
            fuse(&[("gambling", 0.9)], &[adult()]).rating,
            Rating::Medium
        );
        let gamb = ContextFinding::Domain {
            category: Category::Gambling,
            label: "gambling".into(),
        };
        assert_eq!(fuse(&[("explicit", 0.5)], &[gamb]).rating, Rating::Low);
        let custom = ContextFinding::Domain {
            category: Category::Custom(2),
            label: "dating".into(),
        };
        let r = fuse(&[], &[custom]);
        assert_eq!(r.rating, Rating::Low);
        assert_eq!(r.reasons[0].to_string(), "domain:dating");
    }

    #[test]
    fn context_rules() {
        let r = fuse(&[], &[ContextFinding::TitleKeyword("xxx".into())]);
        assert_eq!(
            (r.rating, r.reasons[0].to_string().as_str()),
            (Rating::Low, "title:xxx")
        );
        assert_eq!(
            fuse(&[], &[ContextFinding::App("anonymizing_browser".into())]).rating,
            Rating::Low
        );
        // Incognito alone: clean, but recorded.
        let r = fuse(
            &[],
            &[
                ContextFinding::Incognito,
                ContextFinding::BrowserWithoutExtension,
            ],
        );
        assert_eq!(r.rating, Rating::Clean);
        assert_eq!(r.reasons.len(), 2);
        assert!(r.reasons.iter().all(|x| x.source == ReasonSource::Context));
        // Incognito never escalates an image score.
        assert_eq!(
            fuse(&[("explicit", 0.5)], &[ContextFinding::Incognito]).rating,
            Rating::Low
        );
    }

    #[test]
    fn incognito_capped_at_low() {
        let cfg = PolicyConfig {
            incognito_rating: Rating::Medium,
            ..Default::default()
        };
        assert!(PolicyEngine::new(cfg).is_err());
        let cfg = PolicyConfig {
            incognito_rating: Rating::Low,
            ..Default::default()
        };
        let e = PolicyEngine::new(cfg).unwrap();
        assert_eq!(
            e.fuse(&s(&[]), &[ContextFinding::Incognito]).rating,
            Rating::Low
        );
    }

    #[test]
    fn reasons_sorted_by_strength() {
        let r = fuse(
            &[("explicit", 0.65), ("suggestive", 0.5), ("gambling", 0.45)],
            &[
                ContextFinding::Incognito,
                ContextFinding::TitleKeyword("nsfw".into()),
                adult(),
            ],
        );
        assert_eq!(r.rating, Rating::High);
        let labels: Vec<String> = r.reasons.iter().map(ToString::to_string).collect();
        assert_eq!(
            labels,
            [
                "domain:adult",
                "image:explicit 0.65",
                "image:suggestive 0.50",
                "image:gambling 0.45",
                "title:nsfw",
                "context:incognito",
            ]
        );
    }

    #[test]
    fn borderline() {
        assert!(fuse(&[("explicit", 0.80)], &[]).borderline); // near high
        assert!(fuse(&[("explicit", 0.55)], &[]).borderline); // near medium
        assert!(fuse(&[("suggestive", 0.31)], &[]).borderline); // near low
        assert!(!fuse(&[("explicit", 0.70)], &[]).borderline);
        assert!(!fuse(&[("explicit", 0.20)], &[]).borderline);
        assert!(!fuse(&[("explicit", 0.95)], &[]).borderline);
        // Near the corroboration threshold with an adult domain.
        assert!(fuse(&[("suggestive", 0.35)], &[adult()]).borderline);
        // Near "low" is irrelevant when already medium via the domain...
        let r = fuse(&[("gambling", 0.35)], &[adult()]);
        assert!(!r.borderline);
        // ...and near "medium" is irrelevant when already high.
        assert!(!fuse(&[("explicit", 0.90), ("suggestive", 0.80)], &[]).borderline);
    }

    #[test]
    fn config_validation_and_serde() {
        assert!(PolicyConfig::default().validate().is_ok());
        let bad = [
            PolicyConfig {
                explicit_high: 0.5,
                ..Default::default()
            },
            PolicyConfig {
                any_low: f32::NAN,
                ..Default::default()
            },
            PolicyConfig {
                any_low: 0.0,
                ..Default::default()
            },
            PolicyConfig {
                borderline_margin: 0.9,
                ..Default::default()
            },
            PolicyConfig {
                other_labels: vec!["explicit".into()],
                ..Default::default()
            },
            PolicyConfig {
                domain_ratings: BTreeMap::from([(Category::Custom(99), Rating::High)]),
                ..Default::default()
            },
        ];
        for c in bad {
            assert!(PolicyEngine::new(c).is_err());
        }
        let j = serde_json::to_string(&PolicyConfig::default()).unwrap();
        let back: PolicyConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back, PolicyConfig::default());
        let partial: PolicyConfig = serde_json::from_str(r#"{"explicit_high": 0.9}"#).unwrap();
        assert_eq!(partial.explicit_high, 0.9);
        assert_eq!(partial.any_low, 0.40);
        assert!(serde_json::from_str::<PolicyConfig>(r#"{"show_unblurred": true}"#).is_err());
    }

    fn finding() -> impl Strategy<Value = ContextFinding> {
        prop_oneof![
            (0u8..6).prop_map(|b| {
                let category = match b {
                    0 => Category::Adult,
                    1 => Category::Gambling,
                    2 => Category::Violence,
                    3 => Category::ProxyVpn,
                    n => Category::Custom(n),
                };
                ContextFinding::Domain {
                    category,
                    label: category.to_string(),
                }
            }),
            "[a-z]{1,8}".prop_map(ContextFinding::TitleKeyword),
            "[a-z]{1,8}".prop_map(ContextFinding::App),
            Just(ContextFinding::Incognito),
            Just(ContextFinding::BrowserWithoutExtension),
        ]
    }

    proptest! {
        #[test]
        fn invariants(
            ex in 0f32..=1.0, sg in 0f32..=1.0, ot in 0f32..=1.0, ne in 0f32..=1.0,
            findings in proptest::collection::vec(finding(), 0..6),
        ) {
            let scores = s(&[("explicit", ex), ("suggestive", sg), ("violence", ot), ("neutral", ne)]);
            let r = PolicyEngine::default().fuse(&scores, &findings);
            if r.rating > Rating::Clean {
                prop_assert!(!r.reasons.is_empty());
            }
            // Every context finding is recorded.
            prop_assert!(r.reasons.iter().filter(|x| x.source != ReasonSource::Image).count() == findings.len());
            let in_unit = |x: &Reason| x.score.is_none_or(|v| (0.0..=1.0).contains(&v));
            prop_assert!(r.reasons.iter().all(in_unit));
            prop_assert!(!r.reasons.iter().any(|x| x.label == "neutral"));
            // Incognito / no-extension never change the rating by default.
            if findings.iter().all(|f| matches!(f, ContextFinding::Incognito | ContextFinding::BrowserWithoutExtension)) {
                prop_assert_eq!(r.rating, PolicyEngine::default().fuse(&scores, &[]).rating);
            }
            // Monotone in the explicit score.
            let higher = s(&[("explicit", (ex + 0.2).min(1.0)), ("suggestive", sg), ("violence", ot), ("neutral", ne)]);
            prop_assert!(PolicyEngine::default().fuse(&higher, &findings).rating >= r.rating);
        }
    }
}
