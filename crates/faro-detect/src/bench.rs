//! Model benchmark harness (§3.5 "Screenshot domain gap"): run a candidate
//! classifier over a labelled test set and report how the *policy* rates
//! it, plus CPU latency, and gate on regressions against a baseline.
//!
//! The `model-bench` example (feature `onnx`) is the command line; see
//! DEVELOPMENT.md "Model benchmark" for the commands and for how the real,
//! never-committed test set is handled.
//!
//! ## What is measured
//!
//! Each image is a folder-labelled PNG (layout in [`set`]). It is read and
//! decoded into a [`Frame`](faro_platform::Frame), downscaled to
//! [`MAX_FRAME_SIDE`] exactly as [`Detector::process`](crate::Detector)
//! does, classified, fused by the [`PolicyEngine`] with no context signals,
//! and destroyed (zeroized) before the next image is read.
//!
//! * **Predicted class.** `neutral` when the policy rates the image clean.
//!   Otherwise the policy kind of its top reason: `explicit` for any of the
//!   policy's `explicit_labels`, `suggestive` for `suggestive_labels`, and
//!   the label itself for `other_labels`. So "predicted explicit" means
//!   "an explicit label crossed a policy threshold (`any_low` or above) and
//!   is the strongest reason", which is what a member's allies would see.
//! * **Per-class precision and recall** come from the confusion matrix of
//!   true class (folder) against predicted class.
//! * **Ratings** count, per true class, how many images were rated clean,
//!   low, medium and high, which shows the operating point (for example
//!   how many explicit images reach `medium`, the default thumbnail and
//!   alert level).
//! * **Latency** is the wall-clock time of [`Classifier::classify`]
//!   (preprocessing plus inference) per frame, after `warmup` untimed runs
//!   on the first image. Percentiles are nearest-rank.
//!
//! ## Privacy
//!
//! Images enter only through `Frame`, one at a time, and are zeroized when
//! dropped (see [`set::read_frame`]). Nothing is ever written: the
//! [`BenchReport`] holds only aggregate counts, ratios and timings, and the
//! set is identified by a single digest over all files, from which no
//! single image can be identified or recovered. There are no per-image
//! results anywhere, not even file names.

use crate::classifier::{Classifier, ImageScores, InputSize};
use crate::error::DetectError;
use crate::fusion::{PolicyConfig, PolicyEngine};
use faro_platform::MAX_FRAME_SIDE;
use faro_proto::body::Rating;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::time::Instant;

#[cfg(feature = "onnx")]
pub mod cli;
mod gate;
pub mod set;
pub mod synthetic;

pub use gate::{gate, GateCheck, GateConfig, GateOutcome};
pub use set::{EvalImage, EvalSet};

/// Class of images the policy rates clean.
pub const NEUTRAL: &str = "neutral";
/// Class of the policy's `explicit_labels`.
pub const EXPLICIT: &str = "explicit";
/// Class of the policy's `suggestive_labels`.
pub const SUGGESTIVE: &str = "suggestive";

/// `format` of the JSON report this version writes and reads.
pub const REPORT_FORMAT: &str = "faro-model-bench/1";

/// Domain-separation context of [`SetSummary::digest`].
const SET_DIGEST_CONTEXT: &str = "faro model-bench 2026-11 set digest v1";

/// The class folders a set may have under `policy`: `explicit`,
/// `suggestive`, `neutral` and each of the policy's `other_labels`.
pub fn allowed_classes(policy: &PolicyConfig) -> Vec<String> {
    let mut v: Vec<String> = [EXPLICIT, NEUTRAL, SUGGESTIVE]
        .into_iter()
        .map(String::from)
        .collect();
    v.extend(policy.other_labels.iter().cloned());
    v.sort();
    v.dedup();
    v
}

/// The class the policy assigns to these scores, and the rating (see the
/// module docs).
pub fn predict(policy: &PolicyEngine, scores: &ImageScores) -> (String, Rating) {
    let fused = policy.fuse(scores, &[]);
    let c = policy.config();
    let class = match fused.reasons.first() {
        None => NEUTRAL.to_owned(),
        Some(r) if c.explicit_labels.contains(&r.label) => EXPLICIT.to_owned(),
        Some(r) if c.suggestive_labels.contains(&r.label) => SUGGESTIVE.to_owned(),
        Some(r) => r.label.clone(),
    };
    (class, fused.rating)
}

/// Options for [`run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    /// Untimed classifications of the first image before measuring.
    pub warmup: usize,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { warmup: 3 }
    }
}

/// Run `classifier` over every image of `set` and build the report.
pub fn run(
    classifier: &mut dyn Classifier,
    policy: &PolicyEngine,
    set: &EvalSet,
    opts: &RunOptions,
) -> Result<BenchReport, DetectError> {
    let mut digest = blake3::Hasher::new_derive_key(SET_DIGEST_CONTEXT);
    let mut confusion: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut ratings: BTreeMap<String, [usize; 4]> = BTreeMap::new();
    let mut samples = Vec::with_capacity(set.len());

    for (i, image) in set.images().iter().enumerate() {
        let (frame, file_hash) = set::read_frame(image.path())?;
        // The same bound `Detector::process` applies before classifying.
        let frame = frame.downscale_to_max(MAX_FRAME_SIDE);
        let fail =
            |e: DetectError| DetectError::Bench(format!("{}: {e}", image.relative.display()));
        if i == 0 {
            for _ in 0..opts.warmup {
                classifier.classify(&frame).map_err(fail)?;
            }
        }
        let start = Instant::now();
        let scores = classifier.classify(&frame);
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
        frame.destroy();
        let (predicted, rating) = predict(policy, &scores.map_err(fail)?);

        digest.update(&(image.class.len() as u64).to_le_bytes());
        digest.update(image.class.as_bytes());
        digest.update(file_hash.as_bytes());
        *confusion
            .entry((image.class.clone(), predicted))
            .or_default() += 1;
        ratings.entry(image.class.clone()).or_default()[rating as usize] += 1;
    }

    let labels: Vec<String> = confusion
        .keys()
        .flat_map(|(t, p)| [t.clone(), p.clone()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let rows: Vec<Vec<usize>> = labels
        .iter()
        .map(|t| {
            labels
                .iter()
                .map(|p| confusion.get(&(t.clone(), p.clone())).copied().unwrap_or(0))
                .collect()
        })
        .collect();
    let classes = labels
        .iter()
        .enumerate()
        .map(|(k, label)| {
            let support: usize = rows[k].iter().sum();
            let predicted: usize = rows.iter().map(|r| r[k]).sum();
            let correct = rows[k][k];
            let ratio = |n: usize, d: usize| (d > 0).then(|| n as f64 / d as f64);
            ClassMetrics {
                label: label.clone(),
                support,
                predicted,
                correct,
                precision: ratio(correct, predicted),
                recall: ratio(correct, support),
            }
        })
        .collect();

    let info = classifier.info();
    let c = policy.config();
    Ok(BenchReport {
        format: REPORT_FORMAT.to_owned(),
        model: ModelSummary {
            name: info.name.clone(),
            version: info.version.clone(),
            license: info.license.clone(),
            blake3: info.blake3.clone(),
            input_size: info.input_size,
            labels: info.labels.clone(),
        },
        policy: PolicySummary {
            explicit_labels: c.explicit_labels.clone(),
            suggestive_labels: c.suggestive_labels.clone(),
            other_labels: c.other_labels.clone(),
            explicit_high: c.explicit_high,
            explicit_medium: c.explicit_medium,
            suggestive_medium: c.suggestive_medium,
            any_low: c.any_low,
        },
        set: SetSummary {
            images: set.len(),
            digest: digest.finalize().to_hex().to_string(),
        },
        classes,
        confusion: Confusion { labels, rows },
        ratings: ratings
            .into_iter()
            .map(|(label, [clean, low, medium, high])| RatingCounts {
                label,
                clean,
                low,
                medium,
                high,
            })
            .collect(),
        latency_ms: Latency::from_samples(samples, opts.warmup),
        environment: Environment::current(),
    })
}

/// Benchmark results: aggregate metrics only, never images or per-image
/// results. This is also the format of the checked-in baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchReport {
    /// [`REPORT_FORMAT`].
    pub format: String,
    pub model: ModelSummary,
    pub policy: PolicySummary,
    pub set: SetSummary,
    /// Every class that is a true or a predicted class, sorted by label.
    pub classes: Vec<ClassMetrics>,
    pub confusion: Confusion,
    /// Per true class, sorted by label.
    pub ratings: Vec<RatingCounts>,
    pub latency_ms: Latency,
    pub environment: Environment,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSummary {
    pub name: String,
    pub version: String,
    pub license: String,
    pub blake3: String,
    pub input_size: InputSize,
    pub labels: Vec<String>,
}

/// The image thresholds of the policy the run used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    pub explicit_labels: Vec<String>,
    pub suggestive_labels: Vec<String>,
    pub other_labels: Vec<String>,
    pub explicit_high: f32,
    pub explicit_medium: f32,
    pub suggestive_medium: f32,
    pub any_low: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetSummary {
    pub images: usize,
    /// BLAKE3 (derive-key mode) over every image's class and file hash, in
    /// set order: changes whenever an image is added, removed, edited or
    /// moved to another class, and identifies no single image.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassMetrics {
    pub label: String,
    /// Images whose true class this is.
    pub support: usize,
    /// Images predicted as this class.
    pub predicted: usize,
    /// Images of this class predicted as this class.
    pub correct: usize,
    /// `correct / predicted`; `null` when nothing was predicted as it.
    pub precision: Option<f64>,
    /// `correct / support`; `null` when the set has no such images.
    pub recall: Option<f64>,
}

/// `rows[t][p]`: images of true class `labels[t]` predicted as `labels[p]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confusion {
    pub labels: Vec<String>,
    pub rows: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RatingCounts {
    /// True class.
    pub label: String,
    pub clean: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
}

/// Per-frame classification latency in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Latency {
    /// Timed frames.
    pub frames: usize,
    /// Untimed warm-up runs before them.
    pub warmup: usize,
    pub p50: f64,
    pub p95: f64,
    pub mean: f64,
    pub max: f64,
}

impl Latency {
    fn from_samples(mut ms: Vec<f64>, warmup: usize) -> Self {
        ms.sort_by(f64::total_cmp);
        let n = ms.len();
        // Microsecond resolution keeps baselines readable.
        let round = |v: f64| (v * 1000.0).round() / 1000.0;
        let rank = |q: f64| {
            if n == 0 {
                0.0
            } else {
                round(ms[((q * n as f64).ceil() as usize).clamp(1, n) - 1])
            }
        };
        Latency {
            frames: n,
            warmup,
            p50: rank(0.50),
            p95: rank(0.95),
            mean: round(if n == 0 {
                0.0
            } else {
                ms.iter().sum::<f64>() / n as f64
            }),
            max: round(ms.last().copied().unwrap_or(0.0)),
        }
    }
}

/// Where the numbers were measured. Latency is only comparable on the same
/// machine with the same build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    /// Built with optimisations (`--release`).
    pub optimized: bool,
    /// `faro-detect` version.
    pub faro_detect: String,
}

impl Environment {
    pub fn current() -> Self {
        Environment {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            optimized: !cfg!(debug_assertions),
            faro_detect: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

impl BenchReport {
    pub fn class(&self, label: &str) -> Option<&ClassMetrics> {
        self.classes.iter().find(|c| c.label == label)
    }

    /// Model labels no policy list mentions (ignored for the rating).
    pub fn ignored_labels(&self) -> Vec<&str> {
        let p = &self.policy;
        self.model
            .labels
            .iter()
            .filter(|l| {
                ![&p.explicit_labels, &p.suggestive_labels, &p.other_labels]
                    .iter()
                    .any(|list| list.contains(l))
            })
            .map(String::as_str)
            .collect()
    }

    /// Pretty JSON with a trailing newline, as checked in.
    pub fn to_json(&self) -> Vec<u8> {
        let mut v = serde_json::to_vec_pretty(self).expect("report serializes");
        v.push(b'\n');
        v
    }

    /// Parse a report, refusing other formats.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DetectError> {
        #[derive(Deserialize)]
        struct Probe {
            format: Option<String>,
        }
        let probe: Probe = serde_json::from_slice(bytes)
            .map_err(|e| DetectError::Bench(format!("not a benchmark report: {e}")))?;
        if probe.format.as_deref() != Some(REPORT_FORMAT) {
            return Err(DetectError::Bench(format!(
                "report format {:?}, this version reads {REPORT_FORMAT:?}",
                probe.format
            )));
        }
        serde_json::from_slice(bytes)
            .map_err(|e| DetectError::Bench(format!("malformed benchmark report: {e}")))
    }

    /// The human-readable summary.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        let m = &self.model;
        let p = &self.policy;
        let _ = writeln!(
            s,
            "model    {} {} ({}, blake3 {}), input {}x{}",
            m.name,
            m.version,
            m.license,
            m.blake3.get(..16).unwrap_or(&m.blake3),
            m.input_size.width,
            m.input_size.height
        );
        let ignored = self.ignored_labels();
        if !ignored.is_empty() {
            let _ = writeln!(
                s,
                "         labels ignored by the policy: {}",
                ignored.join(", ")
            );
        }
        let _ = writeln!(
            s,
            "policy   explicit >= {} high, >= {} medium; suggestive >= {} medium; any >= {} low",
            p.explicit_high, p.explicit_medium, p.suggestive_medium, p.any_low
        );
        let _ = writeln!(
            s,
            "set      {} images, digest {}",
            self.set.images,
            self.set.digest.get(..16).unwrap_or(&self.set.digest)
        );

        let w = self
            .confusion
            .labels
            .iter()
            .map(String::len)
            .chain([5])
            .max()
            .unwrap_or(5)
            + 2;
        let f = |v: Option<f64>| v.map_or("-".to_owned(), |v| format!("{v:.3}"));
        let _ = writeln!(
            s,
            "\n{:w$}{:>8}{:>10}{:>11}{:>8}",
            "class", "images", "predicted", "precision", "recall"
        );
        for c in &self.classes {
            let _ = writeln!(
                s,
                "{:w$}{:>8}{:>10}{:>11}{:>8}",
                c.label,
                c.support,
                c.predicted,
                f(c.precision),
                f(c.recall)
            );
        }

        let cw = w.max(8);
        let _ = writeln!(s, "\nconfusion (rows: true class, columns: predicted)");
        let _ = write!(s, "{:w$}", "");
        for l in &self.confusion.labels {
            let _ = write!(s, "{l:>cw$}");
        }
        let _ = writeln!(s);
        for (l, row) in self.confusion.labels.iter().zip(&self.confusion.rows) {
            let _ = write!(s, "{l:w$}");
            for v in row {
                let _ = write!(s, "{v:>cw$}");
            }
            let _ = writeln!(s);
        }

        let _ = writeln!(s, "\nratings (per true class)");
        let _ = writeln!(
            s,
            "{:w$}{:>8}{:>8}{:>8}{:>8}",
            "", "clean", "low", "medium", "high"
        );
        for r in &self.ratings {
            let _ = writeln!(
                s,
                "{:w$}{:>8}{:>8}{:>8}{:>8}",
                r.label, r.clean, r.low, r.medium, r.high
            );
        }

        let l = &self.latency_ms;
        let e = &self.environment;
        let _ = writeln!(
            s,
            "\nlatency  p50 {:.3} ms, p95 {:.3} ms, mean {:.3} ms, max {:.3} ms",
            l.p50, l.p95, l.mean, l.max
        );
        let _ = writeln!(
            s,
            "         {} frames after {} warm-up, classify only, {}-{}{}",
            l.frames,
            l.warmup,
            e.os,
            e.arch,
            if e.optimized {
                ""
            } else {
                ", UNOPTIMIZED build"
            }
        );
        s
    }
}

#[cfg(test)]
pub(crate) mod tests;
