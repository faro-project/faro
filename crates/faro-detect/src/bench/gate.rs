//! The regression gate: compare a run's report with the checked-in
//! baseline and fail when explicit recall or p95 latency got worse by more
//! than the allowed margin. Another model, preprocessing, policy or machine
//! is only a note.

use super::{BenchReport, EXPLICIT};
use crate::error::DetectError;
use std::fmt::Write as _;

/// Margins for [`gate`].
#[derive(Debug, Clone, PartialEq)]
pub struct GateConfig {
    /// Class whose recall is gated.
    pub recall_label: String,
    /// Largest allowed drop in recall, absolute (0.02 = two points).
    pub max_recall_drop: f64,
    /// Largest allowed p95 latency increase, relative (0.25 = 25 %).
    pub max_p95_increase: f64,
}

impl Default for GateConfig {
    fn default() -> Self {
        GateConfig {
            recall_label: EXPLICIT.to_owned(),
            max_recall_drop: 0.02,
            max_p95_increase: 0.25,
        }
    }
}

/// One gated metric.
#[derive(Debug, Clone, PartialEq)]
pub struct GateCheck {
    pub metric: String,
    pub baseline: f64,
    pub current: f64,
    /// The worst value that still passes.
    pub limit: f64,
    pub passed: bool,
}

/// What [`gate`] found.
#[derive(Debug, Clone, PartialEq)]
pub struct GateOutcome {
    pub checks: Vec<GateCheck>,
    /// Differences worth knowing that don't fail the gate (another model,
    /// policy or machine).
    pub notes: Vec<String>,
}

impl GateOutcome {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }

    pub fn to_text(&self) -> String {
        let mut s = String::from("gate\n");
        for c in &self.checks {
            let _ = writeln!(
                s,
                "  {:<22} baseline {:>9.3}  now {:>9.3}  limit {:>9.3}  {}",
                c.metric,
                c.baseline,
                c.current,
                c.limit,
                if c.passed { "ok" } else { "REGRESSION" }
            );
        }
        for n in &self.notes {
            let _ = writeln!(s, "  note: {n}");
        }
        s.push_str(if self.passed() { "PASS\n" } else { "FAIL\n" });
        s
    }
}

/// Compare `current` with `baseline`. An error means the two can't be
/// compared at all (another test set, a missing class, bad margins); a
/// regression is an `Ok` outcome that did not pass.
pub fn gate(
    baseline: &BenchReport,
    current: &BenchReport,
    cfg: &GateConfig,
) -> Result<GateOutcome, DetectError> {
    let bad = |m: String| Err(DetectError::Bench(m));
    for (name, v) in [
        ("max_recall_drop", cfg.max_recall_drop),
        ("max_p95_increase", cfg.max_p95_increase),
    ] {
        if !v.is_finite() || v < 0.0 {
            return bad(format!("{name} must be a non-negative number, got {v}"));
        }
    }
    if baseline.set.digest != current.set.digest {
        return bad(format!(
            "the test set changed (digest {} in the baseline, {} now): \
             re-run on the old set or check in a new baseline",
            short(&baseline.set.digest),
            short(&current.set.digest)
        ));
    }
    let recall = |r: &BenchReport, which: &str| {
        r.class(&cfg.recall_label)
            .and_then(|c| c.recall)
            .ok_or_else(|| {
                DetectError::Bench(format!(
                    "the {which} has no {:?} images to measure recall on",
                    cfg.recall_label
                ))
            })
    };
    let (rb, rc) = (recall(baseline, "baseline")?, recall(current, "run")?);
    let recall_limit = rb - cfg.max_recall_drop;
    let (pb, pc) = (baseline.latency_ms.p95, current.latency_ms.p95);
    if baseline.latency_ms.frames == 0 || current.latency_ms.frames == 0 {
        return bad("a report has no timed frames".into());
    }
    let p95_limit = pb * (1.0 + cfg.max_p95_increase);

    let mut notes = Vec::new();
    let (mb, mc) = (&baseline.model, &current.model);
    if (&mb.name, &mb.version, &mb.blake3) != (&mc.name, &mc.version, &mc.blake3) {
        notes.push(format!(
            "different model: baseline {} {} ({}), now {} {} ({})",
            mb.name,
            mb.version,
            short(&mb.blake3),
            mc.name,
            mc.version,
            short(&mc.blake3)
        ));
    }
    if mb.resize != mc.resize {
        notes.push(format!(
            "different preprocessing: baseline resize {}, now {}",
            mb.resize, mc.resize
        ));
    }
    if baseline.policy != current.policy {
        notes.push("the policy's image thresholds or labels differ from the baseline's".into());
    }
    if baseline.environment != current.environment {
        let e = |r: &BenchReport| {
            let e = &r.environment;
            format!(
                "{}-{}{} faro-detect {}",
                e.os,
                e.arch,
                if e.optimized { "" } else { " unoptimized" },
                e.faro_detect
            )
        };
        notes.push(format!(
            "measured elsewhere (baseline {}, now {}): latency may not be comparable",
            e(baseline),
            e(current)
        ));
    }

    Ok(GateOutcome {
        checks: vec![
            GateCheck {
                metric: format!("{} recall", cfg.recall_label),
                baseline: rb,
                current: rc,
                limit: recall_limit,
                // A hair of slack so that equal ratios never fail on
                // floating-point noise.
                passed: rc >= recall_limit - 1e-9,
            },
            GateCheck {
                metric: "p95 latency (ms)".into(),
                baseline: pb,
                current: pc,
                limit: p95_limit,
                passed: pc <= p95_limit + 1e-9,
            },
        ],
        notes,
    })
}

fn short(hex: &str) -> &str {
    hex.get(..16).unwrap_or(hex)
}
