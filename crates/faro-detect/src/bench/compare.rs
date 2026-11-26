//! Side-by-side metrics of several runs on the same set, such as one model
//! under each [`Resize`](crate::Resize) (`model-bench --resize
//! direct,resize_crop:256`). Aggregates only, like the reports themselves.

use super::BenchReport;
use crate::error::DetectError;
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// Per-class precision, recall and ratings, and p95 latency, of each run in
/// a column headed by its name. The runs must be on the same set.
pub fn compare_text(runs: &[(&str, &BenchReport)]) -> Result<String, DetectError> {
    let Some((_, first)) = runs.first() else {
        return Err(DetectError::Bench("nothing to compare".into()));
    };
    if let Some((name, _)) = runs.iter().find(|(_, r)| r.set != first.set) {
        return Err(DetectError::Bench(format!(
            "run {name:?} is on another set (the images changed during the runs?)"
        )));
    }
    let classes: BTreeSet<&str> = runs
        .iter()
        .flat_map(|(_, r)| r.classes.iter().map(|c| c.label.as_str()))
        .collect();
    let lw = classes.iter().map(|c| c.len()).max().unwrap_or(0).max(8) + 2;
    let mw = 23;
    let cw = runs.iter().map(|(n, _)| n.len()).max().unwrap_or(0).max(9) + 2;
    let f = |v: Option<f64>| v.map_or("-".to_owned(), |v| format!("{v:.3}"));

    let mut s = String::new();
    let _ = writeln!(
        s,
        "comparison on the same set ({} images, digest {})",
        first.set.images,
        first.set.digest.get(..16).unwrap_or(&first.set.digest)
    );
    let _ = write!(s, "{:lw$}{:mw$}", "", "");
    for (name, _) in runs {
        let _ = write!(s, "{name:>cw$}");
    }
    let _ = writeln!(s);
    let row = |s: &mut String, class: &str, metric: &str, cells: Vec<String>| {
        let _ = write!(s, "{class:lw$}{metric:mw$}");
        for c in cells {
            let _ = write!(s, "{c:>cw$}");
        }
        let _ = writeln!(s);
    };
    for class in &classes {
        let metric = |m: fn(&super::ClassMetrics) -> Option<f64>| {
            runs.iter()
                .map(|(_, r)| f(r.class(class).and_then(m)))
                .collect()
        };
        row(&mut s, class, "precision", metric(|c| c.precision));
        row(&mut s, "", "recall", metric(|c| c.recall));
        let ratings = runs
            .iter()
            .map(|(_, r)| {
                r.ratings
                    .iter()
                    .find(|x| x.label == *class)
                    .map_or("-".to_owned(), |x| {
                        format!("{}/{}/{}/{}", x.clean, x.low, x.medium, x.high)
                    })
            })
            .collect();
        row(&mut s, "", "clean/low/medium/high", ratings);
    }
    let p95 = runs
        .iter()
        .map(|(_, r)| format!("{:.3}", r.latency_ms.p95))
        .collect();
    row(&mut s, "latency", "p95 ms", p95);
    Ok(s)
}
