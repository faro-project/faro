//! The `model-bench` command line (feature `onnx`). It lives in the library
//! rather than in the example so that tests can drive it.
//!
//! Exit status: 0 when everything ran (and the gate, if any, passed), 1 on
//! a regression, 2 on any error, including results that can't be compared.

use super::{compare_text, gate, run, BenchReport, EvalSet, GateConfig, RunOptions};
use crate::classifier::onnx::OnnxClassifier;
use crate::classifier::{load_model, load_model_at, Resize, VerifiedModel};
use crate::error::DetectError;
use crate::fusion::{PolicyConfig, PolicyEngine};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const USAGE: &str = "\
usage: model-bench --manifest M.json [--model M.onnx] --set DIR [options]
       model-bench --results R.json --baseline B.json [gate options]
       model-bench --write-synthetic-set DIR

Benchmark an ONNX image classifier on a labelled set of PNG screenshots
(DIR/explicit, DIR/suggestive, DIR/neutral, ...) and print per-class
precision and recall at the policy thresholds, a confusion matrix, the
ratings per class and CPU latency. Nothing but metrics is ever written.

  --manifest PATH        model manifest (licence and BLAKE3 are checked)
  --model PATH           model file, instead of the manifest's `file`
  --set DIR              the labelled test set
  --policy PATH          policy JSON (default: the built-in policy)
  --resize LIST          how frames become the model's input, instead of the
                         manifest's `resize`: direct (the whole frame) or
                         resize_crop:SIDE (to SIDE x SIDE, then the centre).
                         Several, comma-separated (direct,resize_crop:256),
                         run each on the same set and compare them
  --json PATH            also write the results as JSON; with several
                         --resize modes, one file each (r.json becomes
                         r.direct.json and r.resize_crop-256.json)
  --warmup N             untimed runs before timing (default 3)
  --baseline PATH        gate the results against this baseline report
  --results PATH         gate an existing report instead of running
  --write-synthetic-set DIR
                         write the synthetic set (15 solid colours and
                         UI-like windows, labelled by colour) into DIR, a
                         new or empty folder, and exit. For measuring
                         latency without any real image: its precision and
                         recall mean nothing for a real model.

gate options:
  --recall-label NAME    class whose recall is gated (default explicit)
  --max-recall-drop F    allowed absolute recall drop (default 0.02)
  --max-p95-increase F   allowed relative p95 increase (default 0.25)

exit status: 0 ok, 1 regression, 2 error
";

#[derive(Debug, Default)]
struct Args {
    manifest: Option<PathBuf>,
    model: Option<PathBuf>,
    set: Option<PathBuf>,
    policy: Option<PathBuf>,
    /// Empty: the manifest's.
    resize: Vec<Resize>,
    json: Option<PathBuf>,
    baseline: Option<PathBuf>,
    results: Option<PathBuf>,
    write_synthetic_set: Option<PathBuf>,
    warmup: Option<usize>,
    gate: GateConfig,
    help: bool,
}

fn parse(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        if flag == "-h" || flag == "--help" {
            a.help = true;
            continue;
        }
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        let path = |v: String| Some(PathBuf::from(v));
        let number = |v: String| {
            v.parse::<f64>()
                .map_err(|_| format!("{flag}: {v:?} is not a number"))
        };
        match flag.as_str() {
            "--manifest" => a.manifest = path(value()?),
            "--model" => a.model = path(value()?),
            "--set" => a.set = path(value()?),
            "--policy" => a.policy = path(value()?),
            "--resize" => {
                a.resize.clear();
                for mode in value()?.split(',') {
                    let r: Resize = mode.trim().parse().map_err(|e| format!("--resize: {e}"))?;
                    if a.resize.contains(&r) {
                        return Err(format!("--resize: {r} twice"));
                    }
                    a.resize.push(r);
                }
            }
            "--json" => a.json = path(value()?),
            "--baseline" => a.baseline = path(value()?),
            "--results" => a.results = path(value()?),
            "--write-synthetic-set" => a.write_synthetic_set = path(value()?),
            "--warmup" => {
                let v = value()?;
                a.warmup = Some(v.parse().map_err(|_| format!("--warmup: {v:?}"))?);
            }
            "--recall-label" => a.gate.recall_label = value()?,
            "--max-recall-drop" => a.gate.max_recall_drop = number(value()?)?,
            "--max-p95-increase" => a.gate.max_p95_increase = number(value()?)?,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(a)
}

fn read_report(path: &Path) -> Result<BenchReport, DetectError> {
    let bytes = std::fs::read(path).map_err(|source| DetectError::Io {
        path: path.to_owned(),
        source,
    })?;
    BenchReport::from_json(&bytes)
        .map_err(|e| DetectError::Bench(format!("{}: {e}", path.display())))
}

/// `results.json` → `results.resize_crop-256.json`: one report per mode,
/// with no `:` in the name.
fn json_path(path: &Path, resize: Resize) -> PathBuf {
    let mode = resize.to_string().replace(':', "-");
    let stem = match path.extension() {
        Some(e) if e == "json" => path.with_extension(""),
        _ => path.to_owned(),
    };
    let mut name = stem.into_os_string();
    name.push(format!(".{mode}.json"));
    PathBuf::from(name)
}

fn load_policy(path: Option<&Path>) -> Result<PolicyEngine, DetectError> {
    let cfg = match path {
        None => PolicyConfig::default(),
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|source| DetectError::Io {
                path: p.to_owned(),
                source,
            })?;
            serde_json::from_slice(&bytes)
                .map_err(|e| DetectError::Config(format!("{}: {e}", p.display())))?
        }
    };
    PolicyEngine::new(cfg)
}

/// Run the tool. `args` excludes the program name. Returns the exit status.
pub fn main(
    args: impl IntoIterator<Item = String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let args = match parse(args) {
        Ok(a) if a.help => {
            let _ = out.write_all(USAGE.as_bytes());
            return 0;
        }
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(err, "model-bench: {e}\n\n{USAGE}");
            return 2;
        }
    };
    match execute(&args, out, err) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(DetectError::Bench(m)) => {
            let _ = writeln!(err, "model-bench: {m}");
            2
        }
        Err(e) => {
            let _ = writeln!(err, "model-bench: {e}");
            2
        }
    }
}

/// `Ok(false)` is a regression.
fn execute(a: &Args, out: &mut dyn Write, err: &mut dyn Write) -> Result<bool, DetectError> {
    let usage = |m: &str| DetectError::Bench(format!("{m} (see --help)"));
    if let Some(dir) = &a.write_synthetic_set {
        if a.manifest.is_some()
            || a.set.is_some()
            || a.results.is_some()
            || a.baseline.is_some()
            || !a.resize.is_empty()
        {
            return Err(usage("--write-synthetic-set takes no other option"));
        }
        let io = |source| DetectError::Io {
            path: dir.clone(),
            source,
        };
        match std::fs::read_dir(dir) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(usage("--write-synthetic-set needs a new or empty folder"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        super::synthetic::write_synthetic_set(dir)?;
        let _ = writeln!(out, "wrote the synthetic set to {}", dir.display());
        return Ok(true);
    }
    let report = if let Some(results) = &a.results {
        if a.manifest.is_some() || a.set.is_some() || a.json.is_some() || !a.resize.is_empty() {
            return Err(usage(
                "--results gates an existing report; it takes no --manifest, --set, --resize or --json",
            ));
        }
        if a.baseline.is_none() {
            return Err(usage("--results needs --baseline"));
        }
        read_report(results)?
    } else {
        let (Some(manifest), Some(set)) = (&a.manifest, &a.set) else {
            return Err(usage("--manifest and --set are required"));
        };
        let compare = a.resize.len() > 1;
        if compare && a.baseline.is_some() {
            return Err(usage(
                "gate one run at a time: --results PATH.<mode>.json --baseline B.json",
            ));
        }
        let policy = load_policy(a.policy.as_deref())?;
        // Read the baseline first so that a typo fails before a long run.
        if let Some(b) = &a.baseline {
            read_report(b)?;
        }
        let model = match &a.model {
            Some(m) => load_model_at(manifest, m)?,
            None => load_model(manifest)?,
        };
        let set = EvalSet::open(set, &super::allowed_classes(policy.config()))?;
        if cfg!(debug_assertions) {
            let _ = writeln!(
                err,
                "model-bench: warning: unoptimized build, latency is not representative (use --release)"
            );
        }
        let opts = RunOptions {
            warmup: a.warmup.unwrap_or(RunOptions::default().warmup),
        };
        let modes = match a.resize.as_slice() {
            [] => vec![model.info().resize],
            m => m.to_vec(),
        };
        let mut reports = Vec::with_capacity(modes.len());
        for (i, &resize) in modes.iter().enumerate() {
            let mut info = model.info().clone();
            info.resize = resize;
            // The same checks as the manifest's own setting (the crop must
            // fit), and the weights are the bytes already verified.
            let mut classifier =
                OnnxClassifier::new(VerifiedModel::verify(info, model.bytes().to_vec())?)?;
            if compare {
                let _ = writeln!(
                    out,
                    "{}== resize {resize} ==",
                    if i > 0 { "\n" } else { "" }
                );
            }
            let report = run(&mut classifier, &policy, &set, &opts)?;
            let _ = out.write_all(report.to_text().as_bytes());
            if let Some(path) = &a.json {
                let path = if compare {
                    json_path(path, resize)
                } else {
                    path.clone()
                };
                std::fs::write(&path, report.to_json())
                    .map_err(|source| DetectError::Io { path, source })?;
            }
            reports.push(report);
        }
        if compare {
            let names: Vec<String> = modes.iter().map(Resize::to_string).collect();
            let runs: Vec<(&str, &BenchReport)> =
                names.iter().map(String::as_str).zip(&reports).collect();
            let _ = writeln!(out);
            let _ = out.write_all(compare_text(&runs)?.as_bytes());
            return Ok(true);
        }
        reports.pop().expect("one run")
    };

    let Some(baseline) = &a.baseline else {
        return Ok(true);
    };
    let outcome = gate(&read_report(baseline)?, &report, &a.gate)?;
    let _ = writeln!(out, "\nbaseline {}", baseline.display());
    let _ = out.write_all(outcome.to_text().as_bytes());
    Ok(outcome.passed())
}
