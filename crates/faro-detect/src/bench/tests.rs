//! Harness tests on a synthetic set generated here: solid colours and
//! UI-like noise, never a real image. A "classifier" that answers by the
//! dominant colour (red → explicit, green → neutral, blue → suggestive) is
//! enough to exercise every metric. It runs in pure Rust in every build and,
//! with the `onnx` feature, as a real ONNX graph through `OnnxClassifier`.

use super::*;
use crate::classifier::TensorLayout;
use crate::classifier::{postprocess, preprocess, ChannelOrder, ModelInfo, OutputActivation};
use faro_platform::Frame;
use std::path::Path;

/// Labels in output (= RGB channel) order.
const LABELS: [&str; 3] = ["explicit", "neutral", "suggestive"];

pub(crate) fn colour_info(blake3: String) -> ModelInfo {
    ModelInfo {
        name: "dominant-colour".into(),
        version: "1".into(),
        file: "model.onnx".into(),
        input_size: InputSize {
            width: 8,
            height: 8,
        },
        labels: LABELS.map(String::from).to_vec(),
        mean: [0.0; 3],
        std: [0.1; 3],
        channel_order: ChannelOrder::Rgb,
        layout: TensorLayout::Nchw,
        input_scale: 1.0 / 255.0,
        output: OutputActivation::Softmax,
        license: "MIT".into(),
        license_text: Some(crate::classifier::test_support::MIT_TEXT.into()),
        attribution: Some(crate::classifier::test_support::attribution()),
        blake3,
    }
}

/// Softmax over the mean of each normalised channel: the same arithmetic
/// as the `GlobalAveragePool` ONNX graph in `classifier::test_onnx`.
pub(crate) struct DominantColour(ModelInfo);

impl DominantColour {
    pub(crate) fn new() -> Self {
        DominantColour(colour_info("00".repeat(32)))
    }
}

impl Classifier for DominantColour {
    fn info(&self) -> &ModelInfo {
        &self.0
    }

    fn classify(&mut self, frame: &Frame) -> Result<ImageScores, DetectError> {
        let t = preprocess(frame, &self.0);
        let n = t.len() / 3;
        let means: Vec<f32> = t
            .chunks_exact(n)
            .map(|c| c.iter().sum::<f32>() / n as f32)
            .collect();
        postprocess(&means, &self.0)
    }
}

/// Deterministic xorshift, for UI noise.
struct Rng(u32);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
}

/// An RGB image description.
struct Img {
    w: u32,
    h: u32,
    px: Vec<[u8; 3]>,
}

impl Img {
    fn solid(w: u32, h: u32, c: [u8; 3]) -> Self {
        Img {
            w,
            h,
            px: vec![c; (w * h) as usize],
        }
    }

    fn rect(&mut self, x0: u32, y0: u32, x1: u32, y1: u32, c: [u8; 3]) {
        for y in y0..y1.min(self.h) {
            for x in x0..x1.min(self.w) {
                self.px[(y * self.w + x) as usize] = c;
            }
        }
    }

    /// A window: `bg`, a toolbar, a sidebar, lines of "text" and a content
    /// panel of `accent` covering about `accent_frac` of the window, plus
    /// a little per-pixel noise.
    fn ui(bg: [u8; 3], accent: [u8; 3], accent_frac: f32, seed: u32) -> Self {
        let (w, h) = (160u32, 100u32);
        let mut img = Img::solid(w, h, bg);
        let mut rng = Rng(seed | 1);
        let shade = |c: [u8; 3], d: i32| c.map(|v| (i32::from(v) + d).clamp(0, 255) as u8);
        img.rect(0, 0, w, 10, shade(bg, -30)); // toolbar
        img.rect(0, 10, 24, h, shade(bg, -15)); // sidebar
        for line in 0..8 {
            let y = 16 + line * 10;
            let len = 30 + rng.below(90);
            img.rect(30, y, 30 + len, y + 3, shade(bg, -90)); // text
        }
        let side = ((accent_frac * (w * h) as f32).sqrt()) as u32;
        let (x0, y0) = (w - side.min(w), h - side.min(h));
        img.rect(x0, y0, w, h, accent);
        for p in &mut img.px {
            let n = rng.below(9) as i32 - 4;
            *p = shade(*p, n);
        }
        img
    }

    fn save(&self, path: &Path, color: image::ExtendedColorType) {
        let data: Vec<u8> = match color {
            image::ExtendedColorType::Rgb8 => self.px.iter().flatten().copied().collect(),
            image::ExtendedColorType::Rgba8 => self
                .px
                .iter()
                .flat_map(|&[r, g, b]| [r, g, b, 255])
                .collect(),
            image::ExtendedColorType::L8 => self.px.iter().map(|p| p[0]).collect(),
            other => panic!("{other:?}"),
        };
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut out = Vec::new();
        image::ImageEncoder::write_image(
            image::codecs::png::PngEncoder::new(&mut out),
            &data,
            self.w,
            self.h,
            color,
        )
        .unwrap();
        std::fs::write(path, out).unwrap();
    }
}

/// Write the synthetic set: 6 explicit, 6 neutral, 3 suggestive images.
pub(crate) fn write_synthetic_set(root: &Path) {
    use image::ExtendedColorType::{Rgb8, Rgba8, L8};
    let grey = [190, 190, 190];
    let red = [230, 20, 20];
    let blue = [40, 60, 210];
    let green = [40, 180, 60];
    let images: [(&str, Img, image::ExtendedColorType); 15] = [
        (
            "explicit/solid.png",
            Img::solid(96, 64, [220, 30, 30]),
            Rgba8,
        ),
        (
            "explicit/ui-red-panel.png",
            Img::ui(grey, red, 0.7, 1),
            Rgb8,
        ),
        // Larger than MAX_FRAME_SIDE: downscaled first, as in production.
        (
            "explicit/big/dark-red.png",
            Img::solid(1000, 600, [140, 25, 25]),
            Rgba8,
        ),
        (
            "explicit/magenta.png",
            Img::solid(64, 64, [200, 40, 170]),
            Rgba8,
        ),
        // Missed: a mostly grey window with a tiny red patch.
        (
            "explicit/ui-tiny-patch.png",
            Img::ui(grey, red, 0.01, 2),
            Rgba8,
        ),
        // Confused: more blue than red.
        (
            "explicit/violet.png",
            Img::solid(64, 64, [150, 30, 230]),
            Rgba8,
        ),
        ("neutral/grey.png", Img::solid(64, 64, [128, 128, 128]), L8),
        (
            "neutral/ui-light.png",
            Img::ui([235, 235, 235], green, 0.2, 3),
            Rgba8,
        ),
        (
            "neutral/ui-dark.png",
            Img::ui([40, 40, 40], [90, 90, 90], 0.3, 4),
            Rgb8,
        ),
        (
            "neutral/green.png",
            Img::solid(64, 64, [30, 200, 60]),
            Rgba8,
        ),
        (
            "neutral/white.png",
            Img::solid(64, 64, [255, 255, 255]),
            Rgba8,
        ),
        // False positive: orange reads as red.
        (
            "neutral/orange.png",
            Img::solid(64, 64, [230, 90, 40]),
            Rgba8,
        ),
        ("suggestive/blue.png", Img::solid(64, 64, blue), Rgba8),
        (
            "suggestive/ui-blue-panel.png",
            Img::ui(grey, blue, 0.7, 5),
            Rgba8,
        ),
        // Missed: just a grey window.
        (
            "suggestive/ui-plain.png",
            Img::ui([150, 150, 150], [150, 150, 150], 0.0, 6),
            Rgba8,
        ),
    ];
    for (rel, img, color) in images {
        img.save(&root.join(rel), color);
    }
}

fn open(root: &Path) -> EvalSet {
    EvalSet::open(root, &allowed_classes(&PolicyConfig::default())).unwrap()
}

/// What the synthetic set must produce, whichever runtime computes it.
pub(crate) fn assert_synthetic_metrics(r: &BenchReport) {
    assert_eq!(r.format, REPORT_FORMAT);
    assert_eq!(r.set.images, 15);
    assert_eq!(r.confusion.labels, ["explicit", "neutral", "suggestive"]);
    assert_eq!(r.confusion.rows, [[4, 1, 1], [1, 5, 0], [0, 1, 2]]);
    let m = |l: &str| r.class(l).unwrap();
    assert_eq!(
        (
            m("explicit").support,
            m("explicit").predicted,
            m("explicit").correct
        ),
        (6, 5, 4)
    );
    assert_eq!(m("explicit").precision, Some(0.8));
    assert_eq!(m("explicit").recall, Some(4.0 / 6.0));
    assert_eq!(m("neutral").precision, Some(5.0 / 7.0));
    assert_eq!(m("neutral").recall, Some(5.0 / 6.0));
    assert_eq!(m("suggestive").precision, Some(2.0 / 3.0));
    assert_eq!(m("suggestive").recall, Some(2.0 / 3.0));
    let rating = |l: &str| {
        let x = r.ratings.iter().find(|x| x.label == l).unwrap();
        [x.clean, x.low, x.medium, x.high]
    };
    assert_eq!(rating("explicit"), [1, 0, 2, 3]);
    assert_eq!(rating("neutral"), [5, 0, 0, 1]);
    assert_eq!(rating("suggestive"), [1, 0, 2, 0]);
    assert_eq!(r.latency_ms.frames, 15);
    assert!(r.latency_ms.p50 <= r.latency_ms.p95 && r.latency_ms.p95 <= r.latency_ms.max);
    assert!(r.ignored_labels() == ["neutral"]);
}

/// Every file under `root`, relative, sorted.
pub(crate) fn tree(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_owned()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p.strip_prefix(root).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

#[test]
fn synthetic_set_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    write_synthetic_set(dir.path());
    let before = tree(dir.path());
    let set = open(dir.path());
    let policy = PolicyEngine::default();
    let r = run(
        &mut DominantColour::new(),
        &policy,
        &set,
        &RunOptions::default(),
    )
    .unwrap();
    assert_synthetic_metrics(&r);
    assert_eq!(r.latency_ms.warmup, 3);
    // The run wrote nothing.
    assert_eq!(tree(dir.path()), before);

    // Same files, same digest; the report round-trips and gates clean
    // against itself.
    let again = run(
        &mut DominantColour::new(),
        &policy,
        &set,
        &RunOptions { warmup: 0 },
    )
    .unwrap();
    assert_eq!(again.set, r.set);
    assert_eq!(again.confusion, r.confusion);
    let back = BenchReport::from_json(&r.to_json()).unwrap();
    assert_eq!(back, r);
    assert!(gate(&r, &back, &GateConfig::default()).unwrap().passed());

    // The JSON is metrics only: no file names, no paths.
    let json = String::from_utf8(r.to_json()).unwrap();
    for word in [".png", "ui-", "solid", "big", "orange", "violet"] {
        assert!(!json.contains(word), "{word} in {json}");
    }
    assert!(!json.contains(&*dir.path().to_string_lossy()));

    let text = r.to_text();
    assert!(text.contains("explicit"), "{text}");
    assert!(
        text.contains("labels ignored by the policy: neutral"),
        "{text}"
    );

    // Moving one image to another class changes the digest.
    std::fs::rename(
        dir.path().join("neutral/orange.png"),
        dir.path().join("explicit/orange.png"),
    )
    .unwrap();
    let moved = run(
        &mut DominantColour::new(),
        &policy,
        &open(dir.path()),
        &RunOptions { warmup: 0 },
    )
    .unwrap();
    assert_ne!(moved.set.digest, r.set.digest);
    assert!(matches!(
        gate(&r, &moved, &GateConfig::default()),
        Err(DetectError::Bench(_))
    ));
}

#[test]
fn policy_thresholds_drive_the_prediction() {
    let s = |v: &[(&str, f32)]| ImageScores::new(v.iter().copied()).unwrap();
    let p = PolicyEngine::default();
    let class = |v: &[(&str, f32)]| predict(&p, &s(v));
    assert_eq!(
        class(&[("explicit", 0.39)]),
        (NEUTRAL.into(), Rating::Clean)
    );
    assert_eq!(class(&[("porn", 0.40)]), (EXPLICIT.into(), Rating::Low));
    assert_eq!(
        class(&[("explicit", 0.9), ("sexy", 0.95)]),
        (EXPLICIT.into(), Rating::High)
    );
    // Same strength: the higher score is the top reason, as in production.
    assert_eq!(
        class(&[("explicit", 0.7), ("suggestive", 0.9)]),
        (SUGGESTIVE.into(), Rating::Medium)
    );
    assert_eq!(class(&[("gore", 0.5)]), ("gore".into(), Rating::Low));
    assert_eq!(class(&[("neutral", 0.99)]), (NEUTRAL.into(), Rating::Clean));

    // A stricter policy moves the operating point.
    let strict = PolicyEngine::new(PolicyConfig {
        any_low: 0.6,
        ..Default::default()
    })
    .unwrap();
    assert_eq!(predict(&strict, &s(&[("explicit", 0.5)])).0, NEUTRAL);
    assert_eq!(
        allowed_classes(&PolicyConfig::default()),
        [
            "explicit",
            "gambling",
            "gore",
            "neutral",
            "suggestive",
            "violence"
        ]
    );
}

#[test]
fn latency_percentiles_are_nearest_rank() {
    let l = Latency::from_samples((1..=20).rev().map(f64::from).collect(), 2);
    assert_eq!((l.frames, l.warmup), (20, 2));
    assert_eq!((l.p50, l.p95, l.max), (10.0, 19.0, 20.0));
    assert_eq!(l.mean, 10.5);
    let one = Latency::from_samples(vec![0.123_456_7], 0);
    assert_eq!((one.p50, one.p95, one.max), (0.123, 0.123, 0.123));
    assert_eq!(Latency::from_samples(vec![], 0).frames, 0);
}

fn sample_report() -> BenchReport {
    let dir = tempfile::tempdir().unwrap();
    write_synthetic_set(dir.path());
    let mut r = run(
        &mut DominantColour::new(),
        &PolicyEngine::default(),
        &open(dir.path()),
        &RunOptions { warmup: 0 },
    )
    .unwrap();
    r.latency_ms.p95 = 40.0;
    r
}

fn set_recall(r: &mut BenchReport, label: &str, v: f64) {
    r.classes
        .iter_mut()
        .find(|c| c.label == label)
        .unwrap()
        .recall = Some(v);
}

#[test]
fn gate_passes_a_match_and_fails_a_crafted_regression() {
    let base = sample_report();
    let cfg = GateConfig::default();
    let out = gate(&base, &base, &cfg).unwrap();
    assert!(out.passed(), "{}", out.to_text());
    assert!(out.notes.is_empty());
    assert!(out.to_text().ends_with("PASS\n"));

    // Explicit recall: a 0.01 drop is inside the default 0.02 margin...
    let mut now = base.clone();
    set_recall(&mut now, "explicit", 4.0 / 6.0 - 0.01);
    assert!(gate(&base, &now, &cfg).unwrap().passed());
    // ...0.05 is not.
    set_recall(&mut now, "explicit", 4.0 / 6.0 - 0.05);
    let out = gate(&base, &now, &cfg).unwrap();
    assert!(!out.passed());
    assert!(!out.checks[0].passed && out.checks[1].passed);
    assert!(out.to_text().contains("REGRESSION"));
    assert!(out.to_text().ends_with("FAIL\n"));
    // Other classes are not gated.
    let mut now = base.clone();
    set_recall(&mut now, "suggestive", 0.0);
    assert!(gate(&base, &now, &cfg).unwrap().passed());
    // Unless asked for, with a configurable margin.
    let sg = GateConfig {
        recall_label: "suggestive".into(),
        max_recall_drop: 1.0,
        ..Default::default()
    };
    assert!(gate(&base, &now, &sg).unwrap().passed());

    // p95: +20 % passes, +30 % fails, and the margin is configurable.
    let mut now = base.clone();
    now.latency_ms.p95 = 48.0;
    assert!(gate(&base, &now, &cfg).unwrap().passed());
    now.latency_ms.p95 = 52.0;
    let out = gate(&base, &now, &cfg).unwrap();
    assert!(!out.passed() && out.checks[0].passed && !out.checks[1].passed);
    let loose = GateConfig {
        max_p95_increase: 0.5,
        ..Default::default()
    };
    assert!(gate(&base, &now, &loose).unwrap().passed());
    // Getting better never fails.
    now.latency_ms.p95 = 1.0;
    set_recall(&mut now, "explicit", 1.0);
    assert!(gate(&base, &now, &cfg).unwrap().passed());
}

#[test]
fn gate_refuses_incomparable_reports() {
    let base = sample_report();
    let cfg = GateConfig::default();
    let mut other = base.clone();
    other.set.digest = "ff".repeat(32);
    assert!(gate(&base, &other, &cfg).is_err());

    let mut no_explicit = base.clone();
    set_recall(&mut no_explicit, "explicit", 0.0);
    no_explicit
        .classes
        .iter_mut()
        .find(|c| c.label == "explicit")
        .unwrap()
        .recall = None;
    assert!(gate(&base, &no_explicit, &cfg).is_err());
    assert!(gate(&no_explicit, &base, &cfg).is_err());

    for bad in [-0.1, f64::NAN, f64::INFINITY] {
        let c = GateConfig {
            max_recall_drop: bad,
            ..Default::default()
        };
        assert!(gate(&base, &base, &c).is_err());
    }

    // Different model, policy or machine: compared, with a note.
    let mut now = base.clone();
    now.model.version = "2".into();
    now.policy.any_low = 0.5;
    now.environment.optimized = !now.environment.optimized;
    let out = gate(&base, &now, &cfg).unwrap();
    assert!(out.passed());
    assert_eq!(out.notes.len(), 3, "{:?}", out.notes);
}

#[test]
fn report_format_is_checked() {
    let r = sample_report();
    let mut v: serde_json::Value = serde_json::from_slice(&r.to_json()).unwrap();
    v["format"] = "faro-model-bench/0".into();
    assert!(BenchReport::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    v["format"] = REPORT_FORMAT.into();
    v["per_image"] = serde_json::json!([]);
    assert!(BenchReport::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(BenchReport::from_json(b"[]").is_err());
}

#[cfg(feature = "onnx")]
mod onnx {
    use super::*;
    use crate::classifier::test_onnx::mean_pool_model;
    use crate::classifier::{load_model, onnx::OnnxClassifier};

    /// Write the mean-pool graph and its manifest; return the manifest path.
    fn write_model(dir: &Path) -> std::path::PathBuf {
        let model = mean_pool_model(8);
        std::fs::write(dir.join("model.onnx"), &model).unwrap();
        let info = colour_info(blake3::hash(&model).to_hex().to_string());
        let p = dir.join("model.json");
        std::fs::write(&p, serde_json::to_vec_pretty(&info).unwrap()).unwrap();
        p
    }

    #[test]
    fn real_onnx_graph_on_the_synthetic_set() {
        let models = tempfile::tempdir().unwrap();
        let set_dir = tempfile::tempdir().unwrap();
        write_synthetic_set(set_dir.path());
        let mut c = OnnxClassifier::new(load_model(write_model(models.path())).unwrap()).unwrap();
        let r = run(
            &mut c,
            &PolicyEngine::default(),
            &open(set_dir.path()),
            &RunOptions::default(),
        )
        .unwrap();
        assert_synthetic_metrics(&r);
        assert_eq!(r.model.name, "dominant-colour");
    }

    fn cli(args: &[&str]) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = cli::main(args.iter().map(|s| s.to_string()), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn command_line_runs_and_gates() {
        let models = tempfile::tempdir().unwrap();
        let set_dir = tempfile::tempdir().unwrap();
        let out_dir = tempfile::tempdir().unwrap();
        write_synthetic_set(set_dir.path());
        let manifest = write_model(models.path());
        let s = |p: &Path| p.to_str().unwrap().to_owned();
        let (manifest, set) = (s(&manifest), s(set_dir.path()));
        let results = s(&out_dir.path().join("results.json"));
        let set_before = tree(set_dir.path());

        let (code, out, err) = cli(&[
            "--manifest",
            &manifest,
            "--set",
            &set,
            "--json",
            &results,
            "--warmup",
            "1",
        ]);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("confusion"), "{out}");
        // Only the JSON was written, and nothing next to the images.
        assert_eq!(tree(out_dir.path()), ["results.json"]);
        assert_eq!(tree(set_dir.path()), set_before);
        let report = BenchReport::from_json(&std::fs::read(&results).unwrap()).unwrap();
        assert_synthetic_metrics(&report);
        assert_eq!(report.latency_ms.warmup, 1);

        // A matching baseline passes (gate only, and gate after a run with
        // a generous latency margin since timings vary run to run).
        let (code, out, _) = cli(&["--results", &results, "--baseline", &results]);
        assert_eq!(code, 0);
        assert!(out.ends_with("PASS\n"), "{out}");
        let (code, _, err) = cli(&[
            "--manifest",
            &manifest,
            "--set",
            &set,
            "--baseline",
            &results,
            "--max-p95-increase",
            "1000",
        ]);
        assert_eq!(code, 0, "{err}");

        // A crafted regression fails with status 1.
        let mut better = report.clone();
        set_recall(&mut better, "explicit", 0.9);
        let crafted = out_dir.path().join("baseline.json");
        std::fs::write(&crafted, better.to_json()).unwrap();
        let (code, out, _) = cli(&["--results", &results, "--baseline", &s(&crafted)]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("REGRESSION"), "{out}"); // A looser margin lets it through.
        let (code, _, _) = cli(&[
            "--results",
            &results,
            "--baseline",
            &s(&crafted),
            "--max-recall-drop",
            "0.3",
        ]);
        assert_eq!(code, 0);
        let mut faster = report.clone();
        faster.latency_ms.p95 = report.latency_ms.p95 / 10.0;
        std::fs::write(&crafted, faster.to_json()).unwrap();
        let (code, _, _) = cli(&["--results", &results, "--baseline", &s(&crafted)]);
        assert_eq!(code, 1);

        // Another set: an error (2), not a pass.
        let mut moved = report.clone();
        moved.set.digest = "ab".repeat(32);
        std::fs::write(&crafted, moved.to_json()).unwrap();
        let (code, _, err) = cli(&["--results", &results, "--baseline", &s(&crafted)]);
        assert_eq!(code, 2);
        assert!(err.contains("test set changed"), "{err}");

        // Usage errors.
        assert_eq!(cli(&["--set", &set]).0, 2);
        assert_eq!(cli(&["--results", &results]).0, 2);
        assert_eq!(cli(&["--bogus"]).0, 2);
        assert_eq!(cli(&["--warmup"]).0, 2);
        let (code, out, _) = cli(&["--help"]);
        assert_eq!(code, 0);
        assert!(out.starts_with("usage:"));
        // A candidate file whose hash doesn't match the manifest is refused.
        let junk = out_dir.path().join("junk.onnx");
        std::fs::write(&junk, b"junk").unwrap();
        let (code, _, err) = cli(&["--manifest", &manifest, "--model", &s(&junk), "--set", &set]);
        assert_eq!(code, 2);
        assert!(err.contains("integrity"), "{err}");
    }
}
