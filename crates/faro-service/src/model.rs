//! The image classifier the service runs (ARCHITECTURE.md §3.5).
//!
//! The macOS package installs the model at
//! `faro_platform_macos::pkg_layout::MODEL_MANIFEST`. [`load_classifier`]
//! loads it with the licence, attribution and BLAKE3 checks of
//! [`faro_detect::load_model`] and runs it on ONNX Runtime (feature `onnx`,
//! on in release packages). Without a model the service still runs, with
//! [`NullClassifier`] (ratings from context signals only).
//!
//! A packaged service whose model is missing, altered or unloadable is
//! being tampered with or is broken: either way image classification is
//! off, so allies must hear about it. [`ModelLoad::tamper`] is then an
//! `integrity_failure` signal, which the runtime reports once it runs.
//! The component names are fixed strings, never text from the manifest.

use faro_detect::{Classifier, DetectError, NullClassifier};
use faro_platform::{Frame, PixelFormat, MAX_FRAME_SIDE};
use faro_proto::body::TamperSignal;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// `integrity_failure` components.
pub const MODEL_MISSING: &str = "image model (missing)";
pub const MODEL_CHANGED: &str = "image model (changed)";
pub const MODEL_UNUSABLE: &str = "image model (cannot load)";

/// What [`load_classifier`] found.
pub struct ModelLoad {
    pub classifier: Box<dyn Classifier>,
    /// Set when the model should be there and working but isn't.
    pub tamper: Option<TamperSignal>,
}

impl std::fmt::Debug for ModelLoad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelLoad")
            .field("model", &self.classifier.info().name)
            .field("tamper", &self.tamper)
            .finish()
    }
}

/// The model manifest the package installs, on platforms that ship one.
pub fn packaged_manifest() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(PathBuf::from(
            faro_platform_macos::pkg_layout::MODEL_MANIFEST,
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Whether this process is the packaged service, which must have its model:
/// built with ONNX Runtime and run from the installed location.
pub fn model_required() -> bool {
    #[cfg(all(target_os = "macos", feature = "onnx"))]
    {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .is_some_and(|p| p == Path::new(faro_platform_macos::pkg_layout::SERVICE_PROGRAM))
    }
    #[cfg(not(all(target_os = "macos", feature = "onnx")))]
    {
        false
    }
}

fn integrity(component: &str) -> Option<TamperSignal> {
    Some(TamperSignal::IntegrityFailure {
        component: component.to_owned(),
    })
}

/// Load the classifier described by `manifest`. Never fails: a model that
/// can't be used leaves [`NullClassifier`] in place, with a tamper signal
/// if `required` (or if the model is there but altered or broken).
pub fn load_classifier(manifest: Option<&Path>, required: bool) -> ModelLoad {
    let null = |tamper| ModelLoad {
        classifier: Box::new(NullClassifier::new()),
        tamper,
    };
    let Some(path) = manifest else {
        return null(None);
    };
    match open(path) {
        Ok(classifier) => {
            let i = classifier.info();
            tracing::info!(model = %i.name, version = %i.version, license = %i.license, path = %path.display(), "image model loaded");
            ModelLoad {
                classifier,
                tamper: None,
            }
        }
        Err(OpenError::Detect(DetectError::Io { source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            if required {
                tracing::error!(path = %path.display(), "the image model is missing; images are not classified");
                null(integrity(MODEL_MISSING))
            } else {
                tracing::info!(path = %path.display(), "no image model; ratings use context signals only");
                null(None)
            }
        }
        Err(OpenError::Detect(e @ DetectError::Integrity { .. })) => {
            tracing::error!(error = %e, "the image model does not match its manifest; images are not classified");
            null(integrity(MODEL_CHANGED))
        }
        Err(OpenError::NoRuntime) => {
            tracing::warn!(path = %path.display(), "this build has no ONNX Runtime (feature `onnx`); the image model is not used");
            null(if required {
                integrity(MODEL_UNUSABLE)
            } else {
                None
            })
        }
        Err(OpenError::Detect(e)) => {
            tracing::error!(error = %e, path = %path.display(), "cannot load the image model; images are not classified");
            null(integrity(MODEL_UNUSABLE))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error(transparent)]
    Detect(#[from] DetectError),
    #[error("this build has no ONNX Runtime (feature `onnx`)")]
    NoRuntime,
}

/// Load and verify the model, then start ONNX Runtime on it.
pub fn open(path: &Path) -> Result<Box<dyn Classifier>, OpenError> {
    let model = faro_detect::load_model(path)?;
    #[cfg(feature = "onnx")]
    {
        Ok(Box::new(faro_detect::OnnxClassifier::new(model)?))
    }
    #[cfg(not(feature = "onnx"))]
    {
        let _ = model;
        Err(OpenError::NoRuntime)
    }
}

/// Synthetic frames for [`check`], never a real image: three solid
/// colours, whose classifier input is the same whatever the resize (so
/// their scores can be compared with the original model's, see
/// `installers/macos/check-model.sh`), and a UI-like window.
fn check_frames() -> Vec<(&'static str, Frame)> {
    let solid = |v: u8| {
        Frame::new(
            64,
            64,
            PixelFormat::Bgra8,
            0,
            [v, v, v, 255].repeat(64 * 64),
        )
        .expect("a valid frame")
    };
    vec![
        ("solid-black", solid(0)),
        ("solid-white", solid(255)),
        ("solid-grey", solid(128)),
        ("window", window_frame()),
    ]
}

/// A 1440x900 light window, downscaled as `Detector::process` does: a
/// toolbar, a sidebar, lines of "text" and a blue panel.
fn window_frame() -> Frame {
    let (w, h) = (1440usize, 900usize);
    let mut px = [246u8, 246, 246, 255].repeat(w * h);
    let mut rect = |x0: usize, y0: usize, x1: usize, y1: usize, bgra: [u8; 4]| {
        for y in y0..y1.min(h) {
            for x in x0..x1.min(w) {
                px[(y * w + x) * 4..][..4].copy_from_slice(&bgra);
            }
        }
    };
    rect(0, 0, w, 52, [222, 222, 222, 255]);
    rect(0, 52, 220, h, [232, 232, 232, 255]);
    for line in 0..24 {
        let y = 90 + line * 30;
        let len = 300 + (line * 137) % 700;
        rect(260, y, 260 + len, y + 10, [40, 40, 40, 255]);
    }
    rect(1000, 420, 1380, 760, [255, 122, 0, 255]);
    Frame::new(w as u32, h as u32, PixelFormat::Bgra8, 0, px)
        .expect("a valid frame")
        .downscale_to_max(MAX_FRAME_SIDE)
}

/// `faro-service model-check`: load the model exactly as `run` does (the
/// licence, attribution and BLAKE3 checks included), classify synthetic
/// frames, and time `runs` classifications of the window frame. Prints
/// one line per frame with its scores, then the latency.
pub fn check(manifest: &Path, runs: usize, out: &mut dyn Write) -> Result<(), OpenError> {
    let mut c = open(manifest)?;
    let i = c.info().clone();
    let _ = writeln!(
        out,
        "model        {} {} ({}), blake3 {} verified",
        i.name, i.version, i.license, i.blake3
    );
    if let Some(a) = &i.attribution {
        let _ = writeln!(out, "             by {}; {}", a.author, a.source_url);
    }
    let frames = check_frames();
    for (name, frame) in &frames {
        let scores = c.classify(frame)?;
        let text: Vec<String> = scores.iter().map(|(l, v)| format!("{l} {v:.6}")).collect();
        let _ = writeln!(out, "{name:<12} {}", text.join("  "));
    }
    let (_, window) = frames.last().expect("frames");
    let mut ms = Vec::with_capacity(runs);
    for _ in 0..runs.max(1) {
        let t = Instant::now();
        c.classify(window)?;
        ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(f64::total_cmp);
    let _ = writeln!(
        out,
        "latency      p50 {:.1} ms, max {:.1} ms over {} runs ({}-{}, one thread)",
        ms[ms.len() / 2],
        ms[ms.len() - 1],
        ms.len(),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_detect::attribution::Attribution;
    use faro_detect::{ChannelOrder, InputSize, ModelInfo, OutputActivation, TensorLayout};

    fn manifest(dir: &Path, weights: &[u8], license: &str) -> PathBuf {
        let info = ModelInfo {
            name: "test".into(),
            version: "1".into(),
            file: "m.onnx".into(),
            input_size: InputSize {
                width: 8,
                height: 8,
            },
            labels: vec!["nsfw".into()],
            mean: [0.0; 3],
            std: [1.0; 3],
            channel_order: ChannelOrder::Rgb,
            layout: TensorLayout::Nchw,
            input_scale: 1.0 / 255.0,
            output: OutputActivation::Probabilities,
            license: license.into(),
            license_text: Some("Permission is hereby granted ...".into()),
            attribution: Some(Attribution {
                author: "Tests".into(),
                copyright: vec!["Copyright 2026 Tests".into()],
                source_url: "https://example.org".into(),
                license_url: "https://example.org/LICENSE".into(),
                changes: "None.".into(),
            }),
            blake3: blake3::hash(b"weights").to_hex().to_string(),
        };
        std::fs::write(dir.join("m.onnx"), weights).unwrap();
        let p = dir.join("manifest.json");
        std::fs::write(&p, serde_json::to_vec(&info).unwrap()).unwrap();
        p
    }

    fn signal(l: &ModelLoad) -> Option<&str> {
        match &l.tamper {
            Some(TamperSignal::IntegrityFailure { component }) => Some(component),
            None => None,
            Some(other) => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_manifest_means_no_model_and_no_signal() {
        let l = load_classifier(None, true);
        assert_eq!(l.classifier.info().name, "null");
        assert_eq!(signal(&l), None);
    }

    #[test]
    fn a_missing_model_is_tamper_only_when_required() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("manifest.json");
        assert_eq!(signal(&load_classifier(Some(&p), false)), None);
        assert_eq!(
            signal(&load_classifier(Some(&p), true)),
            Some(MODEL_MISSING)
        );
        // The manifest without its model file counts as missing too.
        let p = manifest(dir.path(), b"weights", "MIT");
        std::fs::remove_file(dir.path().join("m.onnx")).unwrap();
        assert_eq!(
            signal(&load_classifier(Some(&p), true)),
            Some(MODEL_MISSING)
        );
    }

    #[test]
    fn an_altered_or_broken_model_is_always_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = manifest(dir.path(), b"weightz", "MIT");
        for required in [false, true] {
            let l = load_classifier(Some(&p), required);
            assert_eq!(l.classifier.info().name, "null");
            assert_eq!(signal(&l), Some(MODEL_CHANGED));
        }
        // A manifest edited to a licence that isn't allowed.
        let p = manifest(dir.path(), b"weights", "AGPL-3.0-only");
        assert_eq!(
            signal(&load_classifier(Some(&p), false)),
            Some(MODEL_UNUSABLE)
        );
        std::fs::write(&p, b"{").unwrap();
        assert_eq!(
            signal(&load_classifier(Some(&p), false)),
            Some(MODEL_UNUSABLE)
        );
    }

    /// The bytes verify but aren't a model ONNX Runtime can load.
    #[cfg(feature = "onnx")]
    #[test]
    fn weights_onnx_runtime_refuses_are_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let p = manifest(dir.path(), b"weights", "MIT");
        assert_eq!(
            signal(&load_classifier(Some(&p), false)),
            Some(MODEL_UNUSABLE)
        );
        let mut out = Vec::new();
        assert!(check(&p, 1, &mut out).is_err());
    }

    /// Without ONNX Runtime a present, valid model is unused, which is only
    /// tamper for a service that must have it.
    #[cfg(not(feature = "onnx"))]
    #[test]
    fn without_onnx_runtime_the_model_is_unused() {
        let dir = tempfile::tempdir().unwrap();
        let p = manifest(dir.path(), b"weights", "MIT");
        assert_eq!(signal(&load_classifier(Some(&p), false)), None);
        assert_eq!(
            signal(&load_classifier(Some(&p), true)),
            Some(MODEL_UNUSABLE)
        );
        assert!(matches!(
            check(&p, 1, &mut Vec::new()),
            Err(OpenError::NoRuntime)
        ));
    }

    #[test]
    fn check_frames_are_synthetic_and_sized_like_captures() {
        let frames = check_frames();
        assert_eq!(frames.len(), 4);
        let (_, w) = &frames[3];
        assert!(w.width().max(w.height()) <= MAX_FRAME_SIDE);
    }
}
