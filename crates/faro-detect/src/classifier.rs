//! Image classifiers and model manifests (§3.5 "Models").
//!
//! A classifier turns a [`Frame`] into [`ImageScores`]: labelled
//! probabilities in `[0, 1]` such as `explicit 0.93`. What a label *means*
//! for the rating is decided by the fusion engine
//! ([`PolicyConfig`](crate::PolicyConfig)), not here, so swapping models only
//! needs a new manifest plus, if label names differ, a policy update.
//!
//! A model is an ONNX file plus a JSON manifest ([`ModelInfo`]). The beta's
//! model ships in the macOS package; later ones come through the signed
//! update channel (§3.8). [`load_model`] checks the manifest's licence
//! against [`ALLOWED_MODEL_LICENSES`] (§11), that the manifest carries the
//! attribution and licence text that licence asks for, and the file's
//! BLAKE3 against the manifest. It hands back the verified bytes so the
//! runtime loads *exactly* what was checked (no re-read from disk, no
//! time-of-check/time-of-use gap).

use crate::attribution::{check_attribution, Attribution};
use crate::error::DetectError;
use crate::resample::resample_rgb;
use crate::scratch::Scratch;
use faro_platform::Frame;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Component, Path};
use zeroize::Zeroizing;

#[cfg(feature = "onnx")]
pub mod onnx;
#[cfg(all(test, feature = "onnx"))]
pub(crate) mod test_onnx;

/// SPDX identifiers of licences accepted for model weights (§11). These are
/// permissive, so a model can ship in every edition of Faro, including builds
/// distributed under terms other than the AGPL; copyleft (GPL, AGPL) and
/// non-commercial licences are deliberately absent.
pub const ALLOWED_MODEL_LICENSES: &[&str] = &[
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "CC0-1.0",
    "CC-BY-4.0",
    "Unlicense",
];

/// Largest manifest accepted, to bound memory on a corrupted file.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;
/// Largest model file accepted (int8 CLIP-style encoders are well below).
const MAX_MODEL_BYTES: u64 = 1 << 30;
/// Largest classifier input side accepted from a manifest.
const MAX_INPUT_SIDE: u32 = 2048;
/// Largest number of output labels accepted from a manifest.
const MAX_LABELS: usize = 1024;

/// Labelled scores in `[0, 1]`, in model output order. Labels are unique.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ImageScores {
    scores: Vec<(String, f32)>,
}

impl ImageScores {
    /// No scores (e.g. no model installed).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build scores, rejecting non-finite values, values outside `[0, 1]`
    /// (allowing 1e-4 of float slack, which is clamped away), empty labels
    /// and duplicate labels. A classifier returning garbage must fail loudly
    /// rather than silently produce a "clean" rating.
    pub fn new<L: Into<String>>(
        scores: impl IntoIterator<Item = (L, f32)>,
    ) -> Result<Self, DetectError> {
        const SLACK: f32 = 1e-4;
        let mut out: Vec<(String, f32)> = Vec::new();
        for (label, score) in scores {
            let label = label.into();
            if label.is_empty() {
                return Err(DetectError::Classifier("empty label".into()));
            }
            if !score.is_finite() || !(-SLACK..=1.0 + SLACK).contains(&score) {
                return Err(DetectError::Classifier(format!(
                    "score for {label:?} out of range: {score}"
                )));
            }
            if out.iter().any(|(l, _)| *l == label) {
                return Err(DetectError::Classifier(format!(
                    "duplicate label {label:?}"
                )));
            }
            out.push((label, score.clamp(0.0, 1.0)));
        }
        Ok(ImageScores { scores: out })
    }

    pub fn get(&self, label: &str) -> Option<f32> {
        self.scores
            .iter()
            .find(|(l, _)| l == label)
            .map(|&(_, s)| s)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, f32)> {
        self.scores.iter().map(|(l, s)| (l.as_str(), *s))
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// Classifier input tensor size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSize {
    pub width: u32,
    pub height: u32,
}

/// How raw model outputs become probabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputActivation {
    /// Mutually exclusive classes: logits → softmax.
    Softmax,
    /// Independent multi-label heads: logits → sigmoid.
    Sigmoid,
    /// The graph already ends in a softmax/sigmoid; values are used as-is
    /// (and must be in `[0, 1]`).
    Probabilities,
}

/// Channel order the model expects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelOrder {
    #[default]
    Rgb,
    /// Caffe-era models such as OpenNSFW.
    Bgr,
}

/// Input tensor layout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TensorLayout {
    /// `[1, 3, H, W]` (PyTorch exports).
    #[default]
    Nchw,
    /// `[1, H, W, 3]` (TensorFlow exports).
    Nhwc,
}

fn default_input_scale() -> f32 {
    1.0 / 255.0
}

/// How the frame is fitted to `input_size` before normalisation.
///
/// Both resample by area averaging and ignore the aspect ratio. A manifest
/// without `resize` means [`Resize::Direct`], what every manifest before
/// this field meant, and a [`Resize::Direct`] manifest serializes without
/// it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Resize {
    /// The whole frame to `input_size` (`"resize": "direct"`). Keeps the
    /// edges of a screenshot.
    #[default]
    Direct,
    /// The whole frame to `side × side`, then the centre `input_size` of
    /// that (`"resize": {"resize_crop": {"side": 256}}`). Yahoo's
    /// reference pipeline for OpenNSFW: 256, then the centre 224×224, which
    /// drops a border of 16 pixels in 256 (6 %) on every side.
    ResizeCrop { side: u32 },
}

impl Resize {
    pub fn is_direct(&self) -> bool {
        *self == Resize::Direct
    }

    /// The size the frame is resampled to, and the offset of the
    /// `input_size` crop within it.
    fn geometry(&self, input: InputSize) -> ((usize, usize), (usize, usize)) {
        let (w, h) = (input.width.max(1) as usize, input.height.max(1) as usize);
        match *self {
            Resize::Direct => ((w, h), (0, 0)),
            Resize::ResizeCrop { side } => {
                let side = (side as usize).max(w).max(h);
                // Integer division, as Yahoo's script crops.
                ((side, side), ((side - w) / 2, (side - h) / 2))
            }
        }
    }
}

/// `direct` or `resize_crop:SIDE`, as `model-bench --resize` takes it.
impl std::fmt::Display for Resize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resize::Direct => f.write_str("direct"),
            Resize::ResizeCrop { side } => write!(f, "resize_crop:{side}"),
        }
    }
}

impl std::str::FromStr for Resize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("{s:?}: expected direct or resize_crop:SIDE (e.g. resize_crop:256)");
        match s.split_once(':') {
            None if s == "direct" => Ok(Resize::Direct),
            Some(("resize_crop", side)) => side
                .parse()
                .map(|side| Resize::ResizeCrop { side })
                .map_err(|_| bad()),
            _ => Err(bad()),
        }
    }
}

/// A model manifest, shipped next to the model file and signed with it.
///
/// Preprocessing: the frame is resized (area average, aspect *not* kept,
/// as is standard for classifiers) to `input_size`, or to a larger square
/// and centre-cropped to it (see [`Resize`]), each 8-bit channel value
/// `v` becomes `(v * input_scale - mean[c]) / std[c]` where `c` indexes the
/// tensor's channel order (after any RGB→BGR swap), and the result is laid
/// out per `layout`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelInfo {
    pub name: String,
    pub version: String,
    /// Model file path relative to the manifest's directory. Must not be
    /// absolute or contain `..`.
    pub file: String,
    pub input_size: InputSize,
    /// How the frame becomes `input_size`. Absent means
    /// [`Resize::Direct`], so older manifests load unchanged, and a direct
    /// manifest serializes without it.
    #[serde(default, skip_serializing_if = "Resize::is_direct")]
    pub resize: Resize,
    /// One label per model output, in output order.
    pub labels: Vec<String>,
    pub mean: [f32; 3],
    pub std: [f32; 3],
    #[serde(default)]
    pub channel_order: ChannelOrder,
    #[serde(default)]
    pub layout: TensorLayout,
    #[serde(default = "default_input_scale")]
    pub input_scale: f32,
    pub output: OutputActivation,
    /// SPDX licence identifier of the weights; see [`ALLOWED_MODEL_LICENSES`].
    pub license: String,
    /// The full text of `license`, verbatim. Required for licences in
    /// [`TEXT_REQUIRED_LICENSES`](crate::attribution::TEXT_REQUIRED_LICENSES),
    /// whose text must travel with every copy of the weights.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_text: Option<String>,
    /// Who made the weights and what Faro changed. Required unless the
    /// licence is in
    /// [`NO_ATTRIBUTION_LICENSES`](crate::attribution::NO_ATTRIBUTION_LICENSES).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
    /// Lowercase hex BLAKE3 of the model file.
    pub blake3: String,
}

impl ModelInfo {
    /// Info for classifiers without a model file (null / scripted).
    fn builtin(name: &str, labels: Vec<String>) -> Self {
        ModelInfo {
            name: name.to_owned(),
            version: "0".to_owned(),
            file: String::new(),
            input_size: InputSize {
                width: 1,
                height: 1,
            },
            resize: Resize::Direct,
            labels,
            mean: [0.0; 3],
            std: [1.0; 3],
            channel_order: ChannelOrder::Rgb,
            layout: TensorLayout::Nchw,
            input_scale: default_input_scale(),
            output: OutputActivation::Probabilities,
            license: "Apache-2.0".to_owned(),
            license_text: None,
            attribution: None,
            blake3: String::new(),
        }
    }

    /// Check internal consistency, the licence allowlist, and that the
    /// attribution and licence text the licence asks for are there.
    pub fn validate(&self) -> Result<(), DetectError> {
        let bad = |m: String| Err(DetectError::Manifest(m));
        if self.name.trim().is_empty() || self.version.trim().is_empty() {
            return bad("name and version must be non-empty".into());
        }
        let InputSize { width, height } = self.input_size;
        if !(1..=MAX_INPUT_SIDE).contains(&width) || !(1..=MAX_INPUT_SIDE).contains(&height) {
            return bad(format!("input_size {width}x{height} out of range"));
        }
        if let Resize::ResizeCrop { side } = self.resize {
            let least = width.max(height);
            if !(least..=MAX_INPUT_SIDE).contains(&side) {
                return bad(format!(
                    "resize_crop side {side} out of range (need {least}..={MAX_INPUT_SIDE}, \
                     at least input_size {width}x{height})"
                ));
            }
        }
        if self.labels.is_empty() || self.labels.len() > MAX_LABELS {
            return bad(format!(
                "{} labels (need 1..={MAX_LABELS})",
                self.labels.len()
            ));
        }
        for (i, l) in self.labels.iter().enumerate() {
            if l.is_empty() || self.labels[..i].contains(l) {
                return bad(format!("label {l:?} is empty or duplicated"));
            }
        }
        if self.mean.iter().any(|m| !m.is_finite()) {
            return bad("mean must be finite".into());
        }
        if self.std.iter().any(|s| !s.is_finite() || *s <= 0.0) {
            return bad("std must be finite and positive".into());
        }
        if !self.input_scale.is_finite() || self.input_scale <= 0.0 {
            return bad("input_scale must be finite and positive".into());
        }
        if self.blake3.len() != 64 || hex::decode(&self.blake3).is_err() {
            return bad("blake3 must be 64 hex characters".into());
        }
        if !ALLOWED_MODEL_LICENSES.contains(&self.license.as_str()) {
            return Err(DetectError::License(self.license.clone()));
        }
        let has_text = |_: &str| {
            self.license_text
                .as_deref()
                .is_some_and(|t| !t.trim().is_empty())
        };
        check_attribution([self.license.as_str()], self.attribution.as_ref(), has_text)
            .map_err(|e| DetectError::Manifest(format!("licence {}: {e}", self.license)))
    }
}

/// An on-device image classifier.
///
/// Implementations receive a borrowed frame and must not retain, copy out,
/// log or persist its pixels. Any buffer derived from them should be
/// zeroized when done (use [`preprocess`], which does this).
pub trait Classifier: Send {
    fn info(&self) -> &ModelInfo;
    fn classify(&mut self, frame: &Frame) -> Result<ImageScores, DetectError>;
}

/// The classifier used when no model is installed: always returns no scores,
/// so ratings come from context signals alone.
#[derive(Debug, Clone)]
pub struct NullClassifier {
    info: ModelInfo,
}

impl Default for NullClassifier {
    fn default() -> Self {
        NullClassifier {
            info: ModelInfo::builtin("null", vec![]),
        }
    }
}

impl NullClassifier {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Classifier for NullClassifier {
    fn info(&self) -> &ModelInfo {
        &self.info
    }

    fn classify(&mut self, _frame: &Frame) -> Result<ImageScores, DetectError> {
        Ok(ImageScores::empty())
    }
}

/// Test double: returns queued results in order, then a fallback forever.
/// Records how often it was called and the frame dimensions it saw (never
/// pixels), so tests can check dedupe behaviour.
#[derive(Debug, Clone)]
pub struct ScriptedClassifier {
    info: ModelInfo,
    queue: VecDeque<Result<ImageScores, String>>,
    fallback: ImageScores,
    calls: usize,
    seen: Vec<(u32, u32)>,
}

impl ScriptedClassifier {
    pub fn new(fallback: ImageScores) -> Self {
        let labels = fallback.iter().map(|(l, _)| l.to_owned()).collect();
        ScriptedClassifier {
            info: ModelInfo::builtin("scripted", labels),
            queue: VecDeque::new(),
            fallback,
            calls: 0,
            seen: Vec::new(),
        }
    }

    /// Queue a result for the next call.
    pub fn push(&mut self, scores: ImageScores) -> &mut Self {
        self.queue.push_back(Ok(scores));
        self
    }

    /// Queue an error for the next call.
    pub fn push_error(&mut self, message: impl Into<String>) -> &mut Self {
        self.queue.push_back(Err(message.into()));
        self
    }

    pub fn calls(&self) -> usize {
        self.calls
    }

    pub fn seen_dimensions(&self) -> &[(u32, u32)] {
        &self.seen
    }
}

impl Classifier for ScriptedClassifier {
    fn info(&self) -> &ModelInfo {
        &self.info
    }

    fn classify(&mut self, frame: &Frame) -> Result<ImageScores, DetectError> {
        self.calls += 1;
        self.seen.push((frame.width(), frame.height()));
        match self.queue.pop_front() {
            Some(Ok(s)) => Ok(s),
            Some(Err(m)) => Err(DetectError::Classifier(m)),
            None => Ok(self.fallback.clone()),
        }
    }
}

/// A model file whose licence and BLAKE3 hash have been checked against its
/// manifest. The bytes are what was hashed; load them, not the path.
#[derive(Clone)]
pub struct VerifiedModel {
    info: ModelInfo,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for VerifiedModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedModel")
            .field("info", &self.info)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl VerifiedModel {
    /// Verify in-memory model bytes against a manifest (used by
    /// [`load_model`]; also useful when the update channel hands over
    /// bytes directly).
    pub fn verify(info: ModelInfo, bytes: Vec<u8>) -> Result<Self, DetectError> {
        info.validate()?;
        let actual = blake3::hash(&bytes);
        let expected = info.blake3.to_ascii_lowercase();
        if actual.to_hex().as_str() != expected {
            return Err(DetectError::Integrity {
                component: format!("model {} {}", info.name, info.version),
                expected,
                actual: actual.to_hex().to_string(),
            });
        }
        Ok(VerifiedModel { info, bytes })
    }

    pub fn info(&self) -> &ModelInfo {
        &self.info
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, DetectError> {
    let io = |source| DetectError::Io {
        path: path.to_owned(),
        source,
    };
    let too_big =
        || DetectError::Manifest(format!("{} is over the {cap}-byte limit", path.display()));
    let file = std::fs::File::open(path).map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    if len > cap {
        return Err(too_big());
    }
    // Bound the read itself, not just the size seen by `metadata`: the file
    // may grow between the two (or be a FIFO / device that reports 0).
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    std::io::Read::read_to_end(&mut std::io::Read::take(file, cap + 1), &mut bytes).map_err(io)?;
    if bytes.len() as u64 > cap {
        return Err(too_big());
    }
    Ok(bytes)
}

/// Load a model manifest (JSON, see [`ModelInfo`]) and its model file,
/// verifying licence and BLAKE3. A hash mismatch is
/// [`DetectError::Integrity`], which the service reports as
/// `TamperSignal::IntegrityFailure`.
pub fn load_model(manifest_path: impl AsRef<Path>) -> Result<VerifiedModel, DetectError> {
    let manifest_path = manifest_path.as_ref();
    let info = read_manifest(manifest_path)?;
    let rel = Path::new(&info.file);
    if info.file.is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(DetectError::Manifest(format!(
            "model file {:?} must be a plain relative path",
            info.file
        )));
    }
    let dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let bytes = read_capped(&dir.join(rel), MAX_MODEL_BYTES)?;
    VerifiedModel::verify(info, bytes)
}

/// Like [`load_model`], but read the model from `model_path` instead of the
/// manifest's `file`, for benchmarking a candidate file that sits elsewhere.
/// The licence and BLAKE3 checks are the same.
pub fn load_model_at(
    manifest_path: impl AsRef<Path>,
    model_path: impl AsRef<Path>,
) -> Result<VerifiedModel, DetectError> {
    let info = read_manifest(manifest_path.as_ref())?;
    let bytes = read_capped(model_path.as_ref(), MAX_MODEL_BYTES)?;
    VerifiedModel::verify(info, bytes)
}

fn read_manifest(path: &Path) -> Result<ModelInfo, DetectError> {
    let raw = read_capped(path, MAX_MANIFEST_BYTES)?;
    let info: ModelInfo =
        serde_json::from_slice(&raw).map_err(|e| DetectError::Manifest(e.to_string()))?;
    info.validate()?;
    Ok(info)
}

/// Turn a frame into the model's input tensor (see [`ModelInfo`] for the
/// exact transform). The returned buffer is zeroized on drop.
pub fn preprocess(frame: &Frame, info: &ModelInfo) -> Zeroizing<Vec<f32>> {
    let (w, h) = (
        info.input_size.width.max(1) as usize,
        info.input_size.height.max(1) as usize,
    );
    let ((rw, rh), (ox, oy)) = info.resize.geometry(info.input_size);
    let img = resample_rgb(frame, rw, rh);
    let plane = img.plane_len();
    let n = w * h;
    let mut out: Scratch<f32> = Scratch::zeroed(n * 3);
    for tc in 0..3 {
        // Tensor channel `tc` reads source plane `sc`.
        let sc = match info.channel_order {
            ChannelOrder::Rgb => tc,
            ChannelOrder::Bgr => 2 - tc,
        };
        let src = &img.data[sc * plane..(sc + 1) * plane];
        let (m, s, k) = (info.mean[tc], info.std[tc], info.input_scale);
        // Row `y` of the crop: the whole image when direct.
        for y in 0..h {
            let start = (y + oy) * rw + ox;
            let row = &src[start..start + w];
            match info.layout {
                TensorLayout::Nchw => {
                    let o = tc * n + y * w;
                    for (o, &v) in out[o..o + w].iter_mut().zip(row) {
                        *o = (v * k - m) / s;
                    }
                }
                TensorLayout::Nhwc => {
                    for (x, &v) in row.iter().enumerate() {
                        out[(y * w + x) * 3 + tc] = (v * k - m) / s;
                    }
                }
            }
        }
    }
    out.into_zeroizing()
}

/// Turn raw model outputs (batch size 1) into labelled scores per
/// [`ModelInfo::output`].
pub fn postprocess(raw: &[f32], info: &ModelInfo) -> Result<ImageScores, DetectError> {
    if raw.len() != info.labels.len() {
        return Err(DetectError::Classifier(format!(
            "model produced {} outputs for {} labels",
            raw.len(),
            info.labels.len()
        )));
    }
    if raw.iter().any(|v| !v.is_finite()) {
        return Err(DetectError::Classifier(
            "model produced non-finite output".into(),
        ));
    }
    let probs: Vec<f32> = match info.output {
        OutputActivation::Softmax => {
            let max = raw.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let exps: Vec<f32> = raw.iter().map(|&v| (v - max).exp()).collect();
            let sum: f32 = exps.iter().sum();
            exps.into_iter().map(|e| e / sum).collect()
        }
        OutputActivation::Sigmoid => raw.iter().map(|&v| 1.0 / (1.0 + (-v).exp())).collect(),
        OutputActivation::Probabilities => raw.to_vec(),
    };
    ImageScores::new(info.labels.iter().cloned().zip(probs))
}

/// Licence fields for test manifests.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::attribution::Attribution;

    pub(crate) const MIT_TEXT: &str = "Permission is hereby granted, free of charge, ...";

    pub(crate) fn attribution() -> Attribution {
        Attribution {
            author: "Faro tests".into(),
            copyright: vec!["Copyright (c) 2026 Faro tests".into()],
            source_url: "https://example.org/model".into(),
            license_url: "https://example.org/model/LICENSE".into(),
            changes: "None: a graph the tests encode by hand.".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_platform::PixelFormat;
    use std::io::Write;

    fn info() -> ModelInfo {
        ModelInfo {
            name: "test".into(),
            version: "1".into(),
            file: "model.onnx".into(),
            input_size: InputSize {
                width: 4,
                height: 2,
            },
            resize: Resize::Direct,
            labels: vec!["neutral".into(), "suggestive".into(), "explicit".into()],
            mean: [0.5, 0.25, 0.0],
            std: [0.5, 0.25, 1.0],
            channel_order: ChannelOrder::Rgb,
            layout: TensorLayout::Nchw,
            input_scale: 1.0 / 255.0,
            output: OutputActivation::Softmax,
            license: "MIT".into(),
            license_text: Some(test_support::MIT_TEXT.into()),
            attribution: Some(test_support::attribution()),
            blake3: blake3::hash(b"weights").to_hex().to_string(),
        }
    }

    fn solid(w: u32, h: u32, f: PixelFormat, px: [u8; 4]) -> Frame {
        Frame::new(w, h, f, 0, px.repeat((w * h) as usize)).unwrap()
    }

    #[test]
    fn scores_validation() {
        assert!(ImageScores::new([("a", 0.5), ("b", 1.0)]).is_ok());
        assert!(ImageScores::new([("a", f32::NAN)]).is_err());
        assert!(ImageScores::new([("a", f32::INFINITY)]).is_err());
        assert!(ImageScores::new([("a", 1.5)]).is_err());
        assert!(ImageScores::new([("a", -0.1)]).is_err());
        assert!(ImageScores::new([("a", 0.1), ("a", 0.2)]).is_err());
        assert!(ImageScores::new([("", 0.1)]).is_err());
        let s = ImageScores::new([("a", 1.00005)]).unwrap();
        assert_eq!(s.get("a"), Some(1.0));
        assert_eq!(s.get("missing"), None);
    }

    #[test]
    fn softmax_sigmoid_identity() {
        let mut i = info();
        let s = postprocess(&[0.0, 0.0, 0.0], &i).unwrap();
        for (_, v) in s.iter() {
            assert!((v - 1.0 / 3.0).abs() < 1e-6);
        }
        // Large logits must not overflow.
        let s = postprocess(&[1000.0, 0.0, -1000.0], &i).unwrap();
        assert!((s.get("neutral").unwrap() - 1.0).abs() < 1e-6);
        i.output = OutputActivation::Sigmoid;
        let s = postprocess(&[0.0, 100.0, -100.0], &i).unwrap();
        assert!((s.get("neutral").unwrap() - 0.5).abs() < 1e-6);
        assert!(s.get("suggestive").unwrap() > 0.999);
        assert!(s.get("explicit").unwrap() < 0.001);
        i.output = OutputActivation::Probabilities;
        assert!(postprocess(&[0.1, 0.2, 0.7], &i).is_ok());
        assert!(postprocess(&[0.1, 0.2, 7.0], &i).is_err());
        assert!(postprocess(&[0.1, 0.2], &i).is_err());
        assert!(postprocess(&[0.1, f32::NAN, 0.2], &i).is_err());
    }

    #[test]
    fn preprocess_nchw_normalises_per_channel() {
        let i = info();
        let t = preprocess(&solid(40, 20, PixelFormat::Bgra8, [0, 64, 255, 255]), &i);
        // RGB = (255, 64, 0)
        assert_eq!(t.len(), 3 * 4 * 2);
        let r = (1.0 - 0.5) / 0.5;
        let g = (64.0 / 255.0 - 0.25) / 0.25;
        let b = (0.0 - 0.0) / 1.0;
        assert!(t[..8].iter().all(|v| (v - r).abs() < 1e-4));
        assert!(t[8..16].iter().all(|v| (v - g).abs() < 1e-4));
        assert!(t[16..].iter().all(|v| (v - b).abs() < 1e-4));
    }

    #[test]
    fn preprocess_bgr_nhwc() {
        let mut i = info();
        i.channel_order = ChannelOrder::Bgr;
        i.layout = TensorLayout::Nhwc;
        i.mean = [0.0; 3];
        i.std = [1.0; 3];
        i.input_scale = 1.0;
        let t = preprocess(&solid(3, 3, PixelFormat::Rgba8, [10, 20, 30, 40]), &i);
        for px in t.as_chunks::<3>().0 {
            assert!((px[0] - 30.0).abs() < 1e-4);
            assert!((px[1] - 20.0).abs() < 1e-4);
            assert!((px[2] - 10.0).abs() < 1e-4);
        }
    }

    /// A frame whose red channel is the column and green the row.
    fn coordinates(w: u32, h: u32) -> Frame {
        let mut px = Vec::new();
        for y in 0..h {
            for x in 0..w {
                px.extend_from_slice(&[x as u8, y as u8, 0, 255]);
            }
        }
        Frame::new(w, h, PixelFormat::Rgba8, 0, px).unwrap()
    }

    #[test]
    fn preprocess_resize_crop_takes_the_centre() {
        let mut i = info();
        i.input_size = InputSize {
            width: 4,
            height: 2,
        };
        i.mean = [0.0; 3];
        i.std = [1.0; 3];
        i.input_scale = 1.0;
        // 8×8 → 8×8 is the identity, so the crop's values are coordinates:
        // columns 2..6 and rows 3..5.
        i.resize = Resize::ResizeCrop { side: 8 };
        let f = coordinates(8, 8);
        for layout in [TensorLayout::Nchw, TensorLayout::Nhwc] {
            i.layout = layout;
            let t = preprocess(&f, &i);
            assert_eq!(t.len(), 3 * 4 * 2);
            for y in 0..2 {
                for x in 0..4 {
                    let (r, g) = match layout {
                        TensorLayout::Nchw => (t[y * 4 + x], t[8 + y * 4 + x]),
                        TensorLayout::Nhwc => (t[(y * 4 + x) * 3], t[(y * 4 + x) * 3 + 1]),
                    };
                    assert_eq!((r, g), ((x + 2) as f32, (y + 3) as f32), "{layout:?}");
                }
            }
        }

        // A white border a quarter of the frame wide: resized to 8 and
        // cropped to the centre 4×4, none of it is left; directly resized,
        // the corners are white.
        let mut px = Vec::new();
        for y in 0..16u32 {
            for x in 0..16u32 {
                let border = !(4..12).contains(&x) || !(4..12).contains(&y);
                px.extend_from_slice(&if border { [255; 4] } else { [0, 0, 0, 255] });
            }
        }
        let f = Frame::new(16, 16, PixelFormat::Rgba8, 0, px).unwrap();
        i.layout = TensorLayout::Nchw;
        i.input_size = InputSize {
            width: 4,
            height: 4,
        };
        let crop = preprocess(&f, &i);
        assert!(crop.iter().all(|&v| v.abs() < 1e-3), "{:?}", &crop[..]);
        i.resize = Resize::Direct;
        let direct = preprocess(&f, &i);
        assert!((direct[0] - 255.0).abs() < 1e-3);
        assert!(direct[5].abs() < 1e-3);
    }

    #[test]
    fn resize_is_optional_in_the_manifest() {
        // The shipped manifests have no `resize`: they mean direct, as they
        // did before the field, and keep their bytes.
        for raw in [
            include_str!("../models/opennsfw/manifest.json"),
            include_str!("../models/opennsfw/manifest-fp32.json"),
        ] {
            assert!(!raw.contains("resize"));
            let i: ModelInfo = serde_json::from_str(raw).unwrap();
            assert_eq!(i.resize, Resize::Direct);
        }
        // Direct is never written, so a manifest written by this version
        // reads in one that has no `resize`.
        let v = serde_json::to_value(info()).unwrap();
        assert!(v.get("resize").is_none(), "{v}");
        let parse = |resize: serde_json::Value| {
            let mut v = serde_json::to_value(info()).unwrap();
            v["resize"] = resize;
            serde_json::from_value::<ModelInfo>(v).map(|i| i.resize)
        };
        assert_eq!(parse("direct".into()).unwrap(), Resize::Direct);
        let crop = parse(serde_json::json!({"resize_crop": {"side": 256}})).unwrap();
        assert_eq!(crop, Resize::ResizeCrop { side: 256 });
        let mut i = info();
        i.resize = crop;
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(
            v["resize"],
            serde_json::json!({"resize_crop": {"side": 256}})
        );
        assert_eq!(serde_json::from_value::<ModelInfo>(v).unwrap(), i);
        // Anything else is refused, as any unknown field is.
        for bad in [
            serde_json::json!("crop"),
            serde_json::json!("resize_crop"),
            serde_json::json!({"resize_crop": {}}),
            serde_json::json!({"resize_crop": {"side": 256, "x": 0}}),
            serde_json::json!({"resize_crop": {"side": -1}}),
        ] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }

        // The command-line spelling.
        for r in [Resize::Direct, Resize::ResizeCrop { side: 256 }] {
            assert_eq!(r.to_string().parse::<Resize>(), Ok(r));
        }
        assert_eq!(
            "resize_crop:256".parse(),
            Ok(Resize::ResizeCrop { side: 256 })
        );
        for bad in [
            "",
            "crop",
            "resize_crop",
            "resize_crop:",
            "resize_crop:x",
            "direct:1",
        ] {
            assert!(bad.parse::<Resize>().is_err(), "{bad}");
        }
    }

    #[test]
    fn manifest_validation() {
        assert!(info().validate().is_ok());
        let mut i = info();
        i.license = "AGPL-3.0-only".into();
        assert!(matches!(i.validate(), Err(DetectError::License(_))));
        let mut i = info();
        i.license = "CC-BY-NC-4.0".into();
        assert!(matches!(i.validate(), Err(DetectError::License(_))));
        let mut i = info();
        i.std = [1.0, 0.0, 1.0];
        assert!(i.validate().is_err());
        let mut i = info();
        i.labels.push("neutral".into());
        assert!(i.validate().is_err());
        let mut i = info();
        i.blake3 = "zz".repeat(32);
        assert!(i.validate().is_err());
        let mut i = info();
        i.input_size.width = 0;
        assert!(i.validate().is_err());
        // The crop must fit in the resized square.
        let mut i = info();
        for (side, ok) in [
            (3, false),
            (4, true),
            (256, true),
            (2048, true),
            (2049, false),
        ] {
            i.resize = Resize::ResizeCrop { side };
            assert_eq!(i.validate().is_ok(), ok, "{side}");
        }
    }

    /// The manifests of the model the macOS package ships, and of its fp32
    /// original (crates/faro-detect/models/opennsfw).
    #[test]
    fn opennsfw_manifests_are_valid() {
        for raw in [
            include_str!("../models/opennsfw/manifest.json"),
            include_str!("../models/opennsfw/manifest-fp32.json"),
        ] {
            let i: ModelInfo = serde_json::from_str(raw).unwrap();
            i.validate().unwrap();
            assert_eq!(i.license, "BSD-2-Clause");
            let a = i.attribution.as_ref().unwrap();
            assert_eq!(a.copyright, ["Copyright 2016, Yahoo Inc."]);
            let text = i.license_text.as_deref().unwrap();
            assert!(text.starts_with("Copyright 2016, Yahoo Inc.\n"));
            assert!(text.contains("Redistributions in binary form must reproduce"));
            assert_eq!(i.labels, ["sfw", "nsfw"]);
            // The default policy reads `nsfw` as explicit.
            let scores = ImageScores::new([("sfw", 0.05), ("nsfw", 0.95)]).unwrap();
            let r = crate::PolicyEngine::default().fuse(&scores, &[]);
            assert_eq!(r.rating, faro_proto::body::Rating::High, "{r:?}");
        }
    }

    #[test]
    fn manifest_needs_what_the_licence_asks_for() {
        let manifest_err = |i: ModelInfo| match i.validate() {
            Err(DetectError::Manifest(m)) => m,
            other => panic!("{other:?}"),
        };
        let mut i = info();
        i.attribution = None;
        assert!(manifest_err(i).contains("requires attribution"));
        let mut i = info();
        i.license_text = Some("  ".into());
        assert!(manifest_err(i).contains("MIT requires its text"));
        let mut i = info();
        i.attribution.as_mut().unwrap().copyright.clear();
        assert!(manifest_err(i).contains("copyright"));
        let mut i = info();
        i.attribution.as_mut().unwrap().changes.clear();
        assert!(manifest_err(i).contains("attribution.changes"));
        // A public-domain dedication needs neither.
        let mut i = info();
        i.license = "CC0-1.0".into();
        i.license_text = None;
        i.attribution = None;
        assert!(i.validate().is_ok());
        // load_model refuses such a manifest before reading the weights.
        let dir = tempfile::tempdir().unwrap();
        let mut i = info();
        i.license_text = None;
        let p = write_model(dir.path(), &i, b"weights");
        assert!(matches!(load_model(&p), Err(DetectError::Manifest(_))));
    }

    fn write_model(dir: &Path, info: &ModelInfo, weights: &[u8]) -> std::path::PathBuf {
        std::fs::File::create(dir.join("model.onnx"))
            .unwrap()
            .write_all(weights)
            .unwrap();
        let p = dir.join("model.json");
        std::fs::write(&p, serde_json::to_vec_pretty(info).unwrap()).unwrap();
        p
    }

    #[test]
    fn load_model_verifies_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_model(dir.path(), &info(), b"weights");
        let m = load_model(&p).unwrap();
        assert_eq!(m.bytes(), b"weights");
        assert_eq!(m.info(), &info());

        // Tampered weights → Integrity.
        let p = write_model(dir.path(), &info(), b"weightz");
        assert!(matches!(load_model(&p), Err(DetectError::Integrity { .. })));

        // A candidate file elsewhere gets the same check.
        let other = dir.path().join("candidate.onnx");
        std::fs::write(&other, b"weights").unwrap();
        assert_eq!(load_model_at(&p, &other).unwrap().bytes(), b"weights");
        std::fs::write(&other, b"weightz").unwrap();
        assert!(matches!(
            load_model_at(&p, &other),
            Err(DetectError::Integrity { .. })
        ));
    }

    #[test]
    fn load_model_rejects_path_escape_and_bad_json() {
        let dir = tempfile::tempdir().unwrap();
        for file in ["../model.onnx", "/etc/passwd", "", "./model.onnx"] {
            let mut i = info();
            i.file = file.into();
            let p = write_model(dir.path(), &i, b"weights");
            assert!(
                matches!(load_model(&p), Err(DetectError::Manifest(_))),
                "{file:?}"
            );
        }
        let p = dir.path().join("bad.json");
        std::fs::write(&p, b"{\"name\": 1}").unwrap();
        assert!(matches!(load_model(&p), Err(DetectError::Manifest(_))));
        // Unknown fields are rejected: a signed manifest must mean exactly
        // what this version understands.
        let mut v = serde_json::to_value(info()).unwrap();
        v["unblur"] = serde_json::Value::Bool(true);
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(matches!(load_model(&p), Err(DetectError::Manifest(_))));
        assert!(matches!(
            load_model(dir.path().join("missing.json")),
            Err(DetectError::Io { .. })
        ));
    }

    #[test]
    fn read_is_bounded_even_when_metadata_lies() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("big.json");
        std::fs::write(&p, vec![b' '; 100]).unwrap();
        assert!(matches!(read_capped(&p, 99), Err(DetectError::Manifest(_))));
        assert_eq!(read_capped(&p, 100).unwrap().len(), 100);
        // A character device reports length 0 but never ends: the read must
        // stop at the cap instead of allocating without bound.
        #[cfg(unix)]
        assert!(matches!(
            read_capped(Path::new("/dev/zero"), 4096),
            Err(DetectError::Manifest(_))
        ));
    }

    #[test]
    fn scripted_classifier_sequence() {
        let mut c = ScriptedClassifier::new(ImageScores::new([("explicit", 0.1)]).unwrap());
        c.push(ImageScores::new([("explicit", 0.9)]).unwrap())
            .push_error("boom");
        let f = solid(2, 3, PixelFormat::Rgba8, [0; 4]);
        assert_eq!(c.classify(&f).unwrap().get("explicit"), Some(0.9));
        assert!(matches!(c.classify(&f), Err(DetectError::Classifier(_))));
        assert_eq!(c.classify(&f).unwrap().get("explicit"), Some(0.1));
        assert_eq!(c.calls(), 3);
        assert_eq!(c.seen_dimensions(), &[(2, 3); 3]);
        assert!(NullClassifier::new().classify(&f).unwrap().is_empty());
    }
}
