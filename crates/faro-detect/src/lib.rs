//! # faro-detect
//!
//! On-device detection for the Faro service (ARCHITECTURE.md §3.4, §3.5).
//! Everything here runs locally; nothing in this crate touches the network.
//!
//! ```text
//! frame ─▶ dHash dedupe ─▶ classifier ─▶ fusion/policy ◀─ context signals
//!                                           │
//!                       rating ≥ threshold ─┴▶ blurred thumbnail
//!       ─▶ frame zeroized ─▶ DetectionOutcome (the only thing that leaves)
//! ```
//!
//! ## Privacy invariants
//!
//! * [`Detector::process`] takes the [`Frame`] **by value** and drops it
//!   (which zeroizes it, see `faro_platform::frame`) before returning. The
//!   only value that leaves is a [`DetectionOutcome`], whose fields are a
//!   rating, textual reasons, a 64-bit perceptual hash, flags and an optional
//!   [`BlurredThumbnail`]. There is no field that could carry raw pixels.
//! * Every intermediate buffer derived from the frame (resampled copies,
//!   blur planes, classifier input tensors) lives in a zeroize-on-drop
//!   scratch buffer allocated at its final size, so no unzeroized copy is
//!   left behind by a reallocation.
//! * The thumbnail is blurred (σ = 12 at 320 px) *and* pixelated before it is
//!   PNG-encoded; the encoder never sees unblurred pixels. There is no option
//!   to turn the blur off.
//! * The crate's unit tests include the §10 "no unblurred frames" test: an
//!   instrumented allocator verifies that the frame buffer and every scratch
//!   buffer are zeroed when freed and that no frame-sized allocation
//!   survives `process`.
//!
//! ## Licensing of models and blocklists (§3.5, §11)
//!
//! Faro's code is Apache-2.0. **No model weights and no blocklists are
//! bundled in this crate.** Models and domain bundles are shipped separately
//! through the signed update channel (§3.8), and every one of them must be
//! Apache-2.0 compatible: permissive licences such as Apache-2.0, MIT, BSD or
//! CC0 are fine; AGPL or non-commercial weights (and blocklists that forbid
//! redistribution) are not. [`load_model`] enforces this against the SPDX
//! identifier in the model manifest (see [`ALLOWED_MODEL_LICENSES`]), in
//! addition to verifying the weights' BLAKE3 hash.
//!
//! ## Features
//!
//! * `onnx` (off by default): `OnnxClassifier`, backed by ONNX Runtime via
//!   the `ort` crate. Without it, [`NullClassifier`] (context-only ratings)
//!   and the [`ScriptedClassifier`] test double are available, and
//!   [`classifier::preprocess`]/[`classifier::postprocess`] remain usable and
//!   tested.
//! * The [`bench`](mod@bench) harness (test-set layout, metrics, regression gate) is
//!   always built; its command line, the `model-bench` example, needs
//!   `onnx`.

pub mod bench;
pub mod classifier;
pub mod context;
pub mod dhash;
pub mod domains;
mod error;
pub mod fusion;
pub mod pipeline;
mod resample;
mod scratch;
pub mod thumbnail;

#[cfg(test)]
mod privacy_tests;

#[cfg(feature = "onnx")]
pub use classifier::onnx::OnnxClassifier;
pub use classifier::{
    load_model, load_model_at, ChannelOrder, Classifier, ImageScores, InputSize, ModelInfo,
    NullClassifier, OutputActivation, ScriptedClassifier, TensorLayout, VerifiedModel,
    ALLOWED_MODEL_LICENSES,
};
pub use context::{AppRule, ContextAnalyzer, ContextConfig, ContextFinding, ContextSignals};
pub use dhash::{dhash, hamming, DedupeDecision, Deduper, DEFAULT_DEDUPE_THRESHOLD};
pub use domains::{Category, CompileStats, DomainCategorizer, DomainCategorizerBuilder};
pub use error::DetectError;
pub use fusion::{FusionResult, PolicyConfig, PolicyEngine};
pub use pipeline::{DetectionOutcome, Detector, DetectorConfig};
pub use thumbnail::{blur_thumbnail, THUMBNAIL_TRANSFORM};

pub use faro_platform::{Frame, PixelFormat};
pub use faro_proto::body::{BlurredThumbnail, Rating, Reason, ReasonSource};
