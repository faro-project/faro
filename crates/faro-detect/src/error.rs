//! Typed errors for the detection pipeline.

use std::path::PathBuf;

/// Everything that can go wrong in `faro-detect`.
///
/// The service maps [`DetectError::Integrity`] to
/// `TamperSignal::IntegrityFailure` (§3.7): a model file that does not match
/// its signed manifest is treated as tampering, not as an ordinary I/O error.
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    /// A model file's BLAKE3 hash does not match its manifest.
    #[error("integrity check failed for {component}: expected blake3 {expected}, got {actual}")]
    Integrity {
        component: String,
        expected: String,
        actual: String,
    },

    /// The model manifest is malformed or internally inconsistent.
    #[error("invalid model manifest: {0}")]
    Manifest(String),

    /// The model's licence is not on the Apache-2.0-compatible allowlist (§11).
    #[error("model licence {0:?} is not Apache-2.0 compatible")]
    License(String),

    /// Reading a model or manifest from disk failed.
    #[error("i/o error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The classifier failed or produced unusable output.
    #[error("classifier error: {0}")]
    Classifier(String),

    /// Encoding the blurred thumbnail failed.
    #[error("thumbnail encoding failed: {0}")]
    Thumbnail(String),

    /// A compiled domain bundle could not be built or parsed.
    #[error("invalid domain bundle: {0}")]
    DomainBundle(String),

    /// A configuration value is out of range.
    #[error("invalid configuration: {0}")]
    Config(String),
}
