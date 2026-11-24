//! Typed errors for metadata verification and target streaming.

use crate::metadata::Role;

/// Why a piece of update metadata was rejected.
///
/// Every variant is a hard rejection: the trusted state is left unchanged
/// (with the single, documented exception of the observed-time high-water
/// mark, see [`crate::TrustedState`] — which is why the state is persisted
/// after errors too). Callers should keep using the
/// metadata they already trust and retry later; an instance mirror that keeps
/// serving rejected metadata can only *delay* updates.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    /// The raw document is larger than the hard cap for its role. Checked
    /// before any parsing so a hostile mirror cannot make us allocate or
    /// parse unbounded input.
    #[error("{role} metadata is {len} bytes, over the {max}-byte limit")]
    TooLarge { role: Role, len: usize, max: usize },

    /// The envelope JSON (or its base64 payload) does not parse.
    #[error("malformed {role} envelope: {reason}")]
    MalformedEnvelope { role: Role, reason: String },

    /// The envelope's `payload_type` is not the one expected for this role.
    /// Prevents a validly signed document of one role being used as another.
    #[error("wrong payload type: expected {expected:?}, found {found:?}")]
    WrongPayloadType { expected: String, found: String },

    /// The envelope carries more signature entries than any legitimate
    /// document needs. Bounds the verification work a mirror can force.
    #[error("{role} envelope carries {count} signatures, over the limit of {max}")]
    TooManySignatures {
        role: Role,
        count: usize,
        max: usize,
    },

    /// Fewer distinct authorised keys produced valid signatures than the
    /// role's threshold requires.
    #[error("{role} signature threshold not met: {valid} valid of {threshold} required")]
    ThresholdNotMet {
        role: Role,
        valid: usize,
        threshold: usize,
    },

    /// The (authenticated) payload does not parse or violates a structural
    /// rule (e.g. a root whose key ids don't match its keys).
    #[error("invalid {role} metadata: {reason}")]
    InvalidMetadata { role: Role, reason: String },

    /// The metadata has expired relative to the effective clock
    /// (`max(now, highest time previously observed)`).
    #[error("{role} metadata expired at {expires_ms} ms (effective now {now_ms} ms)")]
    Expired {
        role: Role,
        expires_ms: i64,
        now_ms: i64,
    },

    /// The offered version is lower than one already trusted: a replay of
    /// old, validly signed metadata.
    #[error("{role} rollback: trusted version {trusted}, offered {offered}")]
    Rollback {
        role: Role,
        trusted: u64,
        offered: u64,
    },

    /// Two different documents were signed with the same version number.
    /// This only happens if a role key is compromised or the release
    /// tooling is broken, so it is surfaced loudly rather than resolved.
    #[error("{role} equivocation: version {version} seen with different content")]
    Equivocation { role: Role, version: u64 },

    /// A root update must advance the version by exactly one so that every
    /// intermediate root's key set vouches for the next.
    #[error("root version must be {expected}, offered {offered}")]
    RootVersionSkip { expected: u64, offered: u64 },

    /// `verify_targets` was called before any timestamp was trusted.
    #[error("no trusted timestamp; verify a timestamp before targets")]
    NoTrustedTimestamp,

    /// The targets document does not match what the trusted timestamp
    /// committed to (mix-and-match attack or a stale mirror).
    #[error("targets do not match the trusted timestamp: {0}")]
    TimestampMismatch(String),
}

/// Why streaming verification of a downloaded target failed.
///
/// On any error the bytes read so far (and anything written to a sink by
/// [`crate::copy_verified_target`]) must be discarded.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    /// The signed length is above the caller's hard cap; nothing was read.
    #[error("target {name:?} is {length} bytes, over the caller's cap of {max_len}")]
    ExceedsCap {
        name: String,
        length: u64,
        max_len: u64,
    },
    /// The source produced more bytes than the signed length.
    #[error("target {name:?} is longer than the signed length {expected}")]
    TooLong { name: String, expected: u64 },
    /// The source ended before the signed length was reached.
    #[error("target {name:?} ended after {got} of {expected} bytes")]
    TooShort {
        name: String,
        got: u64,
        expected: u64,
    },
    /// Length matched but the BLAKE3 digest did not.
    #[error("target {name:?} hash mismatch")]
    HashMismatch { name: String },
    /// The underlying reader or writer failed.
    #[error("I/O error while verifying target: {0}")]
    Io(#[from] std::io::Error),
}
