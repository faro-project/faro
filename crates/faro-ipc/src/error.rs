//! The single error type for every layer of the IPC stack.

use std::path::PathBuf;
use std::time::Duration;

use crate::messages::ShutdownReason;

/// Why a [`WireFrame`](crate::WireFrame) was refused.
///
/// Frames are validated on decode *and* again on conversion to a
/// [`Frame`](faro_platform::Frame), so a malformed frame never reaches the
/// classifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireFrameError {
    /// Width or height is zero.
    #[error("frame has a zero dimension ({width}x{height})")]
    ZeroDimension { width: u32, height: u32 },
    /// The agent must downscale to `MAX_FRAME_SIDE` before sending (§3.1).
    #[error("frame {width}x{height} exceeds the {max}px side limit")]
    TooLarge { width: u32, height: u32, max: u32 },
    /// The pixel buffer does not match `width * height * 4`.
    #[error("pixel buffer is {got} bytes, expected {expected}")]
    BadLength { expected: usize, got: usize },
    /// `faro-platform` refused the frame (should be unreachable after our own
    /// checks, but kept typed rather than panicking).
    #[error("platform rejected frame: {0}")]
    Platform(#[from] faro_platform::FrameError),
}

/// Every failure the IPC layer can report.
///
/// Errors never carry message *content* (titles, URLs, pixels) so they are
/// safe to log; at most they name a message kind or a size.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// An underlying socket/stream operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    // ---- framing -------------------------------------------------------
    /// The first four bytes were not `FARO`: the peer is not speaking this
    /// protocol (or the stream is desynchronized).
    #[error("bad magic: not a Faro IPC frame")]
    BadMagic,
    /// The frame header names a protocol version this build cannot decode.
    #[error("unsupported protocol version {got} (this build speaks {min}..={max})")]
    UnsupportedVersion { got: u16, min: u16, max: u16 },
    /// The declared (or, when encoding, actual) payload is over the cap.
    /// Checked before any payload allocation.
    #[error("payload of {len} bytes exceeds the {max}-byte limit")]
    PayloadTooLarge { len: u64, max: usize },
    /// A `Frames` message carried more displays than allowed.
    #[error("message carries {count} frames, limit is {max}")]
    TooManyFrames { count: usize, max: usize },
    /// The stream or buffer ended in the middle of a message.
    #[error("input ended mid-message ({got} of {expected} bytes)")]
    Truncated { expected: usize, got: usize },
    /// The peer closed the connection cleanly at a message boundary.
    #[error("peer closed the connection")]
    Closed,
    /// The payload decoded but bytes were left over. Strict decoding keeps
    /// the framing unambiguous.
    #[error("payload has {0} trailing bytes")]
    TrailingBytes(usize),
    /// The payload is not a valid postcard encoding of the expected message.
    #[error("malformed payload: {0}")]
    Decode(#[source] postcard::Error),
    /// Serialization failed (should only happen on a buggy `Serialize`).
    #[error("failed to encode message: {0}")]
    Encode(#[source] postcard::Error),
    /// A frame inside a `Frames` message is malformed.
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] WireFrameError),
    /// An earlier error (or a cancelled send) left the connection in an
    /// unknown framing state; it must be dropped.
    #[error("connection is unusable: {0}")]
    Broken(&'static str),

    // ---- session / handshake -------------------------------------------
    /// A receive did not complete in time.
    #[error("timed out after {after:?} waiting for {what}")]
    Timeout { what: &'static str, after: Duration },
    /// The peer sent a valid message that is not allowed at this point.
    #[error("expected {expected}, got {got}")]
    UnexpectedMessage {
        expected: &'static str,
        got: &'static str,
    },
    /// The `Hello`/`Welcome` protocol version disagrees with ours.
    #[error("peer speaks protocol version {peer}, we speak {ours}")]
    VersionMismatch { peer: u16, ours: u16 },
    /// The pid claimed in `Hello` is not the pid the kernel reports for the
    /// socket peer.
    #[error("agent claimed pid {claimed} but the socket peer is pid {actual}")]
    PidMismatch { claimed: u32, actual: u32 },
    /// A handshake string field is longer than allowed.
    #[error("handshake field `{field}` is {len} bytes, limit is {max}")]
    FieldTooLong {
        field: &'static str,
        len: usize,
        max: usize,
    },
    /// The service told the agent to stop.
    #[error("peer requested shutdown: {0:?}")]
    PeerShutdown(ShutdownReason),

    // ---- transport -----------------------------------------------------
    /// The peer's credentials were not accepted by the [`PeerVerifier`](crate::PeerVerifier).
    #[error("peer rejected: {0}")]
    PeerRejected(String),
    /// The kernel could not tell us who the peer is.
    #[error("could not read peer credentials: {0}")]
    PeerCredentials(#[source] std::io::Error),
    /// The socket's directory (or an ancestor) could be manipulated by
    /// another user.
    #[error("insecure socket directory {path}: {reason}")]
    InsecureSocketDir { path: PathBuf, reason: String },
    /// The socket path is unusable (no parent, occupied by a non-socket, ...).
    #[error("invalid socket path {path}: {reason}")]
    InvalidSocketPath { path: PathBuf, reason: String },
    /// Another live server is already listening on the path.
    #[error("another process is already listening on {0}")]
    AddrInUse(PathBuf),
    /// Bind options are out of the allowed range.
    #[error("invalid bind options: {0}")]
    InvalidOptions(String),
    /// An async transport call was made outside a Tokio runtime.
    #[error("no Tokio runtime with I/O enabled is running")]
    NoRuntime,
}

impl IpcError {
    /// Convenience constructor for [`PeerVerifier`](crate::PeerVerifier) implementations.
    pub fn peer_rejected(reason: impl Into<String>) -> Self {
        IpcError::PeerRejected(reason.into())
    }
}

/// Shorthand used throughout the crate.
pub type Result<T, E = IpcError> = std::result::Result<T, E>;
