//! # faro-ipc
//!
//! The local protocol between Faro's per-user **agent** (screen capture,
//! foreground/session info) and the privileged **service** (keys, classifier,
//! event log, uploads) — ARCHITECTURE.md §3.1.
//!
//! Layers, bottom up:
//!
//! * [`codec`] — `FARO` magic + version + length framing around postcard
//!   payloads, with a hard size cap checked before allocation. Sync and async.
//! * [`messages`] — the typed [`AgentMsg`] / [`ServiceMsg`] vocabulary.
//!   Frames travel as [`WireFrame`]: **raw pixels only**, never an encoded
//!   image format, so the service never decodes images it did not produce
//!   (§9).
//! * [`connection`] — a typed, cancellation-safe [`Connection`] over any
//!   async byte stream.
//! * [`transport`] (Unix) — a hardened Unix-domain-socket server/client with
//!   kernel peer credentials and a pluggable [`PeerVerifier`].
//! * [`handshake`] — `Hello`/`Welcome` with a deadline, and ping/pong
//!   liveness for detecting a hung agent.
//! * [`enroll`] — the separate request/response protocol on the enroll
//!   socket, with which the agent asks the service to enroll the computer
//!   (an administrator approves it).
//! * [`status`] — [`StatusReport`], what the running service is doing
//!   (`faro-service status`). Plain data; no message carries it yet.
//!
//! ## Privacy invariant
//!
//! A [`WireFrame`] holds unblurred pixels. It is never `Clone`, its `Debug`
//! is redacted, it is zeroized on drop, and every codec buffer that can hold
//! pixels is [`zeroize::Zeroizing`]. Errors never carry message content.
//!
//! ## Windows
//!
//! TODO(windows): the named-pipe transport (a pipe with a DACL restricted to
//! SYSTEM and the session user, `GetNamedPipeClientProcessId` for the peer
//! pid, and an Authenticode check of the client image) is not implemented
//! yet. It cannot be compiled or tested on the platforms this crate is
//! currently developed on, and unverified security code is worse than none.
//! The codec, messages, [`Connection`] and [`handshake`] are
//! platform-independent and will be reused unchanged over a
//! `tokio::net::windows::named_pipe` stream.

pub mod codec;
pub mod connection;
pub mod enroll;
pub mod error;
pub mod handshake;
pub mod messages;
pub mod peer;
pub mod status;
#[cfg(unix)]
pub mod transport;
pub mod wire_frame;

pub use codec::{
    decode, encode, read_msg, read_msg_async, write_msg, write_msg_async, MAX_FRAMES_PER_MESSAGE,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION,
};
pub use connection::{AgentConnection, Connection, ServiceConnection};
#[cfg(unix)]
pub use enroll::resolve_enroll_socket;
pub use enroll::{
    enroll_socket_path, EnrollClientConnection, EnrollDone, EnrollPreview, EnrollRequest,
    EnrollResponse, EnrollServerConnection, EnrollStatus, EnrollTarget, FailureKind,
    AUTHORIZATION_LEN,
};
pub use error::{IpcError, Result, WireFrameError};
pub use handshake::{
    accept_agent, accept_agent_with_version, hello, ping, read_agent_hello, welcome_agent,
    AgentHello, ServiceWelcome, DEFAULT_PING_TIMEOUT, HELLO_TIMEOUT,
};
pub use messages::{
    AgentMsg, CaptureReason, ServiceMsg, ShutdownReason, WireMessage, WirePermissionState,
    WireSessionChange,
};
#[cfg(unix)]
pub use peer::AllowSameUid;
pub use peer::{AllowUids, PeerInfo, PeerVerifier};
pub use status::{StatusReport, STATUS_SCHEMA};
#[cfg(unix)]
pub use transport::{resolve_agent_socket, session_socket_path, BindOptions, IpcClient, IpcServer};
pub use wire_frame::{WireFrame, WirePixelFormat, MAX_FRAME_BYTES};
