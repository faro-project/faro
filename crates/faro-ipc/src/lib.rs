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
//!   [`limits`] bounds the text an agent sends in them.
//!   Frames travel as [`WireFrame`]: **raw pixels only**, never an encoded
//!   image format, so the service never decodes images it did not produce
//!   (§9).
//! * [`connection`] — a typed, cancellation-safe [`Connection`] over any
//!   async byte stream.
//! * `transport` (Unix) — a hardened Unix-domain-socket server/client with
//!   kernel peer credentials and a pluggable [`PeerVerifier`].
//! * `named_pipe` (Windows) — the same API ([`IpcServer`], [`IpcClient`],
//!   [`BindOptions`]) over named pipes with a DACL, a first-instance guard
//!   and kernel-reported client pid, session and account.
//! * [`endpoint`] — per-account endpoint names, shared by both transports.
//! * [`peer`] / [`sid`] — peer identity and the verifiers that judge it.
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
//! ## Platforms
//!
//! The transport is chosen by the target: Unix sockets on macOS and Linux,
//! named pipes on Windows. Both export the same names ([`IpcServer`],
//! [`IpcClient`], [`BindOptions`], [`session_socket_path`],
//! [`resolve_agent_socket`], [`resolve_enroll_socket`], [`AccountId`],
//! [`ServerStream`], [`ClientStream`]), and the verifiers
//! [`AllowSystemService`] and [`AllowSameUser`] mean the same thing on
//! both, so most call sites need no `cfg`. What differs is how accounts are
//! named (a uid or a [`Sid`]) and what [`BindOptions`] holds.

pub mod codec;
pub mod connection;
pub mod endpoint;
pub mod enroll;
pub mod error;
pub mod handshake;
pub mod limits;
pub mod messages;
#[cfg(windows)]
pub mod named_pipe;
pub mod peer;
pub mod sid;
pub mod status;
#[cfg(unix)]
pub mod transport;
pub mod wire_frame;

pub use codec::{
    decode, encode, read_msg, read_msg_async, write_msg, write_msg_async, MAX_FRAMES_PER_MESSAGE,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION,
};
pub use connection::{AgentConnection, Connection, ServiceConnection};
#[cfg(any(unix, windows))]
pub use endpoint::current_account;
pub use endpoint::{resolve_agent_socket, session_socket_path, AccountId};
pub use enroll::{
    enroll_socket_path, resolve_enroll_socket, EnrollClientConnection, EnrollDone, EnrollPreview,
    EnrollRequest, EnrollResponse, EnrollServerConnection, EnrollStatus, EnrollTarget, FailureKind,
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
#[cfg(windows)]
pub use named_pipe::{BindOptions, IpcClient, IpcServer, PendingConnection};
#[cfg(unix)]
pub use peer::AllowSameUid;
pub use peer::{AllowSameUser, AllowSids, AllowSystemService, AllowUids, PeerInfo, PeerVerifier};
pub use sid::{ParseSidError, Sid};
pub use status::{MemberStatus, StatusReport, STATUS_SCHEMA};
#[cfg(unix)]
pub use transport::{BindOptions, IpcClient, IpcServer};
pub use wire_frame::{WireFrame, WirePixelFormat, MAX_FRAME_BYTES};

/// The stream type of a connection the service accepted
/// ([`IpcServer::accept`]): a Unix socket, or the server end of a pipe.
#[cfg(unix)]
pub type ServerStream = tokio::net::UnixStream;
/// The stream type of a connection the service accepted
/// ([`IpcServer::accept`]): a Unix socket, or the server end of a pipe.
#[cfg(windows)]
pub type ServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

/// The stream type of a connection the agent opened
/// ([`IpcClient::connect`]): a Unix socket, or the client end of a pipe.
#[cfg(unix)]
pub type ClientStream = tokio::net::UnixStream;
/// The stream type of a connection the agent opened
/// ([`IpcClient::connect`]): a Unix socket, or the client end of a pipe.
#[cfg(windows)]
pub type ClientStream = tokio::net::windows::named_pipe::NamedPipeClient;
