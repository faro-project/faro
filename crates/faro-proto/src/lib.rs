//! # faro-proto
//!
//! Wire types shared by every Faro component: the device client, `faro-server`
//! and (via generated TypeScript) the ally web app.
//!
//! Signed and hashed structures expose a `signing_bytes()` method that builds
//! a **canonical, domain-separated** byte string (see [`encoding::Canonical`]
//! and `docs/PROTOCOL.md`). JSON is only a transport encoding and is never
//! signed directly.

pub mod api;
pub mod body;
pub mod encoding;
pub mod event;
pub mod ids;
pub mod keys;
pub mod report;
pub mod roster;

pub use encoding::{EncPublicKey, Hash32, Nonce24, SignPublicKey, Signature};
pub use event::{
    body_aad, genesis_hash, EncryptedItem, Envelope, EventHeader, EventKind, SignedEvent, Urgency,
    EVENT_HEADER_VERSION,
};
pub use ids::{DeviceId, InstanceId, UserId};
