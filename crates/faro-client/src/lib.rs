//! # faro-client
//!
//! The device side of the instance API, shared by every client platform:
//! the desktop service (`faro-service`) and the iOS core (`faro-mobile`).
//! Nothing here knows where a platform keeps its keys or its state; it
//! decides what to send and what to trust.
//!
//! | Module | Role |
//! |---|---|
//! | [`link`] | `faro://enroll` links and enrollment codes |
//! | [`client`] | the signed, size-bounded instance API client |
//! | [`enroll`] | discovery, registration, endorsement verification, manifest bootstrap |
//! | [`uplink`] | uploading the outbox and sending heartbeats |
//! | [`fetch`] | the instance's update mirror, and verifying its metadata |
//! | [`bundle`] | unpacking a verified data bundle |
//! | [`backoff`] | jittered exponential backoff |
//!
//! ## Invariants kept here
//!
//! * **The instance is untrusted.** Responses are size-capped before
//!   parsing, redirects are never followed, endorsements are verified
//!   against the member key pinned at enrollment, the first manifest is
//!   bootstrapped no lower than the endorsement's anchor, and the instance
//!   identity key is pinned and re-checked.
//! * **Updates trust the project, never the instance** (invariant 5):
//!   metadata goes through `faro-update` against the caller's root.
//! * **HTTP and TLS** are `reqwest` on rustls with ring and the OS trust
//!   store, which build for macOS, Windows, Linux and iOS alike.

pub mod backoff;
pub mod bundle;
pub mod client;
pub mod enroll;
pub mod fetch;
pub mod link;
pub mod uplink;

pub use client::{ClientError, ClientOptions, InstanceClient};
pub use enroll::Enrollment;
