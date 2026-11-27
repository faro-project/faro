//! # faro-mobile
//!
//! Faro's Rust core for iOS (docs/IOS.md §13), exposed to Swift with
//! UniFFI in proc-macro mode and built as a static library for the app's
//! XCFramework. It is the desktop's core with an iOS face: the event log,
//! hash chain and outbox are `faro-core`'s, enrollment, uploads and
//! heartbeats `faro-client`'s, signing `faro-crypto`'s, and data bundles
//! `faro-update`'s and `faro-detect`'s (domains only, no ONNX).
//!
//! | Module | Role |
//! |---|---|
//! | [`core`] | [`FaroCore`]: enrollment, events, heartbeats, uploads |
//! | [`keys`] | the [`KeyStore`] the platform implements (the Keychain), and [`MemoryKeyStore`] |
//! | [`store`] | the one database in the app group container |
//! | [`dnsfilter`] | [`DnsFilter`]: the packet tunnel's DNS filter (`faro-dnsfilter`) |
//! | [`reports`] | summaries without double counting, burst flags, the daily report |
//! | [`domains`] | the domain bundle from the signed update channel |
//! | [`types`] | the records and enums Swift sees |
//! | [`error`] | [`FaroError`] |
//!
//! ## Several processes, one chain
//!
//! The app and the packet tunnel each open a [`FaroCore`] on the same app
//! group directory. Every chain append is one `BEGIN EXCLUSIVE`
//! transaction that reads the stored head, seals and signs the event on it
//! and stores both (`faro_core::Outbox::append_exclusive`), so `seq` and
//! `prev_hash` stay strict whichever process appends, and the instance
//! never sees a fork. Nothing about the chain is cached in memory between
//! calls.
//!
//! ## Invariants kept here (docs/DEVELOPMENT.md, docs/IOS.md §4)
//!
//! * **The device encrypts only to its verified recipient manifest**
//!   (invariant 3): approval verifies the endorsement against the member
//!   key pinned at enrollment and bootstraps no lower than its anchor;
//!   later manifests must pass every `faro-core` rule, and each append
//!   seals to the checkpoint in force inside its transaction.
//! * **Tamper can't be silenced** (invariant 4): tamper signals become
//!   `tamper` events, floored at `urgent` by `faro-core` and the instance.
//! * **Updates trust the project, never the instance** (invariant 5): data
//!   bundles verify against the root the app passes in.
//! * **Keys never leave the device**, and Rust wipes its copies of them
//!   ([`keys`]).
//! * **Nothing about browsing leaves the phone** except sealed event
//!   bodies (§4 principle 1): the hosts in a blocked summary exist only
//!   inside the body sealed to the member and allies, and nothing here asks
//!   anyone whether to block.

uniffi::setup_scaffolding!();

pub mod core;
pub mod dnsfilter;
pub mod domains;
pub mod error;
pub mod keys;
pub mod reports;
pub mod store;
pub mod types;

pub use crate::core::FaroCore;
pub use dnsfilter::{DnsFilter, DnsFilterStatus, DnsStep, TunnelNetwork, UpstreamServer};
pub use error::FaroError;
pub use keys::{KeyStore, KeyStoreError, MemoryKeyStore};
pub use types::*;
