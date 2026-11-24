//! # faro-server
//!
//! The Faro instance (ARCHITECTURE.md §4): a deliberately small **encrypted
//! mailbox** plus key directory, liveness monitor and notifier. It never
//! decrypts anything, runs no ML and never holds an unblurred image; all it
//! sees is ciphertext and the plaintext, device-signed header metadata
//! (§5.3).
//!
//! ## Layout
//!
//! | Module | Role |
//! |---|---|
//! | [`config`] | `faro.toml` + `FARO_*` env overrides, validated once at startup |
//! | [`bootstrap`] | data dir, identity key, DB + migrations, instance row, setup token |
//! | [`identity`] | the instance's Ed25519 identity key (pinned by clients) |
//! | [`db`] | sqlx `Any` pool (SQLite default / Postgres) and all SQL ([`db::repo`]) |
//! | [`blob`] | ciphertext blob store (local disk; S3 later) |
//! | [`auth`] | browser sessions, email normalisation, passkey plan |
//! | [`device_auth`] | device token + Ed25519 request-signature extractors |
//! | [`api`] | HTTP handlers, one module per area of §4.5 |
//! | [`router`] | route table and the security middleware stack |
//! | [`settings`] | admin-editable settings (registration, retention, grace) |
//! | [`notify`] | the notifier: fan-out, immediate email, hourly digests (§5.4) |
//! | [`liveness`] | missed-check-in monitor, downtime-aware (§3.7) |
//! | [`retention`] | the daily retention worker (§8) |
//! | [`workers`] | cancellable background loops and uptime bookkeeping |
//! | [`tls`] | built-in HTTPS: ACME (`rustls-acme`) or static certificates |
//! | [`server`] | the HTTP(S) listener and graceful shutdown |
//! | [`backup`] | `faro-server backup`: DB snapshot + identity key + blobs tarball |
//! | [`doctor`] | `faro-server doctor`: read-only configuration checks |
//! | [`cli`] | `faro-server serve \| init \| backup \| doctor \| version` |
//!
//! Integration tests build the full router in-process with
//! [`bootstrap::open`] + [`router::build`], exactly as `serve` does.

pub mod api;
pub mod auth;
pub mod backup;
pub mod blob;
pub mod bootstrap;
pub mod cli;
pub mod clock;
pub mod config;
pub mod db;
pub mod device_auth;
pub mod doctor;
pub mod error;
pub mod identity;
pub mod liveness;
pub mod mailer;
pub mod notify;
pub mod ratelimit;
pub mod retention;
pub mod router;
pub mod server;
pub mod settings;
pub mod state;
pub mod tls;
pub mod tokens;
pub mod workers;

pub use error::{AppError, AppResult};
pub use state::AppState;

/// This server's version, as reported in `/.well-known/faro`.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
