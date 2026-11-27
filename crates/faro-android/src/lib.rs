//! # faro-android
//!
//! Faro's Rust core for Android (docs/ANDROID.md §6), exposed to Kotlin
//! with UniFFI in proc-macro mode and built as `libfaro_android.so`.
//! Unlike iOS's `faro-mobile`, it embeds the desktop service's whole
//! runtime: Android has one app process that a foreground service keeps
//! alive, so the schedule, capture loop, detection, tamper tracking,
//! outbox, uploads and heartbeats are `faro-service`'s, driven through
//! `faro_service::InProcessFrameSource` over an `AgentPlatform` whose calls
//! go to Kotlin.
//!
//! | Module | Role |
//! |---|---|
//! | [`android`] | [`FaroAndroid`]: enrollment, approval, the runtime, status, urgent signals |
//! | [`platform`] | the adapter from [`AndroidPlatform`] to faro-platform's traits: frame checks, the secure-window debounce, address reduction |
//! | [`status`] | the status screen's words |
//! | [`types`] | what Kotlin sees |
//! | [`logging`] | `tracing` to logcat |
//!
//! **The image model** needs ONNX Runtime for Android (the `onnx` feature,
//! which `build-android.sh` turns on; `--no-onnx` leaves it off). The app
//! copies its packaged model to `<data_dir>/faro/models/opennsfw` and tells
//! [`FaroAndroid::new`] it did (`model_packaged`); then the model must load,
//! and a missing, changed or unloadable one is an urgent `integrity_failure`.
//! An app built without a model (or a core without the feature, in the host
//! tests) rates frames from context signals only (the domain list, when one
//! is installed), the status says so, and no tamper signal is raised.
//!
//! ## Invariants kept here (docs/DEVELOPMENT.md)
//!
//! * **No unblurred pixels persist or leave memory.** A screenshot's bytes
//!   move from the UniFFI record straight into a zeroizing
//!   `faro_platform::Frame` (or are wiped if they fail the checks);
//!   `CapturedFrame`'s `Debug` prints no pixels. The copy UniFFI's buffer
//!   held, and Kotlin's own, are outside Rust's reach: Kotlin zeroes its
//!   array and recycles its bitmaps.
//! * **Addresses are `scheme://host/`.** Kotlin reduces them, and
//!   [`platform::reduce_origin`] does it again; none is logged.
//! * **Tamper can't be silenced.** Revoked accessibility and a device admin
//!   disable request are urgent `permission_revoked` events; a sustained
//!   secure window is `window_hidden_from_capture`; nothing on the API
//!   stops, pauses or hides monitoring (`stop` is for the service's own
//!   lifecycle, and allies see the shutdown and then the heartbeats stop).

uniffi::setup_scaffolding!();

pub mod android;
mod error;
pub mod logging;
pub mod platform;
pub mod status;
pub mod types;

pub use android::{AndroidOptions, FaroAndroid, MIN_SERVER_VERSION};
pub use types::*;
