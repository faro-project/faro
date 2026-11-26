//! # faro-service
//!
//! The privileged, per-machine Faro service (ARCHITECTURE.md §3.1). It owns
//! the device's state and keys, the classifier, the hash-chained event log
//! and encrypted outbox, report building, uploads and heartbeats, and it
//! watches over the per-session agent that captures the screen.
//!
//! The binary (`faro-service`) is a thin CLI over this library so that tests
//! can drive everything in-process:
//!
//! | Module | Role |
//! |---|---|
//! | [`config`] | `service.toml` with platform defaults |
//! | [`state`] | the 0700 state directory, 0600 secrets, the enrollment record |
//! | [`link`] | `faro://enroll` links and enrollment codes |
//! | [`client`] | the signed, size-bounded instance API client |
//! | [`enroll`] | enrollment, endorsement verification, manifest bootstrap |
//! | [`enroll_server`] | enrolling from the agent: the enroll socket, an administrator's approval |
//! | [`source`] | the capture side: the agent over IPC, or an in-process platform |
//! | [`model`] | the image classifier: the packaged model, its checks, `model-check` |
//! | [`thresholds`] | `[dev_thresholds]`: lower detection thresholds, in `dev` builds only |
//! | [`runtime`] | `run`: scheduler, detection, events, reports, uploads, heartbeats; `goodbye` |
//! | [`status_view`] | `status`: the state directory and the running service's [`runtime::status`] report, as text or JSON |
//! | [`update`] | client self-update: verify against the project root, download, install; models and blocklists from the same channel ([`update::artifacts`]) |
//! | [`logging`] | where the log goes (the packaged service's log file) and how much |
//! | [`cli`] | the command line |
//!
//! ## Invariants kept here (docs/DEVELOPMENT.md)
//!
//! 1. **No unblurred pixels persist or leave memory.** Frames arrive from
//!    the source by value, are moved into `faro_detect::Detector::process`
//!    (which zeroizes them), and only a `BlurredThumbnail` can reach an
//!    event. Frames are never logged (`SourceEvent`'s `Debug` prints a
//!    count). Unsolicited frames from the agent are dropped unread. A model
//!    from the update channel is built from its files and swapped in
//!    between captures ([`update::artifacts`]): no frame is involved.
//! 2. **The device encrypts only to its verified recipient manifest.** Every
//!    event and report is sealed to `Outbox::current_recipients`, the
//!    checkpoint verified against the member key pinned at enrollment; the
//!    first manifest is bootstrapped only at or above the anchor in the
//!    member-signed endorsement, never trust-on-first-use.
//! 3. **Tamper can't be silenced.** Tamper signals become urgent `tamper`
//!    events (urgency floors applied by `faro-core`); settings changes are
//!    announced; detector thresholds are not configurable (only a `dev`
//!    build can lower them, [`thresholds`]) and tamper thresholds can only
//!    be tightened. The agent is accepted only with a
//!    valid code signature (root service), its departures are classified by
//!    the service rather than by what it says, a session without an agent
//!    becomes an urgent `unmonitored_user_session` event, and a session at
//!    the screen whose connected agent nothing is captured from becomes an
//!    urgent `capture_failing` event.
//! 4. **The instance is untrusted.** Responses are size-capped before
//!    parsing; endorsements and manifests are verified locally; the instance
//!    identity key is pinned and re-checked; redirects are not followed.

pub mod accounts;
pub mod backoff;
pub mod cli;
pub mod client;
pub mod config;
pub mod enroll;
pub mod enroll_server;
pub mod link;
pub mod logging;
pub mod model;
pub mod runtime;
pub mod source;
pub mod state;
pub mod status_view;
pub mod thresholds;
pub mod update;

pub use config::Config;
pub use runtime::{
    say_goodbye, AgentSpawn, GoodbyeError, GoodbyeOptions, GoodbyeOutcome, PauseRequest, Phase,
    Service, ServiceBuilder, ServiceError, ServiceHandle, ServiceStatus, UpdateOverrides,
};
pub use source::{FrameSource, InProcessFrameSource, SourceCommand, SourceEvent, SourceIo};
