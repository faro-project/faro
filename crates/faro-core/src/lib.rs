//! # faro-core
//!
//! The portable client core shared by every client platform (the desktop
//! service and the iOS core, `faro-mobile`): everything a Faro client does
//! that is not OS-specific, not ML and not network.
//!
//! | Module | Role (ARCHITECTURE.md) |
//! |---|---|
//! | [`clock`] | wall/monotonic/boot-id time sources; clock-manipulation detection (§3.6, §3.7) |
//! | [`scheduler`] | randomized capture scheduling, burst mode, pauses, triggers (§3.4) |
//! | [`urgency`] | rating → urgency policy with per-kind floors; tamper signal routing (§5.4, §3.7) |
//! | [`recipients`] | verifying the member-signed, versioned recipient manifest into a [`RecipientSet`] (§5.2, §5.3; PROTOCOL §5.1) |
//! | [`writer`] | building signed, encrypted, hash-chained events (§3.6, §5) |
//! | [`outbox`] | durable, ciphertext-only SQLite queue, chain head and manifest checkpoint (§3.6) |
//! | [`report`] | on-device daily reports, sealed to member and allies (§6) |
//! | [`request`] | per-request device signatures (§4.5) |
//! | [`settings`] | member settings and the change events allies see |
//!
//! ## Privacy invariants enforced here
//!
//! * No API in this crate accepts image pixels. The only image type that can
//!   reach an event or report is `faro_proto::body::BlurredThumbnail`, and it
//!   is encrypted before it is stored ([`outbox::Outbox`] only accepts a
//!   [`writer::PreparedEvent`] or a [`report::SealedReport`]).
//! * Plaintext bodies are serialized into zeroizing buffers and sealed to a
//!   [`RecipientSet`]. Outside this crate a set is only handed out by the
//!   [`Outbox`], from a recipient manifest signed by the pinned member key
//!   that is already the persisted checkpoint, and the outbox refuses to
//!   store any event or report sealed to a set that is not the *current*
//!   checkpoint. So the instance can neither add a reader nor bring back a
//!   removed ally or a rotated-out key, even to a component holding an old
//!   set. The one exception is the first manifest on a device, which is only
//!   as fresh as its [`ManifestAnchor`].
//! * Every header's urgency is at least its kind's floor.

pub mod clock;
pub mod outbox;
pub mod recipients;
pub mod report;
pub mod request;
pub mod scheduler;
pub mod settings;
pub mod urgency;
pub mod writer;

pub use clock::{Clock, ClockGuard, ClockGuardConfig, ClockObservation, ManualClock, SystemClock};
pub use outbox::{ManifestAnchor, Outbox, OutboxError, PruneOutcome, PrunePolicy, PrunedRange};
pub use recipients::{ManifestDecision, RecipientError, RecipientSet};
pub use report::{
    open_report, seal_report, IosReportBuilder, ReportBuilder, ReportError, ReportOptions,
    SealedReport,
};
pub use request::sign_request;
pub use scheduler::{
    CaptureCause, CaptureInfo, Decision, PauseReason, Scheduler, SchedulerConfig, SchedulerError,
    SessionSnapshot, Transition, Trigger, TriggerOutcome,
};
pub use settings::{MemberSettings, SettingsError};
pub use urgency::{route_signal, PolicyError, SignalRoute, UrgencyPolicy};
pub use writer::{open_event_body, EventWriter, OpenError, PreparedEvent, WriterError};
