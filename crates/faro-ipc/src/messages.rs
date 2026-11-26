//! Typed messages exchanged between the per-user agent and the privileged
//! service (ARCHITECTURE.md §3.1).
//!
//! **Encoding stability.** Messages are encoded with postcard, which encodes
//! enum variants by *index* and struct fields by *position*. Therefore:
//! variants and fields here are append-only, and any change that is not a
//! pure append at the end of an enum requires bumping
//! [`PROTOCOL_VERSION`](crate::codec::PROTOCOL_VERSION).
//!
//! **Why wire mirrors.** Several `faro-proto` / `faro-platform` types are
//! designed for JSON (`skip_serializing_if`, internally tagged enums) and do
//! not round-trip through a non-self-describing format like postcard. Rather
//! than change those frozen types, each one crossing this boundary is
//! serialized through a private positional mirror (the `compat` module); the
//! public API still uses the canonical types.

use serde::{Deserialize, Serialize};

use faro_platform::{PermissionState, SessionChange};
use faro_proto::body::{AppInfo, BrowserContext, TamperSignal};

use crate::codec::MAX_FRAMES_PER_MESSAGE;
use crate::error::{IpcError, Result};
use crate::wire_frame::WireFrame;

/// Messages the agent sends to the service.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum AgentMsg {
    /// First message on every connection. See [`crate::handshake`].
    Hello {
        protocol_version: u16,
        agent_version: String,
        /// The agent's own pid; cross-checked against the kernel's view of
        /// the socket peer when available.
        pid: u32,
        /// Opaque OS session identifier (`faro_platform::SessionId`).
        session: String,
        /// Login name of the session user.
        user: String,
    },
    /// One capture of every display. Raw pixels only — never an encoded
    /// image format (§3.1, §9). At most [`MAX_FRAMES_PER_MESSAGE`] frames;
    /// use [`AgentMsg::frames_batches`] for machines with more displays.
    Frames {
        /// Monotonic ms since boot at capture time; frames sharing a value
        /// belong to the same capture.
        captured_at_mono_ms: u64,
        /// Capped at [`MAX_FRAMES_PER_MESSAGE`] *while decoding*, not just
        /// by `validate()` afterwards (see the private `frames_capped`
        /// module), so a hostile frame count is refused before allocation.
        #[serde(deserialize_with = "frames_capped::deserialize")]
        frames: Vec<WireFrame>,
    },
    /// The frontmost app and window title changed.
    Foreground {
        #[serde(with = "compat::opt_app_info")]
        app: Option<AppInfo>,
        title: Option<String>,
    },
    /// Browser context from the extension bridge.
    Browser(#[serde(with = "compat::browser_context")] BrowserContext),
    /// Periodic session state snapshot.
    Session {
        idle_secs: u64,
        locked: bool,
        display_asleep: bool,
    },
    /// An edge in session state (lock, sleep, ...).
    SessionChanged(WireSessionChange),
    /// Current OS permission state. `accessibility` is `None` on platforms
    /// without such a permission.
    Permission {
        screen: WirePermissionState,
        accessibility: Option<bool>,
    },
    /// A tamper or context signal observed in the session (§3.7).
    Tamper(#[serde(with = "compat::tamper_signal")] TamperSignal),
    /// A capture was requested or scheduled but failed. The reason is a short
    /// human-readable diagnostic and must not contain screen content.
    CaptureFailed { reason: String },
    /// Reply to [`ServiceMsg::Ping`], echoing its nonce.
    Pong { nonce: u64 },
    /// The agent is exiting deliberately (logout, shutdown request).
    Goodbye,
}

/// Messages the service sends to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceMsg {
    /// Reply to a valid `Hello`.
    Welcome {
        protocol_version: u16,
        service_version: String,
    },
    /// Capture all displays now and reply with `Frames` (or `CaptureFailed`).
    /// The service owns the schedule (§3.4); the agent never captures on its
    /// own initiative.
    CaptureNow { reason: CaptureReason },
    /// Liveness probe; the agent must answer `Pong { nonce }` promptly.
    Ping { nonce: u64 },
    /// Show a user-visible notice, e.g. the monthly consent notice listing
    /// current allies and the instance operator (§12).
    ShowNotice { title: String, body: String },
    /// The agent should exit.
    Shutdown { reason: ShutdownReason },
}

/// Why the service asked for a capture (§3.4). Carried so the agent can make
/// cheap decisions (e.g. skip the dHash-unchanged shortcut on `Burst`) and for
/// diagnostics; it never changes what is captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaptureReason {
    /// The randomized exponential schedule fired.
    Scheduled,
    /// Burst mode after a borderline/flagged result.
    Burst,
    /// Event trigger: the foreground app changed.
    ForegroundChanged,
    /// Event trigger: a new URL was reported.
    UrlChanged,
    /// Event trigger: a watch-listed DNS domain was resolved.
    WatchedDomain,
    /// The session resumed (unlock / wake).
    SessionResumed,
    /// First capture after the agent connected.
    Startup,
}

/// Why the service is telling the agent to exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ShutdownReason {
    /// The service itself is stopping.
    ServiceStopping,
    /// An update is being installed; the agent will be relaunched.
    Updating,
    /// The user session ended.
    SessionEnded,
    /// A newer agent connection for the same session replaced this one.
    Superseded,
    /// The agent's protocol version is not supported.
    IncompatibleVersion,
    /// The agent sent something it should not have.
    ProtocolViolation,
    /// Faro is being uninstalled.
    Uninstalling,
}

/// Wire mirror of [`PermissionState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WirePermissionState {
    Granted,
    Denied,
    NotDetermined,
    NotRequired,
}

impl From<PermissionState> for WirePermissionState {
    fn from(p: PermissionState) -> Self {
        match p {
            PermissionState::Granted => WirePermissionState::Granted,
            PermissionState::Denied => WirePermissionState::Denied,
            PermissionState::NotDetermined => WirePermissionState::NotDetermined,
            PermissionState::NotRequired => WirePermissionState::NotRequired,
        }
    }
}

impl From<WirePermissionState> for PermissionState {
    fn from(p: WirePermissionState) -> Self {
        match p {
            WirePermissionState::Granted => PermissionState::Granted,
            WirePermissionState::Denied => PermissionState::Denied,
            WirePermissionState::NotDetermined => PermissionState::NotDetermined,
            WirePermissionState::NotRequired => PermissionState::NotRequired,
        }
    }
}

/// Wire mirror of [`SessionChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireSessionChange {
    Locked,
    Unlocked,
    DisplaySleep,
    DisplayWake,
    SystemSleep,
    SystemWake,
}

impl From<SessionChange> for WireSessionChange {
    fn from(c: SessionChange) -> Self {
        match c {
            SessionChange::Locked => WireSessionChange::Locked,
            SessionChange::Unlocked => WireSessionChange::Unlocked,
            SessionChange::DisplaySleep => WireSessionChange::DisplaySleep,
            SessionChange::DisplayWake => WireSessionChange::DisplayWake,
            SessionChange::SystemSleep => WireSessionChange::SystemSleep,
            SessionChange::SystemWake => WireSessionChange::SystemWake,
        }
    }
}

impl From<WireSessionChange> for SessionChange {
    fn from(c: WireSessionChange) -> Self {
        match c {
            WireSessionChange::Locked => SessionChange::Locked,
            WireSessionChange::Unlocked => SessionChange::Unlocked,
            WireSessionChange::DisplaySleep => SessionChange::DisplaySleep,
            WireSessionChange::DisplayWake => SessionChange::DisplayWake,
            WireSessionChange::SystemSleep => SessionChange::SystemSleep,
            WireSessionChange::SystemWake => SessionChange::SystemWake,
        }
    }
}

impl AgentMsg {
    /// Variant name, safe to log (never includes content).
    pub fn kind(&self) -> &'static str {
        match self {
            AgentMsg::Hello { .. } => "Hello",
            AgentMsg::Frames { .. } => "Frames",
            AgentMsg::Foreground { .. } => "Foreground",
            AgentMsg::Browser(_) => "Browser",
            AgentMsg::Session { .. } => "Session",
            AgentMsg::SessionChanged(_) => "SessionChanged",
            AgentMsg::Permission { .. } => "Permission",
            AgentMsg::Tamper(_) => "Tamper",
            AgentMsg::CaptureFailed { .. } => "CaptureFailed",
            AgentMsg::Pong { .. } => "Pong",
            AgentMsg::Goodbye => "Goodbye",
        }
    }

    /// Split one capture of many displays into as many `Frames` messages as
    /// needed to respect [`MAX_FRAMES_PER_MESSAGE`]. All batches share
    /// `captured_at_mono_ms`, which is how the service regroups them.
    ///
    /// Frames are moved, never copied. Returns an empty vec for no frames.
    pub fn frames_batches(captured_at_mono_ms: u64, frames: Vec<WireFrame>) -> Vec<AgentMsg> {
        let mut out = Vec::with_capacity(frames.len().div_ceil(MAX_FRAMES_PER_MESSAGE));
        let mut iter = frames.into_iter().peekable();
        while iter.peek().is_some() {
            let batch: Vec<WireFrame> = iter.by_ref().take(MAX_FRAMES_PER_MESSAGE).collect();
            out.push(AgentMsg::Frames {
                captured_at_mono_ms,
                frames: batch,
            });
        }
        out
    }
}

impl ServiceMsg {
    /// Variant name, safe to log.
    pub fn kind(&self) -> &'static str {
        match self {
            ServiceMsg::Welcome { .. } => "Welcome",
            ServiceMsg::CaptureNow { .. } => "CaptureNow",
            ServiceMsg::Ping { .. } => "Ping",
            ServiceMsg::ShowNotice { .. } => "ShowNotice",
            ServiceMsg::Shutdown { .. } => "Shutdown",
        }
    }
}

/// Deserialize `Frames::frames` with the frame-count cap enforced up front.
///
/// Why not just `validate()` after decoding: the smallest encoded
/// `WireFrame` is 5 bytes but occupies 40 bytes in memory, so a max-size
/// payload of ~1.9 M empty frames made the privileged service allocate
/// ~200 MB (≈ 21× the payload cap) and spend a second building and zeroizing
/// them before `validate()` rejected the message — defeating the point of
/// the payload cap, which is to bound what one hostile peer can make the
/// service allocate. Postcard announces the sequence length first, so we
/// refuse an over-long sequence before decoding a single element (and also
/// count elements, for formats without a length hint).
///
/// The serde error type cannot carry a typed reason through postcard, so the
/// rejected count is parked in a thread-local that
/// [`codec::decode_payload`](crate::codec::decode_payload) turns back into
/// [`IpcError::TooManyFrames`]. Decoding is synchronous on one thread, so the
/// value can't leak between messages; `decode_payload` clears it before and
/// after every decode.
pub(crate) mod frames_capped {
    use std::cell::Cell;
    use std::fmt;

    use serde::de::{Deserializer, SeqAccess, Visitor};

    use crate::codec::MAX_FRAMES_PER_MESSAGE;
    use crate::wire_frame::WireFrame;

    thread_local! {
        static OVER_CAP: Cell<Option<usize>> = const { Cell::new(None) };
    }

    /// Take (and clear) the frame count of the last over-cap sequence seen
    /// on this thread.
    pub(crate) fn take_over_cap() -> Option<usize> {
        OVER_CAP.with(Cell::take)
    }

    fn reject<E: serde::de::Error>(count: usize) -> E {
        OVER_CAP.with(|c| c.set(Some(count)));
        E::invalid_length(count, &FramesVisitor)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<WireFrame>, D::Error> {
        d.deserialize_seq(FramesVisitor)
    }

    struct FramesVisitor;

    impl<'de> Visitor<'de> for FramesVisitor {
        type Value = Vec<WireFrame>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX_FRAMES_PER_MESSAGE} frames")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let hint = seq.size_hint();
            if let Some(n) = hint {
                if n > MAX_FRAMES_PER_MESSAGE {
                    return Err(reject(n));
                }
            }
            // At most MAX_FRAMES_PER_MESSAGE slots, so this never grows; and
            // growing a Vec<WireFrame> would only move pointers, not pixels.
            let mut out = Vec::with_capacity(hint.unwrap_or(0).min(MAX_FRAMES_PER_MESSAGE));
            while let Some(frame) = seq.next_element::<WireFrame>()? {
                if out.len() == MAX_FRAMES_PER_MESSAGE {
                    // `frame` and `out` drop here, zeroizing their pixels.
                    return Err(reject(MAX_FRAMES_PER_MESSAGE + 1));
                }
                out.push(frame);
            }
            Ok(out)
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::AgentMsg {}
    impl Sealed for super::ServiceMsg {}
    impl Sealed for crate::enroll::EnrollRequest {}
    impl Sealed for crate::enroll::EnrollResponse {}
}

/// A message type the codec can carry. Sealed: only [`AgentMsg`] and
/// [`ServiceMsg`] go on the agent's session wire, and
/// [`EnrollRequest`](crate::EnrollRequest) and
/// [`EnrollResponse`](crate::EnrollResponse) on the enroll socket.
pub trait WireMessage:
    Serialize + for<'de> Deserialize<'de> + std::fmt::Debug + sealed::Sealed
{
    /// Semantic checks beyond what the type system enforces. Run before
    /// encoding (so we never send what the peer would reject) and after
    /// decoding (so the receiver never acts on an invalid message).
    fn validate(&self) -> Result<()>;

    /// Variant name, safe to log.
    fn kind_name(&self) -> &'static str;
}

impl WireMessage for AgentMsg {
    fn validate(&self) -> Result<()> {
        if let AgentMsg::Frames { frames, .. } = self {
            if frames.len() > MAX_FRAMES_PER_MESSAGE {
                return Err(IpcError::TooManyFrames {
                    count: frames.len(),
                    max: MAX_FRAMES_PER_MESSAGE,
                });
            }
            for f in frames {
                f.check()?;
            }
        }
        Ok(())
    }

    fn kind_name(&self) -> &'static str {
        self.kind()
    }
}

impl WireMessage for ServiceMsg {
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    fn kind_name(&self) -> &'static str {
        self.kind()
    }
}

/// Positional (postcard-safe) mirrors of `faro-proto` types whose serde
/// attributes assume a self-describing format.
///
/// * `AppInfo` / `BrowserContext` use `skip_serializing_if` on `Option`
///   fields: postcard would omit the field on encode but still expect it on
///   decode, desynchronizing the stream.
/// * `TamperSignal` is internally tagged (`#[serde(tag = "signal")]`), which
///   requires `deserialize_any`, which postcard does not support.
///
/// Conversions are exhaustive matches, so adding a variant/field upstream is
/// a compile error here rather than a silent wire change.
mod compat {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct WireAppInfo {
        id: String,
        name: Option<String>,
    }

    pub mod opt_app_info {
        use super::*;

        pub fn serialize<S: serde::Serializer>(
            v: &Option<AppInfo>,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            let mirror = v.as_ref().map(|a| WireAppInfo {
                id: a.id.clone(),
                name: a.name.clone(),
            });
            mirror.serialize(s)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<Option<AppInfo>, D::Error> {
            let mirror = Option::<WireAppInfo>::deserialize(d)?;
            Ok(mirror.map(|m| AppInfo {
                id: m.id,
                name: m.name,
            }))
        }
    }

    #[derive(Serialize, Deserialize)]
    struct WireBrowserContext {
        url: Option<String>,
        title: Option<String>,
        incognito: bool,
    }

    pub mod browser_context {
        use super::*;

        pub fn serialize<S: serde::Serializer>(
            v: &BrowserContext,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            let BrowserContext {
                url,
                title,
                incognito,
            } = v;
            WireBrowserContext {
                url: url.clone(),
                title: title.clone(),
                incognito: *incognito,
            }
            .serialize(s)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<BrowserContext, D::Error> {
            let m = WireBrowserContext::deserialize(d)?;
            Ok(BrowserContext {
                url: m.url,
                title: m.title,
                incognito: m.incognito,
            })
        }
    }

    /// Externally tagged, positional mirror of [`TamperSignal`]. Order is part
    /// of the wire format: append only.
    #[derive(Serialize, Deserialize)]
    enum WireTamperSignal {
        PermissionRevoked {
            permission: String,
        },
        AgentKilledRepeatedly {
            count: u32,
            window_secs: u64,
        },
        IntegrityFailure {
            component: String,
        },
        ClockManipulation {
            wall_delta_ms: i64,
            mono_delta_ms: i64,
        },
        WaylandTokenLost,
        CaptureFailing {
            consecutive_failures: u32,
        },
        BrowserWithoutExtension {
            browser: String,
        },
        VpnActive,
        VirtualMachine,
        RemoteDesktop,
        UnmonitoredUserSession {
            user: String,
        },
        WindowHiddenFromCapture {
            app: String,
        },
    }

    impl From<&TamperSignal> for WireTamperSignal {
        fn from(t: &TamperSignal) -> Self {
            use TamperSignal as T;
            use WireTamperSignal as W;
            match t.clone() {
                T::PermissionRevoked { permission } => W::PermissionRevoked { permission },
                T::AgentKilledRepeatedly { count, window_secs } => {
                    W::AgentKilledRepeatedly { count, window_secs }
                }
                T::IntegrityFailure { component } => W::IntegrityFailure { component },
                T::ClockManipulation {
                    wall_delta_ms,
                    mono_delta_ms,
                } => W::ClockManipulation {
                    wall_delta_ms,
                    mono_delta_ms,
                },
                T::WaylandTokenLost => W::WaylandTokenLost,
                T::CaptureFailing {
                    consecutive_failures,
                } => W::CaptureFailing {
                    consecutive_failures,
                },
                T::BrowserWithoutExtension { browser } => W::BrowserWithoutExtension { browser },
                T::VpnActive => W::VpnActive,
                T::VirtualMachine => W::VirtualMachine,
                T::RemoteDesktop => W::RemoteDesktop,
                T::UnmonitoredUserSession { user } => W::UnmonitoredUserSession { user },
                T::WindowHiddenFromCapture { app } => W::WindowHiddenFromCapture { app },
            }
        }
    }

    impl From<WireTamperSignal> for TamperSignal {
        fn from(w: WireTamperSignal) -> Self {
            use TamperSignal as T;
            use WireTamperSignal as W;
            match w {
                W::PermissionRevoked { permission } => T::PermissionRevoked { permission },
                W::AgentKilledRepeatedly { count, window_secs } => {
                    T::AgentKilledRepeatedly { count, window_secs }
                }
                W::IntegrityFailure { component } => T::IntegrityFailure { component },
                W::ClockManipulation {
                    wall_delta_ms,
                    mono_delta_ms,
                } => T::ClockManipulation {
                    wall_delta_ms,
                    mono_delta_ms,
                },
                W::WaylandTokenLost => T::WaylandTokenLost,
                W::CaptureFailing {
                    consecutive_failures,
                } => T::CaptureFailing {
                    consecutive_failures,
                },
                W::BrowserWithoutExtension { browser } => T::BrowserWithoutExtension { browser },
                W::VpnActive => T::VpnActive,
                W::VirtualMachine => T::VirtualMachine,
                W::RemoteDesktop => T::RemoteDesktop,
                W::UnmonitoredUserSession { user } => T::UnmonitoredUserSession { user },
                W::WindowHiddenFromCapture { app } => T::WindowHiddenFromCapture { app },
            }
        }
    }

    pub mod tamper_signal {
        use super::*;

        pub fn serialize<S: serde::Serializer>(
            v: &TamperSignal,
            s: S,
        ) -> std::result::Result<S::Ok, S::Error> {
            WireTamperSignal::from(v).serialize(s)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            d: D,
        ) -> std::result::Result<TamperSignal, D::Error> {
            WireTamperSignal::deserialize(d).map(TamperSignal::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire_frame::WirePixelFormat;

    fn frame(id: u32) -> WireFrame {
        WireFrame::new(1, 1, WirePixelFormat::Rgba8, id, vec![0; 4]).unwrap()
    }

    #[test]
    fn frames_batches_respects_cap_and_order() {
        for n in 0..=(3 * MAX_FRAMES_PER_MESSAGE + 1) {
            let frames: Vec<_> = (0..n as u32).map(frame).collect();
            let batches = AgentMsg::frames_batches(77, frames);
            assert_eq!(batches.len(), n.div_ceil(MAX_FRAMES_PER_MESSAGE));
            let mut ids = Vec::new();
            for b in &batches {
                b.validate().unwrap();
                let AgentMsg::Frames {
                    captured_at_mono_ms,
                    frames,
                } = b
                else {
                    panic!("not a Frames message");
                };
                assert_eq!(*captured_at_mono_ms, 77);
                assert!(!frames.is_empty() && frames.len() <= MAX_FRAMES_PER_MESSAGE);
                ids.extend(frames.iter().map(|f| f.display_id()));
            }
            assert_eq!(ids, (0..n as u32).collect::<Vec<_>>());
        }
    }

    #[test]
    fn validate_rejects_too_many_frames() {
        let msg = AgentMsg::Frames {
            captured_at_mono_ms: 0,
            frames: (0..=MAX_FRAMES_PER_MESSAGE as u32).map(frame).collect(),
        };
        assert!(matches!(
            msg.validate(),
            Err(IpcError::TooManyFrames { .. })
        ));
    }

    #[test]
    fn platform_enum_conversions_roundtrip() {
        for p in [
            PermissionState::Granted,
            PermissionState::Denied,
            PermissionState::NotDetermined,
            PermissionState::NotRequired,
        ] {
            assert_eq!(PermissionState::from(WirePermissionState::from(p)), p);
        }
        for c in [
            SessionChange::Locked,
            SessionChange::Unlocked,
            SessionChange::DisplaySleep,
            SessionChange::DisplayWake,
            SessionChange::SystemSleep,
            SessionChange::SystemWake,
        ] {
            assert_eq!(SessionChange::from(WireSessionChange::from(c)), c);
        }
    }

    /// Documents why the compat mirrors exist: the proto types' JSON-oriented
    /// serde attributes do not survive postcard. If this ever starts passing,
    /// the mirrors could be dropped (with a protocol version bump).
    #[test]
    fn proto_types_are_not_directly_postcard_safe() {
        let ctx = BrowserContext {
            url: None,
            title: Some("t".into()),
            incognito: true,
        };
        let direct = postcard::to_allocvec(&ctx)
            .ok()
            .and_then(|b| postcard::from_bytes::<BrowserContext>(&b).ok());
        assert_ne!(direct, Some(ctx));

        let sig = TamperSignal::VpnActive;
        let direct = postcard::to_allocvec(&sig)
            .ok()
            .and_then(|b| postcard::from_bytes::<TamperSignal>(&b).ok());
        assert_ne!(direct, Some(sig));
    }
}
