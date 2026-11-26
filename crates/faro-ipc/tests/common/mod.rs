//! Shared message samples and proptest strategies for the integration tests.
#![allow(dead_code)] // each test binary uses a different subset

use faro_ipc::status::{CaptureState, ServicePhase};
use faro_ipc::{
    AgentMsg, CaptureReason, MemberStatus, ServiceMsg, ShutdownReason, WireFrame,
    WirePermissionState, WirePixelFormat, WireSessionChange, MAX_FRAMES_PER_MESSAGE,
};
use faro_proto::body::{AppInfo, BrowserContext, TamperSignal};
use proptest::prelude::*;

pub fn frame(w: u32, h: u32, fill: u8, display_id: u32) -> WireFrame {
    WireFrame::new(
        w,
        h,
        WirePixelFormat::Bgra8,
        display_id,
        vec![fill; (w * h * 4) as usize],
    )
    .expect("valid test frame")
}

pub fn all_tamper_signals() -> Vec<TamperSignal> {
    vec![
        TamperSignal::PermissionRevoked {
            permission: "screen".into(),
            never_granted: false,
        },
        TamperSignal::AgentKilledRepeatedly {
            count: 3,
            window_secs: 600,
        },
        TamperSignal::IntegrityFailure {
            component: "model".into(),
        },
        TamperSignal::ClockManipulation {
            wall_delta_ms: -86_400_000,
            mono_delta_ms: i64::MAX,
        },
        TamperSignal::WaylandTokenLost,
        TamperSignal::CaptureFailing {
            consecutive_failures: u32::MAX,
        },
        TamperSignal::BrowserWithoutExtension {
            browser: "firefox".into(),
        },
        TamperSignal::VpnActive,
        TamperSignal::VirtualMachine,
        TamperSignal::RemoteDesktop,
        TamperSignal::UnmonitoredUserSession {
            user: "guest".into(),
        },
        TamperSignal::WindowHiddenFromCapture {
            app: "Viewer".into(),
        },
    ]
}

/// One (or more) instance of every `AgentMsg` variant, including the
/// `Option::None` cases that break naive postcard use of proto types.
pub fn all_agent_msgs() -> Vec<AgentMsg> {
    let mut v = vec![
        AgentMsg::Hello {
            protocol_version: faro_ipc::PROTOCOL_VERSION,
            agent_version: "0.1.0".into(),
            pid: 4321,
            session: "console".into(),
            user: "alice".into(),
        },
        AgentMsg::Frames {
            captured_at_mono_ms: 9_123_311,
            frames: vec![frame(4, 3, 1, 0), frame(1, 1, 2, 7)],
        },
        AgentMsg::Frames {
            captured_at_mono_ms: 0,
            frames: vec![],
        },
        AgentMsg::Foreground {
            app: Some(AppInfo {
                id: "com.google.Chrome".into(),
                name: Some("Google Chrome".into()),
            }),
            title: Some("Inbox – ünïcødé ✓".into()),
        },
        AgentMsg::Foreground {
            app: Some(AppInfo {
                id: "chrome.exe".into(),
                name: None,
            }),
            title: None,
        },
        AgentMsg::Foreground {
            app: None,
            title: None,
        },
        AgentMsg::Browser(BrowserContext {
            url: Some("https://example.org/".into()),
            title: Some("Example".into()),
            incognito: false,
        }),
        AgentMsg::Browser(BrowserContext {
            url: None,
            title: None,
            incognito: true,
        }),
        AgentMsg::Session {
            idle_secs: u64::MAX,
            locked: true,
            display_asleep: false,
        },
        AgentMsg::Permission {
            screen: WirePermissionState::Denied,
            accessibility: None,
        },
        AgentMsg::Permission {
            screen: WirePermissionState::Granted,
            accessibility: Some(false),
        },
        AgentMsg::CaptureFailed {
            reason: String::new(),
        },
        AgentMsg::Pong { nonce: u64::MAX },
        AgentMsg::Goodbye,
    ];
    for c in [
        WireSessionChange::Locked,
        WireSessionChange::Unlocked,
        WireSessionChange::DisplaySleep,
        WireSessionChange::DisplayWake,
        WireSessionChange::SystemSleep,
        WireSessionChange::SystemWake,
    ] {
        v.push(AgentMsg::SessionChanged(c));
    }
    for t in all_tamper_signals() {
        v.push(AgentMsg::Tamper(t));
    }
    v
}

pub fn all_service_msgs() -> Vec<ServiceMsg> {
    let mut v = vec![
        ServiceMsg::Welcome {
            protocol_version: faro_ipc::PROTOCOL_VERSION,
            service_version: "0.1.0".into(),
        },
        ServiceMsg::Ping { nonce: 0 },
        ServiceMsg::ShowNotice {
            title: "Faro is running".into(),
            body: "Your allies: Bob, Carol.\nInstance: faro.example (operated by St. X)".into(),
        },
    ];
    for r in [
        CaptureReason::Scheduled,
        CaptureReason::Burst,
        CaptureReason::ForegroundChanged,
        CaptureReason::UrlChanged,
        CaptureReason::WatchedDomain,
        CaptureReason::SessionResumed,
        CaptureReason::Startup,
    ] {
        v.push(ServiceMsg::CaptureNow { reason: r });
    }
    for r in [
        ShutdownReason::ServiceStopping,
        ShutdownReason::Updating,
        ShutdownReason::SessionEnded,
        ShutdownReason::Superseded,
        ShutdownReason::IncompatibleVersion,
        ShutdownReason::ProtocolViolation,
        ShutdownReason::Uninstalling,
    ] {
        v.push(ServiceMsg::Shutdown { reason: r });
    }
    v.push(ServiceMsg::Status(MemberStatus::default()));
    v.push(ServiceMsg::Status(MemberStatus {
        service_version: "0.1.0-beta.1".into(),
        phase: ServicePhase::Running,
        instance_name: "Sam's Faro".into(),
        instance_url: "https://faro.example.org/".into(),
        capture: Some(CaptureState::Paused),
        paused_until_ms: Some(1_700_000_000_000),
        screen_recording: Some(WirePermissionState::Denied),
        accessibility: Some(false),
        consecutive_failures: 7,
        unreachable_since_ms: Some(-1),
        identity_mismatch: true,
        updates_failing: true,
    }));
    v
}

fn arb_member_status() -> impl Strategy<Value = MemberStatus> {
    (
        (text(), text(), text()),
        prop_oneof![
            Just(ServicePhase::Starting),
            Just(ServicePhase::AwaitingEndorsement),
            Just(ServicePhase::Running),
            Just(ServicePhase::ShuttingDown),
            Just(ServicePhase::Stopped),
        ],
        proptest::option::of(prop_oneof![
            Just(CaptureState::NotStarted),
            Just(CaptureState::Active),
            Just(CaptureState::Idle),
            Just(CaptureState::Locked),
            Just(CaptureState::Asleep),
            Just(CaptureState::Paused),
            Just(CaptureState::LoginWindow),
            Just(CaptureState::NoAgent),
            Just(CaptureState::Stopped),
        ]),
        proptest::option::of(any::<i64>()),
        proptest::option::of(prop_oneof![
            Just(WirePermissionState::Granted),
            Just(WirePermissionState::Denied),
            Just(WirePermissionState::NotDetermined),
            Just(WirePermissionState::NotRequired),
        ]),
        proptest::option::of(any::<bool>()),
        any::<u32>(),
        proptest::option::of(any::<i64>()),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(
                (service_version, instance_name, instance_url),
                phase,
                capture,
                paused_until_ms,
                screen_recording,
                accessibility,
                consecutive_failures,
                unreachable_since_ms,
                identity_mismatch,
                updates_failing,
            )| MemberStatus {
                service_version,
                phase,
                instance_name,
                instance_url,
                capture,
                paused_until_ms,
                screen_recording,
                accessibility,
                consecutive_failures,
                unreachable_since_ms,
                identity_mismatch,
                updates_failing,
            },
        )
}

fn text() -> impl Strategy<Value = String> {
    "\\PC{0,24}"
}

fn opt_text() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(text())
}

pub fn arb_wire_frame() -> impl Strategy<Value = WireFrame> {
    (1u32..=6, 1u32..=6, any::<bool>(), any::<u32>()).prop_flat_map(|(w, h, bgra, id)| {
        proptest::collection::vec(any::<u8>(), (w * h * 4) as usize).prop_map(move |px| {
            let fmt = if bgra {
                WirePixelFormat::Bgra8
            } else {
                WirePixelFormat::Rgba8
            };
            WireFrame::new(w, h, fmt, id, px).expect("strategy builds valid frames")
        })
    })
}

pub fn arb_tamper() -> impl Strategy<Value = TamperSignal> {
    prop_oneof![
        // `never_granted` is not carried over IPC (the service decides it).
        text().prop_map(|permission| TamperSignal::PermissionRevoked {
            permission,
            never_granted: false
        }),
        (any::<u32>(), any::<u64>()).prop_map(|(count, window_secs)| {
            TamperSignal::AgentKilledRepeatedly { count, window_secs }
        }),
        text().prop_map(|component| TamperSignal::IntegrityFailure { component }),
        (any::<i64>(), any::<i64>()).prop_map(|(wall_delta_ms, mono_delta_ms)| {
            TamperSignal::ClockManipulation {
                wall_delta_ms,
                mono_delta_ms,
            }
        }),
        Just(TamperSignal::WaylandTokenLost),
        any::<u32>().prop_map(|consecutive_failures| TamperSignal::CaptureFailing {
            consecutive_failures
        }),
        text().prop_map(|browser| TamperSignal::BrowserWithoutExtension { browser }),
        Just(TamperSignal::VpnActive),
        Just(TamperSignal::VirtualMachine),
        Just(TamperSignal::RemoteDesktop),
        text().prop_map(|user| TamperSignal::UnmonitoredUserSession { user }),
        text().prop_map(|app| TamperSignal::WindowHiddenFromCapture { app }),
    ]
}

pub fn arb_agent_msg() -> impl Strategy<Value = AgentMsg> {
    prop_oneof![
        (any::<u16>(), text(), any::<u32>(), text(), text()).prop_map(
            |(protocol_version, agent_version, pid, session, user)| AgentMsg::Hello {
                protocol_version,
                agent_version,
                pid,
                session,
                user
            }
        ),
        (
            any::<u64>(),
            proptest::collection::vec(arb_wire_frame(), 0..=MAX_FRAMES_PER_MESSAGE)
        )
            .prop_map(|(captured_at_mono_ms, frames)| AgentMsg::Frames {
                captured_at_mono_ms,
                frames
            }),
        (proptest::option::of((text(), opt_text())), opt_text()).prop_map(|(app, title)| {
            AgentMsg::Foreground {
                app: app.map(|(id, name)| AppInfo { id, name }),
                title,
            }
        }),
        (opt_text(), opt_text(), any::<bool>()).prop_map(|(url, title, incognito)| {
            AgentMsg::Browser(BrowserContext {
                url,
                title,
                incognito,
            })
        }),
        (any::<u64>(), any::<bool>(), any::<bool>()).prop_map(
            |(idle_secs, locked, display_asleep)| AgentMsg::Session {
                idle_secs,
                locked,
                display_asleep
            }
        ),
        prop_oneof![
            Just(WireSessionChange::Locked),
            Just(WireSessionChange::Unlocked),
            Just(WireSessionChange::DisplaySleep),
            Just(WireSessionChange::DisplayWake),
            Just(WireSessionChange::SystemSleep),
            Just(WireSessionChange::SystemWake),
        ]
        .prop_map(AgentMsg::SessionChanged),
        (
            prop_oneof![
                Just(WirePermissionState::Granted),
                Just(WirePermissionState::Denied),
                Just(WirePermissionState::NotDetermined),
                Just(WirePermissionState::NotRequired),
            ],
            proptest::option::of(any::<bool>())
        )
            .prop_map(|(screen, accessibility)| AgentMsg::Permission {
                screen,
                accessibility
            }),
        arb_tamper().prop_map(AgentMsg::Tamper),
        text().prop_map(|reason| AgentMsg::CaptureFailed { reason }),
        any::<u64>().prop_map(|nonce| AgentMsg::Pong { nonce }),
        proptest::strategy::LazyJust::new(|| AgentMsg::Goodbye),
    ]
}

pub fn arb_service_msg() -> impl Strategy<Value = ServiceMsg> {
    prop_oneof![
        (any::<u16>(), text()).prop_map(|(protocol_version, service_version)| {
            ServiceMsg::Welcome {
                protocol_version,
                service_version,
            }
        }),
        prop_oneof![
            Just(CaptureReason::Scheduled),
            Just(CaptureReason::Burst),
            Just(CaptureReason::ForegroundChanged),
            Just(CaptureReason::UrlChanged),
            Just(CaptureReason::WatchedDomain),
            Just(CaptureReason::SessionResumed),
            Just(CaptureReason::Startup),
        ]
        .prop_map(|reason| ServiceMsg::CaptureNow { reason }),
        any::<u64>().prop_map(|nonce| ServiceMsg::Ping { nonce }),
        (text(), text()).prop_map(|(title, body)| ServiceMsg::ShowNotice { title, body }),
        prop_oneof![
            Just(ShutdownReason::ServiceStopping),
            Just(ShutdownReason::Updating),
            Just(ShutdownReason::SessionEnded),
            Just(ShutdownReason::Superseded),
            Just(ShutdownReason::IncompatibleVersion),
            Just(ShutdownReason::ProtocolViolation),
            Just(ShutdownReason::Uninstalling),
        ]
        .prop_map(|reason| ServiceMsg::Shutdown { reason }),
        arb_member_status().prop_map(ServiceMsg::Status),
    ]
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}
