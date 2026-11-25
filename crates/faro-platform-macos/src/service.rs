//! Service-side macOS integration: launchd job definitions, installation,
//! and GUI session discovery (ARCHITECTURE.md §3.1, §3.3 "Service").
//!
//! # Process layout
//!
//! * `org.faro.service` — a **LaunchDaemon** (root, boot to shutdown).
//! * `org.faro.agent` — a **LaunchAgent** limited to `Aqua` sessions, so
//!   launchd starts one copy inside every graphical login session and
//!   restarts it if it is killed (`KeepAlive`). This is why
//!   [`ServiceHost::spawn_agent_in_session`] is `Unavailable` on macOS: the
//!   service never launches the agent itself; it only observes it over IPC
//!   and reports restarts.
//!
//! # Installation (the installer phase)
//!
//! The plist generators here are pure so the installer tooling and tests can
//! use them. The real installation paths are:
//!
//! 1. **Signed `.pkg` (primary, §3.3 "Distribution")**, built by
//!    `installers/macos/build-pkg.sh`: the payload places the programs in
//!    `/Library/Faro` ([`pkg_layout`]; the agent inside `Faro Agent.app`)
//!    and the plists from [`pkg_daemon_job`] and [`pkg_agent_job`] in
//!    `/Library/LaunchDaemons/org.faro.service.plist` and
//!    `/Library/LaunchAgents/org.faro.agent.plist` (root-owned, 0644). The
//!    `postinstall` script runs `launchctl bootstrap system …` for the
//!    daemon and `launchctl bootstrap gui/<uid> …` for every logged-in
//!    account; the global LaunchAgent covers later logins. Plists for this
//!    path use [`ProgramLocation::Absolute`].
//! 2. **`SMAppService` (macOS 13+)**: the app bundle embeds the plists in
//!    `Contents/Library/LaunchDaemons|LaunchAgents/` using
//!    [`ProgramLocation::BundleRelative`] (`BundleProgram`), and the signed
//!    app registers them. [`MacServiceHost::install`] implements this path;
//!    it refuses with `Unavailable` unless the current process runs from an
//!    `.app` bundle containing both plists, because `SMAppService` resolves
//!    plists relative to the main bundle and validates its code signature.
//!    The daemon additionally needs one-time approval in System Settings →
//!    General → Login Items, which surfaces as `PermissionDenied`.

use std::path::{Component, Path, PathBuf};

use faro_platform::{
    AgentPid, PlatformError, Result as PlatformResult, ServiceHost, SessionId, SessionInfo,
};
use objc2::rc::autoreleasepool;
use objc2_core_foundation::{CFDictionary, CFString};
use objc2_foundation::{NSBundle, NSString};
use objc2_service_management::{SMAppService, SMAppServiceStatus};
use objc2_system_configuration::SCDynamicStore;
use plist::{Dictionary, Value};

use crate::cf;

/// launchd label of the privileged service.
pub const DAEMON_LABEL: &str = "org.faro.service";
/// launchd label of the per-session agent.
pub const AGENT_LABEL: &str = "org.faro.agent";
/// Minimum seconds between launchd restarts. Throttling keeps a crash loop
/// from burning CPU while still restarting a killed agent quickly enough
/// that a gap in coverage is short (and the restart is reported).
pub const DEFAULT_THROTTLE_SECS: u32 = 10;

/// Lowest uid of a regular (human) macOS account. Lower uids are system
/// accounts such as `_mbsetupuser` (Setup Assistant), which own CGS sessions
/// but are not people Faro monitors.
pub const FIRST_REGULAR_UID: u32 = 501;

/// Why a launchd plist could not be generated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlistError {
    #[error("invalid launchd label {0:?}")]
    InvalidLabel(String),
    #[error("program path {0:?} must be absolute and free of '..' components")]
    InvalidAbsolutePath(PathBuf),
    #[error("bundle program path {0:?} must be relative to the bundle and stay inside it")]
    InvalidBundlePath(String),
    #[error("program arguments must not contain NUL bytes")]
    InvalidArgument,
    #[error("plist serialization failed: {0}")]
    Serialize(String),
}

/// Where launchd finds the executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramLocation {
    /// `Program` key; used for plists installed by the `.pkg`.
    Absolute(PathBuf),
    /// `BundleProgram` key, relative to the app bundle; required for
    /// plists registered through `SMAppService`.
    BundleRelative(String),
}

/// launchd job definition (the subset of `launchd.plist(5)` Faro uses).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchdJob {
    pub label: String,
    pub program: ProgramLocation,
    /// Arguments after argv\[0\]; argv\[0\] is derived from the program.
    pub args: Vec<String>,
    pub keep_alive: bool,
    pub run_at_load: bool,
    pub throttle_interval: u32,
    /// `LimitLoadToSessionType = Aqua`: only load in GUI login sessions.
    pub aqua_only: bool,
    /// `ProcessType`; `Interactive` exempts the agent from App Nap-style
    /// throttling so capture timing stays honest.
    pub process_type: Option<&'static str>,
    /// `AssociatedBundleIdentifiers`, which makes System Settings → Login
    /// Items show the job under the Faro app instead of an anonymous entry.
    pub associated_bundle_ids: Vec<String>,
    /// `StandardOutPath` / `StandardErrorPath`. Unset for production jobs
    /// (they log through the unified log); handy for spike tools.
    pub stdout_path: Option<PathBuf>,
    pub stderr_path: Option<PathBuf>,
    /// `StartInterval`: also start the job every N seconds (spike tools).
    pub start_interval: Option<u32>,
}

impl LaunchdJob {
    /// The privileged service daemon.
    pub fn daemon(program: ProgramLocation) -> Self {
        LaunchdJob {
            label: DAEMON_LABEL.into(),
            program,
            args: vec!["run".into()],
            keep_alive: true,
            run_at_load: true,
            throttle_interval: DEFAULT_THROTTLE_SECS,
            aqua_only: false,
            process_type: Some("Standard"),
            associated_bundle_ids: Vec::new(),
            stdout_path: None,
            stderr_path: None,
            start_interval: None,
        }
    }

    /// The per-session agent.
    pub fn agent(program: ProgramLocation) -> Self {
        LaunchdJob {
            label: AGENT_LABEL.into(),
            program,
            args: vec!["run".into()],
            keep_alive: true,
            run_at_load: true,
            throttle_interval: DEFAULT_THROTTLE_SECS,
            aqua_only: true,
            process_type: Some("Interactive"),
            associated_bundle_ids: Vec::new(),
            stdout_path: None,
            stderr_path: None,
            start_interval: None,
        }
    }

    fn validate(&self) -> Result<(), PlistError> {
        validate_label(&self.label)?;
        match &self.program {
            ProgramLocation::Absolute(p) => {
                if !p.is_absolute()
                    || p.components().any(|c| matches!(c, Component::ParentDir))
                    || !p.to_str().is_some_and(|s| !s.contains('\0'))
                {
                    return Err(PlistError::InvalidAbsolutePath(p.clone()));
                }
            }
            ProgramLocation::BundleRelative(p) => {
                let path = Path::new(p);
                let ok = !p.is_empty()
                    && !p.contains('\0')
                    && path.components().all(|c| matches!(c, Component::Normal(_)));
                if !ok {
                    return Err(PlistError::InvalidBundlePath(p.clone()));
                }
            }
        }
        for p in [&self.stdout_path, &self.stderr_path].into_iter().flatten() {
            if !p.is_absolute() || !p.to_str().is_some_and(|s| !s.contains('\0')) {
                return Err(PlistError::InvalidAbsolutePath(p.clone()));
            }
        }
        if self.args.iter().any(|a| a.contains('\0')) {
            return Err(PlistError::InvalidArgument);
        }
        for id in &self.associated_bundle_ids {
            validate_label(id)?;
        }
        Ok(())
    }

    /// Render as an XML property list for launchd / `SMAppService`.
    pub fn to_plist_xml(&self) -> Result<String, PlistError> {
        self.validate()?;
        let mut d = Dictionary::new();
        d.insert("Label".into(), Value::String(self.label.clone()));
        let argv0 = match &self.program {
            ProgramLocation::Absolute(p) => {
                let s = p.to_string_lossy().into_owned();
                d.insert("Program".into(), Value::String(s.clone()));
                s
            }
            ProgramLocation::BundleRelative(p) => {
                d.insert("BundleProgram".into(), Value::String(p.clone()));
                p.clone()
            }
        };
        let argv = std::iter::once(argv0)
            .chain(self.args.iter().cloned())
            .map(Value::String)
            .collect();
        d.insert("ProgramArguments".into(), Value::Array(argv));
        d.insert("RunAtLoad".into(), Value::Boolean(self.run_at_load));
        d.insert("KeepAlive".into(), Value::Boolean(self.keep_alive));
        d.insert(
            "ThrottleInterval".into(),
            Value::Integer(u64::from(self.throttle_interval).into()),
        );
        if self.aqua_only {
            d.insert(
                "LimitLoadToSessionType".into(),
                Value::String("Aqua".into()),
            );
        }
        if let Some(pt) = self.process_type {
            d.insert("ProcessType".into(), Value::String(pt.into()));
        }
        if !self.associated_bundle_ids.is_empty() {
            d.insert(
                "AssociatedBundleIdentifiers".into(),
                Value::Array(
                    self.associated_bundle_ids
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
        }
        if let Some(secs) = self.start_interval {
            d.insert(
                "StartInterval".into(),
                Value::Integer(u64::from(secs).into()),
            );
        }
        if let Some(p) = &self.stdout_path {
            d.insert(
                "StandardOutPath".into(),
                Value::String(p.to_string_lossy().into_owned()),
            );
        }
        if let Some(p) = &self.stderr_path {
            d.insert(
                "StandardErrorPath".into(),
                Value::String(p.to_string_lossy().into_owned()),
            );
        }
        let mut buf = Vec::new();
        Value::Dictionary(d)
            .to_writer_xml(&mut buf)
            .map_err(|e| PlistError::Serialize(e.to_string()))?;
        String::from_utf8(buf).map_err(|e| PlistError::Serialize(e.to_string()))
    }
}

/// launchd labels (and bundle ids) are reverse-DNS: ASCII alphanumerics,
/// `.`, `-`, `_`; no empty segments.
fn validate_label(label: &str) -> Result<(), PlistError> {
    let ok = !label.is_empty()
        && label.len() <= 255
        && label.split('.').all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if ok {
        Ok(())
    } else {
        Err(PlistError::InvalidLabel(label.into()))
    }
}

/// Where the `.pkg` installs Faro (`installers/macos`). Programs live in
/// `/Library/Faro`, root-owned and readable by everyone (every account's
/// session runs the agent); the state directory
/// (`/Library/Application Support/Faro`, 0700) holds only root's data.
pub mod pkg_layout {
    /// The privileged service binary.
    pub const SERVICE_PROGRAM: &str = "/Library/Faro/bin/faro-service";
    /// The agent, inside an app bundle so macOS attributes the Screen
    /// Recording permission (and the code-signing identifier
    /// `org.faro.agent`) to "Faro Agent".
    pub const AGENT_APP: &str = "/Library/Faro/Faro Agent.app";
    pub const AGENT_PROGRAM: &str = "/Library/Faro/Faro Agent.app/Contents/MacOS/faro-agent";
    /// Bundle identifier of `Faro Agent.app`.
    pub const AGENT_BUNDLE_ID: &str = "org.faro.agent";
    /// The installed daemon plist.
    pub const DAEMON_PLIST: &str = "/Library/LaunchDaemons/org.faro.service.plist";
    /// The installed **global** LaunchAgent: launchd starts it in every
    /// account's GUI session, including accounts created after install.
    pub const AGENT_PLIST: &str = "/Library/LaunchAgents/org.faro.agent.plist";
    /// The project's update root of trust (a signed root document), shipped
    /// in release packages (§3.8). Without it the service doesn't update.
    pub const UPDATE_ROOT: &str = "/Library/Faro/update-root.json";
    /// The image model's manifest (`faro_detect::ModelInfo`); the model
    /// file sits next to it. Built by `crates/faro-detect/models/opennsfw`.
    pub const MODEL_MANIFEST: &str = "/Library/Faro/models/opennsfw/manifest.json";
    /// Licences and attribution for the third-party parts of the package
    /// (the image model, ONNX Runtime).
    pub const NOTICES_DIR: &str = "/Library/Faro/notices";
}

/// The daemon job the `.pkg` installs ([`pkg_layout`]).
pub fn pkg_daemon_job() -> LaunchdJob {
    let mut job = LaunchdJob::daemon(ProgramLocation::Absolute(
        pkg_layout::SERVICE_PROGRAM.into(),
    ));
    job.associated_bundle_ids = vec![pkg_layout::AGENT_BUNDLE_ID.into()];
    job
}

/// The global agent job the `.pkg` installs ([`pkg_layout`]).
pub fn pkg_agent_job() -> LaunchdJob {
    let mut job = LaunchdJob::agent(ProgramLocation::Absolute(pkg_layout::AGENT_PROGRAM.into()));
    job.associated_bundle_ids = vec![pkg_layout::AGENT_BUNDLE_ID.into()];
    job
}

/// XML for the LaunchDaemon (`org.faro.service`).
pub fn daemon_plist(program: ProgramLocation) -> Result<String, PlistError> {
    LaunchdJob::daemon(program).to_plist_xml()
}

/// XML for the LaunchAgent (`org.faro.agent`).
pub fn agent_plist(program: ProgramLocation) -> Result<String, PlistError> {
    LaunchdJob::agent(program).to_plist_xml()
}

/// One CGS login session as reported by the dynamic store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSession {
    pub user: String,
    pub uid: u32,
    pub on_console: bool,
    pub login_done: bool,
}

/// Turn raw session records into [`SessionInfo`]s: drop system accounts and
/// sessions still at the login window, dedupe by uid (one GUI session per
/// user on macOS), and identify sessions as `uid:<uid>`.
///
/// `console_uid` is the user currently on the console as reported by the
/// dynamic store's top-level `UID` (what `SCDynamicStoreCopyConsoleUser`
/// returns). When known it is authoritative for `active`: the per-session
/// `kCGSSessionOnConsoleKey` flag has been observed to be `FALSE` for the
/// logged-in user and `TRUE` for `_mbsetupuser` on current macOS, which
/// would otherwise report the only real session as inactive. The per-session
/// flag is used only when the console user is unknown.
pub fn sessions_from_records(
    records: &[ConsoleSession],
    console_uid: Option<u32>,
) -> Vec<SessionInfo> {
    let is_active = |r: &ConsoleSession| match console_uid {
        Some(uid) => r.uid == uid,
        None => r.on_console,
    };
    let mut out: Vec<SessionInfo> = Vec::new();
    for r in records {
        if r.uid < FIRST_REGULAR_UID
            || !r.login_done
            || r.user.is_empty()
            || r.user == "loginwindow"
        {
            continue;
        }
        let id = SessionId(format!("uid:{}", r.uid));
        if let Some(existing) = out.iter_mut().find(|s| s.id == id) {
            existing.active |= is_active(r);
            continue;
        }
        out.push(SessionInfo {
            id,
            user: r.user.clone(),
            graphical: true,
            active: is_active(r),
        });
    }
    out
}

/// What `State:/Users/ConsoleUser` says.
#[derive(Debug, Clone)]
struct ConsoleStore {
    /// Top-level `UID`: the user on the console right now.
    console_uid: Option<u32>,
    sessions: Vec<ConsoleSession>,
}

/// Read `State:/Users/ConsoleUser` from the SystemConfiguration dynamic
/// store. Its `SessionInfo` array lists every CGS session, including users
/// switched away from via fast user switching.
fn read_console_store() -> Option<ConsoleStore> {
    let name = CFString::from_str("org.faro.service");
    // SAFETY: no callback and a null context, which SCDynamicStoreCreate
    // documents as valid for a store used only for synchronous reads.
    let store: objc2_core_foundation::CFRetained<SCDynamicStore> =
        unsafe { SCDynamicStore::new(None, &name, None, std::ptr::null_mut()) }?;
    let key = CFString::from_str("State:/Users/ConsoleUser");
    let value = SCDynamicStore::value(Some(&store), &key)?;
    let dict = value.downcast::<CFDictionary>().ok()?;
    let dict = cf::as_plist_dict(&dict);
    let console_uid = cf::get_i64(dict, "UID").and_then(|u| u32::try_from(u).ok());
    let infos = cf::get_dict_array(dict, "SessionInfo").unwrap_or_default();
    let sessions = infos
        .iter()
        .filter_map(|info| {
            let d = cf::as_plist_dict(info);
            Some(ConsoleSession {
                user: cf::get_string(d, "kCGSSessionUserNameKey")?,
                uid: u32::try_from(cf::get_i64(d, "kCGSSessionUserIDKey")?).ok()?,
                on_console: cf::get_bool(d, "kCGSSessionOnConsoleKey").unwrap_or(false),
                // Older releases omit the key once login has finished.
                login_done: cf::get_bool(d, "kCGSessionLoginDoneKey").unwrap_or(true),
            })
        })
        .collect();
    Some(ConsoleStore {
        console_uid,
        sessions,
    })
}

/// Fallback: only the user currently on the console.
fn read_console_user() -> Option<ConsoleSession> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: NULL store requests a temporary session (documented); uid/gid
    // are valid out-pointers. The returned string follows the Copy rule and
    // is released by CFRetained.
    let user = unsafe { SCDynamicStore::console_user(None, &mut uid, &mut gid) }?;
    Some(ConsoleSession {
        user: user.to_string(),
        uid,
        on_console: true,
        login_done: true,
    })
}

/// Whether the current process runs from an `.app` bundle that carries both
/// launchd plists where `SMAppService` expects them.
fn bundle_with_plists() -> Option<PathBuf> {
    let bundle = NSBundle::mainBundle().bundlePath().to_string();
    let path = PathBuf::from(bundle);
    if path.extension().and_then(|e| e.to_str()) != Some("app") {
        return None;
    }
    let lib = path.join("Contents/Library");
    let daemon = lib.join(format!("LaunchDaemons/{DAEMON_LABEL}.plist"));
    let agent = lib.join(format!("LaunchAgents/{AGENT_LABEL}.plist"));
    (daemon.is_file() && agent.is_file()).then_some(path)
}

fn register(service: &SMAppService, what: &str) -> PlatformResult<()> {
    // SAFETY: plain method calls on a valid SMAppService.
    let result = unsafe { service.registerAndReturnError() };
    // SAFETY: as above.
    let status = unsafe { service.status() };
    if status == SMAppServiceStatus::RequiresApproval {
        return Err(PlatformError::PermissionDenied(format!(
            "{what} needs approval in System Settings > General > Login Items"
        )));
    }
    result.map_err(|e| {
        PlatformError::Os(format!(
            "SMAppService register {what}: {} ({} {})",
            e.localizedDescription(),
            e.domain(),
            e.code()
        ))
    })
}

/// [`ServiceHost`] for macOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacServiceHost;

impl MacServiceHost {
    pub fn new() -> Self {
        MacServiceHost
    }
}

impl ServiceHost for MacServiceHost {
    /// Runs inside an autorelease pool (Foundation/ServiceManagement return
    /// autoreleased objects and the service's threads have no pool).
    fn install(&self) -> PlatformResult<()> {
        autoreleasepool(|_| install_now())
    }

    fn list_sessions(&self) -> PlatformResult<Vec<SessionInfo>> {
        autoreleasepool(|_| {
            let store = read_console_store();
            let records = match &store {
                Some(s) if !s.sessions.is_empty() => s.sessions.clone(),
                _ => read_console_user().into_iter().collect(),
            };
            // Without a top-level UID, fall back to the per-session flags
            // (the `read_console_user` record is marked on-console).
            let console_uid = store.as_ref().and_then(|s| s.console_uid);
            Ok(sessions_from_records(&records, console_uid))
        })
    }

    fn spawn_agent_in_session(&self, _session: &SessionId) -> PlatformResult<AgentPid> {
        Err(PlatformError::Unavailable(
            "on macOS launchd starts org.faro.agent in every Aqua session (LaunchAgent with \
             LimitLoadToSessionType=Aqua and KeepAlive); the service does not spawn it"
                .into(),
        ))
    }
}

/// See [`MacServiceHost::install`]. Must run inside an autorelease pool.
fn install_now() -> PlatformResult<()> {
    if bundle_with_plists().is_none() {
        return Err(PlatformError::Unavailable(
            "SMAppService registration requires running from the signed Faro.app bundle \
                 with embedded launchd plists; use the Faro .pkg installer instead"
                .into(),
        ));
    }
    let daemon_name = NSString::from_str(&format!("{DAEMON_LABEL}.plist"));
    let agent_name = NSString::from_str(&format!("{AGENT_LABEL}.plist"));
    // SAFETY: class constructors taking a plist file name; they do not
    // touch the file system until `register`.
    let (daemon, agent) = unsafe {
        (
            SMAppService::daemonServiceWithPlistName(&daemon_name),
            SMAppService::agentServiceWithPlistName(&agent_name),
        )
    };
    register(&daemon, DAEMON_LABEL)?;
    register(&agent, AGENT_LABEL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(xml: &str) -> Dictionary {
        Value::from_reader_xml(xml.as_bytes())
            .expect("valid plist XML")
            .into_dictionary()
            .expect("top-level dict")
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_string().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn daemon_plist_round_trips() {
        let xml = daemon_plist(ProgramLocation::Absolute(
            "/Applications/Faro.app/Contents/MacOS/faro-service".into(),
        ))
        .unwrap();
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<!DOCTYPE plist"));
        let d = parse(&xml);
        assert_eq!(d["Label"].as_string(), Some(DAEMON_LABEL));
        assert_eq!(
            d["Program"].as_string(),
            Some("/Applications/Faro.app/Contents/MacOS/faro-service")
        );
        assert_eq!(
            strings(&d["ProgramArguments"]),
            vec!["/Applications/Faro.app/Contents/MacOS/faro-service", "run"]
        );
        assert_eq!(d["KeepAlive"].as_boolean(), Some(true));
        assert_eq!(d["RunAtLoad"].as_boolean(), Some(true));
        assert_eq!(d["ThrottleInterval"].as_unsigned_integer(), Some(10));
        assert!(
            d.get("LimitLoadToSessionType").is_none(),
            "daemon is not Aqua-limited"
        );
        assert!(d.get("BundleProgram").is_none());
        assert!(d.get("UserName").is_none(), "daemon runs as root");
    }

    #[test]
    fn agent_plist_is_aqua_limited_and_interactive() {
        let xml = agent_plist(ProgramLocation::BundleRelative(
            "Contents/MacOS/faro-agent".into(),
        ))
        .unwrap();
        let d = parse(&xml);
        assert_eq!(d["Label"].as_string(), Some(AGENT_LABEL));
        assert_eq!(d["LimitLoadToSessionType"].as_string(), Some("Aqua"));
        assert_eq!(d["ProcessType"].as_string(), Some("Interactive"));
        assert_eq!(
            d["BundleProgram"].as_string(),
            Some("Contents/MacOS/faro-agent")
        );
        assert!(d.get("Program").is_none());
        assert_eq!(d["KeepAlive"].as_boolean(), Some(true));
        assert_eq!(d["RunAtLoad"].as_boolean(), Some(true));
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let mut job = LaunchdJob::agent(ProgramLocation::Absolute("/opt/faro <&>/agent".into()));
        job.args = vec![
            "--note=</string><key>UserName</key><string>root".into(),
            "&amp;".into(),
        ];
        let xml = job.to_plist_xml().unwrap();
        let d = parse(&xml);
        assert!(d.get("UserName").is_none(), "argument must not inject keys");
        assert_eq!(
            strings(&d["ProgramArguments"]),
            vec![
                "/opt/faro <&>/agent",
                "--note=</string><key>UserName</key><string>root",
                "&amp;"
            ]
        );
    }

    #[test]
    fn associated_bundle_ids_and_throttle() {
        let mut job = LaunchdJob::daemon(ProgramLocation::Absolute(
            "/usr/local/bin/faro-service".into(),
        ));
        job.associated_bundle_ids = vec!["org.faro.app".into()];
        job.throttle_interval = 30;
        job.keep_alive = false;
        job.stdout_path = Some("/tmp/out.log".into());
        let d = parse(&job.to_plist_xml().unwrap());
        assert_eq!(d["StandardOutPath"].as_string(), Some("/tmp/out.log"));
        assert!(d.get("StandardErrorPath").is_none());
        assert!(d.get("StartInterval").is_none());
        job.stderr_path = Some("relative.log".into());
        assert!(matches!(
            job.to_plist_xml(),
            Err(PlistError::InvalidAbsolutePath(_))
        ));
        assert_eq!(
            strings(&d["AssociatedBundleIdentifiers"]),
            vec!["org.faro.app"]
        );
        assert_eq!(d["ThrottleInterval"].as_unsigned_integer(), Some(30));
        assert_eq!(d["KeepAlive"].as_boolean(), Some(false));
    }

    #[test]
    fn rejects_bad_program_paths() {
        for p in ["relative/faro", "/opt/../etc/faro", ""] {
            assert!(
                matches!(
                    daemon_plist(ProgramLocation::Absolute(p.into())),
                    Err(PlistError::InvalidAbsolutePath(_))
                ),
                "{p:?}"
            );
        }
        for p in [
            "",
            "/Contents/MacOS/x",
            "../x",
            "Contents/../../x",
            "./x",
            "a\0b",
        ] {
            assert!(
                matches!(
                    agent_plist(ProgramLocation::BundleRelative(p.into())),
                    Err(PlistError::InvalidBundlePath(_))
                ),
                "{p:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_labels_and_args() {
        for label in [
            "",
            "org..faro",
            ".org",
            "org.faro.",
            "org/faro",
            "org faro",
            "örg.faro",
        ] {
            let mut job = LaunchdJob::daemon(ProgramLocation::Absolute("/x".into()));
            job.label = label.into();
            assert!(
                matches!(job.to_plist_xml(), Err(PlistError::InvalidLabel(_))),
                "{label:?}"
            );
        }
        let mut job = LaunchdJob::daemon(ProgramLocation::Absolute("/x".into()));
        job.args.push("a\0b".into());
        assert_eq!(job.to_plist_xml(), Err(PlistError::InvalidArgument));
    }

    #[test]
    fn output_is_deterministic() {
        let a = daemon_plist(ProgramLocation::Absolute("/x".into())).unwrap();
        let b = daemon_plist(ProgramLocation::Absolute("/x".into())).unwrap();
        assert_eq!(a, b);
    }

    fn rec(user: &str, uid: u32, on_console: bool, login_done: bool) -> ConsoleSession {
        ConsoleSession {
            user: user.into(),
            uid,
            on_console,
            login_done,
        }
    }

    #[test]
    fn session_records_filtering() {
        let records = vec![
            rec("alice", 501, false, true),
            rec("_mbsetupuser", 248, true, true),
            rec("bob", 502, true, true),
            rec("carol", 503, false, false), // still logging in
            rec("loginwindow", 0, true, true),
            rec("", 504, true, true),
        ];
        let s = sessions_from_records(&records, None);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].id, SessionId("uid:501".into()));
        assert_eq!(s[0].user, "alice");
        assert!(!s[0].active && s[0].graphical);
        assert_eq!(s[1].id, SessionId("uid:502".into()));
        assert!(s[1].active);
    }

    #[test]
    fn duplicate_uid_sessions_merge() {
        let s = sessions_from_records(
            &[
                rec("alice", 501, false, true),
                rec("alice", 501, true, true),
            ],
            None,
        );
        assert_eq!(s.len(), 1);
        assert!(s[0].active);
    }

    /// Regression: on current macOS `kCGSSessionOnConsoleKey` was `FALSE`
    /// for the logged-in user (and `TRUE` for `_mbsetupuser`), so the only
    /// real session was reported inactive. The top-level console `UID` is
    /// authoritative when present.
    #[test]
    fn console_uid_is_authoritative_for_activity() {
        let records = [
            rec("isaiah", 501, false, true),
            rec("_mbsetupuser", 248, true, true),
            rec("bob", 502, true, true),
        ];
        let s = sessions_from_records(&records, Some(501));
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].user.as_str(), s[0].active), ("isaiah", true));
        assert_eq!((s[1].user.as_str(), s[1].active), ("bob", false));
        // Console owned by a filtered system account: nobody is active.
        let s = sessions_from_records(&records, Some(248));
        assert!(s.iter().all(|s| !s.active));
        // Unknown console user: per-session flags decide.
        let s = sessions_from_records(&records, None);
        assert_eq!((s[0].active, s[1].active), (false, true));
    }

    #[test]
    fn spawn_is_unavailable_and_install_refuses_outside_bundle() {
        let host = MacServiceHost::new();
        assert!(matches!(
            host.spawn_agent_in_session(&SessionId("uid:501".into())),
            Err(PlatformError::Unavailable(_))
        ));
        // The test binary is not inside an .app bundle.
        assert!(matches!(host.install(), Err(PlatformError::Unavailable(_))));
    }

    #[test]
    fn list_sessions_smoke() {
        let sessions = MacServiceHost::new().list_sessions().expect("never errors");
        for s in &sessions {
            assert!(s.id.0.starts_with("uid:"));
            assert!(!s.user.is_empty());
        }
        // Whoever runs the tests from a GUI login is the console user, so
        // their session must be the active one.
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        if let Some(mine) = sessions.iter().find(|s| s.id.0 == format!("uid:{me}")) {
            if read_console_user().is_some_and(|c| c.uid == me) {
                assert!(mine.active, "{sessions:?}");
            }
        }
    }
}
