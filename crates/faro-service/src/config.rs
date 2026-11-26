//! Service configuration (`service.toml`).
//!
//! The file is owned by root (or SYSTEM) and lives next to, but not inside,
//! the state directory. Everything in it has a platform default, so a fresh
//! install runs with no file at all; enrollment writes its results to the
//! state directory, never back into this file.
//!
//! **What is deliberately not configurable here.** Anything that would let
//! whoever can edit this file quietly weaken monitoring without allies being
//! told: the detector thresholds, the idle threshold that pauses capture, and
//! the urgency floors. (The one exception is `[dev_thresholds]`, which only a
//! service built with the `dev` feature acts on, and which can only lower
//! thresholds: [`crate::thresholds`]. A release build ignores it.) The tamper-detection knobs in `[capture]` exist but
//! can only be made stricter than their defaults. Member-facing settings (capture interval, urgency
//! mapping, report sharing) *are* read from `[member_settings]`, but every
//! change to them is announced to allies as a `settings_change` event when
//! the service starts ([`crate::runtime`]).
//!
//! **Without `[member_settings]`** the device keeps the settings it last
//! announced (`settings.json` in the state directory), and only a device that
//! has never announced any starts from [`MemberSettings::default`]. So a new
//! default (such as `medium` flags becoming `urgent`) reaches new devices but
//! never silently changes an existing one
//! ([`crate::state::settings_in_effect`]). Removing the section therefore
//! keeps the current settings; to go back to the defaults, write them out.

use crate::thresholds::{DevThresholds, BUILD_ALLOWS_DEV_THRESHOLDS};
use faro_core::MemberSettings;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Errors loading or validating the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("config file {path} is not valid: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("config file {path} is unsafe: {reason}")]
    UnsafeFile { path: PathBuf, reason: String },
    #[error("invalid config value `{field}`: {reason}")]
    Invalid { field: &'static str, reason: String },
}

/// Largest config file accepted. A real one is well under 4 KiB.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The whole configuration file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where keys, the enrollment record and the outbox live (created 0700).
    pub state_dir: PathBuf,
    /// Default instance for `faro-service enroll` when `--instance` is not
    /// given. After enrollment the pinned enrollment record is authoritative.
    pub instance_url: Option<String>,
    pub capture: CaptureConfig,
    pub ipc: IpcConfig,
    pub network: NetworkConfig,
    pub report: ReportConfig,
    pub updates: UpdatesConfig,
    /// The member's settings, if set here. Changes are announced to allies.
    /// `None` keeps the settings last announced, or the defaults on a device
    /// that has announced none ([`crate::state::settings_in_effect`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_settings: Option<MemberSettings>,
    /// Development builds only: lower detection thresholds, for testing
    /// the flag path ([`crate::thresholds`]). A release build ignores it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_thresholds: Option<DevThresholds>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            state_dir: default_state_dir(),
            instance_url: None,
            capture: CaptureConfig::default(),
            ipc: IpcConfig::default(),
            network: NetworkConfig::default(),
            report: ReportConfig::default(),
            updates: UpdatesConfig::default(),
            member_settings: None,
            dev_thresholds: None,
        }
    }
}

/// Capture driver settings.
///
/// These knobs decide how fast tamper is noticed, so they may only be made
/// *stricter* than the defaults: whoever edits `service.toml` (often the
/// member, who has admin rights on their own machine) must not be able to
/// quietly raise thresholds until `agent_killed_repeatedly` or
/// `capture_failing` never fires, without allies being told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    /// How often the service pings the agent to detect a hung process.
    /// 5..=30 (default 30).
    pub agent_ping_secs: u64,
    /// Disconnects within [`CaptureConfig::agent_kill_window_secs`] that
    /// count as the agent being "killed repeatedly" (§3.7). 2..=3
    /// (default 3).
    pub agent_kill_threshold: u32,
    /// 600..=86400 (default 600): a longer window catches slower kill loops.
    pub agent_kill_window_secs: u64,
    /// Consecutive failed captures before a `capture_failing` tamper event.
    /// 1..=5 (default 5).
    pub capture_failure_threshold: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            agent_ping_secs: DEFAULT_AGENT_PING_SECS,
            agent_kill_threshold: DEFAULT_AGENT_KILL_THRESHOLD,
            agent_kill_window_secs: DEFAULT_AGENT_KILL_WINDOW_SECS,
            capture_failure_threshold: DEFAULT_CAPTURE_FAILURE_THRESHOLD,
        }
    }
}

const DEFAULT_AGENT_PING_SECS: u64 = 30;
const DEFAULT_AGENT_KILL_THRESHOLD: u32 = 3;
const DEFAULT_AGENT_KILL_WINDOW_SECS: u64 = 600;
const DEFAULT_CAPTURE_FAILURE_THRESHOLD: u32 = 5;

/// Local IPC with the session agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpcConfig {
    /// Socket path. Its directory must be root-owned and not writable by
    /// others (`faro-ipc` checks this). Must agree with the agent's. A root
    /// service binds one socket per account next to it
    /// (`agent.<uid>.sock`, see `faro_ipc::session_socket_path`), since
    /// every account's agent connects; a non-root development service
    /// binds this path itself.
    pub socket_path: PathBuf,
    /// Extra uids allowed to connect besides each session's own user (they
    /// may claim any listed session). Empty in normal installs.
    pub allowed_uids: Vec<u32>,
    /// The code-signing *designated requirement* the agent binary must
    /// satisfy (macOS), e.g. `anchor apple generic and identifier
    /// "org.faro.agent" and certificate leaf[subject.OU] = "TEAMID"`.
    /// Required for a root service: without it any program the user runs
    /// could pose as the agent (§3.1). Only `dev` builds accept agents by
    /// uid alone.
    pub agent_requirement: Option<String>,
}

impl Default for IpcConfig {
    fn default() -> Self {
        IpcConfig {
            socket_path: default_socket_path(),
            allowed_uids: Vec::new(),
            agent_requirement: None,
        }
    }
}

/// Talking to the instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Heartbeat interval (§4.2: every 5 minutes). 60..=900.
    pub heartbeat_secs: u64,
    /// How often queued events are uploaded when nothing urgent happens.
    pub upload_interval_secs: u64,
    /// How often the recipient manifest and the instance identity are
    /// re-checked.
    pub manifest_refresh_secs: u64,
    /// While waiting for the member to endorse a fresh enrollment.
    pub endorsement_poll_secs: u64,
    /// Per-request timeout.
    pub request_timeout_secs: u64,
    /// Extra PEM CA certificate(s) to trust for the instance, for
    /// self-hosted instances with a private CA.
    pub ca_file: Option<PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            heartbeat_secs: 300,
            upload_interval_secs: 30,
            manifest_refresh_secs: 900,
            endorsement_poll_secs: 10,
            request_timeout_secs: 30,
            ca_file: None,
        }
    }
}

impl NetworkConfig {
    pub fn heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.heartbeat_secs)
    }
    pub fn upload_interval(&self) -> Duration {
        Duration::from_secs(self.upload_interval_secs)
    }
    pub fn manifest_refresh_interval(&self) -> Duration {
        Duration::from_secs(self.manifest_refresh_secs)
    }
    pub fn endorsement_poll_interval(&self) -> Duration {
        Duration::from_secs(self.endorsement_poll_secs)
    }
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }
}

/// Daily report periods.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportConfig {
    /// Report days start at local midnight for this UTC offset. Following
    /// the OS time zone (with DST) is a follow-up; a fixed offset keeps
    /// period boundaries independent of a member-controlled TZ setting.
    pub utc_offset_minutes: i32,
}

/// Client updates (§3.8, [`crate::update`]). There is deliberately no
/// switch to turn them off: an install that stops taking updates would keep
/// whatever bugs (or weaknesses) the project has since fixed. Updates only
/// run when the package ships the project's root of trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdatesConfig {
    /// How often the instance's mirror is checked. 3600..=86400 (default
    /// 21600, every 6 hours), jittered.
    pub check_secs: u64,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        UpdatesConfig {
            check_secs: 6 * 3600,
        }
    }
}

impl UpdatesConfig {
    pub fn check_interval(&self) -> Duration {
        Duration::from_secs(self.check_secs)
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

impl Config {
    /// Load from `path`, or from [`default_config_path`] when `None`.
    ///
    /// An explicitly named file must exist; a missing default file means
    /// "all defaults". On Unix, when running as root, the file must be owned
    /// by root and not writable by group or others: it decides which
    /// instance the device talks to and which settings it reports.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let (path, explicit) = match path {
            Some(p) => (p.to_path_buf(), true),
            None => (default_config_path(), false),
        };
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
                let c = Config::default();
                c.validate()?;
                return Ok(c);
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        check_config_file(&path, &meta)?;
        let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        Self::from_toml_str(&text).map_err(|e| match e {
            ConfigError::Parse { source, .. } => ConfigError::Parse { path, source },
            other => other,
        })
    }

    /// Parse and validate TOML text.
    pub fn from_toml_str(text: &str) -> Result<Config, ConfigError> {
        let c: Config = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: PathBuf::from("<string>"),
            source: Box::new(e),
        })?;
        c.validate()?;
        Ok(c)
    }

    /// Range checks. Out-of-range timing could make the service hammer the
    /// instance or go quiet long enough to look like tamper.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.state_dir.as_os_str().is_empty() {
            return Err(invalid("state_dir", "must not be empty"));
        }
        if !self.state_dir.is_absolute() {
            return Err(invalid("state_dir", "must be an absolute path"));
        }
        if let Some(u) = &self.instance_url {
            crate::link::parse_instance_url(u)
                .map_err(|e| invalid("instance_url", e.to_string()))?;
        }
        let c = &self.capture;
        // Tamper-detection knobs may only be tightened (see CaptureConfig).
        if !(5..=DEFAULT_AGENT_PING_SECS).contains(&c.agent_ping_secs) {
            return Err(invalid("capture.agent_ping_secs", "must be 5..=30"));
        }
        if !(2..=DEFAULT_AGENT_KILL_THRESHOLD).contains(&c.agent_kill_threshold) {
            return Err(invalid("capture.agent_kill_threshold", "must be 2..=3"));
        }
        if !(DEFAULT_AGENT_KILL_WINDOW_SECS..=86_400).contains(&c.agent_kill_window_secs) {
            return Err(invalid(
                "capture.agent_kill_window_secs",
                "must be 600..=86400",
            ));
        }
        if !(1..=DEFAULT_CAPTURE_FAILURE_THRESHOLD).contains(&c.capture_failure_threshold) {
            return Err(invalid(
                "capture.capture_failure_threshold",
                "must be 1..=5",
            ));
        }
        if let Some(r) = &self.ipc.agent_requirement {
            if r.trim().is_empty() || r.len() > 4096 {
                return Err(invalid(
                    "ipc.agent_requirement",
                    "must be a non-empty requirement of at most 4096 bytes",
                ));
            }
        }
        if self.ipc.socket_path.as_os_str().is_empty() || self.ipc.socket_path.file_name().is_none()
        {
            return Err(invalid("ipc.socket_path", "must name a socket file"));
        }
        let n = &self.network;
        if !(60..=900).contains(&n.heartbeat_secs) {
            // The instance's grace period assumes ~5 minute check-ins.
            return Err(invalid("network.heartbeat_secs", "must be 60..=900"));
        }
        if !(1..=3600).contains(&n.upload_interval_secs) {
            return Err(invalid("network.upload_interval_secs", "must be 1..=3600"));
        }
        if !(60..=86_400).contains(&n.manifest_refresh_secs) {
            return Err(invalid(
                "network.manifest_refresh_secs",
                "must be 60..=86400",
            ));
        }
        if !(1..=3600).contains(&n.endorsement_poll_secs) {
            return Err(invalid("network.endorsement_poll_secs", "must be 1..=3600"));
        }
        if !(1..=600).contains(&n.request_timeout_secs) {
            return Err(invalid("network.request_timeout_secs", "must be 1..=600"));
        }
        if !(3600..=86_400).contains(&self.updates.check_secs) {
            return Err(invalid("updates.check_secs", "must be 3600..=86400"));
        }
        if !(-14 * 60..=14 * 60).contains(&self.report.utc_offset_minutes) {
            return Err(invalid(
                "report.utc_offset_minutes",
                "must be within ±14 hours",
            ));
        }
        // A release build ignores the section, so its values can't stop it.
        if let (Some(t), true) = (&self.dev_thresholds, BUILD_ALLOWS_DEV_THRESHOLDS) {
            t.validate().map_err(|e| invalid("dev_thresholds", e))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn check_config_file(path: &Path, meta: &std::fs::Metadata) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let unsafe_file = |reason: String| ConfigError::UnsafeFile {
        path: path.to_path_buf(),
        reason,
    };
    if !meta.is_file() {
        return Err(unsafe_file("not a regular file".into()));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(unsafe_file(format!("larger than {MAX_CONFIG_BYTES} bytes")));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        if meta.uid() != 0 {
            return Err(unsafe_file(format!(
                "owned by uid {}, must be owned by root",
                meta.uid()
            )));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(unsafe_file(format!(
                "mode {:o} is group- or world-writable",
                meta.mode() & 0o7777
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_config_file(path: &Path, meta: &std::fs::Metadata) -> Result<(), ConfigError> {
    // TODO(windows): check the file's DACL (SYSTEM/Administrators only).
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::UnsafeFile {
            path: path.to_path_buf(),
            reason: "not a regular file of reasonable size".into(),
        });
    }
    Ok(())
}

/// Platform default state directory (ARCHITECTURE.md §3.3).
pub fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Faro")
    } else if cfg!(windows) {
        program_data().join("Faro")
    } else {
        PathBuf::from("/var/lib/faro")
    }
}

/// Platform default config file.
pub fn default_config_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Faro/service.toml")
    } else if cfg!(windows) {
        program_data().join("Faro").join("service.toml")
    } else {
        PathBuf::from("/etc/faro/service.toml")
    }
}

/// Platform default agent socket; must match `faro-agent`'s default.
pub fn default_socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/faro/agent.sock")
    } else if cfg!(windows) {
        // Placeholder: the Windows transport is a named pipe (not yet
        // implemented in faro-ipc).
        PathBuf::from(r"\\.\pipe\faro-agent")
    } else {
        PathBuf::from("/run/faro/agent.sock")
    }
}

fn program_data() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate_and_are_platform_specific() {
        let c = Config::default();
        c.validate().unwrap();
        #[cfg(target_os = "macos")]
        assert_eq!(c.state_dir, Path::new("/Library/Application Support/Faro"));
        #[cfg(target_os = "linux")]
        assert_eq!(c.state_dir, Path::new("/var/lib/faro"));
        assert_eq!(c.network.heartbeat_secs, 300);
        assert_eq!(
            c.member_settings, None,
            "the stored settings, or the defaults"
        );
    }

    #[test]
    fn parses_full_file() {
        // `state_dir` must be absolute, and `/tmp/...` is not on Windows.
        // A TOML literal string ('...') keeps the backslashes as written.
        let state = if cfg!(windows) {
            r"C:\faro-state"
        } else {
            "/tmp/faro-state"
        };
        let toml = r#"
            state_dir = '@STATE@'
            instance_url = "https://faro.example.org"
            [capture]
            agent_kill_threshold = 2
            [ipc]
            socket_path = "/tmp/faro-run/agent.sock"
            allowed_uids = [501]
            [network]
            heartbeat_secs = 120
            [report]
            utc_offset_minutes = -300
            [member_settings]
            capture_mean_secs = 90
            urgency = { low = "none", medium = "urgent", high = "urgent" }
            share_top_apps = true
            "#
        .replace("@STATE@", state);
        let c = Config::from_toml_str(&toml).unwrap();
        assert_eq!(c.state_dir, Path::new(state));
        assert_eq!(c.capture.agent_kill_threshold, 2);
        assert_eq!(c.capture.agent_ping_secs, 30, "unset fields keep defaults");
        assert_eq!(c.ipc.allowed_uids, vec![501]);
        assert_eq!(c.network.heartbeat_secs, 120);
        assert_eq!(c.report.utc_offset_minutes, -300);
        let s = c.member_settings.expect("[member_settings] is set");
        assert_eq!(s.capture_mean_secs(), 90);
        assert!(s.share_top_apps());
        assert_eq!(s.urgency().medium(), faro_proto::Urgency::Urgent);
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        assert!(matches!(
            Config::from_toml_str("bogus = 1"),
            Err(ConfigError::Parse { .. })
        ));
        // Detector thresholds are deliberately not configurable.
        assert!(Config::from_toml_str("[capture]\nidle_threshold_secs = 0").is_err());
        // Tamper thresholds can be tightened but not loosened.
        for loosen in [
            "agent_kill_threshold = 100",
            "agent_kill_window_secs = 60",
            "capture_failure_threshold = 1000",
            "agent_ping_secs = 300",
        ] {
            assert!(
                Config::from_toml_str(&format!("[capture]\n{loosen}")).is_err(),
                "{loosen}"
            );
        }
        Config::from_toml_str(
            "[capture]\nagent_kill_threshold = 2\nagent_kill_window_secs = 3600\ncapture_failure_threshold = 2\nagent_ping_secs = 10",
        )
        .unwrap();
        assert!(matches!(
            Config::from_toml_str("state_dir = \"relative/dir\""),
            Err(ConfigError::Invalid {
                field: "state_dir",
                ..
            })
        ));
        assert!(Config::from_toml_str("[updates]\ncheck_secs = 60").is_err());
        assert!(
            Config::from_toml_str("[updates]\nenabled = false").is_err(),
            "no off switch"
        );
        assert_eq!(
            Config::from_toml_str("[updates]\ncheck_secs = 7200")
                .unwrap()
                .updates
                .check_secs,
            7200
        );
        assert!(matches!(
            Config::from_toml_str("[network]\nheartbeat_secs = 5"),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(matches!(
            Config::from_toml_str("instance_url = \"http://faro.example.org\""),
            Err(ConfigError::Invalid {
                field: "instance_url",
                ..
            })
        ));
        // Member settings keep their own floors (urgency can't go below them).
        assert!(Config::from_toml_str(
            "[member_settings]\ncapture_mean_secs = 60\nurgency = { low = \"none\", medium = \"none\", high = \"none\" }"
        )
        .is_err());
        assert!(Config::from_toml_str("[member_settings]\ncapture_mean_secs = 5000\nurgency = { low = \"none\", medium = \"normal\", high = \"urgent\" }").is_err());
    }

    #[test]
    fn missing_default_file_is_defaults_but_explicit_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(matches!(
            Config::load(Some(&missing)),
            Err(ConfigError::Read { .. })
        ));
        let p = dir.path().join("service.toml");
        std::fs::write(&p, "[network]\nupload_interval_secs = 5\n").unwrap();
        let c = Config::load(Some(&p)).unwrap();
        assert_eq!(c.network.upload_interval_secs, 5);
    }
}
