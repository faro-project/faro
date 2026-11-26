//! Where the MSI puts things (installers/windows) and the names the service,
//! the agent, the installer and the docs agree on. The Windows counterpart
//! of `faro_platform_macos::pkg_layout`. Compiled on every OS so tests and
//! release tooling can read the constants.

/// The install directory (`[ProgramFiles64Folder]Faro`).
pub const PROGRAM_DIR: &str = r"C:\Program Files\Faro";
/// The privileged service binary.
pub const SERVICE_PROGRAM: &str = r"C:\Program Files\Faro\faro-service.exe";
/// The session agent binary.
pub const AGENT_PROGRAM: &str = r"C:\Program Files\Faro\faro-agent.exe";
/// The project's update root of trust, shipped in release packages (§3.8).
pub const UPDATE_ROOT: &str = r"C:\Program Files\Faro\update-root.json";
/// The image model's manifest; the model file sits next to it.
pub const MODEL_MANIFEST: &str = r"C:\Program Files\Faro\models\opennsfw\manifest.json";
/// The domain category list's manifest; `domains.bin` sits next to it.
pub const DOMAINS_MANIFEST: &str = r"C:\Program Files\Faro\domains\domains.manifest.json";
/// Licences and attribution for third-party parts of the package.
pub const NOTICES_DIR: &str = r"C:\Program Files\Faro\notices";

/// The service's state directory: SYSTEM and Administrators only
/// (`acl::protect_state_dir`). Holds the config, keys, outbox and journal.
pub const DATA_DIR: &str = r"C:\ProgramData\Faro";
/// The service's log directory, readable by Administrators.
pub const LOG_DIR: &str = r"C:\ProgramData\Faro\logs";
/// The service's log.
pub const SERVICE_LOG: &str = r"C:\ProgramData\Faro\logs\faro-service.log";
/// Each account's agent log, relative to `%LOCALAPPDATA%`.
pub const AGENT_LOG_IN_LOCALAPPDATA: &str = r"Faro\Logs\faro-agent.log";
/// A log is rotated before it grows past this.
pub const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
/// Rotated files kept next to each log.
pub const LOG_KEEP: u32 = 3;

/// The SCM service name.
pub const SERVICE_NAME: &str = "FaroService";
/// The SCM display name.
pub const SERVICE_DISPLAY_NAME: &str = "Faro Service";
/// The service description shown in services.msc.
pub const SERVICE_DESCRIPTION: &str =
    "Faro screen accountability: watches every session and reports to your allies.";

/// The URL scheme the agent handles (enrollment links from the web app).
pub const URL_SCHEME: &str = "faro";

/// The service log's rotation policy.
#[cfg(windows)]
pub fn service_log_rotation() -> faro_platform::logfile::Rotation {
    faro_platform::logfile::Rotation {
        max_bytes: LOG_MAX_BYTES,
        keep: LOG_KEEP,
        mode: 0,
    }
}

/// The agent's log under a `%LOCALAPPDATA%`.
pub fn agent_log(local_app_data: &std::path::Path) -> std::path::PathBuf {
    local_app_data.join(AGENT_LOG_IN_LOCALAPPDATA)
}
