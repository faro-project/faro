//! Installing a verified client package.
//!
//! [`Installer`] is the seam between the platform-independent updater and
//! the OS. The updater calls it only with a file whose length and BLAKE3
//! matched the project-signed targets. Tests inject their own.
//!
//! Before it installs anything, the updater asks the installer to check
//! the package itself ([`Installer::check_package`]). On macOS that is the
//! package's Developer ID signature and notarization
//! ([`super::signature`]), then the version inside it
//! ([`super::package_version`]): a second layer, in case the update keys
//! leak.
//!
//! On macOS ([`LaunchdInstaller`]) the install runs as the one-shot launchd
//! job `org.faro.update` (`faro_platform_macos::update_job`), because the
//! package's preinstall stops this service and would kill an `installer`
//! running as its child. On Windows ([`MsiInstaller`]) the service starts
//! `msiexec` as a detached process outside its own job: the MSI stops this
//! service, replaces it and starts the new one, and a failed install rolls
//! back to the old service, which Windows Installer starts again. Linux
//! doesn't self-update: its packages will come from the project's apt/dnf
//! repository (§3.3).

use super::signature::PackageCheckError;
use faro_update::{TargetInfo, Version};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("cannot prepare the install: {0}")]
    Prepare(String),
    #[error("could not start the install: {0}")]
    Start(String),
}

/// Starts installing a verified package.
pub trait Installer: Send + Sync + std::fmt::Debug {
    /// Check `package` itself before it is installed, beyond the metadata
    /// (on macOS: Faro's Developer ID signature and notarization, and that
    /// the version inside it is `target`'s and above `installed`). There is
    /// no default: every installer says what it checks. Called on a
    /// blocking thread; it must not change anything on disk.
    fn check_package(
        &self,
        package: &Path,
        target: &TargetInfo,
        installed: &Version,
    ) -> Result<(), PackageCheckError>;

    /// Start installing `package` (already verified against `target`).
    /// Returns once the install has *started*: on success the installer
    /// typically stops this service, replaces it and starts the new one.
    fn install(&self, package: &Path, target: &TargetInfo) -> Result<(), InstallError>;

    /// Clean up after a finished install job, if any (at service start).
    fn cleanup(&self) {}
}

/// The installer for this platform, or `None` where the service doesn't
/// update itself. On macOS only the packaged service
/// (`/Library/Faro/bin/faro-service`, run as root) installs updates: a
/// development build run from anywhere else must never install a package
/// over the real one.
pub fn platform_installer(state_dir: &Path) -> Option<std::sync::Arc<dyn Installer>> {
    #[cfg(target_os = "macos")]
    {
        let packaged = std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok())
            .is_some_and(|p| p == Path::new(faro_platform_macos::pkg_layout::SERVICE_PROGRAM));
        // SAFETY: geteuid has no preconditions and cannot fail.
        let root = unsafe { libc::geteuid() } == 0;
        if packaged && root {
            if super::signature::BUILD_POLICY == super::signature::PackagePolicy::RefuseAll {
                tracing::warn!(
                    "this build has no Team ID (FARO_TEAM_ID): it will refuse every update package"
                );
            }
            return Some(std::sync::Arc::new(LaunchdInstaller::new(state_dir)));
        }
        None
    }
    #[cfg(windows)]
    {
        use faro_platform_windows::layout::SERVICE_PROGRAM;
        // Both sides canonical: canonicalize gives a `\\?\` path.
        let packaged = match (
            std::env::current_exe().and_then(|p| p.canonicalize()),
            Path::new(SERVICE_PROGRAM).canonicalize(),
        ) {
            (Ok(running), Ok(packaged)) => running == packaged,
            _ => false,
        };
        if packaged && faro_platform_windows::acl::running_as_system() {
            if super::msi::BUILD_POLICY == super::msi::SignerPolicy::RefuseAll {
                tracing::warn!(
                    "this build has no signer requirement (FARO_WINDOWS_SIGNER): it will refuse every update package"
                );
            }
            return Some(std::sync::Arc::new(MsiInstaller::new(state_dir)));
        }
        None
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = state_dir;
        None
    }
}

/// Windows: install the MSI with `msiexec`, started as a process of its
/// own.
///
/// **Why a detached process, not a scheduled task.** The MSI's
/// `StopServices` stops this service, so the install must not depend on
/// it. Windows doesn't end a process's children when the process exits,
/// and the SCM doesn't put a service in a job, so `msiexec` started by the
/// service outlives it. It is started detached, in a new process group,
/// and with `CREATE_BREAKAWAY_FROM_JOB` in case the service ever runs in a
/// job (one that doesn't allow breaking away makes that fail, and then it
/// is started without). The install itself runs in the Windows Installer
/// service; `msiexec` only drives it. If the install fails, Windows
/// Installer rolls it back, which puts the old service back and starts it
/// again (the rollback of `StopServices`), so nothing like macOS's
/// recovery job is needed. A one-shot scheduled task would add a task to
/// create, run as SYSTEM and clean up (Task Scheduler COM or `schtasks`
/// with an XML definition) for no gain.
#[cfg(windows)]
#[derive(Debug)]
pub struct MsiInstaller {
    log: std::path::PathBuf,
}

#[cfg(windows)]
impl MsiInstaller {
    pub fn new(state_dir: &Path) -> Self {
        MsiInstaller {
            log: state_dir.join(super::INSTALL_LOG),
        }
    }

    /// `%SystemRoot%\System32\msiexec.exe`.
    fn msiexec() -> std::path::PathBuf {
        std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join("msiexec.exe")
    }
}

/// `msiexec`'s arguments: install `package` with no UI, never restart the
/// computer, and log everything to `log`.
#[cfg(any(windows, test))]
fn msiexec_args(package: &Path, log: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "/i".into(),
        package.as_os_str().to_owned(),
        "/qn".into(),
        "/norestart".into(),
        "/l*v".into(),
        log.as_os_str().to_owned(),
        "REBOOT=ReallySuppress".into(),
    ]
}

#[cfg(windows)]
impl Installer for MsiInstaller {
    fn check_package(
        &self,
        package: &Path,
        target: &TargetInfo,
        installed: &Version,
    ) -> Result<(), PackageCheckError> {
        use super::msi::{self, SignerAccepted};
        match msi::check_signature(package)? {
            SignerAccepted::Verified(signer) => tracing::info!(
                version = %target.custom.version,
                signer = %signer.subject,
                thumbprint = %signer.thumbprint_sha256,
                "the update package is signed by Faro's publisher"
            ),
            SignerAccepted::Unchecked => tracing::warn!(
                version = %target.custom.version,
                "development build: installing the update package without checking its signature"
            ),
        }
        // Only once it is known to be Faro's: the package says which
        // product and version it is, and that must be what the metadata
        // says.
        let version = msi::check_version(package, &target.custom.version, installed)?;
        tracing::info!(%version, %installed, "the update package is the version the metadata says");
        Ok(())
    }

    fn install(&self, package: &Path, target: &TargetInfo) -> Result<(), InstallError> {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        const ERROR_ACCESS_DENIED: i32 = 5;

        let spawn = |flags: u32| {
            std::process::Command::new(Self::msiexec())
                .args(msiexec_args(package, &self.log))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .creation_flags(flags)
                .spawn()
        };
        tracing::info!(
            version = %target.custom.version,
            log = %self.log.display(),
            "starting the update install (msiexec)"
        );
        let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        let child = match spawn(base | CREATE_BREAKAWAY_FROM_JOB) {
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => spawn(base),
            r => r,
        }
        .map_err(|e| InstallError::Start(format!("msiexec: {e}")))?;
        // Not waited for: it outlives this service. Dropping the handle
        // leaves the process running.
        tracing::debug!(pid = child.id(), "msiexec started");
        drop(child);
        Ok(())
    }
}

/// macOS: install through the `org.faro.update` launchd job.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct LaunchdInstaller {
    plist: std::path::PathBuf,
    log: std::path::PathBuf,
}

#[cfg(target_os = "macos")]
impl LaunchdInstaller {
    pub fn new(state_dir: &Path) -> Self {
        LaunchdInstaller {
            plist: state_dir.join("update-job.plist"),
            log: state_dir.join(super::INSTALL_LOG),
        }
    }

    fn launchctl(args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new("/bin/launchctl")
            .args(args)
            .output()
            .map_err(|e| format!("launchctl: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "launchctl {} failed ({}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    /// Whether `org.faro.update` is loaded and still running. The new
    /// service is started by the package's postinstall while `installer`,
    /// inside the job, is still finishing: booting the job out then would
    /// kill the install.
    fn job_running() -> bool {
        use faro_platform_macos::update_job::UPDATE_LABEL;
        std::process::Command::new("/bin/launchctl")
            .args(["print", &format!("system/{UPDATE_LABEL}")])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .is_some_and(|o| job_is_running(&String::from_utf8_lossy(&o.stdout)))
    }

    fn remove_job(&self) {
        use faro_platform_macos::update_job::UPDATE_LABEL;
        let _ = Self::launchctl(&["bootout", &format!("system/{UPDATE_LABEL}")]);
    }
}

#[cfg(target_os = "macos")]
impl Installer for LaunchdInstaller {
    fn check_package(
        &self,
        package: &Path,
        target: &TargetInfo,
        installed: &Version,
    ) -> Result<(), PackageCheckError> {
        use super::signature::{self, Accepted};
        match signature::check_package(package)? {
            Accepted::Verified { team_id } => tracing::info!(
                version = %target.custom.version,
                team_id,
                "the update package is signed by Faro's Developer ID and notarized"
            ),
            Accepted::Unchecked => tracing::warn!(
                version = %target.custom.version,
                "development build: installing the update package without checking its signature"
            ),
        }
        // Only once it is known to be Faro's: the package says which
        // version it is, and that must be what the metadata says.
        let version =
            super::package_version::check_version(package, &target.custom.version, installed)?;
        tracing::info!(%version, %installed, "the update package is the version the metadata says");
        Ok(())
    }

    fn install(&self, package: &Path, target: &TargetInfo) -> Result<(), InstallError> {
        use std::io::Write;
        if Self::job_running() {
            return Err(InstallError::Start(
                "an update install is already running".into(),
            ));
        }
        let xml = faro_platform_macos::update_job::update_job_plist(package, &self.log)
            .map_err(|e| InstallError::Prepare(e.to_string()))?;
        // An earlier job, finished or not, would make bootstrap fail.
        self.remove_job();
        let write = || -> std::io::Result<()> {
            let tmp = self.plist.with_extension("plist.tmp");
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(xml.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &self.plist)
        };
        write().map_err(|e| InstallError::Prepare(format!("{}: {e}", self.plist.display())))?;
        tracing::info!(
            version = %target.custom.version,
            log = %self.log.display(),
            "starting the update install job"
        );
        let plist = self.plist.to_string_lossy().into_owned();
        Self::launchctl(&["bootstrap", "system", &plist]).map_err(InstallError::Start)
    }

    fn cleanup(&self) {
        if self.plist.exists() && !Self::job_running() {
            self.remove_job();
            let _ = std::fs::remove_file(&self.plist);
        }
    }
}

/// Parse `launchctl print`: a job whose process is alive reports
/// `state = running`.
#[cfg(any(target_os = "macos", test))]
fn job_is_running(print: &str) -> bool {
    print
        .lines()
        .any(|l| l.trim().strip_prefix("state = ") == Some("running"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msiexec_installs_quietly_and_logs() {
        let args = msiexec_args(
            Path::new(r"C:\ProgramData\Faro\updates\ab.msi"),
            Path::new(r"C:\ProgramData\Faro\update-install.log"),
        );
        let args: Vec<_> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "/i",
                r"C:\ProgramData\Faro\updates\ab.msi",
                "/qn",
                "/norestart",
                "/l*v",
                r"C:\ProgramData\Faro\update-install.log",
                "REBOOT=ReallySuppress",
            ]
        );
    }

    #[test]
    fn launchctl_print_state() {
        let running =
            "system/org.faro.update = {\n\tactive count = 1\n\tstate = running\n\tpid = 812\n}";
        let done = "system/org.faro.update = {\n\tactive count = 0\n\tstate = not running\n\tlast exit code = 0\n}";
        assert!(job_is_running(running));
        assert!(!job_is_running(done));
        assert!(!job_is_running(""));
    }
}
