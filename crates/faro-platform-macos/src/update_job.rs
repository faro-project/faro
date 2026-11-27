//! The one-shot launchd job that installs a client update (ARCHITECTURE.md
//! §3.8).
//!
//! **Why a job of its own.** The package's `preinstall` boots out
//! `org.faro.service` so its files can be replaced. An `installer` started
//! as the service's child would die with the service, part way through the
//! install. So the service writes this job's plist into its state directory
//! (root-owned, 0700) and `launchctl bootstrap`s it as `org.faro.update`.
//! launchd runs it independently of the service.
//!
//! **What it runs.** [`UPDATE_SCRIPT`] runs `installer`. Then, whether the
//! install worked or not, it makes sure the service and every logged-in
//! account's agent are loaded again. A successful install's `postinstall`
//! has already done that. A failed one may have stopped them in
//! `preinstall`, and a service left stopped would look to allies like
//! tamper (missed check-ins, agents missing). The service notices the
//! failure on its next start (its own version didn't change) and gives up
//! on that package after a few attempts.
//!
//! The package path is passed as an argument, never spliced into the
//! script, and `PATH` is fixed in the job, so nothing from the package name
//! or the environment can change what runs as root.
//!
//! **What was checked before.** The service writes this job only for a
//! package whose length and BLAKE3 match the project-signed metadata, and
//! whose own signature passed `faro_service::update::signature`: Faro's
//! Developer ID Installer certificate and notarization. The package stays
//! in the service's root-only state directory between that check and the
//! install.

use crate::service::{pkg_layout, PlistError, AGENT_LABEL, DAEMON_LABEL};
use plist::{Dictionary, Value};
use std::path::Path;

/// launchd label of the update job.
pub const UPDATE_LABEL: &str = "org.faro.update";

/// `PATH` for the job: system tools only.
pub const UPDATE_PATH_ENV: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The job's script, run as `/bin/sh -c UPDATE_SCRIPT faro-update <pkg>`.
/// Exits with `installer`'s status.
pub const UPDATE_SCRIPT: &str = r#"pkg="$1"
installer -pkg "$pkg" -target /
status=$?
echo "faro-update: installer exited with $status"
if ! launchctl print "system/@DAEMON@" >/dev/null 2>&1; then
    echo "faro-update: starting the service again"
    launchctl bootstrap system "@DAEMON_PLIST@"
fi
skip=$(id -u _mbsetupuser 2>/dev/null || echo 0)
for uid in $(ps -axo uid=,comm= | awk -v skip="$skip" '$2 ~ /\/loginwindow$/ && $1 != 0 && $1 != skip { print $1 }' | sort -un); do
    if ! launchctl print "gui/$uid/@AGENT@" >/dev/null 2>&1; then
        echo "faro-update: starting the agent for uid $uid again"
        launchctl bootstrap "gui/$uid" "@AGENT_PLIST@"
    fi
done
exit $status
"#;

/// [`UPDATE_SCRIPT`] with the installed layout filled in.
pub fn update_script() -> String {
    UPDATE_SCRIPT
        .replace("@DAEMON@", DAEMON_LABEL)
        .replace("@DAEMON_PLIST@", pkg_layout::DAEMON_PLIST)
        .replace("@AGENT@", AGENT_LABEL)
        .replace("@AGENT_PLIST@", pkg_layout::AGENT_PLIST)
}

/// The plist for [`UPDATE_LABEL`]: run once at load, installing `pkg`, with
/// output appended to `log`. Both paths must be absolute.
pub fn update_job_plist(pkg: &Path, log: &Path) -> Result<String, PlistError> {
    for p in [pkg, log] {
        if !p.is_absolute() || !p.to_str().is_some_and(|s| !s.contains('\0')) {
            return Err(PlistError::InvalidAbsolutePath(p.to_owned()));
        }
    }
    let s = |v: &str| Value::String(v.to_owned());
    let path = |p: &Path| Value::String(p.to_string_lossy().into_owned());
    let mut d = Dictionary::new();
    d.insert("Label".into(), s(UPDATE_LABEL));
    d.insert("Program".into(), s("/bin/sh"));
    d.insert(
        "ProgramArguments".into(),
        Value::Array(vec![
            s("/bin/sh"),
            s("-c"),
            s(&update_script()),
            s("faro-update"),
            path(pkg),
        ]),
    );
    d.insert("RunAtLoad".into(), Value::Boolean(true));
    d.insert("KeepAlive".into(), Value::Boolean(false));
    d.insert("LaunchOnlyOnce".into(), Value::Boolean(true));
    let mut env = Dictionary::new();
    env.insert("PATH".into(), s(UPDATE_PATH_ENV));
    d.insert("EnvironmentVariables".into(), Value::Dictionary(env));
    d.insert("StandardOutPath".into(), path(log));
    d.insert("StandardErrorPath".into(), path(log));
    let mut buf = Vec::new();
    Value::Dictionary(d)
        .to_writer_xml(&mut buf)
        .map_err(|e| PlistError::Serialize(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| PlistError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_runs_the_fixed_script_with_the_package_as_an_argument() {
        let pkg = Path::new("/Library/Application Support/Faro/updates/a b\"$(x).pkg");
        let xml = update_job_plist(pkg, Path::new("/var/log/faro-update.log")).unwrap();
        let v = Value::from_reader_xml(xml.as_bytes()).unwrap();
        let d = v.as_dictionary().unwrap();
        assert_eq!(d["Label"].as_string(), Some(UPDATE_LABEL));
        let argv: Vec<&str> = d["ProgramArguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_string().unwrap())
            .collect();
        assert_eq!(argv[..2], ["/bin/sh", "-c"]);
        assert_eq!(argv[2], update_script());
        assert!(!argv[2].contains("a b"), "the path is never in the script");
        assert_eq!(argv[3..], ["faro-update", pkg.to_str().unwrap()]);
        assert_eq!(d["KeepAlive"].as_boolean(), Some(false));
        assert_eq!(d["LaunchOnlyOnce"].as_boolean(), Some(true));
        let env = d["EnvironmentVariables"].as_dictionary().unwrap();
        assert_eq!(env["PATH"].as_string(), Some(UPDATE_PATH_ENV));
    }

    #[test]
    fn script_uses_the_installed_layout() {
        let s = update_script();
        assert!(!s.contains('@'), "every placeholder is filled: {s}");
        assert!(s.contains("system/org.faro.service"));
        assert!(s.contains(pkg_layout::DAEMON_PLIST));
        assert!(s.contains(pkg_layout::AGENT_PLIST));
    }

    /// Run the real script with stub `installer`, `launchctl` and `ps` on
    /// `PATH`, and return what the stubs were asked to do.
    fn run_script(installer_status: i32, loaded: &[&str]) -> (i32, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let calls = dir.path().join("calls");
        let stub = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(
                &p,
                format!(
                    "#!/bin/sh\necho \"{name} $*\" >> '{}'\n{body}\n",
                    calls.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        stub("installer", &format!("exit {installer_status}"));
        // `launchctl print X` succeeds only for the loaded jobs.
        let loaded = loaded.join(" ");
        stub(
            "launchctl",
            &format!("if [ \"$1\" = print ]; then for j in {loaded}; do [ \"$2\" = \"$j\" ] && exit 0; done; exit 1; fi; exit 0"),
        );
        stub(
            "ps",
            "echo '    0 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow'\n\
             echo '  501 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow'\n\
             echo '  201 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow'\n\
             echo '  502 /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow'\n\
             echo '  501 /usr/bin/other'",
        );
        // awk and sort come from the system.
        let path = format!("{}:/usr/bin:/bin", dir.path().display());
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", &update_script(), "faro-update", "/tmp/Faro 1.2.pkg"])
            .env_clear()
            .env("PATH", path)
            .output()
            .unwrap();
        let calls = std::fs::read_to_string(&calls).unwrap_or_default();
        (out.status.code().unwrap_or(-1), calls)
    }

    #[test]
    fn script_restarts_whatever_is_not_loaded_and_keeps_the_installer_status() {
        // A failed install that left everything stopped.
        let (status, calls) = run_script(1, &[]);
        assert_eq!(status, 1);
        assert!(
            calls.contains("installer -pkg /tmp/Faro 1.2.pkg -target /"),
            "{calls}"
        );
        assert!(calls.contains(&format!(
            "launchctl bootstrap system {}",
            pkg_layout::DAEMON_PLIST
        )));
        for uid in [201, 501, 502] {
            assert!(
                calls.contains(&format!(
                    "launchctl bootstrap gui/{uid} {}",
                    pkg_layout::AGENT_PLIST
                )),
                "{calls}"
            );
        }
        assert!(
            !calls.contains("gui/0"),
            "the login window's root session is skipped"
        );

        // A good install: postinstall already loaded everything.
        let (status, calls) = run_script(
            0,
            &[
                "system/org.faro.service",
                "gui/201/org.faro.agent",
                "gui/501/org.faro.agent",
                "gui/502/org.faro.agent",
            ],
        );
        assert_eq!(status, 0);
        assert!(!calls.contains("bootstrap"), "{calls}");
    }

    #[test]
    fn relative_paths_are_refused() {
        assert!(update_job_plist(Path::new("x.pkg"), Path::new("/l")).is_err());
        assert!(update_job_plist(Path::new("/x.pkg"), Path::new("l")).is_err());
    }
}
