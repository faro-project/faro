//! The package's own signature: a second check before a macOS install.
//!
//! The update metadata says which bytes to install (PROTOCOL.md §8.2). If
//! someone holds both online keys (targets and timestamp) and controls a
//! mirror, that is not enough on its own. So before the install job
//! starts, the service also checks the downloaded `.pkg` itself:
//!
//! 1. **Signed by Faro.** `pkgutil --check-signature` must report a
//!    signature that chains to Apple's Developer ID CA ("signed by a
//!    developer certificate issued by Apple for distribution"), from a
//!    `Developer ID Installer` certificate whose team is Faro's.
//! 2. **Notarized.** Gatekeeper (`spctl --assess --type install`) must
//!    accept it as `Notarized Developer ID`, from the same team. Release
//!    packages carry a stapled ticket, so this works offline. Without a
//!    ticket Gatekeeper asks Apple, and offline it can't confirm.
//!
//! **Which team.** The Team ID is compiled into the service from
//! `FARO_TEAM_ID`, the same value `build-pkg.sh` builds
//! `ipc.agent_requirement` from. It never comes from the update, its
//! metadata or the mirror. A malformed value fails the build.
//!
//! **Why the command-line tools.** Security.framework has no public API
//! that checks a flat package's signature: `SecStaticCode` covers bundles,
//! Mach-O files and disk images, not `xar` packages. `installer` uses the
//! private PackageKit framework. Re-implementing the `xar` signature check
//! would mean parsing the archive and the certificates ourselves. The two
//! tools are on every Mac (`/usr/sbin`), run with a fixed environment, and
//! are what Apple documents for this check. Their output is parsed
//! strictly, and anything unexpected refuses the package. Two independent
//! evaluations must agree on the team.
//!
//! **Outcomes.** [`PackageCheckError::Rejected`] is positive evidence that
//! the package isn't Faro's: the service records it, never retries that
//! package, and reports a tamper-class integrity failure (ARCHITECTURE.md
//! §3.7). [`PackageCheckError::Unconfirmed`] means the check couldn't
//! conclude (a tool failed, Gatekeeper couldn't confirm notarization, or
//! this build has no Team ID): nothing is installed, and the next check
//! tries again. Either way nothing on disk changes.
//!
//! **Development builds.** A `--dev` package has no Team ID. A service
//! built with the `dev` feature and no `FARO_TEAM_ID` installs packages
//! without this check (they still match the signed metadata). A build
//! without the `dev` feature and without a Team ID refuses every package.
//! The decision is made at compile time ([`BUILD_POLICY`]), never by
//! configuration.

use std::path::Path;

/// `pkgutil`'s status for a Developer ID signature that chains to Apple.
pub const DEVELOPER_ID_STATUS: &str =
    "signed by a developer certificate issued by Apple for distribution";
/// Gatekeeper's source for a notarized Developer ID package.
pub const NOTARIZED_SOURCE: &str = "Notarized Developer ID";
/// The common name of a Developer ID Installer certificate starts with
/// this; Apple ends it with ` (<TEAMID>)`.
pub const INSTALLER_CN_PREFIX: &str = "Developer ID Installer: ";
/// The intermediate that issues Developer ID certificates.
pub const DEVELOPER_ID_CA: &str = "Developer ID Certification Authority";
/// Apple's root.
pub const APPLE_ROOT_CA: &str = "Apple Root CA";

/// The tools, by absolute path.
pub const PKGUTIL: &str = "/usr/sbin/pkgutil";
pub const SPCTL: &str = "/usr/sbin/spctl";

/// The Team ID this service was built with (`FARO_TEAM_ID`), if any. An
/// empty value counts as none (the release workflow passes an empty one
/// for development packages).
pub const BUILD_TEAM_ID: Option<&str> = non_empty(option_env!("FARO_TEAM_ID"));

const _: () = {
    if let Some(t) = BUILD_TEAM_ID {
        assert!(
            is_team_id(t),
            "FARO_TEAM_ID must be a 10-character Apple team ID (A-Z, 0-9)"
        );
    }
};

/// What this build requires of a package, fixed at compile time.
pub const BUILD_POLICY: PackagePolicy = policy_for(BUILD_TEAM_ID, cfg!(feature = "dev"));

/// What a package must be to be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackagePolicy {
    /// Signed with a Developer ID Installer certificate of this team, and
    /// notarized.
    Require { team_id: &'static str },
    /// No Team ID and not a development build: nothing can be installed.
    RefuseAll,
    /// A development build without a Team ID: no signature check. Only a
    /// build with the `dev` feature acts on it.
    Unchecked,
}

/// The policy for a build. A Team ID always wins, also in a development
/// build. Without one, only the `dev` feature skips the check.
pub const fn policy_for(team_id: Option<&'static str>, dev: bool) -> PackagePolicy {
    match team_id {
        Some(team_id) => PackagePolicy::Require { team_id },
        None if dev => PackagePolicy::Unchecked,
        None => PackagePolicy::RefuseAll,
    }
}

const fn non_empty(v: Option<&'static str>) -> Option<&'static str> {
    match v {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// An Apple Team ID: 10 characters, `A-Z` and `0-9`.
pub const fn is_team_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if !(b[i].is_ascii_uppercase() || b[i].is_ascii_digit()) {
            return false;
        }
        i += 1;
    }
    true
}

/// Why a package was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackageCheckError {
    /// The package is not Faro's, or not the version the metadata says
    /// ([`super::package_version`]): never install it, report tamper.
    #[error("the update package is refused: {0}")]
    Rejected(String),
    /// The check couldn't conclude: don't install, try again later.
    #[error("cannot confirm the update package: {0}")]
    Unconfirmed(String),
}

/// A package that passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// Signed by this team and notarized.
    Verified { team_id: &'static str },
    /// A development build: not checked.
    Unchecked,
}

/// A tool [`check_with`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// `pkgutil --check-signature <pkg>`.
    Pkgutil,
    /// `spctl --assess --type install --verbose=2 <pkg>`.
    Spctl,
}

/// What a tool printed (stdout, then stderr) and its exit status (`None`
/// if it was killed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub status: Option<i32>,
    pub text: String,
}

/// Check `pkg` with this build's policy and the real tools.
pub fn check_package(pkg: &Path) -> Result<Accepted, PackageCheckError> {
    check_with(BUILD_POLICY, pkg, &mut run_tool)
}

/// Check `pkg` under `policy`, running the tools through `run`. Fails
/// closed: anything other than a clear pass refuses the package.
pub fn check_with(
    policy: PackagePolicy,
    pkg: &Path,
    run: &mut dyn FnMut(Tool, &Path) -> Result<ToolOutput, String>,
) -> Result<Accepted, PackageCheckError> {
    let team = match policy {
        PackagePolicy::Require { team_id } if is_team_id(team_id) => team_id,
        PackagePolicy::Require { team_id } => {
            return Err(PackageCheckError::Unconfirmed(format!(
                "{team_id:?} is not a Team ID"
            )))
        }
        PackagePolicy::RefuseAll => {
            return Err(PackageCheckError::Unconfirmed(
                "this build has no Team ID (FARO_TEAM_ID), so it can't check packages".into(),
            ))
        }
        // Belt and braces: only a `dev` build ever has this policy, and
        // only a `dev` build acts on it.
        PackagePolicy::Unchecked if cfg!(feature = "dev") => return Ok(Accepted::Unchecked),
        PackagePolicy::Unchecked => {
            return Err(PackageCheckError::Unconfirmed(
                "unchecked packages are accepted only by development builds".into(),
            ))
        }
    };
    if !pkg.is_absolute() {
        return Err(PackageCheckError::Unconfirmed(format!(
            "{} is not an absolute path",
            pkg.display()
        )));
    }
    let out = run(Tool::Pkgutil, pkg)
        .map_err(|e| PackageCheckError::Unconfirmed(format!("pkgutil: {e}")))?;
    judge_pkgutil(&out, team)?;
    let out =
        run(Tool::Spctl, pkg).map_err(|e| PackageCheckError::Unconfirmed(format!("spctl: {e}")))?;
    judge_spctl(&out, team)?;
    Ok(Accepted::Verified { team_id: team })
}

/// What `pkgutil --check-signature` said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PkgutilReport {
    /// The `Status:` line, if exactly one.
    pub status: Option<String>,
    /// More than one `Status:` line.
    pub ambiguous: bool,
    /// The certificate chain's common names, leaf first.
    pub chain: Vec<String>,
}

/// Parse `pkgutil --check-signature`'s output.
pub fn parse_pkgutil(text: &str) -> PkgutilReport {
    let mut r = PkgutilReport::default();
    let mut in_chain = false;
    for line in text.lines().map(str::trim) {
        if let Some(s) = line.strip_prefix("Status: ") {
            r.ambiguous |= r.status.is_some();
            r.status = Some(s.trim().to_owned());
        } else if line == "Certificate Chain:" {
            in_chain = true;
        } else if in_chain {
            // Entries are "1. <common name>"; expiry, fingerprint and
            // separator lines in between are skipped.
            let n = r.chain.len() + 1;
            if let Some(cn) = line.strip_prefix(&format!("{n}. ")) {
                r.chain.push(cn.trim().to_owned());
            }
        }
    }
    r
}

/// The team at the end of a certificate's common name:
/// `Developer ID Installer: Name (ABCDE12345)` → `ABCDE12345`.
pub fn team_of(common_name: &str) -> Option<&str> {
    let (_, rest) = common_name.rsplit_once(" (")?;
    let team = rest.strip_suffix(')')?;
    is_team_id(team).then_some(team)
}

/// Judge `pkgutil --check-signature`'s output for `team`.
pub fn judge_pkgutil(out: &ToolOutput, team: &str) -> Result<(), PackageCheckError> {
    use PackageCheckError::{Rejected, Unconfirmed};
    let r = parse_pkgutil(&out.text);
    if r.ambiguous {
        return Err(Unconfirmed("pkgutil printed more than one status".into()));
    }
    let Some(status) = r.status else {
        return Err(Unconfirmed(format!(
            "pkgutil printed no status (exit {:?})",
            out.status
        )));
    };
    if status != DEVELOPER_ID_STATUS {
        return Err(Rejected(format!("pkgutil: {status}")));
    }
    if out.status != Some(0) {
        return Err(Unconfirmed(format!(
            "pkgutil reported a Developer ID signature but exited with {:?}",
            out.status
        )));
    }
    let Some(leaf) = r.chain.first() else {
        return Err(Unconfirmed("pkgutil printed no certificate chain".into()));
    };
    if !leaf.starts_with(INSTALLER_CN_PREFIX) {
        return Err(Rejected(format!(
            "signed with \"{leaf}\", not a Developer ID Installer certificate"
        )));
    }
    match team_of(leaf) {
        Some(t) if t == team => {}
        Some(t) => return Err(Rejected(format!("signed by team {t}, not {team}"))),
        None => return Err(Rejected(format!("no team in \"{leaf}\""))),
    }
    let n = r.chain.len();
    let issued_by_developer_id = n >= 3
        && r.chain[1..n - 1]
            .iter()
            .any(|c| c.starts_with(DEVELOPER_ID_CA));
    if !issued_by_developer_id || !r.chain[n - 1].starts_with(APPLE_ROOT_CA) {
        return Err(Unconfirmed(format!(
            "unexpected certificate chain: {}",
            r.chain.join(" / ")
        )));
    }
    Ok(())
}

/// What `spctl --assess --type install --verbose=2` said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpctlReport {
    /// `accepted` or `rejected` (with any detail after it).
    pub verdict: Option<String>,
    pub source: Option<String>,
    pub origin: Option<String>,
    /// A key appeared twice.
    pub ambiguous: bool,
}

/// Parse `spctl --assess`'s output: `<path>: accepted`, then `key=value`
/// lines.
pub fn parse_spctl(text: &str) -> SpctlReport {
    let mut r = SpctlReport::default();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let slot = if let Some(v) = line.strip_prefix("source=") {
            Some((&mut r.source, v))
        } else if let Some(v) = line.strip_prefix("origin=") {
            Some((&mut r.origin, v))
        } else if r.verdict.is_none() && !line.contains('=') {
            line.rsplit_once(": ").map(|(_, v)| (&mut r.verdict, v))
        } else {
            None
        };
        if let Some((slot, v)) = slot {
            if slot.is_some() {
                r.ambiguous = true;
            }
            *slot = Some(v.trim().to_owned());
        }
    }
    r
}

/// Judge `spctl --assess`'s output for `team`.
pub fn judge_spctl(out: &ToolOutput, team: &str) -> Result<(), PackageCheckError> {
    use PackageCheckError::{Rejected, Unconfirmed};
    let r = parse_spctl(&out.text);
    if r.ambiguous {
        return Err(Unconfirmed("spctl printed a field twice".into()));
    }
    // A signature from another team is never Faro's, whatever the verdict.
    if let Some(t) = r.origin.as_deref().and_then(team_of) {
        if t != team {
            return Err(Rejected(format!(
                "Gatekeeper: signed by team {t}, not {team}"
            )));
        }
    }
    let accepted = r.verdict.as_deref() == Some("accepted");
    let notarized = r.source.as_deref() == Some(NOTARIZED_SOURCE);
    let ours = r
        .origin
        .as_deref()
        .is_some_and(|o| o.starts_with(INSTALLER_CN_PREFIX) && team_of(o) == Some(team));
    if accepted && notarized && ours && out.status == Some(0) {
        return Ok(());
    }
    Err(Unconfirmed(format!(
        "Gatekeeper did not confirm a notarized Faro package (verdict {}, source {}, exit {:?})",
        r.verdict.as_deref().unwrap_or("none"),
        r.source.as_deref().unwrap_or("none"),
        out.status
    )))
}

/// How long one tool may run. Gatekeeper may ask Apple when there is no
/// stapled ticket.
#[cfg(target_os = "macos")]
const TOOL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Run a tool with a fixed environment and a time limit.
#[cfg(target_os = "macos")]
fn run_tool(tool: Tool, pkg: &Path) -> Result<ToolOutput, String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut cmd = match tool {
        Tool::Pkgutil => {
            let mut c = Command::new(PKGUTIL);
            c.arg("--check-signature");
            c
        }
        Tool::Spctl => {
            let mut c = Command::new(SPCTL);
            c.args(["--assess", "--type", "install", "--verbose=2"]);
            c
        }
    };
    let mut child = cmd
        .arg(pkg)
        .env_clear()
        .env("PATH", faro_platform_macos::update_job::UPDATE_PATH_ENV)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // Read both pipes on their own threads, so a full pipe can't block
    // the tool while we wait for it.
    let reader = |r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            // At most 1 MiB: the real output is a few hundred bytes.
            let _ = r.take(1 << 20).read_to_end(&mut buf);
            buf
        })
    };
    let out = reader(Box::new(child.stdout.take().ok_or("no stdout")?));
    let err = reader(Box::new(child.stderr.take().ok_or("no stderr")?));
    let deadline = std::time::Instant::now() + TOOL_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(s) => break s,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {}s", TOOL_TIMEOUT.as_secs()));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    };
    let mut text = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&err.join().unwrap_or_default()));
    Ok(ToolOutput {
        status: status.code(),
        text,
    })
}

#[cfg(not(target_os = "macos"))]
fn run_tool(_tool: Tool, _pkg: &Path) -> Result<ToolOutput, String> {
    Err("package signatures can only be checked on macOS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use PackageCheckError::{Rejected, Unconfirmed};

    const TEAM: &str = "ABCDE12345";

    /// Output in the shape `pkgutil --check-signature` prints for a
    /// notarized release package (made-up leaf fingerprint). The "(1)" in
    /// the name checks that the team is taken from the last parentheses.
    fn pkgutil_ok(team: &str) -> String {
        format!(
            "Package \"Faro-1.2.0.pkg\":\n\
             \x20  Status: signed by a developer certificate issued by Apple for distribution\n\
             \x20  Notarization: trusted by the Apple notary service\n\
             \x20  Signed with a trusted timestamp on: 2026-11-01 12:00:00 +0000\n\
             \x20  Certificate Chain:\n\
             \x20   1. Developer ID Installer: Faro Project (1) ({team})\n\
             \x20      Expires: 2031-11-01 12:00:00 +0000\n\
             \x20      SHA256 Fingerprint:\n\
             \x20          12 34 56 78 9A BC DE F0 12 34 56 78 9A BC DE F0 12 34 56 78 9A BC\n\
             \x20          DE F0 12 34 56 78 9A BC DE F0\n\
             \x20      ------------------------------------------------------------------------\n\
             \x20   2. Developer ID Certification Authority\n\
             \x20      Expires: 2031-09-17 00:00:00 +0000\n\
             \x20      SHA256 Fingerprint:\n\
             \x20          F1 6C D3 C5 4C 7F 83 CE A4 BF 1A 3E 6A 08 19 C8 AA A8 E4 A1 52 8F\n\
             \x20          D1 44 71 5F 35 06 43 D2 DF 3A\n\
             \x20      ------------------------------------------------------------------------\n\
             \x20   3. Apple Root CA\n\
             \x20      Expires: 2035-02-09 21:40:36 +0000\n\
             \x20      SHA256 Fingerprint:\n\
             \x20          B0 B1 73 0E CB C7 FF 45 05 14 2C 49 F1 29 5E 6E DA 6B CA ED 7E 2C\n\
             \x20          68 C5 BE 91 B5 A1 10 01 F0 24\n"
        )
    }

    fn spctl_ok(team: &str) -> String {
        format!(
            "/Library/Application Support/Faro/updates/ab.pkg: accepted\n\
             source=Notarized Developer ID\n\
             origin=Developer ID Installer: Faro Project (1) ({team})\n"
        )
    }

    fn ok(text: impl Into<String>) -> ToolOutput {
        ToolOutput {
            status: Some(0),
            text: text.into(),
        }
    }

    fn exit(code: i32, text: impl Into<String>) -> ToolOutput {
        ToolOutput {
            status: Some(code),
            text: text.into(),
        }
    }

    /// A runner that answers from canned outputs and records the calls.
    fn canned(
        pkgutil: ToolOutput,
        spctl: ToolOutput,
        calls: &mut Vec<Tool>,
    ) -> impl FnMut(Tool, &Path) -> Result<ToolOutput, String> + '_ {
        move |t, _| {
            calls.push(t);
            Ok(match t {
                Tool::Pkgutil => pkgutil.clone(),
                Tool::Spctl => spctl.clone(),
            })
        }
    }

    fn check(
        policy: PackagePolicy,
        pkgutil: ToolOutput,
        spctl: ToolOutput,
    ) -> Result<Accepted, PackageCheckError> {
        let mut calls = Vec::new();
        let mut run = canned(pkgutil, spctl, &mut calls);
        check_with(policy, Path::new("/var/faro/updates/ab.pkg"), &mut run)
    }

    const REQUIRE: PackagePolicy = PackagePolicy::Require { team_id: TEAM };

    #[test]
    fn a_notarized_package_from_our_team_passes() {
        assert_eq!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), exit(0, spctl_ok(TEAM))),
            Ok(Accepted::Verified { team_id: TEAM })
        );
    }

    #[test]
    fn the_policy_comes_from_the_build() {
        assert_eq!(
            policy_for(Some(TEAM), false),
            PackagePolicy::Require { team_id: TEAM }
        );
        assert_eq!(
            policy_for(Some(TEAM), true),
            PackagePolicy::Require { team_id: TEAM },
            "a Team ID is required even in a development build"
        );
        assert_eq!(policy_for(None, true), PackagePolicy::Unchecked);
        assert_eq!(policy_for(None, false), PackagePolicy::RefuseAll);
        assert_eq!(non_empty(Some("")), None, "an empty FARO_TEAM_ID is none");
        assert_eq!(
            BUILD_POLICY,
            policy_for(BUILD_TEAM_ID, cfg!(feature = "dev"))
        );
    }

    /// The guarantee for release builds: without the `dev` feature no
    /// policy skips the check, not even a forged `Unchecked`.
    #[cfg(not(feature = "dev"))]
    #[test]
    fn a_release_build_never_skips_the_check() {
        assert_ne!(BUILD_POLICY, PackagePolicy::Unchecked);
        let mut calls = Vec::new();
        let r = check_with(
            PackagePolicy::Unchecked,
            Path::new("/x.pkg"),
            &mut canned(ok(""), ok(""), &mut calls),
        );
        assert!(matches!(r, Err(Unconfirmed(_))), "{r:?}");
        let r = check_with(
            PackagePolicy::RefuseAll,
            Path::new("/x.pkg"),
            &mut canned(ok(pkgutil_ok(TEAM)), ok(spctl_ok(TEAM)), &mut calls),
        );
        assert!(matches!(r, Err(Unconfirmed(_))), "{r:?}");
        assert!(calls.is_empty(), "nothing to check against: {calls:?}");
    }

    /// A development build without a Team ID installs unsigned packages,
    /// without running the tools. Run with `--features dev`.
    #[cfg(feature = "dev")]
    #[test]
    fn a_dev_build_without_a_team_skips_the_check() {
        let mut calls = Vec::new();
        let r = check_with(
            PackagePolicy::Unchecked,
            Path::new("/x.pkg"),
            &mut canned(ok("Status: no signature"), ok(""), &mut calls),
        );
        assert_eq!(r, Ok(Accepted::Unchecked));
        assert!(calls.is_empty());
        if BUILD_TEAM_ID.is_none() {
            assert_eq!(BUILD_POLICY, PackagePolicy::Unchecked);
        }
    }

    #[test]
    fn unsigned_or_foreign_packages_are_rejected() {
        let unsigned = "Package \"Faro-1.2.0-dev.pkg\":\n   Status: no signature\n";
        assert_eq!(
            check(REQUIRE, exit(1, unsigned), ok(spctl_ok(TEAM))),
            Err(Rejected("pkgutil: no signature".into()))
        );
        // Another team's Developer ID.
        let r = check(REQUIRE, ok(pkgutil_ok("ZZZZZ99999")), ok(spctl_ok(TEAM)));
        assert_eq!(
            r,
            Err(Rejected("signed by team ZZZZZ99999, not ABCDE12345".into()))
        );
        // A certificate that isn't a Developer ID Installer one.
        let app =
            pkgutil_ok(TEAM).replace("Developer ID Installer: ", "Developer ID Application: ");
        assert!(matches!(
            check(REQUIRE, ok(app), ok(spctl_ok(TEAM))),
            Err(Rejected(_))
        ));
        // A name that tries to smuggle our team in front of its own.
        let smuggled = pkgutil_ok(&format!("{TEAM}) (ZZZZZ99999"));
        assert_eq!(
            check(REQUIRE, ok(smuggled), ok(spctl_ok(TEAM))),
            Err(Rejected("signed by team ZZZZZ99999, not ABCDE12345".into()))
        );
        // Untrusted, self-made, or Apple's own: not Faro.
        for status in [
            "signed by untrusted certificate",
            "signed by a certificate trusted by macOS",
            "signed Apple Software",
            "signed by a developer certificate issued by Apple for distribution (revoked)",
        ] {
            let text = pkgutil_ok(TEAM).replace(DEVELOPER_ID_STATUS, status);
            assert_eq!(
                check(REQUIRE, exit(1, text), ok(spctl_ok(TEAM))),
                Err(Rejected(format!("pkgutil: {status}"))),
                "{status}"
            );
        }
    }

    #[test]
    fn gatekeeper_must_confirm_notarization() {
        // Signed by us but not notarized (or offline without a ticket):
        // not installed, but not evidence of tamper either.
        let unnotarized = "/p.pkg: rejected\nsource=Unnotarized Developer ID\n\
                           origin=Developer ID Installer: Faro Project (1) (ABCDE12345)\n";
        assert!(matches!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), exit(3, unnotarized)),
            Err(Unconfirmed(_))
        ));
        // Accepted for some other reason (a local rule, Gatekeeper off).
        let rule = "/p.pkg: accepted\nsource=my rule\noverride=security disabled\n";
        assert!(matches!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), ok(rule)),
            Err(Unconfirmed(_))
        ));
        // Gatekeeper off but the package still assessed as ours: fine.
        let off = format!("{}override=security disabled\n", spctl_ok(TEAM));
        assert!(check(REQUIRE, ok(pkgutil_ok(TEAM)), ok(off)).is_ok());
        // Another team, per Gatekeeper: rejected whatever the verdict.
        assert!(matches!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), ok(spctl_ok("ZZZZZ99999"))),
            Err(Rejected(_))
        ));
        // A failed exit status is never a pass.
        assert!(matches!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), exit(1, spctl_ok(TEAM))),
            Err(Unconfirmed(_))
        ));
        // Fields given twice are ambiguous.
        let twice = format!("{}source=Notarized Developer ID\n", spctl_ok(TEAM));
        assert!(matches!(
            check(REQUIRE, ok(pkgutil_ok(TEAM)), ok(twice)),
            Err(Unconfirmed(_))
        ));
    }

    #[test]
    fn anything_unexpected_is_unconfirmed() {
        let spctl = || ok(spctl_ok(TEAM));
        // No output, garbage, a killed tool.
        for out in [
            ok(""),
            ok("something else entirely"),
            ToolOutput {
                status: None,
                text: String::new(),
            },
        ] {
            assert!(matches!(check(REQUIRE, out, spctl()), Err(Unconfirmed(_))));
        }
        // A good status with a failed exit.
        assert!(matches!(
            check(REQUIRE, exit(1, pkgutil_ok(TEAM)), spctl()),
            Err(Unconfirmed(_))
        ));
        // Two statuses.
        let two = format!("{}   Status: no signature\n", pkgutil_ok(TEAM));
        assert!(matches!(
            check(REQUIRE, ok(two), spctl()),
            Err(Unconfirmed(_))
        ));
        // A chain that doesn't go through Developer ID to Apple's root.
        let short =
            pkgutil_ok(TEAM).replace("2. Developer ID Certification Authority", "2. Someone");
        assert!(matches!(
            check(REQUIRE, ok(short), spctl()),
            Err(Unconfirmed(_))
        ));
        // A tool that can't run.
        let mut fail =
            |_: Tool, _: &Path| -> Result<ToolOutput, String> { Err("no such file".into()) };
        assert!(matches!(
            check_with(REQUIRE, Path::new("/p.pkg"), &mut fail),
            Err(Unconfirmed(_))
        ));
        // A relative path is never handed to a tool.
        let mut calls = Vec::new();
        let r = check_with(
            REQUIRE,
            Path::new("p.pkg"),
            &mut canned(ok(pkgutil_ok(TEAM)), spctl(), &mut calls),
        );
        assert!(matches!(r, Err(Unconfirmed(_))));
        assert!(calls.is_empty());
    }

    #[test]
    fn gatekeeper_runs_only_after_pkgutil_passes() {
        let mut calls = Vec::new();
        let r = check_with(
            REQUIRE,
            Path::new("/p.pkg"),
            &mut canned(
                exit(1, "Status: no signature"),
                ok(spctl_ok(TEAM)),
                &mut calls,
            ),
        );
        assert!(matches!(r, Err(Rejected(_))));
        assert_eq!(calls, [Tool::Pkgutil]);
        calls.clear();
        let r = check_with(
            REQUIRE,
            Path::new("/p.pkg"),
            &mut canned(ok(pkgutil_ok(TEAM)), ok(spctl_ok(TEAM)), &mut calls),
        );
        assert!(r.is_ok());
        assert_eq!(calls, [Tool::Pkgutil, Tool::Spctl]);
    }

    #[test]
    fn parsing() {
        let r = parse_pkgutil(&pkgutil_ok(TEAM));
        assert_eq!(r.status.as_deref(), Some(DEVELOPER_ID_STATUS));
        assert_eq!(
            r.chain,
            [
                format!("Developer ID Installer: Faro Project (1) ({TEAM})"),
                DEVELOPER_ID_CA.to_owned(),
                APPLE_ROOT_CA.to_owned()
            ]
        );
        let r = parse_spctl(&spctl_ok(TEAM));
        assert_eq!(r.verdict.as_deref(), Some("accepted"));
        assert_eq!(r.source.as_deref(), Some(NOTARIZED_SOURCE));
        assert_eq!(team_of(r.origin.as_deref().unwrap()), Some(TEAM));
        // The real output for an unsigned development package.
        let r = parse_spctl("/Users/x/Faro-0.1.0-dev.pkg: rejected\nsource=no usable signature\n");
        assert_eq!(r.verdict.as_deref(), Some("rejected"));
        assert_eq!(r.source.as_deref(), Some("no usable signature"));
        assert_eq!(r.origin, None);

        assert_eq!(
            team_of("Developer ID Installer: A (ABCDE12345)"),
            Some(TEAM)
        );
        assert_eq!(team_of("Developer ID Installer: A (abcde12345)"), None);
        assert_eq!(team_of("Developer ID Installer: A (ABCDE1234)"), None);
        assert_eq!(team_of("Developer ID Installer: A ABCDE12345"), None);
        assert!(is_team_id(TEAM));
        assert!(!is_team_id("ABCDE1234!"));
    }

    /// The real tools on an unsigned file: `pkgutil` finds no signature.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_tools_reject_an_unsigned_file() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("not-a-package.pkg");
        std::fs::write(&pkg, b"not a xar archive").unwrap();
        let out = run_tool(Tool::Pkgutil, &pkg).unwrap();
        let r = judge_pkgutil(&out, TEAM);
        assert!(r.is_err(), "{out:?}");
        let r = check_with(REQUIRE, &pkg, &mut run_tool);
        assert!(r.is_err(), "{r:?}");
    }
}
