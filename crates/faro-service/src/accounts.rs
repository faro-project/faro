//! The computer's user accounts, shown when the member enrolls it
//! (ARCHITECTURE.md §7, §12): Faro monitors every account, so the member is
//! told which accounts exist and whether the guest account is on before
//! monitoring starts.
//!
//! This is information for the member, not a security boundary: the service
//! monitors whatever sessions the OS reports (`source::sessions`), whether
//! or not an account was listed here.

/// Human accounts on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Accounts {
    /// Short names, sorted.
    pub names: Vec<String>,
    /// The OS guest account is enabled (macOS).
    pub guest_enabled: bool,
}

/// The local accounts, or `None` if this platform cannot list them.
pub fn local_accounts() -> Option<Accounts> {
    imp::local_accounts()
}

/// `dscl . -list /Users UniqueID` output → human accounts (uid ≥ 501, no
/// `_` service accounts).
pub fn parse_dscl_uids(out: &str) -> Vec<String> {
    let mut names: Vec<String> = out
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let uid: i64 = it.next()?.parse().ok()?;
            (uid >= 501 && !name.starts_with('_')).then(|| name.to_owned())
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// `/etc/passwd` → human accounts (uid 1000..65534 with a login shell).
pub fn parse_passwd(text: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            let uid: u32 = f[2].parse().ok()?;
            let shell = f[6].trim();
            let login = !(shell.ends_with("/nologin") || shell.ends_with("/false"));
            ((1000..65534).contains(&uid) && login).then(|| f[0].to_owned())
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// What the member is told at enrollment.
pub fn enrollment_notice(accounts: Option<&Accounts>) -> String {
    let mut out = String::from(
        "Faro will monitor every account on this computer, including accounts created later.\n",
    );
    match accounts {
        Some(a) if !a.names.is_empty() => {
            out.push_str(&format!("Accounts:  {}\n", a.names.join(", ")));
        }
        _ => {}
    }
    if accounts.is_some_and(|a| a.guest_enabled) {
        out.push_str(
            "The guest account is turned on, so anyone can use this computer without a \
             password. Consider turning it off (System Settings > Users & Groups).\n",
        );
    }
    out.push_str("Everyone who uses this computer is told it is monitored when they log in.\n");
    out
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{parse_dscl_uids, Accounts};
    use std::process::Command;

    fn run(program: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(program).args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn local_accounts() -> Option<Accounts> {
        let names = parse_dscl_uids(&run(
            "/usr/bin/dscl",
            &[".", "-list", "/Users", "UniqueID"],
        )?);
        let guest_enabled = run(
            "/usr/bin/defaults",
            &[
                "read",
                "/Library/Preferences/com.apple.loginwindow",
                "GuestEnabled",
            ],
        )
        .is_some_and(|v| v.trim() == "1");
        Some(Accounts {
            names,
            guest_enabled,
        })
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use super::{parse_passwd, Accounts};

    pub fn local_accounts() -> Option<Accounts> {
        let text = std::fs::read_to_string("/etc/passwd").ok()?;
        Some(Accounts {
            names: parse_passwd(&text),
            guest_enabled: false,
        })
    }
}

#[cfg(not(unix))]
mod imp {
    use super::Accounts;

    pub fn local_accounts() -> Option<Accounts> {
        // TODO(windows): NetUserEnum, once there is a Windows client.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dscl_output_keeps_people() {
        let out = "_amavisd                 83\n_mbsetupuser             248\nalex                     501\ndaemon                   1\nGuest                    201\nnobody                   -2\nroot                     0\nsam                      502\n";
        assert_eq!(parse_dscl_uids(out), ["alex", "sam"]);
    }

    #[test]
    fn passwd_keeps_login_accounts() {
        let text = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nalex:x:1000:1000:Alex:/home/alex:/bin/bash\nsvc:x:1001:1001::/var/svc:/usr/sbin/nologin\nsam:x:1002:1002::/home/sam:/usr/bin/zsh\n# comment\nbroken:line\n";
        assert_eq!(parse_passwd(text), ["alex", "sam"]);
    }

    #[test]
    fn notice_lists_accounts_and_warns_about_guest() {
        let a = Accounts {
            names: vec!["alex".into(), "sam".into()],
            guest_enabled: true,
        };
        let n = enrollment_notice(Some(&a));
        assert!(n.contains("every account"));
        assert!(n.contains("Accounts:  alex, sam"));
        assert!(n.contains("guest account is turned on"));
        let n = enrollment_notice(None);
        assert!(n.contains("every account") && !n.contains("guest"));
    }
}
