//! Which interactive sessions exist right now (ARCHITECTURE.md §3.1: every
//! OS account is monitored, so the service needs the full list, not just
//! the console user).
//!
//! A session is identified as `uid:<uid>`, which is also what the agent
//! sends in `Hello` by default:
//!
//! * **macOS** has one GUI (Aqua) session per user, and the global
//!   LaunchAgent starts one agent in each. The list comes from the
//!   SystemConfiguration dynamic store (`MacServiceHost::list_sessions`),
//!   which includes users switched away from with fast user switching.
//! * **Linux** runs the agent as a global systemd *user* unit, so there is
//!   one agent per user manager, that is per uid, however many logind
//!   sessions the user has. Graphical (`x11`/`wayland`) sessions of class
//!   `user` from `/run/systemd/sessions/` are grouped by uid; a uid is
//!   active if any of its sessions is.
//! * A **non-root development service** only ever serves its own user, so
//!   its list is that one session.

use std::collections::BTreeMap;
use std::sync::Arc;

/// One interactive session that should have an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntry {
    /// What the agent sends as `session` in `Hello` (`uid:<uid>`).
    pub id: String,
    /// The account that owns the session; its agent must run as this uid.
    pub uid: u32,
    /// The account's short name, used as the label in events (§3.6).
    pub account: String,
    /// At the screen right now (the console user, or an active seat).
    pub active: bool,
}

/// Lists sessions. `None` means the lookup failed (the caller keeps the
/// last good list rather than concluding everyone logged out).
pub type SessionLister = Arc<dyn Fn() -> Option<Vec<SessionEntry>> + Send + Sync>;

/// The production lister: every OS session for a root service, our own
/// session otherwise.
pub fn default_lister() -> SessionLister {
    if euid() == 0 {
        Arc::new(os_sessions)
    } else {
        Arc::new(|| Some(vec![own_session()]))
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The one session a non-root service serves: its own.
pub fn own_session() -> SessionEntry {
    let uid = euid();
    let account = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| format!("uid:{uid}"));
    SessionEntry {
        id: format!("uid:{uid}"),
        uid,
        account,
        active: true,
    }
}

#[cfg(target_os = "macos")]
fn os_sessions() -> Option<Vec<SessionEntry>> {
    use faro_platform::ServiceHost;
    let sessions = match faro_platform_macos::MacServiceHost::new().list_sessions() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "cannot list login sessions");
            return None;
        }
    };
    Some(
        sessions
            .into_iter()
            .filter(|s| s.graphical)
            .filter_map(|s| {
                let uid = s.id.0.strip_prefix("uid:")?.parse().ok()?;
                Some(SessionEntry {
                    id: s.id.0,
                    uid,
                    account: s.user,
                    active: s.active,
                })
            })
            .collect(),
    )
}

#[cfg(not(target_os = "macos"))]
fn os_sessions() -> Option<Vec<SessionEntry>> {
    let dir = std::path::Path::new("/run/systemd/sessions");
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "cannot list logind sessions");
            return None;
        }
    };
    let mut sessions = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // logind also keeps `<id>.ref` FIFOs here.
        if name.contains('.') {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            if let Some(s) = parse_logind_session(&text) {
                sessions.push(s);
            }
        }
    }
    Some(group_logind_sessions(&sessions))
}

/// The fields of a logind session file (`/run/systemd/sessions/<id>`) that
/// matter here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogindSession {
    pub uid: u32,
    pub user: String,
    pub graphical: bool,
    /// `CLASS=user` (not a greeter, lock screen or background session).
    pub user_class: bool,
    pub active: bool,
    /// `STATE=closing`: the user logged out; lingering processes remain.
    pub closing: bool,
}

/// Parse a logind session file. `None` if it has no usable `UID`.
pub fn parse_logind_session(text: &str) -> Option<LogindSession> {
    let mut kv = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim(), v.trim());
        }
    }
    let uid = kv.get("UID")?.parse().ok()?;
    Some(LogindSession {
        uid,
        user: kv.get("USER").copied().unwrap_or_default().to_owned(),
        graphical: matches!(kv.get("TYPE").copied(), Some("x11" | "wayland" | "mir")),
        user_class: kv.get("CLASS").copied() == Some("user"),
        active: kv.get("ACTIVE").copied() == Some("1"),
        closing: kv.get("STATE").copied() == Some("closing"),
    })
}

/// Group graphical user sessions by uid (one agent per user manager).
pub fn group_logind_sessions(sessions: &[LogindSession]) -> Vec<SessionEntry> {
    let mut by_uid: BTreeMap<u32, SessionEntry> = BTreeMap::new();
    for s in sessions {
        if !s.graphical || !s.user_class || s.closing || s.uid == 0 {
            continue;
        }
        let e = by_uid.entry(s.uid).or_insert_with(|| SessionEntry {
            id: format!("uid:{}", s.uid),
            uid: s.uid,
            account: if s.user.is_empty() {
                format!("uid:{}", s.uid)
            } else {
                s.user.clone()
            },
            active: false,
        });
        e.active |= s.active;
    }
    by_uid.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logind_files_are_grouped_by_uid() {
        let alex_gui = "# This is private data. Do not parse.\nUID=1000\nUSER=alex\nACTIVE=1\nSTATE=active\nTYPE=wayland\nCLASS=user\nSEAT=seat0\n";
        let alex_ssh = "UID=1000\nUSER=alex\nACTIVE=0\nSTATE=online\nTYPE=tty\nCLASS=user\n";
        let guest = "UID=1001\nUSER=guest\nACTIVE=0\nSTATE=online\nTYPE=x11\nCLASS=user\n";
        let greeter = "UID=120\nUSER=gdm\nACTIVE=0\nSTATE=online\nTYPE=wayland\nCLASS=greeter\n";
        let gone = "UID=1002\nUSER=sam\nACTIVE=0\nSTATE=closing\nTYPE=x11\nCLASS=user\n";
        let parsed: Vec<_> = [alex_gui, alex_ssh, guest, greeter, gone, "garbage"]
            .iter()
            .filter_map(|t| parse_logind_session(t))
            .collect();
        assert_eq!(parsed.len(), 5);
        let grouped = group_logind_sessions(&parsed);
        assert_eq!(
            grouped,
            [
                SessionEntry {
                    id: "uid:1000".into(),
                    uid: 1000,
                    account: "alex".into(),
                    active: true,
                },
                SessionEntry {
                    id: "uid:1001".into(),
                    uid: 1001,
                    account: "guest".into(),
                    active: false,
                },
            ]
        );
    }

    #[test]
    fn own_session_matches_the_agent_default() {
        let s = own_session();
        assert_eq!(s.id, format!("uid:{}", euid()));
        assert!(s.active && !s.account.is_empty());
    }
}
