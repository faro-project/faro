//! Development only: launch and relaunch the agent binary
//! (`faro-service run --spawn-agent <path>`).
//!
//! In production the OS keeps the agent alive in the user's session
//! (launchd `KeepAlive` LaunchAgent, a systemd user unit, the Windows
//! service's `CreateProcessAsUser`), because a root service must not run
//! the capture agent itself (§3.1). This spawner runs the agent as the
//! service's own user, which only makes sense for a non-root dev service.

use crate::backoff::Backoff;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::sync::watch;

/// How to launch the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpawn {
    pub program: PathBuf,
    /// Arguments; `{socket}` is replaced by the socket path.
    pub args: Vec<String>,
    pub socket: PathBuf,
}

impl AgentSpawn {
    /// `program run --socket <socket>`, which is what `faro-agent` expects.
    ///
    /// A non-root service also passes `--trust-same-uid-service`: by default
    /// the agent only talks to a root listener, so a dev service running as
    /// the user would otherwise be refused. That flag exists only in agents
    /// built with `--features dev`, which is the point: a release agent
    /// cannot be pointed at a user-run service.
    pub fn new(program: impl Into<PathBuf>, socket: impl Into<PathBuf>) -> Self {
        Self::with_root(program, socket, is_root())
    }

    fn with_root(program: impl Into<PathBuf>, socket: impl Into<PathBuf>, root: bool) -> Self {
        let mut args: Vec<String> = vec!["run".into(), "--socket".into(), "{socket}".into()];
        if !root {
            args.push("--trust-same-uid-service".into());
        }
        AgentSpawn {
            program: program.into(),
            args,
            socket: socket.into(),
        }
    }

    /// The arguments as they will be passed (after `{socket}` substitution).
    pub fn resolved_args(&self) -> Vec<String> {
        let socket = self.socket.display().to_string();
        self.args
            .iter()
            .map(|a| a.replace("{socket}", &socket))
            .collect()
    }

    fn command(&self) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.program);
        c.args(self.resolved_args())
            .env("FARO_AGENT_SOCKET", &self.socket)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        c
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_root() -> bool {
    // LocalSystem is the Windows root: a dev service run by hand is not,
    // and then the agent is told to trust a same-account service.
    faro_platform_windows::acl::running_as_system()
}

/// Keep the agent running until `stop` flips. Each exit is logged; the
/// resulting disconnect is what supervision counts.
pub async fn supervise(spec: AgentSpawn, mut stop: watch::Receiver<bool>) {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    loop {
        if *stop.borrow() {
            return;
        }
        let started = tokio::time::Instant::now();
        let mut child = match spec.command().spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(program = %spec.program.display(), error = %e, "cannot start the agent");
                let d = backoff.next_delay();
                tokio::select! {
                    _ = tokio::time::sleep(d) => continue,
                    _ = stop.wait_for(|s| *s) => return,
                }
            }
        };
        tracing::info!(pid = ?child.id(), "agent started");
        let exited = tokio::select! {
            status = child.wait() => Some(status),
            _ = stop.wait_for(|s| *s) => None,
        };
        match exited {
            Some(status) => {
                tracing::warn!(status = ?status.ok(), "agent exited");
                if started.elapsed() > Duration::from_secs(60) {
                    backoff.reset();
                }
                let d = backoff.next_delay();
                tokio::select! {
                    _ = tokio::time::sleep(d) => {}
                    _ = stop.wait_for(|s| *s) => return,
                }
            }
            None => {
                // Give the agent a moment to exit on the service's Shutdown
                // message, then make sure it is gone.
                if tokio::time::timeout(Duration::from_secs(2), child.wait())
                    .await
                    .is_err()
                {
                    let _ = child.kill().await;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_arguments_name_the_run_subcommand() {
        let user = AgentSpawn::with_root("/bin/faro-agent", "/tmp/s.sock", false);
        assert_eq!(
            user.resolved_args(),
            ["run", "--socket", "/tmp/s.sock", "--trust-same-uid-service"]
        );
        let root = AgentSpawn::with_root("/bin/faro-agent", "/tmp/s.sock", true);
        assert_eq!(root.resolved_args(), ["run", "--socket", "/tmp/s.sock"]);
    }
}
