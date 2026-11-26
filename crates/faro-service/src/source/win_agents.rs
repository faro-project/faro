//! Starting and keeping the session agents on Windows (ARCHITECTURE.md §3.1,
//! §3.7, `faro_platform_windows::service`).
//!
//! On macOS launchd's `KeepAlive` LaunchAgent and on Linux a systemd user
//! unit keep one agent running per user. Windows has nothing like that for
//! every account, so the LocalSystem service does it: it starts
//! `faro-agent.exe run` in every user session
//! ([`WinServiceHost::spawn_in_session`]: the session user's own token, on
//! their desktop) and starts it again when it exits.
//!
//! * **Startup.** Every user session gets an agent, including one switched
//!   away from (its programs keep running). An agent already running there
//!   (the service restarted; the agent outlives it) is **not** adopted:
//!   the service has no handle it can trust to be the process it started,
//!   and the user can start the installed image themselves. A process with
//!   the agent image name, session **and** full image path is stopped and
//!   replaced by one the service spawns, which has the protected process
//!   descriptor (`faro_platform_windows::service`); the IPC source admits
//!   only the pid the launcher recorded for the session. Same-named
//!   programs from other paths are left alone.
//! * **Relaunch.** The agent's process handle is waited on, so a killed
//!   agent is noticed at once; each restart is logged as `agent_restarted`
//!   and started again after a short, growing delay. The *tamper* signal is
//!   not made here: the agent's pipe closing is what
//!   [`super::ipc::IpcFrameSource`] classifies and reports (§3.7).
//! * **Sessions.** The list is re-read every few seconds and at once on
//!   every session change the SCM reports ([`crate::win::session_changes`]):
//!   a logon starts an agent, a logoff stops waiting for it (Windows ends
//!   the session's processes itself).
//!
//! Nothing here stops an agent when the service stops: the IPC source tells
//! them `ServiceStopping`, and they wait for the service to come back.

use super::sessions::{SessionEntry, SessionLister};
use crate::backoff::Backoff;
use faro_platform_windows::service::{parse_session_id, SpawnedAgent, WinServiceHost};
use std::collections::{BTreeMap, BTreeSet};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

/// How often the session list is re-read when nothing reports a change.
const RELIST: Duration = Duration::from_secs(5);
/// How long an agent must have run for its next restart to be immediate.
const HEALTHY_AFTER: Duration = Duration::from_secs(60);

/// A running agent process we wait on.
struct Running {
    process: OwnedHandle,
    pid: u32,
}

/// Launches agents. See the module docs.
pub struct AgentLauncher {
    host: WinServiceHost,
    lister: SessionLister,
    relist: Duration,
}

impl AgentLauncher {
    /// The production launcher: `layout::AGENT_PROGRAM run` in every session
    /// of [`super::sessions::default_lister`].
    pub fn production() -> Self {
        AgentLauncher::new(WinServiceHost::new(), super::sessions::default_lister())
    }

    pub fn new(host: WinServiceHost, lister: SessionLister) -> Self {
        AgentLauncher {
            host,
            lister,
            relist: RELIST,
        }
    }

    /// Run until the task is aborted.
    pub async fn run(self) {
        let mut changes = crate::win::session_changes();
        crate::win::set_launcher_active();
        let running: Arc<Mutex<BTreeMap<u32, u32>>> = Arc::default();
        let mut tasks: BTreeMap<u32, JoinHandle<()>> = BTreeMap::new();
        let host = Arc::new(self.host);
        loop {
            if let Some(list) = (self.lister)() {
                let wanted: BTreeSet<u32> = list.iter().filter_map(wts_id).collect();
                tasks.retain(|id, t| {
                    let keep = wanted.contains(id) && !t.is_finished();
                    if !keep {
                        t.abort();
                        set_running(&running, *id, None);
                    }
                    keep
                });
                for id in wanted {
                    tasks.entry(id).or_insert_with(|| {
                        tokio::spawn(keep_agent(host.clone(), id, running.clone()))
                    });
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(self.relist) => {}
                _ = changes.changed() => {}
            }
        }
    }
}

fn wts_id(s: &SessionEntry) -> Option<u32> {
    parse_session_id(&faro_platform::SessionId(s.id.clone()))
}

/// Record (`Some(pid)`) or forget (`None`) the agent the launcher spawned
/// in `session`.
fn set_running(running: &Mutex<BTreeMap<u32, u32>>, session: u32, pid: Option<u32>) {
    let mut r = running.lock().unwrap_or_else(PoisonError::into_inner);
    match pid {
        Some(pid) => {
            r.insert(session, pid);
        }
        None => {
            r.remove(&session);
        }
    }
    crate::win::set_launched_agents(r.clone());
}

/// Keep one session's agent running until the task is aborted.
async fn keep_agent(
    host: Arc<WinServiceHost>,
    session: u32,
    running: Arc<Mutex<BTreeMap<u32, u32>>>,
) {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    loop {
        let started = Instant::now();
        let h = host.clone();
        let launched = tokio::task::spawn_blocking(move || launch_or_adopt(&h, session)).await;
        let agent = match launched {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                tracing::warn!(session, error = %e, "cannot start the agent in a session; will retry");
                tokio::time::sleep(backoff.next_delay()).await;
                continue;
            }
            Err(_) => return,
        };
        tracing::info!(session, pid = agent.pid, "agent running in a session");
        set_running(&running, session, Some(agent.pid));
        let pid = agent.pid;
        // Cancelled when this task is aborted, so the waiting thread ends
        // within a second instead of at the agent's exit.
        let cancel = Arc::new(AtomicBool::new(false));
        let _guard = CancelOnDrop(cancel.clone());
        let exited = tokio::task::spawn_blocking(move || wait_for_exit(&agent.process, &cancel))
            .await
            .unwrap_or(false);
        set_running(&running, session, None);
        if !exited {
            return;
        }
        if started.elapsed() > HEALTHY_AFTER {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        tracing::warn!(
            event = "agent_restarted",
            session,
            pid,
            restart_in_ms = delay.as_millis() as u64,
            "the session's agent exited; starting it again"
        );
        tokio::time::sleep(delay).await;
    }
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Wait until the process exits (`true`) or `cancel` is set (`false`).
fn wait_for_exit(process: &OwnedHandle, cancel: &AtomicBool) -> bool {
    let h = HANDLE(process.as_raw_handle());
    while !cancel.load(Ordering::Relaxed) {
        // SAFETY: `h` is a process handle with SYNCHRONIZE access, kept
        // alive by `process`.
        if unsafe { WaitForSingleObject(h, 1000) } == WAIT_OBJECT_0 {
            return true;
        }
    }
    false
}

/// Start this service instance own agent in `session`. A same-path agent
/// the service did not start (the service restarted, or the user ran the
/// installed `faro-agent.exe` themselves) is never adopted: the service
/// cannot tell it from an impostor that has patched the genuine image in
/// memory, so it is stopped if possible and ignored otherwise (the IPC
/// source only admits the pid recorded for what the launcher spawned).
fn launch_or_adopt(host: &WinServiceHost, session: u32) -> Result<Running, String> {
    stop_foreign(host.agent_program(), session);
    let SpawnedAgent { pid, process } =
        host.spawn_in_session(session).map_err(|e| e.to_string())?;
    Ok(Running { process, pid })
}

/// Stop every process in `session` with the agent image name and full
/// path. Each is opened once and everything after is done on that handle,
/// so a pid reused in between cannot make us kill or trust the wrong
/// process: an open handle keeps its pid from being recycled.
fn stop_foreign(program: &Path, session: u32) {
    let Some(name) = program
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
    else {
        return;
    };
    // SAFETY: a snapshot handle we close below.
    let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return;
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut pids = Vec::new();
    // SAFETY: `snap` is a valid snapshot and `entry` a correctly sized entry.
    let mut more = unsafe { Process32FirstW(snap, &mut entry) }.is_ok();
    while more {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase() == name {
            pids.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snap, &mut entry) }.is_ok();
    }
    // SAFETY: closing the snapshot we opened.
    let _ = unsafe { CloseHandle(snap) };
    for pid in pids {
        // SAFETY: a process handle we own; the handle (not the pid) is what
        // every later step uses.
        let Ok(h) = (unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                false,
                pid,
            )
        }) else {
            tracing::warn!(
                pid,
                session,
                "cannot open a same-named process; ignoring it"
            );
            continue;
        };
        // SAFETY: a fresh handle; ownership moves to the OwnedHandle.
        let process = unsafe { OwnedHandle::from_raw_handle(h.0 as RawHandle) };
        if crate::win::process_session_id(pid) != Some(session) {
            continue;
        }
        let Ok(image) = faro_platform_windows::authenticode::process_image_of(&process) else {
            continue;
        };
        if !same_path(&image, program) {
            continue;
        }
        tracing::warn!(
            pid,
            session,
            "an agent the service did not start is running here; stopping it and starting our own"
        );
        // SAFETY: `process` has PROCESS_TERMINATE.
        match unsafe { TerminateProcess(h, 1) } {
            Ok(()) => {
                // SAFETY: SYNCHRONIZE access.
                let _ = unsafe { WaitForSingleObject(h, 5000) };
            }
            Err(e) => {
                tracing::warn!(pid, error = %e, "cannot stop it; it will be refused on the agent pipe");
            }
        }
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('/', "\\").to_lowercase();
    norm(a) == norm(b)
}
