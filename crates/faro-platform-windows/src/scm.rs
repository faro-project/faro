//! Service Control Manager integration: installing and removing
//! `FaroService`, and running inside the SCM's service dispatcher.
//!
//! Implemented on the raw Win32 API (the `windows` crate the rest of this
//! crate uses), not the `windows-service` crate: Faro needs the service
//! DACL, the service SID type and session-change payloads, which would mean
//! raw calls next to it anyway.
//!
//! # Installation ([`install_service`])
//!
//! * **LocalSystem, own process, automatic start.** Faro must be running
//!   before anyone logs on, and only LocalSystem may call
//!   `WTSQueryUserToken` to start agents in user sessions.
//! * **Recovery actions:** restart after 5 s, 10 s, then 30 s (and 30 s for
//!   every later failure), with the failure count reset after a day without
//!   one. `FailureActionsOnNonCrashFailures` is on, so exiting with a
//!   non-zero code (what [`run_service_dispatcher`] reports when the service
//!   main returns non-zero or panics) counts as a failure, not only a crash.
//!   A member who manages to kill the service gets it back within seconds,
//!   and its instance sees the gap in heartbeats.
//! * **A protective DACL** ([`SERVICE_SDDL`]): only SYSTEM and
//!   Administrators may stop, pause, reconfigure or delete the service;
//!   interactive users (and services running as other accounts) may only
//!   query its configuration and status and interrogate it. Windows'
//!   default service DACL is similar, but also lets interactive users send
//!   user-defined control codes; this one is explicit, minimal, and
//!   reapplied by every install, so a previously loosened DACL is repaired.
//! * **An unrestricted service SID** (`NT SERVICE\FaroService`), so pipe and
//!   file DACLs can name the service specifically rather than all of SYSTEM.
//!
//! Installing again updates an existing registration in place (binary path,
//! start type, account, then all of the above), which is what an upgrade
//! needs.
//!
//! # Running ([`run_service_dispatcher`])
//!
//! How `faro-service` uses it (`faro-service.exe run`, as registered):
//!
//! ```ignore
//! use faro_platform_windows::scm::{self, ServiceControl};
//!
//! fn main() -> anyhow::Result<()> {
//!     // ...parse the CLI; for `run`:
//!     match scm::run_service_dispatcher(|ctx| {
//!         // On the SCM's service thread. Build the runtime here.
//!         let rt = tokio::runtime::Runtime::new().expect("tokio");
//!         rt.block_on(async move {
//!             // Bridge the std channel into tokio.
//!             let (tx, mut controls) = tokio::sync::mpsc::unbounded_channel();
//!             let rx = ctx.controls;
//!             std::thread::spawn(move || {
//!                 while let Ok(c) = rx.recv() {
//!                     if tx.send(c).is_err() { break; }
//!                 }
//!             });
//!             // ...start the service runtime...
//!             ctx.status.running();
//!             while let Some(c) = controls.recv().await {
//!                 match c {
//!                     ServiceControl::Stop | ServiceControl::Shutdown
//!                     | ServiceControl::Preshutdown => break,
//!                     ServiceControl::SessionChange(ev) => { /* re-list sessions, spawn agents */ }
//!                     ServiceControl::Power(p) => { /* sleep/wake */ }
//!                     ServiceControl::TimeChange => { /* clock check, §3.7 */ }
//!                 }
//!             }
//!             // ...flush and stop; call ctx.status.stop_pending(ms) if slow...
//!             0 // exit code: non-zero triggers the recovery actions
//!         })
//!     }) {
//!         Ok(()) => Ok(()),
//!         // Started from a console, not by the SCM: run in the foreground.
//!         Err(e) if scm::is_not_a_service(&e) => run_in_foreground(),
//!         Err(e) => Err(e.into()),
//!     }
//! }
//! ```
//!
//! The control handler runs on the dispatcher's thread and must return at
//! once, so it only forwards [`ServiceControl`]s down the channel; for stop,
//! shutdown and preshutdown it first reports `SERVICE_STOP_PENDING` itself
//! (with a [`STOP_WAIT_HINT_MS`] hint), so the SCM sees progress even
//! before the service main notices. When the service main returns, the
//! dispatcher reports `SERVICE_STOPPED` with its exit code.

use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS,
    ERROR_SERVICE_MARKED_FOR_DELETE, ERROR_SERVICE_NOT_ACTIVE, NO_ERROR, WIN32_ERROR,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    RegisterServiceCtrlHandlerExW, SetServiceObjectSecurity, SetServiceStatus,
    StartServiceCtrlDispatcherW, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_PRESHUTDOWN,
    SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_ACCEPT_TIMECHANGE, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CONFIG_DESCRIPTION,
    SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT,
    SERVICE_CONTROL_PRESHUTDOWN, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_CONTROL_TIMECHANGE, SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL,
    SERVICE_FAILURE_ACTIONSW, SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
    SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START_PENDING, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::layout;
use crate::service::{command_line, SessionEvent};

/// The service's DACL. SDDL service rights: `CC` query config, `DC` change
/// config, `LC` query status, `SW` enumerate dependents, `RP` start, `WP`
/// stop, `DT` pause/continue, `LO` interrogate, `CR` user-defined control,
/// `SD` delete, `RC` read the DACL, `WD`/`WO` change the DACL/owner.
///
/// * SYSTEM (`SY`): query, start, stop, pause, interrogate, controls.
/// * Administrators (`BA`): everything (an ally keeps the admin password;
///   ARCHITECTURE.md §3.1 recommends members run as standard users).
/// * Interactive users (`IU`) and service-logon accounts (`SU`): query
///   config and status, enumerate dependents, interrogate, read the DACL.
///   Nothing that stops, pauses, reconfigures or deletes it.
pub const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)\
(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
(A;;CCLCSWLORC;;;IU)\
(A;;CCLCSWLORC;;;SU)";

/// Restart delays after the first, second and later failures.
pub const RESTART_DELAYS_MS: [u32; 3] = [5_000, 10_000, 30_000];
/// The failure count resets after this long without a failure.
pub const FAILURE_RESET_SECS: u32 = 24 * 60 * 60;
/// The wait hint reported with `SERVICE_STOP_PENDING` by the control
/// handler: how long the SCM should give the service to stop.
pub const STOP_WAIT_HINT_MS: u32 = 15_000;
/// What `StartServiceCtrlDispatcherW` fails with when the process was not
/// started by the SCM (`ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`).
pub const ERROR_NOT_A_SERVICE: i32 = 1063;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn win_err(e: windows::core::Error) -> std::io::Error {
    match WIN32_ERROR::from_error(&e) {
        Some(code) => std::io::Error::from_raw_os_error(code.0 as i32),
        None => std::io::Error::other(e),
    }
}

fn is_code(e: &windows::core::Error, code: WIN32_ERROR) -> bool {
    WIN32_ERROR::from_error(e) == Some(code)
}

/// An SCM or service handle, closed on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: we own the handle and close it once.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_scm(access: u32) -> std::io::Result<ScHandle> {
    // SAFETY: null machine and database: the local active database.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
        .map(ScHandle)
        .map_err(win_err)
}

/// Register `layout::SERVICE_NAME` to run `binary args…` as LocalSystem,
/// automatic start, with recovery actions, description, service SID and
/// [`SERVICE_SDDL`] (see the module docs). Updates an existing
/// registration. Needs an elevated administrator (`ERROR_ACCESS_DENIED`,
/// os error 5, otherwise).
pub fn install_service(binary: &Path, args: &[String]) -> std::io::Result<()> {
    install_named(
        layout::SERVICE_NAME,
        layout::SERVICE_DISPLAY_NAME,
        layout::SERVICE_DESCRIPTION,
        binary,
        args,
    )
}

fn install_named(
    name: &str,
    display: &str,
    description: &str,
    binary: &Path,
    args: &[String],
) -> std::io::Result<()> {
    if !binary.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the service binary must be an absolute path",
        ));
    }
    let scm = open_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name_w = wide(name);
    let display_w = wide(display);
    // Quoted, so a path with spaces cannot be hijacked by `C:\Program.exe`.
    let cmd_w = wide(&command_line(binary, args));
    // SAFETY: all strings are NUL-terminated and outlive the call; a null
    // account name means LocalSystem.
    let created = unsafe {
        CreateServiceW(
            scm.0,
            PCWSTR(name_w.as_ptr()),
            PCWSTR(display_w.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(cmd_w.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    };
    let svc = match created {
        Ok(h) => ScHandle(h),
        Err(e) if is_code(&e, ERROR_SERVICE_EXISTS) => {
            // SAFETY: valid SCM handle and NUL-terminated name.
            let h = ScHandle(
                unsafe { OpenServiceW(scm.0, PCWSTR(name_w.as_ptr()), SERVICE_ALL_ACCESS) }
                    .map_err(win_err)?,
            );
            // SAFETY: valid service handle; NUL-terminated strings.
            unsafe {
                ChangeServiceConfigW(
                    h.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR(cmd_w.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    w!("LocalSystem"),
                    PCWSTR::null(),
                    PCWSTR(display_w.as_ptr()),
                )
            }
            .map_err(win_err)?;
            h
        }
        Err(e) => return Err(win_err(e)),
    };
    configure(&svc, description)
}

fn configure(svc: &ScHandle, description: &str) -> std::io::Result<()> {
    let mut desc_w = wide(description);
    let desc = SERVICE_DESCRIPTIONW {
        lpDescription: PWSTR(desc_w.as_mut_ptr()),
    };
    // SAFETY: `desc` points at a live NUL-terminated buffer.
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_DESCRIPTION,
            Some((&raw const desc).cast()),
        )
    }
    .map_err(win_err)?;

    let mut actions = RESTART_DELAYS_MS.map(|delay| SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: delay,
    });
    let failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: FAILURE_RESET_SECS,
        lpRebootMsg: PWSTR::null(),
        lpCommand: PWSTR::null(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: `failure` and `actions` are live for the call. (Restart
    // actions need SERVICE_START on the handle, which ALL_ACCESS has.)
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            Some((&raw const failure).cast()),
        )
    }
    .map_err(win_err)?;
    let flag = SERVICE_FAILURE_ACTIONS_FLAG {
        fFailureActionsOnNonCrashFailures: true.into(),
    };
    // SAFETY: `flag` is live for the call.
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            Some((&raw const flag).cast()),
        )
    }
    .map_err(win_err)?;
    let sid = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    // SAFETY: `sid` is live for the call.
    unsafe {
        ChangeServiceConfig2W(
            svc.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            Some((&raw const sid).cast()),
        )
    }
    .map_err(win_err)?;

    let sd = ServiceSd::from_sddl(SERVICE_SDDL)?;
    // SAFETY: valid handle (ALL_ACCESS includes WRITE_DAC) and descriptor.
    unsafe { SetServiceObjectSecurity(svc.0, DACL_SECURITY_INFORMATION, sd.0) }.map_err(win_err)?;
    Ok(())
}

/// A LocalAlloc'd security descriptor from SDDL.
struct ServiceSd(PSECURITY_DESCRIPTOR);

impl ServiceSd {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        use windows::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let w = wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: NUL-terminated input and a valid out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(win_err)?;
        Ok(ServiceSd(sd))
    }
}

impl Drop for ServiceSd {
    fn drop(&mut self) {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        // SAFETY: LocalAlloc'd by the SDDL conversion, freed once.
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

/// Stop (if running) and delete the `layout::SERVICE_NAME` registration,
/// waiting up to 30 s for it to stop. Succeeds if it is not installed.
/// Needs an elevated administrator.
///
/// The uninstaller sends the device's goodbye (§3.7) **before** calling
/// this; stopping the service here is otherwise indistinguishable from
/// tampering.
pub fn uninstall_service() -> std::io::Result<()> {
    uninstall_named(layout::SERVICE_NAME, Duration::from_secs(30))
}

fn uninstall_named(name: &str, wait: Duration) -> std::io::Result<()> {
    const DELETE: u32 = 0x0001_0000;
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name_w = wide(name);
    // SAFETY: valid SCM handle and NUL-terminated name.
    let svc = match unsafe {
        OpenServiceW(
            scm.0,
            PCWSTR(name_w.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        )
    } {
        Ok(h) => ScHandle(h),
        Err(e) if is_code(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
        Err(e) => return Err(win_err(e)),
    };
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid handle and out pointer.
    match unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) } {
        Ok(()) => {}
        Err(e) if is_code(&e, ERROR_SERVICE_NOT_ACTIVE) => {}
        Err(e) => return Err(win_err(e)),
    }
    // SAFETY: valid handle.
    match unsafe { DeleteService(svc.0) } {
        Ok(()) => {}
        Err(e) if is_code(&e, ERROR_SERVICE_MARKED_FOR_DELETE) => {}
        Err(e) => return Err(win_err(e)),
    }
    let deadline = Instant::now() + wait;
    loop {
        // SAFETY: valid handle and out pointer.
        unsafe { QueryServiceStatus(svc.0, &mut status) }.map_err(win_err)?;
        if status.dwCurrentState == SERVICE_STOPPED {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the service did not stop; it is deleted once it does",
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A service's run state, as `QueryServiceStatus` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Other(u32),
}

/// The state of service `name`, or `None` if it is not installed. Needs
/// no privilege (the DACL grants query status to everyone interactive).
pub fn service_state(name: &str) -> std::io::Result<Option<ServiceState>> {
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name_w = wide(name);
    // SAFETY: valid SCM handle and NUL-terminated name.
    let svc = match unsafe { OpenServiceW(scm.0, PCWSTR(name_w.as_ptr()), SERVICE_QUERY_STATUS) } {
        Ok(h) => ScHandle(h),
        Err(e) if is_code(&e, ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(None),
        Err(e) => return Err(win_err(e)),
    };
    let mut status = SERVICE_STATUS::default();
    // SAFETY: valid handle and out pointer.
    unsafe { QueryServiceStatus(svc.0, &mut status) }.map_err(win_err)?;
    Ok(Some(match status.dwCurrentState.0 {
        1 => ServiceState::Stopped,
        2 => ServiceState::StartPending,
        3 => ServiceState::StopPending,
        4 => ServiceState::Running,
        5 => ServiceState::ContinuePending,
        6 => ServiceState::PausePending,
        7 => ServiceState::Paused,
        n => ServiceState::Other(n),
    }))
}

/// A power event (`SERVICE_CONTROL_POWEREVENT`'s event type, `PBT_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerEvent {
    /// `PBT_APMSUSPEND`: the system is about to sleep.
    Suspend,
    /// `PBT_APMRESUMESUSPEND`: resumed by user input.
    ResumeSuspend,
    /// `PBT_APMRESUMEAUTOMATIC`: resumed (always sent on wake).
    ResumeAutomatic,
    /// `PBT_APMPOWERSTATUSCHANGE`: AC/battery change.
    PowerStatusChange,
    /// `PBT_POWERSETTINGCHANGE` (only for registered settings).
    PowerSettingChange,
    Other(u32),
}

impl PowerEvent {
    pub fn from_raw(event_type: u32) -> Self {
        match event_type {
            4 => Self::Suspend,
            7 => Self::ResumeSuspend,
            18 => Self::ResumeAutomatic,
            10 => Self::PowerStatusChange,
            0x8013 => Self::PowerSettingChange,
            n => Self::Other(n),
        }
    }
}

/// A control the SCM sent the service, forwarded by the control handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceControl {
    /// `SERVICE_CONTROL_STOP` (an administrator or the uninstaller). The
    /// handler has already reported `SERVICE_STOP_PENDING`.
    Stop,
    /// `SERVICE_CONTROL_SHUTDOWN`: the system is shutting down (sent only
    /// if preshutdown was not handled in time). Already `STOP_PENDING`.
    Shutdown,
    /// `SERVICE_CONTROL_PRESHUTDOWN`: shutdown is starting; stop promptly.
    /// Already `STOP_PENDING`.
    Preshutdown,
    /// `SERVICE_CONTROL_SESSIONCHANGE`.
    SessionChange(SessionEvent),
    /// `SERVICE_CONTROL_POWEREVENT`.
    Power(PowerEvent),
    /// `SERVICE_CONTROL_TIMECHANGE`: the system clock was set (a §3.7
    /// clock-manipulation signal to check).
    TimeChange,
}

/// The controls the running service accepts.
pub const ACCEPTED_CONTROLS: u32 = SERVICE_ACCEPT_STOP
    | SERVICE_ACCEPT_SHUTDOWN
    | SERVICE_ACCEPT_PRESHUTDOWN
    | SERVICE_ACCEPT_SESSIONCHANGE
    | SERVICE_ACCEPT_POWEREVENT
    | SERVICE_ACCEPT_TIMECHANGE;

/// Map a raw control to a [`ServiceControl`]. `Err(code)` is what the
/// handler returns without forwarding anything (`NO_ERROR` for
/// interrogate and undecodable events, `ERROR_CALL_NOT_IMPLEMENTED` for
/// controls the service does not handle).
///
/// # Safety
/// `data` must be what the SCM passed with `control` to a `HandlerEx`.
pub unsafe fn decode_control(
    control: u32,
    event_type: u32,
    data: *const core::ffi::c_void,
) -> Result<ServiceControl, u32> {
    Ok(match control {
        SERVICE_CONTROL_STOP => ServiceControl::Stop,
        SERVICE_CONTROL_SHUTDOWN => ServiceControl::Shutdown,
        SERVICE_CONTROL_PRESHUTDOWN => ServiceControl::Preshutdown,
        // SAFETY: for SESSIONCHANGE the SCM passes a WTSSESSION_NOTIFICATION.
        SERVICE_CONTROL_SESSIONCHANGE => {
            match unsafe { SessionEvent::from_raw(event_type, data) } {
                Some(e) => ServiceControl::SessionChange(e),
                None => return Err(NO_ERROR.0),
            }
        }
        SERVICE_CONTROL_POWEREVENT => ServiceControl::Power(PowerEvent::from_raw(event_type)),
        SERVICE_CONTROL_TIMECHANGE => ServiceControl::TimeChange,
        SERVICE_CONTROL_INTERROGATE => return Err(NO_ERROR.0),
        _ => return Err(ERROR_CALL_NOT_IMPLEMENTED.0),
    })
}

struct StatusInner {
    /// The SERVICE_STATUS_HANDLE (a pointer-sized value; not closed).
    handle: AtomicUsize,
    status: Mutex<SERVICE_STATUS>,
}

/// Reports the service's state to the SCM. Cheap to clone; usable from
/// any thread.
#[derive(Clone)]
pub struct StatusReporter(Arc<StatusInner>);

impl std::fmt::Debug for StatusReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StatusReporter").finish_non_exhaustive()
    }
}

impl StatusReporter {
    fn new() -> Self {
        StatusReporter(Arc::new(StatusInner {
            handle: AtomicUsize::new(0),
            status: Mutex::new(SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: SERVICE_START_PENDING,
                ..Default::default()
            }),
        }))
    }

    fn set(&self, f: impl FnOnce(&mut SERVICE_STATUS)) {
        let mut s = self.0.status.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
        let h = self.0.handle.load(Ordering::Acquire);
        if h != 0 {
            // SAFETY: `h` is the handle RegisterServiceCtrlHandlerExW returned
            // (valid for the process lifetime); `s` is a valid status.
            let _ = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(h as *mut _), &*s) };
        }
    }

    fn pending(&self, state: SERVICE_STATUS_CURRENT_STATE, wait_hint_ms: u32) {
        self.set(|s| {
            if s.dwCurrentState == state {
                s.dwCheckPoint += 1;
            } else {
                s.dwCurrentState = state;
                s.dwCheckPoint = 1;
            }
            s.dwControlsAccepted = 0;
            s.dwWaitHint = wait_hint_ms;
        });
    }

    /// Still starting: tell the SCM to wait up to `wait_hint_ms` more.
    /// Call periodically during a slow start (the SCM gives up on a
    /// service whose checkpoint stops advancing).
    pub fn start_pending(&self, wait_hint_ms: u32) {
        self.pending(SERVICE_START_PENDING, wait_hint_ms);
    }

    /// Started: report `SERVICE_RUNNING` and accept [`ACCEPTED_CONTROLS`].
    /// Until this is called the SCM sends no controls (and `sc start`
    /// waits).
    pub fn running(&self) {
        self.set(|s| {
            s.dwCurrentState = SERVICE_RUNNING;
            s.dwControlsAccepted = ACCEPTED_CONTROLS;
            s.dwCheckPoint = 0;
            s.dwWaitHint = 0;
        });
    }

    /// Stopping: tell the SCM to wait up to `wait_hint_ms` more.
    pub fn stop_pending(&self, wait_hint_ms: u32) {
        self.pending(SERVICE_STOP_PENDING, wait_hint_ms);
    }

    fn stopped(&self, exit_code: u32) {
        const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
        self.set(|s| {
            s.dwCurrentState = SERVICE_STOPPED;
            s.dwControlsAccepted = 0;
            s.dwCheckPoint = 0;
            s.dwWaitHint = 0;
            if exit_code == 0 {
                s.dwWin32ExitCode = 0;
                s.dwServiceSpecificExitCode = 0;
            } else {
                s.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
                s.dwServiceSpecificExitCode = exit_code;
            }
        });
    }
}

/// What the service main gets.
#[derive(Debug)]
pub struct ServiceContext {
    /// Controls from the SCM, in order. Disconnected once the service
    /// main returns.
    pub controls: Receiver<ServiceControl>,
    /// Report start/stop progress and `running()`.
    pub status: StatusReporter,
    /// Start parameters (`sc start FaroService a b`), without the service
    /// name. Configured command-line arguments are in `std::env::args()`.
    pub args: Vec<String>,
}

type ServiceMain = Box<dyn FnOnce(ServiceContext) -> u32 + Send>;

static SERVICE_MAIN: Mutex<Option<ServiceMain>> = Mutex::new(None);

struct HandlerCtx {
    tx: Sender<ServiceControl>,
    status: StatusReporter,
}

/// Run the service under the SCM: connects to the SCM's dispatcher (which
/// calls `main` on a new thread once the service starts), and returns when
/// the service has stopped.
///
/// `main` receives the control channel and the status reporter, must call
/// [`StatusReporter::running`] once started, and returns the exit code.
/// Zero is a clean stop; non-zero (or a panic, reported as 1) is a failure
/// that triggers the recovery actions.
///
/// If the process was not started by the SCM this fails at once with os
/// error [`ERROR_NOT_A_SERVICE`] (see [`is_not_a_service`]) without calling
/// `main`. Call it **once** per process (Windows refuses a second attempt,
/// even after a failed first one), from the main thread, before
/// starting a tokio runtime (`main` builds its own).
pub fn run_service_dispatcher<F>(main: F) -> std::io::Result<()>
where
    F: FnOnce(ServiceContext) -> u32 + Send + 'static,
{
    static ATTEMPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if ATTEMPTED.swap(true, Ordering::SeqCst) {
        // `StartServiceCtrlDispatcherW` may be called once per process; a
        // second call fails with ERROR_SERVICE_ALREADY_RUNNING even after
        // the first failed.
        return Err(std::io::Error::other(
            "run_service_dispatcher may be called only once per process",
        ));
    }
    *SERVICE_MAIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(main));
    let mut name = wide(layout::SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: a NULL-terminated table whose name buffer outlives the call
    // (which blocks until the service stops).
    let r = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(win_err);
    // Not started (or done): drop a main that never ran.
    SERVICE_MAIN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    r
}

/// Whether `e` from [`run_service_dispatcher`] means "not started by the
/// SCM" (run in the foreground instead).
pub fn is_not_a_service(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_NOT_A_SERVICE)
}

unsafe extern "system" fn service_main(argc: u32, argv: *mut PWSTR) {
    // SAFETY: the SCM passes `argc` valid NUL-terminated strings; argv[0]
    // is the service name.
    let args: Vec<String> = (1..argc as usize)
        .filter_map(|i| unsafe { (*argv.add(i)).to_string().ok() })
        .collect();
    let Some(main) = SERVICE_MAIN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    else {
        return;
    };
    let (tx, rx) = channel();
    let status = StatusReporter::new();
    // Leaked on purpose: the SCM may call the handler until the process
    // exits, and there is one per process.
    let ctx: &'static HandlerCtx = Box::leak(Box::new(HandlerCtx {
        tx,
        status: status.clone(),
    }));
    let name = wide(layout::SERVICE_NAME);
    // SAFETY: NUL-terminated name; `ctx` lives forever.
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR(name.as_ptr()),
            Some(control_handler),
            Some(std::ptr::from_ref(ctx).cast()),
        )
    } {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "RegisterServiceCtrlHandlerExW failed");
            return;
        }
    };
    status.0.handle.store(handle.0 as usize, Ordering::Release);
    status.start_pending(30_000);
    let ctx = ServiceContext {
        controls: rx,
        status: status.clone(),
        args,
    };
    let code = match std::panic::catch_unwind(AssertUnwindSafe(move || main(ctx))) {
        Ok(code) => code,
        Err(_) => {
            tracing::error!("the service main panicked");
            1
        }
    };
    status.stopped(code);
}

unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    data: *mut core::ffi::c_void,
    context: *mut core::ffi::c_void,
) -> u32 {
    // SAFETY: `context` is the leaked HandlerCtx registered with this handler.
    let ctx = unsafe { &*context.cast::<HandlerCtx>() };
    // SAFETY: `data` is what the SCM passed with `control`.
    match unsafe { decode_control(control, event_type, data) } {
        Ok(c) => {
            if matches!(
                c,
                ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown
            ) {
                ctx.status.stop_pending(STOP_WAIT_HINT_MS);
            }
            // The receiver is gone only after the main returned; then the
            // control no longer matters.
            let _ = ctx.tx.send(c);
            NO_ERROR.0
        }
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sddl_parses_and_restricts_users() {
        ServiceSd::from_sddl(SERVICE_SDDL).unwrap();
        // Interactive users: no stop (WP), pause (DT), change config (DC),
        // delete (SD), DACL/owner change (WD/WO), user controls (CR).
        for ace in SERVICE_SDDL
            .split(')')
            .filter(|a| a.ends_with(";;;IU") || a.ends_with(";;;SU"))
        {
            let rights = ace.split(';').nth(2).unwrap();
            let pairs: Vec<&str> = rights
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            for forbidden in ["WP", "DT", "DC", "SD", "WD", "WO", "CR", "RP"] {
                assert!(!pairs.contains(&forbidden), "{ace} grants {forbidden}");
            }
            assert!(pairs.contains(&"LC") && pairs.contains(&"LO"));
        }
    }

    /// The MSI's service DACL and the one `check-msi.ps1` expects are this
    /// module's [`SERVICE_SDDL`], not a second, looser copy.
    #[test]
    fn the_installer_uses_the_same_service_sddl() {
        let wxs = include_str!("../../../installers/windows/Faro.wxs");
        let check = include_str!("../../../installers/windows/check-msi.ps1");
        let quoted = format!("Sddl=\"{SERVICE_SDDL}\"");
        assert!(
            wxs.contains(&quoted),
            "Faro.wxs service PermissionEx differs"
        );
        assert!(
            check.contains(&format!("$ServiceSddl = '{SERVICE_SDDL}'")),
            "check-msi.ps1 expects another service DACL"
        );
    }

    #[test]
    fn controls_decode() {
        // SAFETY: no data needed for these controls.
        unsafe {
            assert_eq!(
                decode_control(SERVICE_CONTROL_STOP, 0, std::ptr::null()),
                Ok(ServiceControl::Stop)
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_PRESHUTDOWN, 0, std::ptr::null()),
                Ok(ServiceControl::Preshutdown)
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_SHUTDOWN, 0, std::ptr::null()),
                Ok(ServiceControl::Shutdown)
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_POWEREVENT, 4, std::ptr::null()),
                Ok(ServiceControl::Power(PowerEvent::Suspend))
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_POWEREVENT, 18, std::ptr::null()),
                Ok(ServiceControl::Power(PowerEvent::ResumeAutomatic))
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_TIMECHANGE, 0, std::ptr::null()),
                Ok(ServiceControl::TimeChange)
            );
            assert_eq!(
                decode_control(SERVICE_CONTROL_INTERROGATE, 0, std::ptr::null()),
                Err(0)
            );
            assert_eq!(decode_control(2 /* PAUSE */, 0, std::ptr::null()), Err(120));
            // A session change without its payload is not forwarded.
            assert_eq!(
                decode_control(SERVICE_CONTROL_SESSIONCHANGE, 5, std::ptr::null()),
                Err(0)
            );
            let n: [u32; 2] = [8, 2];
            assert_eq!(
                decode_control(SERVICE_CONTROL_SESSIONCHANGE, 7, n.as_ptr().cast()),
                Ok(ServiceControl::SessionChange(SessionEvent {
                    kind: crate::service::SessionEventKind::Lock,
                    session: 2
                }))
            );
        }
    }

    #[test]
    fn dispatcher_outside_the_scm_says_so() {
        let e = run_service_dispatcher(|_| panic!("must not run")).unwrap_err();
        assert!(is_not_a_service(&e), "{e}");
        // Windows allows one dispatcher connection attempt per process.
        let e = run_service_dispatcher(|_| 0).unwrap_err();
        assert!(!is_not_a_service(&e), "{e}");
    }

    #[test]
    fn status_reporter_without_handle_tracks_state() {
        let r = StatusReporter::new();
        r.start_pending(1000);
        r.start_pending(1000);
        assert_eq!(r.0.status.lock().unwrap().dwCheckPoint, 2);
        r.running();
        let s = *r.0.status.lock().unwrap();
        assert_eq!(s.dwCurrentState, SERVICE_RUNNING);
        assert_eq!(s.dwControlsAccepted, ACCEPTED_CONTROLS);
        r.stop_pending(5);
        assert_eq!(r.0.status.lock().unwrap().dwCheckPoint, 1);
        r.stopped(3);
        let s = *r.0.status.lock().unwrap();
        assert_eq!(s.dwCurrentState, SERVICE_STOPPED);
        assert_eq!((s.dwWin32ExitCode, s.dwServiceSpecificExitCode), (1066, 3));
    }

    #[test]
    fn service_state_queries_without_privilege() {
        assert_eq!(service_state("FaroNoSuchService-1b9e").unwrap(), None);
        // The event log service exists and runs on every Windows.
        assert_eq!(
            service_state("EventLog").unwrap(),
            Some(ServiceState::Running)
        );
    }

    #[test]
    fn install_needs_admin_and_round_trips_when_elevated() {
        let name = "FaroServiceTest";
        let bin = Path::new(r"C:\Windows\System32\cmd.exe");
        let args = vec!["/c".to_string(), "exit".to_string()];
        if !crate::acl::running_elevated() {
            let e = install_named(name, "Faro test", "test", bin, &args).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(5), "{e}");
            // Not installed: nothing to do, no privilege needed to find out.
            uninstall_named(name, Duration::from_secs(1)).unwrap();
            eprintln!("skipped the install round trip: not elevated");
            return;
        }
        install_named(name, "Faro test", "test", bin, &args).unwrap();
        // Installing again updates in place.
        install_named(name, "Faro test", "test", bin, &args).unwrap();
        assert_eq!(service_state(name).unwrap(), Some(ServiceState::Stopped));
        let out = std::process::Command::new("sc.exe")
            .args(["sdshow", name])
            .output()
            .unwrap();
        let sd = String::from_utf8_lossy(&out.stdout);
        assert!(sd.contains("(A;;CCLCSWLORC;;;IU)"), "{sd}");
        let out = std::process::Command::new("sc.exe")
            .args(["qfailure", name])
            .output()
            .unwrap();
        let q = String::from_utf8_lossy(&out.stdout);
        assert!(q.contains("86400") && q.contains("5000"), "{q}");
        uninstall_named(name, Duration::from_secs(10)).unwrap();
        assert_eq!(service_state(name).unwrap(), None);
        // Uninstalling what is not installed succeeds.
        uninstall_named(name, Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn relative_binaries_are_refused() {
        let e = install_named("x", "x", "x", Path::new("faro-service.exe"), &[]).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}
