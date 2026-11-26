//! Windows tamper and context signals (ARCHITECTURE.md §3.7), as polled by
//! the session agent.
//!
//! | Observation | Source | Signal |
//! |---|---|---|
//! | Running in a VM | BIOS strings in the registry, CPUID | `VirtualMachine` (context) |
//! | VPN tunnel up | `GetAdaptersAddresses` | `VpnActive` (context) |
//! | A large window excluded from capture | `GetWindowDisplayAffinity` | `WindowHiddenFromCapture { app }` (urgent) |
//!
//! There is no capture permission on Windows, so nothing like macOS's
//! `PermissionRevoked` comes from here. Service-side signals (service
//! stopped, agent killed, files changed, remote desktop) are the service's.
//!
//! Every signal is **edge-triggered**, as in `MacTamper`: reported once when
//! the condition starts, re-armed when it ends. The pure state machines are
//! [`edges`] and [`HiddenWindowTracker`]; [`WinTamper`] feeds them live
//! observations. Context signals start from "not active", so a VPN or VM
//! present at startup is reported once on the first poll of each agent run.
//!
//! # Virtual machines
//!
//! The CPUID "hypervisor present" bit alone can't be used: on Windows 11
//! with virtualization-based security (on by default on many machines) the
//! host itself runs on Hyper-V and sets it. So a machine counts as a VM
//! when its firmware names a virtual platform ([`bios_looks_virtual`]:
//! VMware, VirtualBox, QEMU/KVM, Parallels, Xen, Hyper-V's "Virtual
//! Machine", ...), or CPUID reports a hypervisor that is not Hyper-V, or
//! Hyper-V without the root partition's `CreatePartitions` privilege (a
//! Hyper-V guest; [`cpuid_says_guest`]).
//!
//! # VPN heuristic and its false positives
//!
//! An adapter that is up and has a routable unicast address counts as a
//! VPN when it is a PPP adapter (Windows' built-in IKEv2, SSTP, L2TP and
//! PPTP clients), a tunnel other than the IPv6 transition tunnels (Teredo,
//! ISATAP, 6to4), a "proprietary virtual" adapter (WireGuard, Wintun:
//! Tailscale, NordLynx and others), or an Ethernet adapter whose
//! description names a VPN driver (OpenVPN's TAP, AnyConnect, GlobalProtect,
//! FortiClient, ...). Hyper-V, WSL and Docker virtual switches are plain
//! Ethernet with no such description and don't count. Known false
//! positives, which is why the signal is context-only: zero-trust clients
//! (Cloudflare WARP, Zscaler) and mesh networks used for ordinary remote
//! access.
//!
//! # Windows excluded from capture
//!
//! `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` removes a window from
//! every capture (Faro's shows what is behind it); `WDA_MONITOR` blacks it
//! out. Either keeps its content from Faro. On each poll the agent lists
//! the top-level windows (`EnumWindows`) and reads, for each visible one,
//! its display affinity, owner pid and size: never its title or anything
//! drawn in it. Windows that are minimized or cloaked (on another virtual
//! desktop, or a suspended Store app) aren't on screen and don't count.
//!
//! The rules follow macOS's `hidden_windows`: a hidden window counts when it
//! is at least [`MIN_STRIP_SIDE`] pixels on its shorter side; an app is
//! reported when its counting hidden windows add up to [`MIN_HIDDEN_AREA`]
//! for [`FIRE_AFTER_POLLS`] polls in a row; each app is reported once, and
//! again only after [`REARM_AFTER_POLLS`] polls without a hidden window.
//! Sizes are in the agent's coordinate space (DPI-virtualized logical
//! pixels unless the agent is DPI aware), which is close to macOS points.
//!
//! Allowed: Windows' own binaries, an executable directly under
//! `%SystemRoot%\System32` or `%SystemRoot%\SystemApps` (owned by
//! TrustedInstaller; a standard user can't put a program there), which use
//! affinity for some of their own UI (credential prompts, for example). Not
//! allowed even there: hosts that run the member's own code (`rundll32`,
//! `mshta`, script hosts, PowerShell, `cmd`, `conhost`, `dllhost`,
//! `regsvr32`), since any DLL loaded into them can set the affinity. Faro's
//! own process is skipped. No third-party app is allowed: password
//! managers, DRM players and meeting tools that hide windows are reported
//! by name for allies to judge. An administrator could still place a
//! binary in System32; that is the same trust boundary as the rest of
//! Faro's self-protection on Windows.
//!
//! Unlike macOS, a reader needs no permission to see other processes'
//! affinity, so there is no "unreliable reading" case.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use faro_platform::{TamperSignal, TamperSignals};
use windows::core::{BOOL, HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, HWND, LPARAM, RECT};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::AF_UNSPEC;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowDisplayAffinity, GetWindowRect, IsIconic, IsWindowVisible,
};

use crate::foreground::{display_name, file_description, process_image_path, window_pid};

/// Hidden windows thinner than this (pixels) never count.
pub const MIN_STRIP_SIDE: i32 = 64;
/// Total hidden area (square pixels) at which an app is reported.
pub const MIN_HIDDEN_AREA: i64 = 200 * 200;
/// Polls in a row an app must hide windows before it is reported.
pub const FIRE_AFTER_POLLS: u32 = 2;
/// Polls without a hidden window before an app can be reported again (five
/// minutes at the agent's 2 s poll).
pub const REARM_AFTER_POLLS: u32 = 150;
/// Longest app name the signal carries, in characters.
pub const MAX_APP_LABEL: usize = 64;

/// `WDA_MONITOR`, `WDA_EXCLUDEFROMCAPTURE`.
pub const AFFINITY_MONITOR: u32 = 0x01;
pub const AFFINITY_EXCLUDE_FROM_CAPTURE: u32 = 0x11;

/// One poll's worth of context observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TamperObservation {
    pub virtual_machine: bool,
    pub vpn: bool,
}

/// Signals implied by moving from `prev` to `next` (rising edges only).
pub fn edges(prev: &TamperObservation, next: &TamperObservation) -> Vec<TamperSignal> {
    let mut out = Vec::new();
    if !prev.virtual_machine && next.virtual_machine {
        out.push(TamperSignal::VirtualMachine);
    }
    if !prev.vpn && next.vpn {
        out.push(TamperSignal::VpnActive);
    }
    out
}

// ---------------------------------------------------------------------------
// Virtual machines
// ---------------------------------------------------------------------------

/// Firmware vendor/product fragments of virtual platforms (lowercase).
const VIRTUAL_FIRMWARE: &[&str] = &[
    "vmware",
    "virtualbox",
    "innotek",
    "qemu",
    "kvm",
    "parallels",
    "xen",
    "bochs",
    "bhyve",
    "virtual machine",
    "amazon ec2",
    "google compute engine",
];

/// Whether the BIOS manufacturer or product name is a virtual platform.
pub fn bios_looks_virtual(manufacturer: &str, product: &str) -> bool {
    let m = manufacturer.to_ascii_lowercase();
    let p = product.to_ascii_lowercase();
    VIRTUAL_FIRMWARE
        .iter()
        .any(|k| m.contains(k) || p.contains(k))
}

fn registry_string(subkey: &str, value: &str) -> Option<String> {
    let (k, v) = (HSTRING::from(subkey), HSTRING::from(value));
    let mut buf = [0u16; 256];
    let mut bytes = std::mem::size_of_val(&buf) as u32;
    // SAFETY: `buf` is valid for `bytes` bytes; the strings are
    // NUL-terminated.
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if err.is_err() {
        return None;
    }
    let n = (bytes as usize / 2).min(buf.len());
    let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// `(SystemManufacturer, SystemProductName)` from the SMBIOS copy Windows
/// keeps under `HKLM\HARDWARE\DESCRIPTION\System\BIOS` (readable by users).
pub fn bios_strings() -> (String, String) {
    const KEY: &str = r"HARDWARE\DESCRIPTION\System\BIOS";
    (
        registry_string(KEY, "SystemManufacturer").unwrap_or_default(),
        registry_string(KEY, "SystemProductName").unwrap_or_default(),
    )
}

/// Decide from CPUID values whether we are a guest (see module docs).
/// `leaf1_ecx` is CPUID 1's ECX, `vendor` the 12-byte vendor of leaf
/// 0x40000000, `hv_features_ebx` Hyper-V's leaf 0x40000003 EBX.
pub fn guest_from_cpuid(leaf1_ecx: u32, vendor: &[u8; 12], hv_features_ebx: u32) -> bool {
    let hypervisor = leaf1_ecx & (1 << 31) != 0;
    if !hypervisor {
        return false;
    }
    if vendor == b"Microsoft Hv" {
        // CreatePartitions: only the root partition (the host) has it.
        return hv_features_ebx & 1 == 0;
    }
    true
}

/// CPUID's view (x86 only; `false` elsewhere).
pub fn cpuid_says_guest() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::__cpuid;
        #[allow(unused_unsafe)]
        // SAFETY: CPUID is available on every x86 CPU Windows 10 runs on;
        // hypervisor leaves are defined whenever the hypervisor bit is set
        // and are only read then.
        unsafe {
            let l1 = __cpuid(1);
            if l1.ecx & (1 << 31) == 0 {
                return false;
            }
            let v = __cpuid(0x4000_0000);
            let mut vendor = [0u8; 12];
            vendor[..4].copy_from_slice(&v.ebx.to_le_bytes());
            vendor[4..8].copy_from_slice(&v.ecx.to_le_bytes());
            vendor[8..].copy_from_slice(&v.edx.to_le_bytes());
            let features = if v.eax >= 0x4000_0003 {
                __cpuid(0x4000_0003).ebx
            } else {
                0
            };
            guest_from_cpuid(l1.ecx, &vendor, features)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        false
    }
}

/// Whether this machine is a virtual machine (see module docs).
pub fn running_in_vm() -> bool {
    let (m, p) = bios_strings();
    bios_looks_virtual(&m, &p) || cpuid_says_guest()
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

/// `IF_TYPE_*` values used by the heuristic.
pub const IF_TYPE_ETHERNET: u32 = 6;
pub const IF_TYPE_PPP: u32 = 23;
pub const IF_TYPE_PROP_VIRTUAL: u32 = 53;
pub const IF_TYPE_TUNNEL: u32 = 131;
/// `TUNNEL_TYPE_*` of the IPv6 transition tunnels Windows keeps around.
const TRANSITION_TUNNELS: &[i32] = &[
    2,  /* 6over4 */
    11, /* 6to4 */
    13, /* ISATAP */
    14, /* Teredo */
];

/// Adapter description fragments of Ethernet-type VPN drivers (lowercase).
const VPN_DRIVERS: &[&str] = &[
    "tap-windows",
    "tap-win32",
    "openvpn",
    "wireguard",
    "wintun",
    "anyconnect",
    "pangp",
    "globalprotect",
    "fortinet",
    "forticlient",
    "juniper",
    "pulse secure",
    "sonicwall",
    "checkpoint",
    "check point",
    "vpn",
];

/// One network adapter, as `GetAdaptersAddresses` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    pub if_type: u32,
    pub up: bool,
    pub tunnel_type: i32,
    /// The driver's description (not the user-chosen friendly name).
    pub description: String,
    pub addrs: Vec<IpAddr>,
}

fn is_routable(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !v6.is_unspecified() && !v6.is_loopback() && !link_local
        }
    }
}

/// Whether one adapter looks like a VPN tunnel (see module docs).
pub fn is_vpn_adapter(a: &AdapterInfo) -> bool {
    if !a.up || !a.addrs.iter().any(is_routable) {
        return false;
    }
    match a.if_type {
        IF_TYPE_PPP | IF_TYPE_PROP_VIRTUAL => true,
        IF_TYPE_TUNNEL => !TRANSITION_TUNNELS.contains(&a.tunnel_type),
        IF_TYPE_ETHERNET => {
            let d = a.description.to_ascii_lowercase();
            VPN_DRIVERS.iter().any(|k| d.contains(k))
        }
        _ => false,
    }
}

/// Pure VPN heuristic over an adapter snapshot.
pub fn vpn_active(adapters: &[AdapterInfo]) -> bool {
    adapters.iter().any(is_vpn_adapter)
}

/// # Safety
/// `sa` must be null or point to `len` readable bytes of a SOCKADDR.
unsafe fn sockaddr_ip(sa: *const u8, len: usize) -> Option<IpAddr> {
    if sa.is_null() || len < 2 {
        return None;
    }
    // SAFETY: `len` bytes are readable per the contract.
    let bytes = unsafe { std::slice::from_raw_parts(sa, len) };
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    match family {
        2 if len >= 8 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[4], bytes[5], bytes[6], bytes[7],
        ))),
        23 if len >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&bytes[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(a)))
        }
        _ => None,
    }
}

/// Snapshot of every adapter.
pub fn adapters() -> std::io::Result<Vec<AdapterInfo>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut buf: Vec<u64>;
    let mut tries = 0;
    loop {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: `buf` holds `size` bytes, as passed.
        let err = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if err == 0 {
            break;
        }
        tries += 1;
        if err != ERROR_BUFFER_OVERFLOW.0 || tries > 3 {
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
    }
    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses wrote into `buf`,
        // valid while `buf` lives.
        let a = unsafe { &*cur };
        let description = if a.Description.is_null() {
            String::new()
        } else {
            // SAFETY: a NUL-terminated string inside `buf`.
            unsafe { a.Description.to_string() }.unwrap_or_default()
        };
        let mut addrs = Vec::new();
        let mut u = a.FirstUnicastAddress;
        while !u.is_null() {
            // SAFETY: a node of the unicast list inside `buf`.
            let ua = unsafe { &*u };
            // SAFETY: the SOCKET_ADDRESS describes its own length.
            if let Some(ip) = unsafe {
                sockaddr_ip(
                    ua.Address.lpSockaddr as *const u8,
                    usize::try_from(ua.Address.iSockaddrLength).unwrap_or(0),
                )
            } {
                addrs.push(ip);
            }
            u = ua.Next;
        }
        out.push(AdapterInfo {
            if_type: a.IfType,
            up: a.OperStatus == IfOperStatusUp,
            tunnel_type: a.TunnelType.0,
            description,
            addrs,
        });
        cur = a.Next;
    }
    Ok(out)
}

/// Take a live context observation.
pub fn observe() -> TamperObservation {
    TamperObservation {
        virtual_machine: running_in_vm(),
        // If adapters can't be read, keep "no VPN" rather than flapping.
        vpn: adapters().map(|a| vpn_active(&a)).unwrap_or(false),
    }
}

// ---------------------------------------------------------------------------
// Windows excluded from capture
// ---------------------------------------------------------------------------

/// One visible top-level window. No title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowInfo {
    pub pid: u32,
    /// `GetWindowDisplayAffinity`.
    pub affinity: u32,
    pub width: i32,
    pub height: i32,
}

impl WindowInfo {
    pub fn is_hidden(&self) -> bool {
        self.affinity == AFFINITY_EXCLUDE_FROM_CAPTURE || self.affinity == AFFINITY_MONITOR
    }

    fn counts(&self) -> bool {
        self.pid != 0 && self.width.min(self.height) >= MIN_STRIP_SIDE
    }
}

/// The process that owns a hidden window.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Process {
    pub exe_path: Option<String>,
    /// Display name (the version resource's `FileDescription`).
    pub name: Option<String>,
}

/// An app with enough hidden window area this poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenApp {
    /// Stable identity: executable path (lowercase), else pid.
    pub key: String,
    /// What the signal says.
    pub name: String,
}

/// Executables in the system folders that run the member's code.
const RUNS_USER_CODE: &[&str] = &[
    "rundll32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "conhost.exe",
    "dllhost.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "wmic.exe",
    "forfiles.exe",
    "msbuild.exe",
];

/// Whether `exe` is one of Windows' own binaries that may keep windows out
/// of captures (see module docs). `system_root` is `%SystemRoot%`.
pub fn is_allowed_os_process(exe: &str, system_root: &str) -> bool {
    let exe = exe.to_ascii_lowercase().replace('/', "\\");
    if exe.contains("\\..\\") || exe.contains("\\.\\") || exe.starts_with("\\\\") {
        return false;
    }
    let root = system_root
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase();
    if root.is_empty() {
        return false;
    }
    let in_folder = ["system32", "systemapps"]
        .iter()
        .any(|f| exe.starts_with(&format!("{root}\\{f}\\")));
    if !in_folder {
        return false;
    }
    let file = exe.rsplit('\\').next().unwrap_or("");
    !RUNS_USER_CODE.contains(&file)
}

/// Control characters removed, trimmed, at most [`MAX_APP_LABEL`] chars.
pub fn app_label(name: &str) -> String {
    let cut: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_APP_LABEL)
        .collect();
    cut.trim_end().to_owned()
}

fn hidden_app(pid: u32, p: &Process) -> HiddenApp {
    let key = p
        .exe_path
        .as_deref()
        .filter(|k| !k.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| format!("pid:{pid}"));
    let file = p
        .exe_path
        .as_deref()
        .and_then(|e| e.rsplit(['\\', '/']).next())
        .map(app_label)
        .filter(|s| !s.is_empty());
    let name = p
        .name
        .as_deref()
        .map(app_label)
        .filter(|s| !s.is_empty())
        .or(file)
        .unwrap_or_else(|| "An unnamed app".to_owned());
    HiddenApp { key, name }
}

/// Apps hiding enough window area in `windows`, skipping `own_pid` and
/// Windows' own binaries. `resolve` is only called for pids that own a
/// counting hidden window.
pub fn read(
    windows: &[WindowInfo],
    own_pid: u32,
    system_root: &str,
    mut resolve: impl FnMut(u32) -> Process,
) -> Vec<HiddenApp> {
    let mut per_pid: Vec<(u32, i64)> = Vec::new();
    for w in windows {
        if !w.is_hidden() || w.pid == own_pid || !w.counts() {
            continue;
        }
        let area = i64::from(w.width) * i64::from(w.height);
        match per_pid.iter_mut().find(|(pid, _)| *pid == w.pid) {
            Some(e) => e.1 += area,
            None => per_pid.push((w.pid, area)),
        }
    }
    // Several processes of one app (same executable) add up.
    let mut per_app: Vec<(HiddenApp, i64)> = Vec::new();
    for (pid, area) in per_pid {
        let p = resolve(pid);
        if p.exe_path
            .as_deref()
            .is_some_and(|e| is_allowed_os_process(e, system_root))
        {
            continue;
        }
        let app = hidden_app(pid, &p);
        match per_app.iter_mut().find(|(a, _)| a.key == app.key) {
            Some(e) => e.1 += area,
            None => per_app.push((app, area)),
        }
    }
    per_app
        .into_iter()
        .filter(|(_, area)| *area >= MIN_HIDDEN_AREA)
        .map(|(app, _)| app)
        .collect()
}

#[derive(Debug)]
struct AppState {
    seen: u32,
    absent: u32,
    reported: bool,
}

/// Turns readings into edge-triggered signals (see module docs).
#[derive(Debug, Default)]
pub struct HiddenWindowTracker {
    apps: HashMap<String, AppState>,
}

impl HiddenWindowTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one poll's reading.
    pub fn observe(&mut self, apps: &[HiddenApp]) -> Vec<TamperSignal> {
        let mut out = Vec::new();
        for app in apps {
            let s = self.apps.entry(app.key.clone()).or_insert(AppState {
                seen: 0,
                absent: 0,
                reported: false,
            });
            s.seen = s.seen.saturating_add(1);
            s.absent = 0;
            if !s.reported && s.seen >= FIRE_AFTER_POLLS {
                s.reported = true;
                out.push(TamperSignal::WindowHiddenFromCapture {
                    app: app.name.clone(),
                });
            }
        }
        self.apps.retain(|key, s| {
            if apps.iter().any(|a| &a.key == key) {
                return true;
            }
            s.seen = 0;
            s.absent = s.absent.saturating_add(1);
            s.reported && s.absent < REARM_AFTER_POLLS
        });
        out
    }
}

fn is_cloaked(hwnd: HWND) -> bool {
    let mut cloaked = 0u32;
    // SAFETY: a DWORD out-buffer of the size passed.
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            (&mut cloaked as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    }
    .is_ok()
        && cloaked != 0
}

/// Read one window, if it is on screen.
pub fn window_info(hwnd: HWND) -> Option<WindowInfo> {
    // SAFETY: plain queries on a window handle; a stale one just fails.
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() || IsIconic(hwnd).as_bool() {
            return None;
        }
    }
    if is_cloaked(hwnd) {
        return None;
    }
    let mut r = RECT::default();
    // SAFETY: valid out-pointer.
    unsafe { GetWindowRect(hwnd, &mut r) }.ok()?;
    let mut affinity = 0u32;
    // SAFETY: valid out-pointer.
    unsafe { GetWindowDisplayAffinity(hwnd, &mut affinity) }.ok()?;
    Some(WindowInfo {
        pid: window_pid(hwnd)?,
        affinity,
        width: r.right.saturating_sub(r.left),
        height: r.bottom.saturating_sub(r.top),
    })
}

unsafe extern "system" fn collect_window(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the `&mut Vec<WindowInfo>` passed by
    // `on_screen_windows`, alive for the duration of EnumWindows.
    let out = unsafe { &mut *(data.0 as *mut Vec<WindowInfo>) };
    if let Some(w) = window_info(hwnd) {
        out.push(w);
    }
    true.into()
}

/// Every visible top-level window, front to back. Titles are not read.
pub fn on_screen_windows() -> Vec<WindowInfo> {
    let mut out: Vec<WindowInfo> = Vec::new();
    // SAFETY: the callback only touches `out` through the LPARAM.
    let _ = unsafe {
        EnumWindows(
            Some(collect_window),
            LPARAM(&mut out as *mut Vec<WindowInfo> as isize),
        )
    };
    out
}

/// Look up the owner of a hidden window.
pub fn resolve_process(pid: u32) -> Process {
    let Some(path) = process_image_path(pid) else {
        return Process::default();
    };
    let name = display_name(file_description(&path), &path);
    Process {
        exe_path: Some(path.to_string_lossy().into_owned()),
        name,
    }
}

/// `%SystemRoot%`, normally `C:\Windows`.
pub fn system_root() -> String {
    std::env::var("SystemRoot")
        .ok()
        .filter(|s| Path::new(s).is_absolute())
        .unwrap_or_else(|| r"C:\Windows".to_owned())
}

/// One live reading of hidden-window apps.
pub fn read_now() -> Vec<HiddenApp> {
    read(
        &on_screen_windows(),
        std::process::id(),
        &system_root(),
        resolve_process,
    )
}

// ---------------------------------------------------------------------------
// The trait implementation
// ---------------------------------------------------------------------------

/// [`TamperSignals`] for Windows.
#[derive(Debug, Default)]
pub struct WinTamper {
    last: TamperObservation,
    hidden: HiddenWindowTracker,
}

impl WinTamper {
    /// Context signals start from "not active" (see module docs).
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed an observation and return the signals it triggers.
    pub fn observe(&mut self, next: TamperObservation) -> Vec<TamperSignal> {
        let signals = edges(&self.last, &next);
        self.last = next;
        signals
    }
}

impl TamperSignals for WinTamper {
    fn poll(&mut self) -> Vec<TamperSignal> {
        let mut out = self.observe(observe());
        out.extend(self.hidden.observe(&read_now()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_signals_rise_only() {
        let mut t = WinTamper::new();
        let on = TamperObservation {
            virtual_machine: true,
            vpn: true,
        };
        assert_eq!(
            t.observe(on),
            vec![TamperSignal::VirtualMachine, TamperSignal::VpnActive]
        );
        assert!(t.observe(on).is_empty(), "not every poll");
        let vpn_down = TamperObservation { vpn: false, ..on };
        assert!(t.observe(vpn_down).is_empty(), "down is silent");
        assert_eq!(t.observe(on), vec![TamperSignal::VpnActive], "re-armed");
        assert!(TamperSignal::VirtualMachine.is_context_only());
    }

    #[test]
    fn firmware_strings() {
        assert!(bios_looks_virtual("VMware, Inc.", "VMware7,1"));
        assert!(bios_looks_virtual("innotek GmbH", "VirtualBox"));
        assert!(bios_looks_virtual("QEMU", "Standard PC (Q35 + ICH9, 2009)"));
        assert!(bios_looks_virtual(
            "Microsoft Corporation",
            "Virtual Machine"
        ));
        assert!(bios_looks_virtual(
            "Parallels Software International Inc.",
            "Parallels ARM Virtual Machine"
        ));
        assert!(!bios_looks_virtual(
            "Microsoft Corporation",
            "Surface Laptop 5"
        ));
        assert!(!bios_looks_virtual("Dell Inc.", "XPS 13 9310"));
        assert!(!bios_looks_virtual("", ""));
    }

    #[test]
    fn cpuid_rules() {
        let hv = 1 << 31;
        assert!(!guest_from_cpuid(0, b"Microsoft Hv", 0), "no hypervisor");
        assert!(guest_from_cpuid(hv, b"VMwareVMware", 0));
        assert!(guest_from_cpuid(hv, b"KVMKVMKVM\0\0\0", 0));
        assert!(guest_from_cpuid(hv, b"Microsoft Hv", 0), "Hyper-V guest");
        assert!(
            !guest_from_cpuid(hv, b"Microsoft Hv", 1),
            "VBS host (root partition)"
        );
    }

    fn adapter(if_type: u32, up: bool, desc: &str, addr: &str) -> AdapterInfo {
        AdapterInfo {
            if_type,
            up,
            tunnel_type: 0,
            description: desc.into(),
            addrs: vec![addr.parse().unwrap()],
        }
    }

    #[test]
    fn vpn_heuristic() {
        let ordinary = vec![
            adapter(
                IF_TYPE_ETHERNET,
                true,
                "Intel(R) Ethernet Connection",
                "192.168.1.20",
            ),
            adapter(71, true, "Intel(R) Wi-Fi 6E AX211 160MHz", "10.0.0.5"),
            adapter(
                IF_TYPE_ETHERNET,
                true,
                "Hyper-V Virtual Ethernet Adapter",
                "172.20.0.1",
            ),
            adapter(24, true, "Software Loopback Interface 1", "127.0.0.1"),
            AdapterInfo {
                tunnel_type: 14,
                ..adapter(
                    IF_TYPE_TUNNEL,
                    true,
                    "Teredo Tunneling Pseudo-Interface",
                    "2001:0:1::1",
                )
            },
        ];
        assert!(!vpn_active(&ordinary));
        for a in [
            adapter(IF_TYPE_PPP, true, "WAN Miniport (IKEv2)", "10.8.0.2"),
            adapter(IF_TYPE_PROP_VIRTUAL, true, "WireGuard Tunnel", "10.64.0.2"),
            adapter(
                IF_TYPE_PROP_VIRTUAL,
                true,
                "Tailscale Tunnel",
                "100.101.102.103",
            ),
            adapter(IF_TYPE_ETHERNET, true, "TAP-Windows Adapter V9", "10.9.0.6"),
            adapter(
                IF_TYPE_ETHERNET,
                true,
                "Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter",
                "10.1.2.3",
            ),
            adapter(IF_TYPE_TUNNEL, true, "IP-HTTPS", "fd00::5"),
        ] {
            assert!(is_vpn_adapter(&a), "{}", a.description);
        }
        assert!(!is_vpn_adapter(&adapter(
            IF_TYPE_PPP,
            false,
            "down",
            "10.8.0.2"
        )));
        assert!(!is_vpn_adapter(&adapter(
            IF_TYPE_PROP_VIRTUAL,
            true,
            "link-local",
            "169.254.3.4"
        )));
        assert!(!is_vpn_adapter(&adapter(
            IF_TYPE_PROP_VIRTUAL,
            true,
            "ll6",
            "fe80::1"
        )));
    }

    #[test]
    fn sockaddr_parsing() {
        let mut v4 = [0u8; 16];
        v4[0] = 2;
        v4[4..8].copy_from_slice(&[10, 1, 2, 3]);
        // SAFETY: a 16-byte buffer.
        assert_eq!(
            unsafe { sockaddr_ip(v4.as_ptr(), 16) },
            Some("10.1.2.3".parse().unwrap())
        );
        let mut v6 = [0u8; 28];
        v6[0] = 23;
        v6[8] = 0xfd;
        v6[23] = 1;
        // SAFETY: a 28-byte buffer.
        assert_eq!(
            unsafe { sockaddr_ip(v6.as_ptr(), 28) },
            Some("fd00::1".parse().unwrap())
        );
        // SAFETY: null is allowed.
        assert_eq!(unsafe { sockaddr_ip(std::ptr::null(), 0) }, None);
    }

    const ROOT: &str = r"C:\Windows";

    #[test]
    fn os_allowlist() {
        assert!(is_allowed_os_process(
            r"C:\Windows\System32\CredentialUIBroker.exe",
            ROOT
        ));
        assert!(is_allowed_os_process(
            r"c:\windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(
            r"C:\Windows\System32\rundll32.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(r"C:\Windows\explorer.exe", ROOT));
        assert!(!is_allowed_os_process(
            r"C:\Windows\System32\..\Temp\x.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(r"C:\Users\sam\System32\x.exe", ROOT));
        assert!(!is_allowed_os_process(
            r"C:\Program Files\Viewer\viewer.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(
            r"\\server\c$\Windows\System32\x.exe",
            ROOT
        ));
        assert!(!is_allowed_os_process(r"C:\Windows\System32\x.exe", ""));
    }

    fn win(pid: u32, affinity: u32, w: i32, h: i32) -> WindowInfo {
        WindowInfo {
            pid,
            affinity,
            width: w,
            height: h,
        }
    }

    fn resolver(pid: u32) -> Process {
        match pid {
            10 => Process {
                exe_path: Some(r"C:\Program Files\Viewer\viewer.exe".into()),
                name: Some("Viewer".into()),
            },
            11 => Process {
                exe_path: Some(r"C:\Program Files\Viewer\VIEWER.exe".into()),
                name: Some("Viewer".into()),
            },
            20 => Process {
                exe_path: Some(r"C:\Windows\System32\consent.exe".into()),
                name: Some("Consent UI".into()),
            },
            30 => Process {
                exe_path: Some(r"C:\Tools\nameless.exe".into()),
                name: None,
            },
            _ => Process::default(),
        }
    }

    #[test]
    fn reading_rules() {
        let ex = AFFINITY_EXCLUDE_FROM_CAPTURE;
        let windows = vec![
            win(10, ex, 300, 200),               // 60 000: counts
            win(20, ex, 800, 600),               // OS process: allowed
            win(30, AFFINITY_MONITOR, 50, 2000), // a strip
            win(40, 0, 1000, 1000),              // not hidden
            win(99, ex, 1000, 1000),             // ourselves
            win(30, ex, 150, 150),               // 22 500: too small alone
        ];
        let apps = read(&windows, 99, ROOT, resolver);
        assert_eq!(
            apps,
            vec![HiddenApp {
                key: r"c:\program files\viewer\viewer.exe".into(),
                name: "Viewer".into()
            }]
        );
        // Two processes of one app add up; a nameless app uses its file.
        let windows = vec![
            win(10, ex, 150, 150),
            win(11, ex, 150, 150),
            win(30, ex, 210, 210),
        ];
        let apps = read(&windows, 99, ROOT, resolver);
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].name, "Viewer");
        assert_eq!(apps[1].name, "nameless.exe");
        // An unresolvable pid still counts, by pid.
        let apps = read(&[win(77, ex, 500, 500)], 99, ROOT, resolver);
        assert_eq!(apps[0].key, "pid:77");
        assert_eq!(apps[0].name, "An unnamed app");
    }

    #[test]
    fn tracker_fires_once_and_rearms() {
        let viewer = HiddenApp {
            key: "v".into(),
            name: "Viewer".into(),
        };
        let mut t = HiddenWindowTracker::new();
        assert!(
            t.observe(std::slice::from_ref(&viewer)).is_empty(),
            "first poll waits"
        );
        assert_eq!(
            t.observe(std::slice::from_ref(&viewer)),
            vec![TamperSignal::WindowHiddenFromCapture {
                app: "Viewer".into()
            }]
        );
        assert!(t.observe(std::slice::from_ref(&viewer)).is_empty(), "once");
        for _ in 0..REARM_AFTER_POLLS - 1 {
            assert!(t.observe(&[]).is_empty());
        }
        // Back before re-arming: still silent.
        assert!(t.observe(std::slice::from_ref(&viewer)).is_empty());
        assert!(t.observe(std::slice::from_ref(&viewer)).is_empty());
        for _ in 0..REARM_AFTER_POLLS {
            t.observe(&[]);
        }
        assert!(t.observe(std::slice::from_ref(&viewer)).is_empty());
        assert_eq!(
            t.observe(std::slice::from_ref(&viewer)).len(),
            1,
            "re-armed"
        );
    }

    #[test]
    fn labels_are_clean() {
        assert_eq!(app_label("  Vie\u{7}wer \n"), "Viewer");
        assert_eq!(app_label(&"x".repeat(100)).chars().count(), MAX_APP_LABEL);
    }

    #[test]
    fn live_probes_do_not_panic() {
        let a = adapters().expect("GetAdaptersAddresses works");
        assert!(!a.is_empty(), "loopback is always listed");
        let _ = vpn_active(&a);
        let _ = running_in_vm();
        let _ = on_screen_windows();
        let mut t = WinTamper::new();
        let first = t.poll();
        for s in &first {
            assert!(
                s.is_context_only() || matches!(s, TamperSignal::WindowHiddenFromCapture { .. }),
                "{s:?}"
            );
        }
        let again = t.poll();
        assert!(
            again
                .iter()
                .all(|s| !first.contains(s) || !s.is_context_only()),
            "context signals are edge-triggered"
        );
    }
}
