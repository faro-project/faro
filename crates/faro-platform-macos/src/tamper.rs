//! macOS tamper and context signals (ARCHITECTURE.md §3.7).
//!
//! | Observation | Source | Signal |
//! |---|---|---|
//! | Screen Recording revoked | `CGPreflightScreenCaptureAccess` | `PermissionRevoked { "screen_recording" }` (urgent) |
//! | Accessibility revoked | `AXIsProcessTrusted` | `PermissionRevoked { "accessibility" }` (urgent) |
//! | Running in a VM | `sysctl kern.hv_vmm_present` | `VirtualMachine` (context) |
//! | VPN tunnel up | `getifaddrs` | `VpnActive` (context) |
//! | A large window hidden from capture | `CGWindowListCopyWindowInfo` | `WindowHiddenFromCapture { app }` (urgent), see [`crate::hidden_windows`] |
//!
//! Every signal is **edge-triggered**: it is reported once when the
//! condition starts, not on every poll, and re-arms when the condition ends.
//! The pure state machine is [`edges`]; [`MacTamper`] feeds it live
//! observations.
//!
//! Baselines:
//! * Permissions are sampled when [`MacTamper`] is constructed, so a
//!   revocation between construction and the first poll is still caught. A
//!   permission that was already missing at startup is *not* reported as a
//!   revocation; the agent reports it through `permission_state()`, which the
//!   core checks every tick (§3.3).
//! * Context signals start from "not active", so a VPN or VM present at
//!   startup is reported once on the first poll of each agent run.
//!
//! # VPN heuristic and its false positives
//!
//! macOS VPNs (IKEv2/IPsec via NetworkExtension, WireGuard, OpenVPN,
//! Tailscale, …) surface as `utun*`, `ipsec*` or (L2TP/PPTP) `ppp*`
//! interfaces. But macOS itself keeps several `utun` interfaces up at all
//! times for iCloud, Continuity and Handoff; those carry only IPv6
//! link-local (`fe80::/10`) addresses. We therefore count a tunnel only when
//! it is up and running **and** has an IPv4 address or a non-link-local
//! IPv6 address. Known remaining false positives, which is why the signal
//! is context-only: iCloud Private Relay or "Limit IP Address Tracking"
//! configurations that install a tunnel, corporate zero-trust / SASE
//! clients (Cloudflare WARP, Zscaler), mesh networks (Tailscale, ZeroTier)
//! used for ordinary remote access, and developer tools that create tunnels.

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use faro_platform::{PermissionState, TamperSignal, TamperSignals};

use crate::capture::screen_capture_permission;
use crate::foreground::accessibility_trusted;
use crate::hidden_windows::{self, HiddenWindowTracker};

/// Permission names used in `PermissionRevoked`.
pub const PERMISSION_SCREEN_RECORDING: &str = "screen_recording";
pub const PERMISSION_ACCESSIBILITY: &str = "accessibility";

/// One poll's worth of raw observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TamperObservation {
    pub screen_recording: bool,
    pub accessibility: bool,
    pub virtual_machine: bool,
    pub vpn: bool,
}

/// Signals implied by moving from `prev` to `next` (rising edges only,
/// except permissions, which fire on the granted → missing edge).
pub fn edges(prev: &TamperObservation, next: &TamperObservation) -> Vec<TamperSignal> {
    let mut out = Vec::new();
    if prev.screen_recording && !next.screen_recording {
        out.push(TamperSignal::PermissionRevoked {
            permission: PERMISSION_SCREEN_RECORDING.into(),
            never_granted: false,
        });
    }
    if prev.accessibility && !next.accessibility {
        out.push(TamperSignal::PermissionRevoked {
            permission: PERMISSION_ACCESSIBILITY.into(),
            never_granted: false,
        });
    }
    if !prev.virtual_machine && next.virtual_machine {
        out.push(TamperSignal::VirtualMachine);
    }
    if !prev.vpn && next.vpn {
        out.push(TamperSignal::VpnActive);
    }
    out
}

/// Whether macOS reports running under a hypervisor (`kern.hv_vmm_present`).
/// Absent sysctl (older systems) or any error reads as "not a VM".
pub fn running_in_vm() -> bool {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL-terminated; `value`/`len` describe a valid,
    // correctly sized out-buffer; no new value is written.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.hv_vmm_present".as_ptr(),
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    rc == 0 && len == std::mem::size_of::<libc::c_int>() && value != 0
}

/// One address of one interface, as reported by `getifaddrs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddr {
    pub name: String,
    pub flags: u32,
    pub addr: Option<IpAddr>,
}

/// Snapshot of all interface addresses.
pub fn interface_addrs() -> std::io::Result<Vec<InterfaceAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer; on success we own the list and
    // free it exactly once below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list returned by getifaddrs, which
        // stays valid until freeifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated C string owned by the list.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: ifa_addr is null or points to a sockaddr owned by the
            // list, sized for its family.
            let addr = unsafe { sockaddr_to_ip(ifa.ifa_addr) };
            out.push(InterfaceAddr {
                name,
                flags: ifa.ifa_flags,
                addr,
            });
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// # Safety
/// `sa` must be null or point to a valid `sockaddr` whose allocation is
/// large enough for its `sa_family`.
unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: non-null and valid per the contract; read_unaligned avoids
    // assuming alignment of OS-provided buffers.
    let family = unsafe { std::ptr::addr_of!((*sa).sa_family).read_unaligned() };
    match i32::from(family) {
        libc::AF_INET => {
            // SAFETY: family AF_INET guarantees a sockaddr_in.
            let sin = unsafe { sa.cast::<libc::sockaddr_in>().read_unaligned() };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: family AF_INET6 guarantees a sockaddr_in6.
            let sin6 = unsafe { sa.cast::<libc::sockaddr_in6>().read_unaligned() };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn is_tunnel_name(name: &str) -> bool {
    ["utun", "ipsec", "ppp"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Addresses that indicate a routed tunnel (see module docs).
fn is_routable_tunnel_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            let link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            !v6.is_unspecified() && !v6.is_loopback() && !link_local
        }
    }
}

/// Pure VPN heuristic over an interface snapshot (see module docs).
pub fn vpn_active(addrs: &[InterfaceAddr]) -> bool {
    let up_running = (libc::IFF_UP | libc::IFF_RUNNING) as u32;
    addrs.iter().any(|a| {
        is_tunnel_name(&a.name)
            && a.flags & up_running == up_running
            && a.addr.as_ref().is_some_and(is_routable_tunnel_addr)
    })
}

/// Take a live observation.
pub fn observe() -> TamperObservation {
    TamperObservation {
        screen_recording: screen_capture_permission() == PermissionState::Granted,
        accessibility: accessibility_trusted(),
        virtual_machine: running_in_vm(),
        // If the interface list cannot be read, keep "no VPN" rather than
        // flapping; this is a context signal only.
        vpn: interface_addrs().map(|a| vpn_active(&a)).unwrap_or(false),
    }
}

/// [`TamperSignals`] for macOS.
#[derive(Debug)]
pub struct MacTamper {
    last: TamperObservation,
    hidden: HiddenWindowTracker,
}

impl Default for MacTamper {
    fn default() -> Self {
        Self::new()
    }
}

impl MacTamper {
    /// Samples the permission baseline now (see module docs).
    pub fn new() -> Self {
        let now = observe();
        MacTamper {
            last: TamperObservation {
                virtual_machine: false,
                vpn: false,
                ..now
            },
            hidden: HiddenWindowTracker::new(),
        }
    }

    /// Feed an observation and return the signals it triggers.
    pub fn observe(&mut self, next: TamperObservation) -> Vec<TamperSignal> {
        let signals = edges(&self.last, &next);
        self.last = next;
        signals
    }
}

impl TamperSignals for MacTamper {
    fn poll(&mut self) -> Vec<TamperSignal> {
        let now = observe();
        let mut out = self.observe(now);
        // Without Screen Recording every other window reads "not shared"
        // (see `hidden_windows`), so only read with it.
        if now.screen_recording {
            out.extend(self.hidden.observe(&hidden_windows::read_now()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(sr: bool, ax: bool, vm: bool, vpn: bool) -> TamperObservation {
        TamperObservation {
            screen_recording: sr,
            accessibility: ax,
            virtual_machine: vm,
            vpn,
        }
    }

    fn revoked(p: &str) -> TamperSignal {
        TamperSignal::PermissionRevoked {
            permission: p.into(),
            never_granted: false,
        }
    }

    #[test]
    fn permission_revocation_fires_once_and_rearms() {
        let mut t = MacTamper {
            last: obs(true, true, false, false),
            hidden: HiddenWindowTracker::new(),
        };
        assert_eq!(
            t.observe(obs(false, true, false, false)),
            vec![revoked(PERMISSION_SCREEN_RECORDING)]
        );
        assert!(
            t.observe(obs(false, true, false, false)).is_empty(),
            "not every poll"
        );
        assert!(
            t.observe(obs(true, true, false, false)).is_empty(),
            "re-grant is silent"
        );
        assert_eq!(
            t.observe(obs(false, false, false, false)),
            vec![
                revoked(PERMISSION_SCREEN_RECORDING),
                revoked(PERMISSION_ACCESSIBILITY)
            ]
        );
    }

    #[test]
    fn never_granted_is_not_a_revocation() {
        let mut t = MacTamper {
            last: obs(false, false, false, false),
            hidden: HiddenWindowTracker::new(),
        };
        assert!(t.observe(obs(false, false, false, false)).is_empty());
    }

    #[test]
    fn context_signals_rise_only() {
        let mut t = MacTamper {
            last: obs(true, false, false, false),
            hidden: HiddenWindowTracker::new(),
        };
        assert_eq!(
            t.observe(obs(true, false, true, true)),
            vec![TamperSignal::VirtualMachine, TamperSignal::VpnActive]
        );
        assert!(t.observe(obs(true, false, true, true)).is_empty());
        assert!(
            t.observe(obs(true, false, true, false)).is_empty(),
            "VPN down is silent"
        );
        assert_eq!(
            t.observe(obs(true, false, true, true)),
            vec![TamperSignal::VpnActive]
        );
        for s in [TamperSignal::VirtualMachine, TamperSignal::VpnActive] {
            assert!(s.is_context_only());
        }
        assert!(!revoked(PERMISSION_SCREEN_RECORDING).is_context_only());
    }

    fn iface(name: &str, flags: i32, addr: &str) -> InterfaceAddr {
        InterfaceAddr {
            name: name.into(),
            flags: flags as u32,
            addr: Some(addr.parse().unwrap()),
        }
    }

    const UP: i32 = libc::IFF_UP | libc::IFF_RUNNING;

    #[test]
    fn system_utuns_with_link_local_only_are_not_vpn() {
        // What every Mac looks like at rest.
        let addrs = vec![
            iface("lo0", UP, "127.0.0.1"),
            iface("en0", UP, "192.168.1.20"),
            iface("utun0", UP, "fe80::1234:5678:9abc:def0"),
            iface("utun1", UP, "fe80::aaaa"),
            iface("utun3", UP, "febf::1"),
        ];
        assert!(!vpn_active(&addrs));
    }

    #[test]
    fn routed_tunnels_are_vpn() {
        assert!(vpn_active(&[iface("utun4", UP, "10.8.0.2")]));
        assert!(vpn_active(&[iface("utun7", UP, "100.101.102.103")]));
        assert!(vpn_active(&[iface("ipsec0", UP, "172.16.0.5")]));
        assert!(vpn_active(&[iface("ppp0", UP, "10.0.0.9")]));
        assert!(vpn_active(&[iface("utun2", UP, "fd7a:115c:a1e0::1")]));
    }

    #[test]
    fn down_or_not_running_tunnels_are_ignored() {
        assert!(!vpn_active(&[iface("utun4", libc::IFF_UP, "10.8.0.2")]));
        assert!(!vpn_active(&[iface(
            "utun4",
            libc::IFF_RUNNING,
            "10.8.0.2"
        )]));
        assert!(!vpn_active(&[iface("utun4", 0, "10.8.0.2")]));
    }

    #[test]
    fn lookalike_names_and_odd_addresses_are_ignored() {
        for name in [
            "utun", "utunx", "en0", "bridge0", "xutun0", "ipsec", "pppoe0", "awdl0",
        ] {
            assert!(!vpn_active(&[iface(name, UP, "10.8.0.2")]), "{name}");
        }
        for addr in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "::", "::1"] {
            assert!(!vpn_active(&[iface("utun9", UP, addr)]), "{addr}");
        }
        let no_addr = InterfaceAddr {
            name: "utun5".into(),
            flags: UP as u32,
            addr: None,
        };
        assert!(!vpn_active(&[no_addr]));
    }

    #[test]
    fn live_probes_do_not_panic() {
        let addrs = interface_addrs().expect("getifaddrs works on macOS");
        assert!(
            addrs.iter().any(|a| a.name == "lo0"),
            "loopback always present"
        );
        let _ = vpn_active(&addrs);
        let _ = running_in_vm();
        let mut t = MacTamper::new();
        // Only context signals can fire on the very first poll after
        // construction, barring a real revocation racing the test.
        let first = t.poll();
        for s in &first {
            assert!(s.is_context_only() || matches!(s, TamperSignal::PermissionRevoked { .. }));
        }
        // Edge-triggered: a condition that persists is not reported again.
        let again = t.poll();
        assert!(
            again.iter().all(|s| !first.contains(s)),
            "{first:?} then {again:?}"
        );
    }
}
