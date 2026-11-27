//! The tunnel's own addresses and routes (IOS.md §7.1), in one place so
//! the Swift provider and the tests agree.
//!
//! * **The DNS address**, `198.18.0.53` and `2001:2::53`, is what the
//!   phone's resolver sends every query to (`matchDomains = [""]`). Both
//!   are in the benchmarking ranges (RFC 2544 and RFC 5180), which no real
//!   network assigns, so they can't hide a host on the member's network.
//!   A unique local address such as `fd00::53` could: some home routers
//!   number their networks `fd00::/64`.
//! * **The interface addresses**, `198.18.0.1` and `2001:2::1`, are the
//!   tunnel's end of the link.
//! * **The routes** are host routes for the DNS address and for each of
//!   [`RESOLVER_ADDRS`](crate::RESOLVER_ADDRS), and nothing else, so no
//!   other traffic enters the tunnel.

use crate::resolvers::{resolver_v4, resolver_v6};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The tunnel interface's IPv4 address.
pub const TUNNEL_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// The DNS server address the phone is given, IPv4.
pub const DNS_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 53);
/// The tunnel interface's IPv6 address.
pub const TUNNEL_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x2, 0, 0, 0, 0, 0, 0x1);
/// The DNS server address the phone is given, IPv6.
pub const DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x2, 0, 0, 0, 0, 0, 0x53);
/// The tunnel's MTU. Larger answers go back in fragments.
pub const MTU: usize = 1500;

/// Host routes into the tunnel (mask `255.255.255.255`): the DNS address,
/// then the resolver addresses.
pub fn routes_v4() -> Vec<Ipv4Addr> {
    std::iter::once(DNS_V4).chain(resolver_v4()).collect()
}

/// Host routes into the tunnel (prefix length 128): the DNS address, then
/// the resolver addresses.
pub fn routes_v6() -> Vec<Ipv6Addr> {
    std::iter::once(DNS_V6).chain(resolver_v6()).collect()
}

/// Whether `ip` is one of the tunnel's own addresses.
pub fn is_own_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a == TUNNEL_V4 || a == DNS_V4,
        IpAddr::V6(a) => {
            a == TUNNEL_V6
                || a == DNS_V6
                || a.to_ipv4_mapped().is_some_and(|m| is_own_addr(m.into()))
        }
    }
}

/// The network resolver `addr` in the form the tunnel uses, or `None` if
/// it can't be one: unspecified, loopback, multicast or broadcast
/// addresses, port 0, and the tunnel's own addresses (which the system
/// reports as the resolver once the tunnel's DNS settings apply; sending
/// to them would loop). IPv4-mapped IPv6 addresses become IPv4.
pub fn upstream_addr(addr: SocketAddr) -> Option<SocketAddr> {
    let ip = match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let bad = ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || matches!(ip, IpAddr::V4(a) if a.is_broadcast())
        || is_own_addr(ip)
        || addr.port() == 0;
    if bad {
        return None;
    }
    Some(match (addr, ip) {
        (SocketAddr::V6(a), IpAddr::V6(_)) => SocketAddr::V6(a),
        (_, ip) => SocketAddr::new(ip, addr.port()),
    })
}
