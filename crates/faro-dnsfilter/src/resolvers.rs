//! Well-known public resolver addresses (IOS.md §7.4).
//!
//! The tunnel adds a host route for each of these, so traffic to them
//! enters the tunnel. There, DNS-over-HTTPS (TCP 443, or UDP 443 for HTTP/3),
//! DNS-over-TLS (TCP 853) and DNS-over-QUIC (UDP 853) are dropped, because
//! only UDP port 53 is handled ([`crate::Engine::handle_packet`]). Clients
//! then fall back to system DNS. Plain DNS to one of them (UDP 53) is
//! filtered like any other query and answered from the same address, so an
//! app with a hard-coded `8.8.8.8` keeps working, filtered.
//!
//! Only addresses that serve nothing but DNS are listed: routing a shared
//! address (a CDN front such as the one `cloudflare-dns.com` resolves to)
//! would break unrelated sites. Unknown resolvers get through; allies are
//! told this is a limit of DNS filtering.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Version of [`RESOLVER_ADDRS`]. Bump it whenever the list changes.
pub const RESOLVER_LIST_VERSION: u32 = 1;

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[allow(clippy::too_many_arguments)]
const fn v6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Public resolvers with DNS-over-HTTPS, DNS-over-TLS or DNS-over-QUIC on a
/// dedicated address, IPv4 and IPv6. Each is a single host (a /32 or /128
/// route).
pub const RESOLVER_ADDRS: &[IpAddr] = &[
    // Google Public DNS (dns.google).
    v4(8, 8, 8, 8),
    v4(8, 8, 4, 4),
    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x6464),
    v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x0064),
    // Cloudflare 1.1.1.1, with its malware and family filters.
    v4(1, 1, 1, 1),
    v4(1, 0, 0, 1),
    v4(1, 1, 1, 2),
    v4(1, 0, 0, 2),
    v4(1, 1, 1, 3),
    v4(1, 0, 0, 3),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1112),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1002),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1113),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1003),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x0064),
    v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x6400),
    // Quad9: filtered, unfiltered and with ECS.
    v4(9, 9, 9, 9),
    v4(149, 112, 112, 112),
    v4(9, 9, 9, 10),
    v4(149, 112, 112, 10),
    v4(9, 9, 9, 11),
    v4(149, 112, 112, 11),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x10),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x10),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x11),
    v6(0x2620, 0xfe, 0, 0, 0, 0, 0xfe, 0x11),
    // OpenDNS, with FamilyShield.
    v4(208, 67, 222, 222),
    v4(208, 67, 220, 220),
    v4(208, 67, 222, 123),
    v4(208, 67, 220, 123),
    v6(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
    v6(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
    // AdGuard DNS: default, family and unfiltered.
    v4(94, 140, 14, 14),
    v4(94, 140, 15, 15),
    v4(94, 140, 14, 15),
    v4(94, 140, 15, 16),
    v4(94, 140, 14, 140),
    v4(94, 140, 14, 141),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad1, 0xff),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad2, 0xff),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0xbad1, 0xff),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0xbad2, 0xff),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0x1, 0xff),
    v6(0x2a10, 0x50c0, 0, 0, 0, 0, 0x2, 0xff),
    // NextDNS anycast.
    v4(45, 90, 28, 0),
    v4(45, 90, 30, 0),
    // Mullvad DNS.
    v4(194, 242, 2, 2),
    v6(0x2a07, 0xe340, 0, 0, 0, 0, 0, 0x2),
    // Control D free resolvers.
    v4(76, 76, 2, 0),
    v4(76, 76, 10, 0),
    v6(0x2606, 0x1a40, 0, 0, 0, 0, 0, 0),
    v6(0x2606, 0x1a40, 0x1, 0, 0, 0, 0, 0),
];

/// Whether `ip` is one of [`RESOLVER_ADDRS`]. IPv4-mapped IPv6 addresses
/// count as their IPv4 address.
pub fn is_resolver_addr(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    RESOLVER_ADDRS.contains(&ip)
}

/// The IPv4 addresses, for `NEIPv4Route` (mask 255.255.255.255).
pub fn resolver_v4() -> impl Iterator<Item = Ipv4Addr> {
    RESOLVER_ADDRS.iter().filter_map(|ip| match ip {
        IpAddr::V4(a) => Some(*a),
        IpAddr::V6(_) => None,
    })
}

/// The IPv6 addresses, for `NEIPv6Route` (prefix length 128).
pub fn resolver_v6() -> impl Iterator<Item = Ipv6Addr> {
    RESOLVER_ADDRS.iter().filter_map(|ip| match ip {
        IpAddr::V6(a) => Some(*a),
        IpAddr::V4(_) => None,
    })
}
