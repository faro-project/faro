//! IPv4 and IPv6 UDP packets, as `NEPacketTunnelFlow` hands them over and
//! takes them back: one raw IP packet per buffer, no link-layer header.
//!
//! Parsing reads only what a DNS query needs and rejects everything else.
//! Every read is bounds-checked, so no input can make it panic.
//!
//! * **IPv4:** version 4, a header length of at least 20 bytes, a total
//!   length that fits the buffer (trailing bytes past it are ignored), no
//!   fragments, protocol UDP. Options are skipped.
//! * **IPv6:** version 6, a payload length that fits the buffer, next
//!   header UDP. Extension headers are not followed: a DNS query from the
//!   phone's own resolver never carries them, so a packet with one is
//!   rejected rather than half understood.
//! * **UDP:** a length of at least 8 that fits the IP payload, and a
//!   source port other than 0 (a reply could not be addressed).
//!
//! Incoming checksums are not verified. The packets come from the phone's
//! own network stack through the tunnel interface, never from a network,
//! and an app that could forge one could just as well send a correct one.
//! Outgoing packets always get correct checksums.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// IP protocol number of UDP.
pub const PROTO_UDP: u8 = 17;
/// IP protocol number of TCP.
pub const PROTO_TCP: u8 = 6;
/// The hop limit (IPv4 TTL) of packets Faro builds.
pub const HOP_LIMIT: u8 = 64;

const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;

/// Why a packet is not a UDP datagram this crate can handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("empty packet")]
    Empty,
    #[error("IP version {0} is neither 4 nor 6")]
    BadVersion(u8),
    #[error("packet shorter than its headers say")]
    Truncated,
    #[error("bad IP header length")]
    BadHeaderLength,
    #[error("IPv4 fragment")]
    Fragment,
    #[error("TCP, which gets no answer so the client retries over UDP")]
    Tcp,
    #[error("IP protocol {0} is not UDP")]
    NotUdp(u8),
    #[error("bad UDP length")]
    BadUdpLength,
    #[error("UDP source port 0")]
    ZeroSourcePort,
}

/// A parsed UDP datagram: its addresses and its payload, borrowed from the
/// packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    /// Where it came from (the app or resolver on the phone).
    pub src: SocketAddr,
    /// Where it was sent (the tunnel's DNS address, or a routed resolver).
    pub dst: SocketAddr,
    pub payload: &'a [u8],
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

/// Parse an IPv4 or IPv6 packet carrying UDP.
pub fn parse_udp(packet: &[u8]) -> Result<Datagram<'_>, PacketError> {
    let first = *packet.first().ok_or(PacketError::Empty)?;
    match first >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        v => Err(PacketError::BadVersion(v)),
    }
}

fn parse_v4(p: &[u8]) -> Result<Datagram<'_>, PacketError> {
    let header = p.get(..IPV4_HEADER).ok_or(PacketError::Truncated)?;
    let ihl = usize::from(header[0] & 0x0f) * 4;
    if ihl < IPV4_HEADER {
        return Err(PacketError::BadHeaderLength);
    }
    let total = usize::from(be16(header, 2).ok_or(PacketError::Truncated)?);
    if total < ihl {
        return Err(PacketError::BadHeaderLength);
    }
    let p = p.get(..total).ok_or(PacketError::Truncated)?;
    // Flags and fragment offset: MF set or a non-zero offset is a fragment.
    let frag = be16(header, 6).ok_or(PacketError::Truncated)?;
    if frag & 0x3fff != 0 {
        return Err(PacketError::Fragment);
    }
    let proto = header[9];
    check_proto(proto)?;
    let src = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
    let dst = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
    let udp = p.get(ihl..).ok_or(PacketError::Truncated)?;
    parse_udp_header(IpAddr::V4(src), IpAddr::V4(dst), udp)
}

fn parse_v6(p: &[u8]) -> Result<Datagram<'_>, PacketError> {
    let header = p.get(..IPV6_HEADER).ok_or(PacketError::Truncated)?;
    let payload_len = usize::from(be16(header, 4).ok_or(PacketError::Truncated)?);
    let next = header[6];
    check_proto(next)?;
    let src = v6_at(header, 8).ok_or(PacketError::Truncated)?;
    let dst = v6_at(header, 24).ok_or(PacketError::Truncated)?;
    let udp = p
        .get(IPV6_HEADER..IPV6_HEADER + payload_len)
        .ok_or(PacketError::Truncated)?;
    parse_udp_header(IpAddr::V6(src), IpAddr::V6(dst), udp)
}

fn v6_at(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    let s: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
    Some(Ipv6Addr::from(s))
}

fn check_proto(proto: u8) -> Result<(), PacketError> {
    match proto {
        PROTO_UDP => Ok(()),
        PROTO_TCP => Err(PacketError::Tcp),
        other => Err(PacketError::NotUdp(other)),
    }
}

fn parse_udp_header(src: IpAddr, dst: IpAddr, udp: &[u8]) -> Result<Datagram<'_>, PacketError> {
    let header = udp.get(..UDP_HEADER).ok_or(PacketError::Truncated)?;
    let sport = be16(header, 0).ok_or(PacketError::Truncated)?;
    let dport = be16(header, 2).ok_or(PacketError::Truncated)?;
    let len = usize::from(be16(header, 4).ok_or(PacketError::Truncated)?);
    if len < UDP_HEADER {
        return Err(PacketError::BadUdpLength);
    }
    let payload = udp.get(UDP_HEADER..len).ok_or(PacketError::BadUdpLength)?;
    if sport == 0 {
        return Err(PacketError::ZeroSourcePort);
    }
    Ok(Datagram {
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        payload,
    })
}

/// Why a packet could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("source and destination are not the same IP version")]
    MixedFamilies,
    #[error("payload too large for one UDP datagram")]
    TooLarge,
    #[error("MTU too small to fragment into")]
    MtuTooSmall,
}

/// The IPv6 next-header value of a Fragment header.
pub const PROTO_IPV6_FRAGMENT: u8 = 44;
/// Smallest MTU [`build_udp_fragments`] accepts for IPv4 (RFC 791's 68,
/// rounded up to leave room for a useful fragment).
pub const MIN_MTU_V4: usize = 576;
/// Smallest MTU of any IPv6 link (RFC 8200 §5).
pub const MIN_MTU_V6: usize = 1280;

/// [`build_udp`], split into IP fragments of at most `mtu` bytes when the
/// datagram doesn't fit in one packet. A datagram that fits is one packet,
/// exactly as [`build_udp`] builds it. Otherwise each fragment is a full
/// IP packet: IPv4 with `MF` and the offset set (and no `DF`), IPv6 with a
/// Fragment header (RFC 8200 §4.5). Every fragment but the last carries a
/// multiple of 8 bytes. `ident` tells this datagram's fragments apart from
/// another's; IPv4 uses its low 16 bits. The UDP checksum covers the whole
/// datagram, as the receiver checks it after reassembly.
///
/// The tunnel needs this for upstream answers larger than its MTU: an
/// answer to a client that asked with a large EDNS buffer, or one fetched
/// over TCP after a truncated one.
pub fn build_udp_fragments(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    mtu: usize,
    ident: u32,
) -> Result<Vec<Vec<u8>>, BuildError> {
    let whole = build_udp(src, dst, payload)?;
    if whole.len() <= mtu {
        return Ok(vec![whole]);
    }
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            if mtu < MIN_MTU_V4 {
                return Err(BuildError::MtuTooSmall);
            }
            let udp = whole.get(IPV4_HEADER..).unwrap_or_default();
            let chunk = (mtu - IPV4_HEADER) / 8 * 8;
            let mut out = Vec::with_capacity(udp.len().div_ceil(chunk));
            for (i, part) in udp.chunks(chunk).enumerate() {
                let offset = i * chunk;
                let more = offset + part.len() < udp.len();
                let total = (IPV4_HEADER + part.len()) as u16;
                let frag = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
                let mut p = Vec::with_capacity(usize::from(total));
                p.extend_from_slice(&[0x45, 0]);
                p.extend_from_slice(&total.to_be_bytes());
                p.extend_from_slice(&(ident as u16).to_be_bytes());
                p.extend_from_slice(&frag.to_be_bytes());
                p.extend_from_slice(&[HOP_LIMIT, PROTO_UDP, 0, 0]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                let sum = checksum::finish(checksum::add(0, &p));
                p[10..12].copy_from_slice(&sum.to_be_bytes());
                p.extend_from_slice(part);
                out.push(p);
            }
            Ok(out)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            if mtu < MIN_MTU_V6 {
                return Err(BuildError::MtuTooSmall);
            }
            const FRAGMENT_HEADER: usize = 8;
            let udp = whole.get(IPV6_HEADER..).unwrap_or_default();
            let chunk = (mtu - IPV6_HEADER - FRAGMENT_HEADER) / 8 * 8;
            let mut out = Vec::with_capacity(udp.len().div_ceil(chunk));
            for (i, part) in udp.chunks(chunk).enumerate() {
                let offset = i * chunk;
                let more = offset + part.len() < udp.len();
                let len = (FRAGMENT_HEADER + part.len()) as u16;
                let field = (((offset / 8) as u16) << 3) | u16::from(more);
                let mut p = Vec::with_capacity(IPV6_HEADER + usize::from(len));
                p.extend_from_slice(&[0x60, 0, 0, 0]);
                p.extend_from_slice(&len.to_be_bytes());
                p.extend_from_slice(&[PROTO_IPV6_FRAGMENT, HOP_LIMIT]);
                p.extend_from_slice(&s.octets());
                p.extend_from_slice(&d.octets());
                p.extend_from_slice(&[PROTO_UDP, 0]);
                p.extend_from_slice(&field.to_be_bytes());
                p.extend_from_slice(&ident.to_be_bytes());
                p.extend_from_slice(part);
                out.push(p);
            }
            Ok(out)
        }
        _ => Err(BuildError::MixedFamilies),
    }
}

/// Largest UDP payload [`build_udp`] accepts for IPv4: the total length
/// field is 16 bits and covers both headers.
pub const MAX_PAYLOAD_V4: usize = 65535 - IPV4_HEADER - UDP_HEADER;
/// Largest UDP payload [`build_udp`] accepts for IPv6: the payload length
/// field is 16 bits and covers the UDP header (no jumbograms).
pub const MAX_PAYLOAD_V6: usize = 65535 - UDP_HEADER;

/// Build an IPv4 or IPv6 packet carrying one UDP datagram from `src` to
/// `dst`, with correct IP header and UDP checksums.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, BuildError> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            if payload.len() > MAX_PAYLOAD_V4 {
                return Err(BuildError::TooLarge);
            }
            let udp_len = (UDP_HEADER + payload.len()) as u16;
            let total = IPV4_HEADER as u16 + udp_len;
            let mut out = Vec::with_capacity(usize::from(total));
            out.extend_from_slice(&[0x45, 0]);
            out.extend_from_slice(&total.to_be_bytes());
            // Identification 0 with Don't Fragment, as for any atomic
            // datagram (RFC 6864).
            out.extend_from_slice(&[0, 0, 0x40, 0, HOP_LIMIT, PROTO_UDP, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let ip_sum = checksum::finish(checksum::add(0, &out));
            out[10..12].copy_from_slice(&ip_sum.to_be_bytes());
            let pseudo = checksum::pseudo_v4(s, d, udp_len);
            push_udp(&mut out, pseudo, src.port(), dst.port(), udp_len, payload);
            Ok(out)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            if payload.len() > MAX_PAYLOAD_V6 {
                return Err(BuildError::TooLarge);
            }
            let udp_len = (UDP_HEADER + payload.len()) as u16;
            let mut out = Vec::with_capacity(IPV6_HEADER + usize::from(udp_len));
            // Version 6, traffic class 0, flow label 0.
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&udp_len.to_be_bytes());
            out.extend_from_slice(&[PROTO_UDP, HOP_LIMIT]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let pseudo = checksum::pseudo_v6(s, d, u32::from(udp_len));
            push_udp(&mut out, pseudo, src.port(), dst.port(), udp_len, payload);
            Ok(out)
        }
        _ => Err(BuildError::MixedFamilies),
    }
}

fn push_udp(out: &mut Vec<u8>, pseudo: u64, sport: u16, dport: u16, len: u16, payload: &[u8]) {
    let start = out.len();
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(payload);
    let sum = checksum::add(pseudo, &out[start..]);
    let mut sum = checksum::finish(sum);
    // A computed 0 is sent as all ones: 0 means "no checksum" in IPv4 and
    // is not allowed at all in IPv6 (RFC 768, RFC 8200 §8.1).
    if sum == 0 {
        sum = 0xffff;
    }
    out[start + 6..start + 8].copy_from_slice(&sum.to_be_bytes());
}

/// The Internet checksum (RFC 1071).
pub mod checksum {
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Add `data` to a running sum as big-endian 16-bit words, padding an
    /// odd final byte with zero. A `u64` cannot overflow for any packet:
    /// it would take more than 2^32 words.
    pub fn add(mut sum: u64, data: &[u8]) -> u64 {
        let (words, rest) = data.as_chunks::<2>();
        for w in words {
            sum += u64::from(u16::from_be_bytes(*w));
        }
        if let [last] = rest {
            sum += u64::from(*last) << 8;
        }
        sum
    }

    /// Fold the carries and take the one's complement.
    pub fn finish(mut sum: u64) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The IPv4 pseudo-header sum for UDP (RFC 768).
    pub fn pseudo_v4(src: Ipv4Addr, dst: Ipv4Addr, udp_len: u16) -> u64 {
        let mut sum = add(0, &src.octets());
        sum = add(sum, &dst.octets());
        sum + u64::from(super::PROTO_UDP) + u64::from(udp_len)
    }

    /// The IPv6 pseudo-header sum for UDP (RFC 8200 §8.1).
    pub fn pseudo_v6(src: Ipv6Addr, dst: Ipv6Addr, udp_len: u32) -> u64 {
        let mut sum = add(0, &src.octets());
        sum = add(sum, &dst.octets());
        sum = add(sum, &udp_len.to_be_bytes());
        sum + u64::from(super::PROTO_UDP)
    }
}
