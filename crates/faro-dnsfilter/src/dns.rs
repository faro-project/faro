//! DNS queries (RFC 1035): the header and the one question, and the
//! `NXDOMAIN` reply to a blocked one.
//!
//! A query is accepted only if it is a standard query (`QR` = 0, opcode
//! `QUERY`) with exactly one question whose name is made of LDH labels
//! (letters, digits, `-`, and `_` for service names such as
//! `_dns.resolver.arpa`), each at most 63 bytes, at most 255 bytes on the
//! wire. Names are lowercased (ASCII only). Punycode (`xn--…`) is kept as it
//! is: it is plain LDH, and the bundle stores names the same way.
//!
//! Everything else is rejected, and the packet is dropped:
//!
//! * **Several questions.** One could ask about an allowed name and a
//!   blocked one at once, so only one is ever looked at, and never forwarded
//!   with others (RFC 9619 says the same).
//! * **Compression pointers in the question.** The question is the first
//!   name in a query, so a pointer has nothing earlier to point to: it can
//!   only point into the header, at itself or forward. Rejecting every
//!   pointer also rules out compression loops.
//! * **Other bytes in labels** (spaces, dots inside a label, non-ASCII).
//!   No real host name has them, and the filter should never pass a name it
//!   cannot read.
//!
//! Records after the question (an EDNS `OPT` record, usually) are not
//! parsed. An allowed query goes upstream byte for byte.
//!
//! ## Answers
//!
//! An upstream answer is read only as far as [`answer_targets`] needs: the
//! names its answer records point to (CNAME, DNAME, and the target of SVCB
//! and HTTPS records), so that `innocent.example CNAME blocked.example`
//! can't carry a blocked name past the filter. Compression pointers are
//! followed there, but only strictly backwards from where the current run
//! of labels started, which rules out loops. A target that doesn't parse
//! as an LDH name makes the whole answer unreadable.

use std::fmt;

/// Longest name on the wire, with its length bytes and the final zero.
pub const MAX_WIRE_NAME: usize = 255;
/// Longest name written with dots.
pub const MAX_NAME: usize = 253;
/// Longest label.
pub const MAX_LABEL: usize = 63;

const HEADER: usize = 12;
const FLAG_QR: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_CD: u16 = 0x0010;
/// Response code for "the server failed".
pub const RCODE_SERVFAIL: u16 = 2;
/// Response code for "no such name".
pub const RCODE_NXDOMAIN: u16 = 3;

/// A few query types by number. The filter decides every type the same
/// way today, by name only.
pub mod qtype {
    pub const A: u16 = 1;
    pub const AAAA: u16 = 28;
    pub const HTTPS: u16 = 65;
    pub const SVCB: u16 = 64;
    pub const CNAME: u16 = 5;
    pub const DNAME: u16 = 39;
}

/// Why a UDP payload is not a DNS query the filter accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    #[error("shorter than a DNS header and question")]
    Truncated,
    #[error("a response, not a query")]
    NotAQuery,
    #[error("opcode {0} is not QUERY")]
    Opcode(u8),
    #[error("{0} questions, not one")]
    QuestionCount(u16),
    #[error("compression pointer in the question")]
    CompressionPointer,
    #[error("reserved label type")]
    LabelType,
    #[error("name longer than 255 bytes")]
    NameTooLong,
    #[error("byte {0:#04x} in a label")]
    LabelByte(u8),
    #[error("a query, not a response")]
    NotAResponse,
    #[error("compression pointer that doesn't point backwards")]
    BadPointer,
    #[error("record data that doesn't match its name")]
    BadRecord,
}

/// A lowercased DNS name without the trailing dot, stored inline (no
/// allocation). The root is the empty name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DnsName {
    buf: [u8; MAX_NAME],
    len: u8,
}

impl DnsName {
    /// The name, such as `www.example.com`.
    pub fn as_str(&self) -> &str {
        // Only ASCII bytes are ever written, so this always succeeds.
        std::str::from_utf8(self.bytes()).unwrap_or_default()
    }

    fn bytes(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, b: u8) -> Result<(), DnsError> {
        let slot = self
            .buf
            .get_mut(usize::from(self.len))
            .ok_or(DnsError::NameTooLong)?;
        *slot = b;
        self.len += 1;
        Ok(())
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DnsName({:?})", self.as_str())
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed query: what the filter needs, plus where the question ends so
/// a reply can echo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQuery<'a> {
    pub id: u16,
    flags: u16,
    pub name: DnsName,
    pub qtype: u16,
    pub qclass: u16,
    /// The whole message, which is what goes upstream if the name is
    /// allowed.
    msg: &'a [u8],
    /// Offset just past the question (name, type and class).
    question_end: usize,
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn label_byte(b: u8) -> Result<u8, DnsError> {
    if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
        Ok(b.to_ascii_lowercase())
    } else {
        Err(DnsError::LabelByte(b))
    }
}

/// Parse a DNS query (the UDP payload).
pub fn parse_query(msg: &[u8]) -> Result<DnsQuery<'_>, DnsError> {
    let id = be16(msg, 0).ok_or(DnsError::Truncated)?;
    let flags = be16(msg, 2).ok_or(DnsError::Truncated)?;
    let qdcount = be16(msg, 4).ok_or(DnsError::Truncated)?;
    if msg.len() < HEADER {
        return Err(DnsError::Truncated);
    }
    if flags & FLAG_QR != 0 {
        return Err(DnsError::NotAQuery);
    }
    let opcode = ((flags & OPCODE_MASK) >> 11) as u8;
    if opcode != 0 {
        return Err(DnsError::Opcode(opcode));
    }
    if qdcount != 1 {
        return Err(DnsError::QuestionCount(qdcount));
    }

    let mut name = DnsName {
        buf: [0; MAX_NAME],
        len: 0,
    };
    let mut pos = HEADER;
    // Bytes of the name on the wire so far, counting the final zero.
    let mut wire = 1usize;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Truncated)?;
        pos += 1;
        match len & 0xc0 {
            0xc0 => return Err(DnsError::CompressionPointer),
            0x40 | 0x80 => return Err(DnsError::LabelType),
            _ => {}
        }
        if len == 0 {
            break;
        }
        let len = usize::from(len); // at most 63: the top two bits are clear
        wire += 1 + len;
        if wire > MAX_WIRE_NAME {
            return Err(DnsError::NameTooLong);
        }
        let label = msg.get(pos..pos + len).ok_or(DnsError::Truncated)?;
        if !name.is_empty() {
            name.push(b'.')?;
        }
        for &b in label {
            name.push(label_byte(b)?)?;
        }
        pos += len;
    }
    let qtype = be16(msg, pos).ok_or(DnsError::Truncated)?;
    let qclass = be16(msg, pos + 2).ok_or(DnsError::Truncated)?;
    Ok(DnsQuery {
        id,
        flags,
        name,
        qtype,
        qclass,
        msg,
        question_end: pos + 4,
    })
}

impl<'a> DnsQuery<'a> {
    /// The whole query message, unchanged.
    pub fn message(&self) -> &'a [u8] {
        self.msg
    }

    /// The `NXDOMAIN` reply: the same id, `QR` and `RA` set, `RD` and `CD`
    /// copied, and the question echoed byte for byte, so a client that
    /// randomises the case of the name (DNS 0x20) accepts it. No answer,
    /// authority or additional records: with no SOA the answer is not
    /// cached (RFC 2308 §5), so unblocking a name takes effect at once.
    pub fn nxdomain(&self) -> Vec<u8> {
        self.reply(RCODE_NXDOMAIN)
    }

    /// The `SERVFAIL` reply, shaped like [`DnsQuery::nxdomain`]: for an
    /// allowed name that can't be resolved (no upstream resolver, or an
    /// answer that can't be checked).
    pub fn servfail(&self) -> Vec<u8> {
        self.reply(RCODE_SERVFAIL)
    }

    /// The question on the wire (name, type and class), as the client
    /// sent it.
    pub fn question_bytes(&self) -> &'a [u8] {
        // Always in bounds: parse_query read these bytes.
        self.msg.get(HEADER..self.question_end).unwrap_or_default()
    }

    fn reply(&self, rcode: u16) -> Vec<u8> {
        let question = self.question_bytes();
        let flags = FLAG_QR | (self.flags & (FLAG_RD | FLAG_CD)) | FLAG_RA | (rcode & 0x000f);
        let mut out = Vec::with_capacity(HEADER + question.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(question);
        out
    }
}

/// Check that `msg` looks like the response to the query with `id`: at
/// least a header, `QR` set, the same id.
pub fn is_response_to(msg: &[u8], id: u16) -> bool {
    matches!(
        (be16(msg, 0), be16(msg, 2)),
        (Some(rid), Some(flags)) if msg.len() >= HEADER && rid == id && flags & FLAG_QR != 0
    )
}

/// Whether a response has `TC` set: it was cut to fit a UDP buffer, and
/// the whole answer needs TCP.
pub fn is_truncated(msg: &[u8]) -> bool {
    be16(msg, 2).is_some_and(|f| f & FLAG_TC != 0)
}

/// Move past the name at `pos` without reading it: its labels up to the
/// final zero, or up to a compression pointer, which ends the name in
/// place.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0xc0 => {
                msg.get(pos + 1).ok_or(DnsError::Truncated)?;
                return Ok(pos + 2);
            }
            0x40 | 0x80 => return Err(DnsError::LabelType),
            _ => {}
        }
        pos += 1 + usize::from(len);
        if pos > msg.len() {
            return Err(DnsError::Truncated);
        }
        if len == 0 {
            return Ok(pos);
        }
    }
}

/// Read the possibly compressed name at `start`, lowercased, with the
/// query rules for labels. Returns it and where the name ends in place
/// (after its final zero or its first pointer). A pointer must point
/// strictly before the start of the run of labels it ends, so each jump
/// goes further back and the walk always ends.
fn read_name(msg: &[u8], start: usize) -> Result<(DnsName, usize), DnsError> {
    let mut name = DnsName {
        buf: [0; MAX_NAME],
        len: 0,
    };
    let mut pos = start;
    let mut run_start = start;
    let mut end = None;
    // Bytes of the name on the wire so far, counting the final zero.
    let mut wire = 1usize;
    loop {
        let len = *msg.get(pos).ok_or(DnsError::Truncated)?;
        match len & 0xc0 {
            0xc0 => {
                let low = *msg.get(pos + 1).ok_or(DnsError::Truncated)?;
                let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                if target >= run_start {
                    return Err(DnsError::BadPointer);
                }
                end.get_or_insert(pos + 2);
                pos = target;
                run_start = target;
                continue;
            }
            0x40 | 0x80 => return Err(DnsError::LabelType),
            _ => {}
        }
        pos += 1;
        if len == 0 {
            return Ok((name, end.unwrap_or(pos)));
        }
        let len = usize::from(len);
        wire += 1 + len;
        if wire > MAX_WIRE_NAME {
            return Err(DnsError::NameTooLong);
        }
        let label = msg.get(pos..pos + len).ok_or(DnsError::Truncated)?;
        if !name.is_empty() {
            name.push(b'.')?;
        }
        for &b in label {
            name.push(label_byte(b)?)?;
        }
        pos += len;
    }
}

/// Call `f` with every name the answer records of a response point to:
/// the target of each CNAME and DNAME, and the TargetName of each SVCB and
/// HTTPS record other than the root (which stands for the owner itself).
/// Stops at, and returns, the first `Some` that `f` gives.
///
/// The question and answer sections are walked record by record, every
/// length checked. The authority and additional sections are not read: a
/// client follows the chain from its question through the answer section.
pub fn answer_targets<B>(
    msg: &[u8],
    mut f: impl FnMut(&DnsName) -> Option<B>,
) -> Result<Option<B>, DnsError> {
    let flags = be16(msg, 2).ok_or(DnsError::Truncated)?;
    let qdcount = be16(msg, 4).ok_or(DnsError::Truncated)?;
    let ancount = be16(msg, 6).ok_or(DnsError::Truncated)?;
    if msg.len() < HEADER {
        return Err(DnsError::Truncated);
    }
    if flags & FLAG_QR == 0 {
        return Err(DnsError::NotAResponse);
    }
    let mut pos = HEADER;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)? + 4;
    }
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        let rtype = be16(msg, pos).ok_or(DnsError::Truncated)?;
        let rdlen = usize::from(be16(msg, pos + 8).ok_or(DnsError::Truncated)?);
        let rdata = pos + 10;
        let next = rdata + rdlen;
        // The record, and nothing after it: a name in its data may point
        // back into the message, but never run past the record.
        let record = msg.get(..next).ok_or(DnsError::Truncated)?;
        let alias = matches!(rtype, qtype::CNAME | qtype::DNAME);
        let target_at = match rtype {
            _ if alias => rdata,
            // SvcPriority, then TargetName (RFC 9460 §2.2).
            qtype::SVCB | qtype::HTTPS if rdlen >= 2 => rdata + 2,
            qtype::SVCB | qtype::HTTPS => return Err(DnsError::BadRecord),
            _ => {
                pos = next;
                continue;
            }
        };
        let (target, end) = read_name(record, target_at)?;
        if alias && end != next {
            return Err(DnsError::BadRecord);
        }
        if alias || !target.is_empty() {
            if let Some(b) = f(&target) {
                return Ok(Some(b));
            }
        }
        pos = next;
    }
    Ok(None)
}
