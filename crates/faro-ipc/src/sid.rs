//! Windows security identifiers (SIDs), as plain data.
//!
//! On Windows an account is a SID, not a uid: `S-1-5-18` is LocalSystem,
//! `S-1-5-21-…-1001` a local user. The named-pipe transport
//! ([`crate::named_pipe`]) reports the peer's SID in
//! [`PeerInfo::windows_sid`](crate::PeerInfo::windows_sid), and the
//! verifiers ([`AllowSids`](crate::AllowSids),
//! [`AllowSameUser`](crate::AllowSameUser),
//! [`AllowSystemService`](crate::AllowSystemService)) compare SIDs.
//!
//! [`Sid`] is a fixed-size `Copy` value (a SID is at most
//! [`Sid::MAX_LEN`] bytes) so [`PeerInfo`](crate::PeerInfo) stays `Copy`.
//! Parsing and formatting are pure Rust and compiled on every platform, so
//! the code that names accounts (pipe names, configuration) is tested
//! everywhere; only reading a SID out of a token needs Windows.
//!
//! Every constructor validates the binary layout (revision 1, at most 15
//! sub-authorities, length exactly `8 + 4 * count`), so a `Sid` is always
//! well formed and byte equality is SID equality (what `EqualSid` does).

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

/// A validated Windows security identifier.
#[derive(Clone, Copy)]
pub struct Sid {
    len: u8,
    bytes: [u8; Sid::MAX_LEN],
}

/// A string that is not a SID in `S-1-…` form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a SID in S-1-<authority>-<sub-authority>... form")]
pub struct ParseSidError;

impl Sid {
    /// `SECURITY_MAX_SID_SIZE`: revision, count, 6-byte authority and 15
    /// sub-authorities.
    pub const MAX_LEN: usize = 8 + 4 * Self::MAX_SUB_AUTHORITIES;
    /// `SID_MAX_SUB_AUTHORITIES`.
    pub const MAX_SUB_AUTHORITIES: usize = 15;

    /// `S-1-5-18`, LocalSystem: the account the Faro service runs as.
    pub const LOCAL_SYSTEM: Sid = Sid::from_parts(5, &[18]);
    /// `S-1-5-32-544`, the built-in Administrators group. Present (and
    /// enabled) only in an elevated administrator's token; in a filtered,
    /// non-elevated token it is deny-only and grants nothing.
    pub const BUILTIN_ADMINISTRATORS: Sid = Sid::from_parts(5, &[32, 544]);

    /// Build a SID from its identifier authority (48 bits; larger values are
    /// truncated) and sub-authorities.
    ///
    /// # Panics
    ///
    /// With more than [`Sid::MAX_SUB_AUTHORITIES`] sub-authorities (at
    /// compile time when used in a `const`).
    pub const fn from_parts(authority: u64, sub_authorities: &[u32]) -> Sid {
        assert!(
            sub_authorities.len() <= Self::MAX_SUB_AUTHORITIES,
            "too many sub-authorities"
        );
        let mut bytes = [0u8; Self::MAX_LEN];
        bytes[0] = 1;
        bytes[1] = sub_authorities.len() as u8;
        // The identifier authority is big-endian, the sub-authorities are
        // little-endian (that is how Windows lays a SID out).
        let auth = authority.to_be_bytes();
        let mut i = 0;
        while i < 6 {
            bytes[2 + i] = auth[2 + i];
            i += 1;
        }
        let mut s = 0;
        while s < sub_authorities.len() {
            let le = sub_authorities[s].to_le_bytes();
            let mut j = 0;
            while j < 4 {
                bytes[8 + 4 * s + j] = le[j];
                j += 1;
            }
            s += 1;
        }
        Sid {
            len: (8 + 4 * sub_authorities.len()) as u8,
            bytes,
        }
    }

    /// Parse the binary form (what `GetTokenInformation(TokenUser)` and
    /// `GetSecurityInfo` point at). `None` unless `bytes` is exactly one
    /// well-formed SID.
    pub fn from_bytes(bytes: &[u8]) -> Option<Sid> {
        if bytes.len() < 8 || bytes[0] != 1 {
            return None;
        }
        let count = bytes[1] as usize;
        if count > Self::MAX_SUB_AUTHORITIES || bytes.len() != 8 + 4 * count {
            return None;
        }
        let mut out = [0u8; Self::MAX_LEN];
        out[..bytes.len()].copy_from_slice(bytes);
        Some(Sid {
            len: bytes.len() as u8,
            bytes: out,
        })
    }

    /// The binary form, `8 + 4 * count` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The 48-bit identifier authority (5 for `NT AUTHORITY`).
    pub fn authority(&self) -> u64 {
        let mut a = [0u8; 8];
        a[2..].copy_from_slice(&self.bytes[2..8]);
        u64::from_be_bytes(a)
    }

    /// The sub-authorities, in order (the last one of an account SID is its
    /// relative id, e.g. 1001).
    pub fn sub_authorities(&self) -> impl Iterator<Item = u32> + '_ {
        self.as_bytes()[8..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| u32::from_le_bytes(*c))
    }
}

impl FromStr for Sid {
    type Err = ParseSidError;

    /// Parse `S-1-<authority>-<sub>...`, as `ConvertStringSidToSid` does for
    /// numeric SIDs: the authority is decimal, or `0x` and hex when it does
    /// not fit in 32 bits. SDDL aliases (`SY`, `BA`) are not accepted.
    fn from_str(s: &str) -> Result<Sid, ParseSidError> {
        let mut parts = s.split('-');
        if !matches!(parts.next(), Some("S" | "s")) || parts.next() != Some("1") {
            return Err(ParseSidError);
        }
        let auth = parts.next().ok_or(ParseSidError)?;
        let authority = match auth.strip_prefix("0x").or_else(|| auth.strip_prefix("0X")) {
            Some(hex) if !hex.is_empty() && hex.len() <= 12 => {
                u64::from_str_radix(hex, 16).map_err(|_| ParseSidError)?
            }
            Some(_) => return Err(ParseSidError),
            None => u64::from(decimal_u32(auth)?),
        };
        let mut subs = [0u32; Sid::MAX_SUB_AUTHORITIES];
        let mut n = 0;
        for p in parts {
            if n == Sid::MAX_SUB_AUTHORITIES {
                return Err(ParseSidError);
            }
            subs[n] = decimal_u32(p)?;
            n += 1;
        }
        Ok(Sid::from_parts(authority, &subs[..n]))
    }
}

/// A non-empty run of ASCII digits that fits in a `u32` (no sign, no
/// whitespace, which `u32::from_str` would partly accept).
fn decimal_u32(s: &str) -> Result<u32, ParseSidError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseSidError);
    }
    s.parse().map_err(|_| ParseSidError)
}

impl fmt::Display for Sid {
    /// The `S-1-…` form `ConvertSidToStringSid` produces, which is also
    /// what SDDL and pipe names use.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let auth = self.authority();
        if auth < (1 << 32) {
            write!(f, "S-1-{auth}")?;
        } else {
            write!(f, "S-1-0x{auth:012X}")?;
        }
        for s in self.sub_authorities() {
            write!(f, "-{s}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Sid {}

impl Hash for Sid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialOrd for Sid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Sid {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_sids() {
        assert_eq!(Sid::LOCAL_SYSTEM.to_string(), "S-1-5-18");
        assert_eq!(Sid::BUILTIN_ADMINISTRATORS.to_string(), "S-1-5-32-544");
        assert_eq!(
            Sid::LOCAL_SYSTEM.as_bytes(),
            [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
        );
    }

    #[test]
    fn string_round_trip() {
        for s in [
            "S-1-5-18",
            "S-1-5-21-3623811015-3361044348-30300820-1013",
            "S-1-1-0",
            "S-1-0",
            "S-1-16-12288",
            "S-1-0xFFFFFFFFFFFF-1",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
        ] {
            let sid: Sid = s.parse().unwrap();
            assert_eq!(sid.to_string(), s);
            assert_eq!(Sid::from_bytes(sid.as_bytes()), Some(sid));
        }
        // Hex is accepted for any authority but printed only above 32 bits.
        let hex: Sid = "S-1-0x0000FFFFFFFF-1".parse().unwrap();
        assert_eq!(hex.to_string(), "S-1-4294967295-1");
        let sid: Sid = "s-1-5-21-1-2-3-1001".parse().unwrap();
        assert_eq!(sid.authority(), 5);
        assert_eq!(sid.sub_authorities().last(), Some(1001));
    }

    #[test]
    fn malformed_strings_are_refused() {
        for s in [
            "",
            "S",
            "S-1",
            "S-2-5-18",
            "SY",
            "S-1-5-",
            "S-1--18",
            "S-1-5-+18",
            "S-1-5- 18",
            "S-1-5-4294967296",
            "S-1-0x",
            "S-1-0x1000000000000",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
            "S-1-5-18\\..",
        ] {
            assert_eq!(s.parse::<Sid>(), Err(ParseSidError), "{s:?}");
        }
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let good = Sid::LOCAL_SYSTEM;
        assert!(Sid::from_bytes(&good.as_bytes()[..11]).is_none());
        let mut long = good.as_bytes().to_vec();
        long.push(0);
        assert!(Sid::from_bytes(&long).is_none());
        let mut rev = good.as_bytes().to_vec();
        rev[0] = 2;
        assert!(Sid::from_bytes(&rev).is_none());
        let mut too_many = vec![1u8, 16, 0, 0, 0, 0, 0, 5];
        too_many.extend(std::iter::repeat_n(0, 64));
        assert!(Sid::from_bytes(&too_many).is_none());
    }

    #[test]
    fn equality_ignores_unused_storage() {
        let a = Sid::from_parts(5, &[18]);
        let b = Sid::from_bytes(a.as_bytes()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, Sid::from_parts(5, &[18, 0]));
        assert!(Sid::from_parts(5, &[18]) < Sid::from_parts(5, &[19]));
    }
}
