//! Bearer secrets: generation, hashing and the human-typed enrollment code.
//!
//! **No bearer secret is ever stored in plaintext.** Session ids, magic-link
//! tokens, setup tokens, device tokens, enroll codes and invite tokens are
//! stored as a keyed BLAKE3 hash ([`TokenHasher`]). The key is derived from the
//! instance identity key, which lives in a 0600 file outside the database, so
//! a leaked database or backup alone does not let anyone brute-force even the
//! short (40-bit) enrollment codes offline.
//!
//! Each purpose gets its own domain-separation tag, so a session id can never
//! be replayed as a device token even if the bytes collided.

use faro_crypto::{random_bytes, Zeroizing};
use faro_proto::encoding::b64_encode;

/// Domain-separation tag for each kind of secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenPurpose {
    Session,
    MagicLink,
    Setup,
    Device,
    EnrollCode,
    Invite,
    /// Not a secret: used to key rate-limit buckets by email without keeping
    /// plaintext addresses in memory.
    RateLimitEmail,
}

impl TokenPurpose {
    fn tag(self) -> &'static [u8] {
        match self {
            TokenPurpose::Session => b"session",
            TokenPurpose::MagicLink => b"magic-link",
            TokenPurpose::Setup => b"setup",
            TokenPurpose::Device => b"device",
            TokenPurpose::EnrollCode => b"enroll-code",
            TokenPurpose::Invite => b"invite",
            TokenPurpose::RateLimitEmail => b"rate-limit-email",
        }
    }
}

/// Keyed hashing of bearer secrets for storage and lookup.
#[derive(Clone)]
pub struct TokenHasher {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for TokenHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenHasher(<key>)")
    }
}

impl TokenHasher {
    /// Derive the hashing key from the instance identity seed.
    pub fn from_identity_seed(seed: &[u8; 32]) -> Self {
        TokenHasher {
            key: Zeroizing::new(blake3::derive_key(
                "faro-server token storage hash v1",
                seed,
            )),
        }
    }

    /// Lowercase hex of `BLAKE3-keyed(key, tag || 0x00 || secret)`.
    pub fn hash(&self, purpose: TokenPurpose, secret: &str) -> String {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(purpose.tag());
        h.update(&[0]);
        h.update(secret.as_bytes());
        h.finalize().to_hex().to_string()
    }
}

/// A fresh 256-bit random token, base64url (43 chars).
pub fn new_token() -> Zeroizing<String> {
    let bytes = Zeroizing::new(random_bytes::<32>());
    Zeroizing::new(b64_encode(bytes.as_slice()))
}

/// Shape check for tokens produced by [`new_token`], applied before any
/// database lookup so garbage input costs nothing.
pub fn is_token_shaped(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A fresh random 128-bit lowercase hex id (row ids, blob ids, report ids).
pub fn new_hex_id() -> String {
    hex::encode(random_bytes::<16>())
}

/// Crockford base32 alphabet (no I, L, O, U).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A fresh enrollment code, `XXXX-XXXX` (40 bits). Short enough to type from a
/// phone screen; safe because it is single-use, expires in 10 minutes, is bound
/// to one member, and the enroll endpoint is rate-limited.
pub fn new_enroll_code() -> String {
    let bytes = random_bytes::<5>();
    let mut v: u64 = 0;
    for b in bytes {
        v = (v << 8) | u64::from(b);
    }
    let mut chars = [0u8; 8];
    for (i, c) in chars.iter_mut().enumerate() {
        let shift = 35 - 5 * i;
        // Masking to 5 bits makes the index always < 32.
        *c = CROCKFORD[((v >> shift) & 0x1f) as usize];
    }
    let s: String = chars.iter().map(|&b| b as char).collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// Normalise a user-typed enrollment code to its 8 canonical characters.
///
/// Follows Crockford's decoding rules: case-insensitive, `I`/`L` read as `1`,
/// `O` as `0`, and hyphens/spaces are ignored. Returns `None` for anything
/// else so malformed input never reaches the database.
pub fn normalize_enroll_code(input: &str) -> Option<String> {
    if input.len() > 32 {
        return None;
    }
    let mut out = String::with_capacity(8);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'I' | 'L' => '1',
            'O' => '0',
            c if c.is_ascii() && CROCKFORD.contains(&(c as u8)) => c,
            _ => return None,
        };
        out.push(c);
    }
    (out.len() == 8).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_are_purpose_separated_and_keyed() {
        let a = TokenHasher::from_identity_seed(&[1; 32]);
        let b = TokenHasher::from_identity_seed(&[2; 32]);
        let t = "same-secret";
        assert_ne!(
            a.hash(TokenPurpose::Session, t),
            a.hash(TokenPurpose::Device, t)
        );
        assert_ne!(
            a.hash(TokenPurpose::Session, t),
            b.hash(TokenPurpose::Session, t)
        );
        assert_eq!(
            a.hash(TokenPurpose::Session, t),
            a.hash(TokenPurpose::Session, t)
        );
        assert_eq!(a.hash(TokenPurpose::Setup, t).len(), 64);
    }

    #[test]
    fn tokens_are_unique_and_shaped() {
        let a = new_token();
        let b = new_token();
        assert_ne!(*a, *b);
        assert!(is_token_shaped(&a));
        assert!(!is_token_shaped("short"));
        assert!(!is_token_shaped(&format!("{}!", &a[..42])));
    }

    #[test]
    fn enroll_code_roundtrip() {
        for _ in 0..200 {
            let code = new_enroll_code();
            assert_eq!(code.len(), 9);
            assert_eq!(&code[4..5], "-");
            let norm = normalize_enroll_code(&code).unwrap();
            assert_eq!(norm, code.replace('-', ""));
            assert_eq!(
                normalize_enroll_code(&code.to_ascii_lowercase()).unwrap(),
                norm
            );
        }
    }

    #[test]
    fn enroll_code_normalization_rules() {
        assert_eq!(normalize_enroll_code("abcd-efgh").unwrap(), "ABCDEFGH");
        assert_eq!(normalize_enroll_code("o1l0 iIoO").unwrap(), "01101100");
        assert!(normalize_enroll_code("ABCD-EFGU").is_none()); // U is not Crockford
        assert!(normalize_enroll_code("ABCD-EFG").is_none());
        assert!(normalize_enroll_code("ABCD-EFGHJ").is_none());
        assert!(normalize_enroll_code("ABCD/EFGH").is_none());
        assert!(normalize_enroll_code("ÅBCD-EFGH").is_none());
        assert!(normalize_enroll_code(&"-".repeat(100)).is_none());
    }
}
