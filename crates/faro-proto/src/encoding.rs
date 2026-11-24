//! Byte-level helpers: base64url serde adapters, fixed-size byte types and the
//! canonical length-prefixed writer used to build signing and hashing input.
//!
//! The canonical encoding is deliberately trivial so that it can be
//! re-implemented in TypeScript (web app) and audited by hand:
//!
//! * integers are big-endian, fixed width;
//! * strings and byte strings are a `u32` big-endian length followed by the bytes;
//! * fixed-size arrays (hashes, keys) are written raw;
//! * every structure starts with a NUL-terminated ASCII domain-separation tag.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Encode bytes as unpadded base64url (the only base64 flavour Faro uses).
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// serde adapter: `Vec<u8>` <-> base64url string.
pub mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        b64_decode(&s).map_err(serde::de::Error::custom)
    }
}

/// serde adapter: `Option<Vec<u8>>` <-> optional base64url string.
pub mod b64_opt {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_some(&b64_encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| b64_decode(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}

macro_rules! fixed_bytes {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn from_slice(s: &[u8]) -> Option<Self> {
                <[u8; $len]>::try_from(s).ok().map(Self)
            }

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn to_b64(&self) -> String {
                b64_encode(&self.0)
            }

            pub fn from_b64(s: &str) -> Option<Self> {
                b64_decode(s).ok().and_then(|v| Self::from_slice(&v))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_b64())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_b64())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_b64(&s).ok_or_else(|| {
                    serde::de::Error::custom(concat!("invalid ", stringify!($name)))
                })
            }
        }
    };
}

fixed_bytes!(
    /// An Ed25519 public key (device signing key, member signing key, instance identity key).
    SignPublicKey,
    32
);
fixed_bytes!(
    /// An Ed25519 signature.
    Signature,
    64
);
fixed_bytes!(
    /// An X25519 public key (ally / member encryption key).
    EncPublicKey,
    32
);
fixed_bytes!(
    /// An XChaCha20-Poly1305 nonce.
    Nonce24,
    24
);

/// A BLAKE3-256 digest. Serialized as `"b3:<64 lowercase hex chars>"`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub const ZERO: Hash32 = Hash32([0u8; 32]);

    pub fn of(bytes: &[u8]) -> Self {
        Hash32(*blake3::hash(bytes).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_prefixed_hex(&self) -> String {
        format!("b3:{}", hex::encode(self.0))
    }

    pub fn from_prefixed_hex(s: &str) -> Option<Self> {
        let h = s.strip_prefix("b3:")?;
        let v = hex::decode(h).ok()?;
        <[u8; 32]>::try_from(v.as_slice()).ok().map(Hash32)
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed_hex())
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_prefixed_hex())
    }
}

impl Serialize for Hash32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_prefixed_hex())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash32::from_prefixed_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid b3 hash"))
    }
}

/// Builder for canonical signing / hashing input. See module docs for the format.
#[derive(Debug, Default, Clone)]
pub struct Canonical {
    buf: Vec<u8>,
}

impl Canonical {
    /// Start a new canonical buffer with a domain-separation tag.
    /// The tag is written as raw ASCII followed by a single NUL byte.
    pub fn new(tag: &str) -> Self {
        debug_assert!(tag.is_ascii() && !tag.contains('\0'));
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(tag.as_bytes());
        buf.push(0);
        Canonical { buf }
    }

    pub fn u16(mut self, v: u16) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u64(mut self, v: u64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn i64(mut self, v: i64) -> Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(mut self, v: &[u8]) -> Self {
        let len = u32::try_from(v.len()).expect("canonical field longer than u32::MAX");
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(v);
        self
    }

    pub fn str(self, v: &str) -> Self {
        self.bytes(v.as_bytes())
    }

    pub fn fixed(mut self, v: &[u8]) -> Self {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let h = Hash32::of(b"faro");
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.starts_with("\"b3:"));
        let back: Hash32 = serde_json::from_str(&s).unwrap();
        assert_eq!(h, back);
    }

    #[test]
    fn fixed_bytes_reject_wrong_length() {
        assert!(SignPublicKey::from_b64(&b64_encode(&[0u8; 31])).is_none());
        assert!(SignPublicKey::from_b64(&b64_encode(&[0u8; 32])).is_some());
    }

    #[test]
    fn canonical_layout_is_stable() {
        let out = Canonical::new("t").u16(1).str("ab").u64(2).finish();
        assert_eq!(
            out,
            vec![b't', 0, 0, 1, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 2]
        );
    }
}
