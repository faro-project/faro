//! Data bundles: how a model or a blocklist travels as one target.
//!
//! A target is one file, but a model or a domain bundle is two: a JSON
//! manifest and the file it describes. A data bundle joins them:
//!
//! ```text
//! offset  size  content
//! 0       8     "FARODATA"
//! 8       1     format version, 1
//! 9       4     manifest length m, big-endian, 1..=MAX_BUNDLE_MANIFEST_BYTES
//! 13      m     the manifest, byte for byte
//! 13 + m  rest  the payload (the model or the domain bundle)
//! ```
//!
//! The target's BLAKE3 covers the whole bundle, so a bundle that passed
//! [`verify_target_stream`](crate::verify_target_stream) is exactly what the
//! project signed. The manifest says what the payload is and pins its
//! BLAKE3; checking that is the consumer's job (`faro_detect::load_model`,
//! `faro_detect::load_domains`). This module only frames bytes and never
//! parses the manifest.

use std::io::{self, Read, Write};

/// The first bytes of every data bundle.
pub const BUNDLE_MAGIC: &[u8; 8] = b"FARODATA";
/// The only format version.
pub const BUNDLE_FORMAT: u8 = 1;
/// Largest manifest accepted.
pub const MAX_BUNDLE_MANIFEST_BYTES: usize = 1 << 20;
/// Bytes before the manifest.
pub const BUNDLE_HEADER_BYTES: usize = 13;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a Faro data bundle")]
    NotABundle,
    #[error("data bundle format {0} is not supported")]
    Format(u8),
    #[error("data bundle manifest of {0} bytes (expected 1..={MAX_BUNDLE_MANIFEST_BYTES})")]
    ManifestSize(u64),
}

/// Write a bundle of `manifest` and everything `payload` yields. Returns
/// the number of bytes written.
pub fn write_bundle(
    out: &mut impl Write,
    manifest: &[u8],
    payload: &mut impl Read,
) -> Result<u64, BundleError> {
    if manifest.is_empty() || manifest.len() > MAX_BUNDLE_MANIFEST_BYTES {
        return Err(BundleError::ManifestSize(manifest.len() as u64));
    }
    out.write_all(BUNDLE_MAGIC)?;
    out.write_all(&[BUNDLE_FORMAT])?;
    out.write_all(&(manifest.len() as u32).to_be_bytes())?;
    out.write_all(manifest)?;
    let n = io::copy(payload, out)?;
    Ok(BUNDLE_HEADER_BYTES as u64 + manifest.len() as u64 + n)
}

/// Read a bundle's header and manifest. On success `r` is positioned at
/// the first byte of the payload.
pub fn read_bundle_manifest(r: &mut impl Read) -> Result<Vec<u8>, BundleError> {
    let mut header = [0u8; BUNDLE_HEADER_BYTES];
    r.read_exact(&mut header).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => BundleError::NotABundle,
        _ => BundleError::Io(e),
    })?;
    if &header[..8] != BUNDLE_MAGIC {
        return Err(BundleError::NotABundle);
    }
    if header[8] != BUNDLE_FORMAT {
        return Err(BundleError::Format(header[8]));
    }
    let len = u32::from_be_bytes(header[9..13].try_into().expect("4 bytes")) as usize;
    if len == 0 || len > MAX_BUNDLE_MANIFEST_BYTES {
        return Err(BundleError::ManifestSize(len as u64));
    }
    let mut manifest = vec![0u8; len];
    r.read_exact(&mut manifest).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => BundleError::NotABundle,
        _ => BundleError::Io(e),
    })?;
    Ok(manifest)
}

/// A bundle in memory (tests and small tools).
pub fn bundle_bytes(manifest: &[u8], payload: &[u8]) -> Result<Vec<u8>, BundleError> {
    let mut out = Vec::with_capacity(BUNDLE_HEADER_BYTES + manifest.len() + payload.len());
    write_bundle(&mut out, manifest, &mut &payload[..])?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let b = bundle_bytes(b"{\"a\":1}", b"payload bytes").unwrap();
        assert_eq!(&b[..8], BUNDLE_MAGIC);
        let mut r = &b[..];
        assert_eq!(read_bundle_manifest(&mut r).unwrap(), b"{\"a\":1}");
        assert_eq!(r, b"payload bytes");
        // An empty payload is allowed; the manifest decides if that's valid.
        let b = bundle_bytes(b"{}", b"").unwrap();
        let mut r = &b[..];
        assert_eq!(read_bundle_manifest(&mut r).unwrap(), b"{}");
        assert!(r.is_empty());
    }

    #[test]
    fn malformed_bundles_are_refused() {
        let good = bundle_bytes(b"{}", b"x").unwrap();
        let read = |b: &[u8]| read_bundle_manifest(&mut &b[..]);
        assert!(matches!(read(b""), Err(BundleError::NotABundle)));
        assert!(matches!(read(&good[..10]), Err(BundleError::NotABundle)));
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(matches!(read(&bad), Err(BundleError::NotABundle)));
        let mut bad = good.clone();
        bad[8] = 2;
        assert!(matches!(read(&bad), Err(BundleError::Format(2))));
        let mut bad = good.clone();
        bad[9..13].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(read(&bad), Err(BundleError::ManifestSize(0))));
        let mut bad = good.clone();
        bad[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(read(&bad), Err(BundleError::ManifestSize(_))));
        // The manifest is longer than the file.
        let mut bad = good;
        bad[9..13].copy_from_slice(&100u32.to_be_bytes());
        assert!(matches!(read(&bad), Err(BundleError::NotABundle)));
        assert!(matches!(
            bundle_bytes(b"", b"x"),
            Err(BundleError::ManifestSize(0))
        ));
    }
}
