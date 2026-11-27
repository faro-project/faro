//! Unpacking a verified data bundle (`faro_update::bundle`) into a
//! directory, the part every platform shares (PROTOCOL.md §8.2, models and
//! blocklists, step 1).
//!
//! The bundle has already passed `faro_update::verify_target_stream`, so its
//! bytes are what the project signed. The payload's file name still comes
//! from the manifest, so only a plain file name is accepted: no
//! directories, not hidden, not the manifest's own name. Checking what the
//! files are (`faro_detect::load_domains`, `load_model`) is the caller's
//! next step.

use faro_proto::Hash32;
use faro_update::bundle::{read_bundle_manifest, BundleError};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Why a bundle wasn't unpacked.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// Something local failed; nothing is wrong with the bundle.
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The bundle is signed but unusable.
    #[error("{0}")]
    Rejected(String),
}

fn local(path: &Path) -> impl FnOnce(std::io::Error) -> UnpackError + '_ {
    move |source| UnpackError::Io {
        path: path.to_owned(),
        source,
    }
}

/// A plain file name: no directories, not hidden.
pub fn is_plain_file_name(name: &str) -> bool {
    let mut b = name.bytes();
    (1..=128).contains(&name.len())
        && matches!(b.next(), Some(c) if c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// Unpack the bundle at `bundle` into a new directory `staging` (replacing
/// one left by an earlier attempt): the manifest as `manifest_file`, the
/// payload under the name `payload_name` reads from the manifest. Returns
/// the manifest's path and BLAKE3.
pub fn unpack_bundle(
    bundle: &Path,
    staging: &Path,
    manifest_file: &str,
    payload_name: impl FnOnce(&[u8]) -> Result<String, String>,
) -> Result<(PathBuf, Hash32), UnpackError> {
    let mut r = std::io::BufReader::new(std::fs::File::open(bundle).map_err(local(bundle))?);
    let manifest = read_bundle_manifest(&mut r).map_err(|e| match e {
        BundleError::Io(source) => UnpackError::Io {
            path: bundle.to_owned(),
            source,
        },
        e => UnpackError::Rejected(e.to_string()),
    })?;
    let payload = payload_name(&manifest).map_err(UnpackError::Rejected)?;
    if !is_plain_file_name(&payload) || payload == manifest_file {
        return Err(UnpackError::Rejected(format!(
            "the manifest names {payload:?}, not a plain file name"
        )));
    }
    if staging.exists() {
        std::fs::remove_dir_all(staging).map_err(local(staging))?;
    }
    create_private_dir(staging).map_err(local(staging))?;
    let manifest_path = staging.join(manifest_file);
    write_synced(&manifest_path, &mut &manifest[..])?;
    let payload_path = staging.join(&payload);
    write_synced(&payload_path, &mut r)?;
    sync_dir(staging).map_err(local(staging))?;
    Ok((manifest_path, Hash32::of(&manifest)))
}

fn write_synced(path: &Path, from: &mut impl Read) -> Result<(), UnpackError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(local(path))?;
    std::io::copy(from, &mut f).map_err(local(path))?;
    f.sync_all().map_err(local(path))
}

/// Create `dir` and its parents, mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// fsync a directory, so a rename into it is durable (a no-op off Unix).
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_update::bundle::write_bundle;

    fn bundle(dir: &Path, manifest: &[u8], payload: &[u8]) -> PathBuf {
        let p = dir.join("b.data");
        let mut f = std::fs::File::create(&p).unwrap();
        write_bundle(&mut f, manifest, &mut &payload[..]).unwrap();
        p
    }

    #[test]
    fn unpacks_and_refuses_unsafe_names() {
        let d = tempfile::tempdir().unwrap();
        let b = bundle(d.path(), b"{\"file\":\"x.bin\"}", b"payload");
        let staging = d.path().join("s");
        let (m, h) = unpack_bundle(&b, &staging, "m.json", |_| Ok("x.bin".into())).unwrap();
        assert_eq!(std::fs::read(&m).unwrap(), b"{\"file\":\"x.bin\"}");
        assert_eq!(h, Hash32::of(b"{\"file\":\"x.bin\"}"));
        assert_eq!(std::fs::read(staging.join("x.bin")).unwrap(), b"payload");
        for bad in ["../x", ".hidden", "a/b", "m.json", ""] {
            let r = unpack_bundle(&b, &staging, "m.json", |_| Ok(bad.into()));
            assert!(matches!(r, Err(UnpackError::Rejected(_))), "{bad}");
        }
        let not = d.path().join("not");
        std::fs::write(&not, b"hello").unwrap();
        assert!(matches!(
            unpack_bundle(&not, &staging, "m.json", |_| Ok("x".into())),
            Err(UnpackError::Rejected(_))
        ));
    }
}
