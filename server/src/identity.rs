//! The instance identity key (§3.8).
//!
//! An Ed25519 key that clients pin at enrollment via `/.well-known/faro`. It
//! is stored as the raw 32-byte seed in `<data_dir>/identity.key` with mode
//! 0600, outside the database, because:
//!
//! * a database dump or backup should not carry the instance's identity;
//! * the bearer-token hashing key is derived from it ([`TokenHasher`]), so a
//!   leaked database alone cannot be used to brute-force short codes.
//!
//! Losing this file means every client's pinned key stops matching and every
//! session/device token becomes unverifiable, so `backup` (stage B) must
//! include it, and startup refuses to run if the key on disk does not match
//! the public key recorded in the database.

use crate::tokens::TokenHasher;
use faro_crypto::SigningKey;
use faro_proto::SignPublicKey;
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name of the identity key inside the data directory.
pub const IDENTITY_FILE: &str = "identity.key";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity key {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("identity key {0} is corrupt (expected exactly 32 bytes)")]
    Corrupt(PathBuf),
}

/// The loaded identity: signing key plus the token hasher derived from it.
pub struct Identity {
    key: SigningKey,
    hasher: TokenHasher,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.key.public())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn from_signing_key(key: SigningKey) -> Self {
        let hasher = TokenHasher::from_identity_seed(&key.to_bytes());
        Identity { key, hasher }
    }

    pub fn public(&self) -> SignPublicKey {
        self.key.public()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn hasher(&self) -> &TokenHasher {
        &self.hasher
    }
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> IdentityError + '_ {
    move |source| IdentityError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Load `<data_dir>/identity.key`, creating it if it does not exist.
///
/// Returns the identity and whether it was freshly created.
pub fn load_or_create(data_dir: &Path) -> Result<(Identity, bool), IdentityError> {
    let path = data_dir.join(IDENTITY_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::Corrupt(path.clone()))?;
            let seed = faro_crypto::Zeroizing::new(seed);
            warn_if_permissive(&path);
            Ok((
                Identity::from_signing_key(SigningKey::from_bytes(&seed)),
                false,
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SigningKey::generate();
            match write_new_key(&path, &key) {
                Ok(()) => Ok((Identity::from_signing_key(key), true)),
                // Lost a creation race with another process: use theirs.
                Err(IdentityError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    load_or_create(data_dir)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(io_err(&path)(e)),
    }
}

/// Write the seed to a 0600 temp file, fsync, then hard-link it into place.
/// `hard_link` fails if the target exists, so an existing key is never
/// clobbered and a crash never leaves a truncated key at the final path.
fn write_new_key(path: &Path, key: &SigningKey) -> Result<(), IdentityError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".identity.key.tmp-{}", crate::tokens::new_hex_id()));
    let result = (|| {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(io_err(&tmp))?;
        f.write_all(key.to_bytes().as_slice())
            .map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
        std::fs::hard_link(&tmp, path).map_err(io_err(path))?;
        if let Ok(d) = std::fs::File::open(dir) {
            // Best effort: persist the directory entry.
            let _ = d.sync_all();
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&tmp);
    result
}

fn warn_if_permissive(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    "identity key is readable by group/others; run `chmod 600` on it"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_once_then_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let (a, created) = load_or_create(dir.path()).unwrap();
        assert!(created);
        let (b, created) = load_or_create(dir.path()).unwrap();
        assert!(!created);
        assert_eq!(a.public(), b.public());
        assert_eq!(
            a.hasher().hash(crate::tokens::TokenPurpose::Session, "x"),
            b.hasher().hash(crate::tokens::TokenPurpose::Session, "x")
        );
        // No temp files left behind.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(IDENTITY_FILE)]);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        load_or_create(dir.path()).unwrap();
        let mode = std::fs::metadata(dir.path().join(IDENTITY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_key_is_an_error_not_a_silent_regeneration() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(IDENTITY_FILE), b"short").unwrap();
        assert!(matches!(
            load_or_create(dir.path()),
            Err(IdentityError::Corrupt(_))
        ));
    }
}
