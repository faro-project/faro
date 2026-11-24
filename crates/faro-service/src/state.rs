//! The service's protected state directory.
//!
//! | File | Contents | Mode |
//! |---|---|---|
//! | `device.key` | 32-byte Ed25519 seed of the device key | 0600 |
//! | `enrollment.json` | [`Enrollment`]: pinned instance and member keys, device token | 0600 |
//! | `endorsement.json` | the member-signed `DeviceEndorsement`, once verified | 0600 |
//! | `settings.json` | the member settings last announced to allies | 0600 |
//! | `outbox.sqlite3` | `faro_core::Outbox` (ciphertext only) | 0600 |
//!
//! The directory is 0700 and must be owned by the service's user. Secrets
//! are written atomically (temp file created 0600, fsync, rename, fsync of
//! the directory), so a crash never leaves a half-written key.
//!
//! **Key storage.** The device key is a root-only file on every platform for
//! now. ARCHITECTURE.md §3.6 calls for the macOS Keychain / Secure Enclave,
//! TPM via CNG on Windows and optionally TPM2 on Linux; that is a follow-up,
//! and [`load_device_key`] / [`store_device_key`] are the only functions that
//! would change. The key is never logged: `faro_crypto::SigningKey`'s `Debug`
//! prints only the public half.

use faro_crypto::SigningKey;
use faro_proto::keys::{DeviceEndorsement, Signed};
use faro_proto::{DeviceId, InstanceId, SignPublicKey, UserId};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const DEVICE_KEY_FILE: &str = "device.key";
pub const ENROLLMENT_FILE: &str = "enrollment.json";
pub const ENDORSEMENT_FILE: &str = "endorsement.json";
pub const SETTINGS_FILE: &str = "settings.json";
/// Permissions the service has seen granted, so a revocation made while the
/// service was stopped is still reported (runtime/core.rs).
pub const PERMISSIONS_FILE: &str = "permissions.json";

/// Largest state file read back (they are all tiny).
const MAX_STATE_FILE: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state directory {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("state directory {path} is unsafe: {reason}")]
    Unsafe { path: PathBuf, reason: String },
    #[error("state file {path} is corrupt: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("this device is not enrolled yet (run `faro-service enroll`)")]
    NotEnrolled,
    #[error("this device is already enrolled with {instance} as {device}; remove the state directory to enroll again")]
    AlreadyEnrolled { instance: String, device: DeviceId },
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> StateError + '_ {
    move |source| StateError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// What enrollment established, persisted in `enrollment.json`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    /// Normalized instance base URL (ends in `/`).
    pub instance_url: String,
    pub instance_id: InstanceId,
    /// The instance name the member confirmed.
    pub instance_name: String,
    /// Pinned from `/.well-known/faro`; re-checked by the runtime.
    pub instance_identity_pubkey: SignPublicKey,
    pub device_id: DeviceId,
    /// Bearer token. Secret; redacted from `Debug`.
    pub device_token: String,
    pub member_id: UserId,
    /// Pinned at enrollment: the root of trust for the endorsement and every
    /// recipient manifest.
    pub member_sign_pubkey: SignPublicKey,
    pub device_name: String,
    pub enrolled_at_ms: i64,
}

impl fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Enrollment")
            .field("instance_url", &self.instance_url)
            .field("instance_id", &self.instance_id)
            .field("instance_name", &self.instance_name)
            .field("device_id", &self.device_id)
            .field("device_token", &"<redacted>")
            .field("member_id", &self.member_id)
            .field("member_sign_pubkey", &self.member_sign_pubkey)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

impl Drop for Enrollment {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.device_token);
    }
}

/// Handle to the (validated) state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// Open `path`, creating it with mode 0700 if missing.
    ///
    /// On Unix an existing directory must be owned by the current user and
    /// not be a symlink; group/other permission bits are removed (with a
    /// warning) rather than refused, since an installer or a `cp -r` may have
    /// widened them.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StateError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(StateError::Unsafe {
                path,
                reason: "must be an absolute path".into(),
            });
        }
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut b = fs::DirBuilder::new();
                b.recursive(true);
                #[cfg(unix)]
                std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
                b.create(&path).map_err(io_err(&path))?;
            }
            Err(e) => return Err(io_err(&path)(e)),
        }
        secure_dir(&path)?;
        Ok(StateDir { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Atomically write `bytes` to `name` with mode 0600.
    pub fn write_secret(&self, name: &str, bytes: &[u8]) -> Result<(), StateError> {
        let target = self.file(name);
        let suffix: [u8; 8] = faro_crypto::random_bytes();
        let tmp = self.file(&format!(".{name}.tmp-{}", hex::encode(suffix)));
        let result = (|| {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &target)?;
            sync_dir(&self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(io_err(&target))
    }

    /// Read `name`, or `None` if it does not exist. Loose permissions are
    /// tightened to 0600.
    pub fn read_secret(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StateError> {
        let path = self.file(name);
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(&path)(e)),
        };
        if !meta.is_file() {
            return Err(StateError::Unsafe {
                path,
                reason: "not a regular file".into(),
            });
        }
        if meta.len() > MAX_STATE_FILE {
            return Err(StateError::Corrupt {
                path,
                reason: "file is too large".into(),
            });
        }
        tighten_file(&path, &meta)?;
        let bytes = fs::read(&path).map_err(io_err(&path))?;
        Ok(Some(Zeroizing::new(bytes)))
    }

    pub fn exists(&self, name: &str) -> bool {
        self.file(name).exists()
    }

    pub fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StateError> {
        let bytes =
            Zeroizing::new(
                serde_json::to_vec_pretty(value).map_err(|e| StateError::Corrupt {
                    path: self.file(name),
                    reason: e.to_string(),
                })?,
            );
        self.write_secret(name, &bytes)
    }

    pub fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, StateError> {
        let Some(bytes) = self.read_secret(name)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StateError::Corrupt {
                path: self.file(name),
                reason: e.to_string(),
            })
    }

    /// The enrollment record, or [`StateError::NotEnrolled`].
    pub fn enrollment(&self) -> Result<Enrollment, StateError> {
        self.read_json(ENROLLMENT_FILE)?
            .ok_or(StateError::NotEnrolled)
    }

    /// The verified endorsement, if this device has been endorsed.
    pub fn endorsement(&self) -> Result<Option<Signed<DeviceEndorsement>>, StateError> {
        self.read_json(ENDORSEMENT_FILE)
    }
}

/// Generate a fresh device key and store it, replacing any previous one.
///
/// Called at the start of every enrollment: a key from an earlier attempt
/// may already be registered with an instance (and rejected as in use), and
/// a device key is never reused across enrollments.
pub fn store_device_key(dir: &StateDir) -> Result<SigningKey, StateError> {
    let key = SigningKey::generate();
    let seed = key.to_bytes();
    dir.write_secret(DEVICE_KEY_FILE, seed.as_ref())?;
    Ok(key)
}

/// Load the device key.
pub fn load_device_key(dir: &StateDir) -> Result<SigningKey, StateError> {
    let bytes = dir
        .read_secret(DEVICE_KEY_FILE)?
        .ok_or(StateError::NotEnrolled)?;
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| StateError::Corrupt {
                    path: dir.file(DEVICE_KEY_FILE),
                    reason: "device key must be exactly 32 bytes".into(),
                })?,
        );
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> Result<(), StateError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = fs::symlink_metadata(path).map_err(io_err(path))?;
    let unsafe_dir = |reason: String| StateError::Unsafe {
        path: path.to_path_buf(),
        reason,
    };
    if meta.file_type().is_symlink() {
        return Err(unsafe_dir("is a symlink".into()));
    }
    if !meta.is_dir() {
        return Err(unsafe_dir("is not a directory".into()));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(unsafe_dir(format!(
            "owned by uid {}, expected {euid}",
            meta.uid()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        tracing::warn!(path = %path.display(), mode = format!("{:o}", meta.mode() & 0o7777),
            "state directory was accessible to others; restricting to 0700");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_err(path))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_dir(path: &Path) -> Result<(), StateError> {
    // TODO(windows): apply a SYSTEM/Administrators-only DACL (§3.3 Windows).
    let meta = fs::symlink_metadata(path).map_err(io_err(path))?;
    if !meta.is_dir() {
        return Err(StateError::Unsafe {
            path: path.to_path_buf(),
            reason: "is not a directory".into(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn tighten_file(path: &Path, meta: &fs::Metadata) -> Result<(), StateError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if meta.mode() & 0o077 != 0 {
        tracing::warn!(path = %path.display(), "state file was accessible to others; restricting to 0600");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io_err(path))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn tighten_file(_path: &Path, _meta: &fs::Metadata) -> Result<(), StateError> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).unwrap().mode() & 0o7777
    }

    #[test]
    fn creates_private_dir_and_secret_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path().join("a/b/state")).unwrap();
        #[cfg(unix)]
        assert_eq!(mode(dir.path()), 0o700);
        dir.write_secret("x", b"hello").unwrap();
        #[cfg(unix)]
        assert_eq!(mode(&dir.file("x")), 0o600);
        assert_eq!(dir.read_secret("x").unwrap().unwrap().as_slice(), b"hello");
        assert!(dir.read_secret("missing").unwrap().is_none());
        // No temp files left behind.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("x")]);
    }

    #[cfg(unix)]
    #[test]
    fn tightens_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("state");
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        let dir = StateDir::open(&p).unwrap();
        assert_eq!(mode(&p), 0o700);
        fs::write(dir.file("f"), b"1").unwrap();
        fs::set_permissions(dir.file("f"), fs::Permissions::from_mode(0o644)).unwrap();
        dir.read_secret("f").unwrap();
        assert_eq!(mode(&dir.file("f")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            StateDir::open(&link),
            Err(StateError::Unsafe { .. })
        ));
        assert!(matches!(
            StateDir::open("relative"),
            Err(StateError::Unsafe { .. })
        ));
    }

    #[test]
    fn device_key_roundtrip_and_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path().join("s")).unwrap();
        assert!(matches!(
            load_device_key(&dir),
            Err(StateError::NotEnrolled)
        ));
        let k = store_device_key(&dir).unwrap();
        assert_eq!(load_device_key(&dir).unwrap().public(), k.public());
        let k2 = store_device_key(&dir).unwrap();
        assert_ne!(k.public(), k2.public(), "a fresh key every enrollment");
        dir.write_secret(DEVICE_KEY_FILE, b"short").unwrap();
        assert!(matches!(
            load_device_key(&dir),
            Err(StateError::Corrupt { .. })
        ));
    }

    #[test]
    fn enrollment_debug_redacts_token() {
        let e = Enrollment {
            instance_url: "https://a.example/".into(),
            instance_id: InstanceId::new("inst_a"),
            instance_name: "A".into(),
            instance_identity_pubkey: SignPublicKey([1; 32]),
            device_id: DeviceId::new("dev_a"),
            device_token: "super-secret-token".into(),
            member_id: UserId::new("usr_m"),
            member_sign_pubkey: SignPublicKey([2; 32]),
            device_name: "Laptop".into(),
            enrolled_at_ms: 1,
        };
        let s = format!("{e:?}");
        assert!(!s.contains("super-secret-token"), "{s}");
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path().join("s")).unwrap();
        assert!(matches!(dir.enrollment(), Err(StateError::NotEnrolled)));
        dir.write_json(ENROLLMENT_FILE, &e).unwrap();
        assert_eq!(dir.enrollment().unwrap(), e);
    }
}
