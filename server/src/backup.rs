//! `faro-server backup --out FILE.tar` (§4.2 "Backups").
//!
//! Writes one consistent tarball:
//!
//! | Entry | What |
//! |---|---|
//! | `faro.db` | SQLite snapshot made with `VACUUM INTO` (consistent while the server runs) |
//! | `identity.key` | the instance identity: clients pin it, and token hashes derive from it |
//! | `faro.toml` | the config file, if one was given |
//! | `blobs/…` | every ciphertext blob, at its path under the data directory |
//! | `BACKUP-INFO.txt` | version, instance id, time, restore steps |
//!
//! The database is snapshotted **before** the blobs are copied, so every
//! blob the snapshot references is either in the archive or was deleted by
//! retention in between (which would have deleted it anyway). Blobs written
//! after the snapshot may also be included; with no row pointing at them
//! they are swept as orphans after a restore.
//!
//! With Postgres the database is not in the archive: `pg_dump` is the right
//! tool (guidance is printed), and the archive still carries the identity key
//! and blobs, which `pg_dump` cannot.
//!
//! The archive contains the identity key and possibly SMTP credentials, so it
//! is created with mode 0600. The database snapshot is staged in a scratch
//! directory created 0700 (and the snapshot itself is made 0600), so a full
//! copy of the database is never readable by other local users while the
//! backup runs, wherever `--out` points. The finished archive is published
//! without replacing anything that appeared at `--out` meanwhile. Backups follow the retention windows: rotate
//! them (keep at most `blob_days` worth) so deleted data does not live on.

use crate::config::Config;
use crate::db::repo::instance;
use crate::db::{Backend, Db, DbError};
use crate::identity::IDENTITY_FILE;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("{0} does not exist; is this the right data directory? (run `faro-server init`)")]
    NotInitialized(PathBuf),
    #[error("database: {0}")]
    Db(#[from] DbError),
    #[error("database: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("the database has no instance row; run `faro-server init` first")]
    NoInstance,
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("refusing to overwrite existing file {0}")]
    Exists(PathBuf),
    #[error("backup task failed: {0}")]
    Join(String),
    #[error("cannot snapshot the database into {0}: the path must be absolute UTF-8 without control characters")]
    BadSnapshotPath(PathBuf),
    #[error("the database snapshot was not written to {0}")]
    Snapshot(PathBuf),
}

/// The `VACUUM INTO` target inside `scratch`, as a string SQLite will treat
/// as a plain file path: canonical (absolute, no `..`, symlinks resolved),
/// valid UTF-8 (a lossy conversion would snapshot to a different file), free
/// of control characters, and so never starting with `file:`.
fn snapshot_target(scratch: &Path) -> Result<String, BackupError> {
    let dir = std::fs::canonicalize(scratch).map_err(io(scratch))?;
    let target = dir.join("faro.db");
    let bad = || BackupError::BadSnapshotPath(target.clone());
    let s = target.to_str().ok_or_else(bad)?;
    if !target.is_absolute()
        || s.chars().any(char::is_control)
        || s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("file:"))
    {
        return Err(bad());
    }
    Ok(s.to_owned())
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> BackupError + '_ {
    move |source| BackupError::Io {
        path: path.to_owned(),
        source,
    }
}

/// What was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub path: PathBuf,
    pub database_included: bool,
    pub blob_files: u64,
    /// Set for Postgres: how to back up the database itself.
    pub postgres_guidance: Option<String>,
}

/// Removes the scratch directory however the backup ends.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub const POSTGRES_GUIDANCE: &str = "This instance uses Postgres, so the database is not in \
    this archive. Back it up with pg_dump, for example:\n\n    \
    pg_dump --format=custom --file=faro-db.dump \"$FARO_DATABASE_URL\"\n\n\
    and restore with pg_restore. Keep the dump together with this archive: the identity key \
    and blobs in it belong to that database.";

/// Write a backup of the instance described by `cfg` to `out`.
pub async fn run(
    cfg: &Config,
    config_path: Option<&Path>,
    out: &Path,
) -> Result<BackupReport, BackupError> {
    if out.exists() {
        return Err(BackupError::Exists(out.to_owned()));
    }
    let identity = cfg.data_dir.join(IDENTITY_FILE);
    if !identity.is_file() {
        return Err(BackupError::NotInitialized(identity));
    }
    if cfg.database_url.is_none() && !cfg.data_dir.join("faro.db").is_file() {
        return Err(BackupError::NotInitialized(cfg.data_dir.join("faro.db")));
    }
    let db = Db::connect(&cfg.database_url()).await?;
    let inst = instance::get(db.pool())
        .await?
        .ok_or(BackupError::NoInstance)?;

    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => PathBuf::from("."),
    };
    let scratch_dir = parent.join(format!(".faro-backup-{}", crate::tokens::new_hex_id()));
    // Not `_all`: the random name must be new, so nothing else can have
    // planted a file where the snapshot goes. Private: it holds a full copy
    // of the database.
    create_private_dir(&scratch_dir).map_err(io(&scratch_dir))?;
    let scratch = Scratch(scratch_dir);

    let (snapshot, guidance) = match db.backend() {
        Backend::Sqlite => {
            let snap = snapshot_target(&scratch.0)?;
            // The target is a bound parameter (SQLite accepts any string
            // expression after INTO), so no path text is ever spliced into
            // SQL. `snapshot_target` additionally guarantees an absolute,
            // plain path, because sqlx opens SQLite with URI filenames
            // enabled and a `file:` string would be parsed as a URI.
            sqlx::query("VACUUM INTO $1")
                .bind(snap.as_str())
                .execute(db.pool())
                .await?;
            let snap = PathBuf::from(snap);
            if !snap.is_file() {
                return Err(BackupError::Snapshot(snap));
            }
            make_private(&snap).map_err(io(&snap))?;
            (Some(snap), None)
        }
        Backend::Postgres => (None, Some(POSTGRES_GUIDANCE.to_owned())),
    };
    db.close().await;

    let info = format!(
        "Faro instance backup\n\
         server version: {}\n\
         instance id:    {}\n\
         instance name:  {}\n\
         created (unix ms): {}\n\n\
         Restore:\n\
         1. Stop faro-server.\n\
         2. Extract into the data directory: tar -xf <this file> -C <data_dir>\n\
            (faro.db is the SQLite database; if you use a custom database_url, move it there.)\n\
         3. Make sure identity.key is mode 0600 and the directory 0700.\n\
         4. Start faro-server. It refuses to start if identity.key does not match the database.\n\
         {}\n",
        crate::SERVER_VERSION,
        inst.id,
        inst.name,
        crate::clock::Clock::now_ms(&crate::clock::SystemClock),
        guidance.as_deref().unwrap_or(""),
    );

    let job = TarJob {
        out: out.to_owned(),
        partial: parent.join(format!(
            ".{}.partial",
            out.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "backup.tar".to_owned())
        )),
        snapshot,
        identity,
        config: config_path.map(Path::to_owned),
        blobs: cfg.data_dir.join("blobs"),
        info,
    };
    let blob_files = tokio::task::spawn_blocking(move || job.write())
        .await
        .map_err(|e| BackupError::Join(e.to_string()))??;
    drop(scratch);
    Ok(BackupReport {
        path: out.to_owned(),
        database_included: guidance.is_none(),
        blob_files,
        postgres_guidance: guidance,
    })
}

struct TarJob {
    out: PathBuf,
    partial: PathBuf,
    snapshot: Option<PathBuf>,
    identity: PathBuf,
    config: Option<PathBuf>,
    blobs: PathBuf,
    info: String,
}

impl TarJob {
    fn write(self) -> Result<u64, BackupError> {
        let result = self
            .write_partial()
            .and_then(|n| publish_no_replace(&self.partial, &self.out).map(|()| n));
        if result.is_err() {
            let _ = std::fs::remove_file(&self.partial);
        }
        result
    }

    fn write_partial(&self) -> Result<u64, BackupError> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file: File = opts.open(&self.partial).map_err(io(&self.partial))?;
        let mut tar = tar::Builder::new(file);
        tar.follow_symlinks(false);

        let mut info = tar::Header::new_gnu();
        info.set_size(self.info.len() as u64);
        info.set_mode(0o600);
        info.set_mtime(0);
        info.set_cksum();
        tar.append_data(&mut info, "BACKUP-INFO.txt", self.info.as_bytes())
            .map_err(io(&self.partial))?;

        if let Some(s) = &self.snapshot {
            tar.append_path_with_name(s, "faro.db").map_err(io(s))?;
        }
        tar.append_path_with_name(&self.identity, IDENTITY_FILE)
            .map_err(io(&self.identity))?;
        if let Some(c) = &self.config {
            tar.append_path_with_name(c, "faro.toml").map_err(io(c))?;
        }
        let mut n = 0;
        // Canonical layout only: blobs/aa/bb/<id>; the tmp dir is skipped.
        for l1 in sorted_entries(&self.blobs)? {
            if l1 == "tmp" || l1.len() != 2 {
                continue;
            }
            let d1 = self.blobs.join(&l1);
            for l2 in sorted_entries(&d1)? {
                let d2 = d1.join(&l2);
                for name in sorted_entries(&d2)? {
                    if crate::blob::BlobId::parse(&name).is_none() {
                        continue;
                    }
                    let p = d2.join(&name);
                    match tar.append_path_with_name(&p, format!("blobs/{l1}/{l2}/{name}")) {
                        Ok(()) => n += 1,
                        // Deleted by retention while we were copying.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(io(&p)(e)),
                    }
                }
            }
        }
        let mut file = tar.into_inner().map_err(io(&self.partial))?;
        file.flush().map_err(io(&self.partial))?;
        file.sync_all().map_err(io(&self.partial))?;
        Ok(n)
    }
}

/// Create a new directory only its owner can enter (0700 on Unix).
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    // `mut` is only needed for the Unix-only `mode` call below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

/// Restrict a file to its owner (0600 on Unix).
fn make_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Move the finished archive to `out` without ever replacing a file that
/// appeared there since the up-front check: a hard link fails if `out`
/// exists, then the temporary name is dropped. On a filesystem without hard
/// links, fall back to a checked rename.
fn publish_no_replace(partial: &Path, out: &Path) -> Result<(), BackupError> {
    match std::fs::hard_link(partial, out) {
        Ok(()) => {
            std::fs::remove_file(partial).map_err(io(partial))?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(BackupError::Exists(out.to_owned()))
        }
        Err(_) => {
            if out.exists() {
                return Err(BackupError::Exists(out.to_owned()));
            }
            std::fs::rename(partial, out).map_err(io(out))
        }
    }
}

fn sorted_entries(dir: &Path) -> Result<Vec<String>, BackupError> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(dir)(e)),
    };
    let mut v = Vec::new();
    for e in rd {
        let e = e.map_err(io(dir))?;
        if let Some(n) = e.file_name().to_str() {
            v.push(n.to_owned());
        }
    }
    v.sort();
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_target_is_canonical_and_plain() {
        let d = tempfile::tempdir().unwrap();
        let t = snapshot_target(d.path()).unwrap();
        assert!(Path::new(&t).is_absolute());
        assert!(t.ends_with("faro.db"));
        assert!(!t.to_ascii_lowercase().starts_with("file:"));
        // A relative or `..`-laden scratch path is resolved, not passed on.
        let nested = d.path().join("a");
        std::fs::create_dir(&nested).unwrap();
        let dotted = nested.join("..").join("a");
        // Compare as paths, not strings: the separator is `\\` on Windows.
        let resolved = snapshot_target(&dotted).unwrap();
        assert_eq!(resolved, snapshot_target(&nested).unwrap());
        assert_eq!(
            Path::new(&resolved),
            Path::new(&t).parent().unwrap().join("a").join("faro.db")
        );
        assert!(snapshot_target(&d.path().join("missing")).is_err());
    }

    #[test]
    fn publishing_never_replaces_an_existing_file() {
        let d = tempfile::tempdir().unwrap();
        let partial = d.path().join(".b.partial");
        let out = d.path().join("b.tar");
        std::fs::write(&partial, b"new").unwrap();
        std::fs::write(&out, b"someone else's").unwrap();
        assert!(matches!(
            publish_no_replace(&partial, &out),
            Err(BackupError::Exists(_))
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"someone else's");
        std::fs::remove_file(&out).unwrap();
        publish_no_replace(&partial, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"new");
        assert!(!partial.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("scratch");
        create_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(create_private_dir(&dir).is_err(), "must be new");
        let f = dir.join("faro.db");
        std::fs::write(&f, b"x").unwrap();
        make_private(&f).unwrap();
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_target_rejects_control_characters() {
        let d = tempfile::tempdir().unwrap();
        let odd = d.path().join("x\ny");
        std::fs::create_dir(&odd).unwrap();
        assert!(matches!(
            snapshot_target(&odd),
            Err(BackupError::BadSnapshotPath(_))
        ));
    }
}
