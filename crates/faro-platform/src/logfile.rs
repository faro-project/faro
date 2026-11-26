//! A log file that rotates itself by size.
//!
//! The service and the agent write their logs through this when they run
//! from the package (on macOS, `faro_platform_macos::pkg_layout::SERVICE_LOG`
//! and `agent_log`). Rotation is done in-process, not by `newsyslog`: a file
//! launchd opens for a job (`StandardErrorPath`) stays open in the process,
//! so after `newsyslog` renamed it the process would keep writing to the
//! old file until it restarts.
//!
//! When a write would take the file past [`Rotation::max_bytes`], `log` is
//! renamed to `log.1`, `log.1` to `log.2` and so on up to
//! [`Rotation::keep`], the oldest is removed, and a new `log` is opened.
//! Each file is created with [`Rotation::mode`] and has it set again when
//! opened, whatever the umask.
//!
//! Wrap it in a `Mutex` to hand it to `tracing_subscriber` as a writer: the
//! formatter writes each event with one `write_all`, so a file never ends
//! in half a line.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// When to rotate, how many old files to keep, and their permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// Rotate before a write would make the file larger than this.
    pub max_bytes: u64,
    /// Old files to keep (`log.1` … `log.<keep>`). 0 keeps none.
    pub keep: u32,
    /// Unix permission bits of every file (ignored elsewhere).
    pub mode: u32,
}

/// The path of the `n`th rotated file (`faro-service.log.1` for `n = 1`);
/// `n = 0` is the current file itself.
pub fn rotated_path(path: &Path, n: u32) -> PathBuf {
    if n == 0 {
        return path.to_path_buf();
    }
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Every file a log at `path` can consist of, newest first: the current
/// file, then the rotated ones. Some may not exist.
pub fn log_files(path: &Path, rotation: &Rotation) -> Vec<PathBuf> {
    (0..=rotation.keep).map(|n| rotated_path(path, n)).collect()
}

/// An append-only log file that rotates by size ([module docs](self)).
#[derive(Debug)]
pub struct RotatingFile {
    path: PathBuf,
    rotation: Rotation,
    file: File,
    len: u64,
}

impl RotatingFile {
    /// Open (or create) the log at `path` for appending. The directory must
    /// exist.
    pub fn open(path: impl Into<PathBuf>, rotation: Rotation) -> io::Result<Self> {
        let path = path.into();
        let file = open_append(&path, rotation.mode)?;
        let len = file.metadata()?.len();
        Ok(RotatingFile {
            path,
            rotation,
            file,
            len,
        })
    }

    /// The current file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate(&mut self) -> io::Result<()> {
        if self.rotation.keep == 0 {
            std::fs::remove_file(&self.path).or_else(ignore_missing)?;
        } else {
            let oldest = rotated_path(&self.path, self.rotation.keep);
            std::fs::remove_file(&oldest).or_else(ignore_missing)?;
            for n in (0..self.rotation.keep).rev() {
                let from = rotated_path(&self.path, n);
                std::fs::rename(&from, rotated_path(&self.path, n + 1)).or_else(ignore_missing)?;
            }
        }
        self.file = open_append(&self.path, self.rotation.mode)?;
        self.len = self.file.metadata()?.len();
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.len > 0 && self.len.saturating_add(buf.len() as u64) > self.rotation.max_bytes {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.len = self.len.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn ignore_missing(e: io::Error) -> io::Result<()> {
    if e.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
}

#[cfg(unix)]
fn open_append(path: &Path, mode: u32) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // A log is never written through a symbolic link: whoever can write
    // the directory could otherwise point it at another file.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symbolic link", path.display()),
        ));
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(mode)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_append(path: &Path, _mode: u32) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: Rotation = Rotation {
        max_bytes: 10,
        keep: 2,
        mode: 0o640,
    };

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    #[test]
    fn rotates_by_size_and_keeps_the_newest() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("x.log");
        let mut f = RotatingFile::open(&log, SMALL).unwrap();
        for line in [
            "aaaa\n", "bbbb\n", "cccc\n", "dddd\n", "eeee\n", "ffff\n", "gggg\n",
        ] {
            f.write_all(line.as_bytes()).unwrap();
        }
        assert_eq!(read(&log), "gggg\n");
        assert_eq!(read(&rotated_path(&log, 1)), "eeee\nffff\n");
        assert_eq!(read(&rotated_path(&log, 2)), "cccc\ndddd\n");
        assert!(!rotated_path(&log, 3).exists());
        assert_eq!(
            log_files(&log, &SMALL),
            vec![
                log.clone(),
                dir.path().join("x.log.1"),
                dir.path().join("x.log.2")
            ]
        );
    }

    #[test]
    fn appends_to_an_existing_file_and_counts_it() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("x.log");
        std::fs::write(&log, "12345678\n").unwrap();
        let mut f = RotatingFile::open(&log, SMALL).unwrap();
        f.write_all(b"next\n").unwrap();
        assert_eq!(read(&log), "next\n");
        assert_eq!(read(&rotated_path(&log, 1)), "12345678\n");
    }

    #[test]
    fn a_line_longer_than_the_limit_is_written_whole() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("x.log");
        let mut f = RotatingFile::open(&log, SMALL).unwrap();
        f.write_all(b"a line well past ten bytes\n").unwrap();
        assert_eq!(read(&log), "a line well past ten bytes\n");
        assert!(!rotated_path(&log, 1).exists());
    }

    #[test]
    fn keep_zero_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("x.log");
        let mut f = RotatingFile::open(&log, Rotation { keep: 0, ..SMALL }).unwrap();
        f.write_all(b"0123456789").unwrap();
        f.write_all(b"new\n").unwrap();
        assert_eq!(read(&log), "new\n");
        assert!(!rotated_path(&log, 1).exists());
    }

    #[cfg(unix)]
    #[test]
    fn every_file_has_the_mode_and_symlinks_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("x.log");
        std::fs::write(&log, "").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut f = RotatingFile::open(&log, SMALL).unwrap();
        f.write_all(b"0123456789").unwrap();
        f.write_all(b"x\n").unwrap();
        for p in [log.clone(), rotated_path(&log, 1)] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640, "{}", p.display());
        }

        let link = dir.path().join("link.log");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &link).unwrap();
        assert!(RotatingFile::open(&link, SMALL).is_err());
        assert!(!dir.path().join("elsewhere").exists());
    }
}
