//! Streaming verification of downloaded artifacts.
//!
//! The signed length is the only length we believe. A mirror's
//! `Content-Length` header (or a file's size on disk) is never consulted:
//! we read at most `length + 1` bytes — the extra byte is how an overlong
//! stream is detected — and hash as we go, so memory use is constant and an
//! endless or oversized response is cut off at the signed length.

use crate::error::StreamError;
use crate::select::TargetInfo;
use std::io::{ErrorKind, Read, Write};

const CHUNK: usize = 64 * 1024;

/// Read `reader` to the end and check it is exactly `info`'s length and
/// BLAKE3. `max_len` is the caller's own hard cap (e.g. free disk space or a
/// per-kind ceiling); a target whose *signed* length exceeds it is refused
/// before a single byte is read.
pub fn verify_target_stream<R: Read>(
    reader: R,
    info: &TargetInfo,
    max_len: u64,
) -> Result<(), StreamError> {
    run(reader, None, info, max_len)
}

/// Like [`verify_target_stream`], but also copies the bytes to `sink` as
/// they are verified (typically a temporary file next to the install
/// location).
///
/// Bytes reach `sink` *before* the final hash check can pass, so the sink's
/// contents are untrusted until this returns `Ok`; on `Err` the caller must
/// delete them. Bytes beyond the signed length are never written.
pub fn copy_verified_target<R: Read, W: Write>(
    reader: R,
    mut sink: W,
    info: &TargetInfo,
    max_len: u64,
) -> Result<(), StreamError> {
    run(reader, Some(&mut sink), info, max_len)?;
    sink.flush()?;
    Ok(())
}

fn run<R: Read>(
    mut reader: R,
    mut sink: Option<&mut dyn Write>,
    info: &TargetInfo,
    max_len: u64,
) -> Result<(), StreamError> {
    let expected = info.length;
    if expected > max_len {
        return Err(StreamError::ExceedsCap {
            name: info.name.clone(),
            length: expected,
            max_len,
        });
    }
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    loop {
        // Never ask for more than one byte past the signed length.
        let remaining_plus_one = (expected - total).saturating_add(1);
        let want = usize::try_from(remaining_plus_one).map_or(CHUNK, |r| r.min(CHUNK));
        let n = match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            // A reader claiming more than the buffer it was given violates
            // the `Read` contract; refuse rather than index out of bounds.
            Ok(n) if n > want => {
                return Err(
                    std::io::Error::other("reader reported more bytes than requested").into(),
                )
            }
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        // `n <= want <= expected - total + 1`, so this cannot overflow.
        total += n as u64;
        if total > expected {
            return Err(StreamError::TooLong {
                name: info.name.clone(),
                expected,
            });
        }
        let chunk = &buf[..n];
        hasher.update(chunk);
        if let Some(w) = sink.as_mut() {
            w.write_all(chunk)?;
        }
    }
    if total < expected {
        return Err(StreamError::TooShort {
            name: info.name.clone(),
            got: total,
            expected,
        });
    }
    if hasher.finalize().as_bytes() != info.blake3.as_bytes() {
        return Err(StreamError::HashMismatch {
            name: info.name.clone(),
        });
    }
    Ok(())
}
