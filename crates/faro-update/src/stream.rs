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
    let mut verifier = TargetVerifier::new(info, max_len)?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        // Never ask for more than one byte past the signed length.
        let want =
            usize::try_from(verifier.remaining().saturating_add(1)).map_or(CHUNK, |r| r.min(CHUNK));
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
        let chunk = &buf[..n];
        verifier.update(chunk)?;
        if let Some(w) = sink.as_mut() {
            w.write_all(chunk)?;
        }
    }
    verifier.finish()
}

/// Incremental form of [`verify_target_stream`], for callers that receive
/// the artifact in chunks they don't control (an async HTTP body).
///
/// Feed every chunk to [`update`](Self::update) *before* using it, then call
/// [`finish`](Self::finish). `update` fails as soon as the total passes the
/// signed length, so a caller that writes each chunk only after `update`
/// accepted it never stores a byte past that length. As with
/// [`copy_verified_target`], nothing written is trustworthy until `finish`
/// returns `Ok`.
#[derive(Debug)]
pub struct TargetVerifier {
    name: String,
    expected: u64,
    blake3: [u8; 32],
    total: u64,
    hasher: blake3::Hasher,
}

impl TargetVerifier {
    /// Start verifying `info`. Refuses a target whose signed length exceeds
    /// the caller's own cap `max_len` before any byte arrives.
    pub fn new(info: &TargetInfo, max_len: u64) -> Result<Self, StreamError> {
        if info.length > max_len {
            return Err(StreamError::ExceedsCap {
                name: info.name.clone(),
                length: info.length,
                max_len,
            });
        }
        Ok(TargetVerifier {
            name: info.name.clone(),
            expected: info.length,
            blake3: *info.blake3.as_bytes(),
            total: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// Bytes still expected before the signed length is reached.
    pub fn remaining(&self) -> u64 {
        self.expected - self.total
    }

    /// Account for the next chunk. Errors if it takes the total past the
    /// signed length; the chunk must then be discarded.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), StreamError> {
        let n = chunk.len() as u64;
        if n > self.remaining() {
            return Err(StreamError::TooLong {
                name: self.name.clone(),
                expected: self.expected,
            });
        }
        self.total += n;
        self.hasher.update(chunk);
        Ok(())
    }

    /// The stream ended: check the length and the hash.
    pub fn finish(self) -> Result<(), StreamError> {
        if self.total < self.expected {
            return Err(StreamError::TooShort {
                name: self.name,
                got: self.total,
                expected: self.expected,
            });
        }
        if self.hasher.finalize().as_bytes() != &self.blake3 {
            return Err(StreamError::HashMismatch { name: self.name });
        }
        Ok(())
    }
}
