//! Length-prefixed, versioned framing (ARCHITECTURE.md §3.1).
//!
//! ```text
//! +--------+-------------+----------------+---------------------+
//! | "FARO" | version u16 | length u32     | postcard payload    |
//! | 4 B    | big-endian  | big-endian     | `length` bytes      |
//! +--------+-------------+----------------+---------------------+
//! ```
//!
//! Decoding is done by a sans-I/O [`FrameDecoder`] shared by the sync
//! ([`read_msg`]) and async ([`read_msg_async`], [`Connection`](crate::Connection))
//! drivers, so all three have identical semantics:
//!
//! * the header is fully validated (magic, version, length cap) **before**
//!   any payload buffer is allocated;
//! * end of input before the first header byte is [`IpcError::Closed`];
//!   anywhere else it is [`IpcError::Truncated`];
//! * the payload must decode exactly, with no trailing bytes, and pass
//!   [`WireMessage::validate`];
//! * payload buffers (which hold raw pixels for `Frames`) are zeroized when
//!   dropped, on success and on every error path.
//!
//! Nothing in this module panics on arbitrary input (property-tested and
//! fuzzed: see `fuzz/`).

use std::io::{ErrorKind, Read, Write};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::error::{IpcError, Result};
use crate::messages::{frames_capped, WireMessage};
use crate::wire_frame::MAX_FRAME_BYTES;

/// Frame magic: every message starts with these bytes.
pub const MAGIC: [u8; 4] = *b"FARO";

/// The protocol version this build speaks (and writes in every header).
pub const PROTOCOL_VERSION: u16 = 1;

/// The oldest header version this build will accept. Agent and service ship
/// in the same package and are updated together, so the window is a single
/// version today; widening it means teaching [`decode_payload`] the old
/// layout.
pub const MIN_PROTOCOL_VERSION: u16 = 1;

/// Size of the fixed header: magic + version + length.
pub const HEADER_LEN: usize = 4 + 2 + 4;

/// Maximum displays carried by one `Frames` message.
///
/// Four covers the overwhelming majority of desks; machines with more
/// displays send several `Frames` messages sharing `captured_at_mono_ms`
/// (see [`AgentMsg::frames_batches`](crate::AgentMsg::frames_batches)). Keeping this small
/// keeps [`MAX_PAYLOAD_LEN`], and hence the most memory a single (possibly
/// hostile) peer can make the privileged service allocate, small.
pub const MAX_FRAMES_PER_MESSAGE: usize = 4;

/// Room for everything in a payload that is not pixel data: postcard varints
/// and per-frame metadata (< 32 B per frame) and, for non-frame messages,
/// strings such as window titles and URLs. 256 KiB is far above any
/// legitimate title/URL while staying small relative to the pixel budget.
pub const PAYLOAD_OVERHEAD_ALLOWANCE: usize = 256 * 1024;

/// Hard cap on a payload: 4 displays × 768 × 768 × 4 B (9 MiB) + 256 KiB
/// ≈ 9.25 MiB. Checked against the header's declared length before
/// allocating, and against the real length when encoding.
pub const MAX_PAYLOAD_LEN: usize =
    MAX_FRAMES_PER_MESSAGE * MAX_FRAME_BYTES + PAYLOAD_OVERHEAD_ALLOWANCE;

/// A parsed and validated frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub payload_len: usize,
}

/// Parse and validate a header. Never allocates.
pub fn parse_header(bytes: &[u8; HEADER_LEN]) -> Result<FrameHeader> {
    if bytes[0..4] != MAGIC {
        return Err(IpcError::BadMagic);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version) {
        return Err(IpcError::UnsupportedVersion {
            got: version,
            min: MIN_PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
        });
    }
    let len = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    let payload_len = usize::try_from(len).map_err(|_| IpcError::PayloadTooLarge {
        len: u64::from(len),
        max: MAX_PAYLOAD_LEN,
    })?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(IpcError::PayloadTooLarge {
            len: u64::from(len),
            max: MAX_PAYLOAD_LEN,
        });
    }
    Ok(FrameHeader {
        version,
        payload_len,
    })
}

/// Encode `msg` into a complete frame (header + payload).
///
/// The result may contain raw pixels, so it is returned as
/// [`Zeroizing`]. The buffer is sized exactly up front (a counting pass, then
/// a serialize-into-slice pass) so it never reallocates and leaves no stray
/// copies of pixel data in freed memory.
pub fn encode<M: WireMessage>(msg: &M) -> Result<Zeroizing<Vec<u8>>> {
    msg.validate()?;
    let size =
        postcard::serialize_with_flavor::<M, _, usize>(msg, postcard::ser_flavors::Size::default())
            .map_err(IpcError::Encode)?;
    if size > MAX_PAYLOAD_LEN {
        return Err(IpcError::PayloadTooLarge {
            len: size as u64,
            max: MAX_PAYLOAD_LEN,
        });
    }
    let mut buf = Zeroizing::new(vec![0u8; HEADER_LEN + size]);
    let used = postcard::to_slice(msg, &mut buf[HEADER_LEN..])
        .map_err(IpcError::Encode)?
        .len();
    // `size` was computed by the same serializer, so `used == size`; the
    // header is written from `used` regardless so it can never lie.
    buf.truncate(HEADER_LEN + used);
    let len = u32::try_from(used).map_err(|_| IpcError::PayloadTooLarge {
        len: used as u64,
        max: MAX_PAYLOAD_LEN,
    })?;
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    buf[6..10].copy_from_slice(&len.to_be_bytes());
    Ok(buf)
}

/// Decode one complete frame held in memory. `bytes` must contain exactly
/// one frame: shorter is [`IpcError::Truncated`], longer is
/// [`IpcError::TrailingBytes`].
pub fn decode<M: WireMessage>(bytes: &[u8]) -> Result<M> {
    let Some(head) = bytes.first_chunk::<HEADER_LEN>() else {
        return Err(if bytes.is_empty() {
            IpcError::Closed
        } else {
            IpcError::Truncated {
                expected: HEADER_LEN,
                got: bytes.len(),
            }
        });
    };
    let header = parse_header(head)?;
    let body = &bytes[HEADER_LEN..];
    if body.len() < header.payload_len {
        return Err(IpcError::Truncated {
            expected: HEADER_LEN + header.payload_len,
            got: bytes.len(),
        });
    }
    if body.len() > header.payload_len {
        return Err(IpcError::TrailingBytes(body.len() - header.payload_len));
    }
    decode_payload(header.version, body)
}

/// Decode a payload whose header has already been validated.
///
/// `version` selects the payload layout. Only one version exists today; the
/// parameter is the hook for the next one.
pub fn decode_payload<M: WireMessage>(version: u16, payload: &[u8]) -> Result<M> {
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version) {
        return Err(IpcError::UnsupportedVersion {
            got: version,
            min: MIN_PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
        });
    }
    // See `messages::frames_capped`: an over-long frame list is refused
    // during decoding and reported here as the typed error.
    let _ = frames_capped::take_over_cap();
    let decoded = postcard::take_from_bytes::<M>(payload);
    let over_cap = frames_capped::take_over_cap();
    let (msg, rest) = match decoded {
        Ok(v) => v,
        Err(e) => {
            return Err(match over_cap {
                Some(count) => IpcError::TooManyFrames {
                    count,
                    max: MAX_FRAMES_PER_MESSAGE,
                },
                None => IpcError::Decode(e),
            })
        }
    };
    if !rest.is_empty() {
        return Err(IpcError::TrailingBytes(rest.len()));
    }
    msg.validate()?;
    Ok(msg)
}

/// Incremental, sans-I/O frame decoder.
///
/// Drive it by reading into [`FrameDecoder::buf_mut`] and reporting the
/// count to [`FrameDecoder::advance`]. Because all progress lives here and
/// not in a future's stack, an async driver that only `.await`s single
/// `read` calls is cancellation-safe: dropping a pending receive loses no
/// bytes.
#[derive(Default)]
pub struct FrameDecoder {
    header: [u8; HEADER_LEN],
    header_filled: usize,
    /// Present once the header has been validated.
    payload: Option<(u16, Zeroizing<Vec<u8>>)>,
    payload_filled: usize,
}

impl std::fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("buffered", &self.buffered())
            .field("expected", &self.expected())
            .finish()
    }
}

/// A complete, framed payload ready for [`decode_payload`].
pub struct RawPayload {
    pub version: u16,
    /// Zeroized on drop.
    pub bytes: Zeroizing<Vec<u8>>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when no bytes of a partial message are buffered: an EOF now is a
    /// clean close.
    pub fn is_idle(&self) -> bool {
        self.header_filled == 0 && self.payload.is_none()
    }

    /// Bytes of the current message received so far.
    pub fn buffered(&self) -> usize {
        self.header_filled + self.payload_filled
    }

    /// Total bytes of the current message, as far as is known yet.
    pub fn expected(&self) -> usize {
        match &self.payload {
            Some((_, p)) => HEADER_LEN + p.len(),
            None => HEADER_LEN,
        }
    }

    /// The error to report if input ends now.
    pub fn eof_error(&self) -> IpcError {
        if self.is_idle() {
            IpcError::Closed
        } else {
            IpcError::Truncated {
                expected: self.expected(),
                got: self.buffered(),
            }
        }
    }

    /// Where the next bytes should be written. Never empty while a message
    /// is incomplete (zero-length payloads complete inside `advance`).
    pub fn buf_mut(&mut self) -> &mut [u8] {
        match &mut self.payload {
            Some((_, p)) => &mut p[self.payload_filled..],
            None => &mut self.header[self.header_filled..],
        }
    }

    /// Record that `n` bytes were written into [`buf_mut`](Self::buf_mut).
    /// Returns the payload once a whole message has arrived.
    ///
    /// On error the decoder resets; the stream itself should be considered
    /// desynchronized and dropped.
    pub fn advance(&mut self, n: usize) -> Result<Option<RawPayload>> {
        let room = self.buf_mut().len();
        if n > room {
            // A misbehaving reader claimed more than it was given room for.
            self.reset();
            return Err(IpcError::Broken(
                "reader reported more bytes than buffer space",
            ));
        }
        if self.payload.is_some() {
            self.payload_filled += n;
        } else {
            self.header_filled += n;
            if self.header_filled == HEADER_LEN {
                let header = match parse_header(&self.header) {
                    Ok(h) => h,
                    Err(e) => {
                        self.reset();
                        return Err(e);
                    }
                };
                // Bounded by MAX_PAYLOAD_LEN, validated above.
                self.payload = Some((
                    header.version,
                    Zeroizing::new(vec![0u8; header.payload_len]),
                ));
                self.payload_filled = 0;
            }
        }
        match &self.payload {
            Some((_, p)) if self.payload_filled == p.len() => {
                let (version, bytes) = self
                    .payload
                    .take()
                    .ok_or(IpcError::Broken("decoder state lost its payload buffer"))?;
                self.reset();
                Ok(Some(RawPayload { version, bytes }))
            }
            _ => Ok(None),
        }
    }

    fn reset(&mut self) {
        self.header = [0; HEADER_LEN];
        self.header_filled = 0;
        self.payload = None; // Zeroizing drop wipes any partial payload.
        self.payload_filled = 0;
    }
}

/// Write one message to a blocking writer and flush it.
pub fn write_msg<W: Write + ?Sized, M: WireMessage>(w: &mut W, msg: &M) -> Result<()> {
    let buf = encode(msg)?;
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read one message from a blocking reader.
///
/// Reads exactly one frame and never past it, so successive calls on the
/// same reader see successive messages.
pub fn read_msg<R: Read + ?Sized, M: WireMessage>(r: &mut R) -> Result<M> {
    let mut dec = FrameDecoder::new();
    loop {
        let n = match r.read(dec.buf_mut()) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Err(dec.eof_error());
        }
        if let Some(raw) = dec.advance(n)? {
            return decode_payload(raw.version, &raw.bytes);
        }
    }
}

/// Write one message to an async writer and flush it.
///
/// Not cancellation-safe: if the future is dropped mid-write the peer sees a
/// partial frame. [`Connection::send`](crate::Connection::send) tracks this
/// and refuses further sends.
pub async fn write_msg_async<W: AsyncWrite + Unpin + ?Sized, M: WireMessage>(
    w: &mut W,
    msg: &M,
) -> Result<()> {
    let buf = encode(msg)?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read one message from an async reader. Same semantics as [`read_msg`].
///
/// Not cancellation-safe (partial progress lives in this future); use
/// [`Connection::recv`](crate::Connection::recv), which keeps a persistent
/// [`FrameDecoder`], when racing receives against timers.
pub async fn read_msg_async<R: AsyncRead + Unpin + ?Sized, M: WireMessage>(r: &mut R) -> Result<M> {
    let mut dec = FrameDecoder::new();
    loop {
        let n = match r.read(dec.buf_mut()).await {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Err(dec.eof_error());
        }
        if let Some(raw) = dec.advance(n)? {
            return decode_payload(raw.version, &raw.bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{AgentMsg, ServiceMsg};

    fn header(version: u16, len: u32) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&MAGIC);
        h[4..6].copy_from_slice(&version.to_be_bytes());
        h[6..10].copy_from_slice(&len.to_be_bytes());
        h
    }

    #[test]
    fn cap_is_what_the_docs_say() {
        assert_eq!(MAX_FRAME_BYTES, 768 * 768 * 4);
        assert_eq!(MAX_PAYLOAD_LEN, 9 * 1024 * 1024 + 256 * 1024);
        assert!(MAX_PAYLOAD_LEN < u32::MAX as usize);
    }

    #[test]
    fn header_layout_is_stable() {
        let buf = encode(&ServiceMsg::Ping { nonce: 5 }).unwrap();
        assert_eq!(&buf[0..4], b"FARO");
        assert_eq!(&buf[4..6], &[0, 1]);
        let len = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;
        assert_eq!(len, buf.len() - HEADER_LEN);
        // Ping is variant 2, nonce varint 5.
        assert_eq!(&buf[HEADER_LEN..], &[2, 5]);
    }

    #[test]
    fn parse_header_rejects_bad_magic_and_versions() {
        let mut h = header(PROTOCOL_VERSION, 0);
        h[0] = b'X';
        assert!(matches!(parse_header(&h), Err(IpcError::BadMagic)));
        for v in [0u16, PROTOCOL_VERSION + 1, u16::MAX] {
            assert!(matches!(
                parse_header(&header(v, 0)),
                Err(IpcError::UnsupportedVersion { got, .. }) if got == v
            ));
        }
    }

    #[test]
    fn parse_header_length_boundary() {
        assert!(parse_header(&header(1, MAX_PAYLOAD_LEN as u32)).is_ok());
        assert!(matches!(
            parse_header(&header(1, MAX_PAYLOAD_LEN as u32 + 1)),
            Err(IpcError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            parse_header(&header(1, u32::MAX)),
            Err(IpcError::PayloadTooLarge { .. })
        ));
    }

    /// A reader that panics if asked for more than the header before the
    /// header was validated proves oversize is rejected before allocation.
    #[test]
    fn oversize_rejected_after_reading_only_the_header() {
        struct OnlyHeader {
            data: [u8; HEADER_LEN],
            pos: usize,
        }
        impl Read for OnlyHeader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                assert!(
                    self.pos < HEADER_LEN,
                    "decoder read past an oversize header"
                );
                assert!(buf.len() <= HEADER_LEN - self.pos);
                let n = buf.len().min(HEADER_LEN - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }
        let mut r = OnlyHeader {
            data: header(1, u32::MAX),
            pos: 0,
        };
        assert!(matches!(
            read_msg::<_, AgentMsg>(&mut r),
            Err(IpcError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn decoder_handles_byte_at_a_time_and_zero_length_payload() {
        let buf = encode(&AgentMsg::Goodbye).unwrap();
        let mut dec = FrameDecoder::new();
        let mut out = None;
        for &b in buf.iter() {
            assert!(out.is_none());
            dec.buf_mut()[0] = b;
            out = dec.advance(1).unwrap();
        }
        let raw = out.unwrap();
        assert!(dec.is_idle());
        let msg: AgentMsg = decode_payload(raw.version, &raw.bytes).unwrap();
        assert_eq!(msg, AgentMsg::Goodbye);

        // A header announcing an empty payload completes immediately; the
        // empty payload then fails to decode as a message (typed error).
        let mut dec = FrameDecoder::new();
        dec.buf_mut().copy_from_slice(&header(1, 0));
        let raw = dec.advance(HEADER_LEN).unwrap().unwrap();
        assert!(raw.bytes.is_empty());
        assert!(matches!(
            decode_payload::<AgentMsg>(raw.version, &raw.bytes),
            Err(IpcError::Decode(_))
        ));
    }

    #[test]
    fn decode_payload_checks_version_itself() {
        assert!(matches!(
            decode_payload::<AgentMsg>(PROTOCOL_VERSION + 1, &[10]),
            Err(IpcError::UnsupportedVersion { .. })
        ));
        assert_eq!(
            decode_payload::<AgentMsg>(PROTOCOL_VERSION, &[10]).unwrap(),
            AgentMsg::Goodbye
        );
    }

    #[test]
    fn decoder_rejects_overclaiming_reader() {
        let mut dec = FrameDecoder::new();
        assert!(matches!(
            dec.advance(HEADER_LEN + 1),
            Err(IpcError::Broken(_))
        ));
        assert!(dec.is_idle());
    }

    #[test]
    fn eof_classification() {
        assert!(matches!(
            read_msg::<_, AgentMsg>(&mut &[][..]),
            Err(IpcError::Closed)
        ));
        let buf = encode(&ServiceMsg::Ping { nonce: 1 }).unwrap();
        for cut in 1..buf.len() {
            let r = read_msg::<_, ServiceMsg>(&mut &buf[..cut]);
            assert!(
                matches!(r, Err(IpcError::Truncated { got, .. }) if got == cut),
                "cut at {cut}: {r:?}"
            );
            let r = decode::<ServiceMsg>(&buf[..cut]);
            assert!(matches!(r, Err(IpcError::Truncated { .. })), "{r:?}");
        }
    }

    #[test]
    fn trailing_bytes_inside_payload_rejected() {
        let mut buf = encode(&ServiceMsg::Ping { nonce: 1 }).unwrap().to_vec();
        buf.push(0);
        let len = (buf.len() - HEADER_LEN) as u32;
        buf[6..10].copy_from_slice(&len.to_be_bytes());
        assert!(matches!(
            decode::<ServiceMsg>(&buf),
            Err(IpcError::TrailingBytes(1))
        ));
        assert!(matches!(
            read_msg::<_, ServiceMsg>(&mut &buf[..]),
            Err(IpcError::TrailingBytes(1))
        ));
    }

    #[test]
    fn decode_rejects_bytes_after_the_frame() {
        let mut buf = encode(&ServiceMsg::Ping { nonce: 1 }).unwrap().to_vec();
        buf.extend_from_slice(b"junk");
        assert!(matches!(
            decode::<ServiceMsg>(&buf),
            Err(IpcError::TrailingBytes(4))
        ));
    }

    #[test]
    fn read_msg_does_not_overread() {
        let mut stream = Vec::new();
        write_msg(&mut stream, &ServiceMsg::Ping { nonce: 1 }).unwrap();
        write_msg(&mut stream, &ServiceMsg::Ping { nonce: 2 }).unwrap();
        let mut r = &stream[..];
        assert_eq!(
            read_msg::<_, ServiceMsg>(&mut r).unwrap(),
            ServiceMsg::Ping { nonce: 1 }
        );
        assert_eq!(
            read_msg::<_, ServiceMsg>(&mut r).unwrap(),
            ServiceMsg::Ping { nonce: 2 }
        );
        assert!(matches!(
            read_msg::<_, ServiceMsg>(&mut r),
            Err(IpcError::Closed)
        ));
    }

    #[test]
    fn interrupted_reads_are_retried() {
        struct Flaky<'a> {
            data: &'a [u8],
            toggle: bool,
        }
        impl Read for Flaky<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.toggle = !self.toggle;
                if self.toggle {
                    return Err(std::io::Error::from(ErrorKind::Interrupted));
                }
                let n = buf.len().min(1);
                Read::read(&mut self.data, &mut buf[..n])
            }
        }
        let buf = encode(&ServiceMsg::Ping { nonce: 300 }).unwrap();
        let mut r = Flaky {
            data: &buf,
            toggle: false,
        };
        assert_eq!(
            read_msg::<_, ServiceMsg>(&mut r).unwrap(),
            ServiceMsg::Ping { nonce: 300 }
        );
    }
}
