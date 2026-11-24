//! A typed, framed, cancellation-safe message connection over any async
//! byte stream.
//!
//! [`Connection`] is generic over the stream so the same code runs over Unix
//! sockets in production and over in-memory duplex pipes in tests, and over
//! the message direction so the compiler stops the service from sending an
//! `AgentMsg` (or the agent a `ServiceMsg`).

use std::marker::PhantomData;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::codec::{self, FrameDecoder};
use crate::error::{IpcError, Result};
use crate::messages::{AgentMsg, ServiceMsg, WireMessage};
use crate::peer::PeerInfo;

/// The service's end: sends [`ServiceMsg`], receives [`AgentMsg`].
pub type ServiceConnection<S> = Connection<S, ServiceMsg, AgentMsg>;
/// The agent's end: sends [`AgentMsg`], receives [`ServiceMsg`].
pub type AgentConnection<S> = Connection<S, AgentMsg, ServiceMsg>;

/// A framed connection sending `Out` and receiving `In`.
///
/// # Cancellation
///
/// * [`recv`](Self::recv) is **cancellation-safe**: partial input is kept in
///   the connection, so it may be raced in `tokio::select!` or wrapped in a
///   timeout ([`recv_timeout`](Self::recv_timeout)) and simply called again.
/// * [`send`](Self::send) is **not**: if its future is dropped mid-write the
///   peer has a partial frame, so the connection refuses all further sends
///   with [`IpcError::Broken`].
///
/// # Errors are terminal
///
/// After any framing, decode or I/O error from `recv` the byte stream can no
/// longer be trusted to be at a message boundary, so subsequent `recv` calls
/// return [`IpcError::Broken`]. A timeout is *not* an error of this kind.
pub struct Connection<S, Out, In> {
    stream: S,
    peer: Option<PeerInfo>,
    decoder: FrameDecoder,
    read_broken: bool,
    write_broken: bool,
    write_in_progress: bool,
    _dir: PhantomData<fn(Out) -> In>,
}

impl<S, Out, In> std::fmt::Debug for Connection<S, Out, In> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.peer)
            .field("decoder", &self.decoder)
            .field("read_broken", &self.read_broken)
            .field(
                "write_broken",
                &(self.write_broken || self.write_in_progress),
            )
            .finish_non_exhaustive()
    }
}

impl<S, Out, In> Connection<S, Out, In>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Out: WireMessage,
    In: WireMessage,
{
    /// Wrap a stream whose peer is unknown (tests, in-memory pipes).
    pub fn new(stream: S) -> Self {
        Self::with_peer(stream, None)
    }

    /// Wrap a stream whose peer credentials were already read and verified.
    pub fn with_peer(stream: S, peer: Option<PeerInfo>) -> Self {
        Connection {
            stream,
            peer,
            decoder: FrameDecoder::new(),
            read_broken: false,
            write_broken: false,
            write_in_progress: false,
            _dir: PhantomData,
        }
    }

    /// Kernel-reported credentials of the peer, if known.
    pub fn peer(&self) -> Option<&PeerInfo> {
        self.peer.as_ref()
    }

    /// Send one message and flush it.
    ///
    /// Encoding errors (e.g. too many frames) are reported without touching
    /// the stream, so the connection stays usable.
    pub async fn send(&mut self, msg: &Out) -> Result<()> {
        if self.write_broken || self.write_in_progress {
            self.write_broken = true;
            return Err(IpcError::Broken(
                "an earlier send failed or was cancelled mid-write",
            ));
        }
        let buf = codec::encode(msg)?;
        self.write_in_progress = true;
        let res = async {
            self.stream.write_all(&buf).await?;
            self.stream.flush().await
        }
        .await;
        self.write_in_progress = false;
        if let Err(e) = res {
            self.write_broken = true;
            return Err(e.into());
        }
        Ok(())
    }

    /// Receive one message. Cancellation-safe; see the type docs.
    pub async fn recv(&mut self) -> Result<In> {
        if self.read_broken {
            return Err(IpcError::Broken("an earlier receive failed"));
        }
        match self.recv_inner().await {
            Ok(m) => Ok(m),
            Err(e) => {
                self.read_broken = true;
                Err(e)
            }
        }
    }

    async fn recv_inner(&mut self) -> Result<In> {
        loop {
            // The only await point: a single `read`, which is itself
            // cancellation-safe for Tokio streams. All progress is stored in
            // `self.decoder`, never in this future.
            let n = match self.stream.read(self.decoder.buf_mut()).await {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Err(self.decoder.eof_error());
            }
            if let Some(raw) = self.decoder.advance(n)? {
                return codec::decode_payload(raw.version, &raw.bytes);
            }
        }
    }

    /// [`recv`](Self::recv) with a deadline. On timeout the connection is
    /// still usable (partial input is retained).
    pub async fn recv_timeout(&mut self, after: Duration, what: &'static str) -> Result<In> {
        match tokio::time::timeout(after, self.recv()).await {
            Ok(r) => r,
            Err(_) => Err(IpcError::Timeout { what, after }),
        }
    }

    /// Flush and shut down the write side, signalling EOF to the peer.
    pub async fn close(mut self) -> Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    /// Give back the underlying stream. Any partially received message is
    /// discarded (and zeroized).
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode;
    use crate::messages::{AgentMsg, ServiceMsg};
    use crate::wire_frame::{WireFrame, WirePixelFormat};
    use tokio::io::duplex;

    type Pair = (
        ServiceConnection<tokio::io::DuplexStream>,
        AgentConnection<tokio::io::DuplexStream>,
    );

    fn pair() -> Pair {
        let (a, b) = duplex(1 << 16);
        (Connection::new(a), Connection::new(b))
    }

    #[tokio::test]
    async fn send_recv_both_directions() {
        let (mut svc, mut agent) = pair();
        svc.send(&ServiceMsg::Ping { nonce: 9 }).await.unwrap();
        assert_eq!(agent.recv().await.unwrap(), ServiceMsg::Ping { nonce: 9 });
        agent.send(&AgentMsg::Pong { nonce: 9 }).await.unwrap();
        assert_eq!(svc.recv().await.unwrap(), AgentMsg::Pong { nonce: 9 });
    }

    #[tokio::test]
    async fn recv_is_cancellation_safe() {
        let (a, mut raw) = duplex(1 << 16);
        let mut svc: ServiceConnection<_> = Connection::new(a);
        let bytes = encode(&AgentMsg::Pong { nonce: 0xDEAD_BEEF }).unwrap();
        let (first, second) = bytes.split_at(7); // mid-header
        raw.write_all(first).await.unwrap();
        // Time out with a partial header buffered.
        assert!(matches!(
            svc.recv_timeout(Duration::from_millis(20), "pong").await,
            Err(IpcError::Timeout { .. })
        ));
        raw.write_all(second).await.unwrap();
        assert_eq!(
            svc.recv().await.unwrap(),
            AgentMsg::Pong { nonce: 0xDEAD_BEEF }
        );
    }

    #[tokio::test]
    async fn cancelled_partial_payload_resumes() {
        let (a, mut raw) = duplex(64 * 1024 * 1024);
        let mut svc: ServiceConnection<_> = Connection::new(a);
        let frames =
            vec![
                WireFrame::new(300, 300, WirePixelFormat::Bgra8, 1, vec![5; 300 * 300 * 4])
                    .unwrap(),
            ];
        let bytes = encode(&AgentMsg::Frames {
            captured_at_mono_ms: 1,
            frames,
        })
        .unwrap();
        let mid = bytes.len() / 2;
        raw.write_all(&bytes[..mid]).await.unwrap();
        assert!(svc
            .recv_timeout(Duration::from_millis(20), "frames")
            .await
            .is_err());
        raw.write_all(&bytes[mid..]).await.unwrap();
        let AgentMsg::Frames { frames, .. } = svc.recv().await.unwrap() else {
            panic!("wrong variant");
        };
        let f = frames.into_iter().next().unwrap().into_frame().unwrap();
        assert!(f.pixels().iter().all(|&b| b == 5));
    }

    #[tokio::test]
    async fn errors_are_terminal_for_recv() {
        let (a, mut raw) = duplex(1024);
        let mut svc: ServiceConnection<_> = Connection::new(a);
        raw.write_all(b"NOPE\0\x01\0\0\0\0").await.unwrap();
        assert!(matches!(svc.recv().await, Err(IpcError::BadMagic)));
        // Even a valid message afterwards is refused: framing is untrusted.
        raw.write_all(&encode(&AgentMsg::Goodbye).unwrap())
            .await
            .unwrap();
        assert!(matches!(svc.recv().await, Err(IpcError::Broken(_))));
    }

    #[tokio::test]
    async fn clean_close_vs_truncation() {
        let (mut svc, agent) = pair();
        drop(agent);
        assert!(matches!(svc.recv().await, Err(IpcError::Closed)));

        let (a, mut raw) = duplex(1024);
        let mut svc: ServiceConnection<_> = Connection::new(a);
        let bytes = encode(&AgentMsg::Pong { nonce: 1 }).unwrap();
        raw.write_all(&bytes[..bytes.len() - 1]).await.unwrap();
        drop(raw);
        assert!(matches!(svc.recv().await, Err(IpcError::Truncated { .. })));
    }

    #[tokio::test]
    async fn invalid_outgoing_message_does_not_break_connection() {
        let (mut svc, mut agent) = pair();
        let too_many = AgentMsg::Frames {
            captured_at_mono_ms: 0,
            frames: (0..=crate::codec::MAX_FRAMES_PER_MESSAGE as u32)
                .map(|i| WireFrame::new(1, 1, WirePixelFormat::Rgba8, i, vec![0; 4]).unwrap())
                .collect(),
        };
        assert!(matches!(
            agent.send(&too_many).await,
            Err(IpcError::TooManyFrames { .. })
        ));
        agent.send(&AgentMsg::Goodbye).await.unwrap();
        assert_eq!(svc.recv().await.unwrap(), AgentMsg::Goodbye);
    }

    #[tokio::test]
    async fn cancelled_send_breaks_writes() {
        // A tiny pipe that nobody drains makes the write block.
        let (a, _keep) = duplex(16);
        let mut agent: AgentConnection<_> = Connection::new(a);
        let msg = AgentMsg::CaptureFailed {
            reason: "x".repeat(1024),
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), agent.send(&msg))
                .await
                .is_err()
        );
        assert!(matches!(
            agent.send(&AgentMsg::Goodbye).await,
            Err(IpcError::Broken(_))
        ));
    }
}
