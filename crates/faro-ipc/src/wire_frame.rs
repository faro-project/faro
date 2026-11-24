//! Raw screen pixels on the wire (ARCHITECTURE.md §3.1, §3.5, §9).
//!
//! The agent sends **raw, already-downscaled pixels**, never an encoded image
//! format, so the privileged service never runs an image decoder on data it
//! did not produce. A [`WireFrame`] carries the same unblurred content as a
//! [`Frame`], so it inherits the same invariants:
//!
//! * no `Clone`, and a `Debug` that never prints pixels;
//! * the buffer is zeroized when the value is dropped, including on every
//!   validation error path;
//! * it only exists transiently: built by the agent right before sending,
//!   converted into a [`Frame`] by the service right after receiving.
//!
//! It implements `Serialize` only because the IPC codec must put it on the
//! local socket; it must never be serialized anywhere else (disk, network,
//! logs). The codec zeroizes its own encode/decode buffers.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use faro_platform::{Frame, PixelFormat, MAX_FRAME_SIDE};

use crate::error::WireFrameError;

/// Bytes in one frame at the maximum allowed size (768 × 768 × 4 = 2.25 MiB).
pub const MAX_FRAME_BYTES: usize = (MAX_FRAME_SIDE as usize) * (MAX_FRAME_SIDE as usize) * 4;

/// Wire mirror of [`PixelFormat`]. Kept separate so the platform enum can
/// evolve without silently changing the IPC encoding (postcard encodes enums
/// by variant index, so order here is part of the protocol: append only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WirePixelFormat {
    Rgba8,
    Bgra8,
}

impl From<PixelFormat> for WirePixelFormat {
    fn from(f: PixelFormat) -> Self {
        match f {
            PixelFormat::Rgba8 => WirePixelFormat::Rgba8,
            PixelFormat::Bgra8 => WirePixelFormat::Bgra8,
        }
    }
}

impl From<WirePixelFormat> for PixelFormat {
    fn from(f: WirePixelFormat) -> Self {
        match f {
            WirePixelFormat::Rgba8 => PixelFormat::Rgba8,
            WirePixelFormat::Bgra8 => PixelFormat::Bgra8,
        }
    }
}

/// One display's raw pixels in transit from agent to service.
///
/// See the module docs for the privacy invariant.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WireFrame {
    #[zeroize(skip)]
    width: u32,
    #[zeroize(skip)]
    height: u32,
    #[zeroize(skip)]
    format: WirePixelFormat,
    #[zeroize(skip)]
    display_id: u32,
    #[serde(with = "pixel_bytes")]
    pixels: Vec<u8>,
}

impl std::fmt::Debug for WireFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("format", &self.format)
            .field("display_id", &self.display_id)
            .field(
                "pixels",
                &format_args!("<redacted {} bytes>", self.pixels.len()),
            )
            .finish()
    }
}

impl PartialEq for WireFrame {
    fn eq(&self, other: &Self) -> bool {
        self.width == other.width
            && self.height == other.height
            && self.format == other.format
            && self.display_id == other.display_id
            && self.pixels == other.pixels
    }
}

impl Eq for WireFrame {}

impl WireFrame {
    /// Build a frame from a raw, tightly packed 4-byte-per-pixel buffer.
    ///
    /// Takes ownership of `pixels`; on error the buffer is zeroized before it
    /// is dropped.
    pub fn new(
        width: u32,
        height: u32,
        format: WirePixelFormat,
        display_id: u32,
        pixels: Vec<u8>,
    ) -> Result<Self, WireFrameError> {
        let frame = WireFrame {
            width,
            height,
            format,
            display_id,
            pixels,
        };
        // On error `frame` drops here and zeroizes `pixels`.
        frame.check()?;
        Ok(frame)
    }

    /// Agent side: convert a captured [`Frame`] for sending.
    ///
    /// Downscales to [`MAX_FRAME_SIDE`] first if the capture backend did not,
    /// so a conforming agent can never produce a frame the service rejects.
    ///
    /// `Frame` exposes its pixels only by borrow, so this makes exactly one
    /// copy into an exactly-sized allocation (no reallocation, hence no stray
    /// copies left in freed memory) and then drops the `Frame`, which
    /// zeroizes the original buffer.
    pub fn from_frame(frame: Frame) -> Self {
        let frame = frame.downscale_to_max(MAX_FRAME_SIDE);
        let src = frame.pixels();
        let mut pixels = Vec::with_capacity(src.len());
        pixels.extend_from_slice(src);
        let wire = WireFrame {
            width: frame.width(),
            height: frame.height(),
            format: frame.format().into(),
            display_id: frame.display_id(),
            pixels,
        };
        frame.destroy();
        wire
    }

    /// Service side: validate and convert into a [`Frame`] for classification.
    ///
    /// Moves the buffer (no copy). On any error the pixels are zeroized.
    pub fn into_frame(mut self) -> Result<Frame, WireFrameError> {
        self.check()?;
        let pixels = std::mem::take(&mut self.pixels);
        // `Frame::new` zeroizes `pixels` itself if it refuses them.
        let frame = Frame::new(
            self.width,
            self.height,
            self.format.into(),
            self.display_id,
            pixels,
        )?;
        Ok(frame)
    }

    /// Enforce the wire invariants: both sides in `1..=MAX_FRAME_SIDE` and an
    /// exact `width * height * 4` buffer.
    pub fn check(&self) -> Result<(), WireFrameError> {
        let (width, height) = (self.width, self.height);
        if width == 0 || height == 0 {
            return Err(WireFrameError::ZeroDimension { width, height });
        }
        if width > MAX_FRAME_SIDE || height > MAX_FRAME_SIDE {
            return Err(WireFrameError::TooLarge {
                width,
                height,
                max: MAX_FRAME_SIDE,
            });
        }
        // Cannot overflow: both sides are <= 768.
        let expected = width as usize * height as usize * 4;
        if self.pixels.len() != expected {
            return Err(WireFrameError::BadLength {
                expected,
                got: self.pixels.len(),
            });
        }
        Ok(())
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn format(&self) -> WirePixelFormat {
        self.format
    }

    pub fn display_id(&self) -> u32 {
        self.display_id
    }

    /// Borrow the raw pixels. Never copy these anywhere persistent.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

/// Serialize the pixel buffer as a postcard byte string (varint length +
/// raw bytes; wire-identical to a `seq<u8>`), and deserialize it with a
/// single exact-size copy instead of serde's element-by-element `Vec` path,
/// which would grow (and reallocate, leaving unzeroized copies of) the buffer.
mod pixel_bytes {
    use serde::de::{Error as _, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use zeroize::Zeroize;

    use super::MAX_FRAME_BYTES;

    pub fn serialize<S: Serializer>(pixels: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(pixels)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_byte_buf(PixelVisitor)
    }

    struct PixelVisitor;

    impl<'de> Visitor<'de> for PixelVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX_FRAME_BYTES} bytes of raw pixels")
        }

        fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
            if v.len() > MAX_FRAME_BYTES {
                return Err(E::invalid_length(v.len(), &self));
            }
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E: serde::de::Error>(self, mut v: Vec<u8>) -> Result<Vec<u8>, E> {
            if v.len() > MAX_FRAME_BYTES {
                let len = v.len();
                v.zeroize();
                return Err(E::invalid_length(len, &self));
            }
            Ok(v)
        }

        // Only reachable from self-describing formats; postcard always takes
        // the bytes path. Pre-size to the cap so the buffer never reallocates.
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let hint = seq.size_hint().unwrap_or(0).min(MAX_FRAME_BYTES);
            let mut out = Vec::with_capacity(hint.max(MAX_FRAME_BYTES.min(64 * 1024)));
            loop {
                match seq.next_element::<u8>() {
                    Ok(Some(b)) => {
                        if out.len() == MAX_FRAME_BYTES {
                            out.zeroize();
                            return Err(A::Error::invalid_length(MAX_FRAME_BYTES + 1, &self));
                        }
                        if out.len() == out.capacity() {
                            // Grow manually so the old buffer is zeroized.
                            let mut bigger =
                                Vec::with_capacity((out.capacity() * 2).min(MAX_FRAME_BYTES));
                            bigger.extend_from_slice(&out);
                            out.zeroize();
                            out = bigger;
                        }
                        out.push(b);
                    }
                    Ok(None) => return Ok(out),
                    Err(e) => {
                        out.zeroize();
                        return Err(e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wf(w: u32, h: u32) -> Result<WireFrame, WireFrameError> {
        WireFrame::new(
            w,
            h,
            WirePixelFormat::Rgba8,
            1,
            vec![7; w as usize * h as usize * 4],
        )
    }

    #[test]
    fn new_validates_dimensions_and_length() {
        assert!(wf(1, 1).is_ok());
        assert!(wf(MAX_FRAME_SIDE, MAX_FRAME_SIDE).is_ok());
        assert!(matches!(
            wf(0, 4),
            Err(WireFrameError::ZeroDimension { .. })
        ));
        assert!(matches!(
            wf(MAX_FRAME_SIDE + 1, 1),
            Err(WireFrameError::TooLarge { .. })
        ));
        assert!(matches!(
            wf(1, MAX_FRAME_SIDE + 1),
            Err(WireFrameError::TooLarge { .. })
        ));
        assert!(matches!(
            WireFrame::new(2, 2, WirePixelFormat::Bgra8, 0, vec![0; 15]),
            Err(WireFrameError::BadLength {
                expected: 16,
                got: 15
            })
        ));
    }

    #[test]
    fn debug_never_prints_pixels() {
        let f = WireFrame::new(
            1,
            1,
            WirePixelFormat::Rgba8,
            3,
            vec![0xAB, 0xCD, 0xEF, 0x12],
        )
        .unwrap();
        let s = format!("{f:?}");
        assert!(s.contains("redacted"));
        for leaked in ["171", "205", "239", "0xab", "0xAB"] {
            assert!(!s.contains(leaked), "pixel value leaked: {s}");
        }
    }

    #[test]
    fn frame_roundtrip_preserves_everything() {
        let px: Vec<u8> = (0..(3 * 2 * 4)).map(|i| i as u8).collect();
        let frame = Frame::new(3, 2, PixelFormat::Bgra8, 42, px.clone()).unwrap();
        let wire = WireFrame::from_frame(frame);
        assert_eq!((wire.width(), wire.height(), wire.display_id()), (3, 2, 42));
        assert_eq!(wire.format(), WirePixelFormat::Bgra8);
        let back = wire.into_frame().unwrap();
        assert_eq!(back.pixels(), &px[..]);
        assert_eq!(back.format(), PixelFormat::Bgra8);
        assert_eq!(back.display_id(), 42);
    }

    #[test]
    fn from_frame_downscales_oversize_captures() {
        let frame = Frame::new(1600, 900, PixelFormat::Rgba8, 0, vec![9; 1600 * 900 * 4]).unwrap();
        let wire = WireFrame::from_frame(frame);
        assert_eq!((wire.width(), wire.height()), (768, 432));
        assert!(wire.check().is_ok());
    }

    #[test]
    fn into_frame_rejects_tampered_fields() {
        // Simulate a frame that bypassed `new` (e.g. decoded off the wire):
        // fields are private, so build via serde.
        let good = wf(2, 2).unwrap();
        let mut bytes = postcard::to_allocvec(&good).unwrap();
        bytes[0] = 100; // width varint -> 100 (single byte), buffer still 16 bytes
        let bad: WireFrame = postcard::from_bytes(&bytes).unwrap();
        assert!(matches!(
            bad.into_frame(),
            Err(WireFrameError::BadLength { .. })
        ));
    }

    #[test]
    fn pixel_cap_enforced_during_deserialize() {
        // width=1,height=1,format=0,display=0, then a byte string longer than
        // MAX_FRAME_BYTES.
        let mut bytes = vec![1u8, 1, 0, 0];
        let n = MAX_FRAME_BYTES + 1;
        let mut v = n;
        while v >= 0x80 {
            bytes.push((v as u8) | 0x80);
            v >>= 7;
        }
        bytes.push(v as u8);
        bytes.resize(bytes.len() + n, 0);
        assert!(postcard::from_bytes::<WireFrame>(&bytes).is_err());
    }

    #[test]
    fn zeroize_clears_pixels() {
        let mut f = wf(2, 2).unwrap();
        f.zeroize();
        // `Vec::zeroize` wipes the whole allocation and then clears the vec.
        assert!(f.pixels().is_empty());
    }

    #[test]
    fn pixel_format_conversions_roundtrip() {
        for f in [PixelFormat::Rgba8, PixelFormat::Bgra8] {
            assert_eq!(PixelFormat::from(WirePixelFormat::from(f)), f);
        }
    }
}
