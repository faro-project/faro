//! Turning captured [`Frame`]s into [`WireFrame`]s without copying pixels.
//!
//! `WireFrame::from_frame` makes one copy of the buffer (it only sees the
//! frame by borrow). The agent avoids even that: it moves the buffer out
//! with [`Frame::into_parts`] and hands the same allocation to
//! [`WireFrame::new`]. Every path drops the pixels inside a zeroizing owner
//! (`Frame`, `Zeroizing<Vec<u8>>` or `WireFrame`), including errors.

use faro_ipc::{WireFrame, WireFrameError};
use faro_platform::{Frame, MAX_FRAME_SIDE};

/// Convert one captured frame for sending.
///
/// Downscales first if the platform did not (every platform should, in the
/// OS API, but the service rejects anything over [`MAX_FRAME_SIDE`] and a
/// rejected frame is a lost capture). `downscale_to_max` is a no-op for a
/// frame that is already small enough.
pub fn to_wire(frame: Frame) -> Result<WireFrame, WireFrameError> {
    let frame = frame.downscale_to_max(MAX_FRAME_SIDE);
    let (width, height, format, display_id, mut pixels) = frame.into_parts();
    // Move the Vec out of its Zeroizing wrapper; the wrapper is left empty,
    // and WireFrame (ZeroizeOnDrop) takes over responsibility for wiping it.
    // On a validation error WireFrame::new zeroizes the buffer itself.
    let buffer = std::mem::take(&mut *pixels);
    WireFrame::new(width, height, format.into(), display_id, buffer)
}

/// Convert a whole capture. Stops at the first invalid frame; the frames
/// already converted and the ones not yet reached are dropped (zeroized).
pub fn capture_to_wire(frames: Vec<Frame>) -> Result<Vec<WireFrame>, WireFrameError> {
    frames.into_iter().map(to_wire).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use faro_ipc::WirePixelFormat;
    use faro_platform::PixelFormat;

    fn frame(w: u32, h: u32, fmt: PixelFormat, id: u32) -> Frame {
        Frame::new(w, h, fmt, id, vec![7; (w * h * 4) as usize]).unwrap()
    }

    #[test]
    fn small_frame_moves_without_copy() {
        let f = frame(64, 32, PixelFormat::Bgra8, 3);
        let ptr = f.pixels().as_ptr();
        let w = to_wire(f).unwrap();
        assert_eq!(w.pixels().as_ptr(), ptr, "pixels must be moved, not copied");
        assert_eq!((w.width(), w.height(), w.display_id()), (64, 32, 3));
        assert_eq!(w.format(), WirePixelFormat::Bgra8);
        w.check().unwrap();
    }

    #[test]
    fn oversized_frame_is_downscaled() {
        let w = to_wire(frame(1600, 900, PixelFormat::Rgba8, 0)).unwrap();
        assert_eq!((w.width(), w.height()), (768, 432));
        w.check().unwrap();
    }

    #[test]
    fn whole_capture_keeps_order() {
        let frames = (0..3)
            .map(|i| frame(10, 10, PixelFormat::Rgba8, i))
            .collect();
        let wire = capture_to_wire(frames).unwrap();
        let ids: Vec<u32> = wire.iter().map(WireFrame::display_id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }
}
