//! Regression: decoding must not allocate far more than the payload cap.
//!
//! The smallest encoded `WireFrame` is 5 bytes but 40 bytes in memory, so
//! before the frame count was capped *during* decoding, a max-size payload
//! of ~1.9 M empty frames made the service allocate ~200 MB (≈ 21× the
//! payload) before `validate()` rejected it.
//!
//! A counting global allocator measures peak heap use. The file holds a
//! single test so no other test thread allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use faro_ipc::codec::decode_payload;
use faro_ipc::{
    encode, AgentMsg, IpcError, WireFrame, WirePixelFormat, MAX_FRAMES_PER_MESSAGE,
    MAX_PAYLOAD_LEN, PROTOCOL_VERSION,
};

struct Counting;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(p, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Peak extra heap bytes used while running `f`.
fn peak_extra<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = CURRENT.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst).saturating_sub(base))
}

fn push_varint(out: &mut Vec<u8>, mut v: usize) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

#[test]
fn decoding_stays_within_the_payload_budget() {
    // 1. Hostile: a max-size payload declaring ~1.9 M empty frames
    //    (variant 1 = Frames, captured_at = 0, then the count).
    let n = (MAX_PAYLOAD_LEN - 8) / 5;
    let mut hostile = vec![1u8, 0];
    push_varint(&mut hostile, n);
    hostile.resize(MAX_PAYLOAD_LEN, 0);
    let (res, peak) = peak_extra(|| decode_payload::<AgentMsg>(PROTOCOL_VERSION, &hostile));
    assert!(
        matches!(res, Err(IpcError::TooManyFrames { count, max })
            if count == n && max == MAX_FRAMES_PER_MESSAGE),
        "{res:?}"
    );
    assert!(
        peak < 64 * 1024,
        "hostile frame count allocated {peak} bytes"
    );

    // 2. The boundary: exactly one frame too many, each a valid 1x1 frame.
    let mut one_over = vec![1u8, 0];
    push_varint(&mut one_over, MAX_FRAMES_PER_MESSAGE + 1);
    for _ in 0..=MAX_FRAMES_PER_MESSAGE {
        one_over.extend_from_slice(&[1, 1, 0, 0, 4, 9, 9, 9, 9]);
    }
    assert!(matches!(
        decode_payload::<AgentMsg>(PROTOCOL_VERSION, &one_over),
        Err(IpcError::TooManyFrames { .. })
    ));

    // 3. Legitimate worst case: 4 full-size frames. Decoding allocates about
    //    the pixel data once (the frames themselves), nothing more.
    let frames = (0..MAX_FRAMES_PER_MESSAGE as u32)
        .map(|i| WireFrame::new(768, 768, WirePixelFormat::Bgra8, i, vec![7; 768 * 768 * 4]))
        .collect::<Result<Vec<_>, _>>()
        .expect("valid frames");
    let bytes = encode(&AgentMsg::Frames {
        captured_at_mono_ms: 1,
        frames,
    })
    .expect("encodes");
    let payload = &bytes[faro_ipc::codec::HEADER_LEN..];
    let (msg, peak) = peak_extra(|| decode_payload::<AgentMsg>(PROTOCOL_VERSION, payload));
    assert!(matches!(msg, Ok(AgentMsg::Frames { ref frames, .. }) if frames.len() == 4));
    assert!(
        peak <= payload.len() + 64 * 1024,
        "decoding a {}-byte payload allocated {peak} bytes",
        payload.len()
    );

    // 4. The over-cap marker never leaks into the next decode on this thread.
    let ok = encode(&AgentMsg::Goodbye).expect("encodes");
    assert!(matches!(
        decode_payload::<AgentMsg>(PROTOCOL_VERSION, &ok[faro_ipc::codec::HEADER_LEN..]),
        Ok(AgentMsg::Goodbye)
    ));
    assert!(matches!(
        decode_payload::<AgentMsg>(PROTOCOL_VERSION, &[0xFF]),
        Err(IpcError::Decode(_))
    ));
}
