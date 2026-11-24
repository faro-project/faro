//! Hostile and malformed input: the decoder must return a typed error, never
//! panic, never allocate past the cap, and never hand out an invalid frame.

mod common;

use common::*;
use faro_ipc::codec::{HEADER_LEN, MAGIC};
use faro_ipc::{
    decode, encode, read_msg, read_msg_async, AgentMsg, IpcError, ServiceMsg, WireFrameError,
    MAX_FRAMES_PER_MESSAGE, MAX_PAYLOAD_LEN, PROTOCOL_VERSION,
};
use proptest::prelude::*;

fn frame_bytes(version: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + payload.len());
    v.extend_from_slice(&MAGIC);
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// (width, height, pixel-format index, display id, pixel byte count)
type FrameSpec = (u32, u32, u8, u32, usize);
type ErrCheck = fn(&IpcError) -> bool;

/// Hand-encode a `Frames` payload with arbitrary (possibly lying) fields.
fn frames_payload(frames: &[FrameSpec]) -> Vec<u8> {
    let mut p = vec![1u8]; // AgentMsg::Frames variant index
    varint(0, &mut p); // captured_at_mono_ms
    varint(frames.len() as u64, &mut p);
    for &(w, h, fmt, id, len) in frames {
        varint(w.into(), &mut p);
        varint(h.into(), &mut p);
        p.push(fmt);
        varint(id.into(), &mut p);
        varint(len as u64, &mut p);
        p.resize(p.len() + len, 0xEE);
    }
    p
}

#[test]
fn garbage_is_rejected_with_bad_magic() {
    for junk in [&b"GET / HTTP/1.1\r\n"[..], &[0u8; 64][..], &[0xFF; 10][..]] {
        assert!(matches!(
            read_msg::<_, AgentMsg>(&mut &junk[..]),
            Err(IpcError::BadMagic)
        ));
    }
}

#[test]
fn unknown_versions_are_typed_errors() {
    let good = encode(&AgentMsg::Goodbye).unwrap();
    for v in [0, PROTOCOL_VERSION + 1, 0x0100, u16::MAX] {
        let bytes = frame_bytes(v, &good[HEADER_LEN..]);
        let e = read_msg::<_, AgentMsg>(&mut &bytes[..]).unwrap_err();
        assert!(
            matches!(e, IpcError::UnsupportedVersion { got, .. } if got == v),
            "{e:?}"
        );
    }
}

#[test]
fn oversize_declared_length_rejected_without_payload() {
    for len in [MAX_PAYLOAD_LEN as u32 + 1, u32::MAX] {
        let mut h = Vec::new();
        h.extend_from_slice(&MAGIC);
        h.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        h.extend_from_slice(&len.to_be_bytes());
        // Note: no payload bytes follow at all.
        assert!(matches!(
            read_msg::<_, AgentMsg>(&mut &h[..]),
            Err(IpcError::PayloadTooLarge { .. })
        ));
        let rt = runtime();
        assert!(matches!(
            rt.block_on(read_msg_async::<_, AgentMsg>(&mut &h[..])),
            Err(IpcError::PayloadTooLarge { .. })
        ));
    }
}

#[test]
fn encoder_refuses_too_many_frames() {
    let msg = AgentMsg::Frames {
        captured_at_mono_ms: 0,
        frames: (0..=MAX_FRAMES_PER_MESSAGE as u32)
            .map(|i| frame(1, 1, 0, i))
            .collect(),
    };
    assert!(matches!(
        encode(&msg),
        Err(IpcError::TooManyFrames { count, max })
            if count == MAX_FRAMES_PER_MESSAGE + 1 && max == MAX_FRAMES_PER_MESSAGE
    ));
}

#[test]
fn decoder_refuses_too_many_frames() {
    let spec: Vec<_> = (0..=MAX_FRAMES_PER_MESSAGE as u32)
        .map(|i| (1, 1, 0, i, 4))
        .collect();
    let bytes = frame_bytes(PROTOCOL_VERSION, &frames_payload(&spec));
    assert!(matches!(
        decode::<AgentMsg>(&bytes),
        Err(IpcError::TooManyFrames { .. })
    ));
}

#[test]
fn decoder_refuses_frames_that_lie_about_their_size() {
    let cases: &[(&[FrameSpec], ErrCheck)] = &[
        // claims 2x2 but carries 3 bytes
        (&[(2, 2, 0, 0, 3)], |e| {
            matches!(e, IpcError::InvalidFrame(WireFrameError::BadLength { .. }))
        }),
        // zero width
        (&[(0, 2, 0, 0, 0)], |e| {
            matches!(
                e,
                IpcError::InvalidFrame(WireFrameError::ZeroDimension { .. })
            )
        }),
        // over the side limit (would be a non-downscaled capture)
        (&[(769, 1, 0, 0, 769 * 4)], |e| {
            matches!(e, IpcError::InvalidFrame(WireFrameError::TooLarge { .. }))
        }),
        // unknown pixel format index
        (&[(1, 1, 9, 0, 4)], |e| matches!(e, IpcError::Decode(_))),
        // second frame bad, first fine
        (&[(1, 1, 0, 0, 4), (1, 1, 0, 1, 5)], |e| {
            matches!(e, IpcError::InvalidFrame(WireFrameError::BadLength { .. }))
        }),
    ];
    for (spec, check) in cases {
        let bytes = frame_bytes(PROTOCOL_VERSION, &frames_payload(spec));
        let e = decode::<AgentMsg>(&bytes).unwrap_err();
        assert!(check(&e), "{spec:?}: {e:?}");
    }
}

#[test]
fn pixel_buffer_over_frame_cap_rejected() {
    // A single byte string larger than one max-size frame.
    let len = faro_ipc::MAX_FRAME_BYTES + 4;
    let bytes = frame_bytes(PROTOCOL_VERSION, &frames_payload(&[(768, 768, 0, 0, len)]));
    assert!(bytes.len() - HEADER_LEN <= MAX_PAYLOAD_LEN);
    assert!(matches!(
        decode::<AgentMsg>(&bytes),
        Err(IpcError::Decode(_))
    ));
}

#[test]
fn unknown_variant_index_rejected() {
    for idx in [11u8, 0x7F] {
        let bytes = frame_bytes(PROTOCOL_VERSION, &[idx]);
        assert!(matches!(
            decode::<AgentMsg>(&bytes),
            Err(IpcError::Decode(_))
        ));
    }
    let bytes = frame_bytes(PROTOCOL_VERSION, &[5]);
    assert!(matches!(
        decode::<ServiceMsg>(&bytes),
        Err(IpcError::Decode(_))
    ));
}

#[test]
fn invalid_utf8_rejected() {
    // CaptureFailed { reason } with a non-UTF-8 string.
    let bytes = frame_bytes(PROTOCOL_VERSION, &[8, 2, 0xC3, 0x28]);
    assert!(matches!(
        decode::<AgentMsg>(&bytes),
        Err(IpcError::Decode(_))
    ));
}

#[test]
fn every_truncation_of_every_message_is_typed() {
    for msg in all_agent_msgs() {
        let bytes = encode(&msg).unwrap();
        for cut in 0..bytes.len() {
            let e = read_msg::<_, AgentMsg>(&mut &bytes[..cut]).unwrap_err();
            if cut == 0 {
                assert!(matches!(e, IpcError::Closed));
            } else {
                assert!(
                    matches!(e, IpcError::Truncated { got, .. } if got == cut),
                    "{} cut {cut}: {e:?}",
                    msg.kind()
                );
            }
        }
    }
}

#[test]
fn shortened_length_field_is_detected() {
    // Header says the payload is one byte shorter than it is: the payload
    // fails to decode (it is truncated from postcard's point of view).
    let msg = AgentMsg::CaptureFailed {
        reason: "abc".into(),
    };
    let mut bytes = encode(&msg).unwrap().to_vec();
    let len = (bytes.len() - HEADER_LEN - 1) as u32;
    bytes[6..10].copy_from_slice(&len.to_be_bytes());
    bytes.pop();
    assert!(matches!(
        decode::<AgentMsg>(&bytes),
        Err(IpcError::Decode(_))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Arbitrary bytes never panic any decode path.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode::<AgentMsg>(&bytes);
        let _ = decode::<ServiceMsg>(&bytes);
        let _ = read_msg::<_, AgentMsg>(&mut &bytes[..]);
        let _ = read_msg::<_, ServiceMsg>(&mut &bytes[..]);
    }

    /// Random payloads behind a *valid* header reach the postcard layer and
    /// the semantic validation, which must also never panic.
    #[test]
    fn random_payload_behind_valid_header_never_panics(
        payload in proptest::collection::vec(any::<u8>(), 0..512)
    ) {
        let bytes = frame_bytes(PROTOCOL_VERSION, &payload);
        if let Ok(AgentMsg::Frames { frames, .. }) = decode::<AgentMsg>(&bytes) {
            // Anything that decodes must be a valid frame set.
            prop_assert!(frames.len() <= MAX_FRAMES_PER_MESSAGE);
            for f in frames {
                prop_assert!(f.into_frame().is_ok());
            }
        }
        let _ = decode::<ServiceMsg>(&bytes);
    }

    /// Bit flips / byte overwrites in valid encodings never panic and never
    /// yield an invalid frame.
    #[test]
    fn mutated_valid_messages_never_panic(
        msg in arb_agent_msg(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let mut bytes = encode(&msg).unwrap().to_vec();
        for (idx, val) in edits {
            let i = idx.index(bytes.len());
            bytes[i] = val;
        }
        let rt = runtime();
        let sync = read_msg::<_, AgentMsg>(&mut &bytes[..]);
        let streamed = rt.block_on(read_msg_async::<_, AgentMsg>(&mut &bytes[..]));
        // Identical semantics: both succeed (with equal results) or both fail.
        match (&sync, &streamed) {
            (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
            (Err(_), Err(_)) => {}
            _ => prop_assert!(false, "sync {:?} vs async {:?}", sync, streamed),
        }
        if let Ok(AgentMsg::Frames { frames, .. }) = sync {
            for f in frames {
                prop_assert!(f.into_frame().is_ok());
            }
        }
    }
}
