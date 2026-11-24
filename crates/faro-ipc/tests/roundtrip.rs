//! Every message variant survives the codec, sync and async, alone and in a
//! stream, and the sync and async paths produce identical bytes.

mod common;

use common::*;
use faro_ipc::{
    decode, encode, read_msg, read_msg_async, write_msg, write_msg_async, AgentMsg, IpcError,
    ServiceMsg,
};
use proptest::prelude::*;

#[test]
fn every_agent_variant_roundtrips_sync() {
    for msg in all_agent_msgs() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &msg).unwrap();
        assert_eq!(&buf[..], &encode(&msg).unwrap()[..], "{}", msg.kind());
        let back: AgentMsg = read_msg(&mut &buf[..]).unwrap();
        assert_eq!(back, msg);
        assert_eq!(decode::<AgentMsg>(&buf).unwrap(), msg);
    }
}

#[test]
fn every_service_variant_roundtrips_sync() {
    for msg in all_service_msgs() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &msg).unwrap();
        let back: ServiceMsg = read_msg(&mut &buf[..]).unwrap();
        assert_eq!(back, msg);
    }
}

#[tokio::test]
async fn every_variant_roundtrips_async_as_one_stream() {
    let (mut a, mut b) = tokio::io::duplex(1 << 20);
    let agent_msgs = all_agent_msgs();
    let service_msgs = all_service_msgs();
    let n_agent = agent_msgs.len();
    let writer = tokio::spawn(async move {
        for m in &agent_msgs {
            write_msg_async(&mut a, m).await.unwrap();
        }
        for m in &service_msgs {
            write_msg_async(&mut a, m).await.unwrap();
        }
        // dropping `a` closes the stream
    });
    let mut got_agent = Vec::new();
    for _ in 0..n_agent {
        got_agent.push(read_msg_async::<_, AgentMsg>(&mut b).await.unwrap());
    }
    let mut got_service = Vec::new();
    loop {
        match read_msg_async::<_, ServiceMsg>(&mut b).await {
            Ok(m) => got_service.push(m),
            Err(IpcError::Closed) => break,
            Err(e) => panic!("{e}"),
        }
    }
    writer.await.unwrap();
    assert_eq!(got_agent, all_agent_msgs());
    assert_eq!(got_service, all_service_msgs());
}

#[test]
fn sync_and_async_agree_on_bytes() {
    let rt = runtime();
    for msg in all_agent_msgs() {
        let mut sync_buf = Vec::new();
        write_msg(&mut sync_buf, &msg).unwrap();
        let mut async_buf = Vec::new();
        rt.block_on(write_msg_async(&mut async_buf, &msg)).unwrap();
        assert_eq!(sync_buf, async_buf);
        let back: AgentMsg = rt.block_on(read_msg_async(&mut &async_buf[..])).unwrap();
        assert_eq!(back, msg);
    }
}

#[test]
fn max_size_frames_message_roundtrips() {
    // The largest legal message: MAX_FRAMES_PER_MESSAGE full-size frames.
    let side = faro_platform::MAX_FRAME_SIDE;
    let frames: Vec<_> = (0..faro_ipc::MAX_FRAMES_PER_MESSAGE as u32)
        .map(|i| frame(side, side, i as u8 + 1, i))
        .collect();
    let msg = AgentMsg::Frames {
        captured_at_mono_ms: 1,
        frames,
    };
    let buf = encode(&msg).unwrap();
    assert!(buf.len() - 10 <= faro_ipc::MAX_PAYLOAD_LEN);
    let back: AgentMsg = decode(&buf).unwrap();
    assert_eq!(back, msg);
}

proptest! {
    #[test]
    fn arbitrary_agent_msgs_roundtrip(msg in arb_agent_msg()) {
        let bytes = encode(&msg).unwrap();
        let back: AgentMsg = decode(&bytes).unwrap();
        prop_assert_eq!(&back, &msg);
        let back: AgentMsg = read_msg(&mut &bytes[..]).unwrap();
        prop_assert_eq!(&back, &msg);
        let back: AgentMsg = runtime().block_on(read_msg_async(&mut &bytes[..])).unwrap();
        prop_assert_eq!(&back, &msg);
    }

    #[test]
    fn arbitrary_service_msgs_roundtrip(msg in arb_service_msg()) {
        let bytes = encode(&msg).unwrap();
        let back: ServiceMsg = decode(&bytes).unwrap();
        prop_assert_eq!(&back, &msg);
        let back: ServiceMsg = runtime().block_on(read_msg_async(&mut &bytes[..])).unwrap();
        prop_assert_eq!(back, msg);
    }

    /// Frames delivered through a real `Connection` in arbitrary-size chunks
    /// come out as valid `Frame`s with identical pixels.
    #[test]
    fn frames_survive_chunked_delivery_into_platform_frames(
        frames in proptest::collection::vec(arb_wire_frame(), 1..=faro_ipc::MAX_FRAMES_PER_MESSAGE),
        chunk in 1usize..64,
    ) {
        let expected: Vec<(u32, u32, u32, Vec<u8>)> = frames
            .iter()
            .map(|f| (f.width(), f.height(), f.display_id(), f.pixels().to_vec()))
            .collect();
        let bytes = encode(&AgentMsg::Frames { captured_at_mono_ms: 5, frames }).unwrap();
        let got = runtime().block_on(async {
            use tokio::io::AsyncWriteExt;
            let (a, mut raw) = tokio::io::duplex(1 << 16);
            let mut conn: faro_ipc::ServiceConnection<_> = faro_ipc::Connection::new(a);
            let bytes = bytes.to_vec();
            let w = tokio::spawn(async move {
                for c in bytes.chunks(chunk) {
                    raw.write_all(c).await.unwrap();
                }
            });
            let msg = conn.recv().await.unwrap();
            w.await.unwrap();
            msg
        });
        let AgentMsg::Frames { frames, .. } = got else {
            return Err(TestCaseError::fail("wrong variant"));
        };
        for (wf, (w, h, id, px)) in frames.into_iter().zip(expected) {
            let f = wf.into_frame().unwrap();
            prop_assert_eq!((f.width(), f.height(), f.display_id()), (w, h, id));
            prop_assert_eq!(f.pixels(), &px[..]);
        }
    }
}
