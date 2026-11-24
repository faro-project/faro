//! Drive the incremental decoder with attacker-chosen chunk boundaries: the
//! first byte picks the chunk size, the rest is the stream. Several messages
//! may be decoded back to back. Must never panic or loop forever.
#![no_main]

use faro_ipc::codec::{decode_payload, FrameDecoder};
use faro_ipc::AgentMsg;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, mut rest)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk).max(1);
    let mut dec = FrameDecoder::new();
    while !rest.is_empty() {
        let buf = dec.buf_mut();
        let n = buf.len().min(chunk).min(rest.len());
        buf[..n].copy_from_slice(&rest[..n]);
        rest = &rest[n..];
        match dec.advance(n) {
            Ok(Some(raw)) => {
                let _ = decode_payload::<AgentMsg>(raw.version, &raw.bytes);
            }
            Ok(None) => {}
            Err(_) => return,
        }
    }
});
