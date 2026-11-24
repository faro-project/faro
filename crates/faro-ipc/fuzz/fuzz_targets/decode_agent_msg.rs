//! The service's attack surface: arbitrary bytes from a (verified but
//! possibly compromised) agent. Must never panic, and anything that decodes
//! must convert into valid platform frames.
#![no_main]

use faro_ipc::{decode, read_msg, AgentMsg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = decode::<AgentMsg>(data);
    let streamed = read_msg::<_, AgentMsg>(&mut &data[..]);
    if let Ok(AgentMsg::Frames { frames, .. }) = whole {
        for f in frames {
            f.into_frame().expect("decoded frames are always valid");
        }
    }
    drop(streamed);
});
