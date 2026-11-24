//! The agent's view: arbitrary bytes from whatever is listening on the
//! socket. Must never panic.
#![no_main]

use faro_ipc::{decode, read_msg, ServiceMsg};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode::<ServiceMsg>(data);
    let _ = read_msg::<_, ServiceMsg>(&mut &data[..]);
});
