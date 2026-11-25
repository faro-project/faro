//! The enroll socket, both ways: arbitrary bytes from a local process
//! asking the root service to enroll, and from whatever answers the agent.
//! Must never panic.
#![no_main]

use faro_ipc::{decode, read_msg, EnrollRequest, EnrollResponse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode::<EnrollRequest>(data);
    let _ = read_msg::<_, EnrollRequest>(&mut &data[..]);
    let _ = decode::<EnrollResponse>(data);
    let _ = read_msg::<_, EnrollResponse>(&mut &data[..]);
});
