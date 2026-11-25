//! What a device uploads (`POST /v1/events:batch`, a `SignedEvent`) and
//! what a recipient decrypts (an `EventBody`). Must never panic; every
//! decoder must round-trip, `check_shape` must mean what it says, and
//! distinct headers must have distinct signing bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_proto_fuzz::event(data);
});
