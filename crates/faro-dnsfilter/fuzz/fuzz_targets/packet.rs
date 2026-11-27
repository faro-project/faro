//! One raw packet from the tunnel through the engine: never panics, and
//! every reply or forwarded answer is a well-formed packet back to the
//! sender (`faro_dnsfilter_fuzz::packet`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_dnsfilter_fuzz::packet(data);
});
