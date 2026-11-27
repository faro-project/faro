//! An arbitrary upstream answer wrapped back to the client: never panics,
//! and anything wrapped is a well-formed packet carrying the answer
//! unchanged (`faro_dnsfilter_fuzz::response`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_dnsfilter_fuzz::response(data);
});
