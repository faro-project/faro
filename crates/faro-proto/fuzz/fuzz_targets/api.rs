//! The HTTP API types the server reads from devices and browsers and the
//! client reads from its instance. The first byte picks the type (see
//! `faro_proto_fuzz::API_TYPES`), the rest is JSON. Must never panic, and
//! every decoder must round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_proto_fuzz::api(data);
});
