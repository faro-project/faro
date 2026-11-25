//! What a device uploads (`POST /v1/reports`) and what a recipient
//! decrypts (a `DailyReport`). Must never panic, and every decoder must
//! round-trip.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_proto_fuzz::report(data);
});
