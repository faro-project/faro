//! Saved counters and filter configs, as the tunnel loads them from the
//! app group: never panics, and whatever loads round-trips
//! (`faro_dnsfilter_fuzz::state`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_dnsfilter_fuzz::state(data);
});
