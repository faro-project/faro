//! The byte-level helpers in `encoding.rs` (`from_b64`, `from_slice`,
//! `from_prefixed_hex`, the base64 serde adapters, the canonical writer),
//! ids, enum names, key ids and safety codes, on arbitrary bytes and
//! strings. Must never panic; every decoder must round-trip, base64 must
//! be canonical, and the canonical encoding must be unambiguous.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_proto_fuzz::encoding(data);
});
