//! An upstream answer (CNAME, DNAME, SVCB and HTTPS records, truncation)
//! to an allowed query, through the session: never panics, a blocked alias
//! never passes, and only blocked names are counted
//! (`faro_dnsfilter_fuzz::answer`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    faro_dnsfilter_fuzz::answer(data);
});
