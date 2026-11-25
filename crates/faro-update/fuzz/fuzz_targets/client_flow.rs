//! The client's (and the server mirror's) view of an update check: the
//! instance serving updates is the attacker. Starting from the toy
//! project's first root, the input is a sequence of root rotations,
//! timestamps and targets documents (see `faro_update_fuzz::steps`) fed to
//! the same `Updater` calls a client makes, with persistence in between.
//!
//! Must never panic, must keep every state-machine rule, and must never
//! trust a payload the project didn't sign: the fuzzer has no project key,
//! so every root, timestamp and targets payload the state ends up trusting
//! has to be one of the project's own.
#![no_main]

use faro_proto::Hash32;
use faro_update::Updater;
use faro_update_fuzz::{run_step, steps, History};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::sync::LazyLock;

struct Fixture {
    first_root: Vec<u8>,
    signed: BTreeSet<Hash32>,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let h = History::new();
    Fixture {
        signed: h.signed_payloads(),
        first_root: h.first_root,
    }
});

fuzz_target!(|data: &[u8]| {
    let fx = &*FIXTURE;
    let mut u = Updater::bootstrap(&fx.first_root).expect("the toy project's root");
    for step in steps(data) {
        run_step(&mut u, &step);
        let s = u.state();
        assert!(fx.signed.contains(&s.root_payload_hash()), "unsigned root");
        if let Some(t) = s.timestamp() {
            assert!(fx.signed.contains(&t.payload_hash), "unsigned timestamp");
        }
        if let Some(t) = s.targets() {
            assert!(fx.signed.contains(&t.payload_hash), "unsigned targets");
        }
    }
});
