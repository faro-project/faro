//! The same update check, but past the signatures: the input's documents
//! are *payloads*, which the harness signs with the toy project's keys
//! before handing them to the `Updater`, as if a release tool were buggy or
//! a project key compromised. This reaches the payload parser, the
//! structural validation, the version and expiry rules and target selection
//! with arbitrary content, which `client_flow` can't get past the
//! signatures.
//!
//! A targets step signs the payload, then also signs a timestamp that
//! commits to it (the next timestamp version, expiring a day after the
//! step's clock), since the fuzzer can't compute the BLAKE3 commitment.
//!
//! Must never panic and must keep every state-machine rule.
#![no_main]

use faro_update::metadata::MAX_TARGETS_BYTES;
use faro_update::testing::{ToyProject, DAY_MS};
use faro_update::{Role, TargetsMeta, Timestamp, Updater};
use faro_update_fuzz::{project, run_step, steps, Op, Step};
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

struct Fixture {
    project: ToyProject,
    first_root: Vec<u8>,
}

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    let project = project();
    Fixture {
        first_root: project.first_root(),
        project,
    }
});

fuzz_target!(|data: &[u8]| {
    let fx = &*FIXTURE;
    let p = &fx.project;
    let mut u = Updater::bootstrap(&fx.first_root).expect("the toy project's root");
    for step in steps(data) {
        let role = match step.op {
            Op::Root => Role::Root,
            Op::Timestamp => Role::Timestamp,
            Op::Targets => Role::Targets,
            Op::Persist => {
                run_step(&mut u, &step);
                continue;
            }
        };
        let envelope = p.sign_raw(role, step.bytes);
        if step.op == Op::Targets && envelope.len() <= MAX_TARGETS_BYTES {
            // Commit a fresh timestamp to this exact targets document.
            let version = serde_json::from_slice::<serde_json::Value>(step.bytes)
                .ok()
                .and_then(|v| v.get("version")?.as_u64())
                .unwrap_or(1);
            let ts = Timestamp {
                version: u
                    .state()
                    .timestamp()
                    .map_or(1, |t| t.version.saturating_add(1)),
                expires_ms: step.now_ms + DAY_MS,
                targets_meta: TargetsMeta::describe(&envelope, version),
            };
            let ts = serde_json::to_vec(&ts).expect("timestamp serializes");
            let ts = p.sign_raw(Role::Timestamp, &ts);
            run_step(
                &mut u,
                &Step {
                    op: Op::Timestamp,
                    now_ms: step.now_ms,
                    bytes: &ts,
                },
            );
        }
        run_step(
            &mut u,
            &Step {
                op: step.op,
                now_ms: step.now_ms,
                bytes: &envelope,
            },
        );
    }
});
