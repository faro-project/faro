//! Write the seed corpus: valid documents signed by the toy project the
//! targets trust, as `<dir>/<target>/seed-*` (default `corpus/`, where
//! `cargo fuzz run` looks). Deterministic, so re-running only rewrites the
//! same files.
//!
//! ```sh
//! cargo run --example seed_corpus [-- <dir>]
//! ```

use faro_update::Role;
use faro_update_fuzz::{encode_steps, payload, seed_flows, History, Op};
use std::path::{Path, PathBuf};

fn write(dir: &Path, target: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let dir = dir.join(target);
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(format!("seed-{name}")), bytes)
}

fn main() -> std::io::Result<()> {
    let dir: PathBuf = std::env::args_os()
        .nth(1)
        .map_or_else(|| "corpus".into(), Into::into);
    let h = History::new();

    // Single documents: the envelopes as served, and their payloads.
    for (i, (role, env)) in h.envelopes().into_iter().enumerate() {
        let name = format!("{i:02}-{role}");
        write(&dir, "envelope", &name, env)?;
        write(&dir, "metadata", &name, &payload(role, env))?;
    }
    let os = ["13", "10.0.19045", "14.2"];
    for (i, s) in os.iter().enumerate() {
        write(&dir, "metadata", &format!("os-{i}"), s.as_bytes())?;
    }

    // Whole update checks as the mirror serves them...
    let flows = seed_flows(&h);
    for (name, steps) in &flows {
        write(&dir, "client_flow", name, &encode_steps(steps))?;
        // ...and the same checks as payloads for the harness to sign.
        let payloads: Vec<(Op, i64, Vec<u8>)> = steps
            .iter()
            .map(|&(op, hours, bytes)| {
                let role = match op {
                    Op::Root => Role::Root,
                    Op::Timestamp => Role::Timestamp,
                    Op::Targets => Role::Targets,
                    Op::Persist => return (op, hours, Vec::new()),
                };
                (op, hours, payload(role, bytes))
            })
            .collect();
        let payloads: Vec<(Op, i64, &[u8])> = payloads
            .iter()
            .map(|(op, hours, b)| (*op, *hours, b.as_slice()))
            .collect();
        write(&dir, "signed_flow", name, &encode_steps(&payloads))?;
    }
    println!("wrote the seed corpus to {}", dir.display());
    Ok(())
}
