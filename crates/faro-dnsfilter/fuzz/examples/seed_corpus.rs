//! Write the seed corpus (`faro_dnsfilter_fuzz::seeds`) as
//! `<dir>/<target>/seed-*` (default `corpus/`, where `cargo fuzz run`
//! looks). Deterministic, so re-running only rewrites the same files.
//!
//! ```sh
//! cargo run --example seed_corpus [-- <dir>]
//! ```

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let dir: PathBuf = std::env::args_os()
        .nth(1)
        .map_or_else(|| "corpus".into(), Into::into);
    for (target, name, bytes) in faro_dnsfilter_fuzz::seeds() {
        let dir = dir.join(target);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("seed-{name}")), bytes)?;
    }
    println!("wrote the seed corpus to {}", dir.display());
    Ok(())
}
