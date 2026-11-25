//! Benchmark a candidate ONNX image classifier on a labelled test set, and
//! gate the results against a baseline. Metrics only: no image, thumbnail
//! or per-image result is ever written.
//!
//! ```sh
//! cargo run --release -p faro-detect --features onnx --example model-bench -- \
//!     --manifest m.json --set /path/to/set --json results.json
//! ```
//!
//! See `--help`, and DEVELOPMENT.md "Model benchmark".

fn main() -> std::process::ExitCode {
    let code = faro_detect::bench::cli::main(
        std::env::args().skip(1),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::ExitCode::from(code)
}
