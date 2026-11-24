//! `faro-server` binary. All logic lives in the library ([`faro_server::cli`])
//! so integration tests exercise exactly the code the binary runs.

fn main() -> std::process::ExitCode {
    faro_server::cli::main()
}
