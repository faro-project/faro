//! `faro-service`: the privileged Faro service. All logic lives in the
//! library (`faro_service`) so tests can drive it in-process.

fn main() -> std::process::ExitCode {
    faro_service::cli::main()
}
