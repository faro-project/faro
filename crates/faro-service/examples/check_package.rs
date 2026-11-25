//! Run the updater's package signature check on a `.pkg`, by hand.
//!
//! ```sh
//! FARO_TEAM_ID=ABCDE12345 cargo run -p faro-service --example check_package -- Faro-1.2.0.pkg
//! ```
//!
//! It is the same check the packaged service runs before it installs an
//! update (`faro_service::update::signature`), with the Team ID compiled in
//! from `FARO_TEAM_ID`. Without one it refuses every package, and with
//! `--features faro-service/dev` it skips the check. Exit status: 0 if the
//! package would be installed, 1 if it was rejected (the service would
//! report tamper), 2 if the check couldn't conclude.

use faro_service::update::signature::{self, Accepted, PackageCheckError, BUILD_POLICY};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(pkg), None) = (args.next(), args.next()) else {
        eprintln!("usage: check_package <path to .pkg>");
        return ExitCode::from(2);
    };
    let pkg = match std::path::absolute(&pkg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: {e}", pkg.to_string_lossy());
            return ExitCode::from(2);
        }
    };
    println!("policy: {BUILD_POLICY:?}");
    match signature::check_package(&pkg) {
        Ok(Accepted::Verified { team_id }) => {
            println!("accepted: signed by Faro's Developer ID ({team_id}) and notarized");
            ExitCode::SUCCESS
        }
        Ok(Accepted::Unchecked) => {
            println!("accepted without a check (development build)");
            ExitCode::SUCCESS
        }
        Err(e @ PackageCheckError::Rejected(_)) => {
            println!("rejected: {e}");
            ExitCode::from(1)
        }
        Err(e @ PackageCheckError::Unconfirmed(_)) => {
            println!("unconfirmed: {e}");
            ExitCode::from(2)
        }
    }
}
