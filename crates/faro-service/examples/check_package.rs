//! Run the updater's package checks on a `.pkg`, by hand.
//!
//! ```sh
//! FARO_TEAM_ID=ABCDE12345 cargo run -p faro-service --example check_package -- Faro-1.2.0.pkg
//! ```
//!
//! They are the checks the packaged service runs before it installs an
//! update. First the signature (`faro_service::update::signature`), with
//! the Team ID compiled in from `FARO_TEAM_ID`: without one it refuses
//! every package, and with `--features faro-service/dev` it skips it. Then
//! the version inside the package (`faro_service::update::package_version`),
//! which the service compares with the update metadata's and the running
//! one. Exit status: 0 if the package would be installed as the version
//! printed, 1 if it was rejected (the service would report tamper), 2 if a
//! check couldn't conclude.

use faro_service::update::package_version;
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
    let r = match signature::check_package(&pkg) {
        Ok(Accepted::Verified { team_id }) => {
            println!("signature: Faro's Developer ID ({team_id}), notarized");
            Ok(())
        }
        Ok(Accepted::Unchecked) => {
            println!("signature: not checked (development build)");
            Ok(())
        }
        Err(e) => Err(e),
    };
    let r = r.and_then(|()| {
        let v = package_version::read_version(&pkg)?;
        println!("version: {v}");
        Ok(())
    });
    match r {
        Ok(()) => ExitCode::SUCCESS,
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
