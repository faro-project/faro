//! Spike tool for the service side (epic #85 part 4): lists WTS sessions,
//! shows this process's privilege, and optionally launches a program into a
//! session or checks a file's Authenticode signer.
//!
//! ```text
//! cargo run -p faro-platform-windows --example sessions_probe
//! cargo run -p faro-platform-windows --example sessions_probe -- --verify <file> [requirement]
//! cargo run -p faro-platform-windows --example sessions_probe -- --spawn <session-id> <program> [args...]
//! ```
//!
//! `--spawn` needs LocalSystem (`WTSQueryUserToken`). To run it as SYSTEM
//! for a test, from an elevated prompt: `psexec -s -i <path>\sessions_probe.exe
//! --spawn 1 C:\Windows\System32\notepad.exe`, or register it as a one-shot
//! scheduled task running as SYSTEM.

#[cfg(windows)]
fn main() {
    use faro_platform::ServiceHost;
    use faro_platform_windows::{acl, authenticode, service};

    let args: Vec<String> = std::env::args().skip(1).collect();
    println!(
        "running_as_system={} running_elevated={}",
        acl::running_as_system(),
        acl::running_elevated()
    );
    match service::enumerate_sessions() {
        Ok(list) => {
            println!("sessions:");
            for s in list {
                println!(
                    "  {:>3} {:<20} {:<12} {:?} {:?}",
                    s.id,
                    format!("{}\\{}", s.domain, s.user),
                    format!("{:?}", s.state),
                    s.protocol,
                    service::session_id(s.id).0
                );
            }
        }
        Err(e) => println!("cannot list sessions: {e}"),
    }

    match args.first().map(String::as_str) {
        None => {}
        Some("--verify") => {
            let Some(file) = args.get(1) else {
                eprintln!("usage: --verify <file> [requirement]");
                std::process::exit(2);
            };
            let path = std::path::Path::new(file);
            match authenticode::signer_of(path) {
                Ok(s) => println!("signer: {:?} sha256={}", s.subject, s.thumbprint_sha256),
                Err(e) => println!("not verified: {e}"),
            }
            if let Some(text) = args.get(2) {
                match authenticode::SignerRequirement::parse(text)
                    .and_then(|r| authenticode::verify_file(path, &r))
                {
                    Ok(_) => println!("requirement satisfied"),
                    Err(e) => println!("requirement not satisfied: {e}"),
                }
            }
        }
        Some("--spawn") => {
            let (Some(id), Some(program)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: --spawn <session-id> <program> [args...]");
                std::process::exit(2);
            };
            let Ok(id) = id.parse::<u32>() else {
                eprintln!("session id must be a number");
                std::process::exit(2);
            };
            let host =
                faro_platform_windows::WinServiceHost::with_agent(program, args[3..].to_vec());
            match host.spawn_agent_in_session(&service::session_id(id)) {
                Ok(pid) => println!("started pid {} in session {id}", pid.0),
                Err(e) => println!("spawn failed: {e}"),
            }
        }
        Some(other) => {
            eprintln!("unknown option {other}");
            std::process::exit(2);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("sessions_probe is Windows-only");
}
