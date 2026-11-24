//! The `faro-agent` command line, in the library so the service's
//! development spawner (`faro-service run --spawn-agent`) can be tested
//! against the exact arguments the agent accepts.
//!
//! ```text
//! faro-agent run [--socket PATH | env FARO_AGENT_SOCKET] [--session ID] [--user NAME]
//!                [--synthetic] [--trust-same-uid-service] [--no-ui]   # `dev` builds only
//! ```

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "faro-agent", version, about = "Faro per-session agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Connect to the Faro service and serve it until told to stop.
    Run(RunArgs),
}

#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// The service's Unix socket.
    #[arg(long, env = "FARO_AGENT_SOCKET", default_value = crate::DEFAULT_SOCKET_PATH)]
    pub socket: PathBuf,

    /// Session identifier to announce (default: `uid:<uid>`).
    #[arg(long)]
    pub session: Option<String>,

    /// Login name to announce (default: from the user database).
    #[arg(long)]
    pub user: Option<String>,

    /// Capture a scripted fake screen instead of the real one.
    /// Development builds only (`--features dev`).
    #[cfg(feature = "dev")]
    #[arg(long)]
    pub synthetic: bool,

    /// Accept a service running as our own uid instead of root.
    /// Development builds only (`--features dev`).
    #[cfg(feature = "dev")]
    #[arg(long)]
    pub trust_same_uid_service: bool,

    /// Show no menu-bar icon or notice window (macOS), e.g. to run outside
    /// a GUI session. Development builds only (`--features dev`): the icon
    /// is how everyone at the computer knows it is monitored (§12).
    #[cfg(feature = "dev")]
    #[arg(long)]
    pub no_ui: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
        let c = Cli::try_parse_from(["faro-agent", "run", "--socket", "/tmp/a.sock"]).unwrap();
        let Command::Run(args) = c.command;
        assert_eq!(args.socket, PathBuf::from("/tmp/a.sock"));
        // The subcommand is required.
        assert!(Cli::try_parse_from(["faro-agent", "--socket", "/tmp/a.sock"]).is_err());
    }
}
