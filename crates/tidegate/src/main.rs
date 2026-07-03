//! `tidegate` — the local permissions gate for AI coding agents.
//!
//! One binary, three roles, chosen by subcommand:
//! - the **CLI** you run (`connect`, `install`, `posture`, `approve`,
//!   `revoke`, `audit`, `dashboard`);
//! - the **daemon** (`daemon`) — the long-lived gate, started on demand;
//! - the **shim** (`shim <agent>`) — the tiny stdio bridge an agent's MCP
//!   config points at, which hands the connection to the daemon in-process.
//!
//! Keeping all three in one binary is deliberate: an agent config references
//! the same executable the user installed, so there is nothing else to find
//! on PATH and nothing to version-skew.

#![forbid(unsafe_code)]

mod app;
mod commands;
mod providers;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "tidegate",
    version,
    about = "Local permissions gate for AI coding agents — connect once, every agent gets scoped, audited access. They never see the key."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect a service: add its credential to the vault (e.g. `connect github`).
    Connect {
        /// Service name (github, …) or a custom MCP server name.
        service: String,
        /// Non-interactive: read the secret from this env var instead of prompting.
        #[arg(long)]
        secret_env: Option<String>,
    },
    /// Wire agents to the gate for this project (e.g. `install claude codex`).
    Install {
        /// One or more of: claude, codex, cursor.
        agents: Vec<String>,
        /// Project directory (default: current).
        #[arg(long)]
        project: Option<String>,
        /// Initial posture: careful | standard | open.
        #[arg(long, default_value = "standard")]
        posture: String,
    },
    /// Set this project's posture. Widening asks for confirmation.
    Posture {
        /// careful | standard | open.
        level: String,
        #[arg(long)]
        project: Option<String>,
    },
    /// List pending approvals, or approve/deny one.
    Approve {
        /// Pending id. Omit to list.
        id: Option<String>,
        /// Confirmation code from the notification.
        #[arg(long)]
        code: Option<String>,
        /// Deny instead of allow.
        #[arg(long)]
        deny: bool,
        /// Remember the decision (always) rather than once.
        #[arg(long)]
        always: bool,
    },
    /// Revoke a grant now (narrowing — no confirmation needed).
    Revoke {
        /// Grant id (from `audit --grants`).
        grant_id: String,
    },
    /// Print the audit log (hash-chained receipts).
    Audit {
        /// Show live grants instead of receipts.
        #[arg(long)]
        grants: bool,
        /// Verify the receipt chain and report.
        #[arg(long)]
        verify: bool,
    },
    /// Open the local dashboard in your browser.
    Dashboard,
    /// Show gate status.
    Status,
    /// Run the daemon (usually started automatically).
    Daemon,
    /// The per-agent stdio shim (referenced by agent MCP configs).
    Shim {
        /// Agent name this shim serves.
        agent: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Connect { service, secret_env } => commands::connect(&service, secret_env),
        Command::Install { agents, project, posture } => {
            commands::install(&agents, project, &posture)
        }
        Command::Posture { level, project } => commands::posture(&level, project),
        Command::Approve { id, code, deny, always } => commands::approve(id, code, deny, always),
        Command::Revoke { grant_id } => commands::revoke(&grant_id),
        Command::Audit { grants, verify } => commands::audit(grants, verify),
        Command::Dashboard => commands::dashboard(),
        Command::Status => commands::status(),
        Command::Daemon => commands::daemon(),
        Command::Shim { agent } => commands::shim(&agent),
    };
    if let Err(e) = result {
        eprintln!("tidegate: {e}");
        std::process::exit(1);
    }
}
