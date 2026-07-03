//! Tidegate daemon: the local gate every agent tool call passes through.
//!
//! Composition of five pieces, each in its own module:
//! - [`jsonrpc`] — MCP's line-delimited JSON-RPC framing.
//! - [`upstream`] — spawns and speaks to real MCP servers with credentials
//!   injected from the vault.
//! - [`state`] — the persistent world: agents, servers, policy mirror, and
//!   the hash-chained receipt log.
//! - [`gateway`] — the judgement: policy + approvals + receipts, one call at
//!   a time, three terminal outcomes.
//! - [`mcp_server`] / [`http`] — the two faces: agents talk MCP over stdio;
//!   the human talks HTTP to a loopback dashboard and the CLI drives the same
//!   admin API.
//!
//! The invariants these keep are catalogued in `docs/invariants.md`
//! (INV-D1..D6) and enforced by tests in `tests/`.

#![forbid(unsafe_code)]

pub mod gateway;
pub mod http;
pub mod jsonrpc;
pub mod mcp_server;
pub mod notify;
pub mod state;
pub mod upstream;

pub use gateway::{Answer, CallOutcome, Gateway, GatewayError, ResolveCredential};
pub use state::{random_id, sha256_hex, unix_now, Db, Descriptor, Scoper, ServerRow, StateError};

use std::path::{Path, PathBuf};

/// Standard on-disk layout under the tidegate home directory.
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    pub fn new(home: PathBuf) -> Self {
        Paths { home }
    }
    pub fn state_db(&self) -> PathBuf {
        self.home.join("state.db")
    }
    pub fn vault_dir(&self) -> PathBuf {
        self.home.join("vault")
    }
    pub fn dash_key_file(&self) -> PathBuf {
        self.home.join("dashboard.key")
    }
    pub fn control_port_file(&self) -> PathBuf {
        self.home.join("control.port")
    }
}

/// Read (or create) the dashboard key. Stored 0600; the CLI reads it to
/// drive the admin API and to print the dashboard URL.
pub fn load_or_create_dash_key(path: &Path) -> std::io::Result<String> {
    if path.exists() {
        return Ok(std::fs::read_to_string(path)?.trim().to_string());
    }
    let key = random_id("dk") + &random_id("k");
    std::fs::write(path, &key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}
