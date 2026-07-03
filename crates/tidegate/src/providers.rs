//! Provider descriptors — the "Nango lesson" made concrete.
//!
//! Nango supports thousands of services not by writing thousands of clients
//! but by making every provider a *declarative record*. Tidegate does the
//! same: a provider is data — how to spawn its MCP server, which vault secret
//! to inject as which env var, and how to derive a resource scope from a tool
//! call. Adding GitLab, Linear, or Slack is a new entry here (or a JSON file
//! the user drops in), not new gateway code.
//!
//! GitHub ships built in because it is the wedge. Everything else can be
//! connected as a generic MCP server today and given a richer descriptor when
//! someone writes one.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tidegate_daemon::{Descriptor, Scoper, ServerRow};

/// A connectable provider: everything the gate needs to run and scope it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    /// Human blurb shown at connect time.
    pub about: String,
    /// What the credential is, e.g. "a fine-grained personal access token".
    pub credential_hint: String,
    pub command: String,
    pub args: Vec<String>,
    /// vault secret name → env var injected into the server process.
    pub secret_env: BTreeMap<String, String>,
    pub descriptor: Descriptor,
}

impl Provider {
    pub fn into_server_row(self) -> ServerRow {
        ServerRow {
            name: self.name,
            command: self.command,
            args: self.args,
            secret_env: self.secret_env,
            descriptor: self.descriptor,
        }
    }
}

/// Built-in providers. GitHub is first-class; the generic entry lets any MCP
/// server be gated at whole-server granularity immediately.
pub fn builtin(name: &str) -> Option<Provider> {
    match name {
        "github" => Some(github()),
        _ => None,
    }
}

pub fn github() -> Provider {
    let mut secret_env = BTreeMap::new();
    secret_env.insert("github".to_string(), "GITHUB_PERSONAL_ACCESS_TOKEN".to_string());
    Provider {
        name: "github".into(),
        about: "GitHub — repos, issues, and pull requests through the official MCP server.".into(),
        credential_hint: "a fine-grained personal access token (github.com/settings/tokens)".into(),
        // The official GitHub MCP server, run via npx so there is nothing to
        // install ahead of time. Users on Docker can point this at the image
        // instead; it is just a descriptor.
        command: "npx".into(),
        args: vec!["-y".into(), "@modelcontextprotocol/server-github".into()],
        secret_env,
        descriptor: Descriptor {
            // Scope by the repo argument most GitHub tools take. Tools without
            // a repo arg fall back to the whole-server scope (mcp:github).
            scopers: vec![
                Scoper { arg: "repo".into(), template: "github:repo:{}".into() },
                Scoper { arg: "repository".into(), template: "github:repo:{}".into() },
            ],
            // The server annotates read tools, so we rely on readOnlyHint and
            // only override the few that matter for safety if annotations lie.
            tool_classes: BTreeMap::new(),
        },
    }
}

/// A generic MCP server the user names and runs themselves. Gated at
/// whole-server granularity until someone writes it a descriptor.
pub fn generic(name: &str, command: String, args: Vec<String>, secret_env: BTreeMap<String, String>) -> Provider {
    Provider {
        name: name.to_string(),
        about: format!("{name} — a custom MCP server, gated at whole-server scope."),
        credential_hint: "the credential this server needs (stored encrypted)".into(),
        command,
        args,
        secret_env,
        descriptor: Descriptor::default(),
    }
}
