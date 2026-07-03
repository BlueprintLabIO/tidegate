//! Writing agent MCP configs so they launch the tidegate shim.
//!
//! Each supported agent reads a project-scoped MCP config file. We add (or
//! update) exactly one server entry, `tidegate`, pointing at this binary's
//! `shim` subcommand with the per-project token in the env. We never touch
//! other servers in the file (INV-C3: additive, idempotent).
//!
//! Config shapes differ per agent but share a JSON `mcpServers` (or
//! `mcp.servers`) object of `{ command, args, env }`, so one writer with a
//! per-agent path + key covers all three.

use crate::app::{self, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Where each agent keeps its project MCP config, and the JSON pointer to the
/// servers object within it.
struct Layout {
    /// Path relative to the project root.
    rel_path: &'static str,
    /// Top-level key holding the servers map.
    servers_key: &'static str,
}

fn layout(agent: &str) -> Option<Layout> {
    match agent {
        // Claude Code: project-local .mcp.json with { mcpServers: {...} }.
        "claude" => Some(Layout { rel_path: ".mcp.json", servers_key: "mcpServers" }),
        // Cursor: .cursor/mcp.json with { mcpServers: {...} }.
        "cursor" => Some(Layout { rel_path: ".cursor/mcp.json", servers_key: "mcpServers" }),
        // Codex: .codex/mcp.json (JSON form) with { mcpServers: {...} }.
        // (Codex also supports TOML config; we use the per-project JSON form
        //  for parity and to keep one writer.)
        "codex" => Some(Layout { rel_path: ".codex/mcp.json", servers_key: "mcpServers" }),
        _ => None,
    }
}

/// Add/update the `tidegate` MCP server entry in `agent`'s project config.
pub fn wire(agent: &str, project: &str, exe: &Path, token: &str) -> Result<()> {
    let layout = layout(agent)
        .ok_or_else(|| app::msg(format!("no config layout for agent {agent:?}")))?;
    let path = PathBuf::from(project).join(layout.rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut root: Value = if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        serde_json::from_str(&text).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };
    if !root.is_object() {
        root = json!({});
    }

    // Ensure the servers object exists without disturbing siblings.
    let servers = root
        .as_object_mut()
        .unwrap()
        .entry(layout.servers_key)
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }

    servers.as_object_mut().unwrap().insert(
        "tidegate".to_string(),
        json!({
            "command": exe.to_string_lossy(),
            "args": ["shim", agent],
            "env": { "TIDEGATE_AGENT_TOKEN": token }
        }),
    );

    let pretty = serde_json::to_string_pretty(&root).map_err(|e| app::msg(e.to_string()))?;
    std::fs::write(&path, pretty + "\n")?;
    restrict(&path);
    Ok(())
}

#[cfg(unix)]
fn restrict(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // The token lives here — keep it owner-only.
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_p: &Path) {}
