//! The local control socket — a Unix domain socket carrying line-delimited
//! JSON. This is the primary IPC between the daemon and both the per-agent
//! shims and the CLI. MCP is itself a line-delimited JSON-RPC stream, so a
//! stream socket fits it exactly; HTTP request/response framing did not.
//!
//! One thread per connection, all sharing the single [`Gateway`]. A parked
//! `mcp` op (waiting on the approval condvar) blocks only its own connection;
//! an `approve` op on another connection resolves it.
//!
//! Protocol: each request is one JSON line `{ "op": "...", ... }`; each reply
//! is one JSON line. Ops:
//! - `mcp`      { token, elicit, message } -> { message }
//! - `pending`  {} -> { pending: [...] }
//! - `approve`  { id, code?, answer?, posture? } -> { ok } | { error }
//! - `revoke`   { `grant_id` } -> { ok } | { error }
//! - `posture_request` { project, posture } -> { id } | { error }
//! - `state`    {} -> { agents, servers }
//! - `receipts` {} -> { receipts, `chain_broken_at` }

use crate::gateway::{Answer, Gateway, ResolveCredential};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

pub struct SockServer {
    gw: Arc<Gateway>,
    listener: UnixListener,
}

impl SockServer {
    pub fn bind(gw: Arc<Gateway>, path: &Path) -> std::io::Result<Self> {
        // Fresh socket each boot; a stale file would refuse to bind.
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner-only: the socket is an authority surface.
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(SockServer { gw, listener })
    }

    /// Accept forever, one thread per connection.
    pub fn serve(&self) {
        for stream in self.listener.incoming() {
            let Ok(stream) = stream else { continue };
            let gw = self.gw.clone();
            std::thread::spawn(move || handle_conn(gw, stream));
        }
    }
}

fn handle_conn(gw: Arc<Gateway>, stream: UnixStream) {
    let reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut writer = stream;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let reply = dispatch(&gw, &req);
        let out = serde_json::to_string(&reply).unwrap_or_else(|_| "{}".into());
        if writer.write_all(out.as_bytes()).is_err() || writer.write_all(b"\n").is_err() {
            break;
        }
        let _ = writer.flush();
    }
}

fn dispatch(gw: &Gateway, req: &Value) -> Value {
    let op = req.get("op").and_then(Value::as_str).unwrap_or("");
    match op {
        "mcp" => {
            let token = req.get("token").and_then(Value::as_str).unwrap_or("");
            let elicit = req.get("elicit").and_then(Value::as_bool).unwrap_or(false);
            let message: crate::jsonrpc::Message =
                match req.get("message").cloned().and_then(|m| serde_json::from_value(m).ok()) {
                    Some(m) => m,
                    None => return json!({ "error": "missing message" }),
                };
            match crate::mcp_server::handle_request(gw, token, elicit, &message) {
                Some(reply) => json!({ "message": reply }),
                None => json!({ "message": Value::Null }),
            }
        }
        "pending" => json!({ "pending": gw.pending_list(None) }),
        "state" => {
            let agents = gw.db.list_agents().unwrap_or_default();
            let servers = gw.db.list_servers().unwrap_or_default();
            json!({
                "agents": agents,
                "servers": servers.iter().map(|s| json!({ "name": s.name, "command": s.command })).collect::<Vec<_>>(),
            })
        }
        "receipts" => {
            let receipts = gw.db.receipts(Some(200)).unwrap_or_default();
            let broken = gw.db.verify_chain().ok().flatten();
            json!({ "receipts": receipts, "chain_broken_at": broken })
        }
        "revoke" => {
            let Some(grant_id) = req.get("grant_id").and_then(Value::as_str) else {
                return json!({ "error": "grant_id required" });
            };
            match gw.admin_narrow(tidegate_policy::Mutation::RevokeGrant {
                grant_id: grant_id.to_string(),
            }) {
                Ok(()) => json!({ "ok": true }),
                Err(e) => json!({ "error": e.to_string() }),
            }
        }
        "approve" => approve(gw, req),
        "posture_request" => posture_request(gw, req),
        other => json!({ "error": format!("unknown op {other}") }),
    }
}

fn approve(gw: &Gateway, req: &Value) -> Value {
    let Some(id) = req.get("id").and_then(Value::as_str) else {
        return json!({ "error": "id required" });
    };
    let code = req.get("code").and_then(Value::as_str);
    // Posture confirmation vs tool approval.
    if req.get("posture").and_then(Value::as_bool).unwrap_or(false) {
        let Some(code) = code else { return json!({ "error": "code required" }) };
        return match gw.resolve_posture(id, ResolveCredential::Code(code.to_string())) {
            Ok(()) => json!({ "ok": true }),
            Err(e) => json!({ "error": e.to_string() }),
        };
    }
    let Some(code) = code else { return json!({ "error": "code required" }) };
    let answer = req
        .get("answer")
        .and_then(Value::as_str)
        .and_then(Answer::parse)
        .unwrap_or(Answer::AllowOnce);
    match gw.resolve(id, ResolveCredential::Code(code.to_string()), answer) {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "error": e.to_string() }),
    }
}

fn posture_request(gw: &Gateway, req: &Value) -> Value {
    let project = req.get("project").and_then(Value::as_str).unwrap_or("");
    let posture = req
        .get("posture")
        .and_then(Value::as_str)
        .and_then(tidegate_policy::Posture::parse);
    let Some(posture) = posture else { return json!({ "error": "valid posture required" }) };
    if project.is_empty() {
        return json!({ "error": "project required" });
    }
    let Ok(scope) = tidegate_policy::Scope::whole_server("*") else {
        return json!({ "error": "scope" });
    };
    let agents = gw.db.list_agents().unwrap_or_default();
    let mut last_id = String::new();
    for a in agents.iter().filter(|a| a.project == project) {
        let agent = tidegate_policy::AgentKey { agent: a.agent.clone(), project: project.to_string() };
        match gw.request_posture(agent, posture, scope.clone()) {
            Ok((id, _code)) => last_id = id,
            Err(e) => return json!({ "error": e.to_string() }),
        }
    }
    if last_id.is_empty() {
        return json!({ "error": "no agents installed in this project — run `tidegate install` first" });
    }
    json!({ "id": last_id })
}

/// Client side: one round-trip request over the control socket.
pub fn call(sock_path: &Path, req: &Value) -> std::io::Result<Value> {
    let stream = UnixStream::connect(sock_path)?;
    let mut writer = stream.try_clone()?;
    let line = serde_json::to_string(req).map_err(std::io::Error::other)?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp)?;
    serde_json::from_str(&resp).map_err(std::io::Error::other)
}
