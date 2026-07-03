//! The agent-facing MCP server, spoken over stdio by the per-agent shim.
//!
//! This process is what an agent's MCP config points at (via the shim). It
//! authenticates the agent by its token (from `TIDEGATE_AGENT_TOKEN`),
//! advertises the union of connected servers' tools, and routes every
//! tools/call through the [`Gateway`]. It is deliberately a thin translator:
//! all judgement lives in the gateway.

use crate::gateway::{CallOutcome, Gateway};
use crate::jsonrpc::{write_message, Message, MCP_PROTOCOL_VERSION};
use crate::state::sha256_hex;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::time::Duration;
use tidegate_policy::AgentKey;

/// Serve one agent connection to completion over the given reader/writer.
/// `token` identifies the agent; unknown tokens get a uniform init error
/// (INV-D4).
pub fn serve(
    gw: Arc<Gateway>,
    token: &str,
    elicit_capable: bool,
    input: impl BufRead,
    mut output: impl Write,
) {
    let token_hash = sha256_hex(token);
    let agent = match gw.db.agent_by_token_hash(&token_hash) {
        Ok(Some((agent, project))) => AgentKey { agent, project },
        _ => {
            // Uniform refusal: no tool list, no oracle.
            let _ = write_message(
                &mut output,
                &Message::error_response(json!(0), -32001, "tidegate: unrecognized agent token"),
            );
            return;
        }
    };

    for line in input.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Some(msg) = crate::jsonrpc::parse_line(&line) else { continue };
        if msg.is_notification() {
            continue; // initialized, cancelled, etc. — nothing to do
        }
        if !msg.is_request() {
            continue;
        }
        let id = msg.id.clone().unwrap_or(json!(null));
        let method = msg.method.as_deref().unwrap_or("");
        let reply = match method {
            "initialize" => Message::response(
                id,
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "tidegate", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "ping" => Message::response(id, json!({})),
            "tools/list" => match aggregate_tools(&gw) {
                Ok(tools) => Message::response(id, json!({ "tools": tools })),
                Err(e) => Message::error_response(id, -32000, &e),
            },
            "tools/call" => {
                let (name, args) = call_params(&msg.params);
                handle_tools_call(&gw, &agent, &name, args, elicit_capable, id)
            }
            other => {
                Message::error_response(id, -32601, &format!("method not supported: {other}"))
            }
        };
        if write_message(&mut output, &reply).is_err() {
            break;
        }
    }
}

fn aggregate_tools(gw: &Gateway) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for server in gw.db.list_servers().map_err(|e| e.to_string())? {
        match gw.tools_for(&server) {
            Ok(mut t) => out.append(&mut t),
            // A broken upstream should not blank the whole list; report the
            // others and let the agent see what is available.
            Err(_) => continue,
        }
    }
    Ok(out)
}

fn call_params(params: &Option<Value>) -> (String, Value) {
    let p = params.clone().unwrap_or(json!({}));
    let name = p.get("name").and_then(Value::as_str).unwrap_or_default().to_string();
    let args = p.get("arguments").cloned().unwrap_or(json!({}));
    (name, args)
}

fn handle_tools_call(
    gw: &Gateway,
    agent: &AgentKey,
    name: &str,
    args: Value,
    elicit_capable: bool,
    id: Value,
) -> Message {
    // Hold briefly so fast human approvals resolve in-line; otherwise return
    // the model-legible pending result well within the client's tool timeout.
    let wait = Duration::from_secs(if elicit_capable { 0 } else { 25 });
    match gw.handle_call(agent.clone(), name, args, elicit_capable, wait) {
        Ok(CallOutcome::Allowed { result, .. }) => {
            // Pass the upstream result through unchanged; it is already an
            // MCP tools/call result shape.
            Message::response(id, result)
        }
        Ok(CallOutcome::Denied { reason, .. }) => Message::response(
            id,
            tool_error(&format!("Tidegate denied this call: {reason}")),
        ),
        Ok(CallOutcome::Pending { message_for_model, .. }) => {
            // INV-D5: a legible, actionable result — not a JSON-RPC error.
            Message::response(id, tool_error(&message_for_model))
        }
        Err(e) => Message::response(id, tool_error(&format!("Tidegate error: {e}"))),
    }
}

/// An MCP tools/call result with isError set — the shape agents are built to
/// read and relay to the model.
fn tool_error(text: &str) -> Value {
    json!({
        "content": [ { "type": "text", "text": text } ],
        "isError": true
    })
}
