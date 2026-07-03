//! Upstream MCP server processes: spawned by the gate, credentials injected
//! into their environment from the vault, spoken to over stdio JSON-RPC.
//!
//! The agent never touches these processes — that is the whole point. The
//! upstream server itself does see the credential (it must, to call the
//! provider); THREAT_MODEL.md is explicit that upstream servers run under
//! the gate's trust, not the agent's.

use crate::jsonrpc::{parse_line, write_message, Message, MCP_PROTOCOL_VERSION};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const CALL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("failed to spawn upstream server {0:?}: {1}")]
    Spawn(String, std::io::Error),
    #[error("upstream server {0:?} exited or closed its pipe")]
    Closed(String),
    #[error("upstream server {0:?} timed out")]
    Timeout(String),
    #[error("upstream server {0:?} returned protocol error: {1}")]
    Protocol(String, String),
}

/// One tool as advertised by an upstream server.
#[derive(Debug, Clone)]
pub struct UpstreamTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// `readOnlyHint` from MCP tool annotations. `None` = unannotated.
    pub read_only_hint: Option<bool>,
}

pub struct Upstream {
    name: String,
    child: Child,
    stdin: Mutex<ChildStdin>,
    incoming: Mutex<Receiver<Message>>,
    next_id: Mutex<i64>,
    tools: Mutex<Option<Vec<UpstreamTool>>>,
}

impl Upstream {
    /// Spawn and initialize an upstream MCP server. `envs` carries the
    /// injected credential(s); stderr is inherited into the daemon log.
    pub fn spawn(
        name: &str,
        command: &str,
        args: &[String],
        envs: &HashMap<String, String>,
    ) -> Result<Self, UpstreamError> {
        let mut child = Command::new(command)
            .args(args)
            .envs(envs)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| UpstreamError::Spawn(name.to_string(), e))?;

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = channel::<Message>();
        // Reader thread: parses lines for the lifetime of the child. Ends
        // (dropping tx) when the pipe closes, which surfaces as Closed.
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(msg) = parse_line(&line) {
                    if tx.send(msg).is_err() {
                        break;
                    }
                }
            }
        });

        let mut up = Upstream {
            name: name.to_string(),
            child,
            stdin: Mutex::new(stdin),
            incoming: Mutex::new(rx),
            next_id: Mutex::new(1),
            tools: Mutex::new(None),
        };
        up.initialize()?;
        Ok(up)
    }

    fn initialize(&mut self) -> Result<(), UpstreamError> {
        let init = self.request(
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "tidegate", "version": env!("CARGO_PKG_VERSION") }
            }),
        )?;
        // Tolerate older protocol versions the server may negotiate down to;
        // we only use tools/list and tools/call, which are stable.
        let _ = init;
        self.notify("notifications/initialized", json!({}))?;
        Ok(())
    }

    /// Full (paginated) tools/list, cached after first success.
    pub fn tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        if let Some(cached) = self.tools.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(cached);
        }
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => json!({}),
            };
            let result = self.request("tools/list", params)?;
            for t in result.get("tools").and_then(Value::as_array).unwrap_or(&vec![]) {
                out.push(UpstreamTool {
                    name: t.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    input_schema: t.get("inputSchema").cloned().unwrap_or(json!({})),
                    read_only_hint: t
                        .get("annotations")
                        .and_then(|a| a.get("readOnlyHint"))
                        .and_then(Value::as_bool),
                });
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|c| !c.is_empty());
            if cursor.is_none() {
                break;
            }
        }
        *self.tools.lock().unwrap_or_else(|e| e.into_inner()) = Some(out.clone());
        Ok(out)
    }

    /// tools/call. Returns the raw MCP result object (content, isError, …).
    pub fn call_tool(&self, tool: &str, arguments: Value) -> Result<Value, UpstreamError> {
        self.request("tools/call", json!({ "name": tool, "arguments": arguments }))
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn notify(&self, method: &str, params: Value) -> Result<(), UpstreamError> {
        let msg = Message::notification(method, params);
        let mut stdin = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
        write_message(&mut *stdin, &msg).map_err(|_| UpstreamError::Closed(self.name.clone()))
    }

    /// Send a request and wait for its response, answering any interleaved
    /// server-initiated requests with method-not-found (we advertise no
    /// client capabilities) and ignoring notifications.
    fn request(&self, method: &str, params: Value) -> Result<Value, UpstreamError> {
        let id = {
            let mut n = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
            let id = *n;
            *n += 1;
            id
        };
        {
            let msg = Message::request(id, method, params);
            let mut stdin = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
            write_message(&mut *stdin, &msg)
                .map_err(|_| UpstreamError::Closed(self.name.clone()))?;
        }

        let incoming = self.incoming.lock().unwrap_or_else(|e| e.into_inner());
        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| UpstreamError::Timeout(self.name.clone()))?;
            let msg = match incoming.recv_timeout(remaining) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(UpstreamError::Timeout(self.name.clone()))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(UpstreamError::Closed(self.name.clone()))
                }
            };
            if msg.is_response() {
                if msg.id == Some(json!(id)) {
                    if let Some(err) = msg.error {
                        return Err(UpstreamError::Protocol(self.name.clone(), err.to_string()));
                    }
                    return Ok(msg.result.unwrap_or(Value::Null));
                }
                // A response to a request we no longer care about; drop it.
                continue;
            }
            if msg.is_request() {
                let reply = Message::error_response(
                    msg.id.clone().unwrap_or(Value::Null),
                    -32601,
                    "tidegate gateway: method not supported",
                );
                let mut stdin = self.stdin.lock().unwrap_or_else(|e| e.into_inner());
                let _ = write_message(&mut *stdin, &reply);
            }
            // Notifications fall through silently.
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
