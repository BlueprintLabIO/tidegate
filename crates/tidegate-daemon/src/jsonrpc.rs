//! Minimal JSON-RPC 2.0 framing over line-delimited streams.
//!
//! MCP stdio transport is newline-delimited JSON-RPC. We implement exactly
//! the subset we speak — requests, responses, notifications — by hand rather
//! than guessing at a fast-moving SDK's API. The protocol version we target
//! is pinned in [`MCP_PROTOCOL_VERSION`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl Message {
    #[must_use] 
    pub fn request(id: i64, method: &str, params: Value) -> Self {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(id)),
            method: Some(method.into()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    #[must_use] 
    pub fn notification(method: &str, params: Value) -> Self {
        Message {
            jsonrpc: "2.0".into(),
            id: None,
            method: Some(method.into()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    #[must_use] 
    pub fn response(id: Value, result: Value) -> Self {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(id),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    #[must_use] 
    pub fn error_response(id: Value, code: i64, message: &str) -> Self {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(id),
            method: None,
            params: None,
            result: None,
            error: Some(json!({ "code": code, "message": message })),
        }
    }

    #[must_use] 
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    #[must_use] 
    pub fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }

    #[must_use] 
    pub fn is_response(&self) -> bool {
        self.method.is_none() && self.id.is_some()
    }
}

pub fn write_message(w: &mut impl std::io::Write, m: &Message) -> std::io::Result<()> {
    let line = serde_json::to_string(m).map_err(std::io::Error::other)?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

#[must_use] 
pub fn parse_line(line: &str) -> Option<Message> {
    serde_json::from_str(line).ok()
}
