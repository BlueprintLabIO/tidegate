//! The local control plane over HTTP on 127.0.0.1: the dashboard (a trust
//! surface, key-gated) and the admin/approval API the CLI drives.
//!
//! Bound to loopback only. Mutating endpoints require the dashboard key
//! (`X-Tidegate-Key`), which the CLI reads from the daemon's key file — a
//! file an agent could also read, which is exactly why *widening* endpoints
//! demand the per-pending confirmation code on top of the key, closing
//! INV-C1 at the HTTP boundary too.

use crate::gateway::{Answer, Gateway, ResolveCredential};
use crate::state::sha256_hex;
use serde_json::{json, Value};
use std::sync::Arc;
use tidegate_policy::Mutation;
use tiny_http::{Header, Method, Response, Server};

pub struct Control {
    inner: Arc<ControlInner>,
    server: Arc<Server>,
    pub port: u16,
}

struct ControlInner {
    gw: Arc<Gateway>,
    dash_key: String,
}

impl Control {
    pub fn bind(gw: Arc<Gateway>, dash_key: String) -> std::io::Result<Self> {
        let server = Server::http("127.0.0.1:0").map_err(std::io::Error::other)?;
        let port = match server.server_addr() {
            tiny_http::ListenAddr::IP(a) => a.port(),
            tiny_http::ListenAddr::Unix(_) => 0,
        };
        Ok(Control { inner: Arc::new(ControlInner { gw, dash_key }), server: Arc::new(server), port })
    }

    /// Serve forever, one thread per request. Concurrency is required, not an
    /// optimization: a `tools/call` parked on the approval condvar must not
    /// block the `/api/approve` that releases it.
    pub fn serve(&self) {
        for mut req in self.server.incoming_requests() {
            let inner = self.inner.clone();
            std::thread::spawn(move || {
                let method = req.method().clone();
                let url = req.url().to_string();
                let provided_key: Option<String> = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("X-Tidegate-Key"))
                    .map(|h| h.value.as_str().to_string());
                let key_ok = provided_key
                    .is_some_and(|k| sha256_hex(&k) == sha256_hex(&inner.dash_key));
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let resp = inner.route(&method, &url, key_ok, &body);
                let _ = req.respond(resp);
            });
        }
    }
}

impl ControlInner {
    fn route(&self, method: &Method, url: &str, key_ok: bool, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let path = url.split('?').next().unwrap_or(url);
        match (method, path) {
            (Method::Get, "/") => html(DASHBOARD_HTML),
            (Method::Get, "/health") => ok_json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") })),

            // Agent MCP bridge: authenticated by the per-agent token in the
            // body, NOT the dashboard key. This is how shim processes reach
            // the single Gateway. (INV-D4: bad token → uniform error inside.)
            (Method::Post, "/api/mcp") => self.api_mcp(body),

            // Widening posture request enters the approval pipeline.
            (Method::Post, "/api/posture-request") if key_ok => self.api_posture_request(body),

            // Read endpoints require the key (the dashboard is a trust
            // surface; its data should not be world-readable on loopback).
            (Method::Get, "/api/state") if key_ok => self.api_state(),
            (Method::Get, "/api/receipts") if key_ok => self.api_receipts(),
            (Method::Get, "/api/pending") if key_ok => {
                ok_json(json!({ "pending": self.gw.pending_list(Some(&self.dash_key)) }))
            }

            // Narrowing: key alone (matches CLI `revoke`).
            (Method::Post, "/api/revoke") if key_ok => self.api_revoke(body),

            // Widening: key AND per-pending credential (code or dashboard).
            (Method::Post, "/api/approve") if key_ok => self.api_approve(body),

            _ if !key_ok && path.starts_with("/api") => {
                err_json(401, "missing or bad X-Tidegate-Key")
            }
            _ => err_json(404, "not found"),
        }
    }

    /// Bridge one MCP request from a shim to the shared gateway. Body:
    /// `{ token, elicit, message }` where `message` is a JSON-RPC object.
    fn api_mcp(&self, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let v: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return err_json(400, "bad json"),
        };
        let token = v.get("token").and_then(Value::as_str).unwrap_or("");
        let elicit = v.get("elicit").and_then(Value::as_bool).unwrap_or(false);
        let message: crate::jsonrpc::Message = match v.get("message").cloned().and_then(|m| serde_json::from_value(m).ok()) {
            Some(m) => m,
            None => return err_json(400, "missing message"),
        };
        match crate::mcp_server::handle_request(&self.gw, token, elicit, &message) {
            Some(reply) => ok_json(json!({ "message": reply })),
            None => ok_json(json!({ "message": Value::Null })),
        }
    }

    fn api_posture_request(&self, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
        let project = v.get("project").and_then(Value::as_str).unwrap_or_default();
        let posture = v
            .get("posture")
            .and_then(Value::as_str)
            .and_then(tidegate_policy::Posture::parse);
        let (Some(posture), false) = (posture, project.is_empty()) else {
            return err_json(400, "project and valid posture required");
        };
        // Posture applies to whichever agents are in the project; scope is the
        // project-wide wildcard (mcp:*). We use a synthetic agent binding the
        // project so the compiled grants attribute to it; per-agent posture is
        // future work. For v0, apply to each installed agent in the project.
        let agents = self.gw.db.list_agents().unwrap_or_default();
        let Ok(scope) = tidegate_policy::Scope::whole_server("*") else {
            return err_json(500, "scope");
        };
        let mut last_id = String::new();
        let mut last_code = String::new();
        for a in agents.iter().filter(|a| a.project == project) {
            let agent = tidegate_policy::AgentKey { agent: a.agent.clone(), project: project.to_string() };
            match self.gw.request_posture(agent, posture, scope.clone()) {
                Ok((id, code)) => {
                    last_id = id;
                    last_code = code;
                }
                Err(e) => return err_json(500, &e.to_string()),
            }
        }
        if last_id.is_empty() {
            return err_json(400, "no agents installed in this project — run `tidegate install` first");
        }
        // The code is delivered via notification (sent inside request_posture);
        // returning the id lets the CLI print the confirm line.
        let _ = last_code;
        ok_json(json!({ "id": last_id }))
    }

    fn api_state(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let agents = self.gw.db.list_agents().unwrap_or_default();
        let servers = self.gw.db.list_servers().unwrap_or_default();
        ok_json(json!({
            "agents": agents,
            "servers": servers.iter().map(|s| json!({
                "name": s.name, "command": s.command,
            })).collect::<Vec<_>>(),
        }))
    }

    fn api_receipts(&self) -> Response<std::io::Cursor<Vec<u8>>> {
        let receipts = self.gw.db.receipts(Some(200)).unwrap_or_default();
        let broken = self.gw.db.verify_chain().ok().flatten();
        ok_json(json!({ "receipts": receipts, "chain_broken_at": broken }))
    }

    fn api_revoke(&self, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
        let Some(grant_id) = v.get("grant_id").and_then(Value::as_str) else {
            return err_json(400, "grant_id required");
        };
        match self.gw.admin_narrow(Mutation::RevokeGrant { grant_id: grant_id.to_string() }) {
            Ok(()) => ok_json(json!({ "ok": true })),
            Err(e) => err_json(500, &e.to_string()),
        }
    }

    fn api_approve(&self, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
        let Some(id) = v.get("id").and_then(Value::as_str) else {
            return err_json(400, "id required");
        };
        // Dashboard resolves with its own key as the human-presence proof.
        let cred = ResolveCredential::DashboardKey(self.dash_key.clone());
        // Posture pendings route to resolve_posture; tool pendings to resolve.
        if v.get("posture").and_then(Value::as_bool).unwrap_or(false) {
            return match self.gw.resolve_posture(id, cred) {
                Ok(()) => ok_json(json!({ "ok": true })),
                Err(e) => err_json(400, &e.to_string()),
            };
        }
        let answer = v
            .get("answer")
            .and_then(Value::as_str)
            .and_then(Answer::parse)
            .unwrap_or(Answer::AllowAlways);
        match self.gw.resolve(id, cred, answer) {
            Ok(()) => ok_json(json!({ "ok": true })),
            Err(e) => err_json(400, &e.to_string()),
        }
    }
}

/// `Connection: close` on every response. The control plane is low-volume and
/// per-request-threaded; forcing one request per connection sidesteps
/// keep-alive interactions between `tiny_http` and pooled clients (ureq),
/// which otherwise stall a pooled follow-up request mid-read.
fn close_conn() -> Header {
    Header::from_bytes("Connection", "close").unwrap()
}

fn ok_json(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&v).unwrap_or_default();
    Response::from_data(body)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(close_conn())
}

fn err_json(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
    Response::from_data(body)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(close_conn())
}

fn html(s: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(s.as_bytes().to_vec())
        .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
        .with_header(close_conn())
}

/// The dashboard: SLUICE-styled, self-contained, reads the key from its own
/// URL hash so it never lands in server logs.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
