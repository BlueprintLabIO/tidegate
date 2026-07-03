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
    gw: Arc<Gateway>,
    dash_key: String,
    server: Server,
    pub port: u16,
}

impl Control {
    pub fn bind(gw: Arc<Gateway>, dash_key: String) -> std::io::Result<Self> {
        let server = Server::http("127.0.0.1:0").map_err(std::io::Error::other)?;
        let port = match server.server_addr() {
            tiny_http::ListenAddr::IP(a) => a.port(),
            _ => 0,
        };
        Ok(Control { gw, dash_key, server, port })
    }

    /// Serve forever (call in its own thread).
    pub fn serve(&self) {
        for mut req in self.server.incoming_requests() {
            let method = req.method().clone();
            let url = req.url().to_string();
            let provided_key: Option<String> = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("X-Tidegate-Key"))
                .map(|h| h.value.as_str().to_string());
            let key_ok = provided_key
                .map(|k| sha256_hex(&k) == sha256_hex(&self.dash_key))
                .unwrap_or(false);
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);

            let resp = self.route(&method, &url, key_ok, &body);
            let _ = req.respond(resp);
        }
    }

    fn route(&self, method: &Method, url: &str, key_ok: bool, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
        let path = url.split('?').next().unwrap_or(url);
        match (method, path) {
            (Method::Get, "/") => html(DASHBOARD_HTML),
            (Method::Get, "/health") => ok_json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") })),

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

fn ok_json(v: Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&v).unwrap_or_default();
    Response::from_data(body)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn err_json(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
    Response::from_data(body)
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn html(s: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(s.as_bytes().to_vec())
        .with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
}

/// The dashboard: SLUICE-styled, self-contained, reads the key from its own
/// URL hash so it never lands in server logs.
const DASHBOARD_HTML: &str = include_str!("dashboard.html");
