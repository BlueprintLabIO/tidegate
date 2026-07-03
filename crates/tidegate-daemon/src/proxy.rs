//! The broker proxy — the HTTP transport that gates any REST API.
//!
//! An agent points a service's base URL at
//! `http://127.0.0.1:<port>/p/<agent-token>/<service>/<upstream-path>`. The
//! proxy authenticates the agent by the path token, looks up the provider,
//! applies policy (method → read/write, path → resource scope), and on Allow
//! injects the credential from the vault and forwards upstream. The agent
//! never holds the real credential — same guarantee as the MCP path, a
//! different transport into the same [`Gateway`].
//!
//! Loopback only. The path token is per-(agent, project), minted at install,
//! so a call is always attributed. Non-allow outcomes are returned as JSON
//! bodies a model can read and act on (403 deny, 428 pending).

use crate::gateway::{Gateway, ProxyOutcome, ProxyRequest};
use crate::state::sha256_hex;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tidegate_policy::AgentKey;
use tiny_http::{Header, Response, Server};

pub struct ProxyServer {
    gw: Arc<Gateway>,
    server: Arc<Server>,
    pub port: u16,
}

impl ProxyServer {
    pub fn bind(gw: Arc<Gateway>) -> std::io::Result<Self> {
        let server = Server::http("127.0.0.1:0").map_err(std::io::Error::other)?;
        let port = match server.server_addr() {
            tiny_http::ListenAddr::IP(a) => a.port(),
            tiny_http::ListenAddr::Unix(_) => 0,
        };
        Ok(ProxyServer { gw, server: Arc::new(server), port })
    }

    /// Serve forever, one thread per request (a parked approval must not block
    /// other in-flight proxied calls).
    pub fn serve(&self) {
        for mut req in self.server.incoming_requests() {
            let gw = self.gw.clone();
            std::thread::spawn(move || {
                let method = req.method().as_str().to_string();
                let url = req.url().to_string();
                let content_type = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Content-Type"))
                    .map(|h| h.value.as_str().to_string());
                let mut body = Vec::new();
                let _ = req.as_reader().read_to_end(&mut body);
                let resp = handle(&gw, &method, &url, content_type.as_deref(), &body);
                let _ = req.respond(resp);
            });
        }
    }
}

fn handle(
    gw: &Gateway,
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Response<std::io::Cursor<Vec<u8>>> {
    // Split path and query.
    let (raw_path, query) = match url.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url, None),
    };
    // Expect /p/<token>/<service>/<upstream...>
    let parts: Vec<&str> = raw_path.trim_start_matches('/').splitn(4, '/').collect();
    if parts.len() < 3 || parts[0] != "p" {
        return err(400, "expected /p/<token>/<service>/<path>");
    }
    let token = parts[1];
    let service = parts[2];
    let upstream_path = parts.get(3).copied().unwrap_or("");

    // Authenticate the agent by the path token (INV-D4: uniform error).
    let agent = match gw.db.agent_by_token_hash(&sha256_hex(token)) {
        Ok(Some((a, p))) => AgentKey { agent: a, project: p },
        _ => return err(401, "unrecognized agent token"),
    };
    let Ok(Some(provider)) = gw.db.http_provider(service) else {
        return err(404, &format!("no connected HTTP service {service:?} — run `tidegate connect {service}`"));
    };

    // Don't hold the HTTP connection: on ASK, return 428 immediately so the
    // agent's client doesn't hang. The model retries after approval (the
    // 428 body says so). A short grace lets a right-there approval land.
    let wait = Duration::from_secs(2);
    let preq = ProxyRequest { method, path: upstream_path, query, body, content_type };
    match gw.handle_proxy(agent, &provider, &preq, wait) {
        Ok(ProxyOutcome::Allowed { status, content_type, body, .. }) => {
            Response::from_data(body)
                .with_status_code(status)
                .with_header(ct_header(&content_type))
                .with_header(close())
        }
        Ok(ProxyOutcome::Denied { reason, .. }) => err(403, &format!("Tidegate denied this call: {reason}")),
        Ok(ProxyOutcome::Pending { id, message_for_model }) => {
            let body = serde_json::to_vec(&json!({
                "error": "approval_pending",
                "approval_id": id,
                "message": message_for_model,
            }))
            .unwrap_or_default();
            Response::from_data(body)
                .with_status_code(428) // Precondition Required: user must approve
                .with_header(json_header())
                .with_header(close())
        }
        Err(e) => err(502, &format!("Tidegate proxy error: {e}")),
    }
}

fn err(code: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_vec(&json!({ "error": msg })).unwrap_or_default();
    Response::from_data(body).with_status_code(code).with_header(json_header()).with_header(close())
}

fn json_header() -> Header {
    Header::from_bytes("Content-Type", "application/json").unwrap()
}

fn ct_header(ct: &str) -> Header {
    Header::from_bytes("Content-Type", ct.as_bytes()).unwrap_or_else(|()| json_header())
}

fn close() -> Header {
    Header::from_bytes("Connection", "close").unwrap()
}
