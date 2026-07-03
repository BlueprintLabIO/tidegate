//! Integration test for the broker-proxy transport: a mock upstream HTTP
//! server, an agent call driven through the proxy, verifying policy gating,
//! credential injection (agent sends none, upstream receives it), scope
//! isolation, and receipts.

mod support;

use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tidegate_daemon::gateway::{ProxyOutcome, ProxyRequest};
use tidegate_daemon::state::{HttpProviderRow, PathScoper};
use tidegate_daemon::{Answer, Db, Gateway, ResolveCredential};
use tidegate_policy::AgentKey;
use tidegate_vault::Vault;

/// A one-request mock upstream: records the Authorization header it received
/// and replies 200 with a JSON echo. Runs on its own thread per accept.
fn spawn_mock_upstream() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            for line in req.lines() {
                if let Some(v) = line.strip_prefix("Authorization: ") {
                    seen2.lock().unwrap().push(v.trim().to_string());
                }
            }
            let body = json!({ "ok": true }).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            let _ = s.write_all(resp.as_bytes());
        }
    });
    (format!("http://127.0.0.1:{port}"), seen)
}

fn gw_with_provider(base_url: &str, secret: &str) -> (Arc<Gateway>, String) {
    use std::sync::{Mutex, OnceLock};
    // TIDEGATE_MASTER_KEY_FILE is process-global; serialize set-var + open.
    static ENV: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = ENV.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("TIDEGATE_MASTER_KEY_FILE", dir.path().join("master.key"));
    let db = Db::open(&dir.path().join("state.db")).unwrap();
    let vault = Vault::open(&dir.path().join("vault")).unwrap();
    vault.store("acme", secret.as_bytes()).unwrap();
    db.upsert_http_provider(&HttpProviderRow {
        name: "acme".into(),
        base_url: base_url.into(),
        auth_header: "Authorization".into(),
        auth_scheme: "Bearer ".into(),
        secret_name: "acme".into(),
        path_scopers: vec![PathScoper {
            prefix: "repos".into(),
            template: "acme:repo:{1}".into(),
            segments: 1,
        }],
    })
    .unwrap();
    // Keep dir alive for the test by leaking it into the returned tuple via a
    // thread-local is overkill; instead persist by forgetting (test process is
    // short-lived). We return the dir path implicitly by leaking.
    std::mem::forget(dir);
    let gw = Arc::new(Gateway::new(db, vault, "dash").unwrap());
    (gw, "acme".to_string())
}

fn agent() -> AgentKey {
    AgentKey { agent: "claude".into(), project: "/p".into() }
}

const NOWAIT: Duration = Duration::from_millis(0);

#[test]
fn proxy_read_asks_then_flows_and_injects_credential() {
    let (upstream, seen) = spawn_mock_upstream();
    let secret = "sk_live_MUST_NOT_LEAK_1234";
    let (gw, _) = gw_with_provider(&upstream, secret);
    let provider = gw.db.http_provider("acme").unwrap().unwrap();

    // First GET → ASK (empty policy).
    let out = gw
        .handle_proxy(agent(), &provider, &ProxyRequest { method: "GET", path: "repos/acme/thing", query: None, body: b"", content_type: None }, NOWAIT)
        .unwrap();
    assert!(matches!(out, ProxyOutcome::Pending { .. }), "first read should ask");

    // Approve read-always via dashboard key.
    let policy = gw.db.load_policy().unwrap();
    assert!(policy.grants.is_empty());
    // Find the pending id from the pending list.
    let pend = gw.pending_list(Some("dash"));
    let id = pend[0]["id"].as_str().unwrap().to_string();
    gw.resolve(&id, ResolveCredential::DashboardKey("dash".into()), Answer::AllowAlways).unwrap();

    // Now the same GET flows and returns the upstream 200.
    let out = gw
        .handle_proxy(agent(), &provider, &ProxyRequest { method: "GET", path: "repos/acme/thing", query: None, body: b"", content_type: None }, NOWAIT)
        .unwrap();
    match out {
        ProxyOutcome::Allowed { status, body, .. } => {
            assert_eq!(status, 200);
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["ok"], true);
        }
        o => panic!("expected allowed, got {o:?}"),
    }

    // The upstream received the injected credential; the agent supplied none.
    let auth = seen.lock().unwrap();
    assert!(auth.iter().any(|h| h == &format!("Bearer {secret}")), "upstream auth headers: {auth:?}");

    // Receipts recorded, none containing the secret.
    let receipts = gw.db.receipts(None).unwrap();
    let dump = serde_json::to_string(&receipts).unwrap();
    assert!(!dump.contains(secret), "secret leaked into receipts");
    assert!(gw.db.verify_chain().unwrap().is_none());
}

#[test]
fn proxy_scope_isolation_and_write_class() {
    let (upstream, _seen) = spawn_mock_upstream();
    let (gw, _) = gw_with_provider(&upstream, "s");
    let provider = gw.db.http_provider("acme").unwrap().unwrap();

    // Allow read on repo "one".
    let out = gw.handle_proxy(agent(), &provider, &ProxyRequest { method: "GET", path: "repos/one", query: None, body: b"", content_type: None }, NOWAIT).unwrap();
    let id = match out { ProxyOutcome::Pending { id, .. } => id, o => panic!("{o:?}") };
    gw.resolve(&id, ResolveCredential::DashboardKey("dash".into()), Answer::AllowAlways).unwrap();
    assert!(matches!(
        gw.handle_proxy(agent(), &provider, &ProxyRequest { method: "GET", path: "repos/one", query: None, body: b"", content_type: None }, NOWAIT).unwrap(),
        ProxyOutcome::Allowed { .. }
    ));

    // A different repo still asks (scope isolation).
    assert!(matches!(
        gw.handle_proxy(agent(), &provider, &ProxyRequest { method: "GET", path: "repos/two", query: None, body: b"", content_type: None }, NOWAIT).unwrap(),
        ProxyOutcome::Pending { .. }
    ));

    // A POST (write class) to the allowed repo still asks — the read grant
    // does not cover writes.
    assert!(matches!(
        gw.handle_proxy(agent(), &provider, &ProxyRequest { method: "POST", path: "repos/one", query: None, body: b"{}", content_type: Some("application/json") }, NOWAIT).unwrap(),
        ProxyOutcome::Pending { .. }
    ));
}
