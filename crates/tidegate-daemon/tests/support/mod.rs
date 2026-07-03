//! Shared test scaffolding: a mock upstream MCP server and gateway builders.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::TempDir;
use tidegate_daemon::state::{Descriptor, ServerRow};
use tidegate_daemon::{Db, Gateway};
use tidegate_policy::AgentKey;
use tidegate_vault::Vault;

/// A tiny MCP server script (node-free): a Rust bin compiled as a test
/// fixture would need its own crate, so we use a portable shell/python echo
/// server instead. Python 3 is assumed present on dev/CI machines.
pub const MOCK_SERVER_PY: &str = r#"
import sys, json, os
def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    msg = json.loads(line)
    mid = msg.get("id"); method = msg.get("method")
    if method == "initialize":
        send({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"0"}}})
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        send({"jsonrpc":"2.0","id":mid,"result":{"tools":[
            {"name":"read_file","description":"read","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":True}},
            {"name":"create_pr","description":"write","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":False}}
        ]}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        tok = os.environ.get("MOCK_TOKEN","<none>")
        send({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"ok:"+name+":"+tok}],"isError":False}})
    else:
        send({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"no"}})
"#;

pub struct Harness {
    pub gw: Arc<Gateway>,
    pub dash_key: String,
    _dir: TempDir,
    _script: std::path::PathBuf,
}

pub fn agent(name: &str, project: &str) -> AgentKey {
    AgentKey { agent: name.into(), project: project.into() }
}

pub fn build(mock_token: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    write_key_file(dir.path());
    let script = dir.path().join("mock_server.py");
    std::fs::File::create(&script)
        .unwrap()
        .write_all(MOCK_SERVER_PY.as_bytes())
        .unwrap();

    let db = Db::open(&dir.path().join("state.db")).unwrap();
    let vault = Vault::open(&dir.path().join("vault")).unwrap();
    vault.store("mock", mock_token.as_bytes()).unwrap();

    let mut secret_env = std::collections::BTreeMap::new();
    secret_env.insert("mock".to_string(), "MOCK_TOKEN".to_string());
    db.upsert_server(&ServerRow {
        name: "mock".into(),
        command: python().into(),
        args: vec![script.to_string_lossy().to_string()],
        secret_env,
        descriptor: Descriptor {
            scopers: vec![tidegate_daemon::Scoper {
                arg: "repo".into(),
                template: "mock:repo:{}".into(),
            }],
            tool_classes: std::collections::BTreeMap::default(),
        },
    })
    .unwrap();

    let dash_key = "test-dash-key".to_string();
    let gw = Arc::new(Gateway::new(db, vault, &dash_key).unwrap());
    Harness { gw, dash_key, _dir: dir, _script: script }
}

fn write_key_file(dir: &Path) {
    let key_path = dir.join("master.key");
    std::env::set_var("TIDEGATE_MASTER_KEY_FILE", &key_path);
}

pub fn python() -> &'static str {
    // Prefer python3; fall back to python.
    if std::process::Command::new("python3").arg("--version").output().is_ok() {
        "python3"
    } else {
        "python"
    }
}
