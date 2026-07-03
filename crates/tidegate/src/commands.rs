//! CLI command implementations.

use crate::app::{self, Result};
use crate::providers;
use serde_json::{json, Value};
use std::io::Write;
use tidegate_daemon::{
    load_or_create_dash_key, random_id, sha256_hex, unix_now, Db, Gateway, Paths,
};
use tidegate_policy::Posture;
use tidegate_vault::{KeySource, Vault};

mod agentcfg;

const KNOWN_AGENTS: &[&str] = &["claude", "codex", "cursor"];

// ---- connect ----

pub fn connect(service: &str, secret_env: Option<String>) -> Result<()> {
    let p = app::paths()?;
    let vault = open_vault(&p)?;
    // Built-in (github) or a custom MCP server described by env vars:
    //   TIDEGATE_MCP_COMMAND (required for custom), TIDEGATE_MCP_ARGS (space
    //   separated), TIDEGATE_MCP_ENV (the env var name to inject the secret
    //   into). This is the generic path the Nango-style descriptor enables.
    let provider = if let Some(p) = providers::builtin(service) { p } else {
        let command = std::env::var("TIDEGATE_MCP_COMMAND").map_err(|_| {
            app::msg(format!(
                "no built-in provider {service:?}. To connect a custom MCP server, set \
                 TIDEGATE_MCP_COMMAND (and optionally TIDEGATE_MCP_ARGS, TIDEGATE_MCP_ENV)."
            ))
        })?;
        let args = std::env::var("TIDEGATE_MCP_ARGS")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        let mut secret_env = std::collections::BTreeMap::new();
        if let Ok(env_var) = std::env::var("TIDEGATE_MCP_ENV") {
            secret_env.insert(service.to_string(), env_var);
        }
        providers::generic(service, command, args, secret_env)
    };

    println!("Connecting {}.", provider.name);
    println!("  {}", provider.about);

    // Acquire the secret: env (non-interactive) or a hidden prompt.
    let secret = if let Some(var) = secret_env { std::env::var(&var)
    .map_err(|_| app::msg(format!("env var {var} is not set")))? } else {
        println!("  Paste {}.", provider.credential_hint);
        print!("  token (hidden): ");
        std::io::stdout().flush().ok();
        rpassword::read_password().map_err(|e| app::msg(e.to_string()))?
    };
    let secret = secret.trim().to_string();
    if secret.is_empty() {
        return Err(app::msg("empty token — nothing stored"));
    }

    // Store in the vault (the last time this token is in the clear).
    let secret_names: Vec<String> = provider.secret_env.keys().cloned().collect();
    for name in &secret_names {
        vault.store(name, secret.as_bytes()).map_err(|e| app::msg(e.to_string()))?;
    }

    // Register the server in daemon state.
    let db = open_db(&p)?;
    db.upsert_server(&provider.clone().into_server_row())
        .map_err(|e| app::msg(e.to_string()))?;

    let where_key = match vault.key_source() {
        KeySource::OsKeychain => "your OS keychain",
        KeySource::KeyFile => "a key file (TIDEGATE_MASTER_KEY_FILE)",
    };
    println!("\n  ✔ {} → vault", provider.name);
    println!("    encrypted at rest · master key in {where_key} · never leaves this machine");
    println!("    Next: tidegate install claude   (wire an agent to the gate)");
    Ok(())
}

// ---- install ----

pub fn install(agents: &[String], project: Option<String>, posture: &str) -> Result<()> {
    if agents.is_empty() {
        return Err(app::msg("name at least one agent, e.g. `tidegate install claude`"));
    }
    let posture = Posture::parse(posture)
        .ok_or_else(|| app::msg("posture must be careful | standard | open"))?;
    let project = app::canonical_project(project)?;
    let p = app::paths()?;
    let db = open_db(&p)?;
    let exe = std::env::current_exe()?;

    for agent in agents {
        if !KNOWN_AGENTS.contains(&agent.as_str()) {
            println!("  ! {agent}: not a known agent (known: {}). Skipping.", KNOWN_AGENTS.join(", "));
            continue;
        }
        // Mint a per-(agent, project) token; store its hash.
        let token = random_id("tgk") + &random_id("");
        db.insert_agent(&sha256_hex(&token), agent, &project, unix_now())
            .map_err(|e| app::msg(e.to_string()))?;

        // Write the agent's project MCP config to launch our shim.
        agentcfg::wire(agent, &project, &exe, &token)?;
        println!("  ✔ {agent} wired for {project}");
    }

    // Persist the project posture. Careful/Standard need no human event to
    // *set* as an initial choice at install time (this IS the setup approval);
    // but only Standard/Open pre-create grants, and they do so lazily on first
    // use via the gate. Here we just record the posture; the gate compiles it.
    db.set_posture(&project, posture).map_err(|e| app::msg(e.to_string()))?;
    println!(
        "\n  posture: {} — {}",
        posture.as_str(),
        match posture {
            Posture::Careful => "every tool asks",
            Posture::Standard => "reads flow after you approve them once; writes ask",
            Posture::Open => "everything flows; receipts and revoke stay on",
        }
    );
    println!("  Open your agent and try a read. The first novel action will ask.");
    Ok(())
}

// ---- posture ----

pub fn posture(level: &str, project: Option<String>) -> Result<()> {
    let level = Posture::parse(level)
        .ok_or_else(|| app::msg("posture must be careful | standard | open"))?;
    let project = app::canonical_project(project)?;

    // Narrowing (→ careful) applies instantly. Widening (→ open) requests.
    let current = current_posture(&project)?;
    if level <= current {
        // careful < standard < open by derive(Ord); narrowing or equal.
        let p = app::paths()?;
        let db = open_db(&p)?;
        db.set_posture(&project, level).map_err(|e| app::msg(e.to_string()))?;
        // Also strip any grants wider than the new posture would create.
        // (Narrowing is honest: revoke everything, let it re-ask.)
        if level == Posture::Careful {
            revoke_project_grants(&db, &project)?;
        }
        println!("  ✔ posture set to {} (narrowing — applied now)", level.as_str());
        return Ok(());
    }

    // Widening: route through the approval pipeline.
    let resp = app::call(
        json!({ "op": "posture_request", "project": project, "posture": level.as_str() }),
    )?;
    let id = resp.get("id").and_then(Value::as_str).unwrap_or("");
    println!("  posture {} requested for this project.", level.as_str());
    println!("  You have been notified — confirm with:");
    println!("      tidegate approve {id} --code <code>");
    println!("  (or click Confirm in the dashboard). Nothing widened yet.");
    Ok(())
}

// ---- approve / list ----

pub fn approve(id: Option<String>, code: Option<String>, deny: bool, always: bool) -> Result<()> {
    let Some(id) = id else {
        return list_pending();
    };
    let is_posture = id_is_posture(&id)?;
    if is_posture {
        let code = code.ok_or_else(|| app::msg("posture confirmation needs --code <code>"))?;
        app::call(json!({ "op": "approve", "id": id, "code": code, "posture": true }))?;
        println!("  ✔ posture confirmed");
        return Ok(());
    }
    let answer = match (deny, always) {
        (false, false) => "allow_once",
        (false, true) => "allow_always",
        (true, false) => "deny_once",
        (true, true) => "deny_always",
    };
    let code = code.ok_or_else(|| {
        app::msg("approval needs the --code from the notification (that code proves it's you, not the agent)")
    })?;
    app::call(json!({ "op": "approve", "id": id, "code": code, "answer": answer }))?;
    println!("  ✔ {}", answer.replace('_', " "));
    Ok(())
}

fn list_pending() -> Result<()> {
    let resp = app::call(json!({ "op": "pending" }))?;
    let empty = vec![];
    let pending = resp.get("pending").and_then(Value::as_array).unwrap_or(&empty);
    if pending.is_empty() {
        println!("  Nothing waiting.");
        return Ok(());
    }
    println!("  Pending approvals (confirm with the code from the notification):\n");
    for p in pending {
        println!(
            "    {}  {} → {}  ({})",
            p.get("id").and_then(Value::as_str).unwrap_or(""),
            p.get("agent").and_then(Value::as_str).unwrap_or(""),
            p.get("tool").and_then(Value::as_str).unwrap_or(""),
            p.get("resource").and_then(Value::as_str).unwrap_or(""),
        );
    }
    println!("\n  tidegate approve <id> --code <code> [--always] [--deny]");
    Ok(())
}

// ---- revoke ----

pub fn revoke(grant_id: &str) -> Result<()> {
    app::call(json!({ "op": "revoke", "grant_id": grant_id }))?;
    println!("  ✔ revoked {grant_id} (applies to the next call)");
    Ok(())
}

// ---- audit ----

pub fn audit(grants: bool, verify: bool) -> Result<()> {
    let p = app::paths()?;
    let db = open_db(&p)?;
    if verify {
        match db.verify_chain().map_err(|e| app::msg(e.to_string()))? {
            None => println!("  ✔ receipt chain intact ({} receipts)", db.receipts(None).map_err(|e| app::msg(e.to_string()))?.len()),
            Some(seq) => println!("  ✗ chain broken at receipt seq {seq}"),
        }
        return Ok(());
    }
    if grants {
        let policy = db.load_policy().map_err(|e| app::msg(e.to_string()))?;
        if policy.grants.is_empty() {
            println!("  No standing grants.");
        }
        for g in policy.grants.values() {
            let exp = g.expires_at.map_or_else(|| "standing".into(), |t| format!("expires {t}"));
            println!(
                "    {}  {} {:?} {}  [{}]",
                g.id, g.agent.agent, g.class, g.scope.as_str(), exp
            );
        }
        return Ok(());
    }
    let receipts = db.receipts(Some(50)).map_err(|e| app::msg(e.to_string()))?;
    if receipts.is_empty() {
        println!("  No receipts yet.");
    }
    for r in receipts.iter().rev() {
        let d = &r.detail;
        println!(
            "    [{}] {:<8} {} {} {}",
            r.at,
            r.kind,
            r.agent,
            d.get("tool").and_then(Value::as_str).or_else(|| d.get("posture").and_then(Value::as_str)).unwrap_or(""),
            d.get("resource").and_then(Value::as_str).unwrap_or(""),
        );
    }
    Ok(())
}

// ---- dashboard ----

pub fn dashboard() -> Result<()> {
    app::ensure_daemon()?;
    let port = app::control_port()?
        .ok_or_else(|| app::msg("daemon did not publish a dashboard port"))?;
    let key = app::dash_key()?;
    let url = format!("http://127.0.0.1:{port}/#{key}");
    println!("  Dashboard: {url}");
    open_browser(&url);
    Ok(())
}

// ---- status ----

pub fn status() -> Result<()> {
    let p = app::paths()?;
    if p.control_sock().exists() {
        println!("  gate: running (socket {})", p.control_sock().display());
    } else {
        println!("  gate: not running (starts automatically when an agent connects)");
    }
    let db = open_db(&p)?;
    println!("  agents: {}", db.list_agents().map_err(|e| app::msg(e.to_string()))?.len());
    println!("  servers: {}", db.list_servers().map_err(|e| app::msg(e.to_string()))?.len());
    println!("  receipts: {}", db.receipts(None).map_err(|e| app::msg(e.to_string()))?.len());
    Ok(())
}

// ---- daemon ----

pub fn daemon() -> Result<()> {
    crate::commands::run_daemon()
}

// ---- shim ----

pub fn shim(agent: &str) -> Result<()> {
    crate::commands::run_shim(agent)
}

// ================= helpers =================

fn open_vault(p: &Paths) -> Result<Vault> {
    Vault::open(&p.vault_dir()).map_err(|e| app::msg(format!("vault: {e}")))
}

fn open_db(p: &Paths) -> Result<Db> {
    Db::open(&p.state_db()).map_err(|e| app::msg(format!("state: {e}")))
}

fn current_posture(project: &str) -> Result<Posture> {
    let p = app::paths()?;
    let db = open_db(&p)?;
    db.posture(project).map_err(|e| app::msg(e.to_string()))
}

fn revoke_project_grants(db: &Db, project: &str) -> Result<()> {
    let policy = db.load_policy().map_err(|e| app::msg(e.to_string()))?;
    for g in policy.grants.values() {
        if g.agent.project == project {
            db.persist_mutation(&tidegate_policy::Mutation::RevokeGrant {
                grant_id: g.id.clone(),
            })
            .map_err(|e| app::msg(e.to_string()))?;
        }
    }
    Ok(())
}

fn id_is_posture(id: &str) -> Result<bool> {
    // Ask the daemon's pending list; posture pendings carry a posture.* tool.
    let resp = app::call(json!({ "op": "pending" }))?;
    let empty = vec![];
    let pending = resp.get("pending").and_then(Value::as_array).unwrap_or(&empty);
    Ok(pending.iter().any(|p| {
        p.get("id").and_then(Value::as_str) == Some(id)
            && p.get("tool").and_then(Value::as_str).is_some_and(|t| t.starts_with("posture."))
    }))
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd").args(["/C", "start", url]).spawn();
}

// ---- daemon + shim runtimes (in a submodule for clarity) ----

pub fn run_daemon() -> Result<()> {
    use std::sync::Arc;
    let p = app::paths()?;
    let db = open_db(&p)?;
    let vault = open_vault(&p)?;
    let dash_key = load_or_create_dash_key(&p.dash_key_file())?;
    let gw = Arc::new(
        Gateway::new(db, vault, &dash_key).map_err(|e| app::msg(e.to_string()))?,
    );
    // Two faces on one Gateway: a Unix socket for local IPC (shims + CLI),
    // and HTTP for the browser dashboard.
    let control = tidegate_daemon::http::Control::bind(gw.clone(), dash_key.clone())?;
    std::fs::write(p.control_port_file(), control.port.to_string())?;
    let sock = tidegate_daemon::sock::SockServer::bind(gw.clone(), &p.control_sock())?;
    eprintln!(
        "tidegate daemon: socket {} · dashboard 127.0.0.1:{}",
        p.control_sock().display(),
        control.port
    );
    // Socket server on a background thread; HTTP on this one. Both loop forever.
    std::thread::spawn(move || sock.serve());
    control.serve();
    Ok(())
}

/// The shim: an agent launched this (`tidegate shim <agent>`) as its MCP
/// server. It is a thin stdio↔daemon bridge — it does no policy work itself.
/// Every MCP message it reads on stdin it forwards to the daemon's `/api/mcp`
/// (authenticated by this agent's token) and writes the reply back to stdout.
/// This guarantees one Gateway for the whole machine: a single pendings map
/// and a single live `PolicyState`, no matter how many agents are wired.
pub fn run_shim(agent: &str) -> Result<()> {
    use std::io::{BufRead, Write as _};

    let token = std::env::var("TIDEGATE_AGENT_TOKEN")
        .map_err(|_| app::msg("TIDEGATE_AGENT_TOKEN not set — re-run `tidegate install`"))?;
    let elicit = std::env::var("TIDEGATE_ELICIT").map(|v| v == "1").unwrap_or(false);

    // The daemon holds the one true gate. Bring it up if it is not.
    app::ensure_daemon()?;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Forward to the daemon over the control socket. A null reply means
        // "notification, no answer".
        let resp = app::call(
            json!({ "op": "mcp", "token": token, "elicit": elicit, "message": message }),
        )?;
        if let Some(reply) = resp.get("message") {
            if reply.is_null() {
                continue;
            }
            let line = serde_json::to_string(reply).unwrap_or_default();
            if stdout.write_all(line.as_bytes()).is_err() || stdout.write_all(b"\n").is_err() {
                break;
            }
            let _ = stdout.flush();
        }
    }
    let _ = agent; // identity comes from the token, not the name
    Ok(())
}
