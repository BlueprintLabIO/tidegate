//! Shared plumbing: home directory, daemon lifecycle, and the loopback HTTP
//! client the CLI uses to drive the gate's admin API.

use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use tidegate_daemon::Paths;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
    #[error("the gate is not running. Start it with `tidegate daemon` (or run any agent).")]
    DaemonDown,
    #[error("gate: {0}")]
    Api(String),
}

pub fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// Tidegate home: `$TIDEGATE_HOME` or `~/.tidegate`.
pub fn home() -> Result<PathBuf> {
    if let Ok(h) = std::env::var("TIDEGATE_HOME") {
        return Ok(PathBuf::from(h));
    }
    let base = dirs::home_dir().ok_or_else(|| msg("cannot locate home directory"))?;
    Ok(base.join(".tidegate"))
}

pub fn paths() -> Result<Paths> {
    let home = home()?;
    std::fs::create_dir_all(&home)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700));
    }
    Ok(Paths::new(home))
}

/// The running daemon's dashboard control port, if any.
pub fn control_port() -> Result<Option<u16>> {
    let p = paths()?;
    let f = p.control_port_file();
    if !f.exists() {
        return Ok(None);
    }
    let s = std::fs::read_to_string(f)?;
    Ok(s.trim().parse().ok())
}

pub fn dash_key() -> Result<String> {
    let p = paths()?;
    tidegate_daemon::load_or_create_dash_key(&p.dash_key_file()).map_err(Into::into)
}

/// Ensure the daemon is up, spawning it detached if needed. Confirms
/// readiness by round-tripping a ping over the control socket.
pub fn ensure_daemon() -> Result<()> {
    let p = paths()?;
    if sock_ping(&p.control_sock()).is_ok() {
        return Ok(());
    }
    // Spawn `tidegate daemon` detached. If TIDEGATE_DAEMON_LOG is set, route
    // its stderr there (diagnostics; default is silent).
    let exe = std::env::current_exe()?;
    let (out, err) = match std::env::var("TIDEGATE_DAEMON_LOG") {
        Ok(path) => {
            let f = std::fs::File::create(&path)?;
            let f2 = f.try_clone()?;
            (std::process::Stdio::from(f), std::process::Stdio::from(f2))
        }
        Err(_) => (std::process::Stdio::null(), std::process::Stdio::null()),
    };
    std::process::Command::new(exe)
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()?;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if sock_ping(&p.control_sock()).is_ok() {
            return Ok(());
        }
    }
    Err(Error::DaemonDown)
}

fn sock_ping(sock: &std::path::Path) -> Result<()> {
    // A cheap round-trip that any live daemon answers.
    call_raw(sock, &json!({ "op": "pending" }))?;
    Ok(())
}

/// One request/response over the control socket, bringing the daemon up first.
pub fn call(req: Value) -> Result<Value> {
    ensure_daemon()?;
    let p = paths()?;
    let resp = call_raw(&p.control_sock(), &req)?;
    if let Some(err) = resp.get("error").and_then(Value::as_str) {
        return Err(Error::Api(err.to_string()));
    }
    Ok(resp)
}

fn call_raw(sock: &std::path::Path, req: &Value) -> Result<Value> {
    tidegate_daemon::sock::call(sock, req).map_err(|e| Error::Api(e.to_string()))
}

/// Canonicalize a project path (identity is agent × project).
pub fn canonical_project(project: Option<String>) -> Result<String> {
    let raw = match project {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()?,
    };
    let abs = std::fs::canonicalize(&raw).unwrap_or(raw);
    Ok(abs.to_string_lossy().to_string())
}
