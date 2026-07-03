//! The daemon's persistent state: agents, servers, policy, pending
//! approvals, and the hash-chained receipt log. One `SQLite` file
//! (`state.db`), WAL mode, no secret material ever (INV-D1: secrets live in
//! the vault's separate database, full stop).

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;
use tidegate_policy::{DenyRule, Grant, Mutation, PolicyState, Posture};

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("state db: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("state io: {0}")]
    Io(#[from] std::io::Error),
    #[error("corrupt state row: {0}")]
    Corrupt(String),
}

/// A registered agent identity: (agent, project) + hashed bearer token.
#[derive(Debug, Clone, Serialize)]
pub struct AgentRow {
    pub agent: String,
    pub project: String,
    pub created_at: i64,
}

/// A connected upstream MCP server + its provider descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRow {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    /// Vault secret name → env var to inject, e.g.
    /// {"github": "`GITHUB_PERSONAL_ACCESS_TOKEN`"}.
    pub secret_env: std::collections::BTreeMap<String, String>,
    pub descriptor: Descriptor,
}

/// The Nango-lesson data file: everything provider-specific, declaratively.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Descriptor {
    /// Map a tool argument to a resource path:
    /// {"arg": "repo", "template": "github:repo:{}"}.
    #[serde(default)]
    pub scopers: Vec<Scoper>,
    /// Per-tool class overrides beating annotations: {"`delete_repo"`: "write"}.
    #[serde(default)]
    pub tool_classes: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scoper {
    pub arg: String,
    pub template: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub seq: i64,
    pub id: String,
    pub at: i64,
    pub kind: String,
    pub agent: String,
    pub project: String,
    pub detail: Value,
    pub prev_hash: String,
    pub hash: String,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, StateError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agents (
                token_hash TEXT PRIMARY KEY,
                agent TEXT NOT NULL,
                project TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE(agent, project)
            );
            CREATE TABLE IF NOT EXISTS servers (
                name TEXT PRIMARY KEY,
                config TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
                id TEXT PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS denies (
                id TEXT PRIMARY KEY,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS postures (
                project TEXT PRIMARY KEY,
                posture TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL,
                at INTEGER NOT NULL,
                kind TEXT NOT NULL,
                agent TEXT NOT NULL,
                project TEXT NOT NULL,
                detail TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );",
        )?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ---- agents ----

    pub fn insert_agent(
        &self,
        token_hash: &str,
        agent: &str,
        project: &str,
        now: i64,
    ) -> Result<(), StateError> {
        self.conn().execute(
            "INSERT INTO agents (token_hash, agent, project, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent, project) DO UPDATE SET token_hash = ?1",
            params![token_hash, agent, project, now],
        )?;
        Ok(())
    }

    pub fn agent_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, String)>, StateError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT agent, project FROM agents WHERE token_hash = ?1")?;
        let mut rows = stmt.query([token_hash])?;
        match rows.next()? {
            Some(r) => Ok(Some((r.get(0)?, r.get(1)?))),
            None => Ok(None),
        }
    }

    pub fn list_agents(&self) -> Result<Vec<AgentRow>, StateError> {
        let conn = self.conn();
        let mut stmt =
            conn.prepare("SELECT agent, project, created_at FROM agents ORDER BY project, agent")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(AgentRow { agent: r.get(0)?, project: r.get(1)?, created_at: r.get(2)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    // ---- servers ----

    pub fn upsert_server(&self, row: &ServerRow) -> Result<(), StateError> {
        let config = serde_json::to_string(row).map_err(|e| StateError::Corrupt(e.to_string()))?;
        self.conn().execute(
            "INSERT INTO servers (name, config) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET config = ?2",
            params![row.name, config],
        )?;
        Ok(())
    }

    pub fn server(&self, name: &str) -> Result<Option<ServerRow>, StateError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT config FROM servers WHERE name = ?1")?;
        let mut rows = stmt.query([name])?;
        match rows.next()? {
            Some(r) => {
                let config: String = r.get(0)?;
                Ok(Some(
                    serde_json::from_str(&config)
                        .map_err(|e| StateError::Corrupt(e.to_string()))?,
                ))
            }
            None => Ok(None),
        }
    }

    pub fn list_servers(&self) -> Result<Vec<ServerRow>, StateError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT config FROM servers ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<String>, _>>()?;
        rows.into_iter()
            .map(|c| serde_json::from_str(&c).map_err(|e| StateError::Corrupt(e.to_string())))
            .collect()
    }

    // ---- policy persistence (write-through mirror of PolicyState) ----

    pub fn load_policy(&self) -> Result<PolicyState, StateError> {
        let mut state = PolicyState::default();
        let conn = self.conn();
        {
            let mut stmt = conn.prepare("SELECT body FROM grants")?;
            for body in stmt.query_map([], |r| r.get::<_, String>(0))? {
                let g: Grant = serde_json::from_str(&body?)
                    .map_err(|e| StateError::Corrupt(e.to_string()))?;
                state.grants.insert(g.id.clone(), g);
            }
        }
        {
            let mut stmt = conn.prepare("SELECT body FROM denies")?;
            for body in stmt.query_map([], |r| r.get::<_, String>(0))? {
                let d: DenyRule = serde_json::from_str(&body?)
                    .map_err(|e| StateError::Corrupt(e.to_string()))?;
                state.denies.insert(d.id.clone(), d);
            }
        }
        Ok(state)
    }

    /// Persist one mutation. Callers apply the same mutation to their
    /// in-memory `PolicyState`; this keeps disk in lockstep.
    pub fn persist_mutation(&self, m: &Mutation) -> Result<(), StateError> {
        let conn = self.conn();
        match m {
            Mutation::AddGrant(g) => {
                let body =
                    serde_json::to_string(g).map_err(|e| StateError::Corrupt(e.to_string()))?;
                conn.execute(
                    "INSERT INTO grants (id, body) VALUES (?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET body = ?2",
                    params![g.id, body],
                )?;
            }
            Mutation::AddDeny(d) => {
                let body =
                    serde_json::to_string(d).map_err(|e| StateError::Corrupt(e.to_string()))?;
                conn.execute(
                    "INSERT INTO denies (id, body) VALUES (?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET body = ?2",
                    params![d.id, body],
                )?;
            }
            Mutation::RevokeGrant { grant_id } => {
                conn.execute("DELETE FROM grants WHERE id = ?1", [grant_id])?;
            }
            Mutation::RemoveDeny { deny_id } => {
                conn.execute("DELETE FROM denies WHERE id = ?1", [deny_id])?;
            }
            Mutation::ConsumeUse { grant_id } => {
                // Recompute from the in-memory state is racy; instead decrement
                // in SQL mirroring PolicyState::apply's saturating semantics.
                let body: Option<String> = {
                    let mut stmt = conn.prepare("SELECT body FROM grants WHERE id = ?1")?;
                    let mut rows = stmt.query([grant_id])?;
                    match rows.next()? {
                        Some(r) => Some(r.get(0)?),
                        None => None,
                    }
                };
                if let Some(body) = body {
                    let mut g: Grant = serde_json::from_str(&body)
                        .map_err(|e| StateError::Corrupt(e.to_string()))?;
                    if let Some(n) = g.uses_left.as_mut() {
                        *n = n.saturating_sub(1);
                        if *n == 0 {
                            conn.execute("DELETE FROM grants WHERE id = ?1", [grant_id])?;
                            return Ok(());
                        }
                    }
                    let body = serde_json::to_string(&g)
                        .map_err(|e| StateError::Corrupt(e.to_string()))?;
                    conn.execute("UPDATE grants SET body = ?2 WHERE id = ?1", params![grant_id, body])?;
                }
            }
        }
        Ok(())
    }

    // ---- postures ----

    pub fn set_posture(&self, project: &str, posture: Posture) -> Result<(), StateError> {
        self.conn().execute(
            "INSERT INTO postures (project, posture) VALUES (?1, ?2)
             ON CONFLICT(project) DO UPDATE SET posture = ?2",
            params![project, posture.as_str()],
        )?;
        Ok(())
    }

    pub fn posture(&self, project: &str) -> Result<Posture, StateError> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT posture FROM postures WHERE project = ?1")?;
        let mut rows = stmt.query([project])?;
        match rows.next()? {
            Some(r) => {
                let s: String = r.get(0)?;
                Ok(Posture::parse(&s).unwrap_or(Posture::Standard))
            }
            None => Ok(Posture::Standard),
        }
    }

    // ---- receipts (INV-D2, INV-D3) ----

    /// Append a receipt, chaining its hash to the previous one.
    pub fn append_receipt(
        &self,
        id: &str,
        at: i64,
        kind: &str,
        agent: &str,
        project: &str,
        detail: &Value,
    ) -> Result<Receipt, StateError> {
        let conn = self.conn();
        let prev_hash: String = conn
            .query_row("SELECT hash FROM receipts ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .unwrap_or_else(|_| "0".repeat(64));
        let detail_str =
            serde_json::to_string(detail).map_err(|e| StateError::Corrupt(e.to_string()))?;
        let hash = receipt_hash(&prev_hash, id, at, kind, agent, project, &detail_str);
        conn.execute(
            "INSERT INTO receipts (id, at, kind, agent, project, detail, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id, at, kind, agent, project, detail_str, prev_hash, hash],
        )?;
        let seq = conn.last_insert_rowid();
        Ok(Receipt {
            seq,
            id: id.to_string(),
            at,
            kind: kind.to_string(),
            agent: agent.to_string(),
            project: project.to_string(),
            detail: detail.clone(),
            prev_hash,
            hash,
        })
    }

    pub fn receipts(&self, limit: Option<i64>) -> Result<Vec<Receipt>, StateError> {
        let conn = self.conn();
        let sql = match limit {
            Some(_) => {
                "SELECT seq, id, at, kind, agent, project, detail, prev_hash, hash
                 FROM receipts ORDER BY seq DESC LIMIT ?1"
            }
            None => {
                "SELECT seq, id, at, kind, agent, project, detail, prev_hash, hash
                 FROM receipts ORDER BY seq ASC"
            }
        };
        let mut stmt = conn.prepare(sql)?;
        let map = |r: &rusqlite::Row<'_>| {
            let detail: String = r.get(6)?;
            Ok(Receipt {
                seq: r.get(0)?,
                id: r.get(1)?,
                at: r.get(2)?,
                kind: r.get(3)?,
                agent: r.get(4)?,
                project: r.get(5)?,
                detail: serde_json::from_str(&detail).unwrap_or(Value::Null),
                prev_hash: r.get(7)?,
                hash: r.get(8)?,
            })
        };
        let rows = match limit {
            Some(n) => stmt.query_map([n], map)?.collect::<Result<Vec<_>, _>>()?,
            None => stmt.query_map([], map)?.collect::<Result<Vec<_>, _>>()?,
        };
        Ok(rows)
    }

    /// Walk the whole chain; return the first broken seq, if any (INV-D3).
    pub fn verify_chain(&self) -> Result<Option<i64>, StateError> {
        let all = self.receipts(None)?;
        let mut prev = "0".repeat(64);
        for r in &all {
            let detail_str = serde_json::to_string(&r.detail)
                .map_err(|e| StateError::Corrupt(e.to_string()))?;
            let expect =
                receipt_hash(&prev, &r.id, r.at, &r.kind, &r.agent, &r.project, &detail_str);
            if r.prev_hash != prev || r.hash != expect {
                return Ok(Some(r.seq));
            }
            prev.clone_from(&r.hash);
        }
        Ok(None)
    }
}

fn receipt_hash(
    prev: &str,
    id: &str,
    at: i64,
    kind: &str,
    agent: &str,
    project: &str,
    detail: &str,
) -> String {
    let mut h = Sha256::new();
    for part in [prev, id, &at.to_string(), kind, agent, project, detail] {
        h.update(part.as_bytes());
        h.update([0x1f]); // unit separator: unambiguous field boundaries
    }
    hex(&h.finalize())
}

#[must_use] 
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[must_use] 
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

#[must_use] 
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[must_use] 
pub fn random_id(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    format!("{prefix}_{}", hex(&bytes))
}
