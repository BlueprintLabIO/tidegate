//! The gateway: every agent tool call passes through here, exactly once,
//! and terminates in exactly one of executed-with-receipt,
//! denied-with-reason, or pending-with-id (INV-U2).

use crate::notify;
use crate::state::{random_id, sha256_hex, unix_now, Db, ServerRow, StateError};
use crate::upstream::{Upstream, UpstreamError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::Duration;
use tidegate_policy::{
    decide, ApprovalChannel, ApprovalEvent, AgentKey, Decision, DenyRule, Mutation, PolicyState,
    Scope, ToolClass,
};
use tidegate_vault::Vault;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
    #[error("vault: {0}")]
    Vault(String),
    #[error("unknown server {0:?} — run `tidegate connect {0}` first")]
    UnknownServer(String),
    #[error("tool name {0:?} is not namespaced as <server>.<tool>")]
    BadToolName(String),
    #[error("no pending approval {0:?}")]
    UnknownPending(String),
    #[error("approval credential rejected")]
    BadCredential,
    #[error("invalid scope produced by descriptor: {0}")]
    BadScope(String),
}

/// Outcome of one gated call — the three terminal shapes of INV-U2.
#[derive(Debug)]
pub enum CallOutcome {
    /// Upstream result, passed through verbatim.
    Allowed { result: Value, receipt_id: String },
    Denied { reason: String, receipt_id: String },
    Pending {
        id: String,
        /// One-time secret for in-session elicitation resolution. Present
        /// only when the caller declared the client capability; held in shim
        /// memory, never in any tool result (THREAT_MODEL.md).
        elicit_secret: Option<String>,
        message_for_model: String,
    },
}

/// How a resolver proves human presence.
pub enum ResolveCredential {
    /// Confirmation code that traveled a human channel (notification,
    /// dashboard). Required for CLI resolution.
    Code(String),
    /// One-time elicitation secret returned to the shim.
    ElicitSecret(String),
    /// The dashboard session key (the dashboard itself is key-gated).
    DashboardKey(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    AllowOnce,
    AllowAlways,
    DenyOnce,
    DenyAlways,
}

impl Answer {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow_once" => Some(Answer::AllowOnce),
            "allow_always" => Some(Answer::AllowAlways),
            "deny_once" => Some(Answer::DenyOnce),
            "deny_always" => Some(Answer::DenyAlways),
            _ => None,
        }
    }
}

struct Pending {
    id: String,
    agent: AgentKey,
    tool: String,
    class: ToolClass,
    resource: Scope,
    code_hash: String,
    elicit_hash: Option<String>,
    created_at: i64,
    resolution: Option<Answer>,
}

pub struct Gateway {
    pub db: Db,
    vault: Vault,
    policy: Mutex<PolicyState>,
    upstreams: Mutex<HashMap<String, Upstream>>,
    pendings: Mutex<HashMap<String, Pending>>,
    resolved: Condvar,
    dash_key_hash: String,
}

impl Gateway {
    pub fn new(db: Db, vault: Vault, dash_key: &str) -> Result<Self, GatewayError> {
        let policy = db.load_policy()?;
        Ok(Gateway {
            db,
            vault,
            policy: Mutex::new(policy),
            upstreams: Mutex::new(HashMap::new()),
            pendings: Mutex::new(HashMap::new()),
            resolved: Condvar::new(),
            dash_key_hash: sha256_hex(dash_key),
        })
    }

    fn lock_policy(&self) -> std::sync::MutexGuard<'_, PolicyState> {
        self.policy.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply + persist a policy mutation atomically enough for one process:
    /// memory first (source of truth for decisions), then disk.
    fn mutate(&self, m: Mutation) -> Result<(), GatewayError> {
        self.db.persist_mutation(&m)?;
        self.lock_policy().apply(m);
        Ok(())
    }

    // ---- the main path ----

    /// Gate one tool call from an authenticated agent.
    pub fn handle_call(
        &self,
        agent: AgentKey,
        tool_fq: &str,
        arguments: Value,
        elicit_ok: bool,
        wait: Duration,
    ) -> Result<CallOutcome, GatewayError> {
        let (server_name, tool) = tool_fq
            .split_once('.')
            .ok_or_else(|| GatewayError::BadToolName(tool_fq.to_string()))?;
        let server = self
            .db
            .server(server_name)?
            .ok_or_else(|| GatewayError::UnknownServer(server_name.to_string()))?;

        self.ensure_upstream(&server)?;
        let class = self.classify(&server, tool)?;
        let resource = self.resource_for(&server, tool, &arguments)?;

        let req = tidegate_policy::Request {
            agent: agent.clone(),
            tool: tool_fq.to_string(),
            class,
            resource: resource.clone(),
        };
        let decision = { decide(&req, &self.lock_policy(), unix_now()) };

        match decision {
            Decision::Allow { grant_id } => {
                // INV-D2: the receipt opens before the upstream call.
                let receipt_id = random_id("rcp");
                let started = unix_now();
                let result = self.call_upstream(server_name, tool, arguments.clone());
                let ok = result.is_ok();
                self.db.append_receipt(
                    &receipt_id,
                    started,
                    "call",
                    &agent.agent,
                    &agent.project,
                    &json!({
                        "tool": tool_fq,
                        "resource": resource.as_str(),
                        "verdict": "allow",
                        "grant": grant_id,
                        "ok": ok,
                    }),
                )?;
                // One-shot grants burn on use.
                let consume = {
                    let p = self.lock_policy();
                    p.grants.get(&grant_id).and_then(|g| g.uses_left).is_some()
                };
                if consume {
                    self.mutate(Mutation::ConsumeUse { grant_id })?;
                }
                match result {
                    Ok(v) => Ok(CallOutcome::Allowed { result: v, receipt_id }),
                    Err(e) => Ok(CallOutcome::Denied {
                        reason: format!("upstream error: {e}"),
                        receipt_id,
                    }),
                }
            }
            Decision::Deny { rule_id } => {
                let receipt_id = random_id("rcp");
                self.db.append_receipt(
                    &receipt_id,
                    unix_now(),
                    "deny",
                    &agent.agent,
                    &agent.project,
                    &json!({
                        "tool": tool_fq,
                        "resource": resource.as_str(),
                        "verdict": "deny",
                        "rule": rule_id,
                    }),
                )?;
                Ok(CallOutcome::Denied {
                    reason: format!(
                        "denied by standing rule for {tool_fq} on {}. The user can lift this in \
                         the tidegate dashboard.",
                        resource.as_str()
                    ),
                    receipt_id,
                })
            }
            Decision::Ask => self.create_pending(agent, tool_fq, class, resource, elicit_ok, wait),
        }
    }

    fn create_pending(
        &self,
        agent: AgentKey,
        tool_fq: &str,
        class: ToolClass,
        resource: Scope,
        elicit_ok: bool,
        wait: Duration,
    ) -> Result<CallOutcome, GatewayError> {
        let id = random_id("apr");
        let code = format!("{:04}", rand::Rng::gen_range(&mut rand::thread_rng(), 0..10_000u32));
        let elicit_secret = elicit_ok.then(|| random_id("els"));
        let pending = Pending {
            id: id.clone(),
            agent: agent.clone(),
            tool: tool_fq.to_string(),
            class,
            resource: resource.clone(),
            code_hash: sha256_hex(&code),
            elicit_hash: elicit_secret.as_deref().map(sha256_hex),
            created_at: unix_now(),
            resolution: None,
        };
        self.pendings.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), pending);
        self.db.append_receipt(
            &id,
            unix_now(),
            "ask",
            &agent.agent,
            &agent.project,
            &json!({ "tool": tool_fq, "resource": resource.as_str() }),
        )?;

        // The confirmation code travels human channels only: notification +
        // dashboard. Never the return value the model reads.
        if !elicit_ok {
            notify::send(
                "Tidegate approval",
                &format!(
                    "{} wants {} on {} — code {}. Approve: tidegate approve {} --code {} (or dashboard)",
                    agent.agent, tool_fq, resource.as_str(), code, id, code
                ),
            );
            // Give the human `wait` to answer via notification/dashboard.
            let deadline = std::time::Instant::now() + wait;
            let mut guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if guard.get(&id).and_then(|p| p.resolution).is_some() {
                    break;
                }
                let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now())
                else {
                    break;
                };
                let (g, _timeout) = self
                    .resolved
                    .wait_timeout(guard, remaining)
                    .unwrap_or_else(|e| e.into_inner());
                guard = g;
            }
            if let Some(answer) = guard.get(&id).and_then(|p| p.resolution) {
                drop(guard);
                return self.after_resolution(&id, answer);
            }
        } else {
            // Elicitation path: the dashboard still lists it, so also record
            // the code there (dashboard reads pendings live); no OS noise.
        }

        Ok(CallOutcome::Pending {
            id: id.clone(),
            elicit_secret,
            message_for_model: format!(
                "approval_pending id={id}: the user must approve {tool_fq} on {}. They have been \
                 notified (tidegate dashboard also lists it). Retry this exact tool call after \
                 they approve; do not attempt to approve it yourself.",
                resource.as_str()
            ),
        })
    }

    /// Resolve a pending approval with proof of human presence.
    pub fn resolve(
        &self,
        pending_id: &str,
        credential: ResolveCredential,
        answer: Answer,
    ) -> Result<(), GatewayError> {
        let channel = {
            let guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
            let p = guard.get(pending_id).ok_or_else(|| {
                GatewayError::UnknownPending(pending_id.to_string())
            })?;
            match &credential {
                ResolveCredential::Code(c) => {
                    if sha256_hex(c) != p.code_hash {
                        return Err(GatewayError::BadCredential);
                    }
                    ApprovalChannel::ConfirmationCode
                }
                ResolveCredential::ElicitSecret(s) => {
                    if p.elicit_hash.as_deref() != Some(sha256_hex(s).as_str()) {
                        return Err(GatewayError::BadCredential);
                    }
                    ApprovalChannel::Elicitation
                }
                ResolveCredential::DashboardKey(k) => {
                    if sha256_hex(k) != self.dash_key_hash {
                        return Err(GatewayError::BadCredential);
                    }
                    ApprovalChannel::Dashboard
                }
            }
        };

        // Widening happens here — and only here — carrying the approval event.
        let (agent, tool, class, resource) = {
            let mut guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
            let p = guard
                .get_mut(pending_id)
                .ok_or_else(|| GatewayError::UnknownPending(pending_id.to_string()))?;
            p.resolution = Some(answer);
            (p.agent.clone(), p.tool.clone(), p.class, p.resource.clone())
        };

        let approval =
            ApprovalEvent { id: pending_id.to_string(), at: unix_now(), channel };
        match answer {
            Answer::AllowOnce => {
                self.mutate(Mutation::add_grant(
                    random_id("gr"),
                    agent.clone(),
                    class,
                    resource.clone(),
                    Some(unix_now() + 300),
                    Some(1),
                    approval.clone(),
                ))?;
            }
            Answer::AllowAlways => {
                self.mutate(Mutation::add_grant(
                    random_id("gr"),
                    agent.clone(),
                    class,
                    resource.clone(),
                    None,
                    None,
                    approval.clone(),
                ))?;
            }
            Answer::DenyOnce => {}
            Answer::DenyAlways => {
                self.mutate(Mutation::AddDeny(DenyRule {
                    id: random_id("dr"),
                    agent: agent.clone(),
                    class,
                    scope: resource.clone(),
                    tool: Some(tool.clone()),
                }))?;
            }
        }
        self.db.append_receipt(
            &random_id("rcp"),
            unix_now(),
            "approval",
            &agent.agent,
            &agent.project,
            &json!({
                "pending": pending_id,
                "tool": tool,
                "resource": resource.as_str(),
                "answer": format!("{answer:?}"),
                "channel": format!("{:?}", approval.channel),
            }),
        )?;
        self.resolved.notify_all();
        Ok(())
    }

    fn after_resolution(&self, id: &str, answer: Answer) -> Result<CallOutcome, GatewayError> {
        // The grant/deny is already applied; tell the caller to retry so the
        // call flows through the normal (receipted) allow path.
        match answer {
            Answer::AllowOnce | Answer::AllowAlways => Ok(CallOutcome::Pending {
                id: id.to_string(),
                elicit_secret: None,
                message_for_model: "approved: the user granted this. Retry the exact same tool \
                                    call now; it will go through."
                    .to_string(),
            }),
            Answer::DenyOnce | Answer::DenyAlways => Ok(CallOutcome::Denied {
                reason: "the user denied this request".to_string(),
                receipt_id: id.to_string(),
            }),
        }
    }

    /// Pending approvals for the dashboard/CLI. Codes are exposed ONLY to
    /// the dashboard (key-gated); the CLI list omits them by design — the
    /// code must reach the human through a channel the agent does not read.
    pub fn pending_list(&self, include_codes_with_dash_key: Option<&str>) -> Vec<Value> {
        let with_codes = include_codes_with_dash_key
            .map(|k| sha256_hex(k) == self.dash_key_hash)
            .unwrap_or(false);
        let guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
        let mut rows: Vec<&Pending> =
            guard.values().filter(|p| p.resolution.is_none()).collect();
        rows.sort_by_key(|p| p.created_at);
        rows.iter()
            .map(|p| {
                let mut v = json!({
                    "id": p.id,
                    "agent": p.agent.agent,
                    "project": p.agent.project,
                    "tool": p.tool,
                    "class": format!("{:?}", p.class).to_lowercase(),
                    "resource": p.resource.as_str(),
                    "created_at": p.created_at,
                });
                if with_codes {
                    // The dashboard resolves with its own key; codes are for
                    // the human to relay to the CLI. Stored hashed, so the
                    // dashboard shows the hash prefix as a hint only when the
                    // original is unavailable — see note in http.rs.
                    v["code_hash"] = json!(p.code_hash);
                }
                v
            })
            .collect()
    }

    // ---- upstream plumbing ----

    fn ensure_upstream(&self, server: &ServerRow) -> Result<(), GatewayError> {
        let mut ups = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(up) = ups.get_mut(&server.name) {
            if up.is_alive() {
                return Ok(());
            }
            ups.remove(&server.name);
        }
        // Inject credentials: vault secret -> env var. The upstream server
        // process sees the secret; the agent never does (THREAT_MODEL.md).
        let mut envs: HashMap<String, String> = HashMap::new();
        for (secret_name, env_var) in &server.secret_env {
            let value = self
                .vault
                .with_secret(secret_name, |b| String::from_utf8_lossy(b).to_string())
                .map_err(|e| GatewayError::Vault(e.to_string()))?;
            envs.insert(env_var.clone(), value);
        }
        let up = Upstream::spawn(&server.name, &server.command, &server.args, &envs)?;
        ups.insert(server.name.clone(), up);
        Ok(())
    }

    fn call_upstream(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, UpstreamError> {
        let ups = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        let up = ups.get(server).ok_or_else(|| UpstreamError::Closed(server.to_string()))?;
        up.call_tool(tool, arguments)
    }

    /// Proxied tool list for one server, names fully qualified.
    pub fn tools_for(&self, server: &ServerRow) -> Result<Vec<Value>, GatewayError> {
        self.ensure_upstream(server)?;
        let ups = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        let up = ups
            .get(&server.name)
            .ok_or_else(|| UpstreamError::Closed(server.name.clone()))?;
        let tools = up.tools()?;
        Ok(tools
            .iter()
            .map(|t| {
                json!({
                    "name": format!("{}.{}", server.name, t.name),
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "annotations": { "readOnlyHint": t.read_only_hint },
                })
            })
            .collect())
    }

    /// Read class: descriptor override first, then MCP annotation, then the
    /// deny-by-default of trust: unknown = Write.
    fn classify(&self, server: &ServerRow, tool: &str) -> Result<ToolClass, GatewayError> {
        if let Some(c) = server.descriptor.tool_classes.get(tool) {
            return Ok(if c == "read" { ToolClass::Read } else { ToolClass::Write });
        }
        let ups = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(up) = ups.get(&server.name) {
            if let Ok(tools) = up.tools() {
                if let Some(t) = tools.iter().find(|t| t.name == tool) {
                    return Ok(match t.read_only_hint {
                        Some(true) => ToolClass::Read,
                        _ => ToolClass::Write,
                    });
                }
            }
        }
        Ok(ToolClass::Write)
    }

    /// Resource path: first matching descriptor scoper wins; otherwise the
    /// whole-server scope. Values containing the scope separator are
    /// rejected rather than reinterpreted.
    fn resource_for(
        &self,
        server: &ServerRow,
        _tool: &str,
        arguments: &Value,
    ) -> Result<Scope, GatewayError> {
        for scoper in &server.descriptor.scopers {
            if let Some(raw) = arguments.get(&scoper.arg).and_then(Value::as_str) {
                if raw.contains(':') {
                    return Err(GatewayError::BadScope(raw.to_string()));
                }
                let path = scoper.template.replace("{}", raw);
                return Scope::parse(&path).map_err(|e| GatewayError::BadScope(e.to_string()));
            }
        }
        Scope::whole_server(&server.name).map_err(|e| GatewayError::BadScope(e.to_string()))
    }

    // ---- admin (CLI) surface ----

    /// Narrowing-only admin mutations (INV-C1's server-side enforcement):
    /// widening mutations are rejected here regardless of caller identity.
    pub fn admin_narrow(&self, m: Mutation) -> Result<(), GatewayError> {
        assert!(!m.is_widening(), "admin_narrow called with widening mutation — daemon bug");
        self.mutate(m)
    }

    /// A posture-widening request enters the same pending/approval pipeline
    /// as any tool call.
    pub fn request_posture(
        &self,
        agent: AgentKey,
        posture: tidegate_policy::Posture,
        scope: Scope,
    ) -> Result<(String, String), GatewayError> {
        let id = random_id("apr");
        let code = format!("{:04}", rand::Rng::gen_range(&mut rand::thread_rng(), 0..10_000u32));
        // Reuse the pending mechanism with a synthetic tool name; resolution
        // applies compiled posture grants.
        let pending = Pending {
            id: id.clone(),
            agent: agent.clone(),
            tool: format!("posture.{}", posture.as_str()),
            class: ToolClass::Write,
            resource: scope.clone(),
            code_hash: sha256_hex(&code),
            elicit_hash: None,
            created_at: unix_now(),
            resolution: None,
        };
        self.pendings.lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), pending);
        notify::send(
            "Tidegate posture change",
            &format!(
                "{} requests posture {} on {} — code {}. Confirm: tidegate approve {} --code {}",
                agent.agent, posture.as_str(), scope.as_str(), code, id, code
            ),
        );
        Ok((id, code))
    }

    /// Resolve a posture request: compiles the posture into grants under the
    /// approval event. (`resolve` handles tool pendings; posture pendings
    /// route here from the HTTP layer based on the tool prefix.)
    pub fn resolve_posture(
        &self,
        pending_id: &str,
        credential: ResolveCredential,
    ) -> Result<(), GatewayError> {
        let (agent, resource, posture_name) = {
            let guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
            let p = guard.get(pending_id).ok_or_else(|| {
                GatewayError::UnknownPending(pending_id.to_string())
            })?;
            let ok = match &credential {
                ResolveCredential::Code(c) => sha256_hex(c) == p.code_hash,
                ResolveCredential::DashboardKey(k) => sha256_hex(k) == self.dash_key_hash,
                ResolveCredential::ElicitSecret(_) => false,
            };
            if !ok {
                return Err(GatewayError::BadCredential);
            }
            let posture_name = p
                .tool
                .strip_prefix("posture.")
                .ok_or_else(|| GatewayError::UnknownPending(pending_id.to_string()))?
                .to_string();
            (p.agent.clone(), p.resource.clone(), posture_name)
        };
        let posture = tidegate_policy::Posture::parse(&posture_name)
            .ok_or_else(|| GatewayError::UnknownPending(pending_id.to_string()))?;
        let approval = ApprovalEvent {
            id: pending_id.to_string(),
            at: unix_now(),
            channel: match credential {
                ResolveCredential::Code(_) => ApprovalChannel::ConfirmationCode,
                _ => ApprovalChannel::Dashboard,
            },
        };
        for m in tidegate_policy::compile_posture(posture, &agent, &resource, &approval, || {
            random_id("gr")
        }) {
            self.mutate(m)?;
        }
        self.db.set_posture(&agent.project, posture)?;
        {
            let mut guard = self.pendings.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = guard.get_mut(pending_id) {
                p.resolution = Some(Answer::AllowAlways);
            }
        }
        self.db.append_receipt(
            &random_id("rcp"),
            unix_now(),
            "posture",
            &agent.agent,
            &agent.project,
            &json!({ "posture": posture.as_str(), "scope": resource.as_str() }),
        )?;
        self.resolved.notify_all();
        Ok(())
    }
}
