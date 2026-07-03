//! Tidegate's policy engine.
//!
//! Pure and IO-free by construction: the only dependency is `serde`, and the
//! public entry point [`decide`] is a function of (request, state, now).
//! The invariants this crate must keep live in `docs/invariants.md` (INV-P1
//! through INV-P7); every one of them is pinned by a property test in
//! `tests/`.
//!
//! Two ideas carry all the weight:
//!
//! 1. **Grants are the only source of allowance.** There is no posture flag,
//!    no mode branch, no bypass path in [`decide`]. Postures compile to
//!    ordinary grants via [`compile_posture`] (INV-P5).
//! 2. **Widening demands proof of a human.** The constructors of widening
//!    [`Mutation`]s require an [`ApprovalEvent`]; narrowing constructors do
//!    not. The type system carries INV-P4.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod scope;
pub use scope::Scope;

/// A stable identity for one agent wired into one project.
/// Attribution, not authentication — see `THREAT_MODEL.md`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AgentKey {
    /// Agent kind, e.g. "claude", "codex", "cursor".
    pub agent: String,
    /// Canonicalized absolute project path.
    pub project: String,
}

/// Risk class of a tool. Reads settle to standing allows; writes ask.
/// Classification comes from MCP tool annotations (`readOnlyHint`) with
/// unknown tools defaulting to `Write` — deny-by-default extends to
/// trust-by-default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ToolClass {
    Read,
    Write,
}

/// Proof that a human was present for a widening decision.
/// The daemon mints these only from human channels (dashboard click,
/// confirmation code, MCP elicitation answer). The engine never mints one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalEvent {
    pub id: String,
    /// Unix seconds.
    pub at: i64,
    pub channel: ApprovalChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalChannel {
    /// One-click in the local dashboard.
    Dashboard,
    /// `tidegate approve <id> --code <code>` where the code traveled a human
    /// channel (notification / dashboard), never the agent channel.
    ConfirmationCode,
    /// MCP elicitation answered in the agent client's own UI, resolved with a
    /// one-time secret held only in shim memory.
    Elicitation,
    /// Interactive first-run setup (e.g. posture chosen during `install`).
    Setup,
}

/// A standing permission. The only thing that ever produces `Allow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub agent: AgentKey,
    pub class: ToolClass,
    pub scope: Scope,
    /// Unix seconds; `None` = standing until revoked.
    pub expires_at: Option<i64>,
    /// `Some(n)` = usable n more times (one-shot approvals); `None` = unlimited.
    pub uses_left: Option<u32>,
    /// The human-presence event that created this grant (INV-P4).
    pub approval: ApprovalEvent,
}

/// A remembered "no". Deny rules beat grants (an explicit no is stronger
/// than a standing yes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyRule {
    pub id: String,
    pub agent: AgentKey,
    /// `None` = the whole class; `Some(tool)` = one tool.
    pub tool: Option<String>,
    pub class: ToolClass,
    pub scope: Scope,
}

/// One inbound tool call, reduced to what policy needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub agent: AgentKey,
    /// Fully-qualified tool name, e.g. "`github.create_pr`".
    pub tool: String,
    pub class: ToolClass,
    /// The concrete resource this call touches, e.g.
    /// `github:repo:BlueprintLabIO/tidegate`. Always a leaf-ish path;
    /// grants may sit anywhere above it in the lattice.
    pub resource: Scope,
}

/// The three verdicts, and only three (docs/permissions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    /// Allowed under this grant id.
    Allow { grant_id: String },
    /// No standing answer: route to the human channels.
    Ask,
    /// An explicit deny rule matched.
    Deny { rule_id: String },
}

impl Decision {
    /// Permissiveness ordering used by the monotonicity invariants:
    /// Deny(0) < Ask(1) < Allow(2).
    #[must_use] 
    pub fn rank(&self) -> u8 {
        match self {
            Decision::Deny { .. } => 0,
            Decision::Ask => 1,
            Decision::Allow { .. } => 2,
        }
    }
}

/// The engine's entire mutable world. Owned and persisted by the daemon;
/// mutated only through [`PolicyState::apply`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyState {
    pub grants: BTreeMap<String, Grant>,
    pub denies: BTreeMap<String, DenyRule>,
}

/// State mutations. Widening variants can only be constructed through
/// functions that demand an [`ApprovalEvent`] — INV-P4's type-level half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mutation {
    AddGrant(Grant),
    AddDeny(DenyRule),
    RevokeGrant { grant_id: String },
    RemoveDeny { deny_id: String },
    /// Consume one use of a limited grant (bookkeeping, not widening).
    ConsumeUse { grant_id: String },
}

impl Mutation {
    /// The only way to obtain a grant-adding mutation.
    #[must_use] 
    pub fn add_grant(
        id: String,
        agent: AgentKey,
        class: ToolClass,
        scope: Scope,
        expires_at: Option<i64>,
        uses_left: Option<u32>,
        approval: ApprovalEvent,
    ) -> Self {
        Mutation::AddGrant(Grant { id, agent, class, scope, expires_at, uses_left, approval })
    }

    /// Removing a deny rule re-widens whatever the rule was masking, so it
    /// demands an approval event too. The event is recorded by the caller's
    /// audit log; the type signature is what enforces presence.
    #[must_use] 
    pub fn remove_deny(deny_id: String, _approval: ApprovalEvent) -> Self {
        Mutation::RemoveDeny { deny_id }
    }

    /// True if applying this mutation can increase any decision's rank.
    #[must_use] 
    pub fn is_widening(&self) -> bool {
        matches!(self, Mutation::AddGrant(_) | Mutation::RemoveDeny { .. })
    }
}

impl PolicyState {
    pub fn apply(&mut self, m: Mutation) {
        match m {
            Mutation::AddGrant(g) => {
                self.grants.insert(g.id.clone(), g);
            }
            Mutation::AddDeny(d) => {
                self.denies.insert(d.id.clone(), d);
            }
            Mutation::RevokeGrant { grant_id } => {
                self.grants.remove(&grant_id);
            }
            Mutation::RemoveDeny { deny_id } => {
                self.denies.remove(&deny_id);
            }
            Mutation::ConsumeUse { grant_id } => {
                let mut spent = false;
                if let Some(g) = self.grants.get_mut(&grant_id) {
                    if let Some(n) = g.uses_left.as_mut() {
                        *n = n.saturating_sub(1);
                        spent = *n == 0;
                    }
                }
                if spent {
                    self.grants.remove(&grant_id);
                }
            }
        }
    }
}

impl Grant {
    /// Is this grant live at `now` with uses remaining?
    #[must_use] 
    pub fn live(&self, now: i64) -> bool {
        let unexpired = match self.expires_at {
            // INV-P3: expiry is total — the boundary instant is already dead.
            Some(t) => now < t,
            None => true,
        };
        let has_uses = self.uses_left.is_none_or(|n| n > 0);
        unexpired && has_uses
    }

    /// Does this grant cover the request? Class must match exactly; the
    /// requested resource must sit at or below the grant's scope (INV-P6).
    #[must_use] 
    pub fn covers(&self, req: &Request) -> bool {
        self.agent == req.agent && self.class == req.class && self.scope.covers(&req.resource)
    }
}

impl DenyRule {
    #[must_use] 
    pub fn covers(&self, req: &Request) -> bool {
        let tool_match = match &self.tool {
            Some(t) => t == &req.tool,
            None => true,
        };
        self.agent == req.agent
            && self.class == req.class
            && tool_match
            && self.scope.covers(&req.resource)
    }
}

/// The decision function. Pure: same (request, state, now) → same decision
/// (INV-P7). Deny rules are checked before grants — an explicit "no" always
/// beats a standing "yes". With neither, the answer is Ask, never Allow
/// (INV-P1).
#[must_use] 
pub fn decide(req: &Request, state: &PolicyState, now: i64) -> Decision {
    if let Some(d) = state.denies.values().find(|d| d.covers(req)) {
        return Decision::Deny { rule_id: d.id.clone() };
    }
    if let Some(g) = state.grants.values().find(|g| g.live(now) && g.covers(req)) {
        return Decision::Allow { grant_id: g.id.clone() };
    }
    Decision::Ask
}

/// Project postures. Not a mode: a macro over grants (INV-P5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Posture {
    /// Everything asks.
    Careful,
    /// Reads flow after connect; writes ask. The default.
    Standard,
    /// Everything flows; receipts and revoke stay on.
    Open,
}

impl Posture {
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::Careful => "careful",
            Posture::Standard => "standard",
            Posture::Open => "open",
        }
    }

    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "careful" => Some(Posture::Careful),
            "standard" => Some(Posture::Standard),
            "open" => Some(Posture::Open),
            _ => None,
        }
    }
}

/// Compile a posture into the grants it means, for one agent over one scope.
/// The returned mutations all carry the caller's approval event: choosing a
/// posture *is* the human approval, executed in bulk.
pub fn compile_posture(
    posture: Posture,
    agent: &AgentKey,
    scope: &Scope,
    approval: &ApprovalEvent,
    mut fresh_id: impl FnMut() -> String,
) -> Vec<Mutation> {
    let classes: &[ToolClass] = match posture {
        Posture::Careful => &[],
        Posture::Standard => &[ToolClass::Read],
        Posture::Open => &[ToolClass::Read, ToolClass::Write],
    };
    classes
        .iter()
        .map(|class| {
            Mutation::add_grant(
                fresh_id(),
                agent.clone(),
                *class,
                scope.clone(),
                None,
                None,
                approval.clone(),
            )
        })
        .collect()
}
