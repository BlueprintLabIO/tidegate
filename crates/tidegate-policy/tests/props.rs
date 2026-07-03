//! Property tests pinning INV-P1..P7 (docs/invariants.md).
//!
//! Strategy: generate small worlds of agents/scopes/grants/denies and arbitrary
//! requests, then assert the invariant over every generated case. Scopes are
//! drawn from a shallow alphabet so that cover/overlap cases actually occur.

use proptest::prelude::*;
use tidegate_policy::{
    compile_posture, decide, ApprovalChannel, ApprovalEvent, AgentKey, Decision, DenyRule, Grant,
    Mutation, PolicyState, Posture, Request, Scope, ToolClass,
};

fn approval() -> ApprovalEvent {
    ApprovalEvent { id: "apr_test".into(), at: 0, channel: ApprovalChannel::Dashboard }
}

fn agent_strategy() -> impl Strategy<Value = AgentKey> {
    (prop_oneof!["claude", "codex"], prop_oneof!["/p/a", "/p/b"])
        .prop_map(|(a, p): (String, String)| AgentKey { agent: a, project: p })
}

fn class_strategy() -> impl Strategy<Value = ToolClass> {
    prop_oneof![Just(ToolClass::Read), Just(ToolClass::Write)]
}

/// Scopes over a tiny alphabet, 1..=3 segments deep.
fn scope_strategy() -> impl Strategy<Value = Scope> {
    proptest::collection::vec(prop_oneof!["mcp", "github", "repo", "o1", "o2", "x"], 1..=3)
        .prop_map(|segs| Scope::from_segments(segs).expect("alphabet is separator-free"))
}

fn grant_strategy() -> impl Strategy<Value = Grant> {
    (
        agent_strategy(),
        class_strategy(),
        scope_strategy(),
        proptest::option::of(0i64..200),
        proptest::option::of(0u32..3),
        "[a-z0-9]{6}",
    )
        .prop_map(|(agent, class, scope, expires_at, uses_left, id)| Grant {
            id,
            agent,
            class,
            scope,
            expires_at,
            uses_left,
            approval: approval(),
        })
}

fn deny_strategy() -> impl Strategy<Value = DenyRule> {
    (
        agent_strategy(),
        class_strategy(),
        scope_strategy(),
        proptest::option::of(prop_oneof!["t.read", "t.write"]),
        "[a-z0-9]{6}",
    )
        .prop_map(|(agent, class, scope, tool, id)| DenyRule {
            id,
            agent,
            class,
            scope,
            tool,
        })
}

fn state_strategy() -> impl Strategy<Value = PolicyState> {
    (
        proptest::collection::vec(grant_strategy(), 0..6),
        proptest::collection::vec(deny_strategy(), 0..4),
    )
        .prop_map(|(grants, denies)| {
            let mut s = PolicyState::default();
            for g in grants {
                s.apply(Mutation::AddGrant(g));
            }
            for d in denies {
                s.apply(Mutation::AddDeny(d));
            }
            s
        })
}

fn request_strategy() -> impl Strategy<Value = Request> {
    (agent_strategy(), class_strategy(), scope_strategy(), prop_oneof!["t.read", "t.write", "t.z"])
        .prop_map(|(agent, class, resource, tool)| Request {
            agent,
            class,
            resource,
            tool,
        })
}

proptest! {
    /// INV-P1: with no grants, the answer is never Allow — and with no deny
    /// rules either, it is exactly Ask.
    #[test]
    fn deny_by_default(req in request_strategy(), now in 0i64..300) {
        let empty = PolicyState::default();
        prop_assert_eq!(decide(&req, &empty, now), Decision::Ask);
    }

    /// INV-P1 (strong form): Allow only ever cites a grant that is live and
    /// covering. No request is allowed by anything else.
    #[test]
    fn allow_implies_live_covering_grant(
        state in state_strategy(),
        req in request_strategy(),
        now in 0i64..300,
    ) {
        if let Decision::Allow { grant_id } = decide(&req, &state, now) {
            let g = state.grants.get(&grant_id).expect("cited grant exists");
            prop_assert!(g.live(now));
            prop_assert!(g.covers(&req));
        }
    }

    /// INV-P2: revoking any grant never increases any decision's rank.
    #[test]
    fn revocation_is_monotonic(
        state in state_strategy(),
        req in request_strategy(),
        now in 0i64..300,
    ) {
        let before = decide(&req, &state, now);
        for gid in state.grants.keys().cloned().collect::<Vec<_>>() {
            let mut narrowed = state.clone();
            narrowed.apply(Mutation::RevokeGrant { grant_id: gid });
            let after = decide(&req, &narrowed, now);
            prop_assert!(after.rank() <= before.rank(),
                "revoke widened: {:?} -> {:?}", before, after);
        }
    }

    /// INV-P2 (deny side): adding a deny rule never increases any rank.
    #[test]
    fn adding_deny_is_monotonic(
        state in state_strategy(),
        deny in deny_strategy(),
        req in request_strategy(),
        now in 0i64..300,
    ) {
        let before = decide(&req, &state, now);
        let mut s = state;
        s.apply(Mutation::AddDeny(deny));
        prop_assert!(decide(&req, &s, now).rank() <= before.rank());
    }

    /// INV-P3: no grant is live at or after its expiry instant, and an
    /// expired grant never produces Allow.
    #[test]
    fn expiry_is_total(
        state in state_strategy(),
        req in request_strategy(),
        now in 0i64..300,
    ) {
        for g in state.grants.values() {
            if let Some(t) = g.expires_at {
                if now >= t {
                    prop_assert!(!g.live(now));
                }
            }
        }
        if let Decision::Allow { grant_id } = decide(&req, &state, now) {
            let g = &state.grants[&grant_id];
            if let Some(t) = g.expires_at {
                prop_assert!(now < t);
            }
        }
    }

    /// INV-P4 (dynamic half): no sequence of non-widening mutations ever
    /// increases any decision's rank. (The static half — widening mutations
    /// demand an ApprovalEvent — is enforced by constructor signatures.)
    #[test]
    fn no_widening_without_approval(
        state in state_strategy(),
        req in request_strategy(),
        now in 0i64..300,
        // arbitrary sequence of narrowing/bookkeeping mutations over known ids
        picks in proptest::collection::vec((0usize..8, 0usize..3), 0..12),
    ) {
        let before = decide(&req, &state, now);
        let gids: Vec<_> = state.grants.keys().cloned().collect();
        let mut s = state.clone();
        // NB: RemoveDeny is widening and deliberately absent from this set —
        // it cannot even be constructed without an ApprovalEvent.
        for (i, kind) in picks {
            let m = match kind {
                0 if !gids.is_empty() =>
                    Mutation::RevokeGrant { grant_id: gids[i % gids.len()].clone() },
                1 if !gids.is_empty() =>
                    Mutation::ConsumeUse { grant_id: gids[i % gids.len()].clone() },
                _ => continue,
            };
            prop_assert!(!m.is_widening());
            s.apply(m);
        }
        prop_assert!(decide(&req, &s, now).rank() <= before.rank());
    }

    /// INV-P5: a posture's decisions equal the decisions of its compiled
    /// grant-set. There is no posture branch to diverge.
    #[test]
    fn posture_compiles_to_grants(
        agent in agent_strategy(),
        scope in scope_strategy(),
        req in request_strategy(),
        now in 0i64..300,
        posture in prop_oneof![Just(Posture::Careful), Just(Posture::Standard), Just(Posture::Open)],
    ) {
        let mut n = 0u32;
        let muts = compile_posture(posture, &agent, &scope, &approval(), || {
            n += 1;
            format!("g{n}")
        });
        let mut s = PolicyState::default();
        for m in muts {
            s.apply(m);
        }
        let d = decide(&req, &s, now);
        // The semantic definition of each posture, stated independently:
        let should_allow = req.agent == agent
            && scope.covers(&req.resource)
            && match posture {
                Posture::Careful => false,
                Posture::Standard => req.class == ToolClass::Read,
                Posture::Open => true,
            };
        prop_assert_eq!(matches!(d, Decision::Allow { .. }), should_allow);
    }

    /// INV-P6: an Allow's citing grant always has scope covering the
    /// requested resource — and cover is exactly segment-wise prefix.
    #[test]
    fn scope_lattice(a in scope_strategy(), b in scope_strategy()) {
        let a_str = a.as_str().to_string();
        let b_str = b.as_str().to_string();
        let expected = b_str == a_str || b_str.starts_with(&format!("{a_str}:"));
        prop_assert_eq!(a.covers(&b), expected);
    }

    /// INV-P7: decide is a pure function — same inputs, same output, and no
    /// mutation of state.
    #[test]
    fn determinism(
        state in state_strategy(),
        req in request_strategy(),
        now in 0i64..300,
    ) {
        let snapshot = state.clone();
        let d1 = decide(&req, &state, now);
        let d2 = decide(&req, &state, now);
        prop_assert_eq!(d1, d2);
        prop_assert_eq!(state, snapshot);
    }
}

/// Deny rules beat grants: an explicit "no" is stronger than a standing "yes".
#[test]
fn deny_beats_grant() {
    let agent = AgentKey { agent: "claude".into(), project: "/p/a".into() };
    let scope = Scope::parse("github:repo:o1/x").unwrap();
    let mut s = PolicyState::default();
    s.apply(Mutation::add_grant(
        "g1".into(),
        agent.clone(),
        ToolClass::Write,
        scope.clone(),
        None,
        None,
        ApprovalEvent { id: "a1".into(), at: 0, channel: ApprovalChannel::Dashboard },
    ));
    s.apply(Mutation::AddDeny(DenyRule {
        id: "d1".into(),
        agent: agent.clone(),
        class: ToolClass::Write,
        scope: scope.clone(),
        tool: None,
    }));
    let req = Request { agent, tool: "github.create_pr".into(), class: ToolClass::Write, resource: scope };
    assert!(matches!(decide(&req, &s, 0), Decision::Deny { .. }));
}

/// One-shot grants stop allowing after their single use is consumed.
#[test]
fn one_shot_grant_is_consumed() {
    let agent = AgentKey { agent: "codex".into(), project: "/p/a".into() };
    let scope = Scope::parse("mcp:github").unwrap();
    let mut s = PolicyState::default();
    s.apply(Mutation::add_grant(
        "g1".into(),
        agent.clone(),
        ToolClass::Write,
        scope.clone(),
        None,
        Some(1),
        ApprovalEvent { id: "a1".into(), at: 0, channel: ApprovalChannel::Elicitation },
    ));
    let req = Request { agent, tool: "github.create_pr".into(), class: ToolClass::Write, resource: scope };
    assert!(matches!(decide(&req, &s, 0), Decision::Allow { .. }));
    s.apply(Mutation::ConsumeUse { grant_id: "g1".into() });
    assert_eq!(decide(&req, &s, 0), Decision::Ask);
}
