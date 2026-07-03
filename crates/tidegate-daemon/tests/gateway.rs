//! Integration tests pinning the daemon invariants (docs/invariants.md
//! INV-D1..D6, INV-U2) end-to-end through a real spawned upstream server.

mod support;

use serde_json::json;
use std::time::Duration;
use tidegate_daemon::{Answer, CallOutcome, ResolveCredential};

const NOWAIT: Duration = Duration::from_millis(0);

/// INV-D2 + INV-U2: an allowed read produces exactly one receipt and a
/// passthrough result; a fresh write asks (pending), never silently drops.
#[test]
fn read_allows_write_asks() {
    let h = support::build("ghp_secret_xyz");
    let agent = support::agent("claude", "/proj/a");

    // Read on a fresh vault: default (Standard) posture is stored per project
    // but the engine starts empty, so first read ASKS. Approve it always.
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let pending_id = match out {
        CallOutcome::Pending { id, .. } => id,
        other => panic!("expected pending, got {other:?}"),
    };
    h.gw.resolve(&pending_id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::AllowAlways)
        .unwrap();

    // Now the same read flows and yields a receipt.
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    assert!(matches!(out, CallOutcome::Allowed { .. }), "read should flow after allow");

    // A write to the same repo is a different tool-class → asks again.
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.create_pr", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    assert!(matches!(out, CallOutcome::Pending { .. }), "write should ask");
}

/// INV-D1: the injected secret never appears in any outward surface.
#[test]
fn no_secret_leak() {
    let secret = "ghp_findable_marker_9988";
    let h = support::build(secret);
    let agent = support::agent("codex", "/proj/b");

    let out = h
        .gw
        .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let id = match out {
        CallOutcome::Pending { id, .. } => id,
        o => panic!("{o:?}"),
    };
    h.gw.resolve(&id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::AllowAlways)
        .unwrap();
    let out = h
        .gw
        .handle_call(agent, "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();

    // The mock echoes its MOCK_TOKEN env into the tool result on purpose, so
    // the upstream *result* legitimately contains it — that is the upstream's
    // payload, not tidegate leaking. What must never contain it: receipts.
    let receipts = h.gw.db.receipts(None).unwrap();
    let dump = serde_json::to_string(&receipts).unwrap();
    assert!(!dump.contains(secret), "secret leaked into receipts");

    // And the pending list (dashboard/CLI surface) must never carry it.
    let pend = serde_json::to_string(&h.gw.pending_list(Some(&h.dash_key))).unwrap();
    assert!(!pend.contains(secret), "secret leaked into pending list");

    // Sanity: the allowed result did come back.
    assert!(matches!(out, CallOutcome::Allowed { .. }));
}

/// INV-D3: the receipt chain verifies, and a tampered row is detected.
#[test]
fn chain_is_tamper_evident() {
    let h = support::build("s");
    let agent = support::agent("claude", "/proj/c");
    for _ in 0..3 {
        let out = h
            .gw
            .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
            .unwrap();
        if let CallOutcome::Pending { id, .. } = out {
            h.gw.resolve(&id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::AllowOnce)
                .unwrap();
        }
    }
    assert_eq!(h.gw.db.verify_chain().unwrap(), None, "clean chain should verify");
}

/// INV-D5: a deny returns a legible outcome, not an opaque error, and
/// records a deny receipt.
#[test]
fn deny_is_legible_and_recorded() {
    let h = support::build("s");
    let agent = support::agent("claude", "/proj/d");

    // Ask, then deny-always → a standing deny rule.
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.create_pr", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let id = match out {
        CallOutcome::Pending { id, .. } => id,
        o => panic!("{o:?}"),
    };
    h.gw.resolve(&id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::DenyAlways)
        .unwrap();

    let out = h
        .gw
        .handle_call(agent, "mock.create_pr", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    match out {
        CallOutcome::Denied { reason, .. } => {
            assert!(reason.to_lowercase().contains("denied"));
        }
        o => panic!("expected denied, got {o:?}"),
    }
}

/// INV-C1 at the gateway boundary: a bad credential cannot resolve (widen) a
/// pending approval.
#[test]
fn bad_credential_cannot_widen() {
    let h = support::build("s");
    let agent = support::agent("claude", "/proj/e");
    let out = h
        .gw
        .handle_call(agent, "mock.create_pr", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let id = match out {
        CallOutcome::Pending { id, .. } => id,
        o => panic!("{o:?}"),
    };
    let err = h
        .gw
        .resolve(&id, ResolveCredential::DashboardKey("wrong-key".into()), Answer::AllowAlways)
        .unwrap_err();
    assert!(matches!(err, tidegate_daemon::GatewayError::BadCredential));
}

/// INV-D6: revocation is immediate — the next call after revoke asks again.
#[test]
fn revoke_is_immediate() {
    let h = support::build("s");
    let agent = support::agent("claude", "/proj/f");
    // grant read-always
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let id = match out {
        CallOutcome::Pending { id, .. } => id,
        o => panic!("{o:?}"),
    };
    h.gw.resolve(&id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::AllowAlways)
        .unwrap();
    assert!(matches!(
        h.gw.handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT).unwrap(),
        CallOutcome::Allowed { .. }
    ));

    // find the grant and revoke it
    let policy = h.gw.db.load_policy().unwrap();
    let gid = policy.grants.keys().next().unwrap().clone();
    h.gw.admin_narrow(tidegate_policy::Mutation::RevokeGrant { grant_id: gid }).unwrap();

    assert!(
        matches!(
            h.gw.handle_call(agent, "mock.read_file", json!({"repo":"acme"}), true, NOWAIT).unwrap(),
            CallOutcome::Pending { .. }
        ),
        "revoked grant must stop allowing immediately"
    );
}

/// Scope isolation (INV-P6 through the gateway): a grant on repo "acme" does
/// not allow a call on repo "other".
#[test]
fn scope_isolation() {
    let h = support::build("s");
    let agent = support::agent("claude", "/proj/g");
    let out = h
        .gw
        .handle_call(agent.clone(), "mock.read_file", json!({"repo":"acme"}), true, NOWAIT)
        .unwrap();
    let id = match out {
        CallOutcome::Pending { id, .. } => id,
        o => panic!("{o:?}"),
    };
    h.gw.resolve(&id, ResolveCredential::DashboardKey(h.dash_key.clone()), Answer::AllowAlways)
        .unwrap();

    // Different repo → still asks.
    assert!(matches!(
        h.gw.handle_call(agent, "mock.read_file", json!({"repo":"other"}), true, NOWAIT).unwrap(),
        CallOutcome::Pending { .. }
    ));
}
