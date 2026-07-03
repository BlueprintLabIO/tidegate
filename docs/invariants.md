# Invariant map

Every guarantee Tidegate makes, in testable form. Convention (inherited from
Tidebase): each invariant names the property, the module that owns it, and the
test that pins it. A feature lands together with its invariant and its probe;
a guarantee without a test here is marketing, not engineering.

Status legend: **[P]** pinned by a test · **[D]** designed, test pending · **[R]** roadmap.

## Policy engine (`tidegate-policy` — pure, no IO)

- **INV-P1 Deny by default. [P]** For every request whose (agent, project,
  tool-class, scope) is not covered by a live grant, the decision is `Ask`
  (interactive postures) or `Deny` (when no ask channel exists). Never `Allow`.
  — `policy/tests/prop_deny_default.rs`
- **INV-P2 Monotonic revocation. [P]** Revoking any grant never widens access:
  for all requests, decision after revoke ≤ decision before (Allow > Ask > Deny
  ordering). — `policy/tests/prop_monotonic.rs`
- **INV-P3 Total expiry. [P]** No grant evaluates as live at or after its
  expiry instant. Time-boxed grants narrow to nothing, never to something
  else. — `policy/tests/prop_expiry.rs`
- **INV-P4 Widening requires an approval event. [P]** Every state transition
  that increases any decision (per INV-P2's ordering) carries a human-presence
  `ApprovalEvent` in its causal chain. The engine's transition function
  rejects widening mutations without one — this is a type-level requirement
  (the constructor of a widening `Mutation` demands an `ApprovalEvent`), and a
  property test confirms no sequence of non-approval mutations widens
  anything. — `policy/tests/prop_widening.rs`
- **INV-P5 Postures are grants, not modes. [P]** Evaluating under a posture is
  extensionally equal to evaluating under the grant-set that posture compiles
  to. There is no posture branch in the decision path.
  — `policy/tests/prop_posture_compile.rs`
- **INV-P6 Scope lattice is honored. [P]** A grant at scope S allows a request
  at scope S' only if S' ≤ S in the lattice (repo ≤ repo-list containing it ≤
  org-read). No lateral leakage between unrelated repos.
  — `policy/tests/prop_scope_lattice.rs`
- **INV-P7 Determinism. [P]** The engine is a pure function of (request,
  grant-set, now). Same inputs, same decision. — enforced by the crate having
  no IO deps (compile-time) and `policy/tests/prop_determinism.rs`.

## Vault (`tidegate-vault` — no network deps)

- **INV-V1 Secrets are encrypted at rest. [P]** No plaintext secret bytes are
  ever written to the state database; round-trip tests assert ciphertext in
  storage differs from plaintext and decrypts correctly.
  — `vault/tests/envelope.rs`
- **INV-V2 The vault is the sole decryptor. [P]** Decryption is private to the
  vault crate; other crates receive a use-handle, never key material.
  Enforced at compile time (no public decrypt API) and by a compile-fail test.
  — `vault/tests/compile_fail/`
- **INV-V3 Secret types cannot be printed. [P]** Secret wrappers implement
  neither `Display` nor `Debug`-with-content nor `Serialize`; compile-fail
  tests pin it. Buffers are zeroized on drop. — `vault/tests/compile_fail/`
- **INV-V4 Master key lives in the OS keychain. [D]** The database alone is
  insufficient to decrypt; deleting the keychain entry renders the vault
  unreadable. — integration test, macOS CI.

## Daemon (`tidegate-daemon`)

- **INV-D1 No secret material in any outward surface. [P]** Provider tokens
  never appear in MCP results, error strings, logs, or receipts. Tests grep
  every outward-facing serialization of a full call cycle for planted token
  material. — `daemon/tests/no_leak.rs`
- **INV-D2 Every executed call has a receipt. [P]** The only code path that
  performs an upstream call requires an open receipt (type-level: `execute`
  takes an `OpenReceipt`), and integration tests assert receipt count ==
  upstream-call count under success, failure, and mid-call crash.
  — `daemon/tests/receipts.rs`
- **INV-D3 The receipt chain is tamper-evident. [P]** Each receipt hashes its
  predecessor; verification detects any mutation, insertion, or deletion in
  the middle of the log. — `daemon/tests/chain.rs`
- **INV-D4 Unauthenticated calls learn nothing. [P]** A connection without a
  valid agent token gets a uniform error: no tool list, no scope hints, no
  existence oracle for repos or grants. — `daemon/tests/auth.rs`
- **INV-D5 Denials and timeouts are agent-legible. [P]** Every non-Allow
  outcome returns structured content telling the model what happened and what
  can be done next (`approval_pending` + id, `denied` + reason). Never a bare
  error. — `daemon/tests/verdict_shapes.rs`
- **INV-D6 Narrowing is instant. [P]** After a revoke is acknowledged, the
  next call under that grant is refused — no cache serves a revoked grant.
  — `daemon/tests/revoke_latency.rs`

## CLI (`tidegate-cli`)

- **INV-C1 Widening commands only request. [P]** `allow`, `posture open`
  (from `standard`/`careful`), and any grant-creating path exit having created
  a *pending* approval, not a grant. Integration test drives the CLI and
  asserts no decision changed until the approval was resolved out-of-band.
  — `cli/tests/widen_requests.rs`
- **INV-C2 Narrowing commands act immediately. [P]** `revoke` and
  posture-narrowing take effect before the command exits. — `cli/tests/narrow.rs`
- **INV-C3 Install is idempotent and additive. [P]** Running
  `tidegate install <agent>` twice yields one identity and one config entry;
  it never removes or rewrites unrelated MCP servers in the agent's config.
  — `cli/tests/install_idempotent.rs`

## Product-level (measured, not proved)

- **INV-U1 Asks converge to zero.** Under `standard` posture, a project's
  steady-state ask rate approaches zero after its first sessions; a project
  still prompting after a week is a defaults bug. Measured locally
  (`tidegate audit --stats`), not property-tested.
- **INV-U2 The gate never silently drops a call. [P]** Every inbound tool call
  terminates in exactly one of: executed-with-receipt, denied-with-reason,
  pending-with-id. — covered by INV-D2/D5 tests jointly.

## Out of scope in v0 (tracked, deliberately unclaimed)

- Token-side scope narrowing (GitHub App installation tokens). **[R]**
- MCP elicitation as approval channel 1 — implemented behind client-capability
  detection; the OS-notification and timeout-retry channels are the pinned
  baseline. **[D]**
- Cross-machine sync, teams, SSO: not in the threat model, not here. **[R]**
