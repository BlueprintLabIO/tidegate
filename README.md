# Tidegate

**The local permissions gate for AI coding agents.**

Stop pasting secrets into coding agents. Connect a service once, and Claude,
Codex, and Cursor reach it through one local gate with scoped, audited access.
They never see the key.

```
$ tidegate connect github
✔ github → vault  (encrypted · local only)

$ tidegate install claude codex cursor
✔ 3 agents wired  (scoped · no tokens shared)

$ tidegate dashboard
```

## What it does

- **Keys stay home.** Credentials live in an encrypted vault on your disk, the
  master key in your OS keychain. Agents call tools through the gate; the raw
  token never enters an agent's context or a model's transcript. The gate
  injects it only into the upstream service process, at the moment of the call.
- **Ask before write.** Reads settle after you approve them once; writes wait
  for a one-click approval. You decide per novel action, and the gate
  remembers. Deny-by-default, remembered as policy — no config files.
- **Receipts for everything.** Every call, verdict, approval, and revocation is
  appended to a hash-chained audit log. One dashboard, one revoke button, every
  agent.

## Any MCP server, and the wedge

GitHub is built in. Any other MCP server can be connected generically today and
given a richer scoping descriptor when someone writes one — provider specifics
are declarative data, not gateway code. See [`docs/`](docs/) and the
[threat model](THREAT_MODEL.md).

## Install

```
npm install -g tidegate       # or pnpm add -g / yarn global add
brew install blueprintlabio/tap/tidegate
curl -fsSL https://tidegate.dev/install.sh | sh
cargo install tidegate        # from source
```

## Layout

- `crates/tidegate-policy` — the pure, IO-free policy engine (deny-by-default
  grants, scope lattice, human-approval-gated widening). Property-tested.
- `crates/tidegate-vault` — the encrypted secret store; the sole decryptor.
- `crates/tidegate-daemon` — the gate: MCP gateway, approvals, hash-chained
  receipts, control socket, dashboard.
- `crates/tidegate` — the `tidegate` CLI (also hosts the daemon and per-agent
  shim).
- `site/` — the landing page (Astro, SLUICE design system).

Guarantees are catalogued in [`docs/invariants.md`](docs/invariants.md), each
pinned by a test. `#![forbid(unsafe_code)]` across every crate.

## Status

v0, in the open, under construction. The interface is stable enough to build
against; the commands above are what ships.

License: MIT OR Apache-2.0. A Blueprint Lab project, sibling of
[Tidebase](https://tidebase.dev).
