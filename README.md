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
  injects it only at the moment of the call.
- **Ask before write — and the prompt says exactly what.** Reads settle after
  you approve them once; writes wait for a one-click approval that names the
  agent, the tool, and the resource (not a vague "something wants access"). You
  decide per novel action, and the gate remembers. Deny-by-default, no config
  files. Approval works headless — a confirmation code over a notification, not
  a fingerprint you have to be at your desk for.
- **Tamper-evident receipts.** Every call, verdict, approval, and revocation is
  appended to a **hash-chained** audit log — mutating the middle breaks the
  chain visibly. One dashboard, one revoke button, every agent.

## What it gates

- **Any MCP server.** GitHub is built in; any other MCP server connects
  generically today and gets richer per-resource scoping via a declarative
  descriptor — provider specifics are data, not gateway code.
- **Any HTTP API**, through the built-in **broker proxy**: point your client's
  base URL at the gate, and it injects the credential and gates the call
  per-path. A catalog of API-key services (GitHub REST, OpenAI, Anthropic,
  Stripe, Linear, Notion, Slack, Vercel, Cloudflare, …) ships built in; any
  REST endpoint works via `TIDEGATE_HTTP_BASE_URL`.
- **Clients:** Claude Code, Codex, Cursor (`tidegate install claude codex cursor`).

The MCP spec itself says stdio servers should take credentials from the
environment — which is exactly what the gate does. See [`docs/`](docs/) and the
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
