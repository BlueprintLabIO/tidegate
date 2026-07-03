# Landscape: local-first agent credential gates

Research synthesis (2026-07). Every claim below was verified against primary
sources by an adversarial 3-vote check (25/25 confirmed). This informs
Tidegate's positioning and roadmap; it is not marketing copy.

## The gap Tidegate fills

No verified peer combines all of: **local-first + MCP-native + credential
never seen by the agent + per-resource ask/allow/deny + a tamper-evident
(hash-chained) audit log + a polished CLI with headless-capable approval.**
Peers are either hosted platforms or local-but-narrow. The **hash-chained
receipt log appears unique** among the tools surveyed.

## Competitors

| Product | License | Local vs Hosted | Agent sees raw cred? | Per-resource scope | Audit |
|---|---|---|---|---|---|
| Nango | **ELv2** (source-available) | Self-host / cloud (platform) | No | Per-connection | Yes |
| Composio | Hosted | Cloud | No (server inject, per-userID) | Per-user | Yes |
| Arcade.dev | Hosted | Cloud | No (OAuth, stores tokens) | Per-user | — |
| Infisical | **MIT** | Self-host | No — ships an **Agent Vault** broker-proxy | Yes | Yes |
| 1Password | Proprietary | Local | No (`op run` JIT inject) | Per-vault | Activity Log |
| Docker MCP Gateway | — | Local (containers) | Injects creds | Container isolation | — |
| MintMCP / TrueFoundry | Hosted/enterprise | Cloud | No (OAuth broker) | RBAC + approval flows | Yes |
| OneCLI | OSS (Rust) | **Local** | No (FAKE_KEY→REAL_KEY swap) | — | — |
| Bitwarden Agent Access | **Apache-2.0** | Local/tunnel | No (scoped broker) | Scoped | — |
| Marchward | Hosted | Cloud | No | — | — |

## Nango `providers.yaml` licensing verdict

The **entire Nango repo, `providers.yaml` included, is Elastic License 2.0**
(verified: no per-file header; the file inherits the repo LICENSE). ELv2 grants
use/copy/modify/distribute/derivatives, but forbids offering it as a hosted
managed service and stripping notices.

**Verdict: reference the schema, don't bundle the data.** ELv2 is
source-available (not OSI-permissive); dropping it into our MIT repo makes a
mixed-license repo, and the managed-service clause could bite a future hosted
tier. Use `providers.yaml` as a **schema reference** (its fields:
`display_name`, `auth_mode`, `proxy.{base_url, headers}`, `token_url`,
`authorization_url`; 15+ auth modes; 800+ providers) and generate our own
catalog. For the proxy **code**, prefer the permissive peers: Infisical (MIT),
OneCLI (OSS), Bitwarden Agent Access (Apache-2.0).

## MCP standard

- **Authorization is transport-level and optional.** HTTP transports SHOULD do
  OAuth 2.1; **stdio transports should take credentials from the
  environment** — exactly what Tidegate's MCP path does. We are with the spec.
- **Elicitation** (server asks the user mid-call) is emerging: **VS Code
  Insiders is the early client; Claude Code / Cursor / Codex support is
  unconfirmed.** So elicitation cannot be the baseline approval channel — the
  OS-notification + model-legible-timeout-retry fallback is load-bearing.

## UX patterns worth stealing (and two anti-patterns)

From 1Password, the definitive local-approval exemplar:

- **Steal:** defer auth to a trusted local component; one-tap OS-native
  approval; JIT injection that never touches disk/process-list.
- **Avoid — opaque prompt:** 1Password shows only "iTerm2 wants access," not
  *which secret or command*. Tidegate's approval names agent + tool + resource.
- **Avoid — biometric-at-desk breaks headless:** the user isn't there to touch
  the sensor for a remote agent. Tidegate uses a confirmation code over a
  notification, which works headless.

These two are Tidegate's concrete, verified differentiators — keep them.
