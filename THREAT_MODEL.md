# Tidegate threat model

Tidegate is a local permissions gate for AI coding agents. This document states
plainly what it defends against, what it does not, and why. It is a design
contract: code that weakens a claim here is a bug, and claims the code cannot
keep must be removed from here.

## The adversary

The adversary Tidegate exists for is **the agent itself**: a coding agent whose
model has been prompt-injected, is misbehaving, or is simply over-eager, acting
through its sanctioned tool channels (MCP tool calls, shell commands the
harness allows). The adversary is *not* malware running as your user — see
"Out of scope" below.

## What Tidegate defends

1. **Raw credentials never reach agents or models.** Provider tokens (e.g. a
   GitHub PAT) live in an encrypted vault on disk. They are decrypted only
   inside the daemon at the moment of an outbound call to the provider. They
   never appear in an MCP message, an agent's context window, a model
   transcript, a tool result, an error message, or a log line.

2. **Access is scoped and attributed.** Every call is made by an identified
   (agent, project) pair, against an explicit scope (a repo, a list of repos,
   or org-read). An agent allowed to read one repo learns nothing about the
   rest of the account. Blast radius of any single compromised agent session
   is bounded by that agent's grants.

3. **Standing access only widens with a human in the loop.** No sequence of
   shell commands, MCP calls, or API requests widens any grant without a
   human-presence approval event (a click or an in-session answer). Commands
   that *narrow* access apply instantly from anywhere; this asymmetry is
   deliberate — an injected agent can lock itself out, never let itself in.

4. **Everything leaves a receipt.** Every tool call, verdict (allow / ask /
   deny), approval, denial, revocation, posture change, and identity mint is
   appended to a hash-chained, append-only audit log. Tampering with the log
   file breaks the chain visibly.

## Agent identity: attribution, not authentication

Agents authenticate to the daemon with a bearer token minted per
(agent, project) at `tidegate install` and written into that agent's MCP
config. Be precise about what this buys:

- The **model** never sees the token — the harness reads the config, the model
  reads the context window. The token cannot be exfiltrated through the
  sanctioned tool channel.
- Any **process running as your user** that reads another agent's config file
  can impersonate that agent. Cross-agent impersonation therefore requires a
  file read that the victim agent's own harness would surface in its
  permission prompt — a mitigation, not a guarantee.
- Per-project tokens bound the value of any single stolen token.

Identity here is honest **attribution** within your own machine, sufficient for
policy and audit. It is not strong authentication against hostile same-user
code, and we do not claim otherwise.

## Out of scope (v0, stated without apology)

- **A compromised machine.** Malware running as your user can read agent
  configs, impersonate agents, and attempt keychain access (on macOS the
  keychain ACL restricts vault-key decryption to the signed tidegate binary,
  so a foreign process asking triggers a visible OS prompt — a speed bump,
  not a wall). Tidegate narrows what agents can do; it is not endpoint
  security.
- **A computer-use agent that clicks the approval dialog.** The human channel
  assumes the clicker is human.
- **Provider-side enforcement.** In v0, repo and scope limits are enforced by
  the gate, not by the provider token itself: the PAT in the vault may be
  broader than any grant. If the vault is compromised, the token's own scope
  is the limit. Token-side narrowing (GitHub App installation tokens minted
  per repo) is the planned mitigation and the reason it is on the roadmap
  rather than in the marketing.
- **Denial of service by the agent against the daemon.** An agent can spam
  calls; rate limiting is a robustness concern, not a security boundary.

## The layering

Three seams, each honest about what it does not cover:

| Layer | Defends | Does not defend |
|---|---|---|
| Tidegate | the tool channel: what flows through sanctioned agent calls | the filesystem |
| Agent harness (Claude Code, Codex, Cursor permission prompts) | the filesystem and shell surface | the user boundary |
| OS (users, keychain, code-signing ACLs) | the user boundary | a compromised user account |

## Invariants

The machine-checked form of this document lives in
[`docs/invariants.md`](docs/invariants.md). Every claim above that can be
property-tested is listed there with the test that pins it.
