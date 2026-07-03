# What Tidegate gates

Tidegate gates anything where it owns both the **credential** and the
**transport**. That's two transports today.

## 1. MCP servers (stdio)

The gate spawns the MCP server, injects the credential into its environment,
and speaks MCP to your agents through a per-agent shim. The agent talks only to
the gate. This is aligned with the MCP spec, which says stdio servers should
take credentials from the environment.

- **GitHub** — built in (`tidegate connect github`), scoped per repo.
- **Any MCP server** — connect generically at whole-server scope:

  ```
  TIDEGATE_MCP_COMMAND=npx TIDEGATE_MCP_ARGS="-y some-mcp-server" \
  TIDEGATE_MCP_ENV=SOME_TOKEN tidegate connect some-service
  ```

  A provider descriptor (declarative `scopers` + tool-class rules) upgrades it
  to per-resource scoping.

## 2. HTTP APIs (broker proxy)

The gate runs a loopback reverse proxy. Point a service's base URL at
`http://127.0.0.1:<port>/p/<agent-token>/<service>/…` and the gate injects the
credential into the configured header, gates the call (method → read/write,
path → resource scope), and forwards it. Your client sends no credential.

Built-in API-key presets (`tidegate connect <name>`):

| Name | Service | Auth header |
|---|---|---|
| `github-api` | GitHub REST | `Authorization: token …` |
| `openai` | OpenAI | `Authorization: Bearer …` |
| `anthropic` | Anthropic | `x-api-key: …` |
| `stripe` | Stripe | `Authorization: Bearer …` |
| `linear` | Linear | `Authorization: Bearer …` |
| `notion` | Notion | `Authorization: Bearer …` |
| `openrouter` | OpenRouter | `Authorization: Bearer …` |
| `slack` | Slack (bot) | `Authorization: Bearer …` |
| `vercel` | Vercel | `Authorization: Bearer …` |
| `cloudflare` | Cloudflare | `Authorization: Bearer …` |

Any other REST API works without a preset:

```
TIDEGATE_HTTP_BASE_URL=https://api.example.com \
TIDEGATE_HTTP_AUTH_HEADER=Authorization \
TIDEGATE_HTTP_AUTH_SCHEME="Bearer " \
tidegate connect example
```

After `tidegate install <agent>`, the CLI prints the per-agent proxy base URL
to point your SDK at. Run `tidegate status` to see it again.

The provider catalog schema is referenced from Nango's `providers.yaml`; the
data is Tidegate's own (Nango's file is Elastic License 2.0 and is not
bundled).

## Honest boundaries

- **Routing cooperation.** The proxy gates a client that actually routes
  through it (base-URL override). An agent making raw sockets to bypass it is
  not stopped — which matches the threat model (agent misuse through sanctioned
  channels, not a hostile process on your machine).
- **Gateway-side scoping (v0).** Repo/scope limits are enforced by the gate,
  not by the token itself. Token-side narrowing (e.g. GitHub App installation
  tokens) is on the roadmap.
- **Not gated:** arbitrary shell commands with a baked-in credential. That
  belongs to the agent harness's own permission system; Tidegate owns neither
  the credential nor the transport there.
- **OAuth providers** (Google, Slack user-context) need an OAuth app + refresh
  and are staged behind BYO-OAuth-app; the API-key tier ships first.
