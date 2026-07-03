//! Provider descriptors — the "Nango lesson" made concrete.
//!
//! Nango supports thousands of services not by writing thousands of clients
//! but by making every provider a *declarative record*. Tidegate does the
//! same: a provider is data — how to spawn its MCP server, which vault secret
//! to inject as which env var, and how to derive a resource scope from a tool
//! call. Adding GitLab, Linear, or Slack is a new entry here (or a JSON file
//! the user drops in), not new gateway code.
//!
//! GitHub ships built in because it is the wedge. Everything else can be
//! connected as a generic MCP server today and given a richer descriptor when
//! someone writes one.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tidegate_daemon::state::{HttpProviderRow, PathScoper};
use tidegate_daemon::{Descriptor, Scoper, ServerRow};

/// A connectable provider: everything the gate needs to run and scope it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    /// Human blurb shown at connect time.
    pub about: String,
    /// What the credential is, e.g. "a fine-grained personal access token".
    pub credential_hint: String,
    pub command: String,
    pub args: Vec<String>,
    /// vault secret name → env var injected into the server process.
    pub secret_env: BTreeMap<String, String>,
    pub descriptor: Descriptor,
}

impl Provider {
    pub fn into_server_row(self) -> ServerRow {
        ServerRow {
            name: self.name,
            command: self.command,
            args: self.args,
            secret_env: self.secret_env,
            descriptor: self.descriptor,
        }
    }
}

/// Built-in providers. GitHub is first-class; the generic entry lets any MCP
/// server be gated at whole-server granularity immediately.
pub fn builtin(name: &str) -> Option<Provider> {
    match name {
        "github" => Some(github()),
        _ => None,
    }
}

pub fn github() -> Provider {
    let mut secret_env = BTreeMap::new();
    secret_env.insert("github".to_string(), "GITHUB_PERSONAL_ACCESS_TOKEN".to_string());
    Provider {
        name: "github".into(),
        about: "GitHub — repos, issues, and pull requests through the official MCP server.".into(),
        credential_hint: "a fine-grained personal access token (github.com/settings/tokens)".into(),
        // The official GitHub MCP server, run via npx so there is nothing to
        // install ahead of time. Users on Docker can point this at the image
        // instead; it is just a descriptor.
        command: "npx".into(),
        args: vec!["-y".into(), "@modelcontextprotocol/server-github".into()],
        secret_env,
        descriptor: Descriptor {
            // Scope by the repo argument most GitHub tools take. Tools without
            // a repo arg fall back to the whole-server scope (mcp:github).
            scopers: vec![
                Scoper { arg: "repo".into(), template: "github:repo:{}".into() },
                Scoper { arg: "repository".into(), template: "github:repo:{}".into() },
            ],
            // The server annotates read tools, so we rely on readOnlyHint and
            // only override the few that matter for safety if annotations lie.
            tool_classes: BTreeMap::new(),
        },
    }
}

/// A generic MCP server the user names and runs themselves. Gated at
/// whole-server granularity until someone writes it a descriptor.
pub fn generic(name: &str, command: String, args: Vec<String>, secret_env: BTreeMap<String, String>) -> Provider {
    Provider {
        name: name.to_string(),
        about: format!("{name} — a custom MCP server, gated at whole-server scope."),
        credential_hint: "the credential this server needs (stored encrypted)".into(),
        command,
        args,
        secret_env,
        descriptor: Descriptor::default(),
    }
}

// ===================================================================
// HTTP API providers — the broker-proxy catalog.
//
// The "Nango lesson" applied to REST APIs: a provider is a declarative
// record (base URL, which header the credential goes in, path→scope rules).
// The SCHEMA is referenced from Nango's providers.yaml; the DATA here is our
// own — Nango's file is Elastic License 2.0 and is not bundled or copied.
//
// This is the API-key tier: services that authenticate with a bearer/PAT
// token you paste once. OAuth providers (Google, Slack user-context) are
// staged separately.
// ===================================================================

/// A connectable HTTP API. `credential_hint` is shown at connect time.
pub struct HttpProvider {
    pub row: HttpProviderRow,
    pub about: String,
    pub credential_hint: String,
}

fn bearer(name: &str, base: &str, hint: &str, about: &str, scopers: Vec<PathScoper>) -> HttpProvider {
    HttpProvider {
        row: HttpProviderRow {
            name: name.into(),
            base_url: base.into(),
            auth_header: "Authorization".into(),
            auth_scheme: "Bearer ".into(),
            secret_name: name.into(),
            path_scopers: scopers,
        },
        about: about.into(),
        credential_hint: hint.into(),
    }
}

/// Look up a built-in HTTP provider by name.
pub fn http_builtin(name: &str) -> Option<HttpProvider> {
    let p = match name {
        "github-api" => {
            let mut g = bearer(
                "github-api",
                "https://api.github.com",
                "a fine-grained personal access token (github.com/settings/tokens)",
                "GitHub REST API — repos, issues, PRs, over the broker proxy.",
                // /repos/{owner}/{repo}/... → github:repo:{owner}/{repo}
                vec![PathScoper { prefix: "repos".into(), template: "github:repo:{1}/{2}".into(), segments: 2 }],
            );
            g.row.auth_scheme = "token ".into(); // GitHub accepts "token <PAT>"
            g
        }
        "openai" => bearer(
            "openai",
            "https://api.openai.com",
            "an OpenAI API key (platform.openai.com/api-keys)",
            "OpenAI API — chat, embeddings, etc.",
            vec![],
        ),
        "anthropic" => HttpProvider {
            row: HttpProviderRow {
                name: "anthropic".into(),
                base_url: "https://api.anthropic.com".into(),
                auth_header: "x-api-key".into(),
                auth_scheme: String::new(),
                secret_name: "anthropic".into(),
                path_scopers: vec![],
            },
            about: "Anthropic API — Claude models.".into(),
            credential_hint: "an Anthropic API key (console.anthropic.com)".into(),
        },
        "stripe" => bearer(
            "stripe",
            "https://api.stripe.com",
            "a Stripe secret key (dashboard.stripe.com/apikeys)",
            "Stripe API — payments, customers, invoices.",
            vec![PathScoper { prefix: "v1".into(), template: "stripe:{1}".into(), segments: 1 }],
        ),
        "linear" => bearer(
            "linear",
            "https://api.linear.app",
            "a Linear API key (linear.app/settings/api)",
            "Linear API (GraphQL) — issues, projects.",
            vec![],
        ),
        "notion" => {
            let mut n = bearer(
                "notion",
                "https://api.notion.com",
                "a Notion internal integration token (notion.so/my-integrations)",
                "Notion API — pages, databases.",
                vec![],
            );
            n.about = "Notion API — pages, databases. (Set Notion-Version header in your client.)".into();
            n
        }
        "openrouter" => bearer(
            "openrouter",
            "https://openrouter.ai/api",
            "an OpenRouter API key (openrouter.ai/keys)",
            "OpenRouter — many models behind one API.",
            vec![],
        ),
        "slack" => bearer(
            "slack",
            "https://slack.com/api",
            "a Slack bot token (xoxb-…, api.slack.com/apps)",
            "Slack Web API (bot token) — messages, channels.",
            vec![],
        ),
        "vercel" => bearer(
            "vercel",
            "https://api.vercel.com",
            "a Vercel access token (vercel.com/account/tokens)",
            "Vercel API — deployments, projects.",
            vec![],
        ),
        "cloudflare" => bearer(
            "cloudflare",
            "https://api.cloudflare.com/client/v4",
            "a Cloudflare API token (dash.cloudflare.com/profile/api-tokens)",
            "Cloudflare API — DNS, Workers, zones.",
            vec![],
        ),
        _ => return None,
    };
    Some(p)
}

/// A generic HTTP API the user describes themselves (any REST endpoint).
/// This is what makes "any API" literally true — the builtins are just
/// presets over this.
pub fn http_generic(name: &str, base_url: String, auth_header: String, auth_scheme: String) -> HttpProvider {
    HttpProvider {
        row: HttpProviderRow {
            name: name.into(),
            base_url,
            auth_header,
            auth_scheme,
            secret_name: name.into(),
            path_scopers: vec![],
        },
        about: format!("{name} — a custom HTTP API, gated at whole-service scope."),
        credential_hint: "the credential this API needs (stored encrypted)".into(),
    }
}

/// Names of all built-in HTTP providers (for listing / help).
pub fn http_catalog() -> &'static [&'static str] {
    &[
        "github-api", "openai", "anthropic", "stripe", "linear", "notion", "openrouter", "slack",
        "vercel", "cloudflare",
    ]
}
