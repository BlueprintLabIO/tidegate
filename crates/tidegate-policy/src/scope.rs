//! The scope lattice, generalized to resource prefixes.
//!
//! A scope is a hierarchical resource path: `mcp:github`,
//! `github:repo:BlueprintLabIO/tidegate`, `slack:channel:#eng`. A grant at
//! scope S covers a request at resource R iff S is a segment-wise prefix of
//! R (INV-P6). This is what lets tidegate gate *any* MCP server at
//! whole-server granularity today, while provider descriptors add
//! finer-grained paths without touching the engine.
//!
//! Segments are separated by `:`. Prefix matching is per-segment, never
//! per-character: `github:repo:a` does not cover `github:repo:ab`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Scope(String);

impl Scope {
    /// Build a scope from raw segments. Segments must be non-empty and must
    /// not contain the separator; violations are rejected rather than
    /// silently re-delimited, because a scope string that means something
    /// other than what its author wrote is a policy bug.
    pub fn from_segments<I, S>(segments: I) -> Result<Self, InvalidScope>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = String::new();
        let mut any = false;
        for seg in segments {
            let seg = seg.as_ref();
            if seg.is_empty() || seg.contains(':') {
                return Err(InvalidScope(seg.to_string()));
            }
            if any {
                out.push(':');
            }
            out.push_str(seg);
            any = true;
        }
        if !any {
            return Err(InvalidScope(String::new()));
        }
        Ok(Scope(out))
    }

    /// Parse a `:`-delimited scope string.
    pub fn parse(s: &str) -> Result<Self, InvalidScope> {
        Scope::from_segments(s.split(':'))
    }

    #[must_use] 
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split(':')
    }

    /// Segment-wise prefix test: does `self` (a grant's scope) cover
    /// `resource` (a request's concrete path)?
    #[must_use] 
    pub fn covers(&self, resource: &Scope) -> bool {
        let mut mine = self.segments();
        let mut theirs = resource.segments();
        loop {
            match (mine.next(), theirs.next()) {
                (None, _) => return true,          // ran out of prefix: covered
                (Some(_), None) => return false,   // grant is deeper than the resource
                (Some(a), Some(b)) if a == b => continue,
                _ => return false,
            }
        }
    }

    /// The whole-server scope for an MCP server nobody has described yet.
    pub fn whole_server(server: &str) -> Result<Self, InvalidScope> {
        Scope::from_segments(["mcp", server])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidScope(pub String);

impl std::fmt::Display for InvalidScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid scope segment: {:?}", self.0)
    }
}

impl std::error::Error for InvalidScope {}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
