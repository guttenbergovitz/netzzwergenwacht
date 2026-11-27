//! Robots exclusion protocol evaluation.
//!
//! A crawl must be able to say whether it consulted `robots.txt`, what it found, and which
//! discovered URLs it therefore did not fetch. "Robots said no" and "the file could not be
//! retrieved" are different conclusions and are recorded separately; neither is presented as
//! evidence that a URL was absent from the application.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::collection;
use crate::domain::{AuditTarget, CollectorOutcome, ExecutionBudget, TargetPolicy};

/// How the robots exclusion file was obtained for an origin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RobotsOutcome {
    /// `robots.txt` was retrieved and parsed.
    Observed,
    /// No `robots.txt` exists (`404`/`410`), so all paths are allowed by convention.
    Absent,
    /// Retrieval failed or was blocked by policy; no directives could be applied.
    #[default]
    Unavailable,
}

impl RobotsOutcome {
    /// Short human-readable label used in reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Absent => "absent",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone)]
struct RobotsRule {
    allow: bool,
    pattern: String,
}

/// Directives that apply to this agent for one origin.
#[derive(Debug, Clone, Default)]
pub struct RobotsRules {
    rules: Vec<RobotsRule>,
}

impl RobotsRules {
    /// The agent token used when matching `User-agent` groups.
    const AGENT_TOKEN: &'static str = "netzzwergenwacht";

    /// Parses a `robots.txt` body, keeping only the groups that apply to this agent.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        let mut rules = Vec::new();
        let mut group_applies = false;
        let mut awaiting_agent = true;

        for raw in body.lines() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            if key == "user-agent" {
                // A blank line separates groups; a new `user-agent` after rules starts one.
                if !awaiting_agent {
                    group_applies = false;
                    awaiting_agent = true;
                }
                let agent = value.to_ascii_lowercase();
                if agent == "*" || Self::AGENT_TOKEN.starts_with(&agent) && !agent.is_empty() {
                    group_applies = true;
                }
                continue;
            }

            if !matches!(key.as_str(), "allow" | "disallow") {
                continue;
            }
            awaiting_agent = false;
            if !group_applies || value.is_empty() {
                // An empty `Disallow:` is explicitly "no restriction", not a rule.
                continue;
            }
            rules.push(RobotsRule {
                allow: key == "allow",
                pattern: value.to_owned(),
            });
        }

        Self { rules }
    }

    /// Returns `true` when no directive restricts `path_and_query`.
    ///
    /// The longest matching pattern wins, and an `Allow` wins a tie, as the exclusion protocol
    /// specifies. When nothing matches, the path is permitted.
    #[must_use]
    pub fn allows(&self, path_and_query: &str) -> bool {
        let mut best: Option<&RobotsRule> = None;
        for rule in &self.rules {
            if !pattern_matches(&rule.pattern, path_and_query) {
                continue;
            }
            match best {
                Some(current)
                    if current.pattern.len() > rule.pattern.len()
                        || current.pattern.len() == rule.pattern.len() && current.allow =>
                {
                    // Keep the more specific or already-permissive rule.
                }
                _ => best = Some(rule),
            }
        }
        best.is_none_or(|rule| rule.allow)
    }

    /// Number of directives that apply to this agent.
    #[must_use]
    pub fn directive_count(&self) -> usize {
        self.rules.len()
    }

    /// `true` when the origin publishes no directive for this agent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Matches a robots pattern against a path, honouring `*` wildcards and a trailing `$` anchor.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let anchored = pattern.ends_with('$');
    let body = pattern.strip_suffix('$').unwrap_or(pattern);
    let segments: Vec<&str> = body.split('*').collect();

    if !anchored {
        return prefix_matches(&segments, path);
    }

    // Anchored: the pattern must consume the whole path.
    let mut cursor = 0usize;
    for (index, segment) in segments.iter().enumerate() {
        if index == 0 {
            if !path.starts_with(segment) {
                return false;
            }
            cursor = segment.len();
            continue;
        }
        if segment.is_empty() {
            continue;
        }
        let Some(found) = path[cursor..].find(segment) else {
            return false;
        };
        cursor += found + segment.len();
    }
    // The final segment must reach the end of the path when the pattern is anchored.
    cursor == path.len() || segments.last().is_some_and(|last| last.is_empty())
}

/// Matches a wildcard pattern as a prefix: every segment must appear in order.
fn prefix_matches(segments: &[&str], path: &str) -> bool {
    let Some(first) = segments.first() else {
        return true;
    };
    if !path.starts_with(first) {
        return false;
    }
    let mut cursor = first.len();
    for segment in &segments[1..] {
        if segment.is_empty() {
            return true;
        }
        let Some(found) = path[cursor..].find(segment) else {
            return false;
        };
        cursor += found + segment.len();
    }
    true
}

/// Retrieves and evaluates `robots.txt` for the origin of `seed`.
///
/// The retrieval is bounded by the same [`ExecutionBudget`] and [`TargetPolicy`] as the rest of
/// the crawl, so it cannot become an unbounded extra request against the origin.
pub async fn fetch_robots(
    seed: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> (RobotsOutcome, RobotsRules) {
    let Ok(seed_url) = Url::parse(seed.as_str()) else {
        return (RobotsOutcome::Unavailable, RobotsRules::default());
    };
    let Ok(robots_url) = seed_url.join("/robots.txt") else {
        return (RobotsOutcome::Unavailable, RobotsRules::default());
    };
    let Ok(target) = AuditTarget::parse(robots_url.as_str(), policy) else {
        return (RobotsOutcome::Unavailable, RobotsRules::default());
    };

    let snapshot = collection::collect_http(&target, budget, policy).await;
    match &snapshot.http {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            match data.status_code {
                200 => (RobotsOutcome::Observed, RobotsRules::parse(&data.body_text)),
                404 | 410 => (RobotsOutcome::Absent, RobotsRules::default()),
                _ => (RobotsOutcome::Unavailable, RobotsRules::default()),
            }
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => {
            (RobotsOutcome::Unavailable, RobotsRules::default())
        }
    }
}

/// Formats the request path and query of `target`, as matched against robots patterns.
#[must_use]
pub fn path_and_query(target: &AuditTarget) -> String {
    let Ok(url) = Url::parse(target.as_str()) else {
        return "/".to_owned();
    };
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallowed_prefix_is_not_permitted() {
        let rules = RobotsRules::parse("User-agent: *\nDisallow: /admin\n");
        assert!(!rules.allows("/admin/panel"));
        assert!(rules.allows("/public"));
    }

    #[test]
    fn allow_wins_when_the_pattern_is_equally_specific() {
        let rules = RobotsRules::parse("User-agent: *\nDisallow: /private\nAllow: /private\n");
        assert!(rules.allows("/private"));
    }

    #[test]
    fn longer_allow_overrides_a_broader_disallow() {
        let rules = RobotsRules::parse("User-agent: *\nDisallow: /catalog\nAllow: /catalog/open\n");
        assert!(rules.allows("/catalog/open/page"));
        assert!(!rules.allows("/catalog/closed"));
    }

    #[test]
    fn wildcard_and_anchor_patterns_are_honoured() {
        let rules = RobotsRules::parse("User-agent: *\nDisallow: /*/print$\nDisallow: /search*\n");
        assert!(!rules.allows("/article/print"));
        assert!(rules.allows("/article/print/extra"));
        assert!(!rules.allows("/search?q=dwarfs"));
    }

    #[test]
    fn groups_for_other_agents_are_ignored() {
        let rules = RobotsRules::parse(
            "User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow: /tmp\n",
        );
        assert_eq!(rules.directive_count(), 1);
        assert!(rules.allows("/"));
        assert!(!rules.allows("/tmp/file"));
    }

    #[test]
    fn an_empty_disallow_imposes_no_restriction() {
        let rules = RobotsRules::parse("User-agent: *\nDisallow:\n");
        assert_eq!(rules.directive_count(), 0);
        assert!(rules.allows("/anything"));
    }

    #[test]
    fn comments_and_blank_lines_do_not_create_directives() {
        let rules = RobotsRules::parse(
            "User-agent: *\n# a comment\nDisallow: /secret  # trailing comment\n",
        );
        assert_eq!(rules.directive_count(), 1);
        assert!(!rules.allows("/secret"));
    }
}
