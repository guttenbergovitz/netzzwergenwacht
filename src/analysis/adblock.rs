//! Opt-in `EasyList` / `EasyPrivacy` filter-list matcher for `adblock/*` rules.
//!
//! Filter lists (GPL-3.0 / CC-BY-SA) are **never** bundled in this repository;
//! callers supply them on demand from a local cache or explicit opt-in fetch.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, RuleId, Severity,
};

/// Rule identifier for ad-network/adblock resource matches.
pub const RULE_ADBLOCK_AD_RESOURCE: &str = "adblock.easylist.ad_resource";
/// Rule identifier for tracking/analytics script matches.
pub const RULE_ADBLOCK_TRACKER: &str = "adblock.easyprivacy.tracker";

/// Parsed `EasyList` / `EasyPrivacy` rule subset (domain anchors `||...^`, exceptions `@@...`,
/// and substring/path patterns).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdblockFilterList {
    block_domains: Vec<String>,
    allow_domains: Vec<String>,
    block_substrings: Vec<String>,
    allow_substrings: Vec<String>,
}

impl AdblockFilterList {
    /// Parses a filter list text (ignoring `!` comments, `[Adblock ...]` headers, and `##` cosmetic rules).
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut list = Self::default();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('!')
                || trimmed.starts_with('[')
                || trimmed.contains("##")
                || trimmed.contains("#@#")
            {
                continue;
            }
            let (is_allow, rule) = if let Some(rest) = trimmed.strip_prefix("@@") {
                (true, rest)
            } else {
                (false, trimmed)
            };
            let core = rule.split('$').next().unwrap_or(rule).trim();
            if core.is_empty() {
                continue;
            }
            if let Some(domain_part) = core.strip_prefix("||") {
                let domain = domain_part
                    .trim_end_matches('^')
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !domain.is_empty() {
                    if is_allow {
                        list.allow_domains.push(domain);
                    } else {
                        list.block_domains.push(domain);
                    }
                }
            } else {
                let pat = core.trim_matches('*').to_ascii_lowercase();
                if pat.len() >= 4 {
                    if is_allow {
                        list.allow_substrings.push(pat);
                    } else {
                        list.block_substrings.push(pat);
                    }
                }
            }
        }
        list
    }

    /// Returns `true` when `raw_url` matches a blocking rule and no exception rule.
    #[must_use]
    pub fn matches_url(&self, raw_url: &str) -> bool {
        let lower = raw_url.to_ascii_lowercase();
        let host = Url::parse(&lower)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();

        let is_allowed = self
            .allow_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
            || self.allow_substrings.iter().any(|s| lower.contains(s));
        if is_allowed {
            return false;
        }

        self.block_domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
            || self.block_substrings.iter().any(|s| lower.contains(s))
    }
}

/// Result of evaluating opt-in filter lists against observed subresource URLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdblockEvaluation {
    /// URLs matched by the ad-blocking (`EasyList`) list.
    pub ad_matches: Vec<String>,
    /// URLs matched by the privacy-tracking (`EasyPrivacy`) list.
    pub tracker_matches: Vec<String>,
}

/// Evaluates optional `easylist` and `easyprivacy` filter lists against `resource_urls`.
///
/// Unsupplied lists (`None`) emit [`CheckStatus::Skipped`] rather than false passes.
#[must_use]
pub fn evaluate_adblock_lists(
    easylist: Option<&AdblockFilterList>,
    easyprivacy: Option<&AdblockFilterList>,
    resource_urls: &[String],
) -> (AdblockEvaluation, AnalyserResult) {
    let mut eval = AdblockEvaluation::default();
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    eval_single_list(
        easylist,
        resource_urls,
        RULE_ADBLOCK_AD_RESOURCE,
        "Ad-network resources matched EasyList filter rules",
        &mut eval.ad_matches,
        &mut findings,
        &mut checks,
    );
    eval_single_list(
        easyprivacy,
        resource_urls,
        RULE_ADBLOCK_TRACKER,
        "Tracking/telemetry resources matched EasyPrivacy filter rules",
        &mut eval.tracker_matches,
        &mut findings,
        &mut checks,
    );

    (
        eval,
        AnalyserResult {
            dwarf_id: DwarfId::Browser,
            findings,
            checks,
        },
    )
}

fn eval_single_list(
    list: Option<&AdblockFilterList>,
    resource_urls: &[String],
    rule_id: &str,
    title_prefix: &str,
    out_matches: &mut Vec<String>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(list) = list else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(rule_id.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "opt-in filter list not supplied".to_owned(),
        });
        return;
    };

    for url in resource_urls {
        if list.matches_url(url) && !out_matches.contains(url) {
            out_matches.push(url.clone());
        }
    }

    if out_matches.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(rule_id.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(rule_id.to_owned()),
            category: FindingCategory::Browser,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("{title_prefix} ({})", out_matches.len()),
            summary: format!(
                "{} subresource URL(s) matched opt-in filter list rules (for example `{}`).",
                out_matches.len(),
                out_matches[0]
            ),
            evidence_refs: out_matches
                .iter()
                .take(5)
                .map(|u| EvidenceRef::new(EvidenceSource::BrowserRuntime, u.clone()))
                .collect(),
            remediation: Some(
                "Review third-party ad/tracker scripts for consent gating and performance impact."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(rule_id.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_easylist_and_respects_exceptions() {
        let easylist = AdblockFilterList::parse(
            "! Title: Custom test list\n\
             ||doubleclick.net^\n\
             /ads/banner.js\n\
             @@||allowed.doubleclick.net^\n",
        );
        let easyprivacy = AdblockFilterList::parse("||tracker.example.com^\n");
        let urls = vec![
            "https://ad.doubleclick.net/tag.js".to_owned(),
            "https://allowed.doubleclick.net/safe.js".to_owned(),
            "https://tracker.example.com/collect".to_owned(),
            "https://example.com/app.js".to_owned(),
        ];

        let (eval, res) = evaluate_adblock_lists(Some(&easylist), Some(&easyprivacy), &urls);
        assert_eq!(eval.ad_matches, vec!["https://ad.doubleclick.net/tag.js"]);
        assert_eq!(
            eval.tracker_matches,
            vec!["https://tracker.example.com/collect"]
        );
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_ADBLOCK_AD_RESOURCE));
        assert!(ids.contains(&RULE_ADBLOCK_TRACKER));
    }
}
