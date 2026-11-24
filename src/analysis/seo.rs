//! `SEOZwerg` — deterministic HTML metadata and heading-structure checks.

use scraper::{Html, Selector};

use crate::analysis::{header_value, require_http, skip_all};
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceRef, EvidenceSnapshot, Finding,
    FindingCategory, FindingKind, RuleId, Severity,
};

const ZWERG_NAME: &str = "SEOZwerg";
const RULE_TITLE: &str = "seo.meta.title";
const RULE_DESCRIPTION: &str = "seo.meta.description";
const RULE_CANONICAL: &str = "seo.meta.canonical";
const RULE_H1: &str = "seo.structure.h1";

const ALL_RULES: &[&str] = &[RULE_TITLE, RULE_DESCRIPTION, RULE_CANONICAL, RULE_H1];

/// Evaluates basic HTML SEO signals over `snapshot`.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => return skip_all(ZWERG_NAME, ALL_RULES, &reason),
    };

    let is_html = header_value(http, "content-type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"))
        || http.body_text.trim_start().starts_with('<');

    if !is_html {
        return skip_all(
            ZWERG_NAME,
            ALL_RULES,
            "response is not HTML; skipping HTML SEO checks",
        );
    }

    let doc = Html::parse_document(&http.body_text);
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_title(&doc, &mut findings, &mut checks);
    check_description(&doc, &mut findings, &mut checks);
    check_canonical(&doc, &mut findings, &mut checks);
    check_h1(&doc, &mut findings, &mut checks);

    AnalyserResult {
        zwerg_name: ZWERG_NAME.to_owned(),
        findings,
        checks,
    }
}

fn check_title(doc: &Html, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let title_text = Selector::parse("title")
        .ok()
        .and_then(|sel| doc.select(&sel).next())
        .map(|el| el.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    if title_text.is_empty() {
        findings.push(Finding {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Missing or empty <title> element".to_owned(),
            summary: "Document does not contain a non-empty <title> tag.".to_owned(),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: "title=absent_or_empty".to_owned(),
            }],
            remediation: Some("Add a unique, descriptive <title> (10–60 characters).".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
        });
    } else if title_text.chars().count() < 10 || title_text.chars().count() > 60 {
        findings.push(Finding {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!(
                "Suboptimal <title> length ({} chars)",
                title_text.chars().count()
            ),
            summary: format!("Title `{title_text}` is outside the typical 10–60 character range."),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: format!("title_chars={}", title_text.chars().count()),
            }],
            remediation: Some(
                "Keep <title> concise and descriptive (10–60 characters).".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
        });
    }
}

fn check_description(doc: &Html, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let desc = Selector::parse(r#"meta[name="description"]"#)
        .ok()
        .and_then(|sel| doc.select(&sel).next())
        .and_then(|el| el.value().attr("content"))
        .map_or("", str::trim);

    if desc.is_empty() {
        findings.push(Finding {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing or empty meta description".to_owned(),
            summary: "Document does not include a non-empty <meta name=\"description\">."
                .to_owned(),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: "meta.description=absent_or_empty".to_owned(),
            }],
            remediation: Some("Add a concise <meta name=\"description\"> summary.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
        });
    }
}

fn check_canonical(doc: &Html, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let canonical = Selector::parse(r#"link[rel="canonical"]"#)
        .ok()
        .and_then(|sel| doc.select(&sel).next())
        .and_then(|el| el.value().attr("href"))
        .map_or("", str::trim);

    if canonical.is_empty() {
        findings.push(Finding {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Missing canonical link tag".to_owned(),
            summary: "Document does not specify `<link rel=\"canonical\" href=\"...\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: "link.canonical=absent".to_owned(),
            }],
            remediation: Some(
                "Add a canonical link element pointing to the preferred URL.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
        });
    }
}

fn check_h1(doc: &Html, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let h1_count = Selector::parse("h1")
        .ok()
        .map_or(0, |sel| doc.select(&sel).count());

    if h1_count == 0 {
        findings.push(Finding {
            rule_id: RuleId(RULE_H1.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing <h1> heading".to_owned(),
            summary: "Document does not contain an <h1> primary heading.".to_owned(),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: "h1_count=0".to_owned(),
            }],
            remediation: Some(
                "Include one primary <h1> heading describing the page topic.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_H1.to_owned()),
        });
    } else if h1_count > 1 {
        findings.push(Finding {
            rule_id: RuleId(RULE_H1.to_owned()),
            category: FindingCategory::Seo,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Multiple <h1> headings ({h1_count})"),
            summary: format!(
                "Document contains {h1_count} <h1> elements; prefer a single primary heading."
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.body".to_owned(),
                detail: format!("h1_count={h1_count}"),
            }],
            remediation: Some(
                "Use a single <h1> for the main heading and <h2>–<h6> for subsections.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_H1.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_H1.to_owned()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, CollectorOutcome, HttpEvidence, HttpHeader, Measurement, TargetPolicy,
    };

    fn html_snapshot(content_type: &str, body: &str) -> EvidenceSnapshot {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-type".to_owned(),
                        value: content_type.to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 12,
                        unit: "ms".to_owned(),
                    },
                    body_bytes: body.len(),
                    body_truncated: false,
                    body_text: body.to_owned(),
                },
            },
        }
    }

    #[test]
    fn passes_for_well_formed_html() {
        let html = r#"<!doctype html><html><head>
            <title>NetzZwergenWacht Audit Engine</title>
            <meta name="description" content="External web auditing engine.">
            <link rel="canonical" href="https://example.com/">
        </head><body><h1>Welcome</h1></body></html>"#;

        let result = analyse(&html_snapshot("text/html; charset=utf-8", html));
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.checks.len(), ALL_RULES.len());
    }

    #[test]
    fn skips_non_html_responses() {
        let result = analyse(&html_snapshot("application/json", r#"{"ok":true}"#));
        assert_eq!(result.findings.len(), 0);
        assert!(
            result
                .checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }
}
