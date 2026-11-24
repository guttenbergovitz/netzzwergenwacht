//! `SuchZwerg` — search visibility, metadata, and indexability checks.
//!
//! Consumes shared [`DocumentObservations`] and HTTP headers; heading hierarchy
//! and structural semantics belong to `StrukturZwerg`.

use crate::analysis::document::DocumentObservations;
use crate::analysis::header_value;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, RuleId, Severity,
};

const RULE_TITLE: &str = "such.meta.title";
const RULE_DESCRIPTION: &str = "such.meta.description";
const RULE_CANONICAL: &str = "such.meta.canonical";
const RULE_ROBOTS: &str = "such.indexability.robots";

/// All rule identifiers owned by `SuchZwerg`.
pub const ALL_RULES: &[&str] = &[RULE_TITLE, RULE_DESCRIPTION, RULE_CANONICAL, RULE_ROBOTS];

/// Evaluates search metadata and indexability signals over `http` and `obs`.
#[must_use]
pub fn analyse(http: &HttpEvidence, obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_title(obs, &mut findings, &mut checks);
    check_description(obs, &mut findings, &mut checks);
    check_canonical(obs, &mut findings, &mut checks);
    check_robots(http, obs, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Such,
        findings,
        checks,
    }
}

fn check_title(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(title) = obs.title.as_deref() else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Missing or empty <title> element".to_owned(),
            summary: "Document does not contain a non-empty `<title>` tag.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "title=absent_or_empty",
            )],
            remediation: Some("Add a unique, descriptive `<title>` (10–60 characters).".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let len = title.chars().count();
    if (10..=60).contains(&len) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Suboptimal <title> length ({len} chars)"),
            summary: format!("Title `{title}` is outside the typical 10–60 character range."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("title_chars={len}"),
            )],
            remediation: Some(
                "Keep `<title>` concise and descriptive (10–60 characters).".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_description(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.meta_description.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing or empty meta description".to_owned(),
            summary: "Document does not include a non-empty `<meta name=\"description\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "meta.description=absent_or_empty",
            )],
            remediation: Some("Add a concise `<meta name=\"description\">` summary.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_canonical(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.canonical_url.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Missing canonical link tag".to_owned(),
            summary: "Document does not specify `<link rel=\"canonical\" href=\"...\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "link.canonical=absent",
            )],
            remediation: Some(
                "Add a canonical link element pointing to the preferred URL.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_robots(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let meta_noindex = obs
        .meta_robots
        .as_deref()
        .is_some_and(|v| v.to_ascii_lowercase().contains("noindex"));
    let header_noindex = header_value(http, "x-robots-tag")
        .is_some_and(|v| v.to_ascii_lowercase().contains("noindex"));

    if meta_noindex || header_noindex {
        let source = if header_noindex {
            EvidenceSource::HttpHeaders
        } else {
            EvidenceSource::HttpBody
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Page marked noindex".to_owned(),
            summary:
                "Robots directive (`meta[name=\"robots\"]` or `X-Robots-Tag`) includes `noindex`."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(source, "robots=noindex")],
            remediation: Some(
                "Verify `noindex` is intentional if this URL should appear in search results."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, HttpHeader, Measurement, MeasurementUnit, TargetPolicy};

    fn http_with_html(html: &str) -> (HttpEvidence, DocumentObservations) {
        let _ = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let http = HttpEvidence {
            final_url: "https://example.com/".to_owned(),
            status_code: 200,
            redirect_chain: Vec::new(),
            headers: vec![HttpHeader {
                name: "content-type".to_owned(),
                value: "text/html".to_owned(),
            }],
            elapsed_ms: Measurement::Measured {
                value: 10,
                unit: MeasurementUnit::Milliseconds,
            },
            body_bytes: html.len(),
            body_truncated: false,
            body_text: html.to_owned(),
        };
        let obs = DocumentObservations::from_html(html);
        (http, obs)
    }

    #[test]
    fn passes_for_valid_search_metadata() {
        let html = r#"<html><head>
            <title>NetzZwergenWacht Audit Engine</title>
            <meta name="description" content="External web auditing engine.">
            <link rel="canonical" href="https://example.com/">
        </head><body></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
    }
}
