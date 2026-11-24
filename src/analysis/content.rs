//! `InhaltsZwerg` — Phase 1 content quality and freshness checks.
//!
//! Consumes shared [`DocumentObservations`] and HTTP headers without
//! duplicating HTML parsing.

use crate::analysis::document::DocumentObservations;
use crate::analysis::header_value;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, RuleId, Severity,
};

const RULE_THIN_CONTENT: &str = "inh.content.thin_content";
const RULE_FRESHNESS_HEADERS: &str = "inh.content.freshness_headers";

/// All rule identifiers owned by `InhaltsZwerg`.
pub const ALL_RULES: &[&str] = &[RULE_THIN_CONTENT, RULE_FRESHNESS_HEADERS];

/// Evaluates visible word count and freshness header signals over `http` and `obs`.
#[must_use]
pub fn analyse(http: &HttpEvidence, obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_thin_content(obs, &mut findings, &mut checks);
    check_freshness_headers(http, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Inhalts,
        findings,
        checks,
    }
}

fn check_thin_content(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 30 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Very thin visible content ({} words)", obs.visible_word_count),
            summary: format!(
                "Extracted only {} visible words ({} chars) from source HTML body.",
                obs.visible_word_count, obs.visible_char_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("visible_word_count={}", obs.visible_word_count),
            )],
            remediation: Some(
                "Ensure substantive content is rendered in HTML or verify if content is client-side rendered."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if obs.visible_word_count < 100 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Low,
            title: format!("Limited visible content ({} words)", obs.visible_word_count),
            summary: format!(
                "Extracted {} visible words from source HTML body (< 100 words).",
                obs.visible_word_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("visible_word_count={}", obs.visible_word_count),
            )],
            remediation: Some(
                "Consider expanding page copy if this is an informational page.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_freshness_headers(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if header_value(http, "last-modified").is_some_and(|v| !v.trim().is_empty()) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "No Last-Modified header observed".to_owned(),
            summary: "HTTP response did not include a `Last-Modified` freshness timestamp."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "last-modified=absent",
            )],
            remediation: Some(
                "Expose `Last-Modified` where content modification timestamps are meaningful."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, HttpHeader, Measurement, MeasurementUnit, TargetPolicy};

    fn http_with_body(
        body: &str,
        headers: Vec<(&str, &str)>,
    ) -> (HttpEvidence, DocumentObservations) {
        let _ = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let http = HttpEvidence {
            final_url: "https://example.com/".to_owned(),
            status_code: 200,
            redirect_chain: Vec::new(),
            headers: headers
                .into_iter()
                .map(|(n, v)| HttpHeader {
                    name: n.to_owned(),
                    value: v.to_owned(),
                })
                .collect(),
            elapsed_ms: Measurement::Measured {
                value: 10,
                unit: MeasurementUnit::Milliseconds,
            },
            body_bytes: body.len(),
            body_truncated: false,
            body_text: body.to_owned(),
        };
        let obs = DocumentObservations::from_html(body);
        (http, obs)
    }

    #[test]
    fn flags_very_thin_content_and_ignores_scripts() {
        let html = "<html><body><script>var x = 'one two three four five';</script><p>Hello world</p></body></html>";
        let (http, obs) = http_with_body(html, Vec::new());
        assert_eq!(obs.visible_word_count, 2);
        let res = analyse(&http, &obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_THIN_CONTENT && f.severity == Severity::Medium)
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_FRESHNESS_HEADERS)
        );
    }

    #[test]
    fn passes_for_substantive_content_with_last_modified() {
        let words = vec!["word"; 120].join(" ");
        let html = format!("<html><body><main><p>{words}</p></main></body></html>");
        let (http, obs) = http_with_body(
            &html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        assert_eq!(res.findings.len(), 0);
    }
}
