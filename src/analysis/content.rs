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
const RULE_PLACEHOLDER: &str = "inh.content.placeholder_text";
const RULE_TITLE_H1_MATCH: &str = "inh.content.title_h1_duplication";
const RULE_LEGAL_LINKS: &str = "inh.trust.legal_links";

/// All rule identifiers owned by `InhaltsZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_THIN_CONTENT,
    RULE_FRESHNESS_HEADERS,
    RULE_PLACEHOLDER,
    RULE_TITLE_H1_MATCH,
    RULE_LEGAL_LINKS,
];

/// Evaluates visible word count, freshness headers, and content quality signals over `http` and `obs`.
#[must_use]
pub fn analyse(http: &HttpEvidence, obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_thin_content(obs, &mut findings, &mut checks);
    check_freshness_headers(http, &mut findings, &mut checks);
    check_placeholder_text(obs, &mut findings, &mut checks);
    check_title_h1_duplication(obs, &mut findings, &mut checks);
    check_legal_links(obs, &mut findings, &mut checks);

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

fn check_placeholder_text(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let lower = obs.visible_text_sample.to_ascii_lowercase();
    let markers = [
        "lorem ipsum",
        "dolor sit amet",
        "coming soon",
        "under construction",
    ];
    let matched: Vec<&str> = markers
        .iter()
        .copied()
        .filter(|m| lower.contains(m))
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Placeholder text detected in visible content".to_owned(),
            summary: format!("Matched placeholder phrase(s): {}", matched.join(", ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("placeholder_matches={}", matched.join(",")),
            )],
            remediation: Some(
                "Replace placeholder copy with final production content before release.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_title_h1_duplication(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(title) = obs.title.as_deref() else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "title missing".to_owned(),
        });
        return;
    };
    let Some(h1) = obs.headings.iter().find(|h| h.level == 1) else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "h1 missing".to_owned(),
        });
        return;
    };

    if title.eq_ignore_ascii_case(h1.text.trim()) {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Page <title> and <h1> are identical".to_owned(),
            summary: format!(
                "`<title>` and primary `<h1>` both read `{}`.",
                h1.text.trim()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "title_equals_h1=true",
            )],
            remediation: Some(
                "Differentiate `<title>` (search snippet) from `<h1>` (on-page headline) where helpful."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_legal_links(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 100 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page has < 100 visible words".to_owned(),
        });
        return;
    }

    let has_legal_or_contact = obs.links.iter().any(|l| {
        let combined = format!(
            "{} {}",
            l.href.to_ascii_lowercase(),
            l.text.to_ascii_lowercase()
        );
        [
            "privacy",
            "datenschutz",
            "impressum",
            "imprint",
            "terms",
            "legal",
            "contact",
            "kontakt",
        ]
        .iter()
        .any(|kw| combined.contains(kw))
    });

    if has_legal_or_contact {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "No legal, privacy, or contact links detected".to_owned(),
            summary:
                "No links matching privacy, imprint/legal, terms, or contact were found on this page."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("links_checked={}", obs.links.len()),
            )],
            remediation: Some(
                "Expose clear footer links to privacy policy, legal notice/imprint, and contact."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
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
        let html = format!(
            "<html><body><main><p>{words}</p></main><footer><a href=\"/privacy\">Privacy</a></footer></body></html>"
        );
        let (http, obs) = http_with_body(
            &html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        assert_eq!(res.findings.len(), 0);
    }

    #[test]
    fn flags_placeholder_title_h1_match_and_missing_legal_links() {
        let words = vec!["content"; 110].join(" ");
        let html = format!(
            "<html><head><title>Same Headline</title></head><body><h1>Same Headline</h1><p>Lorem ipsum {words}</p></body></html>"
        );
        let (http, obs) = http_with_body(
            &html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_PLACEHOLDER));
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_TITLE_H1_MATCH)
        );
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_LEGAL_LINKS));
    }
}
