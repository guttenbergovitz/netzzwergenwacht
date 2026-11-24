//! `StrukturZwerg` — semantic HTML5 structure and document integrity checks.
//!
//! Consumes shared [`DocumentObservations`] extracted from an HTML5 parser
//! without claiming to validate original un-repaired HTML syntax.

use crate::analysis::document::DocumentObservations;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, RuleId, Severity,
};

const RULE_DUPLICATE_IDS: &str = "str.doc.duplicate_ids";
const RULE_HEADING_HIERARCHY: &str = "str.headings.hierarchy";
const RULE_LANDMARKS: &str = "str.landmarks.presence";
const RULE_INTERACTIVE_SEMANTICS: &str = "str.interactive.native_semantics";
const RULE_CONTAINER_RATIO: &str = "str.doc.container_ratio";

/// All rule identifiers owned by `StrukturZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_DUPLICATE_IDS,
    RULE_HEADING_HIERARCHY,
    RULE_LANDMARKS,
    RULE_INTERACTIVE_SEMANTICS,
    RULE_CONTAINER_RATIO,
];

/// Evaluates semantic HTML structure and element integrity over `obs`.
#[must_use]
pub fn analyse(obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_duplicate_ids(obs, &mut findings, &mut checks);
    check_heading_hierarchy(obs, &mut findings, &mut checks);
    check_landmarks(obs, &mut findings, &mut checks);
    check_interactive_semantics(obs, &mut findings, &mut checks);
    check_container_ratio(obs, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Struktur,
        findings,
        checks,
    }
}

fn check_duplicate_ids(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.duplicate_ids.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let sample = obs
            .duplicate_ids
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Duplicate HTML id attributes ({})", obs.duplicate_ids.len()),
            summary: format!(
                "Element `id` attributes must be unique within a document; duplicates found: {sample}."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("duplicate_ids={sample}"),
            )],
            remediation: Some("Ensure every `id` attribute is unique across the document.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_heading_hierarchy(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let h1_count = obs.headings.iter().filter(|h| h.level == 1).count();
    let mut skipped_jumps = Vec::new();
    for pair in obs.headings.windows(2) {
        if pair[1].level > pair[0].level + 1 {
            skipped_jumps.push(format!("h{}->h{}", pair[0].level, pair[1].level));
        }
    }

    if h1_count == 1 && skipped_jumps.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    if h1_count == 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing primary <h1> heading".to_owned(),
            summary: "Document does not contain an <h1> heading.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpBody, "h1_count=0")],
            remediation: Some("Provide a single primary <h1> describing the document.".to_owned()),
        });
    } else if h1_count > 1 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Multiple <h1> headings ({h1_count})"),
            summary: format!(
                "Document contains {h1_count} <h1> elements; prefer a single primary heading."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("h1_count={h1_count}"),
            )],
            remediation: Some("Use a single <h1> and nest subsections with <h2>–<h6>.".to_owned()),
        });
    }

    if !skipped_jumps.is_empty() {
        let jumps = skipped_jumps.join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Skipped heading hierarchy levels".to_owned(),
            summary: format!("Heading outline skips intermediate levels: {jumps}."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("skipped_jumps={jumps}"),
            )],
            remediation: Some(
                "Maintain sequential heading levels without skipping ranks.".to_owned(),
            ),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_landmarks(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.landmarks.main_count == 1 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!(
                "Expected one <main> landmark (found {})",
                obs.landmarks.main_count
            ),
            summary: format!(
                "Observed landmarks: main={}, nav={}, header={}, footer={}.",
                obs.landmarks.main_count,
                obs.landmarks.nav_count,
                obs.landmarks.header_count,
                obs.landmarks.footer_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("main_count={}", obs.landmarks.main_count),
            )],
            remediation: Some(
                "Wrap primary page content in a single `<main>` landmark element.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_interactive_semantics(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let total_issues =
        obs.links_without_href + obs.clickable_generic_containers + obs.nested_interactive_count;

    if total_issues == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    if obs.clickable_generic_containers > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Generic <div>/<span> used with onclick ({})",
                obs.clickable_generic_containers
            ),
            summary: "Interactive click handlers on generic containers lack native keyboard and role semantics.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("clickable_generic_containers={}", obs.clickable_generic_containers),
            )],
            remediation: Some("Use native `<button>` or `<a href>` elements instead of clickable <div>/<span>.".to_owned()),
        });
    }

    if obs.nested_interactive_count > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Nested interactive elements ({})", obs.nested_interactive_count),
            summary: "Interactive elements (`<a>`, `<button>`, form controls) must not be nested inside each other.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("nested_interactive_count={}", obs.nested_interactive_count),
            )],
            remediation: Some("Separate nested links, buttons, and inputs into sibling elements.".to_owned()),
        });
    }

    if obs.links_without_href > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("<a> elements without href ({})", obs.links_without_href),
            summary:
                "Anchor tags without `href` behave as non-focusable placeholders rather than links."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("links_without_href={}", obs.links_without_href),
            )],
            remediation: Some(
                "Use `<button type=\"button\">` for actions or supply a valid `href`.".to_owned(),
            ),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_container_ratio(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.total_elements < 20 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Too few elements (< 20) to evaluate generic container ratio".to_owned(),
        });
        return;
    }

    let generic = obs.div_count + obs.span_count;
    // Use integer cross-multiplication to avoid floating-point casts.
    if generic * 100 > obs.total_elements * 75 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "High proportion of generic <div>/<span> containers".to_owned(),
            summary: format!(
                "{generic} of {} elements ({:.0}%) are generic <div>/<span> containers; verify semantic elements are used where appropriate.",
                obs.total_elements,
                (generic * 100) / obs.total_elements
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("generic={generic},total={}", obs.total_elements),
            )],
            remediation: Some(
                "Review whether sectioning/landmark elements (`<section>`, `<article>`, `<nav>`) fit key regions."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicate_ids_and_heading_skip() {
        let html = r#"<html><body><main>
            <h1 id="x">One</h1><h3 id="x">Skipped</h3>
        </main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_DUPLICATE_IDS)
        );
        assert!(
            res.findings
                .iter()
                .any(|f| { f.rule_id.0 == RULE_HEADING_HIERARCHY && f.title.contains("Skipped") })
        );
    }

    #[test]
    fn detects_clickable_div_and_nested_button() {
        let html = r#"<html><body><main><h1>Ok</h1>
            <div onclick="go()">Click</div>
            <a href="/a"><button>Nested</button></a>
        </main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_INTERACTIVE_SEMANTICS && f.severity == Severity::High)
        );
    }
}
