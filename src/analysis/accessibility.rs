//! `ZugänglichkeitsZwerg` — Phase 1 source-level accessibility checks.
//!
//! Evaluates statically verifiable accessibility requirements over
//! [`DocumentObservations`] and explicitly marks checks that require Level 2
//! (Rendered DOM / accessibility tree) or Level 3 (Behavioural) evidence as
//! unavailable. Automated checks are never presented as proof of WCAG or legal
//! compliance.

use crate::analysis::document::DocumentObservations;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, AxeEvidence, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel,
    EvidenceRef, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind, RuleId,
    Severity,
};

const RULE_DOC_LANG: &str = "a11y.doc.lang";
const RULE_IMAGE_ALT: &str = "a11y.images.alt";
const RULE_FORM_LABELS: &str = "a11y.forms.labels";
const RULE_ARIA_REFS: &str = "a11y.aria.broken_references";
const RULE_INTERACTIVE_NAMES: &str = "a11y.interactive.accessible_name";
const RULE_RENDERED_AXE: &str = "a11y.rendered.contrast_and_axe";
const RULE_BEHAVIOURAL: &str = "a11y.behavioural.keyboard_and_focus";

/// Source-level rule identifiers owned by `ZugänglichkeitsZwerg`.
pub const SOURCE_RULES: &[&str] = &[
    RULE_DOC_LANG,
    RULE_IMAGE_ALT,
    RULE_FORM_LABELS,
    RULE_ARIA_REFS,
    RULE_INTERACTIVE_NAMES,
];

/// Evaluates source-level accessibility checks and records higher-level gaps.
#[must_use]
pub fn analyse(obs: &DocumentObservations) -> AnalyserResult {
    analyse_with_axe(obs, &CollectorOutcome::default())
}

/// Evaluates source-level accessibility checks together with optional Level 2
/// `axe-core` evidence, while explicitly marking Level 3 behavioural checks
/// as unavailable.
#[must_use]
pub fn analyse_with_axe(
    obs: &DocumentObservations,
    axe: &CollectorOutcome<AxeEvidence>,
) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_doc_lang(obs, &mut findings, &mut checks);
    check_image_alt(obs, &mut findings, &mut checks);
    check_form_labels(obs, &mut findings, &mut checks);
    check_aria_references(obs, &mut findings, &mut checks);
    check_interactive_names(obs, &mut findings, &mut checks);

    check_axe_violations(axe, &mut findings, &mut checks);
    checks.push(CheckStatus::Unavailable {
        rule_id: RuleId(RULE_BEHAVIOURAL.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
        reason:
            "Keyboard navigation and focus management require Level 3 behavioural browser testing"
                .to_owned(),
    });

    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings,
        checks,
    }
}

/// Evaluates only Level 2 `axe-core` evidence without re-running source HTML checks.
#[must_use]
pub fn analyse_axe_only(axe: &CollectorOutcome<AxeEvidence>) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();
    check_axe_violations(axe, &mut findings, &mut checks);
    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings,
        checks,
    }
}

fn check_axe_violations(
    axe: &CollectorOutcome<AxeEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let data = match axe {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => {
            checks.push(CheckStatus::Unavailable {
                rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason:
                    "Colour contrast, computed styles, and axe-core require Level 2 rendered DOM evidence"
                        .to_owned(),
            });
            return;
        }
    };

    if data.violations.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    for violation in &data.violations {
        let severity = match violation.impact.as_deref() {
            Some("critical") => Severity::High,
            Some("serious" | "moderate") => Severity::Medium,
            _ => Severity::Low,
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(format!("a11y.rendered.axe.{}", violation.id)),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: format!(
                "axe-core rule '{}' failed ({} node(s))",
                violation.id, violation.nodes_count
            ),
            summary: violation.description.clone(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::AxeReport,
                format!(
                    "axe-core {} rule '{}' affected {} node(s); help: {}",
                    data.axe_version, violation.id, violation.nodes_count, violation.help_url
                ),
            )],
            remediation: Some(format!("Review axe-core guidance: {}", violation.help_url)),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

/// Builds a skipped result when source HTML is absent or truncated, preserving
/// explicit `Unavailable` markers for Level 2/3 checks.
#[must_use]
pub fn skipped_source_result(reason: &str) -> AnalyserResult {
    let mut checks: Vec<CheckStatus> = SOURCE_RULES
        .iter()
        .map(|id| CheckStatus::Skipped {
            rule_id: RuleId((*id).to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: reason.to_owned(),
        })
        .collect();
    checks.push(CheckStatus::Unavailable {
        rule_id: RuleId(RULE_RENDERED_AXE.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
        reason: "Level 2 rendered DOM evidence unavailable".to_owned(),
    });
    checks.push(CheckStatus::Unavailable {
        rule_id: RuleId(RULE_BEHAVIOURAL.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
        reason: "Level 3 behavioural evidence unavailable".to_owned(),
    });
    AnalyserResult {
        dwarf_id: DwarfId::Zugaenglichkeits,
        findings: Vec::new(),
        checks,
    }
}

fn check_doc_lang(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.html_lang.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing <html lang> attribute".to_owned(),
            summary: "Document root `<html>` lacks a non-empty `lang` attribute for assistive technologies.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "html.lang=absent_or_empty",
            )],
            remediation: Some("Set a valid BCP 47 language tag on `<html>`, e.g. `<html lang=\"en-GB\">`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DOC_LANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_image_alt(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let missing_count = obs.images.iter().filter(|img| img.alt.is_none()).count();
    if missing_count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Images missing alt attribute ({missing_count})"),
            summary: format!(
                "{missing_count} of {} `<img>` elements lack an `alt` attribute (use `alt=\"\"` for decorative images).",
                obs.images.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("images_missing_alt={missing_count}"),
            )],
            remediation: Some(
                "Add descriptive `alt` text to informative images or `alt=\"\"` to decorative ones."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IMAGE_ALT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_form_labels(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let unlabelled = obs
        .form_controls
        .iter()
        .filter(|ctrl| {
            let has_for_label = ctrl
                .id
                .as_ref()
                .is_some_and(|id| obs.label_for_ids.contains(id));
            !ctrl.has_wrapping_label
                && !has_for_label
                && ctrl.aria_label.is_none()
                && ctrl.aria_labelledby.is_none()
        })
        .count();

    if unlabelled == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::High,
            confidence: Confidence::Medium,
            title: format!("Potentially unlabelled form controls ({unlabelled})"),
            summary: format!(
                "{unlabelled} form controls lack a matching `<label>`, `aria-label`, or `aria-labelledby`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("unlabelled_controls={unlabelled}"),
            )],
            remediation: Some(
                "Associate each form control with a `<label for=\"...\">` or ARIA label."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FORM_LABELS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_aria_references(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut broken = Vec::new();
    for aria_ref in &obs.aria_refs {
        for target_id in &aria_ref.referenced_ids {
            if !obs.all_ids.contains(target_id) {
                broken.push(format!(
                    "{}[{}]={target_id}",
                    aria_ref.element_tag, aria_ref.attr_name
                ));
            }
        }
    }

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let sample = broken
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Unresolved ARIA ID references ({})", broken.len()),
            summary: format!("ARIA reference attributes point to missing IDs: {sample}."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("broken_aria_refs={sample}"),
            )],
            remediation: Some(
                "Ensure all IDs referenced by `aria-labelledby`/`aria-describedby` exist."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ARIA_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_interactive_names(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let missing = obs.links_missing_accessible_name + obs.buttons_missing_accessible_name;
    if missing == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            category: FindingCategory::Accessibility,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Interactive controls potentially missing accessible names ({missing})"),
            summary: format!(
                "Observed {} `<a href>` and {} `<button>` elements without visible text or `aria-label`/`title`.",
                obs.links_missing_accessible_name, obs.buttons_missing_accessible_name
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "empty_links={},empty_buttons={}",
                    obs.links_missing_accessible_name, obs.buttons_missing_accessible_name
                ),
            )],
            remediation: Some(
                "Provide text content, `aria-label`, or descriptive `img[alt]` inside links and buttons."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INTERACTIVE_NAMES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_missing_lang_alt_label_and_broken_aria_ref() {
        let html = r#"<html><body>
            <img src="/logo.png">
            <input type="text" id="name">
            <button aria-labelledby="missing-id"></button>
            <a href="/empty"></a>
        </body></html>"#;

        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_DOC_LANG));
        assert!(ids.contains(&RULE_IMAGE_ALT));
        assert!(ids.contains(&RULE_FORM_LABELS));
        assert!(ids.contains(&RULE_ARIA_REFS));
        assert!(ids.contains(&RULE_INTERACTIVE_NAMES));
        assert!(res.checks.iter().any(|c| {
            matches!(
                c,
                CheckStatus::Unavailable {
                    evidence_level: EvidenceLevel::Rendered,
                    ..
                }
            )
        }));
    }

    #[test]
    fn allows_decorative_empty_alt() {
        let html = r#"<html lang="en"><body><img src="/dot.png" alt=""></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(!res.findings.iter().any(|f| f.rule_id.0 == RULE_IMAGE_ALT));
    }

    #[test]
    fn emits_findings_for_axe_violations_and_passes_when_clean() {
        use crate::domain::AxeViolation;
        let html = r#"<html lang="en"><body><p>Hello</p></body></html>"#;
        let obs = DocumentObservations::from_html(html);

        let clean_axe = CollectorOutcome::Captured {
            data: AxeEvidence {
                axe_version: "4.10.0".to_owned(),
                violations: Vec::new(),
                passes_count: 10,
                incomplete_count: 0,
            },
        };
        let clean_res = analyse_with_axe(&obs, &clean_axe);
        assert!(clean_res.checks.iter().any(|c| {
            matches!(c, CheckStatus::Passed { rule_id, .. } if rule_id.0 == RULE_RENDERED_AXE)
        }));

        let failing_axe = CollectorOutcome::Captured {
            data: AxeEvidence {
                axe_version: "4.10.0".to_owned(),
                violations: vec![AxeViolation {
                    id: "color-contrast".to_owned(),
                    impact: Some("serious".to_owned()),
                    description: "Elements must meet minimum color contrast ratio thresholds"
                        .to_owned(),
                    help_url: "https://dequeuniversity.com/rules/axe/4.10/color-contrast"
                        .to_owned(),
                    nodes_count: 3,
                }],
                passes_count: 9,
                incomplete_count: 0,
            },
        };
        let failing_res = analyse_with_axe(&obs, &failing_axe);
        assert!(
            failing_res
                .findings
                .iter()
                .any(|f| f.rule_id.0 == "a11y.rendered.axe.color-contrast"
                    && !f.evidence_refs.is_empty())
        );
    }
}
