//! `GestaltungsZwerg` — Level 2 visual layout and asset integrity checks.
//!
//! Analyses per-viewport [`BrowserEvidence`](crate::domain::BrowserEvidence)
//! observations for horizontal overflow and broken images (`naturalWidth == 0`).

use crate::analysis::skip_all;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    RuleId, Severity,
};

const RULE_HORIZONTAL_OVERFLOW: &str = "vis.layout.horizontal_overflow";
const RULE_BROKEN_IMAGES: &str = "vis.assets.broken_images";

/// All Level 2 rules owned by `GestaltungsZwerg`.
pub const ALL_RULES: &[&str] = &[RULE_HORIZONTAL_OVERFLOW, RULE_BROKEN_IMAGES];

/// Evaluates rendered viewport layout and image integrity observations.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } => {
            return skip_all(
                DwarfId::Gestaltungs,
                ALL_RULES,
                EvidenceLevel::Rendered,
                reason,
            );
        }
        CollectorOutcome::Failed { error } => {
            return skip_all(
                DwarfId::Gestaltungs,
                ALL_RULES,
                EvidenceLevel::Rendered,
                error,
            );
        }
    };

    if browser.viewports.is_empty() {
        return skip_all(
            DwarfId::Gestaltungs,
            ALL_RULES,
            EvidenceLevel::Rendered,
            "no browser viewport observations captured",
        );
    }

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_horizontal_overflow(browser, &mut findings, &mut checks);
    check_broken_images(browser, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Gestaltungs,
        findings,
        checks,
    }
}

fn check_horizontal_overflow(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let overflowing: Vec<_> = browser
        .viewports
        .iter()
        .filter(|vp| vp.has_horizontal_overflow)
        .collect();

    if overflowing.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let evidence_refs = overflowing
        .iter()
        .map(|vp| {
            EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!(
                    "viewport '{}' ({}x{}) reported horizontal overflow",
                    vp.viewport_name, vp.width, vp.height
                ),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
        category: FindingCategory::Visual,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!(
            "Horizontal layout overflow detected in {} viewport(s)",
            overflowing.len()
        ),
        summary: format!(
            "Rendered document scrollWidth exceeded viewport innerWidth in {} viewport(s).",
            overflowing.len()
        ),
        evidence_refs,
        remediation: Some(
            "Constrained wide elements with responsive CSS (for example max-width: 100% or overflow-x handling)."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_HORIZONTAL_OVERFLOW.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

fn check_broken_images(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let broken: Vec<_> = browser
        .viewports
        .iter()
        .flat_map(|vp| {
            vp.broken_images
                .iter()
                .filter(|img| img.natural_width == 0)
                .map(move |img| (vp.viewport_name.as_str(), img.src.as_str()))
        })
        .collect();

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let evidence_refs = broken
        .iter()
        .take(5)
        .map(|(vp_name, src)| {
            EvidenceRef::new(
                EvidenceSource::VisualLayout,
                format!("viewport '{vp_name}': broken image '{src}' (naturalWidth = 0)"),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
        category: FindingCategory::Visual,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("{} broken rendered image(s) detected", broken.len()),
        summary: format!(
            "Rendered DOM reported {} image(s) with naturalWidth == 0.",
            broken.len()
        ),
        evidence_refs,
        remediation: Some(
            "Verify image URLs, MIME types, and responsive srcset candidates resolve cleanly."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_BROKEN_IMAGES.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, BrokenImageObs, BrowserEvidence, TargetPolicy, ViewportLayoutObs,
    };

    fn base_snapshot(browser: CollectorOutcome<BrowserEvidence>) -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser,
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    #[test]
    fn skips_when_browser_evidence_missing() {
        let snap = base_snapshot(CollectorOutcome::default());
        let res = analyse(&snap);
        assert_eq!(res.dwarf_id, DwarfId::Gestaltungs);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }

    #[test]
    fn passes_when_viewports_are_clean() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: None,
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    has_horizontal_overflow: false,
                    broken_images: Vec::new(),
                    screenshot_path: None,
                }],
                provenance: None,
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), 2);
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. }))
        );
    }

    #[test]
    fn detects_horizontal_overflow_and_broken_images() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: None,
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                viewports: vec![ViewportLayoutObs {
                    viewport_name: "mobile".to_owned(),
                    width: 390,
                    height: 844,
                    has_horizontal_overflow: true,
                    broken_images: vec![BrokenImageObs {
                        src: "https://example.com/hero.webp".to_owned(),
                        natural_width: 0,
                    }],
                    screenshot_path: None,
                }],
                provenance: None,
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 2);
        assert!(res.findings.iter().all(|f| !f.evidence_refs.is_empty()));
    }
}
