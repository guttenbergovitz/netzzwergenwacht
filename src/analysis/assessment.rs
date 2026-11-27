//! Multi-dimensional quality assessment model (Phase II §8).
//!
//! Quality is never collapsed into an arbitrary `0–100` score. Instead, each
//! quality domain receives an explicit [`DomainVerdict`] (`Pass`, `Fail`,
//! `InsufficientEvidence`, `NotApplicable`, or `Waived`) grounded in observed
//! collector outcomes, check statuses, and deterministic findings.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis::AuditReport;
use crate::brigade::DwarfId;
use crate::domain::{AnalyserResult, CheckStatus, CollectorOutcome, Severity};

/// Quality dimensions evaluated by `NetzZwergenWacht` (Phase II §8).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QualityDomain {
    /// Functional behaviour and user-facing interaction integrity.
    FunctionalIntegrity,
    /// Browser runtime stability, console/exception health, and resource loading.
    RuntimeStability,
    /// Laboratory and runtime performance characteristics.
    Performance,
    /// Automated accessibility checks (never proof of legal WCAG compliance).
    Accessibility,
    /// Layout geometry, responsive behaviour, and visual integrity.
    VisualQuality,
    /// External surface security, TLS, headers, cookies, and CSP.
    SurfaceSecurity,
    /// Consent behaviour, third-party tracking, and browser storage hygiene.
    Privacy,
    /// Content quality, localisation, media integrity, and link health.
    ContentIntegrity,
    /// Indexability, metadata, structured data, and semantic discoverability.
    Discoverability,
    /// Network availability, transport reliability, and dependency resilience.
    Reliability,
    /// Completeness and integrity of collected diagnostic evidence.
    EvidenceCoverage,
}

impl QualityDomain {
    /// All eleven Phase II quality domains in canonical display order.
    pub const ALL: [Self; 11] = [
        Self::FunctionalIntegrity,
        Self::RuntimeStability,
        Self::Performance,
        Self::Accessibility,
        Self::VisualQuality,
        Self::SurfaceSecurity,
        Self::Privacy,
        Self::ContentIntegrity,
        Self::Discoverability,
        Self::Reliability,
        Self::EvidenceCoverage,
    ];

    /// Concise human-readable label for reports and TUI panels.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FunctionalIntegrity => "Functional Integrity",
            Self::RuntimeStability => "Runtime Stability",
            Self::Performance => "Performance",
            Self::Accessibility => "Accessibility",
            Self::VisualQuality => "Visual Quality",
            Self::SurfaceSecurity => "Surface Security",
            Self::Privacy => "Privacy",
            Self::ContentIntegrity => "Content Integrity",
            Self::Discoverability => "Discoverability",
            Self::Reliability => "Reliability",
            Self::EvidenceCoverage => "Evidence Coverage",
        }
    }
}

/// Explicit verdict for a single [`QualityDomain`] or overall assessment.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DomainVerdict {
    /// No blocking defects observed and required evidence was captured.
    Pass,
    /// One or more blocking defects (`Critical` or `High`) were observed.
    Fail,
    /// Required evidence was missing, failed, skipped, or inconclusive.
    InsufficientEvidence,
    /// Domain is not applicable to the target or configured profile.
    NotApplicable,
    /// Observed defects were explicitly waived under a documented exception.
    Waived,
}

impl DomainVerdict {
    /// Short uppercase badge suitable for tables and terminal summaries.
    #[must_use]
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::InsufficientEvidence => "INSUFF",
            Self::NotApplicable => "N/A",
            Self::Waived => "WAIVED",
        }
    }
}

/// Assessment result for a single [`QualityDomain`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DomainAssessment {
    /// Evaluated quality domain.
    pub domain: QualityDomain,
    /// Explicit verdict for this domain.
    pub verdict: DomainVerdict,
    /// Count of `Critical` or `High` findings in this domain.
    pub critical_high_count: usize,
    /// Count of `Medium` findings in this domain.
    pub medium_count: usize,
    /// Count of `Low` or `Info` findings in this domain.
    pub low_info_count: usize,
    /// Number of checks skipped or unavailable in this domain.
    pub checks_unavailable: usize,
    /// Evidence-grounded explanation of the verdict.
    pub rationale: String,
}

/// Multi-dimensional quality assessment across all Phase II domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QualityAssessment {
    /// Per-domain verdicts and counts.
    pub domains: Vec<DomainAssessment>,
    /// Aggregate verdict that never hides `Fail` or `InsufficientEvidence`.
    pub overall_verdict: DomainVerdict,
    /// Blocking issues (`Critical`/`High` findings or failed required gates).
    pub blockers: Vec<String>,
    /// Explicit scope and evidence limitations.
    pub limitations: Vec<String>,
}

/// Maps an analyser specialist and optional rule prefix to a [`QualityDomain`].
#[must_use]
pub fn domain_for_rule(dwarf_id: DwarfId, rule_id: &str) -> QualityDomain {
    if rule_id.starts_with("sec.privacy") {
        return QualityDomain::Privacy;
    }
    if rule_id.starts_with("browser.interaction") || rule_id.starts_with("func.") {
        return QualityDomain::FunctionalIntegrity;
    }
    match dwarf_id {
        DwarfId::Netz => QualityDomain::Reliability,
        DwarfId::Sicherheits => QualityDomain::SurfaceSecurity,
        DwarfId::Leistungs => QualityDomain::Performance,
        DwarfId::Struktur | DwarfId::Such => QualityDomain::Discoverability,
        DwarfId::Zugaenglichkeits => QualityDomain::Accessibility,
        DwarfId::Inhalts => QualityDomain::ContentIntegrity,
        DwarfId::Gestaltungs => QualityDomain::VisualQuality,
        DwarfId::Browser => QualityDomain::RuntimeStability,
        DwarfId::Dokumentations | DwarfId::Kommandant => QualityDomain::EvidenceCoverage,
    }
}

#[derive(Default)]
struct DomainAccumulator {
    critical_high: usize,
    medium: usize,
    low_info: usize,
    passed_checks: usize,
    skipped_or_unavailable: usize,
}

/// Computes a multi-dimensional [`QualityAssessment`] from an [`AuditReport`].
#[must_use]
pub fn assess_audit_report(report: &AuditReport) -> QualityAssessment {
    let http_complete = matches!(report.http, CollectorOutcome::Captured { .. });
    let mut limitations = Vec::new();
    if !http_complete {
        limitations.push(format!(
            "Primary HTTP collection did not complete cleanly ({:?}).",
            collector_state_label(&report.http)
        ));
    }
    for l2 in &report.level2_collectors {
        if l2.state != "captured" {
            let detail = l2.detail.as_deref().unwrap_or("not captured");
            limitations.push(format!(
                "Collector `{}` is {} ({detail}).",
                l2.collector, l2.state
            ));
        }
    }

    assess_from_analysers(&report.analysers, http_complete, limitations)
}

/// Computes a multi-dimensional [`QualityAssessment`] from an application-wide
/// [`crate::discovery::CrawlSummary`].
#[must_use]
pub fn assess_crawl_summary(summary: &crate::discovery::CrawlSummary) -> QualityAssessment {
    let mut limitations = Vec::new();
    if !summary.coverage.complete {
        limitations.push(format!(
            "Bounded crawl covered {}/{} discovered URL(s).",
            summary.coverage.analysed_urls, summary.coverage.discovered_urls
        ));
    }
    if summary.budget_exhausted {
        limitations.push("Crawl terminated early due to execution budget.".to_owned());
    }

    let mut accs = [
        (
            QualityDomain::FunctionalIntegrity,
            DomainAccumulator::default(),
        ),
        (
            QualityDomain::RuntimeStability,
            DomainAccumulator::default(),
        ),
        (QualityDomain::Performance, DomainAccumulator::default()),
        (QualityDomain::Accessibility, DomainAccumulator::default()),
        (QualityDomain::VisualQuality, DomainAccumulator::default()),
        (QualityDomain::SurfaceSecurity, DomainAccumulator::default()),
        (QualityDomain::Privacy, DomainAccumulator::default()),
        (
            QualityDomain::ContentIntegrity,
            DomainAccumulator::default(),
        ),
        (QualityDomain::Discoverability, DomainAccumulator::default()),
        (QualityDomain::Reliability, DomainAccumulator::default()),
        (
            QualityDomain::EvidenceCoverage,
            DomainAccumulator::default(),
        ),
    ];

    for total in &summary.analysis_totals {
        let domain = domain_for_rule(total.dwarf_id, "");
        if let Some((_, acc)) = accs.iter_mut().find(|(d, _)| *d == domain) {
            acc.passed_checks = acc.passed_checks.saturating_add(total.checks_passed);
            acc.skipped_or_unavailable = acc
                .skipped_or_unavailable
                .saturating_add(total.checks_skipped + total.checks_unavailable);
        }
    }
    for page in &summary.page_diagnostics {
        for f in &page.findings {
            let domain = domain_for_rule(f.dwarf_id, &f.rule_id.0);
            if let Some((_, acc)) = accs.iter_mut().find(|(d, _)| *d == domain) {
                match f.severity {
                    Severity::Critical | Severity::High => {
                        acc.critical_high = acc.critical_high.saturating_add(1);
                    }
                    Severity::Medium => acc.medium = acc.medium.saturating_add(1),
                    Severity::Low | Severity::Info => {
                        acc.low_info = acc.low_info.saturating_add(1);
                    }
                }
            }
        }
    }

    let http_complete = summary.coverage.analysed_urls > 0 && !summary.budget_exhausted;
    finalise_assessment(accs, http_complete, limitations)
}

/// Computes a multi-dimensional [`QualityAssessment`] from raw analyser results
/// and HTTP completeness.
#[must_use]
pub fn assess_from_analysers(
    analysers: &[AnalyserResult],
    http_complete: bool,
    limitations: Vec<String>,
) -> QualityAssessment {
    let accs = accumulate_domains(analysers);
    finalise_assessment(accs, http_complete, limitations)
}

fn finalise_assessment(
    accs: [(QualityDomain, DomainAccumulator); 11],
    http_complete: bool,
    mut limitations: Vec<String>,
) -> QualityAssessment {
    let mut domains = Vec::with_capacity(accs.len());
    let mut blockers = Vec::new();
    let mut any_fail = false;
    let mut any_insufficient = !http_complete;

    for (domain, acc) in accs {
        let assessment = build_domain_assessment(domain, &acc, http_complete);
        match assessment.verdict {
            DomainVerdict::Fail => {
                any_fail = true;
                blockers.push(format!(
                    "{}: {} critical/high finding(s)",
                    domain.label(),
                    acc.critical_high
                ));
            }
            DomainVerdict::InsufficientEvidence => any_insufficient = true,
            DomainVerdict::Pass | DomainVerdict::NotApplicable | DomainVerdict::Waived => {}
        }
        domains.push(assessment);
    }

    if limitations.is_empty() && any_insufficient {
        limitations.push(
            "One or more quality domains lack complete evidence (uncollected or skipped checks)."
                .to_owned(),
        );
    }

    let overall_verdict = if any_fail {
        DomainVerdict::Fail
    } else if any_insufficient {
        DomainVerdict::InsufficientEvidence
    } else {
        DomainVerdict::Pass
    };

    QualityAssessment {
        domains,
        overall_verdict,
        blockers,
        limitations,
    }
}

fn accumulate_domains(analysers: &[AnalyserResult]) -> [(QualityDomain, DomainAccumulator); 11] {
    let mut accs = [
        (
            QualityDomain::FunctionalIntegrity,
            DomainAccumulator::default(),
        ),
        (
            QualityDomain::RuntimeStability,
            DomainAccumulator::default(),
        ),
        (QualityDomain::Performance, DomainAccumulator::default()),
        (QualityDomain::Accessibility, DomainAccumulator::default()),
        (QualityDomain::VisualQuality, DomainAccumulator::default()),
        (QualityDomain::SurfaceSecurity, DomainAccumulator::default()),
        (QualityDomain::Privacy, DomainAccumulator::default()),
        (
            QualityDomain::ContentIntegrity,
            DomainAccumulator::default(),
        ),
        (QualityDomain::Discoverability, DomainAccumulator::default()),
        (QualityDomain::Reliability, DomainAccumulator::default()),
        (
            QualityDomain::EvidenceCoverage,
            DomainAccumulator::default(),
        ),
    ];

    for analyser in analysers {
        for check in &analyser.checks {
            let (rule_id, is_passed, is_unavailable) = match check {
                CheckStatus::Passed { rule_id, .. } => (rule_id, true, false),
                CheckStatus::Failed { rule_id, .. } => (rule_id, false, false),
                CheckStatus::Skipped { rule_id, .. } | CheckStatus::Unavailable { rule_id, .. } => {
                    (rule_id, false, true)
                }
            };
            let domain = domain_for_rule(analyser.dwarf_id, &rule_id.0);
            if let Some((_, acc)) = accs.iter_mut().find(|(d, _)| *d == domain) {
                if is_passed {
                    acc.passed_checks = acc.passed_checks.saturating_add(1);
                } else if is_unavailable {
                    acc.skipped_or_unavailable = acc.skipped_or_unavailable.saturating_add(1);
                }
            }
        }
        for finding in &analyser.findings {
            let domain = domain_for_rule(analyser.dwarf_id, &finding.rule_id.0);
            if let Some((_, acc)) = accs.iter_mut().find(|(d, _)| *d == domain) {
                match finding.severity {
                    Severity::Critical | Severity::High => {
                        acc.critical_high = acc.critical_high.saturating_add(1);
                    }
                    Severity::Medium => {
                        acc.medium = acc.medium.saturating_add(1);
                    }
                    Severity::Low | Severity::Info => {
                        acc.low_info = acc.low_info.saturating_add(1);
                    }
                }
            }
        }
    }

    accs
}

fn build_domain_assessment(
    domain: QualityDomain,
    acc: &DomainAccumulator,
    http_complete: bool,
) -> DomainAssessment {
    let verdict = if acc.critical_high > 0 {
        DomainVerdict::Fail
    } else if domain == QualityDomain::EvidenceCoverage && !http_complete {
        DomainVerdict::InsufficientEvidence
    } else if acc.passed_checks == 0 && acc.medium == 0 && acc.low_info == 0 {
        if acc.skipped_or_unavailable > 0
            || !http_complete
            || domain == QualityDomain::FunctionalIntegrity
        {
            DomainVerdict::InsufficientEvidence
        } else {
            DomainVerdict::NotApplicable
        }
    } else if acc.skipped_or_unavailable > 0 && acc.passed_checks == 0 {
        DomainVerdict::InsufficientEvidence
    } else {
        DomainVerdict::Pass
    };

    let rationale = match verdict {
        DomainVerdict::Fail => format!(
            "{} critical/high and {} medium finding(s) observed.",
            acc.critical_high, acc.medium
        ),
        DomainVerdict::InsufficientEvidence => {
            if acc.skipped_or_unavailable > 0 {
                format!(
                    "{} check(s) skipped or unavailable; cannot assert pass.",
                    acc.skipped_or_unavailable
                )
            } else {
                "No executed checks with complete evidence in this domain.".to_owned()
            }
        }
        DomainVerdict::NotApplicable => "No rules applicable in this run.".to_owned(),
        DomainVerdict::Waived => "Findings explicitly waived.".to_owned(),
        DomainVerdict::Pass => {
            if acc.medium > 0 {
                format!(
                    "{} check(s) passed; {} medium concern(s) noted.",
                    acc.passed_checks, acc.medium
                )
            } else {
                format!(
                    "{} check(s) passed with no blocking findings.",
                    acc.passed_checks
                )
            }
        }
    };

    DomainAssessment {
        domain,
        verdict,
        critical_high_count: acc.critical_high,
        medium_count: acc.medium,
        low_info_count: acc.low_info,
        checks_unavailable: acc.skipped_or_unavailable,
        rationale,
    }
}

fn collector_state_label<T>(outcome: &CollectorOutcome<T>) -> &'static str {
    match outcome {
        CollectorOutcome::Captured { .. } => "captured",
        CollectorOutcome::Partial { .. } => "partial",
        CollectorOutcome::Skipped { .. } => "skipped",
        CollectorOutcome::Failed { .. } => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        EvidenceLevel, EvidenceRef, EvidenceSource, Finding, FindingCategory, FindingFingerprint,
        FindingKind, RuleId,
    };

    fn finding(rule: &str, category: FindingCategory, severity: Severity) -> Finding {
        Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(rule.to_owned()),
            category,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity,
            confidence: crate::domain::Confidence::High,
            title: "Test finding".to_owned(),
            summary: "Summary".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, "observed")],
            remediation: Some("Fix it".to_owned()),
        }
    }

    #[test]
    fn critical_finding_causes_fail_and_never_hides_behind_other_passes() {
        let analysers = vec![
            AnalyserResult {
                dwarf_id: DwarfId::Netz,
                checks: vec![CheckStatus::Passed {
                    rule_id: RuleId("net.http.status".to_owned()),
                    evidence_level: EvidenceLevel::Source,
                }],
                findings: vec![],
            },
            AnalyserResult {
                dwarf_id: DwarfId::Sicherheits,
                checks: vec![CheckStatus::Failed {
                    rule_id: RuleId("sec.headers.csp".to_owned()),
                    evidence_level: EvidenceLevel::Source,
                }],
                findings: vec![finding(
                    "sec.headers.csp",
                    FindingCategory::Security,
                    Severity::High,
                )],
            },
        ];

        let assessment = assess_from_analysers(&analysers, true, vec![]);
        assert_eq!(assessment.overall_verdict, DomainVerdict::Fail);
        let sec = assessment
            .domains
            .iter()
            .find(|d| d.domain == QualityDomain::SurfaceSecurity)
            .expect("security domain");
        assert_eq!(sec.verdict, DomainVerdict::Fail);
        assert_eq!(sec.critical_high_count, 1);
    }

    #[test]
    fn skipped_checks_produce_insufficient_evidence_never_pass() {
        let analysers = vec![AnalyserResult {
            dwarf_id: DwarfId::Zugaenglichkeits,
            checks: vec![CheckStatus::Skipped {
                rule_id: RuleId("a11y.axe.violations".to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason: "axe-core not installed".to_owned(),
            }],
            findings: vec![],
        }];

        let assessment = assess_from_analysers(&analysers, true, vec![]);
        assert_eq!(
            assessment.overall_verdict,
            DomainVerdict::InsufficientEvidence
        );
        let a11y = assessment
            .domains
            .iter()
            .find(|d| d.domain == QualityDomain::Accessibility)
            .expect("a11y domain");
        assert_eq!(a11y.verdict, DomainVerdict::InsufficientEvidence);
        assert_eq!(a11y.checks_unavailable, 1);
    }

    #[test]
    fn failed_http_forces_evidence_coverage_insufficient() {
        let assessment = assess_from_analysers(&[], false, vec![]);
        assert_eq!(
            assessment.overall_verdict,
            DomainVerdict::InsufficientEvidence
        );
        let cov = assessment
            .domains
            .iter()
            .find(|d| d.domain == QualityDomain::EvidenceCoverage)
            .expect("coverage domain");
        assert_eq!(cov.verdict, DomainVerdict::InsufficientEvidence);
    }
}
