//! Compact, agent-oriented (`--format llm`) rendering and fix-prompt generation.
//!
//! Formats deterministic audit and scan findings into concise, evidence-grounded
//! remediation prompts suitable for coding agents and MCP tool responses.

use std::fmt::Write as _;

use crate::analysis::AuditReport;
use crate::analysis::assessment::{QualityAssessment, compute_health_score};
use crate::discovery::{CrawlSummary, FixScope, group_fixes_by_component};
use crate::domain::Measurement;

/// Renders a single-URL [`AuditReport`] in compact `--format llm` markdown with fix prompts.
#[must_use]
pub fn render_audit_llm(report: &AuditReport, assessment: &QualityAssessment) -> String {
    let score = compute_health_score(&report.analysers);
    let score_label = match score.overall_score {
        Measurement::Measured { value, .. } => {
            format!("{value}/100 ({})", score.grade.map_or("?", |g| g.as_str()))
        }
        Measurement::Unavailable { .. }
        | Measurement::Failed { .. }
        | Measurement::Skipped { .. } => "unavailable".to_owned(),
    };

    let mut out = String::new();
    let _ = writeln!(out, "# NetzZwergenWacht LLM Audit Summary");
    let _ = writeln!(out, "target: {}", report.target.as_str());
    let _ = writeln!(out, "overall_verdict: {:?}", assessment.overall_verdict);
    let _ = writeln!(
        out,
        "health_score: {score_label} (observed_checks={}, unobserved_checks={})",
        score.observed_checks, score.unobserved_checks
    );
    let _ = writeln!(
        out,
        "findings: critical={} high={} medium={} low={} info={}",
        report.summary.critical_findings,
        report.summary.high_findings,
        report.summary.medium_findings,
        report.summary.low_findings,
        report.summary.info_findings
    );

    let mut flat: Vec<(&str, &crate::domain::Finding)> = report
        .analysers
        .iter()
        .flat_map(|a| {
            a.findings
                .iter()
                .map(move |f| (a.dwarf_id.display_name(), f))
        })
        .collect();
    flat.sort_by(|(_, a), (_, b)| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.0.cmp(&b.rule_id.0))
    });

    let _ = writeln!(out, "\n## Prioritised Fix Prompts ({})", flat.len());
    for (idx, (dwarf, f)) in flat.iter().take(40).enumerate() {
        let evidence = f
            .evidence_refs
            .iter()
            .take(3)
            .map(|e| e.detail.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        let _ = writeln!(
            out,
            "\n### {}. [{:?}] {} ({dwarf})",
            idx + 1,
            f.severity,
            f.rule_id.0
        );
        let _ = writeln!(out, "issue: {}", f.title);
        let _ = writeln!(out, "evidence: {evidence}");
        let action = f
            .remediation
            .as_deref()
            .unwrap_or("Inspect the cited evidence and resolve the underlying defect.");
        let _ = writeln!(
            out,
            "fix_prompt: Fix `{}` on `{}`: {action}",
            f.rule_id.0,
            report.target.as_str()
        );
    }
    out
}

/// Renders a multi-page [`CrawlSummary`] in compact `--format llm` markdown using
/// component-signature [`crate::discovery::FixGroup`] clustering.
#[must_use]
pub fn render_scan_llm(
    seed_url: &str,
    summary: &CrawlSummary,
    assessment: &QualityAssessment,
) -> String {
    let groups = group_fixes_by_component(summary);
    let mut out = String::new();
    let _ = writeln!(out, "# NetzZwergenWacht LLM Scan Summary");
    let _ = writeln!(out, "seed: {seed_url}");
    let _ = writeln!(
        out,
        "coverage: discovered={} analysed={} failed={} skipped_budget={}",
        summary.coverage.discovered_urls,
        summary.coverage.analysed_urls,
        summary.coverage.failed_urls,
        summary.coverage.skipped_budget_urls
    );
    let _ = writeln!(out, "overall_verdict: {:?}", assessment.overall_verdict);
    let _ = writeln!(out, "\n## Grouped Fix Prompts ({})", groups.len());

    for group in groups.iter().take(40) {
        let scope_label = match group.scope {
            FixScope::SiteWide => "site_wide",
            FixScope::SharedComponent => "shared_component",
            FixScope::PerPage => "per_page",
        };
        let urls_preview = group
            .affected_urls
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            out,
            "\n### {} [{:?} | {scope_label}] {}",
            group.group_id, group.severity, group.rule_id.0
        );
        let _ = writeln!(out, "title: {}", group.title);
        let _ = writeln!(out, "signature: {}", group.component_signature);
        if !urls_preview.is_empty() {
            let _ = writeln!(
                out,
                "affected_urls ({}): {urls_preview}",
                group.affected_urls.len()
            );
        }
        let action = group
            .remediation
            .as_deref()
            .unwrap_or("Resolve this grouped issue across the affected scope.");
        let _ = writeln!(
            out,
            "fix_prompt: Apply `{}` ({scope_label}) fix for `{}`: {action}",
            group.rule_id.0, group.component_signature
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::assessment::assess_from_analysers;
    use crate::domain::{
        AuditTarget, CollectorOutcome, EvidenceSnapshot, HttpEvidence, MeasurementUnit,
        TargetPolicy,
    };

    #[test]
    fn renders_compact_llm_audit_with_fix_prompts() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly)
            .expect("valid target");
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 15,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 64,
                    body_truncated: false,
                    body_text: "<html><body><p>Hello</p></body></html>".to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "http".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let report = crate::analysis::run_all(&snap);
        let assessment = assess_from_analysers(&report.analysers, true, Vec::new());
        let llm = render_audit_llm(&report, &assessment);
        assert!(llm.contains("# NetzZwergenWacht LLM Audit Summary"));
        assert!(llm.contains("fix_prompt:"));
    }
}
