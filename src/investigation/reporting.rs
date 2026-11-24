//! Stakeholder reporting models and Markdown renderers (`DokumentationsZwerg`).

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::brigade::DwarfId;
use crate::domain::{CollectorOutcome, Finding, RuleId, Severity};
use crate::investigation::{
    HypothesisStatus, InvestigationContext, InvestigationReport, InvestigationState,
};

/// Target stakeholder perspective for tailored report rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolePerspective {
    /// Delivery risks, immediate actions, release blockers, verification status.
    ProjectManager,
    /// User impact, affected journeys, backlog candidates, acceptance criteria.
    ProductOwner,
    /// Systemic risks, technical debt, cross-domain correlations, competencies.
    CtoEngineeringManager,
    /// Detailed observations, tool provenance, hypotheses, execution trace.
    TechnicalSpecialist,
}

/// Stakeholder-oriented two-minute executive summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutiveBrief {
    /// Overall condition statement grounded in observed findings.
    pub assessment: String,
    /// Top immediate actions ordered by severity and hypothesis support.
    pub immediate_actions: Vec<String>,
    /// Explicit coverage statement (what was and was not inspected).
    pub coverage_summary: String,
    /// Explicit limitations and uncertainty note.
    pub confidence_note: String,
}

/// Backlog-ready remediation task generated for PM / PO / engineering teams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationTask {
    /// Stable task identifier within the investigation.
    pub id: String,
    /// Concise action title.
    pub title: String,
    /// Problem statement grounded in findings.
    pub problem_statement: String,
    /// Impact severity.
    pub priority: Severity,
    /// Suggested responsible engineering competency.
    pub suggested_competency: String,
    /// Related deterministic rule IDs.
    pub related_rules: Vec<RuleId>,
    /// Suggested acceptance criteria for delivery teams.
    pub acceptance_criteria: Vec<String>,
    /// Verification procedure to confirm completion.
    pub verification_procedure: String,
    /// Explicit uncertainty or internal-investigation notes.
    pub uncertainty_notes: Option<String>,
}

/// Configurable release readiness classification grounded in investigated scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReadinessState {
    /// No blocking findings observed within the investigated scope.
    NoBlockingFindingsWithinScope,
    /// Moderate concerns require stakeholder review or scheduled remediation.
    MaterialConcerns,
    /// High or critical defects represent potential release blockers.
    PotentialReleaseBlockers,
    /// Required evidence was incomplete, failed, or inconclusive.
    InsufficientEvidence,
}

/// Defensible release readiness assessment for stakeholder decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReadinessAssessment {
    /// Overall readiness state.
    pub state: ReleaseReadinessState,
    /// Evidence-backed rationale bullets.
    pub rationale: Vec<String>,
    /// Explicit coverage and evidence limitations.
    pub coverage_limitations: Vec<String>,
}

pub(crate) fn build_stakeholder_outputs(
    ctx: &InvestigationContext,
) -> (
    ExecutiveBrief,
    ReleaseReadinessAssessment,
    Vec<RemediationTask>,
) {
    let mut all_findings: Vec<(DwarfId, &Finding)> = ctx
        .initial_report
        .iter()
        .flat_map(|r| {
            r.analysers
                .iter()
                .flat_map(|a| a.findings.iter().map(move |f| (a.dwarf_id, f)))
        })
        .chain(
            ctx.follow_up_results
                .iter()
                .flat_map(|r| r.findings.iter().map(move |f| (r.dwarf_id, f))),
        )
        .collect();
    all_findings.sort_by_key(|(_, f)| std::cmp::Reverse(f.severity));

    let immediate_actions: Vec<String> = all_findings
        .iter()
        .filter(|(_, f)| f.severity >= Severity::Medium)
        .take(5)
        .map(|(_, f)| format!("[{:?}] {} ({})", f.severity, f.title, f.rule_id.0))
        .collect();

    let assessment = if all_findings
        .iter()
        .any(|(_, f)| f.severity >= Severity::High)
    {
        "Material high-severity quality risks require attention before release.".to_owned()
    } else if all_findings.is_empty() {
        "No defects detected within the investigated scope.".to_owned()
    } else {
        "Minor or moderate quality improvements identified within the investigated scope."
            .to_owned()
    };

    let supported = ctx
        .hypotheses
        .iter()
        .filter(|h| h.status == HypothesisStatus::Supported)
        .count();
    let coverage_summary = if ctx.discovered_pages.is_empty() {
        format!(
            "Single target `{}` investigated; {} tool call(s) executed; {} hypothesis/hypotheses evaluated ({} supported).",
            ctx.target.as_str(),
            ctx.tool_trace.len(),
            ctx.hypotheses.len(),
            supported
        )
    } else {
        let investigated = ctx
            .discovered_pages
            .iter()
            .filter(|p| p.status == crate::discovery::PageCrawlStatus::Investigated)
            .count();
        format!(
            "{} of {} discovered URLs investigated across `{}`; {} systemic issue(s) clustered; {} hypothesis/hypotheses evaluated ({} supported).",
            investigated,
            ctx.discovered_pages.len(),
            ctx.target.host(),
            ctx.systemic_issues.len(),
            ctx.hypotheses.len(),
            supported
        )
    };
    let confidence_note =
        "Deterministic measurements carry high confidence; authenticated journeys were not exercised."
            .to_owned();

    let release_readiness = compute_release_readiness(ctx, &all_findings);
    let remediation_tasks = build_remediation_tasks(ctx, all_findings);

    (
        ExecutiveBrief {
            assessment,
            immediate_actions,
            coverage_summary,
            confidence_note,
        },
        release_readiness,
        remediation_tasks,
    )
}

fn build_remediation_tasks(
    ctx: &InvestigationContext,
    all_findings: Vec<(DwarfId, &Finding)>,
) -> Vec<RemediationTask> {
    all_findings
        .into_iter()
        .filter(|(_, f)| f.severity >= Severity::Medium)
        .take(8)
        .enumerate()
        .map(|(idx, (dwarf_id, f))| RemediationTask {
            id: format!("TASK-{}", idx + 1),
            title: f.title.clone(),
            problem_statement: f.summary.clone(),
            priority: f.severity,
            suggested_competency: competency_for_dwarf(dwarf_id).to_owned(),
            related_rules: vec![f.rule_id.clone()],
            acceptance_criteria: vec![
                f.remediation.clone().unwrap_or_else(|| {
                    "Resolve the underlying defect and verify against captured evidence.".to_owned()
                }),
                format!(
                    "Re-running rule `{}` passes without regressions.",
                    f.rule_id.0
                ),
            ],
            verification_procedure: format!(
                "Re-run `nzw check {}` (or `nzw verify`) and confirm `{}` is resolved.",
                ctx.target.as_str(),
                f.rule_id.0
            ),
            uncertainty_notes: (f.evidence_level != crate::domain::EvidenceLevel::Source).then(
                || {
                    "Verified via Level 2 rendered/runtime evidence; confirm in target environment."
                        .to_owned()
                },
            ),
        })
        .collect()
}

const fn competency_for_dwarf(id: DwarfId) -> &'static str {
    match id {
        DwarfId::Netz | DwarfId::Sicherheits => "Platform / Infrastructure / Security Engineering",
        DwarfId::Leistungs | DwarfId::Browser => "Frontend Performance & Runtime Engineering",
        DwarfId::Struktur | DwarfId::Zugaenglichkeits | DwarfId::Gestaltungs => {
            "Frontend UI & Accessibility Engineering"
        }
        DwarfId::Such | DwarfId::Inhalts => "Content, SEO & Product Engineering",
        DwarfId::Dokumentations | DwarfId::Kommandant => "Product & Quality Engineering",
    }
}

fn compute_release_readiness(
    ctx: &InvestigationContext,
    all_findings: &[(DwarfId, &Finding)],
) -> ReleaseReadinessAssessment {
    let has_critical_or_high = all_findings
        .iter()
        .any(|(_, f)| f.severity >= Severity::High);
    let has_medium = all_findings
        .iter()
        .any(|(_, f)| f.severity == Severity::Medium);
    let http_incomplete = ctx.snapshot.as_ref().is_none_or(|s| {
        matches!(
            s.http,
            CollectorOutcome::Failed { .. }
                | CollectorOutcome::Skipped { .. }
                | CollectorOutcome::Partial { .. }
        )
    });
    let has_inconclusive_hyp = ctx
        .hypotheses
        .iter()
        .any(|h| h.status == HypothesisStatus::Inconclusive);

    let state = if has_critical_or_high {
        ReleaseReadinessState::PotentialReleaseBlockers
    } else if http_incomplete
        || matches!(
            ctx.state,
            InvestigationState::BudgetExhausted | InvestigationState::Failed
        )
        || has_inconclusive_hyp
    {
        ReleaseReadinessState::InsufficientEvidence
    } else if has_medium {
        ReleaseReadinessState::MaterialConcerns
    } else {
        ReleaseReadinessState::NoBlockingFindingsWithinScope
    };

    let mut rationale = Vec::new();
    if has_critical_or_high {
        rationale
            .push("One or more Critical/High deterministic findings were observed.".to_owned());
    }
    if http_incomplete {
        rationale.push("Initial HTTP collection was failed, skipped, or partial.".to_owned());
    }
    if has_inconclusive_hyp {
        rationale.push("At least one diagnostic hypothesis remained inconclusive.".to_owned());
    }
    if rationale.is_empty() {
        rationale.push("All executed checks within scope completed cleanly.".to_owned());
    }
    ReleaseReadinessAssessment {
        state,
        rationale,
        coverage_limitations: vec![
            "Authenticated user journeys were not exercised.".to_owned(),
            if ctx.discovered_pages.is_empty() {
                "Only a single seed URL was investigated.".to_owned()
            } else {
                format!(
                    "Bounded crawl covered {} discovered URL(s).",
                    ctx.discovered_pages.len()
                )
            },
        ],
    }
}

/// Renders an [`InvestigationReport`] as a stakeholder-ready Markdown document.
#[must_use]
pub fn render_markdown_report(report: &InvestigationReport) -> String {
    render_role_perspective_markdown(report, RolePerspective::TechnicalSpecialist)
}

/// Renders an [`InvestigationReport`] tailored to a specific [`RolePerspective`].
#[must_use]
pub fn render_role_perspective_markdown(
    report: &InvestigationReport,
    perspective: RolePerspective,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# NetzZwergenWacht Investigation Report\n");
    let _ = writeln!(out, "- **Audience**: `{perspective:?}`");
    let _ = writeln!(out, "- **Investigation ID**: `{}`", report.id.0);
    let _ = writeln!(out, "- **Target**: {}", report.target.as_str());
    let _ = writeln!(out, "- **Objective**: {}", report.objective);
    let _ = writeln!(out, "- **State**: `{:?}`", report.state);
    let _ = writeln!(
        out,
        "- **Release Readiness**: `{:?}`\n",
        report.release_readiness.state
    );

    let _ = writeln!(out, "## Executive Brief\n");
    let _ = writeln!(out, "{}\n", report.executive_brief.assessment);
    let _ = writeln!(
        out,
        "- **Coverage**: {}",
        report.executive_brief.coverage_summary
    );
    let _ = writeln!(
        out,
        "- **Confidence**: {}\n",
        report.executive_brief.confidence_note
    );

    if !report.executive_brief.immediate_actions.is_empty() {
        let _ = writeln!(out, "### Immediate Actions\n");
        for action in &report.executive_brief.immediate_actions {
            let _ = writeln!(out, "- {action}");
        }
        let _ = writeln!(out);
    }

    if matches!(
        perspective,
        RolePerspective::CtoEngineeringManager | RolePerspective::TechnicalSpecialist
    ) && !report.specialists.is_empty()
    {
        let _ = writeln!(out, "## Specialist Contributions\n");
        for spec in &report.specialists {
            let _ = writeln!(
                out,
                "- **{}** ({}): {} *(Uncertainty: {})*",
                crate::brigade::profile(spec.dwarf_id).display_name,
                spec.focus,
                spec.observations.join("; "),
                spec.uncertainty
            );
        }
        let _ = writeln!(out);
    }

    if matches!(
        perspective,
        RolePerspective::CtoEngineeringManager | RolePerspective::TechnicalSpecialist
    ) && !report.systemic_issues.is_empty()
    {
        let _ = writeln!(out, "## Systemic Issues\n");
        for sys in &report.systemic_issues {
            let _ = writeln!(
                out,
                "- **{}** (`{}`): {} ({} URL(s))",
                sys.id,
                sys.rule_id.0,
                sys.summary,
                sys.affected_urls.len()
            );
        }
        let _ = writeln!(out);
    }

    if matches!(perspective, RolePerspective::TechnicalSpecialist) && !report.hypotheses.is_empty()
    {
        let _ = writeln!(out, "## Diagnostic Hypotheses\n");
        for hyp in &report.hypotheses {
            let _ = writeln!(
                out,
                "- **{}** (`{:?}`, tool `{}`): {}",
                hyp.id, hyp.status, hyp.requested_tool, hyp.proposed_explanation
            );
            if let Some(summary) = &hyp.evaluation_summary {
                let _ = writeln!(out, "  - Evaluation: {summary}");
            }
        }
        let _ = writeln!(out);
    }

    if !report.remediation_tasks.is_empty() {
        append_remediation_tasks(&mut out, &report.remediation_tasks);
    }

    let _ = writeln!(out, "## Conclusion\n\n{}", report.conclusion);
    out
}

fn append_remediation_tasks(out: &mut String, tasks: &[RemediationTask]) {
    let _ = writeln!(out, "## Backlog Remediation Tasks\n");
    for task in tasks {
        let _ = writeln!(
            out,
            "### {} ({:?}) — {}\n",
            task.id, task.priority, task.title
        );
        let _ = writeln!(out, "- **Owner Competency**: {}", task.suggested_competency);
        let _ = writeln!(out, "\n{}\n", task.problem_statement);
        let _ = writeln!(out, "**Acceptance Criteria:**");
        for ac in &task.acceptance_criteria {
            let _ = writeln!(out, "- {ac}");
        }
        let _ = writeln!(out, "\n**Verification:** {}\n", task.verification_procedure);
    }
}
