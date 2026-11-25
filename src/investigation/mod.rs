//! Agentic investigation domain model and `KommandantZwerg` orchestrator.
//!
//! Coordinates specialist capabilities (`LeistungsZwerg`, `BrowserZwerg`,
//! `StrukturZwerg`, `SicherheitsZwerg`, `ZugänglichkeitsZwerg`, `NetzZwerg`)
//! through `rig-core` [`PortableTool`] contracts, enforces [`InvestigationBudget`],
//! emits [`InvestigationEvent`]s, and builds stakeholder-ready
//! [`InvestigationReport`]s.

pub mod browser_timeline;
pub mod events;
pub mod prompts;
pub mod reporting;
pub mod tools;

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rig_core::tool::PortableTool;
use serde::{Deserialize, Serialize};

use crate::adapters;
use crate::analysis::{self, AuditReport};
use crate::brigade::DwarfId;
use crate::collection;
use crate::discovery::{
    self, CrawlBudget, CrawlSummary, DiscoveredPage, PageCrawlStatus, SystemicIssue,
};
use crate::domain::{
    AnalyserResult, AuditTarget, AxeEvidence, BrowserEvidence, CollectorOutcome, EvidenceRef,
    EvidenceSnapshot, ExecutionBudget, LighthouseMetrics, Origin, RuleId, TargetPolicy,
};
use crate::intelligence::{LlmBudget, LlmProvider};

pub use self::events::InvestigationEvent;
pub use self::reporting::{
    ExecutiveBrief, ReleaseReadinessAssessment, ReleaseReadinessState, RemediationTask,
    RolePerspective, render_markdown_report, render_role_perspective_markdown,
};
use self::tools::{
    CrawlAndClusterTool, InspectBrowserRuntimeTool, InspectDocumentStructureTool,
    InspectPagePerformanceTool, InspectRenderedAccessibilityTool, InspectSecurityPostureTool,
    QueryBrowserEvidenceTool, TargetToolArgs, registered_tool_definitions,
};

const OPEN_TAG: &str = "<untrusted_audit_evidence>";
const CLOSE_TAG: &str = "</untrusted_audit_evidence>";

static INV_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique identifier for an investigation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationId(pub String);

impl InvestigationId {
    fn generate(host: &str) -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let seq = INV_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("inv-{host}-{millis}-{seq}"))
    }
}

/// Lifecycle state of an agentic investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationState {
    /// Request accepted.
    Requested,
    /// Scope and policy validated.
    Scoped,
    /// Initial reconnaissance planned.
    Planned,
    /// Active diagnostic collection and tool execution.
    Investigating,
    /// Hypothesis evaluation against collected evidence.
    Evaluating,
    /// Report assembly.
    Reporting,
    /// Completed within budget.
    Completed,
    /// Completed with partial evidence or skipped follow-ups.
    PartiallyCompleted,
    /// Terminated because an explicit budget cap was reached.
    BudgetExhausted,
    /// Cancelled externally.
    Cancelled,
    /// Failed before producing usable results.
    Failed,
}

/// Resource bounds governing an agentic investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationBudget {
    /// Maximum number of typed diagnostic tool invocations.
    pub max_tool_calls: usize,
    /// Maximum number of LLM reasoning turns.
    pub max_llm_turns: usize,
    /// End-to-end wall-clock deadline.
    pub max_duration: Duration,
    /// Per-turn completion token limit.
    pub max_tokens: u32,
}

impl Default for InvestigationBudget {
    fn default() -> Self {
        Self {
            max_tool_calls: 5,
            max_llm_turns: 6,
            max_duration: Duration::from_secs(90),
            max_tokens: 4_096,
        }
    }
}

/// Runtime budget ledger enforced outside the LLM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLedger {
    /// Configured bounds.
    pub budget: InvestigationBudget,
    /// Tool invocations consumed so far.
    pub tool_calls_used: usize,
    /// LLM turns consumed so far.
    pub llm_turns_used: usize,
}

impl BudgetLedger {
    /// Creates a fresh ledger for `budget`.
    #[must_use]
    pub fn new(budget: InvestigationBudget) -> Self {
        Self {
            budget,
            tool_calls_used: 0,
            llm_turns_used: 0,
        }
    }

    fn remaining_duration(&self, started: Instant) -> Duration {
        self.budget.max_duration.saturating_sub(started.elapsed())
    }

    fn try_consume_tool(&mut self, started: Instant) -> Result<Duration, String> {
        let rem = self.remaining_duration(started);
        if rem.is_zero() {
            return Err("investigation max_duration budget exhausted".to_owned());
        }
        if self.tool_calls_used >= self.budget.max_tool_calls {
            return Err("investigation max_tool_calls budget exhausted".to_owned());
        }
        self.tool_calls_used += 1;
        Ok(rem)
    }

    fn try_consume_llm(&mut self, started: Instant) -> Result<Duration, String> {
        let rem = self.remaining_duration(started);
        if rem.is_zero() {
            return Err("investigation max_duration budget exhausted".to_owned());
        }
        if self.llm_turns_used >= self.budget.max_llm_turns {
            return Err("investigation max_llm_turns budget exhausted".to_owned());
        }
        self.llm_turns_used += 1;
        Ok(rem)
    }
}

/// Evaluation outcome of a [`DiagnosticHypothesis`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Formulated from initial observations, awaiting follow-up evidence.
    Proposed,
    /// Supported by follow-up diagnostic evidence.
    Supported,
    /// Contradicted or unsupported by follow-up diagnostic evidence.
    Rejected,
    /// Follow-up evidence was unavailable, failed, or ambiguous.
    Inconclusive,
}

/// Falsifiable diagnostic hypothesis linking an observation to a follow-up tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticHypothesis {
    /// Stable hypothesis identifier within the investigation.
    pub id: String,
    /// Deterministic rule or observation that triggered this hypothesis.
    pub originating_rule: RuleId,
    /// Whether `originating_rule` was verified in the deterministic report.
    pub originating_rule_verified: bool,
    /// Proposed explanation to test.
    pub proposed_explanation: String,
    /// Typed diagnostic tool selected to test this hypothesis.
    pub requested_tool: String,
    /// Current evaluation status.
    pub status: HypothesisStatus,
    /// Evidence-backed evaluation summary.
    pub evaluation_summary: Option<String>,
    /// Supporting evidence references (populated only when `Supported`).
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Contradictory evidence references (populated only when `Rejected`).
    pub contradictory_evidence: Vec<EvidenceRef>,
    /// Evidence gaps recorded when observations were absent or insufficient.
    #[serde(default)]
    pub missing_evidence: Vec<String>,
}

/// Audit trail entry for a single typed diagnostic tool invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInvocationRecord {
    /// Typed tool identifier.
    pub tool_id: String,
    /// Owning specialist dwarf.
    pub dwarf_id: DwarfId,
    /// Whether policy and budget authorised the call.
    pub authorised: bool,
    /// Whether the tool produced usable evidence.
    pub succeeded: bool,
    /// Concise execution summary.
    pub summary: String,
}

/// Domain-specific contribution recorded by an activated specialist dwarf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialistContribution {
    /// Contributing specialist dwarf.
    pub dwarf_id: DwarfId,
    /// Analytical focus for this contribution.
    pub focus: String,
    /// Concrete observations derived from captured evidence.
    pub observations: Vec<String>,
    /// Explicit remaining uncertainty.
    pub uncertainty: String,
}

/// Shared structured context exchanged between `KommandantZwerg` and tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationContext {
    /// Investigation identifier.
    pub id: InvestigationId,
    /// Validated target.
    pub target: AuditTarget,
    /// Stakeholder objective.
    pub objective: String,
    /// Current lifecycle state.
    pub state: InvestigationState,
    /// Latest collected evidence snapshot (preserving initial and follow-up evidence).
    pub snapshot: Option<EvidenceSnapshot>,
    /// Initial Level 1 deterministic report.
    pub initial_report: Option<AuditReport>,
    /// Additional specialist results gathered during investigation.
    pub follow_up_results: Vec<AnalyserResult>,
    /// Pages discovered during optional multi-page crawl.
    pub discovered_pages: Vec<DiscoveredPage>,
    /// Systemic cross-page issues identified during crawl.
    pub systemic_issues: Vec<SystemicIssue>,
    /// Specialist contributions recorded during the investigation.
    pub specialists: Vec<SpecialistContribution>,
    /// Hypotheses formulated and evaluated during the investigation.
    pub hypotheses: Vec<DiagnosticHypothesis>,
    /// Complete trace of tool invocations.
    pub tool_trace: Vec<ToolInvocationRecord>,
    /// Chronological execution events.
    pub events: Vec<InvestigationEvent>,
    /// Budget consumption ledger.
    pub ledger: BudgetLedger,
}

/// Final structured output of an agentic investigation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationReport {
    /// Investigation identifier.
    pub id: InvestigationId,
    /// Validated target.
    pub target: AuditTarget,
    /// Stakeholder objective.
    pub objective: String,
    /// Final lifecycle state.
    pub state: InvestigationState,
    /// Preserved evidence snapshot including follow-up Level 2 captures.
    pub snapshot: Option<EvidenceSnapshot>,
    /// Initial Level 1 deterministic report.
    pub initial_report: Option<AuditReport>,
    /// Additional specialist results.
    pub follow_up_results: Vec<AnalyserResult>,
    /// Pages discovered during optional multi-page crawl.
    pub discovered_pages: Vec<DiscoveredPage>,
    /// Systemic cross-page issues identified during crawl.
    pub systemic_issues: Vec<SystemicIssue>,
    /// Specialist contributions recorded during the investigation.
    pub specialists: Vec<SpecialistContribution>,
    /// Evaluated hypotheses.
    pub hypotheses: Vec<DiagnosticHypothesis>,
    /// Complete tool execution trace.
    pub tool_trace: Vec<ToolInvocationRecord>,
    /// Chronological execution events.
    pub events: Vec<InvestigationEvent>,
    /// Budget consumption summary.
    pub ledger: BudgetLedger,
    /// Stakeholder-facing executive brief.
    pub executive_brief: ExecutiveBrief,
    /// Defensible release readiness assessment.
    pub release_readiness: ReleaseReadinessAssessment,
    /// Backlog-ready remediation tasks.
    pub remediation_tasks: Vec<RemediationTask>,
    /// `KommandantZwerg` conclusion grounded in observed evidence.
    pub conclusion: String,
}

/// Boxed future for diagnostic evidence collection.
pub type CollectFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Typed diagnostic evidence backend enabling deterministic offline tests.
pub trait DiagnosticBackend: Send + Sync {
    /// Collects Level 1 HTTP/TLS snapshot.
    fn collect_http<'a>(
        &'a self,
        target: &'a AuditTarget,
        budget: ExecutionBudget,
        policy: TargetPolicy,
    ) -> CollectFuture<'a, EvidenceSnapshot>;

    /// Collects Level 2 headless browser runtime and layout evidence.
    fn collect_browser<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<BrowserEvidence>>;

    /// Collects Level 2 `axe-core` accessibility evidence.
    fn collect_axe<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<AxeEvidence>>;

    /// Collects Level 2 Lighthouse performance metrics.
    fn collect_lighthouse<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<LighthouseMetrics>>;

    /// Performs a bounded same-origin crawl and systemic issue clustering.
    fn collect_crawl<'a>(
        &'a self,
        target: &'a AuditTarget,
        crawl_budget: CrawlBudget,
        exec_budget: ExecutionBudget,
        policy: TargetPolicy,
    ) -> CollectFuture<'a, CrawlSummary>;
}

/// Production diagnostic backend delegating to `collection` and `adapters`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveDiagnosticBackend;

impl DiagnosticBackend for LiveDiagnosticBackend {
    fn collect_http<'a>(
        &'a self,
        target: &'a AuditTarget,
        budget: ExecutionBudget,
        policy: TargetPolicy,
    ) -> CollectFuture<'a, EvidenceSnapshot> {
        Box::pin(async move { collection::collect_http(target, &budget, policy).await })
    }

    fn collect_browser<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<BrowserEvidence>> {
        Box::pin(adapters::browser::run_browser(target, timeout))
    }

    fn collect_axe<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<AxeEvidence>> {
        Box::pin(adapters::axe::run_axe(target, timeout))
    }

    fn collect_lighthouse<'a>(
        &'a self,
        target: &'a AuditTarget,
        timeout: Duration,
    ) -> CollectFuture<'a, CollectorOutcome<LighthouseMetrics>> {
        Box::pin(adapters::lighthouse::run_lighthouse(target, timeout))
    }

    fn collect_crawl<'a>(
        &'a self,
        target: &'a AuditTarget,
        crawl_budget: CrawlBudget,
        exec_budget: ExecutionBudget,
        policy: TargetPolicy,
    ) -> CollectFuture<'a, CrawlSummary> {
        let seed = target.clone();
        Box::pin(async move {
            discovery::crawl_and_cluster(seed, crawl_budget, exec_budget, policy).await
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawHypothesisDecision {
    #[serde(default)]
    ready_to_conclude: bool,
    #[serde(default)]
    originating_rule: String,
    #[serde(default)]
    proposed_explanation: String,
    #[serde(default)]
    requested_tool: String,
    #[serde(default)]
    conclusion: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawEvaluationDecision {
    status: HypothesisStatus,
    #[serde(default)]
    timeline_sequences: Vec<u32>,
    evaluation_summary: String,
    conclusion: String,
}

/// Executes the multi-turn `KommandantZwerg` agentic investigation loop.
pub async fn run_investigation(
    target: AuditTarget,
    objective: String,
    policy: TargetPolicy,
    budget: InvestigationBudget,
    backend: Arc<dyn DiagnosticBackend>,
    llm: &dyn LlmProvider,
) -> InvestigationReport {
    run_investigation_with_specialists(target, objective, policy, budget, backend, llm, Vec::new())
        .await
}

/// Executes the multi-turn `KommandantZwerg` investigation loop seeded with
/// structured [`SpecialistContribution`]s from prior specialist delegations.
#[allow(clippy::too_many_lines)]
pub async fn run_investigation_with_specialists(
    target: AuditTarget,
    objective: String,
    policy: TargetPolicy,
    budget: InvestigationBudget,
    backend: Arc<dyn DiagnosticBackend>,
    llm: &dyn LlmProvider,
    prior_specialists: Vec<SpecialistContribution>,
) -> InvestigationReport {
    let started = Instant::now();
    let id = InvestigationId::generate(target.host());
    let origin = Origin::from_target(&target);
    let mut ctx = InvestigationContext {
        id: id.clone(),
        target: target.clone(),
        objective,
        state: InvestigationState::Scoped,
        snapshot: None,
        initial_report: None,
        follow_up_results: Vec::new(),
        discovered_pages: Vec::new(),
        systemic_issues: Vec::new(),
        specialists: prior_specialists,
        hypotheses: Vec::new(),
        tool_trace: Vec::new(),
        events: vec![
            InvestigationEvent::InvestigationStarted {
                investigation_id: id.0,
                target: target.as_str().to_owned(),
            },
            InvestigationEvent::ScopeEstablished {
                origin: format!("{:?}://{}:{}", origin.scheme, origin.host, origin.port),
            },
        ],
        ledger: BudgetLedger::new(budget),
    };

    ctx.state = InvestigationState::Planned;
    let Ok(rem) = ctx.ledger.try_consume_tool(started) else {
        return finish_budget_exhausted(
            ctx,
            "investigation budget exhausted before start".to_owned(),
        );
    };

    ctx.state = InvestigationState::Investigating;
    let exec_budget = ExecutionBudget {
        audit_timeout: rem,
        http_timeout: rem.min(Duration::from_secs(30)),
        ..ExecutionBudget::default()
    };
    let mut snapshot = backend.collect_http(&target, exec_budget, policy).await;
    let initial_report = analysis::run_all(&snapshot);
    let known_rules: HashSet<String> = initial_report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| f.rule_id.0.clone()))
        .collect();

    let http_ok = !matches!(snapshot.http, CollectorOutcome::Failed { .. });
    ctx.tool_trace.push(ToolInvocationRecord {
        tool_id: "inspect_http_and_source".to_owned(),
        dwarf_id: DwarfId::Netz,
        authorised: true,
        succeeded: http_ok,
        summary: format!(
            "collected HTTP/TLS snapshot and ran {} analysers",
            initial_report.analysers.len()
        ),
    });
    ctx.events.push(InvestigationEvent::ToolCompleted {
        tool_id: "inspect_http_and_source".to_owned(),
        succeeded: http_ok,
    });
    ctx.initial_report = Some(initial_report.clone());
    ctx.snapshot = Some(snapshot.clone());

    let mut used_tools = HashSet::new();
    let mut final_conclusion = String::new();

    while ctx.ledger.llm_turns_used < budget.max_llm_turns
        && !ctx.ledger.remaining_duration(started).is_zero()
    {
        let Ok(llm_rem) = ctx.ledger.try_consume_llm(started) else {
            return finish_budget_exhausted(ctx, "LLM turn budget exhausted".to_owned());
        };
        let decision = match propose_hypothesis(
            &ctx,
            &initial_report,
            &used_tools,
            llm,
            budget,
            llm_rem,
        )
        .await
        {
            Ok(d) => d,
            Err(err) => {
                ctx.state = InvestigationState::PartiallyCompleted;
                ctx.events
                    .push(InvestigationEvent::InvestigationPartiallyCompleted {
                        investigation_id: ctx.id.0.clone(),
                        reason: err.clone(),
                    });
                return build_report(
                    ctx,
                    format!(
                        "Initial deterministic audit completed; hypothesis generation failed: {err}"
                    ),
                );
            }
        };

        if decision.ready_to_conclude || decision.requested_tool.is_empty() {
            if let Some(c) = decision.conclusion {
                final_conclusion = c;
            }
            break;
        }

        if used_tools.contains(&decision.requested_tool) {
            break;
        }
        used_tools.insert(decision.requested_tool.clone());

        let rule_verified = known_rules.contains(&decision.originating_rule);
        let hyp_id = format!("hyp-{}", ctx.hypotheses.len() + 1);
        ctx.events.push(InvestigationEvent::HypothesisProposed {
            hypothesis_id: hyp_id.clone(),
            originating_rule: decision.originating_rule.clone(),
        });

        let mut hypothesis = DiagnosticHypothesis {
            id: hyp_id.clone(),
            originating_rule: RuleId(decision.originating_rule),
            originating_rule_verified: rule_verified,
            proposed_explanation: decision.proposed_explanation,
            requested_tool: decision.requested_tool.clone(),
            status: HypothesisStatus::Proposed,
            evaluation_summary: None,
            supporting_evidence: Vec::new(),
            contradictory_evidence: Vec::new(),
            missing_evidence: Vec::new(),
        };

        ctx.events.push(InvestigationEvent::ToolRequested {
            tool_id: decision.requested_tool.clone(),
        });
        let Ok(tool_rem) = ctx.ledger.try_consume_tool(started) else {
            ctx.events.push(InvestigationEvent::ToolRejected {
                tool_id: decision.requested_tool.clone(),
                reason: "tool call budget exhausted".to_owned(),
            });
            ctx.hypotheses.push(hypothesis);
            return finish_budget_exhausted(ctx, "tool call budget exhausted".to_owned());
        };
        ctx.events.push(InvestigationEvent::ToolAuthorised {
            tool_id: decision.requested_tool.clone(),
        });

        // Check for specialist consultation requests.
        let (tool_succeeded, new_results, is_consultation) =
            if let Some(dwarf_str) = decision.requested_tool.strip_prefix("consult_specialist:") {
                let dwarf_id = match dwarf_str {
                    "Netz" => Some(DwarfId::Netz),
                    "Sicherheits" => Some(DwarfId::Sicherheits),
                    "Leistungs" => Some(DwarfId::Leistungs),
                    "Struktur" => Some(DwarfId::Struktur),
                    "Zugaenglichkeits" => Some(DwarfId::Zugaenglichkeits),
                    "Such" => Some(DwarfId::Such),
                    "Inhalts" => Some(DwarfId::Inhalts),
                    "Gestaltungs" => Some(DwarfId::Gestaltungs),
                    "Browser" => Some(DwarfId::Browser),
                    "Dokumentations" => Some(DwarfId::Dokumentations),
                    _ => None,
                };
                if let Some(dwarf_id) = dwarf_id {
                    let (ok, results) = consult_specialist_during_investigation(
                        dwarf_id,
                        &hypothesis.proposed_explanation,
                        &mut ctx,
                        &initial_report,
                        llm,
                        tool_rem,
                        Arc::clone(&backend),
                        policy,
                    )
                    .await;
                    (ok, results, true)
                } else {
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: decision.requested_tool.clone(),
                        dwarf_id: DwarfId::Kommandant,
                        authorised: false,
                        succeeded: false,
                        summary: format!("invalid dwarf_id in consult request: {dwarf_str}"),
                    });
                    (false, Vec::new(), false)
                }
            } else {
                let (ok, results) = execute_rig_tool(
                    &decision.requested_tool,
                    &target,
                    policy,
                    tool_rem,
                    Arc::clone(&backend),
                    &mut snapshot,
                    &mut ctx,
                )
                .await;
                (ok, results, false)
            };
        // Consultation tool execution returns results that need to be added to follow_up_results.
        // Regular tool execution via execute_rig_tool already adds to ctx.follow_up_results internally.
        if is_consultation {
            ctx.follow_up_results.extend(new_results.clone());
        }
        ctx.snapshot = Some(snapshot.clone());
        ctx.events.push(InvestigationEvent::ToolCompleted {
            tool_id: decision.requested_tool.clone(),
            succeeded: tool_succeeded,
        });

        ctx.state = InvestigationState::Evaluating;
        let Ok(eval_rem) = ctx.ledger.try_consume_llm(started) else {
            hypothesis.status = HypothesisStatus::Inconclusive;
            ctx.hypotheses.push(hypothesis);
            return finish_budget_exhausted(ctx, "LLM evaluation budget exhausted".to_owned());
        };

        match evaluate_hypothesis(
            &new_results,
            tool_succeeded,
            &snapshot,
            &mut hypothesis,
            llm,
            budget,
            eval_rem,
        )
        .await
        {
            Ok(c) => {
                if hypothesis.status != HypothesisStatus::Inconclusive
                    || final_conclusion.is_empty()
                {
                    final_conclusion = c;
                }
            }
            Err(err) => {
                hypothesis.status = HypothesisStatus::Inconclusive;
                hypothesis.evaluation_summary = Some(err.clone());
                ctx.state = InvestigationState::PartiallyCompleted;
                ctx.hypotheses.push(hypothesis);
                return build_report(
                    ctx,
                    format!("Follow-up evidence collected, but LLM evaluation failed: {err}"),
                );
            }
        }
        ctx.events.push(InvestigationEvent::HypothesisEvaluated {
            hypothesis_id: hyp_id,
            status: format!("{:?}", hypothesis.status),
        });
        ctx.hypotheses.push(hypothesis);
        ctx.state = InvestigationState::Investigating;
    }

    ctx.state = InvestigationState::Completed;
    ctx.events.push(InvestigationEvent::InvestigationCompleted {
        investigation_id: ctx.id.0.clone(),
    });
    if final_conclusion.is_empty() {
        final_conclusion = format!(
            "Completed investigation with {} hypothesis evaluation(s).",
            ctx.hypotheses.len()
        );
    }
    build_report(ctx, final_conclusion)
}

async fn propose_hypothesis(
    ctx: &InvestigationContext,
    report: &AuditReport,
    used_tools: &HashSet<String>,
    llm: &dyn LlmProvider,
    budget: InvestigationBudget,
    timeout: Duration,
) -> Result<RawHypothesisDecision, String> {
    let tool_defs = registered_tool_definitions(
        &ctx.target,
        TargetPolicy::AllowPrivate,
        timeout,
        Arc::new(LiveDiagnosticBackend),
    );
    let mut available: Vec<String> = tool_defs
        .iter()
        .map(|d| d.name.clone())
        .filter(|name| {
            !used_tools.contains(name)
                && name != "inspect_previous_findings"
                && name != "verify_finding"
        })
        .collect();

    if !used_tools.contains("query_browser_timeline") {
        available.push("query_browser_timeline".to_owned());
    }

    // Add specialist consultation tools.
    for dwarf in &[
        "Netz",
        "Sicherheits",
        "Leistungs",
        "Struktur",
        "Zugaenglichkeits",
        "Such",
        "Inhalts",
        "Gestaltungs",
        "Browser",
    ] {
        let tool_name = format!("consult_specialist:{dwarf}");
        if !used_tools.contains(&tool_name) {
            available.push(tool_name);
        }
    }
    let available_refs: Vec<&str> = available.iter().map(String::as_str).collect();

    let contract = prompts::kommandant_hypothesis_prompt(&available_refs);
    let sys = contract.system_prompt;

    let summary: Vec<_> = report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter())
        .take(15)
        .map(|f| format!("{}: {}", f.rule_id.0, f.title))
        .collect();
    let prior_hyps: Vec<_> = ctx
        .hypotheses
        .iter()
        .map(|h| format!("{} ({:?})", h.id, h.status))
        .collect();
    let specialist_notes: Vec<_> = ctx
        .specialists
        .iter()
        .map(|s| {
            format!(
                "{:?} [{}]: {} (uncertainty: {})",
                s.dwarf_id,
                s.focus,
                s.observations.join("; "),
                s.uncertainty
            )
        })
        .collect();

    let user = format!(
        "{OPEN_TAG}\nobjective: {}\ntarget: {}\nprior_hypotheses: {}\nspecialist_contributions: {}\nfindings: {}\nsource_content_evidence: {}\nbrowser_timeline: {}\n{CLOSE_TAG}",
        ctx.objective.replace(CLOSE_TAG, ""),
        ctx.target.as_str(),
        prior_hyps.join(", "),
        specialist_notes.join(" | ").replace(CLOSE_TAG, ""),
        summary.join(" | ").replace(CLOSE_TAG, ""),
        crate::analysis::segmentation::content_evidence_context(ctx.snapshot.as_ref())
            .replace(CLOSE_TAG, ""),
        browser_timeline::timeline_context(ctx.snapshot.as_ref())
    );

    let raw = llm
        .complete(
            &sys,
            &user,
            LlmBudget {
                max_tokens: budget.max_tokens,
                max_requests: 1,
                timeout,
            },
        )
        .await?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid hypothesis JSON: {e}"))
}

/// Executes a single authorised specialist diagnostic tool against `snapshot`.
///
/// Reuses `execute_rig_tool` so scope and target policies are enforced
/// identically to `KommandantZwerg` investigations.
pub async fn run_specialist_tool_on_snapshot(
    tool_id: &str,
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    snapshot: &mut EvidenceSnapshot,
) -> (bool, Vec<AnalyserResult>) {
    let mut ctx = InvestigationContext {
        id: InvestigationId("specialist-delegation".to_owned()),
        target: target.clone(),
        objective: format!("Specialist tool `{tool_id}`"),
        state: InvestigationState::Investigating,
        snapshot: None,
        initial_report: None,
        follow_up_results: Vec::new(),
        discovered_pages: Vec::new(),
        systemic_issues: Vec::new(),
        specialists: Vec::new(),
        hypotheses: Vec::new(),
        tool_trace: Vec::new(),
        events: Vec::new(),
        ledger: BudgetLedger::new(InvestigationBudget::default()),
    };
    execute_rig_tool(
        tool_id, target, policy, timeout, backend, snapshot, &mut ctx,
    )
    .await
}

async fn execute_rig_tool(
    tool_id: &str,
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    snapshot: &mut EvidenceSnapshot,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let args = TargetToolArgs {
        url: target.as_str().to_owned(),
    };
    match tool_id {
        "inspect_browser_runtime" => {
            run_browser_tool(target, policy, timeout, backend, args, snapshot, ctx).await
        }
        "inspect_rendered_accessibility" => {
            run_axe_tool(target, policy, timeout, backend, args, snapshot, ctx).await
        }
        "inspect_page_performance" => {
            run_performance_tool(target, policy, timeout, backend, args, snapshot, ctx).await
        }
        "inspect_document_structure" => {
            run_structure_tool(target, policy, timeout, backend, args, ctx).await
        }
        "inspect_security_posture" => {
            run_security_tool(target, policy, timeout, backend, args, ctx).await
        }
        "crawl_and_cluster_site" => {
            run_crawl_tool(target, policy, timeout, backend, args, ctx).await
        }
        "query_browser_evidence" => {
            run_query_browser_tool(target, policy, timeout, backend, args, ctx).await
        }
        "query_browser_timeline" => {
            let page = browser_timeline::query_browser_timeline(snapshot, 0);
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: tool_id.to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: true,
                succeeded: page.as_ref().is_some_and(|page| !page.events.is_empty()),
                summary: page.as_ref().map_or_else(
                    || "browser timeline unavailable in snapshot".to_owned(),
                    |page| {
                        format!(
                            "snapshot timeline page contains {} events",
                            page.events.len()
                        )
                    },
                ),
            });
            (page.is_some_and(|page| !page.events.is_empty()), Vec::new())
        }
        _ => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: tool_id.to_owned(),
                dwarf_id: DwarfId::Kommandant,
                authorised: false,
                succeeded: false,
                summary: "rejected unrecognised or unauthorised tool request".to_owned(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_query_browser_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = QueryBrowserEvidenceTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(out) => {
            let succeeded = out.collection_status != "failed" && out.collection_status != "skipped";
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "query_browser_evidence".to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: true,
                succeeded,
                summary: format!(
                    "status={}, resources={}, third_party_hosts={}, error_kinds={}",
                    out.collection_status,
                    out.resource_count,
                    out.third_party_hosts.len(),
                    out.runtime_error_counts.len()
                ),
            });
            (succeeded, Vec::new())
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "query_browser_evidence".to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

/// Consults a specialist dwarf during investigation with full evidence context.
/// If specialist requests a tool, executes it and incorporates findings.
///
/// # Provider Routing
/// Currently uses the passed `llm` provider (typically Kommandant's model).
/// P1: Should accept `ProviderRouter` to resolve per-specialist models.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn consult_specialist_during_investigation(
    dwarf_id: DwarfId,
    question: &str,
    ctx: &mut InvestigationContext,
    initial_report: &AuditReport,
    llm: &dyn LlmProvider,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    policy: TargetPolicy,
) -> (bool, Vec<AnalyserResult>) {
    // Build evidence summary from investigation context.
    let finding_summary: Vec<String> = initial_report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter())
        .take(20)
        .map(|f| format!("[{:?}] {}: {}", f.severity, f.rule_id.0, f.title))
        .collect();
    let follow_up_summary: Vec<String> = ctx
        .follow_up_results
        .iter()
        .flat_map(|r| r.findings.iter())
        .take(10)
        .map(|f| format!("[{:?}] {}: {}", f.severity, f.rule_id.0, f.title))
        .collect();
    let prior_hyp_summary: Vec<String> = ctx
        .hypotheses
        .iter()
        .map(|h| format!("{} ({:?}): {}", h.id, h.status, h.proposed_explanation))
        .collect();
    let prior_specialist_summary: Vec<String> = ctx
        .specialists
        .iter()
        .map(|s| {
            format!(
                "{:?} [{}]: {}",
                s.dwarf_id,
                s.focus,
                s.observations.join("; ")
            )
        })
        .collect();

    let contract = prompts::specialist_prompt(dwarf_id, question);
    let evidence_context = format!(
        "Investigation objective: {}\nTarget: {}\n\
         Initial findings: {}\n\
         Follow-up findings: {}\n\
         Prior hypotheses: {}\n\
         Prior specialist contributions: {}\n\
         Source content evidence: {}\n\
         Browser timeline: {}\n\
         Question: {}",
        ctx.objective,
        ctx.target.as_str(),
        finding_summary.join(" | "),
        follow_up_summary.join(" | "),
        prior_hyp_summary.join(" | "),
        prior_specialist_summary.join(" | "),
        crate::analysis::segmentation::content_evidence_context(ctx.snapshot.as_ref()),
        browser_timeline::timeline_context(ctx.snapshot.as_ref()),
        question
    );

    let llm_budget = LlmBudget {
        max_tokens: 512,
        max_requests: 1,
        timeout,
    };

    match llm
        .complete(&contract.system_prompt, &evidence_context, llm_budget)
        .await
    {
        Ok(raw_resp) => {
            // Attempt structured parse; reject unstructured responses.
            let Ok(mut structured) =
                serde_json::from_str::<crate::patrol::SpecialistOutput>(&raw_resp)
            else {
                eprintln!("Specialist consultation failed: unstructured response");
                return (false, Vec::new());
            };

            let mut tool_results = Vec::new();

            // Execute tool if specialist requested one.
            if let Some(ref tool_id) = structured.requested_tool
                && let Some(ref mut snapshot) = ctx.snapshot
            {
                let (tool_ok, tool_outputs) = run_specialist_tool_on_snapshot(
                    tool_id,
                    &ctx.target,
                    policy,
                    timeout,
                    backend,
                    snapshot,
                )
                .await;

                if tool_ok {
                    for res in &tool_outputs {
                        for f in &res.findings {
                            structured.evidence_refs.push(f.rule_id.0.clone());
                            structured
                                .confirmed_observations
                                .push(format!("{}: {}", f.rule_id.0, f.title));
                        }
                    }
                    tool_results = tool_outputs;
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: tool_id.clone(),
                        dwarf_id,
                        authorised: true,
                        succeeded: true,
                        summary: format!(
                            "specialist tool execution via consultation: {} findings",
                            tool_results.iter().map(|r| r.findings.len()).sum::<usize>()
                        ),
                    });
                }
            }

            let contribution = SpecialistContribution {
                dwarf_id,
                focus: question.to_owned(),
                observations: structured.confirmed_observations,
                uncertainty: structured.remaining_uncertainty,
            };
            ctx.specialists.push(contribution);
            ctx.events.push(InvestigationEvent::SpecialistActivated {
                dwarf_id,
                focus: question.to_owned(),
            });

            (true, tool_results)
        }
        Err(err) => {
            eprintln!("Specialist consultation failed: {err}");
            (false, Vec::new())
        }
    }
}

fn record_specialist(
    ctx: &mut InvestigationContext,
    dwarf_id: DwarfId,
    focus: &str,
    results: &[AnalyserResult],
    uncertainty: &str,
) {
    let observations: Vec<String> = results
        .iter()
        .flat_map(|r| r.findings.iter())
        .map(|f| format!("{}: {}", f.rule_id.0, f.title))
        .collect();
    let final_obs = if observations.is_empty() {
        vec!["No defects reported by specialist checks.".to_owned()]
    } else {
        observations
    };
    ctx.specialists.push(SpecialistContribution {
        dwarf_id,
        focus: focus.to_owned(),
        observations: final_obs,
        uncertainty: uncertainty.to_owned(),
    });
    ctx.events.push(InvestigationEvent::SpecialistActivated {
        dwarf_id,
        focus: focus.to_owned(),
    });
}

async fn run_browser_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    snapshot: &mut EvidenceSnapshot,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = InspectBrowserRuntimeTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(out) => {
            snapshot.browser = out.outcome.clone();
            let succeeded = !matches!(out.outcome, CollectorOutcome::Failed { .. });
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_browser_runtime".to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: true,
                succeeded,
                summary: format!(
                    "browser findings: {}, visual findings: {}",
                    out.browser_result.findings.len(),
                    out.visual_result.findings.len()
                ),
            });
            let results = vec![out.browser_result, out.visual_result];
            record_specialist(
                ctx,
                DwarfId::Browser,
                "Headless runtime console & layout",
                &results,
                "External observation only; client-side state transitions beyond initial load were not exercised.",
            );
            ctx.follow_up_results.extend(results.clone());
            (succeeded, results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_browser_runtime".to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_axe_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    snapshot: &mut EvidenceSnapshot,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = InspectRenderedAccessibilityTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(out) => {
            snapshot.axe = out.outcome.clone();
            let succeeded = !matches!(out.outcome, CollectorOutcome::Failed { .. });
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_rendered_accessibility".to_owned(),
                dwarf_id: DwarfId::Zugaenglichkeits,
                authorised: true,
                succeeded,
                summary: format!("rendered a11y findings: {}", out.axe_result.findings.len()),
            });
            let results = vec![out.axe_result];
            record_specialist(
                ctx,
                DwarfId::Zugaenglichkeits,
                "Rendered DOM accessibility (axe-core)",
                &results,
                "Automated checks cannot verify keyboard focus order or full WCAG compliance.",
            );
            ctx.follow_up_results.extend(results.clone());
            (succeeded, results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_rendered_accessibility".to_owned(),
                dwarf_id: DwarfId::Zugaenglichkeits,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_performance_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    snapshot: &mut EvidenceSnapshot,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = InspectPagePerformanceTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(out) => {
            snapshot.lighthouse = out.outcome.clone();
            let succeeded = !matches!(out.outcome, CollectorOutcome::Failed { .. });
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_page_performance".to_owned(),
                dwarf_id: DwarfId::Leistungs,
                authorised: true,
                succeeded,
                summary: format!(
                    "Lighthouse CWV findings: {}",
                    out.performance_result.findings.len()
                ),
            });
            let results = vec![out.performance_result];
            record_specialist(
                ctx,
                DwarfId::Leistungs,
                "Core Web Vitals (Lighthouse laboratory metrics)",
                &results,
                "Laboratory measurements do not replace real-user field telemetry (CrUX/RUM).",
            );
            ctx.follow_up_results.extend(results.clone());
            (succeeded, results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_page_performance".to_owned(),
                dwarf_id: DwarfId::Leistungs,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_structure_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = InspectDocumentStructureTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(res) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_document_structure".to_owned(),
                dwarf_id: DwarfId::Struktur,
                authorised: true,
                succeeded: true,
                summary: format!("structural findings: {}", res.findings.len()),
            });
            let results = vec![res];
            record_specialist(
                ctx,
                DwarfId::Struktur,
                "Semantic HTML structure and interactive semantics",
                &results,
                "Source-level HTML inspection; client-side DOM mutations require BrowserZwerg.",
            );
            ctx.follow_up_results.extend(results.clone());
            (true, results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_document_structure".to_owned(),
                dwarf_id: DwarfId::Struktur,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_security_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = InspectSecurityPostureTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(res) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_security_posture".to_owned(),
                dwarf_id: DwarfId::Sicherheits,
                authorised: true,
                succeeded: true,
                summary: format!("security findings: {}", res.findings.len()),
            });
            let results = vec![res];
            record_specialist(
                ctx,
                DwarfId::Sicherheits,
                "Passive transport & security header posture",
                &results,
                "Passive inspection only; not a penetration test.",
            );
            ctx.follow_up_results.extend(results.clone());
            (true, results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "inspect_security_posture".to_owned(),
                dwarf_id: DwarfId::Sicherheits,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn run_crawl_tool(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
    args: TargetToolArgs,
    ctx: &mut InvestigationContext,
) -> (bool, Vec<AnalyserResult>) {
    let tool = CrawlAndClusterTool::new(target.clone(), policy, timeout, backend);
    match tool.call(args).await {
        Ok(summary) => {
            let investigated = summary
                .pages
                .iter()
                .filter(|p| p.status == PageCrawlStatus::Investigated)
                .count();
            let succeeded = investigated > 0;
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "crawl_and_cluster_site".to_owned(),
                dwarf_id: DwarfId::Netz,
                authorised: true,
                succeeded,
                summary: format!(
                    "crawled {}/{} discovered pages; {} systemic issue(s)",
                    investigated,
                    summary.pages.len(),
                    summary.systemic_issues.len()
                ),
            });
            ctx.discovered_pages = summary.pages;
            ctx.systemic_issues = summary.systemic_issues;
            ctx.follow_up_results.extend(summary.graph_results.clone());
            (succeeded, summary.graph_results)
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "crawl_and_cluster_site".to_owned(),
                dwarf_id: DwarfId::Netz,
                authorised: false,
                succeeded: false,
                summary: err.to_string(),
            });
            (false, Vec::new())
        }
    }
}

async fn evaluate_hypothesis(
    new_results: &[AnalyserResult],
    tool_succeeded: bool,
    snapshot: &EvidenceSnapshot,
    hypothesis: &mut DiagnosticHypothesis,
    llm: &dyn LlmProvider,
    budget: InvestigationBudget,
    timeout: Duration,
) -> Result<String, String> {
    if !tool_succeeded {
        hypothesis.status = HypothesisStatus::Inconclusive;
        let msg = format!(
            "Follow-up tool `{}` failed or produced no usable evidence; hypothesis cannot be confirmed.",
            hypothesis.requested_tool
        );
        hypothesis.evaluation_summary = Some(msg.clone());
        return Ok(msg);
    }

    let contract = prompts::kommandant_evaluation_prompt();
    let sys = &contract.system_prompt;

    let follow_up: Vec<_> = new_results
        .iter()
        .flat_map(|r| r.findings.iter())
        .map(|f| format!("{}: {}", f.rule_id.0, f.title))
        .collect();

    let timeline_requested = matches!(
        hypothesis.requested_tool.as_str(),
        "query_browser_timeline" | "inspect_browser_runtime"
    );
    let timeline = if timeline_requested {
        browser_timeline::timeline_context(Some(snapshot))
    } else {
        "not requested".to_owned()
    };
    let user = format!(
        "{OPEN_TAG}\nhypothesis: {}\nfollow_up_findings: {}\nbrowser_timeline: {timeline}\n{CLOSE_TAG}",
        hypothesis.proposed_explanation.replace(CLOSE_TAG, ""),
        follow_up.join(" | ").replace(CLOSE_TAG, "")
    );

    let raw = llm
        .complete(
            sys,
            &user,
            LlmBudget {
                max_tokens: budget.max_tokens,
                max_requests: 1,
                timeout,
            },
        )
        .await?;
    let eval: RawEvaluationDecision =
        serde_json::from_str(&raw).map_err(|e| format!("invalid evaluation JSON: {e}"))?;

    let mut refs: Vec<EvidenceRef> = new_results
        .iter()
        .flat_map(|r| r.findings.iter())
        .flat_map(|f| f.evidence_refs.iter().cloned())
        .collect();
    if timeline_requested {
        refs.extend(browser_timeline::cited_event_refs(
            snapshot,
            &eval.timeline_sequences,
        ));
    }
    if hypothesis.requested_tool == "query_browser_timeline"
        && refs.is_empty()
        && matches!(
            eval.status,
            HypothesisStatus::Supported | HypothesisStatus::Rejected
        )
    {
        hypothesis.status = HypothesisStatus::Inconclusive;
        let message =
            "Timeline evaluation did not cite an event from the supplied page.".to_owned();
        hypothesis.evaluation_summary = Some(message.clone());
        return Ok(message);
    }
    hypothesis.status = eval.status;
    hypothesis.evaluation_summary = Some(eval.evaluation_summary);
    if refs.is_empty() && eval.status == HypothesisStatus::Supported {
        hypothesis.missing_evidence.push(
            "Follow-up tool emitted no supporting findings; treat conclusion with caution."
                .to_owned(),
        );
    }
    match eval.status {
        HypothesisStatus::Supported => hypothesis.supporting_evidence = refs,
        HypothesisStatus::Rejected => hypothesis.contradictory_evidence = refs,
        HypothesisStatus::Proposed | HypothesisStatus::Inconclusive => {}
    }
    Ok(eval.conclusion)
}

fn finish_budget_exhausted(mut ctx: InvestigationContext, reason: String) -> InvestigationReport {
    ctx.state = InvestigationState::BudgetExhausted;
    ctx.events
        .push(InvestigationEvent::InvestigationPartiallyCompleted {
            investigation_id: ctx.id.0.clone(),
            reason: reason.clone(),
        });
    build_report(ctx, reason)
}

fn build_report(ctx: InvestigationContext, conclusion: String) -> InvestigationReport {
    let (executive_brief, release_readiness, remediation_tasks) =
        reporting::build_stakeholder_outputs(&ctx);
    InvestigationReport {
        id: ctx.id,
        target: ctx.target,
        objective: ctx.objective,
        state: ctx.state,
        snapshot: ctx.snapshot,
        initial_report: ctx.initial_report,
        follow_up_results: ctx.follow_up_results,
        discovered_pages: ctx.discovered_pages,
        systemic_issues: ctx.systemic_issues,
        specialists: ctx.specialists,
        hypotheses: ctx.hypotheses,
        tool_trace: ctx.tool_trace,
        events: ctx.events,
        ledger: ctx.ledger,
        executive_brief,
        release_readiness,
        remediation_tasks,
        conclusion,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::domain::{
        ConsoleErrorEvent, HttpEvidence, HttpHeader, Measurement, MeasurementUnit,
    };
    use crate::intelligence::LlmFuture;

    struct MockBackend {
        browser: CollectorOutcome<BrowserEvidence>,
        axe: CollectorOutcome<AxeEvidence>,
        lighthouse: CollectorOutcome<LighthouseMetrics>,
    }

    impl DiagnosticBackend for MockBackend {
        fn collect_http<'a>(
            &'a self,
            target: &'a AuditTarget,
            _budget: ExecutionBudget,
            _policy: TargetPolicy,
        ) -> CollectFuture<'a, EvidenceSnapshot> {
            let snap = EvidenceSnapshot {
                target: target.clone(),
                captured_at_unix_secs: 1_700_000_000,
                http: CollectorOutcome::Captured {
                    data: HttpEvidence {
                        final_url: target.as_str().to_owned(),
                        status_code: 200,
                        redirect_chain: Vec::new(),
                        headers: vec![HttpHeader {
                            name: "content-type".to_owned(),
                            value: "text/html".to_owned(),
                        }],
                        elapsed_ms: Measurement::Measured {
                            value: 1_800,
                            unit: MeasurementUnit::Milliseconds,
                        },
                        body_bytes: 120,
                        body_truncated: false,
                        body_text: "<html><body><script src='/app.js'></script></body></html>"
                            .to_owned(),
                    },
                },
                tls: CollectorOutcome::default(),
                browser: CollectorOutcome::default(),
                lighthouse: CollectorOutcome::default(),
                axe: CollectorOutcome::default(),
            };
            Box::pin(async move { snap })
        }

        fn collect_browser<'a>(
            &'a self,
            _target: &'a AuditTarget,
            _timeout: Duration,
        ) -> CollectFuture<'a, CollectorOutcome<BrowserEvidence>> {
            let b = self.browser.clone();
            Box::pin(async move { b })
        }

        fn collect_axe<'a>(
            &'a self,
            _target: &'a AuditTarget,
            _timeout: Duration,
        ) -> CollectFuture<'a, CollectorOutcome<AxeEvidence>> {
            let a = self.axe.clone();
            Box::pin(async move { a })
        }

        fn collect_lighthouse<'a>(
            &'a self,
            _target: &'a AuditTarget,
            _timeout: Duration,
        ) -> CollectFuture<'a, CollectorOutcome<LighthouseMetrics>> {
            let l = self.lighthouse.clone();
            Box::pin(async move { l })
        }

        fn collect_crawl<'a>(
            &'a self,
            target: &'a AuditTarget,
            _crawl_budget: CrawlBudget,
            _exec_budget: ExecutionBudget,
            _policy: TargetPolicy,
        ) -> CollectFuture<'a, CrawlSummary> {
            let seed = target.clone();
            Box::pin(async move {
                CrawlSummary {
                    seed: seed.clone(),
                    pages: vec![DiscoveredPage {
                        url: seed,
                        page_type: crate::discovery::PageType::Homepage,
                        depth: 0,
                        status: PageCrawlStatus::Investigated,
                    }],
                    systemic_issues: Vec::new(),
                    budget_exhausted: false,
                    graph_results: Vec::new(),
                }
            })
        }
    }

    struct SequenceLlm {
        responses: Mutex<VecDeque<String>>,
    }

    impl LlmProvider for SequenceLlm {
        fn model_name(&self) -> &'static str {
            "mock-kommandant"
        }

        fn complete<'a>(
            &'a self,
            _system_prompt: &'a str,
            _user_prompt: &'a str,
            _budget: LlmBudget,
        ) -> LlmFuture<'a> {
            let next = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| "{}".to_owned());
            Box::pin(async move { Ok(next) })
        }
    }

    #[tokio::test]
    async fn collaborative_performance_diagnosis_chains_leistungs_browser_and_struktur() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Captured {
                data: BrowserEvidence {
                    final_url: "http://example.org/".to_owned(),
                    browser_version: Some("Chromium 131".to_owned()),
                    console_errors: vec![ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "ReferenceError: app is not defined".to_owned(),
                        ..ConsoleErrorEvent::default()
                    }],
                    failed_requests: Vec::new(),
                    viewports: Vec::new(),
                    ..BrowserEvidence::default()
                },
            },
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::Captured {
                data: LighthouseMetrics {
                    lighthouse_version: "12.0.0".to_owned(),
                    lcp_ms: Measurement::Measured {
                        value: 4_200,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    cls_milli: Measurement::Measured {
                        value: 50,
                        unit: MeasurementUnit::Count,
                    },
                    fcp_ms: Measurement::Measured {
                        value: 1_200,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    tbt_ms: Measurement::Measured {
                        value: 150,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    performance_score: Some(58),
                    provenance: None,
                },
            },
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Slow mobile LCP likely accompanies slow HTTP exchange","requested_tool":"inspect_page_performance"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"LeistungsZwerg measured LCP = 4200 ms","conclusion":"CWV degradation confirmed."}"#.to_owned(),
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Blocking script failure may delay rendering","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"BrowserZwerg observed ReferenceError","conclusion":"Runtime JS failure confirmed."}"#.to_owned(),
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Verify document structure for blocking or malformed elements","requested_tool":"inspect_document_structure"}"#.to_owned(),
                r#"{"status":"rejected","evaluation_summary":"Document structure did not show structural defects","conclusion":"Performance and JS runtime defects confirmed; structure is clean."}"#.to_owned(),
            ])),
        };

        let budget = InvestigationBudget {
            max_tool_calls: 5,
            max_llm_turns: 6,
            ..InvestigationBudget::default()
        };
        let report = run_investigation(
            target,
            "Investigate mobile loading performance".to_owned(),
            TargetPolicy::PublicOnly,
            budget,
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::Completed);
        assert_eq!(report.specialists.len(), 3);
        assert_eq!(report.hypotheses.len(), 3);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
        assert_eq!(report.hypotheses[1].status, HypothesisStatus::Supported);
        assert_eq!(report.hypotheses[2].status, HypothesisStatus::Rejected);
        assert_ne!(report.events.len(), 0);
        let cto_md =
            render_role_perspective_markdown(&report, RolePerspective::CtoEngineeringManager);
        assert!(cto_md.contains("## Specialist Contributions"));
    }

    #[tokio::test]
    async fn kommandant_consults_specialist_with_full_context() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                // Kommandant requests specialist consultation.
                r#"{"ready_to_conclude":false,"originating_rule":"sec.http.tls","proposed_explanation":"TLS configuration unclear; consult SicherheitsZwerg","requested_tool":"consult_specialist:Sicherheits"}"#.to_owned(),
                // Specialist responds requesting security tool for detailed inspection.
                r#"{"confirmed_observations":[],"evidence_refs":[],"remaining_uncertainty":"Need detailed TLS inspection","requested_tool":"inspect_security_posture","recommendation":"Run security analysis"}"#.to_owned(),
                // Kommandant evaluates with specialist input + tool findings.
                r#"{"status":"supported","evaluation_summary":"SicherheitsZwerg confirmed TLS 1.2 via security inspection","conclusion":"TLS configuration confirmed but outdated."}"#.to_owned(),
            ])),
        };

        let budget = InvestigationBudget {
            max_tool_calls: 2,
            max_llm_turns: 3,
            ..InvestigationBudget::default()
        };
        let report = run_investigation(
            target,
            "Assess TLS configuration".to_owned(),
            TargetPolicy::PublicOnly,
            budget,
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::Completed);
        assert_eq!(
            report.specialists.len(),
            1,
            "Should record one specialist consultation"
        );
        assert_eq!(report.specialists[0].dwarf_id, DwarfId::Sicherheits);
        assert!(
            report.specialists[0]
                .focus
                .contains("TLS configuration unclear")
        );
        // Specialist requested tool execution, should have observations from tool findings.
        assert!(
            !report.specialists[0].observations.is_empty(),
            "Specialist should have observations from tool execution"
        );
        assert_eq!(report.hypotheses.len(), 1);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
        // Verify tool was executed during consultation.
        assert!(
            report
                .tool_trace
                .iter()
                .any(|t| t.tool_id == "inspect_security_posture"
                    && t.dwarf_id == DwarfId::Sicherheits),
            "Tool should be traced to specialist"
        );
    }

    #[tokio::test]
    async fn failed_follow_up_forces_inconclusive_even_if_llm_would_support() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Failed {
                error: "chromium missing".to_owned(),
            },
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Check runtime","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"Should never be used","conclusion":"Should never be used"}"#.to_owned(),
                r#"{"ready_to_conclude":true,"conclusion":"Browser unavailable; inconclusive."}"#.to_owned(),
            ])),
        };

        let report = run_investigation(
            target,
            "Check runtime".to_owned(),
            TargetPolicy::PublicOnly,
            InvestigationBudget::default(),
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.hypotheses.len(), 1);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Inconclusive);
        assert_eq!(report.hypotheses[0].supporting_evidence.len(), 0);
    }

    #[tokio::test]
    async fn enforces_tool_call_budget_outside_llm() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"sec.transport.https","proposed_explanation":"Check browser","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
            ])),
        };
        let tight_budget = InvestigationBudget {
            max_tool_calls: 1,
            ..InvestigationBudget::default()
        };

        let report = run_investigation(
            target,
            "Quick check".to_owned(),
            TargetPolicy::PublicOnly,
            tight_budget,
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::BudgetExhausted);
        assert_eq!(report.ledger.tool_calls_used, 1);
        assert_eq!(
            report.release_readiness.state,
            ReleaseReadinessState::PotentialReleaseBlockers
        );
        let md = render_markdown_report(&report);
        assert!(md.contains("# NetzZwergenWacht Investigation Report"));
        assert!(md.contains("## Backlog Remediation Tasks"));
    }

    #[tokio::test]
    async fn preserves_supported_conclusion_when_later_hypothesis_is_inconclusive() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Failed {
                error: "chromium unavailable".to_owned(),
            },
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"sec.transport.https","proposed_explanation":"Check security headers","requested_tool":"inspect_security_posture"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"Confirmed missing HTTPS and security headers","conclusion":"Transport and security headers require remediation."}"#.to_owned(),
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Check browser runtime","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
                r#"{"ready_to_conclude":true,"conclusion":"Transport and security headers require remediation."}"#.to_owned(),
            ])),
        };

        let report = run_investigation(
            target,
            "Verify security and runtime".to_owned(),
            TargetPolicy::PublicOnly,
            InvestigationBudget::default(),
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.hypotheses.len(), 2);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
        assert_eq!(report.hypotheses[1].status, HypothesisStatus::Inconclusive);
        assert_eq!(
            report.conclusion,
            "Transport and security headers require remediation."
        );
    }

    #[tokio::test]
    async fn deduplicates_remediation_tasks_across_initial_and_follow_up_findings() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"sec.transport.https","proposed_explanation":"Check security posture","requested_tool":"inspect_security_posture"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"Confirmed","conclusion":"Confirmed."}"#.to_owned(),
                r#"{"ready_to_conclude":true,"conclusion":"Confirmed."}"#.to_owned(),
            ])),
        };

        let report = run_investigation(
            target,
            "Verify deduplication".to_owned(),
            TargetPolicy::PublicOnly,
            InvestigationBudget::default(),
            backend,
            &llm,
        )
        .await;

        let mut seen = HashSet::new();
        for task in &report.remediation_tasks {
            let key = (
                task.related_rules.first().map(|r| r.0.clone()),
                task.title.clone(),
            );
            assert!(
                seen.insert(key),
                "duplicate remediation task emitted: {}",
                task.title
            );
        }
    }

    #[tokio::test]
    async fn cross_domain_csp_and_runtime_failure_scenario_correlates_browser_and_security() {
        let target = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Captured {
                data: BrowserEvidence {
                    final_url: "https://example.org/".to_owned(),
                    console_errors: vec![ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "CSP violation (script-src): blocked https://cdn.example.net/app.js"
                            .to_owned(),
                        error_kind: Some("csp_violation".to_owned()),
                        source_url: Some("https://example.org/".to_owned()),
                        line_number: Some(12),
                    }],
                    ..BrowserEvidence::default()
                },
            },
            axe: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"browser.js.csp_violation","proposed_explanation":"CSP blocks critical app bundle","requested_tool":"query_browser_evidence"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"Confirmed CSP violation blocking script-src","conclusion":"Confirmed."}"#.to_owned(),
                r#"{"ready_to_conclude":true,"conclusion":"CSP script-src blocks the application bundle, explaining missing interactive rendering."}"#.to_owned(),
            ])),
        };

        let report = run_investigation(
            target,
            "Investigate CSP-induced runtime failure".to_owned(),
            TargetPolicy::PublicOnly,
            InvestigationBudget::default(),
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::Completed);
        assert_ne!(report.hypotheses.len(), 0);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
    }
}
