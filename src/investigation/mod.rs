//! Agentic investigation domain model and `KommandantZwerg` orchestrator.
//!
//! Implements the Milestone B multi-turn investigation loop backed by `rig-core`
//! [`PortableTool`] definitions:
//! initial reconnaissance -> `KommandantZwerg` hypothesis generation ->
//! budget-enforced typed diagnostic tool invocation -> additional evidence
//! collection -> hypothesis evaluation -> structured [`InvestigationReport`]
//! with [`ExecutiveBrief`] and backlog-ready [`RemediationTask`]s.

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
    EvidenceSnapshot, ExecutionBudget, Finding, RuleId, Severity, TargetPolicy,
};
use crate::intelligence::{LlmBudget, LlmProvider};

use self::tools::{
    CrawlAndClusterTool, InspectBrowserRuntimeTool, InspectRenderedAccessibilityTool,
    TargetToolArgs, registered_tool_definitions,
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
            max_tool_calls: 4,
            max_llm_turns: 4,
            max_duration: Duration::from_secs(90),
            max_tokens: 1_024,
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
    /// Related deterministic rule IDs.
    pub related_rules: Vec<RuleId>,
    /// Suggested acceptance criteria for delivery teams.
    pub acceptance_criteria: Vec<String>,
    /// Verification procedure to confirm completion.
    pub verification_procedure: String,
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
    /// Additional Level 2 specialist results gathered during investigation.
    pub follow_up_results: Vec<AnalyserResult>,
    /// Pages discovered during optional multi-page crawl.
    pub discovered_pages: Vec<DiscoveredPage>,
    /// Systemic cross-page issues identified during crawl.
    pub systemic_issues: Vec<SystemicIssue>,
    /// Hypotheses formulated and evaluated during the investigation.
    pub hypotheses: Vec<DiagnosticHypothesis>,
    /// Complete trace of tool invocations.
    pub tool_trace: Vec<ToolInvocationRecord>,
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
    /// Additional Level 2 specialist results.
    pub follow_up_results: Vec<AnalyserResult>,
    /// Pages discovered during optional multi-page crawl.
    pub discovered_pages: Vec<DiscoveredPage>,
    /// Systemic cross-page issues identified during crawl.
    pub systemic_issues: Vec<SystemicIssue>,
    /// Evaluated hypotheses.
    pub hypotheses: Vec<DiagnosticHypothesis>,
    /// Complete tool execution trace.
    pub tool_trace: Vec<ToolInvocationRecord>,
    /// Budget consumption summary.
    pub ledger: BudgetLedger,
    /// Stakeholder-facing executive brief.
    pub executive_brief: ExecutiveBrief,
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
    evaluation_summary: String,
    conclusion: String,
}

/// Executes the multi-turn `KommandantZwerg` agentic investigation loop.
#[allow(clippy::too_many_lines)]
pub async fn run_investigation(
    target: AuditTarget,
    objective: String,
    policy: TargetPolicy,
    budget: InvestigationBudget,
    backend: Arc<dyn DiagnosticBackend>,
    llm: &dyn LlmProvider,
) -> InvestigationReport {
    let started = Instant::now();
    let mut ctx = InvestigationContext {
        id: InvestigationId::generate(target.host()),
        target: target.clone(),
        objective,
        state: InvestigationState::Scoped,
        snapshot: None,
        initial_report: None,
        follow_up_results: Vec::new(),
        discovered_pages: Vec::new(),
        systemic_issues: Vec::new(),
        hypotheses: Vec::new(),
        tool_trace: Vec::new(),
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

    ctx.tool_trace.push(ToolInvocationRecord {
        tool_id: "inspect_http_and_source".to_owned(),
        dwarf_id: DwarfId::Netz,
        authorised: true,
        succeeded: !matches!(snapshot.http, CollectorOutcome::Failed { .. }),
        summary: format!(
            "collected HTTP/TLS snapshot and ran {} analysers",
            initial_report.analysers.len()
        ),
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
        let mut hypothesis = DiagnosticHypothesis {
            id: format!("hyp-{}", ctx.hypotheses.len() + 1),
            originating_rule: RuleId(decision.originating_rule),
            originating_rule_verified: rule_verified,
            proposed_explanation: decision.proposed_explanation,
            requested_tool: decision.requested_tool.clone(),
            status: HypothesisStatus::Proposed,
            evaluation_summary: None,
            supporting_evidence: Vec::new(),
            contradictory_evidence: Vec::new(),
        };

        let Ok(tool_rem) = ctx.ledger.try_consume_tool(started) else {
            ctx.hypotheses.push(hypothesis);
            return finish_budget_exhausted(ctx, "tool call budget exhausted".to_owned());
        };

        let (tool_succeeded, new_results) = execute_rig_tool(
            &decision.requested_tool,
            &target,
            policy,
            tool_rem,
            Arc::clone(&backend),
            &mut snapshot,
            &mut ctx,
        )
        .await;
        ctx.snapshot = Some(snapshot.clone());

        ctx.state = InvestigationState::Evaluating;
        let Ok(eval_rem) = ctx.ledger.try_consume_llm(started) else {
            hypothesis.status = HypothesisStatus::Inconclusive;
            ctx.hypotheses.push(hypothesis);
            return finish_budget_exhausted(ctx, "LLM evaluation budget exhausted".to_owned());
        };

        match evaluate_hypothesis(
            &new_results,
            tool_succeeded,
            &mut hypothesis,
            llm,
            budget,
            eval_rem,
        )
        .await
        {
            Ok(c) => final_conclusion = c,
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
        ctx.hypotheses.push(hypothesis);
        ctx.state = InvestigationState::Investigating;
    }

    ctx.state = InvestigationState::Completed;
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
    let available: Vec<&str> = tool_defs
        .iter()
        .map(|d| d.name.as_str())
        .filter(|name| !used_tools.contains(*name))
        .collect();

    let sys = format!(
        "You are KommandantZwerg. Available unused tools: {available:?}. \
Propose one falsifiable hypothesis grounded in an existing rule_id and pick one unused tool, \
or set `ready_to_conclude: true` if sufficient evidence was gathered. \
Respond strictly with JSON: {{\"ready_to_conclude\": bool, \"originating_rule\": string, \
\"proposed_explanation\": string, \"requested_tool\": string, \"conclusion\": string|null}}."
    );

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

    let user = format!(
        "{OPEN_TAG}\nobjective: {}\ntarget: {}\nprior_hypotheses: {}\nfindings: {}\n{CLOSE_TAG}",
        ctx.objective.replace(CLOSE_TAG, ""),
        ctx.target.as_str(),
        prior_hyps.join(", "),
        summary.join(" | ").replace(CLOSE_TAG, "")
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
            let tool = InspectBrowserRuntimeTool::new(target.clone(), policy, timeout, backend);
            match tool.call(args).await {
                Ok(out) => {
                    snapshot.browser = out.outcome.clone();
                    let succeeded = !matches!(out.outcome, CollectorOutcome::Failed { .. });
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: tool_id.to_owned(),
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
                    ctx.follow_up_results.extend(results.clone());
                    (succeeded, results)
                }
                Err(err) => {
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: tool_id.to_owned(),
                        dwarf_id: DwarfId::Browser,
                        authorised: false,
                        succeeded: false,
                        summary: err.to_string(),
                    });
                    (false, Vec::new())
                }
            }
        }
        "inspect_rendered_accessibility" => {
            let tool =
                InspectRenderedAccessibilityTool::new(target.clone(), policy, timeout, backend);
            match tool.call(args).await {
                Ok(out) => {
                    snapshot.axe = out.outcome.clone();
                    let succeeded = !matches!(out.outcome, CollectorOutcome::Failed { .. });
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: tool_id.to_owned(),
                        dwarf_id: DwarfId::Zugaenglichkeits,
                        authorised: true,
                        succeeded,
                        summary: format!(
                            "rendered a11y findings: {}",
                            out.axe_result.findings.len()
                        ),
                    });
                    let results = vec![out.axe_result];
                    ctx.follow_up_results.extend(results.clone());
                    (succeeded, results)
                }
                Err(err) => {
                    ctx.tool_trace.push(ToolInvocationRecord {
                        tool_id: tool_id.to_owned(),
                        dwarf_id: DwarfId::Zugaenglichkeits,
                        authorised: false,
                        succeeded: false,
                        summary: err.to_string(),
                    });
                    (false, Vec::new())
                }
            }
        }
        "crawl_and_cluster_site" => {
            run_crawl_tool(target, policy, timeout, backend, args, ctx).await
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
                dwarf_id: DwarfId::Struktur,
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
            (succeeded, Vec::new())
        }
        Err(err) => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: "crawl_and_cluster_site".to_owned(),
                dwarf_id: DwarfId::Struktur,
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

    let sys = "You are KommandantZwerg evaluating a diagnostic hypothesis against follow-up \
evidence. Respond strictly with JSON: {\"status\": \"supported\"|\"rejected\"|\"inconclusive\", \
\"evaluation_summary\": string, \"conclusion\": string}.";

    let follow_up: Vec<_> = new_results
        .iter()
        .flat_map(|r| r.findings.iter())
        .map(|f| format!("{}: {}", f.rule_id.0, f.title))
        .collect();

    let user = format!(
        "{OPEN_TAG}\nhypothesis: {}\nfollow_up_findings: {}\n{CLOSE_TAG}",
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

    hypothesis.status = eval.status;
    hypothesis.evaluation_summary = Some(eval.evaluation_summary);

    let refs: Vec<EvidenceRef> = new_results
        .iter()
        .flat_map(|r| r.findings.iter())
        .flat_map(|f| f.evidence_refs.iter().cloned())
        .collect();
    match eval.status {
        HypothesisStatus::Supported => hypothesis.supporting_evidence = refs,
        HypothesisStatus::Rejected => hypothesis.contradictory_evidence = refs,
        HypothesisStatus::Proposed | HypothesisStatus::Inconclusive => {}
    }
    Ok(eval.conclusion)
}

fn build_stakeholder_outputs(ctx: &InvestigationContext) -> (ExecutiveBrief, Vec<RemediationTask>) {
    let mut all_findings: Vec<&Finding> = ctx
        .initial_report
        .iter()
        .flat_map(|r| r.analysers.iter())
        .flat_map(|a| a.findings.iter())
        .chain(ctx.follow_up_results.iter().flat_map(|r| r.findings.iter()))
        .collect();
    all_findings.sort_by_key(|a| std::cmp::Reverse(a.severity));

    let immediate_actions: Vec<String> = all_findings
        .iter()
        .filter(|f| f.severity >= Severity::Medium)
        .take(5)
        .map(|f| format!("[{:?}] {} ({})", f.severity, f.title, f.rule_id.0))
        .collect();

    let assessment = if all_findings.iter().any(|f| f.severity >= Severity::High) {
        "Material high-severity quality risks require attention before release.".to_owned()
    } else if all_findings.is_empty() {
        "No defects detected within the investigated single-target scope.".to_owned()
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
            .filter(|p| p.status == PageCrawlStatus::Investigated)
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
        "Deterministic measurements carry high confidence; multi-page crawl and authenticated journeys were not evaluated in this single-target investigation."
            .to_owned();

    let remediation_tasks = all_findings
        .into_iter()
        .filter(|f| f.severity >= Severity::Medium)
        .take(8)
        .enumerate()
        .map(|(idx, f)| RemediationTask {
            id: format!("TASK-{}", idx + 1),
            title: f.title.clone(),
            problem_statement: f.summary.clone(),
            priority: f.severity,
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
                "Re-run `nzw check {}` (or `nzw investigate`) and confirm `{}` is resolved.",
                ctx.target.as_str(),
                f.rule_id.0
            ),
        })
        .collect();

    (
        ExecutiveBrief {
            assessment,
            immediate_actions,
            coverage_summary,
            confidence_note,
        },
        remediation_tasks,
    )
}

fn finish_budget_exhausted(mut ctx: InvestigationContext, reason: String) -> InvestigationReport {
    ctx.state = InvestigationState::BudgetExhausted;
    build_report(ctx, reason)
}

fn build_report(ctx: InvestigationContext, conclusion: String) -> InvestigationReport {
    let (executive_brief, remediation_tasks) = build_stakeholder_outputs(&ctx);
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
        hypotheses: ctx.hypotheses,
        tool_trace: ctx.tool_trace,
        ledger: ctx.ledger,
        executive_brief,
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
        AxeViolation, ConsoleErrorEvent, HttpEvidence, HttpHeader, Measurement, MeasurementUnit,
    };
    use crate::intelligence::LlmFuture;

    struct MockBackend {
        browser: CollectorOutcome<BrowserEvidence>,
        axe: CollectorOutcome<AxeEvidence>,
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
    async fn multi_turn_investigation_evaluates_hypotheses_and_builds_brief() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Captured {
                data: BrowserEvidence {
                    final_url: "http://example.org/".to_owned(),
                    browser_version: Some("Chromium 131".to_owned()),
                    console_errors: vec![ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "ReferenceError: app is not defined".to_owned(),
                    }],
                    failed_requests: Vec::new(),
                    viewports: Vec::new(),
                },
            },
            axe: CollectorOutcome::Captured {
                data: AxeEvidence {
                    axe_version: "4.10.2".to_owned(),
                    violations: vec![AxeViolation {
                        id: "color-contrast".to_owned(),
                        impact: Some("serious".to_owned()),
                        description: "Contrast ratio too low".to_owned(),
                        help_url: "https://dequeuniversity.com/rules/axe/4.10/color-contrast"
                            .to_owned(),
                        nodes_count: 2,
                    }],
                    passes_count: 5,
                    incomplete_count: 0,
                },
            },
        });
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"ready_to_conclude":false,"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Client script failure may be degrading page runtime","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"BrowserZwerg observed a ReferenceError","conclusion":"Runtime JS error confirmed."}"#.to_owned(),
                r#"{"ready_to_conclude":false,"originating_rule":"a11y.doc.lang","proposed_explanation":"Missing lang often correlates with rendered contrast issues","requested_tool":"inspect_rendered_accessibility"}"#.to_owned(),
                r#"{"status":"rejected","evaluation_summary":"Contrast issue is unrelated to lang","conclusion":"Both runtime JS and contrast issues require remediation."}"#.to_owned(),
            ])),
        };

        let budget = InvestigationBudget {
            max_tool_calls: 3,
            max_llm_turns: 4,
            ..InvestigationBudget::default()
        };
        let report = run_investigation(
            target,
            "Assess release readiness".to_owned(),
            TargetPolicy::PublicOnly,
            budget,
            backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::Completed);
        assert_eq!(report.hypotheses.len(), 2);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
        assert!(report.hypotheses[0].originating_rule_verified);
        assert_ne!(report.hypotheses[0].supporting_evidence.len(), 0);
        // Rejected hypothesis must populate contradictory_evidence, NOT supporting_evidence.
        assert_eq!(report.hypotheses[1].status, HypothesisStatus::Rejected);
        assert_eq!(report.hypotheses[1].supporting_evidence.len(), 0);
        assert_ne!(report.hypotheses[1].contradictory_evidence.len(), 0);
        assert!(report.snapshot.is_some());
        assert_ne!(report.remediation_tasks.len(), 0);
    }

    #[tokio::test]
    async fn failed_follow_up_forces_inconclusive_even_if_llm_would_support() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = Arc::new(MockBackend {
            browser: CollectorOutcome::Failed {
                error: "chromium missing".to_owned(),
            },
            axe: CollectorOutcome::default(),
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
    }
}
