//! Agentic investigation domain model and `KommandantZwerg` orchestrator.
//!
//! Implements the Milestone B proof-of-concept loop described in ADR 0005:
//! initial reconnaissance -> `KommandantZwerg` hypothesis generation ->
//! budget-enforced typed diagnostic tool invocation -> additional evidence
//! collection -> hypothesis evaluation -> structured [`InvestigationReport`].

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::adapters;
use crate::analysis::{self, AuditReport};
use crate::brigade::DwarfId;
use crate::collection;
use crate::domain::{
    AnalyserResult, AuditTarget, AxeEvidence, BrowserEvidence, CollectorOutcome, EvidenceRef,
    EvidenceSnapshot, ExecutionBudget, RuleId, TargetPolicy,
};
use crate::intelligence::{LlmBudget, LlmProvider};

const OPEN_TAG: &str = "<untrusted_audit_evidence>";
const CLOSE_TAG: &str = "</untrusted_audit_evidence>";

/// Unique identifier for an investigation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationId(pub String);

/// Lifecycle state of an agentic investigation.
///
/// Execution status is strictly separate from application health: a
/// [`InvestigationState::Completed`] investigation may reveal critical defects.
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

    fn try_consume_tool(&mut self, started: Instant) -> Result<(), String> {
        if started.elapsed() >= self.budget.max_duration {
            return Err("investigation max_duration budget exhausted".to_owned());
        }
        if self.tool_calls_used >= self.budget.max_tool_calls {
            return Err("investigation max_tool_calls budget exhausted".to_owned());
        }
        self.tool_calls_used += 1;
        Ok(())
    }

    fn try_consume_llm(&mut self, started: Instant) -> Result<(), String> {
        if started.elapsed() >= self.budget.max_duration {
            return Err("investigation max_duration budget exhausted".to_owned());
        }
        if self.llm_turns_used >= self.budget.max_llm_turns {
            return Err("investigation max_llm_turns budget exhausted".to_owned());
        }
        self.llm_turns_used += 1;
        Ok(())
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
    /// Proposed explanation to test.
    pub proposed_explanation: String,
    /// Typed diagnostic tool selected to test this hypothesis.
    pub requested_tool: String,
    /// Current evaluation status.
    pub status: HypothesisStatus,
    /// Evidence-backed evaluation summary.
    pub evaluation_summary: Option<String>,
    /// Supporting evidence references.
    pub supporting_evidence: Vec<EvidenceRef>,
    /// Contradictory evidence references.
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
    /// Latest collected evidence snapshot.
    pub snapshot: Option<EvidenceSnapshot>,
    /// Initial Level 1 deterministic report.
    pub initial_report: Option<AuditReport>,
    /// Additional Level 2 specialist results gathered during investigation.
    pub follow_up_results: Vec<AnalyserResult>,
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
    /// Initial Level 1 deterministic report.
    pub initial_report: Option<AuditReport>,
    /// Additional Level 2 specialist results.
    pub follow_up_results: Vec<AnalyserResult>,
    /// Evaluated hypotheses.
    pub hypotheses: Vec<DiagnosticHypothesis>,
    /// Complete tool execution trace.
    pub tool_trace: Vec<ToolInvocationRecord>,
    /// Budget consumption summary.
    pub ledger: BudgetLedger,
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
}

#[derive(Debug, Deserialize)]
struct RawHypothesisDecision {
    originating_rule: String,
    proposed_explanation: String,
    requested_tool: String,
}

#[derive(Debug, Deserialize)]
struct RawEvaluationDecision {
    status: HypothesisStatus,
    evaluation_summary: String,
    conclusion: String,
}

/// Executes the `KommandantZwerg` agentic investigation loop.
pub async fn run_investigation(
    target: AuditTarget,
    objective: String,
    policy: TargetPolicy,
    budget: InvestigationBudget,
    backend: &dyn DiagnosticBackend,
    llm: &dyn LlmProvider,
) -> InvestigationReport {
    let started = Instant::now();
    let mut ctx = InvestigationContext {
        id: InvestigationId(format!("inv-{}", target.host())),
        target: target.clone(),
        objective,
        state: InvestigationState::Scoped,
        snapshot: None,
        initial_report: None,
        follow_up_results: Vec::new(),
        hypotheses: Vec::new(),
        tool_trace: Vec::new(),
        ledger: BudgetLedger::new(budget),
    };

    ctx.state = InvestigationState::Planned;
    if let Err(reason) = ctx.ledger.try_consume_tool(started) {
        return finish_budget_exhausted(ctx, reason);
    }

    ctx.state = InvestigationState::Investigating;
    let exec_budget = ExecutionBudget {
        audit_timeout: budget.max_duration.min(Duration::from_secs(30)),
        ..ExecutionBudget::default()
    };
    let mut snapshot = backend.collect_http(&target, exec_budget, policy).await;
    let initial_report = analysis::run_all(&snapshot);
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

    if let Err(reason) = ctx.ledger.try_consume_llm(started) {
        return finish_budget_exhausted(ctx, reason);
    }
    let decision = match propose_hypothesis(&ctx, &initial_report, llm, budget).await {
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

    let mut hypothesis = DiagnosticHypothesis {
        id: "hyp-1".to_owned(),
        originating_rule: RuleId(decision.originating_rule),
        proposed_explanation: decision.proposed_explanation,
        requested_tool: decision.requested_tool.clone(),
        status: HypothesisStatus::Proposed,
        evaluation_summary: None,
        supporting_evidence: Vec::new(),
        contradictory_evidence: Vec::new(),
    };

    if let Err(reason) = ctx.ledger.try_consume_tool(started) {
        ctx.hypotheses.push(hypothesis);
        return finish_budget_exhausted(ctx, reason);
    }

    execute_follow_up_tool(
        &decision.requested_tool,
        &target,
        exec_budget.audit_timeout,
        backend,
        &mut snapshot,
        &mut ctx,
    )
    .await;
    ctx.snapshot = Some(snapshot);

    ctx.state = InvestigationState::Evaluating;
    if let Err(reason) = ctx.ledger.try_consume_llm(started) {
        hypothesis.status = HypothesisStatus::Inconclusive;
        ctx.hypotheses.push(hypothesis);
        return finish_budget_exhausted(ctx, reason);
    }

    let conclusion = match evaluate_hypothesis(&ctx, &mut hypothesis, llm, budget).await {
        Ok(c) => c,
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
    };

    ctx.hypotheses.push(hypothesis);
    ctx.state = InvestigationState::Completed;
    build_report(ctx, conclusion)
}

async fn propose_hypothesis(
    ctx: &InvestigationContext,
    report: &AuditReport,
    llm: &dyn LlmProvider,
    budget: InvestigationBudget,
) -> Result<RawHypothesisDecision, String> {
    let sys = "You are KommandantZwerg. Given initial deterministic findings, propose one \
falsifiable diagnostic hypothesis and choose exactly one follow-up tool from: \
`inspect_browser_runtime` or `inspect_rendered_accessibility`. \
Respond strictly with JSON: {\"originating_rule\": string, \"proposed_explanation\": string, \"requested_tool\": string}.";

    let summary: Vec<_> = report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter())
        .take(15)
        .map(|f| format!("{}: {}", f.rule_id.0, f.title))
        .collect();
    let user = format!(
        "{OPEN_TAG}\nobjective: {}\ntarget: {}\nfindings: {}\n{CLOSE_TAG}",
        ctx.objective.replace(CLOSE_TAG, ""),
        ctx.target.as_str(),
        summary.join(" | ").replace(CLOSE_TAG, "")
    );

    let raw = llm
        .complete(
            sys,
            &user,
            LlmBudget {
                max_tokens: budget.max_tokens,
                max_requests: 1,
                timeout: budget.max_duration,
            },
        )
        .await?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid hypothesis JSON: {e}"))
}

async fn execute_follow_up_tool(
    tool_id: &str,
    target: &AuditTarget,
    timeout: Duration,
    backend: &dyn DiagnosticBackend,
    snapshot: &mut EvidenceSnapshot,
    ctx: &mut InvestigationContext,
) {
    match tool_id {
        "inspect_browser_runtime" => {
            snapshot.browser = backend.collect_browser(target, timeout).await;
            let browser_res = analysis::browser::analyse(snapshot);
            let visual_res = analysis::visual::analyse(snapshot);
            let succeeded = !matches!(snapshot.browser, CollectorOutcome::Failed { .. });
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: tool_id.to_owned(),
                dwarf_id: DwarfId::Browser,
                authorised: true,
                succeeded,
                summary: format!(
                    "browser findings: {}, visual findings: {}",
                    browser_res.findings.len(),
                    visual_res.findings.len()
                ),
            });
            ctx.follow_up_results.push(browser_res);
            ctx.follow_up_results.push(visual_res);
        }
        "inspect_rendered_accessibility" => {
            snapshot.axe = backend.collect_axe(target, timeout).await;
            let obs = match &snapshot.http {
                CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
                    analysis::document::DocumentObservations::from_html(&data.body_text)
                }
                _ => analysis::document::DocumentObservations::from_html(""),
            };
            let a11y_res = analysis::accessibility::analyse_with_axe(&obs, &snapshot.axe);
            let succeeded = !matches!(snapshot.axe, CollectorOutcome::Failed { .. });
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: tool_id.to_owned(),
                dwarf_id: DwarfId::Zugaenglichkeits,
                authorised: true,
                succeeded,
                summary: format!("rendered a11y findings: {}", a11y_res.findings.len()),
            });
            ctx.follow_up_results.push(a11y_res);
        }
        _ => {
            ctx.tool_trace.push(ToolInvocationRecord {
                tool_id: tool_id.to_owned(),
                dwarf_id: DwarfId::Kommandant,
                authorised: false,
                succeeded: false,
                summary: "rejected unrecognised or unauthorised tool request".to_owned(),
            });
        }
    }
}

async fn evaluate_hypothesis(
    ctx: &InvestigationContext,
    hypothesis: &mut DiagnosticHypothesis,
    llm: &dyn LlmProvider,
    budget: InvestigationBudget,
) -> Result<String, String> {
    let sys = "You are KommandantZwerg evaluating a diagnostic hypothesis against follow-up \
evidence. Respond strictly with JSON: {\"status\": \"supported\"|\"rejected\"|\"inconclusive\", \
\"evaluation_summary\": string, \"conclusion\": string}.";

    let follow_up: Vec<_> = ctx
        .follow_up_results
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
                timeout: budget.max_duration,
            },
        )
        .await?;
    let eval: RawEvaluationDecision =
        serde_json::from_str(&raw).map_err(|e| format!("invalid evaluation JSON: {e}"))?;

    hypothesis.status = eval.status;
    hypothesis.evaluation_summary = Some(eval.evaluation_summary);
    for res in &ctx.follow_up_results {
        for f in &res.findings {
            hypothesis
                .supporting_evidence
                .extend(f.evidence_refs.iter().cloned());
        }
    }
    Ok(eval.conclusion)
}

fn finish_budget_exhausted(mut ctx: InvestigationContext, reason: String) -> InvestigationReport {
    ctx.state = InvestigationState::BudgetExhausted;
    build_report(ctx, reason)
}

fn build_report(ctx: InvestigationContext, conclusion: String) -> InvestigationReport {
    InvestigationReport {
        id: ctx.id,
        target: ctx.target,
        objective: ctx.objective,
        state: ctx.state,
        initial_report: ctx.initial_report,
        follow_up_results: ctx.follow_up_results,
        hypotheses: ctx.hypotheses,
        tool_trace: ctx.tool_trace,
        ledger: ctx.ledger,
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
            Box::pin(async { CollectorOutcome::default() })
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
    async fn investigation_loop_proposes_runs_tool_and_evaluates_hypothesis() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = MockBackend {
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
        };
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"originating_rule":"perf.http.exchange_duration","proposed_explanation":"Client script failure may be degrading page runtime","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
                r#"{"status":"supported","evaluation_summary":"BrowserZwerg observed a ReferenceError in console","conclusion":"Runtime JavaScript error confirmed; resolve missing script before release."}"#.to_owned(),
            ])),
        };

        let report = run_investigation(
            target,
            "Assess release readiness".to_owned(),
            TargetPolicy::PublicOnly,
            InvestigationBudget::default(),
            &backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::Completed);
        assert_eq!(report.tool_trace.len(), 2);
        assert_eq!(report.tool_trace[1].tool_id, "inspect_browser_runtime");
        assert!(report.tool_trace[1].authorised);
        assert_eq!(report.hypotheses.len(), 1);
        assert_eq!(report.hypotheses[0].status, HypothesisStatus::Supported);
        assert_ne!(report.hypotheses[0].supporting_evidence.len(), 0);
        assert_eq!(report.ledger.tool_calls_used, 2);
        assert_eq!(report.ledger.llm_turns_used, 2);
    }

    #[tokio::test]
    async fn enforces_tool_call_budget_outside_llm() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let backend = MockBackend {
            browser: CollectorOutcome::default(),
        };
        let llm = SequenceLlm {
            responses: Mutex::new(VecDeque::from([
                r#"{"originating_rule":"sec.transport.https","proposed_explanation":"Check browser","requested_tool":"inspect_browser_runtime"}"#.to_owned(),
            ])),
        };
        let tight_budget = InvestigationBudget {
            max_tool_calls: 1, // Only enough for initial HTTP reconnaissance
            ..InvestigationBudget::default()
        };

        let report = run_investigation(
            target,
            "Quick check".to_owned(),
            TargetPolicy::PublicOnly,
            tight_budget,
            &backend,
            &llm,
        )
        .await;

        assert_eq!(report.state, InvestigationState::BudgetExhausted);
        assert_eq!(report.ledger.tool_calls_used, 1);
    }
}
