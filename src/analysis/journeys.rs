//! Deterministic functional behaviour and user journey evaluator (Phase II §5.2–5.3).
//!
//! Evaluates repeatable [`JourneySpec`] assertions and `func.interaction.*` rules
//! strictly over captured [`EvidenceSnapshot`] data (`BrowserEvidence::user_journey_trace`)
//! without performing network I/O or assuming causal correctness from a bare click.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis::assessment::DomainVerdict;
use crate::brigade::DwarfId;
use crate::domain::functional_intelligence::{InteractionActionKind, InteractionTraceStep};
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    RuleId, Severity,
};

const RULE_TRACE_COVERAGE: &str = "func.interaction.trace_coverage";
const RULE_RUNTIME_ERROR: &str = "func.interaction.runtime_error_during_probe";
const RULE_UNRESPONSIVE: &str = "func.interaction.unresponsive_activation";

/// Safety boundary governing which user journeys may be evaluated or executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JourneySafetyPolicy {
    /// Only non-mutating, read-only probes are permitted.
    ReadOnlyOnly,
    /// Mutating journeys (forms, cart, checkout) are explicitly authorised.
    AuthorisedTestEnvironment,
}

/// Deterministic assertion evaluated against an observed [`InteractionTraceStep`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JourneyAssertionKind {
    /// Step observed an application state change.
    StateChanged,
    /// Keyboard focus moved to a new element.
    FocusChanged,
    /// Expanded/collapsed state changed.
    ExpandedChanged,
    /// Active dialog state changed.
    DialogChanged,
    /// Structural DOM fingerprint changed.
    DomFingerprintChanged,
    /// Zero runtime errors were observed in the step window.
    NoRuntimeErrors,
    /// At least one network request was observed in the step window.
    RequestsObserved,
}

/// Expected action and assertions for one step of a [`JourneySpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JourneyStepExpectation {
    /// Expected interaction action kind.
    pub action: InteractionActionKind,
    /// Deterministic assertions that must hold on the matched step.
    pub assertions: Vec<JourneyAssertionKind>,
}

/// Declarative, repeatable user journey specification (Phase II §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JourneySpec {
    /// Stable journey identifier.
    pub id: String,
    /// Human-readable scenario name.
    pub name: String,
    /// Required safety authorisation level.
    pub required_safety: JourneySafetyPolicy,
    /// Ordered step expectations.
    pub steps: Vec<JourneyStepExpectation>,
}

/// Outcome of evaluating a single assertion on a journey step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssertionOutcome {
    /// Assertion held against observed evidence.
    Passed,
    /// Assertion failed against observed evidence.
    Failed {
        /// What was actually observed.
        observed: String,
        /// What the specification expected.
        expected: String,
    },
    /// Assertion could not be evaluated due to missing evidence or policy block.
    Unverified {
        /// Reason verification was not possible.
        reason: String,
    },
}

/// Defensible evaluation result for a [`JourneySpec`] over an [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JourneyEvaluation {
    /// Evaluated journey identifier.
    pub spec_id: String,
    /// Evaluated journey name.
    pub spec_name: String,
    /// Overall verdict (`Pass`, `Fail`, or `InsufficientEvidence`).
    pub verdict: DomainVerdict,
    /// Per-step assertion outcomes.
    pub assertion_outcomes: Vec<AssertionOutcome>,
    /// Supporting evidence references.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Explicit scope or safety limitations.
    pub limitations: Vec<String>,
}

/// Evaluates `spec` deterministically against `snapshot` under `active_policy`.
#[must_use]
pub fn evaluate_journey(
    snapshot: &EvidenceSnapshot,
    spec: &JourneySpec,
    active_policy: JourneySafetyPolicy,
) -> JourneyEvaluation {
    if spec.required_safety == JourneySafetyPolicy::AuthorisedTestEnvironment
        && active_policy == JourneySafetyPolicy::ReadOnlyOnly
    {
        return JourneyEvaluation {
            spec_id: spec.id.clone(),
            spec_name: spec.name.clone(),
            verdict: DomainVerdict::InsufficientEvidence,
            assertion_outcomes: vec![AssertionOutcome::Unverified {
                reason: "journey requires AuthorisedTestEnvironment policy".to_owned(),
            }],
            evidence_refs: Vec::new(),
            limitations: vec![
                "Mutating user journey blocked under ReadOnlyOnly safety policy.".to_owned(),
            ],
        };
    }

    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } | CollectorOutcome::Failed { error: reason } => {
            return JourneyEvaluation {
                spec_id: spec.id.clone(),
                spec_name: spec.name.clone(),
                verdict: DomainVerdict::InsufficientEvidence,
                assertion_outcomes: vec![AssertionOutcome::Unverified {
                    reason: format!("browser evidence unavailable: {reason}"),
                }],
                evidence_refs: Vec::new(),
                limitations: vec![format!("Browser collector unavailable: {reason}")],
            };
        }
    };

    let Some(trace) = browser.user_journey_trace.as_ref() else {
        return JourneyEvaluation {
            spec_id: spec.id.clone(),
            spec_name: spec.name.clone(),
            verdict: DomainVerdict::InsufficientEvidence,
            assertion_outcomes: vec![AssertionOutcome::Unverified {
                reason: "user_journey_trace was not captured".to_owned(),
            }],
            evidence_refs: Vec::new(),
            limitations: vec!["No interaction trace captured in BrowserEvidence.".to_owned()],
        };
    };

    let mut outcomes = Vec::new();
    let mut evidence_refs = Vec::new();
    let mut any_failed = false;
    let mut any_unverified = false;

    for (idx, expected_step) in spec.steps.iter().enumerate() {
        let matched = trace
            .steps
            .iter()
            .skip(idx)
            .find(|s| s.action == expected_step.action);

        let Some(step) = matched else {
            any_unverified = true;
            outcomes.push(AssertionOutcome::Unverified {
                reason: format!("no observed step matching {:?}", expected_step.action),
            });
            continue;
        };

        evidence_refs.push(EvidenceRef::new(
            EvidenceSource::BrowserRuntime,
            format!(
                "step={} action={:?} state_changed={} errors={}",
                step.step_index,
                step.action,
                step.state_changed,
                step.runtime_errors_observed_in_window
            ),
        ));

        for assertion in &expected_step.assertions {
            let outcome = check_step_assertion(step, assertion);
            if matches!(outcome, AssertionOutcome::Failed { .. }) {
                any_failed = true;
            }
            outcomes.push(outcome);
        }
    }

    let verdict = if any_failed {
        DomainVerdict::Fail
    } else if any_unverified || outcomes.is_empty() {
        DomainVerdict::InsufficientEvidence
    } else {
        DomainVerdict::Pass
    };

    JourneyEvaluation {
        spec_id: spec.id.clone(),
        spec_name: spec.name.clone(),
        verdict,
        assertion_outcomes: outcomes,
        evidence_refs,
        limitations: Vec::new(),
    }
}

fn check_step_assertion(
    step: &InteractionTraceStep,
    assertion: &JourneyAssertionKind,
) -> AssertionOutcome {
    let (passed, observed, expected) = match assertion {
        JourneyAssertionKind::StateChanged => (
            step.state_changed,
            format!("state_changed={}", step.state_changed),
            "state_changed=true",
        ),
        JourneyAssertionKind::FocusChanged => (
            step.focus_changed,
            format!("focus_changed={}", step.focus_changed),
            "focus_changed=true",
        ),
        JourneyAssertionKind::ExpandedChanged => (
            step.expanded_changed,
            format!("expanded_changed={}", step.expanded_changed),
            "expanded_changed=true",
        ),
        JourneyAssertionKind::DialogChanged => (
            step.dialog_changed,
            format!("dialog_changed={}", step.dialog_changed),
            "dialog_changed=true",
        ),
        JourneyAssertionKind::DomFingerprintChanged => (
            step.dom_fingerprint_changed,
            format!("dom_fingerprint_changed={}", step.dom_fingerprint_changed),
            "dom_fingerprint_changed=true",
        ),
        JourneyAssertionKind::NoRuntimeErrors => (
            step.runtime_errors_observed_in_window == 0,
            format!(
                "runtime_errors_observed_in_window={}",
                step.runtime_errors_observed_in_window
            ),
            "runtime_errors_observed_in_window=0",
        ),
        JourneyAssertionKind::RequestsObserved => (
            step.requests_observed_in_window > 0,
            format!(
                "requests_observed_in_window={}",
                step.requests_observed_in_window
            ),
            "requests_observed_in_window>0",
        ),
    };

    if passed {
        AssertionOutcome::Passed
    } else {
        AssertionOutcome::Failed {
            observed,
            expected: expected.to_owned(),
        }
    }
}

/// Evaluates deterministic functional behaviour rules (`func.interaction.*`)
/// over `snapshot`.
#[must_use]
pub fn analyse_functional_behaviour(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } | CollectorOutcome::Failed { error: reason } => {
            for rule in [RULE_TRACE_COVERAGE, RULE_RUNTIME_ERROR, RULE_UNRESPONSIVE] {
                checks.push(CheckStatus::Skipped {
                    rule_id: RuleId(rule.to_owned()),
                    evidence_level: EvidenceLevel::Behavioural,
                    reason: reason.clone(),
                });
            }
            return AnalyserResult {
                dwarf_id: DwarfId::Browser,
                findings,
                checks,
            };
        }
    };

    let Some(trace) = browser.user_journey_trace.as_ref() else {
        for rule in [RULE_TRACE_COVERAGE, RULE_RUNTIME_ERROR, RULE_UNRESPONSIVE] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(rule.to_owned()),
                evidence_level: EvidenceLevel::Behavioural,
                reason: "user_journey_trace was not captured".to_owned(),
            });
        }
        return AnalyserResult {
            dwarf_id: DwarfId::Browser,
            findings,
            checks,
        };
    };

    checks.push(CheckStatus::Passed {
        rule_id: RuleId(RULE_TRACE_COVERAGE.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
    });

    check_probe_runtime_errors(&trace.steps, &mut findings, &mut checks);
    check_unresponsive_activations(&trace.steps, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Browser,
        findings,
        checks,
    }
}

fn check_probe_runtime_errors(
    steps: &[InteractionTraceStep],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let error_steps: Vec<&InteractionTraceStep> = steps
        .iter()
        .filter(|s| s.runtime_errors_observed_in_window > 0)
        .collect();
    if error_steps.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RUNTIME_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
        });
        return;
    }

    let total_errors: u32 = error_steps
        .iter()
        .map(|s| s.runtime_errors_observed_in_window)
        .sum();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_RUNTIME_ERROR.to_owned()),
        category: FindingCategory::Browser,
        evidence_level: EvidenceLevel::Behavioural,
        kind: FindingKind::Deterministic,
        severity: Severity::High,
        confidence: Confidence::High,
        title: format!(
            "Runtime errors observed during {} interaction probe(s)",
            error_steps.len()
        ),
        summary: format!(
            "Observed {total_errors} runtime error(s) within bounded interaction probe windows."
        ),
        evidence_refs: error_steps
            .iter()
            .take(5)
            .map(|s| {
                EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!(
                        "step={} action={:?} errors={}",
                        s.step_index, s.action, s.runtime_errors_observed_in_window
                    ),
                )
            })
            .collect(),
        remediation: Some(
            "Inspect console/runtime exceptions triggered during interactive state transitions."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_RUNTIME_ERROR.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
    });
}

fn check_unresponsive_activations(
    steps: &[InteractionTraceStep],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let unresponsive_steps: Vec<&InteractionTraceStep> = steps
        .iter()
        .filter(|s| {
            matches!(
                s.action,
                InteractionActionKind::DisclosureToggle | InteractionActionKind::TabSelect
            ) && !s.state_changed
                && !s.focus_changed
                && !s.expanded_changed
                && !s.dialog_changed
                && !s.dom_fingerprint_changed
                && s.requests_observed_in_window == 0
        })
        .collect();
    if unresponsive_steps.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNRESPONSIVE.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_UNRESPONSIVE.to_owned()),
        category: FindingCategory::Browser,
        evidence_level: EvidenceLevel::Behavioural,
        kind: FindingKind::Heuristic,
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        title: format!(
            "Unresponsive interactive controls ({} probe(s))",
            unresponsive_steps.len()
        ),
        summary: "Activation probes produced no observable DOM, focus, dialog, or network change."
            .to_owned(),
        evidence_refs: unresponsive_steps
            .iter()
            .take(5)
            .map(|s| {
                EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!(
                        "step={} action={:?} tag={:?}",
                        s.step_index, s.action, s.active_tag
                    ),
                )
            })
            .collect(),
        remediation: Some(
            "Verify event handlers, disabled states, and keyboard/click bindings on interactive controls."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_UNRESPONSIVE.to_owned()),
        evidence_level: EvidenceLevel::Behavioural,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::functional_intelligence::{
        InteractionProbePolicy, InteractionWindowTermination, UserJourneyTrace,
    };
    use crate::domain::{AuditTarget, BrowserEvidence, TargetPolicy};

    fn base_snapshot(browser: CollectorOutcome<BrowserEvidence>) -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly)
                .expect("target"),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            tls: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            browser,
            lighthouse: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "unit test".to_owned(),
            },
        }
    }

    fn trace_step(
        step_index: u32,
        action: InteractionActionKind,
        state_changed: bool,
        runtime_errors: u32,
    ) -> InteractionTraceStep {
        InteractionTraceStep {
            step_index,
            action,
            target_node: None,
            target_identity: None,
            active_tag: Some("button".to_owned()),
            active_role: Some("button".to_owned()),
            state_changed,
            focus_changed: false,
            expanded_changed: false,
            dialog_changed: false,
            dom_fingerprint_changed: state_changed,
            runtime_errors_observed_in_window: runtime_errors,
            requests_observed_in_window: 0,
            observation_started_ms: Some(100),
            observation_window_ms: Some(250),
            window_termination: InteractionWindowTermination::WindowElapsed,
            restoration_attempted: false,
            restoration_succeeded: None,
        }
    }

    #[test]
    fn missing_browser_produces_insufficient_evidence_and_skipped_checks() {
        let snap = base_snapshot(CollectorOutcome::Skipped {
            reason: "browser disabled".to_owned(),
        });
        let spec = JourneySpec {
            id: "j1".to_owned(),
            name: "Toggle menu".to_owned(),
            required_safety: JourneySafetyPolicy::ReadOnlyOnly,
            steps: vec![JourneyStepExpectation {
                action: InteractionActionKind::DisclosureToggle,
                assertions: vec![JourneyAssertionKind::StateChanged],
            }],
        };

        let eval = evaluate_journey(&snap, &spec, JourneySafetyPolicy::ReadOnlyOnly);
        assert_eq!(eval.verdict, DomainVerdict::InsufficientEvidence);

        let res = analyse_functional_behaviour(&snap);
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }

    #[test]
    fn mutating_journey_is_blocked_under_read_only_policy() {
        let snap = base_snapshot(CollectorOutcome::Skipped {
            reason: "unused".to_owned(),
        });
        let spec = JourneySpec {
            id: "checkout".to_owned(),
            name: "Submit order".to_owned(),
            required_safety: JourneySafetyPolicy::AuthorisedTestEnvironment,
            steps: vec![],
        };

        let eval = evaluate_journey(&snap, &spec, JourneySafetyPolicy::ReadOnlyOnly);
        assert_eq!(eval.verdict, DomainVerdict::InsufficientEvidence);
        assert_ne!(eval.limitations.len(), 0);
    }

    #[test]
    fn passing_journey_and_runtime_error_detection_work_deterministically() {
        let browser = BrowserEvidence {
            user_journey_trace: Some(UserJourneyTrace {
                candidate_scenarios: Vec::new(),
                steps: vec![
                    trace_step(0, InteractionActionKind::DisclosureToggle, true, 0),
                    trace_step(1, InteractionActionKind::TabSelect, false, 1),
                ],
                truncated: false,
                probe_policy: InteractionProbePolicy::RestrictedBehaviouralProbe,
                network_requests_suppressed: false,
            }),
            ..BrowserEvidence::default()
        };
        let snap = base_snapshot(CollectorOutcome::Captured { data: browser });

        let pass_spec = JourneySpec {
            id: "j-pass".to_owned(),
            name: "Disclosure changes state".to_owned(),
            required_safety: JourneySafetyPolicy::ReadOnlyOnly,
            steps: vec![JourneyStepExpectation {
                action: InteractionActionKind::DisclosureToggle,
                assertions: vec![
                    JourneyAssertionKind::StateChanged,
                    JourneyAssertionKind::NoRuntimeErrors,
                ],
            }],
        };
        let eval = evaluate_journey(&snap, &pass_spec, JourneySafetyPolicy::ReadOnlyOnly);
        assert_eq!(eval.verdict, DomainVerdict::Pass);

        let res = analyse_functional_behaviour(&snap);
        let rules: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(rules.contains(&RULE_RUNTIME_ERROR));
        assert!(rules.contains(&RULE_UNRESPONSIVE));
    }
}
