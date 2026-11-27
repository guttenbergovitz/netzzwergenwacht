//! Contract tests proving that per-agent routing reaches real execution.
//!
//! The investigation loop must resolve a provider for the dwarf that answers, and it
//! must refuse to fall back to an unrelated model when the required dwarf has none.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::discovery::{CrawlBudget, CrawlSummary};
use netzzwergenwacht::domain::{
    AuditTarget, AxeEvidence, BrowserEvidence, CollectorOutcome, EvidenceSnapshot, ExecutionBudget,
    LighthouseMetrics, TargetPolicy,
};
use netzzwergenwacht::intelligence::{LlmBudget, LlmFuture, LlmProvider, ProviderRouter};
use netzzwergenwacht::investigation::{
    DiagnosticBackend, InvestigationBudget, InvestigationReport, InvestigationState,
    run_investigation_with_events_and_router,
};

const NO_BROWSER: &str = "routing test does not collect browser evidence";

struct StaticBackend {
    snapshot: EvidenceSnapshot,
}

impl DiagnosticBackend for StaticBackend {
    fn collect_http<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, EvidenceSnapshot> {
        let snapshot = self.snapshot.clone();
        Box::pin(async move { snapshot })
    }

    fn collect_browser<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<BrowserEvidence>> {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: NO_BROWSER.to_owned(),
            }
        })
    }

    fn collect_axe<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<AxeEvidence>> {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: NO_BROWSER.to_owned(),
            }
        })
    }

    fn collect_lighthouse<'a>(
        &'a self,
        _target: &'a AuditTarget,
        _timeout: Duration,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CollectorOutcome<LighthouseMetrics>>
    {
        Box::pin(async move {
            CollectorOutcome::Skipped {
                reason: NO_BROWSER.to_owned(),
            }
        })
    }

    fn collect_crawl<'a>(
        &'a self,
        target: &'a AuditTarget,
        _crawl_budget: CrawlBudget,
        _exec_budget: ExecutionBudget,
        _policy: TargetPolicy,
    ) -> netzzwergenwacht::investigation::CollectFuture<'a, CrawlSummary> {
        let seed = target.clone();
        Box::pin(async move {
            CrawlSummary {
                seed,
                pages: Vec::new(),
                systemic_issues: Vec::new(),
                budget_exhausted: false,
                graph_results: Vec::new(),
            }
        })
    }
}

/// Provider that records its own model name for every completion it serves.
struct RecordingLlm {
    model: &'static str,
    replies: Mutex<VecDeque<String>>,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl RecordingLlm {
    fn new(model: &'static str, replies: &[&str], calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            model,
            replies: Mutex::new(replies.iter().map(|reply| (*reply).to_owned()).collect()),
            calls,
        }
    }
}

impl LlmProvider for RecordingLlm {
    fn model_name(&self) -> &str {
        self.model
    }

    fn complete<'a>(
        &'a self,
        _system_prompt: &'a str,
        _user_prompt: &'a str,
        _budget: LlmBudget,
    ) -> LlmFuture<'a> {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(self.model);
        }
        let reply = self
            .replies
            .lock()
            .expect("recording replies")
            .pop_front()
            .unwrap_or_else(|| "{}".to_owned());
        Box::pin(async move { Ok(reply) })
    }
}

struct MapRouter(Vec<(DwarfId, Arc<dyn LlmProvider>)>);

impl ProviderRouter for MapRouter {
    fn resolve_for_dwarf(&self, dwarf_id: DwarfId) -> Option<&dyn LlmProvider> {
        self.0
            .iter()
            .find(|(id, _)| *id == dwarf_id)
            .map(|(_, provider)| provider.as_ref())
    }
}

fn target() -> AuditTarget {
    AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).expect("valid target")
}

fn snapshot() -> EvidenceSnapshot {
    EvidenceSnapshot {
        target: target(),
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::Skipped {
            reason: "routing test".to_owned(),
        },
        tls: CollectorOutcome::Skipped {
            reason: "routing test".to_owned(),
        },
        browser: CollectorOutcome::Skipped {
            reason: NO_BROWSER.to_owned(),
        },
        lighthouse: CollectorOutcome::Skipped {
            reason: NO_BROWSER.to_owned(),
        },
        axe: CollectorOutcome::Skipped {
            reason: NO_BROWSER.to_owned(),
        },
    }
}

async fn investigate(router: &dyn ProviderRouter) -> InvestigationReport {
    run_investigation_with_events_and_router(
        target(),
        "Verify routing".to_owned(),
        TargetPolicy::PublicOnly,
        InvestigationBudget::default(),
        Arc::new(StaticBackend {
            snapshot: snapshot(),
        }),
        router,
        Vec::new(),
        &netzzwergenwacht::events::DiagnosticEventSink::noop(),
    )
    .await
}

#[tokio::test]
async fn consultation_is_answered_by_the_routed_specialist_model() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let kommandant = Arc::new(RecordingLlm::new(
        "kommandant-model",
        &[
            r#"{"ready_to_conclude":false,"originating_rule":"rule.html.missing_csp","proposed_explanation":"Check security headers.","requested_tool":"consult_specialist:Sicherheits","conclusion":null}"#,
            r#"{"ready_to_conclude":true,"originating_rule":"rule.html.missing_csp","proposed_explanation":"Concluded.","requested_tool":"","conclusion":"Consultation answered."}"#,
        ],
        Arc::clone(&calls),
    ));
    let specialist = Arc::new(RecordingLlm::new(
        "sicherheits-model",
        &[
            r#"{"confirmed_observations":[],"evidence_refs":[],"remaining_uncertainty":"none","recommendation":"No additional security evidence."}"#,
        ],
        Arc::clone(&calls),
    ));
    let router = MapRouter(vec![
        (DwarfId::Kommandant, kommandant),
        (DwarfId::Sicherheits, specialist),
    ]);

    let report = investigate(&router).await;

    let recorded = calls.lock().expect("recorded calls").clone();
    assert!(
        recorded.contains(&"sicherheits-model"),
        "the specialist model must answer its own consultation, recorded calls: {recorded:?}"
    );
    assert!(
        report
            .specialists
            .iter()
            .any(|c| c.dwarf_id == DwarfId::Sicherheits),
        "the routed specialist contribution should reach the report"
    );
    assert!(
        recorded.contains(&"sicherheits-model"),
        "the routed specialist model must be the one that answered"
    );
}

#[tokio::test]
async fn a_missing_kommandant_model_stops_the_run_instead_of_substituting() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = MapRouter(vec![(
        DwarfId::Sicherheits,
        Arc::new(RecordingLlm::new(
            "sicherheits-model",
            &[],
            Arc::clone(&calls),
        )),
    )]);

    let report = investigate(&router).await;

    assert_eq!(report.state, InvestigationState::PartiallyCompleted);
    assert_eq!(
        report.hypotheses.len(),
        0,
        "no hypothesis may be proposed without a Kommandant model"
    );
    assert_eq!(
        calls.lock().expect("recorded calls").len(),
        0,
        "no other model may answer on the Kommandant's behalf"
    );
}
