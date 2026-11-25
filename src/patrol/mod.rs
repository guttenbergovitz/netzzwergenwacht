//! Autonomous Web Quality Patrol engine.
//!
//! Orchestrates application cartography, institutional memory retrieval,
//! stratified sampling, low-cost deterministic diagnostics, anomaly detection,
//! selective specialist investigation via `KommandantZwerg`, and change-oriented
//! stakeholder reporting.

pub mod memory;
pub mod portfolio;
pub mod sampling;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::analysis::{self, AuditReport};
use crate::brigade::DwarfId;
use crate::collection;
use crate::discovery::{
    PageType, classify_page, detect_locale, discover_same_origin_links, seed_sitemap_urls,
    template_fingerprint,
};
use crate::domain::{
    AuditTarget, CollectorOutcome, ExecutionBudget, Finding, Origin, Severity, TargetPolicy,
};
use crate::intelligence::{LlmBudget, LlmProvider, ProviderRouter};
use crate::investigation::{DiagnosticBackend, InvestigationBudget, InvestigationReport, prompts};
use crate::persistence::{self, RegressionReport};

use self::memory::{
    ApplicationMemory, EvidenceFreshness, RememberedPage, hash_body, load_memory, save_memory,
};
use self::sampling::{SampleSelection, SamplingPlan, build_sampling_plan};

/// Topology map learned and updated across patrols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationMap {
    /// Canonical origin of the application.
    pub origin: String,
    /// Discovered URLs on this origin.
    pub discovered_urls: Vec<String>,
    /// Distinct locale/market tags observed.
    pub locales_observed: Vec<String>,
    /// Classified page types keyed by URL.
    pub page_types: BTreeMap<String, PageType>,
    /// Structural template fingerprints keyed by URL.
    pub template_families: BTreeMap<String, String>,
    /// Unix timestamp when this map was updated.
    pub last_patrolled_unix_secs: u64,
}

/// Classification of an anomaly detected during deterministic patrol checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyCategory {
    /// High or critical defect observed on first encounter.
    NewDefect,
    /// New or reintroduced finding compared with prior patrol memory.
    MaterialRegression,
    /// Previously unseen page or URL discovered on the origin.
    TopologyChange,
}

/// Anomaly detected between deterministic inspection and institutional memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatrolAnomaly {
    /// Stable anomaly identifier for this patrol.
    pub id: String,
    /// Anomaly category.
    pub category: AnomalyCategory,
    /// Affected URL.
    pub affected_url: String,
    /// Preliminary severity.
    pub severity: Severity,
    /// Human-readable description of the anomaly.
    pub summary: String,
    /// Specialist dwarf competency best suited to investigate.
    pub suggested_competency: DwarfId,
}

/// Resource and escalation bounds governing a single patrol run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatrolBudget {
    /// Maximum pages actively inspected per patrol.
    pub max_pages: usize,
    /// Maximum pages eligible for Level 2 deep diagnostics.
    pub max_deep_samples: usize,
    /// Freshness TTL in seconds before a healthy remembered page is re-sampled.
    pub freshness_ttl_secs: u64,
    /// Whether material anomalies may trigger `KommandantZwerg` agentic investigation.
    pub allow_ai_escalation: bool,
    /// Whether `Level2Deep` samples should execute headless browser diagnostics.
    pub enable_level2: bool,
}

impl Default for PatrolBudget {
    fn default() -> Self {
        Self {
            max_pages: 25,
            max_deep_samples: 2,
            freshness_ttl_secs: 3_600,
            allow_ai_escalation: true,
            enable_level2: false,
        }
    }
}

/// Explicit coverage accounting across discovery, sampling, reuse, and limitations.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoverageMatrix {
    /// Total URLs discovered on the origin.
    pub discovered_urls: usize,
    /// URLs actively inspected during this patrol.
    pub inspected_urls: usize,
    /// URLs inspected with Level 2 deep browser diagnostics.
    pub deep_inspected_urls: usize,
    /// Healthy remembered URLs whose prior observations were reused.
    pub reused_urls: usize,
    /// Distinct locale/market tags observed.
    pub locales_observed: Vec<String>,
    /// Distinct page types observed.
    pub page_types_observed: usize,
    /// Distinct structural template families observed.
    pub template_families_observed: usize,
    /// Explicit limitations and unverified scope boundaries.
    pub limitations: Vec<String>,
}

/// Resource consumption ledger recorded for a single patrol run.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PatrolResourceLedger {
    /// HTTP requests made during sitemap/`robots.txt` discovery.
    #[serde(default)]
    pub discovery_requests: usize,
    /// Total HTTP page fetches executed during sampling.
    pub http_requests: usize,
    /// Total Level 2 headless browser sessions executed.
    pub browser_sessions: usize,
    /// Total LLM turns consumed by selective specialist escalation.
    pub llm_requests: usize,
    /// Total diagnostic tool invocations consumed during specialist escalation.
    #[serde(default)]
    pub investigation_tool_calls: usize,
    /// Conditional HTTP revalidation checks (`If-None-Match` / `If-Modified-Since`).
    #[serde(default)]
    pub conditional_checks: usize,
    /// Healthy remembered page observations verified unchanged via conditional HTTP.
    pub reused_observations: usize,
    /// Total patrol wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Structured JSON contract returned by a delegated specialist dwarf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialistOutput {
    /// Confirmed observations grounded in collected evidence.
    #[serde(default)]
    pub confirmed_observations: Vec<String>,
    /// Evidence or rule references cited by the specialist.
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    /// Remaining uncertainty or missing evidence.
    pub remaining_uncertainty: String,
    /// Optional authorised diagnostic tool requested for follow-up evidence.
    #[serde(default)]
    pub requested_tool: Option<String>,
    /// Concise recommendation handed back to `KommandantZwerg`.
    pub recommendation: String,
}

/// Result of delegating a material patrol anomaly to a specialist dwarf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialistDelegation {
    /// Anomaly identifier addressed by this specialist.
    pub anomaly_id: String,
    /// Specialist dwarf competency invoked.
    pub dwarf_id: DwarfId,
    /// Model identifier used for this specialist's reasoning.
    pub model_used: String,
    /// Target URL inspected.
    pub target_url: String,
    /// Concise specialist assessment grounded in the anomaly observations.
    pub assessment: String,
    /// Parsed structured output when the specialist returned valid contract JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<SpecialistOutput>,
    /// Diagnostic tool executed on behalf of the specialist, if requested and authorised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_executed: Option<String>,
    /// Number of findings produced by the executed specialist tool.
    #[serde(default)]
    pub tool_findings_count: usize,
}

/// Change-oriented report produced by [`run_patrol`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatrolReport {
    /// Unique patrol run identifier.
    pub patrol_id: String,
    /// Sequential patrol number (`1` = first encounter, `2+` = recurring patrol).
    pub patrol_number: usize,
    /// Primary application target.
    pub target: AuditTarget,
    /// Whether the patrol completed primary collection without fatal failure.
    pub execution_succeeded: bool,
    /// Reconciled application topology.
    pub application_map: ApplicationMap,
    /// Explicit sampling plan with selection reasons and reused URLs.
    pub sampling_plan: SamplingPlan,
    /// Number of remembered healthy pages whose prior observations were reused.
    pub reused_page_count: usize,
    /// Structured coverage accounting and limitations.
    #[serde(default)]
    pub coverage_matrix: CoverageMatrix,
    /// Resource and AI expenditure ledger for this patrol.
    #[serde(default)]
    pub resource_ledger: PatrolResourceLedger,
    /// Anomalies detected during this patrol.
    pub anomalies: Vec<PatrolAnomaly>,
    /// Cross-page Application Graph results evaluated over inspected patrol pages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub graph_results: Vec<crate::domain::AnalyserResult>,
    /// Specialist competencies activated for anomaly investigation.
    pub specialist_escalations: Vec<DwarfId>,
    /// Per-anomaly specialist assessments produced using per-dwarf model routing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub specialist_delegations: Vec<SpecialistDelegation>,
    /// Optional targeted `KommandantZwerg` investigation triggered by anomalies.
    pub investigation: Option<InvestigationReport>,
    /// Optional regression diff against the previous patrol's seed report.
    pub regression: Option<RegressionReport>,
    /// Explicit human-readable coverage boundaries.
    pub coverage_summary: String,
    /// Concise change-oriented stakeholder summary.
    pub executive_summary: String,
    /// `true` when no material changes, anomalies, or unverified gaps were detected.
    pub is_quiet_patrol: bool,
    /// Non-empty when loading existing [`ApplicationMemory`] failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_load_error: Option<String>,
    /// Non-empty when persisting updated [`ApplicationMemory`] failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_save_error: Option<String>,
}

fn extract_first_url_from_summary(summary: &str) -> Option<String> {
    summary
        .split_whitespace()
        .map(|tok| tok.trim_matches(|c: char| matches!(c, ',' | ';' | '.' | ')' | '(' | '`')))
        .find(|tok| tok.starts_with("http://") || tok.starts_with("https://"))
        .map(str::to_owned)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct SingleProviderRouter<'a>(Option<&'a dyn LlmProvider>);

impl ProviderRouter for SingleProviderRouter<'_> {
    fn resolve_for_dwarf(&self, _dwarf_id: DwarfId) -> Option<&dyn LlmProvider> {
        self.0
    }
}

/// Executes an autonomous web quality patrol against `seed` using a single optional LLM provider.
pub async fn run_patrol(
    seed: AuditTarget,
    policy: TargetPolicy,
    exec_budget: ExecutionBudget,
    patrol_budget: PatrolBudget,
    memory_dir: Option<&Path>,
    llm: Option<&dyn LlmProvider>,
    backend: Arc<dyn DiagnosticBackend>,
) -> PatrolReport {
    let router = SingleProviderRouter(llm);
    Box::pin(run_patrol_with_router(
        seed,
        policy,
        exec_budget,
        patrol_budget,
        memory_dir,
        Some(&router),
        backend,
    ))
    .await
}

/// Executes an autonomous web quality patrol against `seed` with per-dwarf [`ProviderRouter`].
#[allow(clippy::too_many_lines)]
pub async fn run_patrol_with_router(
    seed: AuditTarget,
    policy: TargetPolicy,
    exec_budget: ExecutionBudget,
    patrol_budget: PatrolBudget,
    memory_dir: Option<&Path>,
    router: Option<&dyn ProviderRouter>,
    backend: Arc<dyn DiagnosticBackend>,
) -> PatrolReport {
    let started = std::time::Instant::now();
    let now = unix_now_secs();
    let origin = Origin::from_target(&seed);
    let app_id = memory::ApplicationId::from_origin(&origin);

    let (mut mem, memory_load_error) = match memory_dir {
        Some(dir) => match load_memory(dir, &app_id) {
            Ok(Some(loaded)) => (loaded, None),
            Ok(None) => (ApplicationMemory::new(&seed, now), None),
            Err(err) => (
                ApplicationMemory::new(&seed, now),
                Some(format!("failed to load patrol memory: {err}")),
            ),
        },
        None => (ApplicationMemory::new(&seed, now), None),
    };
    let is_returning = mem.patrol_count > 0;
    let patrol_number = mem.patrol_count + 1;

    // 1. Level 0 discovery: sitemap / sitemap-index + remembered URLs.
    let mut discovered = seed_sitemap_urls(&seed, exec_budget, policy).await;
    let sitemap_urls: std::collections::HashSet<String> =
        discovered.iter().map(|u| u.as_str().to_owned()).collect();
    for url_str in mem.page_records.keys() {
        if let Ok(t) = AuditTarget::parse(url_str, policy)
            && Origin::from_target(&t) == origin
        {
            discovered.push(t);
        }
    }

    // 2. Build stratified SamplingPlan before inspecting pages.
    let mut sampling_plan = build_sampling_plan(
        &seed,
        &discovered,
        if is_returning { Some(&mem) } else { None },
        patrol_budget.max_pages,
        patrol_budget.max_deep_samples,
        now,
        patrol_budget.freshness_ttl_secs,
    );

    // 3. Level 1 deterministic inspection for selected pages.
    let mut seed_report: Option<AuditReport> = None;
    let mut page_reports: Vec<(SampleSelection, AuditReport, Option<String>, Option<String>)> =
        Vec::new();
    let mut page_snapshots: BTreeMap<String, crate::domain::EvidenceSnapshot> = BTreeMap::new();
    let mut locales_set: BTreeSet<String> = mem.known_locales.iter().cloned().collect();
    let mut page_types: BTreeMap<String, PageType> = BTreeMap::new();
    let mut template_families: BTreeMap<String, String> = BTreeMap::new();

    for (url, rec) in &mem.page_records {
        page_types.insert(url.clone(), rec.page_type);
        if let Some(tpl) = &rec.template_fingerprint {
            template_families.insert(url.clone(), tpl.clone());
        }
    }
    for url in &discovered {
        page_types
            .entry(url.as_str().to_owned())
            .or_insert(PageType::Unknown);
    }

    let mut extra_links: Vec<AuditTarget> = Vec::new();
    let mut budget_exhausted = false;
    for sel in &sampling_plan.selections {
        let rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
        if rem.is_zero() {
            budget_exhausted = true;
            break;
        }
        let step_budget = ExecutionBudget {
            audit_timeout: rem,
            http_timeout: exec_budget.http_timeout.min(rem),
            ..exec_budget
        };
        let mut snap = collection::collect_http(&sel.url, &step_budget, policy).await;
        if patrol_budget.enable_level2 && sel.depth == sampling::DiagnosticDepth::Level2Deep {
            let l2_rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
            if !l2_rem.is_zero() {
                snap.browser =
                    crate::adapters::browser::run_browser_with_policy(&sel.url, l2_rem, policy)
                        .await;
            }
        }
        let report = analysis::run_all(&snap);
        let (pt, tpl, body_hash) = if let CollectorOutcome::Captured { data } = &snap.http {
            let obs = analysis::document::DocumentObservations::from_html(&data.body_text);
            let pt = classify_page(&sel.url, &obs);
            let tpl = template_fingerprint(&obs);
            if let Some(loc) = detect_locale(&sel.url, Some(&obs)) {
                locales_set.insert(loc.tag);
            }
            if sel.url == seed {
                extra_links = discover_same_origin_links(&seed, &obs, policy);
            }
            (pt, Some(tpl), Some(hash_body(&data.body_text)))
        } else {
            (sel.page_type.unwrap_or(PageType::Unknown), None, None)
        };
        page_types.insert(sel.url.as_str().to_owned(), pt);
        if let Some(t) = &tpl {
            template_families.insert(sel.url.as_str().to_owned(), t.clone());
        }
        if sel.url == seed {
            seed_report = Some(report.clone());
        }
        page_snapshots.insert(sel.url.as_str().to_owned(), snap);
        page_reports.push((sel.clone(), report, tpl, body_hash));
    }

    // 3b. Verify reused healthy candidates via conditional HTTP (capped at max_pages);
    // immediately re-inspect changed pages while active inspections remain < max_pages.
    let mut verified_reused_count = 0usize;
    let mut unverified_reused_count = 0usize;
    let mut conditional_checks = 0usize;
    for reused_url in &sampling_plan.reused_urls {
        if conditional_checks >= patrol_budget.max_pages {
            unverified_reused_count += 1;
            continue;
        }
        let rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
        if rem.is_zero() {
            budget_exhausted = true;
            unverified_reused_count += 1;
            continue;
        }
        let Some(rec) = mem.page_records.get(reused_url).cloned() else {
            unverified_reused_count += 1;
            continue;
        };
        if rec.etag.is_none() && rec.last_modified.is_none() {
            unverified_reused_count += 1;
            continue;
        }
        let Ok(target) = AuditTarget::parse(reused_url, policy) else {
            unverified_reused_count += 1;
            continue;
        };
        let step_budget = ExecutionBudget {
            audit_timeout: rem,
            http_timeout: exec_budget.http_timeout.min(rem),
            ..exec_budget
        };
        conditional_checks += 1;
        let outcome = collection::check_if_unchanged(
            &target,
            rec.etag.as_deref(),
            rec.last_modified.as_deref(),
            &step_budget,
            policy,
        )
        .await;
        if outcome == collection::ConditionalCheckOutcome::Unchanged {
            verified_reused_count += 1;
            if let Some(entry) = mem.page_records.get_mut(reused_url) {
                entry.freshness = EvidenceFreshness::HttpRepresentationOnly;
                entry.last_inspected_unix_secs = now;
            }
        } else if page_reports.len() < patrol_budget.max_pages {
            // Changed or unverifiable: immediately re-inspect within max_pages cap.
            let snap = collection::collect_http(&target, &step_budget, policy).await;
            let report = analysis::run_all(&snap);
            let (pt, tpl, body_hash) = if let CollectorOutcome::Captured { data } = &snap.http {
                let obs = analysis::document::DocumentObservations::from_html(&data.body_text);
                let pt = classify_page(&target, &obs);
                let tpl = template_fingerprint(&obs);
                (pt, Some(tpl), Some(hash_body(&data.body_text)))
            } else {
                (rec.page_type, None, None)
            };
            page_types.insert(reused_url.clone(), pt);
            if let Some(t) = &tpl {
                template_families.insert(reused_url.clone(), t.clone());
            }
            page_reports.push((
                SampleSelection {
                    url: target,
                    reason: sampling::SelectionReason::RecentlyChanged,
                    depth: sampling::DiagnosticDepth::Level1Deterministic,
                    locale: rec.locale.clone(),
                    page_type: Some(pt),
                },
                report,
                tpl,
                body_hash,
            ));
        } else {
            unverified_reused_count += 1;
        }
    }

    // Include newly discovered homepage links in the application map for subsequent patrols.
    for link in extra_links {
        if !page_types.contains_key(link.as_str()) {
            page_types.insert(link.as_str().to_owned(), PageType::Unknown);
        }
        sampling_plan.total_discovered = page_types.len().max(sampling_plan.total_discovered);
    }

    // 4. Historical comparison on the primary entry point and all remembered subpages.
    let regression = match (&mem.latest_report, &seed_report) {
        (Some(prev), Some(curr)) => Some(persistence::diff_reports(prev, curr)),
        _ => None,
    };
    let subpage_regressions: Vec<RegressionReport> = page_reports
        .iter()
        .filter(|(sel, _, _, _)| sel.url != seed)
        .filter_map(|(sel, curr, _, _)| {
            mem.page_records
                .get(sel.url.as_str())
                .and_then(|rec| rec.latest_report.as_ref())
                .map(|prev| persistence::diff_reports(prev, curr))
        })
        .collect();

    // 5. Application Graph analysis + anomaly detection across seed + subpages.
    let graph_inputs: Vec<crate::analysis::graph::GraphPageInput> = page_reports
        .iter()
        .map(|(sel, rep, _, _)| {
            let in_sitemap = sitemap_urls.contains(sel.url.as_str());
            match &rep.http {
                CollectorOutcome::Captured { data } => {
                    crate::discovery::build_captured_graph_input(
                        &sel.url,
                        data,
                        &crate::analysis::document::DocumentObservations::from_html(
                            &data.body_text,
                        ),
                        usize::from(sel.url != seed),
                        in_sitemap,
                        policy,
                    )
                }
                _ => crate::discovery::unreachable_graph_input(
                    &sel.url,
                    usize::from(sel.url != seed),
                    in_sitemap,
                ),
            }
        })
        .collect();
    let app_graph = crate::analysis::graph::ApplicationGraph::from_pages(
        &graph_inputs,
        page_reports.len() >= discovered.len(),
    );
    let graph_results = crate::analysis::graph::analyse(&app_graph);

    let mut anomalies = detect_anomalies(
        &page_reports,
        regression.as_ref(),
        &subpage_regressions,
        is_returning,
    );
    let prev_graph_rules: std::collections::HashSet<&str> = mem
        .known_graph_rule_ids
        .iter()
        .map(String::as_str)
        .collect();
    let mut current_graph_rules: BTreeSet<String> = BTreeSet::new();
    for res in &graph_results {
        for f in &res.findings {
            let sig = format!("{}::{}", f.rule_id.0, f.summary);
            current_graph_rules.insert(sig.clone());
            let is_new_graph_defect = !is_returning || !prev_graph_rules.contains(sig.as_str());
            if f.severity >= Severity::Medium && is_new_graph_defect {
                let affected_url = extract_first_url_from_summary(&f.summary)
                    .unwrap_or_else(|| seed.as_str().to_owned());
                anomalies.push(PatrolAnomaly {
                    id: format!("anom-graph-{}", anomalies.len() + 1),
                    category: AnomalyCategory::NewDefect,
                    affected_url,
                    severity: f.severity,
                    summary: format!("[Graph: {}] {}", f.rule_id.0, f.title),
                    suggested_competency: res.dwarf_id,
                });
            }
        }
    }

    // 6. Collaborative specialist delegation (with evidence context & authorised tool
    // execution) followed by KommandantZwerg synthesis over specialist contributions,
    // bounded by the remaining patrol wall-clock deadline.
    let mut specialist_escalations: Vec<DwarfId> = Vec::new();
    let mut specialist_delegations: Vec<SpecialistDelegation> = Vec::new();
    let mut prior_specialists: Vec<crate::investigation::SpecialistContribution> = Vec::new();
    let mut specialist_llm_calls = 0usize;
    let mut specialist_tool_calls = 0usize;
    let mut investigation: Option<InvestigationReport> = None;
    let esc_rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
    if esc_rem.is_zero() && !anomalies.is_empty() {
        budget_exhausted = true;
    } else if patrol_budget.allow_ai_escalation && !anomalies.is_empty() {
        for a in anomalies.iter().take(3) {
            if !specialist_escalations.contains(&a.suggested_competency) {
                specialist_escalations.push(a.suggested_competency);
            }
            let spec_rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
            if spec_rem.is_zero() {
                budget_exhausted = true;
                break;
            }
            let spec_llm = router.and_then(|r| {
                r.resolve_for_dwarf(a.suggested_competency)
                    .or_else(|| r.resolve_for_dwarf(DwarfId::Kommandant))
            });
            if let Some(provider) = spec_llm {
                let page_findings: Vec<String> = page_reports
                    .iter()
                    .find(|(sel, _, _, _)| sel.url.as_str() == a.affected_url)
                    .map(|(_, rep, _, _)| {
                        rep.analysers
                            .iter()
                            .flat_map(|an| an.findings.iter())
                            .take(10)
                            .map(|f| format!("[{:?}] {}: {}", f.severity, f.rule_id.0, f.title))
                            .collect()
                    })
                    .unwrap_or_default();
                let contract = prompts::specialist_prompt(a.suggested_competency, &a.summary);
                let user_msg = format!(
                    "Anomaly `{}` on `{}` ({:?}): {}\nObserved deterministic findings on page: {}\nSource content evidence: {}",
                    a.id,
                    a.affected_url,
                    a.severity,
                    a.summary,
                    page_findings.join(" | "),
                    analysis::segmentation::content_evidence_context(
                        page_snapshots.get(&a.affected_url)
                    )
                );
                let llm_budget = LlmBudget {
                    max_tokens: 512,
                    max_requests: 1,
                    timeout: spec_rem.min(std::time::Duration::from_secs(15)),
                };
                specialist_llm_calls += 1;
                if let Ok(raw_resp) = provider
                    .complete(&contract.system_prompt, &user_msg, llm_budget)
                    .await
                {
                    let mut structured = serde_json::from_str::<SpecialistOutput>(&raw_resp).ok();
                    let mut tool_executed = None;
                    let mut tool_findings_count = 0usize;
                    if let Some(ref mut out) = structured
                        && let Some(tool_id) = out.requested_tool.as_deref()
                        && let Ok(spec_target) = AuditTarget::parse(&a.affected_url, policy)
                        && let Some(snap) = page_snapshots.get_mut(&a.affected_url)
                    {
                        let tool_rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
                        if !tool_rem.is_zero() {
                            specialist_tool_calls += 1;
                            let (ok, tool_outputs) =
                                crate::investigation::run_specialist_tool_on_snapshot(
                                    tool_id,
                                    &spec_target,
                                    policy,
                                    tool_rem,
                                    Arc::clone(&backend),
                                    snap,
                                )
                                .await;
                            if ok {
                                tool_executed = Some(tool_id.to_owned());
                                for res in &tool_outputs {
                                    tool_findings_count += res.findings.len();
                                    for f in &res.findings {
                                        out.evidence_refs.push(f.rule_id.0.clone());
                                        out.confirmed_observations
                                            .push(format!("{}: {}", f.rule_id.0, f.title));
                                    }
                                }
                            }
                        }
                    }

                    let contribution = if let Some(ref out) = structured {
                        crate::investigation::SpecialistContribution {
                            dwarf_id: a.suggested_competency,
                            focus: format!("{} ({})", a.id, a.affected_url),
                            observations: out.confirmed_observations.clone(),
                            uncertainty: out.remaining_uncertainty.clone(),
                        }
                    } else {
                        crate::investigation::SpecialistContribution {
                            dwarf_id: a.suggested_competency,
                            focus: format!("{} ({})", a.id, a.affected_url),
                            observations: vec![raw_resp.clone()],
                            uncertainty: "unstructured specialist response".to_owned(),
                        }
                    };
                    prior_specialists.push(contribution);

                    specialist_delegations.push(SpecialistDelegation {
                        anomaly_id: a.id.clone(),
                        dwarf_id: a.suggested_competency,
                        model_used: provider.model_name().to_owned(),
                        target_url: a.affected_url.clone(),
                        assessment: raw_resp,
                        structured_output: structured,
                        tool_executed,
                        tool_findings_count,
                    });
                }
            }
        }

        let kommandant_rem = exec_budget.audit_timeout.saturating_sub(started.elapsed());
        if kommandant_rem.is_zero() {
            budget_exhausted = true;
        } else if let Some(provider) = router.and_then(|r| r.resolve_for_dwarf(DwarfId::Kommandant))
        {
            let investigation_target = AuditTarget::parse(&anomalies[0].affected_url, policy)
                .unwrap_or_else(|_| seed.clone());
            let objective = format!(
                "Synthesise {} specialist findings and investigate {} patrol anomaly(ies); top concern on {}: {}",
                prior_specialists.len(),
                anomalies.len(),
                investigation_target.as_str(),
                anomalies[0].summary
            );
            let default_inv_budget = InvestigationBudget::default();
            let bounded_inv_budget = InvestigationBudget {
                max_duration: kommandant_rem.min(default_inv_budget.max_duration),
                ..default_inv_budget
            };
            investigation = Some(
                crate::investigation::run_investigation_with_specialists(
                    investigation_target,
                    objective,
                    policy,
                    bounded_inv_budget,
                    Arc::clone(&backend),
                    provider,
                    prior_specialists,
                )
                .await,
            );
        }
    }

    // 7. Update institutional memory.
    for (sel, report, tpl, body_hash) in &page_reports {
        let open_finding_count = report.summary.critical_findings
            + report.summary.high_findings
            + report.summary.medium_findings
            + report.summary.low_findings;
        let prev_streak = mem
            .page_records
            .get(sel.url.as_str())
            .map_or(0, |r| r.healthy_streak);
        let healthy_streak = if open_finding_count == 0 {
            prev_streak + 1
        } else {
            0
        };
        let pt = page_types
            .get(sel.url.as_str())
            .copied()
            .unwrap_or(PageType::Unknown);
        let (freshness, etag, last_modified) = match &report.http {
            CollectorOutcome::Captured { data } => (
                EvidenceFreshness::CurrentlyVerified,
                data.headers
                    .iter()
                    .find(|h| h.name == "etag")
                    .map(|h| h.value.clone()),
                data.headers
                    .iter()
                    .find(|h| h.name == "last-modified")
                    .map(|h| h.value.clone()),
            ),
            _ => (EvidenceFreshness::Unverified, None, None),
        };
        mem.page_records.insert(
            sel.url.as_str().to_owned(),
            RememberedPage {
                url: sel.url.as_str().to_owned(),
                locale: sel.locale.clone(),
                page_type: pt,
                template_fingerprint: tpl.clone(),
                content_hash: body_hash.clone(),
                etag,
                last_modified,
                latest_report: Some(report.clone()),
                last_inspected_unix_secs: now,
                open_finding_count,
                healthy_streak,
                freshness,
            },
        );
    }
    mem.patrol_count = patrol_number;
    mem.last_patrolled_unix_secs = now;
    mem.known_locales = locales_set.iter().cloned().collect();
    mem.known_graph_rule_ids = current_graph_rules.into_iter().collect();
    if mem.baseline_report.is_none() {
        mem.baseline_report.clone_from(&seed_report);
    }
    if seed_report.is_some() {
        mem.latest_report.clone_from(&seed_report);
    }
    let memory_save_error = memory_dir
        .and_then(|dir| save_memory(dir, &mem).err())
        .map(|err| format!("failed to save patrol memory: {err}"));

    let execution_succeeded = seed_report
        .as_ref()
        .is_some_and(|r| !matches!(r.http, CollectorOutcome::Failed { .. }));
    let reused_page_count = verified_reused_count;
    let has_subpage_regressions = subpage_regressions
        .iter()
        .any(|r| r.summary.new_count > 0 || r.summary.reintroduced_count > 0);
    let is_quiet_patrol = anomalies.is_empty()
        && !has_subpage_regressions
        && unverified_reused_count == 0
        && !budget_exhausted
        && memory_load_error.is_none()
        && regression
            .as_ref()
            .is_none_or(|r| r.summary.new_count == 0 && r.summary.reintroduced_count == 0);

    let application_map = ApplicationMap {
        origin: origin.canonical_string(),
        discovered_urls: page_types.keys().cloned().collect(),
        locales_observed: locales_set.into_iter().collect(),
        page_types,
        template_families,
        last_patrolled_unix_secs: now,
    };

    let deep_inspected_urls = page_reports
        .iter()
        .filter(|(sel, _, _, _)| {
            patrol_budget.enable_level2 && sel.depth == sampling::DiagnosticDepth::Level2Deep
        })
        .count();
    let distinct_page_types: BTreeSet<PageType> =
        application_map.page_types.values().copied().collect();
    let distinct_templates: BTreeSet<&str> = application_map
        .template_families
        .values()
        .map(String::as_str)
        .collect();
    let mut limitations =
        vec!["Authenticated customer journeys and post-login state were not inspected.".to_owned()];
    if !patrol_budget.enable_level2 {
        limitations.push(
            "Level 2 headless browser diagnostics were not enabled for this patrol.".to_owned(),
        );
    }
    if unverified_reused_count > 0 {
        limitations.push(format!(
            "{unverified_reused_count} healthy candidate(s) lacked verifiable ETag/Last-Modified confirmation and were not counted as verified unchanged."
        ));
    }
    let coverage_matrix = CoverageMatrix {
        discovered_urls: application_map.discovered_urls.len(),
        inspected_urls: page_reports.len(),
        deep_inspected_urls,
        reused_urls: reused_page_count,
        locales_observed: application_map.locales_observed.clone(),
        page_types_observed: distinct_page_types.len(),
        template_families_observed: distinct_templates.len(),
        limitations,
    };

    let coverage_summary = format!(
        "Patrol #{patrol_number}: {} discovered URLs, {} inspected, {} reused healthy observations, {} locale(s) observed.",
        application_map.discovered_urls.len(),
        page_reports.len(),
        reused_page_count,
        application_map.locales_observed.len()
    );
    let executive_summary = build_executive_summary(
        patrol_number,
        execution_succeeded,
        is_quiet_patrol,
        &anomalies,
        regression.as_ref(),
    );

    let resource_ledger = PatrolResourceLedger {
        discovery_requests: usize::from(!discovered.is_empty()).max(1),
        http_requests: page_reports.len(),
        browser_sessions: deep_inspected_urls,
        llm_requests: specialist_llm_calls
            + investigation
                .as_ref()
                .map_or(0, |inv| inv.ledger.llm_turns_used),
        investigation_tool_calls: specialist_tool_calls
            + investigation
                .as_ref()
                .map_or(0, |inv| inv.ledger.tool_calls_used),
        conditional_checks,
        reused_observations: reused_page_count,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    };

    PatrolReport {
        patrol_id: format!("patrol-{patrol_number}-{now}"),
        patrol_number,
        target: seed,
        execution_succeeded,
        application_map,
        sampling_plan,
        reused_page_count,
        coverage_matrix,
        resource_ledger,
        anomalies,
        graph_results,
        specialist_escalations,
        specialist_delegations,
        investigation,
        regression,
        coverage_summary,
        executive_summary,
        is_quiet_patrol,
        memory_load_error,
        memory_save_error,
    }
}

/// Renders a change-oriented Markdown situation report for the requested stakeholder perspective.
#[must_use]
pub fn render_patrol_markdown(
    report: &PatrolReport,
    audience: crate::investigation::reporting::RolePerspective,
) -> String {
    use std::fmt::Write as _;
    let mut md = String::new();
    let _ = writeln!(
        md,
        "# NetzZwergenWacht — Routine Patrol #{} ({audience:?})\n",
        report.patrol_number
    );
    let _ = writeln!(md, "**Application:** `{}`  ", report.target.as_str());
    let _ = writeln!(md, "**Overall assessment:** {}\n", report.executive_summary);

    if report.is_quiet_patrol {
        let persisting = report
            .regression
            .as_ref()
            .map_or(0, |r| r.summary.persisting_count);
        let _ = writeln!(
            md,
            "No material changes detected within the investigated scope ({persisting} previously known finding(s) persisting).\n"
        );
    } else if !report.anomalies.is_empty() {
        let _ = writeln!(md, "## Material Anomalies\n");
        for a in &report.anomalies {
            let _ = writeln!(
                md,
                "- **[{}]** ({:?}, `{}`) {}",
                a.id, a.severity, a.affected_url, a.summary
            );
        }
        let _ = writeln!(md);
    }

    if let Some(reg) = &report.regression {
        let _ = writeln!(md, "## Changes Since Previous Patrol\n");
        let _ = writeln!(
            md,
            "- New: {} | Persisting: {} | Resolved: {} | Reintroduced: {} | Unverified: {}\n",
            reg.summary.new_count,
            reg.summary.persisting_count,
            reg.summary.resolved_count,
            reg.summary.reintroduced_count,
            reg.summary.unverified_count
        );
    }

    let _ = writeln!(md, "## Coverage & Limitations\n");
    let _ = writeln!(
        md,
        "- Discovered URLs: {} | Inspected: {} | Deep Level 2: {} | Reused healthy: {}",
        report.coverage_matrix.discovered_urls,
        report.coverage_matrix.inspected_urls,
        report.coverage_matrix.deep_inspected_urls,
        report.coverage_matrix.reused_urls
    );
    if !report.coverage_matrix.locales_observed.is_empty() {
        let _ = writeln!(
            md,
            "- Locales observed: {}",
            report.coverage_matrix.locales_observed.join(", ")
        );
    }
    for lim in &report.coverage_matrix.limitations {
        let _ = writeln!(md, "- Limitation: {lim}");
    }
    md
}

fn suggested_competency(f: &Finding) -> DwarfId {
    let prefix = f.rule_id.0.split('.').next().unwrap_or("");
    match prefix {
        "sec" => DwarfId::Sicherheits,
        "perf" => DwarfId::Leistungs,
        "a11y" => DwarfId::Zugaenglichkeits,
        "seo" => DwarfId::Such,
        "content" => DwarfId::Inhalts,
        "sem" => DwarfId::Struktur,
        "browser" => DwarfId::Browser,
        "visual" => DwarfId::Gestaltungs,
        _ => DwarfId::Netz,
    }
}

fn push_regression_anomalies(reg: &RegressionReport, anomalies: &mut Vec<PatrolAnomaly>) {
    for f in &reg.new_findings {
        if f.severity >= Severity::Medium {
            anomalies.push(PatrolAnomaly {
                id: format!("ANO-{}", anomalies.len() + 1),
                category: AnomalyCategory::MaterialRegression,
                affected_url: reg.current_target.clone(),
                severity: f.severity,
                summary: format!("New finding `{}`: {}", f.rule_id.0, f.title),
                suggested_competency: suggested_competency(f),
            });
        }
    }
    for f in &reg.reintroduced_findings {
        anomalies.push(PatrolAnomaly {
            id: format!("ANO-{}", anomalies.len() + 1),
            category: AnomalyCategory::MaterialRegression,
            affected_url: reg.current_target.clone(),
            severity: f.severity,
            summary: format!("Reintroduced finding `{}`: {}", f.rule_id.0, f.title),
            suggested_competency: suggested_competency(f),
        });
    }
}

fn detect_anomalies(
    page_reports: &[(SampleSelection, AuditReport, Option<String>, Option<String>)],
    regression: Option<&RegressionReport>,
    subpage_regressions: &[RegressionReport],
    is_returning: bool,
) -> Vec<PatrolAnomaly> {
    let mut anomalies = Vec::new();
    if let Some(reg) = regression {
        push_regression_anomalies(reg, &mut anomalies);
    }
    for reg in subpage_regressions {
        push_regression_anomalies(reg, &mut anomalies);
    }
    if !is_returning {
        for (sel, report, _, _) in page_reports {
            for analyser in &report.analysers {
                for f in &analyser.findings {
                    if f.severity >= Severity::High {
                        anomalies.push(PatrolAnomaly {
                            id: format!("ANO-{}", anomalies.len() + 1),
                            category: AnomalyCategory::NewDefect,
                            affected_url: sel.url.as_str().to_owned(),
                            severity: f.severity,
                            summary: format!(
                                "{} on {}: {}",
                                f.rule_id.0,
                                sel.url.as_str(),
                                f.title
                            ),
                            suggested_competency: suggested_competency(f),
                        });
                    }
                }
            }
        }
    }
    anomalies
}

fn build_executive_summary(
    patrol_number: usize,
    execution_succeeded: bool,
    is_quiet_patrol: bool,
    anomalies: &[PatrolAnomaly],
    regression: Option<&RegressionReport>,
) -> String {
    if !execution_succeeded {
        return format!(
            "Patrol #{patrol_number} failed primary HTTP collection; application health could not be verified."
        );
    }
    if is_quiet_patrol {
        let persisting = regression.map_or(0, |r| r.summary.persisting_count);
        return format!(
            "Patrol #{patrol_number}: no material changes or new anomalies detected within investigated scope ({persisting} previously known finding(s) persisting)."
        );
    }
    let resolved = regression.map_or(0, |r| r.summary.resolved_count);
    format!(
        "Patrol #{patrol_number}: detected {} material anomaly(ies); {resolved} prior finding(s) verified resolved.",
        anomalies.len()
    )
}
