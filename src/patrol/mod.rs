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
use crate::intelligence::LlmProvider;
use crate::investigation::{
    DiagnosticBackend, InvestigationBudget, InvestigationReport, run_investigation,
};
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
            max_pages: 10,
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
    /// Total HTTP page fetches executed during sampling.
    pub http_requests: usize,
    /// Total Level 2 headless browser sessions executed.
    pub browser_sessions: usize,
    /// Total LLM turns consumed by selective specialist escalation.
    pub llm_requests: usize,
    /// Healthy remembered page observations reused without re-fetching.
    pub reused_observations: usize,
    /// Total patrol wall-clock duration in milliseconds.
    pub duration_ms: u64,
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
    /// Specialist competencies activated for anomaly investigation.
    pub specialist_escalations: Vec<DwarfId>,
    /// Optional targeted `KommandantZwerg` investigation triggered by anomalies.
    pub investigation: Option<InvestigationReport>,
    /// Optional regression diff against the previous patrol's seed report.
    pub regression: Option<RegressionReport>,
    /// Explicit human-readable coverage boundaries.
    pub coverage_summary: String,
    /// Concise change-oriented stakeholder summary.
    pub executive_summary: String,
    /// `true` when no material changes or anomalies were detected.
    pub is_quiet_patrol: bool,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Executes an autonomous web quality patrol against `seed`.
#[allow(clippy::too_many_lines)]
pub async fn run_patrol(
    seed: AuditTarget,
    policy: TargetPolicy,
    exec_budget: ExecutionBudget,
    patrol_budget: PatrolBudget,
    memory_dir: Option<&Path>,
    llm: Option<&dyn LlmProvider>,
    backend: Arc<dyn DiagnosticBackend>,
) -> PatrolReport {
    let started = std::time::Instant::now();
    let now = unix_now_secs();
    let origin = Origin::from_target(&seed);
    let app_id = memory::ApplicationId::from_origin(&origin);

    let mut mem = memory_dir
        .and_then(|dir| load_memory(dir, &app_id).ok().flatten())
        .unwrap_or_else(|| ApplicationMemory::new(&seed, now));
    let is_returning = mem.patrol_count > 0;
    let patrol_number = mem.patrol_count + 1;

    // 1. Level 0 discovery: sitemap / sitemap-index + remembered URLs.
    let mut discovered = seed_sitemap_urls(&seed, exec_budget, policy).await;
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
    let mut locales_set: BTreeSet<String> = mem.known_locales.iter().cloned().collect();
    let mut page_types: BTreeMap<String, PageType> = BTreeMap::new();
    let mut template_families: BTreeMap<String, String> = BTreeMap::new();

    for (url, rec) in &mem.page_records {
        page_types.insert(url.clone(), rec.page_type);
        if let Some(tpl) = &rec.template_fingerprint {
            template_families.insert(url.clone(), tpl.clone());
        }
    }

    let mut extra_links: Vec<AuditTarget> = Vec::new();
    for sel in &sampling_plan.selections {
        let mut snap = collection::collect_http(&sel.url, &exec_budget, policy).await;
        if patrol_budget.enable_level2 && sel.depth == sampling::DiagnosticDepth::Level2Deep {
            snap.browser = crate::adapters::browser::run_browser_with_policy(
                &sel.url,
                exec_budget.audit_timeout,
                policy,
            )
            .await;
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
        page_reports.push((sel.clone(), report, tpl, body_hash));
    }

    // Include newly discovered homepage links in the application map for subsequent patrols.
    for link in extra_links {
        if !page_types.contains_key(link.as_str()) {
            page_types.insert(link.as_str().to_owned(), PageType::Unknown);
        }
        sampling_plan.total_discovered = page_types.len().max(sampling_plan.total_discovered);
    }

    // 4. Historical comparison on the primary entry point.
    let regression = match (&mem.latest_report, &seed_report) {
        (Some(prev), Some(curr)) => Some(persistence::diff_reports(prev, curr)),
        _ => None,
    };

    // 5. Anomaly detection.
    let anomalies = detect_anomalies(&page_reports, regression.as_ref(), is_returning);

    // 6. Selective specialist escalation.
    let mut specialist_escalations: Vec<DwarfId> = Vec::new();
    let mut investigation: Option<InvestigationReport> = None;
    if patrol_budget.allow_ai_escalation
        && !anomalies.is_empty()
        && let Some(provider) = llm
    {
        for a in &anomalies {
            if !specialist_escalations.contains(&a.suggested_competency) {
                specialist_escalations.push(a.suggested_competency);
            }
        }
        let objective = format!(
            "Investigate {} patrol anomaly(ies); top concern: {}",
            anomalies.len(),
            anomalies[0].summary
        );
        investigation = Some(
            run_investigation(
                seed.clone(),
                objective,
                policy,
                InvestigationBudget::default(),
                Arc::clone(&backend),
                provider,
            )
            .await,
        );
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
        let freshness = if matches!(report.http, CollectorOutcome::Captured { .. }) {
            EvidenceFreshness::CurrentlyVerified
        } else {
            EvidenceFreshness::Unverified
        };
        mem.page_records.insert(
            sel.url.as_str().to_owned(),
            RememberedPage {
                url: sel.url.as_str().to_owned(),
                locale: sel.locale.clone(),
                page_type: pt,
                template_fingerprint: tpl.clone(),
                content_hash: body_hash.clone(),
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
    if mem.baseline_report.is_none() {
        mem.baseline_report.clone_from(&seed_report);
    }
    if seed_report.is_some() {
        mem.latest_report.clone_from(&seed_report);
    }
    if let Some(dir) = memory_dir {
        let _ = save_memory(dir, &mem);
    }

    let execution_succeeded = seed_report
        .as_ref()
        .is_some_and(|r| !matches!(r.http, CollectorOutcome::Failed { .. }));
    let reused_page_count = sampling_plan.reused_urls.len();
    let is_quiet_patrol = anomalies.is_empty()
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
        http_requests: page_reports.len(),
        browser_sessions: deep_inspected_urls,
        llm_requests: investigation
            .as_ref()
            .map_or(0, |inv| inv.ledger.llm_turns_used),
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
        specialist_escalations,
        investigation,
        regression,
        coverage_summary,
        executive_summary,
        is_quiet_patrol,
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

fn detect_anomalies(
    page_reports: &[(SampleSelection, AuditReport, Option<String>, Option<String>)],
    regression: Option<&RegressionReport>,
    is_returning: bool,
) -> Vec<PatrolAnomaly> {
    let mut anomalies = Vec::new();
    if let Some(reg) = regression {
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
