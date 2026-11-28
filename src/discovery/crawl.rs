//! Concurrent, bounded application crawl.
//!
//! Acquisition is scheduled rather than looped: a bounded number of worker tasks consume from a
//! deduplicating frontier, and every task obeys the caller's [`ExecutionBudget`] and
//! [`TargetPolicy`]. The scheduling contract is recorded in ADR 0027.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use tokio::task::JoinSet;
use url::Url;

use super::frontier::{CrawlFrontier, DiscoverySource, EnqueueOutcome};
use super::resources::{self, ResourceCoverage, ResourceObservation, ResourceRef, ResourceStatus};
use super::robots;
use super::{
    CrawlBudget, CrawlCoverage, CrawlSummary, DiscoveredPage, PageCrawlStatus, PageType,
    aggregate_analysis_totals_with_graph, build_captured_graph_input, classify_page,
    cluster_systemic_issues, discover_same_origin_links, prioritise_representative_urls,
    seed_sitemap_urls_with_robots, unreachable_graph_input,
};
use crate::analysis::AuditReport;
use crate::analysis::document::DocumentObservations;
use crate::analysis::graph::{ApplicationGraph, GraphPageInput};
use crate::collection;
use crate::domain::{AuditTarget, CollectorOutcome, ExecutionBudget, TargetPolicy};

/// Upper bound on concurrent acquisitions against one host.
///
/// The global limit still applies. This bound exists so that a single-origin audit stays polite
/// even when the global budget allows more workers.
const MAX_PER_ORIGIN: usize = 4;

/// Everything one acquisition contributes to the crawl result.
struct PageOutcome {
    target: AuditTarget,
    final_target: Option<AuditTarget>,
    depth: usize,
    status: PageCrawlStatus,
    page_type: PageType,
    links: Vec<AuditTarget>,
    graph_input: Option<GraphPageInput>,
    report: Option<AuditReport>,
    /// HTTP status observed for the page, absent when no response was received.
    http_status: Option<u16>,
    /// Same-origin subresources referenced by the captured document.
    resources: Vec<ResourceRef>,
    /// Cross-origin subresource references observed but not acquired.
    external_resources: usize,
}

/// Crawl-wide acquisition settings shared by every page task.
#[derive(Clone, Copy)]
struct PageSchedule {
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
    max_depth: usize,
}

fn origin_key(target: &AuditTarget) -> String {
    Url::parse(target.as_str())
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_default()
}

fn has_capacity(
    entry: &super::frontier::FrontierEntry,
    in_flight: &HashMap<String, usize>,
    per_origin: usize,
) -> bool {
    in_flight
        .get(&origin_key(&entry.target))
        .copied()
        .unwrap_or(0)
        < per_origin
}

/// Pops the next entry whose origin has spare capacity, holding back the rest.
fn take_spawnable(
    frontier: &mut CrawlFrontier,
    pending: &mut Vec<super::frontier::FrontierEntry>,
    in_flight: &HashMap<String, usize>,
    per_origin: usize,
) -> Option<super::frontier::FrontierEntry> {
    let frontier_min_depth = frontier.peek_min_depth();
    if let Some((position, _)) = pending
        .iter()
        .enumerate()
        .filter(|(_, entry)| has_capacity(entry, in_flight, per_origin))
        .min_by_key(|(_, entry)| entry.depth)
        && frontier_min_depth.is_none_or(|d| pending[position].depth <= d)
    {
        return Some(pending.remove(position));
    }
    let mut blocked = Vec::new();
    let mut picked = None;
    while let Some(entry) = frontier.pop() {
        if has_capacity(&entry, in_flight, per_origin) {
            picked = Some(entry);
            break;
        }
        blocked.push(entry);
    }
    pending.extend(blocked);
    picked
}

/// Acquires one page and prepares everything derived from it.
async fn acquire_page(
    target: AuditTarget,
    depth: usize,
    remaining: std::time::Duration,
    schedule: PageSchedule,
    in_sitemap: bool,
    cache: Arc<collection::CrawlHttpCache>,
) -> PageOutcome {
    let exec_budget = schedule.exec_budget;
    let policy = schedule.policy;
    let max_depth = schedule.max_depth;
    let per_page_budget = ExecutionBudget {
        audit_timeout: exec_budget.audit_timeout.min(remaining),
        http_timeout: exec_budget.http_timeout.min(remaining),
        ..exec_budget
    };
    let snapshot = collection::collect_http_cached(&target, &per_page_budget, policy, &cache).await;
    outcome_from_snapshot(target, depth, max_depth, in_sitemap, policy, &snapshot)
}

fn outcome_from_snapshot(
    target: AuditTarget,
    depth: usize,
    max_depth: usize,
    in_sitemap: bool,
    policy: TargetPolicy,
    snapshot: &crate::domain::EvidenceSnapshot,
) -> PageOutcome {
    let http_status = match &snapshot.http {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            Some(data.status_code)
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    };

    let (
        status,
        final_target,
        page_type,
        links,
        graph_input,
        report,
        resources,
        external_resources,
    ) = match &snapshot.http {
        CollectorOutcome::Captured { data } => {
            let effective_target =
                AuditTarget::parse(&data.final_url, policy).unwrap_or_else(|_| target.clone());
            let same_origin_as_requested = super::Origin::from_target(&effective_target)
                == super::Origin::from_target(&target);
            let observations = DocumentObservations::from_html(&data.body_text);
            let page_type = classify_page(&effective_target, &observations);
            let graph_input =
                build_captured_graph_input(&target, data, &observations, depth, in_sitemap, policy);
            let links = if depth < max_depth && same_origin_as_requested {
                prioritise_representative_urls(discover_same_origin_links(
                    &effective_target,
                    &observations,
                    policy,
                ))
            } else {
                Vec::new()
            };
            // Resources are only inventoried from a complete body: a truncated document would
            // produce a partial resource list that must not be presented as the page's full set.
            let (page_resources, external_resources) =
                resources::discover_page_resources(&effective_target, &observations, policy);
            (
                PageCrawlStatus::Investigated,
                Some(effective_target),
                page_type,
                links,
                Some(graph_input),
                Some(crate::analysis::run_all(snapshot)),
                page_resources,
                external_resources,
            )
        }
        CollectorOutcome::Partial { data, .. } => {
            let effective_target =
                AuditTarget::parse(&data.final_url, policy).unwrap_or_else(|_| target.clone());
            let observations = DocumentObservations::from_html(&data.body_text);
            let page_type = classify_page(&effective_target, &observations);
            (
                PageCrawlStatus::PartiallyInvestigated,
                Some(effective_target),
                page_type,
                Vec::new(),
                Some(build_captured_graph_input(
                    &target,
                    data,
                    &observations,
                    depth,
                    in_sitemap,
                    policy,
                )),
                Some(crate::analysis::run_all(snapshot)),
                Vec::new(),
                0,
            )
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => (
            PageCrawlStatus::Unreachable,
            None,
            PageType::Unknown,
            Vec::new(),
            Some(unreachable_graph_input(&target, depth, in_sitemap)),
            None,
            Vec::new(),
            0,
        ),
    };

    PageOutcome {
        target,
        final_target,
        depth,
        status,
        page_type,
        links,
        graph_input,
        report,
        http_status,
        resources,
        external_resources,
    }
}

/// Maximum bytes read from any single subresource during reconnaissance.
const RESOURCE_BYTE_CAP: usize = 2 * 1024 * 1024;

/// Acquires one discovered resource under the crawl's budget and policy.
async fn acquire_resource(
    reference: ResourceRef,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
    cache: Arc<collection::CrawlHttpCache>,
) -> ResourceObservation {
    let cap = exec_budget.max_response_bytes.min(RESOURCE_BYTE_CAP);
    let fetch = collection::fetch_resource(
        &reference.url,
        policy,
        &cache,
        exec_budget.http_timeout,
        cap,
    )
    .await;
    ResourceObservation {
        url: reference.url.as_str().to_owned(),
        kind: reference.kind,
        status: if fetch.error.is_some() {
            ResourceStatus::Failed
        } else {
            ResourceStatus::Fetched
        },
        http_status: fetch.status_code,
        content_type: fetch.content_type,
        content_encoding: fetch.content_encoding,
        byte_len: fetch.byte_len,
        cache_control: fetch.cache_control,
        etag_present: Some(fetch.etag_present),
        last_modified_present: Some(fetch.last_modified_present),
        truncated: fetch.truncated,
        error: fetch.error,
    }
}

/// Acquires discovered resources with bounded concurrency, never beyond `remaining`.
///
/// Returns the observations, the number cancelled at the deadline and the number never scheduled
/// because the deadline expired first. Nothing is invented for a resource that was not acquired.
async fn acquire_resources(
    references: Vec<ResourceRef>,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
    remaining: std::time::Duration,
    global_limit: usize,
    cache: Arc<collection::CrawlHttpCache>,
) -> (Vec<ResourceObservation>, usize, usize) {
    let deadline = Instant::now() + remaining;
    let mut observations = Vec::new();
    let mut join: JoinSet<ResourceObservation> = JoinSet::new();
    let mut next = 0usize;

    while next < references.len() || !join.is_empty() {
        if Instant::now() >= deadline {
            break;
        }
        while next < references.len() && join.len() < global_limit && Instant::now() < deadline {
            let reference = references[next].clone();
            let cache = Arc::clone(&cache);
            join.spawn(
                async move { acquire_resource(reference, exec_budget, policy, cache).await },
            );
            next = next.saturating_add(1);
        }
        if join.is_empty() {
            break;
        }
        let Some(joined) = join.join_next().await else {
            break;
        };
        if let Ok(observation) = joined {
            observations.push(observation);
        }
    }

    let cancelled = join.len();
    if cancelled > 0 {
        join.abort_all();
        while join.join_next().await.is_some() {}
    }
    let unscheduled = references.len().saturating_sub(next);
    (observations, cancelled, unscheduled)
}

/// Performs a bounded, concurrent, same-origin crawl starting from `seed`.
#[allow(clippy::too_many_lines)] // The scheduler loop is one state machine; splitting it hides invariants.
pub(super) async fn crawl_concurrently(
    seed: AuditTarget,
    crawl_budget: CrawlBudget,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
    observer: super::CrawlObserver<'_>,
) -> CrawlSummary {
    let started = Instant::now();
    let global_limit = exec_budget.max_concurrency.max(1);
    let per_origin_limit = global_limit.clamp(1, MAX_PER_ORIGIN);
    let queue_bound = crawl_budget.max_pages.saturating_mul(4).clamp(32, 4096);

    let mut frontier = CrawlFrontier::new(queue_bound);
    let mut sitemap_urls: HashSet<String> = HashSet::new();

    // The exclusion file is consulted once per crawl, before any page is fetched. A failure to
    // retrieve it is recorded rather than assumed to mean "everything is allowed".
    let (robots_outcome, robots_rules) = robots::fetch_robots(&seed, &exec_budget, policy).await;
    let robots_rules = Arc::new(robots_rules);
    let cache = Arc::new(collection::CrawlHttpCache::new(global_limit.max(2)));

    let _ = frontier.enqueue(seed.clone(), 0, DiscoverySource::Seed);
    observer(super::CrawlProgressEvent::Discovered {
        url: seed.as_str().to_owned(),
        depth: 0,
        source: DiscoverySource::Seed,
    });
    if crawl_budget.max_depth > 0 && crawl_budget.max_pages > 1 {
        for url in
            seed_sitemap_urls_with_robots(&seed, robots_rules.sitemaps(), exec_budget, policy).await
        {
            sitemap_urls.insert(url.as_str().to_owned());
            if frontier.enqueue(url.clone(), 1, DiscoverySource::Sitemap)
                == EnqueueOutcome::Enqueued
            {
                observer(super::CrawlProgressEvent::Discovered {
                    url: url.as_str().to_owned(),
                    depth: 1,
                    source: DiscoverySource::Sitemap,
                });
            }
        }
    }

    let mut pages: Vec<DiscoveredPage> = Vec::new();
    let mut page_reports = Vec::new();
    let mut page_diagnostics: Vec<super::PageDiagnostics> = Vec::new();
    let mut graph_inputs = Vec::new();
    let mut in_flight: JoinSet<PageOutcome> = JoinSet::new();
    let mut in_flight_entries: HashMap<tokio::task::Id, super::frontier::FrontierEntry> =
        HashMap::new();
    let mut per_origin_in_flight: HashMap<String, usize> = HashMap::new();
    let mut pending: Vec<super::frontier::FrontierEntry> = Vec::new();
    let mut fetched = 0usize;
    let mut analysed_pages = 0usize;
    let mut failed_pages = 0usize;
    let mut cancelled = 0usize;
    let mut robots_blocked = 0usize;
    let mut resource_refs: HashMap<String, ResourceRef> = HashMap::new();
    let mut page_resources: Vec<resources::PageResourceEdge> = Vec::new();
    let mut external_resources = 0usize;
    let mut seen_final_urls: HashSet<String> = HashSet::new();
    let mut budget_exhausted = false;
    let mut deadline_reached = false;

    loop {
        if started.elapsed() >= crawl_budget.max_duration {
            deadline_reached = true;
        }

        // Fill the worker pool while budget and origin capacity allow.
        while !deadline_reached
            && in_flight.len() < global_limit
            && fetched < crawl_budget.max_pages
        {
            let Some(entry) = take_spawnable(
                &mut frontier,
                &mut pending,
                &per_origin_in_flight,
                per_origin_limit,
            ) else {
                break;
            };
            // Hard BFS layer barrier: never start depth d+1 while any depth d task is still
            // in flight, so shallower discoveries always win before deeper URLs are popped.
            if in_flight_entries
                .values()
                .map(|active| active.depth)
                .min()
                .is_some_and(|active_depth| entry.depth > active_depth)
            {
                pending.push(entry);
                break;
            }
            let remaining = crawl_budget.max_duration.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                deadline_reached = true;
                // Put the entry back so it is accounted for as skipped, not lost.
                pending.push(entry);
                break;
            }
            if !robots_rules.allows(&robots::path_and_query(&entry.target)) {
                robots_blocked = robots_blocked.saturating_add(1);
                continue;
            }
            let remaining = if fetched > 0
                && let Some(delay) = robots_rules.crawl_delay()
            {
                tokio::time::sleep(delay.min(remaining)).await;
                let left = crawl_budget.max_duration.saturating_sub(started.elapsed());
                if left.is_zero() {
                    deadline_reached = true;
                    pending.push(entry);
                    break;
                }
                left
            } else {
                remaining
            };
            let origin = origin_key(&entry.target);
            *per_origin_in_flight.entry(origin).or_insert(0) += 1;
            fetched = fetched.saturating_add(1);
            let in_sitemap = sitemap_urls.contains(entry.target.as_str());
            let schedule = PageSchedule {
                exec_budget,
                policy,
                max_depth: crawl_budget.max_depth,
            };
            let target_for_task = entry.target.clone();
            let depth_for_task = entry.depth;
            let cache = Arc::clone(&cache);
            let handle = in_flight.spawn(async move {
                acquire_page(
                    target_for_task,
                    depth_for_task,
                    remaining,
                    schedule,
                    in_sitemap,
                    cache,
                )
                .await
            });
            in_flight_entries.insert(handle.id(), entry);
        }

        if in_flight.is_empty() {
            break;
        }

        if deadline_reached {
            // No acquisition may outlive the crawl deadline. Aborting the tasks drops the
            // adapter guards, which terminate any child process group.
            cancelled = cancelled.saturating_add(in_flight.len());
            in_flight.abort_all();
            while in_flight.join_next().await.is_some() {}
            for (_, entry) in in_flight_entries.drain() {
                pages.push(DiscoveredPage {
                    url: entry.target,
                    page_type: PageType::Unknown,
                    depth: entry.depth,
                    status: PageCrawlStatus::SkippedBudget,
                });
            }
            break;
        }

        let Some(joined) = in_flight.join_next_with_id().await else {
            break;
        };
        let outcome = match joined {
            Ok((id, outcome)) => {
                in_flight_entries.remove(&id);
                outcome
            }
            Err(join_err) => {
                if let Some(entry) = in_flight_entries.remove(&join_err.id()) {
                    if let Some(count) = per_origin_in_flight.get_mut(&origin_key(&entry.target)) {
                        *count = count.saturating_sub(1);
                    }
                    failed_pages = failed_pages.saturating_add(1);
                    pages.push(DiscoveredPage {
                        url: entry.target,
                        page_type: PageType::Unknown,
                        depth: entry.depth,
                        status: PageCrawlStatus::Unreachable,
                    });
                }
                continue;
            }
        };

        if let Some(count) = per_origin_in_flight.get_mut(&origin_key(&outcome.target)) {
            *count = count.saturating_sub(1);
        }

        let is_duplicate_final = outcome.final_target.as_ref().is_some_and(|final_target| {
            frontier.mark_seen(final_target);
            !seen_final_urls.insert(final_target.as_str().to_owned())
        });

        if is_duplicate_final {
            page_diagnostics.push(super::PageDiagnostics::from_report(
                outcome.target.as_str(),
                outcome.http_status,
                outcome.page_type,
                outcome.status,
                None,
            ));
        } else {
            for link in outcome.links {
                match frontier.enqueue(link.clone(), outcome.depth + 1, DiscoverySource::Link) {
                    EnqueueOutcome::QueueFull => budget_exhausted = true,
                    EnqueueOutcome::Enqueued => {
                        observer(super::CrawlProgressEvent::Discovered {
                            url: link.as_str().to_owned(),
                            depth: outcome.depth + 1,
                            source: DiscoverySource::Link,
                        });
                    }
                    EnqueueOutcome::Duplicate => {}
                }
            }

            for reference in outcome.resources {
                page_resources.push(resources::PageResourceEdge {
                    page_url: outcome.target.as_str().to_owned(),
                    resource_url: reference.url.as_str().to_owned(),
                    kind: reference.kind,
                });
                resource_refs
                    .entry(reference.url.as_str().to_owned())
                    .or_insert(reference);
            }
            external_resources = external_resources.saturating_add(outcome.external_resources);
            if let Some(input) = outcome.graph_input {
                graph_inputs.push(input);
            }
            if let Some(report) = outcome.report {
                page_diagnostics.push(super::PageDiagnostics::from_report(
                    outcome.target.as_str(),
                    outcome.http_status,
                    outcome.page_type,
                    outcome.status,
                    Some(&report),
                ));
                let report_target = outcome
                    .final_target
                    .unwrap_or_else(|| outcome.target.clone());
                page_reports.push((report_target, outcome.page_type, report));
            } else {
                page_diagnostics.push(super::PageDiagnostics::from_report(
                    outcome.target.as_str(),
                    outcome.http_status,
                    outcome.page_type,
                    outcome.status,
                    None,
                ));
            }
        }
        let completed_url = outcome.target.as_str().to_owned();
        let completed_status = outcome.status;
        if matches!(
            completed_status,
            PageCrawlStatus::Investigated | PageCrawlStatus::PartiallyInvestigated
        ) {
            analysed_pages = analysed_pages.saturating_add(1);
        } else if completed_status == PageCrawlStatus::Unreachable {
            failed_pages = failed_pages.saturating_add(1);
        }
        pages.push(DiscoveredPage {
            url: outcome.target,
            page_type: outcome.page_type,
            depth: outcome.depth,
            status: completed_status,
        });
        observer(super::CrawlProgressEvent::PageCompleted {
            url: completed_url,
            status: completed_status,
            completed_pages: pages.len(),
            analysed_pages,
            failed_pages,
        });
    }

    // Anything still queued was not acquired. Record it explicitly instead of dropping it.
    while let Some(entry) = frontier.pop() {
        budget_exhausted = true;
        pages.push(DiscoveredPage {
            url: entry.target,
            page_type: PageType::Unknown,
            depth: entry.depth,
            status: PageCrawlStatus::SkippedBudget,
        });
    }
    for entry in pending {
        budget_exhausted = true;
        pages.push(DiscoveredPage {
            url: entry.target,
            page_type: PageType::Unknown,
            depth: entry.depth,
            status: PageCrawlStatus::SkippedBudget,
        });
    }

    pages.sort_by(|left, right| left.url.as_str().cmp(right.url.as_str()));
    page_reports.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));

    let failed_urls = pages
        .iter()
        .filter(|page| page.status == PageCrawlStatus::Unreachable)
        .count();
    let analysed_urls = pages
        .iter()
        .filter(|page| {
            matches!(
                page.status,
                PageCrawlStatus::Investigated | PageCrawlStatus::PartiallyInvestigated
            )
        })
        .count();
    let skipped_budget_urls = pages
        .iter()
        .filter(|page| page.status == PageCrawlStatus::SkippedBudget)
        .count();
    let complete = !budget_exhausted && !deadline_reached && cancelled == 0;

    // Shared resources are acquired once per crawl, after the page population is known, so a
    // stylesheet referenced by every page costs one request rather than one per page.
    let mut queued_resources: Vec<ResourceRef> = resource_refs.into_values().collect();
    queued_resources.sort_by(|left, right| left.url.as_str().cmp(right.url.as_str()));
    let discovered_resources = queued_resources.len();
    let max_resources = crawl_budget.max_pages.saturating_mul(8).clamp(32, 1024);
    queued_resources.truncate(max_resources);
    let skipped_by_bound = discovered_resources.saturating_sub(queued_resources.len());

    let remaining_for_resources = crawl_budget.max_duration.saturating_sub(started.elapsed());
    let (mut resource_observations, resource_cancelled, resource_unscheduled) =
        if remaining_for_resources.is_zero() || queued_resources.is_empty() {
            (Vec::new(), 0, queued_resources.len())
        } else {
            acquire_resources(
                queued_resources,
                exec_budget,
                policy,
                remaining_for_resources,
                global_limit,
                Arc::clone(&cache),
            )
            .await
        };
    resource_observations.sort_by(|left, right| left.url.cmp(&right.url));
    let fetched_resources = resource_observations
        .iter()
        .filter(|observation| observation.status == ResourceStatus::Fetched)
        .count();
    let failed_resources = resource_observations
        .iter()
        .filter(|observation| observation.status == ResourceStatus::Failed)
        .count();
    let truncated_resources = resource_observations
        .iter()
        .filter(|observation| observation.truncated)
        .count();
    let resource_coverage = ResourceCoverage {
        discovered_resources,
        fetched_resources,
        failed_resources,
        skipped_resources: skipped_by_bound.saturating_add(resource_unscheduled),
        cancelled_resources: resource_cancelled,
        truncated_resources,
        external_refused: external_resources,
        max_resources,
    };

    let coverage = CrawlCoverage {
        discovered_urls: pages.len().saturating_add(robots_blocked),
        fetched_urls: analysed_urls.saturating_add(failed_urls),
        analysed_urls,
        failed_urls,
        skipped_budget_urls,
        cancelled_urls: cancelled,
        robots_blocked_urls: robots_blocked,
        reused_evidence_urls: 0,
        unknown_urls: pages
            .iter()
            .filter(|page| page.status == PageCrawlStatus::Unknown)
            .count(),
        robots: robots_outcome,
        queue_rejections: frontier.queue_full_count(),
        duplicate_offers: frontier.duplicate_count(),
        max_pages: crawl_budget.max_pages,
        max_depth: crawl_budget.max_depth,
        complete,
        resources: resource_coverage,
    };

    page_resources.sort();
    page_resources.dedup();

    page_diagnostics.sort_by(|left, right| left.url.cmp(&right.url));
    let mut systemic_issues = cluster_systemic_issues(&page_reports);
    systemic_issues.extend(super::cluster_failed_resource_dependencies(
        &resource_observations,
        &page_resources,
        &pages,
    ));
    let graph = ApplicationGraph::from_pages(&graph_inputs, complete);
    let graph_results = crate::analysis::graph::analyse(&graph);
    let analysis_totals = aggregate_analysis_totals_with_graph(&page_reports, &graph_results);

    CrawlSummary {
        seed,
        pages,
        systemic_issues,
        budget_exhausted,
        graph_results,
        coverage,
        resources: resource_observations,
        page_resources,
        analysis_totals,
        page_diagnostics,
    }
}

/// Runs headless browser collection on up to `sample_limit` investigated pages
/// from `summary`, prioritising distinct [`PageType`] templates, and merges
/// runtime and functional findings into `summary`.
pub async fn sample_browser_on_crawl(
    summary: &mut CrawlSummary,
    sample_limit: usize,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
) {
    if sample_limit == 0 {
        return;
    }

    let selected = select_browser_sample_pages(&summary.pages, sample_limit);
    let started = Instant::now();
    let mut browser_reports: Vec<(AuditTarget, PageType, AuditReport)> = Vec::new();

    for page in selected {
        let remaining = exec_budget.audit_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        let outcome = crate::adapters::browser::run_browser_with_policy(
            &page.url,
            remaining.min(std::time::Duration::from_secs(25)),
            policy,
        )
        .await;
        let snapshot = crate::domain::EvidenceSnapshot {
            target: page.url.clone(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Skipped {
                reason: "already acquired during crawl".to_owned(),
            },
            tls: CollectorOutcome::Skipped {
                reason: "not collected in browser sample pass".to_owned(),
            },
            browser: outcome,
            lighthouse: CollectorOutcome::Skipped {
                reason: "not collected in browser sample pass".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "not collected in browser sample pass".to_owned(),
            },
        };
        let browser_res = crate::analysis::browser::analyse(&snapshot);
        let func_res = crate::analysis::journeys::analyse_functional_behaviour(&snapshot);
        let merged = merge_browser_analyser_results(&page.url, browser_res, func_res);
        merge_into_crawl_summary(summary, &page.url, &merged);
        browser_reports.push((
            page.url.clone(),
            page.page_type,
            AuditReport {
                schema_version: crate::analysis::REPORT_SCHEMA_VERSION.to_owned(),
                target: page.url,
                captured_at_unix_secs: 0,
                http: snapshot.http,
                level2_collectors: Vec::new(),
                analysers: vec![merged],
                summary: crate::analysis::AuditSummary::default(),
                rendered_history: None,
                ai_synthesis: None,
            },
        ));
    }

    if browser_reports.len() >= 2 {
        summary
            .systemic_issues
            .extend(cluster_systemic_issues(&browser_reports));
    }
}

fn select_browser_sample_pages(pages: &[DiscoveredPage], limit: usize) -> Vec<DiscoveredPage> {
    let eligible: Vec<&DiscoveredPage> = pages
        .iter()
        .filter(|p| {
            matches!(
                p.status,
                PageCrawlStatus::Investigated | PageCrawlStatus::PartiallyInvestigated
            )
        })
        .collect();
    let mut selected = Vec::new();
    let mut seen_types = HashSet::new();
    for page in &eligible {
        if selected.len() >= limit {
            break;
        }
        if seen_types.insert(page.page_type) {
            selected.push((*page).clone());
        }
    }
    for page in eligible {
        if selected.len() >= limit {
            break;
        }
        if !selected.iter().any(|s| s.url == page.url) {
            selected.push(page.clone());
        }
    }
    selected
}

fn merge_browser_analyser_results(
    _url: &AuditTarget,
    mut a: crate::domain::AnalyserResult,
    b: crate::domain::AnalyserResult,
) -> crate::domain::AnalyserResult {
    a.findings.extend(b.findings);
    a.checks.extend(b.checks);
    a
}

fn merge_into_crawl_summary(
    summary: &mut CrawlSummary,
    url: &AuditTarget,
    res: &crate::domain::AnalyserResult,
) {
    let (mut passed, mut failed, mut skipped, mut unavailable) = (0usize, 0usize, 0usize, 0usize);
    for check in &res.checks {
        match check {
            crate::domain::CheckStatus::Passed { .. } => passed += 1,
            crate::domain::CheckStatus::Failed { .. } => failed += 1,
            crate::domain::CheckStatus::Skipped { .. } => skipped += 1,
            crate::domain::CheckStatus::Unavailable { .. } => unavailable += 1,
        }
    }
    if let Some(diag) = summary
        .page_diagnostics
        .iter_mut()
        .find(|d| d.url == url.as_str())
    {
        diag.checks_passed = diag.checks_passed.saturating_add(passed);
        diag.checks_failed = diag.checks_failed.saturating_add(failed);
        diag.checks_skipped = diag.checks_skipped.saturating_add(skipped);
        diag.checks_unavailable = diag.checks_unavailable.saturating_add(unavailable);
        for f in &res.findings {
            diag.findings.push(super::PageFinding {
                rule_id: f.rule_id.clone(),
                dwarf_id: res.dwarf_id,
                severity: f.severity,
                confidence: f.confidence,
                title: f.title.clone(),
                summary: f.summary.clone(),
                remediation: f.remediation.clone(),
                evidence_refs: f.evidence_refs.clone(),
            });
        }
    }
    if let Some(total) = summary
        .analysis_totals
        .iter_mut()
        .find(|t| t.dwarf_id == res.dwarf_id)
    {
        total.checks_evaluated = total.checks_evaluated.saturating_add(passed + failed);
        total.checks_passed = total.checks_passed.saturating_add(passed);
        total.checks_failed = total.checks_failed.saturating_add(failed);
        total.checks_skipped = total.checks_skipped.saturating_add(skipped);
        total.checks_unavailable = total.checks_unavailable.saturating_add(unavailable);
        total.findings_count = total.findings_count.saturating_add(res.findings.len());
    } else {
        summary.analysis_totals.push(super::DwarfAnalysisTotal {
            dwarf_id: res.dwarf_id,
            checks_evaluated: passed + failed,
            checks_passed: passed,
            checks_failed: failed,
            checks_skipped: skipped,
            checks_unavailable: unavailable,
            findings_count: res.findings.len(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::discovery::RobotsOutcome;
    use crate::domain::TargetPolicy;

    struct Fixture {
        addr: std::net::SocketAddr,
        max_concurrent: Arc<AtomicUsize>,
        requested_paths: Arc<std::sync::Mutex<Vec<String>>>,
    }

    async fn spawn_fixture() -> Fixture {
        spawn_fixture_with_robots(None).await
    }

    async fn spawn_fixture_with_robots(robots: Option<String>) -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let current = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let requested_paths = Arc::new(std::sync::Mutex::new(Vec::new()));

        let current_task = Arc::clone(&current);
        let max_task = Arc::clone(&max_concurrent);
        let paths_task = Arc::clone(&requested_paths);
        let robots = Arc::new(robots);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let current = Arc::clone(&current_task);
                let max_seen = Arc::clone(&max_task);
                let paths = Arc::clone(&paths_task);
                let robots = Arc::clone(&robots);
                tokio::spawn(async move {
                    let live = current.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(live, Ordering::SeqCst);
                    let mut buffer = [0_u8; 2048];
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    if let Ok(mut seen) = paths.lock() {
                        seen.push(path.clone());
                    }
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    let body = if path == "/" {
                        "<html><head><title>Seed</title>\
                         <link rel=\"stylesheet\" href=\"/shared.css\">\
                         <script src=\"/app.js\"></script></head><body>\
                         <a href=\"/a\">A</a><a href=\"/a\">A again</a>\
                         <a href=\"/b\">B</a><a href=\"/c\">C</a>\
                         <img src=\"/logo.png\" alt=\"Logo\"></body></html>"
                            .to_owned()
                    } else if path == "/a" {
                        // Deliberately references the same stylesheet as the seed page.
                        "<html><head><title>A</title>\
                         <link rel=\"stylesheet\" href=\"/shared.css\"></head>\
                         <body><a href=\"/\">Home</a></body></html>"
                            .to_owned()
                    } else if path == "/shared.css" {
                        "body { color: #111; }".to_owned()
                    } else if path == "/app.js" {
                        "window.__nzwFixture = true;".to_owned()
                    } else if path == "/logo.png" {
                        "not-really-a-png-but-eight-bytes".to_owned()
                    } else if path == "/sitemap.xml" {
                        String::new()
                    } else if path == "/robots.txt" {
                        robots.as_deref().unwrap_or_default().to_owned()
                    } else {
                        format!("<html><head><title>{path}</title></head><body>ok</body></html>")
                    };
                    let status = if body.is_empty() {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let content_type = if path.eq_ignore_ascii_case("/shared.css") {
                        "text/css"
                    } else if path.eq_ignore_ascii_case("/app.js") {
                        "application/javascript"
                    } else if path.eq_ignore_ascii_case("/logo.png") {
                        "image/png"
                    } else {
                        "text/html"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: max-age=600\r\nETag: \"fixture\"\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                    current.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        Fixture {
            addr,
            max_concurrent,
            requested_paths,
        }
    }

    #[tokio::test]
    async fn concurrent_crawl_fetches_each_url_once_and_accounts_for_coverage() {
        let fixture = spawn_fixture().await;
        let seed = AuditTarget::parse(
            &format!("http://{}/", fixture.addr),
            TargetPolicy::AllowPrivate,
        )
        .unwrap();
        let summary = crawl_concurrently(
            seed,
            CrawlBudget {
                max_pages: 8,
                max_depth: 1,
                max_duration: Duration::from_secs(20),
            },
            ExecutionBudget {
                max_concurrency: 4,
                ..ExecutionBudget::default()
            },
            TargetPolicy::AllowPrivate,
            &|_event| {},
        )
        .await;

        let investigated = summary
            .pages
            .iter()
            .filter(|page| page.status == PageCrawlStatus::Investigated)
            .count();
        assert_eq!(investigated, 4, "seed plus three linked pages");
        assert_eq!(summary.coverage.discovered_urls, 4);
        assert_eq!(summary.coverage.analysed_urls, 4);
        assert_eq!(summary.coverage.failed_urls, 0);
        assert!(summary.coverage.complete);
        assert!(!summary.budget_exhausted);

        // `/a` is linked twice. Link extraction deduplicates within a page, so the repeated href
        // never reaches the frontier; the page count proves it was acquired once.
        assert_eq!(
            summary
                .pages
                .iter()
                .filter(|page| page.url.as_str().ends_with("/a"))
                .count(),
            1
        );

        // Deterministic ordering regardless of completion order.
        let urls: Vec<&str> = summary.pages.iter().map(|page| page.url.as_str()).collect();
        let mut sorted = urls.clone();
        sorted.sort_unstable();
        assert_eq!(urls, sorted);

        // Proof that acquisition overlapped rather than running strictly sequentially.
        let peak = fixture.max_concurrent.load(Ordering::SeqCst);
        assert!(
            peak >= 2,
            "expected concurrent acquisitions, observed peak {peak}"
        );
    }

    #[tokio::test]
    async fn progress_observer_reports_discovery_and_completion_while_crawling() {
        use std::sync::Mutex;

        let fixture = spawn_fixture().await;
        let seed = AuditTarget::parse(
            &format!("http://{}/", fixture.addr),
            TargetPolicy::AllowPrivate,
        )
        .unwrap();
        let events = Mutex::new(Vec::new());
        let summary = crawl_concurrently(
            seed,
            CrawlBudget {
                max_pages: 8,
                max_depth: 1,
                max_duration: Duration::from_secs(20),
            },
            ExecutionBudget {
                max_concurrency: 4,
                ..ExecutionBudget::default()
            },
            TargetPolicy::AllowPrivate,
            &|event| {
                if let Ok(mut seen) = events.lock() {
                    seen.push(event);
                }
            },
        )
        .await;

        let observed = events.into_inner().unwrap_or_default();
        let discovered = observed
            .iter()
            .filter(|event| matches!(event, super::super::CrawlProgressEvent::Discovered { .. }))
            .count();
        let completed: Vec<(usize, usize)> = observed
            .iter()
            .filter_map(|event| match event {
                super::super::CrawlProgressEvent::PageCompleted {
                    completed_pages,
                    analysed_pages,
                    ..
                } => Some((*completed_pages, *analysed_pages)),
                super::super::CrawlProgressEvent::Discovered { .. } => None,
            })
            .collect();

        assert_eq!(
            discovered, summary.coverage.discovered_urls,
            "every discovered URL is reported once"
        );
        assert_eq!(
            completed.len(),
            summary.pages.len(),
            "every page that reached a final status is reported"
        );
        assert_eq!(
            completed.iter().map(|(done, _)| *done).max(),
            Some(summary.pages.len()),
            "the last report accounts for the whole population"
        );
        assert!(
            completed.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "completed counts advance monotonically"
        );
    }

    #[tokio::test]
    async fn shared_resources_are_acquired_once_and_reported() {
        let fixture = spawn_fixture().await;
        let seed = AuditTarget::parse(
            &format!("http://{}/", fixture.addr),
            TargetPolicy::AllowPrivate,
        )
        .unwrap();
        let summary = crawl_concurrently(
            seed,
            CrawlBudget {
                max_pages: 8,
                max_depth: 1,
                max_duration: Duration::from_secs(20),
            },
            ExecutionBudget {
                max_concurrency: 4,
                ..ExecutionBudget::default()
            },
            TargetPolicy::AllowPrivate,
            &|_event| {},
        )
        .await;

        // Three distinct resources were referenced; `/shared.css` by two different pages.
        assert_eq!(summary.coverage.resources.discovered_resources, 3);
        assert_eq!(summary.coverage.resources.fetched_resources, 3);
        assert_eq!(summary.coverage.resources.failed_resources, 0);
        assert_eq!(summary.coverage.resources.skipped_resources, 0);
        assert_eq!(summary.resources.len(), 3);

        let css_requests = fixture
            .requested_paths
            .lock()
            .unwrap()
            .iter()
            .filter(|path| path.as_str() == "/shared.css")
            .count();
        assert_eq!(
            css_requests, 1,
            "a resource shared by two pages must be acquired once per crawl"
        );

        let css = summary
            .resources
            .iter()
            .find(|resource| resource.url.ends_with("/shared.css"))
            .expect("stylesheet observation");
        assert_eq!(css.kind, crate::discovery::ResourceKind::Stylesheet);
        assert_eq!(css.status, ResourceStatus::Fetched);
        assert_eq!(css.http_status, Some(200));
        assert_eq!(css.content_type.as_deref(), Some("text/css"));
        assert_eq!(css.byte_len, Some(21));
        assert_eq!(css.etag_present, Some(true));
        assert!(!css.truncated);

        // Observations are ordered by URL, so the report is stable across runs.
        let urls: Vec<&str> = summary
            .resources
            .iter()
            .map(|resource| resource.url.as_str())
            .collect();
        let mut sorted = urls.clone();
        sorted.sort_unstable();
        assert_eq!(urls, sorted);

        // The shared stylesheet is referenced from the seed and from `/a`, so the edge table must
        // record two dependents rather than one reference per acquisition.
        let dependents: Vec<&str> = summary
            .page_resources
            .iter()
            .filter(|edge| edge.resource_url.ends_with("/shared.css"))
            .map(|edge| edge.page_url.as_str())
            .collect();
        assert_eq!(dependents.len(), 2);
        assert!(dependents.iter().any(|page| page.ends_with("/a")));
    }

    #[tokio::test]
    async fn robots_disallow_prevents_acquisition_and_is_accounted_for() {
        let fixture =
            spawn_fixture_with_robots(Some("User-agent: *\nDisallow: /b\n".to_owned())).await;
        let target = |path: &str| {
            AuditTarget::parse(
                &format!("http://{}{path}", fixture.addr),
                TargetPolicy::AllowPrivate,
            )
            .unwrap()
        };
        let summary = crawl_concurrently(
            target("/"),
            CrawlBudget {
                max_pages: 8,
                max_depth: 1,
                max_duration: Duration::from_secs(20),
            },
            ExecutionBudget {
                max_concurrency: 4,
                ..ExecutionBudget::default()
            },
            TargetPolicy::AllowPrivate,
            &|_event| {},
        )
        .await;

        assert_eq!(summary.coverage.robots, RobotsOutcome::Observed);
        assert_eq!(summary.coverage.robots_blocked_urls, 1);
        assert_eq!(
            summary
                .pages
                .iter()
                .filter(|page| page.status == PageCrawlStatus::Investigated)
                .count(),
            3,
            "the seed and the two permitted links"
        );

        // The disallowed URL must never reach the origin.
        let requested = fixture.requested_paths.lock().unwrap().clone();
        assert!(
            !requested.iter().any(|path| path == "/b"),
            "robots-disallowed path was fetched: {requested:?}"
        );
    }

    #[tokio::test]
    async fn redirected_page_resolves_relative_links_against_final_url_and_deduplicates() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requested_paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let paths_clone = Arc::clone(&requested_paths);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                let paths = Arc::clone(&paths_clone);
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    paths.lock().unwrap().push(path.clone());

                    let response = match path.as_str() {
                        "/" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><a href=\"/old\">old</a><a href=\"/old-two\">old2</a></body></html>".to_owned(),
                        "/old" | "/old-two" => "HTTP/1.1 301 Moved Permanently\r\nLocation: /new/dir/\r\nConnection: close\r\n\r\n".to_owned(),
                        "/new/dir/" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><a href=\"rel-child\">child</a></body></html>".to_owned(),
                        "/new/dir/rel-child" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body>child page</body></html>".to_owned(),
                        _ => "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nnot found".to_owned(),
                    };
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let seed =
            AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
        let summary = crawl_concurrently(
            seed,
            CrawlBudget {
                max_pages: 10,
                max_depth: 3,
                max_duration: Duration::from_secs(10),
            },
            ExecutionBudget {
                max_concurrency: 2,
                ..ExecutionBudget::default()
            },
            TargetPolicy::AllowPrivate,
            &|_event| {},
        )
        .await;

        let paths = requested_paths.lock().unwrap().clone();
        assert!(
            paths.iter().any(|p| p == "/new/dir/rel-child"),
            "expected relative link to resolve against final_url /new/dir/, got paths: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p == "/rel-child"),
            "relative link resolved against pre-redirect URL /old instead of /new/dir/: {paths:?}"
        );
        let analysed_redirects = summary
            .page_diagnostics
            .iter()
            .filter(|d| {
                (d.url.ends_with("/old") || d.url.ends_with("/old-two"))
                    && (d.checks_failed > 0 || d.checks_passed > 0)
            })
            .count();
        assert_eq!(
            analysed_redirects, 1,
            "expected /new/dir/ to be analysed only once across /old and /old-two redirects"
        );
    }

    #[tokio::test]
    async fn bfs_layer_barrier_keeps_depths_deterministic_when_seed_is_slower_than_sitemap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    let Ok(n) = sock.read(&mut buf).await else {
                        return;
                    };
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();

                    if path == "/" {
                        tokio::time::sleep(Duration::from_millis(35)).await;
                    }

                    let response = match path.as_str() {
                        "/sitemap.xml" => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nConnection: close\r\n\r\n<urlset><url><loc>http://{addr}/map</loc></url></urlset>"
                        ),
                        "/" | "/map" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><a href=\"/shared\">shared</a></body></html>".to_owned(),
                        "/shared" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><a href=\"/shared/leaf\">leaf</a></body></html>".to_owned(),
                        "/shared/leaf" => "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body>leaf</body></html>".to_owned(),
                        _ => "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nnot found".to_owned(),
                    };
                    let _ = sock.write_all(response.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let seed =
            AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
        for _ in 0..3 {
            let summary = crawl_concurrently(
                seed.clone(),
                CrawlBudget {
                    max_pages: 10,
                    max_depth: 2,
                    max_duration: Duration::from_secs(10),
                },
                ExecutionBudget {
                    max_concurrency: 4,
                    ..ExecutionBudget::default()
                },
                TargetPolicy::AllowPrivate,
                &|_event| {},
            )
            .await;

            let shared = summary
                .pages
                .iter()
                .find(|p| p.url.as_str().ends_with("/shared"))
                .expect("/shared should be discovered");
            assert_eq!(
                shared.depth, 1,
                "seed must assign /shared depth 1 before depth-2 tasks run"
            );
            assert!(
                summary
                    .pages
                    .iter()
                    .any(|p| p.url.as_str().ends_with("/shared/leaf")),
                "/shared/leaf at depth 2 must always be discovered"
            );
        }
    }
}
