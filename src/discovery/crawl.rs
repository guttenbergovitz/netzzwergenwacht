//! Concurrent, bounded application crawl.
//!
//! Acquisition is scheduled rather than looped: a bounded number of worker tasks consume from a
//! deduplicating frontier, and every task obeys the caller's [`ExecutionBudget`] and
//! [`TargetPolicy`]. The scheduling contract is recorded in ADR 0027.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use tokio::task::JoinSet;
use url::Url;

use super::frontier::{CrawlFrontier, DiscoverySource, EnqueueOutcome};
use super::{
    CrawlBudget, CrawlCoverage, CrawlSummary, DiscoveredPage, PageCrawlStatus, PageType,
    build_captured_graph_input, classify_page, cluster_systemic_issues, discover_same_origin_links,
    prioritise_representative_urls, seed_sitemap_urls, unreachable_graph_input,
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
    depth: usize,
    status: PageCrawlStatus,
    page_type: PageType,
    links: Vec<AuditTarget>,
    graph_input: Option<GraphPageInput>,
    report: Option<AuditReport>,
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
    if let Some(position) = pending
        .iter()
        .position(|entry| has_capacity(entry, in_flight, per_origin))
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
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
    in_sitemap: bool,
    max_depth: usize,
) -> PageOutcome {
    let per_page_budget = ExecutionBudget {
        audit_timeout: exec_budget.audit_timeout.min(remaining),
        http_timeout: exec_budget.http_timeout.min(remaining),
        ..exec_budget
    };
    let snapshot = collection::collect_http(&target, &per_page_budget, policy).await;

    let (status, page_type, links, graph_input, report) = match &snapshot.http {
        CollectorOutcome::Captured { data } => {
            let observations = DocumentObservations::from_html(&data.body_text);
            let page_type = classify_page(&target, &observations);
            let graph_input =
                build_captured_graph_input(&target, data, &observations, depth, in_sitemap, policy);
            let links = if depth < max_depth {
                prioritise_representative_urls(discover_same_origin_links(
                    &target,
                    &observations,
                    policy,
                ))
            } else {
                Vec::new()
            };
            (
                PageCrawlStatus::Investigated,
                page_type,
                links,
                Some(graph_input),
                Some(crate::analysis::run_all(&snapshot)),
            )
        }
        CollectorOutcome::Partial { data, .. } => {
            let observations = DocumentObservations::from_html(&data.body_text);
            let page_type = classify_page(&target, &observations);
            (
                PageCrawlStatus::PartiallyInvestigated,
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
                Some(crate::analysis::run_all(&snapshot)),
            )
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => (
            PageCrawlStatus::Unreachable,
            PageType::Unknown,
            Vec::new(),
            Some(unreachable_graph_input(&target, depth, in_sitemap)),
            None,
        ),
    };

    PageOutcome {
        target,
        depth,
        status,
        page_type,
        links,
        graph_input,
        report,
    }
}

/// Performs a bounded, concurrent, same-origin crawl starting from `seed`.
#[allow(clippy::too_many_lines)] // The scheduler loop is one state machine; splitting it hides invariants.
pub(super) async fn crawl_concurrently(
    seed: AuditTarget,
    crawl_budget: CrawlBudget,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
) -> CrawlSummary {
    let started = Instant::now();
    let global_limit = exec_budget.max_concurrency.max(1);
    let per_origin_limit = global_limit.clamp(1, MAX_PER_ORIGIN);
    let queue_bound = crawl_budget.max_pages.saturating_mul(4).clamp(32, 4096);

    let mut frontier = CrawlFrontier::new(queue_bound);
    let mut sitemap_urls: HashSet<String> = HashSet::new();

    let _ = frontier.enqueue(seed.clone(), 0, DiscoverySource::Seed);
    if crawl_budget.max_depth > 0 && crawl_budget.max_pages > 1 {
        for url in seed_sitemap_urls(&seed, exec_budget, policy).await {
            sitemap_urls.insert(url.as_str().to_owned());
            let _ = frontier.enqueue(url, 1, DiscoverySource::Sitemap);
        }
    }

    let mut pages: Vec<DiscoveredPage> = Vec::new();
    let mut page_reports = Vec::new();
    let mut graph_inputs = Vec::new();
    let mut in_flight: JoinSet<PageOutcome> = JoinSet::new();
    let mut per_origin_in_flight: HashMap<String, usize> = HashMap::new();
    let mut pending: Vec<super::frontier::FrontierEntry> = Vec::new();
    let mut fetched = 0usize;
    let mut cancelled = 0usize;
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
            let remaining = crawl_budget.max_duration.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                deadline_reached = true;
                // Put the entry back so it is accounted for as skipped, not lost.
                pending.push(entry);
                break;
            }
            let origin = origin_key(&entry.target);
            *per_origin_in_flight.entry(origin).or_insert(0) += 1;
            fetched = fetched.saturating_add(1);
            let in_sitemap = sitemap_urls.contains(entry.target.as_str());
            let budget = exec_budget;
            let max_depth = crawl_budget.max_depth;
            in_flight.spawn(async move {
                acquire_page(
                    entry.target,
                    entry.depth,
                    remaining,
                    budget,
                    policy,
                    in_sitemap,
                    max_depth,
                )
                .await
            });
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
            break;
        }

        let Some(joined) = in_flight.join_next().await else {
            break;
        };
        let Ok(outcome) = joined else {
            // A panicked or aborted worker leaves the frontier consistent but unaccounted;
            // the process budget is what protects the run, so record nothing fabricated.
            continue;
        };

        if let Some(count) = per_origin_in_flight.get_mut(&origin_key(&outcome.target)) {
            *count = count.saturating_sub(1);
        }

        for link in outcome.links {
            match frontier.enqueue(link, outcome.depth + 1, DiscoverySource::Link) {
                EnqueueOutcome::QueueFull => budget_exhausted = true,
                EnqueueOutcome::Enqueued | EnqueueOutcome::Duplicate => {}
            }
        }

        if let Some(input) = outcome.graph_input {
            graph_inputs.push(input);
        }
        if let Some(report) = outcome.report {
            page_reports.push((outcome.target.clone(), outcome.page_type, report));
        }
        pages.push(DiscoveredPage {
            url: outcome.target,
            page_type: outcome.page_type,
            depth: outcome.depth,
            status: outcome.status,
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

    let coverage = CrawlCoverage {
        discovered_urls: pages.len(),
        fetched_urls: fetched,
        analysed_urls,
        failed_urls,
        skipped_budget_urls,
        cancelled_urls: cancelled,
        queue_rejections: frontier.queue_full_count(),
        duplicate_offers: frontier.duplicate_count(),
        max_pages: crawl_budget.max_pages,
        max_depth: crawl_budget.max_depth,
        complete,
    };

    let systemic_issues = cluster_systemic_issues(&page_reports);
    let graph = ApplicationGraph::from_pages(&graph_inputs, complete);
    let graph_results = crate::analysis::graph::analyse(&graph);

    CrawlSummary {
        seed,
        pages,
        systemic_issues,
        budget_exhausted,
        graph_results,
        coverage,
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
    use crate::domain::TargetPolicy;

    struct Fixture {
        addr: std::net::SocketAddr,
        max_concurrent: Arc<AtomicUsize>,
    }

    async fn spawn_fixture() -> Fixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let current = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let current_task = Arc::clone(&current);
        let max_task = Arc::clone(&max_concurrent);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let current = Arc::clone(&current_task);
                let max_seen = Arc::clone(&max_task);
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
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    let body = if path == "/" {
                        "<html><head><title>Seed</title></head><body>\
                         <a href=\"/a\">A</a><a href=\"/a\">A again</a>\
                         <a href=\"/b\">B</a><a href=\"/c\">C</a></body></html>"
                            .to_owned()
                    } else if path == "/sitemap.xml" || path == "/robots.txt" {
                        String::new()
                    } else {
                        format!("<html><head><title>{path}</title></head><body>ok</body></html>")
                    };
                    let status = if body.is_empty() {
                        "404 Not Found"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
}
