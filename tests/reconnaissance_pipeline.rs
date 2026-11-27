//! End-to-end reconnaissance pipeline test: crawl -> analyse -> persist -> query.
//!
//! The fixture is a loopback HTTP server, so the test exercises the real acquisition, robots,
//! subresource and analysis paths without touching the network. It asserts the properties the
//! reconnaissance engine claims: bounded concurrent acquisition, shared resources acquired once,
//! systemic clustering that only links pages genuinely sharing a defect, and an evidence store
//! that answers the same questions after the crawl has finished.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netzzwergenwacht::discovery::{CrawlBudget, PageCrawlStatus, crawl_and_cluster};
use netzzwergenwacht::domain::{AuditTarget, ExecutionBudget, TargetPolicy};
use netzzwergenwacht::evidence_store::{CrawlRecord, EvidenceStore};

struct Fixture {
    addr: SocketAddr,
    requested_paths: Arc<Mutex<Vec<String>>>,
    peak_concurrency: Arc<AtomicUsize>,
}

/// Pages `/a` and `/b` deliberately share the same defect set: no `<title>`, an image without
/// alt text, and a meta description missing. `/c` is the clean control.
fn page(title: Option<&str>, with_defects: bool) -> String {
    let title_tag = title.map_or_else(String::new, |value| format!("<title>{value}</title>"));
    let image = if with_defects {
        "<img src=\"/logo.png\">"
    } else {
        "<img src=\"/logo.png\" alt=\"Logo\">"
    };
    let description = if with_defects {
        String::new()
    } else {
        "<meta name=\"description\" content=\"A clean control page.\">".to_owned()
    };
    format!(
        "<html><head>{title_tag}{description}\
         <link rel=\"stylesheet\" href=\"/shared.css\"></head>\
         <body><h1>{heading}</h1>{image}<a href=\"/\">Home</a></body></html>",
        heading = title.unwrap_or("Untitled"),
    )
}

async fn spawn_fixture() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requested_paths = Arc::new(Mutex::new(Vec::new()));
    let peak_concurrency = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));

    let paths_task = Arc::clone(&requested_paths);
    let peak_task = Arc::clone(&peak_concurrency);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let paths = Arc::clone(&paths_task);
            let peak = Arc::clone(&peak_task);
            let live = Arc::clone(&live);
            tokio::spawn(async move {
                let current = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
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
                tokio::time::sleep(Duration::from_millis(10)).await;

                let (status, content_type, body) = if path == "/" {
                    (
                        "200 OK",
                        "text/html; charset=utf-8",
                        "<html><head><title>Seed</title>\
                         <meta name=\"description\" content=\"Seed page.\">\
                         <link rel=\"stylesheet\" href=\"/shared.css\"></head><body>\
                         <a href=\"/a\">A</a><a href=\"/b\">B</a><a href=\"/c\">C</a>\
                         </body></html>"
                            .to_owned(),
                    )
                } else if path == "/a" || path == "/b" {
                    ("200 OK", "text/html; charset=utf-8", page(None, true))
                } else if path == "/c" {
                    (
                        "200 OK",
                        "text/html; charset=utf-8",
                        page(Some("Control"), false),
                    )
                } else if path == "/shared.css" {
                    ("200 OK", "text/css", "body { color: #222; }".to_owned())
                } else if path == "/logo.png" {
                    ("200 OK", "image/png", "not-really-a-png".to_owned())
                } else {
                    ("404 Not Found", "text/plain", "not found".to_owned())
                };

                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    Fixture {
        addr,
        requested_paths,
        peak_concurrency,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn crawl_persists_coverage_findings_and_shared_resource_dependents() {
    let fixture = spawn_fixture().await;
    let seed = AuditTarget::parse(
        &format!("http://{}/", fixture.addr),
        TargetPolicy::AllowPrivate,
    )
    .unwrap();
    let crawl_budget = CrawlBudget {
        max_pages: 10,
        max_depth: 2,
        max_duration: Duration::from_secs(20),
    };
    let exec_budget = ExecutionBudget {
        audit_timeout: Duration::from_secs(20),
        http_timeout: Duration::from_secs(5),
        ..ExecutionBudget::default()
    };

    let summary = crawl_and_cluster(
        seed.clone(),
        crawl_budget,
        exec_budget,
        TargetPolicy::AllowPrivate,
    )
    .await;

    // Acquisition accounting is a partition, and this crawl reached everything it discovered.
    assert_eq!(summary.coverage.discovered_urls, 4, "{:?}", summary.pages);
    assert_eq!(summary.coverage.analysed_urls, 4);
    assert_eq!(summary.coverage.failed_urls, 0);
    assert_eq!(summary.coverage.skipped_budget_urls, 0);
    assert!(summary.coverage.complete);
    assert!(!summary.budget_exhausted);
    assert!(fixture.peak_concurrency.load(Ordering::SeqCst) >= 2);

    // The shared stylesheet is referenced by all four pages and fetched exactly once.
    let css_requests = fixture
        .requested_paths
        .lock()
        .unwrap()
        .iter()
        .filter(|path| path.as_str() == "/shared.css")
        .count();
    assert_eq!(css_requests, 1);
    assert_eq!(summary.coverage.resources.fetched_resources, 2);
    let css_edges = summary
        .page_resources
        .iter()
        .filter(|edge| edge.resource_url.ends_with("/shared.css"))
        .count();
    assert_eq!(css_edges, 4);

    // Systemic clustering must group a defect that two pages genuinely share, and every cluster
    // must cite at least two observed pages.
    assert_ne!(summary.systemic_issues.len(), 0);
    for issue in &summary.systemic_issues {
        assert!(issue.affected_urls.len() >= 2, "{}", issue.rule_id.0);
    }
    let shared_defect = summary
        .systemic_issues
        .iter()
        .any(|issue| issue.affected_urls.iter().any(|url| url.ends_with("/a")));
    assert!(
        shared_defect,
        "expected a cluster covering the defective pages, saw {:?}",
        summary
            .systemic_issues
            .iter()
            .map(|issue| (&issue.rule_id.0, issue.affected_urls.len()))
            .collect::<Vec<_>>()
    );

    // Persist, then answer the same questions from the store alone.
    let dir = std::env::temp_dir().join(format!("nzw-recon-{}", u64::from(std::process::id()) + 1));
    let store = EvidenceStore::open(&dir.join("evidence.db")).await.unwrap();
    store
        .record_crawl(CrawlRecord {
            run_id: "recon-test-run",
            application: seed.as_str(),
            summary: &summary,
            recorded_at_unix_secs: 1_700_000_000,
        })
        .await
        .unwrap();

    let coverage = store.coverage("recon-test-run").await.unwrap().unwrap();
    assert_eq!(coverage.discovered_urls, summary.coverage.discovered_urls);
    assert_eq!(coverage.analysed_urls, summary.coverage.analysed_urls);
    assert_eq!(
        coverage.resources.fetched_resources,
        summary.coverage.resources.fetched_resources
    );
    assert_eq!(coverage.complete, summary.coverage.complete);

    let pages = store.pages("recon-test-run", None, 16).await.unwrap();
    assert_eq!(pages.len(), 4);
    assert!(
        pages
            .iter()
            .all(|page| page.status == PageCrawlStatus::Investigated)
    );

    let css_url = summary
        .page_resources
        .iter()
        .find(|edge| edge.resource_url.ends_with("/shared.css"))
        .map(|edge| edge.resource_url.clone())
        .unwrap();
    let dependents = store
        .resource_dependents("recon-test-run", &css_url, 16)
        .await
        .unwrap();
    assert_eq!(dependents.len(), 4);

    let stored_issues = store.systemic_issues("recon-test-run", 64).await.unwrap();
    assert_eq!(stored_issues.len(), summary.systemic_issues.len());

    // The path that matters: pages that were analysed produce findings, and those
    // findings are readable from the store with the evidence that raised them.
    let analysed_findings: usize = summary
        .page_diagnostics
        .iter()
        .map(|page| page.findings.len())
        .sum();
    assert!(
        analysed_findings > 0,
        "the fixture pages share defects, so the crawl must have raised findings"
    );

    let stored_findings = store
        .findings("recon-test-run", None, None, 128)
        .await
        .unwrap();
    assert_eq!(stored_findings.len(), analysed_findings);
    assert!(
        stored_findings
            .iter()
            .all(|finding| !finding.evidence_refs.is_empty()),
        "every persisted finding must carry the evidence it was raised from"
    );
    let defective_page = summary
        .page_diagnostics
        .iter()
        .find(|page| !page.findings.is_empty())
        .expect("the fixture pages share defects, so one page must carry findings");
    let for_page = store
        .findings("recon-test-run", Some(&defective_page.url), None, 128)
        .await
        .unwrap();
    assert_eq!(for_page.len(), defective_page.findings.len());
    assert!(
        for_page
            .iter()
            .all(|finding| finding.page_url == defective_page.url),
        "a page filter must not return findings raised on another page"
    );

    let totals = store.dwarf_totals("recon-test-run").await.unwrap();
    assert_eq!(totals.len(), summary.analysis_totals.len());
    let evaluated: usize = totals.iter().map(|total| total.checks_evaluated).sum();
    let expected: usize = summary
        .analysis_totals
        .iter()
        .map(|total| total.checks_evaluated)
        .sum();
    assert_eq!(evaluated, expected);

    let _ = std::fs::remove_dir_all(&dir);
}
