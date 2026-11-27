//! Crawler throughput measurement over a loopback fixture.
//!
//! This is a benchmark, not a regression test: it is ignored by default and asserts only
//! correctness of the acquired population. The numbers it prints describe this machine and this
//! fixture, which is why they must never be quoted as a product capability.
//!
//! Run with:
//! `cargo test --release --locked --test crawler_benchmark -- --ignored --nocapture`

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netzzwergenwacht::discovery::{CrawlBudget, crawl_and_cluster};
use netzzwergenwacht::domain::{AuditTarget, ExecutionBudget, TargetPolicy};

const PAGES: usize = 24;
const PER_RESPONSE_DELAY_MS: u64 = 20;

struct Fixture {
    addr: SocketAddr,
    peak: Arc<AtomicUsize>,
}

fn body_for(path: &str) -> String {
    if path == "/" {
        let mut links = String::new();
        for index in 1..PAGES {
            use std::fmt::Write as _;
            let _ = write!(links, "<a href=\"/p{index}\">{index}</a>");
        }
        format!("<html><head><title>Seed</title></head><body>{links}</body></html>")
    } else {
        format!(
            "<html><head><title>Page {path}</title>\
             <meta name=\"description\" content=\"Benchmark page {path}.\"></head>\
             <body><h1>Benchmark</h1><a href=\"/\">Home</a></body></html>"
        )
    }
}

async fn spawn_fixture() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peak = Arc::new(AtomicUsize::new(0));
    let live = Arc::new(AtomicUsize::new(0));
    let peak_task = Arc::clone(&peak);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let peak = Arc::clone(&peak_task);
            let live = Arc::clone(&live);
            tokio::spawn(async move {
                let current = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                let mut buffer = [0_u8; 1024];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_owned();
                tokio::time::sleep(Duration::from_millis(PER_RESPONSE_DELAY_MS)).await;
                let body = body_for(&path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Fixture { addr, peak }
}

async fn measure(addr: SocketAddr, concurrency: usize) -> (Duration, usize, usize) {
    let seed = AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
    let exec_budget = ExecutionBudget {
        audit_timeout: Duration::from_secs(60),
        http_timeout: Duration::from_secs(5),
        max_concurrency: concurrency,
        ..ExecutionBudget::default()
    };
    let crawl_budget = CrawlBudget {
        max_pages: PAGES + 2,
        max_depth: 1,
        max_duration: Duration::from_secs(60),
    };
    let started = Instant::now();
    let summary =
        crawl_and_cluster(seed, crawl_budget, exec_budget, TargetPolicy::AllowPrivate).await;
    let elapsed = started.elapsed();
    (elapsed, summary.coverage.analysed_urls, summary.pages.len())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measured benchmark; run with --release --ignored --nocapture"]
async fn concurrency_changes_crawl_wall_clock() {
    let fixture = spawn_fixture().await;

    let (serial, serial_analysed, serial_discovered) = measure(fixture.addr, 1).await;
    let (parallel, parallel_analysed, parallel_discovered) = measure(fixture.addr, 4).await;

    let pages = f64::from(u32::try_from(PAGES).unwrap_or(u32::MAX));
    println!("\ncrawler benchmark: {PAGES} pages, {PER_RESPONSE_DELAY_MS} ms per response");
    println!(
        "  concurrency 1: {serial:?} ({:.1} pages/s)",
        pages / serial.as_secs_f64()
    );
    println!(
        "  concurrency 4: {parallel:?} ({:.1} pages/s)",
        pages / parallel.as_secs_f64()
    );
    println!("  peak in-flight: {}", fixture.peak.load(Ordering::SeqCst));

    // Correctness assertions only: both runs must acquire the same population.
    assert_eq!(serial_discovered, PAGES);
    assert_eq!(parallel_discovered, PAGES);
    assert_eq!(serial_analysed, PAGES);
    assert_eq!(parallel_analysed, PAGES);
}
