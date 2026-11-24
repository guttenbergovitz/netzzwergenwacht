//! Comparative evaluation against the `Zwergenprüfstand` benchmark fixtures.
//!
//! Spins up a real local HTTP server serving `fixtures/zwergenpruefstand/` and
//! compares Mode A (single-URL deterministic audit) vs Mode C (multi-turn
//! `KommandantZwerg` investigation with real HTTP crawl + mock LLM reasoning)
//! and verifies `diff_reports` remediation semantics.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use netzzwergenwacht::analysis;
use netzzwergenwacht::collection;
use netzzwergenwacht::domain::{AuditTarget, ExecutionBudget, TargetPolicy};
use netzzwergenwacht::intelligence::{LlmBudget, LlmFuture, LlmProvider};
use netzzwergenwacht::investigation::{
    HypothesisStatus, InvestigationBudget, InvestigationState, LiveDiagnosticBackend,
    ReleaseReadinessState, run_investigation,
};
use netzzwergenwacht::persistence;

fn fixture_body(path: &str) -> (&'static str, &'static str) {
    match path {
        "/healthy.html" => (
            "200 OK",
            include_str!("../fixtures/zwergenpruefstand/healthy.html"),
        ),
        "/perf-and-structure.html" => (
            "200 OK",
            include_str!("../fixtures/zwergenpruefstand/perf-and-structure.html"),
        ),
        "/a11y.html" => (
            "200 OK",
            include_str!("../fixtures/zwergenpruefstand/a11y.html"),
        ),
        "/fixed/a11y.html" => (
            "200 OK",
            include_str!("../fixtures/zwergenpruefstand/fixed/a11y.html"),
        ),
        _ => ("404 Not Found", "<html><body>Not found</body></html>"),
    }
}

async fn spawn_fixture_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = fixture_body(path);
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}"), handle)
}

struct ScriptedKommandant {
    responses: Mutex<VecDeque<String>>,
}

impl LlmProvider for ScriptedKommandant {
    fn model_name(&self) -> &'static str {
        "scripted-kommandant-eval"
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
            .unwrap_or_else(|| r#"{"ready_to_conclude":true,"conclusion":"Done"}"#.to_owned());
        Box::pin(async move { Ok(next) })
    }
}

#[tokio::test]
async fn evaluates_mode_a_deterministic_vs_mode_c_agentic_on_zwergenpruefstand() {
    let (base_url, server) = spawn_fixture_server().await;
    let seed = AuditTarget::parse(
        &format!("{base_url}/perf-and-structure.html"),
        TargetPolicy::AllowPrivate,
    )
    .unwrap();

    // Mode A: Single-URL deterministic audit
    let mode_a_start = Instant::now();
    let snap_a = collection::collect_http(
        &seed,
        &ExecutionBudget::default(),
        TargetPolicy::AllowPrivate,
    )
    .await;
    let report_a = analysis::run_all(&snap_a);
    let mode_a_ms = mode_a_start.elapsed().as_millis();
    let mode_a_rules: Vec<&str> = report_a
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| f.rule_id.0.as_str()))
        .collect();

    // Mode C: Multi-turn agentic investigation with real HTTP crawl + structure tools
    let llm = ScriptedKommandant {
        responses: Mutex::new(VecDeque::from([
            r#"{"ready_to_conclude":false,"originating_rule":"a11y.images.alt","proposed_explanation":"Missing image alt and metadata may recur across linked pages","requested_tool":"crawl_and_cluster_site"}"#.to_owned(),
            r#"{"status":"supported","evaluation_summary":"Crawl discovered /a11y.html and /healthy.html and clustered systemic missing alt and meta description","conclusion":"Systemic template gaps and page-specific accessibility defects confirmed."}"#.to_owned(),
            r#"{"ready_to_conclude":true,"conclusion":"Investigation complete."}"#.to_owned(),
        ])),
    };

    let agentic_start = Instant::now();
    let report_c = run_investigation(
        seed,
        "Assess release readiness and systemic defects".to_owned(),
        TargetPolicy::AllowPrivate,
        InvestigationBudget::default(),
        Arc::new(LiveDiagnosticBackend),
        &llm,
    )
    .await;
    let agentic_ms = agentic_start.elapsed().as_millis();

    assert_eq!(report_c.state, InvestigationState::Completed);
    assert_eq!(
        report_c.release_readiness.state,
        ReleaseReadinessState::PotentialReleaseBlockers
    );
    assert_eq!(report_c.discovered_pages.len(), 3);
    assert!(
        report_c
            .systemic_issues
            .iter()
            .any(|s| s.rule_id.0 == "a11y.images.alt" && s.affected_urls.len() == 2)
    );
    assert_eq!(report_c.hypotheses[0].status, HypothesisStatus::Supported);
    assert_ne!(report_c.remediation_tasks.len(), 0);

    eprintln!(
        "Zwergenpruefstand Eval -> Mode A: {} rules in {} ms | Mode C: {} discovered pages, {} systemic issues, {} tasks in {} ms",
        mode_a_rules.len(),
        mode_a_ms,
        report_c.discovered_pages.len(),
        report_c.systemic_issues.len(),
        report_c.remediation_tasks.len(),
        agentic_ms
    );

    server.abort();
}

#[tokio::test]
async fn verifies_remediation_between_baseline_and_fixed_zwergenpruefstand_page() {
    let (base_url, server) = spawn_fixture_server().await;
    let baseline_target =
        AuditTarget::parse(&format!("{base_url}/a11y.html"), TargetPolicy::AllowPrivate).unwrap();
    let fixed_target = AuditTarget::parse(
        &format!("{base_url}/fixed/a11y.html"),
        TargetPolicy::AllowPrivate,
    )
    .unwrap();

    let snap_base = collection::collect_http(
        &baseline_target,
        &ExecutionBudget::default(),
        TargetPolicy::AllowPrivate,
    )
    .await;
    let snap_fixed = collection::collect_http(
        &fixed_target,
        &ExecutionBudget::default(),
        TargetPolicy::AllowPrivate,
    )
    .await;

    let report_base = analysis::run_all(&snap_base);
    let mut report_fixed = analysis::run_all(&snap_fixed);
    // Align target URL for same-page remediation comparison (simulating post-deploy re-check).
    report_fixed.target = baseline_target;
    let report_fixed_aligned = {
        let mut r = report_fixed;
        for a in &mut r.analysers {
            for f in &mut a.findings {
                f.fingerprint = netzzwergenwacht::domain::FindingFingerprint::compute(
                    r.target.as_str(),
                    &f.rule_id,
                    "",
                );
            }
        }
        r
    };

    let diff = persistence::diff_reports(&report_base, &report_fixed_aligned);
    assert_eq!(diff.not_comparable_reason, None);
    assert_eq!(diff.summary.unverified_count, 0);
    let resolved_ids: Vec<&str> = diff
        .resolved_findings
        .iter()
        .map(|f| f.rule_id.0.as_str())
        .collect();
    for expected in [
        "a11y.doc.lang",
        "a11y.images.alt",
        "a11y.forms.labels",
        "a11y.aria.broken_references",
    ] {
        assert!(
            resolved_ids.contains(&expected),
            "expected `{expected}` in resolved_findings, got {resolved_ids:?}"
        );
    }

    server.abort();
}
