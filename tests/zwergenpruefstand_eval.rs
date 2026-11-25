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
        "/segmentation.html" => (
            "200 OK",
            "<html lang=en><body><nav>Home Offers About Contact</nav><main><p>Product information</p><p lang=de>Lieferbar</p><p hidden>Hidden words</p></main><section></section></body></html>",
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

fn make_http_snapshot(
    html: &str,
    final_url: &str,
    headers: Vec<netzzwergenwacht::domain::HttpHeader>,
    with_tls: bool,
) -> netzzwergenwacht::domain::EvidenceSnapshot {
    use netzzwergenwacht::domain::{
        CollectorOutcome, EvidenceSnapshot, HttpEvidence, Measurement, MeasurementUnit, TlsEvidence,
    };
    let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
    let tls = if with_tls {
        CollectorOutcome::Captured {
            data: TlsEvidence {
                subject: "CN=example.com".to_owned(),
                issuer: "CN=Example CA".to_owned(),
                not_after_unix_secs: 2_000_000_000,
                days_until_expiry: 90,
            },
        }
    } else {
        CollectorOutcome::Skipped {
            reason: "test".to_owned(),
        }
    };
    EvidenceSnapshot {
        target,
        captured_at_unix_secs: 0,
        http: CollectorOutcome::Captured {
            data: HttpEvidence {
                final_url: final_url.to_owned(),
                status_code: 200,
                redirect_chain: Vec::new(),
                headers,
                elapsed_ms: Measurement::Measured {
                    value: 50,
                    unit: MeasurementUnit::Milliseconds,
                },
                body_bytes: html.len(),
                body_truncated: false,
                body_text: html.to_owned(),
            },
        },
        tls,
        browser: CollectorOutcome::default(),
        lighthouse: CollectorOutcome::default(),
        axe: CollectorOutcome::default(),
    }
}

#[test]
fn verifies_aufrustung3_rules_with_clean_control_and_defect_fixture() {
    use netzzwergenwacht::domain::HttpHeader;

    let defect_html = r#"<!doctype html><html lang="en"><head>
        <meta charset="utf-8"><title>Defect Fixture</title><link rel="icon" href="/f.ico">
    </head><body>
        <main><h1></h1><p>Welcome i18n.home.hero_title</p><a href="mailto:test@example.com">Read more</a></main>
        <main><img src="/p.jpg" alt="IMG_001.jpg"><video controls src="/v.mp4"></video></main>
    </body></html>"#;
    let defect_snap = make_http_snapshot(
        defect_html,
        "https://example.com/?token=SECRET_XYZ",
        vec![
            HttpHeader {
                name: "strict-transport-security".to_owned(),
                value: "max-age=31536000".to_owned(),
            },
            HttpHeader {
                name: "content-security-policy".to_owned(),
                value: "default-src 'self'".to_owned(),
            },
            HttpHeader {
                name: "etag".to_owned(),
                value: "bad-etag".to_owned(),
            },
        ],
        true,
    );
    let defect_report = analysis::run_all(&defect_snap);
    let defect_ids: Vec<&str> = defect_report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| f.rule_id.0.as_str()))
        .collect();
    for expected in [
        "sec.csp.missing_object_restriction",
        "sec.csp.missing_base_uri_restriction",
        "sec.exposure.sensitive_url_parameters",
        "netz.http.etag_validation",
        "str.landmarks.duplicate_main",
        "str.headings.empty_heading",
        "a11y.media.missing_caption_track",
        "a11y.images.suspicious_alternative_text",
        "a11y.links.ambiguous_accessible_name",
        "inh.integrity.unresolved_translation_key",
        "inh.integrity.placeholder_contact",
    ] {
        assert!(
            defect_ids.contains(&expected),
            "expected `{expected}` in defect findings, got {defect_ids:?}"
        );
    }
    assert!(
        defect_report
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter())
            .all(|f| !f.summary.contains("SECRET_XYZ"))
    );

    let clean_html = include_str!("../fixtures/zwergenpruefstand/healthy.html");
    let clean_snap = make_http_snapshot(
        clean_html,
        "https://example.com/",
        vec![HttpHeader {
            name: "etag".to_owned(),
            value: "\"v1-clean\"".to_owned(),
        }],
        false,
    );
    let clean_report = analysis::run_all(&clean_snap);
    let clean_ids: Vec<&str> = clean_report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| f.rule_id.0.as_str()))
        .collect();
    assert!(!clean_ids.contains(&"netz.http.etag_validation"));
    assert!(!clean_ids.contains(&"str.landmarks.duplicate_main"));
    assert!(!clean_ids.contains(&"str.headings.empty_heading"));
    assert!(!clean_ids.contains(&"inh.integrity.unresolved_translation_key"));
    assert!(!clean_ids.contains(&"inh.integrity.placeholder_contact"));
}

#[tokio::test]
async fn measures_source_segmentation_and_rejects_truncated_http() {
    use netzzwergenwacht::analysis::segmentation::query_content_evidence;
    use netzzwergenwacht::domain::CheckStatus;

    let (base_url, server) = spawn_fixture_server().await;
    let target = AuditTarget::parse(
        &format!("{base_url}/segmentation.html"),
        TargetPolicy::AllowPrivate,
    )
    .unwrap();
    let complete = collection::collect_http(
        &target,
        &ExecutionBudget::default(),
        TargetPolicy::AllowPrivate,
    )
    .await;
    let budget = ExecutionBudget {
        max_response_bytes: 64,
        ..ExecutionBudget::default()
    };
    let partial = collection::collect_http(&target, &budget, TargetPolicy::AllowPrivate).await;
    server.abort();

    let page = query_content_evidence(&complete, 0).unwrap();
    assert_eq!(page.paragraphs.len(), 2);
    assert_eq!(page.main_words.unwrap().outside_main, 4);
    assert_eq!(page.main_words.unwrap().total, 7);
    let report = analysis::run_all(&complete);
    for id in [
        "inh.content.boilerplate_ratio",
        "inh.content.empty_sections",
    ] {
        assert!(
            report
                .analysers
                .iter()
                .flat_map(|a| &a.findings)
                .any(|f| f.rule_id.0 == id)
        );
    }

    assert!(
        query_content_evidence(&partial, 0)
            .unwrap_err()
            .contains("truncated")
    );
    let report = analysis::run_all(&partial);
    assert!(report.analysers.iter().flat_map(|a| &a.checks).any(|check| {
        matches!(check, CheckStatus::Skipped { rule_id, .. } if rule_id.0 == "inh.content.boilerplate_ratio")
    }));
}
