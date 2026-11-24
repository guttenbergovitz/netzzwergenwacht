//! Integration evaluation of two consecutive autonomous patrols (`nzw patrol`).
//!
//! Demonstrates:
//! 1. Patrol #1: Sitemap-index + multilingual discovery (`en-GB`, `de`), baseline
//!    establishment, and institutional memory persistence.
//! 2. Patrol #2: Memory retrieval, reuse of unchanged fresh healthy pages,
//!    detection of a newly introduced anomaly, selective specialist activation,
//!    and change-oriented `PatrolReport` output.

use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netzzwergenwacht::domain::{AuditTarget, CollectorOutcome, ExecutionBudget, TargetPolicy};
use netzzwergenwacht::intelligence::{LlmBudget, LlmFuture, LlmProvider};
use netzzwergenwacht::investigation::LiveDiagnosticBackend;
use netzzwergenwacht::patrol::{PatrolBudget, run_patrol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct SequenceLlm {
    responses: Mutex<VecDeque<String>>,
    calls: Mutex<usize>,
}

impl LlmProvider for SequenceLlm {
    fn model_name(&self) -> &'static str {
        "mock-patrol-llm"
    }

    fn complete<'a>(
        &'a self,
        system: &'a str,
        _user: &'a str,
        _budget: LlmBudget,
    ) -> LlmFuture<'a> {
        let mut c = self.calls.lock().unwrap();
        *c += 1;
        if system.contains("specialist member of Die Zwergenbrigade") {
            return Box::pin(async move { Ok("Specialist assessment recorded.".to_owned()) });
        }
        let next = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                r#"{"ready_to_conclude":true,"conclusion":"Patrol anomaly investigated."}"#
                    .to_owned()
            });
        Box::pin(async move { Ok(next) })
    }
}

async fn spawn_multilingual_site(introduce_regression: Arc<AtomicBool>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://127.0.0.1:{}", addr.port());
    let base_clone = base.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let regressed = introduce_regression.load(Ordering::SeqCst);
            let origin = base_clone.clone();
            tokio::spawn(async move {
                let mut buf = [0_u8; 2048];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (status, content_type, body) = match path {
                    "/sitemap.xml" => (
                        "200 OK",
                        "application/xml",
                        format!(
                            "<sitemapindex><sitemap><loc>{origin}/sitemap-pages.xml</loc></sitemap></sitemapindex>"
                        ),
                    ),
                    "/sitemap-pages.xml" => (
                        "200 OK",
                        "application/xml",
                        format!(
                            "<urlset>\
                             <url><loc>{origin}/en-gb/home</loc></url>\
                             <url><loc>{origin}/de/start</loc></url>\
                             </urlset>"
                        ),
                    ),
                    "/en-gb/home" => (
                        "200 OK",
                        "text/html; charset=utf-8",
                        format!(
                            "<!doctype html><html lang=\"en-GB\"><head><title>Home EN</title>\
                             <meta name=\"description\" content=\"UK homepage.\"></head>\
                             <body><main><h1>Welcome</h1><p>{}</p></main></body></html>",
                            vec!["content"; 60].join(" ")
                        ),
                    ),
                    "/de/start" => (
                        "200 OK",
                        "text/html; charset=utf-8",
                        format!(
                            "<!doctype html><html lang=\"de\"><head><title>Start DE</title>\
                             <meta name=\"description\" content=\"Deutsche Startseite.\"></head>\
                             <body><main><h1>Willkommen</h1><p>{}</p></main></body></html>",
                            vec!["inhalt"; 60].join(" ")
                        ),
                    ),
                    _ if regressed => (
                        "200 OK",
                        "text/html; charset=utf-8",
                        "<!doctype html><html><head><title>Broken</title></head>\
                         <body><img src=\"/hero.png\"></body></html>"
                            .to_owned(),
                    ),
                    _ => (
                        "200 OK",
                        "text/html; charset=utf-8",
                        format!(
                            "<!doctype html><html lang=\"en-GB\"><head><title>Root</title>\
                             <meta name=\"description\" content=\"Root description.\"></head>\
                             <body><main><h1>Root</h1><p>{}</p></main></body></html>",
                            vec!["healthy"; 60].join(" ")
                        ),
                    ),
                };

                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    base
}

#[tokio::test]
async fn consecutive_patrols_reuse_healthy_memory_and_escalate_new_anomaly() {
    let regressed = Arc::new(AtomicBool::new(false));
    let base = spawn_multilingual_site(Arc::clone(&regressed)).await;
    let seed = AuditTarget::parse(&format!("{base}/"), TargetPolicy::AllowPrivate).unwrap();
    let mem_dir = std::env::temp_dir().join("nzw_patrol_eval_mem");
    let _ = fs::remove_dir_all(&mem_dir);

    let exec_budget = ExecutionBudget {
        audit_timeout: Duration::from_secs(5),
        http_timeout: Duration::from_secs(2),
        ..ExecutionBudget::default()
    };
    let patrol_budget = PatrolBudget {
        max_pages: 10,
        max_deep_samples: 2,
        freshness_ttl_secs: 3_600,
        allow_ai_escalation: true,
        enable_level2: false,
    };
    let backend: Arc<dyn netzzwergenwacht::investigation::DiagnosticBackend> =
        Arc::new(LiveDiagnosticBackend);
    let llm_p1 = SequenceLlm {
        responses: Mutex::new(VecDeque::new()),
        calls: Mutex::new(0),
    };

    // Patrol #1: healthy baseline, discovers sitemap index + en-GB & de locales.
    let p1 = run_patrol(
        seed.clone(),
        TargetPolicy::AllowPrivate,
        exec_budget,
        patrol_budget,
        Some(&mem_dir),
        Some(&llm_p1),
        Arc::clone(&backend),
    )
    .await;
    assert_eq!(p1.patrol_number, 1);
    assert!(p1.execution_succeeded);
    assert!(
        p1.application_map
            .locales_observed
            .contains(&"en-GB".to_owned())
    );
    assert!(
        p1.application_map
            .locales_observed
            .contains(&"de".to_owned())
    );
    assert_eq!(p1.reused_page_count, 0);

    // Patrol #2: introduce a regression on the root page while /en-gb/home and /de/start stay unchanged.
    regressed.store(true, Ordering::SeqCst);
    let llm_p2 = SequenceLlm {
        responses: Mutex::new(VecDeque::from([
            r#"{"ready_to_conclude":false,"originating_rule":"a11y.document.lang","proposed_explanation":"Root template lost lang attribute and alt text","requested_tool":"inspect_document_structure"}"#.to_owned(),
            r#"{"ready_to_conclude":true,"conclusion":"Root page regressed with missing lang and image alt."}"#.to_owned(),
        ])),
        calls: Mutex::new(0),
    };

    let p2 = run_patrol(
        seed,
        TargetPolicy::AllowPrivate,
        exec_budget,
        patrol_budget,
        Some(&mem_dir),
        Some(&llm_p2),
        backend,
    )
    .await;
    assert_eq!(p2.patrol_number, 2);
    assert!(p2.execution_succeeded);
    // On plain HTTP, all pages have `sec.transport.https` findings and are therefore
    // re-selected as `PreviouslyDefective` rather than silently skipped as healthy.
    assert!(
        p2.sampling_plan.selections.iter().any(|s| s.reason
            == netzzwergenwacht::patrol::sampling::SelectionReason::PreviouslyDefective)
    );
    assert_ne!(
        p2.anomalies,
        Vec::<netzzwergenwacht::patrol::PatrolAnomaly>::new()
    );
    assert!(!p2.is_quiet_patrol);
    assert!(p2.investigation.is_some());
    assert!(*llm_p2.calls.lock().unwrap() >= 1);
    assert!(
        p2.regression
            .as_ref()
            .is_some_and(|r| r.summary.new_count >= 1)
    );
    assert!(matches!(
        p2.investigation.as_ref().unwrap().hypotheses[0].status,
        _
    ));
    let _ = CollectorOutcome::<()>::default();
    let _ = fs::remove_dir_all(&mem_dir);
}

#[tokio::test]
async fn quiet_patrol_spends_zero_llm_calls_when_unchanged() {
    let regressed = Arc::new(AtomicBool::new(false));
    let base = spawn_multilingual_site(Arc::clone(&regressed)).await;
    let seed = AuditTarget::parse(&format!("{base}/"), TargetPolicy::AllowPrivate).unwrap();
    let mem_dir = std::env::temp_dir().join("nzw_patrol_quiet_mem");
    let _ = fs::remove_dir_all(&mem_dir);

    let exec_budget = ExecutionBudget {
        audit_timeout: Duration::from_secs(5),
        http_timeout: Duration::from_secs(2),
        ..ExecutionBudget::default()
    };
    let patrol_budget = PatrolBudget {
        max_pages: 10,
        max_deep_samples: 2,
        freshness_ttl_secs: 3_600,
        allow_ai_escalation: true,
        enable_level2: false,
    };
    let backend: Arc<dyn netzzwergenwacht::investigation::DiagnosticBackend> =
        Arc::new(LiveDiagnosticBackend);
    let llm_p1 = SequenceLlm {
        responses: Mutex::new(VecDeque::new()),
        calls: Mutex::new(0),
    };
    let _ = run_patrol(
        seed.clone(),
        TargetPolicy::AllowPrivate,
        exec_budget,
        patrol_budget,
        Some(&mem_dir),
        Some(&llm_p1),
        Arc::clone(&backend),
    )
    .await;

    // Patrol #2 on an unchanged application: must be quiet and spend 0 LLM calls.
    let llm_p2 = SequenceLlm {
        responses: Mutex::new(VecDeque::new()),
        calls: Mutex::new(0),
    };
    let p2 = run_patrol(
        seed,
        TargetPolicy::AllowPrivate,
        exec_budget,
        patrol_budget,
        Some(&mem_dir),
        Some(&llm_p2),
        backend,
    )
    .await;
    assert_eq!(p2.patrol_number, 2);
    assert!(p2.is_quiet_patrol);
    assert_eq!(
        p2.anomalies,
        Vec::<netzzwergenwacht::patrol::PatrolAnomaly>::new()
    );
    assert!(p2.investigation.is_none());
    assert_eq!(p2.resource_ledger.llm_requests, 0);
    assert_eq!(*llm_p2.calls.lock().unwrap(), 0);
    let _ = fs::remove_dir_all(&mem_dir);
}

struct NamedMockLlm {
    model: &'static str,
    response: &'static str,
}

impl LlmProvider for NamedMockLlm {
    fn model_name(&self) -> &str {
        self.model
    }

    fn complete<'a>(
        &'a self,
        _system: &'a str,
        _user: &'a str,
        _budget: LlmBudget,
    ) -> LlmFuture<'a> {
        let out = self.response.to_owned();
        Box::pin(async move { Ok(out) })
    }
}

#[tokio::test]
async fn patrol_delegates_to_distinct_per_dwarf_models() {
    use netzzwergenwacht::brigade::DwarfId;
    use netzzwergenwacht::intelligence::CachedProviderRouter;
    use netzzwergenwacht::patrol::run_patrol_with_router;

    let regressed = Arc::new(AtomicBool::new(true));
    let base = spawn_multilingual_site(regressed).await;
    let seed = AuditTarget::parse(&format!("{base}/"), TargetPolicy::AllowPrivate).unwrap();

    let mut router = CachedProviderRouter::default();
    router.insert(
        DwarfId::Sicherheits,
        Arc::new(NamedMockLlm {
            model: "mock-sec-claude",
            response: r#"{"confirmed_observations":["HTTPS absent on local origin"],"evidence_refs":["sec.transport.https"],"remaining_uncertainty":"None for passive transport","requested_tool":"inspect_security_posture","recommendation":"Enforce HTTPS and HSTS."}"#,
        }),
    );
    router.insert(
        DwarfId::Zugaenglichkeits,
        Arc::new(NamedMockLlm {
            model: "mock-a11y-gpt",
            response: r#"{"confirmed_observations":["Missing <html lang>"],"evidence_refs":["a11y.document.lang"],"remaining_uncertainty":"Full heading hierarchy unchecked","requested_tool":"inspect_document_structure","recommendation":"Restore lang and alt attributes."}"#,
        }),
    );
    router.set_fallback(Arc::new(NamedMockLlm {
        model: "mock-kommandant-reasoner",
        response: r#"{"ready_to_conclude":true,"conclusion":"Delegated specialists confirmed findings."}"#,
    }));

    let backend: Arc<dyn netzzwergenwacht::investigation::DiagnosticBackend> =
        Arc::new(LiveDiagnosticBackend);
    let report = run_patrol_with_router(
        seed,
        TargetPolicy::AllowPrivate,
        ExecutionBudget::default(),
        PatrolBudget {
            max_pages: 5,
            allow_ai_escalation: true,
            ..PatrolBudget::default()
        },
        None,
        Some(&router),
        backend,
    )
    .await;

    assert!(report.execution_succeeded);
    assert_ne!(
        report.specialist_delegations,
        Vec::<netzzwergenwacht::patrol::SpecialistDelegation>::new()
    );
    assert!(
        report
            .specialist_delegations
            .iter()
            .any(|d| d.model_used == "mock-sec-claude" || d.model_used == "mock-a11y-gpt")
    );
    assert!(
        report
            .specialist_delegations
            .iter()
            .any(|d| d.tool_executed.is_some() && d.structured_output.is_some())
    );
    assert!(report.resource_ledger.investigation_tool_calls >= 1);
    let inv = report.investigation.as_ref().unwrap();
    assert_ne!(
        inv.specialists,
        Vec::<netzzwergenwacht::investigation::SpecialistContribution>::new()
    );
}
