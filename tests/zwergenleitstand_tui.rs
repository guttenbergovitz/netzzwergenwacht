//! End-to-end, security, layout, and operational performance integration tests for Zwergenleitstand (`nzw tui`).

use std::time::{Duration, Instant};

use netzzwergenwacht::analysis::{AuditReport, AuditSummary};
use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::domain::{
    AnalyserResult, AuditTarget, BrowserEvidence, CollectorOutcome, Confidence, EvidenceLevel,
    EvidenceRef, EvidenceSnapshot, EvidenceSource, ExecutionBudget, Finding, FindingCategory,
    FindingFingerprint, FindingKind, ResourceTimingObs, RuleId, Severity, TargetPolicy,
};
use netzzwergenwacht::events::{
    CollectorId, DiagnosticEventPayload, DiagnosticRunMode, EventContext, RunId,
    diagnostic_event_channel,
};
use netzzwergenwacht::persistence;
use netzzwergenwacht::tui::{
    AppAction, AppEffect, AppState, DiagnosticArtefacts, EvidenceCategory, GlyphSet, RunLaunchSpec,
    RunLifecycleState, ThemeMode, UserAction, WorkbenchView, execute_diagnostic_run,
    execute_diagnostic_run_cancellable, load_offline_history, load_offline_report, reduce, render,
    save_current_report,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_fixture_http_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = "<!doctype html><html><head><title>Zwergenleitstand Fixture</title></head>\
                        <body><h1>Fixture Heading</h1><img src=\"/hero.png\"><a href=\"/about\">About</a></body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    format!("http://{addr}/")
}

fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn vertical_slice_live_deterministic_audit_to_tui_evidence_and_saved_report() {
    let target_str = spawn_fixture_http_server().await;
    let policy = TargetPolicy::AllowPrivate;
    let audit_target = AuditTarget::parse(&target_str, policy).expect("valid loopback url");
    let budget = ExecutionBudget::default();

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    let run_id = RunId::new("run-vertical-slice");
    let (sink, mut rx) = diagnostic_event_channel(run_id);

    let spec = RunLaunchSpec {
        target: audit_target,
        mode: DiagnosticRunMode::DeterministicCheck,
        enable_browser: false,
        enable_axe: false,
        enable_lighthouse: false,
        provider: netzzwergenwacht::config::ProviderKind::OpenAi,
        model: String::new(),
        evidence_dir: std::path::PathBuf::from(".nzw/evidence"),
        max_pages: 10,
        max_depth: 1,
    };

    let artefacts = Box::pin(execute_diagnostic_run(
        spec,
        policy,
        budget,
        String::from("Verify vertical slice"),
        sink,
    ))
    .await
    .expect("execute live deterministic run");

    let mut received_events = 0_usize;
    while let Ok(event) = rx.try_recv() {
        received_events += 1;
        let _ = reduce(&mut state, AppAction::Diagnostic(Box::new(event)));
    }
    assert!(
        received_events >= 10,
        "expected real collection and specialist analysis events, got {received_events}"
    );

    let _ = reduce(&mut state, AppAction::RunFinished(Box::new(artefacts)));

    assert_eq!(state.lifecycle, RunLifecycleState::Completed);
    assert!(
        !state.findings.is_empty(),
        "real deterministic analysers should emit findings for unhardened HTTP response"
    );
    assert!(
        state
            .brigade_rows
            .iter()
            .any(|row| row.checks_total > 0 && row.findings_count > 0),
        "brigade rows should reflect real specialist execution"
    );

    // Navigate to Findings view and press Enter to jump to supporting Evidence.
    let _ = reduce(
        &mut state,
        AppAction::User(UserAction::SelectView(WorkbenchView::Findings)),
    );
    let _ = reduce(&mut state, AppAction::User(UserAction::Activate));
    assert_eq!(state.active_view, WorkbenchView::Evidence);
    assert_eq!(state.evidence_category, EvidenceCategory::Http);

    // Render into TestBackend and verify real finding and evidence details appear.
    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal
        .draw(|frame| render(frame, &state))
        .expect("draw evidence view");
    let rendered = buffer_text(&terminal);
    assert!(rendered.contains("HTTP"));

    // Save report and reopen offline without network acquisition.
    let tmp_dir = std::env::temp_dir();
    let report_path = tmp_dir.join(format!(
        "nzw-tui-vertical-slice-{}.json",
        std::process::id()
    ));
    state.output_path = Some(report_path.clone());
    let effects = reduce(&mut state, AppAction::User(UserAction::SaveCurrentReport));
    assert!(
        effects
            .iter()
            .any(|eff| matches!(eff, AppEffect::SaveReport(_)))
    );
    let saved_path = save_current_report(&state, &report_path).expect("save report file");
    let loaded_artefacts =
        load_offline_report(&saved_path).expect("load saved report without network");
    assert_eq!(loaded_artefacts.target, target_str);
    assert!(loaded_artefacts.audit_report.is_some());

    // Also verify history JSONL loading.
    let history_path = tmp_dir.join(format!("nzw-tui-history-{}.jsonl", std::process::id()));
    let saved_report = state.audit_report.as_ref().expect("saved report in state");
    persistence::append_report(&history_path, saved_report).expect("append history jsonl");
    let hist_artefacts = load_offline_history(&history_path).expect("load history jsonl");
    assert_eq!(hist_artefacts.history_reports.len(), 1);
    assert!(hist_artefacts.regression_report.is_none());

    let _ = std::fs::remove_file(&report_path);
    let _ = std::fs::remove_file(&history_path);
}

#[test]
#[allow(clippy::too_many_lines)]
fn operational_performance_handles_thousand_findings_and_rapid_events_under_budget() {
    let target = AuditTarget::parse("http://127.0.0.1:8080/", TargetPolicy::AllowPrivate)
        .expect("valid target");

    let mut findings = Vec::with_capacity(1_000);
    for idx in 0..1_000_usize {
        let severity = if idx % 20 == 0 {
            Severity::Critical
        } else if idx % 5 == 0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let rule_id = RuleId(format!("sec.header.rule_{idx:04}"));
        findings.push(Finding {
            fingerprint: FindingFingerprint::compute(target.host(), &rule_id, "x-test"),
            rule_id,
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: format!("Synthetic security finding #{idx}"),
            summary: format!("Detailed diagnostic description for finding #{idx}"),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("x-test-{idx}: missing"),
            )],
            remediation: Some("Apply strict security header policy.".to_owned()),
        });
    }

    let report = AuditReport {
        schema_version: "0.2.0".to_owned(),
        target: target.clone(),
        captured_at_unix_secs: 1_764_000_100,
        http: CollectorOutcome::Skipped {
            reason: "synthetic performance benchmark".to_owned(),
        },
        level2_collectors: Vec::new(),
        rendered_history: None,
        analysers: vec![AnalyserResult {
            dwarf_id: DwarfId::Sicherheits,
            checks: Vec::new(),
            findings,
        }],
        summary: AuditSummary {
            critical_findings: 50,
            high_findings: 150,
            medium_findings: 800,
            low_findings: 0,
            info_findings: 0,
            passed_checks: 0,
            failed_checks: 1_000,
            skipped_checks: 0,
            unavailable_checks: 0,
        },
        ai_synthesis: None,
    };

    let resources = (0..120_u64)
        .map(|idx| ResourceTimingObs {
            url: format!("https://example.org/assets/chunk-{idx}.js"),
            resource_type: "script".to_owned(),
            mime_type: Some("application/javascript".to_owned()),
            status_code: Some(200),
            transfer_size: Some(16_384),
            duration_ms: Some(15 + idx * 3),
            priority: Some("High".to_owned()),
            protocol: Some("h2".to_owned()),
            cache_control: Some("max-age=3600".to_owned()),
            content_encoding: Some("br".to_owned()),
            request_id: Some(format!("req-{idx}")),
            initiator_type: Some("parser".to_owned()),
            initiator_url: Some("https://example.org/".to_owned()),
            start_time_ms: Some(idx * 5),
            endpoint_path: Some(format!("/assets/chunk-{idx}.js")),
            cache_source: None,
            timings: None,
        })
        .collect();

    let snapshot = EvidenceSnapshot {
        target,
        captured_at_unix_secs: 1_764_000_100,
        http: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
        tls: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
        browser: CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.org/".to_owned(),
                browser_version: Some("HeadlessChrome/131.0".to_owned()),
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                timeline: None,
                viewports: Vec::new(),
                resources,
                resources_truncated: false,
                rendered_images: Vec::new(),
                rendered_images_truncated: false,
                rendered_dom_elements: Some(42),
                hydration_errors: Vec::new(),
                rendered_word_count: Some(500),
                rendered_content: None,
                ax_tree: None,
                performance: None,
                storage_summary: None,
                coverage: None,
                behavioural_a11y: None,
                cpu_profile: None,
                consent_banner: None,
                provenance: None,
                interactive_inventory: None,
                application_state: None,
                user_journey_trace: None,
                visual_geometry: None,
                ax_node_inventory: None,
                cookie_and_storage: None,
                third_party_inventory: None,
                security_posture: None,
                security_challenge: None,
                performance_attribution: None,
                media_and_fonts: None,
                indexability_authority: None,
                structured_data: None,
                responsive_comparison: None,
                link_graph: None,
                visual_artifacts: None,
                service_worker: None,
                tls_and_caa: None,
            },
        },
        lighthouse: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
        axe: CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        },
    };

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    let (sink, mut rx) = diagnostic_event_channel(RunId::new("run-perf"));

    // Emit 500 rapid progress events to verify bounded coalescing and non-blocking ingestion.
    for idx in 0..500_usize {
        sink.emit(
            EventContext::new().with_target("https://example.org/"),
            DiagnosticEventPayload::CollectionProgress {
                collector: CollectorId::Browser,
                completed_units: idx,
                total_units: Some(500),
                detail: format!("Capturing resource {idx}"),
            },
        );
    }
    assert!(
        sink.dropped_progress_count() > 0,
        "rapid progress burst over 256-item channel should coalesce excess progress events"
    );

    while let Ok(event) = rx.try_recv() {
        let _ = reduce(&mut state, AppAction::Diagnostic(Box::new(event)));
    }
    assert!(
        state.recent_activity.len() <= 256,
        "recent_activity ring buffer must stay bounded at <= 256 entries"
    );

    let _ = reduce(
        &mut state,
        AppAction::RunFinished(Box::new(DiagnosticArtefacts {
            target: "https://example.org/".to_owned(),
            mode: DiagnosticRunMode::DeterministicCheck,
            snapshot: Some(snapshot),
            audit_report: Some(report),
            investigation_report: None,
            patrol_report: None,
            crawl_summary: None,
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 420,
        })),
    );

    assert_eq!(state.visible_finding_indices.len(), 1_000);

    let backend = TestBackend::new(160, 50);
    let mut terminal = Terminal::new(backend).expect("create test terminal");

    let start = Instant::now();
    for view in WorkbenchView::ALL {
        state.active_view = view;
        terminal
            .draw(|frame| render(frame, &state))
            .expect("render view");
    }
    for cat in EvidenceCategory::ALL {
        state.active_view = WorkbenchView::Evidence;
        state.evidence_category = cat;
        terminal
            .draw(|frame| render(frame, &state))
            .expect("render evidence category");
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(500),
        "rendering all 9 views and all 19 evidence categories took {elapsed:?}"
    );
}

#[test]
fn terminal_security_strips_hostile_escape_sequences_and_redacts_secrets_in_buffer() {
    let target = AuditTarget::parse("https://example.org/callback", TargetPolicy::AllowPrivate)
        .expect("valid target");

    let rule_id = RuleId("sec.test.hostile".to_owned());
    let hostile_finding = Finding {
        fingerprint: FindingFingerprint::compute(target.host(), &rule_id, "hostile"),
        rule_id,
        category: FindingCategory::Security,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::High,
        confidence: Confidence::High,
        title: "Hostile \x1b[31mANSI\x1b[0m \x1b]52;c;ZWNobyBoYWNrZWQ=\x07 \u{202e}BidirectionalTitle".to_owned(),
        summary: "Hostile \x1b[31mANSI\x1b[0m \x1b]52;c;ZWNobyBoYWNrZWQ=\x07 \u{202e}BidirectionalTitle \rOverwrite\x08".to_owned(),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            "Location: https://example.org/login?api_key=leak-me-not\x1b]0;PwnedTitle\x07",
        )],
        remediation: Some("Sanitize untrusted strings.".to_owned()),
    };

    let report = AuditReport {
        schema_version: "0.2.0".to_owned(),
        target,
        captured_at_unix_secs: 1_764_000_200,
        http: CollectorOutcome::Skipped {
            reason: "security fixture".to_owned(),
        },
        level2_collectors: Vec::new(),
        rendered_history: None,
        analysers: vec![AnalyserResult {
            dwarf_id: DwarfId::Sicherheits,
            checks: Vec::new(),
            findings: vec![hostile_finding],
        }],
        summary: AuditSummary {
            critical_findings: 0,
            high_findings: 1,
            medium_findings: 0,
            low_findings: 0,
            info_findings: 0,
            passed_checks: 0,
            failed_checks: 1,
            skipped_checks: 0,
            unavailable_checks: 0,
        },
        ai_synthesis: None,
    };

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    state.launcher.open = false;
    state.ingest_artefacts(DiagnosticArtefacts {
        target: "https://admin:topsecret@example.org/callback?access_token=super-secret-jwt&page=1"
            .to_owned(),
        mode: DiagnosticRunMode::DeterministicCheck,
        snapshot: None,
        audit_report: Some(report),
        investigation_report: None,
        patrol_report: None,
        crawl_summary: None,
        history_reports: Vec::new(),
        regression_report: None,
        elapsed_ms: 15,
    });
    state.active_view = WorkbenchView::Findings;

    let backend = TestBackend::new(140, 40);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal
        .draw(|frame| render(frame, &state))
        .expect("render findings view");

    let text = buffer_text(&terminal);
    assert!(
        !text.contains('\x1b'),
        "ANSI escape sequences must never enter terminal buffer"
    );
    assert!(
        !text.contains('\u{202e}'),
        "BiDi control characters must be stripped"
    );
    assert!(
        !text.contains("ZWNobyBoYWNrZWQ="),
        "OSC 52 payload must be stripped"
    );
    assert!(
        !text.contains("PwnedTitle"),
        "OSC title payload must be stripped"
    );
    assert!(!text.contains("topsecret"), "URL password must be redacted");
    assert!(
        !text.contains("super-secret-jwt"),
        "Sensitive query token must be redacted"
    );
    assert!(
        text.contains("Hostile ANSI"),
        "Readable diagnostic text must remain intact"
    );
}

#[test]
fn responsive_layouts_render_narrow_standard_and_wide_without_panicking() {
    let mut state = AppState::new(ThemeMode::Monochrome, GlyphSet::Ascii);
    state.launcher.open = false;

    let sizes = [
        (60_u16, 18_u16), // below minimum -> fallback message
        (80, 24),         // minimum supported
        (100, 30),        // narrow/standard
        (120, 40),        // standard two-panel
        (160, 50),        // wide layout
        (200, 60),        // extra-wide layout
    ];

    for (w, h) in sizes {
        let _ = reduce(&mut state, AppAction::Resize(w, h));
        let backend = TestBackend::new(w, h);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        for view in WorkbenchView::ALL {
            state.active_view = view;
            terminal
                .draw(|frame| render(frame, &state))
                .expect("render view at responsive size");
        }
    }
}

#[tokio::test]
async fn cancelled_run_stops_before_acquisition() {
    let target =
        AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).expect("target");
    let (sink, _events) = diagnostic_event_channel(RunId::new("run-cancel"));
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    cancel_tx.send(true).expect("pre-cancel the run");

    let spec = RunLaunchSpec {
        target,
        mode: DiagnosticRunMode::DeterministicCheck,
        enable_browser: true,
        enable_axe: true,
        enable_lighthouse: true,
        provider: netzzwergenwacht::config::ProviderKind::OpenAi,
        model: String::new(),
        evidence_dir: std::path::PathBuf::from(".nzw/evidence"),
        max_pages: 10,
        max_depth: 1,
    };
    let outcome = execute_diagnostic_run_cancellable(
        spec,
        TargetPolicy::PublicOnly,
        ExecutionBudget::default(),
        String::from("cancel probe"),
        sink,
        cancel_rx,
        std::path::Path::new(".nzw/memory"),
        std::sync::Arc::new(netzzwergenwacht::intelligence::EmptyProviderRouter),
    )
    .await;

    let error = outcome.expect_err("a pre-cancelled run must not complete");
    assert!(
        error.contains("cancelled by operator"),
        "unexpected cancellation error: {error}"
    );
}

#[test]
fn workbench_patrol_memory_defaults_to_the_shared_directory() {
    let options = netzzwergenwacht::tui::TuiStartupOptions::default();
    assert_eq!(
        options.memory_dir,
        std::path::PathBuf::from(netzzwergenwacht::patrol::memory::DEFAULT_MEMORY_DIR),
        "the workbench must continue the same patrol memory as the CLI"
    );
}

fn render_state(state: &AppState) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 32)).expect("test terminal");
    terminal
        .draw(|frame| render(frame, state))
        .expect("render workbench");
    buffer_text(&terminal)
}

#[test]
fn launcher_exposes_provider_model_and_session_credential() {
    let state = AppState::default();
    let text = render_state(&state);
    for expected in [
        "Provider",
        "Model",
        "Credential (session only)",
        "Test connection",
    ] {
        assert!(
            text.contains(expected),
            "launcher must expose `{expected}`: {text}"
        );
    }
}

#[test]
fn mission_review_summarises_the_route_without_secrets() {
    let mut state = AppState::default();
    state.launcher.open = false;
    state.review_open = true;
    state.config_source = Some("built-in defaults".to_owned());

    let text = render_state(&state);
    assert!(text.contains("MISSION REVIEW"), "review overlay missing");
    assert!(
        text.contains("session only"),
        "review must state that credentials are session-only"
    );
}

#[tokio::test]
async fn agentic_investigation_without_a_kommandant_model_fails_explicitly() {
    let target =
        AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).expect("target");
    let (sink, _events) = diagnostic_event_channel(RunId::new("run-no-model"));
    let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let spec = RunLaunchSpec {
        target,
        mode: DiagnosticRunMode::AgenticInvestigation,
        enable_browser: false,
        enable_axe: false,
        enable_lighthouse: false,
        provider: netzzwergenwacht::config::ProviderKind::OpenAi,
        model: String::new(),
        evidence_dir: std::path::PathBuf::from(".nzw/evidence"),
        max_pages: 10,
        max_depth: 1,
    };

    let outcome = execute_diagnostic_run_cancellable(
        spec,
        TargetPolicy::PublicOnly,
        ExecutionBudget::default(),
        String::from("agentic probe"),
        sink,
        cancel_rx,
        std::path::Path::new(".nzw/memory"),
        std::sync::Arc::new(netzzwergenwacht::intelligence::EmptyProviderRouter),
    )
    .await;

    let error = outcome.expect_err("an unconfigured agentic run must not start");
    assert!(
        error.contains("needs a model configured for KommandantZwerg"),
        "unexpected error: {error}"
    );
}

/// Serves a two-page application so the reconnaissance crawl has something to discover.
async fn spawn_crawl_fixture() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0_u8; 2048];
            let read = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            let body = if request.contains("GET /second") {
                "<!doctype html><html><head><title>Second page</title></head><body><h1>Two</h1></body></html>"
            } else {
                "<!doctype html><html><head><title>Reconnaissance fixture</title>\
                 <link rel=\"stylesheet\" href=\"/shared.css\"></head>\
                 <body><h1>One</h1><a href=\"/second\">Second</a></body></html>"
            };
            let content_type = if request.contains("shared.css") {
                "text/css"
            } else {
                "text/html; charset=utf-8"
            };
            let payload = if request.contains("shared.css") {
                String::from("body { color: #111; }")
            } else {
                body.to_owned()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn reconnaissance_crawl_mode_retains_evidence_and_populates_surface() {
    let target_str = spawn_crawl_fixture().await;
    let policy = TargetPolicy::AllowPrivate;
    let target = AuditTarget::parse(&target_str, policy).expect("valid loopback url");
    let evidence_dir = std::env::temp_dir().join(format!(
        "nzw-scan-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));

    let spec = RunLaunchSpec {
        target,
        mode: DiagnosticRunMode::ReconnaissanceCrawl,
        enable_browser: false,
        enable_axe: false,
        enable_lighthouse: false,
        provider: netzzwergenwacht::config::ProviderKind::OpenAi,
        model: String::new(),
        evidence_dir: evidence_dir.clone(),
        max_pages: 5,
        max_depth: 1,
    };

    let (sink, _rx) = diagnostic_event_channel(RunId::new("run-scan"));
    let artefacts = execute_diagnostic_run_cancellable(
        spec,
        policy,
        ExecutionBudget::default(),
        String::from("Reconnaissance"),
        sink,
        tokio::sync::watch::channel(false).1,
        std::path::Path::new(netzzwergenwacht::patrol::memory::DEFAULT_MEMORY_DIR),
        std::sync::Arc::new(netzzwergenwacht::intelligence::EmptyProviderRouter),
    )
    .await
    .expect("execute reconnaissance crawl");

    let crawl = artefacts
        .crawl_summary
        .as_ref()
        .expect("crawl summary retained");
    assert_eq!(artefacts.mode, DiagnosticRunMode::ReconnaissanceCrawl);
    assert_eq!(
        crawl.coverage.discovered_urls, 2,
        "seed plus one discovered link"
    );
    assert_eq!(crawl.coverage.analysed_urls, 2);
    assert_eq!(crawl.coverage.failed_urls, 0);
    assert_eq!(crawl.coverage.resources.fetched_resources, 1);

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    state.ingest_artefacts(artefacts);
    assert_eq!(state.target_rows.len(), 2);
    assert_eq!(state.run_mode, DiagnosticRunMode::ReconnaissanceCrawl);
    assert!(state.crawl_summary.is_some());

    let store_path = evidence_dir.join("evidence.db");
    assert!(
        store_path.exists(),
        "evidence store written to {}",
        store_path.display()
    );
    let store = netzzwergenwacht::evidence_store::EvidenceStore::open(&store_path)
        .await
        .expect("reopen evidence store");
    let runs = store.runs(8).await.expect("list stored runs");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].discovered_urls, 2);
    let coverage = store
        .coverage(&runs[0].run_id)
        .await
        .expect("read coverage")
        .expect("coverage present");
    assert_eq!(coverage.analysed_urls, 2);

    let _ = std::fs::remove_dir_all(&evidence_dir);
}
