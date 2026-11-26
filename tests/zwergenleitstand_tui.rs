//! End-to-end, security, layout, and operational performance integration tests for Zwergenleitstand (`nzw tui`).

use std::time::{Duration, Instant};

use netzzwergenwacht::analysis::{self, AnalyserResult, AuditReport, AuditSummary};
use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::budget::ExecutionBudget;
use netzzwergenwacht::collection;
use netzzwergenwacht::domain::{
    AuditTarget, BrowserEvidence, BrowserResourceMetric, CollectorOutcome, Confidence,
    DiagnosticCategory, EvidenceRef, EvidenceSnapshot, EvidenceSource, Finding, Measurement,
    RuleId, Severity, TargetPolicy, TargetUrl,
};
use netzzwergenwacht::events::{
    CollectorId, DiagnosticEventPayload, DiagnosticRunMode, EventContext, RunId,
    diagnostic_event_channel,
};
use netzzwergenwacht::persistence;
use netzzwergenwacht::tui::{
    AppAction, AppEffect, AppState, DiagnosticArtefacts, EvidenceCategory, GlyphSet, RunLaunchSpec,
    RunLifecycleState, ThemeMode, UserAction, WorkbenchView, execute_diagnostic_run,
    load_offline_history, load_offline_report, reduce, render, save_current_report,
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
async fn vertical_slice_live_deterministic_audit_to_tui_evidence_and_saved_report() {
    let target_str = spawn_fixture_http_server().await;
    let policy = TargetPolicy {
        allow_private_networks: true,
        allow_http: true,
        ..TargetPolicy::default()
    };
    let target_url =
        TargetUrl::parse_with_policy(&target_str, &policy).expect("valid loopback url");
    let audit_target = AuditTarget::from(target_url);
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
    };

    let artefacts = execute_diagnostic_run(
        spec,
        policy,
        budget,
        String::from("Verify vertical slice"),
        None,
        sink,
    )
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

    assert_eq!(state.lifecycle, RunLifecycleState::Exploring);
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
    persistence::append_history(&history_path, saved_report).expect("append history jsonl");
    let hist_artefacts = load_offline_history(&history_path).expect("load history jsonl");
    assert_eq!(hist_artefacts.history_reports.len(), 1);
    assert!(hist_artefacts.regression_report.is_none());

    let _ = std::fs::remove_file(&report_path);
    let _ = std::fs::remove_file(&history_path);
}

#[test]
fn operational_performance_handles_thousand_findings_and_rapid_events_under_budget() {
    let policy = TargetPolicy {
        allow_private_networks: true,
        allow_http: true,
        ..TargetPolicy::default()
    };
    let target =
        TargetUrl::parse_with_policy("http://127.0.0.1:8080/", &policy).expect("valid target");

    let mut findings = Vec::with_capacity(1_000);
    for idx in 0..1_000_usize {
        findings.push(Finding {
            rule_id: RuleId::new(format!("sec.header.rule_{idx:04}"))
                .expect("valid synthetic rule id"),
            category: DiagnosticCategory::Security,
            dwarf: DwarfId::SicherheitsZwerg,
            severity: if idx % 20 == 0 {
                Severity::Critical
            } else if idx % 5 == 0 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: Confidence::High,
            title: format!("Synthetic security finding #{idx}"),
            description: format!("Detailed diagnostic description for finding #{idx}"),
            remediation: "Apply strict security header policy.".to_owned(),
            evidence: vec![EvidenceRef::new(
                EvidenceSource::HttpHeader,
                format!("x-test-{idx}: missing"),
            )],
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
            dwarf: DwarfId::SicherheitsZwerg,
            category: DiagnosticCategory::Security,
            checks_evaluated: 1_000,
            checks_unavailable: 0,
            findings,
        }],
        summary: AuditSummary {
            total_checks_evaluated: 1_000,
            total_checks_unavailable: 0,
            total_findings: 1_000,
            critical: 50,
            high: 150,
            medium: 800,
            low: 0,
            info: 0,
        },
        ai_synthesis: Measurement::Skipped {
            reason: "not requested".to_owned(),
        },
    };

    let resources = (0..120_u32)
        .map(|idx| BrowserResourceMetric {
            url: format!("https://example.org/assets/chunk-{idx}.js"),
            resource_type: Some("Script".to_owned()),
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
        browser: CollectorOutcome::Captured(BrowserEvidence {
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
            rendered_dom_elements: Vec::new(),
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
        }),
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
        sink.emit_progress(
            EventContext::for_target("https://example.org/"),
            DiagnosticEventPayload::CollectionProgress {
                collector: CollectorId::Browser,
                completed: idx,
                total: Some(500),
                detail: format!("Capturing resource {idx}"),
            },
        );
    }
    assert!(
        sink.dropped_progress_events() > 0,
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
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(250),
        "rendering all 9 views with 1,000 findings and 120 resources took {elapsed:?}"
    );
}

#[test]
fn terminal_security_strips_hostile_escape_sequences_and_redacts_secrets_in_buffer() {
    let policy = TargetPolicy {
        allow_private_networks: true,
        allow_http: true,
        ..TargetPolicy::default()
    };
    let target = TargetUrl::parse_with_policy(
        "https://admin:topsecret@example.org/callback?access_token=super-secret-jwt&page=1",
        &policy,
    )
    .expect("valid target");

    let hostile_finding = Finding {
        rule_id: RuleId::new("sec.test.hostile").expect("valid rule id"),
        category: DiagnosticCategory::Security,
        dwarf: DwarfId::SicherheitsZwerg,
        severity: Severity::High,
        confidence: Confidence::High,
        title:
            "Hostile \x1b[31mANSI\x1b[0m \x1b]52;c;ZWNobyBoYWNrZWQ=\x07 \u{202e}BidirectionalTitle"
                .to_owned(),
        description: "Carriage\rOverwrite and Backspace\x08Attack".to_owned(),
        remediation: "Sanitize untrusted strings.".to_owned(),
        evidence: vec![EvidenceRef::new(
            EvidenceSource::HttpHeader,
            "Location: https://example.org/login?api_key=leak-me-not\x1b]0;PwnedTitle\x07",
        )],
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
            dwarf: DwarfId::SicherheitsZwerg,
            category: DiagnosticCategory::Security,
            checks_evaluated: 1,
            checks_unavailable: 0,
            findings: vec![hostile_finding],
        }],
        summary: AuditSummary {
            total_checks_evaluated: 1,
            total_checks_unavailable: 0,
            total_findings: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
        },
        ai_synthesis: Measurement::Skipped {
            reason: "not requested".to_owned(),
        },
    };

    let mut state = AppState::new(ThemeMode::StandardDark, GlyphSet::Unicode);
    state.launcher.open = false;
    state.ingest_artefacts(DiagnosticArtefacts {
        target: report.target.as_str().to_owned(),
        mode: DiagnosticRunMode::DeterministicCheck,
        snapshot: None,
        audit_report: Some(report),
        investigation_report: None,
        patrol_report: None,
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
