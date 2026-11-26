//! Asynchronous event loop, background diagnostic runner, and file loader for Zwergenleitstand.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::adapters;
use crate::analysis::{self, AuditReport};
use crate::budget::ExecutionBudget;
use crate::collection;
use crate::config::IntelligenceFileConfig;
use crate::domain::{
    AuditTarget, CollectorOutcome, EvidenceSnapshot, TargetPolicy, TargetUrl, ValidationError,
};
use crate::events::{
    CollectorId, DiagnosticEventPayload, DiagnosticEventReceiver, DiagnosticEventSink,
    DiagnosticRunMode, EventContext, RunId, diagnostic_event_channel,
};
use crate::intelligence::IntelligenceConfig;
use crate::investigation::{
    self, InvestigationBudget, InvestigationReport, LiveCollectorBackend,
    RigInvestigationSpecialists,
};
use crate::patrol::{self, PatrolBudget, PatrolMemory, PatrolReport};
use crate::persistence;
use crate::tui::action::{AppAction, AppEffect, RunLaunchSpec};
use crate::tui::keymap::translate_key_event;
use crate::tui::reducer::reduce;
use crate::tui::state::{AppState, DiagnosticArtefacts, RunLifecycleState};
use crate::tui::terminal::TerminalSession;
use crate::tui::theme::{GlyphSet, ThemeMode};
use crate::tui::views::render;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Startup configuration passed from the CLI (`nzw tui` or `--tui`) into the workbench runtime.
#[derive(Debug, Clone)]
pub struct TuiStartupOptions {
    /// Optional initial target URL. If `Some` and no report/history path is provided, starts immediately.
    pub target: Option<String>,
    /// Initial run mode when launching a live run.
    pub mode: DiagnosticRunMode,
    /// Enable Level 2 headless browser collection.
    pub enable_browser: bool,
    /// Enable Level 2 `axe-core` collection.
    pub enable_axe: bool,
    /// Enable Level 2 Lighthouse collection.
    pub enable_lighthouse: bool,
    /// Optional path to an existing JSON report (`AuditReport`, `InvestigationReport`, or `PatrolReport`).
    pub report_path: Option<PathBuf>,
    /// Optional path to a JSONL audit history file for offline regression inspection.
    pub history_path: Option<PathBuf>,
    /// Optional default output path for saving reports (`w`).
    pub output_path: Option<PathBuf>,
    /// Target validation policy (e.g. `--allow-local`).
    pub policy: TargetPolicy,
    /// Execution budget governing network, browser, and LLM limits.
    pub budget: ExecutionBudget,
    /// Investigation objective for `AgenticInvestigation` mode.
    pub objective: String,
    /// Optional explicitly forced theme mode (`--monochrome` or `--high-contrast`).
    pub theme_mode: Option<ThemeMode>,
    /// Force ASCII-only borders and indicators (`--ascii`).
    pub ascii_only: bool,
    /// Optional loaded `[intelligence]` configuration section.
    pub intelligence_file: Option<IntelligenceFileConfig>,
}

impl Default for TuiStartupOptions {
    fn default() -> Self {
        Self {
            target: None,
            mode: DiagnosticRunMode::DeterministicCheck,
            enable_browser: false,
            enable_axe: false,
            enable_lighthouse: false,
            report_path: None,
            history_path: None,
            output_path: None,
            policy: TargetPolicy::default(),
            budget: ExecutionBudget::default(),
            objective: String::from(
                "Identify high-impact web quality, reliability, accessibility, and security issues",
            ),
            theme_mode: None,
            ascii_only: false,
            intelligence_file: None,
        }
    }
}

/// Loads an offline JSON report (`AuditReport`, `InvestigationReport`, or `PatrolReport`) into [`DiagnosticArtefacts`].
///
/// # Errors
///
/// Returns an error string if the file cannot be read or does not match any known report schema.
pub fn load_offline_report(path: &Path) -> Result<DiagnosticArtefacts, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read report {}: {err}", path.display()))?;

    if let Ok(audit_report) = serde_json::from_str::<AuditReport>(&raw) {
        return Ok(DiagnosticArtefacts {
            target: audit_report.target.as_str().to_owned(),
            mode: DiagnosticRunMode::OfflineExploration,
            snapshot: None,
            audit_report: Some(audit_report),
            investigation_report: None,
            patrol_report: None,
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 0,
        });
    }

    if let Ok(inv_report) = serde_json::from_str::<InvestigationReport>(&raw) {
        return Ok(DiagnosticArtefacts {
            target: inv_report.target.as_str().to_owned(),
            mode: DiagnosticRunMode::AgenticInvestigation,
            snapshot: None,
            audit_report: Some(inv_report.initial_report.clone()),
            investigation_report: Some(inv_report),
            patrol_report: None,
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 0,
        });
    }

    if let Ok(patrol_report) = serde_json::from_str::<PatrolReport>(&raw) {
        let target = patrol_report
            .targets
            .first()
            .cloned()
            .unwrap_or_else(|| String::from("https://example.org"));
        let first_inv = patrol_report.escalated_investigations.first().cloned();
        let first_audit = first_inv
            .as_ref()
            .map(|inv| inv.initial_report.clone())
            .or_else(|| patrol_report.entry_report.clone());
        return Ok(DiagnosticArtefacts {
            target,
            mode: DiagnosticRunMode::AutonomousPatrol,
            snapshot: None,
            audit_report: first_audit,
            investigation_report: first_inv,
            patrol_report: Some(patrol_report),
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 0,
        });
    }

    Err(format!(
        "{} is not a valid AuditReport, InvestigationReport, or PatrolReport JSON document",
        path.display()
    ))
}

/// Loads a JSONL audit history file into [`DiagnosticArtefacts`] and computes the latest regression diff.
///
/// # Errors
///
/// Returns an error string if the history file cannot be read or parsed.
pub fn load_offline_history(path: &Path) -> Result<DiagnosticArtefacts, String> {
    let reports = persistence::load_history(path)
        .map_err(|err| format!("failed to load history {}: {err}", path.display()))?;
    let latest = reports.last().cloned();
    let target = latest.as_ref().map_or_else(
        || String::from("https://example.org"),
        |r| r.target.as_str().to_owned(),
    );
    let regression_report = if reports.len() >= 2 {
        Some(persistence::diff_history(&reports))
    } else {
        None
    };

    Ok(DiagnosticArtefacts {
        target,
        mode: DiagnosticRunMode::OfflineExploration,
        snapshot: None,
        audit_report: latest,
        investigation_report: None,
        patrol_report: None,
        history_reports: reports,
        regression_report,
        elapsed_ms: 0,
    })
}

/// Saves the current [`AuditReport`] from [`AppState`] to the target JSON path.
///
/// # Errors
///
/// Returns an error string if no report is available in state or if writing to disk fails.
pub fn save_current_report(state: &AppState, path: &Path) -> Result<PathBuf, String> {
    let report = state
        .audit_report
        .as_ref()
        .ok_or_else(|| String::from("no completed audit report available to save"))?;
    persistence::save_report(path, report)
        .map_err(|err| format!("failed to save report to {}: {err}", path.display()))?;
    Ok(path.to_path_buf())
}

/// Builds the initial [`AppState`] and optional startup [`AppEffect`] from [`TuiStartupOptions`].
///
/// # Errors
///
/// Returns an error string if an explicitly requested `--report`, `--history`, or startup URL fails validation.
pub fn initialize_state(options: &TuiStartupOptions) -> Result<(AppState, Vec<AppEffect>), String> {
    let theme_mode = options
        .theme_mode
        .unwrap_or_else(ThemeMode::detect_from_env);
    let glyphs = if options.ascii_only {
        GlyphSet::Ascii
    } else {
        GlyphSet::detect_from_env()
    };

    let mut state = AppState::new(theme_mode, glyphs);
    state.output_path.clone_from(&options.output_path);
    state.launcher.mode = options.mode;
    state.launcher.enable_browser = options.enable_browser;
    state.launcher.enable_axe = options.enable_axe;
    state.launcher.enable_lighthouse = options.enable_lighthouse;

    if let Some(target) = &options.target {
        state.launcher.target_input.clone_from(target);
        state.target_url.clone_from(target);
    }

    if let Some(report_path) = &options.report_path {
        let mut artefacts = load_offline_report(report_path)?;
        if let Some(history_path) = &options.history_path {
            let hist = load_offline_history(history_path)?;
            artefacts.history_reports = hist.history_reports;
            artefacts.regression_report = hist.regression_report;
        }
        state.launcher.open = false;
        state.ingest_artefacts(artefacts);
        state.status_message = format!("Loaded offline report from {}", report_path.display());
        return Ok((state, Vec::new()));
    }

    if let Some(history_path) = &options.history_path {
        let artefacts = load_offline_history(history_path)?;
        state.launcher.open = false;
        state.ingest_artefacts(artefacts);
        state.active_view = crate::tui::state::WorkbenchView::History;
        state.status_message = format!("Loaded audit history from {}", history_path.display());
        return Ok((state, Vec::new()));
    }

    if let Some(raw_target) = &options.target {
        let validated = parse_target_with_policy(raw_target, &options.policy)
            .map_err(|err| format!("invalid target URL '{raw_target}': {err}"))?;
        state.launcher.open = false;
        state.lifecycle = RunLifecycleState::Starting;
        state.target_url = validated.as_str().to_owned();
        state.run_mode = options.mode;
        let spec = RunLaunchSpec {
            target: validated,
            mode: options.mode,
            enable_browser: options.enable_browser,
            enable_axe: options.enable_axe,
            enable_lighthouse: options.enable_lighthouse,
        };
        return Ok((state, vec![AppEffect::StartRun(spec)]));
    }

    Ok((state, Vec::new()))
}

fn parse_target_with_policy(
    raw: &str,
    policy: &TargetPolicy,
) -> Result<AuditTarget, ValidationError> {
    let url = TargetUrl::parse_with_policy(raw, policy)?;
    Ok(AuditTarget::from(url))
}

struct ActiveBackgroundTask {
    handle: JoinHandle<()>,
    event_rx: DiagnosticEventReceiver,
    result_rx: mpsc::Receiver<Result<DiagnosticArtefacts, String>>,
}

/// Runs the interactive Zwergenleitstand TUI session until the operator exits.
///
/// # Errors
///
/// Returns an `io::Error` if terminal setup, rendering, or startup report loading fails.
pub async fn run_tui(options: TuiStartupOptions) -> io::Result<()> {
    let (mut state, initial_effects) = initialize_state(&options)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;

    let mut session = TerminalSession::enter()?;
    if let Ok(size) = session.terminal_mut().size() {
        state.terminal_width = size.width;
        state.terminal_height = size.height;
    }

    let mut active_task: Option<ActiveBackgroundTask> = None;
    let mut pending_effects = initial_effects;
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);

    loop {
        while let Some(effect) = pending_effects.pop() {
            match effect {
                AppEffect::StartRun(spec) => {
                    if let Some(prev) = active_task.take() {
                        prev.handle.abort();
                    }
                    let seq = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                    let run_id = RunId::new(format!("run-{seq:04}"));
                    state.active_run_id = Some(run_id.as_str().to_owned());
                    active_task = Some(spawn_background_run(
                        run_id,
                        spec,
                        options.policy.clone(),
                        options.budget.clone(),
                        options.objective.clone(),
                        options.intelligence_file.clone(),
                    ));
                }
                AppEffect::CancelActiveRun => {
                    if let Some(prev) = active_task.take() {
                        prev.handle.abort();
                    }
                }
                AppEffect::SaveReport(path) => {
                    let res = save_current_report(&state, &path);
                    let follow_up = reduce(&mut state, AppAction::ReportSaved(res));
                    pending_effects.extend(follow_up);
                }
                AppEffect::Quit => {
                    if let Some(prev) = active_task.take() {
                        prev.handle.abort();
                    }
                    return Ok(());
                }
            }
        }

        if state.should_quit {
            if let Some(prev) = active_task.take() {
                prev.handle.abort();
            }
            return Ok(());
        }

        // Drain bounded diagnostic events from active background run.
        if let Some(task) = &mut active_task {
            let mut drained = 0_usize;
            while drained < 64 {
                match task.event_rx.try_recv() {
                    Ok(ev) => {
                        drained += 1;
                        let effs = reduce(&mut state, AppAction::Diagnostic(Box::new(ev)));
                        pending_effects.extend(effs);
                    }
                    Err(
                        mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected,
                    ) => {
                        break;
                    }
                }
            }

            match task.result_rx.try_recv() {
                Ok(Ok(artefacts)) => {
                    let effs = reduce(&mut state, AppAction::RunFinished(Box::new(artefacts)));
                    pending_effects.extend(effs);
                    active_task = None;
                }
                Ok(Err(err_msg)) => {
                    let effs = reduce(&mut state, AppAction::RunFailed(err_msg));
                    pending_effects.extend(effs);
                    active_task = None;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if matches!(
                        state.lifecycle,
                        RunLifecycleState::Starting | RunLifecycleState::Running
                    ) {
                        let effs = reduce(
                            &mut state,
                            AppAction::RunFailed(String::from(
                                "background diagnostic task terminated unexpectedly",
                            )),
                        );
                        pending_effects.extend(effs);
                    }
                    active_task = None;
                }
            }
        }

        session.terminal_mut().draw(|frame| render(frame, &state))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if let Some(user_action) = translate_key_event(key, &state) {
                        let effs = reduce(&mut state, AppAction::User(user_action));
                        pending_effects.extend(effs);
                    }
                }
                Event::Resize(w, h) => {
                    let effs = reduce(&mut state, AppAction::Resize(w, h));
                    pending_effects.extend(effs);
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            let effs = reduce(&mut state, AppAction::Tick);
            pending_effects.extend(effs);
            last_tick = Instant::now();
        }
    }
}

fn spawn_background_run(
    run_id: RunId,
    spec: RunLaunchSpec,
    policy: TargetPolicy,
    budget: ExecutionBudget,
    objective: String,
    intelligence_file: Option<IntelligenceFileConfig>,
) -> ActiveBackgroundTask {
    let (sink, event_rx) = diagnostic_event_channel(run_id);
    let (result_tx, result_rx) = mpsc::channel(1);

    let handle = tokio::spawn(async move {
        let outcome =
            execute_diagnostic_run(spec, policy, budget, objective, intelligence_file, sink).await;
        let _ = result_tx.send(outcome).await;
    });

    ActiveBackgroundTask {
        handle,
        event_rx,
        result_rx,
    }
}

/// Executes a diagnostic run in the background and streams typed [`crate::events::DiagnosticEvent`]s.
///
/// # Errors
///
/// Returns an error string if target resolution or mandatory execution steps fail.
pub async fn execute_diagnostic_run(
    spec: RunLaunchSpec,
    policy: TargetPolicy,
    budget: ExecutionBudget,
    objective: String,
    intelligence_file: Option<IntelligenceFileConfig>,
    sink: DiagnosticEventSink,
) -> Result<DiagnosticArtefacts, String> {
    let start = Instant::now();
    let target_str = spec.target.as_str().to_owned();
    let target_url = TargetUrl::parse_with_policy(&target_str, &policy)
        .map_err(|err| format!("target blocked by policy: {err}"))?;

    sink.emit_critical(
        EventContext::for_target(&target_str),
        DiagnosticEventPayload::RunStarted {
            mode: spec.mode,
            target: target_str.clone(),
        },
    );

    match spec.mode {
        DiagnosticRunMode::DeterministicCheck | DiagnosticRunMode::OfflineExploration => {
            let snapshot =
                collect_snapshot_with_events(&target_url, &spec, &budget, &policy, &sink).await;

            let report = analysis::run_all_with_events(&snapshot, Some(&sink));
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            sink.emit_critical(
                EventContext::for_target(&target_str),
                DiagnosticEventPayload::RunCompleted {
                    total_findings: report.summary.total_findings,
                    elapsed_ms,
                },
            );

            Ok(DiagnosticArtefacts {
                target: target_str,
                mode: DiagnosticRunMode::DeterministicCheck,
                snapshot: Some(snapshot),
                audit_report: Some(report),
                investigation_report: None,
                patrol_report: None,
                history_reports: Vec::new(),
                regression_report: None,
                elapsed_ms,
            })
        }
        DiagnosticRunMode::AgenticInvestigation => {
            let intel_config =
                IntelligenceConfig::from_env_and_file(None, intelligence_file.as_ref());
            if let Some(config) = intel_config {
                let specialists = RigInvestigationSpecialists::new(config);
                let backend = Arc::new(LiveCollectorBackend::with_policy(policy.clone()));
                let inv_budget = InvestigationBudget::default();
                let inv_report = investigation::run_investigation_with_events(
                    &target_url,
                    &objective,
                    &budget,
                    &policy,
                    &inv_budget,
                    &specialists,
                    backend,
                    None,
                    Some(&sink),
                )
                .await;

                let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                Ok(DiagnosticArtefacts {
                    target: target_str,
                    mode: DiagnosticRunMode::AgenticInvestigation,
                    snapshot: None,
                    audit_report: Some(inv_report.initial_report.clone()),
                    investigation_report: Some(inv_report),
                    patrol_report: None,
                    history_reports: Vec::new(),
                    regression_report: None,
                    elapsed_ms,
                })
            } else {
                sink.emit_critical(
                    EventContext::for_target(&target_str),
                    DiagnosticEventPayload::Warning {
                        message: String::from(
                            "No LLM provider configured; falling back to deterministic brigade audit.",
                        ),
                    },
                );
                let snapshot =
                    collect_snapshot_with_events(&target_url, &spec, &budget, &policy, &sink).await;
                let report = analysis::run_all_with_events(&snapshot, Some(&sink));
                let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
                sink.emit_critical(
                    EventContext::for_target(&target_str),
                    DiagnosticEventPayload::RunPartiallyCompleted {
                        reason: String::from(
                            "Agent provider unavailable; deterministic diagnostics completed",
                        ),
                        total_findings: report.summary.total_findings,
                        elapsed_ms,
                    },
                );
                Ok(DiagnosticArtefacts {
                    target: target_str,
                    mode: DiagnosticRunMode::AgenticInvestigation,
                    snapshot: Some(snapshot),
                    audit_report: Some(report),
                    investigation_report: None,
                    patrol_report: None,
                    history_reports: Vec::new(),
                    regression_report: None,
                    elapsed_ms,
                })
            }
        }
        DiagnosticRunMode::AutonomousPatrol => {
            sink.emit_critical(
                EventContext::for_target(&target_str).with_collector(CollectorId::Http),
                DiagnosticEventPayload::CollectionStarted {
                    collector: CollectorId::Http,
                },
            );
            let patrol_budget = PatrolBudget {
                enable_level2: spec.enable_browser,
                ..PatrolBudget::default()
            };
            let mut memory = PatrolMemory::default();
            let patrol_report = patrol::run_patrol(
                &[target_url.clone()],
                &budget,
                &policy,
                &patrol_budget,
                &mut memory,
                None,
                None,
            )
            .await;

            for page in &patrol_report.application_map.pages {
                sink.emit_critical(
                    EventContext::for_target(&target_str).with_page(page.url.clone()),
                    DiagnosticEventPayload::TargetDiscovered {
                        url: page.url.clone(),
                        source: format!("{:?}", page.discovery_source),
                        depth: page.depth,
                    },
                );
            }

            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let first_audit = patrol_report.entry_report.clone();
            let total_findings = first_audit
                .as_ref()
                .map_or(patrol_report.anomalies.len(), |r| r.summary.total_findings);

            sink.emit_critical(
                EventContext::for_target(&target_str),
                DiagnosticEventPayload::RunCompleted {
                    total_findings,
                    elapsed_ms,
                },
            );

            Ok(DiagnosticArtefacts {
                target: target_str,
                mode: DiagnosticRunMode::AutonomousPatrol,
                snapshot: None,
                audit_report: first_audit,
                investigation_report: patrol_report.escalated_investigations.first().cloned(),
                patrol_report: Some(patrol_report),
                history_reports: Vec::new(),
                regression_report: None,
                elapsed_ms,
            })
        }
    }
}

async fn collect_snapshot_with_events(
    target_url: &TargetUrl,
    spec: &RunLaunchSpec,
    budget: &ExecutionBudget,
    policy: &TargetPolicy,
    sink: &DiagnosticEventSink,
) -> EvidenceSnapshot {
    let target_str = target_url.as_str();

    sink.emit_critical(
        EventContext::for_target(target_str).with_collector(CollectorId::Http),
        DiagnosticEventPayload::CollectionStarted {
            collector: CollectorId::Http,
        },
    );
    let http = collection::collect_http(target_url, budget, policy).await;
    emit_collector_outcome(sink, target_str, CollectorId::Http, &http);

    let tls = if target_url.scheme() == "https" {
        sink.emit_critical(
            EventContext::for_target(target_str).with_collector(CollectorId::Tls),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Tls,
            },
        );
        let outcome = collection::collect_tls(target_url, budget, policy).await;
        emit_collector_outcome(sink, target_str, CollectorId::Tls, &outcome);
        outcome
    } else {
        let reason = String::from("target uses http scheme");
        sink.emit_critical(
            EventContext::for_target(target_str).with_collector(CollectorId::Tls),
            DiagnosticEventPayload::CollectionSkipped {
                collector: CollectorId::Tls,
                reason: reason.clone(),
            },
        );
        CollectorOutcome::Skipped { reason }
    };

    let browser = if spec.enable_browser {
        sink.emit_critical(
            EventContext::for_target(target_str).with_collector(CollectorId::Browser),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Browser,
            },
        );
        let outcome = adapters::browser::collect_browser_with_policy(
            target_url,
            budget.browser_timeout,
            policy,
        )
        .await;
        emit_collector_outcome(sink, target_str, CollectorId::Browser, &outcome);
        outcome
    } else {
        CollectorOutcome::Skipped {
            reason: String::from("not collected"),
        }
    };

    let lighthouse = if spec.enable_lighthouse {
        sink.emit_critical(
            EventContext::for_target(target_str).with_collector(CollectorId::Lighthouse),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Lighthouse,
            },
        );
        let outcome = adapters::lighthouse::collect_lighthouse_with_policy(
            target_url,
            budget.browser_timeout,
            policy,
        )
        .await;
        emit_collector_outcome(sink, target_str, CollectorId::Lighthouse, &outcome);
        outcome
    } else {
        CollectorOutcome::Skipped {
            reason: String::from("not collected"),
        }
    };

    let axe = if spec.enable_axe {
        sink.emit_critical(
            EventContext::for_target(target_str).with_collector(CollectorId::Axe),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Axe,
            },
        );
        let outcome =
            adapters::axe::collect_axe_with_policy(target_url, budget.browser_timeout, policy)
                .await;
        emit_collector_outcome(sink, target_str, CollectorId::Axe, &outcome);
        outcome
    } else {
        CollectorOutcome::Skipped {
            reason: String::from("not collected"),
        }
    };

    let captured_at_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    EvidenceSnapshot {
        target: target_url.clone(),
        captured_at_unix_secs,
        http,
        tls,
        browser,
        lighthouse,
        axe,
    }
}

fn emit_collector_outcome<T>(
    sink: &DiagnosticEventSink,
    target_str: &str,
    collector: CollectorId,
    outcome: &CollectorOutcome<T>,
) {
    let ctx = EventContext::for_target(target_str).with_collector(collector);
    match outcome {
        CollectorOutcome::Captured(_) => {
            sink.emit_critical(
                ctx,
                DiagnosticEventPayload::CollectionCompleted {
                    collector,
                    partial: false,
                    warnings: Vec::new(),
                },
            );
        }
        CollectorOutcome::Partial { warnings, .. } => {
            sink.emit_critical(
                ctx,
                DiagnosticEventPayload::CollectionCompleted {
                    collector,
                    partial: true,
                    warnings: warnings.clone(),
                },
            );
        }
        CollectorOutcome::Failed { error } => {
            sink.emit_critical(
                ctx,
                DiagnosticEventPayload::CollectionFailed {
                    collector,
                    error: error.clone(),
                },
            );
        }
        CollectorOutcome::Skipped { reason } | CollectorOutcome::Unavailable { reason } => {
            sink.emit_critical(
                ctx,
                DiagnosticEventPayload::CollectionSkipped {
                    collector,
                    reason: reason.clone(),
                },
            );
        }
    }
}
