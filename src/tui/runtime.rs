//! Asynchronous event loop, background diagnostic runner, and file loader for Zwergenleitstand.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::adapters;
use crate::analysis::{self, AuditReport};
use crate::collection;
use crate::domain::{
    AuditTarget, CollectorOutcome, EvidenceSnapshot, ExecutionBudget, TargetError, TargetPolicy,
};
use crate::events::{
    CollectorId, DiagnosticEventPayload, DiagnosticEventReceiver, DiagnosticEventSink,
    DiagnosticRunMode, EventContext, RunId, diagnostic_event_channel,
};
use crate::intelligence::ConnectionOutcome;
use crate::investigation::{self, InvestigationBudget, InvestigationReport, LiveDiagnosticBackend};
use crate::patrol::{self, PatrolBudget, PatrolReport};
use crate::persistence;
use crate::tui::action::{AppAction, AppEffect, RunLaunchSpec};
use crate::tui::keymap::translate_key_event;
use crate::tui::reducer::reduce;
use crate::tui::state::{AppState, DiagnosticArtefacts, RunLifecycleState};
use crate::tui::terminal::TerminalSession;
use crate::tui::theme::{GlyphSet, ThemeMode};
use crate::tui::views::render;

static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Time the runtime waits for cooperative shutdown before force-terminating a task.
const CANCELLATION_DEADLINE: Duration = Duration::from_secs(10);

/// Startup configuration passed from the CLI (`nzw tui` or `--tui`) into the workbench runtime.
#[allow(clippy::struct_excessive_bools)]
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
    /// Resolved configuration for this session, when one was loaded or discovered.
    pub config: Option<crate::config::AppConfig>,
    /// Human-readable description of where that configuration came from.
    pub config_source: Option<String>,
    /// Directory for persistent patrol memory. Shared with `nzw patrol` so the
    /// workbench continues the same application history instead of starting fresh.
    pub memory_dir: PathBuf,
    /// Directory for the application-wide evidence store written by reconnaissance crawls.
    pub evidence_dir: PathBuf,
    /// Page bound applied to reconnaissance crawls launched from the workbench.
    pub max_pages: usize,
    /// Link-following depth bound applied to reconnaissance crawls.
    pub max_depth: usize,
    /// Execution budget governing network, browser, and LLM limits.
    pub budget: ExecutionBudget,
    /// Investigation objective for `AgenticInvestigation` mode.
    pub objective: String,
    /// Optional explicitly forced theme mode (`--monochrome` or `--high-contrast`).
    pub theme_mode: Option<ThemeMode>,
    /// Force ASCII-only borders and indicators (`--ascii`).
    pub ascii_only: bool,
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
            config: None,
            config_source: None,
            policy: TargetPolicy::PublicOnly,
            memory_dir: PathBuf::from(crate::patrol::memory::DEFAULT_MEMORY_DIR),
            evidence_dir: PathBuf::from(".nzw/evidence"),
            max_pages: 50,
            max_depth: 2,
            budget: ExecutionBudget::default(),
            objective: String::from(
                "Identify high-impact web quality, reliability, accessibility, and security issues",
            ),
            theme_mode: None,
            ascii_only: false,
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
            crawl_summary: None,
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 0,
        });
    }

    if let Ok(inv_report) = serde_json::from_str::<InvestigationReport>(&raw) {
        return Ok(DiagnosticArtefacts {
            target: inv_report.target.as_str().to_owned(),
            mode: DiagnosticRunMode::AgenticInvestigation,
            snapshot: inv_report.snapshot.clone(),
            audit_report: inv_report.initial_report.clone(),
            investigation_report: Some(inv_report),
            patrol_report: None,
            crawl_summary: None,
            history_reports: Vec::new(),
            regression_report: None,
            elapsed_ms: 0,
        });
    }

    if let Ok(patrol_report) = serde_json::from_str::<PatrolReport>(&raw) {
        let target = patrol_report.target.as_str().to_owned();
        let first_inv = patrol_report.investigation.clone();
        let first_audit = first_inv
            .as_ref()
            .and_then(|inv| inv.initial_report.clone());
        let retained_snapshot = first_inv.as_ref().and_then(|inv| inv.snapshot.clone());
        return Ok(DiagnosticArtefacts {
            target,
            mode: DiagnosticRunMode::AutonomousPatrol,
            snapshot: retained_snapshot,
            audit_report: first_audit,
            investigation_report: first_inv,
            patrol_report: Some(patrol_report),
            crawl_summary: None,
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
    let reports = persistence::load_reports(path)
        .map_err(|err| format!("failed to load history {}: {err}", path.display()))?;
    let latest = reports.last().cloned();
    let target = latest.as_ref().map_or_else(
        || String::from("https://example.org"),
        |r| r.target.as_str().to_owned(),
    );
    let regression_report = if reports.len() >= 2 {
        let prior = &reports[..reports.len() - 1];
        let current = &reports[reports.len() - 1];
        Some(persistence::diff_history(prior, current))
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
        crawl_summary: None,
        history_reports: reports,
        regression_report,
        elapsed_ms: 0,
    })
}

/// Saves the current [`AuditReport`] from [`AppState`] to the target JSONL/JSON path.
///
/// # Errors
///
/// Returns an error string if no report is available in state or if writing to disk fails.
pub fn save_current_report(state: &AppState, path: &Path) -> Result<PathBuf, String> {
    let report = state
        .audit_report
        .as_ref()
        .ok_or_else(|| String::from("no completed audit report available to save"))?;
    persistence::append_report(path, report)
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
    state.launcher.policy = options.policy;
    if let Some(config) = &options.config {
        let kommandant = config
            .models
            .resolve_for_dwarf(crate::brigade::DwarfId::Kommandant);
        state.launcher.provider = kommandant.provider;
        state.launcher.model_input.clone_from(&kommandant.model);
        state.config = Some(config.clone());
    }
    state.config_source.clone_from(&options.config_source);
    state.evidence_dir.clone_from(&options.evidence_dir);
    state.crawl_max_pages = options.max_pages;
    state.crawl_max_depth = options.max_depth;

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
        let validated = parse_target_with_policy(raw_target, options.policy)
            .map_err(|err| format!("invalid target URL '{raw_target}': {err}"))?;
        state.launcher.open = false;
        state.lifecycle = RunLifecycleState::Running;
        validated.as_str().clone_into(&mut state.target_url);
        state.run_mode = options.mode;
        let spec = RunLaunchSpec {
            provider: crate::config::ProviderKind::OpenAi,
            model: String::new(),
            target: validated,
            mode: options.mode,
            enable_browser: options.enable_browser,
            enable_axe: options.enable_axe,
            enable_lighthouse: options.enable_lighthouse,
            evidence_dir: options.evidence_dir.clone(),
            max_pages: options.max_pages,
            max_depth: options.max_depth,
        };
        return Ok((state, vec![AppEffect::StartRun(spec)]));
    }

    Ok((state, Vec::new()))
}

fn parse_target_with_policy(raw: &str, policy: TargetPolicy) -> Result<AuditTarget, TargetError> {
    AuditTarget::parse(raw, policy)
}

struct ActiveBackgroundTask {
    handle: JoinHandle<()>,
    event_rx: DiagnosticEventReceiver,
    result_rx: mpsc::Receiver<Result<DiagnosticArtefacts, String>>,
    /// Cooperative cancellation token observed by the background runner.
    cancel: watch::Sender<bool>,
    /// Deadline after which the runtime stops waiting for a cooperative shutdown.
    cancel_deadline: Option<Instant>,
}

impl ActiveBackgroundTask {
    /// Requests cooperative cancellation and arms the escalation deadline.
    ///
    /// The task is not aborted here: the runtime only reports `Cancelled` once the
    /// join handle finishes, so child processes and browser sessions are confirmed
    /// gone rather than merely assumed to be.
    fn request_cancellation(&mut self) {
        let _ = self.cancel.send(true);
        self.cancel_deadline = Some(Instant::now() + CANCELLATION_DEADLINE);
    }
}

/// Runs the interactive Zwergenleitstand TUI session until the operator exits.
///
/// # Errors
///
/// Returns an `io::Error` if terminal setup, rendering, or startup report loading fails.
#[allow(clippy::too_many_lines)]
/// Renders one frame, converting a view-layer panic into an error instead of an
/// abort so the operator sees which subsystem failed.
fn render_guarded(session: &mut TerminalSession, state: &AppState) -> Result<(), String> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        session
            .terminal_mut()
            .draw(|frame| render(frame, state))
            .map(|_| ())
    }));
    match outcome {
        Ok(result) => result.map_err(|err| format!("render failed: {err}")),
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_owned());
            Err(format!("render panicked: {message}"))
        }
    }
}

/// Runs the Zwergenleitstand until the operator quits.
///
/// # Errors
///
/// Returns an I/O or state-initialisation error, including a view-layer panic converted
/// into a diagnostic message.
#[allow(clippy::too_many_lines)]
pub async fn run_tui(options: TuiStartupOptions) -> io::Result<()> {
    let (mut state, initial_effects) = initialize_state(&options)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;

    let mut session = TerminalSession::enter()?;
    if let Ok(size) = session.terminal_mut().size() {
        state.terminal_width = size.width;
        state.terminal_height = size.height;
    }

    let mut active_task: Option<ActiveBackgroundTask> = None;
    let mut pending_connection_test: Option<mpsc::Receiver<ConnectionOutcome>> = None;
    let mut pending_model_discovery: Option<mpsc::Receiver<Result<Vec<String>, String>>> = None;
    let mut pending_effects = initial_effects;
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(100);

    loop {
        while let Some(effect) = pending_effects.pop() {
            match effect {
                AppEffect::StartRun(spec) => {
                    if let Some(mut prev) = active_task.take() {
                        prev.request_cancellation();
                        prev.handle.abort();
                    }
                    let seq = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                    let run_id = RunId::new(format!("run-{seq:04}"));
                    state.active_run_id = Some(run_id.as_str().to_owned());
                    let router = build_run_router(&spec, &state, options.config.as_ref());
                    active_task = Some(spawn_background_run(
                        run_id,
                        spec,
                        options.policy,
                        options.budget,
                        options.objective.clone(),
                        options.memory_dir.clone(),
                        router,
                    ));
                }
                AppEffect::CancelActiveRun => {
                    if let Some(task) = &mut active_task {
                        task.request_cancellation();
                    }
                }
                AppEffect::TestConnection { spec, credential } => {
                    let (tx, rx) = mpsc::channel(1);
                    tokio::spawn(async move {
                        let outcome = match credential {
                            Some(secret) => {
                                let resolved = crate::credentials::ResolvedCredential {
                                    secret,
                                    source: crate::credentials::CredentialSource::Session,
                                };
                                crate::intelligence::probe_connection(&spec, &resolved).await
                            }
                            None => match crate::credentials::SessionCredentialStore::new()
                                .resolve(&spec)
                            {
                                Some(resolved) => {
                                    crate::intelligence::probe_connection(&spec, &resolved).await
                                }
                                None => {
                                    crate::intelligence::ConnectionOutcome::AuthenticationRejected
                                }
                            },
                        };
                        let _ = tx.send(outcome).await;
                    });
                    pending_connection_test = Some(rx);
                }
                AppEffect::DiscoverModels { spec, credential } => {
                    let (tx, rx) = mpsc::channel(1);
                    tokio::spawn(async move {
                        let resolved = match credential {
                            Some(secret) => Some(crate::credentials::ResolvedCredential {
                                secret,
                                source: crate::credentials::CredentialSource::Session,
                            }),
                            None => {
                                crate::credentials::SessionCredentialStore::new().resolve(&spec)
                            }
                        };
                        let result = match resolved {
                            Some(resolved) => {
                                crate::intelligence::discover_models(&spec, &resolved).await
                            }
                            None => Err(String::from(
                                "no credential is available for model discovery",
                            )),
                        };
                        let _ = tx.send(result).await;
                    });
                    pending_model_discovery = Some(rx);
                }
                AppEffect::SaveReport(path) => {
                    let res = save_current_report(&state, &path);
                    let follow_up = reduce(&mut state, AppAction::ReportSaved(res));
                    pending_effects.extend(follow_up);
                }
                AppEffect::Quit => {
                    if let Some(mut prev) = active_task.take() {
                        prev.request_cancellation();
                        prev.handle.abort();
                    }
                    return Ok(());
                }
            }
        }

        if let Some(rx) = &mut pending_connection_test
            && let Ok(outcome) = rx.try_recv()
        {
            let effs = reduce(&mut state, AppAction::ConnectionTested(outcome));
            pending_effects.extend(effs);
            pending_connection_test = None;
        }

        if let Some(rx) = &mut pending_model_discovery
            && let Ok(result) = rx.try_recv()
        {
            let action = match result {
                Ok(models) => AppAction::ModelsDiscovered(models),
                Err(reason) => AppAction::ModelDiscoveryFailed(reason),
            };
            let effs = reduce(&mut state, action);
            pending_effects.extend(effs);
            pending_model_discovery = None;
        }

        if state.should_quit {
            if let Some(mut prev) = active_task.take() {
                prev.request_cancellation();
                prev.handle.abort();
            }
            return Ok(());
        }

        // Confirm cancellation only once the background task has actually stopped.
        //
        // `Cancelled` is never reported from the operator's request alone: the join
        // handle must have finished, or the escalation deadline must have expired and
        // the task been force-terminated.
        if state.lifecycle == RunLifecycleState::Cancelling {
            let settlement = active_task.as_ref().and_then(|task| {
                if task.handle.is_finished() {
                    Some(false)
                } else {
                    task.cancel_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                        .then_some(true)
                }
            });
            if let Some(escalated) = settlement {
                if let Some(task) = active_task.take() {
                    task.handle.abort();
                }
                let effs = reduce(&mut state, AppAction::CancellationSettled { escalated });
                pending_effects.extend(effs);
            }
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
                    if matches!(state.lifecycle, RunLifecycleState::Running) {
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

        render_guarded(&mut session, &state).map_err(io::Error::other)?;

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
    memory_dir: PathBuf,
    router: Arc<dyn crate::intelligence::ProviderRouter>,
) -> ActiveBackgroundTask {
    let (sink, event_rx) = diagnostic_event_channel(run_id);
    let (result_tx, result_rx) = mpsc::channel(1);
    let (cancel_tx, cancel_rx) = watch::channel(false);

    let handle = tokio::spawn(async move {
        let outcome = Box::pin(execute_diagnostic_run_cancellable(
            spec,
            policy,
            budget,
            objective,
            sink,
            cancel_rx,
            &memory_dir,
            router,
        ))
        .await;
        let _ = Box::pin(result_tx.send(outcome)).await;
    });

    ActiveBackgroundTask {
        handle,
        event_rx,
        result_rx,
        cancel: cancel_tx,
        cancel_deadline: None,
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
    sink: DiagnosticEventSink,
) -> Result<DiagnosticArtefacts, String> {
    let (_cancel, cancel_rx) = watch::channel(false);
    let store = crate::credentials::SessionCredentialStore::new();
    let router: Arc<dyn crate::intelligence::ProviderRouter> = Arc::new(
        crate::intelligence::CachedProviderRouter::from_model_spec(
            &crate::config::ModelSpec {
                provider: spec.provider,
                model: if spec.model.trim().is_empty() {
                    "unspecified".to_owned()
                } else {
                    spec.model.clone()
                },
                base_url: None,
                api_key_env: None,
            },
            &store,
        )
        .unwrap_or_default(),
    );
    execute_diagnostic_run_cancellable(
        spec,
        policy,
        budget,
        objective,
        sink,
        cancel_rx,
        Path::new(crate::patrol::memory::DEFAULT_MEMORY_DIR),
        router,
    )
    .await
}

/// Builds the provider router for a run from the Launcher choice, falling back to
/// the resolved configuration and the session credential store.
fn build_run_router(
    spec: &RunLaunchSpec,
    state: &AppState,
    config: Option<&crate::config::AppConfig>,
) -> Arc<dyn crate::intelligence::ProviderRouter> {
    let model = spec.model.trim();
    if let Some(config) = config {
        // A configuration file describes the whole brigade. The launcher only overrides
        // the Kommandant route, and only when the operator actually entered a model.
        let mut routing = config.models.clone();
        if !model.is_empty() {
            routing.kommandant = Some(
                routing
                    .resolve_for_dwarf(crate::brigade::DwarfId::Kommandant)
                    .with_model_override(spec.provider, model),
            );
        }
        return Arc::new(
            crate::intelligence::CachedProviderRouter::from_config_and_store(
                &routing,
                &state.credentials,
            ),
        );
    }
    if !model.is_empty() {
        let spec_model = crate::config::ModelSpec {
            provider: spec.provider,
            model: model.to_owned(),
            base_url: None,
            api_key_env: None,
        };
        if let Some(router) = crate::intelligence::CachedProviderRouter::from_model_spec(
            &spec_model,
            &state.credentials,
        ) {
            return Arc::new(router);
        }
    }
    Arc::new(crate::intelligence::EmptyProviderRouter)
}

/// Executes a diagnostic run with a cooperative cancellation token.
///
/// The runner checks the token at phase boundaries (before acquisition, before
/// analysis, before investigation and before patrol) and returns an error as soon
/// as cancellation is observed. Long-running collectors may therefore finish their
/// current bounded step before yielding; the runtime only reports `Cancelled` once
/// this future has returned and every guard has been dropped.
///
/// # Errors
///
/// Returns an error string if target resolution, mandatory execution steps fail, or
/// the operator cancels the run.
#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)]
pub async fn execute_diagnostic_run_cancellable(
    spec: RunLaunchSpec,
    policy: TargetPolicy,
    budget: ExecutionBudget,
    objective: String,
    sink: DiagnosticEventSink,
    cancel: watch::Receiver<bool>,
    memory_dir: &Path,
    router: Arc<dyn crate::intelligence::ProviderRouter>,
) -> Result<DiagnosticArtefacts, String> {
    let start = Instant::now();
    let target_str = spec.target.as_str().to_owned();
    let target = AuditTarget::parse(&target_str, policy)
        .map_err(|err| format!("target blocked by policy: {err}"))?;

    sink.emit(
        EventContext::new().with_target(&target_str),
        DiagnosticEventPayload::RunStarted {
            mode: spec.mode,
            target: target_str.clone(),
        },
    );

    match spec.mode {
        DiagnosticRunMode::DeterministicCheck | DiagnosticRunMode::OfflineExploration => {
            if *cancel.borrow() {
                return Err(String::from("cancelled by operator before acquisition"));
            }
            let snapshot =
                collect_snapshot_with_events(&target, &spec, &budget, policy, &sink).await;

            if *cancel.borrow() {
                return Err(String::from("cancelled by operator before analysis"));
            }
            let report = analysis::run_all_with_events(&snapshot, &sink);
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let total_findings = report.summary.critical_findings
                + report.summary.high_findings
                + report.summary.medium_findings
                + report.summary.low_findings
                + report.summary.info_findings;
            sink.emit(
                EventContext::new().with_target(&target_str),
                DiagnosticEventPayload::RunCompleted {
                    summary: format!(
                        "Completed deterministic check with {total_findings} findings in {elapsed_ms} ms"
                    ),
                },
            );

            Ok(DiagnosticArtefacts {
                target: target_str,
                mode: DiagnosticRunMode::DeterministicCheck,
                snapshot: Some(snapshot),
                audit_report: Some(report),
                investigation_report: None,
                patrol_report: None,
                crawl_summary: None,
                history_reports: Vec::new(),
                regression_report: None,
                elapsed_ms,
            })
        }
        DiagnosticRunMode::ReconnaissanceCrawl => {
            let request = CrawlRequest {
                target,
                target_str,
                max_pages: spec.max_pages,
                max_depth: spec.max_depth,
                evidence_dir: spec.evidence_dir.clone(),
                policy,
                budget,
            };
            Box::pin(run_reconnaissance_crawl(request, start, &cancel, &sink)).await
        }
        DiagnosticRunMode::AgenticInvestigation => {
            if *cancel.borrow() {
                return Err(String::from("cancelled by operator before investigation"));
            }
            if router
                .resolve_for_dwarf(crate::brigade::DwarfId::Kommandant)
                .is_none()
            {
                return Err(String::from(
                    "agentic investigation needs a model configured for KommandantZwerg; set a provider and model in the Launcher, or provide a configuration file. No model was substituted.",
                ));
            }
            let backend = Arc::new(LiveDiagnosticBackend);
            let inv_budget = InvestigationBudget::default();
            let inv_report = investigation::run_investigation_with_events_and_router(
                target,
                objective,
                policy,
                inv_budget,
                backend,
                router.as_ref(),
                Vec::new(),
                &sink,
            )
            .await;

            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            Ok(DiagnosticArtefacts {
                target: target_str,
                mode: DiagnosticRunMode::AgenticInvestigation,
                snapshot: inv_report.snapshot.clone(),
                audit_report: inv_report.initial_report.clone(),
                investigation_report: Some(inv_report),
                patrol_report: None,
                crawl_summary: None,
                history_reports: Vec::new(),
                regression_report: None,
                elapsed_ms,
            })
        }
        DiagnosticRunMode::AutonomousPatrol => {
            if *cancel.borrow() {
                return Err(String::from("cancelled by operator before patrol"));
            }
            sink.emit(
                EventContext::new()
                    .with_target(&target_str)
                    .with_collector(CollectorId::Http),
                DiagnosticEventPayload::CollectionStarted {
                    collector: CollectorId::Http,
                },
            );
            let patrol_budget = PatrolBudget {
                enable_level2: spec.enable_browser,
                ..PatrolBudget::default()
            };
            let backend: Arc<dyn investigation::DiagnosticBackend> =
                Arc::new(LiveDiagnosticBackend);
            let patrol_report = Box::pin(patrol::run_patrol_with_router(
                target,
                policy,
                budget,
                patrol_budget,
                Some(memory_dir),
                None,
                backend,
            ))
            .await;

            for limitation in [
                patrol_report.memory_load_error.as_deref(),
                patrol_report.memory_save_error.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                sink.emit(
                    EventContext::new().with_target(&target_str),
                    DiagnosticEventPayload::Warning {
                        message: format!("patrol memory unavailable: {limitation}"),
                    },
                );
            }

            for url in &patrol_report.application_map.discovered_urls {
                sink.emit(
                    EventContext::new()
                        .with_target(&target_str)
                        .with_page(url.as_str()),
                    DiagnosticEventPayload::TargetDiscovered {
                        url: url.clone(),
                        source: String::from("patrol"),
                        depth: 0,
                        status: String::from("completed"),
                    },
                );
            }

            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let first_inv = patrol_report.investigation.clone();
            let first_audit = first_inv
                .as_ref()
                .and_then(|inv| inv.initial_report.clone());
            let total_findings = first_audit
                .as_ref()
                .map_or(patrol_report.anomalies.len(), |r| {
                    r.summary.critical_findings
                        + r.summary.high_findings
                        + r.summary.medium_findings
                        + r.summary.low_findings
                        + r.summary.info_findings
                });

            sink.emit(
                EventContext::new().with_target(&target_str),
                DiagnosticEventPayload::RunCompleted {
                    summary: format!(
                        "Completed autonomous patrol with {total_findings} findings in {elapsed_ms} ms"
                    ),
                },
            );

            Ok(DiagnosticArtefacts {
                target: target_str,
                mode: DiagnosticRunMode::AutonomousPatrol,
                snapshot: None,
                audit_report: first_audit,
                investigation_report: first_inv,
                patrol_report: Some(patrol_report),
                crawl_summary: None,
                history_reports: Vec::new(),
                regression_report: None,
                elapsed_ms,
            })
        }
    }
}

/// Executes an application-wide reconnaissance crawl and retains its evidence.
///
/// Kept in its own future so the crawl and evidence-store state do not inflate the
/// top-level run future; the caller boxes it for the same reason.
#[allow(clippy::too_many_arguments)]
/// Lower-case crawl status label understood by the workbench reducer.
const fn status_label(status: crate::discovery::PageCrawlStatus) -> &'static str {
    use crate::discovery::PageCrawlStatus;
    match status {
        PageCrawlStatus::Investigated => "investigated",
        PageCrawlStatus::PartiallyInvestigated => "partial",
        PageCrawlStatus::SkippedBudget => "skipped",
        PageCrawlStatus::Unreachable => "failed",
    }
}

/// Runs the crawl while translating scheduler progress into workbench events.
///
/// The observer runs between acquisitions, so it reports work already done rather than
/// an estimate of what is left: the discovery collector row shows completed pages against
/// the configured bound, and each newly admitted URL appears in the target surface as queued.
async fn crawl_with_progress(
    target: AuditTarget,
    target_str: &str,
    crawl_budget: crate::discovery::CrawlBudget,
    budget: ExecutionBudget,
    policy: TargetPolicy,
    max_pages: usize,
    sink: &DiagnosticEventSink,
) -> crate::discovery::CrawlSummary {
    let observer = |event: crate::discovery::CrawlProgressEvent| match event {
        crate::discovery::CrawlProgressEvent::Discovered { url, depth, source } => {
            sink.emit(
                EventContext::new()
                    .with_target(target_str)
                    .with_collector(CollectorId::Discovery)
                    .with_page(&url),
                DiagnosticEventPayload::TargetDiscovered {
                    url,
                    depth,
                    source: source.label().to_owned(),
                    status: String::from("queued"),
                },
            );
        }
        crate::discovery::CrawlProgressEvent::PageCompleted {
            url,
            status,
            completed_pages,
            analysed_pages,
            failed_pages,
        } => {
            sink.emit(
                EventContext::new()
                    .with_target(target_str)
                    .with_collector(CollectorId::Discovery)
                    .with_page(&url),
                DiagnosticEventPayload::CollectionProgress {
                    collector: CollectorId::Discovery,
                    completed_units: completed_pages,
                    total_units: Some(max_pages),
                    detail: format!(
                        "analysed {analysed_pages} · failed {failed_pages} · {} · {url}",
                        status_label(status)
                    ),
                },
            );
        }
    };
    crate::discovery::crawl_and_cluster_with_progress(
        target,
        crawl_budget,
        budget,
        policy,
        &observer,
    )
    .await
}

/// Reports that the crawl finished, with the limitations it actually reached.
///
/// The HTTP collector is closed here because the crawl owns the acquisition phase: leaving it
/// `Running` after the run completes would claim work that is no longer happening.
fn emit_crawl_completion(
    target_str: &str,
    crawl: &crate::discovery::CrawlSummary,
    sink: &DiagnosticEventSink,
) {
    let mut warnings = Vec::new();
    if !crawl.coverage.complete {
        warnings.push(format!(
            "{} of {} discovered URLs were not acquired within the crawl budget",
            crawl
                .coverage
                .discovered_urls
                .saturating_sub(crawl.coverage.analysed_urls),
            crawl.coverage.discovered_urls
        ));
    }
    if crawl.coverage.robots_blocked_urls > 0 {
        warnings.push(format!(
            "{} URL(s) excluded by robots.txt",
            crawl.coverage.robots_blocked_urls
        ));
    }
    for collector in [CollectorId::Http, CollectorId::Discovery] {
        sink.emit(
            EventContext::new()
                .with_target(target_str)
                .with_collector(collector),
            DiagnosticEventPayload::CollectionCompleted {
                collector,
                partial: !crawl.coverage.complete,
                warnings: warnings.clone(),
            },
        );
    }
}

/// Persists a completed crawl, reporting a failed write instead of hiding it.
async fn store_crawl_evidence(
    store_path: &std::path::Path,
    run_id: &str,
    application: &str,
    crawl: &crate::discovery::CrawlSummary,
    sink: &DiagnosticEventSink,
) {
    let record = crate::evidence_store::CrawlRecord {
        run_id,
        application,
        summary: crawl,
        recorded_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    };
    let stored = Box::pin(async {
        match crate::evidence_store::EvidenceStore::open(store_path).await {
            Ok(store) => store.record_crawl(record).await,
            Err(err) => Err(err),
        }
    })
    .await;
    if let Err(err) = stored {
        sink.emit(
            EventContext::new().with_target(application),
            DiagnosticEventPayload::Warning {
                message: format!(
                    "reconnaissance evidence not stored at {}: {err}",
                    store_path.display()
                ),
            },
        );
    }
}

/// Everything a reconnaissance crawl needs, bundled so the run signature stays readable.
struct CrawlRequest {
    /// Validated seed target.
    target: AuditTarget,
    /// Seed as entered, used for event context and artefact identity.
    target_str: String,
    /// Page bound requested by the operator.
    max_pages: usize,
    /// Depth bound requested by the operator.
    max_depth: usize,
    /// Directory holding the evidence store.
    evidence_dir: std::path::PathBuf,
    /// Target validation policy.
    policy: TargetPolicy,
    /// Execution budget for the run.
    budget: ExecutionBudget,
}

async fn run_reconnaissance_crawl(
    request: CrawlRequest,
    start: Instant,
    cancel: &watch::Receiver<bool>,
    sink: &DiagnosticEventSink,
) -> Result<DiagnosticArtefacts, String> {
    let CrawlRequest {
        target,
        target_str,
        max_pages,
        max_depth,
        evidence_dir,
        policy,
        budget,
    } = request;
    if *cancel.borrow() {
        return Err(String::from("cancelled by operator before crawl"));
    }
    sink.emit(
        EventContext::new()
            .with_target(&target_str)
            .with_collector(CollectorId::Http),
        DiagnosticEventPayload::CollectionStarted {
            collector: CollectorId::Http,
        },
    );
    let crawl_budget = crate::discovery::CrawlBudget {
        max_pages: max_pages.max(1),
        max_depth,
        max_duration: budget.audit_timeout,
    };
    let crawl = crawl_with_progress(
        target,
        &target_str,
        crawl_budget,
        budget,
        policy,
        max_pages.max(1),
        sink,
    )
    .await;

    for page in &crawl.pages {
        sink.emit(
            EventContext::new()
                .with_target(&target_str)
                .with_page(page.url.as_str()),
            DiagnosticEventPayload::TargetDiscovered {
                url: page.url.as_str().to_owned(),
                source: String::from("crawl"),
                depth: page.depth,
                status: status_label(page.status).to_owned(),
            },
        );
    }

    emit_crawl_completion(&target_str, &crawl, sink);

    let store_path = evidence_dir.join("evidence.db");
    let run_id = format!(
        "tui-scan-{}",
        u64::try_from(start.elapsed().as_millis()).unwrap_or(0)
    );
    store_crawl_evidence(&store_path, &run_id, &target_str, &crawl, sink).await;

    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    sink.emit(
        EventContext::new().with_target(&target_str),
        DiagnosticEventPayload::RunCompleted {
            summary: format!(
                "Reconnaissance crawl analysed {} of {} discovered URLs, {} systemic clusters, in {elapsed_ms} ms",
                crawl.coverage.analysed_urls,
                crawl.coverage.discovered_urls,
                crawl.systemic_issues.len()
            ),
        },
    );

    Ok(DiagnosticArtefacts {
        target: target_str,
        mode: DiagnosticRunMode::ReconnaissanceCrawl,
        snapshot: None,
        audit_report: None,
        investigation_report: None,
        patrol_report: None,
        crawl_summary: Some(crawl),
        history_reports: Vec::new(),
        regression_report: None,
        elapsed_ms,
    })
}

async fn collect_snapshot_with_events(
    target: &AuditTarget,
    spec: &RunLaunchSpec,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    sink: &DiagnosticEventSink,
) -> EvidenceSnapshot {
    let target_str = target.as_str();

    sink.emit(
        EventContext::new()
            .with_target(target_str)
            .with_collector(CollectorId::Http),
        DiagnosticEventPayload::CollectionStarted {
            collector: CollectorId::Http,
        },
    );
    if target.as_str().starts_with("https://") {
        sink.emit(
            EventContext::new()
                .with_target(target_str)
                .with_collector(CollectorId::Tls),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Tls,
            },
        );
    }

    let mut snapshot = collection::collect_http(target, budget, policy).await;
    emit_collector_outcome(sink, target_str, CollectorId::Http, &snapshot.http);
    emit_collector_outcome(sink, target_str, CollectorId::Tls, &snapshot.tls);

    if spec.enable_browser {
        sink.emit(
            EventContext::new()
                .with_target(target_str)
                .with_collector(CollectorId::Browser),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Browser,
            },
        );
        let outcome =
            adapters::browser::run_browser_with_policy(target, budget.audit_timeout, policy).await;
        emit_collector_outcome(sink, target_str, CollectorId::Browser, &outcome);
        snapshot.browser = outcome;
    }

    if spec.enable_lighthouse {
        sink.emit(
            EventContext::new()
                .with_target(target_str)
                .with_collector(CollectorId::Lighthouse),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Lighthouse,
            },
        );
        let outcome =
            adapters::lighthouse::run_lighthouse_with_policy(target, budget.audit_timeout, policy)
                .await;
        emit_collector_outcome(sink, target_str, CollectorId::Lighthouse, &outcome);
        snapshot.lighthouse = outcome;
    }

    if spec.enable_axe {
        sink.emit(
            EventContext::new()
                .with_target(target_str)
                .with_collector(CollectorId::Axe),
            DiagnosticEventPayload::CollectionStarted {
                collector: CollectorId::Axe,
            },
        );
        let outcome = adapters::axe::run_axe(target, budget.audit_timeout).await;
        emit_collector_outcome(sink, target_str, CollectorId::Axe, &outcome);
        snapshot.axe = outcome;
    }

    collection::hydrate_browser_tls_and_caa(&mut snapshot);
    snapshot
}

fn emit_collector_outcome<T>(
    sink: &DiagnosticEventSink,
    target_str: &str,
    collector: CollectorId,
    outcome: &CollectorOutcome<T>,
) {
    let ctx = EventContext::new()
        .with_target(target_str)
        .with_collector(collector);
    match outcome {
        CollectorOutcome::Captured { .. } => {
            sink.emit(
                ctx,
                DiagnosticEventPayload::CollectionCompleted {
                    collector,
                    partial: false,
                    warnings: Vec::new(),
                },
            );
        }
        CollectorOutcome::Partial { warnings, .. } => {
            sink.emit(
                ctx,
                DiagnosticEventPayload::CollectionCompleted {
                    collector,
                    partial: true,
                    warnings: warnings.clone(),
                },
            );
        }
        CollectorOutcome::Failed { error } => {
            sink.emit(
                ctx,
                DiagnosticEventPayload::CollectionFailed {
                    collector,
                    error: error.clone(),
                },
            );
        }
        CollectorOutcome::Skipped { reason } => {
            sink.emit(
                ctx,
                DiagnosticEventPayload::CollectionSkipped {
                    collector,
                    reason: reason.clone(),
                },
            );
        }
    }
}
