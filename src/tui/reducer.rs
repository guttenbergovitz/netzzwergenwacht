//! Pure state reducer for Zwergenleitstand (`(AppState, AppAction) -> Vec<AppEffect>`).
//!
//! All state transitions are deterministic and free of I/O so they can be
//! verified in unit tests without spawning a terminal or network tasks.

use std::path::PathBuf;

use crate::brigade::DwarfId;
use crate::config::{ModelSpec, ProviderKind};
use crate::credentials::CredentialScope;
use crate::domain::AuditTarget;
use crate::events::{CollectorId, DiagnosticEvent, DiagnosticEventPayload, DiagnosticRunMode};
use crate::intelligence::ConnectionOutcome;
use crate::investigation::HypothesisStatus;
use crate::investigation::evidence_query::PAGE_SIZE;
use crate::tui::action::{AppAction, AppEffect, RunLaunchSpec, UserAction};
use crate::tui::sanitize::{sanitize_line, sanitize_url_for_display};
use crate::tui::state::{
    AppState, BrigadeActivityRow, HypothesisRow, LauncherField, RunLifecycleState,
    TargetInspectionState, TargetSurfaceRow, ToolActivityRow, WorkbenchView,
};
use crate::tui::theme::{GlyphSet, OperationalStatus, Theme, ThemeMode};

/// Applies a single [`AppAction`] to [`AppState`] and returns any requested [`AppEffect`]s.
pub fn reduce(state: &mut AppState, action: AppAction) -> Vec<AppEffect> {
    match action {
        AppAction::User(user_action) => reduce_user_action(state, user_action),
        AppAction::Resize(width, height) => {
            state.terminal_width = width;
            state.terminal_height = height;
            Vec::new()
        }
        AppAction::Tick => {
            if matches!(
                state.lifecycle,
                RunLifecycleState::Running | RunLifecycleState::Cancelling
            ) {
                state.system_metrics.elapsed_ms =
                    state.system_metrics.elapsed_ms.saturating_add(100);
            }
            Vec::new()
        }
        AppAction::Diagnostic(event) => {
            reduce_diagnostic_event(state, *event);
            Vec::new()
        }
        AppAction::RunFinished(artefacts) => {
            state.ingest_artefacts(*artefacts);
            state.status_message = format!(
                "Diagnostic run completed for {} ({} finding(s)). Press 4 for Findings or 5 for Evidence.",
                state.target_url,
                state.findings.len()
            );
            Vec::new()
        }
        AppAction::RunFailed(err) => {
            let clean = sanitize_line(&err, 140);
            state.lifecycle = RunLifecycleState::Failed;
            state.push_activity(&format!("Run failed: {clean}"));
            state.status_message = format!("Diagnostic run failed: {clean}");
            Vec::new()
        }
        AppAction::CancellationSettled { escalated } => {
            if escalated {
                state.lifecycle = RunLifecycleState::TerminationEscalated;
                state.push_activity(
                    "Cancellation deadline exceeded; background task force-terminated.",
                );
                state.status_message = String::from(
                    "Cancellation escalated: task cleanup did not confirm before the deadline.",
                );
            } else {
                state.lifecycle = RunLifecycleState::Cancelled;
                state.push_activity("Run cancelled; background task and child processes stopped.");
                state.status_message = String::from("Run cancelled.");
            }
            Vec::new()
        }
        AppAction::ModelsDiscovered(models) => {
            let count = models.len();
            state.launcher.discovered_models = models;
            if state.launcher.model_input.trim().is_empty()
                && let Some(first) = state.launcher.discovered_models.first()
            {
                state.launcher.model_input.clone_from(first);
            }
            state.launcher.discovery_error = None;
            state.launcher.connection = ConnectionOutcome::NotTested;
            state.status_message = format!(
                "Model discovery: {count} model(s) advertised. Left/Right cycles on Model."
            );
            Vec::new()
        }
        AppAction::ModelDiscoveryFailed(reason) => {
            let clean = sanitize_line(&reason, 120);
            state.launcher.discovery_error = Some(clean.clone());
            state.status_message = format!("Model discovery failed: {clean}");
            Vec::new()
        }
        AppAction::ConnectionTested(outcome) => {
            let label = outcome.label();
            state.status_message = format!("Connection test: {label}");
            state.launcher.connection = outcome;
            Vec::new()
        }
        AppAction::ReportSaved(result) => {
            match result {
                Ok(path) => {
                    let display = sanitize_line(&path.display().to_string(), 100);
                    state.push_activity(&format!("Saved report to {display}"));
                    state.status_message = format!("Saved report to {display}");
                }
                Err(err) => {
                    let clean = sanitize_line(&err, 120);
                    state.status_message = format!("Failed to save report: {clean}");
                }
            }
            Vec::new()
        }
    }
}

#[allow(clippy::too_many_lines)]
fn reduce_user_action(state: &mut AppState, action: UserAction) -> Vec<AppEffect> {
    // Handle Launcher modal actions when open.
    if state.launcher.open {
        return reduce_launcher_action(state, action);
    }

    // Handle Search bar input when focused.
    if state.search_focused {
        match action {
            UserAction::BackOrClose | UserAction::Activate => {
                state.search_focused = false;
                state.status_message = format!(
                    "Filter applied ({} / {} findings visible).",
                    state.visible_finding_indices.len(),
                    state.findings.len()
                );
            }
            UserAction::InputChar(ch) => {
                if state.finding_filter.search_query.len() < 80 {
                    state.finding_filter.search_query.push(ch);
                    state.refresh_visible_findings();
                }
            }
            UserAction::InputBackspace => {
                state.finding_filter.search_query.pop();
                state.refresh_visible_findings();
            }
            UserAction::InputClear => {
                state.finding_filter.search_query.clear();
                state.refresh_visible_findings();
            }
            _ => {}
        }
        return Vec::new();
    }

    match action {
        UserAction::NextView => {
            state.active_view = state.active_view.next();
        }
        UserAction::PrevView => {
            state.active_view = state.active_view.prev();
        }
        UserAction::SelectView(view) => {
            state.active_view = view;
        }
        UserAction::MoveDown => move_selection(state, 1),
        UserAction::MoveUp => move_selection(state, -1),
        UserAction::PageDown => move_selection(state, 16),
        UserAction::PageUp => move_selection(state, -16),
        UserAction::FirstItem => move_to_edge(state, false),
        UserAction::LastItem => move_to_edge(state, true),
        UserAction::MoveLeft => match state.active_view {
            WorkbenchView::Evidence => {
                state.evidence_category = state.evidence_category.prev();
                state.evidence_offset = 0;
                state.selected_evidence_row = 0;
            }
            _ => {
                state.active_view = state.active_view.prev();
            }
        },
        UserAction::MoveRight => match state.active_view {
            WorkbenchView::Evidence => {
                state.evidence_category = state.evidence_category.next();
                state.evidence_offset = 0;
                state.selected_evidence_row = 0;
            }
            _ => {
                state.active_view = state.active_view.next();
            }
        },
        UserAction::Activate => handle_activate_in_active_view(state),
        UserAction::BackOrClose => {
            if !state.finding_filter.search_query.is_empty()
                || state.finding_filter.min_severity.is_some()
                || state.finding_filter.dwarf.is_some()
            {
                state.finding_filter.search_query.clear();
                state.finding_filter.min_severity = None;
                state.finding_filter.dwarf = None;
                state.refresh_visible_findings();
                state.status_message = String::from("Cleared all finding filters.");
            }
        }
        UserAction::OpenSearch => {
            state.active_view = WorkbenchView::Findings;
            state.search_focused = true;
            state.status_message =
                String::from("Search findings by rule ID, title, or description (Enter/Esc done).");
        }
        UserAction::CycleSort => {
            state.finding_sort = state.finding_sort.next();
            state.refresh_visible_findings();
            state.status_message = format!("Sorted findings by: {}", state.finding_sort.label());
        }
        UserAction::CycleSeverityFilter => {
            state.finding_filter.cycle_severity();
            state.refresh_visible_findings();
            state.status_message = format!(
                "Severity filter: {} ({} visible)",
                state.finding_filter.severity_label(),
                state.visible_finding_indices.len()
            );
        }
        UserAction::SelectEvidenceCategory(cat) => {
            state.active_view = WorkbenchView::Evidence;
            state.evidence_category = cat;
            state.evidence_offset = 0;
            state.selected_evidence_row = 0;
        }
        UserAction::OpenLauncher => {
            state.launcher.open = true;
            state.launcher.error_message = None;
        }
        UserAction::SaveCurrentReport => {
            if state.audit_report.is_some() {
                let path = state
                    .output_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("nzw-report.json"));
                return vec![AppEffect::SaveReport(path)];
            }
            state.status_message =
                String::from("No AuditReport available to save yet. Run an inspection first.");
        }
        UserAction::CycleTheme => {
            let next_mode = match state.theme.mode {
                ThemeMode::StandardDark => ThemeMode::HighContrast,
                ThemeMode::HighContrast => ThemeMode::Monochrome,
                ThemeMode::Monochrome => ThemeMode::StandardDark,
            };
            state.theme = Theme::new(next_mode, state.theme.glyphs);
            state.status_message = format!("Theme mode: {:?}", state.theme.mode);
        }
        UserAction::ToggleAscii => {
            let next_glyphs = match state.theme.glyphs {
                GlyphSet::Unicode => GlyphSet::Ascii,
                GlyphSet::Ascii => GlyphSet::Unicode,
            };
            state.theme = Theme::new(state.theme.mode, next_glyphs);
            state.status_message = format!("Glyph mode: {:?}", state.theme.glyphs);
        }
        UserAction::ToggleHelp => {
            state.help_open = !state.help_open;
        }
        UserAction::ToggleReview => {
            state.review_open = !state.review_open;
        }
        UserAction::CancelRun => {
            if state.lifecycle == RunLifecycleState::Running {
                state.lifecycle = RunLifecycleState::Cancelling;
                state.push_activity("Cancellation requested by operator...");
                state.status_message =
                    String::from("Cancelling active diagnostic run and terminating child tasks...");
                return vec![AppEffect::CancelActiveRun];
            }
        }
        UserAction::Quit => {
            state.should_quit = true;
            if matches!(
                state.lifecycle,
                RunLifecycleState::Running | RunLifecycleState::Cancelling
            ) {
                return vec![AppEffect::CancelActiveRun, AppEffect::Quit];
            }
            return vec![AppEffect::Quit];
        }
        UserAction::InputChar(_) | UserAction::InputBackspace | UserAction::InputClear => {}
    }

    Vec::new()
}

#[allow(clippy::too_many_lines)]
fn reduce_launcher_action(state: &mut AppState, action: UserAction) -> Vec<AppEffect> {
    match action {
        UserAction::BackOrClose => {
            // Only close Launcher if we already have a run or report loaded; otherwise stay in Launcher.
            if state.audit_report.is_some()
                || state.snapshot.is_some()
                || !state.history_rows.is_empty()
                || matches!(
                    state.lifecycle,
                    RunLifecycleState::Running
                        | RunLifecycleState::Completed
                        | RunLifecycleState::Partial
                )
            {
                state.launcher.open = false;
            }
        }
        UserAction::MoveDown | UserAction::NextView => {
            state.launcher.focused_field = state.launcher.focused_field.next();
        }
        UserAction::MoveUp | UserAction::PrevView => {
            state.launcher.focused_field = state.launcher.focused_field.prev();
        }
        UserAction::MoveLeft => match state.launcher.focused_field {
            LauncherField::Mode => state.launcher.mode = cycle_mode_prev(state.launcher.mode),
            LauncherField::Provider => {
                state.launcher.provider = cycle_provider(state.launcher.provider, false);
                reset_route_verification(state);
            }
            LauncherField::Model if !state.launcher.discovered_models.is_empty() => {
                cycle_discovered_model(state, false);
            }
            _ => toggle_launcher_bool(state),
        },
        UserAction::MoveRight => match state.launcher.focused_field {
            LauncherField::Mode => state.launcher.mode = cycle_mode_next(state.launcher.mode),
            LauncherField::Provider => {
                state.launcher.provider = cycle_provider(state.launcher.provider, true);
                reset_route_verification(state);
            }
            LauncherField::Model if !state.launcher.discovered_models.is_empty() => {
                cycle_discovered_model(state, true);
            }
            _ => toggle_launcher_bool(state),
        },
        UserAction::InputChar(ch) => match state.launcher.focused_field {
            LauncherField::TargetUrl if state.launcher.target_input.len() < 256 => {
                state.launcher.target_input.push(ch);
                state.launcher.error_message = None;
            }
            LauncherField::Model if state.launcher.model_input.len() < 200 => {
                state.launcher.model_input.push(ch);
                state.launcher.error_message = None;
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            LauncherField::Credential if state.launcher.credential_input.char_count() < 4096 => {
                state.launcher.credential_input.push(ch);
                state.launcher.error_message = None;
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            _ => {}
        },
        UserAction::InputBackspace => match state.launcher.focused_field {
            LauncherField::TargetUrl => {
                state.launcher.target_input.pop();
                state.launcher.error_message = None;
            }
            LauncherField::Model => {
                state.launcher.model_input.pop();
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            LauncherField::Credential => {
                state.launcher.credential_input.pop();
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            _ => {}
        },
        UserAction::InputClear => match state.launcher.focused_field {
            LauncherField::TargetUrl => {
                state.launcher.target_input.clear();
                state.launcher.error_message = None;
            }
            LauncherField::Model => {
                state.launcher.model_input.clear();
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            LauncherField::Credential => {
                state.launcher.credential_input.clear();
                state.launcher.connection = ConnectionOutcome::NotTested;
            }
            _ => {}
        },
        UserAction::Activate => match state.launcher.focused_field {
            LauncherField::Mode => {
                state.launcher.mode = cycle_mode_next(state.launcher.mode);
            }
            LauncherField::Provider => {
                state.launcher.provider = cycle_provider(state.launcher.provider, true);
                reset_route_verification(state);
            }
            LauncherField::BrowserToggle
            | LauncherField::AxeToggle
            | LauncherField::LighthouseToggle => {
                toggle_launcher_bool(state);
            }
            LauncherField::TestConnection => {
                return request_connection_test(state);
            }
            LauncherField::DiscoverModels => {
                return request_model_discovery(state);
            }
            LauncherField::TargetUrl
            | LauncherField::Model
            | LauncherField::Credential
            | LauncherField::StartButton => {
                return try_launch_from_launcher(state);
            }
        },
        UserAction::ToggleHelp => {
            state.help_open = !state.help_open;
        }
        UserAction::ToggleReview => {
            state.review_open = !state.review_open;
        }
        UserAction::Quit => {
            state.should_quit = true;
            return vec![AppEffect::Quit];
        }
        _ => {}
    }
    Vec::new()
}

const fn cycle_provider(provider: ProviderKind, forward: bool) -> ProviderKind {
    match (provider, forward) {
        (ProviderKind::OpenAi, true) | (ProviderKind::Ollama, false) => ProviderKind::Anthropic,
        (ProviderKind::Anthropic, true) | (ProviderKind::OpenAi, false) => ProviderKind::Ollama,
        (ProviderKind::Ollama, true) | (ProviderKind::Anthropic, false) => ProviderKind::OpenAi,
    }
}

/// Resolves the model specification the operator configured in the Launcher.
/// Discards verification results that no longer describe the selected route.
fn reset_route_verification(state: &mut AppState) {
    state.launcher.connection = ConnectionOutcome::NotTested;
    state.launcher.discovered_models.clear();
    state.launcher.discovery_error = None;
}

fn launcher_model_spec(state: &AppState) -> Result<ModelSpec, String> {
    let model = state.launcher.model_input.trim();
    let configured = state
        .config
        .as_ref()
        .map(|config| config.models.resolve_for_dwarf(DwarfId::Kommandant).clone());
    if !model.is_empty() {
        // The operator changed the model, not the endpoint: keep the configured endpoint
        // and credential variable when the provider still matches.
        return Ok(match configured {
            Some(configured) => configured.with_model_override(state.launcher.provider, model),
            None => ModelSpec {
                provider: state.launcher.provider,
                model: model.to_owned(),
                base_url: None,
                api_key_env: None,
            },
        });
    }
    match configured {
        Some(configured) => Ok(configured),
        None => Err(String::from(
            "Enter a model identifier or provide a configuration file; no model is configured for KommandantZwerg.",
        )),
    }
}

/// Moves a pending credential into the session store, returning its scope.
fn absorb_launcher_credential(state: &mut AppState, spec: &ModelSpec) {
    if let Some(secret) = state.launcher.credential_input.take() {
        state
            .credentials
            .insert(CredentialScope::for_model_spec(spec), secret);
    }
}

fn request_connection_test(state: &mut AppState) -> Vec<AppEffect> {
    let spec = match launcher_model_spec(state) {
        Ok(spec) => spec,
        Err(message) => {
            state.launcher.error_message = Some(sanitize_line(&message, 120));
            return Vec::new();
        }
    };
    absorb_launcher_credential(state, &spec);
    let resolved = state.credentials.resolve(&spec);
    state.launcher.connection = ConnectionOutcome::Testing;
    state.status_message = format!("Testing {} ...", spec.model);
    vec![AppEffect::TestConnection {
        spec,
        credential: resolved.map(|resolved| resolved.secret),
    }]
}

/// Requests bounded model discovery from the configured provider.
fn request_model_discovery(state: &mut AppState) -> Vec<AppEffect> {
    let spec = match launcher_model_spec(state) {
        Ok(mut spec) => {
            // Discovery only needs the provider and endpoint, not a model name.
            spec.model.clear();
            spec
        }
        Err(message) => {
            state.launcher.error_message = Some(sanitize_line(&message, 120));
            return Vec::new();
        }
    };
    absorb_launcher_credential(state, &spec);
    let resolved = state.credentials.resolve(&spec);
    state.launcher.discovery_error = None;
    state.status_message = format!("Discovering {} models ...", spec.provider.as_str());
    vec![AppEffect::DiscoverModels {
        spec,
        credential: resolved.map(|resolved| resolved.secret),
    }]
}

fn cycle_discovered_model(state: &mut AppState, forward: bool) {
    let models = &state.launcher.discovered_models;
    if models.is_empty() {
        return;
    }
    let current = models
        .iter()
        .position(|model| model == &state.launcher.model_input);
    let next = match (current, forward) {
        (Some(index), true) => (index + 1) % models.len(),
        (Some(0) | None, false) => models.len() - 1,
        (Some(index), false) => index - 1,
        (None, true) => 0,
    };
    let model = models[next].clone();
    state.launcher.model_input = model;
    state.launcher.connection = ConnectionOutcome::NotTested;
}

const fn cycle_mode_next(mode: DiagnosticRunMode) -> DiagnosticRunMode {
    match mode {
        DiagnosticRunMode::DeterministicCheck => DiagnosticRunMode::ReconnaissanceCrawl,
        DiagnosticRunMode::ReconnaissanceCrawl => DiagnosticRunMode::AgenticInvestigation,
        DiagnosticRunMode::AgenticInvestigation => DiagnosticRunMode::AutonomousPatrol,
        DiagnosticRunMode::AutonomousPatrol | DiagnosticRunMode::OfflineExploration => {
            DiagnosticRunMode::DeterministicCheck
        }
    }
}

const fn cycle_mode_prev(mode: DiagnosticRunMode) -> DiagnosticRunMode {
    match mode {
        DiagnosticRunMode::DeterministicCheck | DiagnosticRunMode::OfflineExploration => {
            DiagnosticRunMode::AutonomousPatrol
        }
        DiagnosticRunMode::ReconnaissanceCrawl => DiagnosticRunMode::DeterministicCheck,
        DiagnosticRunMode::AgenticInvestigation => DiagnosticRunMode::ReconnaissanceCrawl,
        DiagnosticRunMode::AutonomousPatrol => DiagnosticRunMode::AgenticInvestigation,
    }
}

fn toggle_launcher_bool(state: &mut AppState) {
    match state.launcher.focused_field {
        LauncherField::BrowserToggle => {
            state.launcher.enable_browser = !state.launcher.enable_browser;
        }
        LauncherField::AxeToggle => {
            state.launcher.enable_axe = !state.launcher.enable_axe;
        }
        LauncherField::LighthouseToggle => {
            state.launcher.enable_lighthouse = !state.launcher.enable_lighthouse;
        }
        _ => {}
    }
}

fn try_launch_from_launcher(state: &mut AppState) -> Vec<AppEffect> {
    let raw = state.launcher.target_input.trim();
    match AuditTarget::parse(raw, state.launcher.policy) {
        Ok(target) => {
            state.launcher.open = false;
            state.launcher.error_message = None;
            state.target_url = sanitize_url_for_display(target.as_str(), 120);
            state.run_mode = state.launcher.mode;
            state.lifecycle = RunLifecycleState::Running;
            state.active_view = WorkbenchView::Overview;
            state.brigade_rows = BrigadeActivityRow::initial_brigade();
            state.findings.clear();
            state.visible_finding_indices.clear();
            state.selected_finding_pos = 0;
            state.hypotheses.clear();
            state.tool_trace.clear();
            state.target_rows.clear();
            state.recent_activity.clear();
            state.system_metrics.elapsed_ms = 0;
            state.system_metrics.total_events_received = 0;
            state.system_metrics.dropped_progress_events = 0;
            state.system_metrics.dropped_events = 0;
            state.system_metrics.last_event_sequence = 0;
            state.system_metrics.sequence_gap_events = 0;
            state.status_message = format!(
                "Starting {} against {}...",
                state.run_mode.label(),
                state.target_url
            );
            let model = state.launcher.model_input.trim().to_owned();
            match launcher_model_spec(state) {
                Ok(spec) => absorb_launcher_credential(state, &spec),
                Err(message) => {
                    if matches!(
                        state.launcher.mode,
                        crate::events::DiagnosticRunMode::AgenticInvestigation
                    ) {
                        state.launcher.open = true;
                        state.launcher.error_message = Some(sanitize_line(&message, 120));
                        return Vec::new();
                    }
                }
            }
            vec![AppEffect::StartRun(RunLaunchSpec {
                target,
                mode: state.launcher.mode,
                enable_browser: state.launcher.enable_browser,
                enable_axe: state.launcher.enable_axe,
                enable_lighthouse: state.launcher.enable_lighthouse,
                provider: state.launcher.provider,
                model,
                evidence_dir: state.evidence_dir.clone(),
                max_pages: state.crawl_max_pages,
                max_depth: state.crawl_max_depth,
            })]
        }
        Err(err) => {
            state.launcher.error_message = Some(sanitize_line(&err.to_string(), 100));
            Vec::new()
        }
    }
}

fn move_selection(state: &mut AppState, delta: isize) {
    match state.active_view {
        WorkbenchView::Overview | WorkbenchView::System => {}
        WorkbenchView::Brigade => {
            state.selected_brigade_index = step_index(
                state.selected_brigade_index,
                state.brigade_rows.len(),
                delta,
            );
        }
        WorkbenchView::Targets => {
            state.selected_target_index =
                step_index(state.selected_target_index, state.target_rows.len(), delta);
        }
        WorkbenchView::Findings => {
            state.selected_finding_pos = step_index(
                state.selected_finding_pos,
                state.visible_finding_indices.len(),
                delta,
            );
        }
        WorkbenchView::Evidence => {
            if delta.abs() >= 16 {
                if delta > 0 {
                    state.evidence_offset = state.evidence_offset.saturating_add(PAGE_SIZE);
                } else {
                    state.evidence_offset = state.evidence_offset.saturating_sub(PAGE_SIZE);
                }
                state.selected_evidence_row = 0;
            } else {
                state.selected_evidence_row =
                    step_index(state.selected_evidence_row, PAGE_SIZE, delta);
            }
        }
        WorkbenchView::Investigation => {
            state.selected_hypothesis_index = step_index(
                state.selected_hypothesis_index,
                state.hypotheses.len(),
                delta,
            );
        }
        WorkbenchView::Topology => {
            state.selected_topology_index = step_index(
                state.selected_topology_index,
                state.topology_rows.len(),
                delta,
            );
        }
        WorkbenchView::History => {
            state.selected_history_index = step_index(
                state.selected_history_index,
                state.history_rows.len(),
                delta,
            );
        }
    }
}

fn move_to_edge(state: &mut AppState, last: bool) {
    match state.active_view {
        WorkbenchView::Overview | WorkbenchView::System => {}
        WorkbenchView::Brigade => {
            state.selected_brigade_index = if last {
                state.brigade_rows.len().saturating_sub(1)
            } else {
                0
            };
        }
        WorkbenchView::Targets => {
            state.selected_target_index = if last {
                state.target_rows.len().saturating_sub(1)
            } else {
                0
            };
        }
        WorkbenchView::Findings => {
            state.selected_finding_pos = if last {
                state.visible_finding_indices.len().saturating_sub(1)
            } else {
                0
            };
        }
        WorkbenchView::Evidence => {
            if !last {
                state.evidence_offset = 0;
                state.selected_evidence_row = 0;
            }
        }
        WorkbenchView::Investigation => {
            state.selected_hypothesis_index = if last {
                state.hypotheses.len().saturating_sub(1)
            } else {
                0
            };
        }
        WorkbenchView::Topology => {
            state.selected_topology_index = if last {
                state.topology_rows.len().saturating_sub(1)
            } else {
                0
            };
        }
        WorkbenchView::History => {
            state.selected_history_index = if last {
                state.history_rows.len().saturating_sub(1)
            } else {
                0
            };
        }
    }
}

fn handle_activate_in_active_view(state: &mut AppState) {
    match state.active_view {
        WorkbenchView::Findings => {
            if let Some(finding) = state.selected_finding() {
                let category = finding.primary_evidence_category;
                let rule = finding.rule_id.clone();
                state.evidence_category = category;
                state.evidence_offset = 0;
                state.selected_evidence_row = 0;
                state.active_view = WorkbenchView::Evidence;
                state.status_message = format!(
                    "Inspecting {} evidence supporting finding '{}'.",
                    category.label(),
                    rule
                );
            }
        }
        WorkbenchView::Brigade => {
            if let Some(row) = state.brigade_rows.get(state.selected_brigade_index) {
                let dwarf = row.dwarf_id;
                state.finding_filter.dwarf = Some(dwarf);
                state.refresh_visible_findings();
                state.active_view = WorkbenchView::Findings;
                state.status_message = format!(
                    "Filtered findings to {} ({} finding(s)). Press Esc to clear filter.",
                    dwarf.display_name(),
                    state.visible_finding_indices.len()
                );
            }
        }
        WorkbenchView::Targets => {
            state.active_view = WorkbenchView::Findings;
        }
        WorkbenchView::History => {
            state.compare_selected_history_entry();
        }
        _ => {}
    }
}

fn step_index(current: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let cur = isize::try_from(current).unwrap_or(0);
    let max_idx = isize::try_from(len.saturating_sub(1)).unwrap_or(0);
    let next = (cur + delta).clamp(0, max_idx);
    usize::try_from(next).unwrap_or(0)
}

#[allow(clippy::too_many_lines)]
fn reduce_diagnostic_event(state: &mut AppState, event: DiagnosticEvent) {
    state.system_metrics.total_events_received += 1;
    state.system_metrics.dropped_progress_events = event.dropped_progress_events;
    state.system_metrics.dropped_events = event.dropped_events;
    let expected_sequence = state.system_metrics.last_event_sequence.saturating_add(1);
    if event.sequence > expected_sequence {
        state.system_metrics.sequence_gap_events += event.sequence - expected_sequence;
    }
    state.system_metrics.last_event_sequence = event.sequence;
    state.active_run_id = Some(event.run_id.0);

    match event.payload {
        DiagnosticEventPayload::RunStarted { mode, target } => {
            state.run_mode = mode;
            state.target_url = sanitize_url_for_display(&target, 120);
            state.lifecycle = RunLifecycleState::Running;
            state.push_activity(&format!("Run started ({}) for {}", mode.label(), target));
        }
        DiagnosticEventPayload::RunCompleted { summary } => {
            state.push_activity(&format!("Run completed: {summary}"));
        }
        DiagnosticEventPayload::RunPartiallyCompleted { reason } => {
            state.lifecycle = RunLifecycleState::Partial;
            state.push_activity(&format!("Run partially completed: {reason}"));
        }
        DiagnosticEventPayload::RunFailed { error } => {
            state.lifecycle = RunLifecycleState::Failed;
            state.push_activity(&format!("Run failed: {error}"));
        }
        DiagnosticEventPayload::RunCancelled { reason } => {
            state.lifecycle = RunLifecycleState::Cancelled;
            state.push_activity(&format!("Run cancelled: {reason}"));
        }
        DiagnosticEventPayload::TargetDiscovered {
            url,
            depth,
            source,
            status,
        } => {
            let display_url = sanitize_url_for_display(&url, 100);
            let insp_state = match status.as_str() {
                "investigated" | "completed" => TargetInspectionState::Completed,
                "partial" => TargetInspectionState::Partial,
                "failed" | "unreachable" => TargetInspectionState::Failed,
                "budget" | "skipped" => TargetInspectionState::SkippedBudget,
                _ => TargetInspectionState::Queued,
            };
            if let Some(existing) = state
                .target_rows
                .iter_mut()
                .find(|r| r.display_url == display_url)
            {
                existing.state = insp_state;
            } else {
                state.target_rows.push(TargetSurfaceRow {
                    display_url: display_url.clone(),
                    discovery_source: sanitize_line(&source, 24),
                    depth,
                    page_type: String::from("Discovered"),
                    http_status: None,
                    state: insp_state,
                    evidence_summary: String::from("Pending"),
                    findings_count: 0,
                });
            }
            state.push_activity(&format!("Target {display_url} ({status})"));
        }
        DiagnosticEventPayload::CollectionStarted { collector } => {
            set_collector_status(
                state,
                collector,
                OperationalStatus::Running,
                "Collecting...",
            );
            state.push_activity(&format!("Collector {} started", collector.label()));
        }
        DiagnosticEventPayload::CollectionProgress {
            collector,
            completed_units,
            total_units,
            detail,
        } => {
            let progress_str = total_units.map_or_else(
                || format!("{completed_units} ({detail})"),
                |tot| format!("{completed_units}/{tot} ({detail})"),
            );
            set_collector_status(state, collector, OperationalStatus::Running, &progress_str);
        }
        DiagnosticEventPayload::CollectionCompleted {
            collector,
            partial,
            warnings,
        } => {
            let status = if partial {
                OperationalStatus::Partial
            } else {
                OperationalStatus::Done
            };
            let summary = if partial {
                format!("Partial ({} warning(s))", warnings.len())
            } else {
                String::from("Captured")
            };
            set_collector_status(state, collector, status, &summary);
            state.push_activity(&format!(
                "Collector {} completed ({summary})",
                collector.label()
            ));
        }
        DiagnosticEventPayload::CollectionFailed { collector, error } => {
            set_collector_status(state, collector, OperationalStatus::Failed, &error);
            state.push_activity(&format!("Collector {} failed: {error}", collector.label()));
        }
        DiagnosticEventPayload::CollectionSkipped { collector, reason } => {
            set_collector_status(state, collector, OperationalStatus::Skipped, &reason);
        }
        DiagnosticEventPayload::AnalysisStarted { dwarf } => {
            if let Some(row) = state.brigade_rows.iter_mut().find(|r| r.dwarf_id == dwarf) {
                row.status = OperationalStatus::Running;
                row.is_agent_activity = false;
                row.current_activity = String::from("Evaluating deterministic rules...");
            }
        }
        DiagnosticEventPayload::AnalysisCompleted {
            dwarf,
            checks_total,
            checks_passed,
            checks_failed,
            checks_skipped,
            checks_inconclusive,
        } => {
            if let Some(row) = state.brigade_rows.iter_mut().find(|r| r.dwarf_id == dwarf) {
                row.checks_total = checks_total;
                row.checks_passed = checks_passed;
                row.checks_failed = checks_failed;
                row.checks_skipped = checks_skipped;
                row.checks_inconclusive = checks_inconclusive;
                row.status = if checks_total > 0 && checks_skipped == checks_total {
                    OperationalStatus::Skipped
                } else if checks_inconclusive > 0 {
                    OperationalStatus::Partial
                } else {
                    OperationalStatus::Done
                };
                row.current_activity =
                    format!("Completed {checks_total} checks ({checks_failed} failed)");
            }
            state.push_activity(&format!(
                "{} evaluated {} checks ({} failed)",
                dwarf.display_name(),
                checks_total,
                checks_failed
            ));
        }
        DiagnosticEventPayload::FindingRecorded {
            dwarf,
            rule_id,
            title,
            severity,
            ..
        } => {
            if let Some(row) = state.brigade_rows.iter_mut().find(|r| r.dwarf_id == dwarf) {
                row.findings_count += 1;
            }
            state.push_activity(&format!(
                "[{:?}] {}: {} ({})",
                severity,
                dwarf.display_name(),
                title,
                rule_id
            ));
        }
        DiagnosticEventPayload::SpecialistActivated { dwarf, focus } => {
            if let Some(row) = state.brigade_rows.iter_mut().find(|r| r.dwarf_id == dwarf) {
                row.status = OperationalStatus::Running;
                row.is_agent_activity = true;
                row.current_activity = sanitize_line(&format!("Agent consultation: {focus}"), 100);
            }
            state.push_activity(&format!(
                "Specialist {} activated: {}",
                dwarf.display_name(),
                focus
            ));
        }
        DiagnosticEventPayload::HypothesisProposed {
            hypothesis_id,
            originating_rule,
            proposed_explanation,
            requested_tool,
        } => {
            if let Some(row) = state
                .brigade_rows
                .iter_mut()
                .find(|r| r.dwarf_id == DwarfId::Kommandant)
            {
                row.status = OperationalStatus::Running;
                row.is_agent_activity = true;
                row.current_activity =
                    sanitize_line(&format!("Testing {hypothesis_id} via {requested_tool}"), 96);
            }
            state.hypotheses.push(HypothesisRow {
                id: sanitize_line(&hypothesis_id, 32),
                originating_rule: sanitize_line(&originating_rule, 96),
                originating_rule_verified: true,
                proposed_explanation: sanitize_line(&proposed_explanation, 220),
                requested_tool: sanitize_line(&requested_tool, 64),
                status: HypothesisStatus::Proposed,
                evaluation_summary: None,
                supporting_evidence: Vec::new(),
                contradictory_evidence: Vec::new(),
                missing_evidence: Vec::new(),
            });
            state.push_activity(&format!(
                "Hypothesis {hypothesis_id} proposed (origin: {originating_rule})"
            ));
        }
        DiagnosticEventPayload::HypothesisEvaluated {
            hypothesis_id,
            status,
            summary,
        } => {
            if let Some(h) = state.hypotheses.iter_mut().find(|h| h.id == hypothesis_id) {
                h.status = match status.to_ascii_lowercase().as_str() {
                    "supported" => HypothesisStatus::Supported,
                    "rejected" => HypothesisStatus::Rejected,
                    _ => HypothesisStatus::Inconclusive,
                };
                if let Some(s) = summary {
                    h.evaluation_summary = Some(sanitize_line(&s, 220));
                }
            }
            state.push_activity(&format!("Hypothesis {hypothesis_id} evaluated: {status}"));
        }
        DiagnosticEventPayload::ToolRequested { tool_id } => {
            state.tool_trace.push(ToolActivityRow {
                tool_id: sanitize_line(&tool_id, 64),
                status: OperationalStatus::Queued,
                summary: String::from("Requested by KommandantZwerg"),
            });
            state.push_activity(&format!("Tool requested: {tool_id}"));
        }
        DiagnosticEventPayload::ToolAuthorised { tool_id } => {
            if let Some(t) = state
                .tool_trace
                .iter_mut()
                .rev()
                .find(|t| t.tool_id == tool_id)
            {
                t.status = OperationalStatus::Running;
                t.summary = String::from("Authorised and executing");
            }
        }
        DiagnosticEventPayload::ToolRejected { tool_id, reason } => {
            if let Some(t) = state
                .tool_trace
                .iter_mut()
                .rev()
                .find(|t| t.tool_id == tool_id)
            {
                t.status = OperationalStatus::Blocked;
                t.summary = sanitize_line(&reason, 100);
            }
            state.push_activity(&format!("Tool {tool_id} rejected: {reason}"));
        }
        DiagnosticEventPayload::ToolCompleted {
            tool_id,
            succeeded,
            summary,
        } => {
            if let Some(t) = state
                .tool_trace
                .iter_mut()
                .rev()
                .find(|t| t.tool_id == tool_id)
            {
                t.status = if succeeded {
                    OperationalStatus::Done
                } else {
                    OperationalStatus::Failed
                };
                t.summary = sanitize_line(&summary, 100);
            }
            state.push_activity(&format!(
                "Tool {tool_id} {}",
                if succeeded { "completed" } else { "failed" }
            ));
        }
        DiagnosticEventPayload::BudgetUpdated {
            llm_turns_used,
            max_llm_turns,
            tool_calls_used,
            max_tool_calls,
            elapsed_ms,
        } => {
            state.system_metrics.llm_turns_used = llm_turns_used;
            state.system_metrics.max_llm_turns = max_llm_turns;
            state.system_metrics.tool_calls_used = tool_calls_used;
            state.system_metrics.max_tool_calls = max_tool_calls;
            state.system_metrics.elapsed_ms = elapsed_ms;
        }
        DiagnosticEventPayload::Warning { message } => {
            state.push_activity(&format!("WARN: {message}"));
        }
    }
}

fn set_collector_status(
    state: &mut AppState,
    collector: CollectorId,
    status: OperationalStatus,
    summary: &str,
) {
    let clean = sanitize_line(summary, 72);
    if let Some(entry) = state
        .system_metrics
        .collector_statuses
        .iter_mut()
        .find(|(c, _, _)| *c == collector)
    {
        entry.1 = status;
        entry.2 = clean;
    } else {
        state
            .system_metrics
            .collector_statuses
            .push((collector, status, clean));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{DiagnosticEvent, DiagnosticEventPayload, EventContext, RunId};

    fn event(sequence: u64, dropped_events: u64) -> DiagnosticEvent {
        DiagnosticEvent {
            run_id: RunId::new("run-gap"),
            sequence,
            elapsed_ms: 5,
            dropped_progress_events: 0,
            dropped_events,
            context: EventContext::new(),
            payload: DiagnosticEventPayload::Warning {
                message: format!("event {sequence}"),
            },
        }
    }

    #[test]
    fn event_sequence_gaps_are_visible_in_system_metrics() {
        let mut state = AppState::default();
        reduce_diagnostic_event(&mut state, event(1, 0));
        reduce_diagnostic_event(&mut state, event(4, 2));

        assert_eq!(state.system_metrics.total_events_received, 2);
        assert_eq!(state.system_metrics.last_event_sequence, 4);
        assert_eq!(state.system_metrics.sequence_gap_events, 2);
        assert_eq!(state.system_metrics.dropped_events, 2);
    }

    #[test]
    fn cancellation_is_only_reported_after_the_task_settles() {
        let mut state = AppState {
            lifecycle: RunLifecycleState::Running,
            ..AppState::default()
        };
        state.launcher.open = false;

        let effects = reduce(&mut state, AppAction::User(UserAction::CancelRun));
        assert_eq!(state.lifecycle, RunLifecycleState::Cancelling);
        assert_eq!(effects, vec![AppEffect::CancelActiveRun]);

        let effects = reduce(
            &mut state,
            AppAction::CancellationSettled { escalated: false },
        );
        assert_eq!(state.lifecycle, RunLifecycleState::Cancelled);
        assert_eq!(effects.len(), 0, "settlement must not request new effects");
        assert_eq!(
            state.lifecycle.operational_status(),
            crate::tui::theme::OperationalStatus::Cancelled
        );
    }

    #[test]
    fn cancellation_that_outlives_the_deadline_is_reported_as_escalated() {
        let mut state = AppState {
            lifecycle: RunLifecycleState::Cancelling,
            ..AppState::default()
        };

        reduce(
            &mut state,
            AppAction::CancellationSettled { escalated: true },
        );

        assert_eq!(state.lifecycle, RunLifecycleState::TerminationEscalated);
        assert_eq!(
            state.lifecycle.operational_status(),
            crate::tui::theme::OperationalStatus::Failed
        );
    }
    #[test]
    fn launcher_credential_input_is_never_rendered_by_debug() {
        let mut state = AppState {
            launcher: crate::tui::state::LauncherState {
                open: true,
                focused_field: crate::tui::state::LauncherField::Credential,
                ..crate::tui::state::LauncherState::default()
            },
            ..AppState::default()
        };

        for ch in "canary-9f3".chars() {
            reduce(&mut state, AppAction::User(UserAction::InputChar(ch)));
        }

        let rendered = format!("{state:?}");
        assert!(
            !rendered.contains("canary-9f3"),
            "session credential must never appear in debug output"
        );
        assert_eq!(state.launcher.credential_input.char_count(), 10);
    }

    #[test]
    fn connection_test_is_requested_with_the_entered_model() {
        let mut state = AppState {
            launcher: crate::tui::state::LauncherState {
                open: true,
                focused_field: crate::tui::state::LauncherField::TestConnection,
                model_input: "test-model".to_owned(),
                ..crate::tui::state::LauncherState::default()
            },
            ..AppState::default()
        };

        let effects = reduce(&mut state, AppAction::User(UserAction::Activate));

        assert_eq!(state.launcher.connection, ConnectionOutcome::Testing);
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, AppEffect::TestConnection { spec, .. } if spec.model == "test-model")),
            "expected a connection test effect for the entered model"
        );
    }

    #[test]
    fn mission_without_a_model_reports_an_explicit_error() {
        let mut state = AppState {
            launcher: crate::tui::state::LauncherState {
                open: true,
                focused_field: crate::tui::state::LauncherField::StartButton,
                mode: crate::events::DiagnosticRunMode::AgenticInvestigation,
                ..crate::tui::state::LauncherState::default()
            },
            ..AppState::default()
        };

        let effects = reduce(&mut state, AppAction::User(UserAction::Activate));

        assert_eq!(effects.len(), 0);
        let message = state
            .launcher
            .error_message
            .as_deref()
            .expect("missing model must be reported");
        assert!(
            message.contains("model"),
            "error should name the missing model, got: {message}"
        );
    }
    #[test]
    fn discovered_models_prefill_and_cycle_the_model_field() {
        let mut state = AppState::default();
        state.launcher.open = true;
        state.launcher.focused_field = LauncherField::Model;

        let _ = reduce(
            &mut state,
            AppAction::ModelsDiscovered(vec!["alpha-model".to_owned(), "beta-model".to_owned()]),
        );
        assert_eq!(state.launcher.model_input, "alpha-model");
        assert_eq!(state.launcher.discovered_models.len(), 2);

        let _ = reduce(&mut state, AppAction::User(UserAction::MoveRight));
        assert_eq!(state.launcher.model_input, "beta-model");

        let _ = reduce(
            &mut state,
            AppAction::ModelDiscoveryFailed("provider rejected the request".to_owned()),
        );
        let error = state
            .launcher
            .discovery_error
            .as_deref()
            .expect("discovery failure recorded");
        assert!(error.contains("rejected"), "unexpected message: {error}");
    }
    #[test]
    fn entered_model_keeps_the_configured_endpoint_and_credential_source() {
        let config = crate::config::AppConfig {
            models: crate::config::ModelRoutingConfig {
                kommandant: Some(ModelSpec {
                    provider: ProviderKind::Anthropic,
                    model: "configured-model".to_owned(),
                    base_url: Some("https://gateway.example.com/v1".to_owned()),
                    api_key_env: Some("GATEWAY_KEY".to_owned()),
                }),
                ..crate::config::ModelRoutingConfig::default()
            },
            ..crate::config::AppConfig::default()
        };
        let mut state = AppState {
            config: Some(config),
            ..AppState::default()
        };
        state.launcher.provider = ProviderKind::Anthropic;
        state.launcher.model_input = "operator-model".to_owned();

        let spec = launcher_model_spec(&state).expect("model resolved");
        assert_eq!(spec.model, "operator-model");
        assert_eq!(
            spec.base_url.as_deref(),
            Some("https://gateway.example.com/v1"),
            "a model override must not discard the configured endpoint"
        );
        assert_eq!(spec.api_key_env.as_deref(), Some("GATEWAY_KEY"));

        state.launcher.provider = ProviderKind::Ollama;
        let spec = launcher_model_spec(&state).expect("model resolved");
        assert_eq!(
            spec.base_url, None,
            "another provider must not inherit an endpoint it does not own"
        );
    }

    #[test]
    fn changing_the_provider_invalidates_route_verification() {
        let mut state = AppState::default();
        state.launcher.open = true;
        state.launcher.focused_field = LauncherField::Provider;
        state.launcher.connection = ConnectionOutcome::Reachable;
        state.launcher.discovered_models = vec!["a".to_owned()];

        let _ = reduce(&mut state, AppAction::User(UserAction::MoveRight));

        assert_eq!(state.launcher.connection, ConnectionOutcome::NotTested);
        assert_eq!(state.launcher.discovered_models.len(), 0);
    }
}
