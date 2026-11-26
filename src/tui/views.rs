//! Pure Ratatui rendering for all Zwergenleitstand views, modals, and status bars.
//!
//! Every rendering function is a pure projection of `&AppState` into a Ratatui
//! [`Frame`]. No network I/O, filesystem access, or subprocess execution takes
//! place during rendering.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Row, Table, Wrap};

use crate::brigade::MOTTO;
use crate::domain::browser_timeline::BrowserEventDetail;
use crate::domain::{CollectorOutcome, Severity};
use crate::investigation::HypothesisStatus;
use crate::investigation::browser_timeline::{
    FailedDependencyFilter, RequestChainFilter, query_browser_timeline, query_failed_dependencies,
    query_request_chains,
};
use crate::investigation::evidence_query::{
    AccessibilityNodeFilter, ElementGeometryFilter, EvidenceQueryStatus, InteractionStepFilter,
    InteractiveElementFilter, LinkGraphFilter, MediaFontFilter, NetworkResourceFilter,
    RenderedBlockFilter, ResponsiveAnomalyFilter, RuntimeErrorFilter, SourceRenderedDiffFilter,
    StorageCookieFilter, StructuredDataFilter, ThirdPartyOriginFilter, compare_source_and_rendered,
    query_accessibility_nodes, query_application_state, query_element_geometry,
    query_indexability_authority, query_interaction_trace, query_interactive_elements,
    query_link_graph, query_media_and_fonts, query_network_resources,
    query_performance_attribution, query_rendered_content, query_responsive_comparison,
    query_runtime_errors, query_security_challenge, query_security_posture,
    query_service_worker_lifecycle, query_storage_and_cookies, query_structured_data,
    query_third_party_origins, query_tls_and_caa, query_visual_artifacts,
};
use crate::tui::sanitize::{sanitize_line, sanitize_url_for_display};
use crate::tui::state::{
    AppState, EvidenceCategory, LauncherField, WorkbenchView, format_rendered_diff_summary,
};
use crate::tui::theme::Theme;

/// Minimum supported terminal width in columns.
pub const MIN_TERMINAL_WIDTH: u16 = 80;
/// Minimum supported terminal height in rows.
pub const MIN_TERMINAL_HEIGHT: u16 = 24;

/// Top-level rendering entry point for Zwergenleitstand.
pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        render_minimum_size_fallback(frame, area, state);
        return;
    }

    let root_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header bar
            Constraint::Length(2), // Navigation bar
            Constraint::Min(14),   // Active workbench view
            Constraint::Length(2), // Footer / search / keybinding bar
        ])
        .split(area);

    render_header(frame, root_chunks[0], state);
    render_navigation_bar(frame, root_chunks[1], state);

    match state.active_view {
        WorkbenchView::Overview => render_overview(frame, root_chunks[2], state),
        WorkbenchView::Brigade => render_brigade(frame, root_chunks[2], state),
        WorkbenchView::Targets => render_targets(frame, root_chunks[2], state),
        WorkbenchView::Findings => render_findings(frame, root_chunks[2], state),
        WorkbenchView::Evidence => render_evidence(frame, root_chunks[2], state),
        WorkbenchView::Investigation => render_investigation(frame, root_chunks[2], state),
        WorkbenchView::Topology => render_topology(frame, root_chunks[2], state),
        WorkbenchView::History => render_history(frame, root_chunks[2], state),
        WorkbenchView::System => render_system(frame, root_chunks[2], state),
    }

    render_footer(frame, root_chunks[3], state);

    if state.launcher.open {
        render_launcher_modal(frame, area, state);
    }
    if state.help_open {
        render_help_modal(frame, area, state);
    }
}

fn render_minimum_size_fallback(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let msg = format!(
        "Terminal too small ({}x{}). Resize to at least {}x{} for Zwergenleitstand. Press q to quit.",
        area.width, area.height, MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT
    );
    let paragraph = Paragraph::new(msg)
        .style(state.theme.warning_style())
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let secs = state.system_metrics.elapsed_ms / 1000;
    let mins = secs / 60;
    let rem_secs = secs % 60;
    let status = state.lifecycle.operational_status();

    let line1 = Line::from(vec![
        Span::styled(
            " NETZZWERGENWACHT / ZWERGENLEITSTAND ",
            state.theme.title_style(),
        ),
        Span::styled(format!("— {MOTTO} "), state.theme.muted_style()),
        Span::raw("  "),
        Span::styled(
            format!("[{}]", status.label()),
            state.theme.status_style(status),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{mins:02}:{rem_secs:02}"),
            state.theme.primary_style(),
        ),
    ]);

    let line2 = Line::from(vec![
        Span::styled(" Target: ", state.theme.muted_style()),
        Span::styled(&state.target_url, state.theme.primary_style()),
        Span::styled("   Mode: ", state.theme.muted_style()),
        Span::styled(state.run_mode.label(), state.theme.title_style()),
        Span::styled("   Findings: ", state.theme.muted_style()),
        Span::styled(
            state.findings.len().to_string(),
            state.theme.primary_style(),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(state.theme.border_style(false));
    let paragraph = Paragraph::new(vec![line1, line2]).block(block);
    frame.render_widget(paragraph, area);
}

fn render_navigation_bar(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let mut spans = Vec::with_capacity(WorkbenchView::ALL.len() * 2);
    for view in WorkbenchView::ALL {
        let is_active = view == state.active_view;
        let label = if area.width < 110 {
            match view {
                WorkbenchView::Overview => "1:Ovr",
                WorkbenchView::Brigade => "2:Brg",
                WorkbenchView::Targets => "3:Tgt",
                WorkbenchView::Findings => "4:Fnd",
                WorkbenchView::Evidence => "5:Evd",
                WorkbenchView::Investigation => "6:Inv",
                WorkbenchView::Topology => "7:Top",
                WorkbenchView::History => "8:Hst",
                WorkbenchView::System => "9:Sys",
            }
        } else {
            view.label()
        };
        let style = if is_active {
            state.theme.selected_style()
        } else {
            state.theme.primary_style()
        };
        spans.push(Span::styled(format!(" {label} "), style));
        spans.push(Span::styled("│", state.theme.muted_style()));
    }
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(state.theme.border_style(false));
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let line1 = if state.search_focused {
        Line::from(vec![
            Span::styled(" SEARCH / FILTER: ", state.theme.title_style()),
            Span::styled(
                &state.finding_filter.search_query,
                state.theme.primary_style(),
            ),
            Span::styled(
                "_  (Enter/Esc finish, Ctrl+U clear)",
                state.theme.muted_style(),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(" STATUS: ", state.theme.muted_style()),
            Span::styled(&state.status_message, state.theme.primary_style()),
        ])
    };

    let line2 = Line::from(vec![Span::styled(
        " 1-9/Tab:View  j/k:Move  Enter:Inspect  /:Search  s:Sort  v:Severity  n:Launcher  w:Save  c:Cancel  ?:Help  q:Quit",
        state.theme.muted_style(),
    )]);

    frame.render_widget(Paragraph::new(vec![line1, line2]), area);
}

#[allow(clippy::too_many_lines)]
fn render_overview(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Min(7),
            Constraint::Length(7),
        ])
        .split(area);

    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(vertical[0]);

    // 1. Application Surface panel (honest measured counters, no fabricated % bars).
    let discovered = state.target_rows.len();
    let inspected = state
        .target_rows
        .iter()
        .filter(|r| {
            matches!(
                r.state,
                crate::tui::state::TargetInspectionState::Completed
                    | crate::tui::state::TargetInspectionState::Partial
            )
        })
        .count();
    let queued = state
        .target_rows
        .iter()
        .filter(|r| matches!(r.state, crate::tui::state::TargetInspectionState::Queued))
        .count();
    let failed = state
        .target_rows
        .iter()
        .filter(|r| matches!(r.state, crate::tui::state::TargetInspectionState::Failed))
        .count();
    let skipped = state
        .target_rows
        .iter()
        .filter(|r| {
            matches!(
                r.state,
                crate::tui::state::TargetInspectionState::SkippedBudget
            )
        })
        .count();

    let total_checks: usize = state.brigade_rows.iter().map(|b| b.checks_total).sum();
    let unverified_checks: usize = state
        .brigade_rows
        .iter()
        .map(|b| b.checks_skipped + b.checks_inconclusive)
        .sum();

    let surface_lines = vec![
        Line::from(format!(
            " Pages discovered: {discovered:<6}  Inspected: {inspected}"
        )),
        Line::from(format!(
            " Queued:           {queued:<6}  Failed:    {failed}"
        )),
        Line::from(format!(" Budget-deferred:  {skipped}")),
        Line::from(""),
        Line::from(format!(
            " Checks evaluated: {total_checks} ({unverified_checks} unverified/skipped)"
        )),
        Line::from(format!(
            " Scope: {}",
            if discovered > 1 {
                "Sampled multi-page surface"
            } else {
                "Single-target inspection"
            }
        )),
    ];
    let surface_block = Block::default()
        .title(" APPLICATION SURFACE & COVERAGE ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(surface_lines).block(surface_block),
        top_cols[0],
    );

    // 2. Findings by severity panel.
    let crit = count_severity(state, Severity::Critical);
    let high = count_severity(state, Severity::High);
    let med = count_severity(state, Severity::Medium);
    let low = count_severity(state, Severity::Low);
    let info = count_severity(state, Severity::Info);

    let findings_lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", Theme::severity_badge(Severity::Critical)),
                state.theme.severity_style(Severity::Critical),
            ),
            Span::raw(format!("Critical:      {crit}")),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {} ", Theme::severity_badge(Severity::High)),
                state.theme.severity_style(Severity::High),
            ),
            Span::raw(format!("High:          {high}")),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {} ", Theme::severity_badge(Severity::Medium)),
                state.theme.severity_style(Severity::Medium),
            ),
            Span::raw(format!("Medium:        {med}")),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {} ", Theme::severity_badge(Severity::Low)),
                state.theme.severity_style(Severity::Low),
            ),
            Span::raw(format!("Low:           {low}")),
        ]),
        Line::from(vec![
            Span::styled(
                format!(" {} ", Theme::severity_badge(Severity::Info)),
                state.theme.severity_style(Severity::Info),
            ),
            Span::raw(format!("Informational: {info}")),
        ]),
    ];
    let findings_block = Block::default()
        .title(" FINDINGS BY SEVERITY ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(findings_lines).block(findings_block),
        top_cols[1],
    );

    // 3. Middle row: Active Brigade + Collectors & Investigation.
    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(vertical[1]);

    let brigade_items: Vec<ListItem<'_>> = state
        .brigade_rows
        .iter()
        .map(|b| {
            let line = Line::from(vec![
                Span::styled(
                    format!(" {:<22} ", b.display_name),
                    state.theme.primary_style(),
                ),
                Span::styled(
                    format!("{:<9} ", b.status.label()),
                    state.theme.status_style(b.status),
                ),
                Span::styled(
                    format!(
                        "{:>2}/{:<2} chk  {:>2} iss",
                        b.checks_passed + b.checks_failed,
                        b.checks_total,
                        b.findings_count
                    ),
                    state.theme.muted_style(),
                ),
            ]);
            ListItem::new(line)
        })
        .collect();
    let brigade_list = List::new(brigade_items).block(
        Block::default()
            .title(" DIE ZWERGENBRIGADE ")
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(false)),
    );
    frame.render_widget(brigade_list, mid_cols[0]);

    let mut right_lines = Vec::new();
    for (collector, status, detail) in &state.system_metrics.collector_statuses {
        right_lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<18} ", collector.label()),
                state.theme.primary_style(),
            ),
            Span::styled(
                format!("{:<9} ", status.label()),
                state.theme.status_style(*status),
            ),
            Span::styled(sanitize_line(detail, 28), state.theme.muted_style()),
        ]));
    }
    if !state.hypotheses.is_empty() {
        right_lines.push(Line::from(""));
        right_lines.push(Line::from(Span::styled(
            format!(" Active Hypotheses: {}", state.hypotheses.len()),
            state.theme.title_style(),
        )));
        for h in state.hypotheses.iter().take(2) {
            right_lines.push(Line::from(format!(
                "  {} [{:?}] {}",
                h.id, h.status, h.originating_rule
            )));
        }
    }
    let collectors_block = Block::default()
        .title(" COLLECTORS & INVESTIGATION ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(right_lines).block(collectors_block),
        mid_cols[1],
    );

    // 4. Bottom row: Rolling recent activity log.
    let activity_lines: Vec<Line<'_>> = if state.recent_activity.is_empty() {
        vec![Line::from(Span::styled(
            " No diagnostic events recorded yet. Press n to open Launcher.",
            state.theme.muted_style(),
        ))]
    } else {
        state
            .recent_activity
            .iter()
            .rev()
            .take(5)
            .rev()
            .map(|entry| Line::from(format!(" {entry}")))
            .collect()
    };
    let activity_block = Block::default()
        .title(" RECENT ACTIVITY ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(activity_lines).block(activity_block),
        vertical[2],
    );
}

fn count_severity(state: &AppState, severity: Severity) -> usize {
    state
        .findings
        .iter()
        .filter(|f| f.severity == severity)
        .count()
}

#[allow(clippy::too_many_lines)]
fn render_brigade(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(11), Constraint::Length(8)])
        .split(area);

    let header = Row::new(vec![
        "Specialist",
        "Status",
        "Mode",
        "Checks",
        "Issues",
        "Activity",
    ])
    .style(state.theme.title_style());

    let rows: Vec<Row<'_>> = state
        .brigade_rows
        .iter()
        .enumerate()
        .map(|(idx, b)| {
            let is_selected = idx == state.selected_brigade_index;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let mode_str = if b.is_agent_activity {
                "Agent LLM"
            } else {
                "Deterministic"
            };
            let checks_str = if b.checks_total > 0 {
                format!(
                    "{}/{} ({} skip)",
                    b.checks_passed + b.checks_failed,
                    b.checks_total,
                    b.checks_skipped
                )
            } else {
                String::from("-")
            };
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.primary_style()
            };
            Row::new(vec![
                format!("{prefix}{}", b.display_name),
                b.status.label().to_owned(),
                mode_str.to_owned(),
                checks_str,
                b.findings_count.to_string(),
                sanitize_line(&b.current_activity, 50),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(24),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" DIE ZWERGENBRIGADE — SPECIALIST REGISTRY (Enter to filter findings) ")
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, chunks[0]);

    if let Some(selected) = state.brigade_rows.get(state.selected_brigade_index) {
        let details = vec![
            Line::from(vec![
                Span::styled(" Specialist:     ", state.theme.muted_style()),
                Span::styled(selected.display_name, state.theme.title_style()),
                Span::styled("   Role: ", state.theme.muted_style()),
                Span::styled(format!("{:?}", selected.role), state.theme.primary_style()),
                Span::styled("   Evidence level: ", state.theme.muted_style()),
                Span::styled(
                    format!("{:?}", selected.required_evidence),
                    state.theme.primary_style(),
                ),
            ]),
            Line::from(vec![
                Span::styled(" Responsibility: ", state.theme.muted_style()),
                Span::styled(selected.responsibility, state.theme.primary_style()),
            ]),
            Line::from(format!(
                " Checks:         {} total | {} passed | {} failed | {} skipped | {} inconclusive",
                selected.checks_total,
                selected.checks_passed,
                selected.checks_failed,
                selected.checks_skipped,
                selected.checks_inconclusive
            )),
            Line::from(format!(
                " Activity:       {} ({})",
                selected.current_activity,
                if selected.is_agent_activity {
                    "LLM Specialist Reasoning"
                } else {
                    "Deterministic Analyser"
                }
            )),
        ];
        let detail_block = Block::default()
            .title(format!(" SELECTED SPECIALIST: {} ", selected.display_name))
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(false));
        frame.render_widget(Paragraph::new(details).block(detail_block), chunks[1]);
    }
}

fn render_targets(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let cols = if area.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area)
    };

    let header =
        Row::new(vec!["State", "HTTP", "Depth", "URL", "Issues"]).style(state.theme.title_style());
    let rows: Vec<Row<'_>> = state
        .target_rows
        .iter()
        .enumerate()
        .map(|(idx, row)| {
            let is_selected = idx == state.selected_target_index;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let http = row
                .http_status
                .map_or_else(|| String::from("---"), |c| c.to_string());
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.primary_style()
            };
            Row::new(vec![
                format!("{prefix}{}", row.state.label()),
                http,
                row.depth.to_string(),
                row.display_url.clone(),
                row.findings_count.to_string(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(24),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " APPLICATION TARGET SURFACE ({} page(s)) ",
                state.target_rows.len()
            ))
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, cols[0]);

    let detail_lines = if let Some(selected) = state.target_rows.get(state.selected_target_index) {
        vec![
            Line::from(vec![
                Span::styled(" URL:       ", state.theme.muted_style()),
                Span::styled(&selected.display_url, state.theme.title_style()),
            ]),
            Line::from(format!(" Status:    {}", selected.state.label())),
            Line::from(format!(
                " HTTP Code: {}",
                selected
                    .http_status
                    .map_or_else(|| String::from("Not observed"), |c| c.to_string())
            )),
            Line::from(format!(" Source:    {}", selected.discovery_source)),
            Line::from(format!(" Depth:     {}", selected.depth)),
            Line::from(format!(" Page Type: {}", selected.page_type)),
            Line::from(format!(" Evidence:  {}", selected.evidence_summary)),
            Line::from(format!(" Findings:  {}", selected.findings_count)),
        ]
    } else {
        vec![Line::from(Span::styled(
            " No targets inspected yet.",
            state.theme.muted_style(),
        ))]
    };

    let detail_block = Block::default()
        .title(" PAGE DETAILS ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        cols[1],
    );
}

#[allow(clippy::too_many_lines)]
fn render_findings(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let cols = if area.width >= 100 {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area)
    };

    let total_visible = state.visible_finding_indices.len();
    let window_size = usize::from(cols[0].height.saturating_sub(4)).max(1);
    let window_start = if state.selected_finding_pos >= window_size {
        state.selected_finding_pos + 1 - window_size
    } else {
        0
    };

    let header =
        Row::new(vec!["Sev", "Dwarf", "Rule ID", "Title"]).style(state.theme.title_style());
    let rows: Vec<Row<'_>> = state
        .visible_finding_indices
        .iter()
        .enumerate()
        .skip(window_start)
        .take(window_size)
        .filter_map(|(pos, &finding_idx)| {
            let f = state.findings.get(finding_idx)?;
            let is_selected = pos == state.selected_finding_pos;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.severity_style(f.severity)
            };
            Some(
                Row::new(vec![
                    format!("{prefix}{}", Theme::severity_badge(f.severity)),
                    f.dwarf_id.profile().display_name.to_owned(),
                    f.rule_id.clone(),
                    f.title.clone(),
                ])
                .style(style),
            )
        })
        .collect();

    let title = format!(
        " FINDINGS ({}/{} | Sort: {} | Filter: {}) ",
        total_visible,
        state.findings.len(),
        state.finding_sort.label(),
        state.finding_filter.severity_label()
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(18),
            Constraint::Length(24),
            Constraint::Min(18),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, cols[0]);

    let detail_lines = if let Some(finding) = state.selected_finding() {
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    format!(" {} ", Theme::severity_badge(finding.severity)),
                    state.theme.severity_style(finding.severity),
                ),
                Span::styled(
                    format!(
                        " {} | Confidence: {:?} | Evidence: {:?}",
                        finding.rule_id, finding.confidence, finding.evidence_level
                    ),
                    state.theme.title_style(),
                ),
            ]),
            Line::from(format!(
                " Specialist: {}",
                finding.dwarf_id.profile().display_name
            )),
            Line::from(format!(" Title:      {}", finding.title)),
            Line::from(""),
            Line::from(Span::styled(
                " Diagnostic Observation:",
                state.theme.title_style(),
            )),
            Line::from(format!(" {}", finding.description)),
            Line::from(""),
            Line::from(Span::styled(
                " Supporting Evidence (Press Enter to open in Evidence Explorer):",
                state.theme.title_style(),
            )),
        ];
        for (i, ev) in finding.evidence_refs.iter().enumerate() {
            lines.push(Line::from(format!(
                "  [{}] {:?}: {}",
                i + 1,
                ev.source,
                sanitize_line(&ev.detail, 90)
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Recommended Remediation:",
            state.theme.title_style(),
        )));
        lines.push(Line::from(format!(" {}", finding.recommendation)));
        lines
    } else {
        vec![Line::from(Span::styled(
            " No finding selected.",
            state.theme.muted_style(),
        ))]
    };

    let detail_block = Block::default()
        .title(" FINDING DETAILS ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        cols[1],
    );
}

#[allow(clippy::too_many_lines)]
fn render_evidence(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10)])
        .split(area);

    // Category selector bar (`h`/`l` or `Left`/`Right` switches category).
    let mut cat_spans = Vec::new();
    for cat in EvidenceCategory::ALL {
        let is_selected = cat == state.evidence_category;
        let style = if is_selected {
            state.theme.selected_style()
        } else {
            state.theme.primary_style()
        };
        cat_spans.push(Span::styled(format!(" {} ", cat.label()), style));
        cat_spans.push(Span::styled("│", state.theme.muted_style()));
    }
    let cat_block = Block::default()
        .title(" EVIDENCE FAMILIES (h/l or Left/Right to switch, PageUp/PageDown to paginate) ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(Line::from(cat_spans)).block(cat_block),
        chunks[0],
    );

    let Some(ref snapshot) = state.snapshot else {
        let lines = render_offline_report_evidence_fallback(state);
        let block = Block::default()
            .title(format!(
                " EVIDENCE EXPLORER / {} ",
                state.evidence_category.label()
            ))
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true));
        frame.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
        return;
    };

    let lines = match state.evidence_category {
        EvidenceCategory::Http => build_http_evidence_lines(snapshot),
        EvidenceCategory::Tls => build_tls_evidence_lines(snapshot),
        EvidenceCategory::RenderedContent => {
            let page = query_rendered_content(
                snapshot,
                &RenderedBlockFilter::default(),
                state.evidence_offset,
            );
            let mut out = vec![Line::from(format!(
                " Status: {} | Total blocks: {} | Offset: {} | ID census complete: {:?}",
                format_query_status(&page.status),
                page.total_matching,
                state.evidence_offset,
                page.id_census_complete
            ))];
            out.push(Line::from(
                " Note: Raw visible_text is omitted by design; SHA-256 text_fingerprint is shown.",
            ));
            out.push(Line::from(""));
            for block in &page.blocks {
                let fp = block
                    .text_fingerprint
                    .map_or("unavailable", |f| f.digest.as_str());
                out.push(Line::from(format!(
                    " Node #{:<4} [{:?}] vis={:?} words={} chars={} fp={}",
                    block.node,
                    block.kind,
                    block.visibility,
                    block.visible_word_count,
                    block.visible_char_count,
                    sanitize_line(fp, 24)
                )));
            }
            out
        }
        EvidenceCategory::SourceRenderedDiff => build_source_rendered_diff_lines(snapshot, state),
        EvidenceCategory::NetworkResources => {
            let page = query_network_resources(
                snapshot,
                &NetworkResourceFilter::default(),
                state.evidence_offset,
            );
            let mut out = vec![Line::from(format!(
                " Status: {} | Matching resources: {} | Offset: {} | Truncated: {}",
                format_query_status(&page.status),
                page.total_matching,
                state.evidence_offset,
                page.resources_truncated
            ))];
            out.push(Line::from(""));
            out.push(Line::from(
                " RESOURCE WATERFALL (Observed start_time_ms & duration_ms):",
            ));
            // The axis spans only observed start times and durations; an
            // unobserved duration must not shorten a bar or stretch the scale.
            let max_end_ms = page
                .resources
                .iter()
                .filter_map(|r| {
                    let start = r.start_time_ms?;
                    Some(match r.duration_ms {
                        Some(duration) => start.saturating_add(duration),
                        None => start,
                    })
                })
                .max()
                .unwrap_or(1)
                .max(1);
            for res in &page.resources {
                let status = res
                    .status_code
                    .map_or_else(|| String::from("---"), |c| c.to_string());
                let size_kib = res
                    .transfer_size
                    .map_or_else(|| String::from("? KiB"), |b| format!("{} KiB", b / 1024));
                let bar = build_waterfall_bar(
                    res.start_time_ms,
                    res.duration_ms,
                    max_end_ms,
                    state.theme.glyphs.bar_fill(),
                );
                out.push(Line::from(format!(
                    " {:<8} {:>3} {:>8} |{}| {}",
                    sanitize_line(&res.resource_type, 8),
                    status,
                    size_kib,
                    bar,
                    sanitize_url_for_display(&res.url, 52)
                )));
            }
            out
        }
        EvidenceCategory::BrowserTimeline => {
            if let Some(page) = query_browser_timeline(snapshot, state.evidence_offset) {
                let mut out = vec![Line::from(format!(
                    " Status: Captured | Page events: {} | Offset: {} | Truncated: {} | End: {:?}",
                    page.events.len(),
                    state.evidence_offset,
                    page.truncated,
                    page.end
                ))];
                out.push(Line::from(""));
                for ev in page.events {
                    let detail = match &ev.detail {
                        BrowserEventDetail::RequestStarted { method, origin, .. } => {
                            format!(
                                "REQ {} {}",
                                method.as_deref().unwrap_or("GET"),
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::Redirect { status, origin, .. } => {
                            format!(
                                "REDIRECT HTTP {:?} -> {}",
                                status,
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::Response { status, origin, .. } => {
                            format!(
                                "RESP HTTP {:?} {}",
                                status,
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::Completed { encoded_bytes, .. } => encoded_bytes
                            .map_or_else(
                                || String::from("COMPLETED (size unobserved)"),
                                |bytes| format!("COMPLETED ({bytes} B)"),
                            ),
                        BrowserEventDetail::NetworkFailure => {
                            String::from("NET FAIL: transport error")
                        }
                        BrowserEventDetail::Cancelled => String::from("CANCELLED"),
                        BrowserEventDetail::BrowserBlocked => String::from("BROWSER BLOCKED"),
                        BrowserEventDetail::PolicyBlocked { origin, .. } => {
                            format!(
                                "POLICY BLOCKED: {}",
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::RuntimeError { category, .. } => {
                            format!("RUNTIME {category:?}")
                        }
                    };
                    out.push(Line::from(format!(
                        " Seq {:<4} | {:<18} | {}",
                        ev.sequence,
                        format!("{:?}", ev.time),
                        detail
                    )));
                }
                out
            } else {
                vec![Line::from(
                    " Status: Unavailable / Skipped — Browser timeline was not collected for this run.",
                )]
            }
        }
        EvidenceCategory::RequestChainsAndFailures => {
            build_request_chains_and_failures_lines(snapshot, state)
        }
        EvidenceCategory::RuntimeErrors => {
            let page = query_runtime_errors(
                snapshot,
                &RuntimeErrorFilter::default(),
                state.evidence_offset,
            );
            let mut out = vec![Line::from(format!(
                " Status: {} | Matching runtime errors: {} | Offset: {}",
                format_query_status(&page.status),
                page.total_matching,
                state.evidence_offset
            ))];
            out.push(Line::from(""));
            for err in &page.console_errors {
                out.push(Line::from(format!(
                    " [{}] {} (source: {})",
                    sanitize_line(err.error_kind.as_deref().unwrap_or(&err.level), 20),
                    sanitize_line(&err.text, 80),
                    err.source_url.as_deref().map_or_else(
                        || String::from("unavailable"),
                        |u| sanitize_url_for_display(u, 40)
                    )
                )));
            }
            out
        }
        EvidenceCategory::InteractiveAndState => build_interactive_and_state_lines(snapshot, state),
        EvidenceCategory::VisualGeometryAndAx => {
            build_visual_geometry_and_ax_lines(snapshot, state)
        }
        EvidenceCategory::SecurityAndPrivacy => build_security_and_privacy_lines(snapshot, state),
        EvidenceCategory::PerformanceAndMedia => build_performance_and_media_lines(snapshot, state),
        EvidenceCategory::SeoAndStructuredData => {
            build_seo_and_structured_data_lines(snapshot, state)
        }
        EvidenceCategory::ResponsiveAndLinks => build_responsive_and_links_lines(snapshot, state),
        EvidenceCategory::VisualSwAndTlsCaa => build_visual_sw_and_tls_caa_lines(snapshot),
        EvidenceCategory::Performance => build_performance_evidence_lines(snapshot),
        EvidenceCategory::Accessibility => build_accessibility_evidence_lines(snapshot),
        EvidenceCategory::Lighthouse => build_lighthouse_evidence_lines(snapshot),
        EvidenceCategory::Axe => build_axe_evidence_lines(snapshot),
    };

    let block = Block::default()
        .title(format!(
            " EVIDENCE EXPLORER / {} ",
            state.evidence_category.label()
        ))
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(true));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn format_query_status(status: &EvidenceQueryStatus) -> String {
    match status {
        EvidenceQueryStatus::Captured => String::from("Captured"),
        EvidenceQueryStatus::Partial { warnings } => {
            format!("Partial ({} warning(s))", warnings.len())
        }
        EvidenceQueryStatus::Failed { error } => format!("Failed ({})", sanitize_line(error, 60)),
        EvidenceQueryStatus::Skipped { reason } => {
            format!("Skipped ({})", sanitize_line(reason, 60))
        }
        EvidenceQueryStatus::Unavailable { reason } => {
            format!("Unavailable ({})", sanitize_line(reason, 60))
        }
    }
}

fn build_waterfall_bar(
    start_ms: Option<u64>,
    duration_ms: Option<u64>,
    max_end_ms: u64,
    fill_ch: &str,
) -> String {
    const WIDTH: usize = 16;
    let Some(start) = start_ms else {
        return "................".to_owned();
    };
    let start_col = usize::try_from((start.saturating_mul(WIDTH as u64)) / max_end_ms)
        .unwrap_or(0)
        .min(WIDTH - 1);
    // An unobserved duration marks only the observed start instant instead of
    // inventing a plausible span.
    let end_col = match duration_ms {
        Some(duration) => {
            let span_cols =
                usize::try_from((duration.max(1).saturating_mul(WIDTH as u64)) / max_end_ms)
                    .unwrap_or(1)
                    .max(1);
            (start_col + span_cols).min(WIDTH)
        }
        None => start_col + 1,
    };
    let mut bar = String::with_capacity(WIDTH);
    for col in 0..WIDTH {
        if col >= start_col && col < end_col {
            bar.push_str(fill_ch);
        } else {
            bar.push(' ');
        }
    }
    bar
}

fn build_http_evidence_lines(snapshot: &crate::domain::EvidenceSnapshot) -> Vec<Line<'static>> {
    match &snapshot.http {
        CollectorOutcome::Captured { data: http }
        | CollectorOutcome::Partial { data: http, .. } => {
            let mut lines = vec![
                Line::from(format!(
                    " Status: Captured | HTTP {} | Redirects: {} | Elapsed: {:?}",
                    http.status_code,
                    http.redirect_chain.len(),
                    http.elapsed_ms
                )),
                Line::from(format!(
                    " Final URL: {}",
                    sanitize_url_for_display(&http.final_url, 100)
                )),
                Line::from(format!(
                    " Body bytes: {} (truncated: {})",
                    http.body_bytes, http.body_truncated
                )),
                Line::from(""),
                Line::from(format!(" Headers ({} captured):", http.headers.len())),
            ];
            for h in http.headers.iter().take(12) {
                lines.push(Line::from(format!(
                    "  {}: {}",
                    sanitize_line(&h.name, 36),
                    sanitize_line(&h.value, 80)
                )));
            }
            lines
        }
        CollectorOutcome::Failed { error } => {
            vec![Line::from(format!(
                " Status: Failed — {}",
                sanitize_line(error, 100)
            ))]
        }
        CollectorOutcome::Skipped { reason } => {
            vec![Line::from(format!(
                " Status: Skipped — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_tls_evidence_lines(snapshot: &crate::domain::EvidenceSnapshot) -> Vec<Line<'static>> {
    match &snapshot.tls {
        CollectorOutcome::Captured { data: tls } | CollectorOutcome::Partial { data: tls, .. } => {
            let mut lines = vec![
                Line::from(" Status: Captured"),
                Line::from(format!(
                    " Subject:          {}",
                    sanitize_line(&tls.subject, 90)
                )),
                Line::from(format!(
                    " Issuer:           {}",
                    sanitize_line(&tls.issuer, 90)
                )),
                Line::from(format!(
                    " Valid NotBefore:  {:?} | Valid NotAfter: {} (Unix secs)",
                    tls.not_before_unix_secs, tls.not_after_unix_secs
                )),
                Line::from(format!(
                    " Days remaining:   {} | Self-signed: {}",
                    tls.days_until_expiry, tls.self_signed
                )),
                Line::from(format!(
                    " Algorithms:       pub={} sig={}",
                    sanitize_line(tls.public_key_algorithm.as_deref().unwrap_or("unknown"), 32),
                    sanitize_line(tls.signature_algorithm.as_deref().unwrap_or("unknown"), 32)
                )),
                Line::from(format!(
                    " SAN entries ({}):  {}",
                    tls.san_entries.len(),
                    if tls.san_entries.is_empty() {
                        String::from("none")
                    } else {
                        sanitize_line(&tls.san_entries.join(", "), 80)
                    }
                )),
                Line::from(format!(
                    " DNS CAA query:    outcome={:?} | records ({}): {}",
                    tls.caa_lookup_outcome,
                    tls.caa_records.len(),
                    if tls.caa_records.is_empty() {
                        String::from("none")
                    } else {
                        sanitize_line(&tls.caa_records.join("; "), 80)
                    }
                )),
            ];
            if lines.is_empty() {
                lines.push(Line::from(" Status: Captured"));
            }
            lines
        }
        CollectorOutcome::Failed { error } => {
            vec![Line::from(format!(
                " Status: Failed — {}",
                sanitize_line(error, 100)
            ))]
        }
        CollectorOutcome::Skipped { reason } => {
            vec![Line::from(format!(
                " Status: Skipped — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_source_rendered_diff_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let page = compare_source_and_rendered(
        snapshot,
        &SourceRenderedDiffFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![
        Line::from(format!(
            " Status: {} | Classification: {:?} | Roles: {} | Offset: {}",
            format_query_status(&page.status),
            page.classification,
            page.total_matching,
            state.evidence_offset
        )),
        Line::from(format!(
            " Source blocks/words: {}/{} | Rendered blocks/words: {}/{} (visible: {}) | Delta ratio: {}%%",
            page.source_total_blocks,
            page.source_total_words,
            page.rendered_total_blocks,
            page.rendered_total_words,
            page.rendered_visible_blocks,
            page.word_delta_milli
        )),
        Line::from(format!(
            " Client-only roles: {:?} | SSR-only roles: {:?}",
            page.client_only_roles, page.ssr_only_roles
        )),
        Line::from(""),
    ];
    for role in &page.roles {
        out.push(Line::from(format!(
            " [{:?}] src_blocks={} src_words={} | dom_blocks={} (vis={}, hid={}) dom_words={} | client_only={} ssr_only={}",
            role.role,
            role.source_blocks,
            role.source_words,
            role.rendered_blocks,
            role.rendered_visible_blocks,
            role.rendered_hidden_blocks,
            role.rendered_visible_words,
            role.client_only,
            role.ssr_only
        )));
    }
    out
}

fn build_request_chains_and_failures_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let chains = query_request_chains(
        snapshot,
        &RequestChainFilter::default(),
        state.evidence_offset,
    );
    let failures = query_failed_dependencies(
        snapshot,
        &FailedDependencyFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![
        Line::from(format!(
            " Status: {} | Chains: {} | Failed dependencies: {} | Offset: {}",
            format_query_status(&chains.status),
            chains.total_matching,
            failures.total_matching,
            state.evidence_offset
        )),
        Line::from(""),
        Line::from(" MULTI-HOP REQUEST CHAINS:"),
    ];
    for chain in chains.chains.iter().take(8) {
        out.push(Line::from(format!(
            "  Req #{:<3} hops={} [{:?}] {} -> {} ({})",
            chain.request_id,
            chain.total_hops,
            chain.outcome,
            sanitize_line(chain.initial_origin.unwrap_or("?"), 28),
            sanitize_line(chain.final_origin.unwrap_or("?"), 28),
            sanitize_line(chain.endpoint_path.unwrap_or("/"), 36)
        )));
    }
    out.push(Line::from(""));
    out.push(Line::from(" FAILED DEPENDENCIES:"));
    for dep in failures.dependencies.iter().take(8) {
        out.push(Line::from(format!(
            "  Seq {:<4} [{:?}] status={:?} type={} origin={} path={}",
            dep.sequence,
            dep.category,
            dep.status_code,
            sanitize_line(dep.resource_type.unwrap_or("?"), 12),
            sanitize_line(dep.origin.unwrap_or("?"), 28),
            sanitize_line(dep.endpoint_path.unwrap_or("/"), 36)
        )));
    }
    out
}

fn build_interactive_and_state_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let elems = query_interactive_elements(
        snapshot,
        &InteractiveElementFilter::default(),
        state.evidence_offset,
    );
    let app_state = query_application_state(snapshot);
    let trace = query_interaction_trace(
        snapshot,
        &InteractionStepFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![Line::from(format!(
        " Status: {} | Interactive controls: {} | Trace steps: {} | Offset: {}",
        format_query_status(&elems.status),
        elems.total_matching,
        trace.total_matching,
        state.evidence_offset
    ))];
    if let Some(st) = app_state.state {
        out.push(Line::from(format!(
            " App State: ready={} modal_open={} dialogs={} expanded={} disabled={} invalid_inputs={} idle={}",
            sanitize_line(&st.document_ready_state, 16),
            st.modal_open,
            st.active_dialog_count,
            st.expanded_control_count,
            st.disabled_control_count,
            st.invalid_input_count,
            st.network_idle_reached
        )));
    }
    out.push(Line::from(""));
    for el in elems.elements.iter().take(8) {
        out.push(Line::from(format!(
            "  Node #{:<4} <{}> role={} [{:?} / {:?}] vis={} focus={} named={}",
            el.node,
            sanitize_line(&el.tag, 12),
            sanitize_line(el.role.as_deref().unwrap_or("-"), 14),
            el.functional_kind,
            el.safety_class,
            el.visible,
            el.keyboard_focusable,
            el.name_present
        )));
    }
    if !trace.steps.is_empty() {
        out.push(Line::from(""));
        out.push(Line::from(format!(
            " INTERACTION TRACE (Candidate scenarios: {:?}):",
            trace.candidate_scenarios
        )));
        for step in trace.steps.iter().take(6) {
            out.push(Line::from(format!(
                "  Step #{:<2} [{:?}] target={:?} changed={} focus_chg={} exp_chg={} dlg_chg={} dom_chg={}",
                step.step_index,
                step.action,
                step.target_node,
                step.state_changed,
                step.focus_changed,
                step.expanded_changed,
                step.dialog_changed,
                step.dom_fingerprint_changed
            )));
        }
    }
    out
}

fn build_visual_geometry_and_ax_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let geom = query_element_geometry(
        snapshot,
        &ElementGeometryFilter::default(),
        state.evidence_offset,
    );
    let ax = query_accessibility_nodes(
        snapshot,
        &AccessibilityNodeFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![
        Line::from(format!(
            " Geometry Status: {} ({} elements) | AX Nodes Status: {} ({} nodes) | Offset: {}",
            format_query_status(&geom.status),
            geom.total_matching,
            format_query_status(&ax.status),
            ax.total_matching,
            state.evidence_offset
        )),
        Line::from(""),
        Line::from(" ELEMENT GEOMETRY & OVERFLOW / OCCLUSION:"),
    ];
    for el in geom.elements.iter().take(7) {
        out.push(Line::from(format!(
            "  Node #{:<4} <{}> {}x{} @ ({},{}) ovf_x={}px ovf_y={}px clipped={} occluded={}",
            el.node,
            sanitize_line(&el.tag, 12),
            el.bbox.width,
            el.bbox.height,
            el.bbox.x,
            el.bbox.y,
            el.horizontal_overflow_px,
            el.vertical_overflow_px,
            el.clipped_by_overflow,
            el.occluded_at_center
        )));
    }
    out.push(Line::from(""));
    out.push(Line::from(" ACCESSIBILITY TREE NODES:"));
    for node in ax.nodes.iter().take(7) {
        out.push(Line::from(format!(
            "  AX #{:<4} role={:<16} interactive={} focusable={} named={} ignored={}",
            node.node_index,
            sanitize_line(&node.role, 16),
            node.interactive,
            node.focusable,
            node.name_present,
            node.ignored
        )));
    }
    out
}

fn build_security_and_privacy_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let posture = query_security_posture(snapshot);
    let challenge = query_security_challenge(snapshot);
    let storage = query_storage_and_cookies(
        snapshot,
        &StorageCookieFilter::default(),
        state.evidence_offset,
    );
    let third_party = query_third_party_origins(
        snapshot,
        &ThirdPartyOriginFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![Line::from(format!(
        " Status: {} | Cookies: {} | Storage keys: {} | 3P origins: {} | Offset: {}",
        format_query_status(&posture.status),
        storage.total_matching_cookies,
        storage.total_matching_storage_keys,
        third_party.total_matching,
        state.evidence_offset
    ))];
    if let Some(p) = posture.posture {
        out.push(Line::from(format!(
            " Headers: CSP={} (unsafe-inline={}, unsafe-eval={}) HSTS={} XCTO={} XFO={} COOP={}",
            p.csp_present,
            p.csp_unsafe_inline_script,
            p.csp_unsafe_eval_script,
            p.hsts_present,
            p.x_content_type_options_nosniff,
            p.x_frame_options_present,
            p.coop_present
        )));
    }
    if let Some(ch) = challenge.challenge {
        out.push(Line::from(format!(
            " Challenge / Bot Wall: detected={} provider={:?} blocking={} captcha_frames={}",
            ch.challenge_detected, ch.provider, ch.blocking_page_content, ch.captcha_frame_count
        )));
    }
    out.push(Line::from(""));
    for c in storage.cookies.iter().take(5) {
        out.push(Line::from(format!(
            "  Cookie {:<24} secure={} http_only={} same_site={:?} third_party={} pre_consent={}",
            sanitize_line(&c.name, 24),
            c.secure,
            c.http_only,
            c.same_site,
            c.third_party
                .map_or("unobserved".to_owned(), |v| v.to_string()),
            c.observed_before_consent
                .map_or("unobserved".to_owned(), |v| v.to_string())
        )));
    }
    for tp in third_party.origins.iter().take(5) {
        out.push(Line::from(format!(
            "  3P Origin {:<32} reqs={} scripts={} script_element_present={} sri_missing={}",
            sanitize_line(&tp.origin, 32),
            tp.total_requests,
            tp.script_requests,
            tp.capability.script_element_present_in_main_frame,
            tp.capability.script_without_sri_count
        )));
    }
    out
}

fn build_performance_and_media_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let perf = query_performance_attribution(snapshot);
    let media = query_media_and_fonts(snapshot, &MediaFontFilter::default(), state.evidence_offset);
    let mut out = vec![Line::from(format!(
        " Perf Attribution Status: {} | Media assets: {} | Fonts: {} | Offset: {}",
        format_query_status(&perf.status),
        media.total_matching_media,
        media.total_matching_fonts,
        state.evidence_offset
    ))];
    if let Some(attr) = perf.attribution {
        if let Some(ref lcp) = attr.lcp_candidate {
            out.push(Line::from(format!(
                " LCP Candidate: <{}> render={:?}ms size={}px² origin={}",
                sanitize_line(&lcp.tag, 14),
                lcp.render_time_ms,
                lcp.size_px_sq,
                sanitize_line(lcp.resource_origin.as_deref().unwrap_or("inline/dom"), 32)
            )));
        }
        out.push(Line::from(format!(
            " CLSTotal={} ({} shift regions) | Render-blocking head: {} scripts, {} stylesheets | deferred/async: {} | confirmed bytes: {}",
            attr.total_cls_milli
                .map_or("unobserved".to_owned(), |v| format!("{v}‰")),
            attr.cls_shift_regions.len(),
            attr.render_blocking_chain.blocking_head_scripts,
            attr.render_blocking_chain.blocking_head_stylesheets,
            attr.render_blocking_chain.deferred_or_async_script_count,
            attr.render_blocking_chain
                .confirmed_blocking_transfer_bytes
                .map_or("unobserved".to_owned(), |v| v.to_string())
        )));
    }
    out.push(Line::from(""));
    for m in media.media_assets.iter().take(6) {
        out.push(Line::from(format!(
            "  Media #{:<3} <{}> {:?} natural={}x{} rendered={}x{} oversize={}‰ lazy={:?}",
            m.node,
            sanitize_line(&m.tag, 10),
            m.format_class,
            m.natural_width,
            m.natural_height,
            m.rendered_width,
            m.rendered_height,
            m.oversize_ratio_milli,
            m.loading
        )));
    }
    for f in media.font_assets.iter().take(5) {
        out.push(Line::from(format!(
            "  Font #{:<3} family={:<20} weight={:<6} display={:?} status={}",
            f.index,
            sanitize_line(&f.font_family, 20),
            sanitize_line(&f.font_weight, 6),
            f.font_display,
            sanitize_line(&f.status, 12)
        )));
    }
    out
}

fn build_seo_and_structured_data_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let idx = query_indexability_authority(snapshot);
    let sd = query_structured_data(
        snapshot,
        &StructuredDataFilter::default(),
        state.evidence_offset,
    );
    let mut out = vec![Line::from(format!(
        " Indexability Status: {} | Structured entities: {} | Issues: {} | Offset: {}",
        format_query_status(&idx.status),
        sd.total_matching_entities,
        sd.issues.len(),
        state.evidence_offset
    ))];
    if let Some(auth) = idx.authority {
        out.push(Line::from(format!(
            " Indexable: {} | Canonical: {:?} | Conflicts: {:?}",
            auth.effectively_indexable, auth.rendered_canonical_path, auth.conflicts
        )));
    }
    if let Some(card) = sd.social_card {
        out.push(Line::from(format!(
            " Social Preview: OG complete={} (title={}, desc={}, img={}) | Twitter complete={}",
            card.og_complete,
            card.og_title_present,
            card.og_description_present,
            card.og_image_present,
            card.twitter_complete
        )));
    }
    out.push(Line::from(""));
    for ent in sd.entities.iter().take(7) {
        out.push(Line::from(format!(
            "  Entity #{:<2} [{:?}] @type={:<20} valid={} missing_required={:?}",
            ent.entity_index,
            ent.syntax,
            sanitize_line(&ent.schema_type, 20),
            ent.valid,
            ent.missing_required_fields
        )));
    }
    out
}

fn build_responsive_and_links_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
    state: &AppState,
) -> Vec<Line<'static>> {
    let resp = query_responsive_comparison(
        snapshot,
        &ResponsiveAnomalyFilter::default(),
        state.evidence_offset,
    );
    let links = query_link_graph(snapshot, &LinkGraphFilter::default(), state.evidence_offset);
    let mut out = vec![Line::from(format!(
        " Responsive Status: {} ({} anomalies) | Link Graph: {} links | Offset: {}",
        format_query_status(&resp.status),
        resp.total_matching_anomalies,
        links.total_matching,
        state.evidence_offset
    ))];
    if let Some(summary) = links.cluster_summary {
        out.push(Line::from(format!(
            " Links Summary: internal={} external={} header/nav={} main={} footer={} empty_anchor={}",
            summary.internal_links,
            summary.external_links,
            summary.header_nav_links,
            summary.main_content_links,
            summary.footer_links,
            summary.empty_anchor_links
        )));
    }
    out.push(Line::from(""));
    for anom in resp.anomalies.iter().take(5) {
        out.push(Line::from(format!(
            "  Anomaly #{:<2} [{:?}] <{}> mobile_val={} desktop_val={}",
            anom.anomaly_index,
            anom.kind,
            sanitize_line(&anom.tag, 12),
            anom.mobile_metric_px,
            anom.desktop_metric_px
                .map_or_else(|| "unobserved".to_owned(), |value| value.to_string())
        )));
    }
    for link in links.links.iter().take(7) {
        out.push(Line::from(format!(
            "  Link #{:<3} [{:?}] same_origin={} words={} target={}{}",
            link.link_index,
            link.placement_region,
            link.same_origin,
            link.anchor_word_count,
            sanitize_line(link.target_origin.as_deref().unwrap_or(""), 24),
            sanitize_line(link.target_path.as_deref().unwrap_or("/"), 36)
        )));
    }
    out
}

fn build_visual_sw_and_tls_caa_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    let vis = query_visual_artifacts(snapshot);
    let sw = query_service_worker_lifecycle(snapshot);
    let tls_caa = query_tls_and_caa(snapshot);
    let mut out = vec![Line::from(format!(
        " Visual Status: {} | Service Worker Status: {} | TLS/CAA Status: {}",
        format_query_status(&vis.status),
        format_query_status(&sw.status),
        format_query_status(&tls_caa.status)
    ))];
    if let Some(v) = vis.artifacts {
        out.push(Line::from(format!(
            " Screenshot SHA-256: {} ({} B) | Estimated retained-rect coverage: {}‰ ({}x{} grid, {}/{} rects{}) | Landmarks: {}",
            sanitize_line(
                v.viewport_screenshot_sha256
                    .as_deref()
                    .unwrap_or("unavailable"),
                24
            ),
            v.screenshot_byte_len
                .map_or_else(|| "unobserved".to_owned(), |bytes| bytes.to_string()),
            v.above_fold_retained_element_coverage_milli
                .map_or_else(|| "unobserved".to_owned(), |milli| milli.to_string()),
            v.coverage_grid_columns
                .map_or_else(|| "?".to_owned(), |value| value.to_string()),
            v.coverage_grid_rows
                .map_or_else(|| "?".to_owned(), |value| value.to_string()),
            v.coverage_retained_element_count
                .map_or_else(|| "?".to_owned(), |value| value.to_string()),
            v.coverage_retained_element_limit
                .map_or_else(|| "?".to_owned(), |value| value.to_string()),
            if v.coverage_elements_truncated {
                ", truncated"
            } else {
                ""
            },
            v.landmarks.len()
        )));
    }
    if let Some(s) = sw.lifecycle {
        out.push(Line::from(format!(
            " Service Worker: state={:?} controlled={} caches={} sw_requests={} manifest={}",
            s.registration_state,
            s.page_controlled,
            s.cache_storage_bucket_count,
            s.sw_served_request_count,
            s.manifest_link_present
        )));
    }
    if let Some(t) = tls_caa.diagnostics {
        out.push(Line::from(format!(
            " TLS/CAA: security_state={} SANs={} CT={:?} (SCTs={}) CAA_outcome={:?} records={}",
            sanitize_line(t.browser_security_state.as_deref().unwrap_or("unknown"), 16),
            t.leaf_certificate.as_ref().map_or(0, |c| c.san_count),
            t.leaf_certificate
                .as_ref()
                .map(|c| c.certificate_transparency_status),
            t.leaf_certificate
                .as_ref()
                .map_or(0, |c| c.signed_certificate_timestamp_count),
            t.caa_lookup_outcome,
            t.caa_records.len()
        )));
    }
    out
}

fn build_performance_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => {
            return vec![Line::from(
                " Status: Skipped / Unavailable — Level 2 browser performance evidence was not collected.",
            )];
        }
    };
    let mut lines = vec![Line::from(format!(
        " Browser: {} | Rendered DOM elements: {:?} | Word count: {:?}",
        browser.browser_version.as_deref().unwrap_or("Chromium"),
        browser.rendered_dom_elements,
        browser.rendered_word_count
    ))];
    if let Some(ref perf) = browser.performance {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " LCP: {} ms | CLS (milli, max window): {} | TTFB: {} ms",
            perf.lcp_ms
                .map_or("unobserved".to_owned(), |v| v.to_string()),
            perf.cls_thousandths
                .map_or("unobserved".to_owned(), |v| v.to_string()),
            perf.ttfb_ms
                .map_or("unobserved".to_owned(), |v| v.to_string())
        )));
        lines.push(Line::from(format!(
            " Long tasks: {} (total {} ms, max {} ms)",
            perf.long_task_count
                .map_or("unobserved".to_owned(), |v| v.to_string()),
            perf.long_task_total_ms
                .map_or("unobserved".to_owned(), |v| v.to_string()),
            perf.max_long_task_ms
                .map_or("unobserved".to_owned(), |v| v.to_string())
        )));
    }
    if let Some(ref cpu) = browser.cpu_profile {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " CPU Profile: {} ms eval ({} ms sampled) — Top scripts:",
            cpu.script_eval_ms, cpu.total_sampled_ms
        )));
        for script in cpu.top_cpu_scripts.iter().take(6) {
            lines.push(Line::from(format!(
                "  {:>6} ms ({} hits)  {}",
                script.self_ms,
                script.hit_count,
                sanitize_url_for_display(&script.url, 70)
            )));
        }
    }
    if let Some(ref cov) = browser.coverage {
        let js_unused = cov.js_total_bytes.saturating_sub(cov.js_used_bytes);
        let css_unused = cov.css_total_bytes.saturating_sub(cov.css_used_bytes);
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " Code Coverage: JS unused {}/{} B | CSS unused {}/{} B",
            js_unused, cov.js_total_bytes, css_unused, cov.css_total_bytes
        )));
    }
    lines
}

fn build_accessibility_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => {
            return vec![Line::from(
                " Status: Skipped / Unavailable — Level 2 browser accessibility tree was not collected.",
            )];
        }
    };
    let mut lines = Vec::new();
    if let Some(ref ax) = browser.ax_tree {
        lines.push(Line::from(format!(
            " AX Tree: {} total nodes | {} ignored | {} hidden focusable | {} unnamed interactive controls",
            ax.total_nodes,
            ax.ignored_nodes,
            ax.hidden_focusable_count,
            ax.interactive_without_name
        )));
    } else {
        lines.push(Line::from(" AX Tree: Unavailable"));
    }
    if let Some(ref beh) = browser.behavioural_a11y {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " Behavioural Focus Probe: {} tab stops | Trap detected: {} | Missing focus indicator: {}",
            beh.tab_stops_observed, beh.focus_trap_detected, beh.missing_focus_indicator_count
        )));
    }
    lines
}

fn build_lighthouse_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    match &snapshot.lighthouse {
        CollectorOutcome::Captured { data: lh } | CollectorOutcome::Partial { data: lh, .. } => {
            vec![
                Line::from(" Status: Captured (Laboratory Lighthouse)"),
                Line::from(format!(" Performance Score: {:?}", lh.performance_score)),
                Line::from(format!(
                    " LCP: {:?} ms | CLS (milli): {:?} | TBT: {:?} ms",
                    lh.lcp_ms, lh.cls_milli, lh.tbt_ms
                )),
            ]
        }
        CollectorOutcome::Failed { error } => {
            vec![Line::from(format!(
                " Status: Failed — {}",
                sanitize_line(error, 100)
            ))]
        }
        CollectorOutcome::Skipped { reason } => {
            vec![Line::from(format!(
                " Status: Skipped — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_axe_evidence_lines(snapshot: &crate::domain::EvidenceSnapshot) -> Vec<Line<'static>> {
    match &snapshot.axe {
        CollectorOutcome::Captured { data: axe } | CollectorOutcome::Partial { data: axe, .. } => {
            let mut lines = vec![Line::from(format!(
                " Status: Captured | Violations: {} | Passes: {} | Incomplete: {}",
                axe.violations.len(),
                axe.passes_count,
                axe.incomplete_count
            ))];
            lines.push(Line::from(""));
            for v in axe.violations.iter().take(12) {
                lines.push(Line::from(format!(
                    " [{}] {} ({} node(s)): {}",
                    sanitize_line(v.impact.as_deref().unwrap_or("unknown"), 12),
                    sanitize_line(&v.id, 32),
                    v.nodes_count,
                    sanitize_line(&v.description, 64)
                )));
            }
            lines
        }
        CollectorOutcome::Failed { error } => {
            vec![Line::from(format!(
                " Status: Failed — {}",
                sanitize_line(error, 100)
            ))]
        }
        CollectorOutcome::Skipped { reason } => {
            vec![Line::from(format!(
                " Status: Skipped — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn render_offline_report_evidence_fallback(state: &AppState) -> Vec<Line<'static>> {
    let Some(ref report) = state.audit_report else {
        return vec![Line::from(
            " No EvidenceSnapshot or AuditReport loaded. Start a run from Launcher (n).",
        )];
    };
    let mut lines = vec![
        Line::from(
            " Loaded from saved AuditReport (raw EvidenceSnapshot not retained in report JSON).",
        ),
        Line::from(""),
    ];
    match &report.http {
        CollectorOutcome::Captured { data: value }
        | CollectorOutcome::Partial { data: value, .. } => {
            lines.push(Line::from(format!(
                " HTTP Summary: status={} final_url={} redirects={} elapsed={:?}",
                value.status_code,
                sanitize_url_for_display(&value.final_url, 80),
                value.redirect_chain.len(),
                value.elapsed_ms
            )));
        }
        other => {
            lines.push(Line::from(format!(" HTTP Summary: {other:?}")));
        }
    }
    if report.rendered_history.is_some() {
        lines.push(Line::from(" Saved Rendered Content History: Present"));
    } else {
        lines.push(Line::from(" Saved Rendered Content History: Not present"));
    }
    lines
}

#[allow(clippy::too_many_lines)]
fn render_investigation(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(7)])
        .split(area);

    let top_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(vertical[0]);

    let header =
        Row::new(vec!["ID", "Status", "Originating Rule", "Tool"]).style(state.theme.title_style());
    let rows: Vec<Row<'_>> = state
        .hypotheses
        .iter()
        .enumerate()
        .map(|(idx, h)| {
            let is_selected = idx == state.selected_hypothesis_index;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let status_label = match h.status {
                HypothesisStatus::Proposed => "PROPOSED",
                HypothesisStatus::Supported => "SUPPORTED",
                HypothesisStatus::Rejected => "REJECTED",
                HypothesisStatus::Inconclusive => "INCONCLUSIVE",
            };
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.primary_style()
            };
            Row::new(vec![
                format!("{prefix}{}", h.id),
                status_label.to_owned(),
                h.originating_rule.clone(),
                h.requested_tool.clone(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(26),
            Constraint::Min(16),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " KOMMANDANTZWERG HYPOTHESES ({}) ",
                state.hypotheses.len()
            ))
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, top_cols[0]);

    let detail_lines = if let Some(h) = state.hypotheses.get(state.selected_hypothesis_index) {
        let mut lines = vec![
            Line::from(format!(" Hypothesis: {} [{:?}]", h.id, h.status)),
            Line::from(format!(
                " Originating rule: {} (verified: {})",
                h.originating_rule, h.originating_rule_verified
            )),
            Line::from(format!(" Requested tool:   {}", h.requested_tool)),
            Line::from(""),
            Line::from(Span::styled(
                " Proposed Explanation (Inferred Hypothesis — Not Established Fact):",
                state.theme.title_style(),
            )),
            Line::from(format!(" {}", h.proposed_explanation)),
        ];
        if let Some(ref eval) = h.evaluation_summary {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Evidence-Backed Evaluation Summary:",
                state.theme.title_style(),
            )));
            lines.push(Line::from(format!(" {eval}")));
        }
        if !h.supporting_evidence.is_empty() {
            lines.push(Line::from(format!(
                " Supporting evidence: {}",
                h.supporting_evidence.join(", ")
            )));
        }
        if !h.missing_evidence.is_empty() {
            lines.push(Line::from(format!(
                " Missing evidence:    {}",
                h.missing_evidence.join(", ")
            )));
        }
        lines
    } else {
        vec![Line::from(Span::styled(
            " No agentic hypotheses recorded. Select Agentic Investigation mode in Launcher to run KommandantZwerg.",
            state.theme.muted_style(),
        ))]
    };

    let detail_block = Block::default()
        .title(" SELECTED HYPOTHESIS & EVIDENCE EVALUATION ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(
        Paragraph::new(detail_lines)
            .block(detail_block)
            .wrap(Wrap { trim: false }),
        top_cols[1],
    );

    let mut tool_lines: Vec<Line<'_>> = state
        .tool_trace
        .iter()
        .rev()
        .take(4)
        .rev()
        .map(|t| {
            Line::from(vec![
                Span::styled(format!(" {:<30} ", t.tool_id), state.theme.primary_style()),
                Span::styled(
                    format!("{:<10} ", t.status.label()),
                    state.theme.status_style(t.status),
                ),
                Span::styled(&t.summary, state.theme.muted_style()),
            ])
        })
        .collect();
    if let Some(ref conclusion) = state.investigation_conclusion {
        tool_lines.push(Line::from(format!(" Conclusion: {conclusion}")));
    }
    if tool_lines.is_empty() {
        tool_lines.push(Line::from(Span::styled(
            " No tool invocations recorded.",
            state.theme.muted_style(),
        )));
    }
    let tool_block = Block::default()
        .title(" TOOL EXECUTION TRACE & CONCLUSION ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(Paragraph::new(tool_lines).block(tool_block), vertical[1]);
}

fn render_topology(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let header = Row::new(vec![
        "Relation",
        "Target / Resource Node",
        "Provenance",
        "Detail",
    ])
    .style(state.theme.title_style());

    let window_size = usize::from(area.height.saturating_sub(4)).max(1);
    let window_start = if state.selected_topology_index >= window_size {
        state.selected_topology_index + 1 - window_size
    } else {
        0
    };

    let rows: Vec<Row<'_>> = state
        .topology_rows
        .iter()
        .enumerate()
        .skip(window_start)
        .take(window_size)
        .map(|(idx, node)| {
            let is_selected = idx == state.selected_topology_index;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let indent = "  ".repeat(node.depth);
            let branch = if node.depth == 0 {
                ""
            } else {
                state.theme.glyphs.tree_branch()
            };
            let provenance = if node.directly_observed {
                "Observed"
            } else {
                "Inferred"
            };
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.primary_style()
            };
            Row::new(vec![
                format!("{prefix}{}", node.relation_kind),
                format!("{indent}{branch}{}", node.label),
                provenance.to_owned(),
                node.detail.clone(),
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Min(36),
            Constraint::Length(12),
            Constraint::Length(28),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(format!(
                " APPLICATION & DEPENDENCY TOPOLOGY ({} node(s)) ",
                state.topology_rows.len()
            ))
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, area);
}

#[allow(clippy::too_many_lines)]
fn render_history(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(9)])
        .split(area);

    let header = Row::new(vec![
        "Run #",
        "Timestamp (Unix)",
        "Target",
        "HTTP",
        "Findings",
        "Checks",
        "Rendered History",
    ])
    .style(state.theme.title_style());

    let rows: Vec<Row<'_>> = state
        .history_rows
        .iter()
        .enumerate()
        .map(|(idx, r)| {
            let is_selected = idx == state.selected_history_index;
            let prefix = if is_selected {
                state.theme.glyphs.selection_indicator()
            } else {
                "  "
            };
            let style = if is_selected {
                state.theme.selected_style()
            } else {
                state.theme.primary_style()
            };
            Row::new(vec![
                format!("{prefix}#{}", r.index + 1),
                r.captured_at_unix_secs.to_string(),
                r.target.clone(),
                r.http_status.clone(),
                format!("{} ({} Crit/High)", r.findings_count, r.high_or_crit_count),
                r.checks_summary.clone(),
                if r.has_rendered_history {
                    String::from("Available")
                } else {
                    String::from("None")
                },
            ])
            .style(style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(16),
            Constraint::Min(22),
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(16),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" HISTORICAL RUNS (Press Enter to compare selected baseline against latest) ")
            .borders(Borders::ALL)
            .border_style(state.theme.border_style(true)),
    );
    frame.render_widget(table, chunks[0]);

    let reg_lines = if let Some(ref reg) = state.regression {
        let mut lines = vec![
            Line::from(format!(
                " Baseline: {} (t={}) -> Current: {} (t={})",
                sanitize_url_for_display(&reg.baseline_target, 48),
                reg.baseline_captured_at_unix_secs,
                sanitize_url_for_display(&reg.current_target, 48),
                reg.current_captured_at_unix_secs
            )),
            Line::from(format!(
                " New: {:<4} | Persisting: {:<4} | Resolved: {:<4} | Reintroduced: {:<4} | Unverified: {:<4} | Changed: {:<4}",
                reg.summary.new_count,
                reg.summary.persisting_count,
                reg.summary.resolved_count,
                reg.summary.reintroduced_count,
                reg.summary.unverified_count,
                reg.summary.changed_count
            )),
            Line::from(format!(
                " Rendered Text Fingerprint Diff: {}",
                format_rendered_diff_summary(reg.rendered_text.as_ref())
            )),
        ];
        if let Some(ref reason) = reg.not_comparable_reason {
            lines.push(Line::from(Span::styled(
                format!(" Comparability Warning: {}", sanitize_line(reason, 100)),
                state.theme.warning_style(),
            )));
        }
        lines.push(Line::from(Span::styled(
            " Note: Unverified checks reflect skipped/unavailable collectors, not resolved issues.",
            state.theme.muted_style(),
        )));
        lines
    } else {
        vec![Line::from(Span::styled(
            " No historical regression comparison loaded. Pass --history <file.jsonl> or --baseline <file.json>.",
            state.theme.muted_style(),
        ))]
    };

    let reg_block = Block::default()
        .title(" HISTORICAL REGRESSION & COMPARABILITY ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(Paragraph::new(reg_lines).block(reg_block), chunks[1]);
}

#[allow(clippy::too_many_lines)]
fn render_system(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let secs = state.system_metrics.elapsed_ms / 1000;
    let left_lines = vec![
        Line::from(format!(
            " Run ID:               {}",
            state
                .active_run_id
                .as_deref()
                .unwrap_or("None (Offline / Idle)")
        )),
        Line::from(format!(" Lifecycle State:      {:?}", state.lifecycle)),
        Line::from(format!(" Elapsed Time:         {secs} s")),
        Line::from(format!(
            " HTTP Requests:        {}",
            state.system_metrics.http_requests
        )),
        Line::from(format!(
            " Browser Sessions:     {}",
            state.system_metrics.browser_sessions
        )),
        Line::from(format!(
            " Structured Events:    {} received ({} progress coalesced, {} dropped, {} sequence gaps)",
            state.system_metrics.total_events_received,
            state.system_metrics.dropped_progress_events,
            state.system_metrics.dropped_events,
            state.system_metrics.sequence_gap_events
        )),
        Line::from(""),
        Line::from(Span::styled(
            " AGENT & BUDGET LEDGER",
            state.theme.title_style(),
        )),
        Line::from(format!(
            " LLM Turns Used:       {} / {}",
            state.system_metrics.llm_turns_used, state.system_metrics.max_llm_turns
        )),
        Line::from(format!(
            " Diagnostic Tool Calls:{} / {}",
            state.system_metrics.tool_calls_used, state.system_metrics.max_tool_calls
        )),
        Line::from(" Token Cost Estimate:  Unavailable (no pricing configured)"),
    ];
    let left_block = Block::default()
        .title(" EXECUTION & BUDGET HEALTH ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(Paragraph::new(left_lines).block(left_block), cols[0]);

    let mut right_lines = vec![
        Line::from(Span::styled(
            " DETECTED RUNTIME INSTRUMENTS",
            state.theme.title_style(),
        )),
        Line::from(format!(
            " Chromium:       {} ({})",
            if state.instruments.chromium_available {
                "Available"
            } else {
                "Unavailable"
            },
            state.instruments.chromium_detail
        )),
        Line::from(format!(
            " axe-core:       {}",
            if state.instruments.axe_available {
                "Available"
            } else {
                "Unavailable"
            }
        )),
        Line::from(format!(
            " Lighthouse:     {}",
            if state.instruments.lighthouse_available {
                "Available"
            } else {
                "Unavailable"
            }
        )),
        Line::from(format!(" Agent Provider: {}", state.instruments.llm_detail)),
        Line::from(""),
        Line::from(Span::styled(
            " TERMINAL & DISPLAY SETTINGS",
            state.theme.title_style(),
        )),
        Line::from(format!(
            " Viewport:       {}x{} (min {}x{})",
            state.terminal_width, state.terminal_height, MIN_TERMINAL_WIDTH, MIN_TERMINAL_HEIGHT
        )),
        Line::from(format!(
            " Theme Mode:     {:?} (press t to cycle)",
            state.theme.mode
        )),
        Line::from(format!(
            " Glyph Set:      {:?} (press a to toggle)",
            state.theme.glyphs
        )),
    ];
    right_lines.push(Line::from(""));
    right_lines.push(Line::from(Span::styled(
        " COLLECTOR OUTCOMES",
        state.theme.title_style(),
    )));
    for (c, status, detail) in &state.system_metrics.collector_statuses {
        right_lines.push(Line::from(format!(
            "  {:<18} {:<10} {}",
            c.label(),
            status.label(),
            detail
        )));
    }
    let right_block = Block::default()
        .title(" INSTRUMENTS & ENVIRONMENT ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(false));
    frame.render_widget(Paragraph::new(right_lines).block(right_block), cols[1]);
}

#[allow(clippy::too_many_lines)]
fn render_launcher_modal(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let modal_area = centered_rect(72, 20, area);
    frame.render_widget(Clear, modal_area);

    let focus_marker = |field: LauncherField| -> &'static str {
        if state.launcher.focused_field == field {
            state.theme.glyphs.selection_indicator()
        } else {
            "  "
        }
    };
    let field_style = |field: LauncherField| {
        if state.launcher.focused_field == field {
            state.theme.selected_style()
        } else {
            state.theme.primary_style()
        }
    };

    let mut lines = vec![
        Line::from(Span::styled(
            " Configure target URL, execution mode, and Level 2 instruments:",
            state.theme.muted_style(),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(" {}Target URL: ", focus_marker(LauncherField::TargetUrl)),
                field_style(LauncherField::TargetUrl),
            ),
            Span::styled(
                format!("[ {} ]", state.launcher.target_input),
                field_style(LauncherField::TargetUrl),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!(
                    " {}Mode (Space/Left/Right): ",
                    focus_marker(LauncherField::Mode)
                ),
                field_style(LauncherField::Mode),
            ),
            Span::styled(
                format!("( * ) {}", state.launcher.mode.label()),
                field_style(LauncherField::Mode),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                " {}Level 2 Chromium Browser:   [{}]  ({})",
                focus_marker(LauncherField::BrowserToggle),
                if state.launcher.enable_browser {
                    "x"
                } else {
                    " "
                },
                if state.instruments.chromium_available {
                    "Available"
                } else {
                    "Not detected"
                }
            ),
            field_style(LauncherField::BrowserToggle),
        )]),
        Line::from(vec![Span::styled(
            format!(
                " {}Level 2 axe-core A11y:      [{}]  ({})",
                focus_marker(LauncherField::AxeToggle),
                if state.launcher.enable_axe { "x" } else { " " },
                if state.instruments.axe_available {
                    "Available"
                } else {
                    "Not detected"
                }
            ),
            field_style(LauncherField::AxeToggle),
        )]),
        Line::from(vec![Span::styled(
            format!(
                " {}Level 2 Lighthouse Perf:    [{}]  ({})",
                focus_marker(LauncherField::LighthouseToggle),
                if state.launcher.enable_lighthouse {
                    "x"
                } else {
                    " "
                },
                if state.instruments.lighthouse_available {
                    "Available"
                } else {
                    "Not detected"
                }
            ),
            field_style(LauncherField::LighthouseToggle),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(
            format!(
                " {}[ START DIAGNOSTIC RUN (Enter) ]",
                focus_marker(LauncherField::StartButton)
            ),
            field_style(LauncherField::StartButton),
        )]),
    ];

    if let Some(ref err) = state.launcher.error_message {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(" Validation error: {err}"),
            state.theme.error_style(),
        )));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Tab/Up/Down:Move field   Enter:Start   Esc:Close   q:Quit",
            state.theme.muted_style(),
        )));
    }

    let block = Block::default()
        .title(" ZWERGENLEITSTAND LAUNCHER ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(true));
    frame.render_widget(Paragraph::new(lines).block(block), modal_area);
}

fn render_help_modal(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let modal_area = centered_rect(70, 20, area);
    frame.render_widget(Clear, modal_area);

    let lines = vec![
        Line::from(Span::styled(
            " Global Navigation & Workbench Controls",
            state.theme.title_style(),
        )),
        Line::from("  1 - 9          Jump directly to Overview..System views"),
        Line::from("  Tab / BackTab  Cycle next / previous view"),
        Line::from("  j / k or Up/Dn Move selection up or down"),
        Line::from("  h / l or Lf/Rt Switch Evidence family or view"),
        Line::from("  g / G          Jump to first / last row"),
        Line::from("  PageUp / PgDn  Paginate 16 items in Evidence or Findings"),
        Line::from("  Enter          Inspect selected item / Jump Finding -> Evidence"),
        Line::from("  /              Focus live search & filter bar in Findings"),
        Line::from("  s              Cycle Findings sort order"),
        Line::from("  v              Cycle Findings minimum severity filter"),
        Line::from("  n              Open Launcher to configure or start a new run"),
        Line::from("  w              Save current AuditReport to JSON"),
        Line::from("  t / a          Cycle theme (Dark/Contrast/Mono) / Toggle ASCII"),
        Line::from("  c              Cancel active diagnostic run"),
        Line::from("  ? / Esc        Close this Help overlay"),
        Line::from("  q / Ctrl+C     Exit Zwergenleitstand"),
    ];
    let block = Block::default()
        .title(" ZWERGENLEITSTAND KEYBOARD REFERENCE ")
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(true));
    frame.render_widget(Paragraph::new(lines).block(block), modal_area);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width.saturating_sub(2));
    let h = height.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect::new(x, y, w, h)
}

#[cfg(test)]
mod tests {
    use super::build_waterfall_bar;

    #[test]
    fn unobserved_start_renders_as_dots() {
        assert_eq!(
            build_waterfall_bar(None, Some(10), 1_000, "#"),
            "................"
        );
    }

    #[test]
    fn unobserved_duration_marks_only_the_observed_start() {
        let bar = build_waterfall_bar(Some(0), None, 1_000, "#");
        assert_eq!(bar.chars().filter(|cell| *cell == '#').count(), 1);
    }

    #[test]
    fn observed_duration_spans_proportional_cells() {
        let bar = build_waterfall_bar(Some(0), Some(1_000), 1_000, "#");
        assert_eq!(bar.chars().filter(|cell| *cell == '#').count(), 16);
    }

    #[test]
    fn observed_duration_never_collapses_to_zero_cells() {
        let bar = build_waterfall_bar(Some(0), Some(1), 1_000_000, "#");
        assert_eq!(bar.chars().filter(|cell| *cell == '#').count(), 1);
    }
}
