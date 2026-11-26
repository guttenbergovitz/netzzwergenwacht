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
use crate::domain::{CollectorOutcome, Measurement, Severity};
use crate::investigation::HypothesisStatus;
use crate::investigation::browser_timeline::query_browser_timeline;
use crate::investigation::evidence_query::{
    EvidenceQueryStatus, NetworkResourceFilter, RenderedBlockFilter, RuntimeErrorFilter,
    query_network_resources, query_rendered_content, query_runtime_errors,
};
use crate::tui::sanitize::{sanitize_line, sanitize_url_for_display};
use crate::tui::state::{
    AppState, EvidenceCategory, LauncherField, WorkbenchView, format_rendered_diff_summary,
};
use crate::tui::theme::{OperationalStatus, Theme};

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
                    f.dwarf_id.display_name().to_owned(),
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
            Line::from(format!(" Specialist: {}", finding.dwarf_id.display_name())),
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
                "  [{}] {:?} ({:?}): {}",
                i + 1,
                ev.source,
                ev.level,
                ev.locator
            )));
            if let Some(ref excerpt) = ev.excerpt {
                lines.push(Line::from(Span::styled(
                    format!("      {excerpt}"),
                    state.theme.muted_style(),
                )));
            }
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
                " Status: {} | Total blocks: {} | Offset: {} | DOM truncated: {} | ID census complete: {:?}",
                format_query_status(&page.status),
                page.total_matching,
                page.offset,
                page.dom_truncated,
                page.id_census_complete
            ))];
            out.push(Line::from(
                " Note: Raw visible_text is omitted by design; SHA-256 text_fingerprint is shown.",
            ));
            out.push(Line::from(""));
            for block in &page.blocks {
                let fp = block.text_fingerprint.as_deref().unwrap_or("unavailable");
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
                page.offset,
                page.resources_truncated
            ))];
            out.push(Line::from(""));
            out.push(Line::from(
                " RESOURCE WATERFALL (Observed start_time_ms & duration_ms):",
            ));
            let max_end_ms = page
                .resources
                .iter()
                .filter_map(|r| Some(r.start_time_ms?.saturating_add(r.duration_ms.unwrap_or(0))))
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
                    " Status: Captured | Retained events: {} | Offset: {} | Truncated: {} | End: {:?}",
                    page.total_events, page.offset, page.truncated, page.end
                ))];
                out.push(Line::from(""));
                for ev in page.events {
                    let detail = match &ev.detail {
                        BrowserEventDetail::RequestStarted {
                            method,
                            origin,
                            resource,
                            ..
                        } => {
                            format!(
                                "REQ {method} {} ({resource:?})",
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::Redirect {
                            status, to_origin, ..
                        } => {
                            format!(
                                "REDIRECT HTTP {status} -> {}",
                                to_origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::Response {
                            status,
                            origin,
                            mime_type,
                            ..
                        } => {
                            format!(
                                "RESP HTTP {status} {} ({})",
                                origin.as_deref().unwrap_or("unavailable"),
                                mime_type.as_deref().unwrap_or("-")
                            )
                        }
                        BrowserEventDetail::Completed {
                            encoded_data_length,
                        } => {
                            format!("COMPLETED ({} B)", encoded_data_length.map_or(0, |b| b))
                        }
                        BrowserEventDetail::NetworkFailure { error_text } => {
                            format!("NET FAIL: {}", sanitize_line(error_text, 48))
                        }
                        BrowserEventDetail::Cancelled { error_text } => {
                            format!(
                                "CANCELLED: {}",
                                error_text.as_deref().unwrap_or("cancelled")
                            )
                        }
                        BrowserEventDetail::BrowserBlocked { reason } => {
                            format!("BROWSER BLOCKED: {reason:?}")
                        }
                        BrowserEventDetail::PolicyBlocked { reason, origin } => {
                            format!(
                                "POLICY BLOCKED ({reason}): {}",
                                origin.as_deref().unwrap_or("unavailable")
                            )
                        }
                        BrowserEventDetail::RuntimeError {
                            kind,
                            message,
                            source_origin,
                        } => {
                            format!(
                                "RUNTIME {kind:?} ({}): {}",
                                source_origin.as_deref().unwrap_or("unavailable"),
                                sanitize_line(message, 48)
                            )
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
                page.offset
            ))];
            out.push(Line::from(""));
            for err in &page.errors {
                out.push(Line::from(format!(
                    " [{}] {} (source: {})",
                    sanitize_line(&err.kind, 20),
                    sanitize_line(&err.text, 80),
                    err.source_url.as_deref().map_or_else(
                        || String::from("unavailable"),
                        |u| sanitize_url_for_display(u, 40)
                    )
                )));
            }
            out
        }
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
    let dur = duration_ms.unwrap_or(10).max(1);
    let start_col = usize::try_from((start.saturating_mul(WIDTH as u64)) / max_end_ms)
        .unwrap_or(0)
        .min(WIDTH - 1);
    let span_cols = usize::try_from((dur.saturating_mul(WIDTH as u64)) / max_end_ms)
        .unwrap_or(1)
        .max(1);
    let end_col = (start_col + span_cols).min(WIDTH);
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
        CollectorOutcome::Collected(http) | CollectorOutcome::Partial { evidence: http, .. } => {
            let mut lines = vec![
                Line::from(format!(
                    " Status: Captured | HTTP {} | Protocol: {} | TTFB: {} ms | Total: {} ms",
                    http.status_code, http.http_version, http.ttfb_ms, http.total_duration_ms
                )),
                Line::from(format!(
                    " Final URL: {}",
                    sanitize_url_for_display(&http.final_url, 100)
                )),
                Line::from(format!(
                    " Remote IP: {} | Body bytes: {} (truncated: {})",
                    http.remote_ip.as_deref().unwrap_or("unavailable"),
                    http.body_bytes,
                    http.body_truncated
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
        CollectorOutcome::Unavailable { reason } => {
            vec![Line::from(format!(
                " Status: Unavailable — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_tls_evidence_lines(snapshot: &crate::domain::EvidenceSnapshot) -> Vec<Line<'static>> {
    match &snapshot.tls {
        CollectorOutcome::Collected(tls) | CollectorOutcome::Partial { evidence: tls, .. } => {
            vec![
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
                    " Valid NotBefore:  {} (Unix secs)",
                    tls.not_before_unix_secs
                )),
                Line::from(format!(
                    " Valid NotAfter:   {} (Unix secs)",
                    tls.not_after_unix_secs
                )),
                Line::from(format!(
                    " Days remaining:   {} | Hostname matches SAN: {}",
                    tls.days_remaining, tls.hostname_matches_san
                )),
                Line::from(format!(
                    " SANs ({}):         {}",
                    tls.san_dns_names.len(),
                    sanitize_line(&tls.san_dns_names.join(", "), 90)
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
        CollectorOutcome::Unavailable { reason } => {
            vec![Line::from(format!(
                " Status: Unavailable — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_performance_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    let Some(browser) = snapshot.browser.evidence() else {
        return vec![Line::from(
            " Status: Skipped / Unavailable — Level 2 browser performance evidence was not collected.",
        )];
    };
    let mut lines = vec![Line::from(format!(
        " Browser: {} | Rendered DOM elements: {} | Word count: {:?}",
        browser.browser_version.as_deref().unwrap_or("Chromium"),
        browser.rendered_dom_elements,
        browser.rendered_word_count
    ))];
    if let Some(ref perf) = browser.performance {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " LCP: {:?} ms | FCP: {:?} ms | CLS: {:?} | TTFB: {:?} ms",
            perf.lcp_ms, perf.fcp_ms, perf.cls_score, perf.ttfb_ms
        )));
        lines.push(Line::from(format!(
            " Long tasks: {:?} (total {:?} ms, max {:?} ms)",
            perf.long_task_count, perf.long_task_total_ms, perf.max_long_task_ms
        )));
    }
    if let Some(ref cpu) = browser.cpu_profile {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " CPU Profile: {} samples ({} ms total) — Top scripts:",
            cpu.total_samples, cpu.total_duration_ms
        )));
        for script in cpu.top_scripts.iter().take(6) {
            lines.push(Line::from(format!(
                "  {:>6} ms ({:>5.1}%)  {}",
                script.estimated_ms,
                script.sample_share_pct,
                sanitize_url_for_display(&script.url, 70)
            )));
        }
    }
    if let Some(ref cov) = browser.coverage {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " Code Coverage: JS unused {}/{} B | CSS unused {}/{} B",
            cov.js_unused_bytes, cov.js_total_bytes, cov.css_unused_bytes, cov.css_total_bytes
        )));
    }
    lines
}

fn build_accessibility_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    let Some(browser) = snapshot.browser.evidence() else {
        return vec![Line::from(
            " Status: Skipped / Unavailable — Level 2 browser accessibility tree was not collected.",
        )];
    };
    let mut lines = Vec::new();
    if let Some(ref ax) = browser.ax_tree {
        lines.push(Line::from(format!(
            " AX Tree: {} total nodes | {} landmarks | {} headings | {} unnamed interactive controls",
            ax.total_nodes, ax.landmarks.len(), ax.headings.len(), ax.unnamed_interactive.len()
        )));
        lines.push(Line::from(format!(
            " Landmarks: {}",
            sanitize_line(&ax.landmarks.join(", "), 80)
        )));
    } else {
        lines.push(Line::from(" AX Tree: Unavailable"));
    }
    if let Some(ref beh) = browser.behavioural_a11y {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            " Behavioural Focus Probe: {} tab stops | Trap detected: {} | Invisible focus count: {}",
            beh.tab_stops_probed, beh.focus_trap_detected, beh.invisible_focus_count
        )));
    }
    lines
}

fn build_lighthouse_evidence_lines(
    snapshot: &crate::domain::EvidenceSnapshot,
) -> Vec<Line<'static>> {
    match &snapshot.lighthouse {
        CollectorOutcome::Collected(lh) | CollectorOutcome::Partial { evidence: lh, .. } => vec![
            Line::from(" Status: Captured (Laboratory Lighthouse)"),
            Line::from(format!(" Performance Score: {:?}", lh.performance_score)),
            Line::from(format!(
                " LCP: {:?} ms | CLS: {:?} | TBT: {:?} ms",
                lh.lcp_ms, lh.cls, lh.tbt_ms
            )),
        ],
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
        CollectorOutcome::Unavailable { reason } => {
            vec![Line::from(format!(
                " Status: Unavailable — {}",
                sanitize_line(reason, 100)
            ))]
        }
    }
}

fn build_axe_evidence_lines(snapshot: &crate::domain::EvidenceSnapshot) -> Vec<Line<'static>> {
    match &snapshot.axe {
        CollectorOutcome::Collected(axe) | CollectorOutcome::Partial { evidence: axe, .. } => {
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
                    sanitize_line(&v.impact, 12),
                    sanitize_line(&v.id, 32),
                    v.nodes,
                    sanitize_line(&v.help, 64)
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
        CollectorOutcome::Unavailable { reason } => {
            vec![Line::from(format!(
                " Status: Unavailable — {}",
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
        Measurement::Measured { value } => {
            lines.push(Line::from(format!(
                " HTTP Summary: status={} final_url={} redirects={} ttfb={}ms total={}ms",
                value.status_code,
                sanitize_url_for_display(&value.final_url, 80),
                value.redirects,
                value.ttfb_ms,
                value.total_duration_ms
            )));
        }
        other => {
            lines.push(Line::from(format!(" HTTP Summary: {other:?}")));
        }
    }
    if let Some(ref rh) = report.rendered_history {
        lines.push(Line::from(format!(
            " Saved Rendered Content History: {} blocks ({}x{} viewport, load_timed_out={})",
            rh.blocks.len(),
            rh.viewport_width,
            rh.viewport_height,
            rh.load_timed_out
        )));
    } else {
        lines.push(Line::from(" Saved Rendered Content History: Not present"));
    }
    lines
}

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
            " Structured Events:    {} received ({} progress coalesced)",
            state.system_metrics.total_events_received,
            state.system_metrics.dropped_progress_events
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
