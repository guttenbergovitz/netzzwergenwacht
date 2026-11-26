//! Zwergenleitstand — Ratatui terminal investigation workbench for NetzZwergenWacht.
//!
//! This module implements a local-first interactive operator interface over the
//! deterministic collection engine, Die Zwergenbrigade analysers, offline Evidence Query
//! Engine, and `KommandantZwerg` agentic investigation loop.
//!
//! Architectural boundaries (ADRs 0010–0015):
//! - The TUI never duplicates diagnostic rules or executes network I/O on the render thread.
//! - All state transitions flow through the pure [`reduce`] function.
//! - All untrusted web strings are sanitized via [`sanitize`] before entering terminal buffers.

pub mod action;
pub mod keymap;
pub mod reducer;
pub mod runtime;
pub mod sanitize;
pub mod state;
pub mod terminal;
pub mod theme;
pub mod views;

pub use self::action::{AppAction, AppEffect, RunLaunchSpec, UserAction};
pub use self::keymap::translate_key_event;
pub use self::reducer::reduce;
pub use self::runtime::{
    TuiStartupOptions, execute_diagnostic_run, initialize_state, load_offline_history,
    load_offline_report, run_tui, save_current_report,
};
pub use self::sanitize::{sanitize_line, sanitize_multiline, sanitize_url_for_display};
pub use self::state::{
    AppState, BrigadeActivityRow, DiagnosticArtefacts, EvidenceCategory, FindingFilterState,
    FindingRow, FindingSortOrder, HistoryEntryRow, HypothesisRow, InstrumentAvailability,
    LauncherField, LauncherState, RunLifecycleState, SystemMetricsState, TargetInspectionState,
    TargetSurfaceRow, ToolActivityRow, TopologyNodeRow, WorkbenchView,
};
pub use self::terminal::TerminalSession;
pub use self::theme::{GlyphSet, OperationalStatus, Theme, ThemeMode};
pub use self::views::{MIN_TERMINAL_HEIGHT, MIN_TERMINAL_WIDTH, render};
