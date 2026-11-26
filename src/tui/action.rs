//! Typed user actions, reducer events, and background effects for Zwergenleitstand.

use std::path::PathBuf;

use crate::domain::AuditTarget;
use crate::events::{DiagnosticEvent, DiagnosticRunMode};
use crate::tui::state::{EvidenceCategory, WorkbenchView};

/// User-triggered actions translated from keyboard input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAction {
    /// Switch to the next workbench view.
    NextView,
    /// Switch to the previous workbench view.
    PrevView,
    /// Select a specific workbench view (`1`–`9`).
    SelectView(WorkbenchView),
    /// Move selection down by one row in the active view.
    MoveDown,
    /// Move selection up by one row in the active view.
    MoveUp,
    /// Move left or select previous sub-category / collapse node.
    MoveLeft,
    /// Move right or select next sub-category / expand node.
    MoveRight,
    /// Jump to the first row in the active list.
    FirstItem,
    /// Jump to the last row in the active list.
    LastItem,
    /// Move one page up (`16` rows).
    PageUp,
    /// Move one page down (`16` rows).
    PageDown,
    /// Activate or inspect the selected item (or start run from Launcher).
    Activate,
    /// Close modal / clear search / return from drill-down.
    BackOrClose,
    /// Open or focus the search/filter bar.
    OpenSearch,
    /// Cycle the active sort order in Findings view.
    CycleSort,
    /// Cycle severity filter in Findings view.
    CycleSeverityFilter,
    /// Select an evidence category directly.
    SelectEvidenceCategory(EvidenceCategory),
    /// Open the Launcher modal to configure or start a new run.
    OpenLauncher,
    /// Save the current report to disk (`report.json` or configured output path).
    SaveCurrentReport,
    /// Cycle theme mode (`StandardDark` -> `HighContrast` -> `Monochrome`).
    CycleTheme,
    /// Toggle ASCII glyph fallback mode.
    ToggleAscii,
    /// Toggle the context-sensitive Help overlay.
    ToggleHelp,
    /// Request cancellation of the active diagnostic run.
    CancelRun,
    /// Request application exit.
    Quit,
    /// Append a character to the currently focused text input (Launcher or Search).
    InputChar(char),
    /// Delete the last character in the currently focused text input.
    InputBackspace,
    /// Clear the currently focused text input.
    InputClear,
}

/// Parameters required to launch a background diagnostic task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLaunchSpec {
    /// Validated audit target.
    pub target: AuditTarget,
    /// Selected execution mode.
    pub mode: DiagnosticRunMode,
    /// Whether Level 2 headless browser collection is enabled.
    pub enable_browser: bool,
    /// Whether Level 2 `axe-core` collection is enabled.
    pub enable_axe: bool,
    /// Whether Level 2 Lighthouse collection is enabled.
    pub enable_lighthouse: bool,
}

/// Top-level reducer inputs combining user actions, engine events, and task completions.
#[derive(Debug, Clone)]
pub enum AppAction {
    /// Keyboard or operator action.
    User(UserAction),
    /// Terminal resize event.
    Resize(u16, u16),
    /// Periodic tick (`100 ms`) updating elapsed timers.
    Tick,
    /// Live diagnostic event received from the background engine task.
    Diagnostic(Box<DiagnosticEvent>),
    /// Background diagnostic run finished and delivered its authoritative artefacts.
    RunFinished(Box<crate::tui::state::DiagnosticArtefacts>),
    /// Background diagnostic run failed with a terminal error message.
    RunFailed(String),
    /// Background report save completed.
    ReportSaved(Result<PathBuf, String>),
    /// The background task observed a cancellation request and has fully stopped,
    /// or the escalation deadline expired and the task was force-terminated.
    CancellationSettled {
        /// `true` when the cooperative deadline expired before the task stopped.
        escalated: bool,
    },
}

/// Side-effects requested by the pure state reducer and executed by the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEffect {
    /// Spawn a background diagnostic run with the given specification.
    StartRun(RunLaunchSpec),
    /// Signal the active cancellation token to stop the running diagnostic task.
    CancelActiveRun,
    /// Persist the current [`crate::analysis::AuditReport`] to the specified path.
    SaveReport(PathBuf),
    /// Terminate the TUI event loop and restore the terminal.
    Quit,
}
