//! Visual language, semantic theme tokens, and terminal accessibility support.
//!
//! Implements ADR 0015:
//! - Semantic theme tokens for `Standard Dark`, `High Contrast`, and `Monochrome`.
//! - Automatic `NO_COLOR` and `TERM=dumb` detection.
//! - Textual severity and operational state markers alongside colour.
//! - Unicode and ASCII symbol sets.

use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;

use crate::domain::Severity;

/// Active colour and contrast mode for Zwergenleitstand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    /// Default dark terminal palette with warm amber/brass accents.
    #[default]
    StandardDark,
    /// High-contrast foreground/background pairs for bright or low-vision setups.
    HighContrast,
    /// Pure monochrome mode using modifiers and explicit textual markers only.
    Monochrome,
}

impl ThemeMode {
    /// Detects the initial theme mode from process environment variables (`NO_COLOR`, `TERM`).
    #[must_use]
    pub fn detect_from_env() -> Self {
        Self::from_env(false)
    }

    /// Detects the initial theme mode from process environment variables (`NO_COLOR`, `TERM`).
    #[must_use]
    pub fn from_env(force_monochrome: bool) -> Self {
        if force_monochrome {
            return Self::Monochrome;
        }
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::Monochrome;
        }
        if std::env::var("TERM").is_ok_and(|term| term.eq_ignore_ascii_case("dumb")) {
            return Self::Monochrome;
        }
        Self::StandardDark
    }

    /// Cycles to the next theme mode.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::StandardDark => Self::HighContrast,
            Self::HighContrast => Self::Monochrome,
            Self::Monochrome => Self::StandardDark,
        }
    }

    /// Short display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::StandardDark => "Dark",
            Self::HighContrast => "High-Contrast",
            Self::Monochrome => "Monochrome",
        }
    }
}

/// Operational status token displayed across brigade, collector, and target views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalStatus {
    /// Completed within scope.
    Done,
    /// Currently executing.
    Running,
    /// Scheduled in queue.
    Queued,
    /// Waiting on prerequisite evidence or specialist input.
    Waiting,
    /// Partially completed or truncated.
    Partial,
    /// Intentionally not executed.
    Skipped,
    /// Execution failed.
    Failed,
    /// Blocked by target or security policy.
    Blocked,
    /// Cancelled by operator.
    Cancelled,
    /// State not yet known.
    Unknown,
}

impl OperationalStatus {
    /// Fixed uppercase label required by ADR 0015.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Done => "DONE",
            Self::Running => "RUNNING",
            Self::Queued => "QUEUED",
            Self::Waiting => "WAITING",
            Self::Partial => "PARTIAL",
            Self::Skipped => "SKIPPED",
            Self::Failed => "FAILED",
            Self::Blocked => "BLOCKED",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Character glyph set supporting both Unicode and pure-ASCII terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GlyphSet {
    /// Standard Unicode box-drawing and indicator glyphs.
    #[default]
    Unicode,
    /// Pure 7-bit ASCII fallback glyphs.
    Ascii,
}

impl GlyphSet {
    /// Creates a glyph set from a boolean ASCII-only flag.
    #[must_use]
    pub const fn new(ascii_only: bool) -> Self {
        if ascii_only {
            Self::Ascii
        } else {
            Self::Unicode
        }
    }

    /// Detects the glyph set from environment variables (`TERM=dumb`).
    #[must_use]
    pub fn detect_from_env() -> Self {
        if std::env::var("TERM").is_ok_and(|term| term.eq_ignore_ascii_case("dumb")) {
            Self::Ascii
        } else {
            Self::Unicode
        }
    }

    /// Returns `true` when pure-ASCII mode is active.
    #[must_use]
    pub const fn is_ascii(self) -> bool {
        matches!(self, Self::Ascii)
    }

    /// Selection cursor prefix for active table/list rows.
    #[must_use]
    pub const fn cursor(self) -> &'static str {
        if self.is_ascii() { "> " } else { "▸ " }
    }

    /// Selection cursor prefix alias for table/list rows.
    #[must_use]
    pub const fn selection_indicator(self) -> &'static str {
        self.cursor()
    }

    /// Solid bar string for horizontal charts and waterfalls.
    #[must_use]
    pub const fn bar_fill(self) -> &'static str {
        if self.is_ascii() { "#" } else { "█" }
    }

    /// Tree branch prefix for intermediate child nodes.
    #[must_use]
    pub const fn tree_branch(self) -> &'static str {
        if self.is_ascii() {
            "|-- "
        } else {
            "├── "
        }
    }

    /// Tree branch prefix for final child nodes.
    #[must_use]
    pub const fn tree_last(self) -> &'static str {
        if self.is_ascii() {
            "`-- "
        } else {
            "└── "
        }
    }

    /// Border set for Ratatui blocks.
    #[must_use]
    pub const fn border_set(self) -> border::Set<'static> {
        if self.is_ascii() {
            border::Set {
                top_left: "+",
                top_right: "+",
                bottom_left: "+",
                bottom_right: "+",
                vertical_left: "|",
                vertical_right: "|",
                horizontal_top: "-",
                horizontal_bottom: "-",
            }
        } else {
            border::PLAIN
        }
    }
}

/// Semantic theme configuration for Zwergenleitstand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Active colour mode.
    pub mode: ThemeMode,
    /// Active glyph set.
    pub glyphs: GlyphSet,
}

impl Theme {
    /// Constructs a theme from explicit mode and glyph set.
    #[must_use]
    pub const fn new(mode: ThemeMode, glyphs: GlyphSet) -> Self {
        Self { mode, glyphs }
    }

    /// Constructs a theme from environment defaults and CLI flags.
    #[must_use]
    pub fn from_flags(force_monochrome: bool, ascii_only: bool) -> Self {
        Self {
            mode: ThemeMode::from_env(force_monochrome),
            glyphs: GlyphSet::new(ascii_only),
        }
    }

    /// Base text style.
    #[must_use]
    pub fn primary(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark | ThemeMode::HighContrast => Style::default().fg(Color::White),
            ThemeMode::Monochrome => Style::default(),
        }
    }

    /// Base text style alias.
    #[must_use]
    pub fn primary_style(self) -> Style {
        self.primary()
    }

    /// Secondary/muted label style.
    #[must_use]
    pub fn muted(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark => Style::default().fg(Color::DarkGray),
            ThemeMode::HighContrast => Style::default().fg(Color::Gray),
            ThemeMode::Monochrome => Style::default().add_modifier(Modifier::DIM),
        }
    }

    /// Secondary/muted label style alias.
    #[must_use]
    pub fn muted_style(self) -> Style {
        self.muted()
    }

    /// Warm brass/amber accent style for titles and brigade identity.
    #[must_use]
    pub fn accent(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            ThemeMode::HighContrast => Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
            ThemeMode::Monochrome => Style::default().add_modifier(Modifier::BOLD),
        }
    }

    /// Title style alias.
    #[must_use]
    pub fn title_style(self) -> Style {
        self.accent()
    }

    /// Border style for focused or unfocused panels.
    #[must_use]
    pub fn border_style(self, focused: bool) -> Style {
        if focused {
            self.border_focused()
        } else {
            self.border_unfocused()
        }
    }

    /// Selected row style alias.
    #[must_use]
    pub fn selected_style(self) -> Style {
        self.selected_row()
    }

    /// Warning text style.
    #[must_use]
    pub fn warning_style(self) -> Style {
        self.severity_style(Severity::Medium)
    }

    /// Error text style.
    #[must_use]
    pub fn error_style(self) -> Style {
        self.severity_style(Severity::Critical)
    }

    /// Border style for the currently focused panel.
    #[must_use]
    pub fn border_focused(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark => Style::default().fg(Color::Yellow),
            ThemeMode::HighContrast => Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
            ThemeMode::Monochrome => Style::default().add_modifier(Modifier::BOLD),
        }
    }

    /// Border style for unfocused panels.
    #[must_use]
    pub fn border_unfocused(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark => Style::default().fg(Color::DarkGray),
            ThemeMode::HighContrast => Style::default().fg(Color::Gray),
            ThemeMode::Monochrome => Style::default(),
        }
    }

    /// Style applied to the currently selected table or list row.
    #[must_use]
    pub fn selected_row(self) -> Style {
        match self.mode {
            ThemeMode::StandardDark => Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            ThemeMode::HighContrast => Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
            ThemeMode::Monochrome => Style::default()
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::BOLD),
        }
    }

    /// Fixed-width textual badge for a finding [`Severity`].
    #[must_use]
    pub const fn severity_badge(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "[CRIT]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MED ]",
            Severity::Low => "[LOW ]",
            Severity::Info => "[INFO]",
        }
    }

    /// Style for a finding [`Severity`].
    #[must_use]
    pub fn severity_style(self, severity: Severity) -> Style {
        match self.mode {
            ThemeMode::Monochrome => match severity {
                Severity::Critical | Severity::High => {
                    Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
                }
                Severity::Medium => Style::default().add_modifier(Modifier::BOLD),
                Severity::Low | Severity::Info => Style::default(),
            },
            ThemeMode::StandardDark | ThemeMode::HighContrast => match severity {
                Severity::Critical => Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
                Severity::High => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                Severity::Medium => Style::default().fg(Color::Yellow),
                Severity::Low => Style::default().fg(Color::Cyan),
                Severity::Info => Style::default().fg(Color::Gray),
            },
        }
    }

    /// Style for an [`OperationalStatus`].
    #[must_use]
    pub fn status_style(self, status: OperationalStatus) -> Style {
        match self.mode {
            ThemeMode::Monochrome => match status {
                OperationalStatus::Running | OperationalStatus::Failed => {
                    Style::default().add_modifier(Modifier::BOLD)
                }
                OperationalStatus::Skipped | OperationalStatus::Unknown => {
                    Style::default().add_modifier(Modifier::DIM)
                }
                _ => Style::default(),
            },
            ThemeMode::StandardDark | ThemeMode::HighContrast => match status {
                OperationalStatus::Done => Style::default().fg(Color::Green),
                OperationalStatus::Running => Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                OperationalStatus::Queued | OperationalStatus::Waiting => {
                    Style::default().fg(Color::Blue)
                }
                OperationalStatus::Partial => Style::default().fg(Color::Yellow),
                OperationalStatus::Skipped | OperationalStatus::Unknown => {
                    Style::default().fg(Color::DarkGray)
                }
                OperationalStatus::Failed | OperationalStatus::Blocked => {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                }
                OperationalStatus::Cancelled => Style::default().fg(Color::Magenta),
            },
        }
    }
}
