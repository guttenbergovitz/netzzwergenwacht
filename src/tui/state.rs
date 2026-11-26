//! Authoritative presentation state for Zwergenleitstand.
//!
//! Keeps collected diagnostic artefacts (`AuditReport`, `EvidenceSnapshot`,
//! `InvestigationReport`, `PatrolReport`, and `RegressionReport`) separate from
//! transient view state (selections, filters, scroll positions, and active
//! dialogs) so rendering remains pure, fast, and deterministic.

use std::collections::VecDeque;
use std::path::PathBuf;

use crate::analysis::AuditReport;
use crate::brigade::{DwarfId, DwarfRole, ZWERGENBRIGADE};
use crate::discovery::{DiscoveredPage, PageCrawlStatus};
use crate::domain::{
    CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef, EvidenceSnapshot, EvidenceSource,
    Finding, Severity, TargetPolicy,
};
use crate::events::{CollectorId, DiagnosticRunMode};
use crate::investigation::{DiagnosticHypothesis, HypothesisStatus, InvestigationReport};
use crate::patrol::PatrolReport;
use crate::persistence::{RegressionReport, RenderedTextDiff};
use crate::tui::sanitize::{sanitize_line, sanitize_multiline, sanitize_url_for_display};
use crate::tui::theme::{GlyphSet, OperationalStatus, Theme, ThemeMode};

/// Maximum number of recent diagnostic events retained in the rolling activity ring buffer.
pub const MAX_RECENT_EVENTS: usize = 256;

/// Primary and secondary workbench views (`1`–`9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkbenchView {
    /// `1`: Operational dashboard, surface counters, severity summary, and live activity.
    Overview,
    /// `2`: Die Zwergenbrigade specialist status, checks, findings, and recent operations.
    Brigade,
    /// `3`: Application surface inventory, crawl status, and per-page inspection details.
    Targets,
    /// `4`: Filterable and sortable remediation findings table with evidence cross-references.
    Findings,
    /// `5`: Offline Evidence Explorer powered by the Evidence Query Engine.
    Evidence,
    /// `6`: `KommandantZwerg` hypotheses, specialist contributions, and tool trace.
    Investigation,
    /// `7`: Navigable application and dependency relationship tree.
    Topology,
    /// `8`: Saved audit history and regression comparison (`RegressionReport` + `RenderedTextDiff`).
    History,
    /// `9`: Execution budget, collectors, LLM token ledger, and instrument availability.
    System,
}

impl WorkbenchView {
    /// Ordered list of all nine workbench views.
    pub const ALL: [Self; 9] = [
        Self::Overview,
        Self::Brigade,
        Self::Targets,
        Self::Findings,
        Self::Evidence,
        Self::Investigation,
        Self::Topology,
        Self::History,
        Self::System,
    ];

    /// Numeric shortcut (`1`–`9`).
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Overview => 1,
            Self::Brigade => 2,
            Self::Targets => 3,
            Self::Findings => 4,
            Self::Evidence => 5,
            Self::Investigation => 6,
            Self::Topology => 7,
            Self::History => 8,
            Self::System => 9,
        }
    }

    /// Concise tab label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "1:Overview",
            Self::Brigade => "2:Brigade",
            Self::Targets => "3:Targets",
            Self::Findings => "4:Findings",
            Self::Evidence => "5:Evidence",
            Self::Investigation => "6:Investigate",
            Self::Topology => "7:Topology",
            Self::History => "8:History",
            Self::System => "9:System",
        }
    }

    /// Next view in cyclic tab order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Overview => Self::Brigade,
            Self::Brigade => Self::Targets,
            Self::Targets => Self::Findings,
            Self::Findings => Self::Evidence,
            Self::Evidence => Self::Investigation,
            Self::Investigation => Self::Topology,
            Self::Topology => Self::History,
            Self::History => Self::System,
            Self::System => Self::Overview,
        }
    }

    /// Previous view in cyclic tab order.
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Overview => Self::System,
            Self::Brigade => Self::Overview,
            Self::Targets => Self::Brigade,
            Self::Findings => Self::Targets,
            Self::Evidence => Self::Findings,
            Self::Investigation => Self::Evidence,
            Self::Topology => Self::Investigation,
            Self::History => Self::Topology,
            Self::System => Self::History,
        }
    }
}

/// Evidence families available in the Evidence Explorer (`5:Evidence`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceCategory {
    /// Level 1 HTTP response metadata, redirect chain, headers, and source excerpt.
    Http,
    /// Level 1 TLS certificate subject, issuer, SANs, algorithms, and validity period.
    Tls,
    /// Rendered DOM block segmentation (via `query_rendered_content`, omitting raw `visible_text`).
    RenderedContent,
    /// Source HTML vs rendered DOM content comparison (via `compare_source_and_rendered`).
    SourceRenderedDiff,
    /// Subresource inventory and transfer waterfall (via `query_network_resources`).
    NetworkResources,
    /// Chronological network and runtime event timeline (via `query_browser_timeline`).
    BrowserTimeline,
    /// Multi-hop request chains and failed dependencies (via `query_request_chains` & `query_failed_dependencies`).
    RequestChainsAndFailures,
    /// Console and uncaught runtime errors (via `query_runtime_errors`).
    RuntimeErrors,
    /// Wave IV-B interactive elements, application state, and interaction trace.
    InteractiveAndState,
    /// Wave IV-C visual geometry, overflow/occlusion, and AX node inventory.
    VisualGeometryAndAx,
    /// Wave IV-D security header posture, challenge detection, cookies/storage, and third-party origins.
    SecurityAndPrivacy,
    /// Wave IV-E LCP/CLS/render-blocking attribution and media/font efficiency.
    PerformanceAndMedia,
    /// Wave IV-F SEO indexability authority and JSON-LD/Microdata/social structured data.
    SeoAndStructuredData,
    /// Wave IV-G cross-breakpoint responsive anomalies and rendered link graph.
    ResponsiveAndLinks,
    /// Wave IV-H visual landmark signatures, Service Worker lifecycle, and TLS/CAA diagnostics.
    VisualSwAndTlsCaa,
    /// Core Web Vitals, Navigation Timing, CPU profile, and JS/CSS coverage.
    Performance,
    /// Accessibility tree (`AxTreeSnapshot`) and behavioural keyboard/focus probe.
    Accessibility,
    /// Level 2 Lighthouse performance and audit metrics.
    Lighthouse,
    /// Level 2 `axe-core` rule violations.
    Axe,
}

impl EvidenceCategory {
    /// All evidence categories in display order.
    pub const ALL: [Self; 19] = [
        Self::Http,
        Self::Tls,
        Self::RenderedContent,
        Self::SourceRenderedDiff,
        Self::NetworkResources,
        Self::BrowserTimeline,
        Self::RequestChainsAndFailures,
        Self::RuntimeErrors,
        Self::InteractiveAndState,
        Self::VisualGeometryAndAx,
        Self::SecurityAndPrivacy,
        Self::PerformanceAndMedia,
        Self::SeoAndStructuredData,
        Self::ResponsiveAndLinks,
        Self::VisualSwAndTlsCaa,
        Self::Performance,
        Self::Accessibility,
        Self::Lighthouse,
        Self::Axe,
    ];

    /// Concise display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP & Source",
            Self::Tls => "TLS Certificate",
            Self::RenderedContent => "Rendered Blocks",
            Self::SourceRenderedDiff => "Source vs Rendered",
            Self::NetworkResources => "Network & Waterfall",
            Self::BrowserTimeline => "Browser Timeline",
            Self::RequestChainsAndFailures => "Chains & Failures",
            Self::RuntimeErrors => "Runtime Errors",
            Self::InteractiveAndState => "Interactive & State",
            Self::VisualGeometryAndAx => "Geometry & AX Nodes",
            Self::SecurityAndPrivacy => "Security & Privacy",
            Self::PerformanceAndMedia => "Perf Attribution & Media",
            Self::SeoAndStructuredData => "SEO & Structured Data",
            Self::ResponsiveAndLinks => "Responsive & Links",
            Self::VisualSwAndTlsCaa => "Visual, SW & TLS/CAA",
            Self::Performance => "Performance & CPU",
            Self::Accessibility => "Accessibility Tree",
            Self::Lighthouse => "Lighthouse",
            Self::Axe => "axe-core",
        }
    }

    /// Next category in cyclic order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Http => Self::Tls,
            Self::Tls => Self::RenderedContent,
            Self::RenderedContent => Self::SourceRenderedDiff,
            Self::SourceRenderedDiff => Self::NetworkResources,
            Self::NetworkResources => Self::BrowserTimeline,
            Self::BrowserTimeline => Self::RequestChainsAndFailures,
            Self::RequestChainsAndFailures => Self::RuntimeErrors,
            Self::RuntimeErrors => Self::InteractiveAndState,
            Self::InteractiveAndState => Self::VisualGeometryAndAx,
            Self::VisualGeometryAndAx => Self::SecurityAndPrivacy,
            Self::SecurityAndPrivacy => Self::PerformanceAndMedia,
            Self::PerformanceAndMedia => Self::SeoAndStructuredData,
            Self::SeoAndStructuredData => Self::ResponsiveAndLinks,
            Self::ResponsiveAndLinks => Self::VisualSwAndTlsCaa,
            Self::VisualSwAndTlsCaa => Self::Performance,
            Self::Performance => Self::Accessibility,
            Self::Accessibility => Self::Lighthouse,
            Self::Lighthouse => Self::Axe,
            Self::Axe => Self::Http,
        }
    }

    /// Previous category in cyclic order.
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::Http => Self::Axe,
            Self::Tls => Self::Http,
            Self::RenderedContent => Self::Tls,
            Self::SourceRenderedDiff => Self::RenderedContent,
            Self::NetworkResources => Self::SourceRenderedDiff,
            Self::BrowserTimeline => Self::NetworkResources,
            Self::RequestChainsAndFailures => Self::BrowserTimeline,
            Self::RuntimeErrors => Self::RequestChainsAndFailures,
            Self::InteractiveAndState => Self::RuntimeErrors,
            Self::VisualGeometryAndAx => Self::InteractiveAndState,
            Self::SecurityAndPrivacy => Self::VisualGeometryAndAx,
            Self::PerformanceAndMedia => Self::SecurityAndPrivacy,
            Self::SeoAndStructuredData => Self::PerformanceAndMedia,
            Self::ResponsiveAndLinks => Self::SeoAndStructuredData,
            Self::VisualSwAndTlsCaa => Self::ResponsiveAndLinks,
            Self::Performance => Self::VisualSwAndTlsCaa,
            Self::Accessibility => Self::Performance,
            Self::Lighthouse => Self::Accessibility,
            Self::Axe => Self::Lighthouse,
        }
    }
}

/// Lifecycle state of the diagnostic workbench run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunLifecycleState {
    /// No run started; waiting in Launcher or exploring loaded files.
    Idle,
    /// Operator is configuring a new run in the Launcher dialog.
    Configuring,
    /// Background diagnostic run is actively executing.
    Running,
    /// Cancellation has been requested; waiting for background task shutdown.
    Cancelling,
    /// Diagnostic run completed cleanly; exploring results.
    Completed,
    /// Diagnostic run completed with partial evidence or warnings.
    Partial,
    /// Diagnostic run failed with an error.
    Failed,
    /// Diagnostic run was cancelled by the operator and cleanup has been confirmed.
    Cancelled,
    /// Cancellation was requested but the task did not stop before the deadline and
    /// had to be force-terminated. Cleanup is not confirmed.
    TerminationEscalated,
}

impl RunLifecycleState {
    /// Maps the run lifecycle state to a semantic [`OperationalStatus`].
    #[must_use]
    pub const fn operational_status(self) -> OperationalStatus {
        match self {
            Self::Idle | Self::Configuring => OperationalStatus::Waiting,
            Self::Running | Self::Cancelling => OperationalStatus::Running,
            Self::Completed => OperationalStatus::Done,
            Self::Partial => OperationalStatus::Partial,
            Self::Failed | Self::TerminationEscalated => OperationalStatus::Failed,
            Self::Cancelled => OperationalStatus::Cancelled,
        }
    }
}

/// Interactive fields in the Launcher setup modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherField {
    /// Target URL text input.
    TargetUrl,
    /// Execution mode (`DeterministicCheck`, `AgenticInvestigation`, `AutonomousPatrol`).
    Mode,
    /// Toggle Level 2 Chromium browser collector.
    BrowserToggle,
    /// Toggle Level 2 `axe-core` collector.
    AxeToggle,
    /// Toggle Level 2 Lighthouse collector.
    LighthouseToggle,
    /// Start action button.
    StartButton,
}

impl LauncherField {
    /// Next field in `Tab` order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::TargetUrl => Self::Mode,
            Self::Mode => Self::BrowserToggle,
            Self::BrowserToggle => Self::AxeToggle,
            Self::AxeToggle => Self::LighthouseToggle,
            Self::LighthouseToggle => Self::StartButton,
            Self::StartButton => Self::TargetUrl,
        }
    }

    /// Previous field in `Shift+Tab` order.
    #[must_use]
    pub const fn prev(self) -> Self {
        match self {
            Self::TargetUrl => Self::StartButton,
            Self::Mode => Self::TargetUrl,
            Self::BrowserToggle => Self::Mode,
            Self::AxeToggle => Self::BrowserToggle,
            Self::LighthouseToggle => Self::AxeToggle,
            Self::StartButton => Self::LighthouseToggle,
        }
    }
}

/// Runtime availability of external diagnostic instruments and AI providers.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstrumentAvailability {
    /// Whether a headless Chromium binary was detected.
    pub chromium_available: bool,
    /// Detected Chromium path or status note.
    pub chromium_detail: String,
    /// Whether `axe-core` adapter prerequisites are available.
    pub axe_available: bool,
    /// Whether `lighthouse` CLI was detected.
    pub lighthouse_available: bool,
    /// Whether an LLM provider API key / configuration is available.
    pub llm_configured: bool,
    /// Configured LLM provider and model summary.
    pub llm_detail: String,
}

impl Default for InstrumentAvailability {
    fn default() -> Self {
        Self::detect()
    }
}

impl InstrumentAvailability {
    /// Probes actual runtime environment variables and standard binary paths without running a browser.
    #[must_use]
    pub fn detect() -> Self {
        let chromium_env = std::env::var("NZW_CHROMIUM_BIN").ok();
        let default_mac_chrome =
            std::path::Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
                .exists();
        let chromium_in_path = which_in_path(&["chromium", "chromium-browser", "google-chrome"]);
        let (chromium_available, chromium_detail) = if let Some(bin) = chromium_env {
            (true, sanitize_line(&bin, 64))
        } else if let Some(bin) = chromium_in_path {
            (true, bin)
        } else if default_mac_chrome {
            (true, "Google Chrome (macOS)".to_owned())
        } else {
            (false, "Not detected".to_owned())
        };

        let node_available = which_in_path(&["node"]).is_some();
        let axe_available = chromium_available && node_available;
        let lighthouse_available = which_in_path(&["lighthouse"]).is_some();

        let llm_key_present = [
            "OPENCODE_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "OPENROUTER_API_KEY",
        ]
        .iter()
        .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()));

        let llm_detail = if llm_key_present {
            "API key configured".to_owned()
        } else {
            "No API key (deterministic mode ready)".to_owned()
        };

        Self {
            chromium_available,
            chromium_detail,
            axe_available,
            lighthouse_available,
            llm_configured: llm_key_present,
            llm_detail,
        }
    }
}

fn which_in_path(candidates: &[&str]) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        for candidate in candidates {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some((*candidate).to_owned());
            }
        }
    }
    None
}

/// Launcher dialog state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherState {
    /// Whether the Launcher modal is currently visible.
    pub open: bool,
    /// Currently focused field.
    pub focused_field: LauncherField,
    /// Editable target URL string.
    pub target_input: String,
    /// Selected diagnostic execution mode.
    pub mode: DiagnosticRunMode,
    /// Enable Level 2 Chromium browser collection.
    pub enable_browser: bool,
    /// Enable Level 2 `axe-core` collection.
    pub enable_axe: bool,
    /// Enable Level 2 Lighthouse collection.
    pub enable_lighthouse: bool,
    /// Target validation policy (e.g. `PublicOnly` vs `AllowPrivate`).
    pub policy: TargetPolicy,
    /// Validation error message displayed inside the Launcher if URL parsing fails.
    pub error_message: Option<String>,
}

impl Default for LauncherState {
    fn default() -> Self {
        Self {
            open: true,
            focused_field: LauncherField::TargetUrl,
            target_input: String::from("https://example.org"),
            mode: DiagnosticRunMode::DeterministicCheck,
            enable_browser: false,
            enable_axe: false,
            enable_lighthouse: false,
            policy: TargetPolicy::PublicOnly,
            error_message: None,
        }
    }
}

/// Live and post-run status row for a single specialist in Die Zwergenbrigade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrigadeActivityRow {
    /// Canonical specialist identifier.
    pub dwarf_id: DwarfId,
    /// German display name (`NetzZwerg`, `SicherheitsZwerg`, etc.).
    pub display_name: &'static str,
    /// Domain responsibility summary.
    pub responsibility: &'static str,
    /// Role (`Specialist`, `Synthesis`, `Commander`).
    pub role: DwarfRole,
    /// Required evidence level.
    pub required_evidence: EvidenceLevel,
    /// Current operational status.
    pub status: OperationalStatus,
    /// Total checks evaluated by this specialist.
    pub checks_total: usize,
    /// Checks that passed.
    pub checks_passed: usize,
    /// Checks that failed.
    pub checks_failed: usize,
    /// Checks skipped due to missing Level 2 evidence.
    pub checks_skipped: usize,
    /// Checks that were inconclusive or unavailable.
    pub checks_inconclusive: usize,
    /// Findings raised by this specialist.
    pub findings_count: usize,
    /// Distinguishes deterministic rule evaluation from LLM specialist consultation.
    pub is_agent_activity: bool,
    /// Latest activity description.
    pub current_activity: String,
}

impl BrigadeActivityRow {
    /// Creates the initial brigade inventory from [`ZWERGENBRIGADE`].
    #[must_use]
    pub fn initial_brigade() -> Vec<Self> {
        ZWERGENBRIGADE
            .iter()
            .map(|profile| Self {
                dwarf_id: profile.id,
                display_name: profile.display_name,
                responsibility: profile.responsibility,
                role: profile.role,
                required_evidence: profile.required_evidence,
                status: OperationalStatus::Waiting,
                checks_total: 0,
                checks_passed: 0,
                checks_failed: 0,
                checks_skipped: 0,
                checks_inconclusive: 0,
                findings_count: 0,
                is_agent_activity: false,
                current_activity: String::from("Idle"),
            })
            .collect()
    }
}

/// Explicit inspection status for a discovered target page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetInspectionState {
    /// Queued or scheduled for inspection.
    Queued,
    /// Currently being collected or analysed.
    Running,
    /// Completed with full scheduled evidence.
    Completed,
    /// Completed with partial or truncated evidence.
    Partial,
    /// Collection failed or target was unreachable.
    Failed,
    /// Skipped due to crawl or execution budget.
    SkippedBudget,
    /// Reused from prior healthy patrol observation via conditional HTTP.
    ReusedUnchanged,
}

impl TargetInspectionState {
    /// Maps to a semantic [`OperationalStatus`].
    #[must_use]
    pub const fn operational_status(self) -> OperationalStatus {
        match self {
            Self::Queued => OperationalStatus::Queued,
            Self::Running => OperationalStatus::Running,
            Self::Completed | Self::ReusedUnchanged => OperationalStatus::Done,
            Self::Partial => OperationalStatus::Partial,
            Self::Failed => OperationalStatus::Failed,
            Self::SkippedBudget => OperationalStatus::Skipped,
        }
    }

    /// Short uppercase table token.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUN",
            Self::Completed => "DONE",
            Self::Partial => "PARTIAL",
            Self::Failed => "FAIL",
            Self::SkippedBudget => "BUDGET",
            Self::ReusedUnchanged => "REUSED",
        }
    }
}

/// Application surface row displayed in `3:Targets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSurfaceRow {
    /// Sanitized URL for terminal display.
    pub display_url: String,
    /// Discovery source (`seed`, `crawl`, `sitemap`, `patrol`).
    pub discovery_source: String,
    /// BFS hop depth from seed.
    pub depth: usize,
    /// Inferred page type label.
    pub page_type: String,
    /// HTTP status code, if observed.
    pub http_status: Option<u16>,
    /// Inspection outcome state.
    pub state: TargetInspectionState,
    /// Available evidence levels summary (`Source`, `Source + Rendered`, etc.).
    pub evidence_summary: String,
    /// Number of findings associated with this page.
    pub findings_count: usize,
}

/// Sort order for the `4:Findings` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSortOrder {
    /// Highest severity first, then confidence, then rule ID (default).
    SeverityDesc,
    /// Highest confidence first, then severity, then rule ID.
    ConfidenceDesc,
    /// Alphabetical by rule ID.
    RuleIdAsc,
    /// Grouped by owning specialist dwarf.
    SpecialistAsc,
}

impl FindingSortOrder {
    /// Cycles to the next deterministic sort order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::SeverityDesc => Self::ConfidenceDesc,
            Self::ConfidenceDesc => Self::RuleIdAsc,
            Self::RuleIdAsc => Self::SpecialistAsc,
            Self::SpecialistAsc => Self::SeverityDesc,
        }
    }

    /// Human-readable sort label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SeverityDesc => "Severity (High -> Info)",
            Self::ConfidenceDesc => "Confidence (High -> Low)",
            Self::RuleIdAsc => "Rule ID (A -> Z)",
            Self::SpecialistAsc => "Specialist Dwarf",
        }
    }
}

/// Active filter criteria for the `4:Findings` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingFilterState {
    /// Minimum severity threshold (`None` = show all severities).
    pub min_severity: Option<Severity>,
    /// Optional specialist filter.
    pub dwarf: Option<DwarfId>,
    /// Case-insensitive substring query matching rule ID, title, or detail.
    pub search_query: String,
}

impl FindingFilterState {
    /// Cycles the minimum severity filter (`All` -> `Critical` -> `High` -> `Medium` -> `Low` -> `All`).
    pub fn cycle_severity(&mut self) {
        self.min_severity = match self.min_severity {
            None => Some(Severity::Critical),
            Some(Severity::Critical) => Some(Severity::High),
            Some(Severity::High) => Some(Severity::Medium),
            Some(Severity::Medium) => Some(Severity::Low),
            Some(Severity::Low | Severity::Info) => None,
        };
    }

    /// Human-readable severity filter label.
    #[must_use]
    pub const fn severity_label(&self) -> &'static str {
        match self.min_severity {
            None => "All Severities",
            Some(Severity::Critical) => "Critical only",
            Some(Severity::High) => "High+",
            Some(Severity::Medium) => "Medium+",
            Some(Severity::Low) => "Low+",
            Some(Severity::Info) => "Info+",
        }
    }
}

/// Sanitized, display-ready finding record in `4:Findings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRow {
    /// Stable index in the authoritative findings vector.
    pub index: usize,
    /// Owning specialist dwarf.
    pub dwarf_id: DwarfId,
    /// Rule identifier (`sec.headers.csp`, etc.).
    pub rule_id: String,
    /// Severity level.
    pub severity: Severity,
    /// Epistemic confidence level.
    pub confidence: Confidence,
    /// Highest evidence level backing this finding.
    pub evidence_level: EvidenceLevel,
    /// Affected target URL (sanitized).
    pub target_url: String,
    /// Sanitized finding title.
    pub title: String,
    /// Sanitized diagnostic description.
    pub description: String,
    /// Sanitized remediation guidance.
    pub recommendation: String,
    /// Sanitized evidence references (`source: locator — excerpt`).
    pub evidence_refs: Vec<EvidenceRef>,
    /// Primary evidence category to jump to when the operator presses `Enter` on this finding.
    pub primary_evidence_category: EvidenceCategory,
}

/// Sanitized hypothesis entry displayed in `6:Investigation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HypothesisRow {
    /// Hypothesis identifier (`hyp-1`, etc.).
    pub id: String,
    /// Originating deterministic rule ID.
    pub originating_rule: String,
    /// Whether the originating rule was verified in the deterministic report.
    pub originating_rule_verified: bool,
    /// Proposed diagnostic explanation.
    pub proposed_explanation: String,
    /// Requested follow-up tool.
    pub requested_tool: String,
    /// Current evaluation status (`Proposed`, `Supported`, `Rejected`, `Inconclusive`).
    pub status: HypothesisStatus,
    /// Evidence-backed evaluation summary.
    pub evaluation_summary: Option<String>,
    /// Supporting evidence references.
    pub supporting_evidence: Vec<String>,
    /// Contradictory evidence references.
    pub contradictory_evidence: Vec<String>,
    /// Missing evidence gaps.
    pub missing_evidence: Vec<String>,
}

impl From<&DiagnosticHypothesis> for HypothesisRow {
    fn from(h: &DiagnosticHypothesis) -> Self {
        Self {
            id: sanitize_line(&h.id, 32),
            originating_rule: sanitize_line(&h.originating_rule.0, 96),
            originating_rule_verified: h.originating_rule_verified,
            proposed_explanation: sanitize_multiline(&h.proposed_explanation, 240),
            requested_tool: sanitize_line(&h.requested_tool, 64),
            status: h.status,
            evaluation_summary: h
                .evaluation_summary
                .as_deref()
                .map(|s| sanitize_multiline(s, 240)),
            supporting_evidence: h
                .supporting_evidence
                .iter()
                .map(|r| sanitize_line(&format!("{:?}: {}", r.source, r.detail), 120))
                .collect(),
            contradictory_evidence: h
                .contradictory_evidence
                .iter()
                .map(|r| sanitize_line(&format!("{:?}: {}", r.source, r.detail), 120))
                .collect(),
            missing_evidence: h
                .missing_evidence
                .iter()
                .map(|m| sanitize_line(m, 120))
                .collect(),
        }
    }
}

/// Tool invocation trace row displayed in `6:Investigation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolActivityRow {
    /// Tool identifier.
    pub tool_id: String,
    /// Status (`REQUESTED`, `AUTHORISED`, `REJECTED`, `DONE`, `FAILED`).
    pub status: OperationalStatus,
    /// Summary or rejection reason.
    pub summary: String,
}

/// Navigable relationship node in `7:Topology`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyNodeRow {
    /// Indentation depth (`0` = target root, `1` = page, `2` = linked resource/target).
    pub depth: usize,
    /// Kind label (`PAGE`, `REDIRECT`, `CANONICAL`, `HREFLANG`, `RESOURCE`, `LINK`).
    pub relation_kind: &'static str,
    /// Sanitized display label.
    pub label: String,
    /// Observed status or detail note.
    pub detail: String,
    /// Whether this relationship is directly observed (`true`) or inferred (`false`).
    pub directly_observed: bool,
}

/// Saved report summary row in `8:History`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntryRow {
    /// Entry index in the loaded history vector.
    pub index: usize,
    /// Unix capture timestamp in seconds.
    pub captured_at_unix_secs: u64,
    /// Target URL.
    pub target: String,
    /// HTTP status summary.
    pub http_status: String,
    /// Total findings count.
    pub findings_count: usize,
    /// Critical + High findings count.
    pub high_or_crit_count: usize,
    /// Checks passed / total checks.
    pub checks_summary: String,
    /// Whether rendered block fingerprints are present for offline diffing.
    pub has_rendered_history: bool,
}

/// System and execution health counters in `9:System`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemMetricsState {
    /// Elapsed wall-clock milliseconds for the active or last run.
    pub elapsed_ms: u64,
    /// Number of HTTP requests recorded.
    pub http_requests: usize,
    /// Number of browser sessions recorded.
    pub browser_sessions: usize,
    /// Number of LLM requests / turns used.
    pub llm_turns_used: usize,
    /// Maximum LLM turns permitted by budget.
    pub max_llm_turns: usize,
    /// Number of tool calls used.
    pub tool_calls_used: usize,
    /// Maximum tool calls permitted by budget.
    pub max_tool_calls: usize,
    /// Number of coalesced/dropped progress events on the bounded event channel.
    pub dropped_progress_events: u64,
    /// Number of non-progress events lost to channel backpressure or closure.
    pub dropped_events: u64,
    /// Highest event sequence number observed for the active run.
    pub last_event_sequence: u64,
    /// Number of sequence numbers missing from the active run's event stream.
    pub sequence_gap_events: u64,
    /// Total structured diagnostic events received.
    pub total_events_received: u64,
    /// Active collectors status summary.
    pub collector_statuses: Vec<(CollectorId, OperationalStatus, String)>,
}

/// Authoritative diagnostic artefacts produced by a background run or loaded from disk.
#[derive(Debug, Clone)]
pub struct DiagnosticArtefacts {
    /// Target URL string.
    pub target: String,
    /// Run mode that produced these artefacts.
    pub mode: DiagnosticRunMode,
    /// Collected evidence snapshot (when available from a live run).
    pub snapshot: Option<EvidenceSnapshot>,
    /// Deterministic audit report.
    pub audit_report: Option<AuditReport>,
    /// Agentic investigation report (when `AgenticInvestigation` or escalated `Patrol` ran).
    pub investigation_report: Option<InvestigationReport>,
    /// Patrol report (when `AutonomousPatrol` ran).
    pub patrol_report: Option<PatrolReport>,
    /// Historical reports loaded from JSONL history.
    pub history_reports: Vec<AuditReport>,
    /// Regression diff between baseline and current report.
    pub regression_report: Option<RegressionReport>,
    /// Elapsed duration in milliseconds.
    pub elapsed_ms: u64,
}

/// Complete application state owned by the Zwergenleitstand TUI loop.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Currently active workbench view (`1`–`9`).
    pub active_view: WorkbenchView,
    /// Current run lifecycle state.
    pub lifecycle: RunLifecycleState,
    /// Active run identifier, if a run has started.
    pub active_run_id: Option<String>,
    /// Target URL being inspected.
    pub target_url: String,
    /// Active diagnostic mode.
    pub run_mode: DiagnosticRunMode,
    /// Launcher modal state.
    pub launcher: LauncherState,
    /// Detected runtime instrument availability.
    pub instruments: InstrumentAvailability,
    /// Visual theme and glyph configuration.
    pub theme: Theme,
    /// Whether the Help overlay (`?`) is currently open.
    pub help_open: bool,
    /// Whether the bottom search/filter input bar (`/`) is currently focused.
    pub search_focused: bool,
    /// Terminal width in columns.
    pub terminal_width: u16,
    /// Terminal height in rows.
    pub terminal_height: u16,
    /// Status banner message in the footer.
    pub status_message: String,
    /// Optional default output path for saving reports (`w`).
    pub output_path: Option<PathBuf>,

    /// Die Zwergenbrigade rows (`2:Brigade`).
    pub brigade_rows: Vec<BrigadeActivityRow>,
    /// Selected row index in `2:Brigade`.
    pub selected_brigade_index: usize,

    /// Application surface rows (`3:Targets`).
    pub target_rows: Vec<TargetSurfaceRow>,
    /// Selected row index in `3:Targets`.
    pub selected_target_index: usize,

    /// Authoritative sanitized findings (`4:Findings`).
    pub findings: Vec<FindingRow>,
    /// Indices into `findings` matching the current filter and sort order.
    pub visible_finding_indices: Vec<usize>,
    /// Selected position inside `visible_finding_indices`.
    pub selected_finding_pos: usize,
    /// Active finding filter criteria.
    pub finding_filter: FindingFilterState,
    /// Active finding sort order.
    pub finding_sort: FindingSortOrder,

    /// Selected evidence category in `5:Evidence`.
    pub evidence_category: EvidenceCategory,
    /// Pagination offset (in items) within the active evidence category.
    pub evidence_offset: usize,
    /// Selected row within the current evidence page.
    pub selected_evidence_row: usize,

    /// Hypotheses displayed in `6:Investigation`.
    pub hypotheses: Vec<HypothesisRow>,
    /// Selected hypothesis index in `6:Investigation`.
    pub selected_hypothesis_index: usize,
    /// Specialist contributions displayed in `6:Investigation`.
    pub specialist_notes: Vec<(DwarfId, String, String)>,
    /// Tool execution trace displayed in `6:Investigation`.
    pub tool_trace: Vec<ToolActivityRow>,
    /// Final investigation conclusion, if available.
    pub investigation_conclusion: Option<String>,

    /// Topology relationship rows in `7:Topology`.
    pub topology_rows: Vec<TopologyNodeRow>,
    /// Selected row index in `7:Topology`.
    pub selected_topology_index: usize,

    /// Historical audit rows in `8:History`.
    pub history_rows: Vec<HistoryEntryRow>,
    /// Selected row index in `8:History`.
    pub selected_history_index: usize,
    /// Active regression comparison report in `8:History`.
    pub regression: Option<RegressionReport>,

    /// System and budget telemetry in `9:System`.
    pub system_metrics: SystemMetricsState,
    /// Rolling ring buffer of recent activity lines (`timestamp + summary`).
    pub recent_activity: VecDeque<String>,

    /// Authoritative captured evidence snapshot (never cloned per frame).
    pub snapshot: Option<EvidenceSnapshot>,
    /// Authoritative deterministic audit report.
    pub audit_report: Option<AuditReport>,
    /// Authoritative loaded history reports for offline comparison.
    pub history_reports: Vec<AuditReport>,
    /// Whether the operator has requested exit.
    pub should_quit: bool,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(ThemeMode::detect_from_env(), GlyphSet::detect_from_env())
    }
}

impl AppState {
    /// Initialises a clean workbench state with the detected theme and brigade registry.
    #[must_use]
    pub fn new(theme_mode: ThemeMode, glyphs: GlyphSet) -> Self {
        Self {
            active_view: WorkbenchView::Overview,
            lifecycle: RunLifecycleState::Configuring,
            active_run_id: None,
            target_url: String::from("https://example.org"),
            run_mode: DiagnosticRunMode::DeterministicCheck,
            launcher: LauncherState::default(),
            instruments: InstrumentAvailability::detect(),
            theme: Theme::new(theme_mode, glyphs),
            help_open: false,
            search_focused: false,
            terminal_width: 120,
            terminal_height: 40,
            status_message: String::from(
                "Ready. Configure target in Launcher or press ? for keyboard help.",
            ),
            output_path: None,
            brigade_rows: BrigadeActivityRow::initial_brigade(),
            selected_brigade_index: 0,
            target_rows: Vec::new(),
            selected_target_index: 0,
            findings: Vec::new(),
            visible_finding_indices: Vec::new(),
            selected_finding_pos: 0,
            finding_filter: FindingFilterState::default(),
            finding_sort: FindingSortOrder::SeverityDesc,
            evidence_category: EvidenceCategory::Http,
            evidence_offset: 0,
            selected_evidence_row: 0,
            hypotheses: Vec::new(),
            selected_hypothesis_index: 0,
            specialist_notes: Vec::new(),
            tool_trace: Vec::new(),
            investigation_conclusion: None,
            topology_rows: Vec::new(),
            selected_topology_index: 0,
            history_rows: Vec::new(),
            selected_history_index: 0,
            regression: None,
            system_metrics: SystemMetricsState {
                collector_statuses: vec![
                    (
                        CollectorId::Http,
                        OperationalStatus::Waiting,
                        "Not started".to_owned(),
                    ),
                    (
                        CollectorId::Tls,
                        OperationalStatus::Waiting,
                        "Not started".to_owned(),
                    ),
                    (
                        CollectorId::Browser,
                        OperationalStatus::Waiting,
                        "Not scheduled".to_owned(),
                    ),
                    (
                        CollectorId::Axe,
                        OperationalStatus::Waiting,
                        "Not scheduled".to_owned(),
                    ),
                    (
                        CollectorId::Lighthouse,
                        OperationalStatus::Waiting,
                        "Not scheduled".to_owned(),
                    ),
                ],
                ..SystemMetricsState::default()
            },
            recent_activity: VecDeque::with_capacity(MAX_RECENT_EVENTS),
            snapshot: None,
            audit_report: None,
            history_reports: Vec::new(),
            should_quit: false,
        }
    }

    /// Appends a sanitized activity entry to the bounded recent activity buffer.
    pub fn push_activity(&mut self, message: &str) {
        if self.recent_activity.len() >= MAX_RECENT_EVENTS {
            self.recent_activity.pop_front();
        }
        let secs = self.system_metrics.elapsed_ms / 1000;
        let mins = secs / 60;
        let rem_secs = secs % 60;
        let clean = sanitize_line(message, 140);
        self.recent_activity
            .push_back(format!("{mins:02}:{rem_secs:02}  {clean}"));
    }

    /// Recomputes `visible_finding_indices` according to `finding_filter` and `finding_sort`,
    /// preserving the currently selected finding when it remains visible.
    pub fn refresh_visible_findings(&mut self) {
        let previous_finding_idx = self
            .visible_finding_indices
            .get(self.selected_finding_pos)
            .copied();

        let query_lower = self.finding_filter.search_query.trim().to_ascii_lowercase();
        let mut indices: Vec<usize> = self
            .findings
            .iter()
            .filter(|f| {
                if let Some(min_sev) = self.finding_filter.min_severity
                    && f.severity > min_sev
                {
                    return false;
                }
                if let Some(dwarf) = self.finding_filter.dwarf
                    && f.dwarf_id != dwarf
                {
                    return false;
                }
                if !query_lower.is_empty() {
                    let matches = f.rule_id.to_ascii_lowercase().contains(&query_lower)
                        || f.title.to_ascii_lowercase().contains(&query_lower)
                        || f.description.to_ascii_lowercase().contains(&query_lower);
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .map(|f| f.index)
            .collect();

        indices.sort_by(|&a, &b| {
            let fa = &self.findings[a];
            let fb = &self.findings[b];
            match self.finding_sort {
                FindingSortOrder::SeverityDesc => fa
                    .severity
                    .cmp(&fb.severity)
                    .then_with(|| fa.confidence.cmp(&fb.confidence))
                    .then_with(|| fa.rule_id.cmp(&fb.rule_id))
                    .then_with(|| fa.index.cmp(&fb.index)),
                FindingSortOrder::ConfidenceDesc => fa
                    .confidence
                    .cmp(&fb.confidence)
                    .then_with(|| fa.severity.cmp(&fb.severity))
                    .then_with(|| fa.rule_id.cmp(&fb.rule_id))
                    .then_with(|| fa.index.cmp(&fb.index)),
                FindingSortOrder::RuleIdAsc => fa
                    .rule_id
                    .cmp(&fb.rule_id)
                    .then_with(|| fa.severity.cmp(&fb.severity))
                    .then_with(|| fa.index.cmp(&fb.index)),
                FindingSortOrder::SpecialistAsc => fa
                    .dwarf_id
                    .display_name()
                    .cmp(fb.dwarf_id.display_name())
                    .then_with(|| fa.severity.cmp(&fb.severity))
                    .then_with(|| fa.rule_id.cmp(&fb.rule_id))
                    .then_with(|| fa.index.cmp(&fb.index)),
            }
        });

        self.visible_finding_indices = indices;
        if let Some(prev) = previous_finding_idx
            && let Some(pos) = self.visible_finding_indices.iter().position(|&i| i == prev)
        {
            self.selected_finding_pos = pos;
        } else if self.selected_finding_pos >= self.visible_finding_indices.len() {
            self.selected_finding_pos = self.visible_finding_indices.len().saturating_sub(1);
        }
    }

    /// Returns the currently selected [`FindingRow`], if any.
    #[must_use]
    pub fn selected_finding(&self) -> Option<&FindingRow> {
        let idx = *self
            .visible_finding_indices
            .get(self.selected_finding_pos)?;
        self.findings.get(idx)
    }

    /// Populates the workbench state from completed or offline [`DiagnosticArtefacts`].
    #[allow(clippy::too_many_lines)]
    pub fn ingest_artefacts(&mut self, artefacts: DiagnosticArtefacts) {
        self.target_url = sanitize_url_for_display(&artefacts.target, 120);
        self.run_mode = artefacts.mode;
        self.system_metrics.elapsed_ms = artefacts.elapsed_ms;
        self.launcher.open = false;

        if let Some(snapshot) = artefacts.snapshot {
            self.update_collectors_from_snapshot(&snapshot);
            self.build_topology_from_snapshot(&snapshot);
            self.snapshot = Some(snapshot);
        }

        if let Some(ref inv) = artefacts.investigation_report {
            self.hypotheses = inv.hypotheses.iter().map(HypothesisRow::from).collect();
            self.selected_hypothesis_index = 0;
            self.specialist_notes = inv
                .specialists
                .iter()
                .map(|s| {
                    (
                        s.dwarf_id,
                        sanitize_line(&s.focus, 96),
                        sanitize_multiline(&s.observations.join("; "), 220),
                    )
                })
                .collect();
            self.tool_trace = inv
                .tool_trace
                .iter()
                .map(|t| ToolActivityRow {
                    tool_id: sanitize_line(&t.tool_id, 64),
                    status: if !t.authorised {
                        OperationalStatus::Blocked
                    } else if t.succeeded {
                        OperationalStatus::Done
                    } else {
                        OperationalStatus::Failed
                    },
                    summary: sanitize_line(&t.summary, 120),
                })
                .collect();
            self.investigation_conclusion = Some(sanitize_multiline(&inv.conclusion, 360));
            self.system_metrics.llm_turns_used = inv.ledger.llm_turns_used;
            self.system_metrics.max_llm_turns = inv.ledger.budget.max_llm_turns;
            self.system_metrics.tool_calls_used = inv.ledger.tool_calls_used;
            self.system_metrics.max_tool_calls = inv.ledger.budget.max_tool_calls;

            if !inv.discovered_pages.is_empty() {
                self.populate_targets_from_discovered(&inv.discovered_pages);
            }
        }

        if let Some(ref patrol) = artefacts.patrol_report {
            self.system_metrics.http_requests = patrol.resource_ledger.http_requests;
            self.system_metrics.browser_sessions = patrol.resource_ledger.browser_sessions;
            self.system_metrics.llm_turns_used = patrol.resource_ledger.llm_requests;
            self.populate_targets_from_patrol(patrol);
            if self.regression.is_none() {
                self.regression.clone_from(&patrol.regression);
            }
        }

        if let Some(report) = artefacts.audit_report {
            self.populate_from_audit_report(&report);
            self.audit_report = Some(report);
        }

        if !artefacts.history_reports.is_empty() {
            self.populate_history(artefacts.history_reports);
        }

        if let Some(reg) = artefacts.regression_report {
            self.regression = Some(reg);
        }

        self.lifecycle = match self.lifecycle {
            RunLifecycleState::Failed | RunLifecycleState::Cancelled => self.lifecycle,
            _ => {
                let any_partial =
                    self.system_metrics
                        .collector_statuses
                        .iter()
                        .any(|(_, st, _)| {
                            matches!(st, OperationalStatus::Partial | OperationalStatus::Failed)
                        });
                if any_partial {
                    RunLifecycleState::Partial
                } else {
                    RunLifecycleState::Completed
                }
            }
        };
    }

    fn update_collectors_from_snapshot(&mut self, snapshot: &EvidenceSnapshot) {
        self.system_metrics.collector_statuses = vec![
            (
                CollectorId::Http,
                outcome_status(&snapshot.http),
                outcome_summary(&snapshot.http),
            ),
            (
                CollectorId::Tls,
                outcome_status(&snapshot.tls),
                outcome_summary(&snapshot.tls),
            ),
            (
                CollectorId::Browser,
                outcome_status(&snapshot.browser),
                outcome_summary(&snapshot.browser),
            ),
            (
                CollectorId::Axe,
                outcome_status(&snapshot.axe),
                outcome_summary(&snapshot.axe),
            ),
            (
                CollectorId::Lighthouse,
                outcome_status(&snapshot.lighthouse),
                outcome_summary(&snapshot.lighthouse),
            ),
        ];
        if matches!(
            snapshot.http,
            CollectorOutcome::Captured { .. } | CollectorOutcome::Partial { .. }
        ) {
            self.system_metrics.http_requests = self.system_metrics.http_requests.max(1);
        }
        if matches!(
            snapshot.browser,
            CollectorOutcome::Captured { .. } | CollectorOutcome::Partial { .. }
        ) {
            self.system_metrics.browser_sessions = self.system_metrics.browser_sessions.max(1);
        }
    }

    fn populate_from_audit_report(&mut self, report: &AuditReport) {
        let display_target = sanitize_url_for_display(report.target.as_str(), 120);
        self.target_url.clone_from(&display_target);

        // Update Brigade rows from analyser results.
        for row in &mut self.brigade_rows {
            if let Some(analyser) = report.analysers.iter().find(|a| a.dwarf_id == row.dwarf_id) {
                let mut passed = 0usize;
                let mut failed = 0usize;
                let mut skipped = 0usize;
                let mut inconclusive = 0usize;
                for check in &analyser.checks {
                    match check {
                        crate::domain::CheckStatus::Passed { .. } => passed += 1,
                        crate::domain::CheckStatus::Failed { .. } => failed += 1,
                        crate::domain::CheckStatus::Skipped { .. } => skipped += 1,
                        crate::domain::CheckStatus::Unavailable { .. } => inconclusive += 1,
                    }
                }
                row.checks_total = analyser.checks.len();
                row.checks_passed = passed;
                row.checks_failed = failed;
                row.checks_skipped = skipped;
                row.checks_inconclusive = inconclusive;
                row.findings_count = analyser.findings.len();
                row.status = if row.checks_total > 0 && skipped == row.checks_total {
                    OperationalStatus::Skipped
                } else if inconclusive > 0 {
                    OperationalStatus::Partial
                } else {
                    OperationalStatus::Done
                };
                row.current_activity = format!(
                    "Evaluated {} checks ({} findings)",
                    row.checks_total, row.findings_count
                );
            } else if row.dwarf_id == DwarfId::Dokumentations {
                row.status = OperationalStatus::Done;
                row.current_activity = String::from("Compiled structured AuditReport");
            }
        }

        // Populate findings table.
        let mut all_findings = Vec::new();
        for analyser in &report.analysers {
            for finding in &analyser.findings {
                let idx = all_findings.len();
                all_findings.push(finding_to_row(
                    idx,
                    analyser.dwarf_id,
                    &display_target,
                    finding,
                ));
            }
        }
        self.findings = all_findings;
        self.refresh_visible_findings();

        // Populate seed target row if no multi-page crawl was loaded.
        if self.target_rows.is_empty() {
            let (http_status, state) = match &report.http {
                CollectorOutcome::Captured { data } => {
                    (Some(data.status_code), TargetInspectionState::Completed)
                }
                CollectorOutcome::Partial { data, .. } => {
                    (Some(data.status_code), TargetInspectionState::Partial)
                }
                CollectorOutcome::Failed { .. } => (None, TargetInspectionState::Failed),
                CollectorOutcome::Skipped { .. } => (None, TargetInspectionState::Partial),
            };
            let has_rendered = report.rendered_history.is_some();
            self.target_rows.push(TargetSurfaceRow {
                display_url: display_target.clone(),
                discovery_source: String::from("seed"),
                depth: 0,
                page_type: String::from("Seed target"),
                http_status,
                state,
                evidence_summary: if has_rendered {
                    String::from("Source + Rendered")
                } else {
                    String::from("Source (Level 1)")
                },
                findings_count: self.findings.len(),
            });
        }

        if self.topology_rows.is_empty() {
            self.build_topology_from_report(report);
        }
    }

    fn populate_targets_from_discovered(&mut self, pages: &[DiscoveredPage]) {
        self.target_rows = pages
            .iter()
            .map(|p| {
                let state = match p.status {
                    PageCrawlStatus::Investigated => TargetInspectionState::Completed,
                    PageCrawlStatus::PartiallyInvestigated => TargetInspectionState::Partial,
                    PageCrawlStatus::SkippedBudget => TargetInspectionState::SkippedBudget,
                    PageCrawlStatus::Unreachable => TargetInspectionState::Failed,
                };
                TargetSurfaceRow {
                    display_url: sanitize_url_for_display(p.url.as_str(), 100),
                    discovery_source: String::from("crawl"),
                    depth: p.depth,
                    page_type: format!("{:?}", p.page_type),
                    http_status: None,
                    state,
                    evidence_summary: String::from("Source (Level 1)"),
                    findings_count: 0,
                }
            })
            .collect();
        self.selected_target_index = 0;
    }

    fn populate_targets_from_patrol(&mut self, patrol: &PatrolReport) {
        let mut rows = Vec::new();
        for selected in &patrol.sampling_plan.selections {
            rows.push(TargetSurfaceRow {
                display_url: sanitize_url_for_display(selected.url.as_str(), 100),
                discovery_source: format!("{:?}", selected.reason),
                depth: 0,
                page_type: format!("{:?}", selected.page_type),
                http_status: None,
                state: TargetInspectionState::Completed,
                evidence_summary: String::from("Patrol sample"),
                findings_count: 0,
            });
        }
        for reused in &patrol.sampling_plan.reused_urls {
            rows.push(TargetSurfaceRow {
                display_url: sanitize_url_for_display(reused.as_str(), 100),
                discovery_source: String::from("memory"),
                depth: 0,
                page_type: String::from("Remembered"),
                http_status: Some(304),
                state: TargetInspectionState::ReusedUnchanged,
                evidence_summary: String::from("Conditional HTTP verified"),
                findings_count: 0,
            });
        }
        if !rows.is_empty() {
            self.target_rows = rows;
            self.selected_target_index = 0;
        }
    }

    fn build_topology_from_snapshot(&mut self, snapshot: &EvidenceSnapshot) {
        let mut rows = Vec::new();
        let root_url = sanitize_url_for_display(snapshot.target.as_str(), 100);
        rows.push(TopologyNodeRow {
            depth: 0,
            relation_kind: "TARGET",
            label: root_url,
            detail: String::from("Seed target"),
            directly_observed: true,
        });

        if let CollectorOutcome::Captured { data: http }
        | CollectorOutcome::Partial { data: http, .. } = &snapshot.http
        {
            for hop in &http.redirect_chain {
                rows.push(TopologyNodeRow {
                    depth: 1,
                    relation_kind: "REDIRECT",
                    label: format!(
                        "{} -> {}",
                        sanitize_url_for_display(&hop.from_url, 60),
                        sanitize_url_for_display(&hop.to_url, 60)
                    ),
                    detail: format!("HTTP {}", hop.status_code),
                    directly_observed: true,
                });
            }
            rows.push(TopologyNodeRow {
                depth: 1,
                relation_kind: "FINAL",
                label: sanitize_url_for_display(&http.final_url, 100),
                detail: format!("HTTP {} ({} B)", http.status_code, http.body_bytes),
                directly_observed: true,
            });
        }

        if let CollectorOutcome::Captured { data: browser }
        | CollectorOutcome::Partial { data: browser, .. } = &snapshot.browser
        {
            for res in browser.resources.iter().take(48) {
                let status_str = res
                    .status_code
                    .map_or_else(|| String::from("---"), |code| format!("HTTP {code}"));
                rows.push(TopologyNodeRow {
                    depth: 2,
                    relation_kind: "RESOURCE",
                    label: sanitize_url_for_display(&res.url, 90),
                    detail: format!("{} | {}", sanitize_line(&res.resource_type, 24), status_str),
                    directly_observed: true,
                });
            }
        }

        self.topology_rows = rows;
        self.selected_topology_index = 0;
    }

    fn build_topology_from_report(&mut self, report: &AuditReport) {
        let mut rows = Vec::new();
        rows.push(TopologyNodeRow {
            depth: 0,
            relation_kind: "TARGET",
            label: sanitize_url_for_display(report.target.as_str(), 100),
            detail: String::from("Saved AuditReport"),
            directly_observed: true,
        });
        if let CollectorOutcome::Captured { data: value }
        | CollectorOutcome::Partial { data: value, .. } = &report.http
        {
            rows.push(TopologyNodeRow {
                depth: 1,
                relation_kind: "FINAL",
                label: sanitize_url_for_display(&value.final_url, 100),
                detail: format!(
                    "HTTP {} ({} redirects)",
                    value.status_code,
                    value.redirect_chain.len()
                ),
                directly_observed: true,
            });
        }
        self.topology_rows = rows;
        self.selected_topology_index = 0;
    }

    fn populate_history(&mut self, reports: Vec<AuditReport>) {
        self.history_rows = reports
            .iter()
            .enumerate()
            .map(|(index, r)| {
                let mut total_findings = 0usize;
                let mut high_or_crit = 0usize;
                let mut total_checks = 0usize;
                let mut passed_checks = 0usize;
                for a in &r.analysers {
                    total_findings += a.findings.len();
                    high_or_crit += a
                        .findings
                        .iter()
                        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
                        .count();
                    total_checks += a.checks.len();
                    passed_checks += a
                        .checks
                        .iter()
                        .filter(|c| matches!(c, crate::domain::CheckStatus::Passed { .. }))
                        .count();
                }
                let http_status = match &r.http {
                    CollectorOutcome::Captured { data: value }
                    | CollectorOutcome::Partial { data: value, .. } => {
                        format!("HTTP {}", value.status_code)
                    }
                    CollectorOutcome::Failed { .. } => String::from("FAILED"),
                    CollectorOutcome::Skipped { .. } => String::from("SKIPPED"),
                };
                HistoryEntryRow {
                    index,
                    captured_at_unix_secs: r.captured_at_unix_secs,
                    target: sanitize_url_for_display(r.target.as_str(), 80),
                    http_status,
                    findings_count: total_findings,
                    high_or_crit_count: high_or_crit,
                    checks_summary: format!("{passed_checks}/{total_checks} passed"),
                    has_rendered_history: r.rendered_history.is_some(),
                }
            })
            .collect();

        if reports.len() >= 2 && self.regression.is_none() {
            let baseline = &reports[reports.len() - 2];
            let current = &reports[reports.len() - 1];
            self.regression = Some(crate::persistence::diff_reports(baseline, current));
        }
        self.history_reports = reports;
        self.selected_history_index = self.history_rows.len().saturating_sub(1);
    }

    /// Recomputes the regression diff in `8:History` comparing the selected baseline entry
    /// against the latest loaded report.
    pub fn compare_selected_history_entry(&mut self) {
        if self.history_reports.len() < 2 {
            return;
        }
        let latest_idx = self.history_reports.len() - 1;
        let baseline_idx = self
            .selected_history_index
            .min(latest_idx.saturating_sub(1));
        let baseline = &self.history_reports[baseline_idx];
        let current = &self.history_reports[latest_idx];
        self.regression = Some(crate::persistence::diff_reports(baseline, current));
        self.status_message = format!(
            "Compared history run #{} (baseline) -> #{} (latest).",
            baseline_idx + 1,
            latest_idx + 1
        );
    }
}

fn outcome_status<T>(outcome: &CollectorOutcome<T>) -> OperationalStatus {
    match outcome {
        CollectorOutcome::Captured { .. } => OperationalStatus::Done,
        CollectorOutcome::Partial { .. } => OperationalStatus::Partial,
        CollectorOutcome::Failed { .. } => OperationalStatus::Failed,
        CollectorOutcome::Skipped { .. } => OperationalStatus::Skipped,
    }
}

fn outcome_summary<T>(outcome: &CollectorOutcome<T>) -> String {
    match outcome {
        CollectorOutcome::Captured { .. } => String::from("Captured"),
        CollectorOutcome::Partial { warnings, .. } => {
            format!("Partial ({} warning(s))", warnings.len())
        }
        CollectorOutcome::Failed { error } => sanitize_line(error, 72),
        CollectorOutcome::Skipped { reason } => sanitize_line(reason, 72),
    }
}

fn finding_to_row(
    index: usize,
    dwarf_id: DwarfId,
    target_url: &str,
    finding: &Finding,
) -> FindingRow {
    let primary_evidence_category =
        finding
            .evidence_refs
            .first()
            .map_or(EvidenceCategory::Http, |e| match e.source {
                EvidenceSource::HttpStatus
                | EvidenceSource::HttpFinalUrl
                | EvidenceSource::HttpRedirectChain
                | EvidenceSource::HttpHeaders
                | EvidenceSource::HttpTiming
                | EvidenceSource::HttpBody => EvidenceCategory::Http,
                EvidenceSource::TlsCertificate => EvidenceCategory::Tls,
                EvidenceSource::BrowserRuntime | EvidenceSource::VisualLayout => {
                    if e.detail.starts_with("rendered-block") {
                        EvidenceCategory::RenderedContent
                    } else if e.detail.starts_with("source-vs-rendered") {
                        EvidenceCategory::SourceRenderedDiff
                    } else if e.detail.starts_with("timeline-event") {
                        EvidenceCategory::BrowserTimeline
                    } else if e.detail.starts_with("interactive-element")
                        || e.detail.starts_with("application-state")
                        || e.detail.starts_with("interaction-step")
                    {
                        EvidenceCategory::InteractiveAndState
                    } else if e.detail.starts_with("geometry-element")
                        || e.detail.starts_with("ax-node")
                    {
                        EvidenceCategory::VisualGeometryAndAx
                    } else if e.detail.starts_with("cookie=")
                        || e.detail.starts_with("third-party-origin=")
                        || e.detail.starts_with("security-posture")
                        || e.detail.starts_with("security-challenge")
                    {
                        EvidenceCategory::SecurityAndPrivacy
                    } else if e.detail.starts_with("performance-attribution")
                        || e.detail.starts_with("media-asset")
                        || e.detail.starts_with("font-asset")
                    {
                        EvidenceCategory::PerformanceAndMedia
                    } else if e.detail.starts_with("indexability-authority")
                        || e.detail.starts_with("structured-entity")
                    {
                        EvidenceCategory::SeoAndStructuredData
                    } else if e.detail.starts_with("responsive-anomaly")
                        || e.detail.starts_with("link-graph")
                    {
                        EvidenceCategory::ResponsiveAndLinks
                    } else if e.detail.starts_with("visual-artifacts")
                        || e.detail.starts_with("service-worker")
                        || e.detail.starts_with("tls-caa")
                    {
                        EvidenceCategory::VisualSwAndTlsCaa
                    } else if e.detail.contains("console") || e.detail.contains("runtime") {
                        EvidenceCategory::RuntimeErrors
                    } else if e.detail.contains("ax") || e.detail.contains("focus") {
                        EvidenceCategory::Accessibility
                    } else if e.detail.contains("lcp")
                        || e.detail.contains("cls")
                        || e.detail.contains("cpu")
                    {
                        EvidenceCategory::Performance
                    } else {
                        EvidenceCategory::NetworkResources
                    }
                }
                EvidenceSource::AxeReport => EvidenceCategory::Axe,
                EvidenceSource::LighthouseReport => EvidenceCategory::Lighthouse,
            });

    let sanitized_refs = finding
        .evidence_refs
        .iter()
        .map(|ev| EvidenceRef {
            source: ev.source,
            detail: sanitize_line(&ev.detail, 140),
        })
        .collect();

    FindingRow {
        index,
        dwarf_id,
        rule_id: sanitize_line(&finding.rule_id.0, 80),
        severity: finding.severity,
        confidence: finding.confidence,
        evidence_level: finding.evidence_level,
        target_url: target_url.to_owned(),
        title: sanitize_line(&finding.title, 120),
        description: sanitize_multiline(&finding.summary, 360),
        recommendation: sanitize_multiline(
            finding
                .remediation
                .as_deref()
                .unwrap_or("No specific remediation guidance."),
            360,
        ),
        evidence_refs: sanitized_refs,
        primary_evidence_category,
    }
}

/// Formats a [`RenderedTextDiff`] summary for display in `8:History`.
#[must_use]
pub fn format_rendered_diff_summary(diff: Option<&RenderedTextDiff>) -> String {
    match diff {
        None => String::from("Not evaluated"),
        Some(RenderedTextDiff::Compared {
            changed_count,
            unchanged_count,
            not_comparable_count,
            ..
        }) => format!(
            "Compared ({changed_count} changed, {unchanged_count} unchanged, {not_comparable_count} not comparable)"
        ),
        Some(RenderedTextDiff::Unavailable { reason }) => format!("Unavailable ({reason})"),
    }
}
