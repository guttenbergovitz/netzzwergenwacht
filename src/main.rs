//! `NetzZwergenWacht` CLI entry point (`DokumentationsZwerg` presentation).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;

use netzzwergenwacht::analysis::{self, AuditReport};
use netzzwergenwacht::brigade::{self, DwarfId, MOTTO};
use netzzwergenwacht::collection;
use netzzwergenwacht::config::{self, AppConfig, PolicyConfig, PolicyEvaluation};
use netzzwergenwacht::doctor;
use netzzwergenwacht::domain::{
    AnalyserResult, AuditTarget, CheckStatus, CollectorOutcome, Measurement, Severity, TargetPolicy,
};
use netzzwergenwacht::events::DiagnosticRunMode;
use netzzwergenwacht::persistence::{self, RegressionReport, RenderedTextDiff};
use netzzwergenwacht::tui::{self, ThemeMode, TuiStartupOptions};

const EXIT_OK: u8 = 0;
const EXIT_FINDINGS: u8 = 1;
const EXIT_COLLECTION_OR_INPUT_ERROR: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "nzw",
    version,
    about = "Evidence-driven external web quality and reliability auditing engine"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a bounded deterministic audit against a target URL.
    Check {
        /// Target HTTP or HTTPS URL to audit.
        url: String,
        /// Optional path to a TOML configuration file (`nzw.toml`).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Optional path to a versioned Application Quality Profile (`nzw-profile.toml`).
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Optional file path to write the rendered output (`json`, `html`, `markdown`, `text`).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Per-request HTTP timeout in seconds.
        #[arg(long)]
        timeout_secs: Option<u64>,
        /// End-to-end collection deadline in seconds (including DNS and redirects).
        #[arg(long)]
        audit_timeout_secs: Option<u64>,
        /// Maximum number of HTTP redirects to follow.
        #[arg(long)]
        max_redirects: Option<usize>,
        /// Fail quality gate if any finding has severity >= this threshold.
        #[arg(long, value_enum)]
        fail_on: Option<FailOnSeverity>,
        /// Optional JSONL file path to append this audit report for history/regression tracking.
        #[arg(long)]
        history: Option<PathBuf>,
        /// Run optional Level 2 Lighthouse subprocess adapter for Core Web Vitals.
        #[arg(long)]
        lighthouse: bool,
        /// Run optional Level 2 headless Chromium subprocess adapter (`BrowserZwerg` & `GestaltungsZwerg`).
        #[arg(long)]
        browser: bool,
        /// Run optional Level 2 `axe-core` subprocess adapter (`ZugänglichkeitsZwerg`).
        #[arg(long)]
        axe: bool,
        /// Run optional `KommandantZwerg` AI synthesis (requires `NZW_LLM_API_KEY`).
        #[arg(long)]
        ai: bool,
        /// Launch the interactive Zwergenleitstand TUI workbench for this check.
        #[arg(long)]
        tui: bool,
    },
    /// Run a bounded deterministic audit over a list of URLs (one per line, `#` comments allowed).
    Batch {
        /// Path to a file containing target URLs.
        targets_file: PathBuf,
        /// Optional path to a TOML configuration file (`nzw.toml`).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Maximum concurrent targets.
        #[arg(long)]
        max_concurrency: Option<usize>,
        /// Fail quality gate if any target has a finding with severity >= this threshold.
        #[arg(long, value_enum)]
        fail_on: Option<FailOnSeverity>,
        /// Optional JSONL file path to append all generated audit reports.
        #[arg(long)]
        history: Option<PathBuf>,
    },
    /// Inspect the resolved configuration without starting a run.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Validate a target URL against target and SSRF policies without fetching.
    Validate {
        /// Target URL to validate.
        url: String,
        /// Allow loopback and private network targets.
        #[arg(long)]
        allow_private: bool,
    },
    /// Report which local instruments and configuration are available.
    Doctor {
        /// Optional path to a TOML configuration file (`nzw.toml`).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Run deterministic application-wide reconnaissance and retain the evidence.
    ///
    /// Unlike `check`, which inspects a single page, `scan` crawls the same-origin
    /// application surface concurrently, acquires shared subresources once, records
    /// explicit coverage and stores the observations in the local evidence store.
    Scan {
        /// Target HTTP or HTTPS URL to reconnaissance.
        url: String,
        /// Optional path to a TOML configuration file (`nzw.toml`).
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Maximum number of pages to acquire.
        #[arg(long, default_value_t = 50)]
        max_pages: usize,
        /// Maximum link-following depth from the seed URL.
        #[arg(long, default_value_t = 2)]
        max_depth: usize,
        /// End-to-end crawl deadline in seconds.
        #[arg(long)]
        audit_timeout_secs: Option<u64>,
        /// Run headless browser checks on up to N sampled pages from the crawl.
        #[arg(long, default_value_t = 0)]
        browser_sample: usize,
        /// Optional file path to write the rendered scan report (`json`, `html`, `markdown`, `text`).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Directory for retained evidence (defaults to `.nzw/evidence`).
        #[arg(long)]
        evidence_dir: Option<PathBuf>,
    },
    /// Compare a baseline and current audit report (JSON or JSONL) for regressions.
    Diff {
        /// Path to baseline JSON or JSONL report file.
        baseline: PathBuf,
        /// Path to current JSON or JSONL report file.
        current: PathBuf,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Optional file path to write the rendered diff (`json`, `html`, `sarif`, `markdown`, `text`).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run a hypothesis-driven `KommandantZwerg` investigation (requires `NZW_LLM_API_KEY`).
    Investigate {
        /// Target HTTP or HTTPS URL to investigate.
        url: String,
        /// Stakeholder objective guiding the investigation.
        #[arg(
            long,
            default_value = "Assess overall web quality and release readiness"
        )]
        objective: String,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Target stakeholder perspective for Markdown output.
        #[arg(long, value_enum, default_value_t = AudienceArg::Technical)]
        audience: AudienceArg,
        /// Include chronological `InvestigationEvent` trace in text output.
        #[arg(long)]
        events: bool,
        /// Launch the interactive Zwergenleitstand TUI workbench for this investigation.
        #[arg(long)]
        tui: bool,
        /// Path to a TOML configuration file (TUI mode only).
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Re-audit a target and verify whether baseline findings are resolved or unverified.
    Verify {
        /// Path to baseline JSONL/JSON report file.
        #[arg(long)]
        baseline: PathBuf,
        /// Target HTTP or HTTPS URL to re-investigate.
        url: String,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Optional file path to write the rendered verification report.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run an autonomous recurring web quality patrol requiring only a target URL or `--targets`.
    Patrol {
        /// Target HTTP or HTTPS URL to patrol (omit when using `--targets`).
        url: Option<String>,
        /// Optional TOML configuration file (`[budget]`, `[policy]`, `[models]`).
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Path to a portfolio TOML file (`applications.toml`).
        #[arg(long)]
        targets: Option<PathBuf>,
        /// Enable selective Level 2 headless browser diagnostics on deep samples.
        #[arg(long)]
        browser: bool,
        /// Directory for persistent application memory (defaults to `.nzw/memory`).
        #[arg(long, default_value = netzzwergenwacht::patrol::memory::DEFAULT_MEMORY_DIR)]
        memory_dir: PathBuf,
        /// Maximum pages actively inspected per patrol.
        #[arg(long, default_value_t = 10)]
        max_pages: usize,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Target stakeholder perspective for Markdown output.
        #[arg(long, value_enum, default_value_t = AudienceArg::Technical)]
        audience: AudienceArg,
        /// Launch the interactive Zwergenleitstand TUI workbench for this patrol.
        #[arg(long)]
        tui: bool,
    },
    /// Present a stored Patrol, Investigation, or Audit JSON/JSONL report.
    Report {
        /// Path to stored JSON or JSONL report file.
        file: PathBuf,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Optional file path to write the rendered report.
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Target stakeholder perspective for Markdown output.
        #[arg(long, value_enum, default_value_t = AudienceArg::Technical)]
        audience: AudienceArg,
    },
    /// Launch Zwergenleitstand, the interactive Ratatui investigation workbench.
    Tui {
        /// Optional target HTTP or HTTPS URL to audit or investigate immediately.
        url: Option<String>,
        /// Optional path to a saved JSON report (`AuditReport`, `InvestigationReport`, or `PatrolReport`) to explore offline.
        #[arg(long)]
        report: Option<PathBuf>,
        /// Optional path to a JSONL audit history file for offline regression analysis.
        #[arg(long)]
        history: Option<PathBuf>,
        /// Optional default output path when saving reports from the workbench (`w`).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Initial diagnostic mode (`check`, `scan`, `investigate`, `patrol`).
        #[arg(short, long, value_enum, default_value_t = TuiModeArg::Check)]
        mode: TuiModeArg,
        /// Enable Level 2 headless Chromium collection (`BrowserZwerg` & `GestaltungsZwerg`).
        #[arg(long)]
        browser: bool,
        /// Enable Level 2 `axe-core` collection (`ZugänglichkeitsZwerg`).
        #[arg(long)]
        axe: bool,
        /// Enable Level 2 Lighthouse collection (`LeistungsZwerg`).
        #[arg(long)]
        lighthouse: bool,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Optional path to a TOML configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Force monochrome rendering (`NO_COLOR` mode).
        #[arg(long)]
        monochrome: bool,
        /// Force high-contrast rendering.
        #[arg(long)]
        high_contrast: bool,
        /// Force ASCII-only borders and indicators.
        #[arg(long)]
        ascii: bool,
        /// Directory for persistent patrol memory shared with `nzw patrol` (defaults to `.nzw/memory`).
        #[arg(long, default_value = netzzwergenwacht::patrol::memory::DEFAULT_MEMORY_DIR)]
        memory_dir: PathBuf,
        /// Directory for the application-wide evidence store written by reconnaissance crawls.
        #[arg(long, default_value = ".nzw/evidence")]
        evidence_dir: PathBuf,
        /// Page bound for reconnaissance crawls launched from the workbench.
        #[arg(long, default_value_t = 50)]
        max_pages: usize,
        /// Link-following depth bound for reconnaissance crawls.
        #[arg(long, default_value_t = 2)]
        max_depth: usize,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TuiModeArg {
    Check,
    Scan,
    Investigate,
    Patrol,
}

impl From<TuiModeArg> for DiagnosticRunMode {
    fn from(value: TuiModeArg) -> Self {
        match value {
            TuiModeArg::Check => Self::DeterministicCheck,
            TuiModeArg::Scan => Self::ReconnaissanceCrawl,
            TuiModeArg::Investigate => Self::AgenticInvestigation,
            TuiModeArg::Patrol => Self::AutonomousPatrol,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AudienceArg {
    Pm,
    Po,
    Cto,
    Technical,
}

impl From<AudienceArg> for netzzwergenwacht::investigation::RolePerspective {
    fn from(value: AudienceArg) -> Self {
        match value {
            AudienceArg::Pm => Self::ProjectManager,
            AudienceArg::Po => Self::ProductOwner,
            AudienceArg::Cto => Self::CtoEngineeringManager,
            AudienceArg::Technical => Self::TechnicalSpecialist,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
    Html,
    Sarif,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Print the effective configuration with credentials redacted.
    Show {
        /// Optional path to a TOML configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<FailOnSeverity> for Severity {
    fn from(value: FailOnSeverity) -> Self {
        match value {
            FailOnSeverity::Critical => Self::Critical,
            FailOnSeverity::High => Self::High,
            FailOnSeverity::Medium => Self::Medium,
            FailOnSeverity::Low => Self::Low,
            FailOnSeverity::Info => Self::Info,
        }
    }
}

#[derive(Debug, Serialize)]
struct TargetErrorEntry {
    raw_target: String,
    error: String,
}

#[derive(Debug, Serialize)]
struct BatchItem {
    report: AuditReport,
    policy: PolicyEvaluation,
}

#[derive(Debug, Serialize)]
struct BatchReport {
    total_targets: usize,
    completed: usize,
    failed_targets: usize,
    target_errors: Vec<TargetErrorEntry>,
    items: Vec<BatchItem>,
}

/// Rendered reconnaissance result, including where its evidence was retained.
#[derive(Debug, Serialize)]
struct ScanReport {
    run_id: String,
    application: String,
    seed_url: String,
    coverage: netzzwergenwacht::discovery::CrawlCoverage,
    resources: Vec<netzzwergenwacht::discovery::ResourceObservation>,
    systemic_issues: Vec<netzzwergenwacht::discovery::SystemicIssue>,
    quality_assessment: netzzwergenwacht::analysis::assessment::QualityAssessment,
    stored_at: Option<String>,
    store_error: Option<String>,
}

impl ScanReport {
    fn render_lines(&self) -> Vec<String> {
        let coverage = &self.coverage;
        let resources = &coverage.resources;
        let mut lines = vec![
            format!("Reconnaissance: {}", self.application),
            format!("  Run:                 {}", self.run_id),
            String::new(),
            "COVERAGE".to_owned(),
            format!("  Discovered URLs:     {}", coverage.discovered_urls),
            format!("  Fetched:             {}", coverage.fetched_urls),
            format!("  Analysed:            {}", coverage.analysed_urls),
            format!("  Failed:              {}", coverage.failed_urls),
            format!("  Skipped (budget):    {}", coverage.skipped_budget_urls),
            format!("  Cancelled:           {}", coverage.cancelled_urls),
            format!("  Robots blocked:      {}", coverage.robots_blocked_urls),
            format!("  Robots file:         {}", coverage.robots.label()),
            format!("  Queue rejections:    {}", coverage.queue_rejections),
            format!("  Duplicate offers:    {}", coverage.duplicate_offers),
            format!(
                "  Bounds:              {} pages, depth {}",
                coverage.max_pages, coverage.max_depth
            ),
            format!(
                "  Complete:            {}",
                if coverage.complete { "yes" } else { "no" }
            ),
            String::new(),
            "RESOURCES".to_owned(),
            format!("  Discovered:          {}", resources.discovered_resources),
            format!("  Fetched:             {}", resources.fetched_resources),
            format!("  Failed:              {}", resources.failed_resources),
            format!("  Skipped (budget):    {}", resources.skipped_resources),
            format!("  Truncated:           {}", resources.truncated_resources),
            format!("  External refused:    {}", resources.external_refused),
        ];
        let payload = netzzwergenwacht::report_html::summarise_resources(&self.resources);
        if payload.measured_count > 0 {
            lines.push(format!(
                "  Measured payload:    {} (JS: {}, CSS: {}, Img: {})",
                netzzwergenwacht::report_html::format_bytes(payload.total_bytes),
                netzzwergenwacht::report_html::format_bytes(payload.script_bytes),
                netzzwergenwacht::report_html::format_bytes(payload.stylesheet_bytes),
                netzzwergenwacht::report_html::format_bytes(payload.image_bytes),
            ));
        }
        for res in netzzwergenwacht::report_html::prioritise_resources(&self.resources)
            .into_iter()
            .take(3)
        {
            let detail = res.byte_len.map_or_else(
                || res.error.as_deref().unwrap_or("—").to_owned(),
                netzzwergenwacht::report_html::format_bytes,
            );
            lines.push(format!("    [{:?}] {} ({detail})", res.status, res.url));
        }
        lines.push(String::new());
        lines.push("DIAGNOSTICS".to_owned());
        lines.push(format!(
            "  Systemic issues:     {}",
            self.systemic_issues.len()
        ));
        for issue in self.systemic_issues.iter().take(10) {
            lines.push(format!(
                "    {} on {} page(s)",
                issue.rule_id.0,
                issue.affected_urls.len()
            ));
        }
        lines.push(String::new());
        lines.push(format!(
            "QUALITY ASSESSMENT: {}",
            self.quality_assessment.overall_verdict.badge()
        ));
        for dom in &self.quality_assessment.domains {
            if dom.verdict != netzzwergenwacht::analysis::assessment::DomainVerdict::NotApplicable {
                lines.push(format!(
                    "  {:<20} {:<6} {}",
                    dom.domain.label(),
                    dom.verdict.badge(),
                    dom.rationale
                ));
            }
        }
        lines.push(String::new());
        match (&self.stored_at, &self.store_error) {
            (Some(path), _) => lines.push(format!("  Evidence retained:   {path}")),
            (None, Some(error)) => lines.push(format!("  Evidence NOT stored: {error}")),
            (None, None) => lines.push("  Evidence NOT stored: no store was opened".to_owned()),
        }
        lines
    }
}

/// Builds a run identity from the seed origin and the current second.
fn scan_run_id(target: &AuditTarget) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    target.as_str().hash(&mut hasher);
    format!("scan-{}-{:016x}", unix_now_secs(), hasher.finish())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();

    match cli.command {
        Command::Config { action } => match action {
            ConfigAction::Show { config, format } => {
                let discovery = config::ConfigDiscovery {
                    explicit: config,
                    ..config::ConfigDiscovery::from_process()
                };
                match discovery.resolve() {
                    Ok(loaded) => {
                        let effective = loaded.config.effective(&loaded.source);
                        match format {
                            OutputFormat::Json => match serde_json::to_string_pretty(&effective) {
                                Ok(json) => println!("{json}"),
                                Err(err) => {
                                    eprintln!("failed to render configuration: {err}");
                                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                                }
                            },
                            OutputFormat::Text | OutputFormat::Markdown => {
                                for line in effective.render_lines() {
                                    println!("{line}");
                                }
                            }
                            OutputFormat::Html => {
                                println!(
                                    "{}",
                                    netzzwergenwacht::report_html::wrap_preformatted_html(
                                        "Effective Configuration",
                                        &effective.render_lines().join("\n"),
                                    )
                                );
                            }
                            OutputFormat::Sarif => {
                                println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
                            }
                        }
                        ExitCode::from(EXIT_OK)
                    }
                    Err(err) => {
                        eprintln!("{err}");
                        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
                    }
                }
            }
        },
        Command::Doctor { config, format } => {
            let (resolved, source) = doctor::resolve_config(config);
            let report = doctor::diagnose(&resolved, source.as_deref());
            match format {
                OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                    Ok(json) => println!("{json}"),
                    Err(err) => {
                        eprintln!("doctor error: {err}");
                        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                    }
                },
                OutputFormat::Text | OutputFormat::Markdown => {
                    for line in report.render_lines() {
                        println!("{line}");
                    }
                }
                OutputFormat::Html => {
                    println!(
                        "{}",
                        netzzwergenwacht::report_html::wrap_preformatted_html(
                            "Doctor Diagnostics",
                            &report.render_lines().join("\n"),
                        )
                    );
                }
                OutputFormat::Sarif => {
                    println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
                }
            }
            if report.is_ready() {
                ExitCode::from(EXIT_OK)
            } else {
                ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
            }
        }
        Command::Scan {
            url,
            config,
            format,
            allow_private,
            max_pages,
            max_depth,
            audit_timeout_secs,
            browser_sample,
            output,
            evidence_dir,
        } => {
            let discovery = config::ConfigDiscovery {
                explicit: config,
                ..config::ConfigDiscovery::from_process()
            };
            let loaded = match discovery.resolve() {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                }
            };
            let policy = target_policy(allow_private);
            let target = match AuditTarget::parse(&url, policy) {
                Ok(target) => target,
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                }
            };
            let exec_budget = budget_with_overrides(&loaded.config, None, audit_timeout_secs, None);
            let crawl_budget = netzzwergenwacht::discovery::CrawlBudget {
                max_pages: max_pages.max(1),
                max_depth,
                max_duration: exec_budget.audit_timeout,
            };
            let mut summary = netzzwergenwacht::discovery::crawl_and_cluster(
                target.clone(),
                crawl_budget,
                exec_budget,
                policy,
            )
            .await;
            if browser_sample > 0 {
                netzzwergenwacht::discovery::sample_browser_on_crawl(
                    &mut summary,
                    browser_sample,
                    exec_budget,
                    policy,
                )
                .await;
            }
            let quality_assessment =
                netzzwergenwacht::analysis::assessment::assess_crawl_summary(&summary);

            let run_id = scan_run_id(&target);
            let directory = evidence_dir.unwrap_or_else(|| PathBuf::from(".nzw/evidence"));
            let store_path = directory.join("evidence.db");
            let record = netzzwergenwacht::evidence_store::CrawlRecord {
                run_id: &run_id,
                application: target.as_str(),
                summary: &summary,
                recorded_at_unix_secs: unix_now_secs(),
            };
            let (stored_at, store_error) =
                match netzzwergenwacht::evidence_store::EvidenceStore::open(&store_path).await {
                    Ok(store) => match store.record_crawl(record).await {
                        Ok(()) => (Some(store_path.display().to_string()), None),
                        Err(err) => (None, Some(err.to_string())),
                    },
                    Err(err) => (None, Some(err.to_string())),
                };

            let report = ScanReport {
                run_id: run_id.clone(),
                application: target.as_str().to_owned(),
                seed_url: summary.seed.as_str().to_owned(),
                coverage: summary.coverage,
                resources: summary.resources.clone(),
                systemic_issues: summary.systemic_issues.clone(),
                quality_assessment,
                stored_at,
                store_error,
            };
            match format {
                OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                    Ok(json) => {
                        if let Err(code) = write_output_or_stdout(output.as_deref(), &json) {
                            return code;
                        }
                    }
                    Err(err) => {
                        eprintln!("scan error: {err}");
                        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                    }
                },
                OutputFormat::Text | OutputFormat::Markdown => {
                    let rendered = report.render_lines().join("\n");
                    if let Err(code) = write_output_or_stdout(output.as_deref(), &rendered) {
                        return code;
                    }
                }
                OutputFormat::Html => {
                    let html = netzzwergenwacht::report_html::render_scan_html(
                        &netzzwergenwacht::report_html::ScanHtmlInput {
                            run_id: &report.run_id,
                            application: &report.application,
                            seed_url: &report.seed_url,
                            coverage: &report.coverage,
                            resources: &report.resources,
                            systemic_issues: &report.systemic_issues,
                            quality_assessment: &report.quality_assessment,
                            stored_at: report.stored_at.as_deref(),
                        },
                    );
                    if let Err(code) = write_output_or_stdout(output.as_deref(), &html) {
                        return code;
                    }
                }
                OutputFormat::Sarif => {
                    let sarif = netzzwergenwacht::report_sarif::render_scan_sarif(
                        &report.seed_url,
                        &report.systemic_issues,
                    );
                    if let Err(code) = write_output_or_stdout(output.as_deref(), &sarif) {
                        return code;
                    }
                }
            }
            if report.store_error.is_some() {
                ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
            } else {
                ExitCode::from(EXIT_OK)
            }
        }
        Command::Validate { url, allow_private } => {
            let policy = target_policy(allow_private);
            match AuditTarget::parse(&url, policy) {
                Ok(target) => {
                    println!(
                        "valid target: {} (host: {})",
                        target.as_str(),
                        target.host()
                    );
                    ExitCode::from(EXIT_OK)
                }
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
                }
            }
        }
        Command::Check {
            url,
            config: config_path,
            profile: profile_path,
            format,
            output,
            allow_private,
            timeout_secs,
            audit_timeout_secs,
            max_redirects,
            fail_on,
            history,
            lighthouse,
            browser,
            axe,
            ai,
            tui: use_tui,
        } => {
            if use_tui {
                let Some(loaded) = load_tui_config(config_path.clone()) else {
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                };
                let options = TuiStartupOptions {
                    target: Some(url),
                    config: Some(loaded.config.clone()),
                    config_source: Some(loaded.source.label()),
                    budget: loaded.config.execution_budget(),
                    policy: if allow_private {
                        TargetPolicy::AllowPrivate
                    } else {
                        loaded.config.target_policy()
                    },
                    mode: DiagnosticRunMode::DeterministicCheck,
                    enable_browser: browser,
                    enable_axe: axe,
                    enable_lighthouse: lighthouse,
                    history_path: history,
                    ..TuiStartupOptions::default()
                };
                return run_tui_cmd(options).await;
            }
            run_check(
                &url,
                config_path.as_deref(),
                profile_path.as_deref(),
                format,
                output.as_deref(),
                allow_private,
                timeout_secs,
                audit_timeout_secs,
                max_redirects,
                fail_on,
                history.as_deref(),
                AdapterOptions {
                    lighthouse,
                    browser,
                    axe,
                },
                ai,
            )
            .await
        }
        Command::Batch {
            targets_file,
            config: config_path,
            format,
            allow_private,
            max_concurrency,
            fail_on,
            history,
        } => {
            run_batch(
                &targets_file,
                config_path.as_deref(),
                format,
                allow_private,
                max_concurrency,
                fail_on,
                history.as_deref(),
            )
            .await
        }
        Command::Diff {
            baseline,
            current,
            format,
            output,
        } => run_diff(&baseline, &current, format, output.as_deref()),
        Command::Investigate {
            url,
            objective,
            allow_private,
            format,
            audience,
            events,
            tui: use_tui,
            config,
        } => {
            if use_tui {
                let Some(loaded) = load_tui_config(config) else {
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                };
                let options = TuiStartupOptions {
                    target: Some(url),
                    config: Some(loaded.config.clone()),
                    config_source: Some(loaded.source.label()),
                    budget: loaded.config.execution_budget(),
                    policy: if allow_private {
                        TargetPolicy::AllowPrivate
                    } else {
                        loaded.config.target_policy()
                    },
                    mode: DiagnosticRunMode::AgenticInvestigation,
                    objective,
                    ..TuiStartupOptions::default()
                };
                return run_tui_cmd(options).await;
            }
            run_investigate(&url, objective, allow_private, format, audience, events).await
        }
        Command::Verify {
            baseline,
            url,
            allow_private,
            format,
            output,
        } => run_verify(&baseline, &url, allow_private, format, output.as_deref()).await,
        Command::Patrol {
            url,
            config: config_path,
            targets,
            browser,
            memory_dir,
            max_pages,
            allow_private,
            format,
            audience,
            tui: use_tui,
        } => {
            if use_tui {
                let options = TuiStartupOptions {
                    target: url,
                    mode: DiagnosticRunMode::AutonomousPatrol,
                    enable_browser: browser,
                    policy: target_policy(allow_private),
                    ..TuiStartupOptions::default()
                };
                return run_tui_cmd(options).await;
            }
            Box::pin(run_patrol_cmd(
                url.as_deref(),
                config_path.as_deref(),
                targets.as_deref(),
                browser,
                &memory_dir,
                max_pages,
                allow_private,
                format,
                audience,
            ))
            .await
        }
        Command::Report {
            file,
            format,
            output,
            audience,
        } => run_report_cmd(&file, format, output.as_deref(), audience),
        Command::Tui {
            url,
            report,
            history,
            output,
            mode,
            browser,
            axe,
            lighthouse,
            allow_private,
            config,
            monochrome,
            high_contrast,
            ascii,
            memory_dir,
            evidence_dir,
            max_pages,
            max_depth,
        } => {
            let discovery = config::ConfigDiscovery {
                explicit: config,
                ..config::ConfigDiscovery::from_process()
            };
            let loaded = match discovery.resolve() {
                Ok(loaded) => loaded,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                }
            };
            let configured_policy = loaded.config.target_policy();
            let budget = loaded.config.execution_budget();
            let config = loaded.config;
            let loaded_source = loaded.source.label();
            let theme_mode = if monochrome {
                Some(ThemeMode::Monochrome)
            } else if high_contrast {
                Some(ThemeMode::HighContrast)
            } else {
                None
            };
            let options = TuiStartupOptions {
                target: url,
                mode: mode.into(),
                enable_browser: browser,
                enable_axe: axe,
                enable_lighthouse: lighthouse,
                report_path: report,
                history_path: history,
                output_path: output,
                policy: if allow_private {
                    TargetPolicy::AllowPrivate
                } else {
                    configured_policy
                },
                budget,
                memory_dir,
                evidence_dir,
                max_pages,
                max_depth,
                config: Some(config),
                config_source: Some(loaded_source),
                theme_mode,
                ascii_only: ascii,
                ..TuiStartupOptions::default()
            };
            run_tui_cmd(options).await
        }
    }
}

/// Resolves the configuration for a workbench launch, reporting a hard error
/// instead of silently falling back to defaults.
fn load_tui_config(explicit: Option<PathBuf>) -> Option<config::LoadedConfig> {
    let discovery = config::ConfigDiscovery {
        explicit,
        ..config::ConfigDiscovery::from_process()
    };
    match discovery.resolve() {
        Ok(loaded) => Some(loaded),
        Err(err) => {
            eprintln!("configuration error: {err}");
            None
        }
    }
}

async fn run_tui_cmd(options: TuiStartupOptions) -> ExitCode {
    if let Err(err) = Box::pin(tui::run_tui(options)).await {
        eprintln!("tui error: {err}");
        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
    }
    ExitCode::from(EXIT_OK)
}

fn render_stored_patrol(
    patrol: &netzzwergenwacht::patrol::PatrolReport,
    raw: &str,
    format: OutputFormat,
    role: netzzwergenwacht::investigation::RolePerspective,
) {
    match format {
        OutputFormat::Json => println!("{raw}"),
        OutputFormat::Markdown => {
            println!(
                "{}",
                netzzwergenwacht::patrol::render_patrol_markdown(patrol, role)
            );
        }
        OutputFormat::Text => {
            println!(
                "NETZZWERGENWACHT — Stored Patrol #{} ({MOTTO})",
                patrol.patrol_number
            );
            println!("Target: {}", patrol.target.as_str());
            println!("Summary: {}", patrol.executive_summary);
            println!("Coverage: {}", patrol.coverage_summary);
        }
        OutputFormat::Html => {
            let md = netzzwergenwacht::patrol::render_patrol_markdown(patrol, role);
            println!(
                "{}",
                netzzwergenwacht::report_html::wrap_preformatted_html(
                    &format!("Stored Patrol #{}", patrol.patrol_number),
                    &md,
                )
            );
        }
        OutputFormat::Sarif => {
            println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
        }
    }
}

fn run_report_cmd(
    file: &Path,
    format: OutputFormat,
    output: Option<&Path>,
    audience: AudienceArg,
) -> ExitCode {
    let raw = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("failed to read {}: {err}", file.display());
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };
    let role: netzzwergenwacht::investigation::RolePerspective = audience.into();

    if let Ok(patrol) = serde_json::from_str::<netzzwergenwacht::patrol::PatrolReport>(&raw) {
        render_stored_patrol(&patrol, &raw, format, role);
        return ExitCode::from(EXIT_OK);
    }

    if let Ok(inv) =
        serde_json::from_str::<netzzwergenwacht::investigation::InvestigationReport>(&raw)
    {
        match format {
            OutputFormat::Json => println!("{raw}"),
            OutputFormat::Markdown => {
                println!(
                    "{}",
                    netzzwergenwacht::investigation::reporting::render_markdown_report(&inv)
                );
            }
            OutputFormat::Text => print_investigation_text(&inv, false),
            OutputFormat::Html => {
                let md = netzzwergenwacht::investigation::reporting::render_markdown_report(&inv);
                println!(
                    "{}",
                    netzzwergenwacht::report_html::wrap_preformatted_html(
                        "Investigation Report",
                        &md,
                    )
                );
            }
            OutputFormat::Sarif => {
                println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
            }
        }
        return ExitCode::from(EXIT_OK);
    }

    match persistence::load_latest_or_single(file) {
        Ok(audit) => {
            let eval = config::evaluate_policy(&audit, &PolicyConfig::default());
            match format {
                OutputFormat::Json => {
                    if let Ok(json) = serde_json::to_string_pretty(&audit) {
                        println!("{json}");
                    }
                }
                OutputFormat::Text | OutputFormat::Markdown => {
                    let assessment =
                        netzzwergenwacht::analysis::assessment::assess_audit_report(&audit);
                    print_text_report(&audit, &eval, &assessment);
                }
                OutputFormat::Html => {
                    let assessment =
                        netzzwergenwacht::analysis::assessment::assess_audit_report(&audit);
                    let html =
                        netzzwergenwacht::report_html::render_audit_html(&audit, &assessment);
                    if let Err(code) = write_output_or_stdout(output, &html) {
                        return code;
                    }
                }
                OutputFormat::Sarif => {
                    let sarif = netzzwergenwacht::report_sarif::render_audit_sarif(&audit);
                    if let Err(code) = write_output_or_stdout(output, &sarif) {
                        return code;
                    }
                }
            }
            ExitCode::from(EXIT_OK)
        }
        Err(err) => {
            eprintln!(
                "failed to parse {} as Patrol, Investigation, or Audit report: {err}",
                file.display()
            );
            ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_patrol_cmd(
    url: Option<&str>,
    config_path: Option<&Path>,
    targets_path: Option<&Path>,
    enable_level2: bool,
    memory_dir: &Path,
    max_pages: usize,
    allow_private: bool,
    format: OutputFormat,
    audience: AudienceArg,
) -> ExitCode {
    let app_cfg = match load_optional_config(config_path) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let router = std::sync::Arc::new(
        netzzwergenwacht::intelligence::CachedProviderRouter::from_routing(&app_cfg.models),
    );
    let exec_budget = app_cfg.execution_budget();
    let backend: std::sync::Arc<dyn netzzwergenwacht::investigation::DiagnosticBackend> =
        std::sync::Arc::new(netzzwergenwacht::investigation::LiveDiagnosticBackend);
    let patrol_budget = netzzwergenwacht::patrol::PatrolBudget {
        max_pages: max_pages.max(1),
        enable_level2,
        ..netzzwergenwacht::patrol::PatrolBudget::default()
    };

    if let Some(cfg_path) = targets_path {
        let cfg =
            match netzzwergenwacht::patrol::portfolio::PortfolioConfig::from_toml_file(cfg_path) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                }
            };
        let router_arc: std::sync::Arc<dyn netzzwergenwacht::intelligence::ProviderRouter> = router;
        let portfolio = netzzwergenwacht::patrol::portfolio::run_portfolio_patrol(
            &cfg,
            allow_private || app_cfg.policy.allow_private,
            exec_budget,
            patrol_budget,
            Some(memory_dir),
            Some(router_arc),
            backend,
        )
        .await;
        return render_portfolio_patrol(&portfolio, format);
    }

    let Some(raw_url) = url else {
        eprintln!("either <URL> or --targets <FILE> must be provided");
        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
    };
    let policy = target_policy(allow_private || app_cfg.policy.allow_private);
    let target = match AuditTarget::parse(raw_url, policy) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("invalid target: {err}");
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };
    let report = Box::pin(netzzwergenwacht::patrol::run_patrol_with_router(
        target,
        policy,
        exec_budget,
        patrol_budget,
        Some(memory_dir),
        Some(router.as_ref()),
        backend,
    ))
    .await;

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialise patrol report: {err}");
                return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
            }
        },
        OutputFormat::Markdown => {
            let role = audience.into();
            println!(
                "{}",
                netzzwergenwacht::patrol::render_patrol_markdown(&report, role)
            );
        }
        OutputFormat::Text => {
            println!(
                "NETZZWERGENWACHT — Autonomous Patrol #{} ({MOTTO})",
                report.patrol_number
            );
            println!("Target: {}", report.target.as_str());
            println!("Summary: {}", report.executive_summary);
            println!("Coverage: {}", report.coverage_summary);
            if !report.anomalies.is_empty() {
                println!("\nAnomalies ({}):", report.anomalies.len());
                for a in &report.anomalies {
                    println!("  - [{}] ({:?}) {}", a.id, a.severity, a.summary);
                }
            }
        }
        OutputFormat::Html => {
            let md = netzzwergenwacht::patrol::render_patrol_markdown(&report, audience.into());
            println!(
                "{}",
                netzzwergenwacht::report_html::wrap_preformatted_html(
                    &format!("Autonomous Patrol #{}", report.patrol_number),
                    &md,
                )
            );
        }
        OutputFormat::Sarif => {
            println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
        }
    }

    if !report.execution_succeeded {
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    } else if report.is_quiet_patrol {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_FINDINGS)
    }
}

fn render_portfolio_patrol(
    portfolio: &netzzwergenwacht::patrol::portfolio::PortfolioPatrolReport,
    format: OutputFormat,
) -> ExitCode {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(portfolio) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialise portfolio report: {err}");
                return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
            }
        },
        OutputFormat::Text | OutputFormat::Markdown => {
            println!(
                "NETZZWERGENWACHT — Portfolio Patrol ({MOTTO}) | Apps: {} | Succeeded: {} | Quiet: {} | Escalated: {}",
                portfolio.total_applications,
                portfolio.succeeded_count,
                portfolio.quiet_count,
                portfolio.escalated_count
            );
            for o in &portfolio.outcomes {
                if let Some(r) = &o.report {
                    println!(
                        "  - [{}] ({:?}) {}",
                        o.id, o.criticality, r.executive_summary
                    );
                } else if let Some(err) = &o.error {
                    println!("  - [{}] ({:?}) ERROR: {err}", o.id, o.criticality);
                }
            }
        }
        OutputFormat::Html => {
            let summary = format!(
                "Apps: {} | Succeeded: {} | Quiet: {} | Escalated: {}",
                portfolio.total_applications,
                portfolio.succeeded_count,
                portfolio.quiet_count,
                portfolio.escalated_count
            );
            println!(
                "{}",
                netzzwergenwacht::report_html::wrap_preformatted_html("Portfolio Patrol", &summary)
            );
        }
        OutputFormat::Sarif => {
            println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
        }
    }
    if portfolio.succeeded_count < portfolio.total_applications {
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    } else if portfolio.quiet_count == portfolio.total_applications {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_FINDINGS)
    }
}

async fn run_verify(
    baseline_path: &Path,
    url: &str,
    allow_private: bool,
    format: OutputFormat,
    output: Option<&Path>,
) -> ExitCode {
    let policy = target_policy(allow_private);
    let target = match AuditTarget::parse(url, policy) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("invalid target: {err}");
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };
    let baseline = match persistence::load_latest_or_single(baseline_path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("failed to load baseline {}: {err}", baseline_path.display());
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };

    let budget = netzzwergenwacht::domain::ExecutionBudget::default();
    let snap = collection::collect_http(&target, &budget, policy).await;
    let current = analysis::run_all(&snap);
    let diff = persistence::diff_reports(&baseline, &current);

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&diff) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialise verification report: {err}");
                return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
            }
        },
        OutputFormat::Text => {
            println!("NETZZWERGENWACHT — Remediation Verification ({MOTTO})");
            println!(
                "Target: {} | Resolved: {} | Persisting: {} | Unverified: {} | New: {}",
                diff.current_target,
                diff.summary.resolved_count,
                diff.summary.persisting_count,
                diff.summary.unverified_count,
                diff.summary.new_count
            );
        }
        OutputFormat::Markdown => {
            println!("# NetzZwergenWacht Verification Report\n");
            println!("- **Target**: {}", diff.current_target);
            println!("- **Resolved**: {}", diff.summary.resolved_count);
            println!("- **Persisting**: {}", diff.summary.persisting_count);
            println!("- **Unverified**: {}", diff.summary.unverified_count);
            println!("- **New**: {}", diff.summary.new_count);
        }
        OutputFormat::Html => {
            let html = netzzwergenwacht::report_html::render_diff_html(&diff);
            if let Err(code) = write_output_or_stdout(output, &html) {
                return code;
            }
        }
        OutputFormat::Sarif => {
            let sarif = netzzwergenwacht::report_sarif::render_diff_sarif(&diff);
            if let Err(code) = write_output_or_stdout(output, &sarif) {
                return code;
            }
        }
    }

    if matches!(current.http, CollectorOutcome::Failed { .. }) {
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    } else if diff.summary.persisting_count > 0
        || diff.summary.new_count > 0
        || diff.summary.unverified_count > 0
    {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

async fn run_investigate(
    url: &str,
    objective: String,
    allow_private: bool,
    format: OutputFormat,
    audience: AudienceArg,
    show_events: bool,
) -> ExitCode {
    let policy = target_policy(allow_private);
    let target = match AuditTarget::parse(url, policy) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("invalid target: {err}");
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };
    let llm = match netzzwergenwacht::intelligence::OpenAiCompatibleProvider::from_env() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("KommandantZwerg unavailable: {err}");
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };

    let backend = std::sync::Arc::new(netzzwergenwacht::investigation::LiveDiagnosticBackend);
    let report = netzzwergenwacht::investigation::run_investigation(
        target,
        objective,
        policy,
        netzzwergenwacht::investigation::InvestigationBudget::default(),
        backend,
        &llm,
    )
    .await;

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(err) => {
                eprintln!("failed to serialise investigation report: {err}");
                return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
            }
        },
        OutputFormat::Text | OutputFormat::Markdown => {
            if matches!(format, OutputFormat::Markdown) {
                println!(
                    "{}",
                    netzzwergenwacht::investigation::render_role_perspective_markdown(
                        &report,
                        audience.into()
                    )
                );
            } else {
                print_investigation_text(&report, show_events);
            }
        }
        OutputFormat::Html => {
            let md = netzzwergenwacht::investigation::render_role_perspective_markdown(
                &report,
                audience.into(),
            );
            println!(
                "{}",
                netzzwergenwacht::report_html::wrap_preformatted_html("Investigation Report", &md)
            );
        }
        OutputFormat::Sarif => {
            println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
        }
    }
    match report.state {
        netzzwergenwacht::investigation::InvestigationState::Failed
        | netzzwergenwacht::investigation::InvestigationState::Cancelled => {
            ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
        }
        netzzwergenwacht::investigation::InvestigationState::PartiallyCompleted
        | netzzwergenwacht::investigation::InvestigationState::BudgetExhausted => {
            ExitCode::from(EXIT_FINDINGS)
        }
        _ => match report.release_readiness.state {
            netzzwergenwacht::investigation::ReleaseReadinessState::NoBlockingFindingsWithinScope => {
                ExitCode::from(EXIT_OK)
            }
            _ => ExitCode::from(EXIT_FINDINGS),
        },
    }
}

fn print_investigation_text(
    report: &netzzwergenwacht::investigation::InvestigationReport,
    show_events: bool,
) {
    println!(
        "NETZZWERGENWACHT — KommandantZwerg Investigation [{}] ({MOTTO})",
        report.id.0
    );
    println!(
        "Target: {} | State: {:?} | Readiness: {:?} | Tools: {}/{} | LLM turns: {}/{}",
        report.target.as_str(),
        report.state,
        report.release_readiness.state,
        report.ledger.tool_calls_used,
        report.ledger.budget.max_tool_calls,
        report.ledger.llm_turns_used,
        report.ledger.budget.max_llm_turns,
    );
    println!("\nExecutive Brief:");
    println!("  Assessment: {}", report.executive_brief.assessment);
    println!("  Coverage: {}", report.executive_brief.coverage_summary);
    println!("  Confidence: {}", report.executive_brief.confidence_note);
    for hyp in &report.hypotheses {
        println!(
            "\nHypothesis [{}] ({:?}): {} -> tool `{}`",
            hyp.id, hyp.status, hyp.proposed_explanation, hyp.requested_tool
        );
        if let Some(summary) = &hyp.evaluation_summary {
            println!("  Evaluation: {summary}");
        }
    }
    if !report.remediation_tasks.is_empty() {
        println!("\nBacklog Remediation Tasks:");
        for task in &report.remediation_tasks {
            println!("  - [{}] ({:?}) {}", task.id, task.priority, task.title);
        }
    }
    if show_events && !report.events.is_empty() {
        println!("\nExecution Events:");
        for ev in &report.events {
            println!("  - {ev:?}");
        }
    }
    println!("\nConclusion: {}", report.conclusion);
}

#[derive(Debug, Clone, Copy)]
struct AdapterOptions {
    lighthouse: bool,
    browser: bool,
    axe: bool,
}

fn remaining_audit_budget(started: std::time::Instant, total: Duration) -> Option<Duration> {
    let rem = total.saturating_sub(started.elapsed());
    if rem.is_zero() { None } else { Some(rem) }
}

/// Applies CLI budget overrides to the configured execution budget.
fn budget_with_overrides(
    app_cfg: &AppConfig,
    timeout_secs: Option<u64>,
    audit_timeout_secs: Option<u64>,
    max_redirects: Option<usize>,
) -> netzzwergenwacht::domain::ExecutionBudget {
    let mut budget = app_cfg.execution_budget();
    if let Some(secs) = timeout_secs {
        budget.http_timeout = Duration::from_secs(secs.max(1));
    }
    if let Some(secs) = audit_timeout_secs {
        budget.audit_timeout = Duration::from_secs(secs.max(1));
    }
    if let Some(hops) = max_redirects {
        budget.max_redirects = hops;
    }
    budget
}

/// Starts the audit clock and collects Level 1 evidence with the configured CAA resolver.
async fn collect_level1(
    target: &AuditTarget,
    budget: &netzzwergenwacht::domain::ExecutionBudget,
    policy: TargetPolicy,
    caa_doh_endpoint: Option<&str>,
) -> (
    std::time::Instant,
    netzzwergenwacht::domain::EvidenceSnapshot,
) {
    let started = std::time::Instant::now();
    let snapshot =
        collection::collect_http_with_caa_endpoint(target, budget, policy, caa_doh_endpoint).await;
    (started, snapshot)
}

#[allow(clippy::too_many_arguments)]
async fn run_check(
    url: &str,
    config_path: Option<&Path>,
    profile_path: Option<&Path>,
    format: OutputFormat,
    output: Option<&Path>,
    allow_private: bool,
    timeout_secs: Option<u64>,
    audit_timeout_secs: Option<u64>,
    max_redirects: Option<usize>,
    fail_on: Option<FailOnSeverity>,
    history: Option<&Path>,
    adapters: AdapterOptions,
    ai: bool,
) -> ExitCode {
    let app_cfg = match load_optional_config(config_path) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let quality_profile = match load_optional_profile(profile_path) {
        Ok(prof) => prof,
        Err(code) => return code,
    };
    let policy_cfg = merge_policy(&app_cfg.policy, allow_private, fail_on);
    let target_pol = if policy_cfg.allow_private {
        TargetPolicy::AllowPrivate
    } else {
        TargetPolicy::PublicOnly
    };
    let target = match AuditTarget::parse(url, target_pol) {
        Ok(target) => target,
        Err(err) => {
            eprintln!("invalid target: {err}");
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };

    let budget = budget_with_overrides(&app_cfg, timeout_secs, audit_timeout_secs, max_redirects);

    let (audit_started, mut snapshot) = collect_level1(
        &target,
        &budget,
        target_pol,
        app_cfg.dns.caa_doh_endpoint.as_deref(),
    )
    .await;
    if adapters.lighthouse {
        snapshot.lighthouse = match remaining_audit_budget(audit_started, budget.audit_timeout) {
            Some(rem) => {
                netzzwergenwacht::adapters::lighthouse::run_lighthouse_with_policy(
                    &target, rem, target_pol,
                )
                .await
            }
            None => CollectorOutcome::Skipped {
                reason: "shared audit_timeout budget exhausted".to_owned(),
            },
        };
    }
    if adapters.browser {
        snapshot.browser = match remaining_audit_budget(audit_started, budget.audit_timeout) {
            Some(rem) => {
                netzzwergenwacht::adapters::browser::run_browser_with_policy(
                    &target, rem, target_pol,
                )
                .await
            }
            None => CollectorOutcome::Skipped {
                reason: "shared audit_timeout budget exhausted".to_owned(),
            },
        };
    }
    if adapters.axe {
        snapshot.axe = match remaining_audit_budget(audit_started, budget.audit_timeout) {
            Some(rem) => netzzwergenwacht::adapters::axe::run_axe(&target, rem).await,
            None => CollectorOutcome::Skipped {
                reason: "shared audit_timeout budget exhausted".to_owned(),
            },
        };
    }
    collection::hydrate_browser_tls_and_caa(&mut snapshot);
    let mut report = analysis::run_all(&snapshot);

    if let Some(history_path) = history
        && let Err(code) = persist_check_history(history_path, &report).await
    {
        return code;
    }

    let eval = config::evaluate_policy(&report, &policy_cfg);
    let assessment =
        netzzwergenwacht::analysis::profile::assess_with_profile(&report, quality_profile.as_ref());
    let code = exit_code_for_report(&report, &eval);

    if ai {
        report.ai_synthesis = run_optional_ai(&report).await;
    }

    emit_audit_output(&report, &eval, &assessment, format, output, code)
}

fn write_output_or_stdout(output: Option<&Path>, content: &str) -> Result<(), ExitCode> {
    if let Some(path) = output {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && let Err(err) = std::fs::create_dir_all(parent)
        {
            eprintln!("failed to create directory {}: {err}", parent.display());
            return Err(ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR));
        }
        if let Err(err) = std::fs::write(path, content) {
            eprintln!("failed to write {}: {err}", path.display());
            return Err(ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR));
        }
        eprintln!("wrote report to {}", path.display());
        Ok(())
    } else {
        println!("{content}");
        Ok(())
    }
}

fn emit_audit_output(
    report: &analysis::AuditReport,
    eval: &config::PolicyEvaluation,
    assessment: &analysis::assessment::QualityAssessment,
    format: OutputFormat,
    output: Option<&Path>,
    code: ExitCode,
) -> ExitCode {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(report) {
            Ok(json) => match write_output_or_stdout(output, &json) {
                Ok(()) => code,
                Err(err_code) => err_code,
            },
            Err(err) => {
                eprintln!("failed to serialise JSON report: {err}");
                ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
            }
        },
        OutputFormat::Text | OutputFormat::Markdown => {
            print_text_report(report, eval, assessment);
            if let Some(syn) = &report.ai_synthesis {
                print_ai_synthesis(syn);
            }
            code
        }
        OutputFormat::Html => {
            let html = netzzwergenwacht::report_html::render_audit_html(report, assessment);
            match write_output_or_stdout(output, &html) {
                Ok(()) => code,
                Err(err_code) => err_code,
            }
        }
        OutputFormat::Sarif => {
            let sarif = netzzwergenwacht::report_sarif::render_audit_sarif(report);
            match write_output_or_stdout(output, &sarif) {
                Ok(()) => code,
                Err(err_code) => err_code,
            }
        }
    }
}

fn load_optional_profile(
    profile_path: Option<&Path>,
) -> Result<Option<netzzwergenwacht::analysis::profile::ApplicationQualityProfile>, ExitCode> {
    let Some(path) = profile_path else {
        return Ok(None);
    };
    netzzwergenwacht::analysis::profile::ApplicationQualityProfile::from_path(path)
        .map(Some)
        .map_err(|err| {
            eprintln!("invalid quality profile {}: {err}", path.display());
            ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
        })
}

async fn persist_check_history(
    history_path: &Path,
    report: &analysis::AuditReport,
) -> Result<(), ExitCode> {
    if let Err(err) = persistence::append_report(history_path, report) {
        eprintln!(
            "failed to append audit history to {}: {err}",
            history_path.display()
        );
        return Err(ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR));
    }
    let store_path = history_path.with_extension("evidence.db");
    if let Ok(store) = netzzwergenwacht::evidence_store::EvidenceStore::open(&store_path).await {
        let run_id = format!("check-{}", report.captured_at_unix_secs);
        let _ = store
            .record_audit_report(
                &run_id,
                report.target.as_str(),
                report,
                report.captured_at_unix_secs,
            )
            .await;
    }
    Ok(())
}

async fn run_optional_ai(
    report: &analysis::AuditReport,
) -> Option<netzzwergenwacht::intelligence::AiSynthesis> {
    let provider = match netzzwergenwacht::intelligence::OpenAiCompatibleProvider::from_env() {
        Ok(p) => p,
        Err(err) => {
            eprintln!("KommandantZwerg skipped: {err}");
            return None;
        }
    };
    let budget = netzzwergenwacht::intelligence::LlmBudget::default();
    match netzzwergenwacht::intelligence::synthesise(report, &provider, &budget).await {
        Ok(syn) => Some(syn),
        Err(err) => {
            eprintln!("KommandantZwerg failed: {err}");
            None
        }
    }
}

fn print_ai_synthesis(syn: &netzzwergenwacht::intelligence::AiSynthesis) {
    println!(
        "\nKommandantZwerg (advisory AI synthesis, model={}):",
        syn.model
    );
    println!("  {}", syn.executive_summary);
    for (idx, action) in syn.prioritised_actions.iter().enumerate() {
        println!("  {}. {action}", idx + 1);
    }
    for corr in &syn.correlations {
        println!("  - [AI] {}: {}", corr.title, corr.summary);
    }
}

fn load_optional_config(path: Option<&Path>) -> Result<AppConfig, ExitCode> {
    let Some(path) = path else {
        return Ok(AppConfig::default());
    };
    AppConfig::from_toml_file(path).map_err(|err| {
        eprintln!("failed to load config {}: {err}", path.display());
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    })
}

fn merge_policy(
    base: &PolicyConfig,
    allow_private_flag: bool,
    fail_on: Option<FailOnSeverity>,
) -> PolicyConfig {
    let mut merged = base.clone();
    if allow_private_flag {
        merged.allow_private = true;
    }
    if let Some(sev) = fail_on {
        merged.fail_on_severity = Some(sev.into());
    }
    merged
}

async fn run_batch(
    targets_file: &Path,
    config_path: Option<&Path>,
    format: OutputFormat,
    allow_private: bool,
    max_concurrency: Option<usize>,
    fail_on: Option<FailOnSeverity>,
    history: Option<&Path>,
) -> ExitCode {
    let app_cfg = match load_optional_config(config_path) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let policy_cfg = merge_policy(&app_cfg.policy, allow_private, fail_on);
    let target_pol = if policy_cfg.allow_private {
        TargetPolicy::AllowPrivate
    } else {
        TargetPolicy::PublicOnly
    };
    let mut budget = app_cfg.execution_budget();
    if let Some(conc) = max_concurrency {
        budget.max_concurrency = conc.max(1);
    }

    let (total_targets, valid_targets, target_errors) =
        match parse_targets_file(targets_file, target_pol) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };

    let snapshots = collection::collect_batch(valid_targets, &budget, target_pol).await;
    let mut items = Vec::with_capacity(snapshots.len());
    let mut any_collection_failed = !target_errors.is_empty();
    let mut any_policy_failed = false;

    for snap in &snapshots {
        let report = analysis::run_all(snap);
        if let Some(history_path) = history
            && let Err(err) = persistence::append_report(history_path, &report)
        {
            eprintln!(
                "failed to append audit history to {}: {err}",
                history_path.display()
            );
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
        if matches!(report.http, CollectorOutcome::Failed { .. }) {
            any_collection_failed = true;
        }
        let policy = config::evaluate_policy(&report, &policy_cfg);
        if !policy.passed {
            any_policy_failed = true;
        }
        items.push(BatchItem { report, policy });
    }

    let batch_report = BatchReport {
        total_targets,
        completed: items.len(),
        failed_targets: target_errors.len(),
        target_errors,
        items,
    };

    let code = if any_collection_failed {
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    } else if any_policy_failed {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::from(EXIT_OK)
    };

    render_batch_report(&batch_report, format, code)
}

fn parse_targets_file(
    targets_file: &Path,
    target_pol: TargetPolicy,
) -> Result<(usize, Vec<AuditTarget>, Vec<TargetErrorEntry>), ExitCode> {
    let raw_lines = fs::read_to_string(targets_file).map_err(|err| {
        eprintln!(
            "failed to read targets file {}: {err}",
            targets_file.display()
        );
        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
    })?;

    let mut valid_targets = Vec::new();
    let mut target_errors = Vec::new();
    let mut total_targets = 0usize;

    for line in raw_lines.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        total_targets += 1;
        match AuditTarget::parse(trimmed, target_pol) {
            Ok(t) => valid_targets.push(t),
            Err(err) => target_errors.push(TargetErrorEntry {
                raw_target: trimmed.to_owned(),
                error: err.to_string(),
            }),
        }
    }

    Ok((total_targets, valid_targets, target_errors))
}

fn render_batch_report(
    batch_report: &BatchReport,
    format: OutputFormat,
    code: ExitCode,
) -> ExitCode {
    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(batch_report) {
            Ok(json) => {
                println!("{json}");
                code
            }
            Err(err) => {
                eprintln!("failed to serialise batch JSON: {err}");
                ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
            }
        },
        OutputFormat::Text | OutputFormat::Markdown => {
            println!("NETZZWERGENWACHT BATCH AUDIT");
            println!(
                "Targets: {} total, {} completed, {} invalid\n",
                batch_report.total_targets, batch_report.completed, batch_report.failed_targets
            );
            for err in &batch_report.target_errors {
                println!("  [INVALID] {} -> {}", err.raw_target, err.error);
            }
            for item in &batch_report.items {
                let status = if item.policy.passed { "PASS" } else { "FAIL" };
                println!(
                    "  [{}] {} (C:{} H:{} M:{} L:{})",
                    status,
                    item.report.target.as_str(),
                    item.report.summary.critical_findings,
                    item.report.summary.high_findings,
                    item.report.summary.medium_findings,
                    item.report.summary.low_findings,
                );
            }
            code
        }
        OutputFormat::Html => {
            let mut lines = vec![format!(
                "Targets: {} total, {} completed, {} invalid",
                batch_report.total_targets, batch_report.completed, batch_report.failed_targets
            )];
            for item in &batch_report.items {
                let status = if item.policy.passed { "PASS" } else { "FAIL" };
                lines.push(format!(
                    "[{status}] {} (C:{} H:{} M:{} L:{})",
                    item.report.target.as_str(),
                    item.report.summary.critical_findings,
                    item.report.summary.high_findings,
                    item.report.summary.medium_findings,
                    item.report.summary.low_findings,
                ));
            }
            println!(
                "{}",
                netzzwergenwacht::report_html::wrap_preformatted_html(
                    "Batch Audit",
                    &lines.join("\n"),
                )
            );
            code
        }
        OutputFormat::Sarif => {
            println!("{}", netzzwergenwacht::report_sarif::empty_sarif());
            code
        }
    }
}

fn run_diff(
    baseline_path: &Path,
    current_path: &Path,
    format: OutputFormat,
    output: Option<&Path>,
) -> ExitCode {
    let baseline = match persistence::load_latest_or_single(baseline_path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("failed to load baseline {}: {err}", baseline_path.display());
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };
    let current = match persistence::load_latest_or_single(current_path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("failed to load current {}: {err}", current_path.display());
            return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
        }
    };

    let diff = persistence::diff_reports(&baseline, &current);
    let code = if diff.summary.new_count > 0 {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::from(EXIT_OK)
    };

    match format {
        OutputFormat::Json => match serde_json::to_string_pretty(&diff) {
            Ok(json) => {
                println!("{json}");
                code
            }
            Err(err) => {
                eprintln!("failed to serialise diff JSON: {err}");
                ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
            }
        },
        OutputFormat::Text | OutputFormat::Markdown => {
            print_diff_report(&diff);
            code
        }
        OutputFormat::Html => {
            let html = netzzwergenwacht::report_html::render_diff_html(&diff);
            match write_output_or_stdout(output, &html) {
                Ok(()) => code,
                Err(err_code) => err_code,
            }
        }
        OutputFormat::Sarif => {
            let sarif = netzzwergenwacht::report_sarif::render_diff_sarif(&diff);
            match write_output_or_stdout(output, &sarif) {
                Ok(()) => code,
                Err(err_code) => err_code,
            }
        }
    }
}

fn print_diff_report(diff: &RegressionReport) {
    println!("NETZZWERGENWACHT REGRESSION DIFF");
    println!("Baseline: {}", diff.baseline_target);
    println!("Current:  {}", diff.current_target);
    println!(
        "Summary:  {} new, {} persisting, {} resolved",
        diff.summary.new_count, diff.summary.persisting_count, diff.summary.resolved_count
    );

    if let Some(rendered) = &diff.rendered_text {
        match rendered {
            RenderedTextDiff::Compared {
                changed_count,
                unchanged_count,
                not_comparable_count,
                reasons,
                ..
            } => {
                println!(
                    "Rendered text: {changed_count} changed, {unchanged_count} unchanged, {not_comparable_count} not comparable"
                );
                for (reason, count) in reasons {
                    println!("  {reason}: {count}");
                }
            }
            RenderedTextDiff::Unavailable { reason } => {
                println!("Rendered text unavailable: {reason}");
            }
        }
    }

    if !diff.new_findings.is_empty() {
        println!("\nNew findings:");
        for f in &diff.new_findings {
            println!("  + [{:?}] ({}) {}", f.severity, f.rule_id.0, f.title);
        }
    }
    if !diff.resolved_findings.is_empty() {
        println!("\nResolved findings:");
        for f in &diff.resolved_findings {
            println!("  - [{:?}] ({}) {}", f.severity, f.rule_id.0, f.title);
        }
    }
}

const fn target_policy(allow_private: bool) -> TargetPolicy {
    if allow_private {
        TargetPolicy::AllowPrivate
    } else {
        TargetPolicy::PublicOnly
    }
}

fn exit_code_for_report(report: &AuditReport, eval: &PolicyEvaluation) -> ExitCode {
    if matches!(report.http, CollectorOutcome::Failed { .. }) {
        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
    }
    if eval.passed {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_FINDINGS)
    }
}

fn print_text_report(
    report: &AuditReport,
    eval: &PolicyEvaluation,
    assessment: &netzzwergenwacht::analysis::assessment::QualityAssessment,
) {
    println!("NETZZWERGENWACHT");
    println!("Die Zwergenbrigade\n");
    println!("Target: {}", report.target.as_str());

    if let CollectorOutcome::Failed { error } = &report.http {
        println!("Collection: FAILED ({error})");
    } else if let CollectorOutcome::Partial { warnings, .. } = &report.http {
        println!("Collection: PARTIAL ({})", warnings.join("; "));
    }

    println!();
    for analyser in &report.analysers {
        let profile = brigade::profile(analyser.dwarf_id);
        let (badge, headline) = summarise_analyser(report, analyser);
        println!("[{:<20}]  {:<4}  {}", profile.display_name, badge, headline);
    }

    println!(
        "\nChecks: {} passed, {} failed, {} skipped, {} unavailable",
        report.summary.passed_checks,
        report.summary.failed_checks,
        report.summary.skipped_checks,
        report.summary.unavailable_checks,
    );
    println!(
        "Findings: {} critical, {} high, {} medium, {} low, {} info",
        report.summary.critical_findings,
        report.summary.high_findings,
        report.summary.medium_findings,
        report.summary.low_findings,
        report.summary.info_findings,
    );
    if !eval.passed {
        println!("Policy Gate: FAILED ({})", eval.violations.join("; "));
    }
    println!("Quality Assessment: {}", assessment.overall_verdict.badge());
    for dom in &assessment.domains {
        if dom.verdict != netzzwergenwacht::analysis::assessment::DomainVerdict::NotApplicable {
            println!(
                "  - {:<20} {:<6} {}",
                dom.domain.label(),
                dom.verdict.badge(),
                dom.rationale
            );
        }
    }

    for analyser in &report.analysers {
        if analyser.findings.is_empty() {
            continue;
        }
        let profile = brigade::profile(analyser.dwarf_id);
        println!("\n[{}]", profile.display_name);
        for finding in &analyser.findings {
            println!(
                "  - [{:?}] ({}) {}",
                finding.severity, finding.rule_id.0, finding.title
            );
            if finding.severity >= Severity::High
                && let Some(fix) = &finding.remediation
            {
                println!("      Fix: {fix}");
            }
        }
    }

    println!("\nThe dwarfs have spoken. Evidence attached.\n");
    println!("{MOTTO}");
}

fn summarise_analyser(report: &AuditReport, analyser: &AnalyserResult) -> (&'static str, String) {
    let all_skipped = analyser.checks.iter().all(|c| {
        matches!(
            c,
            CheckStatus::Skipped { .. } | CheckStatus::Unavailable { .. }
        )
    });
    if all_skipped && analyser.findings.is_empty() {
        let reason = analyser
            .checks
            .first()
            .and_then(|c| match c {
                CheckStatus::Skipped { reason, .. } | CheckStatus::Unavailable { reason, .. } => {
                    Some(reason.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| "Checks skipped".to_owned());
        return ("SKIP", reason);
    }

    if let Some(worst) = analyser.findings.iter().max_by_key(|f| f.severity) {
        let badge = match worst.severity {
            Severity::Critical | Severity::High => "FAIL",
            Severity::Medium | Severity::Low => "WARN",
            Severity::Info => "INFO",
        };
        return (badge, worst.title.clone());
    }

    let detail = match analyser.dwarf_id {
        DwarfId::Netz => match &report.http {
            CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
                format!("HTTP {}", data.status_code)
            }
            _ => "Checks passed".to_owned(),
        },
        DwarfId::Leistungs => match &report.http {
            CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
                if let Measurement::Measured { value, .. } = data.elapsed_ms {
                    format!("HTTP exchange: {value} ms")
                } else {
                    "HTTP checks passed".to_owned()
                }
            }
            _ => "Checks passed".to_owned(),
        },
        _ => "Checks passed".to_owned(),
    };
    ("PASS", detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netzzwergenwacht::domain::HttpEvidence;

    #[test]
    fn exit_code_is_2_on_failed_collection() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = netzzwergenwacht::domain::EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Failed {
                error: "dns error".to_owned(),
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let report = analysis::run_all(&snap);
        let eval = config::evaluate_policy(&report, &PolicyConfig::default());
        assert_eq!(
            exit_code_for_report(&report, &eval),
            ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
        );
    }

    #[test]
    fn exit_code_is_1_when_findings_exist() {
        let target = AuditTarget::parse("http://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = netzzwergenwacht::domain::EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "http://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 10,
                        unit: netzzwergenwacht::domain::MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 0,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let report = analysis::run_all(&snap);
        let eval = config::evaluate_policy(&report, &PolicyConfig::default());
        assert_eq!(
            exit_code_for_report(&report, &eval),
            ExitCode::from(EXIT_FINDINGS)
        );
    }

    #[test]
    fn remaining_audit_budget_returns_none_when_exhausted() {
        let now = std::time::Instant::now();
        assert!(remaining_audit_budget(now, Duration::ZERO).is_none());
        assert!(remaining_audit_budget(now, Duration::from_secs(5)).is_some());
    }
}
