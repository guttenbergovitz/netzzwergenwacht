//! `NetzZwergenWacht` CLI entry point.

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use netzzwergenwacht::analysis::{self, AuditReport};
use netzzwergenwacht::collection;
use netzzwergenwacht::domain::{AuditTarget, ExecutionBudget, TargetPolicy};

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
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Per-request HTTP timeout in seconds.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Maximum number of HTTP redirects to follow.
        #[arg(long, default_value_t = 5)]
        max_redirects: usize,
    },
    /// Validate a target URL against target and SSRF policies without fetching.
    Validate {
        /// Target URL to validate.
        url: String,
        /// Allow loopback and private network targets.
        #[arg(long)]
        allow_private: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Validate { url, allow_private } => {
            let policy = if allow_private {
                TargetPolicy::AllowPrivate
            } else {
                TargetPolicy::PublicOnly
            };
            match AuditTarget::parse(&url, policy) {
                Ok(target) => {
                    println!(
                        "valid target: {} (host: {})",
                        target.as_str(),
                        target.host()
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Check {
            url,
            format,
            allow_private,
            timeout_secs,
            max_redirects,
        } => {
            let policy = if allow_private {
                TargetPolicy::AllowPrivate
            } else {
                TargetPolicy::PublicOnly
            };
            let target = match AuditTarget::parse(&url, policy) {
                Ok(target) => target,
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    return ExitCode::FAILURE;
                }
            };

            let budget = ExecutionBudget {
                http_timeout: Duration::from_secs(timeout_secs.max(1)),
                max_redirects,
                ..ExecutionBudget::default()
            };

            let snapshot = collection::collect_http(&target, &budget, policy).await;
            let report = analysis::run_all(&snapshot);

            match format {
                OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                    Ok(json) => {
                        println!("{json}");
                        ExitCode::SUCCESS
                    }
                    Err(err) => {
                        eprintln!("failed to serialise JSON report: {err}");
                        ExitCode::FAILURE
                    }
                },
                OutputFormat::Text => {
                    print_text_report(&report);
                    ExitCode::SUCCESS
                }
            }
        }
    }
}

fn print_text_report(report: &AuditReport) {
    println!("NetzZwergenWacht v{}", report.schema_version);
    println!("Target: {}", report.target.as_str());
    println!(
        "Checks: {} passed, {} failed, {} skipped, {} unavailable",
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

    for analyser in &report.analysers {
        if analyser.findings.is_empty() {
            continue;
        }
        println!("\n[{}]", analyser.zwerg_name);
        for finding in &analyser.findings {
            println!(
                "  - [{:?}] ({}) {}",
                finding.severity, finding.rule_id.0, finding.title
            );
        }
    }
}
