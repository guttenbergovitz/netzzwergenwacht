//! `NetzZwergenWacht` CLI entry point (`DokumentationsZwerg` presentation).

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use netzzwergenwacht::analysis::{self, AuditReport};
use netzzwergenwacht::brigade::{self, DwarfId, MOTTO};
use netzzwergenwacht::collection;
use netzzwergenwacht::domain::{
    AnalyserResult, AuditTarget, CheckStatus, CollectorOutcome, ExecutionBudget, Measurement,
    Severity, TargetPolicy,
};

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
        /// Output format.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Allow loopback and private network targets (for local testing only).
        #[arg(long)]
        allow_private: bool,
        /// Per-request HTTP timeout in seconds.
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// End-to-end collection deadline in seconds (including DNS and redirects).
        #[arg(long, default_value_t = 60)]
        audit_timeout_secs: u64,
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
            format,
            allow_private,
            timeout_secs,
            audit_timeout_secs,
            max_redirects,
        } => {
            let policy = target_policy(allow_private);
            let target = match AuditTarget::parse(&url, policy) {
                Ok(target) => target,
                Err(err) => {
                    eprintln!("invalid target: {err}");
                    return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
                }
            };

            let budget = ExecutionBudget {
                audit_timeout: Duration::from_secs(audit_timeout_secs.max(1)),
                http_timeout: Duration::from_secs(timeout_secs.max(1)),
                max_redirects,
                ..ExecutionBudget::default()
            };

            let snapshot = collection::collect_http(&target, &budget, policy).await;
            let report = analysis::run_all(&snapshot);
            let code = exit_code_for_report(&report);

            match format {
                OutputFormat::Json => match serde_json::to_string_pretty(&report) {
                    Ok(json) => {
                        println!("{json}");
                        code
                    }
                    Err(err) => {
                        eprintln!("failed to serialise JSON report: {err}");
                        ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR)
                    }
                },
                OutputFormat::Text => {
                    print_text_report(&report);
                    code
                }
            }
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

fn exit_code_for_report(report: &AuditReport) -> ExitCode {
    if matches!(report.http, CollectorOutcome::Failed { .. }) {
        return ExitCode::from(EXIT_COLLECTION_OR_INPUT_ERROR);
    }
    let has_actionable = report.summary.critical_findings > 0
        || report.summary.high_findings > 0
        || report.summary.medium_findings > 0
        || report.summary.low_findings > 0
        || matches!(report.http, CollectorOutcome::Partial { .. });

    if has_actionable {
        ExitCode::from(EXIT_FINDINGS)
    } else {
        ExitCode::from(EXIT_OK)
    }
}

fn print_text_report(report: &AuditReport) {
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
        };
        let report = analysis::run_all(&snap);
        assert_eq!(
            exit_code_for_report(&report),
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
        };
        let report = analysis::run_all(&snap);
        assert_eq!(exit_code_for_report(&report), ExitCode::from(EXIT_FINDINGS));
    }
}
