//! Deterministic analysis engine (Zwerge).
//!
//! All analysers in this module are pure functions over an immutable
//! [`EvidenceSnapshot`] and never perform network or browser I/O.

pub mod seo;
pub mod sicherheits;
pub mod web_browser;

use serde::{Deserialize, Serialize};

use crate::domain::{
    AnalyserResult, AuditTarget, CheckStatus, CollectorOutcome, EvidenceSnapshot, HttpEvidence,
    RuleId, Severity,
};

/// Schema version for serialised [`AuditReport`] JSON payloads.
pub const REPORT_SCHEMA_VERSION: &str = "0.2.0";

/// Aggregated counts across an audit run (never a synthetic quality score).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total findings by severity.
    pub critical_findings: usize,
    /// High-severity findings count.
    pub high_findings: usize,
    /// Medium-severity findings count.
    pub medium_findings: usize,
    /// Low-severity findings count.
    pub low_findings: usize,
    /// Informational findings count.
    pub info_findings: usize,
    /// Rules that passed.
    pub passed_checks: usize,
    /// Rules that emitted findings.
    pub failed_checks: usize,
    /// Rules skipped due to absent evidence or policy.
    pub skipped_checks: usize,
    /// Rules unavailable due to missing capability or external tool.
    pub unavailable_checks: usize,
}

/// Complete deterministic audit report ready for CLI or JSON rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    /// Version of this JSON contract.
    pub schema_version: String,
    /// Validated audit target.
    pub target: AuditTarget,
    /// Snapshot capture timestamp in Unix seconds.
    pub captured_at_unix_secs: u64,
    /// Outcome of HTTP collection.
    pub http: CollectorOutcome<HttpEvidence>,
    /// Per-Zwerg analyser outputs.
    pub analysers: Vec<AnalyserResult>,
    /// Deterministic finding and check counts.
    pub summary: AuditSummary,
}

/// Runs all Phase 1 deterministic Zwerg analysers against `snapshot`.
#[must_use]
pub fn run_all(snapshot: &EvidenceSnapshot) -> AuditReport {
    let analysers = vec![
        web_browser::analyse(snapshot),
        sicherheits::analyse(snapshot),
        seo::analyse(snapshot),
    ];

    let mut summary = AuditSummary::default();
    for analyser in &analysers {
        for finding in &analyser.findings {
            match finding.severity {
                Severity::Critical => summary.critical_findings += 1,
                Severity::High => summary.high_findings += 1,
                Severity::Medium => summary.medium_findings += 1,
                Severity::Low => summary.low_findings += 1,
                Severity::Info => summary.info_findings += 1,
            }
        }
        for check in &analyser.checks {
            match check {
                CheckStatus::Passed { .. } => summary.passed_checks += 1,
                CheckStatus::Failed { .. } => summary.failed_checks += 1,
                CheckStatus::Skipped { .. } => summary.skipped_checks += 1,
                CheckStatus::Unavailable { .. } => summary.unavailable_checks += 1,
            }
        }
    }

    AuditReport {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        target: snapshot.target.clone(),
        captured_at_unix_secs: snapshot.captured_at_unix_secs,
        http: snapshot.http.clone(),
        analysers,
        summary,
    }
}

/// Extracts [`HttpEvidence`] if available, or returns a human-readable skip reason.
pub(crate) fn require_http(snapshot: &EvidenceSnapshot) -> Result<&HttpEvidence, String> {
    match &snapshot.http {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => Ok(data),
        CollectorOutcome::Failed { error } => Err(format!("HTTP collection failed: {error}")),
        CollectorOutcome::Skipped { reason } => Err(format!("HTTP collection skipped: {reason}")),
    }
}

/// Builds an [`AnalyserResult`] where all `rule_ids` are marked skipped.
pub(crate) fn skip_all(zwerg_name: &str, rule_ids: &[&str], reason: &str) -> AnalyserResult {
    AnalyserResult {
        zwerg_name: zwerg_name.to_owned(),
        findings: Vec::new(),
        checks: rule_ids
            .iter()
            .map(|id| CheckStatus::Skipped {
                rule_id: RuleId((*id).to_owned()),
                reason: reason.to_owned(),
            })
            .collect(),
    }
}

/// Case-insensitive lookup for the first matching HTTP header value.
pub(crate) fn header_value<'a>(http: &'a HttpEvidence, name: &str) -> Option<&'a str> {
    let target = name.to_ascii_lowercase();
    http.headers
        .iter()
        .find(|h| h.name == target)
        .map(|h| h.value.as_str())
}
