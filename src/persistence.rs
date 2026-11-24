//! JSONL audit history persistence and cross-run regression diffing.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::AuditReport;
use crate::domain::{Finding, FindingFingerprint};

/// Errors returned by persistence and report-loading operations.
#[derive(Debug, Error)]
pub enum PersistenceError {
    /// Underlying filesystem I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialisation or deserialisation failure.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// A file contained no valid [`AuditReport`] entries.
    #[error("no audit report found in {0}")]
    EmptyReportFile(String),
}

/// Summary counts for a [`RegressionReport`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct RegressionSummary {
    /// Findings newly introduced in the current audit.
    pub new_count: usize,
    /// Findings present in both baseline and current audits.
    pub persisting_count: usize,
    /// Findings present in baseline that no longer appear in current.
    pub resolved_count: usize,
    /// Baseline findings that could not be verified because the current check was skipped or unavailable.
    #[serde(default)]
    pub unverified_count: usize,
    /// Findings whose severity or detail changed between comparable runs.
    #[serde(default)]
    pub changed_count: usize,
    /// Findings previously resolved and later reintroduced.
    #[serde(default)]
    pub reintroduced_count: usize,
}

/// Comparison between a baseline and current [`AuditReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RegressionReport {
    /// Target URL of the baseline audit.
    pub baseline_target: String,
    /// Target URL of the current audit.
    pub current_target: String,
    /// Baseline capture timestamp in Unix seconds.
    pub baseline_captured_at_unix_secs: u64,
    /// Current capture timestamp in Unix seconds.
    pub current_captured_at_unix_secs: u64,
    /// Non-empty when baseline and current targets are not comparable.
    #[serde(default)]
    pub not_comparable_reason: Option<String>,
    /// Newly introduced findings.
    pub new_findings: Vec<Finding>,
    /// Findings persisting from baseline.
    pub persisting_findings: Vec<Finding>,
    /// Findings resolved since baseline (verified against non-skipped checks).
    pub resolved_findings: Vec<Finding>,
    /// Baseline findings that could not be verified because the current check was skipped or unavailable.
    #[serde(default)]
    pub unverified_findings: Vec<Finding>,
    /// Findings whose severity changed since baseline.
    #[serde(default)]
    pub changed_findings: Vec<Finding>,
    /// Findings reintroduced after prior resolution.
    #[serde(default)]
    pub reintroduced_findings: Vec<Finding>,
    /// Summary counts.
    pub summary: RegressionSummary,
}

/// Appends `report` as a single JSON line to `path`, creating parent directories if needed.
///
/// # Errors
///
/// Returns [`PersistenceError`] if directory creation, file opening, or JSON
/// serialisation fails.
pub fn append_report(path: &Path, report: &AuditReport) -> Result<(), PersistenceError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(report)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Loads all [`AuditReport`] entries from a JSONL file (ignoring blank lines).
///
/// # Errors
///
/// Returns [`PersistenceError`] if reading or JSON deserialisation fails.
pub fn load_reports(path: &Path) -> Result<Vec<AuditReport>, PersistenceError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut reports = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        reports.push(serde_json::from_str(trimmed)?);
    }
    Ok(reports)
}

/// Loads either a single JSON [`AuditReport`] or the latest entry from a JSONL file.
///
/// # Errors
///
/// Returns [`PersistenceError`] if the file cannot be read, parsed, or is empty.
pub fn load_latest_or_single(path: &Path) -> Result<AuditReport, PersistenceError> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PersistenceError::EmptyReportFile(
            path.display().to_string(),
        ));
    }
    if let Ok(single) = serde_json::from_str::<AuditReport>(trimmed) {
        return Ok(single);
    }

    let mut last: Option<AuditReport> = None;
    for line in trimmed.lines() {
        let line = line.trim();
        if !line.is_empty() {
            last = Some(serde_json::from_str(line)?);
        }
    }
    last.ok_or_else(|| PersistenceError::EmptyReportFile(path.display().to_string()))
}

/// Returns the most recent report matching `host` from `reports`.
#[must_use]
pub fn latest_for_host<'a>(reports: &'a [AuditReport], host: &str) -> Option<&'a AuditReport> {
    reports.iter().rev().find(|r| r.target.host() == host)
}

/// Compares `baseline` and `current` reports by [`FindingFingerprint`].
#[must_use]
pub fn diff_reports(baseline: &AuditReport, current: &AuditReport) -> RegressionReport {
    if baseline.target.as_str() != current.target.as_str() {
        return RegressionReport {
            baseline_target: baseline.target.as_str().to_owned(),
            current_target: current.target.as_str().to_owned(),
            baseline_captured_at_unix_secs: baseline.captured_at_unix_secs,
            current_captured_at_unix_secs: current.captured_at_unix_secs,
            not_comparable_reason: Some(format!(
                "targets differ (`{}` vs `{}`); refusing cross-target resolution claims",
                baseline.target.as_str(),
                current.target.as_str()
            )),
            new_findings: Vec::new(),
            persisting_findings: Vec::new(),
            resolved_findings: Vec::new(),
            unverified_findings: baseline
                .analysers
                .iter()
                .flat_map(|a| a.findings.iter().cloned())
                .collect(),
            changed_findings: Vec::new(),
            reintroduced_findings: Vec::new(),
            summary: RegressionSummary {
                unverified_count: baseline.analysers.iter().map(|a| a.findings.len()).sum(),
                ..RegressionSummary::default()
            },
        };
    }

    let baseline_by_fp: std::collections::HashMap<&FindingFingerprint, &Finding> = baseline
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| (&f.fingerprint, f)))
        .collect();

    let current_fps: HashSet<&FindingFingerprint> = current
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter().map(|f| &f.fingerprint))
        .collect();

    let mut new_findings = Vec::new();
    let mut persisting_findings = Vec::new();
    let mut changed_findings = Vec::new();
    for analyser in &current.analysers {
        for finding in &analyser.findings {
            if let Some(prev) = baseline_by_fp.get(&finding.fingerprint) {
                persisting_findings.push(finding.clone());
                if prev.severity != finding.severity {
                    changed_findings.push(finding.clone());
                }
            } else {
                new_findings.push(finding.clone());
            }
        }
    }

    let unverified_rules: HashSet<&str> = current
        .analysers
        .iter()
        .flat_map(|a| a.checks.iter())
        .filter_map(|check| match check {
            crate::domain::CheckStatus::Skipped { rule_id, .. }
            | crate::domain::CheckStatus::Unavailable { rule_id, .. } => Some(rule_id.0.as_str()),
            crate::domain::CheckStatus::Passed { .. }
            | crate::domain::CheckStatus::Failed { .. } => None,
        })
        .collect();

    let mut resolved_findings = Vec::new();
    let mut unverified_findings = Vec::new();
    for analyser in &baseline.analysers {
        for finding in &analyser.findings {
            if !current_fps.contains(&finding.fingerprint) {
                if unverified_rules.contains(finding.rule_id.0.as_str()) {
                    unverified_findings.push(finding.clone());
                } else {
                    resolved_findings.push(finding.clone());
                }
            }
        }
    }

    let summary = RegressionSummary {
        new_count: new_findings.len(),
        persisting_count: persisting_findings.len(),
        resolved_count: resolved_findings.len(),
        unverified_count: unverified_findings.len(),
        changed_count: changed_findings.len(),
        reintroduced_count: 0,
    };

    RegressionReport {
        baseline_target: baseline.target.as_str().to_owned(),
        current_target: current.target.as_str().to_owned(),
        baseline_captured_at_unix_secs: baseline.captured_at_unix_secs,
        current_captured_at_unix_secs: current.captured_at_unix_secs,
        not_comparable_reason: None,
        new_findings,
        persisting_findings,
        resolved_findings,
        unverified_findings,
        changed_findings,
        reintroduced_findings: Vec::new(),
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::domain::{
        AuditTarget, CollectorOutcome, EvidenceSnapshot, HttpEvidence, HttpHeader, Measurement,
        MeasurementUnit, TargetPolicy,
    };

    fn make_report(html: &str, headers: Vec<(&str, &str)>, ts: u64) -> AuditReport {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: ts,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "http://example.org/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: headers
                        .into_iter()
                        .map(|(n, v)| HttpHeader {
                            name: n.to_owned(),
                            value: v.to_owned(),
                        })
                        .collect(),
                    elapsed_ms: Measurement::Measured {
                        value: 10,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: html.len(),
                    body_truncated: false,
                    body_text: html.to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "http".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        analysis::run_all(&snap)
    }

    #[test]
    fn jsonl_append_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("nzw_test_jsonl_roundtrip");
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("history.jsonl");

        let r1 = make_report("<html><body><h1>One</h1></body></html>", Vec::new(), 100);
        let r2 = make_report(
            "<html lang='en'><body><h1>Two</h1></body></html>",
            Vec::new(),
            200,
        );

        append_report(&path, &r1).unwrap();
        append_report(&path, &r2).unwrap();

        let loaded = load_reports(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], r1);
        assert_eq!(loaded[1], r2);
        assert_eq!(latest_for_host(&loaded, "example.org"), Some(&r2));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn diff_reports_classifies_new_persisting_and_resolved() {
        let baseline = make_report(
            "<html><body><h1>Title</h1><img src='/a.png'></body></html>",
            Vec::new(),
            100,
        );
        // Fixed img alt, added duplicate id
        let current = make_report(
            "<html><body><h1 id='d'>Title</h1><p id='d'>Dup</p><img src='/a.png' alt='ok'></body></html>",
            Vec::new(),
            200,
        );

        let diff = diff_reports(&baseline, &current);
        assert!(
            diff.resolved_findings
                .iter()
                .any(|f| f.rule_id.0 == "a11y.images.alt")
        );
        assert!(
            diff.new_findings
                .iter()
                .any(|f| f.rule_id.0 == "str.doc.duplicate_ids")
        );
        assert!(diff.summary.persisting_count > 0);
    }

    #[test]
    fn skipped_check_marks_baseline_finding_unverified_not_resolved() {
        let baseline = make_report(
            "<html><body><h1>Title</h1><img src='/a.png'></body></html>",
            Vec::new(),
            100,
        );
        // Simulate a failed HTTP collection in current so all checks are skipped.
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let failed_snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 200,
            http: CollectorOutcome::Failed {
                error: "timeout".to_owned(),
            },
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let current = analysis::run_all(&failed_snap);
        let diff = diff_reports(&baseline, &current);

        assert_eq!(diff.resolved_findings.len(), 0);
        assert!(
            diff.unverified_findings
                .iter()
                .any(|f| f.rule_id.0 == "a11y.images.alt")
        );
    }
}
