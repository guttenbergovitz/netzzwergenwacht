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

mod rendered_diff;
pub use rendered_diff::{RenderedDiffLimit, RenderedTextDiff};

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
    /// Findings whose severity increased since baseline.
    #[serde(default)]
    pub worsened_count: usize,
    /// Findings whose severity decreased since baseline.
    #[serde(default)]
    pub improved_count: usize,
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
    /// Findings whose severity increased since baseline.
    #[serde(default)]
    pub worsened_findings: Vec<Finding>,
    /// Findings whose severity decreased since baseline.
    #[serde(default)]
    pub improved_findings: Vec<Finding>,
    /// Findings reintroduced after prior resolution.
    #[serde(default)]
    pub reintroduced_findings: Vec<Finding>,
    /// Summary counts.
    pub summary: RegressionSummary,
    /// Rendered text comparison, absent in regression reports written before this feature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_text: Option<RenderedTextDiff>,
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
        return cross_target_diff(baseline, current);
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
    let mut worsened_findings = Vec::new();
    let mut improved_findings = Vec::new();
    for analyser in &current.analysers {
        for finding in &analyser.findings {
            if let Some(prev) = baseline_by_fp.get(&finding.fingerprint) {
                persisting_findings.push(finding.clone());
                if prev.severity != finding.severity {
                    changed_findings.push(finding.clone());
                    if finding.severity > prev.severity {
                        worsened_findings.push(finding.clone());
                    } else {
                        improved_findings.push(finding.clone());
                    }
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
        worsened_count: worsened_findings.len(),
        improved_count: improved_findings.len(),
        reintroduced_count: 0,
    };

    RegressionReport {
        baseline_target: baseline.target.as_str().to_owned(),
        current_target: current.target.as_str().to_owned(),
        baseline_captured_at_unix_secs: baseline.captured_at_unix_secs,
        current_captured_at_unix_secs: current.captured_at_unix_secs,
        not_comparable_reason: None,
        rendered_text: Some(rendered_diff::diff_saved_rendered(baseline, current)),
        new_findings,
        persisting_findings,
        resolved_findings,
        unverified_findings,
        changed_findings,
        worsened_findings,
        improved_findings,
        reintroduced_findings: Vec::new(),
        summary,
    }
}

fn cross_target_diff(baseline: &AuditReport, current: &AuditReport) -> RegressionReport {
    RegressionReport {
        baseline_target: baseline.target.as_str().to_owned(),
        current_target: current.target.as_str().to_owned(),
        baseline_captured_at_unix_secs: baseline.captured_at_unix_secs,
        current_captured_at_unix_secs: current.captured_at_unix_secs,
        not_comparable_reason: Some(format!(
            "targets differ (`{}` vs `{}`); refusing cross-target resolution claims",
            baseline.target.as_str(),
            current.target.as_str()
        )),
        rendered_text: Some(RenderedTextDiff::Unavailable {
            reason: RenderedDiffLimit::DifferentPage,
        }),
        new_findings: Vec::new(),
        persisting_findings: Vec::new(),
        resolved_findings: Vec::new(),
        unverified_findings: baseline
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter().cloned())
            .collect(),
        changed_findings: Vec::new(),
        worsened_findings: Vec::new(),
        improved_findings: Vec::new(),
        reintroduced_findings: Vec::new(),
        summary: RegressionSummary {
            unverified_count: baseline.analysers.iter().map(|a| a.findings.len()).sum(),
            ..RegressionSummary::default()
        },
    }
}

/// Compares `current` against the latest report in `history`, classifying any
/// finding that was absent from the immediate baseline but appeared in an
/// earlier historical run for the same target as `reintroduced_findings`.
#[must_use]
pub fn diff_history(history: &[AuditReport], current: &AuditReport) -> RegressionReport {
    let Some(latest) = history.last() else {
        let new_findings: Vec<Finding> = current
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter().cloned())
            .collect();
        let new_count = new_findings.len();
        return RegressionReport {
            baseline_target: current.target.as_str().to_owned(),
            current_target: current.target.as_str().to_owned(),
            baseline_captured_at_unix_secs: 0,
            current_captured_at_unix_secs: current.captured_at_unix_secs,
            not_comparable_reason: Some("no prior baseline report in history".to_owned()),
            rendered_text: Some(RenderedTextDiff::Unavailable {
                reason: RenderedDiffLimit::NoBaseline,
            }),
            new_findings,
            persisting_findings: Vec::new(),
            resolved_findings: Vec::new(),
            unverified_findings: Vec::new(),
            changed_findings: Vec::new(),
            worsened_findings: Vec::new(),
            improved_findings: Vec::new(),
            reintroduced_findings: Vec::new(),
            summary: RegressionSummary {
                new_count,
                ..RegressionSummary::default()
            },
        };
    };

    let mut report = diff_reports(latest, current);
    if report.not_comparable_reason.is_some() || history.len() < 2 {
        return report;
    }

    let earlier_fps: HashSet<&FindingFingerprint> = history[..history.len() - 1]
        .iter()
        .filter(|r| r.target.as_str() == current.target.as_str())
        .flat_map(|r| r.analysers.iter())
        .flat_map(|a| a.findings.iter().map(|f| &f.fingerprint))
        .collect();

    let mut remaining_new = Vec::new();
    for f in report.new_findings {
        if earlier_fps.contains(&f.fingerprint) {
            report.reintroduced_findings.push(f);
        } else {
            remaining_new.push(f);
        }
    }
    report.new_findings = remaining_new;
    report.summary.new_count = report.new_findings.len();
    report.summary.reintroduced_count = report.reintroduced_findings.len();
    report
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

    #[test]
    fn diff_history_detects_reintroduced_findings() {
        let run1 = make_report(
            "<html><body><h1>Title</h1><img src='/a.png'></body></html>",
            Vec::new(),
            100,
        );
        // Fixed in run2
        let run2 = make_report(
            "<html><body><h1>Title</h1><img src='/a.png' alt='ok'></body></html>",
            Vec::new(),
            200,
        );
        // Reintroduced in run3
        let run3 = make_report(
            "<html><body><h1>Title</h1><img src='/a.png'></body></html>",
            Vec::new(),
            300,
        );

        let diff = diff_history(&[run1, run2], &run3);
        assert!(
            diff.reintroduced_findings
                .iter()
                .any(|f| f.rule_id.0 == "a11y.images.alt")
        );
        assert_eq!(diff.summary.reintroduced_count, 1);
        assert_eq!(diff.summary.new_count, 0);
    }

    #[test]
    fn diff_reports_separates_worsened_and_improved_defects() {
        let mut base = make_report("<html><body><h1>Title</h1></body></html>", Vec::new(), 100);
        let mut curr = make_report("<html><body><h1>Title</h1></body></html>", Vec::new(), 200);
        let base_findings = &mut base.analysers[0].findings;
        let f_worsened = Finding {
            fingerprint: FindingFingerprint("fp-worse".to_owned()),
            rule_id: crate::domain::RuleId("r.worse".to_owned()),
            category: crate::domain::FindingCategory::Security,
            evidence_level: crate::domain::EvidenceLevel::Source,
            kind: crate::domain::FindingKind::Deterministic,
            severity: crate::domain::Severity::Low,
            confidence: crate::domain::Confidence::High,
            title: "Worsened".to_owned(),
            summary: "s".to_owned(),
            evidence_refs: Vec::new(),
            remediation: None,
        };
        let f_improved = Finding {
            fingerprint: FindingFingerprint("fp-improve".to_owned()),
            rule_id: crate::domain::RuleId("r.improve".to_owned()),
            category: crate::domain::FindingCategory::Security,
            evidence_level: crate::domain::EvidenceLevel::Source,
            kind: crate::domain::FindingKind::Deterministic,
            severity: crate::domain::Severity::High,
            confidence: crate::domain::Confidence::High,
            title: "Improved".to_owned(),
            summary: "s".to_owned(),
            evidence_refs: Vec::new(),
            remediation: None,
        };
        base_findings.push(f_worsened.clone());
        base_findings.push(f_improved.clone());

        let mut curr_worsened = f_worsened;
        curr_worsened.severity = crate::domain::Severity::Critical;
        let mut curr_improved = f_improved;
        curr_improved.severity = crate::domain::Severity::Medium;
        curr.analysers[0].findings.push(curr_worsened);
        curr.analysers[0].findings.push(curr_improved);

        let diff = diff_reports(&base, &curr);
        assert_eq!(diff.summary.worsened_count, 1);
        assert_eq!(diff.summary.improved_count, 1);
        assert_eq!(diff.worsened_findings[0].fingerprint.0, "fp-worse");
        assert_eq!(diff.improved_findings[0].fingerprint.0, "fp-improve");
    }
}
