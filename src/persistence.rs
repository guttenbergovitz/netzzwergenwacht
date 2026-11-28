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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn diff_crawl_summaries_tracks_page_changes_and_finding_deltas() {
        use crate::brigade::DwarfId;
        use crate::discovery::{
            CrawlCoverage, CrawlSummary, PageCrawlStatus, PageDiagnostics, PageFinding, PageType,
        };
        use crate::domain::{AuditTarget, Confidence, RuleId, Severity, TargetPolicy};

        let seed =
            AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).expect("seed");
        let make_finding = |rule: &str, title: &str, sev: Severity| PageFinding {
            rule_id: RuleId(rule.to_owned()),
            dwarf_id: DwarfId::Such,
            severity: sev,
            confidence: Confidence::High,
            title: title.to_owned(),
            summary: "summary".to_owned(),
            remediation: None,
            evidence_refs: Vec::new(),
        };
        let make_page = |url: &str, status: u16, findings: Vec<PageFinding>| PageDiagnostics {
            url: url.to_owned(),
            http_status: Some(status),
            page_type: PageType::Unknown,
            status: PageCrawlStatus::Investigated,
            checks_passed: 1,
            checks_failed: findings.len(),
            checks_skipped: 0,
            checks_unavailable: 0,
            findings,
        };

        let baseline = CrawlSummary {
            seed: seed.clone(),
            coverage: CrawlCoverage {
                discovered_urls: 3,
                fetched_urls: 3,
                analysed_urls: 3,
                failed_urls: 0,
                skipped_budget_urls: 0,
                cancelled_urls: 0,
                robots_blocked_urls: 0,
                reused_evidence_urls: 0,
                unknown_urls: 0,
                robots: crate::discovery::RobotsOutcome::Absent,
                queue_rejections: 0,
                duplicate_offers: 0,
                max_pages: 10,
                max_depth: 2,
                complete: true,
                resources: crate::discovery::ResourceCoverage::default(),
            },
            budget_exhausted: false,
            pages: Vec::new(),
            systemic_issues: Vec::new(),
            analysis_totals: Vec::new(),
            page_diagnostics: vec![
                make_page(
                    "https://example.com/",
                    200,
                    vec![make_finding(
                        "such.meta.title",
                        "Short title",
                        Severity::Low,
                    )],
                ),
                make_page(
                    "https://example.com/old",
                    200,
                    vec![make_finding(
                        "such.meta.description",
                        "Missing desc",
                        Severity::Medium,
                    )],
                ),
                make_page("https://example.com/about", 200, vec![]),
            ],
            graph_results: Vec::new(),
            resources: Vec::new(),
            page_resources: Vec::new(),
        };

        let current = CrawlSummary {
            page_diagnostics: vec![
                make_page(
                    "https://example.com/",
                    200,
                    vec![make_finding(
                        "such.meta.title",
                        "Short title",
                        Severity::Low,
                    )],
                ),
                make_page(
                    "https://example.com/about",
                    404,
                    vec![make_finding("netz.http.status", "HTTP 404", Severity::High)],
                ),
                make_page("https://example.com/new", 200, vec![]),
            ],
            ..baseline.clone()
        };

        let diff = diff_crawl_summaries(&baseline, &current);
        assert_eq!(diff.added_pages, vec!["https://example.com/new"]);
        assert_eq!(diff.removed_pages, vec!["https://example.com/old"]);
        assert_eq!(diff.status_changed_pages.len(), 1);
        assert_eq!(
            diff.status_changed_pages[0].url,
            "https://example.com/about"
        );
        assert_eq!(diff.status_changed_pages[0].baseline_status, Some(200));
        assert_eq!(diff.status_changed_pages[0].current_status, Some(404));
        assert_eq!(diff.unchanged_pages_count, 1);
        assert_eq!(diff.persisting_findings_count, 1);
        assert_eq!(diff.new_findings.len(), 1);
        assert_eq!(diff.new_findings[0].rule_id, "netz.http.status");
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.resolved_findings[0].rule_id, "such.meta.description");
        assert!(!diff.is_clean_or_improved());
    }
}

/// Classification of a page's status change between two crawl scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPageDiffKind {
    /// Page was not present in the baseline scan.
    Added,
    /// Page was present in the baseline scan but absent in the current scan.
    Removed,
    /// Page HTTP status code changed between baseline and current scans.
    StatusChanged,
    /// Page remained present with the same HTTP status.
    Unchanged,
}

/// Per-page status delta between two crawl scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPageDiff {
    /// Page URL.
    pub url: String,
    /// Classification of the page-level change.
    pub kind: ScanPageDiffKind,
    /// HTTP status in baseline scan.
    pub baseline_status: Option<u16>,
    /// HTTP status in current scan.
    pub current_status: Option<u16>,
}

/// Finding delta entry between two crawl scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanFindingDiffEntry {
    /// Affected page URL (or `"<graph>"` for cross-page graph findings).
    pub url: String,
    /// Rule identifier.
    pub rule_id: String,
    /// Finding severity.
    pub severity: crate::domain::Severity,
    /// Finding title.
    pub title: String,
}

/// Scan-to-scan diff across pages and findings between two [`crate::discovery::CrawlSummary`] runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanDiffReport {
    /// Seed URL of the baseline scan.
    pub baseline_seed: String,
    /// Seed URL of the current scan.
    pub current_seed: String,
    /// Newly discovered page URLs absent from baseline.
    pub added_pages: Vec<String>,
    /// Page URLs present in baseline but absent from current scan.
    pub removed_pages: Vec<String>,
    /// Pages whose observed HTTP status changed between scans.
    pub status_changed_pages: Vec<ScanPageDiff>,
    /// Count of pages present in both scans with identical HTTP status.
    pub unchanged_pages_count: usize,
    /// Findings newly introduced in the current scan.
    pub new_findings: Vec<ScanFindingDiffEntry>,
    /// Findings present in baseline that did not recur in the current scan.
    pub resolved_findings: Vec<ScanFindingDiffEntry>,
    /// Count of findings present in both scans.
    pub persisting_findings_count: usize,
}

impl ScanDiffReport {
    /// Returns `true` when no new findings, removed pages, or status changes occurred.
    #[must_use]
    pub fn is_clean_or_improved(&self) -> bool {
        self.new_findings.is_empty()
            && self.removed_pages.is_empty()
            && self.status_changed_pages.is_empty()
    }
}

/// Computes a deterministic scan-to-scan diff across pages and findings
/// between `baseline` and `current` [`crate::discovery::CrawlSummary`] objects.
#[must_use]
pub fn diff_crawl_summaries(
    baseline: &crate::discovery::CrawlSummary,
    current: &crate::discovery::CrawlSummary,
) -> ScanDiffReport {
    use std::collections::BTreeMap;

    let base_pages: BTreeMap<&str, Option<u16>> = baseline
        .page_diagnostics
        .iter()
        .map(|p| (p.url.as_str(), p.http_status))
        .collect();
    let curr_pages: BTreeMap<&str, Option<u16>> = current
        .page_diagnostics
        .iter()
        .map(|p| (p.url.as_str(), p.http_status))
        .collect();

    let mut added_pages = Vec::new();
    let mut removed_pages = Vec::new();
    let mut status_changed_pages = Vec::new();
    let mut unchanged_pages_count = 0usize;

    for (&url, &curr_status) in &curr_pages {
        match base_pages.get(url) {
            None => added_pages.push(url.to_owned()),
            Some(&base_status) if base_status != curr_status => {
                status_changed_pages.push(ScanPageDiff {
                    url: url.to_owned(),
                    kind: ScanPageDiffKind::StatusChanged,
                    baseline_status: base_status,
                    current_status: curr_status,
                });
            }
            Some(_) => unchanged_pages_count += 1,
        }
    }
    for &url in base_pages.keys() {
        if !curr_pages.contains_key(url) {
            removed_pages.push(url.to_owned());
        }
    }

    let collect_findings = |summary: &crate::discovery::CrawlSummary| {
        let mut map: BTreeMap<(String, String, String), ScanFindingDiffEntry> = BTreeMap::new();
        for page in &summary.page_diagnostics {
            for f in &page.findings {
                let key = (page.url.clone(), f.rule_id.0.clone(), f.title.clone());
                map.insert(
                    key,
                    ScanFindingDiffEntry {
                        url: page.url.clone(),
                        rule_id: f.rule_id.0.clone(),
                        severity: f.severity,
                        title: f.title.clone(),
                    },
                );
            }
        }
        for analyser in &summary.graph_results {
            for f in &analyser.findings {
                let key = ("<graph>".to_owned(), f.rule_id.0.clone(), f.title.clone());
                map.insert(
                    key,
                    ScanFindingDiffEntry {
                        url: "<graph>".to_owned(),
                        rule_id: f.rule_id.0.clone(),
                        severity: f.severity,
                        title: f.title.clone(),
                    },
                );
            }
        }
        map
    };

    let base_findings = collect_findings(baseline);
    let curr_findings = collect_findings(current);

    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();
    let mut persisting_findings_count = 0usize;

    for (key, entry) in &curr_findings {
        if base_findings.contains_key(key) {
            persisting_findings_count += 1;
        } else {
            new_findings.push(entry.clone());
        }
    }
    for (key, entry) in &base_findings {
        if !curr_findings.contains_key(key) {
            resolved_findings.push(entry.clone());
        }
    }

    ScanDiffReport {
        baseline_seed: baseline.seed.as_str().to_owned(),
        current_seed: current.seed.as_str().to_owned(),
        added_pages,
        removed_pages,
        status_changed_pages,
        unchanged_pages_count,
        new_findings,
        resolved_findings,
        persisting_findings_count,
    }
}
