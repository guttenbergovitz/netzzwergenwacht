//! Deterministic analysis engine (**Die Zwergenbrigade**).
//!
//! All analysers in this module are pure functions over an immutable
//! [`EvidenceSnapshot`] (and shared [`document::DocumentObservations`]) and
//! never perform network or browser I/O.

pub mod accessibility;
pub mod adblock;
pub mod aria;
pub mod assessment;
pub mod browser;
pub mod content;
pub mod content_fingerprint;
pub mod document;
pub mod element_identity;
pub mod excerpt;
pub mod graph;
pub mod journeys;
pub mod network;
pub mod performance;
pub mod performance_series;
pub mod profile;
pub mod rendered_history;
pub mod schema;
pub mod security;
pub mod segmentation;
pub mod semantics;
pub mod seo;
pub mod site_rules;
pub mod stats;
pub mod visual;
pub mod visual_diff;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis::document::DocumentObservations;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, AuditTarget, CheckStatus, CollectorOutcome, EvidenceLevel, EvidenceSnapshot,
    FindingFingerprint, HttpEvidence, RuleId, Severity,
};

/// Schema version for serialised [`AuditReport`] JSON payloads.
pub const REPORT_SCHEMA_VERSION: &str = "0.2.0";

/// Aggregated counts across an audit run (never a synthetic quality score).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct AuditSummary {
    /// Critical-severity findings count.
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
    /// Rules skipped due to absent/truncated evidence or policy.
    pub skipped_checks: usize,
    /// Rules unavailable due to missing capability or external tool.
    pub unavailable_checks: usize,
}

/// Compact status summary for an optional Level 2 collector (`browser`, `lighthouse`, `axe`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Level2CollectorStatus {
    /// Collector identifier (`"browser"`, `"lighthouse"`, or `"axe"`).
    pub collector: String,
    /// Outcome state (`"captured"`, `"partial"`, `"failed"`, or `"skipped"`).
    pub state: String,
    /// Optional failure, skip, or partial-capture detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Complete deterministic audit report ready for CLI or JSON rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuditReport {
    /// Version of this JSON contract.
    pub schema_version: String,
    /// Validated audit target.
    pub target: AuditTarget,
    /// Snapshot capture timestamp in Unix seconds.
    pub captured_at_unix_secs: u64,
    /// Outcome of HTTP collection.
    pub http: CollectorOutcome<HttpEvidence>,
    /// Status summaries for optional Level 2 collectors (`browser`, `lighthouse`, `axe`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub level2_collectors: Vec<Level2CollectorStatus>,
    /// Optional rendered identity and fingerprints retained for offline comparisons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_history: Option<rendered_history::RenderedHistoryEvidence>,
    /// Per-Zwerg analyser outputs.
    pub analysers: Vec<AnalyserResult>,
    /// Deterministic finding and check counts.
    pub summary: AuditSummary,
    /// Optional non-authoritative AI synthesis attached when `--ai` is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_synthesis: Option<crate::intelligence::AiSynthesis>,
}

/// Runs all Phase 1 deterministic Zwerg analysers against `snapshot`.
///
/// Parses HTML once into shared [`DocumentObservations`] when a complete HTML
/// body is available. Truncated payloads skip full-document checks to prevent
/// false absence findings.
#[must_use]
pub fn run_all(snapshot: &EvidenceSnapshot) -> AuditReport {
    run_all_with_events(snapshot, &crate::events::DiagnosticEventSink::noop())
}

/// Runs all deterministic Zwerg analysers against `snapshot` while emitting
/// structured lifecycle and finding events to `sink`.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn run_all_with_events(
    snapshot: &EvidenceSnapshot,
    sink: &crate::events::DiagnosticEventSink,
) -> AuditReport {
    let mut analysers = Vec::new();
    let target_url = snapshot.target.as_str();

    let mut run_analyser = |dwarf: DwarfId, f: &mut dyn FnMut() -> AnalyserResult| {
        let ctx = crate::events::EventContext::new()
            .with_target(target_url)
            .with_dwarf(dwarf);
        sink.emit(
            ctx.clone(),
            crate::events::DiagnosticEventPayload::AnalysisStarted { dwarf },
        );
        let result = f();
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        let mut inconclusive = 0usize;
        for check in &result.checks {
            match check {
                CheckStatus::Passed { .. } => passed += 1,
                CheckStatus::Failed { .. } => failed += 1,
                CheckStatus::Skipped { .. } => skipped += 1,
                CheckStatus::Unavailable { .. } => inconclusive += 1,
            }
        }
        for finding in &result.findings {
            sink.emit(
                ctx.clone(),
                crate::events::DiagnosticEventPayload::FindingRecorded {
                    dwarf,
                    rule_id: finding.rule_id.0.clone(),
                    title: finding.title.clone(),
                    severity: finding.severity,
                    confidence: finding.confidence,
                },
            );
        }
        sink.emit(
            ctx,
            crate::events::DiagnosticEventPayload::AnalysisCompleted {
                dwarf,
                checks_total: result.checks.len(),
                checks_passed: passed,
                checks_failed: failed,
                checks_skipped: skipped,
                checks_inconclusive: inconclusive,
            },
        );
        analysers.push(result);
    };

    match extract_complete_html(snapshot) {
        Ok((http, obs)) => {
            run_analyser(DwarfId::Netz, &mut || {
                network::analyse_with_document(snapshot, Some(&obs))
            });
            run_analyser(DwarfId::Sicherheits, &mut || {
                security::analyse_with_document(snapshot, Some(&obs))
            });
            run_analyser(DwarfId::Leistungs, &mut || {
                performance::analyse_with_document(snapshot, Some(&obs))
            });
            run_analyser(DwarfId::Struktur, &mut || {
                semantics::analyse_with_http(&obs, Some(http))
            });
            run_analyser(DwarfId::Zugaenglichkeits, &mut || {
                accessibility::analyse_with_browser(&obs, &snapshot.axe, &snapshot.browser)
            });
            run_analyser(DwarfId::Such, &mut || seo::analyse(http, &obs));
            run_analyser(DwarfId::Inhalts, &mut || content::analyse(http, &obs));
            run_analyser(DwarfId::Browser, &mut || {
                analyse_browser_and_functional(snapshot, Some(&obs))
            });
            run_analyser(DwarfId::Gestaltungs, &mut || {
                visual::analyse_with_document(snapshot, Some(&obs))
            });
        }
        Err(reason) => {
            run_analyser(DwarfId::Netz, &mut || network::analyse(snapshot));
            run_analyser(DwarfId::Sicherheits, &mut || security::analyse(snapshot));
            run_analyser(DwarfId::Leistungs, &mut || performance::analyse(snapshot));
            run_analyser(DwarfId::Struktur, &mut || {
                skip_all(
                    DwarfId::Struktur,
                    semantics::ALL_RULES,
                    EvidenceLevel::Source,
                    &reason,
                )
            });
            run_analyser(DwarfId::Zugaenglichkeits, &mut || {
                accessibility::skipped_source_result(&reason)
            });
            run_analyser(DwarfId::Such, &mut || {
                skip_all(
                    DwarfId::Such,
                    seo::ALL_RULES,
                    EvidenceLevel::Source,
                    &reason,
                )
            });
            run_analyser(DwarfId::Inhalts, &mut || {
                skip_all(
                    DwarfId::Inhalts,
                    content::ALL_RULES,
                    EvidenceLevel::Source,
                    &reason,
                )
            });
            run_analyser(DwarfId::Browser, &mut || {
                analyse_browser_and_functional(snapshot, None)
            });
            run_analyser(DwarfId::Gestaltungs, &mut || {
                visual::analyse_without_document(snapshot, &reason)
            });
        }
    }

    populate_fingerprints(snapshot.target.as_str(), &mut analysers);
    excerpt::enrich_evidence_excerpts(snapshot, &mut analysers);

    let summary = summarise(&analysers);
    let level2_collectors = [
        ("browser", snapshot.browser.status_summary()),
        ("lighthouse", snapshot.lighthouse.status_summary()),
        ("axe", snapshot.axe.status_summary()),
    ]
    .into_iter()
    .map(|(name, (state, detail))| Level2CollectorStatus {
        collector: name.to_owned(),
        state: state.to_owned(),
        detail,
    })
    .collect();

    AuditReport {
        schema_version: REPORT_SCHEMA_VERSION.to_owned(),
        target: snapshot.target.clone(),
        captured_at_unix_secs: snapshot.captured_at_unix_secs,
        http: snapshot.http.clone(),
        level2_collectors,
        rendered_history: rendered_history::RenderedHistoryEvidence::from_outcome(
            &snapshot.browser,
        ),
        analysers,
        summary,
        ai_synthesis: None,
    }
}

fn analyse_browser_and_functional(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
    let mut res = match obs {
        Some(doc) => browser::analyse_with_document(snapshot, Some(doc)),
        None => browser::analyse(snapshot),
    };
    let functional = journeys::analyse_functional_behaviour(snapshot);
    res.findings.extend(functional.findings);
    res.checks.extend(functional.checks);
    res
}

fn populate_fingerprints(page_scope: &str, analysers: &mut [AnalyserResult]) {
    for analyser in analysers {
        for finding in &mut analyser.findings {
            // Fingerprint uses stable page scope + rule ID rather than volatile
            // timing or count prose so latency drift does not churn history.
            finding.fingerprint = FindingFingerprint::compute(page_scope, &finding.rule_id, "");
        }
    }
}

fn summarise(analysers: &[AnalyserResult]) -> AuditSummary {
    let mut summary = AuditSummary::default();
    for analyser in analysers {
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
    summary
}

fn extract_complete_html(
    snapshot: &EvidenceSnapshot,
) -> Result<(&HttpEvidence, DocumentObservations), String> {
    let http = require_complete_html(snapshot)?;
    Ok((http, DocumentObservations::from_html(&http.body_text)))
}

pub(crate) fn require_complete_html(snapshot: &EvidenceSnapshot) -> Result<&HttpEvidence, String> {
    let http = require_http(snapshot)?;
    if http.body_truncated {
        return Err(
            "HTTP response body truncated at budget; skipping full-document HTML checks".to_owned(),
        );
    }
    let is_html = header_value(http, "content-type")
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"))
        || http.body_text.trim_start().starts_with('<');
    if !is_html {
        return Err("response is not HTML; skipping HTML document checks".to_owned());
    }
    Ok(http)
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
pub(crate) fn skip_all(
    dwarf_id: DwarfId,
    rule_ids: &[&str],
    evidence_level: EvidenceLevel,
    reason: &str,
) -> AnalyserResult {
    AnalyserResult {
        dwarf_id,
        findings: Vec::new(),
        checks: rule_ids
            .iter()
            .map(|id| CheckStatus::Skipped {
                rule_id: RuleId((*id).to_owned()),
                evidence_level,
                reason: reason.to_owned(),
            })
            .collect(),
    }
}

/// Case-insensitive lookup for the first matching HTTP header value.
pub(crate) fn header_value<'a>(http: &'a HttpEvidence, name: &str) -> Option<&'a str> {
    http.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{HttpHeader, Measurement, MeasurementUnit, TargetPolicy};

    #[test]
    fn truncated_html_skips_document_checks_without_false_findings() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Partial {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-type".to_owned(),
                        value: "text/html".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 10,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 5,
                    body_truncated: true,
                    body_text: "<html".to_owned(),
                },
                warnings: vec!["truncated".to_owned()],
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };

        let report = run_all(&snap);
        for id in [DwarfId::Struktur, DwarfId::Zugaenglichkeits, DwarfId::Such] {
            let analyser = report.analysers.iter().find(|a| a.dwarf_id == id).unwrap();
            assert_eq!(analyser.findings.len(), 0);
        }
    }

    #[test]
    fn every_emitted_finding_has_non_empty_evidence_refs() {
        let target = AuditTarget::parse("http://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "http://example.com/".to_owned(),
                    status_code: 500,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-type".to_owned(),
                        value: "text/html".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 4000,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 50,
                    body_truncated: false,
                    body_text: "<html><body><img src='/a.png'></body></html>".to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };

        let report = run_all(&snap);
        for analyser in &report.analysers {
            for finding in &analyser.findings {
                assert!(
                    !finding.evidence_refs.is_empty(),
                    "finding {} missing evidence_refs",
                    finding.rule_id.0
                );
            }
        }
    }

    #[test]
    fn rule_selection_filters_include_exclude_and_ignore_patterns() {
        let mut selection = RuleSelection::parse_ignore_str(
            "# comment\n\
             such.meta.description\n\
             rule:a11y.images.*\n\
             /admin/*\n",
        );
        selection.include = vec!["such.*".to_owned(), "a11y.*".to_owned()];
        selection.exclude = vec!["such.social.*".to_owned()];

        assert!(selection.matches_rule("such.meta.title"));
        assert!(!selection.matches_rule("such.meta.description"));
        assert!(!selection.matches_rule("such.social.metadata"));
        assert!(!selection.matches_rule("a11y.images.alt"));
        assert!(selection.matches_rule("a11y.doc.lang"));
        assert!(!selection.matches_rule("sec.headers.csp"));
        assert!(selection.is_url_ignored("https://example.com/admin/users"));
        assert!(!selection.is_url_ignored("https://example.com/blog"));
    }
}

/// Depth/coverage preset for `--level quick|surface|full`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    /// Fast shallow probe (`max_pages = 10`, `max_depth = 1`).
    Quick,
    /// Balanced surface reconnaissance (`max_pages = 50`, `max_depth = 2`).
    #[default]
    Surface,
    /// Deep multi-layer crawl (`max_pages = 250`, `max_depth = 4`).
    Full,
}

impl AuditLevel {
    /// Default `(max_pages, max_depth)` pair for this audit level.
    #[must_use]
    pub const fn default_crawl_bounds(self) -> (usize, usize) {
        match self {
            Self::Quick => (10, 1),
            Self::Surface => (50, 2),
            Self::Full => (250, 4),
        }
    }
}

/// Deterministic rule and URL ignore selection (`--rule-include`, `--rule-exclude`, `.nzwignore`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSelection {
    /// Optional allow-list of rule patterns (supports trailing `*` prefix globs).
    pub include: Vec<String>,
    /// Deny-list of rule patterns from `--rule-exclude`.
    pub exclude: Vec<String>,
    /// Rule patterns loaded from an ignore file.
    pub ignored_rules: Vec<String>,
    /// URL path or full-URL patterns loaded from an ignore file.
    pub ignored_url_patterns: Vec<String>,
}

impl RuleSelection {
    /// Parses ignore file contents (`#` comments, `rule:<pattern>`, rule IDs with `.`, or `/path` patterns).
    #[must_use]
    pub fn parse_ignore_str(raw: &str) -> Self {
        let mut selection = Self::default();
        for line in raw.lines() {
            let trimmed = line.split('#').next().unwrap_or_default().trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(rule_pat) = trimmed.strip_prefix("rule:") {
                let pat = rule_pat.trim();
                if !pat.is_empty() {
                    selection.ignored_rules.push(pat.to_owned());
                }
            } else if trimmed.starts_with('/')
                || trimmed.starts_with("http://")
                || trimmed.starts_with("https://")
            {
                selection.ignored_url_patterns.push(trimmed.to_owned());
            } else {
                selection.ignored_rules.push(trimmed.to_owned());
            }
        }
        selection
    }

    /// Loads a [`RuleSelection`] from `path` on disk.
    ///
    /// # Errors
    ///
    /// Returns an error string if the file cannot be read.
    pub fn from_ignore_file(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read ignore file `{}`: {e}", path.display()))?;
        Ok(Self::parse_ignore_str(&raw))
    }

    /// Returns `true` when `rule_id` should be retained under include/exclude/ignore rules.
    #[must_use]
    pub fn matches_rule(&self, rule_id: &str) -> bool {
        if !self.include.is_empty() && !self.include.iter().any(|pat| wildcard_match(pat, rule_id))
        {
            return false;
        }
        if self
            .exclude
            .iter()
            .chain(self.ignored_rules.iter())
            .any(|pat| wildcard_match(pat, rule_id))
        {
            return false;
        }
        true
    }

    /// Returns `true` when `url` (or its path) matches any ignored URL pattern.
    #[must_use]
    pub fn is_url_ignored(&self, url: &str) -> bool {
        if self.ignored_url_patterns.is_empty() {
            return false;
        }
        let path = url::Url::parse(url)
            .map(|u| u.path().to_owned())
            .unwrap_or_default();
        self.ignored_url_patterns.iter().any(|pat| {
            if pat.starts_with('/') {
                wildcard_match(pat, &path)
            } else {
                wildcard_match(pat, url)
            }
        })
    }

    /// Returns `true` when no include, exclude, or ignore filters are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
            && self.exclude.is_empty()
            && self.ignored_rules.is_empty()
            && self.ignored_url_patterns.is_empty()
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

/// Applies `selection` to a vector of [`AnalyserResult`]s, removing excluded findings
/// and converting excluded checks into [`CheckStatus::Skipped`].
pub fn apply_rule_selection(results: &mut [AnalyserResult], selection: &RuleSelection) {
    if selection.is_empty() {
        return;
    }
    for analyser in results.iter_mut() {
        analyser
            .findings
            .retain(|f| selection.matches_rule(&f.rule_id.0));
        for check in &mut analyser.checks {
            let rule_id = match check {
                CheckStatus::Passed { rule_id, .. }
                | CheckStatus::Failed { rule_id, .. }
                | CheckStatus::Skipped { rule_id, .. }
                | CheckStatus::Unavailable { rule_id, .. } => rule_id.clone(),
            };
            if !selection.matches_rule(&rule_id.0) {
                *check = CheckStatus::Skipped {
                    rule_id,
                    evidence_level: EvidenceLevel::Source,
                    reason: "excluded by rule selection".to_owned(),
                };
            }
        }
    }
}

/// Applies `selection` to a [`crate::discovery::CrawlSummary`], filtering ignored URLs
/// and excluded rules across `page_diagnostics`, `graph_results`, and `systemic_issues`.
pub fn apply_rule_selection_to_crawl(
    summary: &mut crate::discovery::CrawlSummary,
    selection: &RuleSelection,
) {
    if selection.is_empty() {
        return;
    }
    summary
        .page_diagnostics
        .retain(|p| !selection.is_url_ignored(&p.url));
    for page in &mut summary.page_diagnostics {
        page.findings
            .retain(|f| selection.matches_rule(&f.rule_id.0));
    }
    apply_rule_selection(&mut summary.graph_results, selection);
    summary
        .systemic_issues
        .retain(|s| selection.matches_rule(&s.rule_id.0));
}
