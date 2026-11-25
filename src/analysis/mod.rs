//! Deterministic analysis engine (**Die Zwergenbrigade**).
//!
//! All analysers in this module are pure functions over an immutable
//! [`EvidenceSnapshot`] (and shared [`document::DocumentObservations`]) and
//! never perform network or browser I/O.

pub mod accessibility;
pub mod browser;
pub mod content;
pub mod document;
pub mod graph;
pub mod network;
pub mod performance;
pub mod schema;
pub mod security;
pub mod semantics;
pub mod seo;
pub mod visual;

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
    let mut analysers = Vec::new();

    match extract_complete_html(snapshot) {
        Ok((http, obs)) => {
            analysers.push(network::analyse_with_document(snapshot, Some(&obs)));
            analysers.push(security::analyse_with_document(snapshot, Some(&obs)));
            analysers.push(performance::analyse_with_document(snapshot, Some(&obs)));
            analysers.push(semantics::analyse(&obs));
            analysers.push(accessibility::analyse_with_axe(&obs, &snapshot.axe));
            analysers.push(seo::analyse(http, &obs));
            analysers.push(content::analyse(http, &obs));
            analysers.push(browser::analyse_with_document(snapshot, Some(&obs)));
            analysers.push(visual::analyse_with_document(snapshot, Some(&obs)));
        }
        Err(reason) => {
            analysers.push(network::analyse(snapshot));
            analysers.push(security::analyse(snapshot));
            analysers.push(performance::analyse(snapshot));
            analysers.push(skip_all(
                DwarfId::Struktur,
                semantics::ALL_RULES,
                EvidenceLevel::Source,
                &reason,
            ));
            analysers.push(accessibility::skipped_source_result(&reason));
            analysers.push(skip_all(
                DwarfId::Such,
                seo::ALL_RULES,
                EvidenceLevel::Source,
                &reason,
            ));
            analysers.push(skip_all(
                DwarfId::Inhalts,
                content::ALL_RULES,
                EvidenceLevel::Source,
                &reason,
            ));
            analysers.push(browser::analyse(snapshot));
            analysers.push(visual::analyse_without_document(snapshot, &reason));
        }
    }

    populate_fingerprints(snapshot.target.as_str(), &mut analysers);

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
        analysers,
        summary,
        ai_synthesis: None,
    }
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
    Ok((http, DocumentObservations::from_html(&http.body_text)))
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
    let target = name.to_ascii_lowercase();
    http.headers
        .iter()
        .find(|h| h.name == target)
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
}
