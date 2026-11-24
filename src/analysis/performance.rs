//! `LeistungsZwerg` — Phase 1 HTTP-level performance observations.
//!
//! Measures HTTP exchange duration, payload size, compression, cache headers,
//! and redirect overhead without conflating network timings with browser
//! rendering or Core Web Vitals.

use crate::analysis::{header_value, require_http, skip_all};
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSnapshot,
    EvidenceSource, Finding, FindingCategory, FindingKind, HttpEvidence, Measurement, RuleId,
    Severity,
};

const RULE_EXCHANGE_DURATION: &str = "perf.http.exchange_duration";
const RULE_PAYLOAD_SIZE: &str = "perf.http.payload_size";
const RULE_COMPRESSION: &str = "perf.http.compression";
const RULE_CACHE_HEADERS: &str = "perf.http.cache_headers";
const RULE_CORE_WEB_VITALS: &str = "perf.browser.core_web_vitals";

const ALL_SOURCE_RULES: &[&str] = &[
    RULE_EXCHANGE_DURATION,
    RULE_PAYLOAD_SIZE,
    RULE_COMPRESSION,
    RULE_CACHE_HEADERS,
];

/// Configurable thresholds for Phase 1 HTTP performance checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerformanceThresholds {
    /// Medium-severity threshold for HTTP exchange duration in milliseconds.
    pub warn_exchange_ms: u64,
    /// High-severity threshold for HTTP exchange duration in milliseconds.
    pub high_exchange_ms: u64,
    /// Medium-severity threshold for response payload size in bytes.
    pub warn_payload_bytes: usize,
    /// High-severity threshold for response payload size in bytes.
    pub high_payload_bytes: usize,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            warn_exchange_ms: 1_500,
            high_exchange_ms: 3_000,
            warn_payload_bytes: 2 * 1024 * 1024,
            high_payload_bytes: 5 * 1024 * 1024,
        }
    }
}

/// Evaluates Phase 1 HTTP performance observations using default thresholds.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    analyse_with_thresholds(snapshot, PerformanceThresholds::default())
}

/// Evaluates Phase 1 HTTP performance observations using `thresholds`.
#[must_use]
pub fn analyse_with_thresholds(
    snapshot: &EvidenceSnapshot,
    thresholds: PerformanceThresholds,
) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => {
            let mut res = skip_all(
                DwarfId::Leistungs,
                ALL_SOURCE_RULES,
                EvidenceLevel::Source,
                &reason,
            );
            res.checks.push(cwv_unavailable_check());
            return res;
        }
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_exchange_duration(http, thresholds, &mut findings, &mut checks);
    check_payload_size(http, thresholds, &mut findings, &mut checks);
    check_compression(http, &mut findings, &mut checks);
    check_cache_headers(http, &mut findings, &mut checks);
    checks.push(cwv_unavailable_check());

    AnalyserResult {
        dwarf_id: DwarfId::Leistungs,
        findings,
        checks,
    }
}

fn cwv_unavailable_check() -> CheckStatus {
    CheckStatus::Unavailable {
        rule_id: RuleId(RULE_CORE_WEB_VITALS.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
        reason: "Core Web Vitals require Level 2 browser/Lighthouse evidence".to_owned(),
    }
}

fn check_exchange_duration(
    http: &HttpEvidence,
    thresholds: PerformanceThresholds,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Measurement::Measured { value: ms, .. } = http.elapsed_ms else {
        checks.push(CheckStatus::Unavailable {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "HTTP exchange timing was not measured".to_owned(),
        });
        return;
    };

    if ms >= thresholds.high_exchange_ms {
        findings.push(Finding {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Slow HTTP exchange ({ms} ms)"),
            summary: format!(
                "HTTP exchange (including {} redirect hops) took {ms} ms, exceeding {} ms.",
                http.redirect_chain.len(),
                thresholds.high_exchange_ms
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpTiming,
                format!("elapsed_ms={ms}"),
            )],
            remediation: Some(
                "Investigate server TTFB, network latency, and redirect overhead.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if ms >= thresholds.warn_exchange_ms {
        findings.push(Finding {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Elevated HTTP exchange duration ({ms} ms)"),
            summary: format!(
                "HTTP exchange took {ms} ms, exceeding {} ms.",
                thresholds.warn_exchange_ms
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpTiming,
                format!("elapsed_ms={ms}"),
            )],
            remediation: Some("Reduce server response time or unnecessary redirects.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EXCHANGE_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_payload_size(
    http: &HttpEvidence,
    thresholds: PerformanceThresholds,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.body_bytes >= thresholds.high_payload_bytes || http.body_truncated {
        findings.push(Finding {
            rule_id: RuleId(RULE_PAYLOAD_SIZE.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Large response payload ({} bytes)", http.body_bytes),
            summary: format!(
                "Response payload reached {} bytes (truncated={}).",
                http.body_bytes, http.body_truncated
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("body_bytes={}", http.body_bytes),
            )],
            remediation: Some(
                "Reduce document size, inline assets, or enable compression.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PAYLOAD_SIZE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if http.body_bytes >= thresholds.warn_payload_bytes {
        findings.push(Finding {
            rule_id: RuleId(RULE_PAYLOAD_SIZE.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Moderately large response payload ({} bytes)",
                http.body_bytes
            ),
            summary: format!(
                "Response payload is {} bytes, exceeding {} bytes.",
                http.body_bytes, thresholds.warn_payload_bytes
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("body_bytes={}", http.body_bytes),
            )],
            remediation: Some("Trim unnecessary markup and inline scripts.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PAYLOAD_SIZE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PAYLOAD_SIZE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_compression(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let is_compressible = header_value(http, "content-type").is_some_and(|ct| {
        let lower = ct.to_ascii_lowercase();
        lower.contains("text/") || lower.contains("json") || lower.contains("javascript")
    });

    if !is_compressible || http.body_bytes < 1024 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_COMPRESSION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Compression check applies to text/script payloads >= 1024 bytes".to_owned(),
        });
        return;
    }

    let has_encoding = header_value(http, "content-encoding").is_some_and(|enc| {
        let lower = enc.to_ascii_lowercase();
        lower.contains("br")
            || lower.contains("gzip")
            || lower.contains("zstd")
            || lower.contains("deflate")
    });

    if has_encoding {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COMPRESSION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            rule_id: RuleId(RULE_COMPRESSION.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "No Content-Encoding compression observed".to_owned(),
            summary: format!(
                "Textual payload of {} bytes did not advertise gzip, br, or zstd encoding.",
                http.body_bytes
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "content-encoding=absent",
            )],
            remediation: Some(
                "Enable Brotli (`br`) or gzip compression on the origin/CDN.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COMPRESSION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_cache_headers(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_cache = header_value(http, "cache-control").is_some()
        || header_value(http, "etag").is_some()
        || header_value(http, "last-modified").is_some();

    if has_cache {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CACHE_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            rule_id: RuleId(RULE_CACHE_HEADERS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "No explicit cache validation headers observed".to_owned(),
            summary: "Response omitted `Cache-Control`, `ETag`, and `Last-Modified`.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "cache-control/etag/last-modified=absent",
            )],
            remediation: Some(
                "Configure explicit `Cache-Control` or revalidation headers (`ETag`).".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CACHE_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, CollectorOutcome, HttpHeader, MeasurementUnit, TargetPolicy};

    #[test]
    fn flags_slow_http_exchange_and_reports_cwv_unavailable() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "cache-control".to_owned(),
                        value: "max-age=60".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 3_500,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 256,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
        };

        let result = analyse(&snap);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_EXCHANGE_DURATION && f.severity == Severity::High)
        );
        assert!(result.checks.iter().any(|c| {
            matches!(c, CheckStatus::Unavailable { rule_id, .. } if rule_id.0 == RULE_CORE_WEB_VITALS)
        }));
    }
}
