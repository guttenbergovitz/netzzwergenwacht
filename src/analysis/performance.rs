//! `LeistungsZwerg` — Phase 1 HTTP-level performance observations.
//!
//! Measures HTTP exchange duration, payload size, compression, cache headers,
//! and redirect overhead without conflating network timings with browser
//! rendering or Core Web Vitals.

use crate::analysis::document::DocumentObservations;
use crate::analysis::{header_value, require_http, skip_all};
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    HttpEvidence, LighthouseMetrics, Measurement, RuleId, Severity,
};

const RULE_EXCHANGE_DURATION: &str = "perf.http.exchange_duration";
const RULE_PAYLOAD_SIZE: &str = "perf.http.payload_size";
const RULE_COMPRESSION: &str = "perf.http.compression";
const RULE_CACHE_HEADERS: &str = "perf.http.cache_headers";
const RULE_CORE_WEB_VITALS: &str = "perf.browser.core_web_vitals";
const RULE_RENDER_BLOCKING_SCRIPTS: &str = "perf.dom.render_blocking_scripts";
const RULE_THIRD_PARTY_SCRIPTS: &str = "perf.dom.third_party_scripts";

const ALL_SOURCE_RULES: &[&str] = &[
    RULE_EXCHANGE_DURATION,
    RULE_PAYLOAD_SIZE,
    RULE_COMPRESSION,
    RULE_CACHE_HEADERS,
    RULE_RENDER_BLOCKING_SCRIPTS,
    RULE_THIRD_PARTY_SCRIPTS,
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
    analyse_with_document(snapshot, None)
}

/// Evaluates HTTP performance and optional source-DOM script delivery rules.
#[must_use]
pub fn analyse_with_document(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
    analyse_with_thresholds_and_document(snapshot, PerformanceThresholds::default(), obs)
}

/// Evaluates Phase 1 HTTP performance observations using `thresholds`.
#[must_use]
pub fn analyse_with_thresholds(
    snapshot: &EvidenceSnapshot,
    thresholds: PerformanceThresholds,
) -> AnalyserResult {
    analyse_with_thresholds_and_document(snapshot, thresholds, None)
}

fn analyse_with_thresholds_and_document(
    snapshot: &EvidenceSnapshot,
    thresholds: PerformanceThresholds,
    obs: Option<&DocumentObservations>,
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
    if let Some(doc) = obs {
        check_render_blocking_scripts(doc, &mut findings, &mut checks);
        check_third_party_scripts(http, doc, &mut findings, &mut checks);
    }
    check_core_web_vitals(&snapshot.lighthouse, &mut findings, &mut checks);

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

fn check_core_web_vitals(
    lighthouse: &CollectorOutcome<LighthouseMetrics>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let metrics = match lighthouse {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => {
            checks.push(cwv_unavailable_check());
            return;
        }
    };

    let mut refs = Vec::new();
    let mut worst_severity: Option<Severity> = None;

    if let Measurement::Measured { value: lcp_ms, .. } = metrics.lcp_ms
        && lcp_ms > 2_500
    {
        let sev = if lcp_ms > 4_000 {
            Severity::High
        } else {
            Severity::Medium
        };
        worst_severity = Some(worst_severity.map_or(sev, |cur| cur.max(sev)));
        refs.push(EvidenceRef::new(
            EvidenceSource::LighthouseReport,
            format!("LCP = {lcp_ms} ms (threshold 2500 ms)"),
        ));
    }

    if let Measurement::Measured {
        value: cls_milli, ..
    } = metrics.cls_milli
        && cls_milli > 100
    {
        let sev = if cls_milli > 250 {
            Severity::High
        } else {
            Severity::Medium
        };
        worst_severity = Some(worst_severity.map_or(sev, |cur| cur.max(sev)));
        refs.push(EvidenceRef::new(
            EvidenceSource::LighthouseReport,
            format!(
                "CLS = {}.{:03} (threshold 0.100)",
                cls_milli / 1_000,
                cls_milli % 1_000
            ),
        ));
    }

    if let Some(severity) = worst_severity {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CORE_WEB_VITALS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: "Core Web Vitals exceed recommended thresholds".to_owned(),
            summary: format!(
                "Lighthouse ({}) reported Core Web Vitals outside the good threshold.",
                metrics.lighthouse_version
            ),
            evidence_refs: refs,
            remediation: Some(
                "Optimise largest contentful element delivery, reserve layout dimensions, and reduce main-thread blocking."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CORE_WEB_VITALS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CORE_WEB_VITALS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
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
            fingerprint: FindingFingerprint::default(),
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
            fingerprint: FindingFingerprint::default(),
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
            fingerprint: FindingFingerprint::default(),
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
            fingerprint: FindingFingerprint::default(),
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
            fingerprint: FindingFingerprint::default(),
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
            fingerprint: FindingFingerprint::default(),
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

fn check_render_blocking_scripts(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let blocking = obs
        .scripts
        .iter()
        .filter(|s| {
            s.src.is_some()
                && !s.is_async
                && !s.is_defer
                && s.script_type.as_deref() != Some("module")
        })
        .count();

    if blocking == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RENDER_BLOCKING_SCRIPTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let severity = if blocking >= 3 {
            Severity::Low
        } else {
            Severity::Info
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_RENDER_BLOCKING_SCRIPTS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity,
            confidence: Confidence::High,
            title: format!("Synchronous external scripts ({blocking})"),
            summary: format!(
                "Found {blocking} external `<script>` tag(s) without `async`, `defer`, or `type=\"module\"`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("blocking_scripts={blocking}"),
            )],
            remediation: Some(
                "Add `defer` or `async` to non-critical external scripts to avoid blocking HTML parsing."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_RENDER_BLOCKING_SCRIPTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_third_party_scripts(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let page_host = url::Url::parse(&http.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));

    let third_party = obs
        .scripts
        .iter()
        .filter(|s| {
            s.src.as_deref().is_some_and(|raw| {
                url::Url::parse(raw)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                    .is_some_and(|h| page_host.as_deref() != Some(h.as_str()))
            })
        })
        .count();

    if third_party <= 4 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_THIRD_PARTY_SCRIPTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let severity = if third_party > 8 {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIRD_PARTY_SCRIPTS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity,
            confidence: Confidence::High,
            title: format!("High third-party script count ({third_party})"),
            summary: format!(
                "Document embeds {third_party} external third-party scripts across different origins."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("third_party_scripts={third_party}"),
            )],
            remediation: Some(
                "Audit and consolidate third-party scripts to reduce main-thread work and network contention."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIRD_PARTY_SCRIPTS.to_owned()),
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
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
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

    #[test]
    fn flags_slow_lcp_and_high_cls_from_lighthouse() {
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
                        value: 150,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 256,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::Captured {
                data: LighthouseMetrics {
                    lighthouse_version: "12.0.0".to_owned(),
                    lcp_ms: Measurement::Measured {
                        value: 4_200,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    cls_milli: Measurement::Measured {
                        value: 180,
                        unit: MeasurementUnit::Count,
                    },
                    fcp_ms: Measurement::Measured {
                        value: 1_100,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    tbt_ms: Measurement::Measured {
                        value: 120,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    performance_score: Some(62),
                    provenance: None,
                },
            },
            axe: CollectorOutcome::default(),
        };

        let result = analyse(&snap);
        let cwv_finding = result
            .findings
            .iter()
            .find(|f| f.rule_id.0 == RULE_CORE_WEB_VITALS)
            .unwrap();
        assert_eq!(cwv_finding.severity, Severity::High);
        assert_eq!(cwv_finding.evidence_refs.len(), 2);
    }

    #[test]
    fn flags_render_blocking_and_excessive_third_party_scripts() {
        let html = r#"<html><head>
            <script src="https://cdn1.example.org/a.js"></script>
            <script src="https://cdn2.example.org/b.js"></script>
            <script src="https://cdn3.example.org/c.js"></script>
            <script src="https://cdn4.example.org/d.js" defer></script>
            <script src="https://cdn5.example.org/e.js" async></script>
        </head><body></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 50,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: html.len(),
                    body_truncated: false,
                    body_text: html.to_owned(),
                },
            },
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let result = analyse_with_document(&snap, Some(&obs));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_RENDER_BLOCKING_SCRIPTS)
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_THIRD_PARTY_SCRIPTS)
        );
    }
}
