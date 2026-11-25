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
const RULE_DOM_SIZE: &str = "perf.dom.size";
const RULE_INLINE_SCRIPT_WEIGHT: &str = "perf.dom.inline_script_weight";
const RULE_DUPLICATE_SCRIPTS: &str = "perf.dom.duplicate_scripts";
const RULE_RENDER_BLOCKING_CSS: &str = "perf.dom.render_blocking_stylesheets";
const RULE_PRECONNECT: &str = "perf.assets.preconnect";
const RULE_LAZY_LOADING: &str = "perf.assets.lazy_loading";
const RULE_RUNTIME_TRANSFER_WEIGHT: &str = "perf.runtime.total_transfer_weight";
const RULE_RUNTIME_UNCOMPRESSED: &str = "perf.runtime.uncompressed_text_assets";
const RULE_RUNTIME_UNCACHED: &str = "perf.runtime.uncached_static_assets";
const RULE_RENDERED_DOM_SIZE: &str = "perf.runtime.rendered_dom_size";
const RULE_EXCESSIVE_STYLESHEETS: &str = "perf.dom.excessive_stylesheets";
const RULE_FONT_DISPLAY_SWAP: &str = "perf.assets.font_display_swap";
const RULE_RUNTIME_THIRD_PARTY_REQUESTS: &str = "perf.runtime.third_party_requests";
const RULE_LCP_SLOW_TTFB: &str = "perf.lcp.slow_ttfb";
const RULE_JS_LONG_TASKS: &str = "perf.js.long_tasks";
const RULE_WATERFALL_REDIRECTS: &str = "perf.waterfall.redirect_overhead";
const RULE_CACHE_ZERO_MAX_AGE: &str = "perf.cache.zero_max_age";
const RULE_RUNTIME_CLS: &str = "perf.cls.layout_shift_observed";
const RULE_RUNTIME_LCP: &str = "perf.lcp.slow_element_render";
const RULE_FONT_LEGACY_FORMAT: &str = "perf.font.legacy_format";

const ALL_SOURCE_RULES: &[&str] = &[
    RULE_EXCHANGE_DURATION,
    RULE_PAYLOAD_SIZE,
    RULE_COMPRESSION,
    RULE_CACHE_HEADERS,
    RULE_RENDER_BLOCKING_SCRIPTS,
    RULE_THIRD_PARTY_SCRIPTS,
    RULE_DOM_SIZE,
    RULE_INLINE_SCRIPT_WEIGHT,
    RULE_DUPLICATE_SCRIPTS,
    RULE_RENDER_BLOCKING_CSS,
    RULE_PRECONNECT,
    RULE_LAZY_LOADING,
    RULE_EXCESSIVE_STYLESHEETS,
    RULE_FONT_DISPLAY_SWAP,
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
        check_dom_size(doc, &mut findings, &mut checks);
        check_inline_script_weight(doc, &mut findings, &mut checks);
        check_duplicate_scripts(doc, &mut findings, &mut checks);
        check_render_blocking_css(doc, &mut findings, &mut checks);
        check_preconnect(http, doc, &mut findings, &mut checks);
        check_lazy_loading(doc, &mut findings, &mut checks);
        check_excessive_stylesheets(doc, &mut findings, &mut checks);
        check_font_display_swap(doc, &mut findings, &mut checks);
    }
    check_core_web_vitals(&snapshot.lighthouse, &mut findings, &mut checks);
    check_runtime_resources(&snapshot.browser, &mut findings, &mut checks);
    check_runtime_third_party(&snapshot.browser, &mut findings, &mut checks);
    check_runtime_perf_metrics(&snapshot.browser, &mut findings, &mut checks);
    check_waterfall_and_cache_semantics(&snapshot.browser, &mut findings, &mut checks);
    check_runtime_cls_lcp_and_fonts(&snapshot.browser, &mut findings, &mut checks);

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

fn check_dom_size(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.total_elements > 1_500 {
        let severity = if obs.total_elements > 3_000 {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DOM_SIZE.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity,
            confidence: Confidence::High,
            title: format!("Large DOM size ({} elements)", obs.total_elements),
            summary: format!(
                "Source HTML contains {} DOM elements (> 1,500 threshold), increasing style and layout cost.",
                obs.total_elements
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("total_elements={}", obs.total_elements),
            )],
            remediation: Some(
                "Simplify deeply nested wrapper markup and virtualise large lists.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DOM_SIZE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DOM_SIZE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_inline_script_weight(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let inline_bytes: usize = obs.scripts.iter().map(|s| s.inline_bytes).sum();
    if inline_bytes > 50 * 1024 {
        let severity = if inline_bytes > 150 * 1024 {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INLINE_SCRIPT_WEIGHT.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity,
            confidence: Confidence::High,
            title: format!("Heavy inline script/hydration payload ({} KiB)", inline_bytes / 1024),
            summary: format!(
                "Inline `<script>` blocks total {inline_bytes} bytes (> 50 KiB), bloating initial HTML transfer and parse time."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("inline_script_bytes={inline_bytes}"),
            )],
            remediation: Some(
                "Trim embedded hydration/state JSON and externalise cacheable scripts.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INLINE_SCRIPT_WEIGHT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INLINE_SCRIPT_WEIGHT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_duplicate_scripts(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = Vec::new();
    for src in obs.scripts.iter().filter_map(|s| s.src.as_deref()) {
        if !seen.insert(src) {
            duplicates.push(src);
        }
    }

    if duplicates.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_SCRIPTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_SCRIPTS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Duplicate external script references ({})",
                duplicates.len()
            ),
            summary: format!(
                "Same external `<script src>` appears multiple times: {}.",
                duplicates
                    .iter()
                    .take(3)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("duplicate_scripts={}", duplicates.len()),
            )],
            remediation: Some("Deduplicate repeated `<script>` inclusions.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_SCRIPTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_render_blocking_css(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let blocking_css = obs
        .stylesheets
        .iter()
        .filter(|c| {
            c.media
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case("all") || m.eq_ignore_ascii_case("screen"))
        })
        .count();

    if blocking_css > 3 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_RENDER_BLOCKING_CSS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Multiple render-blocking stylesheets ({blocking_css})"),
            summary: format!(
                "Found {blocking_css} blocking `<link rel=\"stylesheet\">` requests (> 3)."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("blocking_stylesheets={blocking_css}"),
            )],
            remediation: Some(
                "Inline critical CSS and bundle or defer non-critical stylesheets.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_RENDER_BLOCKING_CSS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RENDER_BLOCKING_CSS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_preconnect(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let page_origin = url::Url::parse(&http.final_url).ok().map(|u| u.origin());
    let third_party_origins: std::collections::HashSet<String> = obs
        .scripts
        .iter()
        .filter_map(|s| s.src.as_deref())
        .chain(obs.stylesheets.iter().map(|c| c.href.as_str()))
        .filter_map(|raw| {
            let parsed = url::Url::parse(raw).ok()?;
            if page_origin.as_ref().is_some_and(|o| parsed.origin() != *o) {
                Some(parsed.origin().ascii_serialization())
            } else {
                None
            }
        })
        .collect();

    if third_party_origins.len() < 3 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_PRECONNECT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 3 third-party asset origins".to_owned(),
        });
        return;
    }

    if obs.preconnect_count > 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PRECONNECT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PRECONNECT.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "Missing preconnect hints for third-party origins".to_owned(),
            summary: format!(
                "Page loads assets from {} third-party origins without `<link rel=\"preconnect\">` or `dns-prefetch`.",
                third_party_origins.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("third_party_origins={}", third_party_origins.len()),
            )],
            remediation: Some(
                "Add `<link rel=\"preconnect\" href=\"...\">` for critical third-party asset origins."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PRECONNECT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_lazy_loading(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.images.len() < 5 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LAZY_LOADING.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 5 <img> elements on page".to_owned(),
        });
        return;
    }

    let lazy_count = obs
        .images
        .iter()
        .filter(|img| {
            img.loading
                .as_deref()
                .is_some_and(|l| l.eq_ignore_ascii_case("lazy"))
        })
        .count();

    if lazy_count > 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LAZY_LOADING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LAZY_LOADING.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: format!(
                "No lazy-loaded images among {} <img> elements",
                obs.images.len()
            ),
            summary: "None of the page's images declare `loading=\"lazy\"` for offscreen deferral."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("images={};lazy=0", obs.images.len()),
            )],
            remediation: Some(
                "Add `loading=\"lazy\"` to below-the-fold images (keep the hero/LCP image eager)."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LAZY_LOADING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_runtime_resources(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. }) = browser
    else {
        return;
    };

    if !data.resources.is_empty() {
        let total_bytes: u64 = data.resources.iter().filter_map(|r| r.transfer_size).sum();
        if total_bytes > 2 * 1024 * 1024 {
            let severity = if total_bytes > 5 * 1024 * 1024 {
                Severity::Medium
            } else {
                Severity::Low
            };
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_RUNTIME_TRANSFER_WEIGHT.to_owned()),
                category: FindingCategory::Performance,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity,
                confidence: Confidence::High,
                title: format!(
                    "Heavy total page transfer weight ({} KiB)",
                    total_bytes / 1024
                ),
                summary: format!(
                    "Browser transferred {total_bytes} bytes across {} network resources.",
                    data.resources.len()
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!("total_transfer_bytes={total_bytes}"),
                )],
                remediation: Some(
                    "Reduce JS/image/font transfer sizes and eliminate unused third-party payloads."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_RUNTIME_TRANSFER_WEIGHT.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_RUNTIME_TRANSFER_WEIGHT.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }

        check_runtime_uncompressed(data, findings, checks);
        check_runtime_cache_policy(data, findings, checks);
    }

    check_rendered_dom_size(data, findings, checks);
}

fn check_runtime_uncompressed(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    {
        let uncompressed: Vec<&str> = data
            .resources
            .iter()
            .filter(|r| {
                r.transfer_size.is_some_and(|s| s > 1024)
                    && matches!(
                        r.resource_type.as_str(),
                        "script" | "stylesheet" | "document" | "xhr" | "fetch"
                    )
                    && r.content_encoding
                        .as_deref()
                        .is_none_or(|e| e.trim().is_empty())
            })
            .map(|r| r.url.as_str())
            .collect();
        if uncompressed.is_empty() {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_RUNTIME_UNCOMPRESSED.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_RUNTIME_UNCOMPRESSED.to_owned()),
                category: FindingCategory::Performance,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: format!(
                    "Uncompressed text/code subresources ({})",
                    uncompressed.len()
                ),
                summary: format!(
                    "{} script/CSS/document response(s) (> 1 KiB) lacked `Content-Encoding`.",
                    uncompressed.len()
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!("uncompressed_resources={}", uncompressed.len()),
                )],
                remediation: Some(
                    "Enable Brotli (`br`) or gzip compression for all text/script/CSS assets."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_RUNTIME_UNCOMPRESSED.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }
    }
}

fn check_runtime_cache_policy(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    {
        let uncached: Vec<&str> = data
            .resources
            .iter()
            .filter(|r| {
                matches!(
                    r.resource_type.as_str(),
                    "script" | "stylesheet" | "image" | "font"
                ) && r.cache_control.as_deref().is_none_or(|cc| {
                    let lower = cc.to_ascii_lowercase();
                    !lower.contains("max-age=") && !lower.contains("immutable")
                })
            })
            .map(|r| r.url.as_str())
            .collect();
        if uncached.is_empty() {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_RUNTIME_UNCACHED.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_RUNTIME_UNCACHED.to_owned()),
                category: FindingCategory::Performance,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: format!("Static assets missing cache policy ({})", uncached.len()),
                summary: format!(
                    "{} script/CSS/image/font resource(s) lacked `Cache-Control: max-age` or `immutable`.",
                    uncached.len()
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!("uncached_static_resources={}", uncached.len()),
                )],
                remediation: Some(
                    "Serve fingerprinted static assets with long-lived `Cache-Control: public, max-age=31536000, immutable`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_RUNTIME_UNCACHED.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }
    }
}

fn check_rendered_dom_size(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if let Some(dom_count) = data.rendered_dom_elements {
        if dom_count > 1_500 {
            let severity = if dom_count > 3_000 {
                Severity::Medium
            } else {
                Severity::Low
            };
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_RENDERED_DOM_SIZE.to_owned()),
                category: FindingCategory::Performance,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity,
                confidence: Confidence::High,
                title: format!("Large rendered DOM ({dom_count} elements)"),
                summary: format!(
                    "Rendered browser DOM contains {dom_count} elements (> 1,500 threshold)."
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!("rendered_dom_elements={dom_count}"),
                )],
                remediation: Some(
                    "Reduce client-side rendered DOM depth and virtualise offscreen lists."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_RENDERED_DOM_SIZE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_RENDERED_DOM_SIZE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }
    }
}

fn check_excessive_stylesheets(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let count = obs.stylesheets.len();
    if count > 5 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_EXCESSIVE_STYLESHEETS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Excessive external stylesheets ({count})"),
            summary: format!(
                "Document links {count} external stylesheets (> 5), increasing render-blocking roundtrips."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("stylesheet_count={count}"),
            )],
            remediation: Some(
                "Bundle critical CSS and defer non-critical stylesheets.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXCESSIVE_STYLESHEETS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EXCESSIVE_STYLESHEETS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_font_display_swap(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let google_fonts: Vec<&str> = obs
        .stylesheets
        .iter()
        .map(|s| s.href.as_str())
        .filter(|href| href.contains("fonts.googleapis.com/css"))
        .collect();
    if google_fonts.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_FONT_DISPLAY_SWAP.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no Google Fonts stylesheet detected".to_owned(),
        });
        return;
    }

    let missing_display = google_fonts
        .iter()
        .filter(|href| !href.contains("display="))
        .count();
    if missing_display > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FONT_DISPLAY_SWAP.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Google Fonts stylesheet missing display=swap ({missing_display})"),
            summary: format!(
                "{missing_display} Google Fonts stylesheet(s) omit `display=swap` (or fallback/optional), risking invisible text (FOIT)."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("google_fonts_missing_display={missing_display}"),
            )],
            remediation: Some("Append `&display=swap` to Google Fonts CSS URLs.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FONT_DISPLAY_SWAP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FONT_DISPLAY_SWAP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_runtime_third_party(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. }) = browser
    else {
        return;
    };
    let Ok(page_url) = url::Url::parse(&data.final_url) else {
        return;
    };
    let Some(page_host) = page_url.host_str() else {
        return;
    };

    let mut third_party_hosts = std::collections::BTreeSet::new();
    let mut third_party_reqs = 0usize;
    for req in &data.resources {
        if let Ok(req_url) = url::Url::parse(&req.url)
            && let Some(host) = req_url.host_str()
            && !host.eq_ignore_ascii_case(page_host)
        {
            third_party_reqs += 1;
            third_party_hosts.insert(host.to_ascii_lowercase());
        }
    }

    if third_party_reqs >= 25 || third_party_hosts.len() >= 10 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_RUNTIME_THIRD_PARTY_REQUESTS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Heavy third-party network fan-out ({third_party_reqs} requests across {} hosts)",
                third_party_hosts.len()
            ),
            summary: format!(
                "Page load triggered {third_party_reqs} third-party subresource requests across {} external host(s).",
                third_party_hosts.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "third_party_requests={third_party_reqs};third_party_hosts={}",
                    third_party_hosts.len()
                ),
            )],
            remediation: Some(
                "Audit and self-host or defer non-essential third-party scripts and pixels."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_RUNTIME_THIRD_PARTY_REQUESTS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RUNTIME_THIRD_PARTY_REQUESTS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_runtime_perf_metrics(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let perf = match browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.performance.as_ref()
        }
        CollectorOutcome::Skipped { .. } | CollectorOutcome::Failed { .. } => None,
    };
    let Some(perf) = perf else {
        return;
    };

    if let Some(ttfb) = perf.ttfb_ms {
        if ttfb > 800 {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_LCP_SLOW_TTFB.to_owned()),
                category: FindingCategory::Performance,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity: if ttfb > 1_800 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: Confidence::High,
                title: format!("Slow navigation TTFB ({ttfb} ms)"),
                summary: format!(
                    "Browser navigation timing recorded TTFB of {ttfb} ms (> 800 ms threshold)."
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!("ttfb_ms={ttfb}"),
                )],
                remediation: Some(
                    "Optimise server response latency, edge caching, and database queries."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_LCP_SLOW_TTFB.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_LCP_SLOW_TTFB.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }
    }

    if perf.max_long_task_ms > 200 || perf.long_task_total_ms > 300 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_JS_LONG_TASKS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Main-thread JS long tasks ({} tasks, max {} ms)",
                perf.long_task_count, perf.max_long_task_ms
            ),
            summary: format!(
                "Observed {} long task(s) totalling {} ms on the main thread (max {} ms).",
                perf.long_task_count, perf.long_task_total_ms, perf.max_long_task_ms
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "long_tasks={};total_ms={};max_ms={}",
                    perf.long_task_count, perf.long_task_total_ms, perf.max_long_task_ms
                ),
            )],
            remediation: Some(
                "Break up long-running JavaScript tasks, code-split bundles, and yield to the main thread."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_JS_LONG_TASKS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_JS_LONG_TASKS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_waterfall_and_cache_semantics(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. }) = browser
    else {
        return;
    };

    let redirected: Vec<&str> = data
        .resources
        .iter()
        .filter(|r| r.status_code.is_some_and(|s| (300..400).contains(&s)))
        .map(|r| r.url.as_str())
        .collect();
    if redirected.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_WATERFALL_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_WATERFALL_REDIRECTS.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Subresource redirects in waterfall ({})", redirected.len()),
            summary: format!(
                "{} subresource request(s) returned 3xx redirects, adding round-trip latency.",
                redirected.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("redirected_subresources={}", redirected.len()),
            )],
            remediation: Some(
                "Update subresource URLs to point directly to their final canonical destination."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_WATERFALL_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    let zero_max_age: Vec<&str> = data
        .resources
        .iter()
        .filter(|r| {
            matches!(
                r.resource_type.as_str(),
                "script" | "stylesheet" | "image" | "font"
            )
        })
        .filter(|r| {
            r.cache_control.as_deref().is_some_and(|cc| {
                cc.split(',')
                    .map(|d| d.trim().to_ascii_lowercase())
                    .any(|d| d == "max-age=0" || d == "no-store" || d == "no-cache")
            })
        })
        .map(|r| r.url.as_str())
        .collect();
    if zero_max_age.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CACHE_ZERO_MAX_AGE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CACHE_ZERO_MAX_AGE.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Static subresources with zero-cache directives ({})",
                zero_max_age.len()
            ),
            summary: format!(
                "{} static subresource(s) explicitly specify `max-age=0`, `no-cache`, or `no-store`.",
                zero_max_age.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("zero_max_age_static_resources={}", zero_max_age.len()),
            )],
            remediation: Some(
                "Serve static assets with positive `max-age` caching rather than `max-age=0`/`no-store`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CACHE_ZERO_MAX_AGE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_runtime_cls_lcp_and_fonts(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. }) = browser
    else {
        return;
    };

    if let Some(perf) = &data.performance {
        if let Some(cls_milli) = perf.cls_thousandths {
            if cls_milli > 100 {
                findings.push(Finding {
                    fingerprint: FindingFingerprint::default(),
                    rule_id: RuleId(RULE_RUNTIME_CLS.to_owned()),
                    category: FindingCategory::Performance,
                    evidence_level: EvidenceLevel::Rendered,
                    kind: FindingKind::Deterministic,
                    severity: if cls_milli > 250 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::High,
                    title: format!("Browser CLS exceeds 0.10 ({cls_milli} thousandths)"),
                    summary: format!(
                        "PerformanceObserver measured CLS = 0.{cls_milli:03} across {} layout shift(s).",
                        perf.layout_shift_count
                    ),
                    evidence_refs: vec![EvidenceRef::new(
                        EvidenceSource::BrowserRuntime,
                        format!("cls_thousandths={cls_milli};shifts={}", perf.layout_shift_count),
                    )],
                    remediation: Some(
                        "Reserve explicit dimensions on images, embeds, and dynamic containers."
                            .to_owned(),
                    ),
                });
                checks.push(CheckStatus::Failed {
                    rule_id: RuleId(RULE_RUNTIME_CLS.to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                });
            } else {
                checks.push(CheckStatus::Passed {
                    rule_id: RuleId(RULE_RUNTIME_CLS.to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                });
            }
        }

        if let Some(lcp_ms) = perf.lcp_ms {
            if lcp_ms > 2_500 {
                findings.push(Finding {
                    fingerprint: FindingFingerprint::default(),
                    rule_id: RuleId(RULE_RUNTIME_LCP.to_owned()),
                    category: FindingCategory::Performance,
                    evidence_level: EvidenceLevel::Rendered,
                    kind: FindingKind::Deterministic,
                    severity: if lcp_ms > 4_000 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    confidence: Confidence::High,
                    title: format!("Slow browser LCP ({lcp_ms} ms)"),
                    summary: format!(
                        "PerformanceObserver measured LCP of {lcp_ms} ms (element={}).",
                        perf.lcp_element.as_deref().unwrap_or("unknown")
                    ),
                    evidence_refs: vec![EvidenceRef::new(
                        EvidenceSource::BrowserRuntime,
                        format!("lcp_ms={lcp_ms}"),
                    )],
                    remediation: Some(
                        "Prioritise the LCP resource (`fetchpriority=\"high\"`), reduce TTFB, and remove render-blocking dependencies."
                            .to_owned(),
                    ),
                });
                checks.push(CheckStatus::Failed {
                    rule_id: RuleId(RULE_RUNTIME_LCP.to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                });
            } else {
                checks.push(CheckStatus::Passed {
                    rule_id: RuleId(RULE_RUNTIME_LCP.to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                });
            }
        }
    }

    check_runtime_legacy_fonts(data, findings, checks);
}

fn check_runtime_legacy_fonts(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let legacy_fonts: Vec<&str> = data
        .resources
        .iter()
        .filter(|r| r.resource_type == "font")
        .map(|r| r.url.as_str())
        .filter(|u| {
            let path = u.split('?').next().unwrap_or(u).to_ascii_lowercase();
            std::path::Path::new(&path)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| matches!(ext, "ttf" | "otf" | "eot" | "woff"))
        })
        .collect();
    if legacy_fonts.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FONT_LEGACY_FORMAT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FONT_LEGACY_FORMAT.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Legacy font format(s) loaded ({})", legacy_fonts.len()),
            summary: format!(
                "{} webfont(s) delivered in non-WOFF2 format (.ttf/.otf/.eot/.woff).",
                legacy_fonts.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("legacy_fonts={}", legacy_fonts.len()),
            )],
            remediation: Some("Serve modern WOFF2 fonts with Brotli compression.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FONT_LEGACY_FORMAT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
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

    #[test]
    fn flags_duplicate_scripts_blocking_css_preconnect_and_lazy_loading() {
        let html = r#"<html><head>
            <script src="https://cdn1.example.org/a.js" defer></script>
            <script src="https://cdn1.example.org/a.js" defer></script>
            <script src="https://cdn2.example.org/b.js" defer></script>
            <script src="https://cdn3.example.org/c.js" defer></script>
            <link rel="stylesheet" href="/1.css">
            <link rel="stylesheet" href="/2.css">
            <link rel="stylesheet" href="/3.css">
            <link rel="stylesheet" href="/4.css">
        </head><body>
            <img src="/1.png"><img src="/2.png"><img src="/3.png"><img src="/4.png"><img src="/5.png">
        </body></html>"#;
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
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_DUPLICATE_SCRIPTS));
        assert!(ids.contains(&RULE_RENDER_BLOCKING_CSS));
        assert!(ids.contains(&RULE_PRECONNECT));
        assert!(ids.contains(&RULE_LAZY_LOADING));
    }

    #[test]
    fn flags_runtime_transfer_compression_cache_and_rendered_dom() {
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
                    body_bytes: 256,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::Captured {
                data: crate::domain::BrowserEvidence {
                    final_url: "https://example.com/".to_owned(),
                    resources: vec![crate::domain::ResourceTimingObs {
                        url: "https://example.com/app.js".to_owned(),
                        resource_type: "script".to_owned(),
                        mime_type: Some("application/javascript".to_owned()),
                        transfer_size: Some(3 * 1024 * 1024),
                        duration_ms: Some(120),
                        protocol: Some("h2".to_owned()),
                        cache_control: None,
                        content_encoding: None,
                        ..crate::domain::ResourceTimingObs::default()
                    }],
                    rendered_dom_elements: Some(2_200),
                    ..crate::domain::BrowserEvidence::default()
                },
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let result = analyse(&snap);
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_RUNTIME_TRANSFER_WEIGHT));
        assert!(ids.contains(&RULE_RUNTIME_UNCOMPRESSED));
        assert!(ids.contains(&RULE_RUNTIME_UNCACHED));
        assert!(ids.contains(&RULE_RENDERED_DOM_SIZE));
    }

    #[test]
    fn flags_excessive_stylesheets_font_display_and_runtime_third_party() {
        let html = r#"<html><head>
            <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
            <link rel="stylesheet" href="/1.css"><link rel="stylesheet" href="/2.css">
            <link rel="stylesheet" href="/3.css"><link rel="stylesheet" href="/4.css">
            <link rel="stylesheet" href="/5.css">
        </head><body></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let third_party_reqs: Vec<crate::domain::ResourceTimingObs> = (0..10)
            .map(|i| crate::domain::ResourceTimingObs {
                url: format!("https://cdn{i}.thirdparty.test/script.js"),
                resource_type: "script".to_owned(),
                mime_type: None,
                transfer_size: Some(1024),
                duration_ms: None,
                protocol: None,
                cache_control: Some("max-age=3600".to_owned()),
                content_encoding: Some("br".to_owned()),
                ..crate::domain::ResourceTimingObs::default()
            })
            .collect();
        let snap = EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-encoding".to_owned(),
                        value: "br".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 100,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 512,
                    body_truncated: false,
                    body_text: html.to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::Captured {
                data: crate::domain::BrowserEvidence {
                    final_url: "https://example.com/".to_owned(),
                    resources: third_party_reqs,
                    ..crate::domain::BrowserEvidence::default()
                },
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_EXCESSIVE_STYLESHEETS));
        assert!(ids.contains(&RULE_FONT_DISPLAY_SWAP));
        assert!(ids.contains(&RULE_RUNTIME_THIRD_PARTY_REQUESTS));
    }

    #[test]
    fn flags_slow_ttfb_long_tasks_waterfall_redirects_and_zero_max_age() {
        let snap = EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-encoding".to_owned(),
                        value: "br".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 100,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 512,
                    body_truncated: false,
                    body_text: "<html></html>".to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::Captured {
                data: crate::domain::BrowserEvidence {
                    final_url: "https://example.com/".to_owned(),
                    resources: vec![crate::domain::ResourceTimingObs {
                        url: "https://example.com/old-bundle.js".to_owned(),
                        resource_type: "script".to_owned(),
                        status_code: Some(302),
                        cache_control: Some("public, max-age=0".to_owned()),
                        ..crate::domain::ResourceTimingObs::default()
                    }],
                    performance: Some(crate::domain::PerformanceRuntimeObs {
                        ttfb_ms: Some(1_150),
                        long_task_count: 2,
                        long_task_total_ms: 420,
                        max_long_task_ms: 260,
                        ..crate::domain::PerformanceRuntimeObs::default()
                    }),
                    ..crate::domain::BrowserEvidence::default()
                },
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_LCP_SLOW_TTFB));
        assert!(ids.contains(&RULE_JS_LONG_TASKS));
        assert!(ids.contains(&RULE_WATERFALL_REDIRECTS));
        assert!(ids.contains(&RULE_CACHE_ZERO_MAX_AGE));
    }

    #[test]
    fn flags_runtime_cls_lcp_and_legacy_fonts() {
        let snap = EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: vec![HttpHeader {
                        name: "content-encoding".to_owned(),
                        value: "br".to_owned(),
                    }],
                    elapsed_ms: Measurement::Measured {
                        value: 100,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 512,
                    body_truncated: false,
                    body_text: "<html></html>".to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::Captured {
                data: crate::domain::BrowserEvidence {
                    final_url: "https://example.com/".to_owned(),
                    resources: vec![crate::domain::ResourceTimingObs {
                        url: "https://example.com/fonts/body.ttf".to_owned(),
                        resource_type: "font".to_owned(),
                        ..crate::domain::ResourceTimingObs::default()
                    }],
                    performance: Some(crate::domain::PerformanceRuntimeObs {
                        lcp_ms: Some(3_100),
                        lcp_element: Some("img#hero".to_owned()),
                        cls_thousandths: Some(180),
                        layout_shift_count: 2,
                        ..crate::domain::PerformanceRuntimeObs::default()
                    }),
                    ..crate::domain::BrowserEvidence::default()
                },
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_RUNTIME_CLS));
        assert!(ids.contains(&RULE_RUNTIME_LCP));
        assert!(ids.contains(&RULE_FONT_LEGACY_FORMAT));
    }
}
