//! `BrowserZwerg` — Level 2 browser runtime, console, and subresource checks.
//!
//! Analyses [`BrowserEvidence`](crate::domain::BrowserEvidence) captured by a
//! Level 2 browser adapter without performing any I/O. When browser evidence is
//! unavailable, checks are explicitly marked as skipped rather than passed.

use crate::analysis::document::DocumentObservations;
use crate::analysis::skip_all;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    RuleId, Severity,
};

const RULE_CONSOLE_ERRORS: &str = "browser.console.errors";
const RULE_FAILED_REQUESTS: &str = "browser.network.failed_requests";
const RULE_API_FAILURES: &str = "browser.runtime.api_failures";
const RULE_HYDRATION_ERRORS: &str = "browser.runtime.hydration_errors";
const RULE_SOURCE_RENDERED_DIVERGENCE: &str = "browser.runtime.source_rendered_divergence";
const RULE_ANALYTICS_BLOAT: &str = "browser.analytics.tracking_bloat";
const RULE_EXCESSIVE_SUBRESOURCES: &str = "browser.runtime.excessive_subresources";
const RULE_UNCAUGHT_EXCEPTION: &str = "browser.js.uncaught_exception";
const RULE_UNHANDLED_REJECTION: &str = "browser.js.unhandled_rejection";
const RULE_CSP_VIOLATION: &str = "browser.js.csp_violation";
const RULE_CORS_BLOCK: &str = "browser.network.cors_block";

/// All Level 2 rules owned by `BrowserZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_CONSOLE_ERRORS,
    RULE_FAILED_REQUESTS,
    RULE_API_FAILURES,
    RULE_HYDRATION_ERRORS,
    RULE_SOURCE_RENDERED_DIVERGENCE,
    RULE_ANALYTICS_BLOAT,
    RULE_EXCESSIVE_SUBRESOURCES,
    RULE_UNCAUGHT_EXCEPTION,
    RULE_UNHANDLED_REJECTION,
    RULE_CSP_VIOLATION,
    RULE_CORS_BLOCK,
];

/// Evaluates browser runtime console and network subresource observations.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    analyse_with_document(snapshot, None)
}

/// Evaluates browser runtime observations and optional source-vs-rendered divergence.
#[must_use]
pub fn analyse_with_document(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
    let browser = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } => {
            return skip_all(DwarfId::Browser, ALL_RULES, EvidenceLevel::Rendered, reason);
        }
        CollectorOutcome::Failed { error } => {
            return skip_all(DwarfId::Browser, ALL_RULES, EvidenceLevel::Rendered, error);
        }
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_console_errors(browser, &mut findings, &mut checks);
    check_failed_requests(browser, &mut findings, &mut checks);
    check_api_failures(browser, &mut findings, &mut checks);
    check_hydration_errors(browser, &mut findings, &mut checks);
    check_source_rendered_divergence(browser, obs, &mut findings, &mut checks);
    check_analytics_bloat(browser, &mut findings, &mut checks);
    check_excessive_subresources(browser, &mut findings, &mut checks);
    check_uncaught_exceptions(browser, &mut findings, &mut checks);
    check_unhandled_rejections(browser, &mut findings, &mut checks);
    check_csp_violations(browser, &mut findings, &mut checks);
    check_cors_blocks(browser, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Browser,
        findings,
        checks,
    }
}

fn check_console_errors(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if browser.console_errors.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CONSOLE_ERRORS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let count = browser.console_errors.len();
    let evidence_refs = browser
        .console_errors
        .iter()
        .take(5)
        .map(|err| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("[{}] {}", err.level, err.text),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_CONSOLE_ERRORS.to_owned()),
        category: FindingCategory::Browser,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("Browser console recorded {count} error(s)"),
        summary: format!(
            "Headless navigation to {} emitted {count} console error event(s).",
            browser.final_url
        ),
        evidence_refs,
        remediation: Some(
            "Inspect browser console errors and resolve uncaught exceptions or runtime failures."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_CONSOLE_ERRORS.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

fn check_failed_requests(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if browser.failed_requests.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FAILED_REQUESTS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
        return;
    }

    let count = browser.failed_requests.len();
    let has_server_error = browser
        .failed_requests
        .iter()
        .any(|req| req.status_code.is_some_and(|code| code >= 500));
    let evidence_refs = browser
        .failed_requests
        .iter()
        .take(5)
        .map(|req| {
            let status = req
                .status_code
                .map_or_else(String::new, |code| format!(" (HTTP {code})"));
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("{}{status}: {}", req.url, req.error_text),
            )
        })
        .collect();
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_FAILED_REQUESTS.to_owned()),
        category: FindingCategory::Browser,
        evidence_level: EvidenceLevel::Rendered,
        kind: FindingKind::Deterministic,
        severity: if has_server_error {
            Severity::High
        } else {
            Severity::Medium
        },
        confidence: Confidence::High,
        title: format!("Browser observed {count} failed subresource request(s)"),
        summary: format!(
            "During rendered page load of {}, {count} subresource request(s) failed.",
            browser.final_url
        ),
        evidence_refs,
        remediation: Some(
            "Ensure all referenced scripts, stylesheets, fonts, and API endpoints resolve reliably."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_FAILED_REQUESTS.to_owned()),
        evidence_level: EvidenceLevel::Rendered,
    });
}

fn check_api_failures(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let api_urls: std::collections::HashSet<&str> = browser
        .resources
        .iter()
        .filter(|r| matches!(r.resource_type.as_str(), "xhr" | "fetch"))
        .map(|r| r.url.as_str())
        .collect();

    let failed_api: Vec<&str> = browser
        .failed_requests
        .iter()
        .filter(|req| {
            api_urls.contains(req.url.as_str())
                || req.url.contains("/api/")
                || req.url.contains("/graphql")
        })
        .map(|req| req.url.as_str())
        .collect();

    if failed_api.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_API_FAILURES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_API_FAILURES.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Failed client-side API/XHR requests ({})", failed_api.len()),
            summary: format!(
                "{} XHR/Fetch or API request(s) failed during initial page load: {}.",
                failed_api.len(),
                failed_api
                    .iter()
                    .take(3)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("failed_api_requests={}", failed_api.len()),
            )],
            remediation: Some(
                "Resolve failing backend/API endpoints or handle client fetch errors gracefully."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_API_FAILURES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_hydration_errors(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if browser.hydration_errors.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HYDRATION_ERRORS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HYDRATION_ERRORS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Client-side hydration mismatches ({})",
                browser.hydration_errors.len()
            ),
            summary: browser
                .hydration_errors
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | "),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("hydration_errors={}", browser.hydration_errors.len()),
            )],
            remediation: Some(
                "Align SSR HTML output with initial client render state to prevent hydration mismatches."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HYDRATION_ERRORS.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_source_rendered_divergence(
    browser: &crate::domain::BrowserEvidence,
    obs: Option<&DocumentObservations>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (Some(doc), Some(rendered_words)) = (obs, browser.rendered_word_count) else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SOURCE_RENDERED_DIVERGENCE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "source or rendered word count unavailable".to_owned(),
        });
        return;
    };

    if doc.visible_word_count < 30 && rendered_words >= 150 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOURCE_RENDERED_DIVERGENCE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Heavy client-side rendering divergence (CSR-only content)".to_owned(),
            summary: format!(
                "Source HTML contains {} visible words while rendered DOM exposes {} words.",
                doc.visible_word_count, rendered_words
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("source_words={};rendered_words={rendered_words}", doc.visible_word_count),
            )],
            remediation: Some(
                "Consider SSR or pre-rendering primary content for crawlers, agents, and faster FCP."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SOURCE_RENDERED_DIVERGENCE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SOURCE_RENDERED_DIVERGENCE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_analytics_bloat(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const TRACKER_DOMAINS: &[&str] = &[
        "googletagmanager.com",
        "google-analytics.com",
        "doubleclick.net",
        "connect.facebook.net",
        "hotjar.com",
        "clarity.ms",
        "segment.com",
        "mixpanel.com",
    ];
    let mut matched = std::collections::BTreeSet::new();
    for req in &browser.resources {
        let lower = req.url.to_ascii_lowercase();
        for domain in TRACKER_DOMAINS {
            if lower.contains(domain) {
                matched.insert(*domain);
            }
        }
    }

    if matched.len() >= 3 {
        let list: Vec<&str> = matched.iter().copied().collect();
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ANALYTICS_BLOAT.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Multiple analytics/tracking vendors loaded ({})", matched.len()),
            summary: format!(
                "Browser runtime loaded {} distinct tracking/analytics vendors: {}.",
                matched.len(),
                list.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("tracker_vendors={}", list.join(",")),
            )],
            remediation: Some(
                "Consolidate redundant analytics tags and gate non-essential trackers behind consent."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ANALYTICS_BLOAT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ANALYTICS_BLOAT.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_excessive_subresources(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let total = browser.resources.len();
    if total > 80 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_EXCESSIVE_SUBRESOURCES.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Excessive subresource requests ({total})"),
            summary: format!(
                "Initial page load triggered {total} network subresource requests (> 80 threshold)."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("network_requests={total}"),
            )],
            remediation: Some(
                "Bundle small modules, remove unused assets, and lazy-load offscreen resources."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXCESSIVE_SUBRESOURCES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EXCESSIVE_SUBRESOURCES.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_uncaught_exceptions(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let exceptions: Vec<&crate::domain::ConsoleErrorEvent> = browser
        .console_errors
        .iter()
        .filter(|e| {
            e.error_kind.as_deref() == Some("uncaught_exception")
                || (e.error_kind.is_none()
                    && e.level == "exception"
                    && !e.text.to_ascii_lowercase().contains("in promise"))
        })
        .collect();

    if exceptions.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNCAUGHT_EXCEPTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        let sample = exceptions
            .iter()
            .take(3)
            .map(|e| e.text.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_UNCAUGHT_EXCEPTION.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Uncaught JavaScript exceptions ({})", exceptions.len()),
            summary: format!(
                "{} uncaught runtime exception(s) thrown during page execution: {sample}.",
                exceptions.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("uncaught_exceptions={}", exceptions.len()),
            )],
            remediation: Some(
                "Inspect stack traces and fix unhandled runtime exceptions in client scripts."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_UNCAUGHT_EXCEPTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_unhandled_rejections(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let rejections: Vec<&crate::domain::ConsoleErrorEvent> = browser
        .console_errors
        .iter()
        .filter(|e| {
            e.error_kind.as_deref() == Some("unhandled_rejection")
                || e.text.to_ascii_lowercase().contains("unhandledrejection")
                || e.text.to_ascii_lowercase().contains("in promise")
        })
        .collect();

    if rejections.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNHANDLED_REJECTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_UNHANDLED_REJECTION.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Unhandled Promise rejections ({})", rejections.len()),
            summary: format!(
                "{} unhandled asynchronous Promise rejection(s) observed during load.",
                rejections.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("unhandled_rejections={}", rejections.len()),
            )],
            remediation: Some(
                "Add `.catch()` / `try-catch` error handling around async client operations."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_UNHANDLED_REJECTION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_csp_violations(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let csp_errors: Vec<&str> = browser
        .console_errors
        .iter()
        .filter(|e| {
            e.error_kind.as_deref() == Some("csp_violation")
                || e.text
                    .to_ascii_lowercase()
                    .contains("content security policy")
        })
        .map(|e| e.text.as_str())
        .collect();
    let csp_reqs: Vec<&str> = browser
        .failed_requests
        .iter()
        .filter(|r| r.error_text.contains("ERR_BLOCKED_BY_CSP"))
        .map(|r| r.url.as_str())
        .collect();

    let total = csp_errors.len() + csp_reqs.len();
    if total == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_VIOLATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP_VIOLATION.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Runtime Content Security Policy violations ({total})"),
            summary: format!(
                "Browser reported {total} runtime CSP violation(s) blocking scripts, styles, or subresources."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("csp_violations={total}"),
            )],
            remediation: Some(
                "Align Content-Security-Policy directives with legitimate application origins or remove unauthorised embeds."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP_VIOLATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_cors_blocks(
    browser: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let cors_blocked: Vec<&str> = browser
        .failed_requests
        .iter()
        .filter(|r| {
            let lower = r.error_text.to_ascii_lowercase();
            lower.contains("cors")
                || lower.contains("access-control-allow-origin")
                || lower.contains("err_blocked_by_orb")
        })
        .map(|r| r.url.as_str())
        .collect();

    if cors_blocked.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CORS_BLOCK.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CORS_BLOCK.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("CORS-blocked subresource requests ({})", cors_blocked.len()),
            summary: format!(
                "{} subresource/API request(s) failed due to CORS or ORB policy: {}.",
                cors_blocked.len(),
                cors_blocked
                    .iter()
                    .take(3)
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("cors_blocked_requests={}", cors_blocked.len()),
            )],
            remediation: Some(
                "Configure explicit `Access-Control-Allow-Origin` headers for authorised client origins."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CORS_BLOCK.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, BrowserEvidence, ConsoleErrorEvent, FailedNetworkRequest, TargetPolicy,
    };

    fn base_snapshot(browser: CollectorOutcome<BrowserEvidence>) -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser,
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    #[test]
    fn skips_when_browser_evidence_missing() {
        let snap = base_snapshot(CollectorOutcome::Skipped {
            reason: "browser adapter not enabled".to_owned(),
        });
        let res = analyse(&snap);
        assert_eq!(res.dwarf_id, DwarfId::Browser);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }

    #[test]
    fn passes_when_browser_runtime_is_clean() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: Some("Chromium 130".to_owned()),
                console_errors: Vec::new(),
                failed_requests: Vec::new(),
                viewports: Vec::new(),
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. } | CheckStatus::Skipped { .. }))
        );
    }

    #[test]
    fn emits_findings_for_console_and_network_failures() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                browser_version: None,
                console_errors: vec![ConsoleErrorEvent {
                    level: "error".to_owned(),
                    text: "Uncaught ReferenceError: app is not defined".to_owned(),
                    ..ConsoleErrorEvent::default()
                }],
                failed_requests: vec![FailedNetworkRequest {
                    url: "https://example.com/app.js".to_owned(),
                    error_text: "net::ERR_ABORTED".to_owned(),
                    status_code: Some(500),
                }],
                viewports: Vec::new(),
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 2);
        assert!(res.findings.iter().all(|f| !f.evidence_refs.is_empty()));
        assert_eq!(res.findings[1].severity, Severity::High);
    }

    #[test]
    fn flags_api_failures_hydration_errors_and_csr_divergence() {
        let obs =
            DocumentObservations::from_html("<html><body><div id='root'></div></body></html>");
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                failed_requests: vec![FailedNetworkRequest {
                    url: "https://example.com/api/products".to_owned(),
                    error_text: "HTTP 500".to_owned(),
                    status_code: Some(500),
                }],
                hydration_errors: vec![
                    "Hydration failed because the initial UI did not match".to_owned(),
                ],
                rendered_word_count: Some(250),
                ..BrowserEvidence::default()
            },
        });
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_API_FAILURES));
        assert!(ids.contains(&RULE_HYDRATION_ERRORS));
        assert!(ids.contains(&RULE_SOURCE_RENDERED_DIVERGENCE));
    }

    #[test]
    fn flags_analytics_bloat_and_excessive_subresources() {
        let mut requests: Vec<crate::domain::ResourceTimingObs> = [
            "https://www.googletagmanager.com/gtm.js",
            "https://www.google-analytics.com/analytics.js",
            "https://connect.facebook.net/en_US/fbevents.js",
        ]
        .into_iter()
        .map(|u| crate::domain::ResourceTimingObs {
            url: u.to_owned(),
            resource_type: "script".to_owned(),
            transfer_size: Some(512),
            ..crate::domain::ResourceTimingObs::default()
        })
        .collect();
        for i in 0..80 {
            requests.push(crate::domain::ResourceTimingObs {
                url: format!("https://example.com/chunk-{i}.js"),
                resource_type: "script".to_owned(),
                transfer_size: Some(256),
                ..crate::domain::ResourceTimingObs::default()
            });
        }
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                resources: requests,
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_ANALYTICS_BLOAT));
        assert!(ids.contains(&RULE_EXCESSIVE_SUBRESOURCES));
    }

    #[test]
    fn flags_uncaught_exceptions_rejections_csp_and_cors_blocks() {
        let snap = base_snapshot(CollectorOutcome::Captured {
            data: BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                console_errors: vec![
                    ConsoleErrorEvent {
                        level: "exception".to_owned(),
                        text: "TypeError: Cannot read properties of null".to_owned(),
                        error_kind: Some("uncaught_exception".to_owned()),
                        source_url: Some("https://example.com/app.js".to_owned()),
                        line_number: Some(42),
                    },
                    ConsoleErrorEvent {
                        level: "exception".to_owned(),
                        text: "Uncaught (in promise) Error: boom".to_owned(),
                        error_kind: Some("unhandled_rejection".to_owned()),
                        ..ConsoleErrorEvent::default()
                    },
                    ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "CSP violation (script-src): blocked https://evil.test/x.js"
                            .to_owned(),
                        error_kind: Some("csp_violation".to_owned()),
                        ..ConsoleErrorEvent::default()
                    },
                ],
                failed_requests: vec![FailedNetworkRequest {
                    url: "https://api.other.test/data".to_owned(),
                    error_text: "Blocked by CORS policy: No Access-Control-Allow-Origin".to_owned(),
                    status_code: None,
                }],
                ..BrowserEvidence::default()
            },
        });
        let res = analyse(&snap);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_UNCAUGHT_EXCEPTION));
        assert!(ids.contains(&RULE_UNHANDLED_REJECTION));
        assert!(ids.contains(&RULE_CSP_VIOLATION));
        assert!(ids.contains(&RULE_CORS_BLOCK));
    }
}
