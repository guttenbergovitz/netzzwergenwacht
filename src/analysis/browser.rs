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

/// All Level 2 rules owned by `BrowserZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_CONSOLE_ERRORS,
    RULE_FAILED_REQUESTS,
    RULE_API_FAILURES,
    RULE_HYDRATION_ERRORS,
    RULE_SOURCE_RENDERED_DIVERGENCE,
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
}
