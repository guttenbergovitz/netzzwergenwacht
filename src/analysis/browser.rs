//! `BrowserZwerg` — Level 2 browser runtime, console, and subresource checks.
//!
//! Analyses [`BrowserEvidence`](crate::domain::BrowserEvidence) captured by a
//! Level 2 browser adapter without performing any I/O. When browser evidence is
//! unavailable, checks are explicitly marked as skipped rather than passed.

use crate::analysis::skip_all;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    RuleId, Severity,
};

const RULE_CONSOLE_ERRORS: &str = "browser.console.errors";
const RULE_FAILED_REQUESTS: &str = "browser.network.failed_requests";

/// All Level 2 rules owned by `BrowserZwerg`.
pub const ALL_RULES: &[&str] = &[RULE_CONSOLE_ERRORS, RULE_FAILED_REQUESTS];

/// Evaluates browser runtime console and network subresource observations.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
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
                provenance: None,
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), 2);
        assert!(
            res.checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. }))
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
                provenance: None,
            },
        });
        let res = analyse(&snap);
        assert_eq!(res.findings.len(), 2);
        assert!(res.findings.iter().all(|f| !f.evidence_refs.is_empty()));
        assert_eq!(res.findings[1].severity, Severity::High);
    }
}
