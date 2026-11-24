//! `WebBrowserZwerg` — HTTP reliability and redirect-chain checks.

use crate::analysis::{require_http, skip_all};
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceRef, EvidenceSnapshot, Finding,
    FindingCategory, FindingKind, RuleId, Severity,
};

const ZWERG_NAME: &str = "WebBrowserZwerg";
const RULE_HTTP_STATUS: &str = "rel.http.status_error";
const RULE_REDIRECT_CHAIN: &str = "rel.http.redirect_chain";

/// Evaluates HTTP response status and redirect-chain hygiene over `snapshot`.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => {
            return skip_all(
                ZWERG_NAME,
                &[RULE_HTTP_STATUS, RULE_REDIRECT_CHAIN],
                &reason,
            );
        }
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    if http.status_code >= 500 {
        findings.push(Finding {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            category: FindingCategory::Reliability,
            kind: FindingKind::Deterministic,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: format!("HTTP {} server error", http.status_code),
            summary: format!(
                "Final response from {} returned server error status {}",
                http.final_url, http.status_code
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.status".to_owned(),
                detail: format!("status_code={}", http.status_code),
            }],
            remediation: Some("Investigate upstream application and server error logs.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
        });
    } else if http.status_code >= 400 {
        findings.push(Finding {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            category: FindingCategory::Reliability,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("HTTP {} client error", http.status_code),
            summary: format!(
                "Final response from {} returned client error status {}",
                http.final_url, http.status_code
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.status".to_owned(),
                detail: format!("status_code={}", http.status_code),
            }],
            remediation: Some(
                "Verify target URL, access rules, or missing resource routing.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
        });
    }

    if http.redirect_chain.len() > 2 {
        findings.push(Finding {
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
            category: FindingCategory::Reliability,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Long redirect chain ({} hops)", http.redirect_chain.len()),
            summary: format!(
                "Target {} required {} redirects before reaching {}",
                snapshot.target.as_str(),
                http.redirect_chain.len(),
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.redirect_chain".to_owned(),
                detail: format!("hops={}", http.redirect_chain.len()),
            }],
            remediation: Some(
                "Collapse intermediate redirects to point directly to the canonical URL."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
        });
    }

    AnalyserResult {
        zwerg_name: ZWERG_NAME.to_owned(),
        findings,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, CollectorOutcome, HttpEvidence, Measurement, RedirectHop, TargetPolicy,
    };

    fn make_snapshot(status_code: u16, hops: usize) -> EvidenceSnapshot {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let redirect_chain = (0..hops)
            .map(|i| RedirectHop {
                from_url: format!("https://example.com/{i}"),
                status_code: 301,
                to_url: format!("https://example.com/{}", i + 1),
            })
            .collect();

        EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code,
                    redirect_chain,
                    headers: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 10,
                        unit: "ms".to_owned(),
                    },
                    body_bytes: 0,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
        }
    }

    #[test]
    fn flags_5xx_and_long_redirects() {
        let result = analyse(&make_snapshot(503, 3));
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert_eq!(result.findings[1].severity, Severity::Low);
    }

    #[test]
    fn skips_when_http_failed() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snapshot = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Failed {
                error: "timeout".to_owned(),
            },
        };
        let result = analyse(&snapshot);
        assert_eq!(result.findings.len(), 0);
        assert!(
            result
                .checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );
    }
}
