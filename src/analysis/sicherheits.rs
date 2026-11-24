//! `SicherheitsZwerg` — passive HTTP transport and security-header checks.

use crate::analysis::{header_value, require_http, skip_all};
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceRef, EvidenceSnapshot, Finding,
    FindingCategory, FindingKind, HttpEvidence, RuleId, Severity,
};

const ZWERG_NAME: &str = "SicherheitsZwerg";
const RULE_HTTPS: &str = "sec.transport.https";
const RULE_HSTS: &str = "sec.headers.hsts";
const RULE_CSP: &str = "sec.headers.csp";
const RULE_XCTO: &str = "sec.headers.x_content_type_options";
const RULE_XFO: &str = "sec.headers.x_frame_options";
const RULE_REFERRER: &str = "sec.headers.referrer_policy";

const ALL_RULES: &[&str] = &[
    RULE_HTTPS,
    RULE_HSTS,
    RULE_CSP,
    RULE_XCTO,
    RULE_XFO,
    RULE_REFERRER,
];

/// Evaluates passive HTTPS and HTTP security-header posture over `snapshot`.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => return skip_all(ZWERG_NAME, ALL_RULES, &reason),
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    let uses_https = http.final_url.starts_with("https://");
    if uses_https {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HTTPS.to_owned()),
        });
    } else {
        findings.push(Finding {
            rule_id: RuleId(RULE_HTTPS.to_owned()),
            category: FindingCategory::Security,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Final response served over unencrypted HTTP".to_owned(),
            summary: format!(
                "Final URL {} does not use HTTPS, exposing traffic to interception.",
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.final_url".to_owned(),
                detail: http.final_url.clone(),
            }],
            remediation: Some(
                "Serve all public traffic over HTTPS with HTTP->HTTPS redirects.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTPS.to_owned()),
        });
    }

    if uses_https {
        check_required_header(
            http,
            RULE_HSTS,
            "strict-transport-security",
            Severity::Medium,
            "Missing Strict-Transport-Security (HSTS) header",
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` over HTTPS.",
            &mut findings,
            &mut checks,
        );
    } else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HSTS.to_owned()),
            reason: "HSTS only applies to HTTPS responses".to_owned(),
        });
    }

    check_required_header(
        http,
        RULE_CSP,
        "content-security-policy",
        Severity::Medium,
        "Missing Content-Security-Policy (CSP) header",
        "Define a restrictive Content-Security-Policy header to mitigate XSS and injection.",
        &mut findings,
        &mut checks,
    );

    check_xcto(http, &mut findings, &mut checks);
    check_xfo(http, &mut findings, &mut checks);

    check_required_header(
        http,
        RULE_REFERRER,
        "referrer-policy",
        Severity::Info,
        "Missing Referrer-Policy header",
        "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
        &mut findings,
        &mut checks,
    );

    AnalyserResult {
        zwerg_name: ZWERG_NAME.to_owned(),
        findings,
        checks,
    }
}

fn check_xcto(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    match header_value(http, "x-content-type-options") {
        Some(val) if val.trim().eq_ignore_ascii_case("nosniff") => {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_XCTO.to_owned()),
            });
        }
        other => {
            let detail = other.map_or_else(|| "absent".to_owned(), |v| format!("value={v}"));
            findings.push(Finding {
                rule_id: RuleId(RULE_XCTO.to_owned()),
                category: FindingCategory::Security,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "Missing or non-standard X-Content-Type-Options header".to_owned(),
                summary: format!("Expected `x-content-type-options: nosniff`, observed {detail}."),
                evidence_refs: vec![EvidenceRef {
                    source: "http.headers".to_owned(),
                    detail,
                }],
                remediation: Some("Set `X-Content-Type-Options: nosniff`.".to_owned()),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_XCTO.to_owned()),
            });
        }
    }
}

fn check_xfo(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let has_frame_ancestors = header_value(http, "content-security-policy")
        .is_some_and(|csp| csp.to_ascii_lowercase().contains("frame-ancestors"));
    if header_value(http, "x-frame-options").is_some() || has_frame_ancestors {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_XFO.to_owned()),
        });
    } else {
        findings.push(Finding {
            rule_id: RuleId(RULE_XFO.to_owned()),
            category: FindingCategory::Security,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)"
                .to_owned(),
            summary: "Neither `x-frame-options` nor CSP `frame-ancestors` was present.".to_owned(),
            evidence_refs: vec![EvidenceRef {
                source: "http.headers".to_owned(),
                detail: "x-frame-options=absent".to_owned(),
            }],
            remediation: Some(
                "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and CSP `frame-ancestors`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_XFO.to_owned()),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn check_required_header(
    http: &HttpEvidence,
    rule_id: &str,
    header_name: &str,
    severity: Severity,
    title: &str,
    remediation: &str,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if header_value(http, header_name).is_some_and(|v| !v.trim().is_empty()) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(rule_id.to_owned()),
        });
    } else {
        findings.push(Finding {
            rule_id: RuleId(rule_id.to_owned()),
            category: FindingCategory::Security,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: title.to_owned(),
            summary: format!(
                "Response from {} did not include `{header_name}`.",
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef {
                source: "http.headers".to_owned(),
                detail: format!("{header_name}=absent"),
            }],
            remediation: Some(remediation.to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(rule_id.to_owned()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, CollectorOutcome, HttpHeader, Measurement, TargetPolicy};

    fn snapshot_with_headers(final_url: &str, headers: Vec<(&str, &str)>) -> EvidenceSnapshot {
        let target = AuditTarget::parse(final_url, TargetPolicy::PublicOnly).unwrap();
        EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: final_url.to_owned(),
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
                        value: 15,
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
    fn passes_all_checks_when_https_and_headers_present() {
        let snap = snapshot_with_headers(
            "https://example.com/",
            vec![
                ("strict-transport-security", "max-age=31536000"),
                ("content-security-policy", "default-src 'self'"),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "DENY"),
                ("referrer-policy", "no-referrer"),
            ],
        );
        let result = analyse(&snap);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.checks.len(), ALL_RULES.len());
        assert!(
            result
                .checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. }))
        );
    }

    #[test]
    fn flags_http_and_skips_hsts() {
        let snap = snapshot_with_headers("http://example.com/", Vec::new());
        let result = analyse(&snap);
        assert!(result.findings.iter().any(|f| f.rule_id.0 == RULE_HTTPS));
        assert!(result.checks.iter().any(|c| {
            matches!(c, CheckStatus::Skipped { rule_id, .. } if rule_id.0 == RULE_HSTS)
        }));
    }
}
