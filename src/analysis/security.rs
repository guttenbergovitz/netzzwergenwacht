//! `SicherheitsZwerg` — passive HTTP transport and security-header checks.
//!
//! Validates both presence and basic semantic validity of security headers.

use crate::analysis::{header_value, require_http, skip_all};
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
    HttpEvidence, RuleId, Severity,
};

const RULE_HTTPS: &str = "sec.transport.https";
const RULE_TLS_EXPIRY: &str = "sec.tls.certificate_expiry";
const RULE_HSTS: &str = "sec.headers.hsts";
const RULE_CSP: &str = "sec.headers.csp";
const RULE_XCTO: &str = "sec.headers.x_content_type_options";
const RULE_XFO: &str = "sec.headers.x_frame_options";
const RULE_REFERRER: &str = "sec.headers.referrer_policy";

const ALL_RULES: &[&str] = &[
    RULE_HTTPS,
    RULE_TLS_EXPIRY,
    RULE_HSTS,
    RULE_CSP,
    RULE_XCTO,
    RULE_XFO,
    RULE_REFERRER,
];

const VALID_REFERRER_POLICIES: &[&str] = &[
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
];

/// Evaluates passive HTTPS and HTTP security-header posture over `snapshot`.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => {
            return skip_all(
                DwarfId::Sicherheits,
                ALL_RULES,
                EvidenceLevel::Source,
                &reason,
            );
        }
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    let uses_https = http.final_url.starts_with("https://");
    check_https(http, uses_https, &mut findings, &mut checks);
    check_tls_expiry(snapshot, &mut findings, &mut checks);
    check_hsts(http, uses_https, &mut findings, &mut checks);
    check_csp(http, &mut findings, &mut checks);
    check_xcto(http, &mut findings, &mut checks);
    check_xfo(http, &mut findings, &mut checks);
    check_referrer_policy(http, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Sicherheits,
        findings,
        checks,
    }
}

fn check_tls_expiry(
    snapshot: &EvidenceSnapshot,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let tls = match &snapshot.tls {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } => {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: reason.clone(),
            });
            return;
        }
        CollectorOutcome::Failed { error } => {
            checks.push(CheckStatus::Unavailable {
                rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: format!("TLS certificate unavailable: {error}"),
            });
            return;
        }
    };

    if tls.days_until_expiry < 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: "TLS certificate has expired".to_owned(),
            summary: format!(
                "Leaf certificate `{}` expired {} days ago.",
                tls.subject,
                tls.days_until_expiry.abs()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::TlsCertificate,
                format!("days_until_expiry={}", tls.days_until_expiry),
            )],
            remediation: Some("Renew and deploy a valid TLS certificate immediately.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if tls.days_until_expiry < 14 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("TLS certificate expires in {} days", tls.days_until_expiry),
            summary: format!("Leaf certificate `{}` expires within 14 days.", tls.subject),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::TlsCertificate,
                format!("days_until_expiry={}", tls.days_until_expiry),
            )],
            remediation: Some("Renew the TLS certificate and verify automated renewal.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if tls.days_until_expiry < 30 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("TLS certificate expires in {} days", tls.days_until_expiry),
            summary: format!("Leaf certificate `{}` expires within 30 days.", tls.subject),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::TlsCertificate,
                format!("days_until_expiry={}", tls.days_until_expiry),
            )],
            remediation: Some("Schedule TLS certificate renewal.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TLS_EXPIRY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_https(
    http: &HttpEvidence,
    uses_https: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if uses_https {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HTTPS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HTTPS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Final response served over unencrypted HTTP".to_owned(),
            summary: format!(
                "Final URL {} does not use HTTPS, exposing traffic to interception.",
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpFinalUrl,
                http.final_url.clone(),
            )],
            remediation: Some(
                "Serve all public traffic over HTTPS with HTTP->HTTPS redirects.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTPS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_hsts(
    http: &HttpEvidence,
    uses_https: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if !uses_https {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HSTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "HSTS only applies to HTTPS responses".to_owned(),
        });
        return;
    }

    match header_value(http, "strict-transport-security").map(str::trim) {
        Some(val) if parse_hsts_max_age(val).is_some_and(|age| age > 0) => {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_HSTS.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
        Some(val) => {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_HSTS.to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: "Invalid or disabled Strict-Transport-Security (HSTS) header".to_owned(),
                summary: format!("HSTS header `{val}` lacks a positive `max-age` directive (> 0)."),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpHeaders,
                    format!("strict-transport-security={val}"),
                )],
                remediation: Some(
                    "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_HSTS.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
        None => {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_HSTS.to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: "Missing Strict-Transport-Security (HSTS) header".to_owned(),
                summary: format!(
                    "HTTPS response from {} omitted `strict-transport-security`.",
                    http.final_url
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpHeaders,
                    "strict-transport-security=absent",
                )],
                remediation: Some(
                    "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_HSTS.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

fn parse_hsts_max_age(value: &str) -> Option<u64> {
    for part in value.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=')
            && k.trim().eq_ignore_ascii_case("max-age")
        {
            return v.trim().trim_matches('"').parse::<u64>().ok();
        }
    }
    None
}

fn check_csp(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let Some(csp) = header_value(http, "content-security-policy")
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing Content-Security-Policy (CSP) header".to_owned(),
            summary: format!(
                "Response from {} did not include `content-security-policy`.",
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "content-security-policy=absent",
            )],
            remediation: Some(
                "Define a restrictive Content-Security-Policy header to mitigate XSS.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let lower = csp.to_ascii_lowercase();
    let has_unsafe = lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'");
    if has_unsafe {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Permissive Content-Security-Policy directives".to_owned(),
            summary: "Content-Security-Policy allows `'unsafe-inline'` or `'unsafe-eval'`, weakening XSS protection.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("content-security-policy={csp}"),
            )],
            remediation: Some(
                "Replace `'unsafe-inline'` and `'unsafe-eval'` with nonces or hashes where feasible."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_xcto(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    match header_value(http, "x-content-type-options") {
        Some(val) if val.trim().eq_ignore_ascii_case("nosniff") => {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_XCTO.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
        other => {
            let detail = other.map_or_else(|| "absent".to_owned(), |v| format!("value={v}"));
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_XCTO.to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "Missing or invalid X-Content-Type-Options header".to_owned(),
                summary: format!("Expected `x-content-type-options: nosniff`, observed {detail}."),
                evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, detail)],
                remediation: Some("Set `X-Content-Type-Options: nosniff`.".to_owned()),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_XCTO.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

fn check_xfo(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let has_frame_ancestors = header_value(http, "content-security-policy")
        .is_some_and(|csp| csp.to_ascii_lowercase().contains("frame-ancestors"));
    let valid_xfo = header_value(http, "x-frame-options").is_some_and(|v| {
        let upper = v.trim().to_ascii_uppercase();
        upper == "DENY" || upper == "SAMEORIGIN"
    });

    if valid_xfo || has_frame_ancestors {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_XFO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let observed = header_value(http, "x-frame-options").map_or_else(
            || "x-frame-options=absent".to_owned(),
            |v| format!("x-frame-options={v}"),
        );
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_XFO.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Missing or invalid clickjacking protection".to_owned(),
            summary: format!(
                "Expected `X-Frame-Options: DENY|SAMEORIGIN` or CSP `frame-ancestors`; observed {observed}."
            ),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, observed)],
            remediation: Some(
                "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and CSP `frame-ancestors`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_XFO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_referrer_policy(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    match header_value(http, "referrer-policy").map(str::trim) {
        Some(val) if !val.is_empty() => {
            let lower = val.to_ascii_lowercase();
            let last_token = lower.split(',').next_back().map_or("", str::trim);
            if last_token == "unsafe-url" || !VALID_REFERRER_POLICIES.contains(&last_token) {
                findings.push(Finding {
                    fingerprint: FindingFingerprint::default(),
                    rule_id: RuleId(RULE_REFERRER.to_owned()),
                    category: FindingCategory::Security,
                    evidence_level: EvidenceLevel::Source,
                    kind: FindingKind::Deterministic,
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    title: "Weak or unrecognised Referrer-Policy header".to_owned(),
                    summary: format!(
                        "Referrer-Policy `{val}` is weak (`unsafe-url`) or non-standard."
                    ),
                    evidence_refs: vec![EvidenceRef::new(
                        EvidenceSource::HttpHeaders,
                        format!("referrer-policy={val}"),
                    )],
                    remediation: Some(
                        "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter."
                            .to_owned(),
                    ),
                });
                checks.push(CheckStatus::Failed {
                    rule_id: RuleId(RULE_REFERRER.to_owned()),
                    evidence_level: EvidenceLevel::Source,
                });
            } else {
                checks.push(CheckStatus::Passed {
                    rule_id: RuleId(RULE_REFERRER.to_owned()),
                    evidence_level: EvidenceLevel::Source,
                });
            }
        }
        _ => {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_REFERRER.to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Info,
                confidence: Confidence::High,
                title: "Missing Referrer-Policy header".to_owned(),
                summary: format!(
                    "Response from {} did not include `referrer-policy`.",
                    http.final_url
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpHeaders,
                    "referrer-policy=absent",
                )],
                remediation: Some(
                    "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_REFERRER.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, CollectorOutcome, HttpHeader, Measurement, MeasurementUnit, TargetPolicy,
        TlsEvidence,
    };

    fn snapshot_with_headers(final_url: &str, headers: Vec<(&str, &str)>) -> EvidenceSnapshot {
        let target = AuditTarget::parse(final_url, TargetPolicy::PublicOnly).unwrap();
        let tls = if final_url.starts_with("https://") {
            CollectorOutcome::Captured {
                data: TlsEvidence {
                    subject: "CN=example.com".to_owned(),
                    issuer: "CN=Example CA".to_owned(),
                    not_after_unix_secs: 2_000_000_000,
                    days_until_expiry: 90,
                },
            }
        } else {
            CollectorOutcome::Skipped {
                reason: "target did not use HTTPS".to_owned(),
            }
        };
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
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 0,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
            tls,
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    #[test]
    fn passes_all_checks_when_https_and_valid_headers_present() {
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
    fn rejects_hsts_max_age_zero_and_unsafe_csp_and_invalid_xfo() {
        let snap = snapshot_with_headers(
            "https://example.com/",
            vec![
                ("strict-transport-security", "max-age=0"),
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'",
                ),
                ("x-content-type-options", "nosniff"),
                ("x-frame-options", "ALLOW-FROM https://evil.example"),
                ("referrer-policy", "unsafe-url"),
            ],
        );
        let result = analyse(&snap);
        let failed_ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(failed_ids.contains(&RULE_HSTS));
        assert!(failed_ids.contains(&RULE_CSP));
        assert!(failed_ids.contains(&RULE_XFO));
        assert!(failed_ids.contains(&RULE_REFERRER));
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
