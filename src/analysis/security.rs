//! `SicherheitsZwerg` — passive HTTP transport and security-header checks.
//!
//! Validates both presence and basic semantic validity of security headers.

use crate::analysis::document::DocumentObservations;
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
const RULE_COOKIES: &str = "sec.headers.cookies";
const RULE_CORS: &str = "sec.headers.cors";
const RULE_MIXED_CONTENT: &str = "sec.dom.mixed_content";
const RULE_SRI: &str = "sec.dom.subresource_integrity";
const RULE_PERMISSIONS_POLICY: &str = "sec.headers.permissions_policy";
const RULE_VERSION_DISCLOSURE: &str = "sec.headers.version_disclosure";
const RULE_INSECURE_FORMS: &str = "sec.dom.insecure_forms";
const RULE_EXPOSED_SECRETS: &str = "sec.dom.exposed_secrets";
const RULE_CROSS_ORIGIN_ISOLATION: &str = "sec.headers.cross_origin_isolation";
const RULE_SENSITIVE_CACHE: &str = "sec.headers.sensitive_cache";
const RULE_IFRAME_SANDBOX: &str = "sec.dom.iframe_sandbox";

const ALL_RULES: &[&str] = &[
    RULE_HTTPS,
    RULE_TLS_EXPIRY,
    RULE_HSTS,
    RULE_CSP,
    RULE_XCTO,
    RULE_XFO,
    RULE_REFERRER,
    RULE_COOKIES,
    RULE_CORS,
    RULE_MIXED_CONTENT,
    RULE_SRI,
    RULE_PERMISSIONS_POLICY,
    RULE_VERSION_DISCLOSURE,
    RULE_INSECURE_FORMS,
    RULE_EXPOSED_SECRETS,
    RULE_CROSS_ORIGIN_ISOLATION,
    RULE_SENSITIVE_CACHE,
    RULE_IFRAME_SANDBOX,
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
    analyse_with_document(snapshot, None)
}

/// Evaluates passive HTTPS, HTTP security headers, and optional source-DOM security checks.
#[must_use]
pub fn analyse_with_document(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
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
    check_cookies(http, uses_https, &mut findings, &mut checks);
    check_cors(http, &mut findings, &mut checks);
    check_permissions_policy(http, &mut findings, &mut checks);
    check_version_disclosure(http, obs, &mut findings, &mut checks);
    check_exposed_secrets(http, &mut findings, &mut checks);
    check_cross_origin_isolation(http, &mut findings, &mut checks);

    if let Some(doc) = obs {
        check_mixed_content(http, uses_https, doc, &mut findings, &mut checks);
        check_sri(http, doc, &mut findings, &mut checks);
        check_insecure_forms(uses_https, doc, &mut findings, &mut checks);
        check_sensitive_cache(http, doc, &mut findings, &mut checks);
        check_iframe_sandbox(doc, &mut findings, &mut checks);
    } else {
        for rule in [
            RULE_MIXED_CONTENT,
            RULE_SRI,
            RULE_INSECURE_FORMS,
            RULE_SENSITIVE_CACHE,
            RULE_IFRAME_SANDBOX,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "complete HTML document observations unavailable".to_owned(),
            });
        }
    }

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

fn check_cookies(
    http: &HttpEvidence,
    uses_https: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let cookies = http.header_values("set-cookie");
    if cookies.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_COOKIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no Set-Cookie headers observed".to_owned(),
        });
        return;
    }

    let mut missing_secure = 0usize;
    let mut missing_httponly_session = 0usize;
    let mut missing_samesite = 0usize;

    for raw in &cookies {
        let lower = raw.to_ascii_lowercase();
        let mut parts = lower.split(';');
        let name_part = parts
            .next()
            .unwrap_or("")
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        let looks_sensitive = [
            "sess",
            "sid",
            "token",
            "auth",
            "jwt",
            "csrf",
            "xsrf",
            "__host-",
            "__secure-",
        ]
        .iter()
        .any(|kw| name_part.contains(kw));
        let attrs: Vec<&str> = parts.map(str::trim).collect();
        if uses_https && !attrs.contains(&"secure") {
            missing_secure += 1;
        }
        if looks_sensitive && !attrs.contains(&"httponly") {
            missing_httponly_session += 1;
        }
        if !attrs.iter().any(|a| a.starts_with("samesite=")) {
            missing_samesite += 1;
        }
    }

    if missing_secure == 0 && missing_httponly_session == 0 && missing_samesite == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let severity = if missing_secure > 0 || missing_httponly_session > 0 {
            Severity::Medium
        } else {
            Severity::Low
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIES.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity,
            confidence: Confidence::High,
            title: "Cookies missing security hardening attributes".to_owned(),
            summary: format!(
                "Across {} Set-Cookie header(s): {missing_secure} missing `Secure`, {missing_httponly_session} session/auth cookie(s) missing `HttpOnly`, {missing_samesite} missing `SameSite`.",
                cookies.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("set_cookie_count={}", cookies.len()),
            )],
            remediation: Some(
                "Set `Secure`, `HttpOnly`, and `SameSite=Lax` (or `Strict`) on session/sensitive cookies."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_cors(http: &HttpEvidence, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let Some(acao) = http.first_header_value("access-control-allow-origin") else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no Access-Control-Allow-Origin header observed".to_owned(),
        });
        return;
    };

    let trimmed = acao.trim();
    let allow_creds = http
        .first_header_value("access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));

    if trimmed == "*" && allow_creds {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CORS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Invalid wildcard CORS with Allow-Credentials".to_owned(),
            summary:
                "`Access-Control-Allow-Origin: *` is paired with `Access-Control-Allow-Credentials: true`; browsers reject credentialed responses with wildcard origins."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "acao=*;acac=true",
            )],
            remediation: Some(
                "Restrict `Access-Control-Allow-Origin` to explicit trusted origins when credentials are allowed."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if trimmed == "*" {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CORS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "Wildcard CORS policy (`*`)".to_owned(),
            summary: "`Access-Control-Allow-Origin: *` permits cross-origin reads from any origin."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, "acao=*")],
            remediation: Some(
                "Verify wildcard CORS is intentional for public non-sensitive content.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_mixed_content(
    http: &HttpEvidence,
    uses_https: bool,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if !uses_https {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_MIXED_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "target does not use HTTPS".to_owned(),
        });
        return;
    }

    let mut insecure_urls = Vec::new();
    for s in &obs.scripts {
        if let Some(src) = &s.src
            && src.starts_with("http://")
        {
            insecure_urls.push(src.as_str());
        }
    }
    for css in &obs.stylesheets {
        if css.href.starts_with("http://") {
            insecure_urls.push(css.href.as_str());
        }
    }
    for img in &obs.images {
        if let Some(src) = &img.src
            && src.starts_with("http://")
        {
            insecure_urls.push(src.as_str());
        }
    }
    for form in &obs.forms {
        if let Some(action) = &form.action
            && action.starts_with("http://")
        {
            insecure_urls.push(action.as_str());
        }
    }

    if insecure_urls.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MIXED_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MIXED_CONTENT.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Mixed content references ({}) on HTTPS page", insecure_urls.len()),
            summary: format!(
                "HTTPS page `{}` references {} insecure `http://` resource(s) or form action(s).",
                http.final_url,
                insecure_urls.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("mixed_content_count={}", insecure_urls.len()),
            )],
            remediation: Some(
                "Upgrade all embedded scripts, stylesheets, images, and form actions to `https://`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MIXED_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_sri(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let page_origin = url::Url::parse(&http.final_url).ok().map(|u| u.origin());

    let is_cross_origin = |raw: &str| -> bool {
        let Ok(parsed) = url::Url::parse(raw) else {
            return false;
        };
        page_origin
            .as_ref()
            .is_some_and(|origin| parsed.origin() != *origin)
    };

    let missing_script_sri = obs
        .scripts
        .iter()
        .filter(|s| s.src.as_deref().is_some_and(is_cross_origin) && s.integrity.is_none())
        .count();
    let missing_css_sri = obs
        .stylesheets
        .iter()
        .filter(|c| is_cross_origin(&c.href) && c.integrity.is_none())
        .count();

    let total_cross_origin = obs
        .scripts
        .iter()
        .filter(|s| s.src.as_deref().is_some_and(is_cross_origin))
        .count()
        + obs
            .stylesheets
            .iter()
            .filter(|c| is_cross_origin(&c.href))
            .count();

    if total_cross_origin == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SRI.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no cross-origin scripts or stylesheets declared".to_owned(),
        });
        return;
    }

    let missing = missing_script_sri + missing_css_sri;
    if missing == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SRI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SRI.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Cross-origin assets missing Subresource Integrity ({missing})"),
            summary: format!(
                "{missing_script_sri} third-party script(s) and {missing_css_sri} third-party stylesheet(s) lack an `integrity` attribute."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("missing_sri={missing}"),
            )],
            remediation: Some(
                "Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to static third-party CDN assets."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SRI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_permissions_policy(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if header_value(http, "permissions-policy").is_some_and(|v| !v.trim().is_empty()) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PERMISSIONS_POLICY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PERMISSIONS_POLICY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Missing Permissions-Policy header".to_owned(),
            summary: format!(
                "Response from {} did not include a `Permissions-Policy` header.",
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "permissions-policy=absent",
            )],
            remediation: Some(
                "Add `Permissions-Policy` to restrict unused browser APIs (camera, microphone, geolocation)."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PERMISSIONS_POLICY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_version_disclosure(
    http: &HttpEvidence,
    obs: Option<&DocumentObservations>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_version = |val: &str| {
        val.contains('/')
            && val
                .split('/')
                .nth(1)
                .is_some_and(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_digit()))
    };

    let mut exposed = Vec::new();
    for hdr in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(val) = header_value(http, hdr)
            && has_version(val)
        {
            exposed.push(format!("{hdr}: {val}"));
        }
    }
    if let Some(gen_meta) = obs.and_then(|o| o.meta_generator.as_deref())
        && gen_meta.chars().any(|c| c.is_ascii_digit())
    {
        exposed.push(format!("meta[name=generator]: {gen_meta}"));
    }

    if exposed.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_VERSION_DISCLOSURE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_VERSION_DISCLOSURE.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Software version disclosure in headers or generator meta".to_owned(),
            summary: format!("Exposed version indicators: {}.", exposed.join("; ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("version_disclosures={}", exposed.len()),
            )],
            remediation: Some(
                "Strip version numbers from `Server`/`X-Powered-By` headers and `<meta name=\"generator\">`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_VERSION_DISCLOSURE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_insecure_forms(
    uses_https: bool,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.forms.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_INSECURE_FORMS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <form> elements present".to_owned(),
        });
        return;
    }

    let insecure_action = obs.forms.iter().any(|f| {
        uses_https
            && f.action
                .as_deref()
                .is_some_and(|a| a.to_ascii_lowercase().starts_with("http://"))
    });
    let password_get = obs.forms.iter().any(|f| {
        f.has_password_input
            && f.method
                .as_deref()
                .is_none_or(|m| m.eq_ignore_ascii_case("get"))
    });

    if !insecure_action && !password_get {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INSECURE_FORMS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INSECURE_FORMS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Insecure form submission configuration".to_owned(),
            summary: format!(
                "insecure_http_action={insecure_action}; password_form_using_get={password_get}."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("insecure_action={insecure_action};password_get={password_get}"),
            )],
            remediation: Some(
                "Submit forms over `https://` and always use `method=\"POST\"` for password forms."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INSECURE_FORMS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_exposed_secrets(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.body_text.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_EXPOSED_SECRETS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "empty response body".to_owned(),
        });
        return;
    }

    let mut matched = Vec::new();
    let body = &http.body_text;
    if body.contains("-----BEGIN RSA PRIVATE KEY-----")
        || body.contains("-----BEGIN EC PRIVATE KEY-----")
        || body.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
    {
        matched.push("private_key_block");
    }
    if body.contains("sk_live_") {
        matched.push("stripe_live_secret_prefix");
    }
    if body.contains("ghp_") {
        matched.push("github_pat_prefix");
    }
    if let Some(idx) = body.find("AKIA") {
        let rest = &body[idx + 4..];
        if rest.len() >= 16
            && rest[..16]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            matched.push("aws_access_key_id");
        }
    }

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EXPOSED_SECRETS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_EXPOSED_SECRETS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: format!("Potential exposed credential/secret patterns ({})", matched.len()),
            summary: format!("Matched secret indicator(s): {}.", matched.join(", ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("secret_indicators={}", matched.join(",")),
            )],
            remediation: Some(
                "Rotate any exposed credentials immediately and remove secrets from client-side responses."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXPOSED_SECRETS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_cross_origin_isolation(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let opener_policy = header_value(http, "cross-origin-opener-policy");
    let resource_policy = header_value(http, "cross-origin-resource-policy");
    if opener_policy.is_some() && resource_policy.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CROSS_ORIGIN_ISOLATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let mut missing = Vec::new();
        if opener_policy.is_none() {
            missing.push("Cross-Origin-Opener-Policy");
        }
        if resource_policy.is_none() {
            missing.push("Cross-Origin-Resource-Policy");
        }
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CROSS_ORIGIN_ISOLATION.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Missing cross-origin isolation headers".to_owned(),
            summary: format!("Response omits {}.", missing.join(" and ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("missing={}", missing.join(",")),
            )],
            remediation: Some(
                "Set `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` where compatible."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CROSS_ORIGIN_ISOLATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_sensitive_cache(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_password = obs.forms.iter().any(|f| f.has_password_input);
    if !has_password {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SENSITIVE_CACHE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no password form present".to_owned(),
        });
        return;
    }

    let cc = header_value(http, "cache-control")
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if cc.contains("no-store") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SENSITIVE_CACHE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SENSITIVE_CACHE.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Page with password form lacks Cache-Control: no-store".to_owned(),
            summary: format!(
                "Response containing a password input returned `Cache-Control: {}` without `no-store`.",
                if cc.is_empty() { "<missing>" } else { &cc }
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("has_password_form=true;cache_control={cc}"),
            )],
            remediation: Some(
                "Send `Cache-Control: no-store` on authentication and sensitive form responses."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SENSITIVE_CACHE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_iframe_sandbox(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.iframes_without_sandbox == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_IFRAME_SANDBOX.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_IFRAME_SANDBOX.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("<iframe> elements without sandbox ({})", obs.iframes_without_sandbox),
            summary: format!(
                "{} <iframe> element(s) do not specify a `sandbox` attribute.",
                obs.iframes_without_sandbox
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("iframes_without_sandbox={}", obs.iframes_without_sandbox),
            )],
            remediation: Some(
                "Add a restrictive `sandbox` attribute to embedded <iframe> elements where possible."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_IFRAME_SANDBOX.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
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
                ("permissions-policy", "geolocation=()"),
                ("cross-origin-opener-policy", "same-origin"),
                ("cross-origin-resource-policy", "same-origin"),
            ],
        );
        let result = analyse(&snap);
        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.checks.len(), ALL_RULES.len());
        assert!(
            result
                .checks
                .iter()
                .all(|c| matches!(c, CheckStatus::Passed { .. } | CheckStatus::Skipped { .. }))
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

    #[test]
    fn flags_insecure_cookies_cors_mixed_content_and_missing_sri() {
        let mut snap = snapshot_with_headers(
            "https://example.com/",
            vec![
                ("set-cookie", "sid=abc123; Path=/"),
                ("access-control-allow-origin", "*"),
                ("access-control-allow-credentials", "true"),
            ],
        );
        let html = r#"<html><head>
            <script src="https://cdn.other.org/lib.js"></script>
            <link rel="stylesheet" href="http://insecure.example.net/app.css">
        </head><body></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_COOKIES));
        assert!(ids.contains(&RULE_CORS));
        assert!(ids.contains(&RULE_MIXED_CONTENT));
        assert!(ids.contains(&RULE_SRI));
    }

    #[test]
    fn flags_permissions_policy_version_disclosure_insecure_forms_and_secrets() {
        let mut snap = snapshot_with_headers(
            "https://example.com/",
            vec![("server", "nginx/1.24.0"), ("x-powered-by", "PHP/8.2.0")],
        );
        let html = r#"<html><head><meta name="generator" content="WordPress 6.5"></head><body>
            <form action="http://example.com/login" method="GET"><input type="password"></form>
            <script>const k = "sk_live_TESTONLY000000000000";</script>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_PERMISSIONS_POLICY));
        assert!(ids.contains(&RULE_VERSION_DISCLOSURE));
        assert!(ids.contains(&RULE_INSECURE_FORMS));
        assert!(ids.contains(&RULE_EXPOSED_SECRETS));
    }

    #[test]
    fn flags_cross_origin_isolation_sensitive_cache_and_iframe_sandbox() {
        let mut snap = snapshot_with_headers("https://example.com/", Vec::new());
        let html = r#"<html><body>
            <form action="https://example.com/login" method="POST"><input type="password"></form>
            <iframe src="https://embed.example.org/frame" title="Embed"></iframe>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_CROSS_ORIGIN_ISOLATION));
        assert!(ids.contains(&RULE_SENSITIVE_CACHE));
        assert!(ids.contains(&RULE_IFRAME_SANDBOX));
    }
}
