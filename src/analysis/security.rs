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
const RULE_CSP_OBJECT: &str = "sec.csp.missing_object_restriction";
const RULE_CSP_BASE_URI: &str = "sec.csp.missing_base_uri_restriction";
const RULE_CSP_REPORT_ONLY: &str = "sec.csp.report_only_without_enforcement";
const RULE_CSP_UNSAFE_EVAL: &str = "sec.csp.unsafe_eval";
const RULE_COOKIE_PREFIX: &str = "sec.cookies.prefix_violation";
const RULE_COOKIE_LIFETIME: &str = "sec.cookies.excessive_lifetime";
const RULE_FORM_CROSS_ORIGIN: &str = "sec.forms.cross_origin_submission";
const RULE_SENSITIVE_URL_PARAMS: &str = "sec.exposure.sensitive_url_parameters";
const RULE_HSTS_DURATION: &str = "sec.headers.hsts_duration";
const RULE_SENSITIVE_GET_FORM: &str = "sec.forms.sensitive_get_submission";
const RULE_PRIVACY_STORAGE: &str = "sec.privacy.storage_before_consent";
const RULE_PRIVACY_THIRD_PARTY_FLOW: &str = "sec.privacy.third_party_data_flow";
const RULE_CSP_FORM_ACTION: &str = "sec.csp.missing_form_action";
const RULE_CSP_WILDCARD: &str = "sec.csp.wildcard_source";
const RULE_STACK_TRACE_LEAK: &str = "sec.headers.server_error_stack_trace";
const RULE_CONSENT_ASYMMETRY: &str = "sec.privacy.consent_banner_asymmetry";
const RULE_TRACKING_NO_BANNER: &str = "sec.privacy.tracking_without_consent_banner";
const RULE_REJECT_INEFFECTIVE: &str = "sec.privacy.reject_consent_ineffective";
const RULE_SESSION_COOKIE_HTTPONLY: &str = "sec.cookies.session_missing_httponly";
const RULE_COOKIE_INVALID_DOMAIN: &str = "sec.cookies.invalid_domain_scope";
const RULE_COOKIE_INSECURE_SAMESITE: &str = "sec.cookies.insecure_samesite_none";
const RULE_COOKIE_INCONSISTENT_ATTRS: &str = "sec.cookies.inconsistent_attributes";
const RULE_PERSISTENT_IDENTIFIERS: &str = "sec.privacy.persistent_identifiers";
const RULE_LOCALHOST_LEAK: &str = "sec.deploy.localhost_leak";
const RULE_DEBUG_HEADERS: &str = "sec.headers.debug_headers";
const RULE_SOURCE_MAP_EXPOSURE: &str = "sec.deploy.source_map_exposure";

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
    RULE_CSP_OBJECT,
    RULE_CSP_BASE_URI,
    RULE_CSP_REPORT_ONLY,
    RULE_CSP_UNSAFE_EVAL,
    RULE_COOKIE_PREFIX,
    RULE_COOKIE_LIFETIME,
    RULE_FORM_CROSS_ORIGIN,
    RULE_SENSITIVE_URL_PARAMS,
    RULE_HSTS_DURATION,
    RULE_SENSITIVE_GET_FORM,
    RULE_PRIVACY_STORAGE,
    RULE_PRIVACY_THIRD_PARTY_FLOW,
    RULE_CSP_FORM_ACTION,
    RULE_CSP_WILDCARD,
    RULE_STACK_TRACE_LEAK,
    RULE_CONSENT_ASYMMETRY,
    RULE_TRACKING_NO_BANNER,
    RULE_REJECT_INEFFECTIVE,
    RULE_SESSION_COOKIE_HTTPONLY,
    RULE_COOKIE_INVALID_DOMAIN,
    RULE_COOKIE_INSECURE_SAMESITE,
    RULE_COOKIE_INCONSISTENT_ATTRS,
    RULE_PERSISTENT_IDENTIFIERS,
    RULE_LOCALHOST_LEAK,
    RULE_DEBUG_HEADERS,
    RULE_SOURCE_MAP_EXPOSURE,
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
            if matches!(
                snapshot.tls,
                CollectorOutcome::Captured { .. } | CollectorOutcome::Partial { .. }
            ) {
                let mut findings = Vec::new();
                let mut checks = Vec::new();
                check_tls_expiry(snapshot, &mut findings, &mut checks);
                for &rule_id in ALL_RULES {
                    if rule_id != RULE_TLS_EXPIRY {
                        checks.push(CheckStatus::Skipped {
                            rule_id: RuleId(rule_id.to_owned()),
                            evidence_level: EvidenceLevel::Source,
                            reason: reason.clone(),
                        });
                    }
                }
                return AnalyserResult {
                    dwarf_id: DwarfId::Sicherheits,
                    findings,
                    checks,
                };
            }
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
    check_csp_directives(http, &mut findings, &mut checks);
    check_cookie_attributes(http, &mut findings, &mut checks);
    check_session_cookie_httponly(http, &mut findings, &mut checks);
    check_sensitive_url_params(http, &mut findings, &mut checks);
    check_hsts_duration(http, uses_https, &mut findings, &mut checks);
    check_privacy_browser_signals(&snapshot.browser, &mut findings, &mut checks);
    check_stack_trace_leak(http, &mut findings, &mut checks);
    check_debug_headers(http, &mut findings, &mut checks);
    check_source_map_exposure(http, &mut findings, &mut checks);

    if let Some(doc) = obs {
        check_mixed_content(http, uses_https, doc, &mut findings, &mut checks);
        check_sri(http, doc, &mut findings, &mut checks);
        check_insecure_forms(uses_https, doc, &mut findings, &mut checks);
        check_sensitive_cache(http, doc, &mut findings, &mut checks);
        check_iframe_sandbox(doc, &mut findings, &mut checks);
        check_cross_origin_forms(http, doc, &mut findings, &mut checks);
        check_sensitive_get_forms(doc, &mut findings, &mut checks);
        check_csp_form_action(http, doc, &mut findings, &mut checks);
        check_localhost_leaks(http, doc, &mut findings, &mut checks);
    } else {
        for rule in [
            RULE_MIXED_CONTENT,
            RULE_SRI,
            RULE_INSECURE_FORMS,
            RULE_SENSITIVE_CACHE,
            RULE_IFRAME_SANDBOX,
            RULE_FORM_CROSS_ORIGIN,
            RULE_SENSITIVE_GET_FORM,
            RULE_CSP_FORM_ACTION,
            RULE_LOCALHOST_LEAK,
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
                redacted_url(&http.final_url)
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpFinalUrl,
                redacted_url(&http.final_url),
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
                    redacted_url(&http.final_url)
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
                redacted_url(&http.final_url)
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
                    redacted_url(&http.final_url)
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
                redacted_url(&http.final_url),
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
                redacted_url(&http.final_url)
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

fn parse_csp_directives(raw: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map = std::collections::BTreeMap::new();
    for part in raw.split(';') {
        let mut tokens = part.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let key = name.to_ascii_lowercase();
        let values: Vec<String> = tokens.map(str::to_ascii_lowercase).collect();
        map.entry(key).or_insert(values);
    }
    map
}

fn check_csp_directives(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let enforced = header_value(http, "content-security-policy");
    let report_only = header_value(http, "content-security-policy-report-only");

    if enforced.is_none() && report_only.is_some() {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP_REPORT_ONLY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "CSP is Report-Only without an enforced policy".to_owned(),
            summary: "Response sends `Content-Security-Policy-Report-Only` without an enforced `Content-Security-Policy` header.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "csp_report_only=true;csp_enforced=false",
            )],
            remediation: Some("Promote tested CSP directives to `Content-Security-Policy`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP_REPORT_ONLY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_REPORT_ONLY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    let Some(raw_csp) = enforced else {
        for rule in [
            RULE_CSP_OBJECT,
            RULE_CSP_BASE_URI,
            RULE_CSP_UNSAFE_EVAL,
            RULE_CSP_WILDCARD,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "Content-Security-Policy header absent".to_owned(),
            });
        }
        return;
    };

    let directives = parse_csp_directives(raw_csp);
    let default_is_none = directives
        .get("default-src")
        .is_some_and(|v| v.iter().any(|t| t == "'none'"));

    let object_missing = !default_is_none && !directives.contains_key("object-src");
    if object_missing {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP_OBJECT.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "CSP omits object-src restriction".to_owned(),
            summary: "Content-Security-Policy does not declare `object-src 'none'` (or `default-src 'none'`).".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, "csp_missing=object-src")],
            remediation: Some("Add `object-src 'none'` to block legacy plugin execution.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP_OBJECT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_OBJECT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    if directives.contains_key("base-uri") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_BASE_URI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP_BASE_URI.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "CSP omits base-uri restriction".to_owned(),
            summary: "Content-Security-Policy lacks `base-uri`, leaving relative script URLs exposed to `<base>` injection.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, "csp_missing=base-uri")],
            remediation: Some("Add `base-uri 'self'` or `base-uri 'none'` to Content-Security-Policy.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP_BASE_URI.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    check_csp_unsafe_eval(&directives, findings, checks);
    check_csp_wildcard(&directives, findings, checks);
}

fn check_csp_wildcard(
    directives: &std::collections::BTreeMap<String, Vec<String>>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let risky = [
        "default-src",
        "script-src",
        "style-src",
        "object-src",
        "connect-src",
        "frame-src",
        "form-action",
    ];
    let wildcard_dirs: Vec<&str> = risky
        .into_iter()
        .filter(|dir| {
            directives
                .get(*dir)
                .is_some_and(|vals| vals.iter().any(|t| t == "*"))
        })
        .collect();

    if wildcard_dirs.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_WILDCARD.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    let high_risk = wildcard_dirs
        .iter()
        .any(|d| matches!(*d, "default-src" | "script-src" | "object-src"));
    let joined = wildcard_dirs.join(", ");
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_CSP_WILDCARD.to_owned()),
        category: FindingCategory::Security,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: if high_risk {
            Severity::High
        } else {
            Severity::Medium
        },
        confidence: Confidence::High,
        title: format!("CSP uses wildcard `*` in {joined}"),
        summary: format!(
            "Content-Security-Policy permits wildcard `*` source in directive(s): {joined}."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("csp_wildcard={joined}"),
        )],
        remediation: Some(
            "Replace wildcard `*` CSP sources with explicit trusted origins or `'self'`."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_CSP_WILDCARD.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_csp_form_action(
    http: &HttpEvidence,
    doc: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if doc.forms.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CSP_FORM_ACTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <form> elements present".to_owned(),
        });
        return;
    }
    let Some(raw_csp) = header_value(http, "content-security-policy")
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CSP_FORM_ACTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Content-Security-Policy header absent".to_owned(),
        });
        return;
    };

    let directives = parse_csp_directives(raw_csp);
    if directives.contains_key("form-action") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_FORM_ACTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_CSP_FORM_ACTION.to_owned()),
        category: FindingCategory::Security,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Low,
        confidence: Confidence::High,
        title: "CSP omits form-action restriction on page with forms".to_owned(),
        summary: format!(
            "Document contains {} <form> element(s), but Content-Security-Policy omits `form-action`.",
            doc.forms.len()
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("forms={};csp_missing=form-action", doc.forms.len()),
        )],
        remediation: Some("Add `form-action 'self'` (plus authorised destinations) to CSP.".to_owned()),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_CSP_FORM_ACTION.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_stack_trace_leak(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.body_truncated || http.body_text.trim().is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_STACK_TRACE_LEAK.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "complete response body unavailable".to_owned(),
        });
        return;
    }

    let signatures = [
        "Traceback (most recent call last):",
        "Exception in thread ",
        "SQLSTATE[",
        "NullReferenceException",
        "Werkzeug Debugger",
        "ActionController::RoutingError",
        "Fatal error:",
    ];
    let matched = signatures
        .into_iter()
        .find(|sig| http.body_text.contains(sig));

    let Some(sig) = matched else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_STACK_TRACE_LEAK.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_STACK_TRACE_LEAK.to_owned()),
        category: FindingCategory::Security,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::High,
        confidence: Confidence::High,
        title: "Server stack trace or debug signature exposed in response".to_owned(),
        summary: format!("Response body contains server debug signature `{sig}`."),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("stack_trace_signature={sig}"),
        )],
        remediation: Some(
            "Disable framework debug pages in production and return generic error responses."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_STACK_TRACE_LEAK.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_csp_unsafe_eval(
    directives: &std::collections::BTreeMap<String, Vec<String>>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let script_vals = directives
        .get("script-src")
        .or_else(|| directives.get("default-src"));
    if script_vals.is_some_and(|v| v.iter().any(|t| t == "'unsafe-eval'")) {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CSP_UNSAFE_EVAL.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "CSP permits 'unsafe-eval'".to_owned(),
            summary:
                "Effective script policy allows `'unsafe-eval'`, enabling dynamic code evaluation."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "csp_directive='unsafe-eval'",
            )],
            remediation: Some("Remove `'unsafe-eval'` from `script-src`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CSP_UNSAFE_EVAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CSP_UNSAFE_EVAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_cookie_attributes(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const MAX_COOKIE_AGE_SECS: u64 = 34_560_000; // 400 days (RFC 6265bis)
    const TRACKING_LIFETIME_SECS: u64 = 2_592_000; // 30 days
    let cookies = http.header_values("set-cookie");
    if cookies.is_empty() {
        for rule in [
            RULE_COOKIE_PREFIX,
            RULE_COOKIE_LIFETIME,
            RULE_COOKIE_INVALID_DOMAIN,
            RULE_COOKIE_INSECURE_SAMESITE,
            RULE_COOKIE_INCONSISTENT_ATTRS,
            RULE_PERSISTENT_IDENTIFIERS,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "no Set-Cookie headers present".to_owned(),
            });
        }
        return;
    }

    let page_host = url::Url::parse(&http.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));

    let mut prefix_violations = Vec::new();
    let mut excessive_lifetimes = Vec::new();
    let mut invalid_domains = Vec::new();
    let mut insecure_samesite_none = Vec::new();
    let mut inconsistent_attrs = Vec::new();
    let mut persistent_identifiers = Vec::new();

    for raw in &cookies {
        let mut parts = raw.split(';').map(str::trim);
        let Some(name_val) = parts.next() else {
            continue;
        };
        let cookie_name = name_val.split('=').next().unwrap_or("").trim();
        let attrs: Vec<String> = parts.map(str::to_ascii_lowercase).collect();

        let has_secure = attrs.iter().any(|a| a == "secure");
        let has_domain = attrs.iter().any(|a| a.starts_with("domain="));
        let has_root_path = attrs.iter().any(|a| a == "path=/");

        let domain_val = attrs
            .iter()
            .find_map(|a| a.strip_prefix("domain="))
            .map(str::trim);

        let samesite_val = attrs
            .iter()
            .find_map(|a| a.strip_prefix("samesite="))
            .map(str::trim);

        let max_age = attrs
            .iter()
            .find_map(|a| a.strip_prefix("max-age="))
            .and_then(|s| s.trim().parse::<u64>().ok());

        // Existing checks
        if (cookie_name.starts_with("__Host-") && (!has_secure || has_domain || !has_root_path))
            || (cookie_name.starts_with("__Secure-") && !has_secure)
        {
            prefix_violations.push(cookie_name.to_owned());
        }

        if let Some(secs) = max_age.filter(|&secs| secs > MAX_COOKIE_AGE_SECS) {
            excessive_lifetimes.push(format!("{cookie_name} ({secs}s)"));
        }

        if let (Some(domain), Some(host)) = (domain_val, &page_host) {
            let domain = domain.trim_start_matches('.');
            if !host.ends_with(domain) && domain != host {
                invalid_domains.push(format!("{cookie_name} (domain={domain})"));
            }
        }

        // New: insecure SameSite=None
        if samesite_val == Some("none") && !has_secure {
            insecure_samesite_none.push(cookie_name.to_owned());
        }

        // New: inconsistent attributes (SameSite=Strict without Secure is weak)
        if samesite_val == Some("strict") && !has_secure {
            inconsistent_attrs.push(format!("{cookie_name} (SameSite=Strict without Secure)"));
        }

        // New: persistent tracking identifiers
        let is_tracking_name = cookie_name.to_ascii_lowercase().contains("_ga")
            || cookie_name.to_ascii_lowercase().contains("_gid")
            || cookie_name.to_ascii_lowercase().contains("_fbp")
            || cookie_name.to_ascii_lowercase().starts_with("_pk")
            || cookie_name.to_ascii_lowercase().starts_with("__utm");

        if let Some(secs) =
            max_age.filter(|&secs| is_tracking_name && secs > TRACKING_LIFETIME_SECS)
        {
            let rounded_days = secs / 86_400
                + u64::from(
                    secs % 86_400 > 43_200 || (secs % 86_400 == 43_200 && (secs / 86_400) % 2 == 1),
                );
            persistent_identifiers.push(format!("{cookie_name} ({rounded_days}d)"));
        }
    }

    emit_prefix_violations(&prefix_violations, findings, checks);
    emit_excessive_lifetimes(&excessive_lifetimes, findings, checks);
    emit_invalid_domains(&invalid_domains, findings, checks);
    emit_insecure_samesite_none(&insecure_samesite_none, findings, checks);
    emit_inconsistent_attrs(&inconsistent_attrs, findings, checks);
    emit_persistent_identifiers(&persistent_identifiers, findings, checks);
}

fn emit_prefix_violations(
    prefix_violations: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if prefix_violations.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIE_PREFIX.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIE_PREFIX.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Cookie prefix contract violated ({})", prefix_violations.len()),
            summary: format!(
                "Cookies using `__Host-` or `__Secure-` prefix violate required attributes: {}.",
                prefix_violations.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("prefix_violations={}", prefix_violations.join(",")),
            )],
            remediation: Some(
                "Ensure `__Secure-` cookies set `Secure` and `__Host-` cookies set `Secure; Path=/` without `Domain`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIE_PREFIX.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn emit_excessive_lifetimes(
    excessive_lifetimes: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if excessive_lifetimes.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIE_LIFETIME.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIE_LIFETIME.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Cookies exceed 400-day Max-Age cap ({})",
                excessive_lifetimes.len()
            ),
            summary: format!(
                "Set-Cookie declares Max-Age > 400 days: {}.",
                excessive_lifetimes.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("excessive_cookie_lifetimes={}", excessive_lifetimes.len()),
            )],
            remediation: Some("Cap cookie lifetimes to 400 days (34,560,000s) or less.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIE_LIFETIME.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn emit_invalid_domains(
    invalid_domains: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if invalid_domains.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIE_INVALID_DOMAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIE_INVALID_DOMAIN.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Cookies with invalid domain scope ({})",
                invalid_domains.len()
            ),
            summary: format!(
                "Set-Cookie declares Domain attribute not matching page host: {}.",
                invalid_domains.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("invalid_domain_scopes={}", invalid_domains.len()),
            )],
            remediation: Some(
                "Ensure cookie Domain attribute matches or is a parent of page host.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIE_INVALID_DOMAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn emit_insecure_samesite_none(
    insecure_samesite_none: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if insecure_samesite_none.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIE_INSECURE_SAMESITE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIE_INSECURE_SAMESITE.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "SameSite=None cookies without Secure ({})",
                insecure_samesite_none.len()
            ),
            summary: format!(
                "Cookies with SameSite=None must set Secure attribute: {}.",
                insecure_samesite_none.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!(
                    "insecure_samesite_none={}",
                    insecure_samesite_none.join(",")
                ),
            )],
            remediation: Some("Add Secure attribute to all SameSite=None cookies.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIE_INSECURE_SAMESITE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn emit_inconsistent_attrs(
    inconsistent_attrs: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if inconsistent_attrs.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_COOKIE_INCONSISTENT_ATTRS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_COOKIE_INCONSISTENT_ATTRS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Cookies with inconsistent attributes ({})",
                inconsistent_attrs.len()
            ),
            summary: format!(
                "Cookies declare contradictory attributes: {}.",
                inconsistent_attrs.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("inconsistent_attrs={}", inconsistent_attrs.len()),
            )],
            remediation: Some(
                "Add Secure to SameSite=Strict cookies for consistent security.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_COOKIE_INCONSISTENT_ATTRS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn emit_persistent_identifiers(
    persistent_identifiers: &[String],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if persistent_identifiers.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PERSISTENT_IDENTIFIERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PERSISTENT_IDENTIFIERS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Persistent tracking identifiers detected ({})",
                persistent_identifiers.len()
            ),
            summary: format!(
                "Cookies with tracking name patterns and long lifetimes (>30d): {}.",
                persistent_identifiers.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("persistent_trackers={}", persistent_identifiers.len()),
            )],
            remediation: Some(
                "Reduce tracking cookie lifetimes or disclose tracking practices.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PERSISTENT_IDENTIFIERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_cross_origin_forms(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(page_host) = url::Url::parse(&http.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    else {
        return;
    };

    let cross_origin: Vec<&str> = obs
        .forms
        .iter()
        .filter_map(|f| f.action.as_deref())
        .filter(|act| {
            url::Url::parse(act)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|h| h != page_host)
        })
        .collect();

    if cross_origin.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FORM_CROSS_ORIGIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FORM_CROSS_ORIGIN.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Forms submitting to external origins ({})", cross_origin.len()),
            summary: format!(
                "{} <form> element(s) submit to a different host than `{page_host}`.",
                cross_origin.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("cross_origin_forms={}", cross_origin.len()),
            )],
            remediation: Some(
                "Verify external form action targets are authorised and covered by CSP `form-action`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FORM_CROSS_ORIGIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn redacted_url(raw: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(raw) {
        if parsed.query().is_some() {
            parsed.set_query(Some("redacted"));
        }
        return parsed.to_string();
    }
    raw.split('?').next().unwrap_or(raw).to_owned()
}

fn check_sensitive_url_params(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const SENSITIVE_KEYS: &[&str] = &[
        "token",
        "access_token",
        "auth",
        "secret",
        "api_key",
        "apikey",
        "password",
        "passwd",
        "session_id",
        "sid",
    ];
    let Ok(parsed) = url::Url::parse(&http.final_url) else {
        return;
    };
    let matched: Vec<String> = parsed
        .query_pairs()
        .filter_map(|(k, _)| {
            let lower = k.to_ascii_lowercase();
            SENSITIVE_KEYS.contains(&lower.as_str()).then_some(lower)
        })
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SENSITIVE_URL_PARAMS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SENSITIVE_URL_PARAMS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Sensitive parameter names detected in URL query string".to_owned(),
            summary: format!(
                "Final URL contains sensitive query parameter key(s): {} (values redacted).",
                matched.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("sensitive_query_keys={}", matched.join(",")),
            )],
            remediation: Some(
                "Move credentials, tokens, and session identifiers out of URL query strings into headers or POST bodies."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SENSITIVE_URL_PARAMS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_hsts_duration(
    http: &HttpEvidence,
    uses_https: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const MIN_RECOMMENDED_HSTS_SECS: u64 = 15_552_000; // 180 days
    if !uses_https {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HSTS_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "target did not use HTTPS".to_owned(),
        });
        return;
    }
    let Some(hsts) = header_value(http, "strict-transport-security") else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HSTS_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Strict-Transport-Security header absent".to_owned(),
        });
        return;
    };
    let max_age = hsts.split(';').map(str::trim).find_map(|part| {
        part.to_ascii_lowercase()
            .strip_prefix("max-age=")
            .and_then(|v| v.trim().parse::<u64>().ok())
    });

    if let Some(secs) = max_age
        && secs > 0
        && secs < MIN_RECOMMENDED_HSTS_SECS
    {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HSTS_DURATION.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Short HSTS max-age ({secs}s < 180 days)"),
            summary: format!(
                "Strict-Transport-Security `max-age={secs}` is shorter than the recommended 180-day (15,552,000s) minimum."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("hsts_max_age={secs}"),
            )],
            remediation: Some(
                "Increase HSTS `max-age` to at least `15552000` (180 days) or `31536000` (1 year)."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HSTS_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HSTS_DURATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_sensitive_get_forms(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let get_pwd_forms = obs
        .forms
        .iter()
        .filter(|f| f.has_password_input && f.method.as_deref().unwrap_or("get") == "get")
        .count();

    if get_pwd_forms == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SENSITIVE_GET_FORM.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SENSITIVE_GET_FORM.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Password form using HTTP GET method ({get_pwd_forms})"),
            summary: format!(
                "{get_pwd_forms} <form> with a password input submits via GET (explicit or default), exposing credentials in URLs and logs."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("password_get_forms={get_pwd_forms}"),
            )],
            remediation: Some("Set `method=\"POST\"` on all authentication and password forms.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SENSITIVE_GET_FORM.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn is_local_or_dev_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "localhost"
        || h == "127.0.0.1"
        || h == "0.0.0.0"
        || h == "::1"
        || h == "[::1]"
        || h.rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "local" || tld == "localhost")
}

fn check_localhost_leaks(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let page_host = url::Url::parse(&http.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned));
    if page_host.as_deref().is_some_and(is_local_or_dev_host) {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LOCALHOST_LEAK.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "target host itself is a local or development host".to_owned(),
        });
        return;
    }

    let mut leaks = Vec::new();
    let mut inspect = |kind: &str, raw: &str| {
        if leaks.len() >= 10 {
            return;
        }
        if let Ok(parsed) = url::Url::parse(raw.trim())
            && let Some(host) = parsed.host_str()
            && is_local_or_dev_host(host)
        {
            leaks.push(format!("{kind}: {}", parsed.as_str()));
        }
    };

    for script in &obs.scripts {
        if let Some(src) = &script.src {
            inspect("script", src);
        }
    }
    for sheet in &obs.stylesheets {
        inspect("stylesheet", &sheet.href);
    }
    for img in &obs.images {
        if let Some(src) = &img.src {
            inspect("image", src);
        }
    }
    for form in &obs.forms {
        if let Some(action) = &form.action {
            inspect("form", action);
        }
    }
    for link in &obs.links {
        inspect("link", &link.href);
    }

    if leaks.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LOCALHOST_LEAK.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LOCALHOST_LEAK.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LOCALHOST_LEAK.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!(
                "Local/development URLs leaked into public HTML ({})",
                leaks.len()
            ),
            summary: format!(
                "Public page `{}` references {} local/development endpoint(s) (for example `{}`), indicating a misconfigured build or deployment base URL.",
                http.final_url,
                leaks.len(),
                leaks[0]
            ),
            evidence_refs: leaks
                .iter()
                .take(4)
                .map(|entry| EvidenceRef::new(EvidenceSource::HttpBody, entry.clone()))
                .collect(),
            remediation: Some(
                "Replace `localhost`, `127.0.0.1`, and `.local` URLs with production origins or relative paths in build-time environment variables."
                    .to_owned(),
            ),
        });
    }
}

fn check_debug_headers(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const DEBUG_HEADER_NAMES: &[&str] = &[
        "x-debug-token",
        "x-debug-token-link",
        "x-symfony-profiler",
        "x-aspnet-version",
        "x-aspnetmvc-version",
    ];
    let exposed: Vec<String> = http
        .headers
        .iter()
        .filter(|h| {
            let lower = h.name.to_ascii_lowercase();
            DEBUG_HEADER_NAMES.contains(&lower.as_str())
        })
        .map(|h| format!("{}: {}", h.name, h.value))
        .collect();

    if exposed.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DEBUG_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DEBUG_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DEBUG_HEADERS.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Debug/profiler response headers exposed ({})", exposed.len()),
            summary: format!(
                "HTTP response exposes framework profiler or debug header(s) (for example `{}`).",
                exposed[0]
            ),
            evidence_refs: exposed
                .iter()
                .take(4)
                .map(|entry| EvidenceRef::new(EvidenceSource::HttpHeaders, entry.clone()))
                .collect(),
            remediation: Some(
                "Disable development profilers and strip debug headers (`X-Debug-Token*`, `X-AspNet-Version`) in production."
                    .to_owned(),
            ),
        });
    }
}

fn check_source_map_exposure(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut matches = Vec::new();
    for line in http.body_text.lines() {
        if let Some(idx) = line.find("sourceMappingURL=") {
            let url_part = line[idx + "sourceMappingURL=".len()..]
                .trim()
                .trim_end_matches("*/")
                .trim();
            if !url_part.is_empty() && !url_part.starts_with("data:") {
                matches.push(url_part.to_owned());
                if matches.len() >= 4 {
                    break;
                }
            }
        }
    }

    if matches.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SOURCE_MAP_EXPOSURE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SOURCE_MAP_EXPOSURE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOURCE_MAP_EXPOSURE.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Public source map reference(s) exposed ({})", matches.len()),
            summary: format!(
                "Captured response references external source map `{}` via `sourceMappingURL`, which can expose unminified source code.",
                matches[0]
            ),
            evidence_refs: matches
                .iter()
                .map(|m| EvidenceRef::new(EvidenceSource::HttpBody, format!("sourceMappingURL={m}")))
                .collect(),
            remediation: Some(
                "Restrict `.map` files to private error-tracking uploads or strip `sourceMappingURL` comments from public builds."
                    .to_owned(),
            ),
        });
    }
}

fn check_privacy_browser_signals(
    browser: &CollectorOutcome<crate::domain::BrowserEvidence>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let data = match browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Skipped { reason } => {
            for rule in [
                RULE_PRIVACY_STORAGE,
                RULE_PRIVACY_THIRD_PARTY_FLOW,
                RULE_CONSENT_ASYMMETRY,
                RULE_TRACKING_NO_BANNER,
                RULE_REJECT_INEFFECTIVE,
            ] {
                checks.push(CheckStatus::Skipped {
                    rule_id: RuleId((*rule).to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                    reason: reason.clone(),
                });
            }
            return;
        }
        CollectorOutcome::Failed { error } => {
            for rule in [
                RULE_PRIVACY_STORAGE,
                RULE_PRIVACY_THIRD_PARTY_FLOW,
                RULE_CONSENT_ASYMMETRY,
                RULE_TRACKING_NO_BANNER,
                RULE_REJECT_INEFFECTIVE,
            ] {
                checks.push(CheckStatus::Skipped {
                    rule_id: RuleId((*rule).to_owned()),
                    evidence_level: EvidenceLevel::Rendered,
                    reason: error.clone(),
                });
            }
            return;
        }
    };

    if let Some(storage) = &data.storage_summary {
        let total = storage.local_storage_keys
            + storage.session_storage_keys
            + storage.document_cookie_count;
        if total > 0 {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_PRIVACY_STORAGE.to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Rendered,
                kind: FindingKind::Deterministic,
                severity: Severity::Info,
                confidence: Confidence::High,
                title: format!("Client-side storage/cookies populated before consent ({total})"),
                summary: format!(
                    "Fresh browser session observed {} localStorage key(s), {} sessionStorage key(s), and {} document.cookie entry(ies) prior to consent interaction.",
                    storage.local_storage_keys,
                    storage.session_storage_keys,
                    storage.document_cookie_count
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!(
                        "local_storage={};session_storage={};doc_cookies={}",
                        storage.local_storage_keys,
                        storage.session_storage_keys,
                        storage.document_cookie_count
                    ),
                )],
                remediation: Some(
                    "Verify whether observed storage keys and cookies are strictly necessary or require prior consent."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_PRIVACY_STORAGE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_PRIVACY_STORAGE.to_owned()),
                evidence_level: EvidenceLevel::Rendered,
            });
        }
    } else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_PRIVACY_STORAGE.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "browser storage summary unavailable".to_owned(),
        });
    }

    check_privacy_tracker_requests(data, findings, checks);
}

fn check_privacy_tracker_requests(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const TRACKER_HOSTS: &[&str] = &[
        "googletagmanager.com",
        "google-analytics.com",
        "doubleclick.net",
        "connect.facebook.net",
        "hotjar.com",
        "clarity.ms",
        "segment.com",
        "mixpanel.com",
    ];
    let tracker_hits: Vec<&str> = data
        .resources
        .iter()
        .filter_map(|r| {
            let lower = r.url.to_ascii_lowercase();
            TRACKER_HOSTS.iter().copied().find(|h| lower.contains(h))
        })
        .collect();
    if tracker_hits.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PRIVACY_THIRD_PARTY_FLOW.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        let mut unique: Vec<&str> = tracker_hits;
        unique.sort_unstable();
        unique.dedup();
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PRIVACY_THIRD_PARTY_FLOW.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Third-party tracking requests before consent ({})",
                unique.len()
            ),
            summary: format!(
                "Fresh browser session contacted third-party tracking/analytics origin(s): {}.",
                unique.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("tracking_origins={}", unique.join(",")),
            )],
            remediation: Some(
                "Gate non-essential third-party tracking requests behind explicit user consent."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PRIVACY_THIRD_PARTY_FLOW.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    check_consent_banner_signals(data, findings, checks);
}

fn check_session_cookie_httponly(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let cookies = http.header_values("set-cookie");
    if cookies.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SESSION_COOKIE_HTTPONLY.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no Set-Cookie headers present".to_owned(),
        });
        return;
    }

    let missing: Vec<String> = cookies
        .iter()
        .filter_map(|raw| {
            let name = raw.split(';').next()?.split('=').next()?.trim();
            let low_name = name.to_ascii_lowercase();
            let looks_session = [
                "session",
                "sess",
                "sid",
                "jsessionid",
                "phpsessid",
                "auth",
                "token",
                "jwt",
            ]
            .iter()
            .any(|kw| low_name.contains(kw));
            let has_httponly = raw
                .split(';')
                .skip(1)
                .any(|attr| attr.trim().eq_ignore_ascii_case("httponly"));
            (looks_session && !has_httponly).then(|| name.to_owned())
        })
        .collect();

    if missing.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SESSION_COOKIE_HTTPONLY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SESSION_COOKIE_HTTPONLY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Session-like cookies missing HttpOnly ({})", missing.len()),
            summary: format!(
                "Set-Cookie for session/auth cookie(s) omits `HttpOnly`: {}.",
                missing.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("session_cookies_missing_httponly={}", missing.join(",")),
            )],
            remediation: Some(
                "Add `HttpOnly` to all session and authentication cookies to mitigate XSS theft."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SESSION_COOKIE_HTTPONLY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_consent_banner_signals(
    data: &crate::domain::BrowserEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(banner) = data.consent_banner.as_ref() else {
        for rule in [
            RULE_CONSENT_ASYMMETRY,
            RULE_TRACKING_NO_BANNER,
            RULE_REJECT_INEFFECTIVE,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason: "consent banner probe unavailable".to_owned(),
            });
        }
        return;
    };

    if !banner.banner_detected {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CONSENT_ASYMMETRY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "no consent banner detected".to_owned(),
        });
    } else if banner.has_accept_action && !banner.has_reject_action {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CONSENT_ASYMMETRY.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: "Consent banner offers Accept without visible Reject option".to_owned(),
            summary: "Observed a visible consent banner with an accept button but no reject/decline button.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                "consent_banner=detected;accept=true;reject=false",
            )],
            remediation: Some(
                "Provide an equally prominent Reject/Essential-Only button alongside Accept."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CONSENT_ASYMMETRY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CONSENT_ASYMMETRY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    let has_cookies_or_storage = data
        .storage_summary
        .as_ref()
        .is_some_and(|s| s.document_cookie_count > 0 || s.local_storage_keys > 0);
    if !banner.banner_detected && has_cookies_or_storage {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TRACKING_NO_BANNER.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "Cookies or localStorage populated without visible consent banner".to_owned(),
            summary: "Fresh session populated cookies or localStorage without any detected consent banner (not necessarily tracking).".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                "consent_banner=absent;storage_or_cookies=present",
            )],
            remediation: Some(
                "Verify whether non-essential cookies/storage require prior user consent under GDPR/ePrivacy."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TRACKING_NO_BANNER.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TRACKING_NO_BANNER.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    check_reject_consent_probe(banner, data.storage_summary.as_ref(), findings, checks);
}

fn check_reject_consent_probe(
    banner: &crate::domain::ConsentBannerObs,
    pre_storage: Option<&crate::domain::PrivacyStorageSummary>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if banner.banner_dismissed_after_reject.is_none() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_REJECT_INEFFECTIVE.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
            reason: "no clickable reject consent action observed".to_owned(),
        });
        return;
    }

    let pre_cookies = pre_storage.map_or(0, |s| s.document_cookie_count);
    let pre_ls = pre_storage.map_or(0, |s| s.local_storage_keys);
    let cookies_grew = banner
        .cookies_after_reject
        .is_some_and(|after| after > pre_cookies);
    let ls_grew = banner
        .local_storage_after_reject
        .is_some_and(|after| after > pre_ls);
    let not_dismissed = banner.banner_dismissed_after_reject == Some(false);

    if not_dismissed || cookies_grew || ls_grew {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REJECT_INEFFECTIVE.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Behavioural,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Reject consent action failed to suppress storage or dismiss banner".to_owned(),
            summary: format!(
                "Clicking Reject produced dismissed={:?}, cookies_before={pre_cookies} -> after={:?}, local_storage_before={pre_ls} -> after={:?}.",
                banner.banner_dismissed_after_reject,
                banner.cookies_after_reject,
                banner.local_storage_after_reject,
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "reject_probe=attempted;dismissed={:?};cookies_after={:?};ls_after={:?}",
                    banner.banner_dismissed_after_reject,
                    banner.cookies_after_reject,
                    banner.local_storage_after_reject,
                ),
            )],
            remediation: Some(
                "Ensure the Reject action immediately dismisses the banner without writing tracking cookies or localStorage."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REJECT_INEFFECTIVE.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REJECT_INEFFECTIVE.to_owned()),
            evidence_level: EvidenceLevel::Behavioural,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CaaLookupOutcome;
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
                    not_before_unix_secs: Some(1_700_000_000),
                    not_after_unix_secs: 2_000_000_000,
                    days_until_expiry: 90,
                    san_entries: vec!["example.com".to_owned()],
                    signature_algorithm: Some("sha256WithRSAEncryption".to_owned()),
                    public_key_algorithm: Some("rsaEncryption".to_owned()),
                    self_signed: false,
                    caa_records: Vec::new(),
                    caa_query_succeeded: false,
                    caa_lookup_outcome: CaaLookupOutcome::NotAttempted,
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
                (
                    "content-security-policy",
                    "default-src 'self'; object-src 'none'; base-uri 'self'",
                ),
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

    #[test]
    fn flags_csp_directives_cookie_prefixes_cross_origin_forms_and_sensitive_url_params() {
        let mut snap = snapshot_with_headers(
            "https://example.com/callback?access_token=REDACTED_TEST_VAL",
            vec![
                (
                    "content-security-policy",
                    "default-src 'self'; script-src 'self' 'unsafe-eval'",
                ),
                ("set-cookie", "__Host-sid=abc; Path=/app; Max-Age=40000000"),
            ],
        );
        let html = r#"<html><body>
            <form action="https://other.example.net/submit" method="POST"></form>
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
        assert!(ids.contains(&RULE_CSP_OBJECT));
        assert!(ids.contains(&RULE_CSP_BASE_URI));
        assert!(ids.contains(&RULE_CSP_UNSAFE_EVAL));
        assert!(ids.contains(&RULE_COOKIE_PREFIX));
        assert!(ids.contains(&RULE_COOKIE_LIFETIME));
        assert!(ids.contains(&RULE_FORM_CROSS_ORIGIN));
        assert!(ids.contains(&RULE_SENSITIVE_URL_PARAMS));
        // Ensure sensitive query parameter value is never reproduced in findings
        assert!(
            result
                .findings
                .iter()
                .all(|f| !f.summary.contains("REDACTED_TEST_VAL"))
        );
    }

    #[test]
    fn flags_short_hsts_duration_and_sensitive_get_form() {
        let mut snap = snapshot_with_headers(
            "https://example.com/",
            vec![("strict-transport-security", "max-age=86400")],
        );
        let html = r#"<html><body>
            <form action="https://example.com/login" method="GET"><input type="password"></form>
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
        assert!(ids.contains(&RULE_HSTS_DURATION));
        assert!(ids.contains(&RULE_SENSITIVE_GET_FORM));
    }

    #[test]
    fn flags_privacy_storage_and_third_party_tracking_before_consent() {
        let mut snap = snapshot_with_headers("https://example.com/", Vec::new());
        snap.browser = CollectorOutcome::Captured {
            data: crate::domain::BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                storage_summary: Some(crate::domain::PrivacyStorageSummary {
                    local_storage_keys: 2,
                    session_storage_keys: 0,
                    document_cookie_count: 1,
                }),
                resources: vec![crate::domain::ResourceTimingObs {
                    url: "https://www.googletagmanager.com/gtm.js".to_owned(),
                    resource_type: "script".to_owned(),
                    ..crate::domain::ResourceTimingObs::default()
                }],
                ..crate::domain::BrowserEvidence::default()
            },
        };
        let result = analyse(&snap);
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_PRIVACY_STORAGE));
        assert!(ids.contains(&RULE_PRIVACY_THIRD_PARTY_FLOW));
    }

    #[test]
    fn flags_csp_wildcard_missing_form_action_and_stack_trace_leak() {
        let mut snap = snapshot_with_headers(
            "https://example.com/",
            vec![(
                "content-security-policy",
                "default-src *; object-src 'none'",
            )],
        );
        let html = "<html><body><form action=\"/go\"><input type=\"text\"></form><pre>Traceback (most recent call last):</pre></body></html>";
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let obs = DocumentObservations::from_html(html);
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_CSP_WILDCARD));
        assert!(ids.contains(&RULE_CSP_FORM_ACTION));
        assert!(ids.contains(&RULE_STACK_TRACE_LEAK));
    }

    #[test]
    fn flags_consent_banner_asymmetry_and_tracking_without_banner() {
        let mut snap = snapshot_with_headers("https://example.com/", Vec::new());
        snap.browser = CollectorOutcome::Captured {
            data: crate::domain::BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                consent_banner: Some(crate::domain::ConsentBannerObs {
                    banner_detected: true,
                    has_accept_action: true,
                    has_reject_action: false,
                    ..crate::domain::ConsentBannerObs::default()
                }),
                ..crate::domain::BrowserEvidence::default()
            },
        };
        let res = analyse(&snap);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_CONSENT_ASYMMETRY)
        );

        if let CollectorOutcome::Captured { data } = &mut snap.browser {
            data.consent_banner = Some(crate::domain::ConsentBannerObs {
                banner_detected: false,
                has_accept_action: false,
                has_reject_action: false,
                ..crate::domain::ConsentBannerObs::default()
            });
            data.storage_summary = Some(crate::domain::PrivacyStorageSummary {
                local_storage_keys: 1,
                session_storage_keys: 0,
                document_cookie_count: 2,
            });
        }
        let res2 = analyse(&snap);
        assert!(
            res2.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_TRACKING_NO_BANNER)
        );
    }

    #[test]
    fn flags_session_cookie_missing_httponly() {
        let snap = snapshot_with_headers(
            "https://example.com/",
            vec![("set-cookie", "session_id=abc123; Secure; Path=/")],
        );
        let res = analyse(&snap);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_SESSION_COOKIE_HTTPONLY)
        );
    }

    #[test]
    fn flags_ineffective_reject_consent_button() {
        let mut snap = snapshot_with_headers("https://example.com/", Vec::new());
        snap.browser = CollectorOutcome::Captured {
            data: crate::domain::BrowserEvidence {
                final_url: "https://example.com/".to_owned(),
                consent_banner: Some(crate::domain::ConsentBannerObs {
                    banner_detected: true,
                    has_accept_action: true,
                    has_reject_action: true,
                    banner_dismissed_after_reject: Some(false),
                    cookies_after_reject: Some(1),
                    local_storage_after_reject: Some(1),
                }),
                ..crate::domain::BrowserEvidence::default()
            },
        };
        let res = analyse(&snap);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_REJECT_INEFFECTIVE)
        );
    }

    #[test]
    fn flags_localhost_leaks_on_public_target_and_skips_on_local_target() {
        let mut snap = snapshot_with_headers("https://example.com/", Vec::new());
        let html = r#"<!doctype html><html><body>
            <script src="http://localhost:3000/bundle.js"></script>
            <a href="http://127.0.0.1:8080/admin">Admin</a>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let result = analyse_with_document(&snap, Some(&obs));
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_LOCALHOST_LEAK)
        );

        let local_target =
            AuditTarget::parse("http://127.0.0.1:8080/", TargetPolicy::AllowPrivate).unwrap();
        let mut local_snap = EvidenceSnapshot {
            target: local_target,
            ..snap
        };
        if let CollectorOutcome::Captured { data } = &mut local_snap.http {
            data.final_url = "http://127.0.0.1:8080/".to_owned();
        }
        let local_res = analyse_with_document(&local_snap, Some(&obs));
        assert!(local_res.checks.iter().any(|c| matches!(
            c,
            CheckStatus::Skipped { rule_id, .. } if rule_id.0 == RULE_LOCALHOST_LEAK
        )));
    }

    #[test]
    fn flags_debug_headers_and_source_map_exposure() {
        let mut snap =
            snapshot_with_headers("https://example.com/", vec![("X-Debug-Token", "abc123")]);
        let html = "<html><body><script>console.log(1);\n//# sourceMappingURL=app.js.map</script></body></html>";
        let obs = DocumentObservations::from_html(html);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_text = html.to_owned();
            data.body_bytes = html.len();
        }
        let res = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_DEBUG_HEADERS));
        assert!(ids.contains(&RULE_SOURCE_MAP_EXPOSURE));
    }

    #[test]
    fn expired_tls_partial_without_http_still_emits_critical_expiry_finding() {
        use crate::domain::{AuditTarget, CaaLookupOutcome, TargetPolicy, TlsEvidence};

        let target = AuditTarget::parse("https://expired.example/", TargetPolicy::PublicOnly)
            .expect("target");
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Failed {
                error: "HTTP request failed: certificate expired".to_owned(),
            },
            tls: CollectorOutcome::Partial {
                data: TlsEvidence {
                    subject: "CN=expired.example".to_owned(),
                    issuer: "CN=Example CA".to_owned(),
                    not_before_unix_secs: Some(1_600_000_000),
                    not_after_unix_secs: 1_699_800_000,
                    days_until_expiry: -2,
                    san_entries: vec!["expired.example".to_owned()],
                    signature_algorithm: None,
                    public_key_algorithm: None,
                    self_signed: false,
                    caa_records: Vec::new(),
                    caa_query_succeeded: false,
                    caa_lookup_outcome: CaaLookupOutcome::NotAttempted,
                },
                warnings: vec!["captured via diagnostic probe".to_owned()],
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let res = analyse(&snap);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_TLS_EXPIRY && f.severity == Severity::Critical),
            "expected critical sec.tls.certificate_expiry finding, got: {:?}",
            res.findings
        );
    }
}
