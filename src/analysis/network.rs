//! `NetzZwerg` — HTTP reliability, status, and redirect-chain checks.

use std::collections::HashSet;

use crate::analysis::document::DocumentObservations;
use crate::analysis::{header_value, require_http, skip_all};
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSnapshot,
    EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind, HttpEvidence,
    RuleId, Severity,
};

const RULE_HTTP_STATUS: &str = "netz.http.status_error";
const RULE_REDIRECT_CHAIN: &str = "netz.http.redirect_chain";
const RULE_REDIRECT_LOOP: &str = "netz.http.redirect_loop";
const RULE_SOFT_ERROR: &str = "netz.http.soft_error";
const RULE_LINK_HYGIENE: &str = "netz.links.hygiene";
const RULE_URL_UPPERCASE: &str = "netz.url.uppercase_path";
const RULE_URL_QUERY_HYGIENE: &str = "netz.url.query_hygiene";
const RULE_URL_DEEP_PATH: &str = "netz.url.deep_path";
const RULE_REDIRECT_HTTPS_DOWNGRADE: &str = "netz.redirect.https_downgrade";
const RULE_REDIRECT_CROSS_ORIGIN: &str = "netz.redirect.cross_origin_chain";
const RULE_ETAG_VALIDATION: &str = "netz.http.etag_validation";
const RULE_RATE_LIMITING: &str = "netz.http.rate_limiting_observed";
const RULE_CONTENT_TYPE_MISMATCH: &str = "netz.http.content_type_mismatch";
const RULE_INVALID_CONTENT_LENGTH: &str = "netz.http.invalid_content_length";
const RULE_RANGE_REQUEST_SUPPORT: &str = "netz.http.range_request_support";
const RULE_CHARSET_MISMATCH: &str = "netz.http.character_encoding_mismatch";
const RULE_INVALID_CONTENT_ENCODING: &str = "netz.http.invalid_content_encoding";
const RULE_INTERMEDIARY_ERROR: &str = "netz.http.intermediary_error_response";

const ALL_RULES: &[&str] = &[
    RULE_HTTP_STATUS,
    RULE_REDIRECT_CHAIN,
    RULE_REDIRECT_LOOP,
    RULE_SOFT_ERROR,
    RULE_LINK_HYGIENE,
    RULE_URL_UPPERCASE,
    RULE_URL_QUERY_HYGIENE,
    RULE_URL_DEEP_PATH,
    RULE_REDIRECT_HTTPS_DOWNGRADE,
    RULE_REDIRECT_CROSS_ORIGIN,
    RULE_ETAG_VALIDATION,
    RULE_RATE_LIMITING,
    RULE_CONTENT_TYPE_MISMATCH,
    RULE_INVALID_CONTENT_LENGTH,
    RULE_RANGE_REQUEST_SUPPORT,
    RULE_CHARSET_MISMATCH,
    RULE_INVALID_CONTENT_ENCODING,
    RULE_INTERMEDIARY_ERROR,
];

/// Random-URL baseline and confirmation re-fetch outcome used to detect soft-404 responses
/// without fragile title/heading substring heuristics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Soft404Baseline {
    /// Synthetic non-existent URL probed first.
    pub probe_url: String,
    /// HTTP status code returned by `probe_url`.
    pub probe_status: u16,
    /// Distinct-shingle `SimHash` of the primary content returned by `probe_url`, if sufficient text.
    pub probe_simhash: Option<u64>,
    /// Response body byte length returned by `probe_url`.
    pub probe_body_bytes: usize,
    /// Second synthetic non-existent URL fetched to confirm catch-all soft-404 behaviour.
    pub confirmation_url: Option<String>,
    /// HTTP status code returned by `confirmation_url`.
    pub confirmation_status: Option<u16>,
    /// Distinct-shingle `SimHash` returned by `confirmation_url`.
    pub confirmation_simhash: Option<u64>,
}

impl Soft404Baseline {
    /// Returns `true` when both the initial random-URL probe and the confirmation re-fetch
    /// returned HTTP 200 with a consistent fallback template.
    #[must_use]
    pub fn is_confirmed_soft_404_origin(&self) -> bool {
        if self.probe_status != 200 || self.confirmation_status != Some(200) {
            return false;
        }
        match (self.probe_simhash, self.confirmation_simhash) {
            (Some(a), Some(b)) => (a ^ b).count_ones() <= 6,
            (None, None) => true,
            _ => false,
        }
    }

    /// Returns `true` when the audited page matches the confirmed random-URL soft-404 template.
    #[must_use]
    pub fn matches_page(&self, obs: &DocumentObservations, body_bytes: usize) -> bool {
        if !self.is_confirmed_soft_404_origin() {
            return false;
        }
        let page_simhash = crate::analysis::graph::compute_text_simhash(&obs.main_content_text);
        match (self.probe_simhash, page_simhash) {
            (Some(base), Some(page)) => (base ^ page).count_ones() <= 6,
            (None, None) => {
                let max_bytes = self.probe_body_bytes.max(body_bytes);
                if max_bytes == 0 {
                    return true;
                }
                let diff = self.probe_body_bytes.abs_diff(body_bytes);
                diff * 100 <= max_bytes * 15
            }
            _ => false,
        }
    }
}

/// Evaluates HTTP response status and redirect-chain hygiene over `snapshot`.
#[must_use]
pub fn analyse(snapshot: &EvidenceSnapshot) -> AnalyserResult {
    analyse_with_document(snapshot, None)
}

/// Evaluates HTTP reliability, redirect integrity, soft-error heuristics, and link hygiene.
#[must_use]
pub fn analyse_with_document(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
) -> AnalyserResult {
    analyse_with_baseline(snapshot, obs, None)
}

/// Evaluates HTTP reliability, redirect integrity, baseline-verified soft-404s, and link hygiene.
#[must_use]
pub fn analyse_with_baseline(
    snapshot: &EvidenceSnapshot,
    obs: Option<&DocumentObservations>,
    soft_404_baseline: Option<&Soft404Baseline>,
) -> AnalyserResult {
    let http = match require_http(snapshot) {
        Ok(http) => http,
        Err(reason) => {
            return skip_all(DwarfId::Netz, ALL_RULES, EvidenceLevel::Source, &reason);
        }
    };

    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_status(http, &mut findings, &mut checks);
    check_redirects(snapshot, http, &mut findings, &mut checks);
    check_redirect_loop(http, &mut findings, &mut checks);
    check_url_hygiene(http, &mut findings, &mut checks);
    check_redirect_security_and_origin(snapshot, http, &mut findings, &mut checks);
    check_etag_and_rate_limiting(http, &mut findings, &mut checks);
    check_http_integrity_headers(http, obs.is_some(), &mut findings, &mut checks);
    check_content_encoding_integrity(http, &mut findings, &mut checks);
    check_intermediary_error_response(http, &mut findings, &mut checks);

    if let Some(doc) = obs {
        check_soft_error(http, doc, soft_404_baseline, &mut findings, &mut checks);
        check_link_hygiene(http, doc, &mut findings, &mut checks);
        check_charset_mismatch(http, doc, &mut findings, &mut checks);
    } else {
        for rule in [RULE_SOFT_ERROR, RULE_LINK_HYGIENE, RULE_CHARSET_MISMATCH] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "complete HTML document observations unavailable".to_owned(),
            });
        }
    }

    AnalyserResult {
        dwarf_id: DwarfId::Netz,
        findings,
        checks,
    }
}

fn check_status(
    http: &crate::domain::HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.status_code >= 500 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Critical,
            confidence: Confidence::High,
            title: format!("HTTP {} server error", http.status_code),
            summary: format!(
                "Final response from {} returned server error status {}.",
                http.final_url, http.status_code
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("status_code={}", http.status_code),
            )],
            remediation: Some("Investigate upstream application and server error logs.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if http.status_code >= 400 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("HTTP {} client error", http.status_code),
            summary: format!(
                "Final response from {} returned client error status {}.",
                http.final_url, http.status_code
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("status_code={}", http.status_code),
            )],
            remediation: Some(
                "Verify target URL, access rules, or missing resource routing.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HTTP_STATUS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_redirects(
    snapshot: &EvidenceSnapshot,
    http: &crate::domain::HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.redirect_chain.len() > 2 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Long redirect chain ({} hops)", http.redirect_chain.len()),
            summary: format!(
                "Target {} required {} redirects before reaching {}.",
                snapshot.target.as_str(),
                http.redirect_chain.len(),
                http.final_url
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpRedirectChain,
                format!("hops={}", http.redirect_chain.len()),
            )],
            remediation: Some(
                "Collapse intermediate redirects to point directly to the canonical URL."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REDIRECT_CHAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_redirect_loop(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut seen = HashSet::new();
    let mut loop_url = None;
    for hop in &http.redirect_chain {
        seen.insert(hop.from_url.as_str());
        if seen.contains(hop.to_url.as_str()) {
            loop_url = Some(hop.to_url.as_str());
            break;
        }
    }

    if let Some(repeated) = loop_url {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REDIRECT_LOOP.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Redirect loop detected".to_owned(),
            summary: format!("Redirect chain repeated URL `{repeated}`."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpRedirectChain,
                format!("loop_url={repeated}"),
            )],
            remediation: Some(
                "Fix server/CDN redirect rules so targets converge without cycles.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REDIRECT_LOOP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REDIRECT_LOOP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_soft_error(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    baseline: Option<&Soft404Baseline>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.status_code != 200 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: format!("HTTP status is {}, not 200", http.status_code),
        });
        return;
    }

    let Some(baseline) = baseline else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "soft-404 random-URL baseline not collected".to_owned(),
        });
        return;
    };

    if baseline.matches_page(obs, http.body_bytes) {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Soft-404 response served with HTTP 200 (confirmed against random-URL baseline)".to_owned(),
            summary: format!(
                "Response returned HTTP 200 matching the origin's confirmed random-URL fallback template (`{}` -> {}, `{}` -> {}).",
                baseline.probe_url,
                baseline.probe_status,
                baseline.confirmation_url.as_deref().unwrap_or("none"),
                baseline.confirmation_status.unwrap_or(0)
            ),
            evidence_refs: vec![
                EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!("probe_url={};status={}", baseline.probe_url, baseline.probe_status),
                ),
                EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!(
                        "confirmation_url={};status={}",
                        baseline.confirmation_url.as_deref().unwrap_or("none"),
                        baseline.confirmation_status.unwrap_or(0)
                    ),
                ),
            ],
            remediation: Some(
                "Return proper 404/410 HTTP status codes for missing routes instead of serving a fallback template with HTTP 200."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_link_hygiene(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.links.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LINK_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no anchor links observed".to_owned(),
        });
        return;
    }

    let page_host = url::Url::parse(&http.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));

    let js_links = obs
        .links
        .iter()
        .filter(|l| l.href.to_ascii_lowercase().starts_with("javascript:"))
        .count();

    let unsafe_blank_links = obs
        .links
        .iter()
        .filter(|l| {
            let is_blank = l
                .target
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case("_blank"));
            if !is_blank {
                return false;
            }
            let is_external = url::Url::parse(&l.href)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|h| page_host.as_deref() != Some(h.as_str()));
            if !is_external {
                return false;
            }
            let rel = l.rel.as_deref().unwrap_or("").to_ascii_lowercase();
            !rel.contains("noopener") && !rel.contains("noreferrer")
        })
        .count();

    if js_links == 0 && unsafe_blank_links == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LINK_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LINK_HYGIENE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Link hygiene issues detected".to_owned(),
            summary: format!(
                "{js_links} `javascript:` pseudo-link(s) and {unsafe_blank_links} external `target=\"_blank\"` link(s) missing `rel=\"noopener\"`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("js_links={js_links};unsafe_blank={unsafe_blank_links}"),
            )],
            remediation: Some(
                "Replace `javascript:` hrefs with `<button>` elements and add `rel=\"noopener noreferrer\"` on external `target=\"_blank\"` links."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LINK_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_url_hygiene(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Ok(parsed) = url::Url::parse(&http.final_url) else {
        for rule in [
            RULE_URL_UPPERCASE,
            RULE_URL_QUERY_HYGIENE,
            RULE_URL_DEEP_PATH,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "final_url could not be parsed".to_owned(),
            });
        }
        return;
    };

    check_url_uppercase(parsed.path(), findings, checks);
    check_url_query_hygiene(&parsed, findings, checks);
    check_url_deep_path(parsed.path(), findings, checks);
}

fn check_url_uppercase(path: &str, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    if path.chars().any(|c| c.is_ascii_uppercase()) {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_URL_UPPERCASE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Uppercase characters in URL path".to_owned(),
            summary: format!(
                "URL path `{path}` contains uppercase letters, which can cause case-sensitivity duplicates."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("path={path}"),
            )],
            remediation: Some(
                "Normalise URL paths to lowercase and redirect uppercase variants.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_URL_UPPERCASE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_URL_UPPERCASE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_url_query_hygiene(
    parsed: &url::Url,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let query_pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let has_tracking_or_session = query_pairs.iter().any(|(k, _)| {
        let lower = k.to_ascii_lowercase();
        lower.starts_with("utm_")
            || matches!(
                lower.as_str(),
                "fbclid" | "gclid" | "msclkid" | "jsessionid" | "phpsessid"
            )
    });
    if query_pairs.len() > 3 || has_tracking_or_session {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_URL_QUERY_HYGIENE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Noisy or tracking query parameters on final URL".to_owned(),
            summary: format!(
                "Final URL carries {} query parameter(s) (tracking/session={has_tracking_or_session}).",
                query_pairs.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("query_params={}", query_pairs.len()),
            )],
            remediation: Some(
                "Strip tracking/session parameters from canonical URLs and internal links."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_URL_QUERY_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_URL_QUERY_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_url_deep_path(path: &str, findings: &mut Vec<Finding>, checks: &mut Vec<CheckStatus>) {
    let depth = path.split('/').filter(|s| !s.is_empty()).count();
    if depth > 5 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_URL_DEEP_PATH.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: format!("Deeply nested URL path ({depth} segments)"),
            summary: format!("URL path `{path}` has {depth} segments (> 5)."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("path_depth={depth}"),
            )],
            remediation: Some("Keep URL hierarchy concise and shallow where practical.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_URL_DEEP_PATH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_URL_DEEP_PATH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_redirect_security_and_origin(
    snapshot: &EvidenceSnapshot,
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_https_downgrade = http
        .redirect_chain
        .iter()
        .any(|h| h.from_url.starts_with("https://") && h.to_url.starts_with("http://"))
        || (snapshot.target.as_str().starts_with("https://")
            && http.final_url.starts_with("http://"));

    if has_https_downgrade {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REDIRECT_HTTPS_DOWNGRADE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Redirect chain downgrades HTTPS to HTTP".to_owned(),
            summary: "An HTTP redirect transitioned from `https://` to unencrypted `http://`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("final_url={}", http.final_url),
            )],
            remediation: Some(
                "Ensure all redirect targets preserve `https://` without downgrading transport."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REDIRECT_HTTPS_DOWNGRADE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REDIRECT_HTTPS_DOWNGRADE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    let seed_host = url::Url::parse(snapshot.target.as_str())
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let cross_hosts: Vec<String> = http
        .redirect_chain
        .iter()
        .filter_map(|h| url::Url::parse(&h.to_url).ok())
        .filter_map(|u| u.host_str().map(str::to_ascii_lowercase))
        .filter(|h| seed_host.as_deref() != Some(h.as_str()))
        .collect();

    if cross_hosts.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REDIRECT_CROSS_ORIGIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REDIRECT_CROSS_ORIGIN.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Cross-origin redirect chain observed".to_owned(),
            summary: format!(
                "Redirect chain crossed to external host(s): {}.",
                cross_hosts.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("cross_origin_redirects={}", cross_hosts.len()),
            )],
            remediation: Some(
                "Confirm cross-host redirects are intentional and update canonical links accordingly."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REDIRECT_CROSS_ORIGIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_etag_and_rate_limiting(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if let Some(etag) = header_value(http, "etag") {
        let trimmed = etag.trim();
        let valid_quoted =
            (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
                || (trimmed.starts_with("W/\"") && trimmed.ends_with('"') && trimmed.len() >= 4);
        if valid_quoted {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_ETAG_VALIDATION.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_ETAG_VALIDATION.to_owned()),
                category: FindingCategory::Reliability,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "Malformed ETag response header".to_owned(),
                summary: format!(
                    "ETag header `{trimmed}` does not follow RFC 9110 quoted entity-tag syntax (`\"...\"` or `W/\"...\"`)."
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpHeaders,
                    format!("etag={trimmed}"),
                )],
                remediation: Some("Quote entity-tag values per RFC 9110.".to_owned()),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_ETAG_VALIDATION.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    } else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_ETAG_VALIDATION.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "ETag header absent".to_owned(),
        });
    }

    let refusal =
        crate::collection::classify_http_refusal(http.status_code, &http.headers, &http.body_text);
    let rate_limited = http.status_code == 429
        || header_value(http, "retry-after").is_some()
        || header_value(http, "x-ratelimit-remaining").is_some_and(|v| v.trim() == "0")
        || matches!(
            refusal,
            Some(
                crate::collection::RefusalKind::WafChallenge
                    | crate::collection::RefusalKind::BotBlocked
            )
        );
    if rate_limited {
        let refusal_label = match refusal {
            Some(crate::collection::RefusalKind::WafChallenge) => "waf_challenge",
            Some(crate::collection::RefusalKind::BotBlocked) => "bot_blocked",
            Some(crate::collection::RefusalKind::UpstreamUnavailable) => "upstream_unavailable",
            Some(crate::collection::RefusalKind::RateLimited) | None => "rate_limited",
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_RATE_LIMITING.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Rate limiting or WAF/bot refusal observed (HTTP {}, {refusal_label})",
                http.status_code
            ),
            summary: format!(
                "Origin or intermediary signalled `{refusal_label}` / backoff (status={}, retry_after={}).",
                http.status_code,
                header_value(http, "retry-after").unwrap_or("<absent>")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("status={};refusal={refusal_label}", http.status_code),
            )],
            remediation: Some(
                "Respect `Retry-After` backoff, reduce crawl concurrency, or verify WAF/bot-protection rules for legitimate crawlers."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_RATE_LIMITING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RATE_LIMITING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_http_integrity_headers(
    http: &HttpEvidence,
    has_html_obs: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    check_content_type_integrity(http, has_html_obs, findings, checks);
    check_content_length_integrity(http, findings, checks);
    check_range_request_support(http, findings, checks);
}

fn check_content_type_integrity(
    http: &HttpEvidence,
    has_html_obs: bool,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(ct) = (has_html_obs)
        .then(|| header_value(http, "content-type"))
        .flatten()
    else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CONTENT_TYPE_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Content-Type or HTML document observations unavailable".to_owned(),
        });
        return;
    };

    let mime = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if matches!(mime.as_str(), "text/html" | "application/xhtml+xml") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CONTENT_TYPE_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_CONTENT_TYPE_MISMATCH.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("HTML document served with unexpected Content-Type `{mime}`"),
        summary: format!("HTML response declared `Content-Type: {ct}` instead of `text/html`."),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("content_type={ct}"),
        )],
        remediation: Some(
            "Serve HTML documents with `Content-Type: text/html; charset=utf-8`.".to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_CONTENT_TYPE_MISMATCH.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_content_length_integrity(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(raw_cl) = header_value(http, "content-length") else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_INVALID_CONTENT_LENGTH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Content-Length header absent".to_owned(),
        });
        return;
    };

    let mismatch = match raw_cl.trim().parse::<usize>() {
        Ok(len) => {
            !http.body_truncated
                && header_value(http, "content-encoding").is_none()
                && len != http.body_bytes
        }
        Err(_) => true,
    };
    if !mismatch {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INVALID_CONTENT_LENGTH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_INVALID_CONTENT_LENGTH.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: "Invalid or mismatched Content-Length header".to_owned(),
        summary: format!(
            "Response `Content-Length: {raw_cl}` does not match observed payload ({} bytes).",
            http.body_bytes
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("content_length={raw_cl};body_bytes={}", http.body_bytes),
        )],
        remediation: Some(
            "Ensure origin/proxy `Content-Length` matches the transmitted byte length.".to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_INVALID_CONTENT_LENGTH.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_range_request_support(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(accept_ranges) = header_value(http, "accept-ranges") else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_RANGE_REQUEST_SUPPORT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Accept-Ranges header absent".to_owned(),
        });
        return;
    };

    let val = accept_ranges.trim().to_ascii_lowercase();
    if matches!(val.as_str(), "bytes" | "none") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_RANGE_REQUEST_SUPPORT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_RANGE_REQUEST_SUPPORT.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Info,
        confidence: Confidence::High,
        title: format!("Non-standard Accept-Ranges header `{accept_ranges}`"),
        summary: format!("Accept-Ranges `{accept_ranges}` is neither `bytes` nor `none`."),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("accept_ranges={accept_ranges}"),
        )],
        remediation: Some("Use standard `Accept-Ranges: bytes` or `none`.".to_owned()),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_RANGE_REQUEST_SUPPORT.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_charset_mismatch(
    http: &HttpEvidence,
    doc: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let header_charset = header_value(http, "content-type").and_then(|ct| {
        ct.split(';')
            .skip(1)
            .find_map(|part| {
                let (k, v) = part.split_once('=')?;
                k.trim().eq_ignore_ascii_case("charset").then(|| {
                    v.trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_ascii_lowercase()
                })
            })
            .filter(|s| !s.is_empty())
    });

    let (Some(http_cs), Some(html_cs)) = (header_charset, doc.declared_charset.as_deref()) else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CHARSET_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "HTTP Content-Type charset or HTML meta charset unavailable".to_owned(),
        });
        return;
    };

    if http_cs == html_cs {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CHARSET_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_CHARSET_MISMATCH.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("Character encoding mismatch (`{http_cs}` vs `{html_cs}`)"),
        summary: format!(
            "HTTP `Content-Type` declares charset `{http_cs}` while HTML meta declares `{html_cs}`."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("http_charset={http_cs};html_charset={html_cs}"),
        )],
        remediation: Some(
            "Align the HTTP `Content-Type` charset parameter and HTML `<meta charset>` to `utf-8`."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_CHARSET_MISMATCH.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_content_encoding_integrity(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const VALID_CODINGS: &[&str] = &[
        "gzip",
        "x-gzip",
        "br",
        "deflate",
        "zstd",
        "compress",
        "x-compress",
        "identity",
    ];
    let Some(raw) = header_value(http, "content-encoding") else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_INVALID_CONTENT_ENCODING.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Content-Encoding header absent".to_owned(),
        });
        return;
    };

    let mut seen = HashSet::new();
    let mut invalid = false;
    let tokens: Vec<String> = raw
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    if tokens.is_empty() || tokens.iter().any(String::is_empty) {
        invalid = true;
    } else {
        for token in &tokens {
            if !VALID_CODINGS.contains(&token.as_str())
                || (token != "identity" && !seen.insert(token.as_str()))
            {
                invalid = true;
                break;
            }
        }
    }

    if !invalid {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INVALID_CONTENT_ENCODING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_INVALID_CONTENT_ENCODING.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!("Invalid Content-Encoding header `{raw}`"),
        summary: format!(
            "`Content-Encoding: {raw}` contains unrecognised, empty, or duplicated codings."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpHeaders,
            format!("content_encoding={raw}"),
        )],
        remediation: Some(
            "Emit only standard, non-duplicated HTTP content-codings such as `gzip`, `br`, or `zstd`."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_INVALID_CONTENT_ENCODING.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_intermediary_error_response(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.status_code < 400 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INTERMEDIARY_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    let marker = [
        "cf-ray",
        "x-amz-cf-id",
        "x-fastly-request-id",
        "x-served-by",
        "x-cache",
        "x-akamai-transformed",
        "via",
    ]
    .into_iter()
    .find_map(|name| header_value(http, name).map(|v| format!("{name}={v}")))
    .or_else(|| {
        header_value(http, "server").and_then(|s| {
            let low = s.to_ascii_lowercase();
            [
                "cloudflare",
                "varnish",
                "fastly",
                "akamai",
                "envoy",
                "cloudfront",
            ]
            .iter()
            .any(|cdn| low.contains(cdn))
            .then(|| format!("server={s}"))
        })
    });

    let Some(evidence) = marker else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_INTERMEDIARY_ERROR.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "error response lacks observable intermediary attribution headers".to_owned(),
        });
        return;
    };

    let severity = if http.status_code >= 500 {
        Severity::Medium
    } else {
        Severity::Low
    };
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_INTERMEDIARY_ERROR.to_owned()),
        category: FindingCategory::Reliability,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity,
        confidence: Confidence::Medium,
        title: format!(
            "HTTP {} error response with observable intermediary headers",
            http.status_code
        ),
        summary: format!(
            "Error status {} carried intermediary/proxy attribution ({evidence}).",
            http.status_code
        ),
        evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, evidence)],
        remediation: Some(
            "Inspect CDN/reverse-proxy and origin logs to isolate whether the failure occurred at the edge or origin."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_INTERMEDIARY_ERROR.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, CollectorOutcome, HttpEvidence, Measurement, MeasurementUnit, RedirectHop,
        TargetPolicy,
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
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 0,
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
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
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

    #[test]
    fn flags_redirect_loop_soft_error_and_link_hygiene() {
        let mut snap = make_snapshot(200, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.redirect_chain = vec![
                RedirectHop {
                    from_url: "https://example.com/a".to_owned(),
                    status_code: 301,
                    to_url: "https://example.com/b".to_owned(),
                },
                RedirectHop {
                    from_url: "https://example.com/b".to_owned(),
                    status_code: 302,
                    to_url: "https://example.com/a".to_owned(),
                },
            ];
        }
        let html = r#"<html><head><title>404 Page Not Found</title></head><body>
            <a href="javascript:void(0)">Click</a>
            <a href="https://external.example.org/" target="_blank">Ext</a>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_REDIRECT_LOOP));
        assert!(ids.contains(&RULE_LINK_HYGIENE));
        assert!(
            !ids.contains(&RULE_SOFT_ERROR),
            "substring title '404 Page Not Found' without baseline must not false-positive"
        );
    }

    #[test]
    fn detects_soft_404_only_with_confirmed_random_url_baseline() {
        let error_template = "<html><head><title>Not Found</title></head><body><main><p>We could not find the requested resource on this server. Please check the web address or return to the main application portal for navigation and support information across all available services.</p></main></body></html>";
        let mut snap = make_snapshot(200, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.body_bytes = error_template.len();
            data.body_text = error_template.to_owned();
        }
        let obs = DocumentObservations::from_html(error_template);
        let simhash = crate::analysis::graph::compute_text_simhash(&obs.main_content_text);

        // 1. Substring-only without baseline does not trigger.
        let without_baseline = analyse_with_document(&snap, Some(&obs));
        assert!(
            !without_baseline
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_SOFT_ERROR)
        );

        // 2. Confirmed random-URL baseline matching the template triggers soft-404.
        let confirmed_baseline = Soft404Baseline {
            probe_url: "https://example.com/__nzw-soft404-probe-9f4c2a7e1b".to_owned(),
            probe_status: 200,
            probe_simhash: simhash,
            probe_body_bytes: error_template.len(),
            confirmation_url: Some(
                "https://example.com/__nzw-soft404-confirm-3e8d1b5a4c".to_owned(),
            ),
            confirmation_status: Some(200),
            confirmation_simhash: simhash,
        };
        let with_baseline = analyse_with_baseline(&snap, Some(&obs), Some(&confirmed_baseline));
        assert!(
            with_baseline
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_SOFT_ERROR)
        );

        // 3. Unconfirmed baseline (e.g. confirmation returned 404) does not trigger.
        let mut unconfirmed = confirmed_baseline;
        unconfirmed.confirmation_status = Some(404);
        let res_unconfirmed = analyse_with_baseline(&snap, Some(&obs), Some(&unconfirmed));
        assert!(
            !res_unconfirmed
                .findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_SOFT_ERROR)
        );
    }

    #[test]
    fn flags_url_uppercase_query_hygiene_and_deep_path() {
        let mut snap = make_snapshot(200, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.final_url =
                "https://example.com/a/b/c/d/e/MyPage?utm_source=x&a=1&b=2&c=3".to_owned();
        }
        let result = analyse(&snap);
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_URL_UPPERCASE));
        assert!(ids.contains(&RULE_URL_QUERY_HYGIENE));
        assert!(ids.contains(&RULE_URL_DEEP_PATH));
    }

    #[test]
    fn flags_https_downgrade_cross_origin_malformed_etag_and_rate_limiting() {
        let mut snap = make_snapshot(429, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.final_url = "http://other.example.net/".to_owned();
            data.redirect_chain = vec![RedirectHop {
                from_url: "https://example.com/".to_owned(),
                status_code: 302,
                to_url: "http://other.example.net/".to_owned(),
            }];
            data.headers = vec![
                crate::domain::HttpHeader {
                    name: "etag".to_owned(),
                    value: "unquoted-tag".to_owned(),
                },
                crate::domain::HttpHeader {
                    name: "retry-after".to_owned(),
                    value: "30".to_owned(),
                },
            ];
        }
        let result = analyse(&snap);
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_REDIRECT_HTTPS_DOWNGRADE));
        assert!(ids.contains(&RULE_REDIRECT_CROSS_ORIGIN));
        assert!(ids.contains(&RULE_ETAG_VALIDATION));
        assert!(ids.contains(&RULE_RATE_LIMITING));
    }

    #[test]
    fn flags_content_type_mismatch_invalid_content_length_and_range_header() {
        let mut snap = make_snapshot(200, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.headers = vec![
                crate::domain::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "text/plain".to_owned(),
                },
                crate::domain::HttpHeader {
                    name: "content-length".to_owned(),
                    value: "9999".to_owned(),
                },
                crate::domain::HttpHeader {
                    name: "accept-ranges".to_owned(),
                    value: "kilobytes".to_owned(),
                },
            ];
        }
        let obs = DocumentObservations::from_html("<html><body><p>Hi</p></body></html>");
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_CONTENT_TYPE_MISMATCH));
        assert!(ids.contains(&RULE_INVALID_CONTENT_LENGTH));
        assert!(ids.contains(&RULE_RANGE_REQUEST_SUPPORT));
    }

    #[test]
    fn flags_charset_mismatch_invalid_content_encoding_and_intermediary_error() {
        let mut snap = make_snapshot(502, 0);
        if let CollectorOutcome::Captured { data } = &mut snap.http {
            data.headers = vec![
                crate::domain::HttpHeader {
                    name: "content-type".to_owned(),
                    value: "text/html; charset=iso-8859-1".to_owned(),
                },
                crate::domain::HttpHeader {
                    name: "content-encoding".to_owned(),
                    value: "gzip, unknown-codec".to_owned(),
                },
                crate::domain::HttpHeader {
                    name: "cf-ray".to_owned(),
                    value: "8abc123-FRA".to_owned(),
                },
            ];
        }
        let obs = DocumentObservations::from_html(
            r#"<!doctype html><html><head><meta charset="utf-8"></head><body><p>Err</p></body></html>"#,
        );
        let result = analyse_with_document(&snap, Some(&obs));
        let ids: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.rule_id.0.as_str())
            .collect();
        assert!(ids.contains(&RULE_CHARSET_MISMATCH));
        assert!(ids.contains(&RULE_INVALID_CONTENT_ENCODING));
        assert!(ids.contains(&RULE_INTERMEDIARY_ERROR));
    }
}
