//! `NetzZwerg` — HTTP reliability, status, and redirect-chain checks.

use std::collections::HashSet;

use crate::analysis::document::DocumentObservations;
use crate::analysis::{require_http, skip_all};
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

const ALL_RULES: &[&str] = &[
    RULE_HTTP_STATUS,
    RULE_REDIRECT_CHAIN,
    RULE_REDIRECT_LOOP,
    RULE_SOFT_ERROR,
    RULE_LINK_HYGIENE,
    RULE_URL_UPPERCASE,
    RULE_URL_QUERY_HYGIENE,
    RULE_URL_DEEP_PATH,
];

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

    if let Some(doc) = obs {
        check_soft_error(http, doc, &mut findings, &mut checks);
        check_link_hygiene(http, doc, &mut findings, &mut checks);
    } else {
        for rule in [RULE_SOFT_ERROR, RULE_LINK_HYGIENE] {
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

    let title_lower = obs
        .title
        .as_deref()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let h1_lower = obs
        .headings
        .iter()
        .find(|h| h.level == 1)
        .map(|h| h.text.to_ascii_lowercase())
        .unwrap_or_default();
    let combined = format!("{title_lower} {h1_lower}");
    let looks_like_error_page = [
        "404",
        "410",
        "page not found",
        "not found",
        "nie znaleziono",
        "strona nie istnieje",
        "seite nicht gefunden",
        "nicht gefunden",
        "500 internal server error",
        "error 404",
    ]
    .iter()
    .any(|p| combined.contains(p));

    if looks_like_error_page && obs.visible_word_count < 80 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOFT_ERROR.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Low,
            title: "Potential soft-404 / error page served with HTTP 200".to_owned(),
            summary: format!(
                "Response returned HTTP 200 with error-like title `{}` and {} visible words.",
                obs.title.as_deref().unwrap_or(""),
                obs.visible_word_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("status=200;words={}", obs.visible_word_count),
            )],
            remediation: Some(
                "Return proper 404/410/5xx HTTP status codes for missing or error pages."
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
        assert!(ids.contains(&RULE_SOFT_ERROR));
        assert!(ids.contains(&RULE_LINK_HYGIENE));
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
}
