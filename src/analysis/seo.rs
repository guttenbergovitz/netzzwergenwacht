//! `SuchZwerg` — search visibility, metadata, and indexability checks.
//!
//! Consumes shared [`DocumentObservations`] and HTTP headers; heading hierarchy
//! and structural semantics belong to `StrukturZwerg`.

use crate::analysis::document::DocumentObservations;
use crate::analysis::header_value;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, RuleId, Severity,
};

const RULE_TITLE: &str = "such.meta.title";
const RULE_DESCRIPTION: &str = "such.meta.description";
const RULE_CANONICAL: &str = "such.meta.canonical";
const RULE_ROBOTS: &str = "such.indexability.robots";
const RULE_H1: &str = "such.meta.h1";
const RULE_HREFLANG: &str = "such.i18n.hreflang";
const RULE_JSON_LD: &str = "such.schema.json_ld";
const RULE_SOCIAL: &str = "such.social.metadata";
const RULE_URL_HYGIENE: &str = "such.url.hygiene";

/// All rule identifiers owned by `SuchZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_TITLE,
    RULE_DESCRIPTION,
    RULE_CANONICAL,
    RULE_ROBOTS,
    RULE_H1,
    RULE_HREFLANG,
    RULE_JSON_LD,
    RULE_SOCIAL,
    RULE_URL_HYGIENE,
];

/// Evaluates search metadata and indexability signals over `http` and `obs`.
#[must_use]
pub fn analyse(http: &HttpEvidence, obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_title(obs, &mut findings, &mut checks);
    check_description(obs, &mut findings, &mut checks);
    check_canonical(obs, &mut findings, &mut checks);
    check_robots(http, obs, &mut findings, &mut checks);
    check_h1(obs, &mut findings, &mut checks);
    check_hreflang(obs, &mut findings, &mut checks);
    check_json_ld(obs, &mut findings, &mut checks);
    check_social_meta(obs, &mut findings, &mut checks);
    check_url_hygiene(http, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Such,
        findings,
        checks,
    }
}

fn check_title(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(title) = obs.title.as_deref() else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Missing or empty <title> element".to_owned(),
            summary: "Document does not contain a non-empty `<title>` tag.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "title=absent_or_empty",
            )],
            remediation: Some("Add a unique, descriptive `<title>` (10–60 characters).".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let len = title.chars().count();
    if (10..=60).contains(&len) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Suboptimal <title> length ({len} chars)"),
            summary: format!("Title `{title}` is outside the typical 10–60 character range."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("title_chars={len}"),
            )],
            remediation: Some(
                "Keep `<title>` concise and descriptive (10–60 characters).".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_description(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.meta_description.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing or empty meta description".to_owned(),
            summary: "Document does not include a non-empty `<meta name=\"description\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "meta.description=absent_or_empty",
            )],
            remediation: Some("Add a concise `<meta name=\"description\">` summary.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DESCRIPTION.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_canonical(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.canonical_url.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Missing canonical link tag".to_owned(),
            summary: "Document does not specify `<link rel=\"canonical\" href=\"...\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "link.canonical=absent",
            )],
            remediation: Some(
                "Add a canonical link element pointing to the preferred URL.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CANONICAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_robots(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let meta_noindex = obs
        .meta_robots
        .as_deref()
        .is_some_and(|v| v.to_ascii_lowercase().contains("noindex"));
    let header_noindex = header_value(http, "x-robots-tag")
        .is_some_and(|v| v.to_ascii_lowercase().contains("noindex"));

    if meta_noindex || header_noindex {
        let source = if header_noindex {
            EvidenceSource::HttpHeaders
        } else {
            EvidenceSource::HttpBody
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Page marked noindex".to_owned(),
            summary:
                "Robots directive (`meta[name=\"robots\"]` or `X-Robots-Tag`) includes `noindex`."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(source, "robots=noindex")],
            remediation: Some(
                "Verify `noindex` is intentional if this URL should appear in search results."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ROBOTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_h1(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let h1_count = obs
        .headings
        .iter()
        .filter(|h| h.level == 1 && !h.text.is_empty())
        .count();
    match h1_count {
        1 => checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_H1.to_owned()),
            evidence_level: EvidenceLevel::Source,
        }),
        0 => {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_H1.to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: "Missing primary <h1> heading".to_owned(),
                summary: "Document does not contain a non-empty `<h1>` heading.".to_owned(),
                evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpBody, "h1_count=0")],
                remediation: Some(
                    "Add a single descriptive `<h1>` heading matching the page topic.".to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_H1.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
        n => {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_H1.to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Heuristic,
                severity: Severity::Low,
                confidence: Confidence::Medium,
                title: format!("Multiple <h1> headings ({n})"),
                summary: format!("Document contains {n} non-empty `<h1>` headings."),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!("h1_count={n}"),
                )],
                remediation: Some("Prefer a single primary `<h1>` heading per page.".to_owned()),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_H1.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

fn check_hreflang(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.hreflangs.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HREFLANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no hreflang alternate links declared".to_owned(),
        });
        return;
    }

    let mut seen = std::collections::HashSet::new();
    let mut duplicates = Vec::new();
    let mut non_absolute = Vec::new();
    let mut has_x_default = false;

    for item in &obs.hreflangs {
        let lang = item.lang.to_ascii_lowercase();
        if lang == "x-default" {
            has_x_default = true;
        }
        if !seen.insert(lang.clone()) {
            duplicates.push(lang);
        }
        if !item.href.starts_with("http://") && !item.href.starts_with("https://") {
            non_absolute.push(item.href.clone());
        }
    }

    let mut issues = Vec::new();
    if !duplicates.is_empty() {
        issues.push(format!("duplicate hreflang(s): {}", duplicates.join(", ")));
    }
    if !non_absolute.is_empty() {
        issues.push(format!(
            "{} non-absolute hreflang URL(s)",
            non_absolute.len()
        ));
    }
    if obs.hreflangs.len() >= 2 && !has_x_default {
        issues.push("missing `x-default` fallback".to_owned());
    }

    if issues.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HREFLANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HREFLANG.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Invalid or incomplete hreflang configuration".to_owned(),
            summary: issues.join("; "),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("hreflang_count={}", obs.hreflangs.len()),
            )],
            remediation: Some(
                "Ensure unique `hreflang` codes, absolute URLs, and an `x-default` fallback."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HREFLANG.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_json_ld(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.json_ld_blocks.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_JSON_LD.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no JSON-LD structured data blocks present".to_owned(),
        });
        return;
    }

    let mut invalid_blocks = 0usize;
    let mut missing_schema_keys = 0usize;

    for raw in &obs.json_ld_blocks {
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(val) => {
                let has_keys = match &val {
                    serde_json::Value::Object(map) => {
                        map.contains_key("@context")
                            && (map.contains_key("@type") || map.contains_key("@graph"))
                    }
                    serde_json::Value::Array(items) => !items.is_empty(),
                    _ => false,
                };
                if !has_keys {
                    missing_schema_keys += 1;
                }
            }
            Err(_) => invalid_blocks += 1,
        }
    }

    if invalid_blocks == 0 && missing_schema_keys == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_JSON_LD.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_JSON_LD.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Invalid or incomplete JSON-LD structured data".to_owned(),
            summary: format!(
                "{invalid_blocks} malformed JSON-LD block(s), {missing_schema_keys} missing `@context`/`@type`."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("json_ld_blocks={}", obs.json_ld_blocks.len()),
            )],
            remediation: Some(
                "Validate `<script type=\"application/ld+json\">` syntax and include `@context` and `@type`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_JSON_LD.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_social_meta(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let social = &obs.social_meta;
    let present_og = [
        social.og_title.is_some(),
        social.og_description.is_some(),
        social.og_image.is_some(),
    ]
    .into_iter()
    .filter(|&b| b)
    .count();

    if present_og == 3 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SOCIAL.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOCIAL.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: if present_og == 0 {
                "Missing Open Graph social metadata".to_owned()
            } else {
                format!("Incomplete Open Graph metadata ({present_og}/3 core tags)")
            },
            summary: "Core Open Graph tags (`og:title`, `og:description`, `og:image`) are missing or incomplete."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("og_core_tags={present_og}/3"),
            )],
            remediation: Some(
                "Add `og:title`, `og:description`, and `og:image` meta properties for consistent link previews."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SOCIAL.to_owned()),
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
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_URL_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "final URL could not be parsed".to_owned(),
        });
        return;
    };
    let path = parsed.path();
    let has_uppercase = path.chars().any(|c| c.is_ascii_uppercase());
    let has_underscores = path.contains('_');
    if !has_uppercase && !has_underscores {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_URL_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_URL_HYGIENE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Non-canonical URL path formatting".to_owned(),
            summary: format!("URL path `{path}` contains uppercase characters or underscores."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                format!("path={path}"),
            )],
            remediation: Some(
                "Prefer lowercase, hyphen-separated URL paths for consistent canonicalisation."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_URL_HYGIENE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, HttpHeader, Measurement, MeasurementUnit, TargetPolicy};

    fn http_with_html(html: &str) -> (HttpEvidence, DocumentObservations) {
        let _ = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let http = HttpEvidence {
            final_url: "https://example.com/".to_owned(),
            status_code: 200,
            redirect_chain: Vec::new(),
            headers: vec![HttpHeader {
                name: "content-type".to_owned(),
                value: "text/html".to_owned(),
            }],
            elapsed_ms: Measurement::Measured {
                value: 10,
                unit: MeasurementUnit::Milliseconds,
            },
            body_bytes: html.len(),
            body_truncated: false,
            body_text: html.to_owned(),
        };
        let obs = DocumentObservations::from_html(html);
        (http, obs)
    }

    #[test]
    fn passes_for_valid_search_metadata() {
        let html = r#"<html><head>
            <title>NetzZwergenWacht Audit Engine</title>
            <meta name="description" content="External web auditing engine.">
            <link rel="canonical" href="https://example.com/">
            <meta property="og:title" content="NetzZwergenWacht">
            <meta property="og:description" content="External web auditing engine.">
            <meta property="og:image" content="https://example.com/og.png">
        </head><body><h1>NetzZwergenWacht</h1></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        assert_eq!(res.findings.len(), 0);
        assert_eq!(res.checks.len(), ALL_RULES.len());
    }

    #[test]
    fn flags_invalid_hreflang_and_malformed_json_ld() {
        let html = r#"<html><head>
            <title>NetzZwergenWacht Audit Engine</title>
            <meta name="description" content="External web auditing engine.">
            <link rel="canonical" href="https://example.com/">
            <link rel="alternate" hreflang="en" href="/en">
            <link rel="alternate" hreflang="en" href="https://example.com/en">
            <script type="application/ld+json">{invalid json</script>
        </head><body><h1>Main</h1></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_HREFLANG));
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_JSON_LD));
    }
}
