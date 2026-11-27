//! `SuchZwerg` — search visibility, metadata, and indexability checks.
//!
//! Consumes shared [`DocumentObservations`] and HTTP headers; heading hierarchy
//! and structural semantics belong to `StrukturZwerg`.

use crate::analysis::document::DocumentObservations;
use crate::analysis::header_value;
use crate::analysis::schema;
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
const RULE_CANONICAL_ABSOLUTE: &str = "such.meta.canonical_absolute";
const RULE_FEED_AUTODISCOVERY: &str = "such.feeds.autodiscovery";
const RULE_HREFLANG_SELF_REF: &str = "such.i18n.missing_self_reference";
const RULE_SOCIAL_IMAGE: &str = "such.social.missing_preview_image";
const RULE_MULTIPLE_TITLES: &str = "such.meta.multiple_titles";
const RULE_MULTIPLE_CANONICALS: &str = "such.canonical.multiple_declarations";
const RULE_AX_RENDERING_DEP: &str = "such.ax.rendering_dependency";
const RULE_NOINDEX_CANONICAL_CONFLICT: &str = "such.indexability.noindex_canonical_conflict";
const RULE_EMPTY_JSON_LD_ENTITIES: &str = "such.schema.empty_json_ld_entities";
const RULE_ROBOTS_HEADER_CONFLICT: &str = "such.indexability.robots_header_conflict";
const RULE_OG_URL_MISMATCH: &str = "such.social.og_url_mismatch";

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
    RULE_CANONICAL_ABSOLUTE,
    RULE_FEED_AUTODISCOVERY,
    RULE_HREFLANG_SELF_REF,
    RULE_SOCIAL_IMAGE,
    RULE_MULTIPLE_TITLES,
    RULE_MULTIPLE_CANONICALS,
    RULE_AX_RENDERING_DEP,
    schema::RULE_SCHEMA_TYPE_REQUIREMENTS,
    schema::RULE_SCHEMA_SAME_AS,
    schema::RULE_SCHEMA_ENTITY_REFS,
    RULE_NOINDEX_CANONICAL_CONFLICT,
    RULE_EMPTY_JSON_LD_ENTITIES,
    RULE_ROBOTS_HEADER_CONFLICT,
    RULE_OG_URL_MISMATCH,
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
    schema::analyse_into(obs, &mut findings, &mut checks);
    check_social_meta(obs, &mut findings, &mut checks);
    check_url_hygiene(http, &mut findings, &mut checks);
    check_canonical_absolute(obs, &mut findings, &mut checks);
    check_feed_autodiscovery(obs, &mut findings, &mut checks);
    check_hreflang_self_reference(http, obs, &mut findings, &mut checks);
    check_social_preview_image(obs, &mut findings, &mut checks);
    check_multiple_titles_and_canonicals(obs, &mut findings, &mut checks);
    check_ax_rendering_dependency(http, obs, &mut findings, &mut checks);
    check_noindex_canonical_conflict_and_schema(http, obs, &mut findings, &mut checks);
    check_robots_header_conflict(http, obs, &mut findings, &mut checks);
    check_og_url_mismatch(obs, &mut findings, &mut checks);

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

    for item in &obs.hreflangs {
        let lang = item.lang.to_ascii_lowercase();
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
                let has_schema_keys = |v: &serde_json::Value| -> bool {
                    v.as_object().is_some_and(|map| {
                        map.contains_key("@context")
                            && (map.contains_key("@type") || map.contains_key("@graph"))
                    })
                };
                let valid_shape = match &val {
                    serde_json::Value::Object(_) => has_schema_keys(&val),
                    serde_json::Value::Array(items) => {
                        !items.is_empty() && items.iter().all(has_schema_keys)
                    }
                    _ => false,
                };
                if !valid_shape {
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

fn check_canonical_absolute(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(canonical) = obs.canonical_url.as_deref() else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CANONICAL_ABSOLUTE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no canonical link declared".to_owned(),
        });
        return;
    };

    if canonical.starts_with("https://") || canonical.starts_with("http://") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CANONICAL_ABSOLUTE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CANONICAL_ABSOLUTE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Relative canonical URL".to_owned(),
            summary: format!(
                "Canonical link `{canonical}` is relative; search engines require an absolute `https://` URL."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("canonical={canonical}"),
            )],
            remediation: Some("Use a fully-qualified absolute URL in `<link rel=\"canonical\">`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CANONICAL_ABSOLUTE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_feed_autodiscovery(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.feed_links_count > 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FEED_AUTODISCOVERY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if obs.visible_word_count < 150 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_FEED_AUTODISCOVERY.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page has fewer than 150 visible words".to_owned(),
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FEED_AUTODISCOVERY.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "No RSS/Atom/JSON feed autodiscovery link".to_owned(),
            summary: "Substantive page does not advertise a syndication feed via `<link rel=\"alternate\" type=\"application/rss+xml\">`."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "feed_links_count=0",
            )],
            remediation: Some(
                "Expose an RSS, Atom, or JSON Feed autodiscovery link in `<head>` for editorial sections."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FEED_AUTODISCOVERY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_hreflang_self_reference(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.hreflangs.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HREFLANG_SELF_REF.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no hreflang declarations present".to_owned(),
        });
        return;
    }

    let expected = obs.canonical_url.as_deref().unwrap_or(&http.final_url);
    let expected_norm = expected.trim_end_matches('/');
    let has_self = obs
        .hreflangs
        .iter()
        .any(|h| h.href.trim_end_matches('/') == expected_norm);

    if has_self {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HREFLANG_SELF_REF.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HREFLANG_SELF_REF.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Hreflang cluster omits self-referencing alternate link".to_owned(),
            summary: format!(
                "Page declares {} hreflang link(s) without a self-referencing entry for `{expected}`.",
                obs.hreflangs.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("hreflang_count={};self_ref=false", obs.hreflangs.len()),
            )],
            remediation: Some(
                "Include a self-referencing `<link rel=\"alternate\" hreflang=\"...\">` pointing to the page's canonical URL."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HREFLANG_SELF_REF.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_social_preview_image(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_og = obs.social_meta.og_title.is_some() || obs.social_meta.og_description.is_some();
    if !has_og {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SOCIAL_IMAGE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no Open Graph metadata declared".to_owned(),
        });
        return;
    }

    let valid_img = obs
        .social_meta
        .og_image
        .as_deref()
        .is_some_and(|img| img.starts_with("https://") || img.starts_with("http://"));

    if valid_img {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SOCIAL_IMAGE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SOCIAL_IMAGE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Open Graph metadata missing absolute og:image".to_owned(),
            summary: "Document declares Open Graph tags without an absolute `https://`/`http://` `og:image` preview URL.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "og_image_valid=false",
            )],
            remediation: Some("Provide an absolute `og:image` URL (1200x630 recommended).".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SOCIAL_IMAGE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_multiple_titles_and_canonicals(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.title_count > 1 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MULTIPLE_TITLES.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Multiple <title> elements ({})", obs.title_count),
            summary: format!(
                "Document declares {} <title> elements; crawlers expect a single `<title>`.",
                obs.title_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("title_count={}", obs.title_count),
            )],
            remediation: Some("Emit only one `<title>` element in `<head>`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MULTIPLE_TITLES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MULTIPLE_TITLES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    if obs.canonical_count > 1 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MULTIPLE_CANONICALS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Multiple <link rel=\"canonical\"> declarations ({})", obs.canonical_count),
            summary: format!(
                "Document declares {} canonical links, which causes search engines to ignore canonicalisation.",
                obs.canonical_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("canonical_count={}", obs.canonical_count),
            )],
            remediation: Some("Emit a single `<link rel=\"canonical\">` in `<head>`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MULTIPLE_CANONICALS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MULTIPLE_CANONICALS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_ax_rendering_dependency(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.body_bytes > 512 && obs.visible_word_count < 20 && obs.scripts.len() >= 2 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AX_RENDERING_DEP.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: "Primary content appears dependent on client-side JS rendering".to_owned(),
            summary: format!(
                "Source HTML ({} bytes, {} script(s)) contains only {} visible word(s), limiting non-JS crawler/agent extraction.",
                http.body_bytes,
                obs.scripts.len(),
                obs.visible_word_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "visible_words={};scripts={}",
                    obs.visible_word_count,
                    obs.scripts.len()
                ),
            )],
            remediation: Some(
                "Provide server-side rendered (SSR) or pre-rendered HTML for primary content."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AX_RENDERING_DEP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AX_RENDERING_DEP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_noindex_canonical_conflict_and_schema(
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
    let is_noindex = meta_noindex || header_noindex;

    if let Some(canon) = obs.canonical_url.as_deref()
        && is_noindex
    {
        let diff_target = canon != http.final_url;
        if diff_target {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_NOINDEX_CANONICAL_CONFLICT.to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: "Conflicting noindex directive and external canonical".to_owned(),
                summary: format!(
                    "Page declares `noindex` while canonical points to `{canon}` instead of `{}`.",
                    http.final_url
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!("noindex=true;canonical={canon}"),
                )],
                remediation: Some(
                    "Remove `noindex` when consolidating via `rel=\"canonical\"`, or drop the cross-URL canonical."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_NOINDEX_CANONICAL_CONFLICT.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_NOINDEX_CANONICAL_CONFLICT.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    } else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_NOINDEX_CANONICAL_CONFLICT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page does not combine noindex with canonical".to_owned(),
        });
    }

    if obs.json_ld_blocks.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_EMPTY_JSON_LD_ENTITIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no JSON-LD blocks present".to_owned(),
        });
    } else {
        let extracted = crate::analysis::schema::extract_entities(&obs.json_ld_blocks);
        let has_typed_entity = extracted
            .entities
            .iter()
            .any(|e| !e.entity_types.is_empty());
        if has_typed_entity {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_EMPTY_JSON_LD_ENTITIES.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_EMPTY_JSON_LD_ENTITIES.to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "JSON-LD blocks yield no typed Schema.org entities".to_owned(),
                summary: format!(
                    "Found {} JSON-LD block(s), but none declared a valid `@type` entity.",
                    obs.json_ld_blocks.len()
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!(
                        "json_ld_blocks={};typed_entities=0",
                        obs.json_ld_blocks.len()
                    ),
                )],
                remediation: Some(
                    "Include valid Schema.org `@context` and `@type` fields in JSON-LD blocks."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_EMPTY_JSON_LD_ENTITIES.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

fn check_robots_header_conflict(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let x_robots = header_value(http, "x-robots-tag").map(str::to_ascii_lowercase);
    let meta_robots = obs.meta_robots.as_deref().map(str::to_ascii_lowercase);

    let (Some(hdr), Some(meta)) = (x_robots, meta_robots) else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ROBOTS_HEADER_CONFLICT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let hdr_noindex = hdr.contains("noindex");
    let meta_noindex = meta.contains("noindex");
    let hdr_nofollow = hdr.contains("nofollow");
    let meta_nofollow = meta.contains("nofollow");

    if hdr_noindex != meta_noindex || hdr_nofollow != meta_nofollow {
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ROBOTS_HEADER_CONFLICT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ROBOTS_HEADER_CONFLICT.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Conflicting HTTP `X-Robots-Tag` and HTML `<meta name=\"robots\">` directives"
                .to_owned(),
            summary: format!(
                "HTTP `X-Robots-Tag` (`{hdr}`) and HTML `<meta name=\"robots\">` (`{meta}`) disagree on `noindex`/`nofollow`."
            ),
            evidence_refs: vec![
                EvidenceRef::new(EvidenceSource::HttpHeaders, format!("x-robots-tag={hdr}")),
                EvidenceRef::new(EvidenceSource::HttpBody, format!("meta_robots={meta}")),
            ],
            remediation: Some(
                "Align `X-Robots-Tag` and `<meta name=\"robots\">` so search engines receive unambiguous indexability directives."
                    .to_owned(),
            ),
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ROBOTS_HEADER_CONFLICT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_og_url_mismatch(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let (Some(og_url), Some(canonical)) = (
        obs.social_meta.og_url.as_deref(),
        obs.canonical_url.as_deref(),
    ) else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_OG_URL_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    let norm = |u: &str| u.trim().trim_end_matches('/').to_ascii_lowercase();
    if norm(og_url) == norm(canonical) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_OG_URL_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_OG_URL_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_OG_URL_MISMATCH.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "`og:url` does not match `<link rel=\"canonical\">`".to_owned(),
            summary: format!(
                "Open Graph `og:url` (`{og_url}`) differs from canonical URL (`{canonical}`), which can split social share metadata across URLs."
            ),
            evidence_refs: vec![
                EvidenceRef::new(EvidenceSource::HttpBody, format!("og:url={og_url}")),
                EvidenceRef::new(EvidenceSource::HttpBody, format!("canonical={canonical}")),
            ],
            remediation: Some(
                "Set `<meta property=\"og:url\">` to the exact canonical URL of the page."
                    .to_owned(),
            ),
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

    #[test]
    fn allows_optional_x_default_and_rejects_invalid_json_ld_array_item() {
        let html = r#"<html><head>
            <title>NetzZwergenWacht Audit Engine</title>
            <meta name="description" content="External web auditing engine.">
            <link rel="canonical" href="https://example.com/">
            <link rel="alternate" hreflang="en" href="https://example.com/en">
            <link rel="alternate" hreflang="de" href="https://example.com/de">
            <script type="application/ld+json">[{"foo":"bar"}]</script>
        </head><body><h1>Main</h1></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        assert!(!res.findings.iter().any(|f| f.rule_id.0 == RULE_HREFLANG));
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_JSON_LD));
    }

    #[test]
    fn flags_relative_canonical_and_missing_feed_on_substantive_page() {
        let words = vec!["Editorial article paragraph word"; 40].join(" ");
        let html = format!(
            r#"<html><head>
                <title>NetzZwergenWacht Article</title>
                <meta name="description" content="External web auditing engine.">
                <link rel="canonical" href="/relative-path">
            </head><body><h1>Article</h1><p>{words}</p></body></html>"#
        );
        let (http, obs) = http_with_html(&html);
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_CANONICAL_ABSOLUTE));
        assert!(ids.contains(&RULE_FEED_AUTODISCOVERY));
    }

    #[test]
    fn flags_missing_hreflang_self_ref_and_missing_og_image() {
        let html = r#"<html><head>
            <title>NetzZwergenWacht</title>
            <meta name="description" content="Desc">
            <link rel="canonical" href="https://example.com/">
            <link rel="alternate" hreflang="de" href="https://example.com/de">
            <meta property="og:title" content="NZW">
        </head><body><h1>NZW</h1></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_HREFLANG_SELF_REF));
        assert!(ids.contains(&RULE_SOCIAL_IMAGE));
    }

    #[test]
    fn flags_multiple_titles_canonicals_and_js_rendering_dependency() {
        let padding = "<!-- pad -->".repeat(50);
        let html = format!(
            r#"<html><head>
                <title>One</title><title>Two</title>
                <link rel="canonical" href="https://example.com/a">
                <link rel="canonical" href="https://example.com/b">
                <script src="/a.js"></script><script src="/b.js"></script>
            </head><body><div id="root">{padding}</div></body></html>"#
        );
        let (http, obs) = http_with_html(&html);
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_MULTIPLE_TITLES));
        assert!(ids.contains(&RULE_MULTIPLE_CANONICALS));
        assert!(ids.contains(&RULE_AX_RENDERING_DEP));
    }

    #[test]
    fn flags_noindex_canonical_conflict_and_typeless_json_ld() {
        let html = r#"<html><head>
            <meta name="robots" content="noindex">
            <link rel="canonical" href="https://example.com/other">
            <script type="application/ld+json">{"@context":"https://schema.org","name":"NoType"}</script>
        </head><body></body></html>"#;
        let (http, obs) = http_with_html(html);
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_NOINDEX_CANONICAL_CONFLICT));
        assert!(ids.contains(&RULE_EMPTY_JSON_LD_ENTITIES));
    }

    #[test]
    fn flags_robots_header_conflict_and_og_url_mismatch() {
        let html = r#"<html><head>
            <meta name="robots" content="index,follow">
            <link rel="canonical" href="https://example.com/product">
            <meta property="og:url" content="https://example.com/old-product">
        </head><body></body></html>"#;
        let (mut http, obs) = http_with_html(html);
        http.headers.push(crate::domain::HttpHeader {
            name: "X-Robots-Tag".to_owned(),
            value: "noindex".to_owned(),
        });
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_ROBOTS_HEADER_CONFLICT));
        assert!(ids.contains(&RULE_OG_URL_MISMATCH));
    }
}
