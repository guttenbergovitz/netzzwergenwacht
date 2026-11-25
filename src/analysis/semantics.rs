//! `StrukturZwerg` — semantic HTML5 structure and document integrity checks.
//!
//! Consumes shared [`DocumentObservations`] extracted from an HTML5 parser
//! without claiming to validate original un-repaired HTML syntax.

use crate::analysis::document::DocumentObservations;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, RuleId, Severity,
};

const RULE_DUPLICATE_IDS: &str = "str.doc.duplicate_ids";
const RULE_HEADING_HIERARCHY: &str = "str.headings.hierarchy";
const RULE_LANDMARKS: &str = "str.landmarks.presence";
const RULE_INTERACTIVE_SEMANTICS: &str = "str.interactive.native_semantics";
const RULE_CONTAINER_RATIO: &str = "str.doc.container_ratio";
const RULE_CHARSET: &str = "str.doc.charset";
const RULE_SKIP_LINK: &str = "str.nav.skip_link";
const RULE_META_REFRESH: &str = "str.doc.meta_refresh";
const RULE_FAVICON: &str = "str.doc.favicon";
const RULE_DUPLICATE_MAIN: &str = "str.landmarks.duplicate_main";
const RULE_EMPTY_HEADING: &str = "str.headings.empty_heading";
const RULE_INVALID_DOCTYPE: &str = "str.html.invalid_doctype";
const RULE_INVALID_LABEL_ASSOC: &str = "str.forms.invalid_association";
const RULE_FORM_MISSING_SUBMIT: &str = "str.forms.missing_submit_control";
const RULE_NESTED_INTERACTIVE: &str = "str.html.nested_interactive";

/// All rule identifiers owned by `StrukturZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_DUPLICATE_IDS,
    RULE_HEADING_HIERARCHY,
    RULE_LANDMARKS,
    RULE_INTERACTIVE_SEMANTICS,
    RULE_CONTAINER_RATIO,
    RULE_CHARSET,
    RULE_SKIP_LINK,
    RULE_META_REFRESH,
    RULE_FAVICON,
    RULE_DUPLICATE_MAIN,
    RULE_EMPTY_HEADING,
    RULE_INVALID_DOCTYPE,
    RULE_INVALID_LABEL_ASSOC,
    RULE_FORM_MISSING_SUBMIT,
    RULE_NESTED_INTERACTIVE,
];

/// Evaluates semantic HTML structure and element integrity over `obs`.
#[must_use]
pub fn analyse(obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_duplicate_ids(obs, &mut findings, &mut checks);
    check_heading_hierarchy(obs, &mut findings, &mut checks);
    check_landmarks(obs, &mut findings, &mut checks);
    check_interactive_semantics(obs, &mut findings, &mut checks);
    check_container_ratio(obs, &mut findings, &mut checks);
    check_charset(obs, &mut findings, &mut checks);
    check_skip_link(obs, &mut findings, &mut checks);
    check_meta_refresh(obs, &mut findings, &mut checks);
    check_favicon(obs, &mut findings, &mut checks);
    check_duplicate_main(obs, &mut findings, &mut checks);
    check_empty_headings(obs, &mut findings, &mut checks);
    check_doctype(obs, &mut findings, &mut checks);
    check_label_associations(obs, &mut findings, &mut checks);
    check_form_submit_controls(obs, &mut findings, &mut checks);
    check_nested_interactive(obs, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Struktur,
        findings,
        checks,
    }
}

fn check_duplicate_ids(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.duplicate_ids.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let sample = obs
            .duplicate_ids
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Duplicate HTML id attributes ({})", obs.duplicate_ids.len()),
            summary: format!(
                "Element `id` attributes must be unique within a document; duplicates found: {sample}."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("duplicate_ids={sample}"),
            )],
            remediation: Some("Ensure every `id` attribute is unique across the document.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_IDS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_heading_hierarchy(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let h1_count = obs.headings.iter().filter(|h| h.level == 1).count();
    let mut skipped_jumps = Vec::new();
    for pair in obs.headings.windows(2) {
        if pair[1].level > pair[0].level + 1 {
            skipped_jumps.push(format!("h{}->h{}", pair[0].level, pair[1].level));
        }
    }

    if h1_count == 1 && skipped_jumps.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    if h1_count == 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing primary <h1> heading".to_owned(),
            summary: "Document does not contain an <h1> heading.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpBody, "h1_count=0")],
            remediation: Some("Provide a single primary <h1> describing the document.".to_owned()),
        });
    } else if h1_count > 1 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Multiple <h1> headings ({h1_count})"),
            summary: format!(
                "Document contains {h1_count} <h1> elements; prefer a single primary heading."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("h1_count={h1_count}"),
            )],
            remediation: Some("Use a single <h1> and nest subsections with <h2>–<h6>.".to_owned()),
        });
    }

    if !skipped_jumps.is_empty() {
        let jumps = skipped_jumps.join(", ");
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: "Skipped heading hierarchy levels".to_owned(),
            summary: format!("Heading outline skips intermediate levels: {jumps}."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("skipped_jumps={jumps}"),
            )],
            remediation: Some(
                "Maintain sequential heading levels without skipping ranks.".to_owned(),
            ),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_HEADING_HIERARCHY.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_landmarks(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.landmarks.main_count == 1 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!(
                "Expected one <main> landmark (found {})",
                obs.landmarks.main_count
            ),
            summary: format!(
                "Observed landmarks: main={}, nav={}, header={}, footer={}.",
                obs.landmarks.main_count,
                obs.landmarks.nav_count,
                obs.landmarks.header_count,
                obs.landmarks.footer_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("main_count={}", obs.landmarks.main_count),
            )],
            remediation: Some(
                "Wrap primary page content in a single `<main>` landmark element.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LANDMARKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_interactive_semantics(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let total_issues =
        obs.links_without_href + obs.clickable_generic_containers + obs.nested_interactive_count;

    if total_issues == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    if obs.clickable_generic_containers > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Generic <div>/<span> used with onclick ({})",
                obs.clickable_generic_containers
            ),
            summary: "Interactive click handlers on generic containers lack native keyboard and role semantics.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("clickable_generic_containers={}", obs.clickable_generic_containers),
            )],
            remediation: Some("Use native `<button>` or `<a href>` elements instead of clickable <div>/<span>.".to_owned()),
        });
    }

    if obs.nested_interactive_count > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Nested interactive elements ({})", obs.nested_interactive_count),
            summary: "Interactive elements (`<a>`, `<button>`, form controls) must not be nested inside each other.".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("nested_interactive_count={}", obs.nested_interactive_count),
            )],
            remediation: Some("Separate nested links, buttons, and inputs into sibling elements.".to_owned()),
        });
    }

    if obs.links_without_href > 0 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("<a> elements without href ({})", obs.links_without_href),
            summary:
                "Anchor tags without `href` behave as non-focusable placeholders rather than links."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("links_without_href={}", obs.links_without_href),
            )],
            remediation: Some(
                "Use `<button type=\"button\">` for actions or supply a valid `href`.".to_owned(),
            ),
        });
    }

    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_INTERACTIVE_SEMANTICS.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_container_ratio(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.total_elements < 20 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "Too few elements (< 20) to evaluate generic container ratio".to_owned(),
        });
        return;
    }

    let generic = obs.div_count + obs.span_count;
    // Use integer cross-multiplication to avoid floating-point casts.
    if generic * 100 > obs.total_elements * 75 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "High proportion of generic <div>/<span> containers".to_owned(),
            summary: format!(
                "{generic} of {} elements ({:.0}%) are generic <div>/<span> containers; verify semantic elements are used where appropriate.",
                obs.total_elements,
                (generic * 100) / obs.total_elements
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("generic={generic},total={}", obs.total_elements),
            )],
            remediation: Some(
                "Review whether sectioning/landmark elements (`<section>`, `<article>`, `<nav>`) fit key regions."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CONTAINER_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_charset(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.charset_declared {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CHARSET.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CHARSET.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing HTML <meta charset> declaration".to_owned(),
            summary: "Document does not declare `<meta charset=\"utf-8\">` (or Content-Type meta)."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "meta.charset=absent",
            )],
            remediation: Some("Add `<meta charset=\"utf-8\">` early inside `<head>`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CHARSET.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_skip_link(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.landmarks.nav_count == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SKIP_LINK.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <nav> landmark present".to_owned(),
        });
        return;
    }

    if obs.has_skip_link {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SKIP_LINK.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SKIP_LINK.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "No skip-navigation link detected".to_owned(),
            summary:
                "Document includes `<nav>` landmarks without an early `#main`/`#content` skip link."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("nav_count={};has_skip_link=false", obs.landmarks.nav_count),
            )],
            remediation: Some(
                "Add an early `<a href=\"#main-content\">Skip to main content</a>` link."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SKIP_LINK.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_meta_refresh(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if let Some(content) = &obs.meta_refresh {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_META_REFRESH.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Document uses <meta http-equiv=\"refresh\">".to_owned(),
            summary: format!(
                "Meta refresh (`{content}`) triggers unexpected redirects or reloads for assistive technology users."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("meta_refresh={content}"),
            )],
            remediation: Some(
                "Replace `<meta http-equiv=\"refresh\">` with server-side HTTP 301/302/308 redirects."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_META_REFRESH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_META_REFRESH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_favicon(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.has_favicon {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FAVICON.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FAVICON.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "No favicon link declared".to_owned(),
            summary:
                "Document `<head>` lacks `<link rel=\"icon\">` or `<link rel=\"shortcut icon\">`."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "has_favicon=false",
            )],
            remediation: Some(
                "Declare a `<link rel=\"icon\" href=\"/favicon.ico\">` or SVG icon in `<head>`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FAVICON.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_duplicate_main(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.landmarks.main_count <= 1 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_MAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_MAIN.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Multiple <main> landmarks ({})", obs.landmarks.main_count),
            summary: format!(
                "Document contains {} <main> elements; HTML5 permits only one visible primary `<main>` landmark.",
                obs.landmarks.main_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("main_count={}", obs.landmarks.main_count),
            )],
            remediation: Some("Retain a single visible `<main>` landmark per document.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_MAIN.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_empty_headings(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let empty_count = obs
        .headings
        .iter()
        .filter(|h| h.text.trim().is_empty())
        .count();
    if empty_count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EMPTY_HEADING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_EMPTY_HEADING.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Empty heading elements ({empty_count})"),
            summary: format!(
                "{empty_count} heading element(s) (`<h1>`–`<h6>`) contain no visible text."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("empty_headings={empty_count}"),
            )],
            remediation: Some(
                "Provide meaningful heading text or replace empty spacing headings with CSS."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EMPTY_HEADING.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_doctype(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.doctype_kind == Some("html5") {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INVALID_DOCTYPE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INVALID_DOCTYPE.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Missing or legacy HTML DOCTYPE declaration".to_owned(),
            summary: format!(
                "Document lacks `<!DOCTYPE html>` (detected={}), risking quirks-mode rendering.",
                obs.doctype_kind.unwrap_or("none")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("doctype={}", obs.doctype_kind.unwrap_or("none")),
            )],
            remediation: Some("Start every HTML5 document with `<!DOCTYPE html>`.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INVALID_DOCTYPE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_label_associations(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let broken: Vec<&str> = obs
        .label_for_ids
        .iter()
        .filter(|id| !obs.all_ids.contains(*id))
        .map(String::as_str)
        .collect();
    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_INVALID_LABEL_ASSOC.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_INVALID_LABEL_ASSOC.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Broken <label for> associations ({})", broken.len()),
            summary: format!(
                "{} `<label for=\"...\">` attribute(s) reference missing element IDs.",
                broken.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("broken_label_for={}", broken.len()),
            )],
            remediation: Some(
                "Ensure every `<label for=\"id\">` matches an existing form control `id`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_INVALID_LABEL_ASSOC.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_form_submit_controls(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.forms.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_FORM_MISSING_SUBMIT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no <form> elements present".to_owned(),
        });
        return;
    }

    let missing = obs
        .forms
        .iter()
        .filter(|form| !form.has_submit_control)
        .count();
    if missing == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FORM_MISSING_SUBMIT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_FORM_MISSING_SUBMIT.to_owned()),
        category: FindingCategory::Semantics,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Low,
        confidence: Confidence::Medium,
        title: format!("{missing} <form> element(s) lack a submit control"),
        summary: format!(
            "{missing} form(s) contain no `<button type=\"submit\">` or `<input type=\"submit\">`."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("forms_without_submit={missing}"),
        )],
        remediation: Some(
            "Provide an explicit `<button type=\"submit\">` or `<input type=\"submit\">` inside each `<form>`."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_FORM_MISSING_SUBMIT.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_nested_interactive(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.nested_interactive_count == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_NESTED_INTERACTIVE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_NESTED_INTERACTIVE.to_owned()),
        category: FindingCategory::Semantics,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!(
            "Nested interactive elements detected ({})",
            obs.nested_interactive_count
        ),
        summary: format!(
            "Found {} interactive element(s) nested inside `<a>` or `<button>`, which violates HTML5 content models.",
            obs.nested_interactive_count
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("nested_interactive={}", obs.nested_interactive_count),
        )],
        remediation: Some(
            "Unnest `<button>` and `<a href>` elements so each interactive control is a sibling rather than a descendant."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_NESTED_INTERACTIVE.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicate_ids_and_heading_skip() {
        let html = r#"<html><body><main>
            <h1 id="x">One</h1><h3 id="x">Skipped</h3>
        </main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_DUPLICATE_IDS)
        );
        assert!(
            res.findings
                .iter()
                .any(|f| { f.rule_id.0 == RULE_HEADING_HIERARCHY && f.title.contains("Skipped") })
        );
    }

    #[test]
    fn detects_clickable_div_and_nested_button() {
        let html = r#"<html><body><main><h1>Ok</h1>
            <div onclick="go()">Click</div>
            <a href="/a"><button>Nested</button></a>
        </main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_INTERACTIVE_SEMANTICS && f.severity == Severity::High)
        );
    }

    #[test]
    fn flags_missing_charset_and_skip_link() {
        let html = r#"<html><head><title>T</title></head><body>
            <nav><a href="/home">Home</a></nav><main><h1>Hi</h1></main>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_CHARSET));
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_SKIP_LINK));
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_FAVICON));
    }

    #[test]
    fn flags_meta_refresh() {
        let html = r#"<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3;url=/other"><link rel="icon" href="/favicon.ico"></head><body><main><h1>Hi</h1></main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_META_REFRESH)
        );
        assert!(!res.findings.iter().any(|f| f.rule_id.0 == RULE_FAVICON));
    }

    #[test]
    fn flags_duplicate_main_and_empty_headings() {
        let html = r#"<html><head><meta charset="utf-8"><link rel="icon" href="/f.ico"></head>
            <body><main><h1>Main</h1></main><main><h2></h2></main></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_DUPLICATE_MAIN));
        assert!(ids.contains(&RULE_EMPTY_HEADING));
    }

    #[test]
    fn flags_missing_doctype_and_broken_label_for() {
        let html = r#"<html><body><label for="missing_input">Email</label></body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_INVALID_DOCTYPE));
        assert!(ids.contains(&RULE_INVALID_LABEL_ASSOC));
    }

    #[test]
    fn flags_form_missing_submit_and_nested_interactive() {
        let html = r#"<!doctype html><html><body>
            <form action="/search"><input type="text"></form>
            <a href="/x"><button type="button">Nested</button></a>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        let res = analyse(&obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_FORM_MISSING_SUBMIT));
        assert!(ids.contains(&RULE_NESTED_INTERACTIVE));
    }
}
