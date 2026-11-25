//! `InhaltsZwerg` — Phase 1 content quality and freshness checks.
//!
//! Consumes shared [`DocumentObservations`] and HTTP headers without
//! duplicating HTML parsing.

use crate::analysis::document::DocumentObservations;
use crate::analysis::header_value;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, RuleId, Severity,
};

const RULE_THIN_CONTENT: &str = "inh.content.thin_content";
const RULE_FRESHNESS_HEADERS: &str = "inh.content.freshness_headers";
const RULE_PLACEHOLDER: &str = "inh.content.placeholder_text";
const RULE_TITLE_H1_MATCH: &str = "inh.content.title_h1_duplication";
const RULE_LEGAL_LINKS: &str = "inh.trust.legal_links";
const RULE_MOJIBAKE: &str = "inh.content.mojibake";
const RULE_UNRENDERED_MARKUP: &str = "inh.content.unrendered_markup";
const RULE_STALE_COPYRIGHT: &str = "inh.content.stale_copyright";
const RULE_READABILITY: &str = "inh.content.readability";
const RULE_AUTHOR_OR_DATE: &str = "inh.trust.author_or_date";
const RULE_TEXT_TO_HTML_RATIO: &str = "inh.content.text_to_html_ratio";
const RULE_AX_SIGNALS: &str = "inh.ax.machine_readable_signals";
const RULE_UNRESOLVED_I18N_KEY: &str = "inh.integrity.unresolved_translation_key";
const RULE_PLACEHOLDER_CONTACT: &str = "inh.integrity.placeholder_contact";

/// All rule identifiers owned by `InhaltsZwerg`.
pub const ALL_RULES: &[&str] = &[
    RULE_THIN_CONTENT,
    RULE_FRESHNESS_HEADERS,
    RULE_PLACEHOLDER,
    RULE_TITLE_H1_MATCH,
    RULE_LEGAL_LINKS,
    RULE_MOJIBAKE,
    RULE_UNRENDERED_MARKUP,
    RULE_STALE_COPYRIGHT,
    RULE_READABILITY,
    RULE_AUTHOR_OR_DATE,
    RULE_TEXT_TO_HTML_RATIO,
    RULE_AX_SIGNALS,
    RULE_UNRESOLVED_I18N_KEY,
    RULE_PLACEHOLDER_CONTACT,
];

/// Evaluates visible word count, freshness headers, and content quality signals over `http` and `obs`.
#[must_use]
pub fn analyse(http: &HttpEvidence, obs: &DocumentObservations) -> AnalyserResult {
    let mut findings = Vec::new();
    let mut checks = Vec::new();

    check_thin_content(obs, &mut findings, &mut checks);
    check_freshness_headers(http, &mut findings, &mut checks);
    check_placeholder_text(obs, &mut findings, &mut checks);
    check_title_h1_duplication(obs, &mut findings, &mut checks);
    check_legal_links(obs, &mut findings, &mut checks);
    check_mojibake(obs, &mut findings, &mut checks);
    check_unrendered_markup(obs, &mut findings, &mut checks);
    check_stale_copyright(obs, &mut findings, &mut checks);
    check_readability(obs, &mut findings, &mut checks);
    check_author_or_date(obs, &mut findings, &mut checks);
    check_text_to_html_ratio(http, obs, &mut findings, &mut checks);
    check_ax_signals(obs, &mut findings, &mut checks);
    check_unresolved_translation_keys(obs, &mut findings, &mut checks);
    check_placeholder_contact(obs, &mut findings, &mut checks);

    AnalyserResult {
        dwarf_id: DwarfId::Inhalts,
        findings,
        checks,
    }
}

fn check_thin_content(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 30 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Very thin visible content ({} words)", obs.visible_word_count),
            summary: format!(
                "Extracted only {} visible words ({} chars) from source HTML body.",
                obs.visible_word_count, obs.visible_char_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("visible_word_count={}", obs.visible_word_count),
            )],
            remediation: Some(
                "Ensure substantive content is rendered in HTML or verify if content is client-side rendered."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if obs.visible_word_count < 100 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Low,
            title: format!("Limited visible content ({} words)", obs.visible_word_count),
            summary: format!(
                "Extracted {} visible words from source HTML body (< 100 words).",
                obs.visible_word_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("visible_word_count={}", obs.visible_word_count),
            )],
            remediation: Some(
                "Consider expanding page copy if this is an informational page.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_THIN_CONTENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_freshness_headers(
    http: &HttpEvidence,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if header_value(http, "last-modified").is_some_and(|v| !v.trim().is_empty()) {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "No Last-Modified header observed".to_owned(),
            summary: "HTTP response did not include a `Last-Modified` freshness timestamp."
                .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpHeaders,
                "last-modified=absent",
            )],
            remediation: Some(
                "Expose `Last-Modified` where content modification timestamps are meaningful."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_FRESHNESS_HEADERS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_placeholder_text(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let lower = obs.visible_text_sample.to_ascii_lowercase();
    let markers = [
        "lorem ipsum",
        "dolor sit amet",
        "coming soon",
        "under construction",
    ];
    let matched: Vec<&str> = markers
        .iter()
        .copied()
        .filter(|m| lower.contains(m))
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Placeholder text detected in visible content".to_owned(),
            summary: format!("Matched placeholder phrase(s): {}", matched.join(", ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("placeholder_matches={}", matched.join(",")),
            )],
            remediation: Some(
                "Replace placeholder copy with final production content before release.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PLACEHOLDER.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_title_h1_duplication(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(title) = obs.title.as_deref() else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "title missing".to_owned(),
        });
        return;
    };
    let Some(h1) = obs.headings.iter().find(|h| h.level == 1) else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "h1 missing".to_owned(),
        });
        return;
    };

    if title.eq_ignore_ascii_case(h1.text.trim()) {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: "Page <title> and <h1> are identical".to_owned(),
            summary: format!(
                "`<title>` and primary `<h1>` both read `{}`.",
                h1.text.trim()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "title_equals_h1=true",
            )],
            remediation: Some(
                "Differentiate `<title>` (search snippet) from `<h1>` (on-page headline) where helpful."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TITLE_H1_MATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_legal_links(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 100 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page has < 100 visible words".to_owned(),
        });
        return;
    }

    let has_legal_or_contact = obs.links.iter().any(|l| {
        let combined = format!(
            "{} {}",
            l.href.to_ascii_lowercase(),
            l.text.to_ascii_lowercase()
        );
        [
            "privacy",
            "datenschutz",
            "impressum",
            "imprint",
            "terms",
            "legal",
            "contact",
            "kontakt",
        ]
        .iter()
        .any(|kw| combined.contains(kw))
    });

    if has_legal_or_contact {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: "No legal, privacy, or contact links detected".to_owned(),
            summary:
                "No links matching privacy, imprint/legal, terms, or contact were found on this page."
                    .to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("links_checked={}", obs.links.len()),
            )],
            remediation: Some(
                "Expose clear footer links to privacy policy, legal notice/imprint, and contact."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LEGAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_mojibake(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let sample = &obs.visible_text_sample;
    let markers = ["Ã¤", "Ã¶", "Ã¼", "ÃŸ", "Ã©", "â€™", "â€œ", "\u{FFFD}"];
    let matched: Vec<&str> = markers
        .iter()
        .copied()
        .filter(|m| sample.contains(m))
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MOJIBAKE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MOJIBAKE.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Character encoding corruption (mojibake) detected".to_owned(),
            summary: format!(
                "Visible text contains likely UTF-8/Latin-1 decoding artefacts ({} pattern(s)).",
                matched.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("mojibake_patterns={}", matched.len()),
            )],
            remediation: Some(
                "Ensure UTF-8 encoding across database, templates, and HTTP `Content-Type` headers."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MOJIBAKE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_unrendered_markup(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let sample = &obs.visible_text_sample;
    let markers = ["{{", "}}", "<%", "%>", "[object Object]"];
    let matched: Vec<&str> = markers
        .iter()
        .copied()
        .filter(|m| sample.contains(m))
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNRENDERED_MARKUP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_UNRENDERED_MARKUP.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Unrendered template syntax or JS leakage in visible text".to_owned(),
            summary: format!("Detected raw template/runtime tokens: {}.", matched.join(", ")),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("unrendered_tokens={}", matched.len()),
            )],
            remediation: Some(
                "Verify server/client template rendering and strip unresolved interpolation tokens."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_UNRENDERED_MARKUP.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_stale_copyright(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let sample = &obs.visible_text_sample;
    let lower = sample.to_ascii_lowercase();
    let mut years = Vec::new();
    for marker in ["©", "copyright"] {
        for (idx, _) in lower.match_indices(marker) {
            let tail = &sample[idx..sample.len().min(idx + 32)];
            for tok in tail.split(|c: char| !c.is_ascii_digit()) {
                if tok.len() == 4
                    && let Ok(yr) = tok.parse::<u16>()
                    && (1995..=2030).contains(&yr)
                {
                    years.push(yr);
                }
            }
        }
    }

    let Some(&max_year) = years.iter().max() else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_STALE_COPYRIGHT.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no copyright year detected in visible sample".to_owned(),
        });
        return;
    };

    if max_year < 2024 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_STALE_COPYRIGHT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: format!("Potentially stale copyright year ({max_year})"),
            summary: format!("Latest detected copyright year in page sample is {max_year}."),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("copyright_year={max_year}"),
            )],
            remediation: Some(
                "Update footer copyright notice if the site is actively maintained.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_STALE_COPYRIGHT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_STALE_COPYRIGHT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_readability(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 120 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_READABILITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 120 visible words for readability assessment".to_owned(),
        });
        return;
    }

    let sample_words = obs.visible_text_sample.split_whitespace().count();
    let sentence_endings = obs
        .visible_text_sample
        .chars()
        .filter(|&c| matches!(c, '.' | '!' | '?'))
        .count()
        .max(1);
    let avg_words_per_sentence = sample_words / sentence_endings;

    if avg_words_per_sentence > 32 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_READABILITY.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Low,
            title: format!("Dense sentence structure (~{avg_words_per_sentence} words/sentence)"),
            summary: format!(
                "Sampled visible copy averages ~{avg_words_per_sentence} words per sentence (> 32)."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("avg_words_per_sentence={avg_words_per_sentence}"),
            )],
            remediation: Some(
                "Break long paragraphs into shorter sentences and scannable headings/lists."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_READABILITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_READABILITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_author_or_date(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 150 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_AUTHOR_OR_DATE.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page has fewer than 150 visible words".to_owned(),
        });
        return;
    }

    if obs.author_or_date_signal.is_some() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AUTHOR_OR_DATE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AUTHOR_OR_DATE.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "Substantive content lacks author or publication date metadata".to_owned(),
            summary: format!(
                "Page has {} visible words without `<meta name=\"author\">`, `<time datetime>`, or Schema.org author/datePublished.",
                obs.visible_word_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("visible_word_count={};author_or_date=none", obs.visible_word_count),
            )],
            remediation: Some(
                "Add author attribution and publication/updated `<time datetime>` or JSON-LD `datePublished`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AUTHOR_OR_DATE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_text_to_html_ratio(
    http: &HttpEvidence,
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if http.body_bytes < 2048 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_TEXT_TO_HTML_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "HTML payload smaller than 2048 bytes".to_owned(),
        });
        return;
    }

    let ratio_pct = (obs.visible_char_count * 100) / http.body_bytes.max(1);
    if ratio_pct < 5 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_TEXT_TO_HTML_RATIO.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Low visible text-to-HTML ratio ({ratio_pct}%)"),
            summary: format!(
                "Only {} visible chars out of {} HTML bytes ({ratio_pct}% < 5%).",
                obs.visible_char_count, http.body_bytes
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "visible_chars={};body_bytes={}",
                    obs.visible_char_count, http.body_bytes
                ),
            )],
            remediation: Some(
                "Reduce inline script/markup bloat or render substantive text server-side."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_TEXT_TO_HTML_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TEXT_TO_HTML_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_ax_signals(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 150 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_AX_SIGNALS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "page has fewer than 150 visible words".to_owned(),
        });
        return;
    }

    let has_landmarks = obs.landmarks.main_count > 0 && !obs.headings.is_empty();
    let has_structured = obs.json_ld_count > 0;
    if has_landmarks && has_structured {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_AX_SIGNALS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_AX_SIGNALS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::Medium,
            title: "Incomplete Agent Experience (AX) machine-readable signals".to_owned(),
            summary: format!(
                "Substantive page lacks complete machine-readable structure (main_count={}, headings={}, json_ld={}).",
                obs.landmarks.main_count,
                obs.headings.len(),
                obs.json_ld_count
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "main={};headings={};json_ld={}",
                    obs.landmarks.main_count,
                    obs.headings.len(),
                    obs.json_ld_count
                ),
            )],
            remediation: Some(
                "Wrap primary content in `<main>` with clear headings and Schema.org JSON-LD."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_AX_SIGNALS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_unresolved_translation_keys(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const PREFIXES: &[&str] = &["i18n.", "common.", "nav.", "errors.", "buttons.", "labels."];
    let matched: Vec<&str> = obs
        .visible_text_sample
        .split_whitespace()
        .filter(|tok| {
            let clean =
                tok.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_');
            PREFIXES.iter().any(|p| clean.starts_with(p)) && clean.matches('.').count() >= 2
        })
        .take(5)
        .collect();

    if matched.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNRESOLVED_I18N_KEY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_UNRESOLVED_I18N_KEY.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Unresolved translation keys in visible text ({})",
                matched.len()
            ),
            summary: format!(
                "Detected raw localisation key tokens in rendered text: {}.",
                matched.join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("unresolved_i18n_keys={}", matched.join(",")),
            )],
            remediation: Some("Verify i18n message bundle loading and fallback keys.".to_owned()),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_UNRESOLVED_I18N_KEY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_placeholder_contact(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    const PLACEHOLDERS: &[&str] = &[
        "example@example.com",
        "test@example.com",
        "info@example.com",
        "info@example.org",
        "test@test.com",
        "123-456-7890",
        "555-0100",
    ];
    let text_lower = obs.visible_text_sample.to_ascii_lowercase();
    let in_text = PLACEHOLDERS.iter().any(|p| text_lower.contains(p));
    let in_links = obs.links.iter().any(|l| {
        let href = l.href.to_ascii_lowercase();
        (href.starts_with("mailto:") || href.starts_with("tel:"))
            && PLACEHOLDERS.iter().any(|p| href.contains(p))
    });

    if !in_text && !in_links {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_PLACEHOLDER_CONTACT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_PLACEHOLDER_CONTACT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Placeholder contact details published".to_owned(),
            summary: "Page contains placeholder email or telephone numbers (for example `example.com` or `555-0100`).".to_owned(),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "placeholder_contact=true",
            )],
            remediation: Some(
                "Replace template contact placeholders with real organisation details.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_PLACEHOLDER_CONTACT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, HttpHeader, Measurement, MeasurementUnit, TargetPolicy};

    fn http_with_body(
        body: &str,
        headers: Vec<(&str, &str)>,
    ) -> (HttpEvidence, DocumentObservations) {
        let _ = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let http = HttpEvidence {
            final_url: "https://example.com/".to_owned(),
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
                value: 10,
                unit: MeasurementUnit::Milliseconds,
            },
            body_bytes: body.len(),
            body_truncated: false,
            body_text: body.to_owned(),
        };
        let obs = DocumentObservations::from_html(body);
        (http, obs)
    }

    #[test]
    fn flags_very_thin_content_and_ignores_scripts() {
        let html = "<html><body><script>var x = 'one two three four five';</script><p>Hello world</p></body></html>";
        let (http, obs) = http_with_body(html, Vec::new());
        assert_eq!(obs.visible_word_count, 2);
        let res = analyse(&http, &obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_THIN_CONTENT && f.severity == Severity::Medium)
        );
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_FRESHNESS_HEADERS)
        );
    }

    #[test]
    fn passes_for_substantive_content_with_last_modified() {
        let words = vec!["Clear sentence with readable words."; 25].join(" ");
        let html = format!(
            "<html><body><main><p>{words}</p></main><footer><a href=\"/privacy\">Privacy</a></footer></body></html>"
        );
        let (http, obs) = http_with_body(
            &html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        assert_eq!(res.findings.len(), 0);
    }

    #[test]
    fn flags_placeholder_title_h1_match_and_missing_legal_links() {
        let words = vec!["content"; 110].join(" ");
        let html = format!(
            "<html><head><title>Same Headline</title></head><body><h1>Same Headline</h1><p>Lorem ipsum {words}</p></body></html>"
        );
        let (http, obs) = http_with_body(
            &html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_PLACEHOLDER));
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_TITLE_H1_MATCH)
        );
        assert!(res.findings.iter().any(|f| f.rule_id.0 == RULE_LEGAL_LINKS));
    }

    #[test]
    fn flags_mojibake_unrendered_markup_stale_copyright_and_dense_readability() {
        let long_sentence = vec!["word"; 130].join(" ");
        let html = format!(
            "<html><body><p>Broken Ã¤ {{user.name}} [object Object] {long_sentence}</p><footer>© 2021 Acme</footer></body></html>"
        );
        let (http, obs) = http_with_body(&html, Vec::new());
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_MOJIBAKE));
        assert!(ids.contains(&RULE_UNRENDERED_MARKUP));
        assert!(ids.contains(&RULE_STALE_COPYRIGHT));
        assert!(ids.contains(&RULE_READABILITY));
    }

    #[test]
    fn flags_missing_author_or_date_on_substantive_content() {
        let words = vec!["Substantive editorial sentence with clear structure."; 30].join(" ");
        let html = format!("<html><body><main><p>{words}</p></main></body></html>");
        let (http, obs) = http_with_body(&html, Vec::new());
        let res = analyse(&http, &obs);
        assert!(
            res.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_AUTHOR_OR_DATE)
        );
    }

    #[test]
    fn flags_low_text_to_html_ratio_and_incomplete_ax_signals() {
        let padding = "<div><span></span></div>".repeat(150);
        let words = vec!["word"; 160].join(" ");
        let html = format!("<html><body>{padding}<p>{words}</p></body></html>");
        let (http, obs) = http_with_body(&html, Vec::new());
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_AX_SIGNALS));
        let tiny_text_html = format!("<html><body>{padding}<p>hi</p></body></html>");
        let (http2, obs2) = http_with_body(&tiny_text_html, Vec::new());
        let res2 = analyse(&http2, &obs2);
        assert!(
            res2.findings
                .iter()
                .any(|f| f.rule_id.0 == RULE_TEXT_TO_HTML_RATIO)
        );
    }

    #[test]
    fn flags_unresolved_i18n_keys_and_placeholder_contacts() {
        let html = r#"<html><body>
            <p>Welcome to i18n.home.hero_title and common.nav.submit</p>
            <a href="mailto:test@example.com">Contact test@example.com</a>
        </body></html>"#;
        let (http, obs) = http_with_body(html, Vec::new());
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_UNRESOLVED_I18N_KEY));
        assert!(ids.contains(&RULE_PLACEHOLDER_CONTACT));
    }
}
