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
const RULE_ALL_CAPS_HEADINGS: &str = "inh.content.all_caps_headings";
const RULE_DOUBLE_ESCAPED_ENTITIES: &str = "inh.integrity.double_escaped_entities";
const RULE_LANGUAGE_MISMATCH: &str = "inh.i18n.language_mismatch";
const RULE_EXCESSIVE_LINK_DENSITY: &str = "inh.content.excessive_link_density";
const RULE_REPEATED_HEADINGS: &str = "inh.content.repeated_headings";
const RULE_MIXED_PARAGRAPHS: &str = "inh.language.mixed_paragraphs";
const RULE_UNTRANSLATED_FRAGMENT: &str = "inh.language.untranslated_fragment";
const RULE_BOILERPLATE_RATIO: &str = "inh.content.boilerplate_ratio";
const RULE_DUPLICATE_PARAGRAPHS: &str = "inh.content.duplicate_paragraphs";
const RULE_EMPTY_SECTIONS: &str = "inh.content.empty_sections";
const RULE_TRUNCATED_TEXT: &str = "inh.content.truncated_text";

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
    RULE_ALL_CAPS_HEADINGS,
    RULE_DOUBLE_ESCAPED_ENTITIES,
    RULE_LANGUAGE_MISMATCH,
    RULE_EXCESSIVE_LINK_DENSITY,
    RULE_REPEATED_HEADINGS,
    RULE_MIXED_PARAGRAPHS,
    RULE_UNTRANSLATED_FRAGMENT,
    RULE_BOILERPLATE_RATIO,
    RULE_DUPLICATE_PARAGRAPHS,
    RULE_EMPTY_SECTIONS,
    RULE_TRUNCATED_TEXT,
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
    check_all_caps_headings(obs, &mut findings, &mut checks);
    check_double_escaped_entities(obs, &mut findings, &mut checks);
    check_language_mismatch(obs, &mut findings, &mut checks);
    check_link_density_and_repeated_headings(obs, &mut findings, &mut checks);
    check_content_intelligence(obs, &mut findings, &mut checks);

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

fn check_all_caps_headings(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.headings.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_ALL_CAPS_HEADINGS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no headings present".to_owned(),
        });
        return;
    }

    let shouty: Vec<&str> = obs
        .headings
        .iter()
        .filter(|h| {
            let alpha: Vec<char> = h.text.chars().filter(|c| c.is_alphabetic()).collect();
            alpha.len() >= 8 && alpha.iter().all(|c| c.is_uppercase())
        })
        .map(|h| h.text.as_str())
        .collect();

    if shouty.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ALL_CAPS_HEADINGS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_ALL_CAPS_HEADINGS.to_owned()),
        category: FindingCategory::Content,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Low,
        confidence: Confidence::High,
        title: format!("All-uppercase headings detected ({})", shouty.len()),
        summary: format!(
            "{} heading(s) use all-uppercase text in source HTML (for example `{}`), reducing scannability.",
            shouty.len(),
            shouty[0]
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("all_caps_headings={}", shouty.len()),
        )],
        remediation: Some(
            "Write headings in natural sentence or title case and apply CSS `text-transform: uppercase` if needed."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_ALL_CAPS_HEADINGS.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_double_escaped_entities(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let artefacts = ["&amp;", "&lt;", "&gt;", "&nbsp;", "&quot;"];
    let matched = artefacts
        .into_iter()
        .find(|pat| obs.visible_text_sample.contains(pat));

    let Some(pat) = matched else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DOUBLE_ESCAPED_ENTITIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    };

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_DOUBLE_ESCAPED_ENTITIES.to_owned()),
        category: FindingCategory::Content,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: "Double-escaped HTML entities in visible text".to_owned(),
        summary: format!(
            "Visible text contains literal entity sequence `{pat}` after HTML decoding, indicating double-escaping."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("double_escaped_entity={pat}"),
        )],
        remediation: Some(
            "Decode or normalise upstream content once before HTML template escaping.".to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_DOUBLE_ESCAPED_ENTITIES.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_language_mismatch(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(declared_raw) = obs
        .html_lang
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LANGUAGE_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "declared <html lang> unavailable".to_owned(),
        });
        return;
    };
    let declared = declared_raw
        .split(['-', '_'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let Some(detected) = detect_dominant_language(&obs.visible_text_sample) else {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_LANGUAGE_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "insufficient text sample for deterministic language detection".to_owned(),
        });
        return;
    };

    if declared == detected {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LANGUAGE_MISMATCH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_LANGUAGE_MISMATCH.to_owned()),
        category: FindingCategory::Content,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Heuristic,
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        title: format!("Declared language `{declared_raw}` mismatches detected `{detected}` text"),
        summary: format!(
            "`<html lang=\"{declared_raw}\">` disagrees with dominant stopword profile `{detected}` in visible text."
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody,
            format!("html_lang={declared_raw};detected_lang={detected}"),
        )],
        remediation: Some(format!(
            "Update `<html lang>` to `{detected}` or ensure page copy matches `{declared_raw}`."
        )),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_LANGUAGE_MISMATCH.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

/// Detect dominant language using whatlang. Returns ISO 639-1 code if confident.
fn detect_dominant_language(text: &str) -> Option<&'static str> {
    if text.len() < 50 {
        return None;
    }
    let info = whatlang::detect(text)?;
    if !info.is_reliable() {
        return None;
    }
    Some(match info.lang() {
        whatlang::Lang::Eng => "en",
        whatlang::Lang::Deu => "de",
        whatlang::Lang::Pol => "pl",
        whatlang::Lang::Fra => "fr",
        whatlang::Lang::Spa => "es",
        whatlang::Lang::Nld => "nl",
        whatlang::Lang::Ita => "it",
        whatlang::Lang::Por => "pt",
        whatlang::Lang::Rus => "ru",
        whatlang::Lang::Jpn => "ja",
        whatlang::Lang::Kor => "ko",
        whatlang::Lang::Cmn => "zh",
        whatlang::Lang::Ara => "ar",
        whatlang::Lang::Hin => "hi",
        whatlang::Lang::Swe => "sv",
        whatlang::Lang::Dan => "da",
        whatlang::Lang::Fin => "fi",
        whatlang::Lang::Ces => "cs",
        whatlang::Lang::Ukr => "uk",
        _ => return None,
    })
}

fn check_link_density_and_repeated_headings(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.visible_word_count < 30 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_EXCESSIVE_LINK_DENSITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "visible word count below 30 words".to_owned(),
        });
    } else {
        let link_words: usize = obs
            .links
            .iter()
            .map(|l| l.text.split_whitespace().count())
            .sum();
        if link_words.saturating_mul(100) / obs.visible_word_count > 60 {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(RULE_EXCESSIVE_LINK_DENSITY.to_owned()),
                category: FindingCategory::Content,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Heuristic,
                severity: Severity::Low,
                confidence: Confidence::Medium,
                title: "High link-text density over editorial content".to_owned(),
                summary: format!(
                    "Anchor text accounts for {link_words} of {} visible words (> 60%).",
                    obs.visible_word_count
                ),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    format!(
                        "link_words={link_words};visible_words={}",
                        obs.visible_word_count
                    ),
                )],
                remediation: Some(
                    "Balance navigation/link lists with substantive descriptive copy.".to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(RULE_EXCESSIVE_LINK_DENSITY.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_EXCESSIVE_LINK_DENSITY.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }

    let mut counts = std::collections::HashMap::new();
    for h in &obs.headings {
        let norm = h.text.trim().to_ascii_lowercase();
        if norm.len() >= 6 {
            *counts.entry(norm).or_insert(0usize) += 1;
        }
    }
    let repeated: Vec<(String, usize)> = counts.into_iter().filter(|(_, c)| *c >= 3).collect();
    if repeated.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_REPEATED_HEADINGS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_REPEATED_HEADINGS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Repeated identical headings ({})", repeated.len()),
            summary: format!(
                "Heading `{}` appears {} times on the same page.",
                repeated[0].0, repeated[0].1
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("repeated_heading_groups={}", repeated.len()),
            )],
            remediation: Some(
                "Give repeated cards/sections distinct headings so users and screen readers can differentiate them."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_REPEATED_HEADINGS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

/// Advanced content intelligence scanner covering language mixing, duplicate paragraphs,
/// truncation detection, and empty sections.
fn check_content_intelligence(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let content = &obs.content;
    if content.paragraphs_truncated {
        for rule in [
            RULE_MIXED_PARAGRAPHS,
            RULE_UNTRANSLATED_FRAGMENT,
            RULE_DUPLICATE_PARAGRAPHS,
        ] {
            skip_content_check(checks, rule, "source paragraph retention limit reached");
        }
    } else {
        let paragraphs: Vec<_> = content
            .paragraphs
            .iter()
            .filter(|paragraph| paragraph.text.split_whitespace().count() >= 10)
            .collect();
        let document_language = obs.html_lang.as_deref().map(primary_language);
        let mixing_sample: Vec<_> = paragraphs
            .iter()
            .filter(|paragraph| {
                !paragraph.has_nested_language
                    && paragraph.language().map(primary_language) == document_language
            })
            .copied()
            .collect();
        check_mixed_paragraphs(&mixing_sample, findings, checks);
        check_untranslated_fragments(&paragraphs, findings, checks);
        check_duplicate_paragraphs_impl(&paragraphs, findings, checks);
    }
    skip_content_check(
        checks,
        RULE_TRUNCATED_TEXT,
        "visible clipping requires rendered geometry",
    );
    check_empty_sections(obs, findings, checks);
    check_boilerplate(obs, findings, checks);
}

fn check_mixed_paragraphs(
    paragraphs: &[&super::segmentation::ParagraphObservation],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if paragraphs.len() < 2 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_MIXED_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 2 substantial paragraphs".to_owned(),
        });
        return;
    }

    let detected: Vec<_> = paragraphs
        .iter()
        .filter_map(|paragraph| {
            detect_dominant_language(&paragraph.text).map(|language| (paragraph.element, language))
        })
        .collect();
    let unique_langs: std::collections::BTreeSet<_> =
        detected.iter().map(|(_, language)| *language).collect();

    if unique_langs.len() >= 2 {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_MIXED_PARAGRAPHS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: Confidence::Medium,
            title: format!("Mixed language paragraphs detected ({} languages)", unique_langs.len()),
            summary: format!(
                "Page content contains paragraphs in multiple languages: {}.",
                unique_langs.iter().copied().collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: detected.iter().map(|(element, language)| EvidenceRef::new(EvidenceSource::HttpBody, format!("body-element={};detected={language}", element.0))).collect(),
            remediation: Some(
                "Ensure consistent language per page or use lang attributes on mixed-language sections.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_MIXED_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else if detected.len() < paragraphs.len() {
        skip_content_check(
            checks,
            RULE_MIXED_PARAGRAPHS,
            "reliable language detection is incomplete",
        );
    } else {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_MIXED_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn primary_language(language: &str) -> String {
    language
        .split(['-', '_'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn check_untranslated_fragments(
    paragraphs: &[&super::segmentation::ParagraphObservation],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let comparisons: Vec<_> = paragraphs
        .iter()
        .filter_map(|paragraph| {
            if paragraph.has_nested_language {
                return None;
            }
            let declared = primary_language(paragraph.language()?);
            let detected = detect_dominant_language(&paragraph.text)?;
            (!declared.is_empty()).then_some((paragraph.element, declared, detected))
        })
        .collect();
    if comparisons.is_empty() {
        skip_content_check(
            checks,
            RULE_UNTRANSLATED_FRAGMENT,
            "no paragraphs with a declaration and reliable language detection",
        );
        return;
    }
    let mismatches: Vec<_> = comparisons
        .iter()
        .filter(|(_, declared, detected)| declared != detected)
        .collect();

    if mismatches.is_empty() && comparisons.len() < paragraphs.len() {
        skip_content_check(
            checks,
            RULE_UNTRANSLATED_FRAGMENT,
            "reliable language comparison is incomplete",
        );
    } else if mismatches.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_UNTRANSLATED_FRAGMENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let unique: std::collections::BTreeSet<_> =
            mismatches.iter().map(|(_, _, detected)| detected).collect();
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_UNTRANSLATED_FRAGMENT.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Untranslated fragments detected ({} mismatches)", mismatches.len()),
            summary: format!(
                "Detected language differs from the effective declaration in {} paragraph(s). Detected codes: {}.",
                mismatches.len(),
                unique.iter().map(|&&l| l).collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: mismatches.iter().map(|(element, _, detected)| EvidenceRef::new(EvidenceSource::HttpBody, format!("body-element={};detected={detected}", element.0))).collect(),
            remediation: Some(
                "Translate untranslated fragments or wrap them with appropriate lang attributes.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_UNTRANSLATED_FRAGMENT.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_duplicate_paragraphs_impl(
    paragraphs: &[&super::segmentation::ParagraphObservation],
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if paragraphs.len() < 2 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_DUPLICATE_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than 2 substantial paragraphs".to_owned(),
        });
        return;
    }

    let mut seen = std::collections::BTreeMap::<_, Vec<_>>::new();
    for &p in paragraphs {
        seen.entry(p.text.to_lowercase())
            .or_default()
            .push(p.element);
    }

    let duplicates: Vec<_> = seen
        .values()
        .filter(|elements| elements.len() >= 2)
        .collect();

    if duplicates.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        let total_dupes: usize = duplicates.iter().map(|elements| elements.len()).sum();
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_PARAGRAPHS.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Duplicate paragraphs detected ({} unique)",
                duplicates.len()
            ),
            summary: format!(
                "{} paragraph(s) appear multiple times. Total duplicates: {total_dupes}.",
                duplicates.len()
            ),
            evidence_refs: duplicates
                .iter()
                .flat_map(|elements| elements.iter())
                .map(|element| {
                    EvidenceRef::new(
                        EvidenceSource::HttpBody,
                        format!("body-element={}", element.0),
                    )
                })
                .collect(),
            remediation: Some(
                "Review and consolidate duplicate content or use component-based architecture."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_PARAGRAPHS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn skip_content_check(checks: &mut Vec<CheckStatus>, rule: &str, reason: &str) {
    checks.push(CheckStatus::Skipped {
        rule_id: RuleId(rule.to_owned()),
        evidence_level: EvidenceLevel::Source,
        reason: reason.to_owned(),
    });
}

fn check_empty_sections(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.content.regions_observed == 0 {
        skip_content_check(checks, RULE_EMPTY_SECTIONS, "no eligible source regions");
        return;
    }
    if obs.content.empty_regions.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EMPTY_SECTIONS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_EMPTY_SECTIONS.to_owned()),
        category: FindingCategory::Content,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Heuristic,
        severity: Severity::Low,
        confidence: Confidence::Low,
        title: "Empty regions in source HTML".to_owned(),
        summary: "The referenced regions contain neither child elements nor substantive source text. Check whether the application populates them at runtime.".to_owned(),
        evidence_refs: obs.content.empty_regions.iter().map(|element| EvidenceRef::new(
            EvidenceSource::HttpBody, format!("body-element={}", element.0),
        )).collect(),
        remediation: Some("Inspect the rendered regions and remove unused landmarks.".to_owned()),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_EMPTY_SECTIONS.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_boilerplate(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let Some(words) = obs.content.main_words else {
        skip_content_check(
            checks,
            RULE_BOILERPLATE_RATIO,
            "requires a unique main landmark and eligible source text",
        );
        return;
    };
    if words.outside_main <= words.total / 2 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_BOILERPLATE_RATIO.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }
    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_BOILERPLATE_RATIO.to_owned()),
        category: FindingCategory::Content,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Heuristic,
        severity: Severity::Low,
        confidence: Confidence::Low,
        title: "Most eligible source words are outside the main landmark".to_owned(),
        summary: format!("{} of {} words are outside the unique main landmark. Review the placement of substantive content.", words.outside_main, words.total),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpBody, format!("outside_main_words={};total_words={}", words.outside_main, words.total),
        )],
        remediation: Some("Check whether the main landmark encloses the primary content.".to_owned()),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_BOILERPLATE_RATIO.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
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
    fn detects_duplicate_paragraphs_without_source_newlines() {
        let paragraph =
            "This paragraph contains enough words to be considered substantial during the audit.";
        let html = format!("<main><p>{paragraph}</p><p>{paragraph}</p></main>");
        let (http, obs) = http_with_body(&html, vec![]);
        assert!(
            analyse(&http, &obs)
                .findings
                .iter()
                .any(|finding| finding.rule_id.0 == RULE_DUPLICATE_PARAGRAPHS)
        );
    }

    #[test]
    fn passes_for_substantive_content_with_last_modified() {
        let html = r#"<html lang="en"><body><main>
            <h1>Comprehensive Web Quality Audit Guide</h1>
            <p>This is a clear and unique first paragraph with substantive content about web quality and diagnostic capabilities.
            We explore various aspects of automated testing and verification procedures that ensure optimal user experience.</p>
            <p>Here is another distinct paragraph discussing different diagnostic capabilities and metrics that matter most.
            Performance monitoring helps identify bottlenecks while accessibility testing ensures inclusive design principles.</p>
            <p>The third paragraph covers performance monitoring and accessibility considerations thoroughly with detailed examples.
            Security headers and content policies protect users from various attack vectors and ensure data integrity.</p>
            <p>Fourth paragraph explores security headers and privacy compliance requirements in detail with practical guidance.
            Regular audits help maintain standards compliance and catch regressions early in the development lifecycle.</p>
            <p>Additional content paragraph provides even more context about quality assurance methodologies and best practices.
            Automated testing combined with manual review creates a comprehensive quality assurance strategy.</p>
        </main><footer><a href="/privacy">Privacy</a> | <a href="/terms">Terms</a></footer></body></html>"#;
        let (http, obs) = http_with_body(
            html,
            vec![("last-modified", "Tue, 24 Nov 2026 12:00:00 GMT")],
        );
        let res = analyse(&http, &obs);
        for f in &res.findings {
            eprintln!("Finding: {} - {}", f.rule_id.0, f.title);
        }
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

    #[test]
    fn flags_all_caps_headings_and_double_escaped_entities() {
        let html = r"<html><body>
            <h1>WELCOME TO OUR PLATFORM</h1>
            <p>Price is &amp;amp; details &amp;nbsp; follow.</p>
        </body></html>";
        let (http, obs) = http_with_body(html, Vec::new());
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_ALL_CAPS_HEADINGS));
        assert!(ids.contains(&RULE_DOUBLE_ESCAPED_ENTITIES));
    }

    #[test]
    fn flags_language_mismatch_link_density_and_repeated_headings() {
        let html = r#"<html lang="en"><body>
            <h2>Read More</h2><h2>Read More</h2><h2>Read More</h2>
            <p>To jest polski tekst który nie pasuje do zadeklarowanego języka oraz zawiera wiele słów dla testu oraz przez niego jest wykrywany aby sprawdzić język.</p>
            <a href="/a">One two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen</a>
            <a href="/b">Sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive</a>
            <a href="/c">Twentysix twentyseven twentyeight twentynine thirty thirtyone thirtytwo thirtythree thirtyfour thirtyfive</a>
            <a href="/d">Alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron</a>
        </body></html>"#;
        let (http, obs) = http_with_body(html, Vec::new());
        let res = analyse(&http, &obs);
        let ids: Vec<&str> = res.findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_LANGUAGE_MISMATCH));
        assert!(ids.contains(&RULE_EXCESSIVE_LINK_DENSITY));
        assert!(ids.contains(&RULE_REPEATED_HEADINGS));
    }
}
