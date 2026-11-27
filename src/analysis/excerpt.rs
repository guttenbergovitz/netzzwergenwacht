//! Deterministic `cargo`-style source excerpt extraction for [`EvidenceRef`].
//!
//! Extracts bounded, single-line source excerpts with 1-based line/column
//! coordinates and caret underline spans from an [`EvidenceSnapshot`] so TUI
//! and report views can pinpoint the exact header, HTML element, or selector
//! behind a finding without holding full page bodies inside findings.

use crate::domain::{
    AnalyserResult, CollectorOutcome, EvidenceExcerpt, EvidenceRef, EvidenceSnapshot,
    EvidenceSource, Finding, HttpEvidence,
};

const MAX_EXCERPT_CHARS: usize = 120;
const MAX_LABEL_CHARS: usize = 72;
const MAX_HELP_CHARS: usize = 120;

const KNOWN_HEADERS: &[&str] = &[
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "cache-control",
    "content-encoding",
    "content-type",
    "set-cookie",
    "access-control-allow-origin",
    "server",
    "x-powered-by",
    "location",
    "etag",
    "vary",
];

/// Enriches [`EvidenceRef`] entries across `analysers` with bounded source excerpts
/// derived from `snapshot`.
///
/// Existing excerpts on a reference are preserved untouched.
pub fn enrich_evidence_excerpts(snapshot: &EvidenceSnapshot, analysers: &mut [AnalyserResult]) {
    let http = match &snapshot.http {
        CollectorOutcome::Captured { data: h } | CollectorOutcome::Partial { data: h, .. } => {
            Some(h)
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    };
    let location = http
        .map(|h| h.final_url.as_str())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| snapshot.target.as_str());

    for analyser in analysers {
        for finding in &mut analyser.findings {
            let label = truncate_chars(&finding.title, MAX_LABEL_CHARS);
            let help = finding
                .remediation
                .as_deref()
                .map(|r| truncate_chars(r, MAX_HELP_CHARS));
            let rule_id = finding.rule_id.0.clone();

            for ev in &mut finding.evidence_refs {
                if ev.excerpt.is_some() {
                    continue;
                }
                ev.excerpt = build_excerpt_for_ref(
                    snapshot,
                    http,
                    location,
                    &rule_id,
                    &label,
                    help.as_deref(),
                    ev,
                );
            }
        }
    }
}

fn build_excerpt_for_ref(
    snapshot: &EvidenceSnapshot,
    http: Option<&HttpEvidence>,
    location: &str,
    rule_id: &str,
    label: &str,
    help: Option<&str>,
    ev: &EvidenceRef,
) -> Option<EvidenceExcerpt> {
    match ev.source {
        EvidenceSource::HttpHeaders => {
            http.and_then(|h| excerpt_from_headers(h, location, rule_id, &ev.detail, label, help))
        }
        EvidenceSource::HttpBody => http.and_then(|h| {
            if h.body_text.is_empty() {
                None
            } else {
                excerpt_from_html(&h.body_text, location, rule_id, &ev.detail, label, help)
            }
        }),
        EvidenceSource::HttpStatus | EvidenceSource::HttpFinalUrl => http.map(|h| {
            let status_str = h.status_code.to_string();
            let snippet = truncate_chars(
                &format!("HTTP {status_str} {}", h.final_url),
                MAX_EXCERPT_CHARS,
            );
            EvidenceExcerpt {
                location: location.to_owned(),
                line: None,
                column: None,
                snippet,
                highlight_start: Some(5),
                highlight_len: Some(status_str.chars().count()),
                label: Some(label.to_owned()),
                help: help.map(str::to_owned),
            }
        }),
        EvidenceSource::HttpRedirectChain => http.and_then(|h| {
            let hop = h.redirect_chain.first()?;
            let status_str = hop.status_code.to_string();
            let snippet = truncate_chars(
                &format!("HTTP {status_str} {} -> {}", hop.from_url, hop.to_url),
                MAX_EXCERPT_CHARS,
            );
            Some(EvidenceExcerpt {
                location: location.to_owned(),
                line: None,
                column: None,
                snippet,
                highlight_start: Some(5),
                highlight_len: Some(status_str.chars().count()),
                label: Some(label.to_owned()),
                help: help.map(str::to_owned),
            })
        }),
        EvidenceSource::AxeReport => excerpt_from_axe(snapshot, location, &ev.detail, label, help),
        EvidenceSource::HttpTiming
        | EvidenceSource::TlsCertificate
        | EvidenceSource::BrowserRuntime
        | EvidenceSource::LighthouseReport
        | EvidenceSource::VisualLayout => None,
    }
}

fn excerpt_from_headers(
    http: &HttpEvidence,
    location: &str,
    rule_id: &str,
    detail: &str,
    label: &str,
    help: Option<&str>,
) -> Option<EvidenceExcerpt> {
    let header_name = detect_header_name(rule_id, detail)?;
    if let Some(value) = http.first_header_value(header_name) {
        let prefix = format!("{header_name}: ");
        let raw_line = format!("{prefix}{value}");
        let snippet = truncate_chars(&raw_line, MAX_EXCERPT_CHARS);
        let prefix_chars = prefix.chars().count();
        let snippet_chars = snippet.chars().count();
        let highlight_start = prefix_chars.min(snippet_chars);
        let highlight_len = snippet_chars.saturating_sub(highlight_start).max(1);
        return Some(EvidenceExcerpt {
            location: location.to_owned(),
            line: None,
            column: None,
            snippet,
            highlight_start: Some(highlight_start),
            highlight_len: Some(highlight_len),
            label: Some(label.to_owned()),
            help: help.map(str::to_owned),
        });
    }

    let missing_phrase = format!("missing `{header_name}`");
    let raw_line = format!(
        "HTTP {} (response headers: {missing_phrase})",
        http.status_code
    );
    let snippet = truncate_chars(&raw_line, MAX_EXCERPT_CHARS);
    let start = snippet
        .find(header_name)
        .map(|b| snippet[..b].chars().count());
    let len = start.map(|_| header_name.chars().count());
    Some(EvidenceExcerpt {
        location: location.to_owned(),
        line: None,
        column: None,
        snippet,
        highlight_start: start,
        highlight_len: len,
        label: Some(label.to_owned()),
        help: help.map(str::to_owned),
    })
}

fn detect_header_name(rule_id: &str, detail: &str) -> Option<&'static str> {
    let detail_lower = detail.to_ascii_lowercase();
    let rule_lower = rule_id.to_ascii_lowercase();

    for &hdr in KNOWN_HEADERS {
        if detail_lower.contains(hdr) {
            return Some(hdr);
        }
    }

    if rule_lower.contains("hsts") {
        return Some("strict-transport-security");
    }
    if rule_lower.contains("csp") {
        return Some("content-security-policy");
    }
    if rule_lower.contains("frame") || rule_lower.contains("clickjacking") {
        return Some("x-frame-options");
    }
    if rule_lower.contains("nosniff") || rule_lower.contains("content_type_options") {
        return Some("x-content-type-options");
    }
    if rule_lower.contains("referrer") {
        return Some("referrer-policy");
    }
    if rule_lower.contains("permissions") {
        return Some("permissions-policy");
    }
    if rule_lower.contains("cookie") {
        return Some("set-cookie");
    }
    if rule_lower.contains("compression") || rule_lower.contains("encoding") {
        return Some("content-encoding");
    }
    if rule_lower.contains("cache") {
        return Some("cache-control");
    }
    if rule_lower.contains("cors") {
        return Some("access-control-allow-origin");
    }

    None
}

fn excerpt_from_html(
    body: &str,
    location: &str,
    rule_id: &str,
    detail: &str,
    label: &str,
    help: Option<&str>,
) -> Option<EvidenceExcerpt> {
    let needle_hit = find_html_target_span(body, rule_id, detail)?;
    build_line_excerpt(
        body,
        needle_hit.start_byte,
        needle_hit.end_byte,
        location,
        label,
        help,
    )
}

struct ByteSpan {
    start_byte: usize,
    end_byte: usize,
}

fn find_html_target_span(body: &str, rule_id: &str, detail: &str) -> Option<ByteSpan> {
    let rule_lower = rule_id.to_ascii_lowercase();
    let detail_lower = detail.to_ascii_lowercase();

    if (rule_lower.contains("alt") || (rule_lower.contains("img") && detail_lower.contains("alt")))
        && let Some(span) = find_img_without_alt(body)
    {
        return Some(span);
    }

    let candidate_needles: &[&str] =
        if rule_lower.contains("title") || detail_lower.contains("<title") {
            &["<title", "<head"]
        } else if rule_lower.contains("description") || detail_lower.contains("description") {
            &["name=\"description\"", "name='description'", "<head"]
        } else if rule_lower.contains("canonical") || detail_lower.contains("canonical") {
            &["rel=\"canonical\"", "rel='canonical'", "<head"]
        } else if rule_lower.contains("robots") {
            &["name=\"robots\"", "name='robots'", "<head"]
        } else if rule_lower.contains("viewport") {
            &["name=\"viewport\"", "name='viewport'", "<head"]
        } else if rule_lower.contains("charset") {
            &["charset=", "<head"]
        } else if rule_lower.contains("lang") {
            &["<html"]
        } else if rule_lower.contains("h1") || detail_lower.contains("<h1") {
            &["<h1", "<body"]
        } else if rule_lower.contains("img") || detail_lower.contains("<img") {
            &["<img"]
        } else if rule_lower.contains("link") || detail_lower.contains("<a") {
            &["<a "]
        } else if rule_lower.contains("schema") || rule_lower.contains("json_ld") {
            &["application/ld+json", "<head"]
        } else {
            &[]
        };

    for &needle in candidate_needles {
        if let Some(span) = find_tag_or_needle_span(body, needle) {
            return Some(span);
        }
    }

    None
}

fn find_img_without_alt(body: &str) -> Option<ByteSpan> {
    let lower = body.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(rel_pos) = lower[offset..].find("<img") {
        let start = offset + rel_pos;
        let close_rel = lower[start..].find('>')?;
        let end = start + close_rel + 1;
        let tag_lower = &lower[start..end];
        if !tag_lower.contains("alt=") {
            return Some(ByteSpan {
                start_byte: start,
                end_byte: end,
            });
        }
        offset = end;
    }
    None
}

fn find_tag_or_needle_span(body: &str, needle: &str) -> Option<ByteSpan> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find(&needle.to_ascii_lowercase())?;
    let line_start = lower[..start].rfind('\n').map_or(0, |i| i + 1);
    let tag_start = if needle.starts_with('<') {
        start
    } else {
        lower[line_start..=start].rfind('<').unwrap_or(start)
    };
    let end = lower[tag_start..]
        .find('>')
        .map_or(start + needle.len(), |i| tag_start + i + 1);
    Some(ByteSpan {
        start_byte: tag_start,
        end_byte: end.min(body.len()),
    })
}

fn build_line_excerpt(
    body: &str,
    start_byte: usize,
    end_byte: usize,
    location: &str,
    label: &str,
    help: Option<&str>,
) -> Option<EvidenceExcerpt> {
    if start_byte >= body.len() {
        return None;
    }

    let line_start_byte = body[..start_byte].rfind('\n').map_or(0, |i| i + 1);
    let line_end_byte = body[start_byte..]
        .find('\n')
        .map_or(body.len(), |i| start_byte + i);

    let line_number = body[..line_start_byte]
        .bytes()
        .filter(|&b| b == b'\n')
        .count()
        + 1;
    let raw_line = body[line_start_byte..line_end_byte].trim_end_matches('\r');
    let trimmed_leading = raw_line.trim_start();
    let leading_ws_bytes = raw_line.len().saturating_sub(trimmed_leading.len());

    let rel_start_byte = start_byte
        .saturating_sub(line_start_byte)
        .saturating_sub(leading_ws_bytes);
    let rel_end_byte = end_byte
        .min(line_end_byte)
        .saturating_sub(line_start_byte)
        .saturating_sub(leading_ws_bytes)
        .max(rel_start_byte + 1);

    let col_in_trimmed = byte_offset_to_char_offset(trimmed_leading, rel_start_byte);
    let span_chars = byte_offset_to_char_offset(trimmed_leading, rel_end_byte)
        .saturating_sub(col_in_trimmed)
        .max(1);
    let column =
        byte_offset_to_char_offset(raw_line, start_byte.saturating_sub(line_start_byte)) + 1;

    let (snippet, highlight_start, highlight_len) = window_around_highlight(
        trimmed_leading,
        col_in_trimmed,
        span_chars,
        MAX_EXCERPT_CHARS,
    );

    Some(EvidenceExcerpt {
        location: location.to_owned(),
        line: Some(line_number),
        column: Some(column),
        snippet,
        highlight_start: Some(highlight_start),
        highlight_len: Some(highlight_len),
        label: Some(label.to_owned()),
        help: help.map(str::to_owned),
    })
}

fn excerpt_from_axe(
    snapshot: &EvidenceSnapshot,
    location: &str,
    detail: &str,
    label: &str,
    help: Option<&str>,
) -> Option<EvidenceExcerpt> {
    let selector = match &snapshot.axe {
        CollectorOutcome::Captured { data: axe } | CollectorOutcome::Partial { data: axe, .. } => {
            axe.violations
                .iter()
                .find(|v| detail.contains(&v.id) || detail.contains(&v.description))
                .and_then(|v| v.target_selectors.first())
                .map(String::as_str)
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    };

    let target = selector.unwrap_or(detail).trim();
    if target.is_empty() {
        return None;
    }

    let snippet = truncate_chars(&format!("DOM selector: {target}"), MAX_EXCERPT_CHARS);
    let prefix_chars = "DOM selector: ".chars().count();
    let highlight_len = snippet.chars().count().saturating_sub(prefix_chars).max(1);
    Some(EvidenceExcerpt {
        location: location.to_owned(),
        line: None,
        column: None,
        snippet,
        highlight_start: Some(prefix_chars),
        highlight_len: Some(highlight_len),
        label: Some(label.to_owned()),
        help: help.map(str::to_owned),
    })
}

fn window_around_highlight(
    text: &str,
    highlight_char: usize,
    highlight_len: usize,
    max_chars: usize,
) -> (String, usize, usize) {
    let total_chars = text.chars().count();
    if total_chars <= max_chars {
        return (
            text.to_owned(),
            highlight_char,
            highlight_len
                .min(total_chars.saturating_sub(highlight_char))
                .max(1),
        );
    }

    let context_before = max_chars / 3;
    let start_char = highlight_char.saturating_sub(context_before);
    let end_char = (start_char + max_chars).min(total_chars);
    let prefix_ellipsis = if start_char > 0 { "... " } else { "" };
    let suffix_ellipsis = if end_char < total_chars { " ..." } else { "" };

    let slice: String = text
        .chars()
        .skip(start_char)
        .take(end_char.saturating_sub(start_char))
        .collect();
    let snippet = format!("{prefix_ellipsis}{slice}{suffix_ellipsis}");
    let adjusted_start = highlight_char
        .saturating_sub(start_char)
        .saturating_add(prefix_ellipsis.chars().count());
    let max_hl = slice
        .chars()
        .count()
        .saturating_sub(highlight_char.saturating_sub(start_char))
        .max(1);
    (snippet, adjusted_start, highlight_len.min(max_hl).max(1))
}

fn byte_offset_to_char_offset(s: &str, byte_offset: usize) -> usize {
    let clamped = byte_offset.min(s.len());
    let mut chars = 0usize;
    for (idx, _) in s.char_indices() {
        if idx >= clamped {
            break;
        }
        chars += 1;
    }
    chars
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    let count = clean.chars().count();
    if count <= max_chars {
        clean
    } else {
        let head: String = clean.chars().take(max_chars.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

/// Convenience helper for callers attaching an excerpt directly to a [`Finding`].
#[allow(dead_code)]
pub(crate) fn attach_first_excerpt(finding: &mut Finding, excerpt: EvidenceExcerpt) {
    if let Some(first) = finding.evidence_refs.first_mut() {
        first.excerpt = Some(excerpt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brigade::DwarfId;
    use crate::domain::{
        AuditTarget, Confidence, EvidenceLevel, FindingFingerprint, FindingKind, HttpHeader,
        Measurement, MeasurementUnit, RuleId, Severity, TargetPolicy,
    };

    fn sample_snapshot(html: &str, headers: Vec<HttpHeader>) -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers,
                    elapsed_ms: Measurement::Measured {
                        value: 42,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: html.len(),
                    body_truncated: false,
                    body_text: html.to_owned(),
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            browser: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            lighthouse: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "test".to_owned(),
            },
        }
    }

    #[test]
    fn enriches_html_img_missing_alt_with_exact_line_and_column() {
        let html = "<!doctype html>\n<html>\n  <body>\n    <img src=\"/hero.webp\" class=\"banner\">\n  </body>\n</html>";
        let snapshot = sample_snapshot(html, Vec::new());
        let mut analysers = vec![AnalyserResult {
            dwarf_id: DwarfId::Zugaenglichkeits,
            findings: vec![Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId("zugaenglichkeits.img.missing_alt".to_owned()),
                category: crate::domain::FindingCategory::Accessibility,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: "Image missing alt attribute".to_owned(),
                summary: "An <img> element has no alt attribute.".to_owned(),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpBody,
                    "1 image missing alt",
                )],
                remediation: Some("Add descriptive alt text or alt=\"\".".to_owned()),
            }],
            checks: Vec::new(),
        }];

        enrich_evidence_excerpts(&snapshot, &mut analysers);

        let excerpt = analysers[0].findings[0].evidence_refs[0]
            .excerpt
            .as_ref()
            .expect("excerpt should be attached");
        assert_eq!(excerpt.line, Some(4));
        assert_eq!(excerpt.column, Some(5));
        assert_eq!(excerpt.snippet, "<img src=\"/hero.webp\" class=\"banner\">");
        assert_eq!(excerpt.highlight_start, Some(0));
        assert_eq!(excerpt.highlight_len, Some(excerpt.snippet.len()));
    }

    #[test]
    fn enriches_missing_security_header_with_synthetic_response_line() {
        let snapshot = sample_snapshot("<html></html>", Vec::new());
        let mut analysers = vec![AnalyserResult {
            dwarf_id: DwarfId::Sicherheits,
            findings: vec![Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId("sicherheits.headers.missing_hsts".to_owned()),
                category: crate::domain::FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::High,
                confidence: Confidence::High,
                title: "Missing Strict-Transport-Security header".to_owned(),
                summary: "HSTS header is absent.".to_owned(),
                evidence_refs: vec![EvidenceRef::new(
                    EvidenceSource::HttpHeaders,
                    "strict-transport-security header absent",
                )],
                remediation: Some("Send Strict-Transport-Security on HTTPS responses.".to_owned()),
            }],
            checks: Vec::new(),
        }];

        enrich_evidence_excerpts(&snapshot, &mut analysers);

        let excerpt = analysers[0].findings[0].evidence_refs[0]
            .excerpt
            .as_ref()
            .expect("header excerpt should be attached");
        assert!(excerpt.snippet.contains("strict-transport-security"));
        assert!(excerpt.highlight_start.is_some());
    }
}
