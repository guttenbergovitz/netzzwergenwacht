//! Structured XML sitemap parser and protocol-limit validator.
//!
//! Produces a [`SitemapEvidence`] summary over `<urlset>` and `<sitemapindex>`
//! payloads while enforcing Sitemaps.org protocol bounds (50,000 entries and
//! 50 MiB uncompressed XML) and recording syntax, duplicate, and cross-origin warnings.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::discovery::Origin;
use crate::domain::{AuditTarget, TargetPolicy};

/// Maximum number of `<url>` or `<sitemap>` entries permitted per sitemap file by Sitemaps.org.
pub const MAX_SITEMAP_URLS: usize = 50_000;

/// Maximum uncompressed byte size (50 MiB) permitted per sitemap file by Sitemaps.org.
pub const MAX_SITEMAP_BYTES: usize = 52_428_800;

/// Kind of XML sitemap root element observed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SitemapKind {
    /// Standard `<urlset>` listing page URLs.
    UrlSet,
    /// `<sitemapindex>` referencing child sitemaps.
    SitemapIndex,
    /// Missing or unrecognised root element.
    #[default]
    Unknown,
}

/// Single `<url>` entry extracted from a `<urlset>` sitemap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapUrlEntry {
    /// Normalised `<loc>` URL.
    pub loc: String,
    /// Optional `<lastmod>` timestamp/date string.
    pub lastmod: Option<String>,
    /// Optional `<changefreq>` hint.
    pub changefreq: Option<String>,
    /// Optional `<priority>` value.
    pub priority: Option<String>,
    /// Optional `(hreflang, href)` pairs from `<xhtml:link rel="alternate" .../>`.
    pub alternates: Vec<(String, String)>,
}

/// Single `<sitemap>` entry extracted from a `<sitemapindex>` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapIndexEntry {
    /// Normalised child sitemap `<loc>` URL.
    pub loc: String,
    /// Optional `<lastmod>` timestamp/date string.
    pub lastmod: Option<String>,
}

/// Validation or protocol warning observed while parsing a sitemap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapWarning {
    /// Human-readable warning message.
    pub message: String,
}

/// Structured evidence parsed from an XML sitemap payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SitemapEvidence {
    /// Detected sitemap root kind.
    pub kind: SitemapKind,
    /// Uncompressed payload byte length.
    pub byte_len: usize,
    /// Same-origin URL entries extracted from `<urlset>`.
    pub urls: Vec<SitemapUrlEntry>,
    /// Same-origin child sitemap entries extracted from `<sitemapindex>`.
    pub child_sitemaps: Vec<SitemapIndexEntry>,
    /// Number of duplicate `<loc>` entries skipped.
    pub duplicate_locs: usize,
    /// Number of cross-origin `<loc>` entries skipped.
    pub cross_origin_locs: usize,
    /// Whether parsing stopped at [`MAX_SITEMAP_URLS`] or [`MAX_SITEMAP_BYTES`].
    pub truncated_by_protocol_limit: bool,
    /// Validation and syntax warnings recorded during parsing.
    pub warnings: Vec<SitemapWarning>,
}

impl SitemapEvidence {
    /// Parses `xml` against `base` origin and `policy`, enforcing Sitemaps.org limits.
    #[must_use]
    pub fn parse(xml: &str, base: &AuditTarget, policy: TargetPolicy) -> Self {
        Self::parse_with_limit(xml, base, policy, MAX_SITEMAP_URLS)
    }

    /// Variant of [`Self::parse`] allowing an explicit entry cap for deterministic testing.
    #[must_use]
    pub fn parse_with_limit(
        xml: &str,
        base: &AuditTarget,
        policy: TargetPolicy,
        max_entries: usize,
    ) -> Self {
        let mut evidence = Self {
            byte_len: xml.len(),
            ..Self::default()
        };
        if xml.len() > MAX_SITEMAP_BYTES {
            evidence.truncated_by_protocol_limit = true;
            evidence.warnings.push(SitemapWarning {
                message: format!(
                    "sitemap payload ({} bytes) exceeds 50 MiB Sitemaps.org protocol limit",
                    xml.len()
                ),
            });
        }

        let cleaned = strip_xml_comments_and_pis(xml);
        evidence.kind = detect_root_kind(&cleaned);
        if evidence.kind == SitemapKind::Unknown {
            evidence.warnings.push(SitemapWarning {
                message: "missing <urlset> or <sitemapindex> root element".to_owned(),
            });
            return evidence;
        }

        let base_origin = Origin::from_target(base);
        let mut seen = HashSet::new();
        match evidence.kind {
            SitemapKind::UrlSet => {
                parse_urlset_blocks(
                    &cleaned,
                    &base_origin,
                    policy,
                    max_entries,
                    &mut seen,
                    &mut evidence,
                );
            }
            SitemapKind::SitemapIndex => {
                parse_sitemap_blocks(
                    &cleaned,
                    &base_origin,
                    policy,
                    max_entries,
                    &mut seen,
                    &mut evidence,
                );
            }
            SitemapKind::Unknown => {}
        }
        evidence
    }
}

fn detect_root_kind(xml: &str) -> SitemapKind {
    if find_open_tag(xml, "sitemapindex").is_some() {
        SitemapKind::SitemapIndex
    } else if find_open_tag(xml, "urlset").is_some() {
        SitemapKind::UrlSet
    } else {
        SitemapKind::Unknown
    }
}

fn strip_xml_comments_and_pis(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while !rest.is_empty() {
        if let Some(pos) = rest.find("<!--") {
            out.push_str(&rest[..pos]);
            let after = &rest[pos + 4..];
            if let Some(end) = after.find("-->") {
                rest = &after[end + 3..];
            } else {
                break;
            }
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

fn find_open_tag(xml: &str, tag: &str) -> Option<(usize, usize)> {
    let needle = format!("<{tag}");
    let mut offset = 0usize;
    while let Some(rel) = xml[offset..].find(&needle) {
        let start = offset + rel;
        let after = &xml[start + needle.len()..];
        let gt = after.find('>')?;
        let boundary = after.as_bytes().first().copied();
        let valid_boundary =
            boundary.is_some_and(|b| b == b'>' || b.is_ascii_whitespace() || b == b'/');
        if valid_boundary {
            return Some((start, start + needle.len() + gt + 1));
        }
        offset = start + needle.len() + gt + 1;
    }
    None
}

fn next_block<'a>(xml: &'a str, tag: &str) -> Option<(&'a str, &'a str)> {
    let (_, body_start) = find_open_tag(xml, tag)?;
    let close_tag = format!("</{tag}>");
    let end_rel = xml[body_start..].find(&close_tag)?;
    let block = &xml[body_start..body_start + end_rel];
    let rest = &xml[body_start + end_rel + close_tag.len()..];
    Some((block, rest))
}

fn extract_child_text(block: &str, tag: &str) -> Option<String> {
    let (inner, _) = next_block(block, tag)?;
    let decoded = decode_xml_text(inner);
    let trimmed = decoded.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn extract_xhtml_alternates(block: &str) -> Vec<(String, String)> {
    let mut alts = Vec::new();
    let mut rest = block;
    while let Some(pos) = rest.find("<xhtml:link") {
        let after = &rest[pos + 11..];
        let Some(gt) = after.find('>') else {
            break;
        };
        let attrs = &after[..gt];
        if extract_attr(attrs, "rel").is_some_and(|r| r.eq_ignore_ascii_case("alternate"))
            && let (Some(lang), Some(href)) =
                (extract_attr(attrs, "hreflang"), extract_attr(attrs, "href"))
        {
            alts.push((lang, decode_xml_text(&href)));
        }
        rest = &after[gt + 1..];
    }
    alts
}

fn extract_attr(attrs: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let pos = attrs.find(&needle)?;
    let after = attrs[pos + needle.len()..].trim_start();
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &after[1..];
    let end = inner.find(quote)?;
    let val = inner[..end].trim();
    (!val.is_empty()).then(|| val.to_owned())
}

fn validate_url_entry(entry: &SitemapUrlEntry, warnings: &mut Vec<SitemapWarning>) {
    if let Some(ref priority) = entry.priority {
        let valid = priority
            .parse::<f64>()
            .is_ok_and(|p| p.is_finite() && (0.0..=1.0).contains(&p));
        if !valid {
            warnings.push(SitemapWarning {
                message: format!("invalid <priority> `{priority}` for {}", entry.loc),
            });
        }
    }
    if let Some(ref freq) = entry.changefreq
        && !matches!(
            freq.to_ascii_lowercase().as_str(),
            "always" | "hourly" | "daily" | "weekly" | "monthly" | "yearly" | "never"
        )
    {
        warnings.push(SitemapWarning {
            message: format!("invalid <changefreq> `{freq}` for {}", entry.loc),
        });
    }
    if let Some(ref lastmod) = entry.lastmod {
        let looks_iso =
            lastmod.len() >= 10 && lastmod.as_bytes()[4] == b'-' && lastmod.as_bytes()[7] == b'-';
        if !looks_iso {
            warnings.push(SitemapWarning {
                message: format!("non-ISO-8601 <lastmod> `{lastmod}` for {}", entry.loc),
            });
        }
    }
}

fn parse_urlset_blocks(
    xml: &str,
    base_origin: &Origin,
    policy: TargetPolicy,
    max_entries: usize,
    seen: &mut HashSet<String>,
    evidence: &mut SitemapEvidence,
) {
    let mut rest = xml;
    let mut total_blocks = 0usize;
    while let Some((block, next_rest)) = next_block(rest, "url") {
        rest = next_rest;
        total_blocks += 1;
        if total_blocks > max_entries {
            evidence.truncated_by_protocol_limit = true;
            evidence.warnings.push(SitemapWarning {
                message: format!("sitemap truncated at {max_entries} URL protocol limit"),
            });
            break;
        }
        let Some(raw_loc) = extract_child_text(block, "loc") else {
            evidence.warnings.push(SitemapWarning {
                message: "<url> block missing <loc>".to_owned(),
            });
            continue;
        };
        let Ok(target) = AuditTarget::parse(&raw_loc, policy) else {
            evidence.warnings.push(SitemapWarning {
                message: format!("invalid or disallowed <loc> `{raw_loc}`"),
            });
            continue;
        };
        if Origin::from_target(&target) != *base_origin {
            evidence.cross_origin_locs += 1;
            continue;
        }
        if !seen.insert(target.as_str().to_owned()) {
            evidence.duplicate_locs += 1;
            continue;
        }
        let entry = SitemapUrlEntry {
            loc: target.as_str().to_owned(),
            lastmod: extract_child_text(block, "lastmod"),
            changefreq: extract_child_text(block, "changefreq"),
            priority: extract_child_text(block, "priority"),
            alternates: extract_xhtml_alternates(block),
        };
        validate_url_entry(&entry, &mut evidence.warnings);
        evidence.urls.push(entry);
    }
}

fn parse_sitemap_blocks(
    xml: &str,
    base_origin: &Origin,
    policy: TargetPolicy,
    max_entries: usize,
    seen: &mut HashSet<String>,
    evidence: &mut SitemapEvidence,
) {
    let mut rest = xml;
    let mut total_blocks = 0usize;
    while let Some((block, next_rest)) = next_block(rest, "sitemap") {
        rest = next_rest;
        total_blocks += 1;
        if total_blocks > max_entries {
            evidence.truncated_by_protocol_limit = true;
            evidence.warnings.push(SitemapWarning {
                message: format!("sitemapindex truncated at {max_entries} entry protocol limit"),
            });
            break;
        }
        let Some(raw_loc) = extract_child_text(block, "loc") else {
            evidence.warnings.push(SitemapWarning {
                message: "<sitemap> block missing <loc>".to_owned(),
            });
            continue;
        };
        let Ok(target) = AuditTarget::parse(&raw_loc, policy) else {
            continue;
        };
        if Origin::from_target(&target) != *base_origin {
            evidence.cross_origin_locs += 1;
            continue;
        }
        if !seen.insert(target.as_str().to_owned()) {
            evidence.duplicate_locs += 1;
            continue;
        }
        evidence.child_sitemaps.push(SitemapIndexEntry {
            loc: target.as_str().to_owned(),
            lastmod: extract_child_text(block, "lastmod"),
        });
    }
}

/// Decodes CDATA wrappers and standard/numeric XML character entities.
#[must_use]
pub fn decode_xml_text(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(cdata) = trimmed
        .strip_prefix("<![CDATA[")
        .and_then(|s| s.strip_suffix("]]>"))
    {
        return cdata.trim().to_owned();
    }
    let mut out = String::with_capacity(trimmed.len());
    let mut rest = trimmed;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';')
            && semi <= 10
        {
            let entity = &after[..semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if entity.starts_with('#') => {
                    entity[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urlset_with_metadata_alternates_warnings_and_limits() {
        let base = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly)
            .expect("valid target");
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <!-- <url><loc>https://example.org/commented-out</loc></url> -->
            <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
                    xmlns:xhtml="http://www.w3.org/1999/xhtml">
                <url>
                    <loc>https://example.org/blog?a=1&amp;b=2</loc>
                    <lastmod>2026-11-28</lastmod>
                    <changefreq>weekly</changefreq>
                    <priority>0.8</priority>
                    <xhtml:link rel="alternate" hreflang="de" href="https://example.org/de/blog"/>
                </url>
                <url>
                    <loc>https://example.org/blog?a=1&amp;b=2</loc>
                </url>
                <url>
                    <loc>https://other.example.com/external</loc>
                </url>
                <url>
                    <loc>https://example.org/bad-meta</loc>
                    <priority>2.5</priority>
                    <changefreq>sometimes</changefreq>
                    <lastmod>yesterday</lastmod>
                </url>
            </urlset>"#;

        let ev = SitemapEvidence::parse(xml, &base, TargetPolicy::PublicOnly);
        assert_eq!(ev.kind, SitemapKind::UrlSet);
        assert_eq!(ev.urls.len(), 2);
        assert_eq!(ev.duplicate_locs, 1);
        assert_eq!(ev.cross_origin_locs, 1);
        assert_eq!(ev.urls[0].loc, "https://example.org/blog?a=1&b=2");
        assert_eq!(ev.urls[0].lastmod.as_deref(), Some("2026-11-28"));
        assert_eq!(ev.urls[0].alternates.len(), 1);
        assert!(
            ev.warnings
                .iter()
                .any(|w| w.message.contains("invalid <priority>"))
        );
        assert!(
            ev.warnings
                .iter()
                .any(|w| w.message.contains("invalid <changefreq>"))
        );
        assert!(
            ev.warnings
                .iter()
                .any(|w| w.message.contains("non-ISO-8601 <lastmod>"))
        );

        let capped = SitemapEvidence::parse_with_limit(xml, &base, TargetPolicy::PublicOnly, 1);
        assert!(capped.truncated_by_protocol_limit);
        assert_eq!(capped.urls.len(), 1);
    }

    #[test]
    fn parses_sitemapindex_entries_and_ignores_cross_origin() {
        let base = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly)
            .expect("valid target");
        let xml = r"<sitemapindex>
            <sitemap>
                <loc>https://example.org/sitemap-en.xml</loc>
                <lastmod>2026-11-01</lastmod>
            </sitemap>
            <sitemap>
                <loc>https://other.example.com/sitemap.xml</loc>
            </sitemap>
        </sitemapindex>";

        let ev = SitemapEvidence::parse(xml, &base, TargetPolicy::PublicOnly);
        assert_eq!(ev.kind, SitemapKind::SitemapIndex);
        assert_eq!(ev.child_sitemaps.len(), 1);
        assert_eq!(
            ev.child_sitemaps[0].loc,
            "https://example.org/sitemap-en.xml"
        );
        assert_eq!(ev.child_sitemaps[0].lastmod.as_deref(), Some("2026-11-01"));
        assert_eq!(ev.cross_origin_locs, 1);
    }
}
