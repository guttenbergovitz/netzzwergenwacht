//! Subresource discovery and acquisition.
//!
//! A page's scripts, stylesheets and images are diagnostic objects in their own right, and a
//! stylesheet referenced by every page should be acquired once rather than once per page. This
//! module turns page observations into deduplicated resource references and records what an
//! acquisition actually observed.
//!
//! Bodies are counted and discarded. Reconnaissance needs to know that a resource exists, what it
//! claims to be and how large it is; it does not need to retain a copy of it, and retaining binary
//! payloads would turn a cache into a liability.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::analysis::document::DocumentObservations;
use crate::domain::{AuditTarget, Origin, TargetPolicy};

/// Kind of subresource discovered on a page.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// External JavaScript referenced by `<script src>`.
    #[default]
    Script,
    /// Stylesheet referenced by `<link rel="stylesheet">`.
    Stylesheet,
    /// Image referenced by `<img src>`.
    Image,
}

impl ResourceKind {
    /// Stable lowercase label used in reports and evidence references.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Stylesheet => "stylesheet",
            Self::Image => "image",
        }
    }
}

/// A discovered subresource that belongs to the crawl's origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Absolute, fragment-free URL.
    pub url: AuditTarget,
    /// Resource family the reference was discovered as.
    pub kind: ResourceKind,
}

/// What happened to a discovered resource.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// Acquired; the observation carries the response facts.
    #[default]
    Fetched,
    /// Acquisition was attempted and failed.
    Failed,
    /// Never acquired because the crawl deadline or resource bound was reached.
    SkippedBudget,
}

/// One resource acquisition, recorded from what the response actually showed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceObservation {
    /// Absolute URL of the resource.
    pub url: String,
    /// Resource family the reference was discovered as.
    pub kind: ResourceKind,
    /// Whether the resource was acquired.
    pub status: ResourceStatus,
    /// Response status code, when a response was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Declared `Content-Type`, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Declared `Content-Encoding`, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
    /// Bytes read from the body, which is discarded immediately afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<u64>,
    /// Declared `Cache-Control`, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// Whether the response carried an `ETag`; `None` when no response was received, so an
    /// unacquired or failed resource never claims the header was absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag_present: Option<bool>,
    /// Whether the response carried `Last-Modified`; `None` when no response was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified_present: Option<bool>,
    /// Whether the read stopped at the byte cap, so `byte_len` is a lower bound.
    pub truncated: bool,
    /// Failure reason, when acquisition failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ResourceObservation {
    /// Builds an observation for a resource that was never acquired.
    #[must_use]
    pub fn skipped(reference: &ResourceRef, status: ResourceStatus) -> Self {
        Self {
            url: reference.url.as_str().to_owned(),
            kind: reference.kind,
            status,
            ..Self::default()
        }
    }
}

/// Resource accounting for one crawl.
///
/// `external_refused` counts references to other origins that were discovered but not acquired.
/// Reconnaissance stays inside the authorised origin; an external dependency is recorded as
/// present, never fetched on the strength of a link alone.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCoverage {
    /// Distinct same-origin resources discovered across all inspected pages.
    pub discovered_resources: usize,
    /// Resources handed to an acquisition worker.
    pub fetched_resources: usize,
    /// Resources whose acquisition failed.
    pub failed_resources: usize,
    /// Resources left unacquired because the resource bound was reached.
    pub skipped_resources: usize,
    /// Resources whose acquisition was cancelled when the crawl deadline expired.
    pub cancelled_resources: usize,
    /// Resources whose body read stopped at the byte cap.
    pub truncated_resources: usize,
    /// Cross-origin references discovered but deliberately not acquired.
    pub external_refused: usize,
    /// Configured resource bound for this crawl.
    pub max_resources: usize,
}

/// Extracts distinct same-origin subresource references from one page.
///
/// Relative URLs are resolved against `base` and fragments are dropped. References to other
/// origins are counted in `external_refused` rather than returned: the caller decides policy, and
/// this function never widens the acquisition scope on its own.
#[must_use]
pub fn discover_page_resources(
    base: &AuditTarget,
    observations: &DocumentObservations,
    policy: TargetPolicy,
) -> (Vec<ResourceRef>, usize) {
    let Ok(base_url) = Url::parse(base.as_str()) else {
        return (Vec::new(), 0);
    };
    let base_origin = Origin::from_target(base);
    let mut seen = std::collections::HashSet::new();
    let mut references = Vec::new();
    let mut external_refused = 0usize;

    let candidates = observations
        .scripts
        .iter()
        .filter_map(|script| script.src.as_deref().map(|src| (src, ResourceKind::Script)))
        .chain(
            observations
                .stylesheets
                .iter()
                .map(|sheet| (sheet.href.as_str(), ResourceKind::Stylesheet)),
        )
        .chain(
            observations
                .images
                .iter()
                .filter_map(|image| image.src.as_deref().map(|src| (src, ResourceKind::Image))),
        );

    for (raw, kind) in candidates {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("data:") || lower.starts_with("blob:") || lower.starts_with('#') {
            continue;
        }
        let Ok(mut resolved) = base_url.join(trimmed) else {
            continue;
        };
        resolved.set_fragment(None);
        if !matches!(resolved.scheme(), "http" | "https") {
            continue;
        }
        let Ok(target) = AuditTarget::parse(resolved.as_str(), policy) else {
            continue;
        };
        if Origin::from_target(&target) != base_origin {
            external_refused = external_refused.saturating_add(1);
            continue;
        }
        if !seen.insert(target.as_str().to_owned()) {
            continue;
        }
        references.push(ResourceRef { url: target, kind });
    }

    (references, external_refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(raw: &str) -> AuditTarget {
        AuditTarget::parse(raw, TargetPolicy::PublicOnly).expect("target")
    }

    fn observations() -> DocumentObservations {
        DocumentObservations::from_html(
            r#"<html><head>
                <link rel="stylesheet" href="/site.css">
                <script src="/app.js"></script>
                <script>inline()</script>
            </head><body>
                <img src="picture.png" alt="Picture">
                <img src="https://cdn.example.net/lib.js" alt="External">
                <img src="data:image/png;base64,AAAA" alt="Inline">
            </body></html>"#,
        )
    }

    #[test]
    fn resolves_relative_references_and_counts_external_ones() {
        let base = target("https://example.org/docs/guide");
        let (references, external) =
            discover_page_resources(&base, &observations(), TargetPolicy::PublicOnly);
        assert_eq!(
            external, 1,
            "the CDN reference must be counted, not fetched"
        );
        let urls: Vec<&str> = references.iter().map(|r| r.url.as_str()).collect();
        // Scripts are collected before stylesheets, so discovery order follows the element family.
        assert_eq!(
            urls,
            vec![
                "https://example.org/app.js",
                "https://example.org/site.css",
                "https://example.org/docs/picture.png",
            ]
        );
        assert_eq!(references[0].kind, ResourceKind::Script);
        assert_eq!(references[1].kind, ResourceKind::Stylesheet);
        assert_eq!(references[2].kind, ResourceKind::Image);
    }

    #[test]
    fn the_same_url_is_reported_once() {
        let base = target("https://example.org/");
        let obs = DocumentObservations::from_html(
            r#"<html><head><script src="/bundle.js"></script></head>
            <body><img src="/bundle.js" alt="Same URL twice"></body></html>"#,
        );
        let (references, _) = discover_page_resources(&base, &obs, TargetPolicy::PublicOnly);
        assert_eq!(references.len(), 1);
        assert_eq!(references[0].kind, ResourceKind::Script);
    }

    #[test]
    fn inline_and_empty_references_are_ignored() {
        let base = target("https://example.org/");
        let obs = DocumentObservations::from_html(
            r#"<html><body><img src="" alt="Empty"><img alt="Missing"></body></html>"#,
        );
        let (references, external) = discover_page_resources(&base, &obs, TargetPolicy::PublicOnly);
        assert_eq!(references.len(), 0);
        assert_eq!(external, 0);
    }
}
