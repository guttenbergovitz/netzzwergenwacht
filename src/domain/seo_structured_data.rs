//! Search, indexability authority, and structured data / social preview domain contracts (Wave IV-F).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::rendered_content::RenderedTextFingerprint;

/// Specific conflict or defect in a page's indexability and canonical authority signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IndexabilityConflictKind {
    /// HTTP `X-Robots-Tag` and HTML `<meta name="robots">` directives contradict one another.
    HttpVsMetaRobotsConflict,
    /// Raw HTML `<meta name="robots">` and client-rendered `<meta name="robots">` differ.
    SourceVsRenderedRobotsDrift,
    /// Multiple `<link rel="canonical">` tags with different targets exist in the DOM.
    MultipleConflictingCanonicals,
    /// Raw HTML canonical target and client-rendered canonical target differ.
    SourceVsRenderedCanonicalDrift,
    /// Canonical URL points to a different origin or path while the page is marked `noindex`.
    NoindexWithNonSelfCanonical,
    /// `hreflang` alternate links lack a self-referential entry for the current page language.
    MissingSelfReferentialHreflang,
    /// Duplicate `hreflang` language-region codes point to conflicting URLs.
    DuplicateHreflangCode,
}

/// Alternate language/region (`rel="alternate" hreflang="..."`) entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HreflangAlternateObs {
    /// Normalized `hreflang` code (e.g. `en-gb`, `de-de`, `x-default`).
    pub hreflang: String,
    /// Secret-safe target origin (`scheme://host[:port]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href_origin: Option<String>,
    /// Secret-safe target pathname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href_path: Option<String>,
    /// Whether this entry points back to the current audited page.
    pub is_self_referential: bool,
}

/// Consolidated indexability, canonical, and internationalisation authority evidence.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct IndexabilityAuthorityEvidence {
    /// Whether the page is effectively indexable by search engines (`status == 200` and no `noindex`).
    pub effectively_indexable: bool,
    /// Whether an HTTP `X-Robots-Tag` header with `noindex` was observed.
    pub http_x_robots_noindex: bool,
    /// Whether an HTTP `X-Robots-Tag` header with `nofollow` was observed.
    pub http_x_robots_nofollow: bool,
    /// Whether the rendered DOM contains a `<meta name="robots" content="...noindex...">` directive.
    pub rendered_meta_noindex: bool,
    /// Whether the rendered DOM contains a `<meta name="robots" content="...nofollow...">` directive.
    pub rendered_meta_nofollow: bool,
    /// Number of `<link rel="canonical">` elements present in the rendered DOM.
    pub canonical_tag_count: u32,
    /// Secret-safe canonical target origin from the rendered DOM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_canonical_origin: Option<String>,
    /// Secret-safe canonical target pathname from the rendered DOM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_canonical_path: Option<String>,
    /// Whether the rendered canonical points to the audited page's own final URL.
    pub canonical_is_self_referential: bool,
    /// Whether a `<link rel="prev">` or `<link rel="next">` pagination link is present.
    pub has_pagination_rel_links: bool,
    /// Bounded list of `hreflang` alternate links (capped at 64).
    pub hreflang_alternates: Vec<HreflangAlternateObs>,
    /// Whether additional `hreflang` links were truncated.
    pub hreflang_truncated: bool,
    /// Detected indexability or canonical conflicts.
    pub conflicts: Vec<IndexabilityConflictKind>,
}

/// Syntax format of an embedded structured data block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StructuredDataSyntax {
    /// `<script type="application/ld+json">`.
    JsonLd,
    /// HTML5 `itemscope` / `itemtype` Microdata.
    Microdata,
    /// `RDFa` `typeof` / `property` attributes.
    Rdfa,
}

/// Single structured data entity summary extracted from JSON-LD, Microdata, or `RDFa`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StructuredEntitySummary {
    /// Zero-based entity index (`0..32`).
    pub entity_index: u32,
    /// Syntax source of the entity.
    pub syntax: StructuredDataSyntax,
    /// Normalized `@type` or `itemtype` name (e.g. `Article`, `Product`, `Organization`, `BreadcrumbList`).
    pub schema_type: String,
    /// Whether the `@context` or `itemtype` namespace resolves to `schema.org`.
    pub is_schema_org: bool,
    /// Top-level property keys present on this entity (sorted, capped at 32 keys; never raw values).
    pub property_keys: Vec<String>,
    /// Required Schema.org rich-result properties that are missing for this `@type`.
    pub missing_required_fields: Vec<String>,
    /// Whether the entity parsed cleanly and satisfied all required rich-result properties.
    pub valid: bool,
}

/// Completeness of `OpenGraph` (`og:*`) and Twitter/X (`twitter:*`) social preview card metadata.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SocialPreviewCardCompleteness {
    /// `og:title` present and non-empty.
    pub og_title_present: bool,
    /// `og:description` present and non-empty.
    pub og_description_present: bool,
    /// `og:image` present and non-empty.
    pub og_image_present: bool,
    /// `og:url` present and non-empty.
    pub og_url_present: bool,
    /// `og:type` present and non-empty.
    pub og_type_present: bool,
    /// Whether the core `OpenGraph` card (`title`, `description`, `image`, `url`) is complete.
    pub og_complete: bool,
    /// `twitter:card` value (`summary`, `summary_large_image`, etc.), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub twitter_card_kind: Option<String>,
    /// `twitter:title` (or fallback `og:title`) present.
    pub twitter_title_present: bool,
    /// `twitter:image` (or fallback `og:image`) present.
    pub twitter_image_present: bool,
    /// Whether the Twitter/X preview card is complete.
    pub twitter_complete: bool,
    /// SHA-256 fingerprint of the rendered `<title>` text for cross-checking against `og:title`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_title_fingerprint: Option<RenderedTextFingerprint>,
}

/// Complete structured data and social preview inventory for a rendered page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct StructuredDataInventory {
    /// Total `<script type="application/ld+json">` blocks found in the rendered DOM.
    pub json_ld_block_count: u32,
    /// Number of JSON-LD blocks that failed JSON parsing.
    pub malformed_json_ld_count: u32,
    /// Bounded list of extracted structured entities (capped at 32).
    pub entities: Vec<StructuredEntitySummary>,
    /// Whether additional entities were truncated.
    pub entities_truncated: bool,
    /// Social preview card completeness summary.
    pub social_card: SocialPreviewCardCompleteness,
    /// High-level validation issue codes observed across structured data blocks.
    #[serde(default)]
    pub issues: Vec<String>,
}
