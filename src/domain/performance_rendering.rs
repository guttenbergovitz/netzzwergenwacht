//! Performance attribution, media asset, and webfont domain contracts (Wave IV-E).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::functional_intelligence::ElementBoundingBox;
use crate::domain::rendered_content::RenderedElementIdentity;

/// Largest Contentful Paint (LCP) candidate element attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LcpCandidateObs {
    /// Stable cross-capture element identity of the LCP element, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RenderedElementIdentity>,
    /// Lowercase tag name of the LCP element (`img`, `h1`, `div`, `video`, etc.).
    pub tag: String,
    /// Effective paint or render timestamp in milliseconds from navigation start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub render_time_ms: Option<u64>,
    /// Reported LCP candidate area (`width * height`) in CSS square pixels.
    pub size_px_sq: u64,
    /// Bounding box of the LCP candidate in CSS pixels.
    #[serde(default)]
    pub bbox: ElementBoundingBox,
    /// Origin of the backing image/video resource when the LCP candidate is media-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_origin: Option<String>,
    /// Secret-safe pathname of the backing media resource, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    /// Whether the LCP candidate was above the fold at initial paint.
    pub above_the_fold: bool,
}

/// Cumulative Layout Shift (CLS) shift region attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ClsShiftRegionObs {
    /// Zero-based index of the layout shift entry.
    pub shift_index: u32,
    /// Layout shift score in thousandths (`1` = `0.001`).
    pub score_milli: u32,
    /// Timestamp of the shift in milliseconds from navigation start.
    pub start_time_ms: u64,
    /// Stable element identity of the primary shifted node, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_node_identity: Option<RenderedElementIdentity>,
    /// Lowercase tag name of the primary shifted node, if resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_node_tag: Option<String>,
}

/// Render-blocking critical path summary in `<head>`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RenderBlockingChainSummary {
    /// Number of synchronous `<script src>` elements in `<head>` without `defer` or `async`.
    pub blocking_head_scripts: u32,
    /// Number of non-print `<link rel="stylesheet">` elements in `<head>`.
    pub blocking_head_stylesheets: u32,
    /// Number of `<link rel="preload">` hints declared.
    pub preload_hint_count: u32,
    /// Number of `<link rel="preconnect">` hints declared.
    pub preconnect_hint_count: u32,
    /// Total transfer bytes of render-blocking scripts and stylesheets, when known.
    pub blocking_transfer_bytes: u64,
}

/// Consolidated performance attribution evidence (LCP, CLS regions, blocking chain).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PerformanceAttributionEvidence {
    /// Final Largest Contentful Paint candidate element attribution, if observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lcp_candidate: Option<LcpCandidateObs>,
    /// Total Cumulative Layout Shift score in thousandths (`0.100` = `100`).
    #[serde(default)]
    pub total_cls_milli: u32,
    /// Bounded list of layout shift regions (capped at 16).
    pub cls_shift_regions: Vec<ClsShiftRegionObs>,
    /// Render-blocking head critical path summary.
    pub render_blocking_chain: RenderBlockingChainSummary,
}

/// Image or media format classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaFormatClass {
    /// Next-gen AVIF format (`image/avif`).
    Avif,
    /// Modern WebP format (`image/webp`).
    Webp,
    /// Vector SVG format (`image/svg+xml`).
    Svg,
    /// Legacy JPEG format (`image/jpeg`).
    Jpeg,
    /// Legacy PNG format (`image/png`).
    Png,
    /// Animated or static GIF format (`image/gif`).
    Gif,
    /// Video container (`video/*`).
    Video,
    /// Data URI or inline blob.
    InlineData,
    /// Unrecognised or unspecified media format.
    Unknown,
}

/// Loading strategy applied to an image or media element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MediaLoadingStrategy {
    /// `loading="lazy"`.
    Lazy,
    /// `loading="eager"`.
    Eager,
    /// Attribute omitted (browser default eager behaviour).
    Default,
}

/// Single rendered media or image asset diagnostic observation.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MediaAssetObs {
    /// Zero-based media asset index (`0..128`).
    pub node: u32,
    /// Stable cross-capture element identity.
    pub identity: RenderedElementIdentity,
    /// Lowercase tag name (`img`, `picture`, `video`, `svg`).
    pub tag: String,
    /// Secret-safe resource origin (`scheme://host[:port]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_origin: Option<String>,
    /// Secret-safe resource pathname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_path: Option<String>,
    /// Detected media format class.
    pub format_class: MediaFormatClass,
    /// Rendered CSS width in pixels.
    pub rendered_width: u32,
    /// Rendered CSS height in pixels.
    pub rendered_height: u32,
    /// Intrinsic (`naturalWidth`) width in pixels.
    pub natural_width: u32,
    /// Intrinsic (`naturalHeight`) height in pixels.
    pub natural_height: u32,
    /// Ratio of intrinsic pixel area to rendered pixel area in thousandths (`1000` = `1.0x`).
    #[serde(default)]
    pub oversize_ratio_milli: u32,
    /// Whether explicit `width` and `height` attributes (or CSS `aspect-ratio`) prevent layout shift.
    pub has_intrinsic_sizing: bool,
    /// Whether responsive `srcset` or `<picture>` source candidates are present.
    pub has_responsive_sources: bool,
    /// Effective `loading` attribute strategy.
    pub loading: MediaLoadingStrategy,
    /// Effective `fetchpriority` attribute (`high`, `low`, `auto`), if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_priority: Option<String>,
    /// Whether the media element intersects the initial above-the-fold viewport.
    pub above_the_fold: bool,
    /// Whether a non-empty `alt` attribute is present (or `alt=""` decorative).
    pub has_alt_attribute: bool,
    /// Whether the image is marked decorative (`alt=""` or `role="presentation"`).
    pub is_decorative: bool,
}

/// CSS `@font-face` `font-display` descriptor value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FontDisplayPolicy {
    /// `font-display: swap`.
    Swap,
    /// `font-display: optional`.
    Optional,
    /// `font-display: fallback`.
    Fallback,
    /// `font-display: block`.
    Block,
    /// `font-display: auto` or omitted.
    Auto,
}

/// Single webfont face observation from `document.fonts` and resource timings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FontAssetObs {
    /// Zero-based font index (`0..64`).
    pub index: u32,
    /// Font family name (`FontFace.family`, sanitized).
    pub font_family: String,
    /// Font style (`normal`, `italic`, etc.).
    pub font_style: String,
    /// Font weight (`400`, `700`, `normal`, `bold`, etc.).
    pub font_weight: String,
    /// Loading status from `FontFace.status` (`loaded`, `unloaded`, `loading`, `error`).
    pub status: String,
    /// Effective `font-display` policy.
    pub font_display: FontDisplayPolicy,
    /// Whether a matching `<link rel="preload" as="font">` hint exists in `<head>`.
    pub preloaded: bool,
}

/// Complete media and font diagnostic inventory for a rendered page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MediaAndFontInventory {
    /// Bounded list of rendered media elements (capped at 128).
    pub media_assets: Vec<MediaAssetObs>,
    /// Whether additional media assets were truncated.
    pub media_truncated: bool,
    /// Bounded list of webfont faces (capped at 64).
    pub font_assets: Vec<FontAssetObs>,
    /// Whether additional font faces were truncated.
    pub fonts_truncated: bool,
    /// Total font transfer bytes observed across network resources.
    pub total_font_transfer_bytes: u64,
}
