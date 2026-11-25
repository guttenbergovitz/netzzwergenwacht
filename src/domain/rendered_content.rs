//! Bounded observations of content after Chromium renders the main document.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Semantic region or paragraph in the rendered document.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RenderedBlockKind {
    /// An HTML paragraph.
    Paragraph,
    /// Primary content region.
    Main,
    /// Navigation region.
    Navigation,
    /// Header or banner region.
    Header,
    /// Footer or content information region.
    Footer,
    /// Complementary content.
    Aside,
    /// Section or ARIA region.
    Section,
    /// An article.
    Article,
}

/// Visibility according to the measured computed CSS properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RenderedCssVisibility {
    /// CSS did not suppress the element in the measured properties.
    Visible,
    /// CSS suppressed the element in the measured properties.
    Hidden,
}

/// An observed paragraph or region and its bounded CSS-eligible text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedContentBlock {
    /// One-based node visit position, scoped to this capture.
    pub node: u32,
    /// Observed semantic kind.
    pub kind: RenderedBlockKind,
    /// Computed CSS visibility of the block element.
    pub visibility: RenderedCssVisibility,
    /// Observed descendant text whose computed CSS permitted display.
    pub visible_text: String,
    /// Whether text exceeded the per-block retention bound.
    pub text_truncated: bool,
    /// Identity signals, absent in captures made before identity collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RenderedBlockIdentity>,
    /// Versioned fingerprint of the block's complete observed visible text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_fingerprint: Option<RenderedTextFingerprint>,
}

/// Fingerprint of observed rendered text under a versioned normalisation contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedTextFingerprint {
    /// Version of the extraction, normalisation and digest contract.
    pub version: u16,
    /// Hexadecimal digest. Version 1 uses SHA-256 over NFC UTF-8.
    pub digest: String,
}

/// Limits reached during segmentation. Any set flag means coverage is partial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedContentLimits {
    /// The traversal reached the node budget.
    pub nodes: bool,
    /// One or more subtrees exceeded the depth budget.
    pub depth: bool,
    /// The number of observed blocks exceeded the retention budget.
    pub blocks: bool,
}

impl RenderedContentLimits {
    /// Whether structural coverage was limited.
    #[must_use]
    pub const fn reached(&self) -> bool {
        self.nodes || self.depth || self.blocks
    }
}

/// A bounded segmentation of the main document at one viewport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedContentSegmentation {
    /// Viewport width in CSS pixels.
    pub viewport_width: u32,
    /// Viewport height in CSS pixels.
    pub viewport_height: u32,
    /// Retained blocks in document order.
    pub blocks: Vec<RenderedContentBlock>,
    /// Structural collection limits that affected coverage.
    pub limits: RenderedContentLimits,
    /// Whether all main-document light DOM elements were visited for ID counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_census_complete: Option<bool>,
}

impl RenderedContentSegmentation {
    /// Whether traversal or text retention was partial.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.limits.reached()
            || self.id_census_complete == Some(false)
            || self.blocks.iter().any(|block| block.text_truncated)
    }
}

/// Identity signals independent of the capture-local node position and text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedBlockIdentity {
    /// Body-relative ancestry and tag, without sibling ordinals.
    pub path: Option<Vec<String>>,
    /// ID presence and observed uniqueness in the main document.
    pub id: RenderedBlockId,
}

/// Identity evidence for an HTML ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RenderedBlockId {
    /// The element had no non-empty ID.
    Absent,
    /// The census observed a unique ID.
    Unique {
        /// SHA-256 digest of the UTF-16LE ID value.
        key: String,
    },
    /// The census observed at least two occurrences.
    Duplicate {
        /// SHA-256 digest of the UTF-16LE ID value.
        key: String,
    },
    /// The ID exceeded the field limit or uniqueness could not be established.
    Unavailable,
}
