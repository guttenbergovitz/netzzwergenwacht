//! Bounded observations of content after Chromium renders the main document.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Semantic region or paragraph in the rendered document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
}

impl RenderedContentSegmentation {
    /// Whether traversal or text retention was partial.
    #[must_use]
    pub fn is_partial(&self) -> bool {
        self.limits.reached() || self.blocks.iter().any(|block| block.text_truncated)
    }
}
