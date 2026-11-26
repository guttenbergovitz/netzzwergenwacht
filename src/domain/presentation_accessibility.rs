//! Presentation geometry and accessibility node inventory domain contracts (Wave IV-C).
//!
//! Captures bounded element-level geometry (scroll/client dimensions, overflow clipping,
//! stacking context, and centre-point hit-test occlusion) alongside a bounded per-node
//! Chromium Accessibility (`AX`) tree inventory without storing raw visible text or
//! secret form values.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::functional_intelligence::ElementBoundingBox;
use crate::domain::rendered_content::RenderedElementIdentity;

/// CSS overflow behaviour along a single axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CssOverflowKind {
    /// Content is not clipped (`visible`).
    #[default]
    Visible,
    /// Content is clipped without scrollbars (`hidden`).
    Hidden,
    /// Content is clipped to the padding box (`clip`).
    Clip,
    /// Scrollbars are always provided (`scroll`).
    Scroll,
    /// Scrollbars are provided when content overflows (`auto`).
    Auto,
    /// Non-standard or unrecognised overflow value.
    Other,
}

/// CSS positioning scheme for an inspected element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CssPositionKind {
    /// Default normal-flow positioning (`static`).
    #[default]
    Static,
    /// Offset relative to normal flow (`relative`).
    Relative,
    /// Positioned relative to nearest positioned ancestor (`absolute`).
    Absolute,
    /// Positioned relative to the viewport (`fixed`).
    Fixed,
    /// Hybrid scroll-threshold positioning (`sticky`).
    Sticky,
}

/// Stacking context and positioning metadata for an inspected element.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct StackingContextObs {
    /// Computed CSS `position` scheme.
    pub position: CssPositionKind,
    /// Parsed integer `z-index` when explicitly set (omitted for `auto`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub z_index: Option<i32>,
    /// Whether computed `position`, `z-index`, `opacity`, or `transform` creates a stacking context.
    pub establishes_stacking_context: bool,
}

/// Element-level visual geometry, overflow clipping, and hit-test occlusion observation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ElementGeometryObs {
    /// 1-based traversal index within the geometry pass.
    pub node: u32,
    /// Stable cross-capture element identity (hashed ID and structural path).
    pub identity: RenderedElementIdentity,
    /// Lowercase HTML tag name.
    pub tag: String,
    /// Explicit or implicit ARIA role when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Rounded bounding box in CSS pixels relative to the layout viewport.
    pub bbox: ElementBoundingBox,
    /// Element `scrollWidth` in CSS pixels.
    pub scroll_width: u32,
    /// Element `scrollHeight` in CSS pixels.
    pub scroll_height: u32,
    /// Element `clientWidth` in CSS pixels.
    pub client_width: u32,
    /// Element `clientHeight` in CSS pixels.
    pub client_height: u32,
    /// Computed `overflow-x` behaviour.
    pub overflow_x: CssOverflowKind,
    /// Computed `overflow-y` behaviour.
    pub overflow_y: CssOverflowKind,
    /// Horizontal overflow excess (`max(0, scrollWidth - clientWidth)`) in CSS pixels.
    pub horizontal_overflow_px: u32,
    /// Vertical overflow excess (`max(0, scrollHeight - clientHeight)`) in CSS pixels.
    pub vertical_overflow_px: u32,
    /// Whether non-zero content overflow is clipped by `hidden` or `clip` without scrollbars.
    pub clipped_by_overflow: bool,
    /// Whether `document.elementFromPoint` at the element's centre resolves to an unrelated element.
    pub occluded_at_center: bool,
    /// Lowercase tag name of the occluding top-most element when `occluded_at_center` is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occluding_tag: Option<String>,
    /// Stacking and positioning context for the element.
    pub stacking: StackingContextObs,
}

/// Explicit traversal and retention bounds for the visual geometry collector.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct VisualGeometryLimits {
    /// Whether the DOM traversal cap (16,384 nodes) was reached.
    pub dom_truncated: bool,
    /// Whether the DOM depth cap (64 levels) was reached.
    pub depth_truncated: bool,
    /// Whether the retained element geometry cap (128 elements) was reached.
    pub elements_truncated: bool,
}

/// Bounded element-level visual geometry inventory for a rendered page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct VisualGeometryInventory {
    /// Viewport width in CSS pixels during the geometry measurement pass.
    pub viewport_width: u32,
    /// Viewport height in CSS pixels during the geometry measurement pass.
    pub viewport_height: u32,
    /// Retained element geometry observations in document pre-order.
    pub elements: Vec<ElementGeometryObs>,
    /// Explicit traversal and retention truncation flags.
    pub limits: VisualGeometryLimits,
}

/// Source from which Chromium computed an accessibility node's accessible name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AxNameSourceKind {
    /// Name came from an explicit attribute (`aria-label`, `alt`, etc.).
    Attribute,
    /// Name came from a referenced element (`aria-labelledby`, `<label for>`).
    RelatedElement,
    /// Name was computed from descendant text contents.
    Contents,
    /// Name fell back to a placeholder attribute.
    Placeholder,
    /// Name came from a `title` attribute or fallback tooltip.
    Title,
    /// No accessible name was present.
    #[default]
    None,
    /// Other or unspecified CDP name source.
    Other,
}

/// Per-node observation from the Chromium Accessibility (`AX`) tree.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccessibilityNodeObs {
    /// 1-based index of this node within the retained AX inventory.
    pub node_index: u32,
    /// Sanitized CDP AX node identifier.
    pub ax_node_id: String,
    /// 1-based index of the parent node within the retained inventory, if retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_index: Option<u32>,
    /// Number of direct child AX nodes reported by Chromium.
    pub child_count: u32,
    /// Normalized lowercase AX role (for example `"button"`, `"heading"`, `"dialog"`).
    pub role: String,
    /// Whether a non-empty accessible name was computed.
    pub name_present: bool,
    /// Character count of the trimmed accessible name.
    pub name_length: u32,
    /// Versioned SHA-256 fingerprint (`sha256:v1:<64 lowercase hex>`) of the accessible name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_fingerprint: Option<String>,
    /// Source used by Chromium to compute the accessible name.
    pub name_source: AxNameSourceKind,
    /// Whether an accessible description was present.
    pub description_present: bool,
    /// Whether the AX node is keyboard focusable.
    pub focusable: bool,
    /// Whether the AX node currently holds focus.
    pub focused: bool,
    /// Whether the AX node is marked disabled.
    pub disabled: bool,
    /// Expanded state when reported (`aria-expanded`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded: Option<bool>,
    /// Selected state when reported (`aria-selected`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<bool>,
    /// Checked state when reported (`"true"`, `"false"`, `"mixed"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<String>,
    /// Modal state when reported (`aria-modal`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modal: Option<bool>,
    /// Live region politeness setting when reported (`"polite"`, `"assertive"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_politeness: Option<String>,
    /// Whether Chromium marked this AX node as ignored.
    pub ignored: bool,
    /// Primary reason Chromium ignored this AX node, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ignored_reason: Option<String>,
    /// Whether the node represents an interactive control role.
    pub interactive: bool,
}

/// Explicit retention bounds for the per-node accessibility tree inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccessibilityInventoryLimits {
    /// Total AX nodes returned by `Accessibility.getFullAXTree` before filtering/capping.
    pub total_cdp_nodes: u32,
    /// Whether the retained AX node cap (256 nodes) was reached.
    pub nodes_truncated: bool,
}

/// Bounded per-node Chromium Accessibility (`AX`) tree inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccessibilityNodeInventory {
    /// Retained AX node observations.
    pub nodes: Vec<AccessibilityNodeObs>,
    /// Explicit retention and truncation metadata.
    pub limits: AccessibilityInventoryLimits,
}
