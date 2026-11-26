//! Responsive cross-viewport layout anomalies and internal/external link graph contracts (Wave IV-G).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::rendered_content::{RenderedElementIdentity, RenderedTextFingerprint};

/// Specific cross-viewport responsive layout defect class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponsiveAnomalyKind {
    /// Element or document causes horizontal scroll overflow at mobile width (`375px`).
    MobileHorizontalOverflow,
    /// Interactive control touch target is smaller than `24x24` CSS pixels on mobile.
    UndersizedMobileTouchTarget,
    /// Primary content or navigation visible on desktop (`1280px`) is hidden on mobile without a disclosure trigger.
    ContentHiddenOnMobileWithoutTrigger,
    /// Fixed or sticky header/banner obscures more than 35% of the mobile viewport height.
    ExcessiveFixedHeaderObstruction,
}

/// Single cross-viewport responsive anomaly observation comparing mobile (`375x667`) and desktop (`1280x800`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResponsiveAnomalyObs {
    /// Zero-based anomaly index (`0..64`).
    pub anomaly_index: u32,
    /// Classification of the responsive layout defect.
    pub kind: ResponsiveAnomalyKind,
    /// Stable cross-capture element identity of the affected element, if element-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RenderedElementIdentity>,
    /// Lowercase tag name of the affected element.
    pub tag: String,
    /// Measured metric value on mobile (`375px` viewport) in CSS pixels.
    pub mobile_metric_px: u32,
    /// Measured metric value on desktop (`1280px` viewport) in CSS pixels.
    pub desktop_metric_px: u32,
}

/// Consolidated responsive cross-viewport comparison evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ResponsiveComparisonEvidence {
    /// Mobile viewport width in CSS pixels (`375`).
    pub mobile_viewport_width: u32,
    /// Mobile document `scrollWidth` in CSS pixels.
    pub mobile_scroll_width: u32,
    /// Desktop viewport width in CSS pixels (`1280`).
    pub desktop_viewport_width: u32,
    /// Desktop document `scrollWidth` in CSS pixels.
    pub desktop_scroll_width: u32,
    /// Count of interactive controls visible on desktop, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_visible_controls: Option<u32>,
    /// Count of interactive controls visible on mobile, when measured. Never inferred
    /// from the desktop viewport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile_visible_controls: Option<u32>,
    /// Count of undersized (`< 24x24px`) touch targets on mobile.
    pub mobile_undersized_touch_targets: u32,
    /// Bounded list of element-level responsive anomalies (capped at 64).
    pub anomalies: Vec<ResponsiveAnomalyObs>,
    /// Whether additional anomalies were truncated.
    pub anomalies_truncated: bool,
}

/// Structural DOM landmark or page region where a link or form is placed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkPlacementRegion {
    /// Inside `<header>` or `<nav>`.
    HeaderOrNav,
    /// Inside `<main>` or `<article>`.
    MainContent,
    /// Inside `<aside>` or complementary sidebar.
    Complementary,
    /// Inside `<footer>`.
    Footer,
    /// Outside any semantic landmark region.
    UnscopedBody,
}

/// Single rendered hyperlink observation in the page link graph.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedLinkObs {
    /// Zero-based link index (`0..256`).
    pub link_index: u32,
    /// Stable cross-capture element identity of the `<a>` element.
    pub identity: RenderedElementIdentity,
    /// Structural landmark region containing the link.
    pub placement_region: LinkPlacementRegion,
    /// Secret-safe target origin (`scheme://host[:port]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_origin: Option<String>,
    /// Secret-safe target pathname (stripped of query secrets and fragments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<String>,
    /// Whether the target shares the audited page origin.
    pub same_origin: bool,
    /// Whether the link is a fragment-only (`#...`) anchor.
    pub fragment_only: bool,
    /// Whether the link is currently visible in the rendered DOM.
    pub visible: bool,
    /// Word count of the link's visible or accessible anchor text.
    pub anchor_word_count: u32,
    /// SHA-256 fingerprint of the normalised anchor text (never raw text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_text_fingerprint: Option<RenderedTextFingerprint>,
    /// Whether `rel` includes `nofollow`.
    pub rel_nofollow: bool,
    /// Whether `rel` includes `noopener` or `noreferrer`.
    pub rel_noopener: bool,
    /// Whether `target="_blank"` is set.
    pub opens_new_tab: bool,
}

/// Rendered `<form>` submission endpoint contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedFormEndpointObs {
    /// Zero-based form index (`0..32`).
    pub form_index: u32,
    /// Stable cross-capture element identity of the `<form>` element.
    pub identity: RenderedElementIdentity,
    /// Normalized HTTP method (`GET`, `POST`, `DIALOG`).
    pub method: String,
    /// Secret-safe action target origin (`scheme://host[:port]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_origin: Option<String>,
    /// Secret-safe action target pathname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_path: Option<String>,
    /// Whether the form action targets the same origin over HTTPS.
    pub secure_same_origin_action: bool,
    /// Total input/select/textarea controls inside the form.
    pub field_count: u32,
    /// Number of required controls inside the form.
    pub required_field_count: u32,
    /// Whether the form contains a password or payment input.
    pub has_sensitive_input: bool,
}

/// Aggregated link distribution across semantic placement regions.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LinkClusterSummary {
    /// Total internal (same-origin) links discovered.
    pub internal_links: u32,
    /// Total external (cross-origin) links discovered.
    pub external_links: u32,
    /// Links placed in `<header>` or `<nav>`.
    pub header_nav_links: u32,
    /// Links placed in `<main>` or `<article>`.
    pub main_content_links: u32,
    /// Links placed in `<footer>`.
    pub footer_links: u32,
    /// Links with empty accessible anchor text (`anchor_word_count == 0`).
    pub empty_anchor_links: u32,
}

/// Complete rendered link graph and form endpoint inventory for a page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LinkGraphInventory {
    /// Aggregated link cluster counts across landmarks.
    pub cluster_summary: LinkClusterSummary,
    /// Bounded list of rendered hyperlinks (capped at 256).
    pub links: Vec<RenderedLinkObs>,
    /// Whether additional links were truncated.
    pub links_truncated: bool,
    /// Bounded list of rendered `<form>` endpoints (capped at 32).
    pub forms: Vec<RenderedFormEndpointObs>,
    /// Whether additional forms were truncated.
    pub forms_truncated: bool,
}
