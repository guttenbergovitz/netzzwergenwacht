//! Functional intelligence domain contracts (Wave IV-B):
//! - Interactive Element Inventory Collector
//! - Application State Collector
//! - Bounded Read-Only User Journey & Interaction Collector
//!
//! All types in this module are pure domain data structures free of I/O or
//! transport concerns. Never store raw input values, form secrets, or
//! uncontrolled DOM text.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::rendered_content::{RenderedElementIdentity, RenderedTextFingerprint};

/// Rendered bounding box in integer CSS pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ElementBoundingBox {
    /// Horizontal offset from the viewport origin in CSS pixels.
    pub x: i32,
    /// Vertical offset from the viewport origin in CSS pixels.
    pub y: i32,
    /// Rendered box width in CSS pixels.
    pub width: u32,
    /// Rendered box height in CSS pixels.
    pub height: u32,
}

/// Safety classification governing whether an interactive element may be
/// exercised automatically during read-only inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InteractionSafetyClass {
    /// Read-only in-page UI toggle (tabs, accordions, disclosures, menus, dialogs).
    #[default]
    ReadOnlyUiToggle,
    /// Read-only navigation link (`<a href="...">`).
    ReadOnlyNavigation,
    /// Data-entry form control (`<input>`, `<select>`, `<textarea>`).
    FormInput,
    /// State-changing submission, mutation, or payment/account trigger.
    StateChangingSubmission,
}

/// Functional classification of a UI control or interactive component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FunctionalComponentKind {
    /// Primary or secondary navigation menu trigger or item.
    NavigationMenu,
    /// Search input or search trigger button.
    Search,
    /// Product option, variant, or configuration selector.
    ProductSelector,
    /// Facet or result filter control.
    Filter,
    /// Result ordering / sort control.
    Sort,
    /// Pagination link or page selector.
    Pagination,
    /// Locale, currency, or language selector.
    LanguageSelector,
    /// Form input or fieldset control.
    Form,
    /// Call-to-action button or primary action link.
    Cta,
    /// Modal dialog or drawer trigger/dismiss control.
    Dialog,
    /// Tablist or tab trigger (`role="tab"`).
    Tabs,
    /// Accordion or `<details>`/`<summary>` disclosure control.
    Accordion,
    /// Carousel or slider pagination control.
    Carousel,
    /// Combobox, autocomplete, or custom select trigger.
    Combobox,
    /// Audio/video media playback control.
    MediaPlayer,
    /// File or asset download trigger.
    DownloadControl,
    /// Unclassified interactive control.
    #[default]
    GenericControl,
}

/// Sanitized navigation target metadata for links and form actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InteractiveTargetLink {
    /// Target origin (`scheme://host[:port]`) when external or absolute, if parseable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href_origin: Option<String>,
    /// Secret-safe pathname without query string or fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href_path: Option<String>,
    /// Whether the target shares the audited document origin.
    pub same_origin: bool,
    /// Whether the link targets an in-page fragment anchor (`#section`).
    #[serde(default)]
    pub fragment_only: bool,
}

/// Single interactive element observation in the rendered DOM.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InteractiveElementObs {
    /// Pre-order traversal node index within the interactive inventory.
    pub node: u32,
    /// Stable cross-capture element identity.
    pub identity: RenderedElementIdentity,
    /// Lowercase HTML tag name (`a`, `button`, `input`, `select`, `summary`, etc.).
    pub tag: String,
    /// Effective ARIA or implicit landmark/widget role, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Input or button `type` attribute (`button`, `submit`, `search`, `checkbox`, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_type: Option<String>,
    /// Whether a non-empty accessible name or label was resolved.
    #[serde(default)]
    pub name_present: bool,
    /// SHA-256 fingerprint of the normalised accessible name (never raw text).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessible_name_fingerprint: Option<RenderedTextFingerprint>,
    /// Character count of the normalised accessible name (`0` when unnamed).
    #[serde(default)]
    pub accessible_name_char_count: u32,
    /// Whether the control is currently visible (`display != none`, `visibility != hidden`, non-zero box).
    #[serde(default)]
    pub visible: bool,
    /// Whether the control is enabled (not `disabled` and not `aria-disabled="true"`).
    #[serde(default)]
    pub enabled: bool,
    /// Whether the control is explicitly disabled.
    #[serde(default)]
    pub disabled: bool,
    /// `aria-expanded` or `<details open>` state when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded: Option<bool>,
    /// `aria-selected` or `<option selected>` state when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<bool>,
    /// `checked` or `aria-checked` state when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    /// Whether the form control is marked required.
    #[serde(default)]
    pub required: bool,
    /// Whether the form control is marked invalid (`aria-invalid="true"` or `:invalid`).
    #[serde(default)]
    pub invalid: bool,
    /// Whether the control is reachable in the sequential keyboard tab order.
    #[serde(default)]
    pub keyboard_focusable: bool,
    /// Effective `tabindex` value when explicitly set or natively focusable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab_index: Option<i32>,
    /// Rendered bounding box in CSS pixels.
    #[serde(default)]
    pub bbox: ElementBoundingBox,
    /// Sanitized navigation target when the element is a link or form trigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_link: Option<InteractiveTargetLink>,
    /// Safety classification for automated interaction.
    pub safety_class: InteractionSafetyClass,
    /// Functional UI component classification.
    pub functional_kind: FunctionalComponentKind,
}

/// Collection bounds and truncation markers for the interactive element inventory.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct InteractiveInventoryLimits {
    /// Maximum interactive elements recorded (`256`).
    pub max_elements: u32,
    /// Total interactive candidates discovered before truncation.
    pub discovered_elements: u32,
    /// Whether additional interactive elements were omitted after reaching `max_elements`.
    pub elements_truncated: bool,
}

/// Complete interactive element inventory for a rendered page.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct InteractiveElementInventory {
    /// Bounded list of interactive elements in pre-order DOM traversal.
    pub elements: Vec<InteractiveElementObs>,
    /// Collection bounds and truncation metadata.
    pub limits: InteractiveInventoryLimits,
}

/// Structured application state snapshot captured from the live browser runtime.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ApplicationStateSnapshot {
    /// `document.readyState` (`loading`, `interactive`, `complete`).
    pub document_ready_state: String,
    /// Secret-safe pathname of the current location (`location.pathname`).
    pub location_path: String,
    /// Whether a location hash fragment is currently active.
    pub has_location_hash: bool,
    /// History length (`history.length`).
    pub history_length: u32,
    /// Lowercase tag name of `document.activeElement`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_element_tag: Option<String>,
    /// Effective role of `document.activeElement`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_element_role: Option<String>,
    /// Number of currently open modal or non-modal dialogs (`dialog[open]`, `[role="dialog"]`).
    pub active_dialog_count: u32,
    /// Whether a modal dialog or overlay is currently open (`active_dialog_count > 0`).
    #[serde(default)]
    pub modal_open: bool,
    /// Number of currently selected tab controls (`[role="tab"][aria-selected="true"]`).
    pub active_tab_count: u32,
    /// Number of currently expanded controls (`[aria-expanded="true"]`, `details[open]`).
    pub expanded_control_count: u32,
    /// Number of disabled controls (`:disabled`, `[aria-disabled="true"]`).
    pub disabled_control_count: u32,
    /// Number of required form inputs.
    pub required_input_count: u32,
    /// Number of invalid form inputs (`:invalid`, `[aria-invalid="true"]`).
    pub invalid_input_count: u32,
    /// Number of visible loading indicators (`[aria-busy="true"]`, `[role="progressbar"]`).
    pub loading_indicator_count: u32,
    /// Number of visible error banners or alert regions (`[role="alert"]`).
    pub alert_region_count: u32,
    /// Current horizontal scroll offset in CSS pixels.
    pub scroll_x: i32,
    /// Current vertical scroll offset in CSS pixels.
    pub scroll_y: i32,
    /// Total scrollable document height in CSS pixels.
    pub document_scroll_height: u32,
    /// Whether the network reached idle equilibrium before snapshot capture.
    pub network_idle_reached: bool,
    /// Bounded structural digest over tag/role/id-uniqueness/disclosure state.
    ///
    /// Only a hash of the bounded walk is retained, never the raw structure. The
    /// projection is not the complete DOM; the coverage fields below state how
    /// much of the document it describes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_fingerprint: Option<String>,
    /// Version of the structural fingerprint algorithm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_fingerprint_version: Option<u32>,
    /// Number of element nodes included in the bounded walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_nodes_visited: Option<u32>,
    /// Node budget applied to the bounded walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_max_nodes: Option<u32>,
    /// Maximum element depth the bounded walk descends to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_max_depth: Option<u32>,
    /// Whether the node budget ended the walk before the document was exhausted.
    #[serde(default)]
    pub structural_nodes_truncated: bool,
    /// Whether the depth budget ended the walk before the document was exhausted.
    #[serde(default)]
    pub structural_depth_truncated: bool,
}

/// Read-only action executed during a bounded interaction probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InteractionActionKind {
    /// Sequential `Tab` key press advancing keyboard focus.
    #[default]
    TabFocusAdvance,
    /// `Escape` key press testing modal/overlay dismissal.
    EscapeDismiss,
    /// Read-only disclosure or accordion toggle (`details > summary`, `[aria-expanded]`).
    DisclosureToggle,
    /// Read-only tab activation (`[role="tab"]`).
    TabSelect,
}

/// Candidate user journey scenario discovered from the interactive inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CandidateJourneyScenario {
    /// Site search discovery flow.
    SiteSearch,
    /// Primary navigation and menu disclosure flow.
    NavigationDisclosure,
    /// Tabbed content switching flow.
    TabbedInterface,
    /// Accordion / FAQ disclosure expansion flow.
    AccordionExpansion,
    /// Modal dialog or consent banner dismissal flow.
    ModalDismissal,
    /// Faceted filtering or sorting flow.
    FilterOrSort,
    /// Multi-page pagination traversal flow.
    PaginationTraversal,
    /// Locale or language switching flow.
    LanguageSelection,
    /// Data-entry form validation flow.
    FormEntry,
}

/// Single step recorded in a bounded read-only interaction trace.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InteractionTraceStep {
    /// Zero-based sequential step index (`0..16`).
    pub step_index: u32,
    /// Action executed at this step.
    pub action: InteractionActionKind,
    /// Target interactive element node index from [`InteractiveElementInventory`], if targeted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<u32>,
    /// Stable identity of the target or newly focused element, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_identity: Option<RenderedElementIdentity>,
    /// Lowercase tag name of the element receiving focus or activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_tag: Option<String>,
    /// Effective role of the element receiving focus or activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_role: Option<String>,
    /// Whether any observable application state changed as a result of this step.
    #[serde(default)]
    pub state_changed: bool,
    /// Whether keyboard focus moved to a new element.
    pub focus_changed: bool,
    /// Whether expanded control count or state changed as a result of the action.
    pub expanded_changed: bool,
    /// Whether active dialog count changed as a result of the action.
    pub dialog_changed: bool,
    /// Whether the structural fingerprint changed after the action.
    #[serde(default)]
    pub dom_fingerprint_changed: bool,
    /// Number of new runtime console errors or exceptions triggered during the step.
    pub new_runtime_errors: u32,
    /// Number of network requests initiated during the step.
    pub triggered_requests: u32,
}

/// Bounded read-only interaction trace and discovered candidate user journeys.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct UserJourneyTrace {
    /// Candidate scenarios discovered from the page's interactive controls.
    pub candidate_scenarios: Vec<CandidateJourneyScenario>,
    /// Recorded read-only interaction steps (capped at 16 steps).
    pub steps: Vec<InteractionTraceStep>,
    /// Whether the step budget (`16`) truncated additional candidate steps.
    pub truncated: bool,
}
