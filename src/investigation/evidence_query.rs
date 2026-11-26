//! Deterministic offline query engine over a captured [`EvidenceSnapshot`].
//!
//! Provides bounded, paginated, zero-acquisition views over Level 2 browser
//! evidence (rendered content blocks, subresource network timings, and runtime
//! errors) so `KommandantZwerg` and specialist dwarfs can inspect already
//! captured evidence without launching additional browser sessions or exposing
//! raw untrusted page text in prompts.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::domain::{
    AccessibilityNodeObs, ApplicationStateSnapshot, BrowserEvidence, CandidateJourneyScenario,
    CollectorOutcome, ConsoleErrorEvent, CookieSameSiteMode, ElementGeometryObs, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, FontAssetObs, FunctionalComponentKind,
    IndexabilityAuthorityEvidence, InteractionActionKind, InteractionSafetyClass,
    InteractionTraceStep, InteractiveElementObs, LinkClusterSummary, LinkPlacementRegion,
    MediaAssetObs, MediaFormatClass, PerformanceAttributionEvidence, RenderedBlockIdentity,
    RenderedBlockKind, RenderedContentBlock, RenderedContentLimits, RenderedCssVisibility,
    RenderedFormEndpointObs, RenderedLinkObs, RenderedTextFingerprint, ResourceTimingObs,
    ResponsiveAnomalyKind, ResponsiveAnomalyObs, RuntimeCookieObs, SecurityChallengeEvidence,
    SecurityPostureSummary, ServiceWorkerLifecycleEvidence, SocialPreviewCardCompleteness,
    StorageKeyObs, StructuredDataSyntax, StructuredEntitySummary, ThirdPartyOriginObs,
    TlsAndCaaDiagnostics, TlsEvidence, VisualArtifactEvidence, WebStorageArea,
};
use crate::investigation::tools::QueryBrowserEvidenceOutput;

/// Maximum number of items returned in a single offline evidence query page.
pub const PAGE_SIZE: usize = 16;

/// Default skip reason emitted by [`CollectorOutcome::default`].
const DEFAULT_NOT_COLLECTED_REASON: &str = "not collected";

/// Explicit availability and completeness state of an offline snapshot query.
///
/// Preserves the distinction between uncollected, skipped, failed, partial,
/// and unavailable sub-artefacts so callers never confuse missing collection
/// with zero observed items.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EvidenceQueryStatus {
    /// Collector and sub-artefact completed within configured bounds.
    Captured,
    /// Collector or sub-artefact reached a sampling, traversal, or retention limit.
    Partial {
        /// Explicit completeness warnings or reached limit descriptions.
        warnings: Vec<String>,
    },
    /// Enclosing collector ran and failed.
    Failed {
        /// Collector error description.
        error: String,
    },
    /// Enclosing collector was skipped (including `"not collected"`).
    Skipped {
        /// Reason the collector was skipped.
        reason: String,
    },
    /// Enclosing collector ran, but the specific sub-artefact was not recorded.
    Unavailable {
        /// Explanation of why the sub-artefact is absent.
        reason: String,
    },
}

/// Filter predicates for [`query_rendered_content`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenderedBlockFilter {
    /// Restrict results to a specific semantic block kind.
    pub kind: Option<RenderedBlockKind>,
    /// Restrict results to a specific computed CSS visibility state.
    pub visibility: Option<RenderedCssVisibility>,
    /// Restrict results to blocks with a verified unique HTML `id` digest.
    pub require_unique_id: bool,
}

impl RenderedBlockFilter {
    fn matches(&self, block: &RenderedContentBlock) -> bool {
        if let Some(expected_kind) = self.kind
            && block.kind != expected_kind
        {
            return false;
        }
        if let Some(expected_vis) = self.visibility
            && block.visibility != expected_vis
        {
            return false;
        }
        if self.require_unique_id {
            let has_unique_id = block
                .identity
                .as_ref()
                .is_some_and(|id| matches!(id.id, crate::domain::RenderedBlockId::Unique { .. }));
            if !has_unique_id {
                return false;
            }
        }
        true
    }
}

/// Sanitised summary of a single [`RenderedContentBlock`] omitting raw `visible_text`.
///
/// Exposes structural identity, computed visibility, word/character counts,
/// truncation status, and the versioned SHA-256 `text_fingerprint` without
/// injecting untrusted document prose into agent prompts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedBlockSummary<'a> {
    /// One-based capture-scoped node visit position.
    pub node: u32,
    /// Semantic region or paragraph kind.
    pub kind: RenderedBlockKind,
    /// Computed CSS visibility of the block element.
    pub visibility: RenderedCssVisibility,
    /// Whitespace-delimited word count derived from `visible_text`.
    pub visible_word_count: usize,
    /// Unicode scalar count derived from `visible_text`.
    pub visible_char_count: usize,
    /// Whether `visible_text` exceeded the per-block retention bound.
    pub text_truncated: bool,
    /// Structural path and HTML ID uniqueness metadata, when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<&'a RenderedBlockIdentity>,
    /// Versioned SHA-256 digest over normalised visible text, when captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_fingerprint: Option<&'a RenderedTextFingerprint>,
}

impl<'a> RenderedBlockSummary<'a> {
    fn from_block(block: &'a RenderedContentBlock) -> Self {
        Self {
            node: block.node,
            kind: block.kind,
            visibility: block.visibility,
            visible_word_count: block.visible_text.split_whitespace().count(),
            visible_char_count: block.visible_text.chars().count(),
            text_truncated: block.text_truncated,
            identity: block.identity.as_ref(),
            text_fingerprint: block.text_fingerprint.as_ref(),
        }
    }
}

/// One bounded page of rendered content blocks from a captured [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedContentQueryPage<'a> {
    /// Availability and completeness status of rendered content segmentation.
    pub status: EvidenceQueryStatus,
    /// Viewport width in CSS pixels when segmentation is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport_width: Option<u32>,
    /// Viewport height in CSS pixels when segmentation is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport_height: Option<u32>,
    /// SHA-256 digest of the final browser URL when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_key: Option<&'a str>,
    /// Whether the main-document light-DOM ID census visited all elements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_census_complete: Option<bool>,
    /// Structural traversal limits reached during collection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<RenderedContentLimits>,
    /// Total number of blocks matching the supplied filter across the segmentation.
    pub total_matching: usize,
    /// Bounded page of matching block summaries (at most [`PAGE_SIZE`]).
    pub blocks: Vec<RenderedBlockSummary<'a>>,
    /// Offset of the next matching page, if additional blocks remain.
    pub next_offset: Option<usize>,
}

/// Queries up to [`PAGE_SIZE`] rendered content blocks from `snapshot` without starting a browser.
#[must_use]
pub fn query_rendered_content<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &RenderedBlockFilter,
    offset: usize,
) -> RenderedContentQueryPage<'a> {
    let (data, mut warnings) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, Vec::new()),
        CollectorOutcome::Partial { data, warnings } => (data, warnings.clone()),
        CollectorOutcome::Failed { error } => {
            return empty_rendered_page(EvidenceQueryStatus::Failed {
                error: error.clone(),
            });
        }
        CollectorOutcome::Skipped { reason } => {
            return empty_rendered_page(EvidenceQueryStatus::Skipped {
                reason: reason.clone(),
            });
        }
    };

    let Some(segmentation) = data.rendered_content.as_ref() else {
        return empty_rendered_page(EvidenceQueryStatus::Unavailable {
            reason: "rendered_content segmentation not present in browser evidence".to_owned(),
        });
    };

    if segmentation.limits.nodes {
        warnings.push("rendered content node traversal limit reached".to_owned());
    }
    if segmentation.limits.depth {
        warnings.push("rendered content subtree depth limit reached".to_owned());
    }
    if segmentation.limits.blocks {
        warnings.push("rendered content block retention limit reached".to_owned());
    }
    if segmentation.id_census_complete == Some(false) {
        warnings.push("rendered content HTML ID census was incomplete".to_owned());
    }
    if segmentation.blocks.iter().any(|b| b.text_truncated) {
        warnings.push("one or more rendered blocks had visible_text truncated".to_owned());
    }

    let matching: Vec<RenderedBlockSummary<'a>> = segmentation
        .blocks
        .iter()
        .filter(|block| filter.matches(block))
        .map(RenderedBlockSummary::from_block)
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let status = if warnings.is_empty() {
        EvidenceQueryStatus::Captured
    } else {
        EvidenceQueryStatus::Partial { warnings }
    };

    RenderedContentQueryPage {
        status,
        viewport_width: Some(segmentation.viewport_width),
        viewport_height: Some(segmentation.viewport_height),
        page_key: segmentation.page_key.as_deref(),
        id_census_complete: segmentation.id_census_complete,
        limits: Some(segmentation.limits.clone()),
        total_matching,
        blocks: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
    }
}

const fn empty_rendered_page(status: EvidenceQueryStatus) -> RenderedContentQueryPage<'static> {
    RenderedContentQueryPage {
        status,
        viewport_width: None,
        viewport_height: None,
        page_key: None,
        id_census_complete: None,
        limits: None,
        total_matching: 0,
        blocks: Vec::new(),
        next_offset: None,
    }
}

/// Serialises page 0 of [`query_rendered_content`] for bounded prompt inclusion.
///
/// Escapes `<` as `\u003c` so untrusted attribute/path tokens cannot close XML
/// evidence delimiters. Never includes raw `visible_text`.
#[must_use]
pub fn rendered_content_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "rendered content unavailable".to_owned();
    };
    let page = query_rendered_content(snapshot, &RenderedBlockFilter::default(), 0);
    if page.blocks.is_empty()
        && matches!(
            page.status,
            EvidenceQueryStatus::Skipped { .. }
                | EvidenceQueryStatus::Failed { .. }
                | EvidenceQueryStatus::Unavailable { .. }
        )
    {
        return "rendered content unavailable".to_owned();
    }
    serde_json::to_string(&page).map_or_else(
        |_| "rendered content unavailable".to_owned(),
        |json| json.replace('<', r"\u003c"),
    )
}

/// Maps cited rendered block `node` identifiers on page 0 into [`EvidenceRef`]s.
///
/// Only blocks present on the supplied page 0 (`offset = 0`) are accepted so
/// LLM evaluations cannot fabricate citations to uninspected node numbers.
#[must_use]
pub fn cited_rendered_block_refs(snapshot: &EvidenceSnapshot, nodes: &[u32]) -> Vec<EvidenceRef> {
    let page = query_rendered_content(snapshot, &RenderedBlockFilter::default(), 0);
    page.blocks
        .into_iter()
        .filter(|block| nodes.contains(&block.node))
        .map(|block| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "rendered-block-node={}:kind={}:visibility={}",
                    block.node,
                    block_kind_label(block.kind),
                    visibility_label(block.visibility)
                ),
            )
        })
        .collect()
}

const fn block_kind_label(kind: RenderedBlockKind) -> &'static str {
    match kind {
        RenderedBlockKind::Paragraph => "paragraph",
        RenderedBlockKind::Main => "main",
        RenderedBlockKind::Navigation => "navigation",
        RenderedBlockKind::Header => "header",
        RenderedBlockKind::Footer => "footer",
        RenderedBlockKind::Aside => "aside",
        RenderedBlockKind::Section => "section",
        RenderedBlockKind::Article => "article",
    }
}

const fn visibility_label(visibility: RenderedCssVisibility) -> &'static str {
    match visibility {
        RenderedCssVisibility::Visible => "visible",
        RenderedCssVisibility::Hidden => "hidden",
    }
}

/// Filter predicates for [`query_network_resources`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkResourceFilter<'a> {
    /// Case-insensitive CDP/initiator resource type filter (e.g. `"script"`, `"image"`).
    pub resource_type: Option<&'a str>,
    /// Minimum observed load duration in milliseconds.
    pub min_duration_ms: Option<u64>,
    /// Minimum observed transfer size in bytes.
    pub min_transfer_bytes: Option<u64>,
    /// When `true`, only include resources with HTTP status codes `>= 400`.
    pub status_error_only: bool,
}

impl NetworkResourceFilter<'_> {
    fn matches(&self, resource: &ResourceTimingObs) -> bool {
        if let Some(expected_type) = self.resource_type
            && !resource.resource_type.eq_ignore_ascii_case(expected_type)
        {
            return false;
        }
        if let Some(min_dur) = self.min_duration_ms
            && resource.duration_ms.unwrap_or(0) < min_dur
        {
            return false;
        }
        if let Some(min_bytes) = self.min_transfer_bytes
            && resource.transfer_size.unwrap_or(0) < min_bytes
        {
            return false;
        }
        !(self.status_error_only && resource.status_code.is_none_or(|code| code < 400))
    }
}

/// One bounded page of subresource network observations from [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkResourcesQueryPage<'a> {
    /// Availability and completeness status of browser resource observations.
    pub status: EvidenceQueryStatus,
    /// Whether the underlying collector truncated `BrowserEvidence::resources`.
    pub resources_truncated: bool,
    /// Total number of captured resources matching the filter.
    pub total_matching: usize,
    /// Bounded page of matching resources (at most [`PAGE_SIZE`]).
    pub resources: Vec<&'a ResourceTimingObs>,
    /// Offset of the next matching page, if additional resources remain.
    pub next_offset: Option<usize>,
}

/// Queries up to [`PAGE_SIZE`] captured subresource timing records without starting a browser.
#[must_use]
pub fn query_network_resources<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &NetworkResourceFilter<'_>,
    offset: usize,
) -> NetworkResourcesQueryPage<'a> {
    let (data, mut warnings) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, Vec::new()),
        CollectorOutcome::Partial { data, warnings } => (data, warnings.clone()),
        CollectorOutcome::Failed { error } => {
            return NetworkResourcesQueryPage {
                status: EvidenceQueryStatus::Failed {
                    error: error.clone(),
                },
                resources_truncated: false,
                total_matching: 0,
                resources: Vec::new(),
                next_offset: None,
            };
        }
        CollectorOutcome::Skipped { reason } => {
            return NetworkResourcesQueryPage {
                status: EvidenceQueryStatus::Skipped {
                    reason: reason.clone(),
                },
                resources_truncated: false,
                total_matching: 0,
                resources: Vec::new(),
                next_offset: None,
            };
        }
    };

    if data.resources_truncated {
        warnings.push("browser resources list was truncated at collector sampling cap".to_owned());
    }

    let matching: Vec<&'a ResourceTimingObs> = data
        .resources
        .iter()
        .filter(|res| filter.matches(res))
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let status = if warnings.is_empty() {
        EvidenceQueryStatus::Captured
    } else {
        EvidenceQueryStatus::Partial { warnings }
    };

    NetworkResourcesQueryPage {
        status,
        resources_truncated: data.resources_truncated,
        total_matching,
        resources: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
    }
}

/// Filter predicates for [`query_runtime_errors`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeErrorFilter<'a> {
    /// Case-insensitive error kind filter (e.g. `"csp_violation"`, `"uncaught_exception"`).
    pub error_kind: Option<&'a str>,
}

impl RuntimeErrorFilter<'_> {
    fn matches(&self, event: &ConsoleErrorEvent) -> bool {
        let Some(expected) = self.error_kind else {
            return true;
        };
        let actual = event.error_kind.as_deref().unwrap_or(&event.level);
        actual.eq_ignore_ascii_case(expected)
    }
}

/// One bounded page of browser console/runtime error observations from [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeErrorsQueryPage<'a> {
    /// Availability and completeness status of browser runtime error observations.
    pub status: EvidenceQueryStatus,
    /// Total number of console error events matching the filter.
    pub total_matching: usize,
    /// Bounded page of matching console error events (at most [`PAGE_SIZE`]).
    pub console_errors: Vec<&'a ConsoleErrorEvent>,
    /// Total failed subresource requests observed in `BrowserEvidence::failed_requests`.
    pub failed_requests_count: usize,
    /// Total hydration mismatch errors observed in `BrowserEvidence::hydration_errors`.
    pub hydration_errors_count: usize,
    /// Offset of the next matching page, if additional console errors remain.
    pub next_offset: Option<usize>,
}

/// Queries up to [`PAGE_SIZE`] captured browser console/runtime errors without starting a browser.
#[must_use]
pub fn query_runtime_errors<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &RuntimeErrorFilter<'_>,
    offset: usize,
) -> RuntimeErrorsQueryPage<'a> {
    let (data, warnings) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, Vec::new()),
        CollectorOutcome::Partial { data, warnings } => (data, warnings.clone()),
        CollectorOutcome::Failed { error } => {
            return RuntimeErrorsQueryPage {
                status: EvidenceQueryStatus::Failed {
                    error: error.clone(),
                },
                total_matching: 0,
                console_errors: Vec::new(),
                failed_requests_count: 0,
                hydration_errors_count: 0,
                next_offset: None,
            };
        }
        CollectorOutcome::Skipped { reason } => {
            return RuntimeErrorsQueryPage {
                status: EvidenceQueryStatus::Skipped {
                    reason: reason.clone(),
                },
                total_matching: 0,
                console_errors: Vec::new(),
                failed_requests_count: 0,
                hydration_errors_count: 0,
                next_offset: None,
            };
        }
    };

    let matching: Vec<&'a ConsoleErrorEvent> = data
        .console_errors
        .iter()
        .filter(|err| filter.matches(err))
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let status = if warnings.is_empty() {
        EvidenceQueryStatus::Captured
    } else {
        EvidenceQueryStatus::Partial { warnings }
    };

    RuntimeErrorsQueryPage {
        status,
        total_matching,
        console_errors: matching[start..end].to_vec(),
        failed_requests_count: data.failed_requests.len(),
        hydration_errors_count: data.hydration_errors.len(),
        next_offset: (end < total_matching).then_some(end),
    }
}

/// Summarises a [`CollectorOutcome<BrowserEvidence>`] into [`QueryBrowserEvidenceOutput`].
///
/// Shared between offline snapshot queries and live `QueryBrowserEvidenceTool`
/// executions so waterfall, third-party host, and runtime-error aggregations stay
/// identical.
#[must_use]
pub fn summarise_browser_outcome(
    outcome: &CollectorOutcome<BrowserEvidence>,
) -> QueryBrowserEvidenceOutput {
    let (status, detail) = outcome.status_summary();
    let warnings = detail.into_iter().collect();

    let Some(data) = (match outcome {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => Some(data),
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    }) else {
        return QueryBrowserEvidenceOutput {
            collection_status: status.to_owned(),
            warnings,
            resource_count: 0,
            resources_truncated: false,
            total_transfer_bytes: 0,
            third_party_hosts: Vec::new(),
            runtime_error_counts: BTreeMap::new(),
            slowest_resources: Vec::new(),
        };
    };

    let page_host = url::Url::parse(&data.final_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
    let mut third_party_hosts = BTreeSet::new();
    let mut total_transfer_bytes = 0_u64;
    for res in &data.resources {
        total_transfer_bytes = total_transfer_bytes.saturating_add(res.transfer_size.unwrap_or(0));
        if let Ok(u) = url::Url::parse(&res.url)
            && let Some(h) = u.host_str().map(str::to_ascii_lowercase)
            && page_host.as_deref() != Some(h.as_str())
        {
            third_party_hosts.insert(h);
        }
    }

    let mut runtime_error_counts = BTreeMap::new();
    for err in &data.console_errors {
        let kind = err.error_kind.clone().unwrap_or_else(|| err.level.clone());
        *runtime_error_counts.entry(kind).or_insert(0) += 1;
    }

    let mut slowest = data.resources.clone();
    slowest.sort_by_key(|a| Reverse(a.duration_ms.unwrap_or(0)));
    slowest.truncate(10);

    QueryBrowserEvidenceOutput {
        collection_status: status.to_owned(),
        warnings,
        resource_count: data.resources.len(),
        resources_truncated: data.resources_truncated,
        total_transfer_bytes,
        third_party_hosts: third_party_hosts.into_iter().collect(),
        runtime_error_counts,
        slowest_resources: slowest,
    }
}

/// Builds a [`QueryBrowserEvidenceOutput`] directly from `snapshot` when browser
/// collection has already been attempted or explicitly skipped by policy.
///
/// Returns `None` only when `snapshot.browser` is still in its initial default
/// `CollectorOutcome::Skipped { reason: "not collected" }` state.
#[must_use]
pub fn query_browser_evidence_from_snapshot(
    snapshot: &EvidenceSnapshot,
) -> Option<QueryBrowserEvidenceOutput> {
    if matches!(
        &snapshot.browser,
        CollectorOutcome::Skipped { reason } if reason == DEFAULT_NOT_COLLECTED_REASON
    ) {
        return None;
    }
    Some(summarise_browser_outcome(&snapshot.browser))
}

fn extract_browser_with_status(
    snapshot: &EvidenceSnapshot,
) -> Result<(&BrowserEvidence, EvidenceQueryStatus), EvidenceQueryStatus> {
    match &snapshot.browser {
        CollectorOutcome::Captured { data } => Ok((data, EvidenceQueryStatus::Captured)),
        CollectorOutcome::Partial { data, warnings } => Ok((
            data,
            EvidenceQueryStatus::Partial {
                warnings: warnings.clone(),
            },
        )),
        CollectorOutcome::Failed { error } => Err(EvidenceQueryStatus::Failed {
            error: error.clone(),
        }),
        CollectorOutcome::Skipped { reason } => Err(EvidenceQueryStatus::Skipped {
            reason: reason.clone(),
        }),
    }
}

fn serialize_prompt_context<T: Serialize>(value: &T, fallback: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| fallback.to_owned())
        .replace('<', "\\u003c")
}

// ============================================================================
// Wave IV-A2.3: Source HTML vs Rendered DOM Structural Comparison
// ============================================================================

/// High-level rendering architecture classification comparing raw HTTP HTML and rendered DOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceVsRenderedClassification {
    /// Source HTML and rendered DOM have closely aligned block and word counts.
    ServerRenderedParity,
    /// Source HTML is a minimal shell; primary content appears only after client execution.
    ClientRenderedShell,
    /// Server-rendered HTML is significantly augmented by client-side DOM hydration.
    HybridClientAugmented,
    /// Source HTML contains content that was removed, collapsed, or hidden in the rendered DOM.
    RenderedContentReducedOrHidden,
    /// Neither source nor rendered blocks contained primary textual content.
    EmptyOrNonTextual,
}

/// Filter predicates for [`compare_source_and_rendered`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceRenderedDiffFilter {
    /// Match only a specific content role.
    pub role: Option<ContentRole>,
    /// Match only roles where client-only or SSR-only drift occurred.
    pub only_mismatches: bool,
}

/// Role-level structural comparison between raw HTML source blocks and rendered DOM blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceVsRenderedRoleEntry {
    /// Content role category (`main_candidate`, `navigation`, `boilerplate`, `heading`, `general`).
    pub role: ContentRole,
    /// Number of blocks in raw HTML source assigned to this role.
    pub source_blocks: usize,
    /// Word count in raw HTML source assigned to this role.
    pub source_words: usize,
    /// Total rendered DOM blocks mapped to this role.
    pub rendered_blocks: usize,
    /// Visible rendered DOM blocks mapped to this role.
    pub rendered_visible_blocks: usize,
    /// Hidden (`display:none` / `visibility:hidden`) rendered DOM blocks mapped to this role.
    pub rendered_hidden_blocks: usize,
    /// Word count across visible rendered DOM blocks mapped to this role.
    pub rendered_visible_words: usize,
    /// Signed word count delta (`rendered_visible_words as i64 - source_words as i64`).
    pub word_delta: i64,
    /// Whether this role is present in rendered DOM but absent in source HTML.
    pub client_only: bool,
    /// Whether this role is present in source HTML but absent in visible rendered DOM.
    pub ssr_only: bool,
}

/// Offline structural comparison between Level 1 HTTP HTML and Level 2 rendered DOM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceVsRenderedQueryPage {
    /// Combined availability status of HTTP source and browser rendered content.
    pub status: EvidenceQueryStatus,
    /// Overall rendering parity classification.
    pub classification: Option<SourceVsRenderedClassification>,
    /// Number of role entries matching the filter.
    pub total_matching: usize,
    /// Total source blocks across all roles.
    pub source_total_blocks: usize,
    /// Total source words across all roles.
    pub source_total_words: usize,
    /// Total rendered blocks across all roles.
    pub rendered_total_blocks: usize,
    /// Total visible rendered blocks across all roles.
    pub rendered_visible_blocks: usize,
    /// Total visible rendered words across all roles.
    pub rendered_total_words: usize,
    /// Alias for `rendered_total_words`.
    pub rendered_visible_words: usize,
    /// Signed word delta in thousandths relative to `max(source_total_words, 1)`.
    pub word_delta_milli: i64,
    /// Roles present only in the client-rendered DOM.
    pub client_only_roles: Vec<ContentRole>,
    /// Roles present in raw HTML source but absent from visible rendered DOM.
    pub ssr_only_roles: Vec<ContentRole>,
    /// Per-role structural comparison entries.
    pub roles: Vec<SourceVsRenderedRoleEntry>,
}

/// Semantic content role category used when comparing source HTML against rendered DOM.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ContentRole {
    /// Primary main content landmark (`<main>` or `[role="main"]`).
    MainCandidate,
    /// Heading content (`<h1>`..`<h6>`).
    Heading,
    /// General paragraph, article, or section content.
    General,
    /// Navigation landmark (`<nav>` or `[role="navigation"]`).
    Navigation,
    /// Boilerplate landmark (`<header>`, `<footer>`, `<aside>`).
    Boilerplate,
}

fn map_rendered_kind_to_role(kind: RenderedBlockKind) -> ContentRole {
    match kind {
        RenderedBlockKind::Main => ContentRole::MainCandidate,
        RenderedBlockKind::Navigation => ContentRole::Navigation,
        RenderedBlockKind::Header | RenderedBlockKind::Footer | RenderedBlockKind::Aside => {
            ContentRole::Boilerplate
        }
        RenderedBlockKind::Paragraph | RenderedBlockKind::Section | RenderedBlockKind::Article => {
            ContentRole::General
        }
    }
}

struct SourceRoleBlockSummary {
    role: ContentRole,
    word_count: usize,
}

fn extract_source_role_blocks(snapshot: &EvidenceSnapshot) -> Option<Vec<SourceRoleBlockSummary>> {
    let http = crate::analysis::require_complete_html(snapshot).ok()?;
    let document = scraper::Html::parse_document(&http.body_text);
    let mut blocks = Vec::new();
    let role_selectors: &[(&str, ContentRole)] = &[
        ("main, [role='main']", ContentRole::MainCandidate),
        ("h1, h2, h3, h4, h5, h6", ContentRole::Heading),
        ("p, article, section", ContentRole::General),
        ("nav, [role='navigation']", ContentRole::Navigation),
        ("header, footer, aside", ContentRole::Boilerplate),
    ];
    for &(sel_str, role) in role_selectors {
        if let Ok(selector) = scraper::Selector::parse(sel_str) {
            for elem in document.select(&selector).take(128) {
                let word_count = elem.text().flat_map(str::split_whitespace).count();
                if word_count > 0 {
                    blocks.push(SourceRoleBlockSummary { role, word_count });
                }
            }
        }
    }
    Some(blocks)
}

/// Compares raw HTML source segmentation against rendered DOM segmentation offline.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn compare_source_and_rendered(
    snapshot: &EvidenceSnapshot,
    filter: &SourceRenderedDiffFilter,
    _offset: usize,
) -> SourceVsRenderedQueryPage {
    let Some(source_blocks_vec) = extract_source_role_blocks(snapshot) else {
        let status = match &snapshot.http {
            CollectorOutcome::Failed { error } => EvidenceQueryStatus::Failed {
                error: error.clone(),
            },
            CollectorOutcome::Skipped { reason } => EvidenceQueryStatus::Skipped {
                reason: reason.clone(),
            },
            _ => EvidenceQueryStatus::Unavailable {
                reason: "source HTML segmentation unavailable".to_owned(),
            },
        };
        return SourceVsRenderedQueryPage {
            status,
            classification: None,
            total_matching: 0,
            source_total_blocks: 0,
            source_total_words: 0,
            rendered_total_blocks: 0,
            rendered_visible_blocks: 0,
            rendered_total_words: 0,
            rendered_visible_words: 0,
            word_delta_milli: 0,
            client_only_roles: Vec::new(),
            ssr_only_roles: Vec::new(),
            roles: Vec::new(),
        };
    };

    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return SourceVsRenderedQueryPage {
                status,
                classification: None,
                total_matching: 0,
                source_total_blocks: source_blocks_vec.len(),
                source_total_words: source_blocks_vec.iter().map(|b| b.word_count).sum(),
                rendered_total_blocks: 0,
                rendered_visible_blocks: 0,
                rendered_total_words: 0,
                rendered_visible_words: 0,
                word_delta_milli: 0,
                client_only_roles: Vec::new(),
                ssr_only_roles: Vec::new(),
                roles: Vec::new(),
            };
        }
    };

    let Some(rendered_seg) = browser.rendered_content.as_ref() else {
        return SourceVsRenderedQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "rendered DOM content segmentation was not captured".to_owned(),
            },
            classification: None,
            total_matching: 0,
            source_total_blocks: source_blocks_vec.len(),
            source_total_words: source_blocks_vec.iter().map(|b| b.word_count).sum(),
            rendered_total_blocks: 0,
            rendered_visible_blocks: 0,
            rendered_total_words: 0,
            rendered_visible_words: 0,
            word_delta_milli: 0,
            client_only_roles: Vec::new(),
            ssr_only_roles: Vec::new(),
            roles: Vec::new(),
        };
    };

    let all_roles = [
        ContentRole::MainCandidate,
        ContentRole::Heading,
        ContentRole::General,
        ContentRole::Navigation,
        ContentRole::Boilerplate,
    ];

    let mut roles = Vec::with_capacity(all_roles.len());
    let mut client_only_roles = Vec::new();
    let mut ssr_only_roles = Vec::new();
    let mut source_total_words = 0_usize;
    let mut rendered_visible_blocks_total = 0_usize;
    let mut rendered_visible_words_total = 0_usize;

    for role in all_roles {
        let src_iter = source_blocks_vec.iter().filter(|b| b.role == role);
        let source_blocks = src_iter.clone().count();
        let source_words: usize = src_iter.map(|b| b.word_count).sum();
        source_total_words = source_total_words.saturating_add(source_words);

        let dom_iter = rendered_seg
            .blocks
            .iter()
            .filter(|b| map_rendered_kind_to_role(b.kind) == role);
        let rendered_blocks = dom_iter.clone().count();
        let rendered_visible_blocks = dom_iter
            .clone()
            .filter(|b| b.visibility == RenderedCssVisibility::Visible)
            .count();
        let rendered_hidden_blocks = rendered_blocks.saturating_sub(rendered_visible_blocks);
        let rendered_visible_words: usize = dom_iter
            .filter(|b| b.visibility == RenderedCssVisibility::Visible)
            .map(|b| b.visible_text.split_whitespace().count())
            .sum();

        rendered_visible_blocks_total =
            rendered_visible_blocks_total.saturating_add(rendered_visible_blocks);
        rendered_visible_words_total =
            rendered_visible_words_total.saturating_add(rendered_visible_words);

        let word_delta = i64::try_from(rendered_visible_words).unwrap_or(i64::MAX)
            - i64::try_from(source_words).unwrap_or(i64::MAX);
        let client_only = source_blocks == 0 && rendered_visible_blocks > 0;
        let ssr_only = source_blocks > 0 && rendered_visible_blocks == 0;
        if client_only {
            client_only_roles.push(role);
        }
        if ssr_only {
            ssr_only_roles.push(role);
        }

        if let Some(expected_role) = filter.role
            && role != expected_role
        {
            continue;
        }
        if filter.only_mismatches && !client_only && !ssr_only && word_delta == 0 {
            continue;
        }

        roles.push(SourceVsRenderedRoleEntry {
            role,
            source_blocks,
            source_words,
            rendered_blocks,
            rendered_visible_blocks,
            rendered_hidden_blocks,
            rendered_visible_words,
            word_delta,
            client_only,
            ssr_only,
        });
    }

    let classification = if source_total_words == 0 && rendered_visible_words_total == 0 {
        SourceVsRenderedClassification::EmptyOrNonTextual
    } else if source_total_words < 20 && rendered_visible_words_total >= 50 {
        SourceVsRenderedClassification::ClientRenderedShell
    } else if rendered_visible_words_total > source_total_words.saturating_mul(3) / 2 {
        SourceVsRenderedClassification::HybridClientAugmented
    } else if rendered_visible_words_total.saturating_mul(2) < source_total_words {
        SourceVsRenderedClassification::RenderedContentReducedOrHidden
    } else {
        SourceVsRenderedClassification::ServerRenderedParity
    };

    let denom = i64::try_from(source_total_words.max(1)).unwrap_or(1);
    let diff = i64::try_from(rendered_visible_words_total).unwrap_or(0)
        - i64::try_from(source_total_words).unwrap_or(0);
    let word_delta_milli = diff.saturating_mul(1000) / denom;
    let total_matching = roles.len();

    SourceVsRenderedQueryPage {
        status,
        classification: Some(classification),
        total_matching,
        source_total_blocks: source_blocks_vec.len(),
        source_total_words,
        rendered_total_blocks: rendered_seg.blocks.len(),
        rendered_visible_blocks: rendered_visible_blocks_total,
        rendered_total_words: rendered_visible_words_total,
        rendered_visible_words: rendered_visible_words_total,
        word_delta_milli,
        client_only_roles,
        ssr_only_roles,
        roles,
    }
}

/// Offline structural comparison alias without filter arguments.
#[must_use]
pub fn query_source_vs_rendered(snapshot: &EvidenceSnapshot) -> SourceVsRenderedQueryPage {
    compare_source_and_rendered(snapshot, &SourceRenderedDiffFilter::default(), 0)
}

pub(super) fn source_vs_rendered_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "source vs rendered comparison unavailable".to_owned();
    };
    let page = query_source_vs_rendered(snapshot);
    serialize_prompt_context(&page, "source vs rendered comparison unavailable")
}

pub(super) fn cited_source_vs_rendered_refs(
    snapshot: &EvidenceSnapshot,
    roles: &[String],
) -> Vec<EvidenceRef> {
    let page = query_source_vs_rendered(snapshot);
    page.roles
        .iter()
        .filter(|entry| {
            let role_str = format!("{:?}", entry.role).to_ascii_lowercase();
            let snake = match entry.role {
                ContentRole::MainCandidate => "main_candidate",
                ContentRole::Navigation => "navigation",
                ContentRole::Boilerplate => "boilerplate",
                ContentRole::Heading => "heading",
                ContentRole::General => "general",
            };
            roles
                .iter()
                .any(|r| r.eq_ignore_ascii_case(snake) || r.eq_ignore_ascii_case(&role_str))
        })
        .map(|entry| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "source-vs-rendered:role={:?}:src_words={}:dom_words={}",
                    entry.role, entry.source_words, entry.rendered_visible_words
                ),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-B: Functional Intelligence (Interactive Inventory, App State, Trace)
// ============================================================================

/// Filter predicates for [`query_interactive_elements`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InteractiveElementFilter {
    /// Match only elements of a specific functional UI kind.
    pub functional_kind: Option<FunctionalComponentKind>,
    /// Match only elements of a specific safety classification.
    pub safety_class: Option<InteractionSafetyClass>,
    /// Match only visible elements when `Some(true)`.
    pub visible: Option<bool>,
    /// Match only elements lacking an accessible name (`!name_present`).
    pub only_unnamed: bool,
}

/// Paginated offline view over [`BrowserEvidence::interactive_inventory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InteractiveElementsQueryPage<'a> {
    /// Availability status of the interactive element inventory collector.
    pub status: EvidenceQueryStatus,
    /// Total elements matching the filter.
    pub total_matching: usize,
    /// Current page of matching interactive elements (capped at [`PAGE_SIZE`]).
    pub elements: Vec<&'a InteractiveElementObs>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
    /// Whether the collector cap (`256`) truncated additional elements.
    pub truncated: bool,
}

/// Queries up to [`PAGE_SIZE`] interactive elements from [`EvidenceSnapshot`].
#[must_use]
pub fn query_interactive_elements<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &InteractiveElementFilter,
    offset: usize,
) -> InteractiveElementsQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return InteractiveElementsQueryPage {
                status,
                total_matching: 0,
                elements: Vec::new(),
                next_offset: None,
                truncated: false,
            };
        }
    };

    let Some(inv) = browser.interactive_inventory.as_ref() else {
        return InteractiveElementsQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "interactive element inventory was not captured".to_owned(),
            },
            total_matching: 0,
            elements: Vec::new(),
            next_offset: None,
            truncated: false,
        };
    };

    let matching: Vec<&'a InteractiveElementObs> = inv
        .elements
        .iter()
        .filter(|el| {
            filter
                .functional_kind
                .is_none_or(|k| el.functional_kind == k)
                && filter.safety_class.is_none_or(|s| el.safety_class == s)
                && filter.visible.is_none_or(|v| el.visible == v)
                && (!filter.only_unnamed || !el.name_present)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    InteractiveElementsQueryPage {
        status,
        total_matching,
        elements: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
        truncated: inv.limits.elements_truncated,
    }
}

pub(super) fn interactive_elements_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "interactive elements unavailable".to_owned();
    };
    let page = query_interactive_elements(snapshot, &InteractiveElementFilter::default(), 0);
    serialize_prompt_context(&page, "interactive elements unavailable")
}

pub(super) fn cited_interactive_element_refs(
    snapshot: &EvidenceSnapshot,
    nodes: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_interactive_elements(snapshot, &InteractiveElementFilter::default(), 0);
    let mut allowed: Vec<u32> = page
        .elements
        .iter()
        .filter(|el| nodes.contains(&el.node))
        .map(|el| el.node)
        .collect();
    allowed.sort_unstable();
    allowed.dedup();
    allowed
        .into_iter()
        .filter_map(|node| {
            page.elements.iter().find(|el| el.node == node).map(|el| {
                EvidenceRef::new(
                    EvidenceSource::BrowserRuntime,
                    format!(
                        "interactive-element={}:tag={}:kind={:?}",
                        el.node, el.tag, el.functional_kind
                    ),
                )
            })
        })
        .collect()
}

/// Offline view over [`BrowserEvidence::application_state`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApplicationStateQueryPage<'a> {
    /// Availability status of the application state collector.
    pub status: EvidenceQueryStatus,
    /// Captured application state snapshot, if available.
    pub state: Option<&'a ApplicationStateSnapshot>,
}

/// Queries the captured application state snapshot without starting a browser.
#[must_use]
pub fn query_application_state(snapshot: &EvidenceSnapshot) -> ApplicationStateQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return ApplicationStateQueryPage {
                status,
                state: None,
            };
        }
    };
    let Some(state) = browser.application_state.as_ref() else {
        return ApplicationStateQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "application state snapshot was not captured".to_owned(),
            },
            state: None,
        };
    };
    ApplicationStateQueryPage {
        status,
        state: Some(state),
    }
}

pub(super) fn application_state_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "application state unavailable".to_owned();
    };
    let page = query_application_state(snapshot);
    serialize_prompt_context(&page, "application state unavailable")
}

pub(super) fn cited_application_state_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_application_state(snapshot);
    let Some(state) = page.state else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "application-state:ready={}:dialogs={}:invalid={}",
            state.document_ready_state, state.active_dialog_count, state.invalid_input_count
        ),
    )]
}

/// Filter predicates for [`query_interaction_trace`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InteractionStepFilter {
    /// Match only steps of a specific action kind.
    pub action: Option<InteractionActionKind>,
    /// Match only steps that produced a focus, expansion, dialog, or runtime error change.
    pub only_state_changing: bool,
}

/// Type alias for interaction trace filter.
pub type InteractionTraceFilter = InteractionStepFilter;

/// Paginated offline view over [`BrowserEvidence::user_journey_trace`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InteractionTraceQueryPage<'a> {
    /// Availability status of the user journey interaction trace collector.
    pub status: EvidenceQueryStatus,
    /// Candidate scenarios discovered from the interactive inventory.
    pub candidate_scenarios: &'a [CandidateJourneyScenario],
    /// Total trace steps matching the filter.
    pub total_matching: usize,
    /// Current page of interaction trace steps (capped at [`PAGE_SIZE`]).
    pub steps: Vec<&'a InteractionTraceStep>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
    /// Whether the 16-step cap truncated additional steps.
    pub truncated: bool,
}

/// Queries the bounded read-only interaction trace from [`EvidenceSnapshot`].
#[must_use]
pub fn query_interaction_trace<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &InteractionStepFilter,
    offset: usize,
) -> InteractionTraceQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return InteractionTraceQueryPage {
                status,
                candidate_scenarios: &[],
                total_matching: 0,
                steps: Vec::new(),
                next_offset: None,
                truncated: false,
            };
        }
    };
    let Some(trace) = browser.user_journey_trace.as_ref() else {
        return InteractionTraceQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "user journey interaction trace was not captured".to_owned(),
            },
            candidate_scenarios: &[],
            total_matching: 0,
            steps: Vec::new(),
            next_offset: None,
            truncated: false,
        };
    };

    let matching: Vec<&'a InteractionTraceStep> = trace
        .steps
        .iter()
        .filter(|s| {
            filter.action.is_none_or(|a| s.action == a)
                && (!filter.only_state_changing
                    || s.state_changed
                    || s.focus_changed
                    || s.expanded_changed
                    || s.dialog_changed
                    || s.dom_fingerprint_changed
                    || s.new_runtime_errors > 0)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    InteractionTraceQueryPage {
        status,
        candidate_scenarios: &trace.candidate_scenarios,
        total_matching,
        steps: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
        truncated: trace.truncated,
    }
}

pub(super) fn interaction_trace_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "interaction trace unavailable".to_owned();
    };
    let page = query_interaction_trace(snapshot, &InteractionStepFilter::default(), 0);
    serialize_prompt_context(&page, "interaction trace unavailable")
}

pub(super) fn cited_interaction_step_refs(
    snapshot: &EvidenceSnapshot,
    steps: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_interaction_trace(snapshot, &InteractionStepFilter::default(), 0);
    page.steps
        .iter()
        .filter(|s| steps.contains(&s.step_index))
        .map(|s| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("interaction-step={}:action={:?}", s.step_index, s.action),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-C: Presentation & Accessibility (Element Geometry & AX Nodes)
// ============================================================================

/// Filter predicates for [`query_element_geometry`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElementGeometryFilter {
    /// Match only elements whose content is clipped by overflow.
    pub only_clipped: bool,
    /// Match only elements occluded at their centre point by another element.
    pub only_occluded: bool,
    /// Match only elements with horizontal overflow (`horizontal_overflow_px > 0`).
    pub only_horizontal_overflow: bool,
}

/// Paginated offline view over [`BrowserEvidence::visual_geometry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElementGeometryQueryPage<'a> {
    /// Availability status of the visual geometry collector.
    pub status: EvidenceQueryStatus,
    /// Viewport width in CSS pixels.
    pub viewport_width: u32,
    /// Viewport height in CSS pixels.
    pub viewport_height: u32,
    /// Total elements matching the filter.
    pub total_matching: usize,
    /// Current page of matching element geometry records (capped at [`PAGE_SIZE`]).
    pub elements: Vec<&'a ElementGeometryObs>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
    /// Whether the 256-element cap truncated additional elements.
    pub truncated: bool,
}

/// Queries up to [`PAGE_SIZE`] element geometry records from [`EvidenceSnapshot`].
#[must_use]
pub fn query_element_geometry<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &ElementGeometryFilter,
    offset: usize,
) -> ElementGeometryQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return ElementGeometryQueryPage {
                status,
                viewport_width: 0,
                viewport_height: 0,
                total_matching: 0,
                elements: Vec::new(),
                next_offset: None,
                truncated: false,
            };
        }
    };
    let Some(geom) = browser.visual_geometry.as_ref() else {
        return ElementGeometryQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "visual geometry inventory was not captured".to_owned(),
            },
            viewport_width: 0,
            viewport_height: 0,
            total_matching: 0,
            elements: Vec::new(),
            next_offset: None,
            truncated: false,
        };
    };

    let matching: Vec<&'a ElementGeometryObs> = geom
        .elements
        .iter()
        .filter(|el| {
            (!filter.only_clipped || el.clipped_by_overflow)
                && (!filter.only_occluded || el.occluded_at_center)
                && (!filter.only_horizontal_overflow || el.horizontal_overflow_px > 0)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    ElementGeometryQueryPage {
        status,
        viewport_width: geom.viewport_width,
        viewport_height: geom.viewport_height,
        total_matching,
        elements: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
        truncated: geom.limits.elements_truncated,
    }
}

pub(super) fn element_geometry_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "element geometry unavailable".to_owned();
    };
    let page = query_element_geometry(snapshot, &ElementGeometryFilter::default(), 0);
    serialize_prompt_context(&page, "element geometry unavailable")
}

pub(super) fn cited_element_geometry_refs(
    snapshot: &EvidenceSnapshot,
    nodes: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_element_geometry(snapshot, &ElementGeometryFilter::default(), 0);
    page.elements
        .iter()
        .filter(|el| nodes.contains(&el.node))
        .map(|el| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("geometry-element={}:tag={}", el.node, el.tag),
            )
        })
        .collect()
}

/// Filter predicates for [`query_accessibility_nodes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessibilityNodeFilter<'a> {
    /// Case-insensitive exact match on AX role (`button`, `link`, `dialog`, etc.).
    pub role: Option<&'a str>,
    /// Match only interactive AX nodes.
    pub only_interactive: bool,
    /// Match only interactive AX nodes lacking an accessible name (`interactive && !name_present`).
    pub only_unnamed_interactive: bool,
    /// Match only focusable AX nodes inside an ignored subtree (`ignored && focusable`).
    pub only_ignored_focusable: bool,
}

/// Paginated offline view over [`BrowserEvidence::ax_node_inventory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessibilityNodesQueryPage<'a> {
    /// Availability status of the accessibility node inventory collector.
    pub status: EvidenceQueryStatus,
    /// Total AX nodes matching the filter.
    pub total_matching: usize,
    /// Current page of matching AX nodes (capped at [`PAGE_SIZE`]).
    pub nodes: Vec<&'a AccessibilityNodeObs>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
    /// Whether the 256-node cap truncated additional AX nodes.
    pub truncated: bool,
}

/// Queries up to [`PAGE_SIZE`] Accessibility (`AX`) tree nodes from [`EvidenceSnapshot`].
#[must_use]
pub fn query_accessibility_nodes<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &AccessibilityNodeFilter<'_>,
    offset: usize,
) -> AccessibilityNodesQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return AccessibilityNodesQueryPage {
                status,
                total_matching: 0,
                nodes: Vec::new(),
                next_offset: None,
                truncated: false,
            };
        }
    };
    let Some(ax) = browser.ax_node_inventory.as_ref() else {
        return AccessibilityNodesQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "accessibility node inventory was not captured".to_owned(),
            },
            total_matching: 0,
            nodes: Vec::new(),
            next_offset: None,
            truncated: false,
        };
    };

    let matching: Vec<&'a AccessibilityNodeObs> = ax
        .nodes
        .iter()
        .filter(|n| {
            filter.role.is_none_or(|r| n.role.eq_ignore_ascii_case(r))
                && (!filter.only_interactive || n.interactive)
                && (!filter.only_unnamed_interactive || (n.interactive && !n.name_present))
                && (!filter.only_ignored_focusable || (n.ignored && n.focusable))
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    AccessibilityNodesQueryPage {
        status,
        total_matching,
        nodes: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
        truncated: ax.limits.nodes_truncated,
    }
}

pub(super) fn accessibility_nodes_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "accessibility nodes unavailable".to_owned();
    };
    let page = query_accessibility_nodes(snapshot, &AccessibilityNodeFilter::default(), 0);
    serialize_prompt_context(&page, "accessibility nodes unavailable")
}

pub(super) fn cited_accessibility_node_refs(
    snapshot: &EvidenceSnapshot,
    indices: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_accessibility_nodes(snapshot, &AccessibilityNodeFilter::default(), 0);
    page.nodes
        .iter()
        .filter(|n| indices.contains(&n.node_index))
        .map(|n| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("ax-node={}:role={}", n.node_index, n.role),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-D: Security, Privacy, Third-Party Capability & Anti-Bot Challenge
// ============================================================================

/// Filter predicates for [`query_storage_and_cookies`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageCookieFilter {
    /// Match only third-party cookies.
    pub only_third_party_cookies: bool,
    /// Match only cookies missing `Secure` or `HttpOnly`.
    pub only_insecure_cookies: bool,
    /// Match only cookies with a specific `SameSite` policy.
    pub same_site: Option<CookieSameSiteMode>,
    /// Match only storage keys from a specific Web Storage area.
    pub storage_area: Option<WebStorageArea>,
}

/// Type alias for cookie and storage filter.
pub type CookieStorageFilter = StorageCookieFilter;

/// Paginated offline view over [`BrowserEvidence::cookie_and_storage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CookiesAndStorageQueryPage<'a> {
    /// Availability status of the cookie and storage collector.
    pub status: EvidenceQueryStatus,
    /// Total cookies matching the filter.
    pub total_matching_cookies: usize,
    /// Current page of matching cookies (capped at [`PAGE_SIZE`]).
    pub cookies: Vec<&'a RuntimeCookieObs>,
    /// Total Web Storage keys matching the filter.
    pub total_matching_storage_keys: usize,
    /// Current page of matching storage keys (capped at [`PAGE_SIZE`]).
    pub storage_keys: Vec<&'a StorageKeyObs>,
    /// Number of `IndexedDB` databases detected.
    pub indexed_db_count: u32,
    /// Offset of the next page when more cookies or storage keys exist.
    pub next_offset: Option<usize>,
}

/// Queries sanitized cookie metadata and Web Storage keys from [`EvidenceSnapshot`].
#[must_use]
pub fn query_storage_and_cookies<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &StorageCookieFilter,
    offset: usize,
) -> CookiesAndStorageQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return CookiesAndStorageQueryPage {
                status,
                total_matching_cookies: 0,
                cookies: Vec::new(),
                total_matching_storage_keys: 0,
                storage_keys: Vec::new(),
                indexed_db_count: 0,
                next_offset: None,
            };
        }
    };
    let Some(inv) = browser.cookie_and_storage.as_ref() else {
        return CookiesAndStorageQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "cookie and storage inventory was not captured".to_owned(),
            },
            total_matching_cookies: 0,
            cookies: Vec::new(),
            total_matching_storage_keys: 0,
            storage_keys: Vec::new(),
            indexed_db_count: 0,
            next_offset: None,
        };
    };

    let matching_cookies: Vec<&'a RuntimeCookieObs> = inv
        .cookies
        .iter()
        .filter(|c| {
            (!filter.only_third_party_cookies || c.third_party == Some(true))
                && (!filter.only_insecure_cookies || !c.secure || !c.http_only)
                && filter.same_site.is_none_or(|ss| c.same_site == ss)
        })
        .collect();
    let matching_keys: Vec<&'a StorageKeyObs> = inv
        .storage_keys
        .iter()
        .filter(|k| filter.storage_area.is_none_or(|area| k.area == area))
        .collect();

    let total_matching_cookies = matching_cookies.len();
    let total_matching_storage_keys = matching_keys.len();
    let c_start = offset.min(total_matching_cookies);
    let c_end = c_start
        .saturating_add(PAGE_SIZE)
        .min(total_matching_cookies);
    let k_start = offset.min(total_matching_storage_keys);
    let k_end = k_start
        .saturating_add(PAGE_SIZE)
        .min(total_matching_storage_keys);
    let next_offset = (c_end < total_matching_cookies || k_end < total_matching_storage_keys)
        .then_some(offset.saturating_add(PAGE_SIZE));

    CookiesAndStorageQueryPage {
        status,
        total_matching_cookies,
        cookies: matching_cookies[c_start..c_end].to_vec(),
        total_matching_storage_keys,
        storage_keys: matching_keys[k_start..k_end].to_vec(),
        indexed_db_count: inv.indexed_db_count,
        next_offset,
    }
}

/// Alias for [`query_storage_and_cookies`].
#[must_use]
pub fn query_cookies_and_storage<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &StorageCookieFilter,
    offset: usize,
) -> CookiesAndStorageQueryPage<'a> {
    query_storage_and_cookies(snapshot, filter, offset)
}

pub(super) fn cookies_and_storage_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "cookies and storage unavailable".to_owned();
    };
    let page = query_storage_and_cookies(snapshot, &StorageCookieFilter::default(), 0);
    serialize_prompt_context(&page, "cookies and storage unavailable")
}

pub(super) fn cited_cookie_or_storage_refs(
    snapshot: &EvidenceSnapshot,
    names: &[String],
) -> Vec<EvidenceRef> {
    let page = query_storage_and_cookies(snapshot, &StorageCookieFilter::default(), 0);
    let mut refs = Vec::new();
    for cookie in &page.cookies {
        if names.iter().any(|n| n == &cookie.name) {
            refs.push(EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("cookie={}:domain={}", cookie.name, cookie.domain),
            ));
        }
    }
    for key in &page.storage_keys {
        if names.iter().any(|n| n == &key.key) {
            refs.push(EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("storage-key={}:area={:?}", key.key, key.area),
            ));
        }
    }
    refs
}

/// Filter predicates for [`query_third_party_origins`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ThirdPartyOriginFilter<'a> {
    /// Case-insensitive substring match against the third-party origin.
    pub origin_contains: Option<&'a str>,
    /// Match only origins executing JavaScript in the main frame.
    pub only_main_frame_scripts: bool,
    /// Match only origins with external scripts lacking Subresource Integrity (`script_without_sri_count > 0`).
    pub only_missing_sri: bool,
}

/// Paginated offline view over [`BrowserEvidence::third_party_inventory`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThirdPartyOriginsQueryPage<'a> {
    /// Availability status of the third-party inventory collector.
    pub status: EvidenceQueryStatus,
    /// Total third-party origins matching the filter.
    pub total_matching: usize,
    /// Current page of matching third-party origins (capped at [`PAGE_SIZE`]).
    pub origins: Vec<&'a ThirdPartyOriginObs>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
    /// Whether the 128-origin cap truncated additional origins.
    pub truncated: bool,
}

/// Queries up to [`PAGE_SIZE`] third-party origins and capabilities from [`EvidenceSnapshot`].
#[must_use]
pub fn query_third_party_origins<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &ThirdPartyOriginFilter<'_>,
    offset: usize,
) -> ThirdPartyOriginsQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return ThirdPartyOriginsQueryPage {
                status,
                total_matching: 0,
                origins: Vec::new(),
                next_offset: None,
                truncated: false,
            };
        }
    };
    let Some(inv) = browser.third_party_inventory.as_ref() else {
        return ThirdPartyOriginsQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "third-party origin inventory was not captured".to_owned(),
            },
            total_matching: 0,
            origins: Vec::new(),
            next_offset: None,
            truncated: false,
        };
    };

    let matching: Vec<&'a ThirdPartyOriginObs> = inv
        .origins
        .iter()
        .filter(|o| {
            filter.origin_contains.is_none_or(|needle| {
                o.origin
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            }) && (!filter.only_main_frame_scripts
                || o.capability.script_element_present_in_main_frame)
                && (!filter.only_missing_sri || o.capability.script_without_sri_count > 0)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    ThirdPartyOriginsQueryPage {
        status,
        total_matching,
        origins: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
        truncated: inv.truncated,
    }
}

pub(super) fn third_party_origins_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "third-party origins unavailable".to_owned();
    };
    let page = query_third_party_origins(snapshot, &ThirdPartyOriginFilter::default(), 0);
    serialize_prompt_context(&page, "third-party origins unavailable")
}

pub(super) fn cited_third_party_origin_refs(
    snapshot: &EvidenceSnapshot,
    origins: &[String],
) -> Vec<EvidenceRef> {
    let page = query_third_party_origins(snapshot, &ThirdPartyOriginFilter::default(), 0);
    page.origins
        .iter()
        .filter(|o| origins.iter().any(|c| c.eq_ignore_ascii_case(&o.origin)))
        .map(|o| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("third-party-origin={}", o.origin),
            )
        })
        .collect()
}

/// Offline view over [`BrowserEvidence::security_posture`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityPostureQueryPage<'a> {
    /// Availability status of the security posture summary.
    pub status: EvidenceQueryStatus,
    /// Captured security posture summary, if available.
    pub posture: Option<&'a SecurityPostureSummary>,
}

/// Queries the consolidated HTTP/DOM security posture from [`EvidenceSnapshot`].
#[must_use]
pub fn query_security_posture(snapshot: &EvidenceSnapshot) -> SecurityPostureQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return SecurityPostureQueryPage {
                status,
                posture: None,
            };
        }
    };
    let Some(posture) = browser.security_posture.as_ref() else {
        return SecurityPostureQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "security posture summary was not captured".to_owned(),
            },
            posture: None,
        };
    };
    SecurityPostureQueryPage {
        status,
        posture: Some(posture),
    }
}

pub(super) fn security_posture_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "security posture unavailable".to_owned();
    };
    let page = query_security_posture(snapshot);
    serialize_prompt_context(&page, "security posture unavailable")
}

pub(super) fn cited_security_posture_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_security_posture(snapshot);
    let Some(p) = page.posture else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "security-posture:csp={}:hsts={}:mixed_content={}",
            p.csp_present, p.hsts_present, p.mixed_content_request_count
        ),
    )]
}

/// Offline view over [`BrowserEvidence::security_challenge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecurityChallengeQueryPage<'a> {
    /// Availability status of the security challenge collector.
    pub status: EvidenceQueryStatus,
    /// Captured challenge and anti-bot evidence, if available.
    pub challenge: Option<&'a SecurityChallengeEvidence>,
}

/// Queries anti-bot challenge, WAF interstitial, and CAPTCHA wall evidence from [`EvidenceSnapshot`].
#[must_use]
pub fn query_security_challenge(snapshot: &EvidenceSnapshot) -> SecurityChallengeQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return SecurityChallengeQueryPage {
                status,
                challenge: None,
            };
        }
    };
    let Some(challenge) = browser.security_challenge.as_ref() else {
        return SecurityChallengeQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "security challenge evidence was not captured".to_owned(),
            },
            challenge: None,
        };
    };
    SecurityChallengeQueryPage {
        status,
        challenge: Some(challenge),
    }
}

/// Alias for [`query_security_challenge`].
#[must_use]
pub fn query_security_challenges(snapshot: &EvidenceSnapshot) -> SecurityChallengeQueryPage<'_> {
    query_security_challenge(snapshot)
}

pub(super) fn security_challenges_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "security challenges unavailable".to_owned();
    };
    let page = query_security_challenge(snapshot);
    serialize_prompt_context(&page, "security challenges unavailable")
}

pub(super) fn cited_security_challenge_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_security_challenge(snapshot);
    let Some(c) = page.challenge else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "security-challenge:detected={}:provider={:?}",
            c.challenge_detected, c.provider
        ),
    )]
}

// ============================================================================
// Wave IV-E: Performance Attribution, Media & Fonts
// ============================================================================

/// Offline view over [`BrowserEvidence::performance_attribution`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PerformanceAttributionQueryPage<'a> {
    /// Availability status of the performance attribution collector.
    pub status: EvidenceQueryStatus,
    /// Captured LCP candidate, CLS shift regions, and render-blocking chain, if available.
    pub attribution: Option<&'a PerformanceAttributionEvidence>,
}

/// Queries LCP candidate element, CLS shift regions, and render-blocking chain from [`EvidenceSnapshot`].
#[must_use]
pub fn query_performance_attribution(
    snapshot: &EvidenceSnapshot,
) -> PerformanceAttributionQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return PerformanceAttributionQueryPage {
                status,
                attribution: None,
            };
        }
    };
    let Some(attribution) = browser.performance_attribution.as_ref() else {
        return PerformanceAttributionQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "performance attribution evidence was not captured".to_owned(),
            },
            attribution: None,
        };
    };
    PerformanceAttributionQueryPage {
        status,
        attribution: Some(attribution),
    }
}

pub(super) fn performance_attribution_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "performance attribution unavailable".to_owned();
    };
    let page = query_performance_attribution(snapshot);
    serialize_prompt_context(&page, "performance attribution unavailable")
}

pub(super) fn cited_performance_attribution_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_performance_attribution(snapshot);
    let Some(attr) = page.attribution else {
        return Vec::new();
    };
    let lcp_tag = attr
        .lcp_candidate
        .as_ref()
        .map_or("none", |lcp| lcp.tag.as_str());
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "performance-attribution:lcp_tag={}:cls_shifts={}:blocking_scripts={}",
            lcp_tag,
            attr.cls_shift_regions.len(),
            attr.render_blocking_chain.blocking_head_scripts
        ),
    )]
}

/// Filter predicates for [`query_media_and_fonts`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaFontFilter {
    /// Match only media assets of a specific format class.
    pub format_class: Option<MediaFormatClass>,
    /// Match only media assets lacking intrinsic width/height sizing (`!has_intrinsic_sizing`).
    pub only_missing_intrinsic_sizing: bool,
    /// Match only above-the-fold media assets.
    pub only_above_the_fold: bool,
}

/// Paginated offline view over [`BrowserEvidence::media_and_fonts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaAndFontsQueryPage<'a> {
    /// Availability status of the media and font collector.
    pub status: EvidenceQueryStatus,
    /// Total media assets matching the filter.
    pub total_matching_media: usize,
    /// Current page of matching media assets (capped at [`PAGE_SIZE`]).
    pub media_assets: Vec<&'a MediaAssetObs>,
    /// Total webfont faces in the inventory.
    pub total_matching_fonts: usize,
    /// Current page of webfont faces (capped at [`PAGE_SIZE`]).
    pub font_assets: Vec<&'a FontAssetObs>,
    /// Total font transfer bytes observed.
    pub total_font_transfer_bytes: u64,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
}

/// Queries media assets and webfont diagnostics from [`EvidenceSnapshot`].
#[must_use]
pub fn query_media_and_fonts<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &MediaFontFilter,
    offset: usize,
) -> MediaAndFontsQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return MediaAndFontsQueryPage {
                status,
                total_matching_media: 0,
                media_assets: Vec::new(),
                total_matching_fonts: 0,
                font_assets: Vec::new(),
                total_font_transfer_bytes: 0,
                next_offset: None,
            };
        }
    };
    let Some(inv) = browser.media_and_fonts.as_ref() else {
        return MediaAndFontsQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "media and font inventory was not captured".to_owned(),
            },
            total_matching_media: 0,
            media_assets: Vec::new(),
            total_matching_fonts: 0,
            font_assets: Vec::new(),
            total_font_transfer_bytes: 0,
            next_offset: None,
        };
    };

    let matching_media: Vec<&'a MediaAssetObs> = inv
        .media_assets
        .iter()
        .filter(|m| {
            filter.format_class.is_none_or(|fc| m.format_class == fc)
                && (!filter.only_missing_intrinsic_sizing || !m.has_intrinsic_sizing)
                && (!filter.only_above_the_fold || m.above_the_fold)
        })
        .collect();
    let all_fonts: Vec<&'a FontAssetObs> = inv.font_assets.iter().collect();
    let total_matching_media = matching_media.len();
    let total_matching_fonts = all_fonts.len();
    let m_start = offset.min(total_matching_media);
    let m_end = m_start.saturating_add(PAGE_SIZE).min(total_matching_media);
    let f_start = offset.min(total_matching_fonts);
    let f_end = f_start.saturating_add(PAGE_SIZE).min(total_matching_fonts);
    let next_offset = (m_end < total_matching_media || f_end < total_matching_fonts)
        .then_some(offset.saturating_add(PAGE_SIZE));

    MediaAndFontsQueryPage {
        status,
        total_matching_media,
        media_assets: matching_media[m_start..m_end].to_vec(),
        total_matching_fonts,
        font_assets: all_fonts[f_start..f_end].to_vec(),
        total_font_transfer_bytes: inv.total_font_transfer_bytes,
        next_offset,
    }
}

pub(super) fn media_and_fonts_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "media and fonts unavailable".to_owned();
    };
    let page = query_media_and_fonts(snapshot, &MediaFontFilter::default(), 0);
    serialize_prompt_context(&page, "media and fonts unavailable")
}

pub(super) fn cited_media_or_font_refs(
    snapshot: &EvidenceSnapshot,
    media_nodes: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_media_and_fonts(snapshot, &MediaFontFilter::default(), 0);
    page.media_assets
        .iter()
        .filter(|m| media_nodes.contains(&m.node))
        .map(|m| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("media-asset={}:format={:?}", m.node, m.format_class),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-F: Search, Indexability Authority & Structured Data
// ============================================================================

/// Offline view over [`BrowserEvidence::indexability_authority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndexabilityAuthorityQueryPage<'a> {
    /// Availability status of the indexability authority collector.
    pub status: EvidenceQueryStatus,
    /// Captured indexability, canonical, and `hreflang` authority evidence, if available.
    pub authority: Option<&'a IndexabilityAuthorityEvidence>,
}

/// Queries indexability, canonical, and `hreflang` authority from [`EvidenceSnapshot`].
#[must_use]
pub fn query_indexability_authority(
    snapshot: &EvidenceSnapshot,
) -> IndexabilityAuthorityQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return IndexabilityAuthorityQueryPage {
                status,
                authority: None,
            };
        }
    };
    let Some(authority) = browser.indexability_authority.as_ref() else {
        return IndexabilityAuthorityQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "indexability authority evidence was not captured".to_owned(),
            },
            authority: None,
        };
    };
    IndexabilityAuthorityQueryPage {
        status,
        authority: Some(authority),
    }
}

/// Alias for [`query_indexability_authority`].
#[must_use]
pub fn query_indexability_and_authority(
    snapshot: &EvidenceSnapshot,
) -> IndexabilityAuthorityQueryPage<'_> {
    query_indexability_authority(snapshot)
}

pub(super) fn indexability_authority_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "indexability authority unavailable".to_owned();
    };
    let page = query_indexability_authority(snapshot);
    serialize_prompt_context(&page, "indexability authority unavailable")
}

pub(super) fn cited_indexability_authority_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_indexability_authority(snapshot);
    let Some(auth) = page.authority else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "indexability-authority:indexable={}:conflicts={}",
            auth.effectively_indexable,
            auth.conflicts.len()
        ),
    )]
}

/// Filter predicates for [`query_structured_data`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredDataFilter<'a> {
    /// Match only entities of a specific syntax (`JsonLd`, `Microdata`, `Rdfa`).
    pub syntax: Option<StructuredDataSyntax>,
    /// Case-insensitive substring match against `@type` (`schema_type`).
    pub schema_type_contains: Option<&'a str>,
    /// Match only entities missing required rich-result properties (`!valid`).
    pub only_invalid: bool,
}

/// Type alias for structured data filter.
pub type StructuredEntityFilter<'a> = StructuredDataFilter<'a>;

/// Paginated offline view over [`BrowserEvidence::structured_data`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StructuredEntitiesQueryPage<'a> {
    /// Availability status of the structured data collector.
    pub status: EvidenceQueryStatus,
    /// Total JSON-LD `<script>` blocks discovered.
    pub json_ld_block_count: u32,
    /// Count of malformed JSON-LD blocks that failed JSON parsing.
    pub malformed_json_ld_count: u32,
    /// Social preview card completeness (`og:*` and `twitter:*`).
    pub social_card: Option<&'a SocialPreviewCardCompleteness>,
    /// Validation issue codes observed across structured data blocks.
    pub issues: &'a [String],
    /// Total structured entities matching the filter.
    pub total_matching_entities: usize,
    /// Alias for `total_matching_entities`.
    pub total_matching: usize,
    /// Current page of matching structured entities (capped at [`PAGE_SIZE`]).
    pub entities: Vec<&'a StructuredEntitySummary>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
}

/// Queries structured data entities and social preview card completeness from [`EvidenceSnapshot`].
#[must_use]
pub fn query_structured_data<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &StructuredDataFilter<'_>,
    offset: usize,
) -> StructuredEntitiesQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return StructuredEntitiesQueryPage {
                status,
                json_ld_block_count: 0,
                malformed_json_ld_count: 0,
                social_card: None,
                issues: &[],
                total_matching_entities: 0,
                total_matching: 0,
                entities: Vec::new(),
                next_offset: None,
            };
        }
    };
    let Some(sd) = browser.structured_data.as_ref() else {
        return StructuredEntitiesQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "structured data inventory was not captured".to_owned(),
            },
            json_ld_block_count: 0,
            malformed_json_ld_count: 0,
            social_card: None,
            issues: &[],
            total_matching_entities: 0,
            total_matching: 0,
            entities: Vec::new(),
            next_offset: None,
        };
    };

    let matching: Vec<&'a StructuredEntitySummary> = sd
        .entities
        .iter()
        .filter(|e| {
            filter.syntax.is_none_or(|s| e.syntax == s)
                && filter.schema_type_contains.is_none_or(|needle| {
                    e.schema_type
                        .to_ascii_lowercase()
                        .contains(&needle.to_ascii_lowercase())
                })
                && (!filter.only_invalid || !e.valid)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    StructuredEntitiesQueryPage {
        status,
        json_ld_block_count: sd.json_ld_block_count,
        malformed_json_ld_count: sd.malformed_json_ld_count,
        social_card: Some(&sd.social_card),
        issues: &sd.issues,
        total_matching_entities: total_matching,
        total_matching,
        entities: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
    }
}

/// Alias for [`query_structured_data`].
#[must_use]
pub fn query_structured_entities<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &StructuredDataFilter<'_>,
    offset: usize,
) -> StructuredEntitiesQueryPage<'a> {
    query_structured_data(snapshot, filter, offset)
}

pub(super) fn structured_entities_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "structured entities unavailable".to_owned();
    };
    let page = query_structured_data(snapshot, &StructuredDataFilter::default(), 0);
    serialize_prompt_context(&page, "structured entities unavailable")
}

pub(super) fn cited_structured_entity_refs(
    snapshot: &EvidenceSnapshot,
    indices: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_structured_data(snapshot, &StructuredDataFilter::default(), 0);
    page.entities
        .iter()
        .filter(|e| indices.contains(&e.entity_index))
        .map(|e| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "structured-entity={}:type={}",
                    e.entity_index, e.schema_type
                ),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-G: Cross-Context & Graph (Responsive Layout & Link/Form Graph)
// ============================================================================

/// Filter predicates for [`query_responsive_comparison`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponsiveAnomalyFilter {
    /// Match only responsive anomalies of a specific kind.
    pub kind: Option<ResponsiveAnomalyKind>,
}

/// Type alias for responsive layout filter.
pub type ResponsiveLayoutFilter = ResponsiveAnomalyFilter;

/// Paginated offline view over [`BrowserEvidence::responsive_comparison`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponsiveLayoutQueryPage<'a> {
    /// Availability status of the responsive comparison collector.
    pub status: EvidenceQueryStatus,
    /// Mobile viewport width (`375`).
    pub mobile_viewport_width: u32,
    /// Mobile scroll width.
    pub mobile_scroll_width: u32,
    /// Desktop viewport width (`1280`).
    pub desktop_viewport_width: u32,
    /// Desktop scroll width.
    pub desktop_scroll_width: u32,
    /// Count of undersized (`< 24x24px`) touch targets on mobile, when measured.
    pub mobile_undersized_touch_targets: Option<u32>,
    /// Total responsive anomalies matching the filter.
    pub total_matching_anomalies: usize,
    /// Alias for `total_matching_anomalies`.
    pub total_matching: usize,
    /// Current page of matching responsive anomalies (capped at [`PAGE_SIZE`]).
    pub anomalies: Vec<&'a ResponsiveAnomalyObs>,
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
}

/// Queries cross-viewport (`375x667` vs `1280x800`) responsive anomalies from [`EvidenceSnapshot`].
#[must_use]
pub fn query_responsive_comparison<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &ResponsiveAnomalyFilter,
    offset: usize,
) -> ResponsiveLayoutQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return ResponsiveLayoutQueryPage {
                status,
                mobile_viewport_width: 0,
                mobile_scroll_width: 0,
                desktop_viewport_width: 0,
                desktop_scroll_width: 0,
                mobile_undersized_touch_targets: None,
                total_matching_anomalies: 0,
                total_matching: 0,
                anomalies: Vec::new(),
                next_offset: None,
            };
        }
    };
    let Some(resp) = browser.responsive_comparison.as_ref() else {
        return ResponsiveLayoutQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "responsive cross-viewport comparison was not captured".to_owned(),
            },
            mobile_viewport_width: 0,
            mobile_scroll_width: 0,
            desktop_viewport_width: 0,
            desktop_scroll_width: 0,
            mobile_undersized_touch_targets: None,
            total_matching_anomalies: 0,
            total_matching: 0,
            anomalies: Vec::new(),
            next_offset: None,
        };
    };

    let matching: Vec<&'a ResponsiveAnomalyObs> = resp
        .anomalies
        .iter()
        .filter(|a| filter.kind.is_none_or(|k| a.kind == k))
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    ResponsiveLayoutQueryPage {
        status,
        mobile_viewport_width: resp.mobile_viewport_width,
        mobile_scroll_width: resp.mobile_scroll_width,
        desktop_viewport_width: resp.desktop_viewport_width,
        desktop_scroll_width: resp.desktop_scroll_width,
        mobile_undersized_touch_targets: resp.mobile_undersized_touch_targets,
        total_matching_anomalies: total_matching,
        total_matching,
        anomalies: matching[start..end].to_vec(),
        next_offset: (end < total_matching).then_some(end),
    }
}

/// Alias for [`query_responsive_comparison`].
#[must_use]
pub fn query_responsive_layout<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &ResponsiveAnomalyFilter,
    offset: usize,
) -> ResponsiveLayoutQueryPage<'a> {
    query_responsive_comparison(snapshot, filter, offset)
}

pub(super) fn responsive_layout_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "responsive layout comparison unavailable".to_owned();
    };
    let page = query_responsive_comparison(snapshot, &ResponsiveAnomalyFilter::default(), 0);
    serialize_prompt_context(&page, "responsive layout comparison unavailable")
}

pub(super) fn cited_responsive_anomaly_refs(
    snapshot: &EvidenceSnapshot,
    indices: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_responsive_comparison(snapshot, &ResponsiveAnomalyFilter::default(), 0);
    page.anomalies
        .iter()
        .filter(|a| indices.contains(&a.anomaly_index))
        .map(|a| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("responsive-anomaly={}:kind={:?}", a.anomaly_index, a.kind),
            )
        })
        .collect()
}

/// Filter predicates for [`query_link_graph`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkGraphFilter {
    /// Match only links in a specific structural placement region.
    pub placement_region: Option<LinkPlacementRegion>,
    /// Match only external (`!same_origin`) links.
    pub only_external: bool,
    /// Match only links with empty accessible anchor text (`anchor_word_count == 0`).
    pub only_empty_anchor: bool,
}

/// Paginated offline view over [`BrowserEvidence::link_graph`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkGraphQueryPage<'a> {
    /// Availability status of the link graph collector.
    pub status: EvidenceQueryStatus,
    /// Aggregated link distribution across landmarks.
    pub cluster_summary: Option<&'a LinkClusterSummary>,
    /// Total links matching the filter.
    pub total_matching: usize,
    /// Alias for `total_matching`.
    pub total_matching_links: usize,
    /// Current page of matching links (capped at [`PAGE_SIZE`]).
    pub links: Vec<&'a RenderedLinkObs>,
    /// Rendered `<form>` submission endpoints.
    pub forms: &'a [RenderedFormEndpointObs],
    /// Offset of the next page, if any.
    pub next_offset: Option<usize>,
}

/// Queries the rendered internal/external link graph and form endpoints from [`EvidenceSnapshot`].
#[must_use]
pub fn query_link_graph<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &LinkGraphFilter,
    offset: usize,
) -> LinkGraphQueryPage<'a> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return LinkGraphQueryPage {
                status,
                cluster_summary: None,
                total_matching: 0,
                total_matching_links: 0,
                links: Vec::new(),
                forms: &[],
                next_offset: None,
            };
        }
    };
    let Some(lg) = browser.link_graph.as_ref() else {
        return LinkGraphQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "link graph inventory was not captured".to_owned(),
            },
            cluster_summary: None,
            total_matching: 0,
            total_matching_links: 0,
            links: Vec::new(),
            forms: &[],
            next_offset: None,
        };
    };

    let matching: Vec<&'a RenderedLinkObs> = lg
        .links
        .iter()
        .filter(|l| {
            filter
                .placement_region
                .is_none_or(|r| l.placement_region == r)
                && (!filter.only_external || !l.same_origin)
                && (!filter.only_empty_anchor || l.anchor_word_count == 0)
        })
        .collect();
    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);

    LinkGraphQueryPage {
        status,
        cluster_summary: Some(&lg.cluster_summary),
        total_matching,
        total_matching_links: total_matching,
        links: matching[start..end].to_vec(),
        forms: &lg.forms,
        next_offset: (end < total_matching).then_some(end),
    }
}

/// Alias for [`query_link_graph`].
#[must_use]
pub fn query_link_graph_and_forms<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &LinkGraphFilter,
    offset: usize,
) -> LinkGraphQueryPage<'a> {
    query_link_graph(snapshot, filter, offset)
}

pub(super) fn link_graph_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "link graph unavailable".to_owned();
    };
    let page = query_link_graph(snapshot, &LinkGraphFilter::default(), 0);
    serialize_prompt_context(&page, "link graph unavailable")
}

pub(super) fn cited_link_or_form_refs(
    snapshot: &EvidenceSnapshot,
    indices: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_link_graph(snapshot, &LinkGraphFilter::default(), 0);
    page.links
        .iter()
        .filter(|l| indices.contains(&l.link_index))
        .map(|l| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!(
                    "link-graph={}:region={:?}:same_origin={}",
                    l.link_index, l.placement_region, l.same_origin
                ),
            )
        })
        .collect()
}

// ============================================================================
// Wave IV-H: Visual Screenshot Digest, Service Worker & Extended TLS/CAA
// ============================================================================

/// Offline view over [`BrowserEvidence::visual_artifacts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VisualArtifactsQueryPage<'a> {
    /// Availability status of the visual artifact collector.
    pub status: EvidenceQueryStatus,
    /// Captured viewport screenshot SHA-256 digest and landmark boxes, if available.
    pub artifacts: Option<&'a VisualArtifactEvidence>,
}

/// Queries the viewport screenshot SHA-256 digest and landmark region coverage from [`EvidenceSnapshot`].
#[must_use]
pub fn query_visual_artifacts(snapshot: &EvidenceSnapshot) -> VisualArtifactsQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return VisualArtifactsQueryPage {
                status,
                artifacts: None,
            };
        }
    };
    let Some(artifacts) = browser.visual_artifacts.as_ref() else {
        return VisualArtifactsQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "visual artifacts evidence was not captured".to_owned(),
            },
            artifacts: None,
        };
    };
    VisualArtifactsQueryPage {
        status,
        artifacts: Some(artifacts),
    }
}

pub(super) fn visual_artifacts_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "visual artifacts unavailable".to_owned();
    };
    let page = query_visual_artifacts(snapshot);
    serialize_prompt_context(&page, "visual artifacts unavailable")
}

pub(super) fn cited_visual_artifact_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_visual_artifacts(snapshot);
    let Some(v) = page.artifacts else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "visual-artifacts:coverage_milli={}:landmarks={}",
            v.above_fold_coverage_milli,
            v.landmarks.len()
        ),
    )]
}

/// Offline view over [`BrowserEvidence::service_worker`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceWorkerQueryPage<'a> {
    /// Availability status of the service worker lifecycle collector.
    pub status: EvidenceQueryStatus,
    /// Captured Service Worker, Cache Storage, and manifest lifecycle evidence, if available.
    pub lifecycle: Option<&'a ServiceWorkerLifecycleEvidence>,
}

/// Queries Service Worker registration, Cache Storage, and manifest lifecycle from [`EvidenceSnapshot`].
#[must_use]
pub fn query_service_worker_lifecycle(snapshot: &EvidenceSnapshot) -> ServiceWorkerQueryPage<'_> {
    let (browser, status) = match extract_browser_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return ServiceWorkerQueryPage {
                status,
                lifecycle: None,
            };
        }
    };
    let Some(lifecycle) = browser.service_worker.as_ref() else {
        return ServiceWorkerQueryPage {
            status: EvidenceQueryStatus::Unavailable {
                reason: "service worker lifecycle evidence was not captured".to_owned(),
            },
            lifecycle: None,
        };
    };
    ServiceWorkerQueryPage {
        status,
        lifecycle: Some(lifecycle),
    }
}

/// Alias for [`query_service_worker_lifecycle`].
#[must_use]
pub fn query_service_workers(snapshot: &EvidenceSnapshot) -> ServiceWorkerQueryPage<'_> {
    query_service_worker_lifecycle(snapshot)
}

pub(super) fn service_worker_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "service worker lifecycle unavailable".to_owned();
    };
    let page = query_service_worker_lifecycle(snapshot);
    serialize_prompt_context(&page, "service worker lifecycle unavailable")
}

pub(super) fn cited_service_worker_refs(
    snapshot: &EvidenceSnapshot,
    cited: bool,
) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_service_worker_lifecycle(snapshot);
    let Some(sw) = page.lifecycle else {
        return Vec::new();
    };
    vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "service-worker:state={:?}:controlled={}:caches={}",
            sw.registration_state, sw.page_controlled, sw.cache_storage_bucket_count
        ),
    )]
}

/// Offline view over [`BrowserEvidence::tls_and_caa`] and [`EvidenceSnapshot::tls`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsAndCaaQueryPage<'a> {
    /// Availability status of the TLS and CAA diagnostics.
    pub status: EvidenceQueryStatus,
    /// Handshake TLS certificate evidence from Level 1 collection, if captured.
    pub handshake_tls: Option<&'a TlsEvidence>,
    /// Extended browser security state, CT compliance, SAN, and DNS CAA diagnostics, if captured.
    pub diagnostics: Option<&'a TlsAndCaaDiagnostics>,
}

/// Queries combined TLS certificate, CT compliance, and DNS CAA diagnostics from [`EvidenceSnapshot`].
#[must_use]
pub fn query_tls_and_caa(snapshot: &EvidenceSnapshot) -> TlsAndCaaQueryPage<'_> {
    let handshake_tls = match &snapshot.tls {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => Some(data),
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    };
    let browser_diag = match &snapshot.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.tls_and_caa.as_ref()
        }
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
    };

    if handshake_tls.is_none() && browser_diag.is_none() {
        let status = match &snapshot.tls {
            CollectorOutcome::Failed { error } => EvidenceQueryStatus::Failed {
                error: error.clone(),
            },
            CollectorOutcome::Skipped { reason } => EvidenceQueryStatus::Skipped {
                reason: reason.clone(),
            },
            _ => EvidenceQueryStatus::Unavailable {
                reason: "TLS and CAA diagnostics were not captured".to_owned(),
            },
        };
        return TlsAndCaaQueryPage {
            status,
            handshake_tls: None,
            diagnostics: None,
        };
    }

    TlsAndCaaQueryPage {
        status: EvidenceQueryStatus::Captured,
        handshake_tls,
        diagnostics: browser_diag,
    }
}

pub(super) fn tls_and_caa_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "TLS and CAA diagnostics unavailable".to_owned();
    };
    let page = query_tls_and_caa(snapshot);
    serialize_prompt_context(&page, "TLS and CAA diagnostics unavailable")
}

pub(super) fn cited_tls_and_caa_refs(snapshot: &EvidenceSnapshot, cited: bool) -> Vec<EvidenceRef> {
    if !cited {
        return Vec::new();
    }
    let page = query_tls_and_caa(snapshot);
    if let Some(tls) = page.handshake_tls {
        return vec![EvidenceRef::new(
            EvidenceSource::TlsCertificate,
            format!(
                "tls-caa:days_until_expiry={}:san_count={}:caa_records={}",
                tls.days_until_expiry,
                tls.san_entries.len(),
                tls.caa_records.len()
            ),
        )];
    }
    if let Some(diag) = page.diagnostics {
        return vec![EvidenceRef::new(
            EvidenceSource::BrowserRuntime,
            format!(
                "tls-caa:security_state={:?}:caa_records={}",
                diag.browser_security_state,
                diag.caa_records.len()
            ),
        )];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, RenderedBlockId, RenderedContentSegmentation, TargetPolicy};

    fn base_snapshot() -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    fn sample_block(node: u32, kind: RenderedBlockKind, text: &str) -> RenderedContentBlock {
        RenderedContentBlock {
            node,
            kind,
            visibility: RenderedCssVisibility::Visible,
            visible_text: text.to_owned(),
            text_truncated: false,
            identity: Some(RenderedBlockIdentity {
                path: Some(vec!["main".to_owned(), "p".to_owned()]),
                id: RenderedBlockId::Unique {
                    key: format!("id-digest-{node}"),
                },
            }),
            text_fingerprint: Some(RenderedTextFingerprint {
                version: 1,
                digest: format!("sha256-{node}"),
            }),
        }
    }

    #[test]
    fn preserves_explicit_skipped_failed_and_unavailable_statuses() {
        let mut snapshot = base_snapshot();
        assert_eq!(
            query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0).status,
            EvidenceQueryStatus::Skipped {
                reason: "not collected".to_owned(),
            }
        );
        assert!(query_browser_evidence_from_snapshot(&snapshot).is_none());

        snapshot.browser = CollectorOutcome::Failed {
            error: "chromium timeout".to_owned(),
        };
        assert_eq!(
            query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0).status,
            EvidenceQueryStatus::Failed {
                error: "chromium timeout".to_owned(),
            }
        );
        assert_eq!(
            query_network_resources(&snapshot, &NetworkResourceFilter::default(), 0).status,
            EvidenceQueryStatus::Failed {
                error: "chromium timeout".to_owned(),
            }
        );
        assert_eq!(
            query_runtime_errors(&snapshot, &RuntimeErrorFilter::default(), 0).status,
            EvidenceQueryStatus::Failed {
                error: "chromium timeout".to_owned(),
            }
        );

        let summary = query_browser_evidence_from_snapshot(&snapshot).unwrap();
        assert_eq!(summary.collection_status, "failed");

        snapshot.browser = CollectorOutcome::Captured {
            data: BrowserEvidence::default(),
        };
        assert_eq!(
            query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0).status,
            EvidenceQueryStatus::Unavailable {
                reason: "rendered_content segmentation not present in browser evidence".to_owned(),
            }
        );
    }

    #[test]
    fn rendered_content_query_paginates_filters_and_omits_raw_visible_text() {
        let mut snapshot = base_snapshot();
        let mut blocks: Vec<RenderedContentBlock> = (1..=18)
            .map(|node| {
                sample_block(
                    node,
                    RenderedBlockKind::Paragraph,
                    "secret-canary-prose second-word",
                )
            })
            .collect();
        blocks[0].kind = RenderedBlockKind::Main;
        blocks[1].visibility = RenderedCssVisibility::Hidden;
        blocks[1].identity = Some(RenderedBlockIdentity {
            path: None,
            id: RenderedBlockId::Absent,
        });

        snapshot.browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                rendered_content: Some(RenderedContentSegmentation {
                    viewport_width: 1280,
                    viewport_height: 720,
                    blocks,
                    limits: RenderedContentLimits {
                        nodes: false,
                        depth: false,
                        blocks: false,
                    },
                    id_census_complete: Some(true),
                    page_key: Some("page-sha256".to_owned()),
                }),
                ..BrowserEvidence::default()
            },
        };

        let page0 = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
        assert_eq!(page0.status, EvidenceQueryStatus::Captured);
        assert_eq!(page0.total_matching, 18);
        assert_eq!(page0.blocks.len(), PAGE_SIZE);
        assert_eq!(page0.next_offset, Some(16));
        assert_eq!(page0.blocks[0].visible_word_count, 2);

        let page1 = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 16);
        assert_eq!(page1.blocks.len(), 2);
        assert_eq!(page1.blocks[0].node, 17);
        assert_eq!(page1.next_offset, None);

        let context_json = rendered_content_context(Some(&snapshot));
        assert!(
            !context_json.contains("secret-canary-prose"),
            "prompt context must never serialise raw visible_text"
        );
        assert!(context_json.contains("sha256-1"));

        // Citation validation accepts only nodes on page 0 (1..=16) and rejects 17 or 999.
        let refs = cited_rendered_block_refs(&snapshot, &[1, 1, 17, 999]);
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0],
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                "rendered-block-node=1:kind=main:visibility=visible"
            )
        );

        let filter = RenderedBlockFilter {
            kind: Some(RenderedBlockKind::Paragraph),
            visibility: Some(RenderedCssVisibility::Visible),
            require_unique_id: true,
        };
        let filtered = query_rendered_content(&snapshot, &filter, 0);
        assert_eq!(filtered.total_matching, 16);
    }

    #[test]
    fn filters_network_resources_and_runtime_errors_from_snapshot() {
        let mut snapshot = base_snapshot();
        snapshot.browser = CollectorOutcome::Partial {
            data: BrowserEvidence {
                final_url: "https://example.org/".to_owned(),
                resources_truncated: true,
                resources: vec![
                    ResourceTimingObs {
                        url: "https://example.org/app.js".to_owned(),
                        resource_type: "script".to_owned(),
                        duration_ms: Some(420),
                        transfer_size: Some(90_000),
                        status_code: Some(200),
                        ..ResourceTimingObs::default()
                    },
                    ResourceTimingObs {
                        url: "https://cdn.thirdparty.example/Pixel.js".to_owned(),
                        resource_type: "script".to_owned(),
                        duration_ms: Some(45),
                        transfer_size: Some(2_000),
                        status_code: Some(502),
                        ..ResourceTimingObs::default()
                    },
                ],
                console_errors: vec![
                    ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "CSP violation".to_owned(),
                        error_kind: Some("csp_violation".to_owned()),
                        ..ConsoleErrorEvent::default()
                    },
                    ConsoleErrorEvent {
                        level: "error".to_owned(),
                        text: "Uncaught TypeError".to_owned(),
                        error_kind: Some("uncaught_exception".to_owned()),
                        ..ConsoleErrorEvent::default()
                    },
                ],
                ..BrowserEvidence::default()
            },
            warnings: vec!["navigation soft timeout".to_owned()],
        };

        let res_page = query_network_resources(
            &snapshot,
            &NetworkResourceFilter {
                resource_type: Some("SCRIPT"),
                min_duration_ms: None,
                min_transfer_bytes: None,
                status_error_only: true,
            },
            0,
        );
        assert!(matches!(
            res_page.status,
            EvidenceQueryStatus::Partial { .. }
        ));
        assert!(res_page.resources_truncated);
        assert_eq!(res_page.total_matching, 1);
        assert_eq!(res_page.resources[0].status_code, Some(502));

        let err_page = query_runtime_errors(
            &snapshot,
            &RuntimeErrorFilter {
                error_kind: Some("CSP_VIOLATION"),
            },
            0,
        );
        assert_eq!(err_page.total_matching, 1);
        assert_eq!(err_page.console_errors[0].text, "CSP violation");

        let summary = query_browser_evidence_from_snapshot(&snapshot).unwrap();
        assert_eq!(summary.collection_status, "partial");
        assert_eq!(summary.resource_count, 2);
        assert_eq!(summary.total_transfer_bytes, 92_000);
        assert_eq!(
            summary.third_party_hosts,
            vec!["cdn.thirdparty.example".to_owned()]
        );
        assert_eq!(summary.runtime_error_counts.get("csp_violation"), Some(&1));
    }

    #[test]
    fn third_party_cookie_filter_requires_an_observed_relationship() {
        let mut snapshot = base_snapshot();
        let cookie = |name: &str, third_party: Option<bool>| crate::domain::RuntimeCookieObs {
            name: name.to_owned(),
            domain: "example.org".to_owned(),
            path: "/".to_owned(),
            secure: true,
            http_only: true,
            same_site: crate::domain::CookieSameSiteMode::Lax,
            session: true,
            value_byte_len: 12,
            third_party,
            has_security_prefix: false,
            observed_before_consent: None,
        };
        snapshot.browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                cookie_and_storage: Some(crate::domain::CookieAndStorageInventory {
                    cookies: vec![
                        cookie("observed_third_party", Some(true)),
                        cookie("observed_first_party", Some(false)),
                        cookie("unknown_scope", None),
                    ],
                    storage_keys: Vec::new(),
                    indexed_db_count: 0,
                    indexed_db_databases: Vec::new(),
                    indexed_db_enumerated: false,
                    cookies_enumerated: true,
                    storage_enumerated: true,
                    limits: crate::domain::CookieStorageLimits::default(),
                }),
                ..BrowserEvidence::default()
            },
        };

        let page = query_storage_and_cookies(
            &snapshot,
            &StorageCookieFilter {
                only_third_party_cookies: true,
                ..StorageCookieFilter::default()
            },
            0,
        );
        assert_eq!(page.total_matching_cookies, 1);
        assert_eq!(page.cookies[0].name, "observed_third_party");
    }
}
