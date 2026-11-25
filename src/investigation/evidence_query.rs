//! Deterministic offline query engine over a captured [`EvidenceSnapshot`].
//!
//! Provides bounded, paginated, zero-acquisition views over Level 2 browser
//! evidence (rendered content blocks, subresource network timings, and runtime
//! errors) so `KommandantZwerg` and specialist dwarfs can inspect already
//! captured evidence without launching additional browser sessions or exposing
//! raw untrusted page text in prompts.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::domain::{
    BrowserEvidence, CollectorOutcome, ConsoleErrorEvent, EvidenceRef, EvidenceSnapshot,
    EvidenceSource, RenderedBlockIdentity, RenderedBlockKind, RenderedContentBlock,
    RenderedContentLimits, RenderedCssVisibility, RenderedTextFingerprint, ResourceTimingObs,
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
}
