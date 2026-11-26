//! Bounded investigation queries over previously collected browser events.
//!
//! Provides both raw page-based access (`query_browser_timeline`), predicate-filtered
//! timeline queries (`query_browser_timeline_filtered`), and multi-hop request lifecycle
//! reconstruction (`query_request_chains`) over `&EvidenceSnapshot` without starting a
//! browser process.

use serde::Serialize;

use crate::domain::{
    BrowserEventDetail, BrowserTimeline, BrowserTimelineEvent, CollectorOutcome, EvidenceRef,
    EvidenceSnapshot, EvidenceSource, TimelineEnd, TimelineRuntimeKind,
};

use super::evidence_query::{EvidenceQueryStatus, PAGE_SIZE};

/// Status alias for timeline queries preserving collector availability states.
pub type BrowserTimelineQueryStatus = EvidenceQueryStatus;

/// One page of browser timeline evidence from a captured snapshot.
#[derive(Debug, Serialize)]
pub struct BrowserTimelinePage<'a> {
    /// Source events in receive order.
    pub events: &'a [BrowserTimelineEvent],
    /// Offset of the next retained page.
    pub next_offset: Option<usize>,
    /// Whether collection discarded later events.
    pub truncated: bool,
    /// Why observation ended.
    pub end: TimelineEnd,
    /// Whether the enclosing browser collection was partial.
    pub browser_partial: bool,
}

/// Discriminant for filtering `BrowserTimelineEvent` records by event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTimelineEventKind {
    /// Browser started a request.
    RequestStarted,
    /// Redirect response observed before next hop.
    Redirect,
    /// HTTP response received.
    Response,
    /// Resource loading finished.
    Completed,
    /// Transport failure reported.
    NetworkFailure,
    /// Load was cancelled.
    Cancelled,
    /// Browser-side block reported by Chromium.
    BrowserBlocked,
    /// Request rejected by collector target policy.
    PolicyBlocked,
    /// Runtime error observed.
    RuntimeError,
}

/// Filter predicates for querying browser timeline events offline.
#[derive(Debug, Clone, Default)]
pub struct BrowserTimelineFilter<'a> {
    /// Match only events of a specific kind.
    pub kind: Option<BrowserTimelineEventKind>,
    /// Case-insensitive substring match against the event's origin, if present.
    pub origin_contains: Option<&'a str>,
    /// Exact match against the CDP request identifier (`RequestHop::id`).
    pub request_id: Option<&'a str>,
    /// Minimum HTTP status code on `Redirect` or `Response` events.
    pub min_status: Option<u16>,
    /// Maximum HTTP status code on `Redirect` or `Response` events.
    pub max_status: Option<u16>,
    /// Match only `RuntimeError` events of a specific category.
    pub runtime_category: Option<TimelineRuntimeKind>,
    /// Match only failure/error events (`HTTP >= 400`, transport failures, blocks, runtime errors).
    pub only_failures: bool,
}

/// Bounded page of filtered browser timeline events with explicit collector status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserTimelineQueryPage<'a> {
    /// Availability status of the underlying browser timeline collector.
    pub status: EvidenceQueryStatus,
    /// Matching events in the current page (capped at `PAGE_SIZE`).
    pub events: Vec<&'a BrowserTimelineEvent>,
    /// Total number of events matching the filter across the retained timeline.
    pub total_matching: usize,
    /// Offset of the next page when more matching events exist.
    pub next_offset: Option<usize>,
    /// Whether the 512-event collector cap discarded later observations.
    pub truncated: bool,
    /// Why timeline observation ended, when available.
    pub end: Option<TimelineEnd>,
}

/// Terminal or last-observed outcome of a reconstructed request lifecycle chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RequestChainOutcome {
    /// The request completed loading with a non-error HTTP status (or no error status).
    Completed,
    /// The request received an HTTP 4xx or 5xx response.
    HttpError {
        /// Final observed HTTP status code.
        status: u16,
    },
    /// The request failed at the network transport layer.
    NetworkFailure,
    /// The request was cancelled before completion.
    Cancelled,
    /// Chromium blocked the request client-side.
    BrowserBlocked,
    /// The collector blocked the request under `TargetPolicy`.
    PolicyBlocked,
    /// No terminal completion or failure event was recorded within the observation window.
    Incomplete,
}

/// Reconstructed lifecycle of a single CDP request ID across redirect hops and terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestChainSummary<'a> {
    /// Browser protocol request identifier (`RequestHop::id`).
    pub request_id: &'a str,
    /// Initial HTTP method, when observed.
    pub method: Option<&'a str>,
    /// Distinct origins traversed in hop order.
    pub origins: Vec<&'a str>,
    /// Initial origin of the request chain, if observed.
    pub initial_origin: Option<&'a str>,
    /// Final origin of the request chain, if observed.
    pub final_origin: Option<&'a str>,
    /// Secret-safe endpoint pathname, if observed.
    pub endpoint_path: Option<&'a str>,
    /// Number of redirect events observed for this request ID.
    pub redirect_hops: usize,
    /// Total hops (`1 + redirect_hops`).
    pub total_hops: usize,
    /// Final HTTP response status code observed, if any.
    pub final_status: Option<u16>,
    /// Encoded transfer size from `Completed`, when measured.
    pub encoded_bytes: Option<u64>,
    /// Classified outcome of the request chain.
    pub outcome: RequestChainOutcome,
    /// Ordered timeline event sequence numbers belonging to this request chain.
    pub sequences: Vec<u32>,
}

/// Failure category for a failed or blocked subresource dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedDependencyCategory {
    /// HTTP 4xx or 5xx response.
    HttpStatusError,
    /// Network-layer failure.
    NetworkFailure,
    /// Cancelled before completion.
    Cancelled,
    /// Blocked by browser client-side policy (CORS/CORB/CSP/mixed-content).
    BrowserBlocked,
    /// Blocked by `TargetPolicy` (SSRF / private network guard).
    PolicyBlocked,
}

/// Consolidated failed or blocked dependency entry from the browser timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedDependencyEntry<'a> {
    /// Terminal or failure event sequence number.
    pub sequence: u32,
    /// CDP request identifier, if request-correlated.
    pub request_id: Option<&'a str>,
    /// Classified failure category.
    pub category: FailedDependencyCategory,
    /// HTTP status code when `category == HttpStatusError`.
    pub status_code: Option<u16>,
    /// Origin of the failed dependency, if recorded.
    pub origin: Option<&'a str>,
    /// Secret-safe pathname of the failed dependency, if recorded.
    pub endpoint_path: Option<&'a str>,
    /// CDP resource type (`Document`, `Script`, `Stylesheet`, `XHR`, `Fetch`, etc.), if recorded.
    pub resource_type: Option<&'a str>,
    /// Initiator type (`parser`, `script`, `preload`, `other`), if recorded.
    pub initiator_type: Option<&'a str>,
    /// Policy block reason when `category == PolicyBlocked`.
    pub policy_reason: Option<&'a str>,
}

/// Filter predicates for querying failed or blocked dependencies offline.
#[derive(Debug, Clone, Default)]
pub struct FailedDependencyFilter<'a> {
    /// Match only a specific failure category.
    pub category: Option<FailedDependencyCategory>,
    /// Case-insensitive substring match against origin.
    pub origin_contains: Option<&'a str>,
    /// Case-insensitive substring match against `endpoint_path`.
    pub path_contains: Option<&'a str>,
    /// Case-insensitive exact match against `resource_type`.
    pub resource_type: Option<&'a str>,
}

/// Bounded page of failed or blocked dependencies from a captured browser timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedDependenciesQueryPage<'a> {
    /// Availability status of the underlying browser timeline collector.
    pub status: EvidenceQueryStatus,
    /// Matching failed dependencies in the current page (capped at `PAGE_SIZE`).
    pub dependencies: Vec<FailedDependencyEntry<'a>>,
    /// Total number of failed dependencies matching the filter.
    pub total_matching: usize,
    /// Offset of the next page when more matching entries exist.
    pub next_offset: Option<usize>,
    /// Whether the 512-event collector cap discarded later observations.
    pub truncated: bool,
    /// Why timeline observation ended, when available.
    pub end: Option<TimelineEnd>,
}

/// Filter predicates for querying reconstructed request chains offline.
#[derive(Debug, Clone, Default)]
pub struct RequestChainFilter<'a> {
    /// Case-insensitive substring match against any origin traversed by the chain.
    pub origin_contains: Option<&'a str>,
    /// Match only chains ending in an HTTP error, transport failure, or block.
    pub only_failures: bool,
    /// Match only chains that experienced at least one redirect hop.
    pub only_redirects: bool,
}

/// Bounded page of reconstructed request chains from a captured browser timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestChainsQueryPage<'a> {
    /// Availability status of the underlying browser timeline collector.
    pub status: EvidenceQueryStatus,
    /// Reconstructed request chains in the current page (capped at `PAGE_SIZE`).
    pub chains: Vec<RequestChainSummary<'a>>,
    /// Total number of chains matching the filter across the retained timeline.
    pub total_matching: usize,
    /// Offset of the next page when more matching chains exist.
    pub next_offset: Option<usize>,
    /// Whether the 512-event collector cap discarded later observations.
    pub truncated: bool,
    /// Why timeline observation ended, when available.
    pub end: Option<TimelineEnd>,
}

/// Reads up to 16 events without starting a browser.
///
/// Returns `None` when timeline evidence is unavailable.
#[must_use]
pub fn query_browser_timeline(
    snapshot: &EvidenceSnapshot,
    offset: usize,
) -> Option<BrowserTimelinePage<'_>> {
    let (data, browser_partial) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, false),
        CollectorOutcome::Partial { data, .. } => (data, true),
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => return None,
    };
    let timeline = data.timeline.as_ref()?;
    let start = offset.min(timeline.events.len());
    let end = start.saturating_add(PAGE_SIZE).min(timeline.events.len());
    Some(BrowserTimelinePage {
        events: &timeline.events[start..end],
        next_offset: (end < timeline.events.len()).then_some(end),
        truncated: timeline.truncated,
        end: timeline.end,
        browser_partial,
    })
}

/// Queries browser timeline events with predicate filtering and explicit collector status.
#[must_use]
pub fn query_browser_timeline_filtered<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &BrowserTimelineFilter<'_>,
    offset: usize,
) -> BrowserTimelineQueryPage<'a> {
    let (timeline, status) = match extract_timeline_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return BrowserTimelineQueryPage {
                status,
                events: Vec::new(),
                total_matching: 0,
                next_offset: None,
                truncated: false,
                end: None,
            };
        }
    };

    let matching: Vec<&'a BrowserTimelineEvent> = timeline
        .events
        .iter()
        .filter(|ev| matches_timeline_filter(ev, filter))
        .collect();

    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let events = matching[start..end].to_vec();

    BrowserTimelineQueryPage {
        status,
        events,
        total_matching,
        next_offset: (end < total_matching).then_some(end),
        truncated: timeline.truncated,
        end: Some(timeline.end),
    }
}

/// Reconstructs multi-hop request lifecycles grouped by CDP request ID in first-seen order.
#[must_use]
pub fn query_request_chains<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &RequestChainFilter<'_>,
    offset: usize,
) -> RequestChainsQueryPage<'a> {
    let (timeline, status) = match extract_timeline_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return RequestChainsQueryPage {
                status,
                chains: Vec::new(),
                total_matching: 0,
                next_offset: None,
                truncated: false,
                end: None,
            };
        }
    };

    let all_chains = reconstruct_chains(timeline);
    let matching: Vec<RequestChainSummary<'a>> = all_chains
        .into_iter()
        .filter(|chain| matches_chain_filter(chain, filter))
        .collect();

    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let chains = matching[start..end].to_vec();

    RequestChainsQueryPage {
        status,
        chains,
        total_matching,
        next_offset: (end < total_matching).then_some(end),
        truncated: timeline.truncated,
        end: Some(timeline.end),
    }
}

/// Queries failed or blocked subresource dependencies correlated across request hops.
#[must_use]
pub fn query_failed_dependencies<'a>(
    snapshot: &'a EvidenceSnapshot,
    filter: &FailedDependencyFilter<'_>,
    offset: usize,
) -> FailedDependenciesQueryPage<'a> {
    let (timeline, status) = match extract_timeline_with_status(snapshot) {
        Ok(pair) => pair,
        Err(status) => {
            return FailedDependenciesQueryPage {
                status,
                dependencies: Vec::new(),
                total_matching: 0,
                next_offset: None,
                truncated: false,
                end: None,
            };
        }
    };

    let all_failed = extract_failed_dependencies(timeline);
    let matching: Vec<FailedDependencyEntry<'a>> = all_failed
        .into_iter()
        .filter(|entry| matches_failed_dependency_filter(entry, filter))
        .collect();

    let total_matching = matching.len();
    let start = offset.min(total_matching);
    let end = start.saturating_add(PAGE_SIZE).min(total_matching);
    let dependencies = matching[start..end].to_vec();

    FailedDependenciesQueryPage {
        status,
        dependencies,
        total_matching,
        next_offset: (end < total_matching).then_some(end),
        truncated: timeline.truncated,
        end: Some(timeline.end),
    }
}

pub(super) fn timeline_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    snapshot
        .and_then(|snapshot| query_browser_timeline(snapshot, 0))
        .and_then(|page| serde_json::to_string(&page).ok())
        .map_or_else(
            || "browser timeline unavailable".to_owned(),
            |json| json.replace('<', r"\u003c"),
        )
}

pub(super) fn request_chains_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "browser request chains unavailable".to_owned();
    };
    let page = query_request_chains(snapshot, &RequestChainFilter::default(), 0);
    serde_json::to_string(&page).map_or_else(
        |_| "browser request chains unavailable".to_owned(),
        |json| json.replace('<', r"\u003c"),
    )
}

pub(super) fn failed_dependencies_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "failed dependencies unavailable".to_owned();
    };
    let page = query_failed_dependencies(snapshot, &FailedDependencyFilter::default(), 0);
    serde_json::to_string(&page).map_or_else(
        |_| "failed dependencies unavailable".to_owned(),
        |json| json.replace('<', r"\u003c"),
    )
}

pub(super) fn cited_event_refs(snapshot: &EvidenceSnapshot, sequences: &[u32]) -> Vec<EvidenceRef> {
    query_browser_timeline(snapshot, 0)
        .into_iter()
        .flat_map(|page| page.events)
        .filter(|event| sequences.contains(&event.sequence))
        .map(|event| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("timeline-event={}", event.sequence),
            )
        })
        .collect()
}

pub(super) fn cited_chain_event_refs(
    snapshot: &EvidenceSnapshot,
    sequences: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_request_chains(snapshot, &RequestChainFilter::default(), 0);
    let mut allowed_sequences: Vec<u32> = page
        .chains
        .iter()
        .flat_map(|chain| chain.sequences.iter().copied())
        .filter(|seq| sequences.contains(seq))
        .collect();
    allowed_sequences.sort_unstable();
    allowed_sequences.dedup();
    allowed_sequences
        .into_iter()
        .map(|seq| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("timeline-event={seq}"),
            )
        })
        .collect()
}

pub(super) fn cited_failed_dependency_refs(
    snapshot: &EvidenceSnapshot,
    sequences: &[u32],
) -> Vec<EvidenceRef> {
    let page = query_failed_dependencies(snapshot, &FailedDependencyFilter::default(), 0);
    page.dependencies
        .iter()
        .filter(|dep| sequences.contains(&dep.sequence))
        .map(|dep| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("timeline-event={}", dep.sequence),
            )
        })
        .collect()
}

fn extract_timeline_with_status(
    snapshot: &EvidenceSnapshot,
) -> Result<(&BrowserTimeline, EvidenceQueryStatus), EvidenceQueryStatus> {
    let (browser, status) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, EvidenceQueryStatus::Captured),
        CollectorOutcome::Partial { data, warnings } => (
            data,
            EvidenceQueryStatus::Partial {
                warnings: warnings.clone(),
            },
        ),
        CollectorOutcome::Failed { error } => {
            return Err(EvidenceQueryStatus::Failed {
                error: error.clone(),
            });
        }
        CollectorOutcome::Skipped { reason } => {
            return Err(EvidenceQueryStatus::Skipped {
                reason: reason.clone(),
            });
        }
    };

    let Some(timeline) = browser.timeline.as_ref() else {
        return Err(EvidenceQueryStatus::Unavailable {
            reason: "browser timeline was not captured".to_owned(),
        });
    };

    Ok((timeline, status))
}

fn event_kind(detail: &BrowserEventDetail) -> BrowserTimelineEventKind {
    match detail {
        BrowserEventDetail::RequestStarted { .. } => BrowserTimelineEventKind::RequestStarted,
        BrowserEventDetail::Redirect { .. } => BrowserTimelineEventKind::Redirect,
        BrowserEventDetail::Response { .. } => BrowserTimelineEventKind::Response,
        BrowserEventDetail::Completed { .. } => BrowserTimelineEventKind::Completed,
        BrowserEventDetail::NetworkFailure => BrowserTimelineEventKind::NetworkFailure,
        BrowserEventDetail::Cancelled => BrowserTimelineEventKind::Cancelled,
        BrowserEventDetail::BrowserBlocked => BrowserTimelineEventKind::BrowserBlocked,
        BrowserEventDetail::PolicyBlocked { .. } => BrowserTimelineEventKind::PolicyBlocked,
        BrowserEventDetail::RuntimeError { .. } => BrowserTimelineEventKind::RuntimeError,
    }
}

fn event_origin(detail: &BrowserEventDetail) -> Option<&str> {
    match detail {
        BrowserEventDetail::RequestStarted { origin, .. }
        | BrowserEventDetail::Redirect { origin, .. }
        | BrowserEventDetail::Response { origin, .. }
        | BrowserEventDetail::PolicyBlocked { origin, .. } => origin.as_deref(),
        BrowserEventDetail::Completed { .. }
        | BrowserEventDetail::NetworkFailure
        | BrowserEventDetail::Cancelled
        | BrowserEventDetail::BrowserBlocked
        | BrowserEventDetail::RuntimeError { .. } => None,
    }
}

fn event_endpoint_path(detail: &BrowserEventDetail) -> Option<&str> {
    match detail {
        BrowserEventDetail::RequestStarted { endpoint_path, .. }
        | BrowserEventDetail::Redirect { endpoint_path, .. }
        | BrowserEventDetail::Response { endpoint_path, .. }
        | BrowserEventDetail::PolicyBlocked { endpoint_path, .. } => endpoint_path.as_deref(),
        BrowserEventDetail::Completed { .. }
        | BrowserEventDetail::NetworkFailure
        | BrowserEventDetail::Cancelled
        | BrowserEventDetail::BrowserBlocked
        | BrowserEventDetail::RuntimeError { .. } => None,
    }
}

fn event_status(detail: &BrowserEventDetail) -> Option<u16> {
    match detail {
        BrowserEventDetail::Redirect { status, .. }
        | BrowserEventDetail::Response { status, .. } => *status,
        _ => None,
    }
}

fn is_failure_event(detail: &BrowserEventDetail) -> bool {
    match detail {
        BrowserEventDetail::Response {
            status: Some(code), ..
        } => *code >= 400,
        BrowserEventDetail::NetworkFailure
        | BrowserEventDetail::Cancelled
        | BrowserEventDetail::BrowserBlocked
        | BrowserEventDetail::PolicyBlocked { .. }
        | BrowserEventDetail::RuntimeError { .. } => true,
        _ => false,
    }
}

fn matches_timeline_filter(
    event: &BrowserTimelineEvent,
    filter: &BrowserTimelineFilter<'_>,
) -> bool {
    if let Some(expected_kind) = filter.kind
        && event_kind(&event.detail) != expected_kind
    {
        return false;
    }
    if let Some(needle) = filter.origin_contains {
        let Some(origin) = event_origin(&event.detail) else {
            return false;
        };
        if !origin
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
        {
            return false;
        }
    }
    if let Some(expected_req_id) = filter.request_id {
        let Some(req) = event.request.as_ref() else {
            return false;
        };
        if req.id != expected_req_id {
            return false;
        }
    }
    if let Some(min) = filter.min_status {
        let Some(status) = event_status(&event.detail) else {
            return false;
        };
        if status < min {
            return false;
        }
    }
    if let Some(max) = filter.max_status {
        let Some(status) = event_status(&event.detail) else {
            return false;
        };
        if status > max {
            return false;
        }
    }
    if let Some(expected_cat) = filter.runtime_category {
        let BrowserEventDetail::RuntimeError { category } = event.detail else {
            return false;
        };
        if category != expected_cat {
            return false;
        }
    }
    !filter.only_failures || is_failure_event(&event.detail)
}

fn reconstruct_chains(timeline: &BrowserTimeline) -> Vec<RequestChainSummary<'_>> {
    let mut chains: Vec<RequestChainSummary<'_>> = Vec::new();

    for event in &timeline.events {
        let Some(req) = event.request.as_ref() else {
            continue;
        };
        let chain = if let Some(existing) = chains.iter_mut().find(|c| c.request_id == req.id) {
            existing
        } else {
            chains.push(RequestChainSummary {
                request_id: &req.id,
                method: None,
                origins: Vec::new(),
                initial_origin: None,
                final_origin: None,
                endpoint_path: None,
                redirect_hops: 0,
                total_hops: 1,
                final_status: None,
                encoded_bytes: None,
                outcome: RequestChainOutcome::Incomplete,
                sequences: Vec::new(),
            });
            let idx = chains.len() - 1;
            &mut chains[idx]
        };

        chain.sequences.push(event.sequence);
        if let Some(origin) = event_origin(&event.detail) {
            if chain.initial_origin.is_none() {
                chain.initial_origin = Some(origin);
            }
            chain.final_origin = Some(origin);
            if !chain.origins.contains(&origin) {
                chain.origins.push(origin);
            }
        }
        if let Some(path) = event_endpoint_path(&event.detail) {
            chain.endpoint_path = Some(path);
        }

        match &event.detail {
            BrowserEventDetail::RequestStarted { method, .. } => {
                if chain.method.is_none() {
                    chain.method = method.as_deref();
                }
            }
            BrowserEventDetail::Redirect { .. } => {
                chain.redirect_hops = chain.redirect_hops.saturating_add(1);
                chain.total_hops = chain.redirect_hops.saturating_add(1);
            }
            BrowserEventDetail::Response { status, .. } => {
                chain.final_status = *status;
                if let Some(code) = *status
                    && code >= 400
                {
                    chain.outcome = RequestChainOutcome::HttpError { status: code };
                }
            }
            BrowserEventDetail::Completed { encoded_bytes } => {
                chain.encoded_bytes = *encoded_bytes;
                if !matches!(chain.outcome, RequestChainOutcome::HttpError { .. }) {
                    chain.outcome = RequestChainOutcome::Completed;
                }
            }
            BrowserEventDetail::NetworkFailure => {
                chain.outcome = RequestChainOutcome::NetworkFailure;
            }
            BrowserEventDetail::Cancelled => {
                chain.outcome = RequestChainOutcome::Cancelled;
            }
            BrowserEventDetail::BrowserBlocked => {
                chain.outcome = RequestChainOutcome::BrowserBlocked;
            }
            BrowserEventDetail::PolicyBlocked { .. } => {
                chain.outcome = RequestChainOutcome::PolicyBlocked;
            }
            BrowserEventDetail::RuntimeError { .. } => {}
        }
    }

    chains
}

fn matches_chain_filter(chain: &RequestChainSummary<'_>, filter: &RequestChainFilter<'_>) -> bool {
    if let Some(needle) = filter.origin_contains {
        let lower = needle.to_ascii_lowercase();
        if !chain
            .origins
            .iter()
            .any(|origin| origin.to_ascii_lowercase().contains(&lower))
        {
            return false;
        }
    }
    if filter.only_redirects && chain.redirect_hops == 0 {
        return false;
    }
    if filter.only_failures {
        let is_fail = matches!(
            chain.outcome,
            RequestChainOutcome::HttpError { .. }
                | RequestChainOutcome::NetworkFailure
                | RequestChainOutcome::Cancelled
                | RequestChainOutcome::BrowserBlocked
                | RequestChainOutcome::PolicyBlocked
        );
        if !is_fail {
            return false;
        }
    }
    true
}

#[derive(Default)]
struct RequestContext<'a> {
    origin: Option<&'a str>,
    endpoint_path: Option<&'a str>,
    resource_type: Option<&'a str>,
    initiator_type: Option<&'a str>,
}

#[allow(clippy::too_many_lines)]
fn extract_failed_dependencies(timeline: &BrowserTimeline) -> Vec<FailedDependencyEntry<'_>> {
    let mut contexts: std::collections::BTreeMap<&str, RequestContext<'_>> =
        std::collections::BTreeMap::new();
    let mut failed: Vec<FailedDependencyEntry<'_>> = Vec::new();

    for event in &timeline.events {
        let req_id = event.request.as_ref().map(|r| r.id.as_str());
        if let Some(id) = req_id {
            let ctx = contexts.entry(id).or_default();
            match &event.detail {
                BrowserEventDetail::RequestStarted {
                    origin,
                    endpoint_path,
                    resource_type,
                    initiator_type,
                    ..
                } => {
                    if origin.is_some() {
                        ctx.origin = origin.as_deref();
                    }
                    if endpoint_path.is_some() {
                        ctx.endpoint_path = endpoint_path.as_deref();
                    }
                    if resource_type.is_some() {
                        ctx.resource_type = resource_type.as_deref();
                    }
                    if initiator_type.is_some() {
                        ctx.initiator_type = initiator_type.as_deref();
                    }
                }
                BrowserEventDetail::Redirect {
                    origin,
                    endpoint_path,
                    ..
                }
                | BrowserEventDetail::Response {
                    origin,
                    endpoint_path,
                    ..
                }
                | BrowserEventDetail::PolicyBlocked {
                    origin,
                    endpoint_path,
                } => {
                    if origin.is_some() {
                        ctx.origin = origin.as_deref();
                    }
                    if endpoint_path.is_some() {
                        ctx.endpoint_path = endpoint_path.as_deref();
                    }
                }
                _ => {}
            }
        }

        let ctx = req_id.and_then(|id| contexts.get(id));
        match &event.detail {
            BrowserEventDetail::Response {
                status: Some(code),
                origin,
                endpoint_path,
                ..
            } if *code >= 400 => {
                failed.push(FailedDependencyEntry {
                    sequence: event.sequence,
                    request_id: req_id,
                    category: FailedDependencyCategory::HttpStatusError,
                    status_code: Some(*code),
                    origin: origin.as_deref().or_else(|| ctx.and_then(|c| c.origin)),
                    endpoint_path: endpoint_path
                        .as_deref()
                        .or_else(|| ctx.and_then(|c| c.endpoint_path)),
                    resource_type: ctx.and_then(|c| c.resource_type),
                    initiator_type: ctx.and_then(|c| c.initiator_type),
                    policy_reason: None,
                });
            }
            BrowserEventDetail::NetworkFailure => {
                failed.push(FailedDependencyEntry {
                    sequence: event.sequence,
                    request_id: req_id,
                    category: FailedDependencyCategory::NetworkFailure,
                    status_code: None,
                    origin: ctx.and_then(|c| c.origin),
                    endpoint_path: ctx.and_then(|c| c.endpoint_path),
                    resource_type: ctx.and_then(|c| c.resource_type),
                    initiator_type: ctx.and_then(|c| c.initiator_type),
                    policy_reason: None,
                });
            }
            BrowserEventDetail::Cancelled => {
                failed.push(FailedDependencyEntry {
                    sequence: event.sequence,
                    request_id: req_id,
                    category: FailedDependencyCategory::Cancelled,
                    status_code: None,
                    origin: ctx.and_then(|c| c.origin),
                    endpoint_path: ctx.and_then(|c| c.endpoint_path),
                    resource_type: ctx.and_then(|c| c.resource_type),
                    initiator_type: ctx.and_then(|c| c.initiator_type),
                    policy_reason: None,
                });
            }
            BrowserEventDetail::BrowserBlocked => {
                failed.push(FailedDependencyEntry {
                    sequence: event.sequence,
                    request_id: req_id,
                    category: FailedDependencyCategory::BrowserBlocked,
                    status_code: None,
                    origin: ctx.and_then(|c| c.origin),
                    endpoint_path: ctx.and_then(|c| c.endpoint_path),
                    resource_type: ctx.and_then(|c| c.resource_type),
                    initiator_type: ctx.and_then(|c| c.initiator_type),
                    policy_reason: None,
                });
            }
            BrowserEventDetail::PolicyBlocked {
                origin,
                endpoint_path,
            } => {
                failed.push(FailedDependencyEntry {
                    sequence: event.sequence,
                    request_id: req_id,
                    category: FailedDependencyCategory::PolicyBlocked,
                    status_code: None,
                    origin: origin.as_deref().or_else(|| ctx.and_then(|c| c.origin)),
                    endpoint_path: endpoint_path
                        .as_deref()
                        .or_else(|| ctx.and_then(|c| c.endpoint_path)),
                    resource_type: ctx.and_then(|c| c.resource_type),
                    initiator_type: ctx.and_then(|c| c.initiator_type),
                    policy_reason: None,
                });
            }
            _ => {}
        }
    }

    failed
}

fn matches_failed_dependency_filter(
    entry: &FailedDependencyEntry<'_>,
    filter: &FailedDependencyFilter<'_>,
) -> bool {
    if let Some(cat) = filter.category
        && entry.category != cat
    {
        return false;
    }
    if let Some(needle) = filter.origin_contains {
        let Some(origin) = entry.origin else {
            return false;
        };
        if !origin
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
        {
            return false;
        }
    }
    if let Some(needle) = filter.path_contains {
        let Some(path) = entry.endpoint_path else {
            return false;
        };
        if !path
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
        {
            return false;
        }
    }
    if let Some(expected_type) = filter.resource_type {
        let Some(actual) = entry.resource_type else {
            return false;
        };
        if !actual.eq_ignore_ascii_case(expected_type) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AuditTarget, BrowserEvidence, RequestHop, TargetPolicy};

    fn sample_snapshot() -> EvidenceSnapshot {
        EvidenceSnapshot {
            target: AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::Captured {
                data: BrowserEvidence::default(),
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        }
    }

    #[test]
    fn queries_retained_events_and_validates_citations_against_the_supplied_page() {
        let mut snapshot = sample_snapshot();
        assert!(query_browser_timeline(&snapshot, 0).is_none());
        let mut timeline = BrowserTimeline {
            events: Vec::new(),
            truncated: false,
            end: TimelineEnd::ObservationEnded,
        };
        let CollectorOutcome::Captured { data } = &mut snapshot.browser else {
            panic!("expected captured browser evidence");
        };
        data.timeline = Some(timeline.clone());
        assert_eq!(
            query_browser_timeline(&snapshot, 0).unwrap().events.len(),
            0
        );

        timeline.events = (1..=17)
            .map(|sequence| BrowserTimelineEvent {
                sequence,
                time: None,
                request: None,
                frame: None,
                loader: None,
                detail: BrowserEventDetail::NetworkFailure,
            })
            .collect();
        snapshot.browser = CollectorOutcome::Partial {
            data: BrowserEvidence {
                timeline: Some(timeline),
                ..BrowserEvidence::default()
            },
            warnings: vec!["fixture warning".to_owned()],
        };
        let page = query_browser_timeline(&snapshot, 0).unwrap();
        assert!(page.browser_partial);
        assert_eq!(page.next_offset, Some(16));
        assert_eq!(
            query_browser_timeline(&snapshot, 16).unwrap().events[0].sequence,
            17
        );
        assert_eq!(cited_event_refs(&snapshot, &[1, 1, 17, 100]).len(), 1);
    }

    #[test]
    fn filtered_timeline_preserves_skipped_failed_and_unavailable_status() {
        let mut snapshot = sample_snapshot();
        snapshot.browser = CollectorOutcome::Skipped {
            reason: "not collected".to_owned(),
        };
        let skipped =
            query_browser_timeline_filtered(&snapshot, &BrowserTimelineFilter::default(), 0);
        assert_eq!(
            skipped.status,
            EvidenceQueryStatus::Skipped {
                reason: "not collected".to_owned()
            }
        );

        snapshot.browser = CollectorOutcome::Failed {
            error: "chromium timeout".to_owned(),
        };
        let failed =
            query_browser_timeline_filtered(&snapshot, &BrowserTimelineFilter::default(), 0);
        assert_eq!(
            failed.status,
            EvidenceQueryStatus::Failed {
                error: "chromium timeout".to_owned()
            }
        );

        snapshot.browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                timeline: None,
                ..BrowserEvidence::default()
            },
        };
        let unavailable =
            query_browser_timeline_filtered(&snapshot, &BrowserTimelineFilter::default(), 0);
        assert_eq!(
            unavailable.status,
            EvidenceQueryStatus::Unavailable {
                reason: "browser timeline was not captured".to_owned()
            }
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reconstructs_redirect_and_failure_request_chains_and_validates_chain_citations() {
        let timeline = BrowserTimeline {
            events: vec![
                BrowserTimelineEvent {
                    sequence: 1,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-1".to_owned(),
                        hop: Some(0),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::RequestStarted {
                        method: Some("GET".to_owned()),
                        origin: Some("https://example.org".to_owned()),
                        endpoint_path: Some("/start".to_owned()),
                        resource_type: Some("document".to_owned()),
                        initiator_type: Some("other".to_owned()),
                    },
                },
                BrowserTimelineEvent {
                    sequence: 2,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-1".to_owned(),
                        hop: Some(0),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::Redirect {
                        status: Some(302),
                        origin: Some("https://example.org".to_owned()),
                        endpoint_path: Some("/start".to_owned()),
                    },
                },
                BrowserTimelineEvent {
                    sequence: 18,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-1".to_owned(),
                        hop: Some(1),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::Response {
                        status: Some(200),
                        origin: Some("https://cdn.example.org".to_owned()),
                        endpoint_path: Some("/final".to_owned()),
                        mime_type: Some("text/html".to_owned()),
                        cache_source: None,
                        timing: None,
                    },
                },
                BrowserTimelineEvent {
                    sequence: 19,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-1".to_owned(),
                        hop: Some(1),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::Completed {
                        encoded_bytes: Some(4096),
                    },
                },
                BrowserTimelineEvent {
                    sequence: 20,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-2".to_owned(),
                        hop: Some(0),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::RequestStarted {
                        method: Some("POST".to_owned()),
                        origin: Some("https://api.example.org".to_owned()),
                        endpoint_path: Some("/v1/items".to_owned()),
                        resource_type: Some("xhr".to_owned()),
                        initiator_type: Some("script".to_owned()),
                    },
                },
                BrowserTimelineEvent {
                    sequence: 21,
                    time: None,
                    request: Some(RequestHop {
                        id: "req-2".to_owned(),
                        hop: Some(0),
                    }),
                    frame: None,
                    loader: None,
                    detail: BrowserEventDetail::PolicyBlocked {
                        origin: Some("https://api.example.org".to_owned()),
                        endpoint_path: Some("/v1/items".to_owned()),
                    },
                },
            ],
            truncated: false,
            end: TimelineEnd::ObservationEnded,
        };

        let mut snapshot = sample_snapshot();
        snapshot.browser = CollectorOutcome::Captured {
            data: BrowserEvidence {
                timeline: Some(timeline),
                ..BrowserEvidence::default()
            },
        };

        let all_chains = query_request_chains(&snapshot, &RequestChainFilter::default(), 0);
        assert_eq!(all_chains.status, EvidenceQueryStatus::Captured);
        assert_eq!(all_chains.total_matching, 2);
        assert_eq!(all_chains.chains[0].request_id, "req-1");
        assert_eq!(all_chains.chains[0].redirect_hops, 1);
        assert_eq!(
            all_chains.chains[0].origins,
            vec!["https://example.org", "https://cdn.example.org"]
        );
        assert_eq!(all_chains.chains[0].final_status, Some(200));
        assert_eq!(all_chains.chains[0].encoded_bytes, Some(4096));
        assert_eq!(all_chains.chains[0].outcome, RequestChainOutcome::Completed);
        assert_eq!(all_chains.chains[0].sequences, vec![1, 2, 18, 19]);

        assert_eq!(all_chains.chains[1].request_id, "req-2");
        assert_eq!(
            all_chains.chains[1].outcome,
            RequestChainOutcome::PolicyBlocked
        );

        let failed_only = query_request_chains(
            &snapshot,
            &RequestChainFilter {
                only_failures: true,
                ..RequestChainFilter::default()
            },
            0,
        );
        assert_eq!(failed_only.total_matching, 1);
        assert_eq!(failed_only.chains[0].request_id, "req-2");

        let refs = cited_chain_event_refs(&snapshot, &[2, 18, 999]);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].detail, "timeline-event=2");
        assert_eq!(refs[1].detail, "timeline-event=18");
    }
}
