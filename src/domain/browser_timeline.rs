//! Session-scoped browser event observations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Recorded events and their collection boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserTimeline {
    /// Events in collector receive order.
    pub events: Vec<BrowserTimelineEvent>,
    /// Whether the event cap discarded later observations.
    pub truncated: bool,
    /// Why observation ended.
    pub end: TimelineEnd,
}

/// The observed end of a browser timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEnd {
    /// The collector reached its normal snapshot boundary.
    ObservationEnded,
    /// Page load did not complete within the navigation deadline.
    LoadTimedOut,
}

/// Session-local identity shared by events from one request hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RequestHop {
    /// Browser protocol request identifier.
    pub id: String,
    /// Zero-based redirect hop, unavailable when the start was not observed.
    pub hop: Option<u32>,
}

/// A protocol timestamp with its original clock domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "clock", content = "microseconds", rename_all = "snake_case")]
pub enum BrowserEventTime {
    /// CDP monotonic clock.
    Monotonic(u64),
    /// CDP Unix epoch clock.
    Unix(u64),
}

/// One browser observation in the shared receive sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserTimelineEvent {
    /// One-based position in the captured event sequence.
    pub sequence: u32,
    /// Browser-provided time, where available.
    pub time: Option<BrowserEventTime>,
    /// Request hop where the protocol provides a request identity.
    pub request: Option<RequestHop>,
    /// CDP frame identifier, where provided.
    pub frame: Option<String>,
    /// CDP document loader identifier, where provided.
    pub loader: Option<String>,
    /// Typed event details.
    #[serde(flatten)]
    pub detail: BrowserEventDetail,
}

/// Runtime classifications shared by the timeline producer and consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineRuntimeKind {
    /// An error-level console message.
    ConsoleError,
    /// An uncaught script exception.
    UncaughtException,
    /// An unhandled promise rejection.
    UnhandledRejection,
    /// A console diagnostic classified as a CSP violation.
    CspViolation,
}

/// Cache or wire source reported by Chromium for an HTTP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineCacheSource {
    /// Served over the network.
    Network,
    /// Served from the browser disk cache.
    DiskCache,
    /// Served or intercepted by a Service Worker.
    ServiceWorker,
    /// Served from the prefetch cache.
    PrefetchCache,
    /// Conditional request revalidated with HTTP 304 Not Modified.
    Revalidated304,
}

/// Non-negative connection and response timing phases in milliseconds from CDP `ResourceTiming`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimelinePhaseTimings {
    /// DNS lookup duration in milliseconds (`dnsEnd - dnsStart`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<u64>,
    /// TCP connection duration in milliseconds (`connectEnd - connectStart`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
    /// TLS handshake duration in milliseconds (`sslEnd - sslStart`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ms: Option<u64>,
    /// Request send duration in milliseconds (`sendEnd - sendStart`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_ms: Option<u64>,
    /// Time to first response header byte in milliseconds (`receiveHeadersEnd - sendEnd`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,
}

/// Protocol observations with separate HTTP and transport outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserEventDetail {
    /// The browser started a request.
    RequestStarted {
        /// HTTP method when retained.
        method: Option<String>,
        /// URL reduced to its origin.
        origin: Option<String>,
        /// Secret-safe normalised URL pathname without query string or fragment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_path: Option<String>,
        /// Lowercase CDP resource type (for example `"document"`, `"script"`, `"xhr"`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resource_type: Option<String>,
        /// Lowercase CDP initiator category (`"parser"`, `"script"`, `"preload"`, `"other"`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initiator_type: Option<String>,
    },
    /// CDP reported a redirect response and subsequently started another hop.
    Redirect {
        /// HTTP redirect status, where provided.
        status: Option<u16>,
        /// Redirecting response origin.
        origin: Option<String>,
        /// Secret-safe normalised URL pathname of the redirect source.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_path: Option<String>,
    },
    /// The browser received an HTTP response.
    Response {
        /// HTTP status, including client and server errors.
        status: Option<u16>,
        /// Response origin.
        origin: Option<String>,
        /// Secret-safe normalised URL pathname of the response.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_path: Option<String>,
        /// Response MIME type reported by Chromium.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        /// Cache or wire source for the response.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_source: Option<TimelineCacheSource>,
        /// Per-request connection and TTFB timing phases when reported by CDP.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TimelinePhaseTimings>,
    },
    /// The browser completed loading the resource.
    Completed {
        /// Encoded transfer size, when measured.
        encoded_bytes: Option<u64>,
    },
    /// A transport failure was reported.
    NetworkFailure,
    /// A load was cancelled.
    Cancelled,
    /// Chromium reported a browser-side block.
    BrowserBlocked,
    /// The collector rejected a request under its target policy.
    PolicyBlocked {
        /// Rejected request origin, where retained.
        origin: Option<String>,
        /// Secret-safe normalised URL pathname of the rejected request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint_path: Option<String>,
    },
    /// A runtime error was observed.
    RuntimeError {
        /// Category derived from the runtime event.
        category: TimelineRuntimeKind,
    },
}
