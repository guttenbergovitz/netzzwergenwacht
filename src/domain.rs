//! Core domain types and invariants for `NetzZwergenWacht`.
//!
//! This module stays strictly free of transport, browser, persistence, and LLM
//! concerns so all layers can share validated contracts without coupling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::{Host, Url};

use crate::brigade::DwarfId;

/// Policy governing whether private or loopback targets are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetPolicy {
    /// Reject loopback, link-local, and private network addresses (default).
    #[default]
    PublicOnly,
    /// Permit private/loopback targets (for explicit local testing only).
    AllowPrivate,
}

/// Supported target URL schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetScheme {
    /// Unencrypted HTTP (`http://`).
    Http,
    /// TLS-encrypted HTTPS (`https://`).
    Https,
}

/// Validation errors when constructing an [`AuditTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetError {
    /// The input URL was empty or whitespace-only.
    #[error("target URL must not be empty")]
    Empty,
    /// The URL could not be parsed according to RFC 3986.
    #[error("invalid target URL: {0}")]
    InvalidUrl(String),
    /// The URL did not use `http://` or `https://`.
    #[error("target URL must use http:// or https://")]
    UnsupportedScheme,
    /// The URL contained embedded username or password credentials.
    #[error("target URL must not contain embedded credentials")]
    EmbeddedCredentials,
    /// The URL authority did not contain a valid host.
    #[error("target URL must contain a non-empty host")]
    MissingHost,
    /// The target IP address is forbidden under [`TargetPolicy::PublicOnly`].
    #[error("target IP {0} is not permitted under PublicOnly policy")]
    ForbiddenIp(IpAddr),
}

/// Validated external audit target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct AuditTarget {
    url: String,
    scheme: TargetScheme,
    host: String,
    port: u16,
}

#[derive(Deserialize)]
struct RawAuditTarget {
    url: String,
}

impl<'de> Deserialize<'de> for AuditTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAuditTarget::deserialize(deserializer)?;
        Self::parse(&raw.url, TargetPolicy::AllowPrivate).map_err(serde::de::Error::custom)
    }
}

impl AuditTarget {
    /// Parses and validates an external HTTP(S) target URL under `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError`] if the URL is empty, malformed, uses a scheme
    /// other than `http`/`https`, contains embedded credentials, lacks a host,
    /// or resolves to a forbidden IP literal under [`TargetPolicy::PublicOnly`].
    pub fn parse(raw: &str, policy: TargetPolicy) -> Result<Self, TargetError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(TargetError::Empty);
        }

        let parsed = Url::parse(trimmed).map_err(|e| TargetError::InvalidUrl(e.to_string()))?;

        let scheme = match parsed.scheme() {
            "http" => TargetScheme::Http,
            "https" => TargetScheme::Https,
            _ => return Err(TargetError::UnsupportedScheme),
        };

        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(TargetError::EmbeddedCredentials);
        }

        let host = match parsed.host() {
            Some(Host::Domain(domain)) if !domain.is_empty() => domain.to_ascii_lowercase(),
            Some(Host::Ipv4(v4)) => {
                let ip = IpAddr::V4(v4);
                if policy == TargetPolicy::PublicOnly && is_forbidden_ip(ip) {
                    return Err(TargetError::ForbiddenIp(ip));
                }
                v4.to_string()
            }
            Some(Host::Ipv6(v6)) => {
                let ip = IpAddr::V6(v6);
                if policy == TargetPolicy::PublicOnly && is_forbidden_ip(ip) {
                    return Err(TargetError::ForbiddenIp(ip));
                }
                format!("[{v6}]")
            }
            _ => return Err(TargetError::MissingHost),
        };

        let port = parsed.port_or_known_default().unwrap_or(match scheme {
            TargetScheme::Http => 80,
            TargetScheme::Https => 443,
        });

        Ok(Self {
            url: parsed.into(),
            scheme,
            host,
            port,
        })
    }

    /// Returns the canonicalised URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Returns the validated URL scheme.
    #[must_use]
    pub const fn scheme(&self) -> TargetScheme {
        self.scheme
    }

    /// Returns the normalised target host (lowercased domain or IP literal).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the effective target port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Complete web origin `(scheme, host, effective_port)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Origin {
    /// Scheme (`http` or `https`).
    pub scheme: TargetScheme,
    /// Normalised host.
    pub host: String,
    /// Effective port (e.g. `80`, `443`, `8443`).
    pub port: u16,
}

impl Origin {
    /// Extracts the [`Origin`] of a validated [`AuditTarget`].
    #[must_use]
    pub fn from_target(target: &AuditTarget) -> Self {
        Self {
            scheme: target.scheme(),
            host: target.host().to_owned(),
            port: target.port(),
        }
    }

    /// Returns a canonical `scheme://host:port` string representation.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        let scheme = match self.scheme {
            TargetScheme::Http => "http",
            TargetScheme::Https => "https",
        };
        format!("{scheme}://{}:{}", self.host, self.port)
    }
}

/// Explicit investigation scope enforcing origin, additional origins, and SSRF policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InvestigationScope {
    /// Primary authorised origin.
    pub primary_origin: Origin,
    /// Explicitly authorised additional origins.
    #[serde(default)]
    pub additional_origins: Vec<Origin>,
    /// Network SSRF policy.
    pub policy: TargetPolicy,
    /// Whether third-party subresource requests are allowed during browser runs.
    pub allow_third_party_subresources: bool,
}

impl InvestigationScope {
    /// Builds a strict single-origin scope for `target`.
    #[must_use]
    pub fn for_target(target: &AuditTarget, policy: TargetPolicy) -> Self {
        Self {
            primary_origin: Origin::from_target(target),
            additional_origins: Vec::new(),
            policy,
            allow_third_party_subresources: true,
        }
    }

    /// Returns `true` if `candidate` matches `primary_origin` or an explicitly
    /// authorised additional origin.
    #[must_use]
    pub fn permits_target(&self, candidate: &AuditTarget) -> bool {
        let origin = Origin::from_target(candidate);
        origin == self.primary_origin || self.additional_origins.contains(&origin)
    }
}

/// Returns `true` if `ip` belongs to a loopback, private, link-local,
/// unspecified, CGNAT, or multicast range that must be blocked for SSRF defence.
#[must_use]
pub const fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6),
    }
}

const fn is_forbidden_ipv4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        // "This network" 0.0.0.0/8
        || octets[0] == 0
        // CGNAT 100.64.0.0/10
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
}

const fn is_forbidden_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }
    let segs = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        // Unique local addresses fc00::/7
        || (segs[0] & 0xfe00) == 0xfc00
        // Link-local fe80::/10
        || (segs[0] & 0xffc0) == 0xfe80
}

/// Explicit resource bounds governing an audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBudget {
    /// End-to-end deadline for the entire audit collection stage (including DNS and redirects).
    pub audit_timeout: Duration,
    /// Per-request HTTP timeout.
    pub http_timeout: Duration,
    /// Maximum number of HTTP redirects to follow.
    pub max_redirects: usize,
    /// Maximum response payload size in bytes.
    pub max_response_bytes: usize,
    /// Maximum concurrent collection tasks.
    pub max_concurrency: usize,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self {
            audit_timeout: Duration::from_secs(60),
            http_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_response_bytes: 10 * 1024 * 1024, // 10 MiB
            max_concurrency: 4,
        }
    }
}

/// Strongly typed rule identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RuleId(pub String);

/// Stable cross-run finding fingerprint for regression tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
pub struct FindingFingerprint(pub String);

impl FindingFingerprint {
    /// Computes a deterministic 64-bit FNV-1a hex fingerprint for a finding.
    #[must_use]
    pub fn compute(host: &str, rule_id: &RuleId, subject_detail: &str) -> Self {
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0100_0000_01b3;

        let mut hash = FNV_OFFSET_BASIS;
        for part in [
            host.as_bytes(),
            b"|",
            rule_id.0.as_bytes(),
            b"|",
            subject_detail.as_bytes(),
        ] {
            for &byte in part {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
        Self(format!("{hash:016x}"))
    }
}

/// Evidence capability level required or used by an observation or rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLevel {
    /// Level 1: HTTP responses and original HTML without JavaScript execution.
    Source,
    /// Level 2: Browser-rendered DOM, computed styles, accessibility tree, and layout.
    Rendered,
    /// Level 3: Controlled browser interaction, keyboard navigation, and focus management.
    Behavioural,
}

/// Epistemic classification of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// Verified by an exact deterministic rule over captured evidence.
    Deterministic,
    /// Pattern or threshold indicator with documented assumptions.
    Heuristic,
    /// Cross-domain correlation inferred from multiple findings.
    Inferred,
    /// Optional LLM-generated synthesis; never authoritative.
    AiInterpretation,
}

/// Logical audit domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// HTTP status, redirects, and endpoint reliability.
    Reliability,
    /// Transport security, headers, cookies, and authorised security checks.
    Security,
    /// Load timing, Core Web Vitals, and resource efficiency.
    Performance,
    /// Semantic HTML, heading hierarchy, and document integrity.
    Semantics,
    /// Machine-verifiable accessibility checks (never proof of legal compliance).
    Accessibility,
    /// Search metadata, structured data, and crawl directives.
    Seo,
    /// Text structure, readability metrics, and freshness signals.
    Content,
    /// Layout overflow, broken assets, and responsive integrity.
    Visual,
    /// Browser runtime, console errors, and failed subresource requests.
    Browser,
}

/// Finding severity levels.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational observation with no immediate risk.
    Info,
    /// Low-priority improvement opportunity.
    Low,
    /// Moderate issue affecting quality or posture.
    Medium,
    /// High-priority defect requiring prompt remediation.
    High,
    /// Critical reliability or security failure.
    Critical,
}

/// Confidence in a finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Indirect or heuristic signal.
    Low,
    /// Reliable signal with minor ambiguity.
    Medium,
    /// Direct, unambiguous evidence.
    High,
}

/// Typed measurement unit preventing stringly-typed unit drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementUnit {
    /// Duration in milliseconds.
    Milliseconds,
    /// Size in bytes.
    Bytes,
    /// Dimensionless integer count.
    Count,
}

/// Explicit representation of a measurement that never conflates failure with zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Measurement<T> {
    /// Successfully captured measurement with explicit unit.
    Measured {
        /// Measured value.
        value: T,
        /// Typed measurement unit.
        unit: MeasurementUnit,
    },
    /// Measurement could not be obtained (for example missing tool or unsupported target).
    Unavailable {
        /// Human-readable explanation of why the measurement was unavailable.
        reason: String,
    },
    /// Measurement collection attempted and failed.
    Failed {
        /// Error description.
        error: String,
    },
    /// Measurement was intentionally skipped (for example disabled by budget or policy).
    Skipped {
        /// Reason the check was skipped.
        reason: String,
    },
}

/// Typed source location within an [`EvidenceSnapshot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Final HTTP status code.
    HttpStatus,
    /// Final resolved URL after redirects.
    HttpFinalUrl,
    /// HTTP redirect chain.
    HttpRedirectChain,
    /// HTTP response headers.
    HttpHeaders,
    /// HTTP exchange timing measurement.
    HttpTiming,
    /// Raw or parsed HTTP response body / HTML document.
    HttpBody,
    /// TLS peer certificate metadata.
    TlsCertificate,
    /// Headless browser runtime events (console, failed requests).
    BrowserRuntime,
    /// Lighthouse performance report.
    LighthouseReport,
    /// axe-core rendered accessibility report.
    AxeReport,
    /// Browser viewport layout and visual asset observations.
    VisualLayout,
}

/// Reference linking a finding back to an artefact inside an [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceRef {
    /// Typed source within the snapshot.
    pub source: EvidenceSource,
    /// Specific observed detail or excerpt.
    pub detail: String,
}

impl EvidenceRef {
    /// Constructs a new [`EvidenceRef`].
    #[must_use]
    pub fn new(source: EvidenceSource, detail: impl Into<String>) -> Self {
        Self {
            source,
            detail: detail.into(),
        }
    }
}

/// Normalised audit finding emitted by a deterministic or heuristic analyser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// Stable cross-run fingerprint for regression diffing.
    #[serde(default)]
    pub fingerprint: FindingFingerprint,
    /// Stable rule identifier (for example `netz.http.status_error`).
    pub rule_id: RuleId,
    /// Audit domain category.
    pub category: FindingCategory,
    /// Evidence capability level used to produce this finding.
    pub evidence_level: EvidenceLevel,
    /// Epistemic classification.
    pub kind: FindingKind,
    /// Impact severity.
    pub severity: Severity,
    /// Confidence in the finding.
    pub confidence: Confidence,
    /// Concise human-readable title.
    pub title: String,
    /// Detailed explanation grounded in observed facts.
    pub summary: String,
    /// Traceability references into [`EvidenceSnapshot`].
    pub evidence_refs: Vec<EvidenceRef>,
    /// Optional actionable remediation guidance.
    pub remediation: Option<String>,
}

/// Execution status of an individual rule or check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckStatus {
    /// Check ran against valid evidence and passed.
    Passed {
        /// Rule identifier.
        rule_id: RuleId,
        /// Evidence level evaluated.
        evidence_level: EvidenceLevel,
    },
    /// Check ran against valid evidence and emitted one or more findings.
    Failed {
        /// Rule identifier.
        rule_id: RuleId,
        /// Evidence level evaluated.
        evidence_level: EvidenceLevel,
    },
    /// Check was skipped because required evidence was absent or disabled.
    Skipped {
        /// Rule identifier.
        rule_id: RuleId,
        /// Evidence level required.
        evidence_level: EvidenceLevel,
        /// Reason the check was skipped.
        reason: String,
    },
    /// Check could not be evaluated due to missing capability or tool.
    Unavailable {
        /// Rule identifier.
        rule_id: RuleId,
        /// Evidence level required.
        evidence_level: EvidenceLevel,
        /// Reason the check was unavailable.
        reason: String,
    },
}

/// Output produced by a single Zwerg analyser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalyserResult {
    /// Stable dwarf identifier.
    pub dwarf_id: DwarfId,
    /// Normalised findings produced by this analyser.
    pub findings: Vec<Finding>,
    /// Per-rule execution statuses.
    pub checks: Vec<CheckStatus>,
}

/// Single HTTP header observed in a response (name lowercased).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpHeader {
    /// Lowercased header name.
    pub name: String,
    /// Raw header value (lossy UTF-8 if non-ASCII).
    pub value: String,
}

/// Single redirect hop followed during HTTP collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RedirectHop {
    /// URL requested in this hop.
    pub from_url: String,
    /// HTTP redirect status code (for example `301`, `302`).
    pub status_code: u16,
    /// Resolved target URL from the `Location` header.
    pub to_url: String,
}

/// Evidence captured from a single bounded HTTP collection pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HttpEvidence {
    /// Final URL after following allowed redirects.
    pub final_url: String,
    /// HTTP status code of the final response.
    pub status_code: u16,
    /// Ordered redirect chain followed before the final response.
    pub redirect_chain: Vec<RedirectHop>,
    /// Response headers from the final response.
    pub headers: Vec<HttpHeader>,
    /// Total elapsed wall-clock time for the HTTP exchange.
    pub elapsed_ms: Measurement<u64>,
    /// Captured response body bytes count.
    pub body_bytes: usize,
    /// Whether the body was truncated at `ExecutionBudget::max_response_bytes`.
    pub body_truncated: bool,
    /// Lossy UTF-8 body text (empty if non-textual or truncated at 0).
    pub body_text: String,
}

impl HttpEvidence {
    /// Returns all header values matching `name` (ASCII case-insensitive).
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        let needle = name.to_ascii_lowercase();
        self.headers
            .iter()
            .filter(|h| h.name == needle)
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Returns the first header value matching `name` (ASCII case-insensitive).
    #[must_use]
    pub fn first_header_value(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|h| h.name == needle)
            .map(|h| h.value.as_str())
    }
}

/// TLS peer certificate evidence extracted from the `rustls` handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TlsEvidence {
    /// Subject distinguished name of the leaf certificate.
    pub subject: String,
    /// Issuer distinguished name of the leaf certificate.
    pub issuer: String,
    /// Certificate `notAfter` timestamp in seconds since the Unix epoch.
    pub not_after_unix_secs: i64,
    /// Signed days remaining until expiry (negative when already expired).
    pub days_until_expiry: i64,
}

/// Outcome of an individual collector stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CollectorOutcome<T> {
    /// Collection completed within budget.
    Captured {
        /// Captured artefact.
        data: T,
    },
    /// Collection partially succeeded (for example payload truncated at budget cap).
    Partial {
        /// Partially captured artefact.
        data: T,
        /// Warnings explaining what was truncated or degraded.
        warnings: Vec<String>,
    },
    /// Collection failed; downstream analysers must treat evidence as absent.
    Failed {
        /// Failure reason.
        error: String,
    },
    /// Collection was skipped by configuration or policy.
    Skipped {
        /// Reason collection was skipped.
        reason: String,
    },
}

impl<T> Default for CollectorOutcome<T> {
    fn default() -> Self {
        Self::Skipped {
            reason: "not collected".to_owned(),
        }
    }
}

impl<T> CollectorOutcome<T> {
    /// Returns a compact `(state, detail)` summary without cloning the payload.
    #[must_use]
    pub fn status_summary(&self) -> (&'static str, Option<String>) {
        match self {
            Self::Captured { .. } => ("captured", None),
            Self::Partial { warnings, .. } => ("partial", Some(warnings.join("; "))),
            Self::Failed { error } => ("failed", Some(error.clone())),
            Self::Skipped { reason } => ("skipped", Some(reason.clone())),
        }
    }
}

/// JavaScript console error or runtime exception observed during Level 2 browser execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ConsoleErrorEvent {
    /// Console severity level (for example `"error"`, `"exception"`).
    pub level: String,
    /// Console message text or sanitised exception description.
    pub text: String,
    /// Classified error kind (`"uncaught_exception"`, `"unhandled_rejection"`, `"csp_violation"`, `"console_error"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Source script or document URL where the error originated, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// 1-based line number in `source_url`, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

/// Subresource request failure observed during Level 2 browser execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FailedNetworkRequest {
    /// Requested subresource URL.
    pub url: String,
    /// Failure description or error text.
    pub error_text: String,
    /// Optional HTTP status code if a response was received.
    pub status_code: Option<u16>,
}

/// Broken image observed in the rendered DOM (`naturalWidth == 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrokenImageObs {
    /// Image `src` attribute or resolved URL.
    pub src: String,
    /// Rendered `naturalWidth` (0 indicates broken/unloaded image).
    pub natural_width: u64,
}

/// Layout and visual integrity observations for a single browser viewport.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ViewportLayoutObs {
    /// Logical viewport label (for example `"mobile"`, `"desktop"`).
    pub viewport_name: String,
    /// Viewport width in CSS pixels.
    pub width: u32,
    /// Viewport height in CSS pixels.
    pub height: u32,
    /// Whether `document.documentElement.scrollWidth > window.innerWidth`.
    pub has_horizontal_overflow: bool,
    /// Images that failed to decode or load in this viewport.
    pub broken_images: Vec<BrokenImageObs>,
    /// Count of sampled visible text nodes with computed `font-size < 12px`.
    #[serde(default)]
    pub small_text_nodes: usize,
    /// Count of visible interactive elements smaller than `44x44` CSS px.
    #[serde(default)]
    pub small_tap_targets: usize,
    /// Count of visible interactive controls positioned outside the horizontal viewport.
    #[serde(default)]
    pub offscreen_controls: usize,
    /// Percentage (`0..=100`) of viewport height covered by top fixed/sticky bars.
    #[serde(default)]
    pub fixed_header_height_pct: u8,
    /// Optional path to a captured screenshot artefact.
    pub screenshot_path: Option<String>,
}

/// Network resource timing and HTTP header observation from Level 2 browser execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceTimingObs {
    /// Requested resource URL.
    pub url: String,
    /// Initiator or CDP resource type (for example `"script"`, `"stylesheet"`, `"image"`, `"font"`).
    pub resource_type: String,
    /// CDP request identifier for waterfall correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Initiator category (`"parser"`, `"script"`, `"preload"`, `"other"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_type: Option<String>,
    /// Initiator script or document URL, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator_url: Option<String>,
    /// Request start offset in milliseconds relative to navigation start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time_ms: Option<u64>,
    /// Observed HTTP status code from response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Initial browser fetch priority (for example `"VeryHigh"`, `"High"`, `"Low"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    /// Observed MIME type from response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Encoded transfer size in bytes when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_size: Option<u64>,
    /// Resource load duration in milliseconds when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Negotiated protocol (for example `"h2"`, `"h3"`, `"http/1.1"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Observed `Cache-Control` response header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
    /// Observed `Content-Encoding` response header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

/// Rendered image geometry and loading state captured in the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedImageObs {
    /// Resolved `currentSrc` or `src` attribute.
    pub src: String,
    /// Intrinsic image width in pixels.
    pub natural_width: u64,
    /// Intrinsic image height in pixels.
    pub natural_height: u64,
    /// Rendered CSS layout box width in pixels.
    pub rendered_width: u64,
    /// Rendered CSS layout box height in pixels.
    pub rendered_height: u64,
    /// Whether the image intersects the initial desktop viewport.
    pub in_initial_viewport: bool,
    /// Explicit `loading` attribute (`"lazy"` / `"eager"`), if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loading: Option<String>,
}

/// Summary of the Level 2 browser Accessibility Tree (`Accessibility.getFullAXTree`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AccessibilityTreeSummary {
    /// Total accessibility nodes inspected (up to collector sampling limit).
    pub total_nodes: usize,
    /// Number of nodes marked `ignored` in the accessibility tree.
    pub ignored_nodes: usize,
    /// Interactive nodes (button, link, textbox, etc.) with an empty accessible name.
    pub interactive_without_name: usize,
    /// Focusable nodes inside an ignored (`aria-hidden` / `display:none`) subtree.
    pub hidden_focusable_count: usize,
    /// Whether the accessibility tree exceeded the collector sampling cap.
    pub truncated: bool,
}

/// Level 2 navigation timing, LCP, CLS, and Long Task telemetry from the browser runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PerformanceRuntimeObs {
    /// DNS lookup duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_ms: Option<u64>,
    /// TCP connection establishment duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_ms: Option<u64>,
    /// TLS negotiation duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ms: Option<u64>,
    /// Time to first byte in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttfb_ms: Option<u64>,
    /// Response download duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_ms: Option<u64>,
    /// `domInteractive` timestamp in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dom_interactive_ms: Option<u64>,
    /// `domContentLoadedEventEnd` timestamp in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dom_content_loaded_ms: Option<u64>,
    /// `loadEventEnd` timestamp in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load_event_ms: Option<u64>,
    /// Largest Contentful Paint in milliseconds from `PerformanceObserver`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lcp_ms: Option<u64>,
    /// Tag/selector summary of the LCP element, if observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lcp_element: Option<String>,
    /// Resource URL of the LCP element, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lcp_url: Option<String>,
    /// Cumulative Layout Shift expressed in integer thousandths (for example `150` = `0.150`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cls_thousandths: Option<u64>,
    /// Number of layout shift entries without recent input.
    pub layout_shift_count: usize,
    /// Number of main-thread long tasks (`> 50ms`).
    pub long_task_count: usize,
    /// Total duration of observed long tasks in milliseconds.
    pub long_task_total_ms: u64,
    /// Maximum single long task duration in milliseconds.
    pub max_long_task_ms: u64,
}

/// Level 2 client-side storage and cookie count summary (counts only, never values).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PrivacyStorageSummary {
    /// Number of keys in `window.localStorage` observed on load.
    pub local_storage_keys: usize,
    /// Number of keys in `window.sessionStorage` observed on load.
    pub session_storage_keys: usize,
    /// Number of cookies visible to `document.cookie`.
    pub document_cookie_count: usize,
}

/// Level 2 browser runtime and visual layout evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct BrowserEvidence {
    /// Final URL after client-side navigation.
    pub final_url: String,
    /// Browser version string if recorded.
    pub browser_version: Option<String>,
    /// Console error events emitted during navigation.
    pub console_errors: Vec<ConsoleErrorEvent>,
    /// Failed subresource network requests.
    pub failed_requests: Vec<FailedNetworkRequest>,
    /// Per-viewport layout and broken-asset observations.
    pub viewports: Vec<ViewportLayoutObs>,
    /// Captured subresource network timings, transfer sizes, and response headers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceTimingObs>,
    /// Whether `resources` was truncated due to collector sampling limits.
    #[serde(default)]
    pub resources_truncated: bool,
    /// Rendered image geometry and viewport intersection observations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rendered_images: Vec<RenderedImageObs>,
    /// Whether `rendered_images` was truncated due to collector sampling limits.
    #[serde(default)]
    pub rendered_images_truncated: bool,
    /// Total element count in the rendered DOM (`document.querySelectorAll('*').length`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_dom_elements: Option<usize>,
    /// Hydration mismatch errors/warnings captured from the browser console.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hydration_errors: Vec<String>,
    /// Visible word count extracted from rendered `document.body.innerText`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rendered_word_count: Option<usize>,
    /// Level 2 Accessibility Tree summary (`Accessibility.getFullAXTree`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ax_tree: Option<AccessibilityTreeSummary>,
    /// Level 2 Navigation Timing, LCP, CLS, and Long Task telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance: Option<PerformanceRuntimeObs>,
    /// Level 2 client-side storage and cookie counts (without values).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_summary: Option<PrivacyStorageSummary>,
    /// Level 2 CDP JavaScript and CSS code coverage summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageSummary>,
    /// Measurement provenance (viewport, throttling profile, lab/field origin, timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<MeasurementProvenance>,
}

/// Level 2 CDP JavaScript and CSS rule/byte coverage summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct CoverageSummary {
    /// Total sampled JavaScript bytes across loaded scripts.
    pub js_total_bytes: u64,
    /// Executed JavaScript bytes during initial page load.
    pub js_used_bytes: u64,
    /// Total sampled CSS rule bytes across loaded stylesheets.
    pub css_total_bytes: u64,
    /// Matched CSS rule bytes during initial page load.
    pub css_used_bytes: u64,
    /// Number of scripts included in JS coverage sampling.
    pub js_scripts_sampled: usize,
    /// Number of CSS rule ranges sampled.
    pub css_rules_sampled: usize,
}

/// Execution provenance attached to Level 2 browser/lab measurements.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct MeasurementProvenance {
    /// Emulated or observed viewport (for example `"mobile"` or `"mobile (390x844), desktop (1280x720)"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewport: Option<String>,
    /// Network/CPU throttling profile (for example `"unthrottled"` or `"simulate"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttling_profile: Option<String>,
    /// Measurement origin (`"lab"` or `"field"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Capture timestamp (ISO-8601 when emitted by CDP/Lighthouse).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
}

/// Level 2 Core Web Vitals and performance metrics from Lighthouse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LighthouseMetrics {
    /// Recorded Lighthouse version.
    pub lighthouse_version: String,
    /// Largest Contentful Paint in milliseconds.
    pub lcp_ms: Measurement<u64>,
    /// Cumulative Layout Shift in thousandths (for example `120` = `0.120`).
    pub cls_milli: Measurement<u64>,
    /// First Contentful Paint in milliseconds.
    pub fcp_ms: Measurement<u64>,
    /// Total Blocking Time in milliseconds.
    pub tbt_ms: Measurement<u64>,
    /// Optional Lighthouse performance category score (`0..=100`).
    pub performance_score: Option<u8>,
    /// Measurement provenance (viewport, throttling profile, lab/field origin, timestamp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<MeasurementProvenance>,
}

/// Single accessibility violation reported by `axe-core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AxeViolation {
    /// Stable axe rule ID (for example `"color-contrast"`).
    pub id: String,
    /// Impact level (`"critical"`, `"serious"`, `"moderate"`, `"minor"`).
    pub impact: Option<String>,
    /// Short rule description.
    pub description: String,
    /// Reference documentation URL.
    pub help_url: String,
    /// Number of affected DOM nodes.
    pub nodes_count: usize,
}

/// Level 2 rendered-DOM accessibility evidence from `axe-core`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AxeEvidence {
    /// Recorded `axe-core` version.
    pub axe_version: String,
    /// Reported rule violations.
    pub violations: Vec<AxeViolation>,
    /// Number of passed rules.
    pub passes_count: usize,
    /// Number of rules requiring manual review.
    pub incomplete_count: usize,
}

/// Immutable snapshot of all collected evidence for a single target audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceSnapshot {
    /// Validated audit target.
    pub target: AuditTarget,
    /// Capture timestamp in seconds since the Unix epoch.
    pub captured_at_unix_secs: u64,
    /// HTTP collection outcome.
    pub http: CollectorOutcome<HttpEvidence>,
    /// TLS certificate collection outcome.
    pub tls: CollectorOutcome<TlsEvidence>,
    /// Level 2 browser runtime and visual layout outcome.
    #[serde(default)]
    pub browser: CollectorOutcome<BrowserEvidence>,
    /// Level 2 Lighthouse performance outcome.
    #[serde(default)]
    pub lighthouse: CollectorOutcome<LighthouseMetrics>,
    /// Level 2 axe-core accessibility outcome.
    #[serde(default)]
    pub axe: CollectorOutcome<AxeEvidence>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_https_target() {
        let target =
            AuditTarget::parse("https://Example.COM/path?x=1", TargetPolicy::PublicOnly).unwrap();
        assert_eq!(target.scheme(), TargetScheme::Https);
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.port(), 443);
        assert_eq!(target.as_str(), "https://example.com/path?x=1");
    }

    #[test]
    fn reject_invalid_scheme_credentials_or_empty_host() {
        assert_eq!(
            AuditTarget::parse("", TargetPolicy::PublicOnly),
            Err(TargetError::Empty)
        );
        assert_eq!(
            AuditTarget::parse("ftp://example.com", TargetPolicy::PublicOnly),
            Err(TargetError::UnsupportedScheme)
        );
        assert_eq!(
            AuditTarget::parse("https://user:pass@example.com", TargetPolicy::PublicOnly),
            Err(TargetError::EmbeddedCredentials)
        );
        assert!(matches!(
            AuditTarget::parse("https://:443/path", TargetPolicy::PublicOnly),
            Err(TargetError::InvalidUrl(_))
        ));
    }

    #[test]
    fn deserialise_rejects_invalid_audit_target() {
        let bad_json =
            r#"{"url":"ftp://evil.example/","scheme":"https","host":"evil.example","port":443}"#;
        let res: Result<AuditTarget, _> = serde_json::from_str(bad_json);
        assert!(res.is_err());

        let creds_json = r#"{"url":"https://user:pw@example.com/","scheme":"https","host":"example.com","port":443}"#;
        let res_creds: Result<AuditTarget, _> = serde_json::from_str(creds_json);
        assert!(res_creds.is_err());
    }

    #[test]
    fn public_only_blocks_private_loopback_and_link_local_ips() {
        let forbidden = [
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://172.16.5.4/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[fc00::1]/",
            "http://[::ffff:127.0.0.1]/",
        ];

        for raw in forbidden {
            let err = AuditTarget::parse(raw, TargetPolicy::PublicOnly).unwrap_err();
            assert!(
                matches!(err, TargetError::ForbiddenIp(_)),
                "expected ForbiddenIp for {raw}, got {err:?}"
            );
            assert!(
                AuditTarget::parse(raw, TargetPolicy::AllowPrivate).is_ok(),
                "AllowPrivate should permit {raw}"
            );
        }
    }

    #[test]
    fn measurement_keeps_failures_distinct_from_zero() {
        let ok: Measurement<u64> = Measurement::Measured {
            value: 0,
            unit: MeasurementUnit::Count,
        };
        let failed: Measurement<u64> = Measurement::Failed {
            error: "timeout".to_owned(),
        };
        assert_ne!(ok, failed);
    }

    #[test]
    fn fingerprint_is_deterministic_and_host_scoped() {
        assert_ne!(
            FindingFingerprint::compute("example.com", &RuleId("r1".to_owned()), "d1"),
            FindingFingerprint::compute("example.org", &RuleId("r1".to_owned()), "d1")
        );
        assert_eq!(
            FindingFingerprint::compute("example.com", &RuleId("r1".to_owned()), "d1"),
            FindingFingerprint::compute("example.com", &RuleId("r1".to_owned()), "d1")
        );
    }

    #[test]
    fn default_execution_budget_is_bounded() {
        let budget = ExecutionBudget::default();
        assert!(budget.max_concurrency > 0);
        assert!(budget.max_response_bytes > 0);
        assert!(budget.http_timeout > Duration::ZERO);
        assert!(budget.audit_timeout >= budget.http_timeout);
    }
}
