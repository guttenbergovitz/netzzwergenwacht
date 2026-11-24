//! Core domain types and invariants for `NetzZwergenWacht`.
//!
//! This module stays strictly free of transport, browser, persistence, and LLM
//! concerns so all layers can share validated contracts without coupling.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::{Host, Url};

use crate::brigade::DwarfId;

/// Policy governing whether private or loopback targets are permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetPolicy {
    /// Reject loopback, link-local, and private network addresses (default).
    #[default]
    PublicOnly,
    /// Permit private/loopback targets (for explicit local testing only).
    AllowPrivate,
}

/// Supported target URL schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

/// Evidence capability level required or used by an observation or rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// Reference linking a finding back to an artefact inside an [`EvidenceSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyserResult {
    /// Stable dwarf identifier.
    pub dwarf_id: DwarfId,
    /// Normalised findings produced by this analyser.
    pub findings: Vec<Finding>,
    /// Per-rule execution statuses.
    pub checks: Vec<CheckStatus>,
}

/// Single HTTP header observed in a response (name lowercased).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    /// Lowercased header name.
    pub name: String,
    /// Raw header value (lossy UTF-8 if non-ASCII).
    pub value: String,
}

/// Single redirect hop followed during HTTP collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedirectHop {
    /// URL requested in this hop.
    pub from_url: String,
    /// HTTP redirect status code (for example `301`, `302`).
    pub status_code: u16,
    /// Resolved target URL from the `Location` header.
    pub to_url: String,
}

/// Evidence captured from a single bounded HTTP collection pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Outcome of an individual collector stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Immutable snapshot of all collected evidence for a single target audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSnapshot {
    /// Validated audit target.
    pub target: AuditTarget,
    /// Capture timestamp in seconds since the Unix epoch.
    pub captured_at_unix_secs: u64,
    /// HTTP collection outcome.
    pub http: CollectorOutcome<HttpEvidence>,
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
    fn default_execution_budget_is_bounded() {
        let budget = ExecutionBudget::default();
        assert!(budget.max_concurrency > 0);
        assert!(budget.max_response_bytes > 0);
        assert!(budget.http_timeout > Duration::ZERO);
        assert!(budget.audit_timeout >= budget.http_timeout);
    }
}
