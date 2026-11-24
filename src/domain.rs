//! Core domain types and invariants for `NetzZwergenWacht`.

use std::fmt;
use std::time::Duration;

/// Validated external audit target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTarget {
    url: String,
    scheme: TargetScheme,
    host: String,
}

/// Supported target URL schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetScheme {
    /// Unencrypted HTTP (`http://`).
    Http,
    /// TLS-encrypted HTTPS (`https://`).
    Https,
}

/// Validation errors when constructing an [`AuditTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The input URL was empty or whitespace-only.
    Empty,
    /// The URL did not start with `http://` or `https://`.
    UnsupportedScheme,
    /// The URL authority did not contain a non-empty host.
    MissingHost,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "target URL must not be empty"),
            Self::UnsupportedScheme => write!(f, "target URL must start with http:// or https://"),
            Self::MissingHost => write!(f, "target URL must contain a non-empty host"),
        }
    }
}

impl std::error::Error for TargetError {}

impl AuditTarget {
    /// Parses and validates an external HTTP(S) target URL.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError`] if the URL is empty, uses a scheme other than
    /// `http://` or `https://`, or has an empty host component.
    pub fn parse(raw: &str) -> Result<Self, TargetError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(TargetError::Empty);
        }

        let (scheme, rest) = if let Some(rest) = trimmed.strip_prefix("https://") {
            (TargetScheme::Https, rest)
        } else if let Some(rest) = trimmed.strip_prefix("http://") {
            (TargetScheme::Http, rest)
        } else {
            return Err(TargetError::UnsupportedScheme);
        };

        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.split(':').next().unwrap_or("").trim();
        if host.is_empty() {
            return Err(TargetError::MissingHost);
        }

        Ok(Self {
            url: trimmed.to_owned(),
            scheme,
            host: host.to_ascii_lowercase(),
        })
    }

    /// Returns the canonicalised raw URL string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    /// Returns the validated URL scheme.
    #[must_use]
    pub const fn scheme(&self) -> TargetScheme {
        self.scheme
    }

    /// Returns the lowercased target hostname.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Explicit resource bounds governing an audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
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
            http_timeout: Duration::from_secs(30),
            max_redirects: 5,
            max_response_bytes: 10 * 1024 * 1024, // 10 MiB
            max_concurrency: 4,
        }
    }
}

/// Strongly typed rule identifier paired with a semantic rule version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(pub String);

/// Epistemic classification of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Logical audit domain (preserving Zwerg domain ownership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    /// HTTP status, redirects, and browser network/console reliability.
    Reliability,
    /// Transport security, headers, cookies, and authorised security checks.
    Security,
    /// Load timing, Core Web Vitals, and resource efficiency.
    Performance,
    /// Machine-verifiable accessibility checks (never proof of legal compliance).
    Accessibility,
    /// Search metadata, structured data, and crawl directives.
    Seo,
    /// Text structure, readability metrics, and freshness signals.
    Content,
    /// Layout overflow, broken assets, and responsive integrity.
    Visual,
}

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Indirect or heuristic signal.
    Low,
    /// Reliable signal with minor ambiguity.
    Medium,
    /// Direct, unambiguous evidence.
    High,
}

/// Explicit representation of a measurement that never conflates failure with zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measurement<T> {
    /// Successfully captured measurement with explicit unit.
    Measured {
        /// Measured value.
        value: T,
        /// Measurement unit (for example `"ms"`, `"bytes"`, `"count"`).
        unit: &'static str,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_https_target() {
        let target = AuditTarget::parse("https://Example.COM/path?x=1").expect("valid URL");
        assert_eq!(target.scheme(), TargetScheme::Https);
        assert_eq!(target.host(), "example.com");
        assert_eq!(target.as_str(), "https://Example.COM/path?x=1");
    }

    #[test]
    fn reject_invalid_scheme_or_empty_host() {
        assert_eq!(AuditTarget::parse(""), Err(TargetError::Empty));
        assert_eq!(
            AuditTarget::parse("ftp://example.com"),
            Err(TargetError::UnsupportedScheme)
        );
        assert_eq!(
            AuditTarget::parse("https:///path"),
            Err(TargetError::MissingHost)
        );
    }

    #[test]
    fn measurement_keeps_failures_distinct_from_zero() {
        let ok: Measurement<u64> = Measurement::Measured {
            value: 0,
            unit: "count",
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
    }
}
