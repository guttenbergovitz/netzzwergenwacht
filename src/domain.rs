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
    Http,
    Https,
}

/// Validation errors when constructing an [`AuditTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    UnsupportedScheme,
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

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.url
    }

    #[must_use]
    pub const fn scheme(&self) -> TargetScheme {
        self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// Explicit resource bounds governing an audit run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub http_timeout: Duration,
    pub max_redirects: usize,
    pub max_response_bytes: usize,
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
    Deterministic,
    Heuristic,
    Inferred,
    AiInterpretation,
}

/// Logical audit domain (preserving Zwerg domain ownership).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingCategory {
    Reliability,
    Security,
    Performance,
    Accessibility,
    Seo,
    Content,
    Visual,
}

/// Finding severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence in a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Explicit representation of a measurement that never conflates failure with zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measurement<T> {
    Measured { value: T, unit: &'static str },
    Unavailable { reason: String },
    Failed { error: String },
    Skipped { reason: String },
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
