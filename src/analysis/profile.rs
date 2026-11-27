//! Optional, versioned Application Quality Profile (Phase II §7).
//!
//! Generic rule sets cannot determine whether a specific digital product meets
//! its own acceptance criteria. An [`ApplicationQualityProfile`] declares the
//! expected application kind, criticality, locales, critical pages, required
//! collectors, performance budgets, and explicit rule waivers.
//!
//! Absence of a profile never blocks exploratory auditing, but restricts
//! definitive product-acceptance claims.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::AuditReport;
use crate::analysis::assessment::{
    DomainVerdict, QualityAssessment, QualityDomain, assess_audit_report, domain_for_rule,
};
use crate::domain::Severity;

/// Supported profile schema version.
pub const PROFILE_SCHEMA_VERSION: &str = "1";

/// Errors produced when loading or validating an [`ApplicationQualityProfile`].
#[derive(Debug, Error)]
pub enum ProfileError {
    /// Underlying filesystem read failure.
    #[error("failed to read quality profile {path}: {source}")]
    Io {
        /// Profile path.
        path: String,
        /// I/O error.
        source: std::io::Error,
    },
    /// TOML deserialisation failure.
    #[error("invalid quality profile TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// Semantic validation failure.
    #[error("invalid quality profile: {0}")]
    Validation(String),
}

/// High-level architecture classification of the target application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
    /// Static website.
    Static,
    /// Server-side rendered application.
    Ssr,
    /// Client-side single-page application.
    Spa,
    /// Online store / checkout platform.
    Ecommerce,
    /// Content management driven website.
    Cms,
    /// General interactive web application.
    #[default]
    WebApp,
}

/// Business/operational criticality tier of the target application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityLevel {
    /// Low-risk informational property.
    Low,
    /// Standard production web property.
    #[default]
    Standard,
    /// High-visibility customer-facing product.
    High,
    /// Revenue-critical or regulated service.
    MissionCritical,
}

/// Laboratory performance thresholds declared by a product profile.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct PerformanceBudgets {
    /// Maximum acceptable Largest Contentful Paint (ms).
    pub max_lcp_ms: Option<u64>,
    /// Maximum acceptable Cumulative Layout Shift in thousandths (`100` = `0.100`).
    pub max_cls_milli: Option<u32>,
    /// Maximum acceptable Time To First Byte (ms).
    pub max_ttfb_ms: Option<u64>,
}

/// Documented exception waiving a specific diagnostic rule for a product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleWaiver {
    /// Rule identifier being waived (e.g. `sec.headers.csp`).
    pub rule_id: String,
    /// Justification recorded for auditability.
    pub reason: String,
    /// Approving role or stakeholder.
    pub approved_by: String,
}

/// Versioned Application Quality Profile (Phase II §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApplicationQualityProfile {
    /// Schema version (`"1"`).
    pub schema_version: String,
    /// Logical name of the product under assessment.
    pub application_name: String,
    /// Architectural kind.
    #[serde(default)]
    pub application_kind: ApplicationKind,
    /// Business criticality tier.
    #[serde(default)]
    pub criticality: CriticalityLevel,
    /// Expected BCP-47 locale tags (e.g. `["en", "de", "pl"]`).
    #[serde(default)]
    pub expected_locales: Vec<String>,
    /// Critical URL paths expected to be covered.
    #[serde(default)]
    pub critical_pages: Vec<String>,
    /// Collectors that must succeed (`"http"`, `"browser"`, `"lighthouse"`, `"axe"`).
    #[serde(default)]
    pub required_collectors: Vec<String>,
    /// Optional performance budgets.
    #[serde(default)]
    pub performance_budgets: Option<PerformanceBudgets>,
    /// Minimum inspected page coverage percentage (`0..=100`).
    #[serde(default)]
    pub min_coverage_percent: Option<u8>,
    /// Explicit rule waivers.
    #[serde(default)]
    pub waivers: Vec<RuleWaiver>,
    /// Maximum acceptable age of reused observations in seconds.
    #[serde(default)]
    pub max_observation_age_secs: Option<u64>,
}

impl ApplicationQualityProfile {
    /// Parses and validates an [`ApplicationQualityProfile`] from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Toml`] on syntax errors or [`ProfileError::Validation`]
    /// if required fields or bounds are invalid.
    pub fn from_toml_str(raw: &str) -> Result<Self, ProfileError> {
        let profile: Self = toml::from_str(raw)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Loads and validates an [`ApplicationQualityProfile`] from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Io`], [`ProfileError::Toml`], or [`ProfileError::Validation`].
    pub fn from_path(path: &Path) -> Result<Self, ProfileError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ProfileError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&raw)
    }

    /// Validates profile invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Validation`] when `schema_version`, `application_name`,
    /// `min_coverage_percent`, or a waiver is invalid.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::Validation(format!(
                "unsupported schema_version `{}` (expected `{PROFILE_SCHEMA_VERSION}`)",
                self.schema_version
            )));
        }
        if self.application_name.trim().is_empty() {
            return Err(ProfileError::Validation(
                "application_name must not be empty".to_owned(),
            ));
        }
        if let Some(pct) = self.min_coverage_percent
            && pct > 100
        {
            return Err(ProfileError::Validation(format!(
                "min_coverage_percent ({pct}) must be <= 100"
            )));
        }
        for waiver in &self.waivers {
            if waiver.rule_id.trim().is_empty() || waiver.reason.trim().is_empty() {
                return Err(ProfileError::Validation(
                    "rule waivers require non-empty rule_id and reason".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Evaluates `report` against an optional [`ApplicationQualityProfile`].
///
/// Exploratory audits (`profile == None`) remain supported, with an explicit
/// limitation noting that product-specific acceptance criteria were not supplied.
#[must_use]
pub fn assess_with_profile(
    report: &AuditReport,
    profile: Option<&ApplicationQualityProfile>,
) -> QualityAssessment {
    let mut assessment = assess_audit_report(report);
    let Some(profile) = profile else {
        assessment.limitations.push(
            "Exploratory audit only: no Application Quality Profile was supplied.".to_owned(),
        );
        return assessment;
    };

    apply_waivers(report, profile, &mut assessment);
    check_required_collectors(report, profile, &mut assessment);
    recompute_overall_verdict(&mut assessment);
    assessment
}

fn apply_waivers(
    report: &AuditReport,
    profile: &ApplicationQualityProfile,
    assessment: &mut QualityAssessment,
) {
    if profile.waivers.is_empty() {
        return;
    }
    let waived_rules: std::collections::HashSet<&str> =
        profile.waivers.iter().map(|w| w.rule_id.as_str()).collect();

    for dom in &mut assessment.domains {
        if dom.verdict != DomainVerdict::Fail {
            continue;
        }
        let unwaived_blocking = report
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter().map(move |f| (a.dwarf_id, f)))
            .filter(|(dwarf, f)| {
                f.severity >= Severity::High
                    && domain_for_rule(*dwarf, &f.rule_id.0) == dom.domain
                    && !waived_rules.contains(f.rule_id.0.as_str())
            })
            .count();
        if unwaived_blocking == 0 {
            dom.verdict = DomainVerdict::Waived;
            dom.rationale = format!(
                "{} critical/high finding(s) covered by documented profile waivers.",
                dom.critical_high_count
            );
            let prefix = format!("{}:", dom.domain.label());
            assessment.blockers.retain(|b| !b.starts_with(&prefix));
        }
    }
}

fn check_required_collectors(
    report: &AuditReport,
    profile: &ApplicationQualityProfile,
    assessment: &mut QualityAssessment,
) {
    for req in &profile.required_collectors {
        let name = req.trim().to_ascii_lowercase();
        if name.is_empty() || name == "http" {
            continue;
        }
        let captured = report
            .level2_collectors
            .iter()
            .any(|c| c.collector == name && c.state == "captured");
        if !captured {
            assessment.limitations.push(format!(
                "Profile `{}` requires collector `{name}`, which did not capture evidence.",
                profile.application_name
            ));
            if let Some(cov) = assessment
                .domains
                .iter_mut()
                .find(|d| d.domain == QualityDomain::EvidenceCoverage)
            {
                cov.verdict = DomainVerdict::InsufficientEvidence;
                cov.rationale = format!("Required collector `{name}` did not capture evidence.");
            }
        }
    }
}

fn recompute_overall_verdict(assessment: &mut QualityAssessment) {
    let any_fail = assessment
        .domains
        .iter()
        .any(|d| d.verdict == DomainVerdict::Fail);
    let any_insufficient = assessment
        .domains
        .iter()
        .any(|d| d.verdict == DomainVerdict::InsufficientEvidence);
    assessment.overall_verdict = if any_fail {
        DomainVerdict::Fail
    } else if any_insufficient {
        DomainVerdict::InsufficientEvidence
    } else {
        DomainVerdict::Pass
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::AuditSummary;
    use crate::brigade::DwarfId;
    use crate::domain::{
        AnalyserResult, AuditTarget, CheckStatus, CollectorOutcome, Confidence, EvidenceLevel,
        EvidenceRef, EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind,
        HttpEvidence, Measurement, MeasurementUnit, RuleId, TargetPolicy,
    };

    fn sample_report(findings: Vec<Finding>) -> AuditReport {
        AuditReport {
            schema_version: "0.2.0".to_owned(),
            target: AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly)
                .expect("target"),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.org/".to_owned(),
                    status_code: 200,
                    redirect_chain: Vec::new(),
                    headers: Vec::new(),
                    elapsed_ms: Measurement::Measured {
                        value: 10,
                        unit: MeasurementUnit::Milliseconds,
                    },
                    body_bytes: 0,
                    body_truncated: false,
                    body_text: String::new(),
                },
            },
            rendered_history: None,
            level2_collectors: Vec::new(),
            analysers: vec![AnalyserResult {
                dwarf_id: DwarfId::Sicherheits,
                findings,
                checks: vec![CheckStatus::Passed {
                    rule_id: RuleId("sec.headers.hsts".to_owned()),
                    evidence_level: EvidenceLevel::Source,
                }],
            }],
            summary: AuditSummary::default(),
            ai_synthesis: None,
        }
    }

    #[test]
    fn rejects_invalid_schema_version_and_coverage_bounds() {
        let bad_ver = r#"
            schema_version = "99"
            application_name = "Shop"
        "#;
        assert!(ApplicationQualityProfile::from_toml_str(bad_ver).is_err());

        let bad_cov = r#"
            schema_version = "1"
            application_name = "Shop"
            min_coverage_percent = 120
        "#;
        assert!(ApplicationQualityProfile::from_toml_str(bad_cov).is_err());
    }

    #[test]
    fn missing_required_collector_forces_insufficient_evidence() {
        let profile = ApplicationQualityProfile::from_toml_str(
            r#"
            schema_version = "1"
            application_name = "Storefront"
            application_kind = "ecommerce"
            criticality = "mission_critical"
            required_collectors = ["browser"]
        "#,
        )
        .expect("valid profile");

        let report = sample_report(Vec::new());
        let assessment = assess_with_profile(&report, Some(&profile));
        assert_eq!(
            assessment.overall_verdict,
            DomainVerdict::InsufficientEvidence
        );
        let cov = assessment
            .domains
            .iter()
            .find(|d| d.domain == QualityDomain::EvidenceCoverage)
            .expect("coverage domain");
        assert_eq!(cov.verdict, DomainVerdict::InsufficientEvidence);
    }

    #[test]
    fn documented_waiver_marks_domain_waived_without_hiding_counts() {
        let profile = ApplicationQualityProfile::from_toml_str(
            r#"
            schema_version = "1"
            application_name = "Legacy Portal"

            [[waivers]]
            rule_id = "sec.headers.csp"
            reason = "Legacy inline script migration scheduled for Q2"
            approved_by = "CISO"
        "#,
        )
        .expect("valid profile");

        let report = sample_report(vec![Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId("sec.headers.csp".to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Missing CSP".to_owned(),
            summary: "No CSP header".to_owned(),
            evidence_refs: vec![EvidenceRef::new(EvidenceSource::HttpHeaders, "csp=absent")],
            remediation: Some("Add CSP".to_owned()),
        }]);

        let assessment = assess_with_profile(&report, Some(&profile));
        let sec = assessment
            .domains
            .iter()
            .find(|d| d.domain == QualityDomain::SurfaceSecurity)
            .expect("security domain");
        assert_eq!(sec.verdict, DomainVerdict::Waived);
        assert_eq!(sec.critical_high_count, 1);
    }
}
