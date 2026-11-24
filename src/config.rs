//! TOML configuration loading and policy quality-gate evaluation.

use std::fs;
use std::path::Path;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::AuditReport;
use crate::domain::{CollectorOutcome, ExecutionBudget, Severity, TargetPolicy};

/// Errors returned when loading or validating an [`AppConfig`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Failed to read configuration file.
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// Failed to parse TOML syntax or fields.
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
}

/// Top-level application configuration loaded from TOML.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    /// Resource governance limits.
    pub budget: BudgetConfig,
    /// Audit policy and CI quality-gate thresholds.
    pub policy: PolicyConfig,
}

impl AppConfig {
    /// Loads and parses an [`AppConfig`] from a TOML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read or contains invalid TOML.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }

    /// Converts [`BudgetConfig`] into a validated [`ExecutionBudget`].
    #[must_use]
    pub fn execution_budget(&self) -> ExecutionBudget {
        let defaults = ExecutionBudget::default();
        ExecutionBudget {
            audit_timeout: Duration::from_secs(
                self.budget
                    .audit_timeout_secs
                    .unwrap_or(defaults.audit_timeout.as_secs())
                    .max(1),
            ),
            http_timeout: Duration::from_secs(
                self.budget
                    .http_timeout_secs
                    .unwrap_or(defaults.http_timeout.as_secs())
                    .max(1),
            ),
            max_redirects: self.budget.max_redirects.unwrap_or(defaults.max_redirects),
            max_response_bytes: self
                .budget
                .max_response_bytes
                .unwrap_or(defaults.max_response_bytes)
                .max(1),
            max_concurrency: self
                .budget
                .max_concurrency
                .unwrap_or(defaults.max_concurrency)
                .max(1),
        }
    }

    /// Returns the effective [`TargetPolicy`].
    #[must_use]
    pub const fn target_policy(&self) -> TargetPolicy {
        if self.policy.allow_private {
            TargetPolicy::AllowPrivate
        } else {
            TargetPolicy::PublicOnly
        }
    }
}

/// Resource budget configuration section (`[budget]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BudgetConfig {
    /// End-to-end collection deadline in seconds.
    pub audit_timeout_secs: Option<u64>,
    /// Per-request HTTP timeout in seconds.
    pub http_timeout_secs: Option<u64>,
    /// Maximum HTTP redirects to follow.
    pub max_redirects: Option<usize>,
    /// Maximum response payload bytes.
    pub max_response_bytes: Option<usize>,
    /// Maximum concurrent targets in batch mode.
    pub max_concurrency: Option<usize>,
}

/// Policy quality-gate thresholds (`[policy]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Fail quality gate if any finding has severity `>= fail_on_severity`.
    pub fail_on_severity: Option<Severity>,
    /// Maximum allowed critical findings before failing.
    pub max_critical: Option<usize>,
    /// Maximum allowed high findings before failing.
    pub max_high: Option<usize>,
    /// Permit private/loopback targets (for local testing only).
    pub allow_private: bool,
    /// Optional Level 2 collectors (`"browser"`, `"lighthouse"`, `"axe"`) that must
    /// produce `"captured"` evidence for the quality gate to pass.
    pub require_collectors: Vec<String>,
}

/// Result of evaluating an [`AuditReport`] against a [`PolicyConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyEvaluation {
    /// Whether the audit satisfied all configured policy gates.
    pub passed: bool,
    /// Human-readable gate violations when `passed` is `false`.
    pub violations: Vec<String>,
}

/// Evaluates `report` against `policy`.
///
/// When no explicit threshold (`fail_on_severity`, `max_critical`, `max_high`)
/// is configured, any finding of `Low` or higher severity (or `Partial`
/// collection) fails the gate.
#[must_use]
pub fn evaluate_policy(report: &AuditReport, policy: &PolicyConfig) -> PolicyEvaluation {
    let mut violations = Vec::new();

    if matches!(report.http, CollectorOutcome::Failed { .. }) {
        violations.push("HTTP collection failed".to_owned());
    } else if matches!(report.http, CollectorOutcome::Skipped { .. }) {
        violations.push("HTTP collection was skipped".to_owned());
    } else if matches!(report.http, CollectorOutcome::Partial { .. }) {
        violations.push("HTTP collection was partial (response truncated)".to_owned());
    }

    for req in &policy.require_collectors {
        let name = req.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        match report
            .level2_collectors
            .iter()
            .find(|c| c.collector == name)
        {
            Some(status) if status.state == "captured" => {}
            Some(status) => {
                let detail = status.detail.as_deref().unwrap_or("no detail");
                violations.push(format!(
                    "required collector `{name}` did not capture evidence (state={}, {detail})",
                    status.state
                ));
            }
            None => {
                violations.push(format!(
                    "required collector `{name}` outcome is missing from report"
                ));
            }
        }
    }

    let has_explicit_thresholds = policy.fail_on_severity.is_some()
        || policy.max_critical.is_some()
        || policy.max_high.is_some();

    if let Some(threshold) = policy.fail_on_severity {
        let count: usize = report
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter())
            .filter(|f| f.severity >= threshold)
            .count();
        if count > 0 {
            violations.push(format!(
                "{count} findings met or exceeded severity threshold {threshold:?}"
            ));
        }
    }

    if let Some(max_crit) = policy.max_critical
        && report.summary.critical_findings > max_crit
    {
        violations.push(format!(
            "critical findings ({}) exceeded max_critical ({max_crit})",
            report.summary.critical_findings
        ));
    }

    if let Some(max_high) = policy.max_high
        && report.summary.high_findings > max_high
    {
        violations.push(format!(
            "high findings ({}) exceeded max_high ({max_high})",
            report.summary.high_findings
        ));
    }

    if !has_explicit_thresholds {
        let actionable = report.summary.critical_findings
            + report.summary.high_findings
            + report.summary.medium_findings
            + report.summary.low_findings;
        if actionable > 0 {
            violations.push(format!(
                "{actionable} actionable findings detected under default policy"
            ));
        }
    }

    PolicyEvaluation {
        passed: violations.is_empty(),
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::domain::{
        AuditTarget, EvidenceSnapshot, HttpEvidence, Measurement, MeasurementUnit,
    };

    #[test]
    fn parses_toml_config_and_maps_budget() {
        let raw = r#"
[budget]
http_timeout_secs = 10
max_concurrency = 2

[policy]
fail_on_severity = "high"
max_critical = 0
allow_private = true
"#;
        let cfg: AppConfig = toml::from_str(raw).unwrap();
        let budget = cfg.execution_budget();
        assert_eq!(budget.http_timeout, Duration::from_secs(10));
        assert_eq!(budget.max_concurrency, 2);
        assert_eq!(cfg.policy.fail_on_severity, Some(Severity::High));
        assert_eq!(cfg.target_policy(), TargetPolicy::AllowPrivate);
    }

    #[test]
    fn policy_gate_respects_fail_on_severity_threshold() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "http://example.org/".to_owned(),
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
            tls: CollectorOutcome::Skipped {
                reason: "http".to_owned(),
            },
            browser: CollectorOutcome::default(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let report = analysis::run_all(&snap);

        // HTTP target produces High finding (sec.transport.https), no Critical findings.
        let crit_only = PolicyConfig {
            fail_on_severity: Some(Severity::Critical),
            ..PolicyConfig::default()
        };
        assert!(evaluate_policy(&report, &crit_only).passed);

        let high_gate = PolicyConfig {
            fail_on_severity: Some(Severity::High),
            ..PolicyConfig::default()
        };
        assert!(!evaluate_policy(&report, &high_gate).passed);
    }

    #[test]
    fn policy_gate_enforces_required_level2_collectors() {
        let target = AuditTarget::parse("http://example.org/", TargetPolicy::PublicOnly).unwrap();
        let snap = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "http://example.org/".to_owned(),
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
            tls: CollectorOutcome::Skipped {
                reason: "http".to_owned(),
            },
            browser: CollectorOutcome::Skipped {
                reason: "not enabled".to_owned(),
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let report = analysis::run_all(&snap);
        let gate = PolicyConfig {
            fail_on_severity: Some(Severity::Critical),
            require_collectors: vec!["browser".to_owned()],
            ..PolicyConfig::default()
        };
        let eval = evaluate_policy(&report, &gate);
        assert!(!eval.passed);
        assert!(
            eval.violations
                .iter()
                .any(|v| v.contains("required collector `browser` did not capture evidence"))
        );
    }
}
