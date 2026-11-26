//! TOML configuration loading and policy quality-gate evaluation.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::AuditReport;
use crate::brigade::DwarfId;
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
    /// Per-role and per-dwarf LLM provider/model routing.
    pub models: ModelRoutingConfig,
    /// External diagnostic dependencies such as the DNS resolver.
    pub dns: DnsConfig,
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

/// Supported `rig-core` LLM provider families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// `OpenAI` and OpenAI-compatible endpoints (`OpenRouter`, vLLM, `LiteLLM`).
    #[default]
    #[serde(rename = "openai")]
    OpenAi,
    /// Anthropic Claude Messages API.
    Anthropic,
    /// Local Ollama server.
    Ollama,
}

/// Provider and model selection for an agent role or specific dwarf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelSpec {
    /// Provider family (`openai`, `anthropic`, `ollama`).
    pub provider: ProviderKind,
    /// Model identifier (for example `"gpt-4o-mini"` or `"claude-3-5-sonnet-latest"`).
    pub model: String,
    /// Optional base URL override.
    pub base_url: Option<String>,
    /// Optional environment variable name holding the API key.
    pub api_key_env: Option<String>,
}

impl Default for ModelSpec {
    fn default() -> Self {
        Self {
            provider: ProviderKind::OpenAi,
            model: "gpt-4o-mini".to_owned(),
            base_url: None,
            api_key_env: None,
        }
    }
}

/// External diagnostic dependency configuration (`[dns]`).
///
/// `NetzZwergenWacht` is local-first: no external resolver is contacted unless an
/// endpoint is configured here. The endpoint is recorded with the observation so
/// a reader can tell which resolver produced the answer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Optional DNS-over-HTTPS JSON endpoint used for CAA lookups.
    ///
    /// The endpoint must use `https`. When absent, CAA acquisition is not attempted
    /// and the observation records [`crate::domain::CaaLookupOutcome::NotAttempted`]
    /// rather than an empty successful result.
    pub caa_doh_endpoint: Option<String>,
}

/// Per-role and per-dwarf model routing configuration (`[models]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ModelRoutingConfig {
    /// Default fallback model used when no role or dwarf override is set.
    pub default: ModelSpec,
    /// Optional model override for `KommandantZwerg`.
    pub kommandant: Option<ModelSpec>,
    /// Optional model override for specialist dwarfs.
    pub specialist: Option<ModelSpec>,
    /// Optional model override for `DokumentationsZwerg`.
    pub dokumentation: Option<ModelSpec>,
    /// Optional per-dwarf overrides keyed by lowercase dwarf ID (e.g. `"leistungs"`, `"gestaltungs"`).
    pub dwarfs: BTreeMap<String, ModelSpec>,
}

impl ModelRoutingConfig {
    /// Resolves the effective [`ModelSpec`] for `dwarf_id`.
    #[must_use]
    pub fn resolve_for_dwarf(&self, dwarf_id: DwarfId) -> &ModelSpec {
        let key = match dwarf_id {
            DwarfId::Netz => "netz",
            DwarfId::Sicherheits => "sicherheits",
            DwarfId::Leistungs => "leistungs",
            DwarfId::Struktur => "struktur",
            DwarfId::Zugaenglichkeits => "zugaenglichkeits",
            DwarfId::Such => "such",
            DwarfId::Inhalts => "inhalts",
            DwarfId::Gestaltungs => "gestaltungs",
            DwarfId::Browser => "browser",
            DwarfId::Dokumentations => "dokumentations",
            DwarfId::Kommandant => "kommandant",
        };
        if let Some(specific) = self.dwarfs.get(key) {
            return specific;
        }
        match dwarf_id {
            DwarfId::Kommandant => self.kommandant.as_ref().unwrap_or(&self.default),
            DwarfId::Dokumentations => self.dokumentation.as_ref().unwrap_or(&self.default),
            _ => self.specialist.as_ref().unwrap_or(&self.default),
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

    #[test]
    fn model_routing_resolves_per_dwarf_then_role_then_default() {
        let raw = r#"
[models.default]
provider = "openai"
model = "gpt-4o-mini"

[models.kommandant]
provider = "anthropic"
model = "claude-3-5-sonnet-latest"

[models.dwarfs.inhalts]
provider = "ollama"
model = "llama3.2"
"#;
        let cfg: AppConfig = toml::from_str(raw).unwrap();
        assert_eq!(
            cfg.models.resolve_for_dwarf(DwarfId::Kommandant).model,
            "claude-3-5-sonnet-latest"
        );
        assert_eq!(
            cfg.models.resolve_for_dwarf(DwarfId::Inhalts).provider,
            ProviderKind::Ollama
        );
        assert_eq!(
            cfg.models.resolve_for_dwarf(DwarfId::Leistungs).model,
            "gpt-4o-mini"
        );
    }
}
