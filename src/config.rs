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
    /// The file parsed but contains values that cannot be used.
    #[error("invalid configuration at `{field}`: {message}")]
    Validation {
        /// Dotted path of the offending field.
        field: String,
        /// Why the value is unusable.
        message: String,
    },
}

impl ConfigError {
    /// Builds a [`ConfigError::Validation`] for `field`.
    fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
}

/// Top-level application configuration loaded from TOML.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct ModelSpec {
    /// Provider family (`openai`, `anthropic`, `ollama`).
    ///
    /// The historical `kind` spelling is accepted as an alias so configuration files
    /// written against the older documentation keep working.
    #[serde(alias = "kind")]
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
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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
        if let Some(specific) = self.dwarfs.get(dwarf_id.config_key()) {
            return specific;
        }
        match dwarf_id {
            DwarfId::Kommandant => self.kommandant.as_ref().unwrap_or(&self.default),
            DwarfId::Dokumentations => self.dokumentation.as_ref().unwrap_or(&self.default),
            _ => self.specialist.as_ref().unwrap_or(&self.default),
        }
    }

    /// Describes where the effective specification for `dwarf_id` came from.
    ///
    /// The label is stable and safe to display: it names the configuration table that
    /// supplied the value, never a credential.
    #[must_use]
    pub fn resolve_origin_for_dwarf(&self, dwarf_id: DwarfId) -> &'static str {
        if self.dwarfs.contains_key(dwarf_id.config_key()) {
            return "models.dwarfs";
        }
        match dwarf_id {
            DwarfId::Kommandant if self.kommandant.is_some() => "models.kommandant",
            DwarfId::Dokumentations if self.dokumentation.is_some() => "models.dokumentation",
            _ if self.specialist.is_some() => "models.specialist",
            _ => "models.default",
        }
    }
}

/// Resource budget configuration section (`[budget]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
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

/// Where the effective configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// A file named explicitly with `--config`.
    ExplicitFile(std::path::PathBuf),
    /// A file named by the `NZW_CONFIG` environment variable.
    EnvironmentFile(std::path::PathBuf),
    /// `nzw.toml` found in the current working directory.
    WorkingDirectory(std::path::PathBuf),
    /// The user configuration file under `$XDG_CONFIG_HOME` or `$HOME/.config`.
    UserConfig(std::path::PathBuf),
    /// No file was found; built-in defaults are in effect.
    BuiltInDefaults,
}

impl ConfigSource {
    /// Returns a human-readable description suitable for `nzw config show`.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::ExplicitFile(path) => format!("explicit file {}", path.display()),
            Self::EnvironmentFile(path) => format!("NZW_CONFIG {}", path.display()),
            Self::WorkingDirectory(path) => format!("working directory {}", path.display()),
            Self::UserConfig(path) => format!("user configuration {}", path.display()),
            Self::BuiltInDefaults => "built-in defaults".to_owned(),
        }
    }
}

/// A parsed configuration together with the source that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    /// Validated configuration.
    pub config: AppConfig,
    /// Where it came from.
    pub source: ConfigSource,
}

/// Configuration discovery inputs, resolved in precedence order.
///
/// The struct is explicit so discovery is testable without mutating process-wide
/// environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiscovery {
    /// Path supplied with `--config`.
    pub explicit: Option<std::path::PathBuf>,
    /// Path supplied by `NZW_CONFIG`.
    pub environment: Option<std::path::PathBuf>,
    /// Directory searched for `nzw.toml`.
    pub working_directory: std::path::PathBuf,
    /// User configuration path, when one can be determined.
    pub user_config: Option<std::path::PathBuf>,
}

impl ConfigDiscovery {
    /// Collects discovery inputs from the current process environment.
    #[must_use]
    pub fn from_process() -> Self {
        let environment = std::env::var("NZW_CONFIG")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from);
        let user_config = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .map(|home| std::path::PathBuf::from(home).join(".config"))
            })
            .map(|root| root.join("netzzwergenwacht").join("nzw.toml"));
        Self {
            explicit: None,
            environment,
            working_directory: std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from(".")),
            user_config,
        }
    }

    /// Resolves the configuration that applies to this invocation.
    ///
    /// A missing discovered file is not an error: built-in defaults apply and the
    /// source says so. A file that exists but cannot be parsed or validated is an
    /// error, because silently ignoring an operator's configuration would be worse
    /// than refusing to start.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a named or existing file cannot be read, parsed or
    /// validated.
    pub fn resolve(&self) -> Result<LoadedConfig, ConfigError> {
        if let Some(path) = &self.explicit {
            return Ok(LoadedConfig {
                config: load_validated(path)?,
                source: ConfigSource::ExplicitFile(path.clone()),
            });
        }
        if let Some(path) = &self.environment {
            return Ok(LoadedConfig {
                config: load_validated(path)?,
                source: ConfigSource::EnvironmentFile(path.clone()),
            });
        }
        let local = self.working_directory.join("nzw.toml");
        if local.is_file() {
            return Ok(LoadedConfig {
                config: load_validated(&local)?,
                source: ConfigSource::WorkingDirectory(local),
            });
        }
        if let Some(user) = &self.user_config
            && user.is_file()
        {
            return Ok(LoadedConfig {
                config: load_validated(user)?,
                source: ConfigSource::UserConfig(user.clone()),
            });
        }
        let config = AppConfig::default();
        config.validate()?;
        Ok(LoadedConfig {
            config,
            source: ConfigSource::BuiltInDefaults,
        })
    }
}

fn load_validated(path: &Path) -> Result<AppConfig, ConfigError> {
    let config = AppConfig::from_toml_file(path)?;
    config.validate()?;
    Ok(config)
}

/// Resolved provider and model for one agent, with its configuration origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveRoute {
    /// Lowercase configuration key of the agent.
    pub agent: String,
    /// German display name (`KommandantZwerg`, `NetzZwerg`, …).
    pub display_name: String,
    /// Provider family.
    pub provider: String,
    /// Model identifier.
    pub model: String,
    /// Configured endpoint override, if any.
    pub base_url: Option<String>,
    /// Where the credential is expected to come from, without revealing it.
    pub credential_reference: String,
    /// Configuration table that supplied this route.
    pub origin: String,
}

/// Redacted, resolved view of an [`AppConfig`].
///
/// Secrets never appear: routes name the credential *source* only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveConfiguration {
    /// Human-readable configuration source.
    pub source: String,
    /// Effective target policy (`public_only` or `allow_private`).
    pub target_policy: String,
    /// End-to-end collection deadline in seconds.
    pub audit_timeout_secs: u64,
    /// Per-request HTTP timeout in seconds.
    pub http_timeout_secs: u64,
    /// Maximum redirects.
    pub max_redirects: usize,
    /// Maximum response bytes.
    pub max_response_bytes: usize,
    /// Maximum concurrency.
    pub max_concurrency: usize,
    /// Collectors the policy gate requires.
    pub require_collectors: Vec<String>,
    /// Configured DNS-over-HTTPS endpoint for CAA, if any.
    pub dns_caa_endpoint: Option<String>,
    /// Resolved model route per agent.
    pub routes: Vec<EffectiveRoute>,
}

impl EffectiveConfiguration {
    /// Renders the configuration as terminal lines for `nzw config show` and the
    /// Mission Review panel.
    #[must_use]
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Configuration source : {}", self.source),
            format!("Target policy        : {}", self.target_policy),
            format!(
                "Budget               : audit {} s, http {} s, redirects {}, response {} B, concurrency {}",
                self.audit_timeout_secs,
                self.http_timeout_secs,
                self.max_redirects,
                self.max_response_bytes,
                self.max_concurrency
            ),
            format!(
                "Required collectors  : {}",
                if self.require_collectors.is_empty() {
                    "none".to_owned()
                } else {
                    self.require_collectors.join(", ")
                }
            ),
            format!(
                "DNS CAA endpoint     : {}",
                self.dns_caa_endpoint.as_deref().unwrap_or("not configured")
            ),
            "Model routing        :".to_owned(),
        ];
        for route in &self.routes {
            let endpoint = route.base_url.as_deref().unwrap_or("provider default");
            lines.push(format!(
                "  {:<18} {:<22} {:>8} / {}  [{}] endpoint={} credential={}",
                route.agent,
                route.display_name,
                route.provider,
                route.model,
                route.origin,
                endpoint,
                route.credential_reference
            ));
        }
        lines
    }
}

impl ProviderKind {
    /// Returns the canonical configuration spelling of this provider.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Ollama => "ollama",
        }
    }
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_endpoint(field: &str, raw: &str) -> Result<(), ConfigError> {
    let url = url::Url::parse(raw)
        .map_err(|err| ConfigError::validation(field, format!("not a valid URL: {err}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::validation(
            field,
            "must not contain embedded credentials",
        ));
    }
    let Some(host) = url.host_str() else {
        return Err(ConfigError::validation(field, "must name a host"));
    };
    match url.scheme() {
        "https" => {}
        "http" if is_local_host(host) => {}
        "http" => {
            return Err(ConfigError::validation(
                field,
                "plain http is only permitted for loopback endpoints; use https",
            ));
        }
        other => {
            return Err(ConfigError::validation(
                field,
                format!("unsupported scheme `{other}`"),
            ));
        }
    }
    Ok(())
}

fn validate_model_spec(field: &str, spec: &ModelSpec) -> Result<(), ConfigError> {
    if spec.model.trim().is_empty() {
        return Err(ConfigError::validation(
            format!("{field}.model"),
            "model identifier must not be empty",
        ));
    }
    if spec.model.len() > 200 || spec.model.chars().any(char::is_control) {
        return Err(ConfigError::validation(
            format!("{field}.model"),
            "model identifier must be at most 200 characters and free of control characters",
        ));
    }
    if let Some(base_url) = &spec.base_url {
        validate_endpoint(&format!("{field}.base_url"), base_url)?;
    }
    if let Some(env) = &spec.api_key_env {
        let valid = !env.is_empty()
            && env
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            return Err(ConfigError::validation(
                format!("{field}.api_key_env"),
                "must be an environment variable name (A-Z, 0-9, underscore)",
            ));
        }
    }
    Ok(())
}

impl AppConfig {
    /// Validates values that TOML syntax alone cannot reject.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.budget.audit_timeout_secs == Some(0) {
            return Err(ConfigError::validation(
                "budget.audit_timeout_secs",
                "must be at least 1 second",
            ));
        }
        if let Some(secs) = self.budget.audit_timeout_secs
            && secs > 3_600
        {
            return Err(ConfigError::validation(
                "budget.audit_timeout_secs",
                "must not exceed 3600 seconds",
            ));
        }
        if self.budget.http_timeout_secs == Some(0) {
            return Err(ConfigError::validation(
                "budget.http_timeout_secs",
                "must be at least 1 second",
            ));
        }
        if let Some(secs) = self.budget.http_timeout_secs
            && secs > 3_600
        {
            return Err(ConfigError::validation(
                "budget.http_timeout_secs",
                "must not exceed 3600 seconds",
            ));
        }
        if let Some(redirects) = self.budget.max_redirects
            && redirects > 100
        {
            return Err(ConfigError::validation(
                "budget.max_redirects",
                "must not exceed 100",
            ));
        }
        if self.budget.max_response_bytes == Some(0) {
            return Err(ConfigError::validation(
                "budget.max_response_bytes",
                "must be at least 1 byte",
            ));
        }
        if self.budget.max_concurrency == Some(0) {
            return Err(ConfigError::validation(
                "budget.max_concurrency",
                "must be at least 1",
            ));
        }
        if let Some(concurrency) = self.budget.max_concurrency
            && concurrency > 64
        {
            return Err(ConfigError::validation(
                "budget.max_concurrency",
                "must not exceed 64",
            ));
        }

        for collector in &self.policy.require_collectors {
            let name = collector.trim().to_ascii_lowercase();
            if !matches!(name.as_str(), "browser" | "lighthouse" | "axe") {
                return Err(ConfigError::validation(
                    "policy.require_collectors",
                    format!(
                        "unknown collector `{collector}`; supported names are browser, lighthouse and axe"
                    ),
                ));
            }
        }

        if let Some(endpoint) = &self.dns.caa_doh_endpoint {
            validate_endpoint("dns.caa_doh_endpoint", endpoint)?;
        }

        validate_model_spec("models.default", &self.models.default)?;
        if let Some(spec) = &self.models.kommandant {
            validate_model_spec("models.kommandant", spec)?;
        }
        if let Some(spec) = &self.models.specialist {
            validate_model_spec("models.specialist", spec)?;
        }
        if let Some(spec) = &self.models.dokumentation {
            validate_model_spec("models.dokumentation", spec)?;
        }
        for (key, spec) in &self.models.dwarfs {
            if DwarfId::from_config_key(key).is_none() {
                return Err(ConfigError::validation(
                    format!("models.dwarfs.{key}"),
                    "unknown dwarf key; see `nzw config show` for the supported keys",
                ));
            }
            validate_model_spec(&format!("models.dwarfs.{key}"), spec)?;
        }
        Ok(())
    }

    /// Resolves the effective route for every agent in the brigade registry.
    #[must_use]
    pub fn effective_routes(&self) -> Vec<EffectiveRoute> {
        crate::brigade::ZWERGENBRIGADE
            .iter()
            .map(|profile| {
                let spec = self.models.resolve_for_dwarf(profile.id);
                EffectiveRoute {
                    agent: profile.id.config_key().to_owned(),
                    display_name: profile.display_name.to_owned(),
                    provider: spec.provider.as_str().to_owned(),
                    model: spec.model.clone(),
                    base_url: spec.base_url.clone(),
                    credential_reference: spec
                        .api_key_env
                        .as_ref()
                        .map_or_else(|| "provider default".to_owned(), |env| format!("env:{env}")),
                    origin: self.models.resolve_origin_for_dwarf(profile.id).to_owned(),
                }
            })
            .collect()
    }

    /// Returns a redacted, resolved view of this configuration.
    #[must_use]
    pub fn effective(&self, source: &ConfigSource) -> EffectiveConfiguration {
        let budget = self.execution_budget();
        EffectiveConfiguration {
            source: source.label(),
            target_policy: match self.target_policy() {
                TargetPolicy::PublicOnly => "public_only".to_owned(),
                TargetPolicy::AllowPrivate => "allow_private".to_owned(),
            },
            audit_timeout_secs: budget.audit_timeout.as_secs(),
            http_timeout_secs: budget.http_timeout.as_secs(),
            max_redirects: budget.max_redirects,
            max_response_bytes: budget.max_response_bytes,
            max_concurrency: budget.max_concurrency,
            require_collectors: self.policy.require_collectors.clone(),
            dns_caa_endpoint: self.dns.caa_doh_endpoint.clone(),
            routes: self.effective_routes(),
        }
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
