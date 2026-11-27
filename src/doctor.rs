//! Local environment diagnosis for `nzw doctor`.
//!
//! The doctor answers one question: can this machine run the parts of
//! `NetzZwergenWacht` the operator intends to use? It inspects the local
//! environment only — no target is contacted, no provider is called, and no
//! credential value is ever read or printed.
//!
//! Every check reports a [`DoctorStatus`] plus an actionable hint, so a missing
//! instrument is a statement of fact rather than a guess. Deterministic audits
//! never require Node.js or a language model; only the browser-backed collectors
//! and the agentic investigation paths have instrument requirements.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{AppConfig, ConfigDiscovery, ConfigError};

/// Minimum Node.js major version the browser harness supports.
pub const MINIMUM_NODE_MAJOR: u32 = 22;

/// Outcome of a single environment check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    /// The requirement is satisfied.
    Ready,
    /// The requirement is optional and unsatisfied.
    Optional,
    /// The requirement is missing and the affected features cannot run.
    Missing,
    /// The environment cannot support the requirement at all.
    Unsupported,
}

impl DoctorStatus {
    /// Returns the short label used in text output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Optional => "optional",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
        }
    }

    const fn is_blocking(self) -> bool {
        matches!(self, Self::Missing | Self::Unsupported)
    }
}

/// One diagnosis entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorCheck {
    /// Stable identifier (`chromium`, `node`, `config`, …).
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Current status.
    pub status: DoctorStatus,
    /// What was observed.
    pub detail: String,
    /// What the operator can do about it.
    pub hint: String,
}

/// Complete diagnosis of the local environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    /// Individual checks in presentation order.
    pub checks: Vec<DoctorCheck>,
    /// Number of checks that block the reported capabilities.
    pub blocking_count: usize,
    /// Configuration source that was resolved, when resolution succeeded.
    pub config_source: Option<String>,
    /// Configuration resolution error, when one occurred.
    pub config_error: Option<String>,
}

impl DoctorReport {
    /// Returns `true` when no check blocks the reported capabilities.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.blocking_count == 0 && self.config_error.is_none()
    }

    /// Renders the report as terminal lines.
    #[must_use]
    pub fn render_lines(&self) -> Vec<String> {
        let mut lines = Vec::with_capacity(self.checks.len() + 4);
        lines.push("NetzZwergenWacht environment diagnosis".to_owned());
        lines.push(format!(
            "Configuration: {}",
            self.config_source
                .as_deref()
                .unwrap_or("unavailable (see below)")
        ));
        if let Some(error) = &self.config_error {
            lines.push(format!("Configuration error: {error}"));
        }
        lines.push(String::new());
        for check in &self.checks {
            lines.push(format!(
                "[{:<11}] {:<24} {}",
                check.status.label(),
                check.name,
                check.detail
            ));
            if check.status.is_blocking() || check.status == DoctorStatus::Optional {
                lines.push(format!("              hint: {}", check.hint));
            }
        }
        lines.push(String::new());
        if self.is_ready() {
            lines.push(
                "Deterministic audits are ready. Value fields are limited to what the installed instruments can observe."
                    .to_owned(),
            );
        } else {
            lines.push(format!(
                "{} blocking requirement(s) must be resolved before the affected features run.",
                self.blocking_count
            ));
        }
        lines
    }
}

/// Runs every local environment check.
#[must_use]
pub fn diagnose(
    config: &Result<AppConfig, ConfigError>,
    source_label: Option<&str>,
) -> DoctorReport {
    let mut checks = vec![
        rust_version_check(),
        chromium_check(),
        node_check(),
        axe_check(),
        lighthouse_check(),
    ];
    checks.push(config_check(config, source_label));
    checks.push(model_check(config));
    checks.push(patrol_memory_check());
    let blocking_count = checks
        .iter()
        .filter(|check| check.status.is_blocking())
        .count();
    DoctorReport {
        checks,
        blocking_count,
        config_source: source_label.map(str::to_owned),
        config_error: config.as_ref().err().map(ToString::to_string),
    }
}

fn rust_version_check() -> DoctorCheck {
    DoctorCheck {
        id: "rust",
        name: "Rust toolchain",
        status: DoctorStatus::Ready,
        detail: format!("compiled with Rust {}", env!("CARGO_PKG_RUST_VERSION")),
        hint: String::new(),
    }
}

fn chromium_check() -> DoctorCheck {
    let candidates = chromium_candidates();
    for candidate in &candidates {
        if is_executable(candidate) {
            return DoctorCheck {
                id: "chromium",
                name: "Chromium browser",
                status: DoctorStatus::Ready,
                detail: format!("found {}", candidate.display()),
                hint: String::new(),
            };
        }
    }
    DoctorCheck {
        id: "chromium",
        name: "Chromium browser",
        status: DoctorStatus::Missing,
        detail: format!(
            "none of {} candidate paths is executable",
            candidates.len()
        ),
        hint: "install Chrome/Chromium or set NZW_CHROMIUM_BIN to its binary; required for browser-backed collectors"
            .to_owned(),
    }
}

fn chromium_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(value) = std::env::var("NZW_CHROMIUM_BIN")
        && !value.trim().is_empty()
    {
        candidates.push(PathBuf::from(value));
    }
    for name in [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ] {
        candidates.extend(path_lookup(name));
    }
    candidates.push(PathBuf::from(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ));
    candidates.push(PathBuf::from("/opt/homebrew/bin/chromium"));
    candidates
}

fn node_check() -> DoctorCheck {
    let Some(binary) = path_lookup("node").into_iter().next() else {
        return DoctorCheck {
            id: "node",
            name: "Node.js runtime",
            status: DoctorStatus::Missing,
            detail: "`node` is not on PATH".to_owned(),
            hint: format!(
                "install Node.js {MINIMUM_NODE_MAJOR} or newer; the browser harness requires it (built-in WebSocket and fetch, no extra npm packages)"
            ),
        };
    };
    match command_version(&binary, "--version") {
        Some(raw) => {
            let major = parse_major(&raw);
            match major {
                Some(version) if version >= MINIMUM_NODE_MAJOR => DoctorCheck {
                    id: "node",
                    name: "Node.js runtime",
                    status: DoctorStatus::Ready,
                    detail: format!("{} ({})", raw, binary.display()),
                    hint: String::new(),
                },
                Some(_older) => DoctorCheck {
                    id: "node",
                    name: "Node.js runtime",
                    status: DoctorStatus::Unsupported,
                    detail: format!("{raw} is older than {MINIMUM_NODE_MAJOR}"),
                    hint: "upgrade Node.js; older runtimes lack the global WebSocket the CDP harness uses"
                        .to_owned(),
                },
                None => DoctorCheck {
                    id: "node",
                    name: "Node.js runtime",
                    status: DoctorStatus::Unsupported,
                    detail: format!("could not parse version output `{raw}`"),
                    hint: format!("install Node.js {MINIMUM_NODE_MAJOR} or newer"),
                },
            }
        }
        None => DoctorCheck {
            id: "node",
            name: "Node.js runtime",
            status: DoctorStatus::Unsupported,
            detail: "`node --version` did not run".to_owned(),
            hint: format!("install Node.js {MINIMUM_NODE_MAJOR} or newer"),
        },
    }
}

fn axe_check() -> DoctorCheck {
    let explicit = std::env::var("NZW_AXE_BIN")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let binary = explicit
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| path_lookup("axe").into_iter().next());
    match binary {
        Some(path) if is_executable(&path) => DoctorCheck {
            id: "axe",
            name: "axe-core CLI",
            status: DoctorStatus::Ready,
            detail: format!("found {}", path.display()),
            hint: String::new(),
        },
        _ => DoctorCheck {
            id: "axe",
            name: "axe-core CLI",
            status: DoctorStatus::Optional,
            detail: "`axe` is not available".to_owned(),
            hint:
                "install @axe-core/cli or set NZW_AXE_BIN; only `--axe` accessibility runs need it"
                    .to_owned(),
        },
    }
}

fn lighthouse_check() -> DoctorCheck {
    match path_lookup("lighthouse").into_iter().next() {
        Some(path) => DoctorCheck {
            id: "lighthouse",
            name: "Lighthouse CLI",
            status: DoctorStatus::Ready,
            detail: format!("found {}", path.display()),
            hint: String::new(),
        },
        None => DoctorCheck {
            id: "lighthouse",
            name: "Lighthouse CLI",
            status: DoctorStatus::Optional,
            detail: "`lighthouse` is not on PATH".to_owned(),
            hint: "install the lighthouse CLI; only `--lighthouse` runs need it".to_owned(),
        },
    }
}

fn config_check(
    config: &Result<AppConfig, ConfigError>,
    source_label: Option<&str>,
) -> DoctorCheck {
    match config {
        Ok(config) => {
            let routes = config.effective_routes().len();
            DoctorCheck {
                id: "config",
                name: "Configuration",
                status: DoctorStatus::Ready,
                detail: format!(
                    "{} resolved, {routes} agent route(s)",
                    source_label.unwrap_or("built-in defaults")
                ),
                hint: String::new(),
            }
        }
        Err(error) => DoctorCheck {
            id: "config",
            name: "Configuration",
            status: DoctorStatus::Missing,
            detail: error.to_string(),
            hint: "fix the reported field or pass --config with a valid file; see CONFIG.md"
                .to_owned(),
        },
    }
}

fn model_check(config: &Result<AppConfig, ConfigError>) -> DoctorCheck {
    let Ok(config) = config else {
        return DoctorCheck {
            id: "models",
            name: "Language model routing",
            status: DoctorStatus::Optional,
            detail: "not evaluated because the configuration is invalid".to_owned(),
            hint: "resolve the configuration error first".to_owned(),
        };
    };
    let spec = config
        .models
        .resolve_for_dwarf(crate::brigade::DwarfId::Kommandant);
    let credential = config
        .effective_routes()
        .into_iter()
        .find(|route| route.agent == "kommandant")
        .map_or_else(
            || "provider default".to_owned(),
            |route| route.credential_reference,
        );
    DoctorCheck {
        id: "models",
        name: "Language model routing",
        status: DoctorStatus::Ready,
        detail: format!(
            "KommandantZwerg: {} / {} (credential source: {credential})",
            spec.provider.as_str(),
            spec.model
        ),
        hint: "agentic investigations also accept a provider, model and session credential entered in Mission Control"
            .to_owned(),
    }
}

fn patrol_memory_check() -> DoctorCheck {
    let dir = Path::new(crate::patrol::memory::DEFAULT_MEMORY_DIR);
    if dir.is_dir() {
        return DoctorCheck {
            id: "memory",
            name: "Patrol memory",
            status: DoctorStatus::Ready,
            detail: format!("{} exists", dir.display()),
            hint: String::new(),
        };
    }
    DoctorCheck {
        id: "memory",
        name: "Patrol memory",
        status: DoctorStatus::Optional,
        detail: format!("{} does not exist yet", dir.display()),
        hint: "created automatically on the first patrol; `nzw patrol --memory-dir` shares it with the workbench"
            .to_owned(),
    }
}

fn path_lookup(name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Some(path) = std::env::var_os("PATH") else {
        return found;
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            found.push(candidate);
        }
    }
    found
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.is_file()
            && std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn command_version(binary: &Path, flag: &str) -> Option<String> {
    let output = Command::new(binary).arg(flag).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn parse_major(raw: &str) -> Option<u32> {
    raw.trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|part| part.parse().ok())
}

/// Resolves the configuration for the doctor and reports the source label.
pub fn resolve_config(
    explicit: Option<PathBuf>,
) -> (Result<AppConfig, ConfigError>, Option<String>) {
    let discovery = ConfigDiscovery {
        explicit,
        ..ConfigDiscovery::from_process()
    };
    match discovery.resolve() {
        Ok(loaded) => (Ok(loaded.config), Some(loaded.source.label())),
        Err(error) => (Err(error), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_major_accepts_prefixed_versions() {
        assert_eq!(parse_major("v22.4.1"), Some(22));
        assert_eq!(parse_major("24.0.0"), Some(24));
        assert_eq!(parse_major("not-a-version"), None);
    }

    #[test]
    fn invalid_configuration_blocks_the_report() {
        let invalid = AppConfig {
            budget: crate::config::BudgetConfig {
                max_concurrency: Some(0),
                ..crate::config::BudgetConfig::default()
            },
            ..AppConfig::default()
        };
        let error = invalid.validate().expect_err("zero concurrency rejected");
        let report = diagnose(&Err(error), None);
        assert!(!report.is_ready());
        assert!(report.config_error.is_some());
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.id == "config" && check.status == DoctorStatus::Missing)
        );
    }

    #[test]
    fn report_never_contains_credential_values() {
        let config = AppConfig::default();
        let report = diagnose(&Ok(config), Some("built-in defaults"));
        let rendered = report.render_lines().join("\n");
        assert_eq!(report.blocking_count, 0);
        assert!(!rendered.contains("sk-"));
    }
}
