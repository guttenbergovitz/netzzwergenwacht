//! Bounded multi-application portfolio patrol orchestration.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::domain::{AuditTarget, ExecutionBudget, TargetPolicy};
use crate::intelligence::ProviderRouter;
use crate::investigation::DiagnosticBackend;
use crate::patrol::{PatrolBudget, PatrolReport, run_patrol_with_router};

/// Business criticality tier for a portfolio application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationCriticality {
    /// High business/customer impact (patrolled first).
    High,
    /// Standard operational importance.
    #[default]
    Medium,
    /// Campaign or low-risk property.
    Low,
}

/// Single application entry in `applications.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationEntry {
    /// Stable human-readable identifier (e.g. `"corporate-website"`).
    pub id: String,
    /// Target HTTP or HTTPS URL.
    pub url: String,
    /// Optional criticality tier (`high`, `medium`, `low`).
    #[serde(default)]
    pub criticality: ApplicationCriticality,
    /// Optional override permitting private/loopback targets for this entry.
    #[serde(default)]
    pub allow_private: Option<bool>,
    /// Optional per-application page cap.
    #[serde(default)]
    pub max_pages: Option<usize>,
}

/// Portfolio configuration loaded from `applications.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PortfolioConfig {
    /// Applications to patrol.
    pub applications: Vec<ApplicationEntry>,
    /// Maximum concurrent application patrols (capped at 4).
    pub max_concurrency: Option<usize>,
}

impl PortfolioConfig {
    /// Parses a TOML portfolio configuration string.
    ///
    /// # Errors
    ///
    /// Returns an error string if the TOML is invalid or `applications` is empty.
    pub fn from_toml_str(raw: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(raw).map_err(|e| format!("invalid portfolio TOML: {e}"))?;
        if cfg.applications.is_empty() {
            return Err(
                "portfolio TOML must define at least one [[applications]] entry".to_owned(),
            );
        }
        Ok(cfg)
    }

    /// Reads and parses a TOML portfolio configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error string if the file cannot be read or parsed.
    pub fn from_toml_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        Self::from_toml_str(&raw)
    }
}

/// Per-application outcome inside a [`PortfolioPatrolReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationPatrolOutcome {
    /// Application identifier from `applications.toml`.
    pub id: String,
    /// Target URL string.
    pub url: String,
    /// Criticality tier.
    pub criticality: ApplicationCriticality,
    /// Full [`PatrolReport`] when target parsing succeeded.
    pub report: Option<PatrolReport>,
    /// Error message when target parsing or setup failed before patrol execution.
    pub error: Option<String>,
}

/// Aggregated portfolio patrol report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortfolioPatrolReport {
    /// Total applications configured.
    pub total_applications: usize,
    /// Applications that completed primary collection.
    pub succeeded_count: usize,
    /// Applications with quiet patrols (no material new anomalies).
    pub quiet_count: usize,
    /// Applications that triggered specialist escalation.
    pub escalated_count: usize,
    /// Individual application outcomes ordered by criticality then config order.
    pub outcomes: Vec<ApplicationPatrolOutcome>,
}

/// Runs bounded patrols across all configured applications in `config`.
///
/// Orders `High` criticality applications ahead of `Medium` and `Low`, limits
/// concurrency via a [`Semaphore`] (default `2`, capped at `4`), and isolates
/// individual application failures so one failing target never aborts the portfolio.
#[allow(clippy::too_many_lines)]
pub async fn run_portfolio_patrol(
    config: &PortfolioConfig,
    default_allow_private: bool,
    exec_budget: ExecutionBudget,
    base_patrol_budget: PatrolBudget,
    memory_dir: Option<&Path>,
    router: Option<Arc<dyn ProviderRouter>>,
    backend: Arc<dyn DiagnosticBackend>,
) -> PortfolioPatrolReport {
    let mut indexed: Vec<(usize, ApplicationEntry)> =
        config.applications.iter().cloned().enumerate().collect();
    indexed.sort_by_key(|(idx, entry)| (entry.criticality, *idx));

    let concurrency = config.max_concurrency.unwrap_or(2).clamp(1, 4);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mem_dir_owned = memory_dir.map(Path::to_path_buf);

    let mut join_set = JoinSet::new();
    for (order_idx, entry) in indexed {
        let sem = Arc::clone(&semaphore);
        let mem_dir_task = mem_dir_owned.clone();
        let router_task = router.clone();
        let backend_task = Arc::clone(&backend);

        join_set.spawn(async move {
            let Ok(_permit) = sem.acquire_owned().await else {
                return (
                    order_idx,
                    ApplicationPatrolOutcome {
                        id: entry.id,
                        url: entry.url,
                        criticality: entry.criticality,
                        report: None,
                        error: Some("portfolio concurrency semaphore closed".to_owned()),
                    },
                );
            };
            let allow_priv = entry.allow_private.unwrap_or(default_allow_private);
            let policy = if allow_priv {
                TargetPolicy::AllowPrivate
            } else {
                TargetPolicy::PublicOnly
            };
            let target = match AuditTarget::parse(&entry.url, policy) {
                Ok(t) => t,
                Err(err) => {
                    return (
                        order_idx,
                        ApplicationPatrolOutcome {
                            id: entry.id,
                            url: entry.url,
                            criticality: entry.criticality,
                            report: None,
                            error: Some(format!("invalid target: {err}")),
                        },
                    );
                }
            };
            let budget = PatrolBudget {
                max_pages: entry
                    .max_pages
                    .unwrap_or(base_patrol_budget.max_pages)
                    .max(1),
                ..base_patrol_budget
            };
            let report = Box::pin(run_patrol_with_router(
                target,
                policy,
                exec_budget,
                budget,
                mem_dir_task.as_deref(),
                router_task.as_deref(),
                backend_task,
            ))
            .await;
            (
                order_idx,
                ApplicationPatrolOutcome {
                    id: entry.id,
                    url: entry.url,
                    criticality: entry.criticality,
                    report: Some(report),
                    error: None,
                },
            )
        });
    }

    let mut collected = Vec::with_capacity(config.applications.len());
    while let Some(res) = join_set.join_next().await {
        if let Ok(item) = res {
            collected.push(item);
        }
    }
    collected.sort_by_key(|(idx, outcome)| (outcome.criticality, *idx));

    let outcomes: Vec<ApplicationPatrolOutcome> = collected.into_iter().map(|(_, o)| o).collect();
    let total_applications = outcomes.len();
    let succeeded_count = outcomes
        .iter()
        .filter(|o| o.report.as_ref().is_some_and(|r| r.execution_succeeded))
        .count();
    let quiet_count = outcomes
        .iter()
        .filter(|o| o.report.as_ref().is_some_and(|r| r.is_quiet_patrol))
        .count();
    let escalated_count = outcomes
        .iter()
        .filter(|o| o.report.as_ref().is_some_and(|r| r.investigation.is_some()))
        .count();

    PortfolioPatrolReport {
        total_applications,
        succeeded_count,
        quiet_count,
        escalated_count,
        outcomes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::investigation::LiveDiagnosticBackend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn parses_portfolio_toml_with_criticality() {
        let raw = r#"
max_concurrency = 2

[[applications]]
id = "campaign"
url = "https://campaign.example.org"
criticality = "low"

[[applications]]
id = "corporate"
url = "https://example.org"
criticality = "high"
"#;
        let cfg = PortfolioConfig::from_toml_str(raw).unwrap();
        assert_eq!(cfg.applications.len(), 2);
        assert_eq!(cfg.applications[0].criticality, ApplicationCriticality::Low);
        assert_eq!(
            cfg.applications[1].criticality,
            ApplicationCriticality::High
        );
    }

    #[tokio::test]
    async fn portfolio_patrol_isolates_invalid_targets_and_patrols_valid_ones() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let body = "<!doctype html><html lang=\"en-GB\"><head><title>OK</title></head><body><main><h1>OK</h1></main></body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                });
            }
        });

        let cfg = PortfolioConfig {
            applications: vec![
                ApplicationEntry {
                    id: "bad-target".to_owned(),
                    url: "http://127.0.0.1:9/".to_owned(),
                    criticality: ApplicationCriticality::Low,
                    allow_private: Some(false),
                    max_pages: None,
                },
                ApplicationEntry {
                    id: "local-ok".to_owned(),
                    url: format!("http://127.0.0.1:{}/", addr.port()),
                    criticality: ApplicationCriticality::High,
                    allow_private: Some(true),
                    max_pages: Some(2),
                },
            ],
            max_concurrency: Some(2),
        };
        let backend: Arc<dyn DiagnosticBackend> = Arc::new(LiveDiagnosticBackend);
        let report = run_portfolio_patrol(
            &cfg,
            false,
            ExecutionBudget::default(),
            PatrolBudget {
                allow_ai_escalation: false,
                ..PatrolBudget::default()
            },
            None,
            None,
            backend,
        )
        .await;
        assert_eq!(report.total_applications, 2);
        assert_eq!(report.succeeded_count, 1);
        assert_eq!(report.outcomes[0].id, "local-ok");
        assert!(
            report.outcomes[0]
                .report
                .as_ref()
                .unwrap()
                .execution_succeeded
        );
        assert_eq!(report.outcomes[1].id, "bad-target");
        assert!(report.outcomes[1].error.is_some());
    }
}
