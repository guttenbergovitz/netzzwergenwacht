//! Typed `rig-core` [`PortableTool`] implementations for `KommandantZwerg`.
//!
//! Exposes bounded, explicitly authorised diagnostic tools (`BrowserZwerg`,
//! `GestaltungsZwerg`, `ZugänglichkeitsZwerg`) using `rig_core::tool::PortableTool`
//! so tool schemas, arguments, and outputs are type-checked and Rig-compatible.

use std::sync::Arc;
use std::time::Duration;

use rig_core::completion::ToolDefinition;
use rig_core::tool::{PortableTool, portable_tool_definition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis;
use crate::discovery::{CrawlBudget, CrawlSummary};
use crate::domain::{
    AnalyserResult, AuditTarget, AxeEvidence, BrowserEvidence, CollectorOutcome, ExecutionBudget,
    InvestigationScope, TargetPolicy,
};
use crate::investigation::DiagnosticBackend;

/// Typed arguments for [`InspectBrowserRuntimeTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetToolArgs {
    /// Target URL to inspect (must match the authorised investigation target).
    pub url: String,
}

/// Failure returned by a diagnostic tool execution.
#[derive(Debug, Error)]
pub enum DiagnosticToolError {
    /// Target URL failed validation or differed from the authorised scope.
    #[error("unauthorised or invalid target: {0}")]
    UnauthorisedTarget(String),
}

/// Output produced by [`InspectBrowserRuntimeTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserToolOutput {
    /// Raw browser evidence outcome.
    pub outcome: CollectorOutcome<BrowserEvidence>,
    /// `BrowserZwerg` deterministic analysis.
    pub browser_result: AnalyserResult,
    /// `GestaltungsZwerg` deterministic analysis.
    pub visual_result: AnalyserResult,
}

/// `rig-core` [`PortableTool`] wrapping headless Chromium + `BrowserZwerg`/`GestaltungsZwerg`.
pub struct InspectBrowserRuntimeTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl InspectBrowserRuntimeTool {
    /// Constructs a new scoped browser diagnostic tool.
    #[must_use]
    pub fn new(
        authorised_target: AuditTarget,
        policy: TargetPolicy,
        timeout: Duration,
        backend: Arc<dyn DiagnosticBackend>,
    ) -> Self {
        Self {
            authorised_target,
            policy,
            timeout,
            backend,
        }
    }
}

impl PortableTool for InspectBrowserRuntimeTool {
    const NAME: &'static str = "inspect_browser_runtime";
    type Args = TargetToolArgs;
    type Output = BrowserToolOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Run headless Chromium against the authorised URL to collect console errors, \
failed subresource requests, horizontal overflow, and broken rendered images."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Authorised target URL" }
            },
            "required": ["url"]
        })
    }

    async fn call(&self, arguments: Self::Args) -> Result<Self::Output, Self::Error> {
        let parsed = AuditTarget::parse(&arguments.url, self.policy)
            .map_err(|e| DiagnosticToolError::UnauthorisedTarget(e.to_string()))?;
        let scope = InvestigationScope::for_target(&self.authorised_target, self.policy);
        if !scope.permits_target(&parsed) {
            return Err(DiagnosticToolError::UnauthorisedTarget(format!(
                "target '{}' is outside authorised origin",
                parsed.as_str()
            )));
        }

        let outcome = self.backend.collect_browser(&parsed, self.timeout).await;
        let mut snap = crate::domain::EvidenceSnapshot {
            target: parsed,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser: outcome.clone(),
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        let browser_result = analysis::browser::analyse(&snap);
        let visual_result = analysis::visual::analyse(&snap);
        snap.browser = outcome.clone();
        Ok(BrowserToolOutput {
            outcome,
            browser_result,
            visual_result,
        })
    }
}

/// Output produced by [`InspectRenderedAccessibilityTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxeToolOutput {
    /// Raw `axe-core` outcome.
    pub outcome: CollectorOutcome<AxeEvidence>,
    /// `ZugänglichkeitsZwerg` Level 2 `axe-core` analysis.
    pub axe_result: AnalyserResult,
}

/// `rig-core` [`PortableTool`] wrapping `axe-core` + `ZugänglichkeitsZwerg`.
pub struct InspectRenderedAccessibilityTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl InspectRenderedAccessibilityTool {
    /// Constructs a new scoped rendered-accessibility diagnostic tool.
    #[must_use]
    pub fn new(
        authorised_target: AuditTarget,
        policy: TargetPolicy,
        timeout: Duration,
        backend: Arc<dyn DiagnosticBackend>,
    ) -> Self {
        Self {
            authorised_target,
            policy,
            timeout,
            backend,
        }
    }
}

impl PortableTool for InspectRenderedAccessibilityTool {
    const NAME: &'static str = "inspect_rendered_accessibility";
    type Args = TargetToolArgs;
    type Output = AxeToolOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Run axe-core against the rendered DOM of the authorised URL to detect \
colour contrast and ARIA accessibility violations."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Authorised target URL" }
            },
            "required": ["url"]
        })
    }

    async fn call(&self, arguments: Self::Args) -> Result<Self::Output, Self::Error> {
        let parsed = AuditTarget::parse(&arguments.url, self.policy)
            .map_err(|e| DiagnosticToolError::UnauthorisedTarget(e.to_string()))?;
        let scope = InvestigationScope::for_target(&self.authorised_target, self.policy);
        if !scope.permits_target(&parsed) {
            return Err(DiagnosticToolError::UnauthorisedTarget(format!(
                "target '{}' is outside authorised origin",
                parsed.as_str()
            )));
        }

        let outcome = self.backend.collect_axe(&parsed, self.timeout).await;
        let axe_result = analysis::accessibility::analyse_axe_only(&outcome);
        Ok(AxeToolOutput {
            outcome,
            axe_result,
        })
    }
}

/// `rig-core` [`PortableTool`] wrapping bounded same-origin crawling and
/// systemic issue clustering.
pub struct CrawlAndClusterTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl CrawlAndClusterTool {
    /// Constructs a new scoped crawl-and-cluster diagnostic tool.
    #[must_use]
    pub fn new(
        authorised_target: AuditTarget,
        policy: TargetPolicy,
        timeout: Duration,
        backend: Arc<dyn DiagnosticBackend>,
    ) -> Self {
        Self {
            authorised_target,
            policy,
            timeout,
            backend,
        }
    }
}

impl PortableTool for CrawlAndClusterTool {
    const NAME: &'static str = "crawl_and_cluster_site";
    type Args = TargetToolArgs;
    type Output = CrawlSummary;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Perform a bounded same-origin crawl (up to 5 pages, depth 1) from the \
authorised URL, classify page types, and cluster recurring systemic issues."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Authorised seed URL" }
            },
            "required": ["url"]
        })
    }

    async fn call(&self, arguments: Self::Args) -> Result<Self::Output, Self::Error> {
        let parsed = AuditTarget::parse(&arguments.url, self.policy)
            .map_err(|e| DiagnosticToolError::UnauthorisedTarget(e.to_string()))?;
        let scope = InvestigationScope::for_target(&self.authorised_target, self.policy);
        if !scope.permits_target(&parsed) {
            return Err(DiagnosticToolError::UnauthorisedTarget(format!(
                "target '{}' is outside authorised origin",
                parsed.as_str()
            )));
        }

        let crawl_budget = CrawlBudget {
            max_pages: 5,
            max_depth: 1,
            max_duration: self.timeout,
        };
        let exec_budget = ExecutionBudget {
            audit_timeout: self.timeout,
            http_timeout: self.timeout.min(Duration::from_secs(15)),
            ..ExecutionBudget::default()
        };
        Ok(self
            .backend
            .collect_crawl(&parsed, crawl_budget, exec_budget, self.policy)
            .await)
    }
}

/// Returns `rig-core` [`ToolDefinition`] schemas for all registered follow-up tools.
#[must_use]
pub fn registered_tool_definitions(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
) -> Vec<ToolDefinition> {
    let browser =
        InspectBrowserRuntimeTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let axe = InspectRenderedAccessibilityTool::new(
        target.clone(),
        policy,
        timeout,
        Arc::clone(&backend),
    );
    let crawl = CrawlAndClusterTool::new(target.clone(), policy, timeout, backend);
    vec![
        portable_tool_definition(&browser),
        portable_tool_definition(&axe),
        portable_tool_definition(&crawl),
    ]
}
