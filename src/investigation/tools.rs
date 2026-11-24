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
    InvestigationScope, LighthouseMetrics, TargetPolicy,
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

/// Output produced by [`InspectPagePerformanceTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceToolOutput {
    /// Raw Lighthouse outcome.
    pub outcome: CollectorOutcome<LighthouseMetrics>,
    /// `LeistungsZwerg` Level 2 performance analysis.
    pub performance_result: AnalyserResult,
}

/// `rig-core` [`PortableTool`] wrapping Lighthouse + `LeistungsZwerg` CWV diagnosis.
pub struct InspectPagePerformanceTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl InspectPagePerformanceTool {
    /// Constructs a new scoped performance diagnostic tool.
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

impl PortableTool for InspectPagePerformanceTool {
    const NAME: &'static str = "inspect_page_performance";
    type Args = TargetToolArgs;
    type Output = PerformanceToolOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Run Lighthouse against the authorised URL to measure Core Web Vitals \
(LCP, CLS, FCP, TBT) and performance score."
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

        let outcome = self.backend.collect_lighthouse(&parsed, self.timeout).await;
        let snap = crate::domain::EvidenceSnapshot {
            target: parsed,
            captured_at_unix_secs: 0,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::default(),
            lighthouse: outcome.clone(),
            axe: CollectorOutcome::default(),
        };
        let performance_result = analysis::performance::analyse(&snap);
        Ok(PerformanceToolOutput {
            outcome,
            performance_result,
        })
    }
}

/// `rig-core` [`PortableTool`] wrapping `StrukturZwerg` semantic HTML inspection.
pub struct InspectDocumentStructureTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl InspectDocumentStructureTool {
    /// Constructs a new scoped document-structure diagnostic tool.
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

impl PortableTool for InspectDocumentStructureTool {
    const NAME: &'static str = "inspect_document_structure";
    type Args = TargetToolArgs;
    type Output = AnalyserResult;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Inspect HTML5 landmarks, heading hierarchy, duplicate IDs, and interactive \
element semantics for the authorised URL."
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

        let exec_budget = ExecutionBudget {
            audit_timeout: self.timeout,
            http_timeout: self.timeout.min(Duration::from_secs(15)),
            ..ExecutionBudget::default()
        };
        let snap = self
            .backend
            .collect_http(&parsed, exec_budget, self.policy)
            .await;
        match &snap.http {
            CollectorOutcome::Captured { data } => {
                let obs = analysis::document::DocumentObservations::from_html(&data.body_text);
                Ok(analysis::semantics::analyse(&obs))
            }
            _ => Ok(AnalyserResult {
                dwarf_id: crate::brigade::DwarfId::Struktur,
                findings: Vec::new(),
                checks: Vec::new(),
            }),
        }
    }
}

/// `rig-core` [`PortableTool`] wrapping `SicherheitsZwerg` security posture checks.
pub struct InspectSecurityPostureTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl InspectSecurityPostureTool {
    /// Constructs a new scoped security-posture diagnostic tool.
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

impl PortableTool for InspectSecurityPostureTool {
    const NAME: &'static str = "inspect_security_posture";
    type Args = TargetToolArgs;
    type Output = AnalyserResult;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Inspect HTTPS enforcement, TLS certificate metadata, HSTS, CSP, and security \
headers for the authorised URL."
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

        let exec_budget = ExecutionBudget {
            audit_timeout: self.timeout,
            http_timeout: self.timeout.min(Duration::from_secs(15)),
            ..ExecutionBudget::default()
        };
        let snap = self
            .backend
            .collect_http(&parsed, exec_budget, self.policy)
            .await;
        Ok(analysis::security::analyse(&snap))
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
    let crawl = CrawlAndClusterTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let perf =
        InspectPagePerformanceTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let structure =
        InspectDocumentStructureTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let security = InspectSecurityPostureTool::new(target.clone(), policy, timeout, backend);
    vec![
        portable_tool_definition(&browser),
        portable_tool_definition(&axe),
        portable_tool_definition(&crawl),
        portable_tool_definition(&perf),
        portable_tool_definition(&structure),
        portable_tool_definition(&security),
    ]
}
