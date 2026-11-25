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

/// Arguments for [`InspectPreviousFindingsTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousFindingsArgs {
    /// Path to a local JSON/JSONL audit report file.
    pub report_path: String,
}

/// Summary of historical findings returned by [`InspectPreviousFindingsTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousFindingsOutput {
    /// Baseline target URL.
    pub target: String,
    /// Capture timestamp in Unix seconds.
    pub captured_at_unix_secs: u64,
    /// Rule IDs of findings present in the baseline report.
    pub finding_rules: Vec<String>,
}

/// `rig-core` [`PortableTool`] wrapping `DokumentationsZwerg` historical report lookup.
pub struct InspectPreviousFindingsTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
}

impl InspectPreviousFindingsTool {
    /// Constructs a new scoped historical findings tool.
    #[must_use]
    pub fn new(authorised_target: AuditTarget, policy: TargetPolicy) -> Self {
        Self {
            authorised_target,
            policy,
        }
    }
}

impl PortableTool for InspectPreviousFindingsTool {
    const NAME: &'static str = "inspect_previous_findings";
    type Args = PreviousFindingsArgs;
    type Output = PreviousFindingsOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Load the latest historical audit report for the authorised origin and list its finding rule IDs."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "report_path": { "type": "string", "description": "Path to JSON/JSONL baseline report" }
            },
            "required": ["report_path"]
        })
    }

    fn call(
        &self,
        arguments: Self::Args,
    ) -> impl std::future::Future<Output = Result<Self::Output, Self::Error>> + Send {
        let res = (|| {
            let report = crate::persistence::load_latest_or_single(std::path::Path::new(
                &arguments.report_path,
            ))
            .map_err(|e| DiagnosticToolError::UnauthorisedTarget(e.to_string()))?;
            let scope = InvestigationScope::for_target(&self.authorised_target, self.policy);
            if !scope.permits_target(&report.target) {
                return Err(DiagnosticToolError::UnauthorisedTarget(format!(
                    "baseline target '{}' is outside authorised origin",
                    report.target.as_str()
                )));
            }
            let finding_rules = report
                .analysers
                .iter()
                .flat_map(|a| a.findings.iter().map(|f| f.rule_id.0.clone()))
                .collect();
            Ok(PreviousFindingsOutput {
                target: report.target.as_str().to_owned(),
                captured_at_unix_secs: report.captured_at_unix_secs,
                finding_rules,
            })
        })();
        std::future::ready(res)
    }
}

/// Arguments for [`VerifyFindingTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFindingArgs {
    /// Target URL to re-check.
    pub url: String,
    /// Deterministic rule ID to verify.
    pub rule_id: String,
}

/// Result returned by [`VerifyFindingTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFindingOutput {
    /// Verified rule identifier.
    pub rule_id: String,
    /// Verification outcome (`"resolved"`, `"persisting"`, or `"unverified"`).
    pub status: String,
}

/// `rig-core` [`PortableTool`] re-checking a specific `rule_id` against the authorised URL.
pub struct VerifyFindingTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl VerifyFindingTool {
    /// Constructs a new scoped finding-verification tool.
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

impl PortableTool for VerifyFindingTool {
    const NAME: &'static str = "verify_finding";
    type Args = VerifyFindingArgs;
    type Output = VerifyFindingOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Re-check a specific deterministic rule ID against the authorised URL to verify remediation."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "url": { "type": "string", "description": "Authorised target URL" },
                "rule_id": { "type": "string", "description": "Rule ID to verify" }
            },
            "required": ["url", "rule_id"]
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
        let report = analysis::run_all(&snap);

        let still_present = report
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter())
            .any(|f| f.rule_id.0 == arguments.rule_id);
        let unverified = report
            .analysers
            .iter()
            .flat_map(|a| a.checks.iter())
            .any(|c| {
                matches!(
                    c,
                    crate::domain::CheckStatus::Skipped { rule_id, .. }
                        | crate::domain::CheckStatus::Unavailable { rule_id, .. }
                    if rule_id.0 == arguments.rule_id
                )
            });

        let status = if still_present {
            "persisting"
        } else if unverified {
            "unverified"
        } else {
            "resolved"
        };

        Ok(VerifyFindingOutput {
            rule_id: arguments.rule_id,
            status: status.to_owned(),
        })
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
    let security =
        InspectSecurityPostureTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let prev = InspectPreviousFindingsTool::new(target.clone(), policy);
    let verify = VerifyFindingTool::new(target.clone(), policy, timeout, Arc::clone(&backend));
    let query_browser = QueryBrowserEvidenceTool::new(target.clone(), policy, timeout, backend);
    vec![
        portable_tool_definition(&browser),
        portable_tool_definition(&axe),
        portable_tool_definition(&crawl),
        portable_tool_definition(&perf),
        portable_tool_definition(&structure),
        portable_tool_definition(&security),
        portable_tool_definition(&prev),
        portable_tool_definition(&verify),
        portable_tool_definition(&query_browser),
    ]
}

/// Compact waterfall and runtime-error summary returned by [`QueryBrowserEvidenceTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryBrowserEvidenceOutput {
    /// Status of the browser collection (`"captured"`, `"partial"`, `"failed"`, `"skipped"`).
    pub collection_status: String,
    /// Explicit completeness warnings (for example truncation or load timeout).
    pub warnings: Vec<String>,
    /// Total captured subresource count.
    pub resource_count: usize,
    /// Whether the subresource list was truncated at the collector cap.
    pub resources_truncated: bool,
    /// Total encoded transfer bytes across captured subresources.
    pub total_transfer_bytes: u64,
    /// Distinct third-party hostnames observed in subresource requests.
    pub third_party_hosts: Vec<String>,
    /// Count of runtime errors grouped by `error_kind`.
    pub runtime_error_counts: std::collections::BTreeMap<String, usize>,
    /// Sample of up to 10 slowest subresources (`url`, `resource_type`, `duration_ms`, `transfer_size`, `initiator_type`).
    pub slowest_resources: Vec<crate::domain::ResourceTimingObs>,
}

/// `rig-core` [`PortableTool`] for selective querying of structured browser waterfall and error telemetry.
pub struct QueryBrowserEvidenceTool {
    authorised_target: AuditTarget,
    policy: TargetPolicy,
    timeout: Duration,
    backend: Arc<dyn DiagnosticBackend>,
}

impl QueryBrowserEvidenceTool {
    /// Constructs a new scoped browser evidence query tool.
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

impl PortableTool for QueryBrowserEvidenceTool {
    const NAME: &'static str = "query_browser_evidence";
    type Args = TargetToolArgs;
    type Output = QueryBrowserEvidenceOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Query structured browser waterfall summary, third-party origins, categorised runtime \
errors, and collection completeness flags without returning unbounded raw arrays."
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
        let (status, detail) = outcome.status_summary();
        let warnings = detail.into_iter().collect();

        let Some(data) = (match &outcome {
            CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
                Some(data)
            }
            CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => None,
        }) else {
            return Ok(QueryBrowserEvidenceOutput {
                collection_status: status.to_owned(),
                warnings,
                resource_count: 0,
                resources_truncated: false,
                total_transfer_bytes: 0,
                third_party_hosts: Vec::new(),
                runtime_error_counts: std::collections::BTreeMap::new(),
                slowest_resources: Vec::new(),
            });
        };

        let page_host = url::Url::parse(&data.final_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        let mut third_party_hosts = std::collections::BTreeSet::new();
        let mut total_transfer_bytes = 0_u64;
        for res in &data.resources {
            total_transfer_bytes =
                total_transfer_bytes.saturating_add(res.transfer_size.unwrap_or(0));
            if let Ok(u) = url::Url::parse(&res.url)
                && let Some(h) = u.host_str().map(str::to_ascii_lowercase)
                && page_host.as_deref() != Some(h.as_str())
            {
                third_party_hosts.insert(h);
            }
        }

        let mut runtime_error_counts = std::collections::BTreeMap::new();
        for err in &data.console_errors {
            let kind = err.error_kind.clone().unwrap_or_else(|| err.level.clone());
            *runtime_error_counts.entry(kind).or_insert(0) += 1;
        }

        let mut slowest = data.resources.clone();
        slowest.sort_by_key(|a| std::cmp::Reverse(a.duration_ms.unwrap_or(0)));
        slowest.truncate(10);

        Ok(QueryBrowserEvidenceOutput {
            collection_status: status.to_owned(),
            warnings,
            resource_count: data.resources.len(),
            resources_truncated: data.resources_truncated,
            total_transfer_bytes,
            third_party_hosts: third_party_hosts.into_iter().collect(),
            runtime_error_counts,
            slowest_resources: slowest,
        })
    }
}
