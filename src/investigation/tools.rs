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
    let calc_dist = CalculateDistributionTool;
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
        portable_tool_definition(&calc_dist),
    ]
}

/// Typed arguments for [`CalculateDistributionTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculateDistributionArgs {
    /// Metric name (for example `"ttfb_ms"`, `"transfer_bytes"`).
    pub metric: String,
    /// Named numeric observations (`label`, optional `value`).
    pub samples: Vec<NamedSample>,
}

/// A single labelled numeric sample for [`CalculateDistributionTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedSample {
    /// Sample label (for example page URL or resource URL).
    pub label: String,
    /// Observed value (`None` if missing/unavailable).
    pub value: Option<u64>,
}

/// Output produced by [`CalculateDistributionTool`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculateDistributionOutput {
    /// Metric name echoed back.
    pub metric: String,
    /// Descriptive statistics summary.
    pub summary: crate::analysis::stats::DistributionSummary,
    /// Upper-tail Tukey IQR outliers (empty when `< 4` non-missing samples).
    pub outliers: Vec<crate::analysis::stats::OutlierPoint>,
}

/// `rig-core` [`PortableTool`] computing descriptive statistics and Tukey IQR outliers.
pub struct CalculateDistributionTool;

impl PortableTool for CalculateDistributionTool {
    const NAME: &'static str = "calculate_distribution";
    type Args = CalculateDistributionArgs;
    type Output = CalculateDistributionOutput;
    type Error = DiagnosticToolError;

    fn description(&self) -> String {
        "Calculate descriptive statistics (count, missing, min, max, mean, median, p75, p95, IQR, MAD) \
and identify Tukey IQR upper-tail outliers over a list of labelled numeric observations."
            .to_owned()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "metric": { "type": "string", "description": "Metric name" },
                "samples": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": { "type": "string" },
                            "value": { "type": ["integer", "null"] }
                        },
                        "required": ["label", "value"]
                    }
                }
            },
            "required": ["metric", "samples"]
        })
    }

    fn call(
        &self,
        arguments: Self::Args,
    ) -> impl std::future::Future<Output = Result<Self::Output, Self::Error>> + Send {
        let raw: Vec<Option<u64>> = arguments.samples.iter().map(|s| s.value).collect();
        let summary = crate::analysis::stats::summarise_u64(&raw);
        let present: Vec<(String, u64)> = arguments
            .samples
            .into_iter()
            .filter_map(|s| s.value.map(|v| (s.label, v)))
            .collect();
        let outliers = crate::analysis::stats::identify_upper_iqr_outliers(&present);
        std::future::ready(Ok(CalculateDistributionOutput {
            metric: arguments.metric,
            summary,
            outliers,
        }))
    }
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
    ///
    /// `None` when at least one captured subresource has no observed transfer
    /// size, because the sum would otherwise present an unknown contributor as
    /// zero bytes.
    pub total_transfer_bytes: Option<u64>,
    /// Distinct third-party hostnames observed in subresource requests.
    pub third_party_hosts: Vec<String>,
    /// Count of runtime errors grouped by `error_kind`.
    pub runtime_error_counts: std::collections::BTreeMap<String, usize>,
    /// Sample of up to 10 slowest subresources with an observed duration
    /// (`url`, `resource_type`, `duration_ms`, `transfer_size`, `initiator_type`).
    ///
    /// Subresources whose duration was not observed are excluded rather than
    /// ranked as if they took zero milliseconds.
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
        Ok(crate::investigation::evidence_query::summarise_browser_outcome(&outcome))
    }
}
