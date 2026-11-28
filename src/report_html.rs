//! Self-contained, offline HTML report renderer for single-page audits and crawls.
//!
//! Produces dependency-free HTML5 documents with inline CSS and strict HTML
//! escaping so untrusted target content (URLs, titles, error strings, DOM
//! excerpts) can never inject scripts or markup.

use std::fmt::Write as _;

use crate::analysis::AuditReport;
use crate::analysis::assessment::{DomainVerdict, QualityAssessment};
use crate::brigade::{MOTTO, profile};
use crate::discovery::{
    CrawlCoverage, ResourceKind, ResourceObservation, ResourceStatus, SystemicIssue,
};
use crate::domain::{AnalyserResult, CollectorOutcome, Finding, Severity};
use crate::persistence::RegressionReport;

const HEAVY_UNCOMPRESSED_THRESHOLD_BYTES: u64 = 20 * 1024;

/// Aggregated measured byte sizes across discovered subresources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourcePayloadSummary {
    /// Sum of measured `byte_len` values across all resources.
    pub total_bytes: u64,
    /// Sum of measured `byte_len` values for scripts.
    pub script_bytes: u64,
    /// Sum of measured `byte_len` values for stylesheets.
    pub stylesheet_bytes: u64,
    /// Sum of measured `byte_len` values for images.
    pub image_bytes: u64,
    /// Number of resources with an observed `byte_len`.
    pub measured_count: usize,
    /// Count of fetched `Script`/`Stylesheet` resources >= 20 KB without `Content-Encoding`.
    pub uncompressed_heavy_count: usize,
}

/// Computes measured payload totals and heavy-uncompressed counts over `resources`.
#[must_use]
pub fn summarise_resources(resources: &[ResourceObservation]) -> ResourcePayloadSummary {
    let mut summary = ResourcePayloadSummary::default();
    for res in resources {
        if let Some(bytes) = res.byte_len {
            summary.measured_count += 1;
            summary.total_bytes = summary.total_bytes.saturating_add(bytes);
            match res.kind {
                ResourceKind::Script => {
                    summary.script_bytes = summary.script_bytes.saturating_add(bytes);
                }
                ResourceKind::Stylesheet => {
                    summary.stylesheet_bytes = summary.stylesheet_bytes.saturating_add(bytes);
                }
                ResourceKind::Image => {
                    summary.image_bytes = summary.image_bytes.saturating_add(bytes);
                }
            }
            if res.status == ResourceStatus::Fetched
                && matches!(res.kind, ResourceKind::Script | ResourceKind::Stylesheet)
                && bytes >= HEAVY_UNCOMPRESSED_THRESHOLD_BYTES
                && res.content_encoding.is_none()
            {
                summary.uncompressed_heavy_count += 1;
            }
        }
    }
    summary
}

/// Returns borrowed references to `resources` sorted with failures first, then
/// heaviest measured payloads first, then lexicographically by URL.
#[must_use]
pub fn prioritise_resources(resources: &[ResourceObservation]) -> Vec<&ResourceObservation> {
    let mut refs: Vec<&ResourceObservation> = resources.iter().collect();
    refs.sort_by(|a, b| {
        let rank = |s: ResourceStatus| match s {
            ResourceStatus::Failed => 0_u8,
            ResourceStatus::Fetched => 1_u8,
            ResourceStatus::SkippedBudget => 2_u8,
        };
        rank(a.status)
            .cmp(&rank(b.status))
            .then_with(|| b.byte_len.unwrap_or(0).cmp(&a.byte_len.unwrap_or(0)))
            .then_with(|| a.url.cmp(&b.url))
    });
    refs
}

/// Formats a byte count into a human-readable ASCII size (`B`, `KB`, `MB`).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * 1_024;
    if bytes >= MB {
        let whole = bytes / MB;
        let frac = ((bytes % MB) * 100) / MB;
        format!("{whole}.{frac:02} MB")
    } else if bytes >= KB {
        let whole = bytes / KB;
        let frac = ((bytes % KB) * 10) / KB;
        format!("{whole}.{frac} KB")
    } else {
        format!("{bytes} B")
    }
}

/// Borrowed inputs required to render a multi-page reconnaissance HTML report.
pub struct ScanHtmlInput<'a> {
    /// Stable run identifier.
    pub run_id: &'a str,
    /// Target application origin or label.
    pub application: &'a str,
    /// Initial seed URL.
    pub seed_url: &'a str,
    /// Crawl and resource coverage summary.
    pub coverage: &'a CrawlCoverage,
    /// Discovered shared/external resources.
    pub resources: &'a [ResourceObservation],
    /// Clustered cross-page systemic issues.
    pub systemic_issues: &'a [SystemicIssue],
    /// Site-wide Application Graph analyser results (`graph.*`).
    pub graph_results: &'a [AnalyserResult],
    /// Unified multi-domain quality assessment.
    pub quality_assessment: &'a QualityAssessment,
    /// Optional local `EvidenceStore` path where the crawl was persisted.
    pub stored_at: Option<&'a str>,
}

/// Escapes untrusted text for safe insertion into HTML body text and attributes.
#[must_use]
pub fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Renders a single-page [`AuditReport`] and its [`QualityAssessment`] as a
/// self-contained HTML5 document.
#[must_use]
pub fn render_audit_html(report: &AuditReport, assessment: &QualityAssessment) -> String {
    let mut body = String::new();

    let _ = writeln!(
        body,
        "<header class=\"hero\">\
         <div>\
           <p class=\"eyebrow\">NetzZwergenWacht &middot; {}</p>\
           <h1>Audit Report: {}</h1>\
           <p class=\"meta\">Captured at Unix {} &middot; Schema v{}</p>\
         </div>\
         <div class=\"verdict {}\">{}</div>\
         </header>",
        escape_html(MOTTO),
        escape_html(report.target.as_str()),
        report.captured_at_unix_secs,
        escape_html(&report.schema_version),
        verdict_class(assessment.overall_verdict),
        escape_html(assessment.overall_verdict.badge()),
    );

    render_summary_cards(&mut body, report);
    render_blockers_section(&mut body, assessment, Some(report));
    render_domains_section(&mut body, assessment);
    render_collectors_section(&mut body, report);
    render_findings_section(&mut body, report);
    render_limitations_section(&mut body, &assessment.limitations);

    wrap_document(
        &format!("NetzZwergenWacht Audit — {}", report.target.as_str()),
        &body,
    )
}

/// Renders a multi-page reconnaissance scan as a self-contained HTML5 document.
#[must_use]
pub fn render_scan_html(input: &ScanHtmlInput<'_>) -> String {
    let mut body = String::new();
    let cov = input.coverage;

    let _ = writeln!(
        body,
        "<header class=\"hero\">\
         <div>\
           <p class=\"eyebrow\">NetzZwergenWacht &middot; {}</p>\
           <h1>Reconnaissance Scan: {}</h1>\
           <p class=\"meta\">Seed: {} &middot; Run ID: {}</p>\
         </div>\
         <div class=\"verdict {}\">{}</div>\
         </header>",
        escape_html(MOTTO),
        escape_html(input.application),
        escape_html(input.seed_url),
        escape_html(input.run_id),
        verdict_class(input.quality_assessment.overall_verdict),
        escape_html(input.quality_assessment.overall_verdict.badge()),
    );

    let _ = writeln!(
        body,
        "<section class=\"cards\">\
         <div class=\"card\"><span class=\"label\">Discovered URLs</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Fetched</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Analysed</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Failed</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Skipped (budget)</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Systemic Issues</span><strong>{}</strong></div>\
         </section>",
        cov.discovered_urls,
        cov.fetched_urls,
        cov.analysed_urls,
        if cov.failed_urls > 0 { "sev-high" } else { "" },
        cov.failed_urls,
        cov.skipped_budget_urls,
        if input.systemic_issues.is_empty() {
            ""
        } else {
            "sev-crit"
        },
        input.systemic_issues.len(),
    );

    render_blockers_section(&mut body, input.quality_assessment, None);
    render_systemic_issues_section(&mut body, input.systemic_issues);
    render_graph_results_section(&mut body, input.graph_results);
    render_domains_section(&mut body, input.quality_assessment);
    render_resources_section(&mut body, cov, input.resources);
    render_limitations_section(&mut body, &input.quality_assessment.limitations);

    if let Some(path) = input.stored_at {
        let _ = writeln!(
            body,
            "<p class=\"meta\">Evidence retained at <code>{}</code></p>",
            escape_html(path)
        );
    }

    wrap_document(
        &format!("NetzZwergenWacht Scan — {}", input.application),
        &body,
    )
}

/// Wraps plain text or Markdown output in a clean, XSS-safe HTML5 document.
#[must_use]
pub fn wrap_preformatted_html(title: &str, content: &str) -> String {
    let body = format!(
        "<header class=\"hero\"><div><p class=\"eyebrow\">NetzZwergenWacht &middot; {}</p><h1>{}</h1></div></header>\
         <section class=\"panel\"><pre class=\"pre-wrap\">{}</pre></section>",
        escape_html(MOTTO),
        escape_html(title),
        escape_html(content),
    );
    wrap_document(title, &body)
}

/// Borrowed invalid-target entry for a batch HTML report.
pub struct BatchHtmlError<'a> {
    /// Raw target string from the targets file.
    pub raw_target: &'a str,
    /// Validation or collection error description.
    pub error: &'a str,
}

/// Borrowed completed-target entry for a batch HTML report.
pub struct BatchHtmlItem<'a> {
    /// Completed single-page audit report.
    pub report: &'a AuditReport,
    /// Whether the target passed the configured policy gate.
    pub passed: bool,
}

/// Renders a multi-target batch audit as a self-contained HTML5 portfolio dashboard.
#[must_use]
pub fn render_batch_html(
    total_targets: usize,
    completed: usize,
    failed_targets: usize,
    errors: &[BatchHtmlError<'_>],
    items: &[BatchHtmlItem<'_>],
) -> String {
    let passed_count = items.iter().filter(|i| i.passed).count();
    let failed_policy = items.len().saturating_sub(passed_count);
    let has_failures = failed_targets > 0 || failed_policy > 0;
    let badge_class = if has_failures { "sev-crit" } else { "sev-pass" };
    let badge_label = if has_failures { "FAIL" } else { "PASS" };

    let mut body = String::new();
    let _ = writeln!(
        body,
        "<header class=\"hero\">\
         <div>\
           <p class=\"eyebrow\">NetzZwergenWacht &middot; {}</p>\
           <h1>Batch Portfolio Audit</h1>\
           <p class=\"meta\">{} target(s) configured &middot; {} completed</p>\
         </div>\
         <div class=\"verdict {badge_class}\">{badge_label}</div>\
         </header>",
        escape_html(MOTTO),
        total_targets,
        completed,
    );

    let _ = writeln!(
        body,
        "<section class=\"cards\">\
         <div class=\"card\"><span class=\"label\">Total Targets</span><strong>{total_targets}</strong></div>\
         <div class=\"card\"><span class=\"label\">Completed</span><strong>{completed}</strong></div>\
         <div class=\"card sev-pass\"><span class=\"label\">Passed Policy</span><strong>{passed_count}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Failed Policy</span><strong>{failed_policy}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Invalid Targets</span><strong>{failed_targets}</strong></div>\
         </section>",
        if failed_policy > 0 { "sev-crit" } else { "" },
        if failed_targets > 0 { "sev-high" } else { "" },
    );

    if !errors.is_empty() {
        let _ = writeln!(
            body,
            "<section class=\"panel\"><h2>Invalid Targets ({})</h2>\
             <table><thead><tr><th>Target</th><th>Error</th></tr></thead><tbody>",
            errors.len(),
        );
        for err in errors {
            let _ = writeln!(
                body,
                "<tr><td><code>{}</code></td><td>{}</td></tr>",
                escape_html(err.raw_target),
                escape_html(err.error),
            );
        }
        let _ = writeln!(body, "</tbody></table></section>");
    }

    let _ = writeln!(
        body,
        "<section class=\"panel\"><h2>Target Results ({})</h2>\
         <table><thead><tr><th>Target</th><th>Policy</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Top Issue</th></tr></thead><tbody>",
        items.len(),
    );
    for item in items {
        let s = &item.report.summary;
        let badge = if item.passed { "sev-pass" } else { "sev-crit" };
        let label = if item.passed { "PASS" } else { "FAIL" };
        let top_issue = item
            .report
            .analysers
            .iter()
            .flat_map(|a| a.findings.iter())
            .min_by_key(|f| match f.severity {
                Severity::Critical => 0_u8,
                Severity::High => 1_u8,
                Severity::Medium => 2_u8,
                Severity::Low => 3_u8,
                Severity::Info => 4_u8,
            })
            .map_or_else(
                || "—".to_owned(),
                |f| format!("{}: {}", f.rule_id.0, f.title),
            );
        let _ = writeln!(
            body,
            "<tr><td><code>{}</code></td><td><span class=\"badge {badge}\">{label}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(item.report.target.as_str()),
            s.critical_findings,
            s.high_findings,
            s.medium_findings,
            s.low_findings,
            escape_html(&top_issue),
        );
    }
    let _ = writeln!(body, "</tbody></table></section>");

    wrap_document("NetzZwergenWacht Batch Portfolio Audit", &body)
}

/// Renders a cross-run [`RegressionReport`] (`diff` / `verify`) as a
/// self-contained HTML5 document highlighting new, reintroduced, worsened,
/// and resolved findings.
#[must_use]
pub fn render_diff_html(diff: &RegressionReport) -> String {
    let mut body = String::new();
    let s = &diff.summary;
    let has_regressions = s.new_count > 0 || s.reintroduced_count > 0 || s.worsened_count > 0;
    let badge_class = if diff.not_comparable_reason.is_some() {
        "sev-med"
    } else if has_regressions {
        "sev-crit"
    } else {
        "sev-pass"
    };
    let badge_label = if diff.not_comparable_reason.is_some() {
        "NOT COMPARABLE"
    } else if has_regressions {
        "REGRESSIONS"
    } else {
        "NO NEW REGRESSIONS"
    };

    let _ = writeln!(
        body,
        "<header class=\"hero\">\
         <div>\
           <p class=\"eyebrow\">NetzZwergenWacht &middot; {}</p>\
           <h1>Regression Comparison</h1>\
           <p class=\"meta\">Baseline: {} (Unix {}) &rarr; Current: {} (Unix {})</p>\
         </div>\
         <div class=\"verdict {badge_class}\">{badge_label}</div>\
         </header>",
        escape_html(MOTTO),
        escape_html(&diff.baseline_target),
        diff.baseline_captured_at_unix_secs,
        escape_html(&diff.current_target),
        diff.current_captured_at_unix_secs,
    );

    if let Some(reason) = &diff.not_comparable_reason {
        let _ = writeln!(
            body,
            "<section class=\"panel\"><h2>Comparability Warning</h2><p>{}</p></section>",
            escape_html(reason),
        );
    }

    let _ = writeln!(
        body,
        "<section class=\"cards\">\
         <div class=\"card {}\"><span class=\"label\">New</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Reintroduced</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Worsened</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Persisting</span><strong>{}</strong></div>\
         <div class=\"card sev-pass\"><span class=\"label\">Resolved</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Unverified</span><strong>{}</strong></div>\
         </section>",
        if s.new_count > 0 { "sev-crit" } else { "" },
        s.new_count,
        if s.reintroduced_count > 0 {
            "sev-crit"
        } else {
            ""
        },
        s.reintroduced_count,
        if s.worsened_count > 0 { "sev-high" } else { "" },
        s.worsened_count,
        s.persisting_count,
        s.resolved_count,
        s.unverified_count,
    );

    render_diff_bucket(&mut body, "New Findings", &diff.new_findings);
    render_diff_bucket(
        &mut body,
        "Reintroduced Findings",
        &diff.reintroduced_findings,
    );
    render_diff_bucket(&mut body, "Worsened Findings", &diff.worsened_findings);
    render_diff_bucket(&mut body, "Resolved Findings", &diff.resolved_findings);

    wrap_document(
        &format!("NetzZwergenWacht Regression Diff — {}", diff.current_target),
        &body,
    )
}

fn render_diff_bucket(out: &mut String, heading: &str, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>{} ({})</h2>",
        escape_html(heading),
        findings.len(),
    );
    for finding in findings {
        render_finding_card(out, finding);
    }
    let _ = writeln!(out, "</section>");
}

fn render_summary_cards(out: &mut String, report: &AuditReport) {
    let s = &report.summary;
    let _ = writeln!(
        out,
        "<section class=\"cards\">\
         <div class=\"card {}\"><span class=\"label\">Critical</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">High</span><strong>{}</strong></div>\
         <div class=\"card {}\"><span class=\"label\">Medium</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Low / Info</span><strong>{}</strong></div>\
         <div class=\"card sev-pass\"><span class=\"label\">Passed Checks</span><strong>{}</strong></div>\
         <div class=\"card\"><span class=\"label\">Skipped / Unavail</span><strong>{}</strong></div>\
         </section>",
        if s.critical_findings > 0 {
            "sev-crit"
        } else {
            ""
        },
        s.critical_findings,
        if s.high_findings > 0 { "sev-high" } else { "" },
        s.high_findings,
        if s.medium_findings > 0 { "sev-med" } else { "" },
        s.medium_findings,
        s.low_findings + s.info_findings,
        s.passed_checks,
        s.skipped_checks + s.unavailable_checks,
    );
}

fn render_blockers_section(
    out: &mut String,
    assessment: &QualityAssessment,
    report: Option<&AuditReport>,
) {
    if assessment.blockers.is_empty() {
        return;
    }
    let _ = writeln!(out, "<section class=\"panel\"><h2>Top Blockers</h2><ul>");
    for blocker in &assessment.blockers {
        let fix = report.and_then(|r| find_remediation_for_blocker(r, blocker));
        if let Some(rec) = fix {
            let _ = writeln!(
                out,
                "<li><strong>{}</strong><br><span class=\"fix\">Fix: {}</span></li>",
                escape_html(blocker),
                escape_html(rec),
            );
        } else {
            let _ = writeln!(out, "<li><strong>{}</strong></li>", escape_html(blocker));
        }
    }
    let _ = writeln!(out, "</ul></section>");
}

fn find_remediation_for_blocker<'a>(report: &'a AuditReport, blocker: &str) -> Option<&'a str> {
    report
        .analysers
        .iter()
        .flat_map(|a| a.findings.iter())
        .find(|f| {
            matches!(f.severity, Severity::Critical | Severity::High)
                && (blocker.contains(&f.rule_id.0) || blocker.contains(&f.title))
        })
        .and_then(|f| f.remediation.as_deref())
}

fn render_domains_section(out: &mut String, assessment: &QualityAssessment) {
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Quality Domains</h2>\
         <table><thead><tr><th>Domain</th><th>Verdict</th><th>Crit/High</th><th>Med</th><th>Unavailable</th><th>Rationale</th></tr></thead><tbody>"
    );
    for dom in &assessment.domains {
        if dom.verdict == DomainVerdict::NotApplicable {
            continue;
        }
        let _ = writeln!(
            out,
            "<tr><td><strong>{}</strong></td><td><span class=\"badge {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(dom.domain.label()),
            verdict_class(dom.verdict),
            escape_html(dom.verdict.badge()),
            dom.critical_high_count,
            dom.medium_count,
            dom.checks_unavailable,
            escape_html(&dom.rationale),
        );
    }
    let _ = writeln!(out, "</tbody></table></section>");
}

fn render_collectors_section(out: &mut String, report: &AuditReport) {
    let http_state = match &report.http {
        CollectorOutcome::Captured { data } => {
            format!(
                "captured (HTTP {}, {} B)",
                data.status_code, data.body_bytes
            )
        }
        CollectorOutcome::Partial { warnings, .. } => {
            format!("partial ({})", warnings.join("; "))
        }
        CollectorOutcome::Failed { error } => format!("failed ({error})"),
        CollectorOutcome::Skipped { reason } => format!("skipped ({reason})"),
    };
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Collector Coverage</h2>\
         <table><thead><tr><th>Collector</th><th>State</th><th>Detail</th></tr></thead><tbody>\
         <tr><td><code>http</code></td><td>status</td><td>{}</td></tr>",
        escape_html(&http_state),
    );
    for c in &report.level2_collectors {
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            escape_html(&c.collector),
            escape_html(&c.state),
            escape_html(c.detail.as_deref().unwrap_or("—")),
        );
    }
    let _ = writeln!(out, "</tbody></table></section>");
}

fn render_findings_section(out: &mut String, report: &AuditReport) {
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Findings by Specialist (Die Zwergenbrigade)</h2>"
    );
    let mut any_finding = false;
    for analyser in &report.analysers {
        if analyser.findings.is_empty() {
            continue;
        }
        any_finding = true;
        let dwarf_profile = profile(analyser.dwarf_id);
        let _ = writeln!(
            out,
            "<div class=\"specialist\"><h3>{} <span class=\"muted\">({}) &middot; {} finding(s)</span></h3>",
            escape_html(dwarf_profile.display_name),
            escape_html(dwarf_profile.responsibility),
            analyser.findings.len(),
        );
        for f in &analyser.findings {
            render_finding_card(out, f);
        }
        let _ = writeln!(out, "</div>");
    }
    if !any_finding {
        let _ = writeln!(
            out,
            "<p class=\"muted\">No findings emitted within observed evidence.</p>"
        );
    }
    let _ = writeln!(out, "</section>");
}

fn render_finding_card(out: &mut String, f: &Finding) {
    let sev_class = match f.severity {
        Severity::Critical => "sev-crit",
        Severity::High => "sev-high",
        Severity::Medium => "sev-med",
        Severity::Low | Severity::Info => "sev-low",
    };
    let _ = writeln!(
        out,
        "<article class=\"finding {}\">\
         <div class=\"finding-head\">\
           <span class=\"badge {}\">{:?}</span>\
           <strong>{}</strong>\
           <code>{}</code>\
         </div>\
         <p>{}</p>",
        sev_class,
        sev_class,
        f.severity,
        escape_html(&f.title),
        escape_html(&f.rule_id.0),
        escape_html(&f.summary),
    );
    if let Some(remediation) = &f.remediation {
        let _ = writeln!(
            out,
            "<p class=\"fix\"><strong>Recommendation:</strong> {}</p>",
            escape_html(remediation),
        );
    }
    if !f.evidence_refs.is_empty() {
        let _ = writeln!(out, "<ul class=\"evidence\">");
        for ev in f.evidence_refs.iter().take(4) {
            let _ = writeln!(
                out,
                "<li><code>{:?}</code>: {}</li>",
                ev.source,
                escape_html(&ev.detail),
            );
        }
        let _ = writeln!(out, "</ul>");
    }
    let _ = writeln!(out, "</article>");
}

fn render_systemic_issues_section(out: &mut String, issues: &[SystemicIssue]) {
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Systemic Issues (Clustered Across Pages)</h2>"
    );
    if issues.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"muted\">No recurring cross-page systemic issues detected.</p></section>"
        );
        return;
    }
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Affected Pages</th><th>Summary</th><th>Sample URLs</th></tr></thead><tbody>"
    );
    for issue in issues {
        let sample_urls: Vec<String> = issue
            .affected_urls
            .iter()
            .take(5)
            .map(|u| escape_html(u))
            .collect();
        let sev_class = match issue.severity {
            Severity::Critical => "sev-crit",
            Severity::High => "sev-high",
            Severity::Medium => "sev-med",
            Severity::Low | Severity::Info => "sev-low",
        };
        let _ = writeln!(
            out,
            "<tr><td><span class=\"badge {}\">{:?}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
            sev_class,
            issue.severity,
            escape_html(&issue.rule_id.0),
            issue.affected_urls.len(),
            escape_html(&issue.summary),
            sample_urls.join("</code><br><code>"),
        );
    }
    let _ = writeln!(out, "</tbody></table></section>");
}

fn render_graph_results_section(out: &mut String, graph_results: &[AnalyserResult]) {
    let findings: Vec<(&AnalyserResult, &Finding)> = graph_results
        .iter()
        .flat_map(|a| a.findings.iter().map(move |f| (a, f)))
        .collect();
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Site-Wide Graph Findings</h2>"
    );
    if findings.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"muted\">No site-wide graph findings detected.</p></section>"
        );
        return;
    }
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Specialist</th><th>Title</th><th>Summary</th></tr></thead><tbody>"
    );
    for (analyser, finding) in findings {
        let sev_class = match finding.severity {
            Severity::Critical => "sev-crit",
            Severity::High => "sev-high",
            Severity::Medium => "sev-med",
            Severity::Low | Severity::Info => "sev-low",
        };
        let _ = writeln!(
            out,
            "<tr><td><span class=\"badge {}\">{:?}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            sev_class,
            finding.severity,
            escape_html(&finding.rule_id.0),
            escape_html(analyser.dwarf_id.display_name()),
            escape_html(&finding.title),
            escape_html(&finding.summary),
        );
    }
    let _ = writeln!(out, "</tbody></table></section>");
}

fn render_resources_section(
    out: &mut String,
    cov: &CrawlCoverage,
    resources: &[ResourceObservation],
) {
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Shared Resources ({} discovered, {} failed)</h2>",
        cov.resources.discovered_resources, cov.resources.failed_resources
    );
    if resources.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"muted\">No shared subresources recorded.</p></section>"
        );
        return;
    }
    let summary = summarise_resources(resources);
    if summary.measured_count > 0 {
        let _ = writeln!(
            out,
            "<p class=\"meta\" style=\"margin-bottom:10px;\">Measured payload ({} resource(s)): <strong>{}</strong> &middot; Scripts: {} &middot; Stylesheets: {} &middot; Images: {}{}</p>",
            summary.measured_count,
            format_bytes(summary.total_bytes),
            format_bytes(summary.script_bytes),
            format_bytes(summary.stylesheet_bytes),
            format_bytes(summary.image_bytes),
            if summary.uncompressed_heavy_count > 0 {
                format!(
                    " &middot; <span class=\"badge sev-high\">{} uncompressed &ge; 20 KB</span>",
                    summary.uncompressed_heavy_count
                )
            } else {
                String::new()
            },
        );
    }
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Resource</th><th>Kind</th><th>Status</th><th>HTTP</th><th>Size</th><th>Encoding</th><th>Detail</th></tr></thead><tbody>"
    );
    for res in prioritise_resources(resources).into_iter().take(40) {
        let state_badge = match res.status {
            ResourceStatus::Failed => "sev-high",
            ResourceStatus::Fetched => "sev-pass",
            ResourceStatus::SkippedBudget => "sev-low",
        };
        let status = res
            .http_status
            .map_or_else(|| "—".to_owned(), |c| c.to_string());
        let size = res.byte_len.map_or_else(
            || "—".to_owned(),
            |b| {
                if res.truncated {
                    format!("{}+", format_bytes(b))
                } else {
                    format_bytes(b)
                }
            },
        );
        let encoding = match res.status {
            ResourceStatus::Fetched => res.content_encoding.as_deref().unwrap_or("none"),
            _ => "—",
        };
        let encoding_html = if res.status == ResourceStatus::Fetched
            && matches!(res.kind, ResourceKind::Script | ResourceKind::Stylesheet)
            && res
                .byte_len
                .is_some_and(|b| b >= HEAVY_UNCOMPRESSED_THRESHOLD_BYTES)
            && res.content_encoding.is_none()
        {
            "<span class=\"badge sev-high\">uncompressed</span>".to_owned()
        } else {
            escape_html(encoding)
        };
        let detail = res.error.as_deref().unwrap_or("—");
        let _ = writeln!(
            out,
            "<tr><td><code>{}</code></td><td>{:?}</td><td><span class=\"badge {}\">{:?}</span></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&res.url),
            res.kind,
            state_badge,
            res.status,
            escape_html(&status),
            escape_html(&size),
            encoding_html,
            escape_html(detail),
        );
    }
    let _ = writeln!(out, "</tbody></table></section>");
}

fn render_limitations_section(out: &mut String, limitations: &[String]) {
    if limitations.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "<section class=\"panel\"><h2>Scope &amp; Evidence Limitations</h2><ul>"
    );
    for lim in limitations {
        let _ = writeln!(out, "<li>{}</li>", escape_html(lim));
    }
    let _ = writeln!(out, "</ul></section>");
}

const fn verdict_class(verdict: DomainVerdict) -> &'static str {
    match verdict {
        DomainVerdict::Pass => "sev-pass",
        DomainVerdict::Fail => "sev-crit",
        DomainVerdict::InsufficientEvidence => "sev-med",
        DomainVerdict::NotApplicable | DomainVerdict::Waived => "sev-low",
    }
}

fn wrap_document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>{}</title>\n\
         <style>{}</style>\n\
         </head>\n<body>\n<main class=\"wrap\">\n{}\n</main>\n</body>\n</html>\n",
        escape_html(title),
        REPORT_CSS,
        body,
    )
}

const REPORT_CSS: &str = r"
:root { color-scheme: light dark; --bg: #0f1419; --panel: #182028; --text: #e6edf3; --muted: #8b949e; --border: #2d3748; --pass: #1f883d; --crit: #cf222e; --high: #d97706; --med: #2563eb; --low: #4b5563; }
@media (prefers-color-scheme: light) { :root { --bg: #f6f8fa; --panel: #ffffff; --text: #1f2328; --muted: #57606a; --border: #d0d7de; } }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.5; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 24px 16px 48px; }
.hero { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 20px; }
.eyebrow { margin: 0 0 4px; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
h1 { margin: 0 0 6px; font-size: 22px; overflow-wrap: anywhere; }
h2 { margin: 0 0 12px; font-size: 17px; }
h3 { margin: 16px 0 8px; font-size: 15px; }
.meta, .muted { color: var(--muted); font-size: 13px; margin: 0; }
.verdict { padding: 8px 14px; border-radius: 6px; font-weight: 700; font-size: 14px; color: #fff; white-space: nowrap; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; }
.card .label { display: block; font-size: 12px; color: var(--muted); }
.card strong { font-size: 22px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 18px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #fff; }
.sev-pass { background: var(--pass); }
.sev-crit { background: var(--crit); }
.sev-high { background: var(--high); }
.sev-med { background: var(--med); }
.sev-low { background: var(--low); }
.card.sev-crit, .card.sev-high, .card.sev-med, .card.sev-pass { background: var(--panel); border-left: 4px solid currentColor; }
.card.sev-crit { border-left-color: var(--crit); }
.card.sev-high { border-left-color: var(--high); }
.card.sev-med { border-left-color: var(--med); }
.card.sev-pass { border-left-color: var(--pass); }
.finding { border: 1px solid var(--border); border-left-width: 4px; border-radius: 6px; padding: 12px; margin-bottom: 10px; background: transparent; }
.finding.sev-crit { border-left-color: var(--crit); }
.finding.sev-high { border-left-color: var(--high); }
.finding.sev-med { border-left-color: var(--med); }
.finding.sev-low { border-left-color: var(--low); }
.finding-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px; }
.fix { font-size: 13px; margin: 6px 0 0; }
.evidence { margin: 8px 0 0; padding-left: 18px; font-size: 12px; color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; overflow-wrap: anywhere; }
.pre-wrap { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; margin: 0; }
";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::analysis::assessment::{DomainAssessment, QualityDomain, assess_audit_report};
    use crate::brigade::DwarfId;
    use crate::discovery::{
        CrawlCoverage, ResourceCoverage, ResourceKind, ResourceObservation, ResourceStatus,
        SystemicClassification, SystemicIssue,
    };
    use crate::domain::{
        AuditTarget, CollectorOutcome, Confidence, EvidenceLevel, EvidenceRef, EvidenceSnapshot,
        EvidenceSource, Finding, FindingCategory, FindingFingerprint, FindingKind, HttpEvidence,
        Measurement, MeasurementUnit, RuleId, TargetPolicy,
    };

    #[test]
    fn audit_html_escapes_hostile_strings_and_includes_verdict_and_findings() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let body_html =
            "<html><head><title><script>alert(1)</script></title></head><body>Hi</body></html>";
        let snapshot = EvidenceSnapshot {
            target: target.clone(),
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: vec![],
                    headers: vec![],
                    body_bytes: body_html.len(),
                    body_text: body_html.to_owned(),
                    body_truncated: false,
                    elapsed_ms: Measurement::Measured {
                        value: 42,
                        unit: MeasurementUnit::Milliseconds,
                    },
                },
            },
            tls: CollectorOutcome::Skipped {
                reason: "not requested".to_owned(),
            },
            browser: CollectorOutcome::Skipped {
                reason: "not requested".to_owned(),
            },
            lighthouse: CollectorOutcome::Skipped {
                reason: "not requested".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "not requested".to_owned(),
            },
        };
        let mut report = analysis::run_all(&snapshot);
        report.analysers[0].findings.push(Finding {
            rule_id: RuleId("sec.test.xss".to_owned()),
            category: FindingCategory::Security,
            kind: FindingKind::Deterministic,
            severity: Severity::Critical,
            confidence: Confidence::High,
            evidence_level: EvidenceLevel::Source,
            title: "Hostile <script>alert(1)</script> title".to_owned(),
            summary: "Observed unescaped <img onerror=alert(1)>".to_owned(),
            remediation: Some("Escape HTML before rendering.".to_owned()),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                "<script>alert(1)</script>",
            )],
            fingerprint: FindingFingerprint("fp-1".to_owned()),
        });
        report.summary.critical_findings += 1;
        let assessment = assess_audit_report(&report);

        let html = render_audit_html(&report, &assessment);
        assert!(html.contains("<!doctype html>"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("Top Blockers"));
        assert!(html.contains("Escape HTML before rendering."));
        assert!(html.contains("sec.test.xss"));
    }

    #[test]
    fn scan_html_renders_systemic_clusters_and_coverage() {
        let coverage = CrawlCoverage {
            discovered_urls: 12,
            fetched_urls: 10,
            analysed_urls: 10,
            failed_urls: 1,
            skipped_budget_urls: 1,
            max_pages: 50,
            max_depth: 3,
            complete: true,
            resources: ResourceCoverage {
                discovered_resources: 5,
                fetched_resources: 4,
                failed_resources: 1,
                ..ResourceCoverage::default()
            },
            ..CrawlCoverage::default()
        };
        let issues = vec![SystemicIssue {
            id: "cluster-1".to_owned(),
            rule_id: RuleId("browser.runtime.console_error".to_owned()),
            affected_urls: vec![
                "https://example.com/".to_owned(),
                "https://example.com/pricing".to_owned(),
            ],
            affected_page_types: vec![],
            classification: SystemicClassification::VerifiedCommonCause,
            summary: "Shared <script> analytics bundle failed on 2 pages".to_owned(),
            recurrence_confidence: Confidence::High,
            shared_cause_confidence: Confidence::High,
            severity: Severity::High,
            dwarf_id: DwarfId::Browser,
        }];
        let resources = vec![ResourceObservation {
            url: "https://cdn.example.com/app.js".to_owned(),
            kind: ResourceKind::Script,
            status: ResourceStatus::Failed,
            http_status: Some(500),
            error: Some("HTTP 500".to_owned()),
            ..ResourceObservation::default()
        }];
        let assessment = QualityAssessment {
            domains: vec![DomainAssessment {
                domain: QualityDomain::RuntimeStability,
                verdict: DomainVerdict::Fail,
                critical_high_count: 1,
                medium_count: 0,
                low_info_count: 0,
                checks_unavailable: 0,
                rationale: "1 systemic runtime error".to_owned(),
            }],
            overall_verdict: DomainVerdict::Fail,
            blockers: vec!["browser.runtime.console_error on 2 pages".to_owned()],
            limitations: vec![],
        };

        let html = render_scan_html(&ScanHtmlInput {
            run_id: "run-123",
            application: "https://example.com/",
            seed_url: "https://example.com/",
            coverage: &coverage,
            resources: &resources,
            systemic_issues: &issues,
            graph_results: &[],
            quality_assessment: &assessment,
            stored_at: Some("/tmp/evidence.db"),
        });

        assert!(html.contains("Systemic Issues (Clustered Across Pages)"));
        assert!(html.contains("browser.runtime.console_error"));
        assert!(html.contains("https://cdn.example.com/app.js"));
        assert!(!html.contains("<script> analytics"));
        assert!(html.contains("&lt;script&gt; analytics"));
    }

    #[test]
    fn scan_html_prioritises_failed_and_heaviest_resources_and_summarises_payload() {
        let coverage = CrawlCoverage {
            discovered_urls: 2,
            fetched_urls: 2,
            analysed_urls: 2,
            resources: ResourceCoverage {
                discovered_resources: 3,
                fetched_resources: 2,
                failed_resources: 1,
                ..ResourceCoverage::default()
            },
            ..CrawlCoverage::default()
        };
        let resources = vec![
            ResourceObservation {
                url: "https://example.com/small.css".to_owned(),
                kind: ResourceKind::Stylesheet,
                status: ResourceStatus::Fetched,
                http_status: Some(200),
                byte_len: Some(2_048),
                content_encoding: Some("gzip".to_owned()),
                ..ResourceObservation::default()
            },
            ResourceObservation {
                url: "https://example.com/heavy.js".to_owned(),
                kind: ResourceKind::Script,
                status: ResourceStatus::Fetched,
                http_status: Some(200),
                byte_len: Some(150_000),
                content_encoding: None,
                ..ResourceObservation::default()
            },
            ResourceObservation {
                url: "https://example.com/broken.js".to_owned(),
                kind: ResourceKind::Script,
                status: ResourceStatus::Failed,
                http_status: Some(503),
                error: Some("HTTP 503".to_owned()),
                ..ResourceObservation::default()
            },
        ];
        let assessment = QualityAssessment {
            domains: vec![],
            overall_verdict: DomainVerdict::Fail,
            blockers: vec![],
            limitations: vec![],
        };

        let html = render_scan_html(&ScanHtmlInput {
            run_id: "run-prio",
            application: "https://example.com/",
            seed_url: "https://example.com/",
            coverage: &coverage,
            resources: &resources,
            systemic_issues: &[],
            graph_results: &[],
            quality_assessment: &assessment,
            stored_at: None,
        });

        let broken_pos = html.find("https://example.com/broken.js").unwrap();
        let heavy_pos = html.find("https://example.com/heavy.js").unwrap();
        let small_pos = html.find("https://example.com/small.css").unwrap();
        assert!(broken_pos < heavy_pos);
        assert!(heavy_pos < small_pos);
        assert!(html.contains("uncompressed"));
        assert!(html.contains("Measured payload"));
    }

    #[test]
    fn diff_html_renders_regressions_and_escapes_hostile_strings() {
        let mut diff = crate::persistence::RegressionReport {
            baseline_target: "https://example.com/".to_owned(),
            current_target: "https://example.com/".to_owned(),
            baseline_captured_at_unix_secs: 100,
            current_captured_at_unix_secs: 200,
            not_comparable_reason: None,
            new_findings: vec![Finding {
                fingerprint: FindingFingerprint("fp-new".to_owned()),
                rule_id: RuleId("sec.test.new".to_owned()),
                category: FindingCategory::Security,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::High,
                confidence: Confidence::High,
                title: "New <script>alert(1)</script> regression".to_owned(),
                summary: "Regression details".to_owned(),
                evidence_refs: vec![],
                remediation: Some("Fix it".to_owned()),
            }],
            persisting_findings: vec![],
            resolved_findings: vec![],
            unverified_findings: vec![],
            changed_findings: vec![],
            worsened_findings: vec![],
            improved_findings: vec![],
            reintroduced_findings: vec![],
            summary: crate::persistence::RegressionSummary {
                new_count: 1,
                ..Default::default()
            },
            rendered_text: None,
        };
        diff.summary.resolved_count = 2;

        let html = render_diff_html(&diff);
        assert!(html.contains("REGRESSIONS"));
        assert!(html.contains("New Findings (1)"));
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn batch_html_renders_portfolio_table_and_escapes_errors() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let snapshot = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Skipped {
                reason: "offline".to_owned(),
            },
            tls: CollectorOutcome::Skipped {
                reason: "offline".to_owned(),
            },
            browser: CollectorOutcome::Skipped {
                reason: "offline".to_owned(),
            },
            lighthouse: CollectorOutcome::Skipped {
                reason: "offline".to_owned(),
            },
            axe: CollectorOutcome::Skipped {
                reason: "offline".to_owned(),
            },
        };
        let report = analysis::run_all(&snapshot);
        let html = render_batch_html(
            2,
            1,
            1,
            &[BatchHtmlError {
                raw_target: "http://<bad>",
                error: "invalid host",
            }],
            &[BatchHtmlItem {
                report: &report,
                passed: false,
            }],
        );
        assert!(html.contains("Batch Portfolio Audit"));
        assert!(html.contains("https://example.com/"));
        assert!(!html.contains("http://<bad>"));
        assert!(html.contains("http://&lt;bad&gt;"));
    }
}
