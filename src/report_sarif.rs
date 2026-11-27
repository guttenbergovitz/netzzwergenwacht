//! SARIF 2.1.0 exporter for CI/CD and GitHub Code Scanning integrations.
//!
//! Maps deterministic [`crate::domain::Finding`] items from single-page audits and clustered
//! [`SystemicIssue`] records from application scans into OASIS SARIF 2.1.0
//! JSON payloads without inventing locations or severities.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::analysis::AuditReport;
use crate::discovery::SystemicIssue;
use crate::domain::{Finding, Severity};
use crate::persistence::RegressionReport;

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_INFO_URI: &str = "https://github.com/guttenbergovitz/netzzwergenwacht";

/// Maps internal finding [`Severity`] to OASIS SARIF result level.
#[must_use]
pub const fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Renders a single-page [`AuditReport`] as a SARIF 2.1.0 JSON string.
#[must_use]
pub fn render_audit_sarif(report: &AuditReport) -> String {
    let mut rules_by_id: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    let uri = report.target.as_str();

    for analyser in &report.analysers {
        for finding in &analyser.findings {
            push_finding_sarif(finding, uri, None, &mut rules_by_id, &mut results);
        }
    }

    let rules: Vec<Value> = rules_by_id.into_values().collect();
    build_sarif_envelope(&rules, &results)
}

/// Aggregates findings from multiple [`AuditReport`] entries into one SARIF 2.1.0 payload.
#[must_use]
pub fn render_batch_sarif(reports: &[&AuditReport]) -> String {
    let mut rules_by_id: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    for report in reports {
        let uri = report.target.as_str();
        for analyser in &report.analysers {
            for finding in &analyser.findings {
                push_finding_sarif(finding, uri, None, &mut rules_by_id, &mut results);
            }
        }
    }
    let rules: Vec<Value> = rules_by_id.into_values().collect();
    build_sarif_envelope(&rules, &results)
}

/// Renders only new, reintroduced, and worsened findings from a [`RegressionReport`]
/// as a SARIF 2.1.0 payload so CI gates annotate regressions without baseline noise.
#[must_use]
pub fn render_diff_sarif(diff: &RegressionReport) -> String {
    let mut rules_by_id: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    let uri = diff.current_target.as_str();

    for finding in &diff.new_findings {
        push_finding_sarif(finding, uri, Some("[NEW] "), &mut rules_by_id, &mut results);
    }
    for finding in &diff.reintroduced_findings {
        push_finding_sarif(
            finding,
            uri,
            Some("[REINTRODUCED] "),
            &mut rules_by_id,
            &mut results,
        );
    }
    for finding in &diff.worsened_findings {
        push_finding_sarif(
            finding,
            uri,
            Some("[WORSENED] "),
            &mut rules_by_id,
            &mut results,
        );
    }

    let rules: Vec<Value> = rules_by_id.into_values().collect();
    build_sarif_envelope(&rules, &results)
}

fn push_finding_sarif<'a>(
    finding: &'a Finding,
    uri: &str,
    prefix: Option<&str>,
    rules_by_id: &mut BTreeMap<&'a str, Value>,
    results: &mut Vec<Value>,
) {
    let rule_id = finding.rule_id.0.as_str();
    let level = sarif_level(finding.severity);
    rules_by_id.entry(rule_id).or_insert_with(|| {
        json!({
            "id": rule_id,
            "shortDescription": { "text": finding.title },
            "fullDescription": { "text": finding.summary },
            "defaultConfiguration": { "level": level },
            "help": {
                "text": finding.remediation.as_deref().unwrap_or("Inspect captured evidence for remediation details.")
            }
        })
    });

    let mut msg = format!(
        "{}{}: {}",
        prefix.unwrap_or(""),
        finding.title,
        finding.summary
    );
    if let Some(remediation) = &finding.remediation {
        msg.push_str(" Recommendation: ");
        msg.push_str(remediation);
    }

    results.push(json!({
        "ruleId": rule_id,
        "level": level,
        "message": { "text": msg },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": uri }
            }
        }],
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint.0
        }
    }));
}

/// Renders clustered [`SystemicIssue`] records from a multi-page scan as a
/// SARIF 2.1.0 JSON string.
#[must_use]
pub fn render_scan_sarif(seed_url: &str, systemic_issues: &[SystemicIssue]) -> String {
    let mut rules_by_id: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();

    for issue in systemic_issues {
        let rule_id = issue.rule_id.0.as_str();
        let level = sarif_level(issue.severity);
        rules_by_id.entry(rule_id).or_insert_with(|| {
            json!({
                "id": rule_id,
                "shortDescription": { "text": format!("Systemic issue: {rule_id}") },
                "fullDescription": { "text": issue.summary },
                "defaultConfiguration": { "level": level }
            })
        });

        let primary_uri = issue.affected_urls.first().map_or(seed_url, String::as_str);
        let related_locations: Vec<Value> = issue
            .affected_urls
            .iter()
            .skip(1)
            .take(10)
            .enumerate()
            .map(|(idx, url)| {
                json!({
                    "id": idx + 1,
                    "physicalLocation": {
                        "artifactLocation": { "uri": url }
                    }
                })
            })
            .collect();

        results.push(json!({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": format!(
                    "{} (affects {} page(s))",
                    issue.summary,
                    issue.affected_urls.len()
                )
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": primary_uri }
                }
            }],
            "relatedLocations": related_locations,
            "partialFingerprints": {
                "primaryLocationLineHash": issue.id
            }
        }));
    }

    let rules: Vec<Value> = rules_by_id.into_values().collect();
    build_sarif_envelope(&rules, &results)
}

/// Renders a valid empty SARIF 2.1.0 envelope for commands without finding locations.
#[must_use]
pub fn empty_sarif() -> String {
    build_sarif_envelope(&[], &[])
}

fn build_sarif_envelope(rules: &[Value], results: &[Value]) -> String {
    let payload = json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "NetzZwergenWacht",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": TOOL_INFO_URI,
                    "rules": rules
                }
            },
            "results": results
        }]
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis;
    use crate::brigade::DwarfId;
    use crate::discovery::SystemicClassification;
    use crate::domain::{
        AuditTarget, CollectorOutcome, Confidence, EvidenceLevel, EvidenceSnapshot, Finding,
        FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, Measurement,
        MeasurementUnit, RuleId, TargetPolicy,
    };

    #[test]
    fn audit_sarif_produces_valid_2_1_0_payload_with_rules_and_fingerprints() {
        let target = AuditTarget::parse("https://example.com/", TargetPolicy::PublicOnly).unwrap();
        let body = "<html><head><title>Ok</title></head><body>Hi</body></html>";
        let snapshot = EvidenceSnapshot {
            target,
            captured_at_unix_secs: 1_700_000_000,
            http: CollectorOutcome::Captured {
                data: HttpEvidence {
                    final_url: "https://example.com/".to_owned(),
                    status_code: 200,
                    redirect_chain: vec![],
                    headers: vec![],
                    body_bytes: body.len(),
                    body_text: body.to_owned(),
                    body_truncated: false,
                    elapsed_ms: Measurement::Measured {
                        value: 15,
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
            fingerprint: FindingFingerprint("fp-sarif-1".to_owned()),
            rule_id: RuleId("sec.headers.csp".to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: "Missing Content-Security-Policy".to_owned(),
            summary: "Response has no CSP header.".to_owned(),
            evidence_refs: vec![],
            remediation: Some("Add a strict CSP header.".to_owned()),
        });

        let sarif_str = render_audit_sarif(&report);
        let parsed: Value = serde_json::from_str(&sarif_str).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        let run = &parsed["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "NetzZwergenWacht");
        let results = run["results"].as_array().unwrap();
        let csp = results
            .iter()
            .find(|r| r["ruleId"] == "sec.headers.csp")
            .unwrap();
        assert_eq!(csp["level"], "error");
        assert_eq!(
            csp["partialFingerprints"]["primaryLocationLineHash"],
            "fp-sarif-1"
        );
    }

    #[test]
    fn scan_sarif_clusters_systemic_issues_with_related_locations() {
        let issues = vec![SystemicIssue {
            id: "sys-1".to_owned(),
            rule_id: RuleId("browser.runtime.client_error_fallback".to_owned()),
            affected_urls: vec![
                "https://example.com/".to_owned(),
                "https://example.com/checkout".to_owned(),
            ],
            affected_page_types: vec![],
            classification: SystemicClassification::VerifiedCommonCause,
            summary: "Shared bundle crashed".to_owned(),
            recurrence_confidence: Confidence::High,
            shared_cause_confidence: Confidence::High,
            severity: Severity::Critical,
            dwarf_id: DwarfId::Browser,
        }];

        let sarif_str = render_scan_sarif("https://example.com/", &issues);
        let parsed: Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.com/checkout"
        );
    }

    #[test]
    fn diff_sarif_emits_only_new_reintroduced_and_worsened_regressions() {
        let make_finding = |id: &str, fp: &str| Finding {
            fingerprint: FindingFingerprint(fp.to_owned()),
            rule_id: RuleId(id.to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: id.to_owned(),
            summary: "summary".to_owned(),
            evidence_refs: vec![],
            remediation: None,
        };
        let diff = RegressionReport {
            baseline_target: "https://example.com/".to_owned(),
            current_target: "https://example.com/".to_owned(),
            baseline_captured_at_unix_secs: 100,
            current_captured_at_unix_secs: 200,
            not_comparable_reason: None,
            new_findings: vec![make_finding("sec.new", "fp-new")],
            persisting_findings: vec![make_finding("sec.old", "fp-old")],
            resolved_findings: vec![],
            unverified_findings: vec![],
            changed_findings: vec![],
            worsened_findings: vec![],
            improved_findings: vec![],
            reintroduced_findings: vec![make_finding("sec.reintro", "fp-reintro")],
            summary: crate::persistence::RegressionSummary {
                new_count: 1,
                persisting_count: 1,
                reintroduced_count: 1,
                ..Default::default()
            },
            rendered_text: None,
        };

        let sarif_str = render_diff_sarif(&diff);
        let parsed: Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "sec.new");
        assert_eq!(results[1]["ruleId"], "sec.reintro");
    }

    #[test]
    fn batch_sarif_aggregates_findings_across_targets() {
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
        let mut report = analysis::run_all(&snapshot);
        report.analysers[0].findings.push(Finding {
            fingerprint: FindingFingerprint("fp-batch".to_owned()),
            rule_id: RuleId("sec.batch.test".to_owned()),
            category: FindingCategory::Security,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Batch test".to_owned(),
            summary: "Batch summary".to_owned(),
            evidence_refs: vec![],
            remediation: None,
        });

        let sarif_str = render_batch_sarif(&[&report]);
        let parsed: Value = serde_json::from_str(&sarif_str).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert!(results.iter().any(|r| r["ruleId"] == "sec.batch.test"));
    }
}
