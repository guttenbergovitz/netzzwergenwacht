//! Bounded `axe-core` subprocess adapter.
//!
//! Invokes the `@axe-core/cli` (`axe`) binary in headless mode with an explicit
//! timeout and parses its JSON report into typed [`AxeEvidence`].

use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use crate::adapters::run_bounded_command;
use crate::domain::{AuditTarget, AxeEvidence, AxeViolation, CollectorOutcome};

/// Runs `axe` against `target` within `timeout`, returning a typed outcome.
///
/// Respects `NZW_AXE_BIN` if set, otherwise invokes `axe`. If the binary is
/// not installed, returns [`CollectorOutcome::Failed`] without aborting the
/// remaining audit stages.
pub async fn run_axe(target: &AuditTarget, timeout: Duration) -> CollectorOutcome<AxeEvidence> {
    let bin = std::env::var("NZW_AXE_BIN").unwrap_or_else(|_| "axe".to_owned());
    let mut cmd = Command::new(bin);
    cmd.arg(target.as_str()).arg("--stdout");

    let stdout = match run_bounded_command("axe", &mut cmd, timeout).await {
        Ok(out) => out,
        Err(error) => return CollectorOutcome::Failed { error },
    };

    match parse_axe_json(&stdout) {
        Ok(evidence) => CollectorOutcome::Captured { data: evidence },
        Err(error) => CollectorOutcome::Failed { error },
    }
}

/// Parses raw `@axe-core/cli` JSON output (array or single report object) into
/// typed [`AxeEvidence`].
///
/// # Errors
///
/// Returns an error string if the payload is not valid JSON or lacks a
/// `violations` array.
pub fn parse_axe_json(raw: &str) -> Result<AxeEvidence, String> {
    let root: Value = serde_json::from_str(raw).map_err(|e| format!("invalid axe JSON: {e}"))?;

    let report = match &root {
        Value::Array(items) => items
            .first()
            .ok_or_else(|| "axe JSON array is empty".to_owned())?,
        Value::Object(_) => &root,
        _ => return Err("axe JSON must be an object or array".to_owned()),
    };

    let violations_val = report
        .get("violations")
        .and_then(Value::as_array)
        .ok_or_else(|| "axe JSON missing `violations` array".to_owned())?;

    let axe_version = report
        .pointer("/testEngine/version")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_owned();

    let violations = violations_val
        .iter()
        .filter_map(|v| {
            let id = v.get("id").and_then(Value::as_str)?.to_owned();
            let impact = v.get("impact").and_then(Value::as_str).map(str::to_owned);
            let description = v
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let help_url = v
                .get("helpUrl")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let nodes_arr = v.get("nodes").and_then(Value::as_array);
            let nodes_count = nodes_arr.map_or(0, Vec::len);
            let target_selectors = nodes_arr
                .into_iter()
                .flatten()
                .filter_map(|node| node.get("target").and_then(Value::as_array))
                .filter_map(|targets| {
                    let parts: Vec<&str> = targets.iter().filter_map(Value::as_str).collect();
                    if parts.is_empty() {
                        None
                    } else {
                        let joined = parts.join(" >> ");
                        Some(joined.chars().take(160).collect::<String>())
                    }
                })
                .take(16)
                .collect();
            Some(AxeViolation {
                id,
                impact,
                description,
                help_url,
                nodes_count,
                target_selectors,
            })
        })
        .collect();

    let passes_count = report
        .get("passes")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let incomplete_count = report
        .get("incomplete")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    Ok(AxeEvidence {
        axe_version,
        violations,
        passes_count,
        incomplete_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_axe_cli_array_output() {
        let raw = r#"[
            {
                "testEngine": { "version": "4.10.2" },
                "violations": [
                    {
                        "id": "color-contrast",
                        "impact": "serious",
                        "description": "Contrast ratio too low",
                        "helpUrl": "https://dequeuniversity.com/rules/axe/4.10/color-contrast",
                        "nodes": [{}, {}]
                    }
                ],
                "passes": [{}, {}, {}],
                "incomplete": [{}]
            }
        ]"#;

        let parsed = parse_axe_json(raw).unwrap();
        assert_eq!(parsed.axe_version, "4.10.2");
        assert_eq!(parsed.violations.len(), 1);
        assert_eq!(parsed.violations[0].id, "color-contrast");
        assert_eq!(parsed.violations[0].nodes_count, 2);
        assert_eq!(parsed.passes_count, 3);
        assert_eq!(parsed.incomplete_count, 1);
    }

    #[test]
    fn rejects_missing_violations_array() {
        let raw = r#"{ "testEngine": { "version": "4.10.2" } }"#;
        assert!(parse_axe_json(raw).is_err());
    }
}
