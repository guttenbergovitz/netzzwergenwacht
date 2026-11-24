//! Bounded Lighthouse subprocess adapter.
//!
//! Invokes the `lighthouse` CLI in headless mode with an explicit timeout and
//! parses its JSON report into typed [`LighthouseMetrics`].

use std::time::Duration;

use serde_json::Value;
use tokio::process::Command;

use crate::adapters::run_bounded_command;
use crate::domain::{
    AuditTarget, CollectorOutcome, LighthouseMetrics, Measurement, MeasurementUnit,
};

/// Runs `lighthouse` against `target` within `timeout`, returning a typed outcome.
///
/// If the `lighthouse` binary is not installed, returns [`CollectorOutcome::Failed`]
/// with a clear diagnostic rather than aborting the entire audit.
pub async fn run_lighthouse(
    target: &AuditTarget,
    timeout: Duration,
) -> CollectorOutcome<LighthouseMetrics> {
    let mut cmd = Command::new("lighthouse");
    cmd.arg(target.as_str())
        .arg("--output=json")
        .arg("--output-path=stdout")
        .arg("--quiet")
        .arg("--chrome-flags=--headless --no-sandbox --disable-gpu");

    let stdout = match run_bounded_command("lighthouse", &mut cmd, timeout).await {
        Ok(out) => out,
        Err(error) => return CollectorOutcome::Failed { error },
    };

    match parse_lighthouse_json(&stdout) {
        Ok(metrics) => CollectorOutcome::Captured { data: metrics },
        Err(error) => CollectorOutcome::Failed { error },
    }
}

/// Parses raw Lighthouse JSON output into typed [`LighthouseMetrics`].
///
/// # Errors
///
/// Returns an error string if the payload is not valid JSON or lacks a
/// `lighthouseVersion` string.
pub fn parse_lighthouse_json(raw: &str) -> Result<LighthouseMetrics, String> {
    let root: Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid Lighthouse JSON: {e}"))?;

    let version = root
        .get("lighthouseVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| "Lighthouse JSON missing `lighthouseVersion`".to_owned())?
        .to_owned();

    let audits = root.get("audits");
    let lcp_ms = extract_ms_audit(audits, "largest-contentful-paint");
    let fcp_ms = extract_ms_audit(audits, "first-contentful-paint");
    let tbt_ms = extract_ms_audit(audits, "total-blocking-time");
    let cls_milli = extract_cls_milli(audits);

    let performance_score = root
        .pointer("/categories/performance/score")
        .and_then(Value::as_f64)
        .and_then(|s| {
            let pct = (s * 100.0).round();
            if (0.0..=100.0).contains(&pct) {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Some(pct as u8)
            } else {
                None
            }
        });

    Ok(LighthouseMetrics {
        lighthouse_version: version,
        lcp_ms,
        cls_milli,
        fcp_ms,
        tbt_ms,
        performance_score,
    })
}

fn extract_ms_audit(audits: Option<&Value>, key: &str) -> Measurement<u64> {
    let Some(val) = audits
        .and_then(|a| a.get(key))
        .and_then(|item| item.get("numericValue"))
        .and_then(Value::as_f64)
    else {
        return Measurement::Unavailable {
            reason: format!("Lighthouse audit `{key}` numericValue absent"),
        };
    };

    if val.is_finite() && val >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rounded = val.round() as u64;
        Measurement::Measured {
            value: rounded,
            unit: MeasurementUnit::Milliseconds,
        }
    } else {
        Measurement::Failed {
            error: format!("Lighthouse audit `{key}` returned non-finite or negative value"),
        }
    }
}

fn extract_cls_milli(audits: Option<&Value>) -> Measurement<u64> {
    let Some(val) = audits
        .and_then(|a| a.get("cumulative-layout-shift"))
        .and_then(|item| item.get("numericValue"))
        .and_then(Value::as_f64)
    else {
        return Measurement::Unavailable {
            reason: "Lighthouse audit `cumulative-layout-shift` numericValue absent".to_owned(),
        };
    };

    if val.is_finite() && val >= 0.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let milli = (val * 1000.0).round() as u64;
        Measurement::Measured {
            value: milli,
            unit: MeasurementUnit::Count,
        }
    } else {
        Measurement::Failed {
            error: "Lighthouse CLS returned non-finite or negative value".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lighthouse_json_fixture() {
        let fixture = r#"{
            "lighthouseVersion": "12.2.0",
            "categories": {
                "performance": { "score": 0.92 }
            },
            "audits": {
                "largest-contentful-paint": { "numericValue": 1840.4 },
                "cumulative-layout-shift": { "numericValue": 0.045 },
                "first-contentful-paint": { "numericValue": 910.2 },
                "total-blocking-time": { "numericValue": 45.0 }
            }
        }"#;

        let metrics = parse_lighthouse_json(fixture).unwrap();
        assert_eq!(metrics.lighthouse_version, "12.2.0");
        assert_eq!(metrics.performance_score, Some(92));
        assert_eq!(
            metrics.lcp_ms,
            Measurement::Measured {
                value: 1840,
                unit: MeasurementUnit::Milliseconds
            }
        );
        assert_eq!(
            metrics.cls_milli,
            Measurement::Measured {
                value: 45,
                unit: MeasurementUnit::Count
            }
        );
    }

    #[test]
    fn missing_audits_are_recorded_as_unavailable_not_zero() {
        let fixture = r#"{ "lighthouseVersion": "12.2.0", "audits": {} }"#;
        let metrics = parse_lighthouse_json(fixture).unwrap();
        assert!(matches!(metrics.lcp_ms, Measurement::Unavailable { .. }));
        assert!(matches!(metrics.cls_milli, Measurement::Unavailable { .. }));
    }
}
