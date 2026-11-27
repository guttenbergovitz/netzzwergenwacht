//! Repeated laboratory performance series and budget evaluation (Phase II §5.5).
//!
//! Single-shot Lighthouse or browser runs cannot establish reliable performance
//! posture. This module aggregates repeated [`PerformanceSample`] series using
//! [`summarise_u64`] (`median`, `p75`, `iqr`) across explicit [`CacheState`] and
//! [`DeviceProfile`] conditions, strictly separating laboratory measurements
//! from field telemetry (`CrUX` / real-user INP).

use serde::{Deserialize, Serialize};

use crate::analysis::assessment::DomainVerdict;
use crate::analysis::profile::PerformanceBudgets;
use crate::analysis::stats::{DistributionSummary, summarise_u64};

/// Minimum repeated runs required before a laboratory series can assert a pass.
pub const MIN_REPEATED_SAMPLES: usize = 2;

/// Cache condition under which a performance series was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheState {
    /// Fresh browser context with empty HTTP/asset cache.
    ColdCache,
    /// Repeat navigation reusing warm cache.
    WarmCache,
}

/// Emulated or native device class for a performance series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceProfile {
    /// Mobile viewport and CPU/network profile.
    Mobile,
    /// Desktop viewport and profile.
    Desktop,
}

/// Explicit distinction between synthetic laboratory runs and real-user field telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementBasis {
    /// Synthetic controlled laboratory runs (never equivalent to field CrUX/INP).
    LaboratoryOnly,
}

/// Single laboratory run measurement sample.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PerformanceSample {
    /// Time to First Byte in milliseconds.
    pub ttfb_ms: Option<u64>,
    /// First Contentful Paint in milliseconds.
    pub fcp_ms: Option<u64>,
    /// Largest Contentful Paint in milliseconds.
    pub lcp_ms: Option<u64>,
    /// Cumulative Layout Shift in thousandths (`100` = `0.100`).
    pub cls_milli: Option<u64>,
    /// Total Blocking Time in milliseconds.
    pub tbt_ms: Option<u64>,
}

/// Input series for a single `(cache_state, device, throttling_profile)` matrix cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSeriesInput {
    /// Cache condition.
    pub cache_state: CacheState,
    /// Device class.
    pub device: DeviceProfile,
    /// Throttling profile label (e.g. `"mobile_slow_4g"`, `"unthrottled"`).
    pub throttling_profile: String,
    /// Ordered repeated samples.
    pub samples: Vec<PerformanceSample>,
}

/// Aggregated distribution summary and budget verdict for a repeated performance series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSeriesSummary {
    /// Cache condition.
    pub cache_state: CacheState,
    /// Device class.
    pub device: DeviceProfile,
    /// Throttling profile label.
    pub throttling_profile: String,
    /// Explicit measurement basis (`LaboratoryOnly`).
    pub measurement_basis: MeasurementBasis,
    /// Number of runs in the series.
    pub sample_count: usize,
    /// TTFB distribution (ms).
    pub ttfb_ms: DistributionSummary,
    /// FCP distribution (ms).
    pub fcp_ms: DistributionSummary,
    /// LCP distribution (ms).
    pub lcp_ms: DistributionSummary,
    /// CLS distribution (thousandths).
    pub cls_milli: DistributionSummary,
    /// TBT distribution (ms).
    pub tbt_ms: DistributionSummary,
    /// Series verdict (`Pass`, `Fail`, or `InsufficientEvidence`).
    pub verdict: DomainVerdict,
    /// Budget breaches evaluated against `p75`.
    pub budget_violations: Vec<String>,
    /// Explicit methodological limitations.
    pub limitations: Vec<String>,
}

/// Aggregates `input` into distributions and evaluates optional `budgets` at `p75`.
///
/// Fewer than [`MIN_REPEATED_SAMPLES`] runs or missing budgeted metrics yield
/// [`DomainVerdict::InsufficientEvidence`], never `Pass`.
#[must_use]
pub fn evaluate_performance_series(
    input: &PerformanceSeriesInput,
    budgets: Option<&PerformanceBudgets>,
) -> PerformanceSeriesSummary {
    let ttfb_samples: Vec<Option<u64>> = input.samples.iter().map(|s| s.ttfb_ms).collect();
    let fcp_samples: Vec<Option<u64>> = input.samples.iter().map(|s| s.fcp_ms).collect();
    let lcp_samples: Vec<Option<u64>> = input.samples.iter().map(|s| s.lcp_ms).collect();
    let cls_samples: Vec<Option<u64>> = input.samples.iter().map(|s| s.cls_milli).collect();
    let tbt_samples: Vec<Option<u64>> = input.samples.iter().map(|s| s.tbt_ms).collect();

    let ttfb_ms = summarise_u64(&ttfb_samples);
    let fcp_ms = summarise_u64(&fcp_samples);
    let lcp_ms = summarise_u64(&lcp_samples);
    let cls_milli = summarise_u64(&cls_samples);
    let tbt_ms = summarise_u64(&tbt_samples);

    let sample_count = input.samples.len();
    let mut budget_violations = Vec::new();
    let mut limitations = vec![
        "Laboratory measurements only; not equivalent to field Core Web Vitals (CrUX/INP)."
            .to_owned(),
    ];

    let mut insufficient = sample_count < MIN_REPEATED_SAMPLES;
    if insufficient {
        limitations.push(format!(
            "Only {sample_count} sample(s) captured; at least {MIN_REPEATED_SAMPLES} repeated runs are required."
        ));
    }

    if let Some(b) = budgets {
        check_budget(
            "LCP",
            lcp_ms.p75,
            b.max_lcp_ms,
            "ms",
            &mut insufficient,
            &mut budget_violations,
            &mut limitations,
        );
        check_budget(
            "CLS",
            cls_milli.p75,
            b.max_cls_milli.map(u64::from),
            "milli",
            &mut insufficient,
            &mut budget_violations,
            &mut limitations,
        );
        check_budget(
            "TTFB",
            ttfb_ms.p75,
            b.max_ttfb_ms,
            "ms",
            &mut insufficient,
            &mut budget_violations,
            &mut limitations,
        );
    }

    let verdict = if !budget_violations.is_empty() {
        DomainVerdict::Fail
    } else if insufficient {
        DomainVerdict::InsufficientEvidence
    } else {
        DomainVerdict::Pass
    };

    PerformanceSeriesSummary {
        cache_state: input.cache_state,
        device: input.device,
        throttling_profile: input.throttling_profile.clone(),
        measurement_basis: MeasurementBasis::LaboratoryOnly,
        sample_count,
        ttfb_ms,
        fcp_ms,
        lcp_ms,
        cls_milli,
        tbt_ms,
        verdict,
        budget_violations,
        limitations,
    }
}

fn check_budget(
    metric: &str,
    observed_p75: Option<u64>,
    max_allowed: Option<u64>,
    unit: &str,
    insufficient: &mut bool,
    violations: &mut Vec<String>,
    limitations: &mut Vec<String>,
) {
    let Some(limit) = max_allowed else {
        return;
    };
    let Some(p75) = observed_p75 else {
        *insufficient = true;
        limitations.push(format!(
            "Budgeted metric {metric} has no observed p75 value."
        ));
        return;
    };
    if p75 > limit {
        violations.push(format!(
            "{metric} p75 ({p75} {unit}) exceeded budget ({limit} {unit})"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ttfb: u64, lcp: u64, cls: u64) -> PerformanceSample {
        PerformanceSample {
            ttfb_ms: Some(ttfb),
            fcp_ms: Some(ttfb + 200),
            lcp_ms: Some(lcp),
            cls_milli: Some(cls),
            tbt_ms: Some(50),
        }
    }

    #[test]
    fn single_shot_series_is_insufficient_evidence_never_pass() {
        let input = PerformanceSeriesInput {
            cache_state: CacheState::ColdCache,
            device: DeviceProfile::Mobile,
            throttling_profile: "mobile_slow_4g".to_owned(),
            samples: vec![sample(120, 1800, 20)],
        };
        let res = evaluate_performance_series(&input, None);
        assert_eq!(res.verdict, DomainVerdict::InsufficientEvidence);
        assert_eq!(res.measurement_basis, MeasurementBasis::LaboratoryOnly);
    }

    #[test]
    fn repeated_series_computes_p75_and_enforces_budgets() {
        let input = PerformanceSeriesInput {
            cache_state: CacheState::WarmCache,
            device: DeviceProfile::Desktop,
            throttling_profile: "unthrottled".to_owned(),
            samples: vec![
                sample(100, 1500, 10),
                sample(120, 2200, 20),
                sample(140, 2900, 30),
                sample(160, 3100, 40),
            ],
        };
        let budgets = PerformanceBudgets {
            max_lcp_ms: Some(2500),
            max_cls_milli: Some(100),
            max_ttfb_ms: Some(500),
        };
        let res = evaluate_performance_series(&input, Some(&budgets));
        assert_eq!(res.verdict, DomainVerdict::Fail);
        assert_eq!(res.budget_violations.len(), 1);
        assert!(res.budget_violations[0].contains("LCP p75"));
    }

    #[test]
    fn repeated_series_within_budget_passes_with_lab_limitation() {
        let input = PerformanceSeriesInput {
            cache_state: CacheState::ColdCache,
            device: DeviceProfile::Mobile,
            throttling_profile: "mobile_slow_4g".to_owned(),
            samples: vec![sample(150, 1800, 20), sample(180, 2100, 40)],
        };
        let budgets = PerformanceBudgets {
            max_lcp_ms: Some(2500),
            max_cls_milli: Some(100),
            max_ttfb_ms: Some(500),
        };
        let res = evaluate_performance_series(&input, Some(&budgets));
        assert_eq!(res.verdict, DomainVerdict::Pass);
        assert!(res.limitations.iter().any(|l| l.contains("CrUX/INP")));
    }
}
