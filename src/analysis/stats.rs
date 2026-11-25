//! Native Rust descriptive statistics and robust outlier detection.
//!
//! Provides deterministic, sample-size-aware summary metrics and Tukey IQR
//! outlier detection over numeric telemetry without external dependencies.

use serde::{Deserialize, Serialize};

/// Descriptive statistics computed over a series of optional `u64` observations.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DistributionSummary {
    /// Number of non-missing observations.
    pub count: usize,
    /// Number of missing (`None`) observations.
    pub missing_count: usize,
    /// Minimum observed value (`None` when `count == 0`).
    pub min: Option<u64>,
    /// Maximum observed value (`None` when `count == 0`).
    pub max: Option<u64>,
    /// Arithmetic mean rounded to nearest integer (`None` when `count == 0`).
    pub mean: Option<u64>,
    /// 50th percentile / median (`None` when `count == 0`).
    pub median: Option<u64>,
    /// 75th percentile (`None` when `count == 0`).
    pub p75: Option<u64>,
    /// 95th percentile (`None` when `count == 0`).
    pub p95: Option<u64>,
    /// Interquartile range (`p75 - p25`, `None` when `count < 2`).
    pub iqr: Option<u64>,
    /// Median absolute deviation from the median (`None` when `count < 2`).
    pub mad: Option<u64>,
}

/// Observation exceeding the upper Tukey IQR fence (`Q3 + 1.5 * IQR`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutlierPoint {
    /// Identifier of the anomalous entity (for example page URL or asset URL).
    pub label: String,
    /// Observed numeric value.
    pub value: u64,
    /// Upper Tukey fence threshold (`Q3 + 1.5 * IQR`).
    pub upper_fence: u64,
}

/// Computes descriptive statistics for `samples`, preserving `missing_count`.
#[must_use]
pub fn summarise_u64(samples: &[Option<u64>]) -> DistributionSummary {
    let mut present: Vec<u64> = samples.iter().copied().flatten().collect();
    let missing_count = samples.len().saturating_sub(present.len());
    if present.is_empty() {
        return DistributionSummary {
            count: 0,
            missing_count,
            ..DistributionSummary::default()
        };
    }

    present.sort_unstable();
    let count = present.len();
    let sum: u128 = present.iter().map(|&v| u128::from(v)).sum();
    let mean = u64::try_from((sum + u128::from(count as u64) / 2) / u128::from(count as u64))
        .unwrap_or(u64::MAX);

    let p25 = percentile_sorted(&present, 25);
    let median = percentile_sorted(&present, 50);
    let p75 = percentile_sorted(&present, 75);
    let p95 = percentile_sorted(&present, 95);

    let (iqr, mad) = if count >= 2 {
        let mut abs_devs: Vec<u64> = present.iter().map(|&v| v.abs_diff(median)).collect();
        abs_devs.sort_unstable();
        (
            Some(p75.saturating_sub(p25)),
            Some(percentile_sorted(&abs_devs, 50)),
        )
    } else {
        (None, None)
    };

    DistributionSummary {
        count,
        missing_count,
        min: present.first().copied(),
        max: present.last().copied(),
        mean: Some(mean),
        median: Some(median),
        p75: Some(p75),
        p95: Some(p95),
        iqr,
        mad,
    }
}

/// Identifies upper-tail outliers using Tukey's `Q3 + 1.5 * IQR` fence.
///
/// Returns an empty vector when fewer than 4 samples are provided to avoid
/// unstable quartile estimates on tiny samples.
#[must_use]
pub fn identify_upper_iqr_outliers(samples: &[(String, u64)]) -> Vec<OutlierPoint> {
    if samples.len() < 4 {
        return Vec::new();
    }
    let mut sorted: Vec<u64> = samples.iter().map(|(_, v)| *v).collect();
    sorted.sort_unstable();
    let q1 = percentile_sorted(&sorted, 25);
    let q3 = percentile_sorted(&sorted, 75);
    let iqr = q3.saturating_sub(q1);
    let upper_fence = q3.saturating_add(iqr.saturating_add(iqr / 2));

    let mut outliers: Vec<OutlierPoint> = samples
        .iter()
        .filter(|(_, v)| *v > upper_fence)
        .map(|(label, v)| OutlierPoint {
            label: label.clone(),
            value: *v,
            upper_fence,
        })
        .collect();
    outliers.sort_by_key(|o| std::cmp::Reverse(o.value));
    outliers
}

fn percentile_sorted(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) * pct) / 100;
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_descriptive_stats_and_missing_count() {
        let samples = vec![Some(100), None, Some(200), Some(300), Some(400), Some(500)];
        let summary = summarise_u64(&samples);
        assert_eq!(summary.count, 5);
        assert_eq!(summary.missing_count, 1);
        assert_eq!(summary.min, Some(100));
        assert_eq!(summary.max, Some(500));
        assert_eq!(summary.mean, Some(300));
        assert_eq!(summary.median, Some(300));
        assert_eq!(summary.iqr, Some(200));
        assert_eq!(summary.mad, Some(100));
    }

    #[test]
    fn handles_empty_and_all_missing_samples() {
        let summary = summarise_u64(&[None, None]);
        assert_eq!(summary.count, 0);
        assert_eq!(summary.missing_count, 2);
        assert_eq!(summary.median, None);
    }

    #[test]
    fn identifies_upper_iqr_outliers_only_when_sample_size_sufficient() {
        let tiny = vec![("a".to_owned(), 10), ("b".to_owned(), 1000)];
        assert_eq!(identify_upper_iqr_outliers(&tiny).len(), 0);

        let normal = vec![
            ("p1".to_owned(), 100),
            ("p2".to_owned(), 110),
            ("p3".to_owned(), 120),
            ("p4".to_owned(), 130),
            ("p5".to_owned(), 140),
            ("slow".to_owned(), 950),
        ];
        let outliers = identify_upper_iqr_outliers(&normal);
        assert_eq!(outliers.len(), 1);
        assert_eq!(outliers[0].label, "slow");
        assert_eq!(outliers[0].value, 950);
    }
}
