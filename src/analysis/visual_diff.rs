//! Deterministic cross-run visual evidence comparison (Phase II §5.7 & §9).
//!
//! Compares [`VisualArtifactEvidence`] between a baseline and current
//! [`EvidenceSnapshot`] without relying on subjective LLM vision judgments.
//! Viewport mismatches or missing artefacts are reported as `NonComparable`,
//! never as `Unchanged`, and minor screenshot digest changes with stable
//! landmark geometry are separated from material layout regressions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::diagnostics_lifecycle::VisualArtifactEvidence;
use crate::domain::{CollectorOutcome, EvidenceRef, EvidenceSnapshot, EvidenceSource};

/// Tolerance policy for deterministic visual comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VisualComparisonPolicy {
    /// Maximum tolerated shift in above-the-fold retained element coverage
    /// (in thousandths, e.g. `150` = `15%`) when dynamic content changes.
    pub max_coverage_delta_milli: u32,
}

impl Default for VisualComparisonPolicy {
    fn default() -> Self {
        Self {
            max_coverage_delta_milli: 150,
        }
    }
}

/// Classification of a cross-run visual comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VisualComparisonOutcome {
    /// Viewport, screenshot digest, and landmarks match identically.
    Unchanged,
    /// Screenshot digest changed, but landmark visibility and coverage remained within tolerance.
    DynamicVarianceWithinTolerance,
    /// Significant layout coverage shift or primary landmark visibility change observed.
    LayoutRegression,
    /// Runs cannot be compared (missing artefacts, skipped browser, or differing viewports).
    NonComparable {
        /// Explicit reason comparison could not be established.
        reason: String,
    },
}

/// Result of comparing visual artefacts across two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VisualComparisonReport {
    /// Classification of the visual delta.
    pub outcome: VisualComparisonOutcome,
    /// Shared viewport dimensions `(width, height)` when comparable.
    pub viewport: Option<(u32, u32)>,
    /// Whether the SHA-256 screenshot digest changed (`None` if either digest is absent).
    pub screenshot_digest_changed: Option<bool>,
    /// Absolute delta in `above_fold_retained_element_coverage_milli`, if both measured.
    pub coverage_delta_milli: Option<u32>,
    /// Landmark roles whose presence or above-the-fold visibility changed.
    pub changed_landmarks: Vec<String>,
    /// Evidence references grounding the comparison.
    pub evidence_refs: Vec<EvidenceRef>,
}

/// Compares visual artefacts extracted from two [`EvidenceSnapshot`]s.
#[must_use]
pub fn compare_browser_visuals(
    baseline: &EvidenceSnapshot,
    current: &EvidenceSnapshot,
    policy: VisualComparisonPolicy,
) -> VisualComparisonReport {
    let base_visual = match &baseline.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.visual_artifacts.as_ref()
        }
        CollectorOutcome::Skipped { reason } | CollectorOutcome::Failed { error: reason } => {
            return non_comparable(format!("baseline browser unavailable: {reason}"));
        }
    };
    let curr_visual = match &current.browser {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            data.visual_artifacts.as_ref()
        }
        CollectorOutcome::Skipped { reason } | CollectorOutcome::Failed { error: reason } => {
            return non_comparable(format!("current browser unavailable: {reason}"));
        }
    };

    compare_visual_artifacts(base_visual, curr_visual, policy)
}

/// Compares two optional [`VisualArtifactEvidence`] records under `policy`.
#[must_use]
pub fn compare_visual_artifacts(
    baseline: Option<&VisualArtifactEvidence>,
    current: Option<&VisualArtifactEvidence>,
    policy: VisualComparisonPolicy,
) -> VisualComparisonReport {
    let (Some(base), Some(curr)) = (baseline, current) else {
        return non_comparable("visual_artifacts missing in baseline or current run".to_owned());
    };

    let (Some(bw), Some(bh), Some(cw), Some(ch)) = (
        base.viewport_width,
        base.viewport_height,
        curr.viewport_width,
        curr.viewport_height,
    ) else {
        return non_comparable("viewport dimensions missing in baseline or current run".to_owned());
    };

    if (bw, bh) != (cw, ch) {
        return non_comparable(format!(
            "viewport dimensions differ ({bw}x{bh} vs {cw}x{ch})"
        ));
    }

    let screenshot_digest_changed = match (
        base.viewport_screenshot_sha256.as_deref(),
        curr.viewport_screenshot_sha256.as_deref(),
    ) {
        (Some(a), Some(b)) => Some(a != b),
        _ => None,
    };

    let coverage_delta_milli = match (
        base.above_fold_retained_element_coverage_milli,
        curr.above_fold_retained_element_coverage_milli,
    ) {
        (Some(a), Some(b)) => Some(a.abs_diff(b)),
        _ => None,
    };

    let changed_landmarks = diff_landmarks(base, curr);
    let mut evidence_refs = vec![EvidenceRef::new(
        EvidenceSource::BrowserRuntime,
        format!(
            "viewport={bw}x{bh} digest_changed={screenshot_digest_changed:?} coverage_delta_milli={coverage_delta_milli:?}"
        ),
    )];
    if !changed_landmarks.is_empty() {
        evidence_refs.push(EvidenceRef::new(
            EvidenceSource::BrowserRuntime,
            format!("changed_landmarks={}", changed_landmarks.join(",")),
        ));
    }

    let layout_regressed = coverage_delta_milli
        .is_some_and(|delta| delta > policy.max_coverage_delta_milli)
        || !changed_landmarks.is_empty();

    let outcome = if layout_regressed {
        VisualComparisonOutcome::LayoutRegression
    } else if screenshot_digest_changed == Some(false) {
        VisualComparisonOutcome::Unchanged
    } else if screenshot_digest_changed == Some(true) || coverage_delta_milli.is_some() {
        VisualComparisonOutcome::DynamicVarianceWithinTolerance
    } else {
        VisualComparisonOutcome::NonComparable {
            reason: "neither screenshot digest nor coverage grid was captured".to_owned(),
        }
    };

    VisualComparisonReport {
        outcome,
        viewport: Some((bw, bh)),
        screenshot_digest_changed,
        coverage_delta_milli,
        changed_landmarks,
        evidence_refs,
    }
}

fn diff_landmarks(base: &VisualArtifactEvidence, curr: &VisualArtifactEvidence) -> Vec<String> {
    let mut changed = Vec::new();
    for b in &base.landmarks {
        match curr
            .landmarks
            .iter()
            .find(|c| c.landmark_role == b.landmark_role)
        {
            Some(c) if c.above_the_fold == b.above_the_fold => {}
            Some(_) => changed.push(format!("{}(fold_changed)", b.landmark_role)),
            None => changed.push(format!("{}(removed)", b.landmark_role)),
        }
    }
    for c in &curr.landmarks {
        if !base
            .landmarks
            .iter()
            .any(|b| b.landmark_role == c.landmark_role)
        {
            changed.push(format!("{}(added)", c.landmark_role));
        }
    }
    changed
}

fn non_comparable(reason: String) -> VisualComparisonReport {
    VisualComparisonReport {
        outcome: VisualComparisonOutcome::NonComparable { reason },
        viewport: None,
        screenshot_digest_changed: None,
        coverage_delta_milli: None,
        changed_landmarks: Vec::new(),
        evidence_refs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::diagnostics_lifecycle::VisualRegionLandmarkObs;
    use crate::domain::functional_intelligence::ElementBoundingBox;

    fn visual(sha: Option<&str>, w: u32, h: u32, cov: u32) -> VisualArtifactEvidence {
        VisualArtifactEvidence {
            viewport_screenshot_sha256: sha.map(ToOwned::to_owned),
            screenshot_byte_len: sha.map(|_| 1024),
            viewport_width: Some(w),
            viewport_height: Some(h),
            above_fold_retained_element_coverage_milli: Some(cov),
            coverage_grid_columns: Some(8),
            coverage_grid_rows: Some(8),
            coverage_retained_element_count: Some(4),
            coverage_retained_element_limit: Some(64),
            coverage_elements_truncated: false,
            landmarks: vec![VisualRegionLandmarkObs {
                landmark_role: "main".to_owned(),
                bbox: ElementBoundingBox {
                    x: 0,
                    y: 80,
                    width: w,
                    height: 600,
                },
                viewport_coverage_milli: 700,
                above_the_fold: true,
            }],
        }
    }

    #[test]
    fn mismatched_viewports_are_non_comparable() {
        let base = visual(Some("aaa"), 1280, 800, 500);
        let curr = visual(Some("aaa"), 390, 844, 500);
        let res =
            compare_visual_artifacts(Some(&base), Some(&curr), VisualComparisonPolicy::default());
        assert!(matches!(
            res.outcome,
            VisualComparisonOutcome::NonComparable { .. }
        ));
    }

    #[test]
    fn minor_dynamic_digest_change_within_coverage_tolerance_is_not_regression() {
        let base = visual(Some("aaa"), 1280, 800, 500);
        let curr = visual(Some("bbb"), 1280, 800, 540);
        let res =
            compare_visual_artifacts(Some(&base), Some(&curr), VisualComparisonPolicy::default());
        assert_eq!(
            res.outcome,
            VisualComparisonOutcome::DynamicVarianceWithinTolerance
        );
        assert_eq!(res.coverage_delta_milli, Some(40));
    }

    #[test]
    fn large_coverage_shift_or_missing_landmark_flags_layout_regression() {
        let base = visual(Some("aaa"), 1280, 800, 500);
        let mut curr = visual(Some("bbb"), 1280, 800, 200);
        curr.landmarks[0].above_the_fold = false;

        let res =
            compare_visual_artifacts(Some(&base), Some(&curr), VisualComparisonPolicy::default());
        assert_eq!(res.outcome, VisualComparisonOutcome::LayoutRegression);
        assert_eq!(res.coverage_delta_milli, Some(300));
        assert_eq!(res.changed_landmarks, vec!["main(fold_changed)"]);
    }
}
