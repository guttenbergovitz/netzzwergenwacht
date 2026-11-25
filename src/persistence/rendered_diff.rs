//! Compares the saved rendered projection without fetching either page.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::analysis::AuditReport;
use crate::analysis::content_fingerprint::{
    BlockTextChange, TextComparisonLimit, compare_content_text,
};
use crate::analysis::element_identity::{ElementComparisonError, match_rendered_content};

/// Why a report pair lacks a comparable rendered text capture.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error,
)]
#[serde(rename_all = "snake_case")]
pub enum RenderedDiffLimit {
    /// No baseline report was available.
    #[error("no prior baseline report in history")]
    NoBaseline,
    /// The baseline was saved without rendered comparison evidence.
    #[error("baseline has no saved rendered evidence")]
    MissingBaseline,
    /// The current report was saved without rendered comparison evidence.
    #[error("current report has no saved rendered evidence")]
    MissingCurrent,
    /// The target or observed final page differs.
    #[error("audits refer to different pages")]
    DifferentPage,
    /// The desktop viewport dimensions differ.
    #[error("rendered viewports differ")]
    DifferentViewport,
    /// Traversal, identity census, or browser load was incomplete.
    #[error("rendered identity coverage was incomplete")]
    IncompleteCapture,
    /// A saved capture lacks the identity metadata needed for matching.
    #[error("saved rendered identity evidence is unavailable")]
    MissingIdentity,
}

/// Rendered text comparison for the baseline blocks in two saved reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RenderedTextDiff {
    /// A comparison was possible at the capture level.
    Compared {
        /// Number of baseline blocks with a different complete text fingerprint.
        changed_count: usize,
        /// Number of baseline blocks with the same complete text fingerprint.
        unchanged_count: usize,
        /// Number of baseline blocks for which no text comparison was possible.
        not_comparable_count: usize,
        /// Counts of per-block comparison limitations.
        reasons: BTreeMap<TextComparisonLimit, usize>,
        /// Per-block results keyed by baseline capture-local position.
        blocks: BTreeMap<u32, BlockTextChange>,
    },
    /// A capture-level limitation prevented comparison.
    Unavailable {
        /// The reason no comparison could be made.
        reason: RenderedDiffLimit,
    },
}

impl From<ElementComparisonError> for RenderedDiffLimit {
    fn from(error: ElementComparisonError) -> Self {
        match error {
            ElementComparisonError::DifferentPage => Self::DifferentPage,
            ElementComparisonError::DifferentViewport => Self::DifferentViewport,
            ElementComparisonError::Incomplete => Self::IncompleteCapture,
            ElementComparisonError::Unavailable => Self::MissingIdentity,
        }
    }
}

pub(super) fn diff_saved_rendered(
    baseline: &AuditReport,
    current: &AuditReport,
) -> RenderedTextDiff {
    match compare(baseline, current) {
        Ok(blocks) => {
            let mut changed_count = 0;
            let mut unchanged_count = 0;
            let mut reasons = BTreeMap::new();
            for change in blocks.values() {
                match change {
                    BlockTextChange::Changed { .. } => changed_count += 1,
                    BlockTextChange::Unchanged { .. } => unchanged_count += 1,
                    BlockTextChange::NotComparable { reason } => {
                        *reasons.entry(*reason).or_insert(0) += 1;
                    }
                }
            }
            RenderedTextDiff::Compared {
                changed_count,
                unchanged_count,
                not_comparable_count: reasons.values().sum(),
                reasons,
                blocks,
            }
        }
        Err(reason) => RenderedTextDiff::Unavailable { reason },
    }
}

fn compare(
    baseline: &AuditReport,
    current: &AuditReport,
) -> Result<BTreeMap<u32, BlockTextChange>, RenderedDiffLimit> {
    let baseline = baseline
        .rendered_history
        .as_ref()
        .ok_or(RenderedDiffLimit::MissingBaseline)?;
    let current = current
        .rendered_history
        .as_ref()
        .ok_or(RenderedDiffLimit::MissingCurrent)?;
    if baseline.page_key != current.page_key {
        return Err(RenderedDiffLimit::DifferentPage);
    }
    if baseline.load_timed_out || current.load_timed_out {
        return Err(RenderedDiffLimit::IncompleteCapture);
    }
    let baseline = baseline.comparison_content();
    let current = current.comparison_content();
    let identities = match_rendered_content(&baseline, &current)?;
    Ok(compare_content_text(&baseline, &current, &identities))
}
