//! Compares complete rendered text observations on independently matched blocks.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::element_identity::{ElementComparisonError, ElementMatch, match_rendered_blocks};
use crate::domain::{
    BrowserEvidence, RenderedContentBlock, RenderedContentSegmentation, RenderedCssVisibility,
    RenderedTextFingerprint,
};

/// Why a baseline block's text cannot be compared.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    JsonSchema,
    thiserror::Error,
)]
#[serde(rename_all = "snake_case")]
pub enum TextComparisonLimit {
    /// More than one element identity candidate was observed.
    #[error("ambiguous element identity")]
    AmbiguousIdentity,
    /// A comparable matching element was unavailable.
    #[error("missing identity match")]
    MissingIdentityMatch,
    /// At least one retained text observation was truncated.
    #[error("truncated text")]
    TextTruncated,
    /// At least one block was CSS-hidden at measurement time.
    #[error("CSS-hidden block")]
    HiddenBlock,
    /// At least one capture did not provide a text fingerprint.
    #[error("missing text fingerprint")]
    MissingFingerprint,
    /// A version or digest representation is unsupported.
    #[error("unsupported text fingerprint")]
    UnsupportedFingerprint,
}

/// Compared content of a baseline block in the measured scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BlockTextChange {
    /// The normalised text fingerprints agree.
    Unchanged {
        /// Capture-local node position in the current document.
        current: u32,
    },
    /// The normalised text fingerprints differ.
    Changed {
        /// Capture-local node position in the current document.
        current: u32,
    },
    /// The available evidence cannot establish a text change.
    NotComparable {
        /// The observed comparison limitation.
        reason: TextComparisonLimit,
    },
}

type Changes = BTreeMap<u32, BlockTextChange>;

/// Compares normalised text for existing baseline blocks, keyed by their capture-local positions.
///
/// The comparison uses the existing element matcher and does not acquire the page.
///
/// # Errors
///
/// Returns the element matcher's typed error when the captures cannot be compared.
pub fn compare_rendered_block_text(
    baseline: &BrowserEvidence,
    current: &BrowserEvidence,
) -> Result<Changes, ElementComparisonError> {
    let identities = match_rendered_blocks(baseline, current)?;
    let baseline = baseline
        .rendered_content
        .as_ref()
        .ok_or(ElementComparisonError::Unavailable)?;
    let current = current
        .rendered_content
        .as_ref()
        .ok_or(ElementComparisonError::Unavailable)?;
    Ok(compare_content_text(baseline, current, &identities))
}

pub(crate) fn compare_content_text(
    baseline: &RenderedContentSegmentation,
    current: &RenderedContentSegmentation,
    identities: &BTreeMap<u32, ElementMatch>,
) -> Changes {
    let current_by_node: BTreeMap<_, _> = current
        .blocks
        .iter()
        .map(|block| (block.node, block))
        .collect();
    baseline
        .blocks
        .iter()
        .map(|block| {
            let result = match identities.get(&block.node) {
                Some(ElementMatch::Matched { current, .. }) => current_by_node
                    .get(current)
                    .map_or_else(missing_identity, |candidate| compare_text(block, candidate)),
                Some(ElementMatch::Ambiguous) => BlockTextChange::NotComparable {
                    reason: TextComparisonLimit::AmbiguousIdentity,
                },
                _ => missing_identity(),
            };
            (block.node, result)
        })
        .collect()
}

const fn missing_identity() -> BlockTextChange {
    BlockTextChange::NotComparable {
        reason: TextComparisonLimit::MissingIdentityMatch,
    }
}

fn compare_text(
    baseline: &RenderedContentBlock,
    current: &RenderedContentBlock,
) -> BlockTextChange {
    match compare_fingerprints(baseline, current) {
        Ok(true) => BlockTextChange::Unchanged {
            current: current.node,
        },
        Ok(false) => BlockTextChange::Changed {
            current: current.node,
        },
        Err(reason) => BlockTextChange::NotComparable { reason },
    }
}

fn compare_fingerprints(
    baseline: &RenderedContentBlock,
    current: &RenderedContentBlock,
) -> Result<bool, TextComparisonLimit> {
    if baseline.text_truncated || current.text_truncated {
        return Err(TextComparisonLimit::TextTruncated);
    }
    if baseline.visibility == RenderedCssVisibility::Hidden
        || current.visibility == RenderedCssVisibility::Hidden
    {
        return Err(TextComparisonLimit::HiddenBlock);
    }
    let baseline = baseline
        .text_fingerprint
        .as_ref()
        .ok_or(TextComparisonLimit::MissingFingerprint)?;
    let current = current
        .text_fingerprint
        .as_ref()
        .ok_or(TextComparisonLimit::MissingFingerprint)?;
    if !supported(baseline) || !supported(current) {
        return Err(TextComparisonLimit::UnsupportedFingerprint);
    }
    Ok(baseline.digest == current.digest)
}

fn supported(fingerprint: &RenderedTextFingerprint) -> bool {
    fingerprint.version == 1
        && fingerprint.digest.len() == 64
        && fingerprint
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::RenderedBlockKind;

    fn block() -> RenderedContentBlock {
        RenderedContentBlock {
            node: 1,
            kind: RenderedBlockKind::Paragraph,
            visibility: RenderedCssVisibility::Visible,
            visible_text: "normalised excerpt".to_owned(),
            text_truncated: false,
            identity: None,
            text_fingerprint: Some(RenderedTextFingerprint {
                version: 1,
                digest: "a".repeat(64),
            }),
        }
    }

    #[test]
    fn rejects_absent_unsupported_and_malformed_fingerprints() {
        let baseline = block();
        let mut current = block();
        current.text_fingerprint.as_mut().unwrap().version = 2;
        assert_eq!(
            compare_fingerprints(&baseline, &current),
            Err(TextComparisonLimit::UnsupportedFingerprint)
        );
        current.text_fingerprint = Some(RenderedTextFingerprint {
            version: 1,
            digest: "z".repeat(64),
        });
        assert_eq!(
            compare_fingerprints(&baseline, &current),
            Err(TextComparisonLimit::UnsupportedFingerprint)
        );
        current.text_fingerprint = None;
        assert_eq!(
            compare_fingerprints(&baseline, &current),
            Err(TextComparisonLimit::MissingFingerprint)
        );
    }

    #[test]
    fn hidden_and_truncated_text_override_matching_digests() {
        let baseline = block();
        let mut current = block();
        current.visibility = RenderedCssVisibility::Hidden;
        assert_eq!(
            compare_fingerprints(&baseline, &current),
            Err(TextComparisonLimit::HiddenBlock)
        );
        current.text_truncated = true;
        assert_eq!(
            compare_fingerprints(&baseline, &current),
            Err(TextComparisonLimit::TextTruncated)
        );
    }
}
