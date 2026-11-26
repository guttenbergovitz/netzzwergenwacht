//! Conservative matching of rendered blocks across comparable captures.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::domain::{
    BrowserEvidence, RenderedBlockId, RenderedBlockKind, RenderedContentBlock,
    RenderedContentSegmentation, TimelineEnd,
};

/// Evidence used to associate two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchBasis {
    /// The same ID was observed as unique in both documents.
    UniqueId,
    /// Both blocks lack an ID and have a unique matching kind and tag path.
    UniqueStructure,
}

/// A baseline block's relationship to the current capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ElementMatch {
    /// One candidate was found on each side of the comparison.
    Matched {
        /// Capture-local node position in the current document.
        current: u32,
        /// The observation supporting the match.
        basis: MatchBasis,
    },
    /// More than one candidate or a duplicated ID was observed.
    Ambiguous,
    /// No comparable block was found under the available key.
    NoCandidate,
    /// A usable identity key was unavailable.
    Unavailable,
}

/// Why a pair of rendered captures cannot establish element identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ElementComparisonError {
    /// The browser captures ended on different pages.
    #[error("rendered captures have different final URLs")]
    DifferentPage,
    /// The rendered content or identity census was unavailable.
    #[error("rendered element identity evidence unavailable")]
    Unavailable,
    /// The structural traversal or ID census did not complete.
    #[error("rendered element identity coverage incomplete")]
    Incomplete,
    /// The captures used different viewport dimensions.
    #[error("rendered captures have different viewports")]
    DifferentViewport,
}

/// Matches baseline block positions against a subsequent capture of the same page.
///
/// Text is independent of identity. A match associates observations and does
/// not establish that the application retained the same source component.
///
/// # Errors
///
/// Returns an explicit error for incomparable captures or missing structural evidence.
pub fn match_rendered_blocks(
    baseline: &BrowserEvidence,
    current: &BrowserEvidence,
) -> Result<BTreeMap<u32, ElementMatch>, ElementComparisonError> {
    if baseline.final_url != current.final_url {
        return Err(ElementComparisonError::DifferentPage);
    }
    let baseline = comparable_content(baseline)?;
    let current = comparable_content(current)?;
    match_rendered_content(baseline, current)
}

pub(crate) fn match_rendered_content(
    baseline: &RenderedContentSegmentation,
    current: &RenderedContentSegmentation,
) -> Result<BTreeMap<u32, ElementMatch>, ElementComparisonError> {
    for content in [baseline, current] {
        match content.id_census_complete {
            None => return Err(ElementComparisonError::Unavailable),
            Some(false) => return Err(ElementComparisonError::Incomplete),
            Some(true) => {}
        }
        if content.limits.reached() {
            return Err(ElementComparisonError::Incomplete);
        }
        if content.blocks.iter().any(|block| block.identity.is_none()) {
            return Err(ElementComparisonError::Unavailable);
        }
    }
    if (baseline.viewport_width, baseline.viewport_height)
        != (current.viewport_width, current.viewport_height)
    {
        return Err(ElementComparisonError::DifferentViewport);
    }
    let baseline_index = index_blocks(&baseline.blocks);
    let current_index = index_blocks(&current.blocks);
    Ok(baseline
        .blocks
        .iter()
        .map(|block| {
            (
                block.node,
                match_block(block, &baseline_index, &current_index),
            )
        })
        .collect())
}

fn comparable_content(
    evidence: &BrowserEvidence,
) -> Result<&RenderedContentSegmentation, ElementComparisonError> {
    let content = evidence
        .rendered_content
        .as_ref()
        .ok_or(ElementComparisonError::Unavailable)?;
    if evidence
        .timeline
        .as_ref()
        .is_some_and(|timeline| timeline.end == TimelineEnd::LoadTimedOut)
    {
        return Err(ElementComparisonError::Incomplete);
    }
    Ok(content)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Key<'a> {
    Id(&'a str),
    Structure(RenderedBlockKind, &'a [String]),
}

type Index<'a> = BTreeMap<Key<'a>, Vec<&'a RenderedContentBlock>>;

fn index_blocks(blocks: &[RenderedContentBlock]) -> Index<'_> {
    let mut index = Index::new();
    for block in blocks {
        if let Some(identity) = &block.identity {
            if let RenderedBlockId::Unique { key } | RenderedBlockId::Duplicate { key } =
                &identity.id
            {
                index.entry(Key::Id(key)).or_default().push(block);
            }
            if let Some(path) = &identity.path {
                index
                    .entry(Key::Structure(block.kind, path))
                    .or_default()
                    .push(block);
            }
        }
    }
    index
}

fn match_block(
    block: &RenderedContentBlock,
    baseline: &Index<'_>,
    current: &Index<'_>,
) -> ElementMatch {
    let Some(identity) = &block.identity else {
        return ElementMatch::Unavailable;
    };
    let (key, basis) = match &identity.id {
        RenderedBlockId::Absent => {
            let Some(path) = &identity.path else {
                return ElementMatch::Unavailable;
            };
            (
                Key::Structure(block.kind, path),
                MatchBasis::UniqueStructure,
            )
        }
        RenderedBlockId::Unique { key } => (Key::Id(key), MatchBasis::UniqueId),
        RenderedBlockId::Duplicate { .. } => return ElementMatch::Ambiguous,
        RenderedBlockId::Unavailable => return ElementMatch::Unavailable,
    };

    if baseline.get(&key).is_some_and(|blocks| blocks.len() > 1) {
        return ElementMatch::Ambiguous;
    }
    match current.get(&key).map(Vec::as_slice).unwrap_or_default() {
        [] => ElementMatch::NoCandidate,
        [candidate] => {
            let candidate_id = candidate.identity.as_ref().map(|identity| &identity.id);
            match (basis, candidate_id) {
                (_, Some(RenderedBlockId::Duplicate { .. })) => ElementMatch::Ambiguous,
                (_, Some(RenderedBlockId::Unavailable) | None) => ElementMatch::Unavailable,
                (MatchBasis::UniqueStructure, Some(RenderedBlockId::Absent))
                | (MatchBasis::UniqueId, Some(RenderedBlockId::Unique { .. }))
                    if candidate.kind == block.kind =>
                {
                    ElementMatch::Matched {
                        current: candidate.node,
                        basis,
                    }
                }
                _ => ElementMatch::NoCandidate,
            }
        }
        _ => ElementMatch::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{RenderedBlockIdentity, RenderedContentLimits, RenderedCssVisibility};

    fn capture(census: Option<bool>) -> BrowserEvidence {
        BrowserEvidence {
            final_url: "https://example.test/page".to_owned(),
            rendered_content: Some(RenderedContentSegmentation {
                viewport_width: 1280,
                viewport_height: 720,
                blocks: vec![RenderedContentBlock {
                    node: 1,
                    kind: RenderedBlockKind::Paragraph,
                    visibility: RenderedCssVisibility::Visible,
                    visible_text: "retained excerpt".to_owned(),
                    text_truncated: true,
                    text_fingerprint: None,
                    identity: Some(RenderedBlockIdentity {
                        id: RenderedBlockId::Absent,
                        path: Some(vec!["body".to_owned(), "p".to_owned()]),
                    }),
                }],
                limits: RenderedContentLimits {
                    nodes: false,
                    depth: false,
                    blocks: false,
                },
                id_census_complete: census,
                page_key: None,
            }),
            ..BrowserEvidence::default()
        }
    }

    #[test]
    fn distinguishes_missing_and_incomplete_identity_from_text_truncation() {
        let baseline = capture(Some(true));
        assert_eq!(
            match_rendered_blocks(&baseline, &capture(None)),
            Err(ElementComparisonError::Unavailable)
        );
        assert_eq!(
            match_rendered_blocks(&baseline, &capture(Some(false))),
            Err(ElementComparisonError::Incomplete)
        );
        assert_eq!(
            match_rendered_blocks(&baseline, &capture(Some(true))).unwrap()[&1],
            ElementMatch::Matched {
                current: 1,
                basis: MatchBasis::UniqueStructure
            }
        );
    }

    #[test]
    fn rejects_a_different_page_or_viewport() {
        let baseline = capture(Some(true));
        let mut current = capture(Some(true));
        current.rendered_content.as_mut().unwrap().viewport_width = 390;
        assert_eq!(
            match_rendered_blocks(&baseline, &current),
            Err(ElementComparisonError::DifferentViewport)
        );
        current.final_url = "https://example.test/other".to_owned();
        assert_eq!(
            match_rendered_blocks(&baseline, &current),
            Err(ElementComparisonError::DifferentPage)
        );
    }
}
