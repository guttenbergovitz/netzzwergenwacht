//! Minimal rendered evidence retained in audit history for deterministic comparison.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::domain::{
    BrowserEvidence, CollectorOutcome, RenderedBlockIdentity, RenderedBlockKind,
    RenderedContentBlock, RenderedContentLimits, RenderedContentSegmentation,
    RenderedCssVisibility, RenderedTextFingerprint, TimelineEnd,
};

/// Rendered comparison inputs saved with an audit report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RenderedHistoryEvidence {
    pub(crate) page_key: String,
    viewport_width: u32,
    viewport_height: u32,
    pub(crate) load_timed_out: bool,
    limits: RenderedContentLimits,
    id_census_complete: Option<bool>,
    blocks: Vec<SavedBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
struct SavedBlock {
    node: u32,
    kind: RenderedBlockKind,
    visibility: RenderedCssVisibility,
    text_truncated: bool,
    identity: Option<RenderedBlockIdentity>,
    text_fingerprint: Option<RenderedTextFingerprint>,
}

impl RenderedHistoryEvidence {
    pub(super) fn from_outcome(outcome: &CollectorOutcome<BrowserEvidence>) -> Option<Self> {
        let data = match outcome {
            CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
            CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => return None,
        };
        let content = data.rendered_content.as_ref()?;
        Some(Self {
            page_key: content.page_key.as_ref()?.clone(),
            viewport_width: content.viewport_width,
            viewport_height: content.viewport_height,
            load_timed_out: data
                .timeline
                .as_ref()
                .is_some_and(|timeline| timeline.end == TimelineEnd::LoadTimedOut),
            limits: content.limits.clone(),
            id_census_complete: content.id_census_complete,
            blocks: content
                .blocks
                .iter()
                .map(|block| SavedBlock {
                    node: block.node,
                    kind: block.kind,
                    visibility: block.visibility,
                    text_truncated: block.text_truncated,
                    identity: block.identity.clone(),
                    text_fingerprint: block.text_fingerprint.clone(),
                })
                .collect(),
        })
    }

    pub(crate) fn comparison_content(&self) -> RenderedContentSegmentation {
        RenderedContentSegmentation {
            viewport_width: self.viewport_width,
            viewport_height: self.viewport_height,
            blocks: self
                .blocks
                .iter()
                .map(|block| RenderedContentBlock {
                    node: block.node,
                    kind: block.kind,
                    visibility: block.visibility,
                    // The matcher uses identity and fingerprint metadata only.
                    visible_text: String::new(),
                    text_truncated: block.text_truncated,
                    identity: block.identity.clone(),
                    text_fingerprint: block.text_fingerprint.clone(),
                })
                .collect(),
            limits: self.limits.clone(),
            id_census_complete: self.id_census_complete,
            page_key: None,
        }
    }
}
