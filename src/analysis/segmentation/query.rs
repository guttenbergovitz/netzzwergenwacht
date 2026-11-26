use scraper::Html;
use serde::{Deserialize, Serialize};

use super::{ContentSegmentation, MainContentWords, SourceElement};

/// Metadata safe to include in an agent context without submitting page text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParagraphExtent {
    /// Reference scoped to the captured document.
    pub element: SourceElement,
    /// Number of words in the normalised paragraph.
    pub words: usize,
}

/// Bounded view of source segmentation produced from already captured evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentEvidencePage {
    /// Paragraph metadata in document order.
    pub paragraphs: Vec<ParagraphExtent>,
    /// Offset of the next retained paragraph page.
    pub next_offset: Option<usize>,
    /// Whether extraction omitted paragraphs because of a limit.
    pub paragraphs_truncated: bool,
    /// Whether the source tree exceeded analysis limits.
    pub tree_limit_reached: bool,
    /// Source text distribution, where measurable.
    pub main_words: Option<MainContentWords>,
}

/// Queries existing source evidence without performing acquisition.
///
/// # Errors
///
/// Returns the source eligibility reason when complete HTML is unavailable.
pub fn query_content_evidence(
    snapshot: &crate::domain::EvidenceSnapshot,
    offset: usize,
) -> Result<ContentEvidencePage, String> {
    const PAGE_SIZE: usize = 16;
    let http = crate::analysis::require_complete_html(snapshot)?;
    let content = ContentSegmentation::extract(&Html::parse_document(&http.body_text));
    let next = offset.saturating_add(PAGE_SIZE);
    Ok(ContentEvidencePage {
        paragraphs: content
            .paragraphs
            .iter()
            .skip(offset)
            .take(PAGE_SIZE)
            .map(|paragraph| ParagraphExtent {
                element: paragraph.element,
                words: paragraph.text.split_whitespace().count(),
            })
            .collect(),
        next_offset: (next < content.paragraphs.len()).then_some(next),
        paragraphs_truncated: content.paragraphs_truncated,
        tree_limit_reached: content.tree_limit_reached,
        main_words: content.main_words,
    })
}

pub(crate) fn content_evidence_context(
    snapshot: Option<&crate::domain::EvidenceSnapshot>,
) -> String {
    const MAX_CONTEXT_SOURCE_BYTES: usize = 512 * 1024;
    let Some(snapshot) = snapshot else {
        return "unavailable".to_owned();
    };
    if crate::analysis::require_complete_html(snapshot)
        .is_ok_and(|http| http.body_text.len() > MAX_CONTEXT_SOURCE_BYTES)
    {
        return "source content exceeds the agent context extraction budget".to_owned();
    }
    match query_content_evidence(snapshot, 0) {
        Ok(page) => serde_json::to_string(&page).unwrap_or_else(|_| "unavailable".to_owned()),
        Err(_) => "complete source HTML unavailable".to_owned(),
    }
}
