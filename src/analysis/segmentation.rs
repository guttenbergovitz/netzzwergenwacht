//! Bounded source HTML segmentation shared by content checks and evidence consumers.

use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};

const MAX_BLOCKS: usize = 256;
const MAX_BLOCK_BYTES: usize = 4096;
const MAX_LANGUAGE_BYTES: usize = 128;
const MAX_SOURCE_NODES: usize = 32_768;
const MAX_SOURCE_DEPTH: usize = 128;

/// A content block's position in the source document's element order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceElement(pub usize);

/// Source HTML paragraph evidence. CSS and client rendering require a browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParagraphObservation {
    /// Reference scoped to this source document.
    pub element: SourceElement,
    /// Text with Unicode whitespace collapsed.
    pub text: String,
    /// Language declared on the paragraph, including an explicitly empty declaration.
    pub local_language: Option<String>,
    /// Nearest ancestor declaration.
    pub inherited_language: Option<String>,
    /// A nested language declaration makes whole-paragraph detection ambiguous.
    pub has_nested_language: bool,
}

impl ParagraphObservation {
    /// Returns the language declaration in effect for this paragraph.
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        self.local_language
            .as_deref()
            .or(self.inherited_language.as_deref())
    }
}

/// Source text distribution for a unique main landmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MainContentWords {
    /// Number of eligible words outside the main landmark.
    pub outside_main: usize,
    /// Number of eligible words in the body.
    pub total: usize,
}

/// Observations derived from one complete source HTML body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentSegmentation {
    /// Retained paragraphs in document order.
    pub paragraphs: Vec<ParagraphObservation>,
    /// Whether the paragraph count or text size exceeded the retention limits.
    pub paragraphs_truncated: bool,
    /// The tree exceeded the node count or depth allowed for segmentation.
    pub tree_limit_reached: bool,
    /// Main content word distribution, when a unique eligible main region exists.
    pub main_words: Option<MainContentWords>,
    /// Source regions with no child elements and no substantive text.
    pub empty_regions: Vec<SourceElement>,
    /// Number of eligible structural regions examined.
    pub regions_observed: usize,
    /// Whether reports of empty regions were capped.
    pub empty_regions_truncated: bool,
}

impl ContentSegmentation {
    pub(super) fn extract(document: &Html) -> Self {
        let Ok(body_selector) = Selector::parse("body") else {
            return Self::default();
        };
        let Some(body) = document.select(&body_selector).next() else {
            return Self::default();
        };
        let mut nodes = body.descendants();
        if nodes
            .by_ref()
            .take(MAX_SOURCE_NODES)
            .any(|node| node.ancestors().nth(MAX_SOURCE_DEPTH).is_some())
            || nodes.next().is_some()
        {
            return Self {
                tree_limit_reached: true,
                paragraphs_truncated: true,
                ..Self::default()
            };
        }
        let mut result = Self::default();
        let mut mains = 0;
        let mut main_count = 0;
        for (position, element) in body.descendants().filter_map(ElementRef::wrap).enumerate() {
            let tag = element.value().name();
            let main = tag == "main" || element.value().attr("role") == Some("main");
            let region = main || matches!(tag, "section" | "nav" | "header" | "footer" | "aside");
            if !(region || tag == "p") || !eligible(element) {
                continue;
            }
            if main {
                mains += 1;
                if mains == 1 {
                    main_count = count_words(element);
                }
            }
            if region {
                result.regions_observed += 1;
                if element.child_elements().next().is_none()
                    && element.text().all(|text| text.trim().is_empty())
                {
                    if result.empty_regions.len() < MAX_BLOCKS {
                        result.empty_regions.push(SourceElement(position));
                    } else {
                        result.empty_regions_truncated = true;
                    }
                }
            }
            if tag == "p" {
                result.record_paragraph(element, SourceElement(position));
            }
        }
        if mains == 1 {
            let total = count_words(body);
            if total > 0 {
                result.main_words = Some(MainContentWords {
                    outside_main: total - main_count,
                    total,
                });
            }
        }
        result
    }

    fn record_paragraph(&mut self, element: ElementRef<'_>, reference: SourceElement) {
        if self.paragraphs.len() == MAX_BLOCKS {
            self.paragraphs_truncated = true;
            return;
        }
        let local_language = element.value().attr("lang");
        let inherited_language = element
            .ancestors()
            .filter_map(ElementRef::wrap)
            .find_map(|ancestor| ancestor.value().attr("lang"));
        if [local_language, inherited_language]
            .into_iter()
            .flatten()
            .any(|lang| lang.len() > MAX_LANGUAGE_BYTES)
        {
            self.paragraphs_truncated = true;
            return;
        }
        let mut text = String::new();
        for part in eligible_text(element) {
            if text.len().saturating_add(part.len()) > MAX_BLOCK_BYTES {
                self.paragraphs_truncated = true;
                return;
            }
            text.push_str(part);
        }
        self.paragraphs.push(ParagraphObservation {
            element: reference,
            text: text.split_whitespace().collect::<Vec<_>>().join(" "),
            local_language: local_language.map(str::to_owned),
            inherited_language: inherited_language.map(str::to_owned),
            has_nested_language: element
                .descendants()
                .filter_map(ElementRef::wrap)
                .any(|child| {
                    child.id() != element.id()
                        && child.value().attr("lang").is_some()
                        && eligible(child)
                }),
        });
    }
}

fn eligible(element: ElementRef<'_>) -> bool {
    std::iter::once(element)
        .chain(element.ancestors().filter_map(ElementRef::wrap))
        .all(|ancestor| {
            let value = ancestor.value();
            value.attr("hidden").is_none()
                && !matches!(value.name(), "script" | "style" | "template" | "noscript")
        })
}

fn eligible_text(element: ElementRef<'_>) -> impl Iterator<Item = &str> {
    let mut stack = vec![(*element, false)];
    std::iter::from_fn(move || {
        while let Some((node, closing)) = stack.pop() {
            if closing {
                return Some(" ");
            }
            if let Some(sibling) = node.next_sibling().filter(|_| node.id() != element.id()) {
                stack.push((sibling, false));
            }
            if let Some(text) = node.value().as_text() {
                return Some(&**text);
            }
            if let Some(child) = ElementRef::wrap(node) {
                let value = child.value();
                if value.attr("hidden").is_some()
                    || matches!(value.name(), "script" | "style" | "template" | "noscript")
                {
                    continue;
                }
                let boundary = value.attr("role") == Some("main")
                    || matches!(
                        value.name(),
                        "br" | "hr"
                            | "p"
                            | "div"
                            | "main"
                            | "section"
                            | "article"
                            | "nav"
                            | "aside"
                            | "header"
                            | "footer"
                            | "li"
                            | "td"
                            | "th"
                            | "dt"
                            | "dd"
                            | "h1"
                            | "h2"
                            | "h3"
                            | "h4"
                            | "h5"
                            | "h6"
                            | "pre"
                            | "blockquote"
                    );
                if boundary {
                    stack.push((node, true));
                }
                if let Some(first_child) = node.first_child() {
                    stack.push((first_child, false));
                }
                if boundary {
                    return Some(" ");
                }
            }
        }
        None
    })
}

fn count_words(element: ElementRef<'_>) -> usize {
    let mut words = 0;
    let mut inside = false;
    for character in eligible_text(element).flat_map(str::chars) {
        let non_space = !character.is_whitespace();
        words += usize::from(non_space && !inside);
        inside = non_space;
    }
    words
}

mod query;

pub(crate) use query::content_evidence_context;
pub use query::{ContentEvidencePage, ParagraphExtent, query_content_evidence};

#[cfg(test)]
mod tests;
