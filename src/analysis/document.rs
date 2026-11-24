//! Shared Level 1 (Source) HTML5 document observation model.
//!
//! Parses a complete HTML response once and extracts structured observations
//! consumed by `StrukturZwerg`, `ZugänglichkeitsZwerg`, and `SuchZwerg`,
//! avoiding repeated HTML parsing across analysers.

use std::collections::{HashMap, HashSet};

use scraper::{ElementRef, Html, Selector};

/// Single heading element (`<h1>`–`<h6>`) observed in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadingObs {
    /// Heading level (`1..=6`).
    pub level: u8,
    /// Trimmed text content of the heading.
    pub text: String,
}

/// Counts of primary HTML5 landmark elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LandmarkCounts {
    /// Number of `<main>` elements.
    pub main_count: usize,
    /// Number of `<nav>` elements.
    pub nav_count: usize,
    /// Number of `<header>` elements.
    pub header_count: usize,
    /// Number of `<footer>` elements.
    pub footer_count: usize,
}

/// Observed `<img>` element attributes relevant to accessibility and structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageObs {
    /// Image `src` attribute, if present.
    pub src: Option<String>,
    /// Image `alt` attribute (`Some("")` indicates explicit decorative image; `None` means missing).
    pub alt: Option<String>,
}

/// Observed form control (`<input>`, `<select>`, `<textarea>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormControlObs {
    /// Element tag name (`input`, `select`, `textarea`).
    pub tag: String,
    /// `type` attribute (for `<input>`).
    pub control_type: Option<String>,
    /// `id` attribute for matching `<label for="...">`.
    pub id: Option<String>,
    /// Whether the control is wrapped inside a `<label>` ancestor.
    pub has_wrapping_label: bool,
    /// Non-empty `aria-label` attribute.
    pub aria_label: Option<String>,
    /// Non-empty `aria-labelledby` attribute.
    pub aria_labelledby: Option<String>,
}

/// Observed ARIA ID-reference attribute (`aria-labelledby` or `aria-describedby`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AriaRefObs {
    /// Tag name of the element carrying the attribute.
    pub element_tag: String,
    /// Attribute name (`"aria-labelledby"` or `"aria-describedby"`).
    pub attr_name: &'static str,
    /// Whitespace-separated ID tokens referenced by the attribute.
    pub referenced_ids: Vec<String>,
}

/// Shared observations extracted from a single HTML5 parse pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DocumentObservations {
    /// Trimmed `<title>` text, if present and non-empty.
    pub title: Option<String>,
    /// Trimmed `<html lang="...">` value, if present and non-empty.
    pub html_lang: Option<String>,
    /// Trimmed `<meta name="description" content="...">`, if present and non-empty.
    pub meta_description: Option<String>,
    /// Trimmed `<meta name="robots" content="...">`, if present and non-empty.
    pub meta_robots: Option<String>,
    /// Trimmed `<link rel="canonical" href="...">`, if present and non-empty.
    pub canonical_url: Option<String>,
    /// Count of `<link rel="alternate" hreflang="...">` elements.
    pub hreflang_count: usize,
    /// Count of `<script type="application/ld+json">` blocks.
    pub json_ld_count: usize,
    /// Headings in document order.
    pub headings: Vec<HeadingObs>,
    /// Landmark element counts.
    pub landmarks: LandmarkCounts,
    /// All unique `id` values present in the document.
    pub all_ids: HashSet<String>,
    /// `id` values that appear more than once (sorted for determinism).
    pub duplicate_ids: Vec<String>,
    /// `for` attribute values collected from `<label for="...">`.
    pub label_for_ids: HashSet<String>,
    /// Observed `<img>` elements.
    pub images: Vec<ImageObs>,
    /// Observed form controls (excluding `type="hidden"`, `submit`, `reset`, `button`).
    pub form_controls: Vec<FormControlObs>,
    /// Count of `<a>` elements lacking an `href` attribute.
    pub links_without_href: usize,
    /// Count of `<a href="...">` elements with no text and no `aria-label`/`title`.
    pub links_missing_accessible_name: usize,
    /// Count of `<button>` elements with no text and no `aria-label`/`aria-labelledby`/`title`.
    pub buttons_missing_accessible_name: usize,
    /// Count of `<div>`/`<span>` elements with `onclick` and no `role` attribute.
    pub clickable_generic_containers: usize,
    /// Count of nested interactive elements (e.g. `<a>` inside `<button>` or vice versa).
    pub nested_interactive_count: usize,
    /// Observed `aria-labelledby` / `aria-describedby` references.
    pub aria_refs: Vec<AriaRefObs>,
    /// Count of `<div>` elements.
    pub div_count: usize,
    /// Count of `<span>` elements.
    pub span_count: usize,
    /// Total element count in the parsed tree.
    pub total_elements: usize,
}

impl DocumentObservations {
    /// Parses `html` once using an HTML5 parser and extracts shared observations.
    #[must_use]
    pub fn from_html(html: &str) -> Self {
        let doc = Html::parse_document(html);
        let mut obs = Self {
            title: first_text(&doc, "title"),
            html_lang: first_attr(&doc, "html", "lang"),
            meta_description: first_attr(&doc, r#"meta[name="description"]"#, "content"),
            meta_robots: first_attr(&doc, r#"meta[name="robots"]"#, "content"),
            canonical_url: first_attr(&doc, r#"link[rel="canonical"]"#, "href"),
            hreflang_count: count_selector(&doc, r#"link[rel="alternate"][hreflang]"#),
            json_ld_count: count_selector(&doc, r#"script[type="application/ld+json"]"#),
            ..Self::default()
        };

        extract_ids_and_counts(&doc, &mut obs);
        extract_headings(&doc, &mut obs);
        extract_landmarks(&doc, &mut obs);
        extract_images_and_forms(&doc, &mut obs);
        extract_interactive_and_aria(&doc, &mut obs);

        obs
    }
}

fn first_text(doc: &Html, selector: &str) -> Option<String> {
    let sel = Selector::parse(selector).ok()?;
    let text = doc.select(&sel).next()?.text().collect::<String>();
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

fn first_attr(doc: &Html, selector: &str, attr: &str) -> Option<String> {
    let sel = Selector::parse(selector).ok()?;
    let val = doc.select(&sel).next()?.value().attr(attr)?.trim();
    (!val.is_empty()).then(|| val.to_owned())
}

fn count_selector(doc: &Html, selector: &str) -> usize {
    Selector::parse(selector)
        .ok()
        .map_or(0, |sel| doc.select(&sel).count())
}

fn extract_ids_and_counts(doc: &Html, obs: &mut DocumentObservations) {
    let mut id_counts: HashMap<String, usize> = HashMap::new();
    if let Ok(all_sel) = Selector::parse("*") {
        for el in doc.select(&all_sel) {
            obs.total_elements += 1;
            match el.value().name() {
                "div" => obs.div_count += 1,
                "span" => obs.span_count += 1,
                _ => {}
            }
            if let Some(id) = el.value().attr("id").map(str::trim)
                && !id.is_empty()
            {
                *id_counts.entry(id.to_owned()).or_insert(0) += 1;
                obs.all_ids.insert(id.to_owned());
            }
        }
    }
    let mut dups: Vec<String> = id_counts
        .into_iter()
        .filter_map(|(id, count)| (count > 1).then_some(id))
        .collect();
    dups.sort();
    obs.duplicate_ids = dups;
}

fn extract_headings(doc: &Html, obs: &mut DocumentObservations) {
    if let Ok(sel) = Selector::parse("h1, h2, h3, h4, h5, h6") {
        for el in doc.select(&sel) {
            let level = match el.value().name() {
                "h1" => 1,
                "h2" => 2,
                "h3" => 3,
                "h4" => 4,
                "h5" => 5,
                _ => 6,
            };
            let text = el.text().collect::<String>().trim().to_owned();
            obs.headings.push(HeadingObs { level, text });
        }
    }
}

fn extract_landmarks(doc: &Html, obs: &mut DocumentObservations) {
    obs.landmarks = LandmarkCounts {
        main_count: count_selector(doc, "main"),
        nav_count: count_selector(doc, "nav"),
        header_count: count_selector(doc, "header"),
        footer_count: count_selector(doc, "footer"),
    };
}

fn extract_images_and_forms(doc: &Html, obs: &mut DocumentObservations) {
    if let Ok(img_sel) = Selector::parse("img") {
        for el in doc.select(&img_sel) {
            obs.images.push(ImageObs {
                src: el.value().attr("src").map(str::to_owned),
                alt: el.value().attr("alt").map(str::to_owned),
            });
        }
    }

    if let Ok(label_sel) = Selector::parse("label[for]") {
        for el in doc.select(&label_sel) {
            if let Some(target_id) = el.value().attr("for").map(str::trim)
                && !target_id.is_empty()
            {
                obs.label_for_ids.insert(target_id.to_owned());
            }
        }
    }

    if let Ok(ctrl_sel) = Selector::parse("input, select, textarea") {
        for el in doc.select(&ctrl_sel) {
            let tag = el.value().name().to_owned();
            let control_type = el
                .value()
                .attr("type")
                .map(|s| s.trim().to_ascii_lowercase());
            if tag == "input"
                && matches!(
                    control_type.as_deref(),
                    Some("hidden" | "submit" | "reset" | "button" | "image")
                )
            {
                continue;
            }
            let has_wrapping_label = has_ancestor(&el, "label");
            obs.form_controls.push(FormControlObs {
                tag,
                control_type,
                id: non_empty_attr(&el, "id"),
                has_wrapping_label,
                aria_label: non_empty_attr(&el, "aria-label"),
                aria_labelledby: non_empty_attr(&el, "aria-labelledby"),
            });
        }
    }
}

fn extract_interactive_and_aria(doc: &Html, obs: &mut DocumentObservations) {
    if let Ok(a_sel) = Selector::parse("a") {
        for el in doc.select(&a_sel) {
            if el.value().attr("href").is_none() {
                obs.links_without_href += 1;
            } else if !has_accessible_text_or_label(&el) {
                obs.links_missing_accessible_name += 1;
            }
        }
    }

    if let Ok(btn_sel) = Selector::parse("button") {
        for el in doc.select(&btn_sel) {
            if !has_accessible_text_or_label(&el) {
                obs.buttons_missing_accessible_name += 1;
            }
            if has_descendant_interactive(&el) {
                obs.nested_interactive_count += 1;
            }
        }
    }

    if let Ok(a_href_sel) = Selector::parse("a[href]") {
        for el in doc.select(&a_href_sel) {
            if has_descendant_interactive(&el) {
                obs.nested_interactive_count += 1;
            }
        }
    }

    if let Ok(div_span_sel) = Selector::parse("div[onclick], span[onclick]") {
        for el in doc.select(&div_span_sel) {
            if el.value().attr("role").is_none() {
                obs.clickable_generic_containers += 1;
            }
        }
    }

    if let Ok(aria_sel) = Selector::parse("[aria-labelledby], [aria-describedby]") {
        for el in doc.select(&aria_sel) {
            for attr_name in ["aria-labelledby", "aria-describedby"] {
                if let Some(raw) = el.value().attr(attr_name) {
                    let ids: Vec<String> = raw.split_whitespace().map(str::to_owned).collect();
                    if !ids.is_empty() {
                        obs.aria_refs.push(AriaRefObs {
                            element_tag: el.value().name().to_owned(),
                            attr_name,
                            referenced_ids: ids,
                        });
                    }
                }
            }
        }
    }
}

fn non_empty_attr(el: &ElementRef<'_>, attr: &str) -> Option<String> {
    el.value()
        .attr(attr)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn has_ancestor(el: &ElementRef<'_>, tag_name: &str) -> bool {
    let mut current = el.parent();
    while let Some(node) = current {
        if let Some(parent_el) = ElementRef::wrap(node)
            && parent_el.value().name() == tag_name
        {
            return true;
        }
        current = node.parent();
    }
    false
}

fn has_accessible_text_or_label(el: &ElementRef<'_>) -> bool {
    let text = el.text().collect::<String>();
    if !text.trim().is_empty() {
        return true;
    }
    if non_empty_attr(el, "aria-label").is_some()
        || non_empty_attr(el, "aria-labelledby").is_some()
        || non_empty_attr(el, "title").is_some()
    {
        return true;
    }
    if let Ok(img_sel) = Selector::parse("img[alt]") {
        for img in el.select(&img_sel) {
            if non_empty_attr(&img, "alt").is_some() {
                return true;
            }
        }
    }
    false
}

fn has_descendant_interactive(el: &ElementRef<'_>) -> bool {
    if let Ok(sel) = Selector::parse("a[href], button, input, select, textarea") {
        // Skip the element itself (select includes self if matching; check != el.id()).
        return el.select(&sel).any(|child| child.id() != el.id());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_shared_observations_in_single_parse() {
        let html = r#"<!doctype html><html lang="en-GB"><head>
            <title>Test Page</title>
            <meta name="description" content="Desc">
            <link rel="canonical" href="https://example.org/">
        </head><body>
            <header><nav><a href="/home">Home</a></nav></header>
            <main>
                <h1 id="dup">Title</h1>
                <h2 id="dup">Sub</h2>
                <img src="/a.png" alt="Logo">
                <form><label for="email">Email</label><input id="email" type="email"></form>
            </main>
            <footer>Footer</footer>
        </body></html>"#;

        let obs = DocumentObservations::from_html(html);
        assert_eq!(obs.title.as_deref(), Some("Test Page"));
        assert_eq!(obs.html_lang.as_deref(), Some("en-GB"));
        assert_eq!(obs.duplicate_ids, vec!["dup"]);
        assert_eq!(obs.headings.len(), 2);
        assert_eq!(obs.landmarks.main_count, 1);
        assert_eq!(obs.images.len(), 1);
        assert_eq!(obs.form_controls.len(), 1);
        assert!(obs.label_for_ids.contains("email"));
    }
}
