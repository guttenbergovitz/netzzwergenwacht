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

/// Observed `<img>` element attributes relevant to accessibility, layout, and performance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageObs {
    /// Image `src` attribute, if present.
    pub src: Option<String>,
    /// Image `alt` attribute (`Some("")` indicates explicit decorative image; `None` means missing).
    pub alt: Option<String>,
    /// Explicit `width` attribute, if present.
    pub width: Option<String>,
    /// Explicit `height` attribute, if present.
    pub height: Option<String>,
    /// Explicit `loading` attribute (for example `"lazy"` or `"eager"`), if present.
    pub loading: Option<String>,
    /// Whether `srcset` is declared on `<img>` or an enclosing `<picture>` `<source>`.
    pub has_srcset: bool,
}

/// Observed `<a href="...">` link element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkObs {
    /// Trimmed `href` attribute value.
    pub href: String,
    /// Trimmed visible anchor text.
    pub text: String,
    /// Trimmed `rel` attribute, if present.
    pub rel: Option<String>,
    /// Trimmed `target` attribute, if present.
    pub target: Option<String>,
}

/// Observed `<link rel="alternate" hreflang="...">` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HreflangObs {
    /// Trimmed `hreflang` value (for example `"en-GB"`, `"x-default"`).
    pub lang: String,
    /// Trimmed `href` value.
    pub href: String,
}

/// Observed `<script>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptObs {
    /// External `src` attribute, or `None` for inline scripts.
    pub src: Option<String>,
    /// Whether the `async` boolean attribute is present.
    pub is_async: bool,
    /// Whether the `defer` boolean attribute is present.
    pub is_defer: bool,
    /// Trimmed `type` attribute, if present.
    pub script_type: Option<String>,
    /// Trimmed `integrity` (SRI) attribute, if present.
    pub integrity: Option<String>,
    /// Byte length of inline script text (`0` for external scripts).
    pub inline_bytes: usize,
}

/// Observed `<link rel="stylesheet">` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StylesheetObs {
    /// Trimmed `href` attribute value.
    pub href: String,
    /// Trimmed `integrity` (SRI) attribute, if present.
    pub integrity: Option<String>,
    /// Trimmed `media` attribute, if present.
    pub media: Option<String>,
}

/// Observed `<form>` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormObs {
    /// Trimmed `action` attribute, if present.
    pub action: Option<String>,
    /// Lowercased `method` attribute, if present.
    pub method: Option<String>,
    /// Whether the form contains an `<input type="password">`.
    pub has_password_input: bool,
    /// Whether the form contains a submit button or submit/image input.
    pub has_submit_control: bool,
}

/// Observed Open Graph and Twitter Card social metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SocialMetaObs {
    /// `<meta property="og:title" content="...">`
    pub og_title: Option<String>,
    /// `<meta property="og:description" content="...">`
    pub og_description: Option<String>,
    /// `<meta property="og:image" content="...">`
    pub og_image: Option<String>,
    /// `<meta property="og:url" content="...">`
    pub og_url: Option<String>,
    /// `<meta property="og:type" content="...">`
    pub og_type: Option<String>,
    /// `<meta name="twitter:card" content="...">`
    pub twitter_card: Option<String>,
    /// `<meta name="twitter:title" content="...">`
    pub twitter_title: Option<String>,
    /// `<meta name="twitter:description" content="...">`
    pub twitter_description: Option<String>,
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
    /// Bounded content blocks and source landmark measurements.
    pub content: super::segmentation::ContentSegmentation,
    /// Trimmed `<title>` text, if present and non-empty.
    pub title: Option<String>,
    /// Trimmed `<html lang="...">` value, if present and non-empty.
    pub html_lang: Option<String>,
    /// Trimmed `<meta name="description" content="...">`, if present and non-empty.
    pub meta_description: Option<String>,
    /// Trimmed `<meta name="robots" content="...">`, if present and non-empty.
    pub meta_robots: Option<String>,
    /// Trimmed `<meta name="generator" content="...">`, if present and non-empty.
    pub meta_generator: Option<String>,
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
    /// Visible word count extracted from `<body>` (excluding script/style/noscript).
    pub visible_word_count: usize,
    /// Visible character count extracted from `<body>` (excluding script/style/noscript).
    pub visible_char_count: usize,
    /// Bounded sample of visible body text (up to 4096 bytes) for content-quality heuristics.
    pub visible_text_sample: String,
    /// Raw `href` values from `<a href="...">` elements in document order.
    pub link_hrefs: Vec<String>,
    /// Structured `<a href="...">` link observations.
    pub links: Vec<LinkObs>,
    /// Trimmed `<meta name="viewport" content="...">`, if present.
    pub viewport_meta: Option<String>,
    /// Whether `<meta charset="...">` or `<meta http-equiv="content-type">` is declared.
    pub charset_declared: bool,
    /// Structured `<link rel="alternate" hreflang="...">` observations.
    pub hreflangs: Vec<HreflangObs>,
    /// Raw text contents of `<script type="application/ld+json">` blocks.
    pub json_ld_blocks: Vec<String>,
    /// Open Graph and Twitter Card metadata.
    pub social_meta: SocialMetaObs,
    /// Observed `<script>` elements.
    pub scripts: Vec<ScriptObs>,
    /// Observed `<link rel="stylesheet">` elements.
    pub stylesheets: Vec<StylesheetObs>,
    /// Observed `<form>` elements.
    pub forms: Vec<FormObs>,
    /// Whether a skip-navigation link (`<a href="#...">` early in the document) is present.
    pub has_skip_link: bool,
    /// Whether a favicon `<link rel="icon">` or `<link rel="shortcut icon">` is declared.
    pub has_favicon: bool,
    /// Count of `<link rel="preconnect">` or `<link rel="dns-prefetch">` hints.
    pub preconnect_count: usize,
    /// Count of inline `<svg>` elements lacking `aria-hidden="true"` and an accessible label.
    pub inline_svg_without_a11y: usize,
    /// Trimmed `<meta http-equiv="refresh" content="...">`, if present.
    pub meta_refresh: Option<String>,
    /// Count of data `<table>` elements lacking any `<th>` header cell.
    pub tables_without_headers: usize,
    /// Count of visible `<iframe>` elements lacking a `title` or `aria-label`.
    pub iframes_without_title: usize,
    /// Count of elements with a positive `tabindex` (`> 0`).
    pub positive_tabindex_count: usize,
    /// Count of `<video>` or `<audio>` elements with `autoplay` and without `muted`.
    pub autoplay_unmuted_media: usize,
    /// Detected author or publication/modification date metadata signal, if present.
    pub author_or_date_signal: Option<&'static str>,
    /// Count of `<iframe>` elements lacking a `sandbox` attribute.
    pub iframes_without_sandbox: usize,
    /// Count of RSS/Atom/JSON feed autodiscovery `<link rel="alternate">` elements.
    pub feed_links_count: usize,
    /// Count of non-background `<video>` elements lacking `controls` or `poster`.
    pub videos_without_controls_or_poster: usize,
    /// Count of non-background `<video>` elements lacking `<track kind="captions"|"subtitles">`.
    pub videos_without_captions: usize,
    /// Detected doctype declaration (`Some("html5")`, `Some("legacy")`, or `None`).
    pub doctype_kind: Option<&'static str>,
    /// Total count of `<title>` elements in the document.
    pub title_count: usize,
    /// Total count of `<link rel="canonical">` elements in the document.
    pub canonical_count: usize,
    /// Normalised charset declared via `<meta charset>` or `<meta http-equiv="content-type">`.
    pub declared_charset: Option<String>,
    /// Trimmed `<meta http-equiv="Content-Security-Policy" content="...">`, if present.
    pub meta_csp: Option<String>,
    /// Trimmed `<base href="...">` URL, if present.
    pub base_href: Option<String>,
}

impl DocumentObservations {
    /// Parses `html` once using an HTML5 parser and extracts shared observations.
    #[must_use]
    pub fn from_html(html: &str) -> Self {
        let doc = Html::parse_document(html);
        let json_ld_blocks = extract_json_ld_from_doc(&doc);
        let hreflangs = extract_hreflangs(&doc);
        let mut obs = Self {
            content: super::segmentation::ContentSegmentation::extract(&doc),
            title: first_text(&doc, "title"),
            html_lang: first_attr(&doc, "html", "lang"),
            meta_description: first_meta_attr_ci(&doc, "name", "description", "content"),
            meta_robots: first_meta_attr_ci(&doc, "name", "robots", "content"),
            meta_generator: first_meta_attr_ci(&doc, "name", "generator", "content"),
            canonical_url: first_attr(&doc, r#"link[rel="canonical"]"#, "href"),
            hreflang_count: hreflangs.len(),
            json_ld_count: json_ld_blocks.len(),
            viewport_meta: first_meta_attr_ci(&doc, "name", "viewport", "content"),
            charset_declared: count_selector(&doc, "meta[charset]") > 0
                || first_meta_attr_ci(&doc, "http-equiv", "content-type", "content").is_some(),
            hreflangs,
            json_ld_blocks,
            social_meta: extract_social_meta(&doc),
            has_favicon: count_selector(&doc, r#"link[rel="icon"], link[rel="shortcut icon"]"#) > 0,
            preconnect_count: count_selector(
                &doc,
                r#"link[rel="preconnect"], link[rel="dns-prefetch"]"#,
            ),
            meta_refresh: first_meta_attr_ci(&doc, "http-equiv", "refresh", "content"),
            doctype_kind: detect_doctype(html),
            title_count: count_selector(&doc, "title"),
            canonical_count: count_selector(&doc, r#"link[rel="canonical"]"#),
            declared_charset: extract_declared_charset(&doc),
            meta_csp: first_meta_attr_ci(&doc, "http-equiv", "content-security-policy", "content"),
            base_href: first_attr(&doc, "base[href]", "href"),
            ..Self::default()
        };

        extract_ids_and_counts(&doc, &mut obs);
        extract_headings(&doc, &mut obs);
        extract_landmarks(&doc, &mut obs);
        extract_images_and_forms(&doc, &mut obs);
        extract_scripts_and_styles(&doc, &mut obs);
        extract_interactive_and_aria(&doc, &mut obs);
        extract_visible_text_stats(&doc, &mut obs);
        extract_wave5_observations(&doc, &mut obs);

        obs
    }
}

fn first_meta_attr_ci(
    doc: &Html,
    match_attr: &str,
    expected: &str,
    value_attr: &str,
) -> Option<String> {
    let sel = Selector::parse("meta").ok()?;
    for el in doc.select(&sel) {
        if el
            .value()
            .attr(match_attr)
            .is_some_and(|v| v.trim().eq_ignore_ascii_case(expected))
            && let Some(val) = el.value().attr(value_attr)
        {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}

fn extract_declared_charset(doc: &Html) -> Option<String> {
    if let Some(cs) = first_attr(doc, "meta[charset]", "charset") {
        return Some(cs.trim().to_ascii_lowercase());
    }
    let content = first_attr(doc, r#"meta[http-equiv="content-type"]"#, "content")?;
    content
        .split(';')
        .skip(1)
        .find_map(|part| {
            let (k, v) = part.split_once('=')?;
            k.trim().eq_ignore_ascii_case("charset").then(|| {
                v.trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_ascii_lowercase()
            })
        })
        .filter(|s| !s.is_empty())
}

fn detect_doctype(html: &str) -> Option<&'static str> {
    let trimmed = html.trim_start_matches('\u{feff}').trim_start();
    let prefix = trimmed.get(..15).unwrap_or(trimmed).to_ascii_lowercase();
    if prefix.starts_with("<!doctype html>") || prefix.starts_with("<!doctype html ") {
        Some("html5")
    } else if prefix.starts_with("<!doctype") {
        Some("legacy")
    } else {
        None
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

fn extract_json_ld_from_doc(doc: &Html) -> Vec<String> {
    let Ok(sel) = Selector::parse(r#"script[type="application/ld+json"]"#) else {
        return Vec::new();
    };
    doc.select(&sel)
        .filter_map(|el| {
            let text = el.text().collect::<String>();
            let trimmed = text.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        })
        .collect()
}

fn extract_hreflangs(doc: &Html) -> Vec<HreflangObs> {
    let Ok(sel) = Selector::parse(r#"link[rel="alternate"][hreflang]"#) else {
        return Vec::new();
    };
    doc.select(&sel)
        .filter_map(|el| {
            let lang = non_empty_attr(&el, "hreflang")?;
            let href = non_empty_attr(&el, "href")?;
            Some(HreflangObs { lang, href })
        })
        .collect()
}

fn extract_social_meta(doc: &Html) -> SocialMetaObs {
    SocialMetaObs {
        og_title: first_attr(doc, r#"meta[property="og:title"]"#, "content"),
        og_description: first_attr(doc, r#"meta[property="og:description"]"#, "content"),
        og_image: first_attr(doc, r#"meta[property="og:image"]"#, "content"),
        og_url: first_attr(doc, r#"meta[property="og:url"]"#, "content"),
        og_type: first_attr(doc, r#"meta[property="og:type"]"#, "content"),
        twitter_card: first_attr(doc, r#"meta[name="twitter:card"]"#, "content"),
        twitter_title: first_attr(doc, r#"meta[name="twitter:title"]"#, "content"),
        twitter_description: first_attr(doc, r#"meta[name="twitter:description"]"#, "content"),
    }
}

fn extract_wave5_observations(doc: &Html, obs: &mut DocumentObservations) {
    if let Ok(table_sel) = Selector::parse("table") {
        let th_sel = Selector::parse("th").ok();
        for el in doc.select(&table_sel) {
            let role = el.value().attr("role").map(str::trim);
            if matches!(role, Some("presentation" | "none")) {
                continue;
            }
            let has_th = th_sel
                .as_ref()
                .is_some_and(|s| el.select(s).next().is_some());
            if !has_th {
                obs.tables_without_headers += 1;
            }
        }
    }

    if let Ok(iframe_sel) = Selector::parse("iframe") {
        for el in doc.select(&iframe_sel) {
            let hidden = el
                .value()
                .attr("aria-hidden")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
            let role = el.value().attr("role").map(str::trim);
            if hidden || matches!(role, Some("presentation" | "none")) {
                continue;
            }
            let has_title = non_empty_attr(&el, "title").is_some()
                || non_empty_attr(&el, "aria-label").is_some()
                || non_empty_attr(&el, "aria-labelledby").is_some();
            if !has_title {
                obs.iframes_without_title += 1;
            }
        }
    }

    if let Ok(tab_sel) = Selector::parse("[tabindex]") {
        for el in doc.select(&tab_sel) {
            if let Some(raw) = el.value().attr("tabindex").map(str::trim)
                && let Ok(val) = raw.parse::<i32>()
                && val > 0
            {
                obs.positive_tabindex_count += 1;
            }
        }
    }

    if let Ok(media_sel) = Selector::parse("video[autoplay], audio[autoplay]") {
        for el in doc.select(&media_sel) {
            if el.value().attr("muted").is_none() {
                obs.autoplay_unmuted_media += 1;
            }
        }
    }

    let has_meta_author = first_attr(doc, r#"meta[name="author"]"#, "content").is_some()
        || first_attr(doc, r#"meta[property="article:published_time"]"#, "content").is_some()
        || first_attr(doc, r#"meta[property="article:modified_time"]"#, "content").is_some();
    let has_time_el = count_selector(doc, "time[datetime]") > 0;
    let has_json_ld_date = obs.json_ld_blocks.iter().any(|b| {
        b.contains("datePublished") || b.contains("dateModified") || b.contains("\"author\"")
    });
    obs.author_or_date_signal = if has_meta_author {
        Some("meta")
    } else if has_time_el {
        Some("time[datetime]")
    } else if has_json_ld_date {
        Some("json-ld")
    } else {
        None
    };

    if let Ok(iframe_sel) = Selector::parse("iframe") {
        for el in doc.select(&iframe_sel) {
            if el.value().attr("sandbox").is_none() {
                obs.iframes_without_sandbox += 1;
            }
        }
    }

    obs.feed_links_count = count_selector(
        doc,
        r#"link[rel="alternate"][type="application/rss+xml"], link[rel="alternate"][type="application/atom+xml"], link[rel="alternate"][type="application/feed+json"]"#,
    );

    if let Ok(video_sel) = Selector::parse("video") {
        let track_sel = Selector::parse(r#"track[kind="captions"], track[kind="subtitles"]"#).ok();
        for el in doc.select(&video_sel) {
            let is_bg = el.value().attr("autoplay").is_some() && el.value().attr("muted").is_some();
            if !is_bg
                && (el.value().attr("controls").is_none()
                    || non_empty_attr(&el, "poster").is_none())
            {
                obs.videos_without_controls_or_poster += 1;
            }
            if !is_bg
                && track_sel
                    .as_ref()
                    .is_none_or(|s| el.select(s).next().is_none())
            {
                obs.videos_without_captions += 1;
            }
        }
    }
}

fn extract_scripts_and_styles(doc: &Html, obs: &mut DocumentObservations) {
    if let Ok(script_sel) = Selector::parse("script") {
        for el in doc.select(&script_sel) {
            let src = non_empty_attr(&el, "src");
            let inline_bytes = if src.is_some() {
                0
            } else {
                el.text().map(str::len).sum()
            };
            obs.scripts.push(ScriptObs {
                src,
                is_async: el.value().attr("async").is_some(),
                is_defer: el.value().attr("defer").is_some(),
                script_type: non_empty_attr(&el, "type"),
                integrity: non_empty_attr(&el, "integrity"),
                inline_bytes,
            });
        }
    }

    if let Ok(css_sel) = Selector::parse(r#"link[rel="stylesheet"][href]"#) {
        for el in doc.select(&css_sel) {
            if let Some(href) = non_empty_attr(&el, "href") {
                obs.stylesheets.push(StylesheetObs {
                    href,
                    integrity: non_empty_attr(&el, "integrity"),
                    media: non_empty_attr(&el, "media"),
                });
            }
        }
    }
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
            let has_srcset = non_empty_attr(&el, "srcset").is_some()
                || has_ancestor_with_selector(&el, "picture", "source[srcset]");
            obs.images.push(ImageObs {
                src: el.value().attr("src").map(str::to_owned),
                alt: el.value().attr("alt").map(str::to_owned),
                width: non_empty_attr(&el, "width"),
                height: non_empty_attr(&el, "height"),
                loading: non_empty_attr(&el, "loading"),
                has_srcset,
            });
        }
    }

    if let Ok(svg_sel) = Selector::parse("svg") {
        for el in doc.select(&svg_sel) {
            let hidden = el
                .value()
                .attr("aria-hidden")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
            let has_label = non_empty_attr(&el, "aria-label").is_some()
                || non_empty_attr(&el, "aria-labelledby").is_some()
                || Selector::parse("title").is_ok_and(|t| el.select(&t).next().is_some());
            if !hidden && !has_label {
                obs.inline_svg_without_a11y += 1;
            }
        }
    }

    if let Ok(form_sel) = Selector::parse("form") {
        let pwd_sel = Selector::parse(r#"input[type="password"]"#).ok();
        let submit_sel = Selector::parse(
            r#"input[type="submit"], input[type="image"], button[type="submit"], button:not([type])"#,
        )
        .ok();
        for el in doc.select(&form_sel) {
            let has_password_input = pwd_sel
                .as_ref()
                .is_some_and(|s| el.select(s).next().is_some());
            let has_submit_control = submit_sel
                .as_ref()
                .is_some_and(|s| el.select(s).next().is_some());
            obs.forms.push(FormObs {
                action: non_empty_attr(&el, "action"),
                method: non_empty_attr(&el, "method").map(|m| m.to_ascii_lowercase()),
                has_password_input,
                has_submit_control,
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
        for (idx, el) in doc.select(&a_href_sel).enumerate() {
            if let Some(href) = el.value().attr("href") {
                let trimmed = href.trim();
                if !trimmed.is_empty() {
                    let text = el
                        .text()
                        .collect::<String>()
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    if idx < 5 && trimmed.starts_with('#') && trimmed.len() > 1 {
                        let lower = text.to_ascii_lowercase();
                        if lower.contains("skip")
                            || lower.contains("main")
                            || lower.contains("content")
                        {
                            obs.has_skip_link = true;
                        }
                    }
                    obs.link_hrefs.push(trimmed.to_owned());
                    obs.links.push(LinkObs {
                        href: trimmed.to_owned(),
                        text,
                        rel: non_empty_attr(&el, "rel"),
                        target: non_empty_attr(&el, "target"),
                    });
                }
            }
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

fn extract_visible_text_stats(doc: &Html, obs: &mut DocumentObservations) {
    let Ok(body_sel) = Selector::parse("body") else {
        return;
    };
    let Some(body) = doc.select(&body_sel).next() else {
        return;
    };

    let sample_cap: usize = 4_096;

    let mut words = 0usize;
    let mut chars = 0usize;
    let mut sample = String::new();

    for node in body.descendants() {
        if let Some(text) = node.value().as_text() {
            let inside_ignored = node.ancestors().any(|anc| {
                anc.value()
                    .as_element()
                    .is_some_and(|el| matches!(el.name(), "script" | "style" | "noscript"))
            });
            if !inside_ignored {
                for word in text.split_whitespace() {
                    words += 1;
                    chars += word.chars().count();
                    if sample.len() < sample_cap {
                        if !sample.is_empty() {
                            sample.push(' ');
                        }
                        let rem = sample_cap.saturating_sub(sample.len());
                        if word.len() <= rem {
                            sample.push_str(word);
                        }
                    }
                }
            }
        }
    }

    obs.visible_word_count = words;
    obs.visible_char_count = chars;
    obs.visible_text_sample = sample;
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

fn has_ancestor_with_selector(el: &ElementRef<'_>, tag_name: &str, selector: &str) -> bool {
    let Ok(sel) = Selector::parse(selector) else {
        return false;
    };
    let mut current = el.parent();
    while let Some(node) = current {
        if let Some(parent_el) = ElementRef::wrap(node)
            && parent_el.value().name() == tag_name
        {
            return parent_el.select(&sel).next().is_some();
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

    #[test]
    fn extracts_rich_slice_1_observations() {
        let html = r##"<!doctype html><html lang="en-GB"><head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Rich Page</title>
            <link rel="icon" href="/favicon.ico">
            <link rel="alternate" hreflang="en" href="https://example.org/en">
            <link rel="alternate" hreflang="x-default" href="https://example.org/">
            <meta property="og:title" content="OG Rich">
            <meta name="twitter:card" content="summary_large_image">
            <link rel="stylesheet" href="https://cdn.example.org/app.css" integrity="sha384-abc">
            <script src="https://cdn.example.org/app.js" defer></script>
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite"}</script>
        </head><body>
            <a href="#main-content">Skip to main content</a>
            <a href="https://external.example.com/" target="_blank" rel="noopener">External</a>
            <main id="main-content">
                <img src="/hero.webp" alt="Hero" width="800" height="600" loading="eager">
                <form action="/submit" method="POST"><input type="text" aria-label="Name"></form>
            </main>
        </body></html>"##;

        let obs = DocumentObservations::from_html(html);
        assert!(obs.charset_declared);
        assert_eq!(
            obs.viewport_meta.as_deref(),
            Some("width=device-width, initial-scale=1")
        );
        assert!(obs.has_favicon);
        assert!(obs.has_skip_link);
        assert_eq!(obs.hreflang_count, 2);
        assert_eq!(obs.hreflangs[0].lang, "en");
        assert_eq!(obs.json_ld_count, 1);
        assert!(obs.json_ld_blocks[0].contains("WebSite"));
        assert_eq!(obs.social_meta.og_title.as_deref(), Some("OG Rich"));
        assert_eq!(
            obs.social_meta.twitter_card.as_deref(),
            Some("summary_large_image")
        );
        assert_eq!(obs.stylesheets.len(), 1);
        assert_eq!(obs.stylesheets[0].integrity.as_deref(), Some("sha384-abc"));
        assert_eq!(obs.scripts.len(), 2);
        assert!(obs.scripts[0].is_defer);
        assert_eq!(obs.links.len(), 2);
        assert_eq!(obs.links[1].rel.as_deref(), Some("noopener"));
        assert_eq!(obs.images[0].width.as_deref(), Some("800"));
        assert_eq!(obs.images[0].height.as_deref(), Some("600"));
        assert_eq!(obs.images[0].loading.as_deref(), Some("eager"));
        assert_eq!(obs.forms.len(), 1);
        assert_eq!(obs.forms[0].method.as_deref(), Some("post"));
        assert!(obs.visible_text_sample.contains("Skip to main content"));
    }

    #[test]
    fn extracts_wave5_accessibility_and_trust_observations() {
        let html = r#"<!doctype html><html lang="en-GB"><head>
            <meta http-equiv="refresh" content="5;url=/next">
            <meta name="author" content="Krzysztof">
        </head><body>
            <table><tr><td>Cell</td></tr></table>
            <table role="presentation"><tr><td>Layout</td></tr></table>
            <iframe src="/embed"></iframe>
            <iframe src="/ok" title="Embedded map"></iframe>
            <div tabindex="2">Jump</div>
            <video autoplay src="/clip.mp4"></video>
            <video autoplay muted src="/bg.mp4"></video>
        </body></html>"#;
        let obs = DocumentObservations::from_html(html);
        assert_eq!(obs.meta_refresh.as_deref(), Some("5;url=/next"));
        assert_eq!(obs.tables_without_headers, 1);
        assert_eq!(obs.iframes_without_title, 1);
        assert_eq!(obs.positive_tabindex_count, 1);
        assert_eq!(obs.autoplay_unmuted_media, 1);
        assert_eq!(obs.author_or_date_signal, Some("meta"));
    }
}
