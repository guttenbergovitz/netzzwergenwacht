//! WAI-ARIA 1.2 specification tables and source-HTML Accessible Name (`AccName`) computation.
//!
//! Provides deterministic role/attribute validation tables and static HTML
//! accessible-name resolution following WAI-ARIA 1.2 and `AccName` 1.2 precedence
//! without requiring a live browser or accessibility tree.

use std::collections::HashSet;

use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};

/// Standard WAI-ARIA 1.2 concrete roles (landmarks, widgets, document structure, live regions).
pub const VALID_ARIA_ROLES: &[&str] = &[
    "alert",
    "alertdialog",
    "application",
    "article",
    "banner",
    "blockquote",
    "button",
    "caption",
    "cell",
    "checkbox",
    "code",
    "columnheader",
    "combobox",
    "complementary",
    "contentinfo",
    "definition",
    "deletion",
    "dialog",
    "directory",
    "document",
    "emphasis",
    "feed",
    "figure",
    "form",
    "generic",
    "grid",
    "gridcell",
    "group",
    "heading",
    "img",
    "insertion",
    "link",
    "list",
    "listbox",
    "listitem",
    "log",
    "main",
    "mark",
    "marquee",
    "math",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "meter",
    "navigation",
    "none",
    "note",
    "option",
    "paragraph",
    "presentation",
    "progressbar",
    "radio",
    "radiogroup",
    "region",
    "row",
    "rowgroup",
    "rowheader",
    "scrollbar",
    "search",
    "searchbox",
    "separator",
    "slider",
    "spinbutton",
    "status",
    "strong",
    "subscript",
    "suggestion",
    "superscript",
    "switch",
    "tab",
    "table",
    "tablist",
    "tabpanel",
    "term",
    "textbox",
    "time",
    "timer",
    "toolbar",
    "tooltip",
    "tree",
    "treegrid",
    "treeitem",
];

/// Global WAI-ARIA 1.2 states and properties valid on any role.
pub const GLOBAL_ARIA_ATTRIBUTES: &[&str] = &[
    "aria-atomic",
    "aria-busy",
    "aria-controls",
    "aria-current",
    "aria-describedby",
    "aria-description",
    "aria-details",
    "aria-disabled",
    "aria-dropeffect",
    "aria-errormessage",
    "aria-flowto",
    "aria-grabbed",
    "aria-haspopup",
    "aria-hidden",
    "aria-invalid",
    "aria-keyshortcuts",
    "aria-label",
    "aria-labelledby",
    "aria-live",
    "aria-owns",
    "aria-relevant",
    "aria-roledescription",
];

/// Non-global WAI-ARIA 1.2 states and properties.
pub const ROLE_SPECIFIC_ARIA_ATTRIBUTES: &[&str] = &[
    "aria-activedescendant",
    "aria-autocomplete",
    "aria-braillelabel",
    "aria-brailleroledescription",
    "aria-checked",
    "aria-colcount",
    "aria-colindex",
    "aria-colindextext",
    "aria-colspan",
    "aria-expanded",
    "aria-level",
    "aria-modal",
    "aria-multiline",
    "aria-multiselectable",
    "aria-orientation",
    "aria-placeholder",
    "aria-posinset",
    "aria-pressed",
    "aria-readonly",
    "aria-required",
    "aria-rowcount",
    "aria-rowindex",
    "aria-rowindextext",
    "aria-rowspan",
    "aria-selected",
    "aria-setsize",
    "aria-sort",
    "aria-valuemax",
    "aria-valuemin",
    "aria-valuenow",
    "aria-valuetext",
];

/// Returns `true` when `role` is a valid concrete WAI-ARIA 1.2 role (case-insensitive).
#[must_use]
pub fn is_valid_aria_role(role: &str) -> bool {
    let lower = role.trim().to_ascii_lowercase();
    VALID_ARIA_ROLES.contains(&lower.as_str())
}

/// Returns `true` when `attr` is a recognised WAI-ARIA 1.2 state or property.
#[must_use]
pub fn is_valid_aria_attribute(attr: &str) -> bool {
    let lower = attr.trim().to_ascii_lowercase();
    GLOBAL_ARIA_ATTRIBUTES.contains(&lower.as_str())
        || ROLE_SPECIFIC_ARIA_ATTRIBUTES.contains(&lower.as_str())
}

/// Returns required `aria-*` attributes for `role` per WAI-ARIA 1.2.
#[must_use]
pub fn required_aria_attributes(role: &str) -> &'static [&'static str] {
    match role.trim().to_ascii_lowercase().as_str() {
        "checkbox" | "menuitemcheckbox" | "menuitemradio" | "radio" | "switch" => &["aria-checked"],
        "combobox" => &["aria-expanded"],
        "heading" => &["aria-level"],
        "meter" | "scrollbar" | "slider" | "spinbutton" => &["aria-valuenow"],
        "option" => &["aria-selected"],
        _ => &[],
    }
}

/// Returns `true` when `role` prohibits author-supplied accessible naming in WAI-ARIA 1.2.
#[must_use]
pub fn role_prohibits_naming(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "caption"
            | "code"
            | "deletion"
            | "emphasis"
            | "generic"
            | "insertion"
            | "mark"
            | "none"
            | "paragraph"
            | "presentation"
            | "strong"
            | "subscript"
            | "suggestion"
            | "superscript"
            | "term"
            | "time"
    )
}

/// Summary of WAI-ARIA 1.2 static validation findings across a parsed document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AriaValidationSummary {
    /// `(tag, role)` pairs with unrecognised `role` tokens.
    pub invalid_roles: Vec<(String, String)>,
    /// `(tag, role, missing_attr)` tuples where a required `aria-*` attribute is absent.
    pub missing_required_attrs: Vec<(String, String, String)>,
    /// `(tag, attr_name)` pairs with unrecognised `aria-*` attributes.
    pub unknown_aria_attrs: Vec<(String, String)>,
}

impl AriaValidationSummary {
    /// Total number of WAI-ARIA 1.2 conformance issues detected.
    #[must_use]
    pub fn total_issues(&self) -> usize {
        self.invalid_roles.len() + self.missing_required_attrs.len() + self.unknown_aria_attrs.len()
    }
}

/// Validates WAI-ARIA 1.2 roles, required attributes, and `aria-*` attribute names in `doc`.
#[must_use]
pub fn validate_document_aria(doc: &Html) -> AriaValidationSummary {
    let mut summary = AriaValidationSummary::default();
    let Ok(all_sel) = Selector::parse("*") else {
        return summary;
    };

    for el in doc.select(&all_sel) {
        let tag = el.value().name().to_owned();
        for (attr_name, _) in el.value().attrs() {
            if attr_name.starts_with("aria-") && !is_valid_aria_attribute(attr_name) {
                summary
                    .unknown_aria_attrs
                    .push((tag.clone(), attr_name.to_owned()));
            }
        }

        if let Some(raw_role) = el.value().attr("role") {
            let tokens: Vec<&str> = raw_role.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }
            // Per WAI-ARIA, the first recognised token in a space-separated fallback list applies.
            let matched = tokens.iter().copied().find(|t| is_valid_aria_role(t));
            let Some(effective_role) = matched else {
                summary
                    .invalid_roles
                    .push((tag.clone(), raw_role.trim().to_owned()));
                continue;
            };
            for &req in required_aria_attributes(effective_role) {
                let has_native_equivalent = matches!(
                    (tag.as_str(), effective_role, req),
                    (
                        "h1" | "h2" | "h3" | "h4" | "h5" | "h6",
                        "heading",
                        "aria-level"
                    ) | ("input", "checkbox" | "radio", "aria-checked")
                        | ("option", "option", "aria-selected")
                        | ("meter", "meter", "aria-valuenow")
                );
                if !has_native_equivalent && el.value().attr(req).is_none() {
                    summary.missing_required_attrs.push((
                        tag.clone(),
                        effective_role.to_ascii_lowercase(),
                        req.to_owned(),
                    ));
                }
            }
        }
    }

    summary
}

/// Computes the source-HTML accessible name of `el` following `AccName` 1.2 precedence:
/// `aria-labelledby` -> `aria-label` -> native HTML label / `alt` / `value` ->
/// visible subtree text -> `title` fallback.
#[must_use]
pub fn compute_accessible_name(el: &ElementRef<'_>, doc: &Html) -> String {
    let mut visited_ids = HashSet::new();
    compute_name_inner(el, doc, &mut visited_ids)
}

fn compute_name_inner(
    el: &ElementRef<'_>,
    doc: &Html,
    visited_ids: &mut HashSet<String>,
) -> String {
    if let Some(labelledby) = el.value().attr("aria-labelledby") {
        let mut parts = Vec::new();
        for id in labelledby.split_whitespace() {
            if !visited_ids.insert(id.to_owned()) {
                continue;
            }
            if let Some(target) = find_element_by_id(doc, id) {
                let text = collect_subtree_text(&target, true);
                if !text.is_empty() {
                    parts.push(text);
                }
            }
        }
        let joined = normalise_ws(&parts.join(" "));
        if !joined.is_empty() {
            return joined;
        }
    }

    if let Some(label) = el.value().attr("aria-label") {
        let norm = normalise_ws(label);
        if !norm.is_empty() {
            return norm;
        }
    }

    let tag = el.value().name();
    if tag == "img"
        && let Some(alt) = el.value().attr("alt")
    {
        return normalise_ws(alt);
    }

    if matches!(tag, "input" | "select" | "textarea") {
        if let Some(id) = el
            .value()
            .attr("id")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && let Some(label_text) = find_label_for_id(doc, id)
        {
            return label_text;
        }
        for anc in el.ancestors() {
            if let Some(anc_el) = ElementRef::wrap(anc)
                && anc_el.value().name() == "label"
            {
                let text = collect_subtree_text(&anc_el, false);
                if !text.is_empty() {
                    return text;
                }
            }
        }
        if tag == "input" {
            let input_type = el
                .value()
                .attr("type")
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            if matches!(input_type.as_str(), "submit" | "reset" | "button")
                && let Some(val) = el.value().attr("value")
            {
                let norm = normalise_ws(val);
                if !norm.is_empty() {
                    return norm;
                }
            }
        }
    }

    let subtree = collect_subtree_text(el, false);
    if !subtree.is_empty() {
        return subtree;
    }

    el.value()
        .attr("title")
        .map(normalise_ws)
        .unwrap_or_default()
}

fn find_element_by_id<'a>(doc: &'a Html, id: &str) -> Option<ElementRef<'a>> {
    let sel = Selector::parse("[id]").ok()?;
    doc.select(&sel)
        .find(|el| el.value().attr("id").is_some_and(|v| v == id))
}

fn find_label_for_id(doc: &Html, id: &str) -> Option<String> {
    let sel = Selector::parse("label[for]").ok()?;
    for label in doc.select(&sel) {
        if label.value().attr("for").is_some_and(|f| f.trim() == id) {
            let text = collect_subtree_text(&label, false);
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn collect_subtree_text(el: &ElementRef<'_>, include_aria_hidden_root: bool) -> String {
    let mut parts = Vec::new();
    collect_node_text(*el, include_aria_hidden_root, &mut parts);
    normalise_ws(&parts.join(" "))
}

fn collect_node_text(el: ElementRef<'_>, ignore_self_hidden: bool, parts: &mut Vec<String>) {
    let tag = el.value().name();
    if matches!(tag, "script" | "style" | "noscript" | "template") {
        return;
    }
    if !ignore_self_hidden
        && el
            .value()
            .attr("aria-hidden")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
    {
        return;
    }
    if tag == "img" {
        if let Some(alt) = el.value().attr("alt") {
            let norm = normalise_ws(alt);
            if !norm.is_empty() {
                parts.push(norm);
            }
        }
        return;
    }

    for child in el.children() {
        if let Some(text) = child.value().as_text() {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                parts.push(trimmed.to_owned());
            }
        } else if let Some(child_el) = ElementRef::wrap(child) {
            collect_node_text(child_el, false, parts);
        }
    }
}

fn normalise_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_wai_aria_1_2_roles_required_attrs_and_unknown_attrs() {
        let html = r#"<html><body>
            <div role="bogusrole">Bad</div>
            <div role="checkbox">Unchecked</div>
            <div role="checkbox" aria-checked="true">Checked</div>
            <button aria-bogus="1">Click</button>
            <h2 role="heading">Native heading level</h2>
        </body></html>"#;
        let doc = Html::parse_document(html);
        let summary = validate_document_aria(&doc);
        assert_eq!(
            summary.invalid_roles,
            vec![("div".to_owned(), "bogusrole".to_owned())]
        );
        assert_eq!(
            summary.missing_required_attrs,
            vec![(
                "div".to_owned(),
                "checkbox".to_owned(),
                "aria-checked".to_owned()
            )]
        );
        assert_eq!(
            summary.unknown_aria_attrs,
            vec![("button".to_owned(), "aria-bogus".to_owned())]
        );
    }

    #[test]
    fn computes_accname_1_2_precedence_for_controls_and_labelledby() {
        let html = r#"<html><body>
            <span id="lbl-1" aria-hidden="true">Hidden Label</span>
            <button id="b1" aria-labelledby="lbl-1" aria-label="Fallback">Text</button>
            <label for="email-in">Email Address</label>
            <input id="email-in" type="email">
            <a id="link-img" href="/home"><img src="/logo.png" alt="Home Logo"></a>
        </body></html>"#;
        let doc = Html::parse_document(html);

        let b1 = find_element_by_id(&doc, "b1").expect("b1");
        assert_eq!(compute_accessible_name(&b1, &doc), "Hidden Label");

        let email = find_element_by_id(&doc, "email-in").expect("email");
        assert_eq!(compute_accessible_name(&email, &doc), "Email Address");

        let link = find_element_by_id(&doc, "link-img").expect("link");
        assert_eq!(compute_accessible_name(&link, &doc), "Home Logo");
    }
}
