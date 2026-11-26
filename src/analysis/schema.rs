//! Wave I — Structured Data (`Schema.org`) & Entity Graph extraction and validation.
//!
//! Extracts typed entities from `DocumentObservations::json_ld_blocks` once,
//! validates Schema.org type-specific requirements (`Product`, `Organization`,
//! `LocalBusiness`, `Article`, `BreadcrumbList`, `FAQPage`, `WebSite`, `Review`,
//! `VideoObject`), checks `sameAs` URLs and intra-page `@id` references, and
//! feeds compact [`SchemaEntitySummary`] records into [`crate::analysis::graph::ApplicationGraph`].

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::analysis::document::DocumentObservations;
use crate::domain::{
    CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding, FindingCategory,
    FindingFingerprint, FindingKind, RuleId, Severity,
};

/// Rule checking Schema.org type-specific required/recommended properties.
pub const RULE_SCHEMA_TYPE_REQUIREMENTS: &str = "such.schema.type_requirements";
/// Rule checking `sameAs` URL validity on JSON-LD entities.
pub const RULE_SCHEMA_SAME_AS: &str = "such.schema.same_as";
/// Rule checking intra-page `#fragment` `@id` references.
pub const RULE_SCHEMA_ENTITY_REFS: &str = "such.schema.entity_references";

/// Compact entity summary carried into `ApplicationGraph` for cross-page checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaEntitySummary {
    /// `@id` value if declared.
    pub id: Option<String>,
    /// Normalised `@type` names (without `https://schema.org/` prefix).
    pub entity_types: Vec<String>,
    /// Trimmed `name` or `headline`, if present.
    pub name: Option<String>,
    /// `sameAs` URLs declared on this entity.
    pub same_as: Vec<String>,
    /// `@id` references pointed to by properties of this entity.
    pub referenced_ids: Vec<String>,
}

/// Extracted JSON-LD entities and per-entity validation diagnostics for a single page.
#[derive(Debug, Clone, Default)]
pub struct SchemaExtraction {
    /// All entities discovered in valid JSON-LD blocks (including `@graph` items).
    pub entities: Vec<SchemaEntitySummary>,
    /// Type-specific missing property messages (`"<Type>: missing <field>"`).
    pub type_issues: Vec<String>,
    /// Invalid `sameAs` values (non-HTTP/HTTPS or unparseable).
    pub invalid_same_as: Vec<String>,
    /// Intra-page `#id` references with no matching `@id` definition on the page.
    pub unresolved_fragment_refs: Vec<String>,
}

/// Extracts and validates JSON-LD entities from `json_ld_blocks`.
#[must_use]
pub fn extract_entities(json_ld_blocks: &[String]) -> SchemaExtraction {
    let mut out = SchemaExtraction::default();
    let mut defined_ids: HashSet<String> = HashSet::new();

    for raw in json_ld_blocks {
        let Ok(val) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        collect_value_entities(&val, &mut out, &mut defined_ids);
    }

    for entity in &out.entities {
        for ref_id in &entity.referenced_ids {
            if ref_id.starts_with('#') && !defined_ids.contains(ref_id) {
                out.unresolved_fragment_refs.push(ref_id.clone());
            }
        }
    }

    out
}

/// Appends `SuchZwerg` Schema.org per-page checks into `findings` and `checks`.
pub fn analyse_into(
    obs: &DocumentObservations,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if obs.json_ld_blocks.is_empty() {
        for rule in [
            RULE_SCHEMA_TYPE_REQUIREMENTS,
            RULE_SCHEMA_SAME_AS,
            RULE_SCHEMA_ENTITY_REFS,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "no JSON-LD structured data blocks present".to_owned(),
            });
        }
        return;
    }

    let extracted = extract_entities(&obs.json_ld_blocks);
    evaluate_type_requirements(&extracted, findings, checks);
    evaluate_same_as(&extracted, findings, checks);
    evaluate_entity_refs(&extracted, findings, checks);
}

fn evaluate_type_requirements(
    extracted: &SchemaExtraction,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    if extracted.entities.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SCHEMA_TYPE_REQUIREMENTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no valid JSON-LD entities extracted".to_owned(),
        });
        return;
    }

    if extracted.type_issues.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SCHEMA_TYPE_REQUIREMENTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SCHEMA_TYPE_REQUIREMENTS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Structured data missing search-eligibility properties ({})",
                extracted.type_issues.len()
            ),
            summary: extracted
                .type_issues
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("schema_type_issues={}", extracted.type_issues.len()),
            )],
            remediation: Some(
                "Populate recommended Rich Results / Schema.org properties for each declared entity type."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SCHEMA_TYPE_REQUIREMENTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn evaluate_same_as(
    extracted: &SchemaExtraction,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let total_same_as: usize = extracted.entities.iter().map(|e| e.same_as.len()).sum();
    if total_same_as == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SCHEMA_SAME_AS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no `sameAs` properties declared".to_owned(),
        });
        return;
    }

    if extracted.invalid_same_as.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SCHEMA_SAME_AS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SCHEMA_SAME_AS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Invalid `sameAs` URLs in structured data ({})",
                extracted.invalid_same_as.len()
            ),
            summary: format!(
                "Found non-HTTP(S) or invalid `sameAs` values: {}.",
                extracted
                    .invalid_same_as
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("invalid_same_as={}", extracted.invalid_same_as.len()),
            )],
            remediation: Some(
                "Use full `https://` profile/entity URLs in `sameAs` arrays.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SCHEMA_SAME_AS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn evaluate_entity_refs(
    extracted: &SchemaExtraction,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let has_fragment_refs = extracted
        .entities
        .iter()
        .any(|e| e.referenced_ids.iter().any(|r| r.starts_with('#')));
    if !has_fragment_refs {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_SCHEMA_ENTITY_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no intra-page `#id` entity references declared".to_owned(),
        });
        return;
    }

    if extracted.unresolved_fragment_refs.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SCHEMA_ENTITY_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SCHEMA_ENTITY_REFS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Dangling intra-page JSON-LD `@id` references ({})",
                extracted.unresolved_fragment_refs.len()
            ),
            summary: format!(
                "Unresolved `@id` reference(s): {}.",
                extracted
                    .unresolved_fragment_refs
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!(
                    "unresolved_entity_refs={}",
                    extracted.unresolved_fragment_refs.len()
                ),
            )],
            remediation: Some(
                "Ensure every `#id` entity reference matches a defined `@id` in the `@graph`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SCHEMA_ENTITY_REFS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn collect_value_entities(
    val: &Value,
    out: &mut SchemaExtraction,
    defined_ids: &mut HashSet<String>,
) {
    match val {
        Value::Array(items) => {
            for item in items {
                collect_value_entities(item, out, defined_ids);
            }
        }
        Value::Object(map) => {
            if let Some(Value::Array(graph_items)) = map.get("@graph") {
                for item in graph_items {
                    collect_value_entities(item, out, defined_ids);
                }
            }
            let is_definition =
                map.contains_key("@type") || map.keys().any(|k| !k.starts_with('@'));
            if is_definition {
                let entity = extract_object_entity(map, out, defined_ids);
                out.entities.push(entity);
            }
            for (k, v) in map {
                if !k.starts_with('@') {
                    collect_value_entities(v, out, defined_ids);
                }
            }
        }
        _ => {}
    }
}

fn extract_object_entity(
    map: &Map<String, Value>,
    out: &mut SchemaExtraction,
    defined_ids: &mut HashSet<String>,
) -> SchemaEntitySummary {
    let id = map
        .get("@id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if let Some(ref eid) = id {
        defined_ids.insert(eid.clone());
    }

    let entity_types = extract_types(map.get("@type"));
    let name = map
        .get("name")
        .or_else(|| map.get("headline"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let mut same_as = Vec::new();
    if let Some(sa) = map.get("sameAs") {
        collect_same_as(sa, &mut same_as, &mut out.invalid_same_as);
    }

    let mut referenced_ids = Vec::new();
    for (k, v) in map {
        if k.starts_with('@') {
            continue;
        }
        collect_referenced_ids(v, &mut referenced_ids);
    }

    for ty in &entity_types {
        validate_type_fields(ty, map, &mut out.type_issues);
    }

    SchemaEntitySummary {
        id,
        entity_types,
        name,
        same_as,
        referenced_ids,
    }
}

fn extract_types(val: Option<&Value>) -> Vec<String> {
    let normalise = |raw: &str| -> Option<String> {
        let trimmed = raw
            .trim()
            .trim_start_matches("https://schema.org/")
            .trim_start_matches("http://schema.org/");
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    };
    match val {
        Some(Value::String(s)) => normalise(s).into_iter().collect(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().and_then(normalise))
            .collect(),
        _ => Vec::new(),
    }
}

fn collect_same_as(val: &Value, valid: &mut Vec<String>, invalid: &mut Vec<String>) {
    let mut push_url = |raw: &str| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        let ok = url::Url::parse(trimmed)
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some());
        if ok {
            valid.push(trimmed.to_owned());
        } else {
            invalid.push(trimmed.to_owned());
        }
    };
    match val {
        Value::String(s) => push_url(s),
        Value::Array(items) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    push_url(s);
                }
            }
        }
        _ => {}
    }
}

fn collect_referenced_ids(val: &Value, refs: &mut Vec<String>) {
    match val {
        Value::Object(map) => {
            if let Some(Value::String(id)) = map.get("@id") {
                let trimmed = id.trim();
                if !trimmed.is_empty() {
                    refs.push(trimmed.to_owned());
                }
            }
            for (k, v) in map {
                if k != "@id" {
                    collect_referenced_ids(v, refs);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_referenced_ids(item, refs);
            }
        }
        _ => {}
    }
}

fn has_non_empty(map: &Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(_) | Value::Bool(_)) => true,
        _ => false,
    }
}

fn validate_type_fields(ty: &str, map: &Map<String, Value>, issues: &mut Vec<String>) {
    match ty {
        "Product" => {
            if !has_non_empty(map, "name") {
                issues.push("Product: missing `name`".to_owned());
            }
            if !has_non_empty(map, "offers")
                && !has_non_empty(map, "aggregateRating")
                && !has_non_empty(map, "review")
            {
                issues.push("Product: missing `offers`, `aggregateRating`, or `review`".to_owned());
            }
        }
        "Organization" => {
            for req in ["name", "url"] {
                if !has_non_empty(map, req) {
                    issues.push(format!("Organization: missing `{req}`"));
                }
            }
        }
        "LocalBusiness" => {
            for req in ["name", "address"] {
                if !has_non_empty(map, req) {
                    issues.push(format!("LocalBusiness: missing `{req}`"));
                }
            }
        }
        "Article" | "BlogPosting" | "NewsArticle" => {
            if !has_non_empty(map, "headline") && !has_non_empty(map, "name") {
                issues.push(format!("{ty}: missing `headline`"));
            }
            for req in ["author", "datePublished"] {
                if !has_non_empty(map, req) {
                    issues.push(format!("{ty}: missing `{req}`"));
                }
            }
        }
        "BreadcrumbList" => {
            if !has_non_empty(map, "itemListElement") {
                issues.push("BreadcrumbList: missing `itemListElement`".to_owned());
            }
        }
        "FAQPage" => {
            if !has_non_empty(map, "mainEntity") {
                issues.push("FAQPage: missing `mainEntity`".to_owned());
            }
        }
        "WebSite" => {
            for req in ["name", "url"] {
                if !has_non_empty(map, req) {
                    issues.push(format!("WebSite: missing `{req}`"));
                }
            }
        }
        "Review" => {
            if !has_non_empty(map, "itemReviewed") {
                issues.push("Review: missing `itemReviewed`".to_owned());
            }
            if !has_non_empty(map, "reviewRating") && !has_non_empty(map, "author") {
                issues.push("Review: missing `reviewRating` or `author`".to_owned());
            }
        }
        "VideoObject" => {
            for req in ["name", "description"] {
                if !has_non_empty(map, req) {
                    issues.push(format!("VideoObject: missing `{req}`"));
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_product_and_graph_references_and_same_as() {
        let block = r##"{
            "@context": "https://schema.org",
            "@graph": [
                {
                    "@type": "Organization",
                    "@id": "#org",
                    "name": "Example Org",
                    "url": "https://example.com/",
                    "sameAs": ["not-a-url", "https://github.com/example"]
                },
                {
                    "@type": "Product",
                    "name": "Widget",
                    "brand": {"@id": "#missing-brand"}
                }
            ]
        }"##
        .to_owned();
        let obs = DocumentObservations {
            json_ld_blocks: vec![block],
            ..DocumentObservations::default()
        };
        let mut findings = Vec::new();
        let mut checks = Vec::new();
        analyse_into(&obs, &mut findings, &mut checks);

        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.0.as_str()).collect();
        assert!(ids.contains(&RULE_SCHEMA_TYPE_REQUIREMENTS));
        assert!(ids.contains(&RULE_SCHEMA_SAME_AS));
        assert!(ids.contains(&RULE_SCHEMA_ENTITY_REFS));
    }

    #[test]
    fn registers_nested_inline_entity_ids_in_defined_set() {
        let block = r##"{
            "@context": "https://schema.org",
            "@type": "Article",
            "headline": "Hello",
            "author": {"@type": "Person", "name": "Ada"},
            "datePublished": "2026-11-25",
            "publisher": {"@type": "Organization", "@id": "#pub", "name": "Acme", "url": "https://example.com/"},
            "mainEntityOfPage": {"@id": "#pub"}
        }"##
        .to_owned();
        let extracted = extract_entities(&[block]);
        assert_eq!(extracted.unresolved_fragment_refs, Vec::<String>::new());
        assert_eq!(extracted.entities.len(), 3);
    }
}
