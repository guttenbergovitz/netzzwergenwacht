//! Site-wide deterministic rule framework over a typed [`PageFeaturesTable`].
//!
//! Provides a trait-based [`SiteRule`] abstraction and [`SiteRuleRegistry`]
//! for cross-page checks that evaluate aggregate distributions, consistency,
//! and structural patterns across all observed pages in a crawl or patrol.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::analysis::document::DocumentObservations;
use crate::analysis::graph::{ApplicationGraph, GraphPageInput};
use crate::brigade::DwarfId;
use crate::discovery::PageType;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, HttpEvidence, RuleId, Severity,
};

/// Rule ID for site-wide declared `<html lang>` consistency checks.
pub const RULE_SITE_LANGUAGE_CONSISTENCY: &str = "site.i18n.language_consistency";
/// Rule ID for site-wide missing meta description pattern detection.
pub const RULE_SITE_MISSING_DESCRIPTION_PATTERN: &str = "site.seo.missing_meta_description_pattern";
/// Rule ID for site-wide thin-page concentration detection.
pub const RULE_SITE_THIN_PAGE_CONCENTRATION: &str = "site.content.thin_page_concentration";
/// Rule ID for template-level metadata consistency within a chrome cluster.
pub const RULE_SITE_TEMPLATE_CONSISTENCY: &str = "site.seo.template_metadata_consistency";

/// Deterministic page-type classification paired with confidence and supporting signals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageTypeClassification {
    /// Assigned functional page type.
    pub page_type: PageType,
    /// Discrete confidence level for the classification.
    pub confidence: Confidence,
    /// Signal strength score in basis points (`0..=10_000`).
    pub score_bps: u16,
    /// Deterministic signals contributing to this classification.
    pub signals: Vec<String>,
}

impl Default for PageTypeClassification {
    fn default() -> Self {
        Self {
            page_type: PageType::Unknown,
            confidence: Confidence::Low,
            score_bps: 2_000,
            signals: Vec::new(),
        }
    }
}

/// Compact per-page feature vector used by [`SiteRule`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageFeatures {
    /// Normalised final page URL.
    pub url: String,
    /// Originally requested URL before redirects.
    pub requested_url: String,
    /// HTTP status code, if captured.
    pub status_code: Option<u16>,
    /// Crawl or BFS hop depth from seed (`0` = seed).
    pub depth: usize,
    /// Shortest BFS click-depth from home following internal links, if reachable.
    #[serde(default)]
    pub bfs_click_depth: Option<usize>,
    /// Whether this URL was present in `sitemap.xml`.
    pub in_sitemap: bool,
    /// Whether the page is indexable (HTTP 200 and not `noindex`).
    pub indexable: bool,
    /// Trimmed `<title>`, if present.
    pub title: Option<String>,
    /// Trimmed `<meta name="description">`, if present.
    pub meta_description: Option<String>,
    /// Resolved `<link rel="canonical">` URL, if declared.
    pub canonical_url: Option<String>,
    /// Declared `<html lang="...">` primary value, if present.
    pub lang: Option<String>,
    /// Visible word count extracted from `<body>`, if measured.
    pub word_count: Option<usize>,
    /// Count of resolved internal links originating from this page.
    pub internal_link_count: usize,
    /// Count of `hreflang` alternate declarations on this page.
    pub hreflang_count: usize,
    /// Distinct-shingle `SimHash` of primary content, if available.
    pub text_simhash: Option<u64>,
    /// Schema.org `@type` names observed in JSON-LD on this page.
    pub schema_types: Vec<String>,
    /// Optional 64-bit chrome fingerprint for template clustering.
    #[serde(default)]
    pub chrome_fingerprint: Option<u64>,
    /// Deterministic page-type classification with confidence.
    #[serde(default)]
    pub classification: PageTypeClassification,
}

impl PageFeatures {
    /// Projects a [`GraphPageInput`] into a [`PageFeatures`] row.
    #[must_use]
    pub fn from_graph_page(page: &GraphPageInput) -> Self {
        let mut schema_types: Vec<String> = page
            .entities
            .iter()
            .flat_map(|e| e.entity_types.iter().cloned())
            .collect();
        schema_types.sort();
        schema_types.dedup();
        let mut features = Self {
            url: page.url.clone(),
            requested_url: page.requested_url.clone(),
            status_code: page.status_code,
            depth: page.depth,
            bfs_click_depth: None,
            in_sitemap: page.in_sitemap,
            indexable: page.indexable,
            title: page.title.clone(),
            meta_description: page.meta_description.clone(),
            canonical_url: page.canonical_url.clone(),
            lang: page.lang.clone(),
            word_count: page.word_count,
            internal_link_count: page.internal_links.len(),
            hreflang_count: page.hreflangs.len(),
            text_simhash: page.text_simhash,
            schema_types,
            chrome_fingerprint: page.chrome_fingerprint,
            classification: PageTypeClassification::default(),
        };
        features.classification = classify_page_features(&features, false);
        features
    }

    /// Constructs a [`PageFeatures`] row directly from HTTP and DOM observations.
    #[must_use]
    pub fn from_http_and_doc(
        requested_url: &str,
        http: &HttpEvidence,
        obs: &DocumentObservations,
        depth: usize,
        in_sitemap: bool,
    ) -> Self {
        let meta_noindex = obs
            .meta_robots
            .as_deref()
            .is_some_and(|v| v.to_ascii_lowercase().contains("noindex"));
        let indexable = http.status_code == 200 && !meta_noindex;
        let mut schema_types: Vec<String> =
            crate::analysis::schema::extract_entities(&obs.json_ld_blocks)
                .entities
                .into_iter()
                .flat_map(|e| e.entity_types)
                .collect();
        schema_types.sort();
        schema_types.dedup();

        let mut features = Self {
            url: http.final_url.clone(),
            requested_url: requested_url.to_owned(),
            status_code: Some(http.status_code),
            depth,
            bfs_click_depth: None,
            in_sitemap,
            indexable,
            title: obs.title.clone(),
            meta_description: obs.meta_description.clone(),
            canonical_url: obs.canonical_url.clone(),
            lang: obs.html_lang.clone(),
            word_count: Some(obs.visible_word_count),
            internal_link_count: obs.links.len(),
            hreflang_count: obs.hreflangs.len(),
            text_simhash: crate::analysis::graph::compute_text_simhash(&obs.main_content_text),
            schema_types,
            chrome_fingerprint: obs.chrome_fingerprint,
            classification: PageTypeClassification::default(),
        };
        features.classification = classify_page_features(&features, !obs.form_controls.is_empty());
        features
    }
}

fn path_has_segment(path: &str, segment: &str) -> bool {
    path.split('/').any(|part| part == segment)
}

/// Classifies a page from [`PageFeatures`] and optional form presence, returning
/// a deterministic [`PageTypeClassification`] with confidence and signal provenance.
#[must_use]
#[derive(Clone, Copy)]
struct TwoSignalSpec<'a> {
    page_type: PageType,
    primary_hit: bool,
    primary_signal: &'a str,
    secondary_hit: bool,
    secondary_signal: &'a str,
    both_bps: u16,
    primary_only_bps: u16,
    secondary_only_bps: u16,
}

fn two_signal_classification(spec: TwoSignalSpec<'_>) -> Option<PageTypeClassification> {
    if !spec.primary_hit && !spec.secondary_hit {
        return None;
    }
    let mut signals = Vec::new();
    if spec.primary_hit {
        signals.push(spec.primary_signal.to_owned());
    }
    if spec.secondary_hit {
        signals.push(spec.secondary_signal.to_owned());
    }
    let (confidence, score_bps) = match (spec.primary_hit, spec.secondary_hit) {
        (true, true) => (Confidence::High, spec.both_bps),
        (true, false) => (Confidence::Medium, spec.primary_only_bps),
        (false, true) => (Confidence::Medium, spec.secondary_only_bps),
        (false, false) => return None,
    };
    Some(PageTypeClassification {
        page_type: spec.page_type,
        confidence,
        score_bps,
        signals,
    })
}

/// Classifies a page from [`PageFeatures`] and optional form presence, returning
/// a deterministic [`PageTypeClassification`] with confidence and signal provenance.
#[must_use]
pub fn classify_page_features(
    features: &PageFeatures,
    has_form_controls: bool,
) -> PageTypeClassification {
    let path = url::Url::parse(&features.url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();

    if path == "/" || path.is_empty() {
        return PageTypeClassification {
            page_type: PageType::Homepage,
            confidence: Confidence::High,
            score_bps: 9_500,
            signals: vec!["url:root_path".to_owned()],
        };
    }

    let has_schema = |candidates: &[&str]| -> bool {
        features
            .schema_types
            .iter()
            .any(|t| candidates.iter().any(|c| t.eq_ignore_ascii_case(c)))
    };

    if ["login", "signin", "auth", "register", "signup"]
        .iter()
        .any(|seg| path_has_segment(&path, seg))
    {
        return two_signal_classification(TwoSignalSpec {
            page_type: PageType::Auth,
            primary_hit: true,
            primary_signal: "url:auth_segment",
            secondary_hit: has_form_controls,
            secondary_signal: "dom:form_controls",
            both_bps: 9_200,
            primary_only_bps: 7_500,
            secondary_only_bps: 7_500,
        })
        .unwrap_or_default();
    }

    if [
        "privacy",
        "terms",
        "legal",
        "imprint",
        "impressum",
        "datenschutz",
        "gdpr",
    ]
    .iter()
    .any(|seg| path_has_segment(&path, seg))
    {
        return PageTypeClassification {
            page_type: PageType::Legal,
            confidence: Confidence::High,
            score_bps: 9_000,
            signals: vec!["url:legal_segment".to_owned()],
        };
    }

    if let Some(cls) = two_signal_classification(TwoSignalSpec {
        page_type: PageType::Contact,
        primary_hit: path_has_segment(&path, "contact") || path_has_segment(&path, "kontakt"),
        primary_signal: "url:contact_segment",
        secondary_hit: has_schema(&["ContactPage"]),
        secondary_signal: "schema:ContactPage",
        both_bps: 9_500,
        primary_only_bps: 7_800,
        secondary_only_bps: 7_800,
    })
    .or_else(|| {
        two_signal_classification(TwoSignalSpec {
            page_type: PageType::Support,
            primary_hit: ["help", "support", "faq", "docs"]
                .iter()
                .any(|seg| path_has_segment(&path, seg)),
            primary_signal: "url:support_segment",
            secondary_hit: has_schema(&["FAQPage", "QAPage", "HowTo"]),
            secondary_signal: "schema:support_type",
            both_bps: 9_400,
            primary_only_bps: 7_600,
            secondary_only_bps: 7_600,
        })
    }) {
        return cls;
    }

    if has_form_controls {
        return PageTypeClassification {
            page_type: PageType::Form,
            confidence: Confidence::Medium,
            score_bps: 7_200,
            signals: vec!["dom:form_controls".to_owned()],
        };
    }

    classify_content_or_listing(features, &has_schema)
}

fn classify_content_or_listing(
    features: &PageFeatures,
    has_schema: &dyn Fn(&[&str]) -> bool,
) -> PageTypeClassification {
    if let Some(cls) = two_signal_classification(TwoSignalSpec {
        page_type: PageType::Article,
        primary_hit: has_schema(&["Article", "BlogPosting", "NewsArticle", "TechArticle"]),
        primary_signal: "schema:article_type",
        secondary_hit: features.word_count.is_some_and(|wc| wc >= 250),
        secondary_signal: "content:word_count>=250",
        both_bps: 9_200,
        primary_only_bps: 7_600,
        secondary_only_bps: 6_500,
    }) {
        return cls;
    }

    two_signal_classification(TwoSignalSpec {
        page_type: PageType::Listing,
        primary_hit: has_schema(&["CollectionPage", "SearchResultsPage", "ItemList"]),
        primary_signal: "schema:listing_type",
        secondary_hit: features.internal_link_count >= 15,
        secondary_signal: "links:internal>=15",
        both_bps: 9_000,
        primary_only_bps: 6_800,
        secondary_only_bps: 6_800,
    })
    .unwrap_or_default()
}

/// Deterministic, URL-indexed table of [`PageFeatures`] across a site crawl.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PageFeaturesTable {
    rows: BTreeMap<String, PageFeatures>,
}

impl PageFeaturesTable {
    /// Builds a [`PageFeaturesTable`] from an [`ApplicationGraph`].
    #[must_use]
    pub fn from_graph(graph: &ApplicationGraph) -> Self {
        let rows = graph
            .pages
            .iter()
            .map(|(url, page)| {
                let mut features = PageFeatures::from_graph_page(page);
                features.bfs_click_depth = graph.click_depth(url);
                (url.clone(), features)
            })
            .collect();
        Self { rows }
    }

    /// Builds a [`PageFeaturesTable`] from an iterator of [`PageFeatures`].
    #[must_use]
    pub fn from_pages(pages: impl IntoIterator<Item = PageFeatures>) -> Self {
        let mut rows = BTreeMap::new();
        for page in pages {
            rows.insert(page.url.clone(), page);
        }
        Self { rows }
    }

    /// Number of pages in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Returns `true` when the table contains no pages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Looks up a page row by final URL.
    #[must_use]
    pub fn get(&self, url: &str) -> Option<&PageFeatures> {
        self.rows.get(url)
    }

    /// Iterates over all page rows in deterministic URL order.
    pub fn iter(&self) -> impl Iterator<Item = &PageFeatures> {
        self.rows.values()
    }

    /// Iterates over indexable page rows in deterministic URL order.
    pub fn indexable_pages(&self) -> impl Iterator<Item = &PageFeatures> {
        self.rows.values().filter(|p| p.indexable)
    }
}

/// Read-only context supplied to every [`SiteRule`] evaluation.
pub struct SiteRuleContext<'a> {
    /// Typed per-page feature table.
    pub pages: &'a PageFeaturesTable,
    /// Optional full [`ApplicationGraph`] when graph topology is available.
    pub graph: Option<&'a ApplicationGraph>,
    /// Whether all discovered internal URLs were inspected.
    pub coverage_complete: bool,
}

/// Deterministic cross-page rule operating over [`SiteRuleContext`].
pub trait SiteRule: Send + Sync {
    /// Stable rule identifier (e.g. `"site.i18n.language_consistency"`).
    fn id(&self) -> &'static str;

    /// Responsible dwarf in **Die Zwergenbrigade**.
    fn dwarf(&self) -> DwarfId;

    /// Evaluates the rule against `ctx`, appending findings and check statuses.
    fn evaluate(
        &self,
        ctx: &SiteRuleContext<'_>,
        findings: &mut Vec<Finding>,
        checks: &mut Vec<CheckStatus>,
    );
}

/// Registry and runner for deterministic [`SiteRule`] implementations.
#[derive(Default)]
pub struct SiteRuleRegistry {
    rules: Vec<Box<dyn SiteRule>>,
}

impl SiteRuleRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Creates a registry populated with all built-in site-wide rules.
    #[must_use]
    pub fn with_default_rules() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(SiteLanguageConsistencyRule));
        registry.register(Box::new(SiteMissingDescriptionPatternRule));
        registry.register(Box::new(SiteThinPageConcentrationRule));
        registry.register(Box::new(SiteTemplateConsistencyRule));
        registry
    }

    /// Registers an additional [`SiteRule`].
    pub fn register(&mut self, rule: Box<dyn SiteRule>) {
        self.rules.push(rule);
    }

    /// Returns the registered rule identifiers in evaluation order.
    #[must_use]
    pub fn rule_ids(&self) -> Vec<&'static str> {
        self.rules.iter().map(|r| r.id()).collect()
    }

    /// Evaluates all registered rules over `ctx`, grouping outputs by [`DwarfId`].
    #[must_use]
    pub fn evaluate_all(&self, ctx: &SiteRuleContext<'_>) -> Vec<AnalyserResult> {
        let mut grouped: BTreeMap<DwarfId, (Vec<Finding>, Vec<CheckStatus>)> = BTreeMap::new();
        for rule in &self.rules {
            let entry = grouped.entry(rule.dwarf()).or_default();
            rule.evaluate(ctx, &mut entry.0, &mut entry.1);
        }
        grouped
            .into_iter()
            .map(|(dwarf_id, (findings, checks))| AnalyserResult {
                dwarf_id,
                findings,
                checks,
            })
            .collect()
    }
}

/// Convenience helper that evaluates the default [`SiteRuleRegistry`] over `graph`.
#[must_use]
pub fn analyse_graph(graph: &ApplicationGraph) -> Vec<AnalyserResult> {
    if graph.pages.is_empty() {
        return Vec::new();
    }
    let table = PageFeaturesTable::from_graph(graph);
    let ctx = SiteRuleContext {
        pages: &table,
        graph: Some(graph),
        coverage_complete: graph.coverage_complete,
    };
    SiteRuleRegistry::with_default_rules().evaluate_all(&ctx)
}

/// Flags inconsistent or missing `<html lang>` declarations across indexable pages
/// that do not declare `hreflang` alternates.
pub struct SiteLanguageConsistencyRule;

impl SiteRule for SiteLanguageConsistencyRule {
    fn id(&self) -> &'static str {
        RULE_SITE_LANGUAGE_CONSISTENCY
    }

    fn dwarf(&self) -> DwarfId {
        DwarfId::Such
    }

    fn evaluate(
        &self,
        ctx: &SiteRuleContext<'_>,
        findings: &mut Vec<Finding>,
        checks: &mut Vec<CheckStatus>,
    ) {
        let indexable: Vec<&PageFeatures> = ctx.pages.indexable_pages().collect();
        if indexable.len() < 3 {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "fewer than three indexable pages in PageFeaturesTable".to_owned(),
            });
            return;
        }

        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut missing_lang_urls: Vec<&str> = Vec::new();
        for page in &indexable {
            match page
                .lang
                .as_deref()
                .map(|l| l.split('-').next().unwrap_or(l).trim().to_ascii_lowercase())
                .filter(|l| !l.is_empty())
            {
                Some(primary) => *counts.entry(primary).or_default() += 1,
                None => missing_lang_urls.push(page.url.as_str()),
            }
        }

        let has_hreflang = indexable.iter().any(|p| p.hreflang_count > 0);
        let distinct_langs = counts.len();
        let inconsistent = (!has_hreflang && distinct_langs > 1)
            || (!counts.is_empty() && !missing_lang_urls.is_empty());

        if inconsistent {
            let summary_langs: Vec<String> =
                counts.iter().map(|(k, v)| format!("{k}={v}")).collect();
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(self.id().to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: "Inconsistent <html lang> declarations across site pages".to_owned(),
                summary: format!(
                    "Observed languages [{}] with {} indexable page(s) missing `<html lang>` (hreflang_present={has_hreflang}).",
                    summary_langs.join(", "),
                    missing_lang_urls.len()
                ),
                evidence_refs: missing_lang_urls
                    .iter()
                    .take(5)
                    .map(|u| EvidenceRef::new(EvidenceSource::HttpBody, format!("missing_lang={u}")))
                    .collect(),
                remediation: Some(
                    "Declare a consistent `<html lang>` attribute on every indexable page and pair multilingual variants with `hreflang`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

/// Flags systemic omission of `<meta name="description">` across indexable pages.
pub struct SiteMissingDescriptionPatternRule;

impl SiteRule for SiteMissingDescriptionPatternRule {
    fn id(&self) -> &'static str {
        RULE_SITE_MISSING_DESCRIPTION_PATTERN
    }

    fn dwarf(&self) -> DwarfId {
        DwarfId::Such
    }

    fn evaluate(
        &self,
        ctx: &SiteRuleContext<'_>,
        findings: &mut Vec<Finding>,
        checks: &mut Vec<CheckStatus>,
    ) {
        let indexable: Vec<&PageFeatures> = ctx.pages.indexable_pages().collect();
        if indexable.len() < 3 {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "fewer than three indexable pages in PageFeaturesTable".to_owned(),
            });
            return;
        }

        let missing: Vec<&str> = indexable
            .iter()
            .filter(|p| {
                p.meta_description
                    .as_deref()
                    .is_none_or(|d| d.trim().is_empty())
            })
            .map(|p| p.url.as_str())
            .collect();

        if missing.len() * 2 >= indexable.len() {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(self.id().to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Medium,
                confidence: Confidence::High,
                title: format!(
                    "Systemic missing meta description ({}/{} indexable pages)",
                    missing.len(),
                    indexable.len()
                ),
                summary: format!(
                    "{} of {} indexable pages lack `<meta name=\"description\">`.",
                    missing.len(),
                    indexable.len()
                ),
                evidence_refs: missing
                    .iter()
                    .take(5)
                    .map(|u| EvidenceRef::new(EvidenceSource::HttpBody, (*u).to_owned()))
                    .collect(),
                remediation: Some(
                    "Add unique, descriptive `<meta name=\"description\">` tags across page templates."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

/// Flags high concentration of thin-content indexable pages (< 150 visible words).
pub struct SiteThinPageConcentrationRule;

impl SiteRule for SiteThinPageConcentrationRule {
    fn id(&self) -> &'static str {
        RULE_SITE_THIN_PAGE_CONCENTRATION
    }

    fn dwarf(&self) -> DwarfId {
        DwarfId::Inhalts
    }

    fn evaluate(
        &self,
        ctx: &SiteRuleContext<'_>,
        findings: &mut Vec<Finding>,
        checks: &mut Vec<CheckStatus>,
    ) {
        let measured: Vec<(&str, usize)> = ctx
            .pages
            .indexable_pages()
            .filter_map(|p| p.word_count.map(|wc| (p.url.as_str(), wc)))
            .collect();
        if measured.len() < 3 {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "fewer than three indexable pages with measured word_count".to_owned(),
            });
            return;
        }

        let thin: Vec<(&str, usize)> = measured
            .iter()
            .copied()
            .filter(|&(_, wc)| wc < 150)
            .collect();

        if thin.len() >= 3 && thin.len() * 10 >= measured.len() * 3 {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(self.id().to_owned()),
                category: FindingCategory::Content,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Heuristic,
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                title: format!(
                    "High concentration of thin-content pages ({}/{})",
                    thin.len(),
                    measured.len()
                ),
                summary: format!(
                    "{} of {} indexable pages contain fewer than 150 visible words.",
                    thin.len(),
                    measured.len()
                ),
                evidence_refs: thin
                    .iter()
                    .take(5)
                    .map(|(u, wc)| {
                        EvidenceRef::new(EvidenceSource::HttpBody, format!("{u} (words={wc})"))
                    })
                    .collect(),
                remediation: Some(
                    "Enrich thin indexable pages with substantive primary content or mark utility pages `noindex`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

/// Group of pages sharing the same structural chrome fingerprint (likely rendered by the same template).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateCluster {
    /// Shared 64-bit chrome fingerprint.
    pub chrome_fingerprint: u64,
    /// Sorted URLs belonging to this template cluster.
    pub urls: Vec<String>,
    /// Dominant [`PageType`] observed across cluster members.
    pub dominant_page_type: PageType,
}

/// Clusters pages in `table` by their `chrome_fingerprint`.
#[must_use]
pub fn cluster_templates(table: &PageFeaturesTable) -> Vec<TemplateCluster> {
    let mut grouped: BTreeMap<u64, Vec<&PageFeatures>> = BTreeMap::new();
    for page in table.iter() {
        if let Some(fp) = page.chrome_fingerprint {
            grouped.entry(fp).or_default().push(page);
        }
    }

    let mut clusters: Vec<TemplateCluster> = grouped
        .into_iter()
        .map(|(fp, members)| {
            let mut type_counts: BTreeMap<String, (PageType, usize)> = BTreeMap::new();
            for m in &members {
                let key = format!("{:?}", m.classification.page_type);
                let entry = type_counts
                    .entry(key)
                    .or_insert((m.classification.page_type, 0));
                entry.1 += 1;
            }
            let dominant_page_type = type_counts
                .into_values()
                .max_by_key(|(_, count)| *count)
                .map_or(PageType::Unknown, |(pt, _)| pt);
            let urls = members.into_iter().map(|m| m.url.clone()).collect();
            TemplateCluster {
                chrome_fingerprint: fp,
                urls,
                dominant_page_type,
            }
        })
        .collect();

    clusters.sort_by(|a, b| {
        b.urls
            .len()
            .cmp(&a.urls.len())
            .then_with(|| a.chrome_fingerprint.cmp(&b.chrome_fingerprint))
    });
    clusters
}

/// Flags inconsistent `<meta name="description">` presence across indexable pages
/// sharing the same template chrome fingerprint.
pub struct SiteTemplateConsistencyRule;

impl SiteRule for SiteTemplateConsistencyRule {
    fn id(&self) -> &'static str {
        RULE_SITE_TEMPLATE_CONSISTENCY
    }

    fn dwarf(&self) -> DwarfId {
        DwarfId::Such
    }

    fn evaluate(
        &self,
        ctx: &SiteRuleContext<'_>,
        findings: &mut Vec<Finding>,
        checks: &mut Vec<CheckStatus>,
    ) {
        let clusters: Vec<TemplateCluster> = cluster_templates(ctx.pages)
            .into_iter()
            .filter(|c| c.urls.len() >= 3)
            .collect();
        if clusters.is_empty() {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "no template cluster with at least three pages".to_owned(),
            });
            return;
        }

        let mut inconsistent_clusters = Vec::new();
        for cluster in &clusters {
            let mut with_desc = 0usize;
            let mut without_desc = 0usize;
            for url in &cluster.urls {
                if let Some(page) = ctx.pages.get(url)
                    && page.indexable
                {
                    if page
                        .meta_description
                        .as_deref()
                        .is_some_and(|d| !d.trim().is_empty())
                    {
                        with_desc += 1;
                    } else {
                        without_desc += 1;
                    }
                }
            }
            if with_desc > 0 && without_desc > 0 {
                inconsistent_clusters.push(format!(
                    "chrome={:016x} ({with_desc} with desc, {without_desc} missing)",
                    cluster.chrome_fingerprint
                ));
            }
        }

        if inconsistent_clusters.is_empty() {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            findings.push(Finding {
                fingerprint: FindingFingerprint::default(),
                rule_id: RuleId(self.id().to_owned()),
                category: FindingCategory::Seo,
                evidence_level: EvidenceLevel::Source,
                kind: FindingKind::Deterministic,
                severity: Severity::Low,
                confidence: Confidence::High,
                title: format!(
                    "Inconsistent template metadata across {} chrome cluster(s)",
                    inconsistent_clusters.len()
                ),
                summary: format!(
                    "Template cluster(s) sharing identical chrome have inconsistent `<meta name=\"description\">` coverage: {}.",
                    inconsistent_clusters.join("; ")
                ),
                evidence_refs: inconsistent_clusters
                    .iter()
                    .take(5)
                    .map(|c| EvidenceRef::new(EvidenceSource::HttpBody, c.clone()))
                    .collect(),
                remediation: Some(
                    "Ensure every page rendered from a shared template populates `<meta name=\"description\">`."
                        .to_owned(),
                ),
            });
            checks.push(CheckStatus::Failed {
                rule_id: RuleId(self.id().to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feature_row(url: &str) -> PageFeatures {
        PageFeatures {
            url: url.to_owned(),
            requested_url: url.to_owned(),
            status_code: Some(200),
            depth: 1,
            bfs_click_depth: Some(1),
            in_sitemap: true,
            indexable: true,
            title: Some(format!("Title for {url}")),
            meta_description: Some(format!("Description for {url}")),
            canonical_url: Some(url.to_owned()),
            lang: Some("en".to_owned()),
            word_count: Some(320),
            internal_link_count: 5,
            hreflang_count: 0,
            text_simhash: None,
            schema_types: Vec::new(),
            chrome_fingerprint: Some(0x1111_2222_3333_4444),
            classification: PageTypeClassification::default(),
        }
    }

    #[test]
    fn template_clustering_groups_pages_by_chrome_and_detects_inconsistency() {
        let fp = 0x1234_5678_9abc_def0;
        let mut p1 = feature_row("https://example.com/blog/1");
        p1.chrome_fingerprint = Some(fp);
        let mut p2 = feature_row("https://example.com/blog/2");
        p2.chrome_fingerprint = Some(fp);
        let mut p3 = feature_row("https://example.com/blog/3");
        p3.chrome_fingerprint = Some(fp);
        p3.meta_description = None;

        let table = PageFeaturesTable::from_pages([p1, p2, p3]);
        let clusters = cluster_templates(&table);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].urls.len(), 3);

        let ctx = SiteRuleContext {
            pages: &table,
            graph: None,
            coverage_complete: true,
        };
        let res = SiteRuleRegistry::with_default_rules().evaluate_all(&ctx);
        let ids: Vec<&str> = res
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();
        assert!(ids.contains(&RULE_SITE_TEMPLATE_CONSISTENCY));
    }

    #[test]
    fn page_type_classifier_reports_confidence_and_signals() {
        let mut article = feature_row("https://example.com/posts/rust-engine");
        article.schema_types = vec!["Article".to_owned()];
        article.word_count = Some(600);
        let article_cls = classify_page_features(&article, false);
        assert_eq!(article_cls.page_type, PageType::Article);
        assert_eq!(article_cls.confidence, Confidence::High);
        assert!(article_cls.score_bps >= 9_000);
        assert!(
            article_cls
                .signals
                .iter()
                .any(|s| s == "schema:article_type")
        );

        let unknown = feature_row("https://example.com/custom-landing");
        let mut u = unknown;
        u.word_count = Some(50);
        u.internal_link_count = 2;
        let unknown_cls = classify_page_features(&u, false);
        assert_eq!(unknown_cls.page_type, PageType::Unknown);
        assert_eq!(unknown_cls.confidence, Confidence::Low);
    }

    #[test]
    fn site_rule_registry_flags_language_description_and_thin_patterns() {
        let mut p1 = feature_row("https://example.com/a");
        p1.meta_description = None;
        p1.word_count = Some(60);

        let mut p2 = feature_row("https://example.com/b");
        p2.lang = None;
        p2.meta_description = None;
        p2.word_count = Some(90);

        let mut p3 = feature_row("https://example.com/c");
        p3.lang = Some("de".to_owned());
        p3.word_count = Some(40);

        let table = PageFeaturesTable::from_pages([p1, p2, p3]);
        let ctx = SiteRuleContext {
            pages: &table,
            graph: None,
            coverage_complete: true,
        };
        let results = SiteRuleRegistry::with_default_rules().evaluate_all(&ctx);
        let ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(ids.contains(&RULE_SITE_LANGUAGE_CONSISTENCY));
        assert!(ids.contains(&RULE_SITE_MISSING_DESCRIPTION_PATTERN));
        assert!(ids.contains(&RULE_SITE_THIN_PAGE_CONCENTRATION));
    }

    #[test]
    fn site_rule_registry_passes_healthy_site_and_skips_small_samples() {
        let small = PageFeaturesTable::from_pages([
            feature_row("https://example.com/"),
            feature_row("https://example.com/about"),
        ]);
        let small_ctx = SiteRuleContext {
            pages: &small,
            graph: None,
            coverage_complete: true,
        };
        let small_res = SiteRuleRegistry::with_default_rules().evaluate_all(&small_ctx);
        assert!(small_res.iter().all(|r| r.findings.is_empty()));
        assert!(
            small_res
                .iter()
                .flat_map(|r| r.checks.iter())
                .all(|c| matches!(c, CheckStatus::Skipped { .. }))
        );

        let healthy = PageFeaturesTable::from_pages([
            feature_row("https://example.com/"),
            feature_row("https://example.com/about"),
            feature_row("https://example.com/pricing"),
        ]);
        let healthy_ctx = SiteRuleContext {
            pages: &healthy,
            graph: None,
            coverage_complete: true,
        };
        let healthy_res = SiteRuleRegistry::with_default_rules().evaluate_all(&healthy_ctx);
        assert!(healthy_res.iter().all(|r| r.findings.is_empty()));
        assert!(
            healthy_res
                .iter()
                .flat_map(|r| r.checks.iter())
                .all(|c| matches!(c, CheckStatus::Passed { .. }))
        );
    }
}
