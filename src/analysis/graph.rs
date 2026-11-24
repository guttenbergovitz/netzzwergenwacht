//! Wave I — Application Graph deterministic analysis (`NetzZwerg`, `SuchZwerg`, `StrukturZwerg`, `InhaltsZwerg`).
//!
//! Evaluates cross-page relationships (broken internal links, links to
//! redirects or non-indexable pages, broken fragment anchors, orphan sitemap
//! candidates, canonical chains/loops, `hreflang` reciprocity/self-reference,
//! and duplicate titles/descriptions) over a typed [`ApplicationGraph`]
//! without performing network I/O.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::analysis::document::HreflangObs;
use crate::analysis::schema::SchemaEntitySummary;
use crate::brigade::DwarfId;
use crate::domain::{
    AnalyserResult, CheckStatus, Confidence, EvidenceLevel, EvidenceRef, EvidenceSource, Finding,
    FindingCategory, FindingFingerprint, FindingKind, RuleId, Severity,
};

const RULE_BROKEN_INTERNAL_LINKS: &str = "graph.links.broken_internal";
const RULE_LINKS_TO_REDIRECTS: &str = "graph.links.to_redirects";
const RULE_LINKS_TO_NON_INDEXABLE: &str = "graph.links.to_non_indexable";
const RULE_BROKEN_ANCHORS: &str = "graph.links.broken_anchors";
const RULE_ORPHAN_CANDIDATES: &str = "graph.crawl.orphan_candidates";
const RULE_CANONICAL_GRAPH: &str = "graph.seo.canonical_chain_or_loop";
const RULE_HREFLANG_RECIPROCITY: &str = "graph.i18n.hreflang_reciprocity";
const RULE_DUPLICATE_METADATA: &str = "graph.content.duplicate_metadata";
const RULE_ENTITY_CONFLICTS: &str = "graph.schema.entity_conflicts";
const RULE_DANGLING_ENTITIES: &str = "graph.schema.dangling_entities";

/// All rule identifiers evaluated by the Application Graph engine.
pub const ALL_RULES: &[&str] = &[
    RULE_BROKEN_INTERNAL_LINKS,
    RULE_LINKS_TO_REDIRECTS,
    RULE_LINKS_TO_NON_INDEXABLE,
    RULE_BROKEN_ANCHORS,
    RULE_ORPHAN_CANDIDATES,
    RULE_CANONICAL_GRAPH,
    RULE_HREFLANG_RECIPROCITY,
    RULE_DUPLICATE_METADATA,
    RULE_ENTITY_CONFLICTS,
    RULE_DANGLING_ENTITIES,
];

/// Per-page input record used to construct an [`ApplicationGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPageInput {
    /// Normalised final URL after redirects.
    pub url: String,
    /// Original requested URL before redirects.
    pub requested_url: String,
    /// HTTP status code (`None` if unreachable or collection failed).
    pub status_code: Option<u16>,
    /// Intermediate redirect targets traversed before reaching `url`.
    pub redirect_targets: Vec<String>,
    /// BFS hop depth from seed (`0` = seed).
    pub depth: usize,
    /// Whether this URL was present in `sitemap.xml`.
    pub in_sitemap: bool,
    /// Whether the page is indexable (HTTP 200 and not `noindex`).
    pub indexable: bool,
    /// Resolved `<link rel="canonical">` URL, if declared.
    pub canonical_url: Option<String>,
    /// Trimmed `<title>`, if present.
    pub title: Option<String>,
    /// Trimmed `<meta name="description">`, if present.
    pub meta_description: Option<String>,
    /// Resolved same-origin internal link target URLs (fragments stripped).
    pub internal_links: Vec<String>,
    /// Resolved `hreflang` alternate declarations.
    pub hreflangs: Vec<HreflangObs>,
    /// Same-page fragment targets (without leading `#`).
    pub same_page_fragments: Vec<String>,
    /// All element `id`s present on this page.
    pub all_ids: HashSet<String>,
    /// Primary document language (`<html lang="...">`), if declared.
    pub lang: Option<String>,
    /// Structured data entities extracted from JSON-LD blocks on this page.
    pub entities: Vec<SchemaEntitySummary>,
}

/// Normalised application-level URL, link, canonical, and hreflang graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationGraph {
    /// Pages indexed by their primary URL (`url`).
    pub pages: BTreeMap<String, GraphPageInput>,
    /// Map from `requested_url` -> final `url` for redirected nodes.
    pub redirect_map: BTreeMap<String, String>,
    /// Incoming internal link sources per target URL.
    pub incoming_links: BTreeMap<String, BTreeSet<String>>,
    /// Whether all discovered internal targets are present in `pages`.
    pub coverage_complete: bool,
}

impl ApplicationGraph {
    /// Builds an [`ApplicationGraph`] from crawled page records.
    #[must_use]
    pub fn from_pages(inputs: &[GraphPageInput], coverage_complete: bool) -> Self {
        let mut pages = BTreeMap::new();
        let mut redirect_map = BTreeMap::new();
        let mut incoming_links: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for page in inputs {
            if page.requested_url != page.url {
                redirect_map.insert(page.requested_url.clone(), page.url.clone());
            }
            for hop in &page.redirect_targets {
                if hop != &page.url {
                    redirect_map.insert(hop.clone(), page.url.clone());
                }
            }
            pages.insert(page.url.clone(), page.clone());
        }

        for page in inputs {
            for target in &page.internal_links {
                let resolved = redirect_map.get(target).unwrap_or(target);
                incoming_links
                    .entry(resolved.clone())
                    .or_default()
                    .insert(page.url.clone());
            }
        }

        Self {
            pages,
            redirect_map,
            incoming_links,
            coverage_complete,
        }
    }
}

/// Evaluates all Application Graph rules across `graph`, grouped by responsible dwarf.
#[must_use]
pub fn analyse(graph: &ApplicationGraph) -> Vec<AnalyserResult> {
    let mut netz_findings = Vec::new();
    let mut netz_checks = Vec::new();
    let mut such_findings = Vec::new();
    let mut such_checks = Vec::new();
    let mut str_findings = Vec::new();
    let mut str_checks = Vec::new();
    let mut inh_findings = Vec::new();
    let mut inh_checks = Vec::new();

    if graph.pages.is_empty() {
        return Vec::new();
    }

    check_broken_internal_links(graph, &mut netz_findings, &mut netz_checks);
    check_links_to_redirects(graph, &mut netz_findings, &mut netz_checks);
    check_orphan_candidates(graph, &mut netz_findings, &mut netz_checks);

    check_links_to_non_indexable(graph, &mut such_findings, &mut such_checks);
    check_canonical_graph(graph, &mut such_findings, &mut such_checks);
    check_hreflang_reciprocity(graph, &mut such_findings, &mut such_checks);
    check_entity_graph(graph, &mut such_findings, &mut such_checks);

    check_broken_anchors(graph, &mut str_findings, &mut str_checks);
    check_duplicate_metadata(graph, &mut inh_findings, &mut inh_checks);

    vec![
        AnalyserResult {
            dwarf_id: DwarfId::Netz,
            findings: netz_findings,
            checks: netz_checks,
        },
        AnalyserResult {
            dwarf_id: DwarfId::Such,
            findings: such_findings,
            checks: such_checks,
        },
        AnalyserResult {
            dwarf_id: DwarfId::Struktur,
            findings: str_findings,
            checks: str_checks,
        },
        AnalyserResult {
            dwarf_id: DwarfId::Inhalts,
            findings: inh_findings,
            checks: inh_checks,
        },
    ]
}

fn check_broken_internal_links(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut broken = Vec::new();
    for page in graph.pages.values() {
        for link in &page.internal_links {
            let target_url = graph.redirect_map.get(link).unwrap_or(link);
            if let Some(target_page) = graph.pages.get(target_url) {
                let is_broken = match target_page.status_code {
                    Some(code) => code >= 400,
                    None => true,
                };
                if is_broken {
                    broken.push(format!(
                        "{} -> {} ({:?})",
                        page.url, link, target_page.status_code
                    ));
                }
            }
        }
    }

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_BROKEN_INTERNAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_BROKEN_INTERNAL_LINKS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!("Broken internal links ({})", broken.len()),
            summary: format!(
                "Detected {} internal link(s) resolving to 4xx/5xx or unreachable pages: {}.",
                broken.len(),
                broken
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("broken_internal_links={}", broken.len()),
            )],
            remediation: Some(
                "Update or remove internal links pointing to failing or missing URLs.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_BROKEN_INTERNAL_LINKS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_links_to_redirects(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut redirected_links = Vec::new();
    for page in graph.pages.values() {
        for link in &page.internal_links {
            if let Some(final_dest) = graph.redirect_map.get(link) {
                redirected_links.push(format!("{} -> {} => {}", page.url, link, final_dest));
            }
        }
    }

    if redirected_links.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LINKS_TO_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LINKS_TO_REDIRECTS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!(
                "Internal links pointing to redirects ({})",
                redirected_links.len()
            ),
            summary: format!(
                "{} internal link(s) point to redirecting URLs instead of final destinations.",
                redirected_links.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpRedirectChain,
                format!("links_to_redirects={}", redirected_links.len()),
            )],
            remediation: Some(
                "Point internal links directly to canonical final URLs to avoid extra hops."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LINKS_TO_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_orphan_candidates(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let sitemap_pages: Vec<&GraphPageInput> = graph
        .pages
        .values()
        .filter(|p| p.in_sitemap && p.depth > 0)
        .collect();

    if sitemap_pages.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_ORPHAN_CANDIDATES.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no non-seed sitemap pages in graph".to_owned(),
        });
        return;
    }

    let orphans: Vec<&str> = sitemap_pages
        .into_iter()
        .filter(|p| {
            graph
                .incoming_links
                .get(&p.url)
                .is_none_or(BTreeSet::is_empty)
        })
        .map(|p| p.url.as_str())
        .collect();

    if orphans.is_empty() {
        if graph.coverage_complete {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_ORPHAN_CANDIDATES.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(RULE_ORPHAN_CANDIDATES.to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "incomplete crawl coverage; absence of orphans cannot be verified"
                    .to_owned(),
            });
        }
    } else {
        let confidence = if graph.coverage_complete {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ORPHAN_CANDIDATES.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence,
            title: format!("Orphan sitemap page candidates ({})", orphans.len()),
            summary: format!(
                "{} sitemap URL(s) had zero observed incoming internal links (coverage_complete={}).",
                orphans.len(),
                graph.coverage_complete
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("orphan_candidates={}", orphans.len()),
            )],
            remediation: Some(
                "Ensure important sitemap pages are linked from site navigation or hub pages."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ORPHAN_CANDIDATES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_links_to_non_indexable(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut hits = Vec::new();
    for page in graph.pages.values() {
        for link in &page.internal_links {
            let target_url = graph.redirect_map.get(link).unwrap_or(link);
            if let Some(target_page) = graph.pages.get(target_url)
                && target_page.status_code == Some(200)
                && !target_page.indexable
            {
                hits.push(format!("{} -> {}", page.url, target_url));
            }
        }
    }

    if hits.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_LINKS_TO_NON_INDEXABLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_LINKS_TO_NON_INDEXABLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Internal links to noindex pages ({})", hits.len()),
            summary: format!(
                "{} internal link(s) target pages marked `noindex`.",
                hits.len()
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("links_to_noindex={}", hits.len()),
            )],
            remediation: Some(
                "Review whether `noindex` targets should be linked or marked `rel=\"nofollow\"`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_LINKS_TO_NON_INDEXABLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_canonical_graph(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut issues = Vec::new();
    for page in graph.pages.values() {
        let Some(canon) = page.canonical_url.as_deref() else {
            continue;
        };
        if canon == page.url {
            continue;
        }
        if let Some(target_page) = graph.pages.get(canon) {
            if target_page.status_code.is_some_and(|c| c >= 400) || !target_page.indexable {
                issues.push(format!(
                    "{} canonicalises to non-indexable/error {}",
                    page.url, canon
                ));
            } else if let Some(next_canon) = target_page.canonical_url.as_deref()
                && next_canon != canon
            {
                if next_canon == page.url {
                    issues.push(format!("canonical loop: {} <-> {}", page.url, canon));
                } else {
                    issues.push(format!(
                        "canonical chain: {} -> {} -> {}",
                        page.url, canon, next_canon
                    ));
                }
            }
        }
    }

    if issues.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CANONICAL_GRAPH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CANONICAL_GRAPH.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Canonical graph anomalies ({})", issues.len()),
            summary: issues.iter().take(3).cloned().collect::<Vec<_>>().join("; "),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("canonical_graph_issues={}", issues.len()),
            )],
            remediation: Some(
                "Ensure canonical links point directly to indexable HTTP-200 self-canonical targets without chains or loops."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CANONICAL_GRAPH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_hreflang_reciprocity(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let pages_with_hreflang: Vec<&GraphPageInput> = graph
        .pages
        .values()
        .filter(|p| !p.hreflangs.is_empty())
        .collect();

    if pages_with_hreflang.is_empty() {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HREFLANG_RECIPROCITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no pages with hreflang declarations in graph".to_owned(),
        });
        return;
    }

    let mut issues = Vec::new();
    for page in &pages_with_hreflang {
        let has_self = page.hreflangs.iter().any(|h| h.href == page.url);
        if !has_self {
            issues.push(format!("{} missing self-referential hreflang", page.url));
        }
        for alt in &page.hreflangs {
            if alt.href == page.url {
                continue;
            }
            if let Some(target) = graph.pages.get(&alt.href) {
                let reciprocal = target.hreflangs.iter().any(|t| t.href == page.url);
                if !reciprocal {
                    issues.push(format!(
                        "{} -> {} missing reciprocal return tag",
                        page.url, alt.href
                    ));
                }
            }
        }
    }

    if issues.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HREFLANG_RECIPROCITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HREFLANG_RECIPROCITY.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Hreflang reciprocity/self-reference gaps ({})",
                issues.len()
            ),
            summary: issues
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("; "),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("hreflang_graph_issues={}", issues.len()),
            )],
            remediation: Some(
                "Ensure every `hreflang` cluster includes self-references and mutual return links."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HREFLANG_RECIPROCITY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_broken_anchors(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut broken = Vec::new();
    let mut total_checked = 0usize;

    for page in graph.pages.values() {
        for frag in &page.same_page_fragments {
            if frag.is_empty() || frag.eq_ignore_ascii_case("top") {
                continue;
            }
            total_checked += 1;
            if !page.all_ids.contains(frag) {
                broken.push(format!("{}#{}", page.url, frag));
            }
        }
    }

    if total_checked == 0 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_BROKEN_ANCHORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "no same-page fragment anchors observed".to_owned(),
        });
        return;
    }

    if broken.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_BROKEN_ANCHORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_BROKEN_ANCHORS.to_owned()),
            category: FindingCategory::Semantics,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Broken same-page fragment anchors ({})", broken.len()),
            summary: format!(
                "{} `#fragment` link(s) reference non-existent element IDs: {}.",
                broken.len(),
                broken
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("broken_anchors={}", broken.len()),
            )],
            remediation: Some(
                "Ensure every `#fragment` target matches an existing `id` in the document."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_BROKEN_ANCHORS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_duplicate_metadata(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut by_title: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut by_desc: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for page in graph.pages.values() {
        if !page.indexable || page.status_code != Some(200) {
            continue;
        }
        if let Some(title) = page.title.as_deref()
            && !title.is_empty()
        {
            by_title.entry(title).or_default().push(&page.url);
        }
        if let Some(desc) = page.meta_description.as_deref()
            && !desc.is_empty()
        {
            by_desc.entry(desc).or_default().push(&page.url);
        }
    }

    let dup_titles: usize = by_title.values().filter(|urls| urls.len() > 1).count();
    let dup_descs: usize = by_desc.values().filter(|urls| urls.len() > 1).count();

    if dup_titles == 0 && dup_descs == 0 {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DUPLICATE_METADATA.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DUPLICATE_METADATA.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: "Duplicate titles or meta descriptions across pages".to_owned(),
            summary: format!(
                "{dup_titles} duplicate `<title>` group(s) and {dup_descs} duplicate meta description group(s) across indexable pages."
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("dup_titles={dup_titles};dup_descriptions={dup_descs}"),
            )],
            remediation: Some(
                "Give every indexable page a unique `<title>` and `<meta name=\"description\">`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DUPLICATE_METADATA.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_entity_graph(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let any_entities = graph.pages.values().any(|p| !p.entities.is_empty());
    if !any_entities {
        for rule in [RULE_ENTITY_CONFLICTS, RULE_DANGLING_ENTITIES] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "no JSON-LD entities in graph".to_owned(),
            });
        }
        return;
    }

    let mut by_id: BTreeMap<&str, Vec<(Option<&str>, &SchemaEntitySummary)>> = BTreeMap::new();
    let mut defined_ids: HashSet<&str> = HashSet::new();

    for page in graph.pages.values() {
        let primary_lang = page
            .lang
            .as_deref()
            .and_then(|l| l.split(['-', '_']).next())
            .map(str::trim);
        for entity in &page.entities {
            if let Some(id) = entity.id.as_deref() {
                defined_ids.insert(id);
                by_id.entry(id).or_default().push((primary_lang, entity));
            }
        }
    }

    let mut conflicts = Vec::new();
    for (id, entries) in &by_id {
        if entries.len() < 2 {
            continue;
        }
        let first_types = &entries[0].1.entity_types;
        let type_conflict = entries
            .iter()
            .skip(1)
            .any(|(_, e)| &e.entity_types != first_types);
        let first_lang = entries[0].0;
        let first_name = &entries[0].1.name;
        let same_lang_name_conflict = entries.iter().skip(1).any(|(lang, e)| {
            *lang == first_lang && first_name.is_some() && e.name.is_some() && &e.name != first_name
        });
        if type_conflict || same_lang_name_conflict {
            conflicts.push((*id).to_owned());
        }
    }

    if conflicts.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_ENTITY_CONFLICTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_ENTITY_CONFLICTS.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Conflicting Schema.org entity definitions ({})",
                conflicts.len()
            ),
            summary: format!(
                "Shared `@id` entity/entities have conflicting `@type` or `name` across pages: {}.",
                conflicts
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("entity_conflicts={}", conflicts.len()),
            )],
            remediation: Some(
                "Keep `@type` and canonical `name` consistent wherever a shared `@id` is emitted."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_ENTITY_CONFLICTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }

    check_dangling_entities(graph, &defined_ids, findings, checks);
}

fn check_dangling_entities(
    graph: &ApplicationGraph,
    defined_ids: &HashSet<&str>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let same_host = graph
        .pages
        .keys()
        .next()
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase));

    let mut dangling = Vec::new();
    for page in graph.pages.values() {
        for entity in &page.entities {
            for ref_id in &entity.referenced_ids {
                let is_internal_id = ref_id.starts_with('#')
                    || same_host.as_deref().is_some_and(|h| {
                        url::Url::parse(ref_id)
                            .ok()
                            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                            .is_some_and(|rh| rh == h)
                    });
                if is_internal_id && !defined_ids.contains(ref_id.as_str()) {
                    dangling.push(ref_id.clone());
                }
            }
        }
    }

    if dangling.is_empty() {
        if graph.coverage_complete {
            checks.push(CheckStatus::Passed {
                rule_id: RuleId(RULE_DANGLING_ENTITIES.to_owned()),
                evidence_level: EvidenceLevel::Source,
            });
        } else {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId(RULE_DANGLING_ENTITIES.to_owned()),
                evidence_level: EvidenceLevel::Source,
                reason: "incomplete crawl coverage; entity resolution cannot be verified"
                    .to_owned(),
            });
        }
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DANGLING_ENTITIES.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Low,
            confidence: if graph.coverage_complete {
                Confidence::High
            } else {
                Confidence::Low
            },
            title: format!("Dangling internal entity references ({})", dangling.len()),
            summary: format!(
                "{} internal `@id` reference(s) did not resolve to any crawled entity definition: {}.",
                dangling.len(),
                dangling.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("dangling_entities={}", dangling.len()),
            )],
            remediation: Some(
                "Ensure referenced `@id` entities are defined in the site's JSON-LD `@graph`."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DANGLING_ENTITIES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> GraphPageInput {
        GraphPageInput {
            url: url.to_owned(),
            requested_url: url.to_owned(),
            status_code: Some(200),
            redirect_targets: Vec::new(),
            depth: 1,
            in_sitemap: true,
            indexable: true,
            canonical_url: Some(url.to_owned()),
            title: Some(format!("Title {url}")),
            meta_description: Some(format!("Desc {url}")),
            internal_links: Vec::new(),
            hreflangs: Vec::new(),
            same_page_fragments: Vec::new(),
            all_ids: HashSet::new(),
            lang: Some("en".to_owned()),
            entities: Vec::new(),
        }
    }

    #[test]
    fn detects_broken_links_redirects_noindex_anchors_orphans_and_duplicates() {
        let mut home = page("https://example.com/");
        home.depth = 0;
        home.internal_links = vec![
            "https://example.com/missing".to_owned(),
            "https://example.com/old".to_owned(),
            "https://example.com/private".to_owned(),
        ];
        home.same_page_fragments = vec!["nonexistent".to_owned()];

        let mut missing = page("https://example.com/missing");
        missing.status_code = Some(404);
        missing.indexable = false;

        let mut new_target = page("https://example.com/new");
        new_target.requested_url = "https://example.com/old".to_owned();
        new_target.title = home.title.clone();

        let mut private = page("https://example.com/private");
        private.indexable = false;

        let orphan = page("https://example.com/orphan");

        let graph =
            ApplicationGraph::from_pages(&[home, missing, new_target, private, orphan], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_BROKEN_INTERNAL_LINKS));
        assert!(rule_ids.contains(&RULE_LINKS_TO_REDIRECTS));
        assert!(rule_ids.contains(&RULE_LINKS_TO_NON_INDEXABLE));
        assert!(rule_ids.contains(&RULE_BROKEN_ANCHORS));
        assert!(rule_ids.contains(&RULE_ORPHAN_CANDIDATES));
        assert!(rule_ids.contains(&RULE_DUPLICATE_METADATA));
    }

    #[test]
    fn detects_canonical_chain_loop_and_missing_hreflang_reciprocity() {
        let mut en = page("https://example.com/en");
        en.canonical_url = Some("https://example.com/de".to_owned());
        en.hreflangs = vec![
            HreflangObs {
                lang: "en".to_owned(),
                href: "https://example.com/en".to_owned(),
            },
            HreflangObs {
                lang: "de".to_owned(),
                href: "https://example.com/de".to_owned(),
            },
        ];

        let mut de = page("https://example.com/de");
        de.canonical_url = Some("https://example.com/en".to_owned());
        de.hreflangs = vec![HreflangObs {
            lang: "de".to_owned(),
            href: "https://example.com/de".to_owned(),
        }];

        let graph = ApplicationGraph::from_pages(&[en, de], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_CANONICAL_GRAPH));
        assert!(rule_ids.contains(&RULE_HREFLANG_RECIPROCITY));
    }

    #[test]
    fn detects_cross_page_entity_conflicts_and_dangling_entities() {
        let mut p1 = page("https://example.com/a");
        p1.entities = vec![SchemaEntitySummary {
            id: Some("https://example.com/#org".to_owned()),
            entity_types: vec!["Organization".to_owned()],
            name: Some("Acme Corp".to_owned()),
            same_as: Vec::new(),
            referenced_ids: vec!["https://example.com/#missing-author".to_owned()],
        }];

        let mut p2 = page("https://example.com/b");
        p2.entities = vec![SchemaEntitySummary {
            id: Some("https://example.com/#org".to_owned()),
            entity_types: vec!["Organization".to_owned()],
            name: Some("Different Name".to_owned()),
            same_as: Vec::new(),
            referenced_ids: Vec::new(),
        }];

        let graph = ApplicationGraph::from_pages(&[p1, p2], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_ENTITY_CONFLICTS));
        assert!(rule_ids.contains(&RULE_DANGLING_ENTITIES));
    }
}
