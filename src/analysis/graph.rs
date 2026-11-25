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
const RULE_DEEP_CRAWL_DEPTH: &str = "graph.crawl.deep_crawl_depth";
const RULE_SITEMAP_NON_INDEXABLE: &str = "graph.seo.sitemap_non_indexable";
const RULE_EXCESSIVE_INTERNAL_REDIRECTS: &str = "graph.links.excessive_internal_redirects";
const RULE_CRAWL_TRAP_CANDIDATE: &str = "graph.crawl.trap_candidate";
const RULE_SHARED_FAILED_DEPENDENCY: &str = "graph.resources.shared_failed_dependency";
const RULE_THIRD_PARTY_CONCENTRATION: &str = "graph.resources.third_party_concentration";
const RULE_TRAILING_SLASH_INCONSISTENCY: &str = "graph.seo.trailing_slash_inconsistency";
const RULE_HTTP_HTTPS_MIXED_PAGES: &str = "graph.seo.http_https_mixed_pages";
const RULE_HEAVY_SHARED_ASSET: &str = "graph.resources.heavy_shared_asset";
const RULE_NEAR_DUPLICATE_SIMHASH: &str = "graph.content.near_duplicate_simhash";

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
    RULE_DEEP_CRAWL_DEPTH,
    RULE_SITEMAP_NON_INDEXABLE,
    RULE_EXCESSIVE_INTERNAL_REDIRECTS,
    RULE_CRAWL_TRAP_CANDIDATE,
    RULE_SHARED_FAILED_DEPENDENCY,
    RULE_THIRD_PARTY_CONCENTRATION,
    RULE_TRAILING_SLASH_INCONSISTENCY,
    RULE_HTTP_HTTPS_MIXED_PAGES,
    RULE_HEAVY_SHARED_ASSET,
    RULE_NEAR_DUPLICATE_SIMHASH,
];

/// Compact subresource record attached to a [`GraphPageInput`] for `ResourceGraph` projection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphResourceInput {
    /// Subresource URL.
    pub url: String,
    /// Observed HTTP status code, if known.
    pub status_code: Option<u16>,
    /// Observed transfer size in bytes, if known.
    pub transfer_size: Option<u64>,
    /// Observed `Cache-Control` header, if known.
    pub cache_control: Option<String>,
}

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
    /// Optional subresource observations for cross-page `ResourceGraph` correlation.
    pub resources: Vec<GraphResourceInput>,
    /// Optional 64-bit `SimHash` of visible body text for near-duplicate clustering.
    pub text_simhash: Option<u64>,
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
    check_deep_crawl_depth(graph, &mut netz_findings, &mut netz_checks);
    check_excessive_internal_redirects(graph, &mut netz_findings, &mut netz_checks);
    check_crawl_trap_candidates(graph, &mut netz_findings, &mut netz_checks);
    check_resource_graph_dependencies(graph, &mut netz_findings, &mut netz_checks);
    check_heavy_shared_assets(graph, &mut netz_findings, &mut netz_checks);

    check_links_to_non_indexable(graph, &mut such_findings, &mut such_checks);
    check_canonical_graph(graph, &mut such_findings, &mut such_checks);
    check_hreflang_reciprocity(graph, &mut such_findings, &mut such_checks);
    check_entity_graph(graph, &mut such_findings, &mut such_checks);
    check_sitemap_non_indexable(graph, &mut such_findings, &mut such_checks);
    check_trailing_slash_and_scheme_consistency(graph, &mut such_findings, &mut such_checks);

    check_broken_anchors(graph, &mut str_findings, &mut str_checks);
    check_duplicate_metadata(graph, &mut inh_findings, &mut inh_checks);
    check_near_duplicate_simhash(graph, &mut inh_findings, &mut inh_checks);

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

fn check_deep_crawl_depth(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let deep: Vec<String> = graph
        .pages
        .values()
        .filter(|p| p.depth > 3)
        .map(|p| format!("{} (depth={})", p.url, p.depth))
        .collect();

    if deep.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_DEEP_CRAWL_DEPTH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_DEEP_CRAWL_DEPTH.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Low,
            confidence: Confidence::High,
            title: format!("Pages buried at crawl depth > 3 ({})", deep.len()),
            summary: format!(
                "{} page(s) require more than 3 clicks from the seed URL: {}.",
                deep.len(),
                deep.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("deep_pages={}", deep.len()),
            )],
            remediation: Some(
                "Flatten site navigation and add internal links to important deep pages."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_DEEP_CRAWL_DEPTH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_sitemap_non_indexable(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let bad: Vec<String> = graph
        .pages
        .values()
        .filter(|p| p.in_sitemap && (!p.indexable || p.status_code.is_some_and(|s| s >= 300)))
        .map(|p| p.url.clone())
        .collect();

    if bad.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SITEMAP_NON_INDEXABLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SITEMAP_NON_INDEXABLE.to_owned()),
            category: FindingCategory::Seo,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!(
                "Non-indexable or non-200 URLs in sitemap.xml ({})",
                bad.len()
            ),
            summary: format!(
                "{} sitemap URL(s) are marked `noindex` or return non-200 status: {}.",
                bad.len(),
                bad.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("sitemap_non_indexable={}", bad.len()),
            )],
            remediation: Some(
                "Include only canonical, HTTP 200, indexable URLs in `sitemap.xml`.".to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SITEMAP_NON_INDEXABLE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_excessive_internal_redirects(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let multi_hop: Vec<String> = graph
        .pages
        .values()
        .filter(|p| p.redirect_targets.len() >= 2)
        .map(|p| format!("{} ({} hops)", p.requested_url, p.redirect_targets.len()))
        .collect();

    if multi_hop.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_EXCESSIVE_INTERNAL_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_EXCESSIVE_INTERNAL_REDIRECTS.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Deterministic,
            severity: Severity::Medium,
            confidence: Confidence::High,
            title: format!("Multi-hop internal redirect chains ({})", multi_hop.len()),
            summary: format!(
                "{} URL(s) traverse 2 or more redirect hops: {}.",
                multi_hop.len(),
                multi_hop
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpStatus,
                format!("multi_hop_redirects={}", multi_hop.len()),
            )],
            remediation: Some(
                "Collapse multi-hop redirects into a single 301/308 hop and update internal links."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_EXCESSIVE_INTERNAL_REDIRECTS.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_crawl_trap_candidates(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut path_variants: BTreeMap<String, usize> = BTreeMap::new();
    for url_str in graph.pages.keys() {
        if let Ok(parsed) = url::Url::parse(url_str)
            && parsed.query().is_some()
        {
            let base = format!(
                "{}://{}{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                parsed.path()
            );
            *path_variants.entry(base).or_insert(0) += 1;
        }
    }
    let traps: Vec<String> = path_variants
        .into_iter()
        .filter(|(_, count)| *count >= 5)
        .map(|(base, count)| format!("{base} ({count} query variants)"))
        .collect();

    if traps.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_CRAWL_TRAP_CANDIDATE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_CRAWL_TRAP_CANDIDATE.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Potential parameterised crawl trap(s) ({})", traps.len()),
            summary: format!(
                "Detected path(s) generating >= 5 parameterised URL variants: {}.",
                traps.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("crawl_trap_paths={}", traps.len()),
            )],
            remediation: Some(
                "Canonicalise faceted/filter query URLs or disallow unbounded parameter combinations in robots.txt."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_CRAWL_TRAP_CANDIDATE.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    }
}

fn check_resource_graph_dependencies(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let pages_with_res: Vec<&GraphPageInput> = graph
        .pages
        .values()
        .filter(|p| !p.resources.is_empty())
        .collect();
    if pages_with_res.len() < 2 {
        for rule in [
            RULE_SHARED_FAILED_DEPENDENCY,
            RULE_THIRD_PARTY_CONCENTRATION,
        ] {
            checks.push(CheckStatus::Skipped {
                rule_id: RuleId((*rule).to_owned()),
                evidence_level: EvidenceLevel::Rendered,
                reason: "fewer than 2 pages with subresource telemetry".to_owned(),
            });
        }
        return;
    }

    let mut failed_by_url: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut host_pages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for page in &pages_with_res {
        let page_host = url::Url::parse(&page.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
        for res in &page.resources {
            if res.status_code.is_some_and(|s| s >= 400) {
                failed_by_url
                    .entry(res.url.clone())
                    .or_default()
                    .insert(page.url.clone());
            }
            if let Ok(u) = url::Url::parse(&res.url)
                && let Some(h) = u.host_str().map(str::to_ascii_lowercase)
                && page_host.as_deref() != Some(h.as_str())
            {
                host_pages.entry(h).or_default().insert(page.url.clone());
            }
        }
    }

    let shared_failed: Vec<String> = failed_by_url
        .into_iter()
        .filter(|(_, pages)| pages.len() >= 2)
        .map(|(url, pages)| format!("{url} ({} pages)", pages.len()))
        .collect();
    if shared_failed.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_SHARED_FAILED_DEPENDENCY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_SHARED_FAILED_DEPENDENCY.to_owned()),
            category: FindingCategory::Reliability,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: Severity::High,
            confidence: Confidence::High,
            title: format!(
                "Shared failing subresource dependencies ({})",
                shared_failed.len()
            ),
            summary: format!(
                "{} subresource(s) failed across multiple pages: {}.",
                shared_failed.len(),
                shared_failed
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("shared_failed_resources={}", shared_failed.len()),
            )],
            remediation: Some(
                "Repair or remove broken shared template dependencies affecting multiple routes."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_SHARED_FAILED_DEPENDENCY.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }

    emit_third_party_concentration(host_pages, pages_with_res.len(), findings, checks);
}

fn emit_third_party_concentration(
    host_pages: BTreeMap<String, BTreeSet<String>>,
    total_pages: usize,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let concentrated: Vec<String> = host_pages
        .into_iter()
        .filter(|(_, pages)| pages.len() * 2 >= total_pages)
        .map(|(host, pages)| format!("{host} ({}/{total_pages})", pages.len()))
        .collect();
    if concentrated.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_THIRD_PARTY_CONCENTRATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_THIRD_PARTY_CONCENTRATION.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Heuristic,
            severity: Severity::Info,
            confidence: Confidence::High,
            title: format!(
                "High third-party origin concentration ({})",
                concentrated.len()
            ),
            summary: format!(
                "External host(s) loaded across >= 50% of inspected pages: {}.",
                concentrated
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("concentrated_third_party_hosts={}", concentrated.len()),
            )],
            remediation: Some(
                "Assess availability and latency risk of widely shared third-party origins."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_THIRD_PARTY_CONCENTRATION.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn check_trailing_slash_and_scheme_consistency(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut path_variants: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut host_schemes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for url_str in graph.pages.keys() {
        let Ok(parsed) = url::Url::parse(url_str) else {
            continue;
        };
        let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
            continue;
        };
        host_schemes
            .entry(host.clone())
            .or_default()
            .insert(parsed.scheme().to_ascii_lowercase());

        let path = parsed.path();
        if path != "/" {
            let trimmed = path.trim_end_matches('/').to_owned();
            path_variants
                .entry((host, trimmed))
                .or_default()
                .insert(path.to_owned());
        }
    }

    report_trailing_slash_conflicts(path_variants, findings, checks);
    report_mixed_scheme_hosts(host_schemes, findings, checks);
}

fn report_trailing_slash_conflicts(
    path_variants: BTreeMap<(String, String), BTreeSet<String>>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let slash_conflicts: Vec<String> = path_variants
        .into_iter()
        .filter(|(_, variants)| variants.len() > 1)
        .map(|((host, base), _)| format!("{host}{base}"))
        .collect();
    if slash_conflicts.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_TRAILING_SLASH_INCONSISTENCY.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_TRAILING_SLASH_INCONSISTENCY.to_owned()),
        category: FindingCategory::Seo,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Low,
        confidence: Confidence::High,
        title: format!(
            "Trailing-slash URL inconsistencies ({})",
            slash_conflicts.len()
        ),
        summary: format!(
            "{} path(s) exist both with and without a trailing slash (for example `{}`).",
            slash_conflicts.len(),
            slash_conflicts[0]
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpStatus,
            format!("trailing_slash_conflicts={}", slash_conflicts.len()),
        )],
        remediation: Some(
            "Enforce a single trailing-slash convention via 301 redirects and canonical tags."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_TRAILING_SLASH_INCONSISTENCY.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn report_mixed_scheme_hosts(
    host_schemes: BTreeMap<String, BTreeSet<String>>,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mixed_hosts: Vec<String> = host_schemes
        .into_iter()
        .filter(|(_, schemes)| schemes.contains("http") && schemes.contains("https"))
        .map(|(host, _)| host)
        .collect();
    if mixed_hosts.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HTTP_HTTPS_MIXED_PAGES.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
        return;
    }

    findings.push(Finding {
        fingerprint: FindingFingerprint::default(),
        rule_id: RuleId(RULE_HTTP_HTTPS_MIXED_PAGES.to_owned()),
        category: FindingCategory::Seo,
        evidence_level: EvidenceLevel::Source,
        kind: FindingKind::Deterministic,
        severity: Severity::Medium,
        confidence: Confidence::High,
        title: format!(
            "Mixed HTTP and HTTPS pages on same host ({})",
            mixed_hosts.len()
        ),
        summary: format!(
            "Application graph observed both `http://` and `https://` pages on host(s): {}.",
            mixed_hosts.join(", ")
        ),
        evidence_refs: vec![EvidenceRef::new(
            EvidenceSource::HttpStatus,
            format!("mixed_scheme_hosts={}", mixed_hosts.len()),
        )],
        remediation: Some(
            "Redirect all `http://` URLs permanently (301) to `https://` and enable HSTS."
                .to_owned(),
        ),
    });
    checks.push(CheckStatus::Failed {
        rule_id: RuleId(RULE_HTTP_HTTPS_MIXED_PAGES.to_owned()),
        evidence_level: EvidenceLevel::Source,
    });
}

fn check_heavy_shared_assets(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let mut asset_pages: BTreeMap<String, (BTreeSet<String>, u64, bool)> = BTreeMap::new();
    let mut any_resources = false;
    for page in graph.pages.values() {
        for res in &page.resources {
            any_resources = true;
            if let Some(bytes) = res.transfer_size {
                let entry = asset_pages
                    .entry(res.url.clone())
                    .or_insert_with(|| (BTreeSet::new(), 0, false));
                entry.0.insert(page.url.clone());
                entry.1 = entry.1.max(bytes);
                let weak_cache = res
                    .cache_control
                    .as_deref()
                    .is_some_and(is_weak_cache_control);
                entry.2 |= weak_cache;
            }
        }
    }

    if !any_resources {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_HEAVY_SHARED_ASSET.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
            reason: "no browser subresource observations in graph".to_owned(),
        });
        return;
    }

    let mut any_weak_cache = false;
    let heavy: Vec<String> = asset_pages
        .into_iter()
        .filter(|(_, (pages, max_bytes, _))| pages.len() >= 2 && *max_bytes > 512_000)
        .map(|(url, (pages, max_bytes, weak_cache))| {
            any_weak_cache |= weak_cache;
            let cache_note = if weak_cache { ", weak/uncached" } else { "" };
            format!(
                "{url} ({} KiB, {} pages{cache_note})",
                max_bytes / 1024,
                pages.len()
            )
        })
        .collect();
    if heavy.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_HEAVY_SHARED_ASSET.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_HEAVY_SHARED_ASSET.to_owned()),
            category: FindingCategory::Performance,
            evidence_level: EvidenceLevel::Rendered,
            kind: FindingKind::Deterministic,
            severity: if any_weak_cache {
                Severity::Medium
            } else {
                Severity::Low
            },
            confidence: Confidence::High,
            title: format!("Heavy shared subresource dependencies ({})", heavy.len()),
            summary: format!(
                "{} subresource(s) > 500 KiB are shared across multiple pages: {}.",
                heavy.len(),
                heavy[0]
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("heavy_shared_assets={}", heavy.len()),
            )],
            remediation: Some(
                "Code-split or compress heavy shared bundles/media referenced across multiple routes."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_HEAVY_SHARED_ASSET.to_owned()),
            evidence_level: EvidenceLevel::Rendered,
        });
    }
}

fn is_weak_cache_control(raw: &str) -> bool {
    let mut max_age_secs: Option<u64> = None;
    for directive in raw.split(',') {
        let token = directive.trim().to_ascii_lowercase();
        if matches!(token.as_str(), "no-store" | "no-cache") {
            return true;
        }
        if let Some(val) = token.strip_prefix("max-age=")
            && let Ok(secs) = val.trim().trim_matches('"').parse::<u64>()
        {
            max_age_secs = Some(secs);
        }
    }
    max_age_secs.is_none_or(|secs| secs < 3_600)
}

/// Computes a 64-bit FNV-1a `SimHash` over normalised word shingles when `text` has >= 25 tokens.
#[must_use]
pub fn compute_text_simhash(text: &str) -> Option<u64> {
    let tokens: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect();
    if tokens.len() < 25 {
        return None;
    }

    let mut weights = [0_i32; 64];
    for window in tokens.windows(3) {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for tok in window {
            for b in tok.as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h ^= 0xff;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for (bit, weight) in weights.iter_mut().enumerate() {
            if (h >> bit) & 1 == 1 {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }
    }

    let mut fingerprint = 0_u64;
    for (bit, &w) in weights.iter().enumerate() {
        if w > 0 {
            fingerprint |= 1_u64 << bit;
        }
    }
    Some(fingerprint)
}

fn check_near_duplicate_simhash(
    graph: &ApplicationGraph,
    findings: &mut Vec<Finding>,
    checks: &mut Vec<CheckStatus>,
) {
    let hashed: Vec<(&str, u64)> = graph
        .pages
        .values()
        .filter(|p| p.indexable)
        .filter_map(|p| p.text_simhash.map(|h| (p.url.as_str(), h)))
        .collect();
    if hashed.len() < 2 {
        checks.push(CheckStatus::Skipped {
            rule_id: RuleId(RULE_NEAR_DUPLICATE_SIMHASH.to_owned()),
            evidence_level: EvidenceLevel::Source,
            reason: "fewer than two indexable pages with text_simhash".to_owned(),
        });
        return;
    }

    let mut pairs = Vec::new();
    for i in 0..hashed.len() {
        for j in (i + 1)..hashed.len() {
            let dist = (hashed[i].1 ^ hashed[j].1).count_ones();
            if dist <= 6 {
                pairs.push(format!(
                    "{} ~ {} (hamming={dist})",
                    hashed[i].0, hashed[j].0
                ));
            }
        }
    }

    if pairs.is_empty() {
        checks.push(CheckStatus::Passed {
            rule_id: RuleId(RULE_NEAR_DUPLICATE_SIMHASH.to_owned()),
            evidence_level: EvidenceLevel::Source,
        });
    } else {
        findings.push(Finding {
            fingerprint: FindingFingerprint::default(),
            rule_id: RuleId(RULE_NEAR_DUPLICATE_SIMHASH.to_owned()),
            category: FindingCategory::Content,
            evidence_level: EvidenceLevel::Source,
            kind: FindingKind::Heuristic,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            title: format!("Near-duplicate content pairs detected ({})", pairs.len()),
            summary: format!(
                "{} indexable page pair(s) share SimHash distance <= 4 (for example `{}`).",
                pairs.len(),
                pairs[0]
            ),
            evidence_refs: vec![EvidenceRef::new(
                EvidenceSource::HttpBody,
                format!("near_duplicate_pairs={}", pairs.len()),
            )],
            remediation: Some(
                "Consolidate near-duplicate pages with canonical tags or differentiate page copy."
                    .to_owned(),
            ),
        });
        checks.push(CheckStatus::Failed {
            rule_id: RuleId(RULE_NEAR_DUPLICATE_SIMHASH.to_owned()),
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
            resources: Vec::new(),
            text_simhash: None,
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

    #[test]
    fn detects_deep_crawl_depth_and_sitemap_non_indexable() {
        let mut p1 = page("https://example.com/deep");
        p1.depth = 4;
        p1.in_sitemap = true;
        p1.indexable = false;

        let graph = ApplicationGraph::from_pages(&[p1], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_DEEP_CRAWL_DEPTH));
        assert!(rule_ids.contains(&RULE_SITEMAP_NON_INDEXABLE));
    }

    #[test]
    fn detects_excessive_redirects_crawl_traps_and_resource_graph_dependencies() {
        let mut p1 = page("https://example.com/filter?color=1");
        p1.redirect_targets = vec![
            "https://example.com/old1".to_owned(),
            "https://example.com/old2".to_owned(),
        ];
        p1.resources = vec![GraphResourceInput {
            url: "https://cdn.thirdparty.test/broken.js".to_owned(),
            status_code: Some(404),
            transfer_size: Some(0),
            cache_control: None,
        }];
        let mut p2 = page("https://example.com/filter?color=2");
        p2.resources = p1.resources.clone();
        let p3 = page("https://example.com/filter?color=3");
        let p4 = page("https://example.com/filter?color=4");
        let p5 = page("https://example.com/filter?color=5");

        let graph = ApplicationGraph::from_pages(&[p1, p2, p3, p4, p5], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_EXCESSIVE_INTERNAL_REDIRECTS));
        assert!(rule_ids.contains(&RULE_CRAWL_TRAP_CANDIDATE));
        assert!(rule_ids.contains(&RULE_SHARED_FAILED_DEPENDENCY));
        assert!(rule_ids.contains(&RULE_THIRD_PARTY_CONCENTRATION));
    }

    #[test]
    fn detects_trailing_slash_mixed_scheme_and_heavy_shared_asset() {
        let mut p1 = page("https://example.com/about");
        p1.resources = vec![GraphResourceInput {
            url: "https://example.com/vendor.js".to_owned(),
            status_code: Some(200),
            transfer_size: Some(700_000),
            cache_control: Some("no-cache".to_owned()),
        }];
        let mut p2 = page("https://example.com/about/");
        p2.resources = p1.resources.clone();
        let p3 = page("http://example.com/legacy");

        let graph = ApplicationGraph::from_pages(&[p1, p2, p3], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();

        assert!(rule_ids.contains(&RULE_TRAILING_SLASH_INCONSISTENCY));
        assert!(rule_ids.contains(&RULE_HTTP_HTTPS_MIXED_PAGES));
        assert!(rule_ids.contains(&RULE_HEAVY_SHARED_ASSET));
    }

    #[test]
    fn detects_near_duplicate_pages_via_simhash() {
        let base_text = "NetzZwergenWacht inspects web application security accessibility performance structure and search metadata deterministically across every route in the application graph for reliable evidence and continuous quality assurance across large multi page web applications with deterministic verification and repeatable results.";
        let near_text = "NetzZwergenWacht inspects web application security accessibility performance structure and search metadata deterministically across every route in the application graph for reliable evidence and continuous quality assurance across large multi page web applications with deterministic verification and repeatable outputs.";
        let mut p1 = page("https://example.com/p1");
        p1.text_simhash = compute_text_simhash(base_text);
        let mut p2 = page("https://example.com/p2");
        p2.text_simhash = compute_text_simhash(near_text);
        let graph = ApplicationGraph::from_pages(&[p1, p2], true);
        let results = analyse(&graph);
        let rule_ids: Vec<&str> = results
            .iter()
            .flat_map(|r| r.findings.iter().map(|f| f.rule_id.0.as_str()))
            .collect();
        assert!(rule_ids.contains(&RULE_NEAR_DUPLICATE_SIMHASH));
    }
}
