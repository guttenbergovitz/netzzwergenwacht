//! Bounded adaptive crawling, page classification, and systemic issue clustering.
//!
//! Implements Milestone C application-level discovery: resolves same-origin
//! links from [`DocumentObservations`], classifies representative [`PageType`]s,
//! tracks explicit [`PageCrawlStatus`] for every discovered URL, and clusters
//! recurring findings across pages into [`SystemicIssue`]s.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::analysis::document::DocumentObservations;
use crate::analysis::{self, AuditReport};
use crate::collection;
use crate::domain::{
    AuditTarget, CollectorOutcome, Confidence, ExecutionBudget, Origin, RuleId, TargetPolicy,
};

/// Representative page category inferred from URL path and document signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageType {
    /// Root landing page (`/`).
    Homepage,
    /// Authentication / login entry point.
    Auth,
    /// Legal, privacy, terms, or imprint page.
    Legal,
    /// Contact or enquiry page.
    Contact,
    /// Help, FAQ, or support documentation.
    Support,
    /// Page containing interactive form controls.
    Form,
    /// Long-form editorial / blog / article page.
    Article,
    /// Listing or catalogue page.
    Listing,
    /// Unclassified page type.
    Unknown,
}

/// Explicit crawl coverage status for each discovered URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageCrawlStatus {
    /// Page was fetched and analysed completely.
    Investigated,
    /// Page was fetched with partial/truncated evidence.
    PartiallyInvestigated,
    /// Page was discovered but skipped due to [`CrawlBudget`].
    SkippedBudget,
    /// Page failed collection or was unreachable.
    Unreachable,
}

/// Record of a discovered URL and its crawl outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredPage {
    /// Normalised target URL.
    pub url: AuditTarget,
    /// Inferred page type (if investigated).
    pub page_type: PageType,
    /// BFS hop depth from the seed URL.
    pub depth: usize,
    /// Explicit crawl outcome.
    pub status: PageCrawlStatus,
}

/// Resource bounds governing bounded multi-page crawling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlBudget {
    /// Maximum number of pages to fetch and analyse.
    pub max_pages: usize,
    /// Maximum link-following depth from seed URL (`0` = seed only).
    pub max_depth: usize,
    /// End-to-end wall-clock crawl deadline.
    pub max_duration: Duration,
}

impl Default for CrawlBudget {
    fn default() -> Self {
        Self {
            max_pages: 10,
            max_depth: 2,
            max_duration: Duration::from_secs(60),
        }
    }
}

/// Epistemic classification of a cross-page systemic cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemicClassification {
    /// Same rule fired on multiple pages without proven shared origin.
    RepeatedRuleOccurrence,
    /// Pattern across multiple page types suggests a shared template/component.
    SuspectedSharedTemplate,
    /// Server-level header/transport rule suggests shared configuration.
    SuspectedCommonConfiguration,
    /// Confirmed common cause backed by explicit shared-asset/config evidence.
    VerifiedCommonCause,
}

/// Cross-page systemic issue clustering repeated occurrences of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemicIssue {
    /// Stable cluster identifier.
    pub id: String,
    /// Recurring deterministic rule ID.
    pub rule_id: RuleId,
    /// Distinct URLs exhibiting this rule.
    pub affected_urls: Vec<String>,
    /// Distinct page types affected.
    pub affected_page_types: Vec<PageType>,
    /// Classification distinguishing recurrence from confirmed root cause.
    pub classification: SystemicClassification,
    /// Concise summary explaining the cross-page pattern.
    pub summary: String,
    /// Confidence that the finding recurs across the observed pages.
    pub recurrence_confidence: Confidence,
    /// Confidence that the occurrences share a single underlying cause.
    pub shared_cause_confidence: Confidence,
}

/// Output of a bounded multi-page crawl and systemic clustering run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlSummary {
    /// Seed target URL.
    pub seed: AuditTarget,
    /// All discovered URLs with explicit coverage status.
    pub pages: Vec<DiscoveredPage>,
    /// Clustered issues appearing across 2 or more investigated pages.
    pub systemic_issues: Vec<SystemicIssue>,
    /// Whether the crawl terminated early due to [`CrawlBudget`].
    pub budget_exhausted: bool,
}

/// Extracts normalised, deduplicated, same-origin [`AuditTarget`] links from `obs`.
#[must_use]
pub fn discover_same_origin_links(
    base: &AuditTarget,
    obs: &DocumentObservations,
    policy: TargetPolicy,
) -> Vec<AuditTarget> {
    let Ok(base_url) = Url::parse(base.as_str()) else {
        return Vec::new();
    };
    let base_origin = Origin::from_target(base);
    let mut seen = HashSet::new();
    seen.insert(base.as_str().to_owned());

    let mut out = Vec::new();
    for raw_href in &obs.link_hrefs {
        let lower = raw_href.to_ascii_lowercase();
        if lower.starts_with('#')
            || lower.starts_with("mailto:")
            || lower.starts_with("tel:")
            || lower.starts_with("javascript:")
        {
            continue;
        }
        let Ok(mut resolved) = base_url.join(raw_href) else {
            continue;
        };
        resolved.set_fragment(None);
        let candidate = resolved.as_str().to_owned();
        let Ok(target) = AuditTarget::parse(&candidate, policy) else {
            continue;
        };
        if Origin::from_target(&target) != base_origin {
            continue;
        }
        if !seen.insert(target.as_str().to_owned()) {
            continue;
        }
        out.push(target);
    }
    out
}

/// Extracts and normalises same-origin URLs from an XML sitemap `<loc>` list.
#[must_use]
pub fn parse_sitemap_urls(xml: &str, base: &AuditTarget, policy: TargetPolicy) -> Vec<AuditTarget> {
    let base_origin = Origin::from_target(base);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<loc>") {
        let after = &rest[start + 5..];
        let Some(end) = after.find("</loc>") else {
            break;
        };
        let raw = after[..end].trim();
        if let Ok(target) = AuditTarget::parse(raw, policy)
            && Origin::from_target(&target) == base_origin
            && seen.insert(target.as_str().to_owned())
        {
            out.push(target);
        }
        rest = &after[end + 6..];
    }
    out
}

/// Orders discovered URLs so journey-critical pages are sampled ahead of legal/boilerplate pages.
#[must_use]
pub fn prioritise_representative_urls(mut urls: Vec<AuditTarget>) -> Vec<AuditTarget> {
    urls.sort_by_key(|u| {
        let p = Url::parse(u.as_str())
            .map(|parsed| parsed.path().to_ascii_lowercase())
            .unwrap_or_default();
        if p == "/" || p.is_empty() {
            0
        } else if p.contains("checkout")
            || p.contains("cart")
            || p.contains("product")
            || p.contains("pricing")
            || p.contains("login")
        {
            1
        } else if p.contains("privacy")
            || p.contains("terms")
            || p.contains("legal")
            || p.contains("imprint")
        {
            3
        } else {
            2
        }
    });
    urls
}

/// Classifies a page from its URL path and [`DocumentObservations`].
#[must_use]
pub fn classify_page(url: &AuditTarget, obs: &DocumentObservations) -> PageType {
    let path = Url::parse(url.as_str())
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();

    if path == "/" || path.is_empty() {
        return PageType::Homepage;
    }
    if path.contains("login") || path.contains("signin") || path.contains("auth") {
        return PageType::Auth;
    }
    if path.contains("privacy")
        || path.contains("terms")
        || path.contains("legal")
        || path.contains("imprint")
    {
        return PageType::Legal;
    }
    if path.contains("contact") {
        return PageType::Contact;
    }
    if path.contains("help") || path.contains("support") || path.contains("faq") {
        return PageType::Support;
    }
    if !obs.form_controls.is_empty() {
        return PageType::Form;
    }
    if obs.visible_word_count >= 250 {
        return PageType::Article;
    }
    if obs.link_hrefs.len() >= 15 {
        return PageType::Listing;
    }
    PageType::Unknown
}

/// Clusters findings recurring across 2 or more pages into [`SystemicIssue`]s.
#[must_use]
pub fn cluster_systemic_issues(
    page_reports: &[(AuditTarget, PageType, AuditReport)],
) -> Vec<SystemicIssue> {
    let mut by_rule: BTreeMap<String, Vec<(&str, PageType)>> = BTreeMap::new();
    for (target, page_type, report) in page_reports {
        let mut seen_rules_on_page = HashSet::new();
        for analyser in &report.analysers {
            for finding in &analyser.findings {
                if seen_rules_on_page.insert(finding.rule_id.0.as_str()) {
                    by_rule
                        .entry(finding.rule_id.0.clone())
                        .or_default()
                        .push((target.as_str(), *page_type));
                }
            }
        }
    }

    let mut clusters = Vec::new();
    for (rule_id, occurrences) in by_rule {
        if occurrences.len() < 2 {
            continue;
        }
        let affected_urls: Vec<String> = occurrences
            .iter()
            .map(|(url, _)| (*url).to_owned())
            .collect();
        let mut affected_page_types: Vec<PageType> =
            occurrences.iter().map(|(_, pt)| *pt).collect();
        affected_page_types.sort();
        affected_page_types.dedup();

        let count = affected_urls.len();
        let is_config_rule = rule_id.starts_with("sec.") || rule_id.starts_with("netz.");
        let classification = if is_config_rule {
            SystemicClassification::SuspectedCommonConfiguration
        } else if affected_page_types.len() >= 2 {
            SystemicClassification::SuspectedSharedTemplate
        } else {
            SystemicClassification::RepeatedRuleOccurrence
        };
        clusters.push(SystemicIssue {
            id: format!("SYS-{}", clusters.len() + 1),
            rule_id: RuleId(rule_id.clone()),
            affected_urls,
            affected_page_types,
            classification,
            summary: format!(
                "Rule `{rule_id}` recurred across {count} distinct pages ({classification:?})."
            ),
            recurrence_confidence: if count >= 3 {
                Confidence::High
            } else {
                Confidence::Medium
            },
            // Recurrence across pages does not prove a single internal root cause.
            shared_cause_confidence: if is_config_rule {
                Confidence::Medium
            } else {
                Confidence::Low
            },
        });
    }
    clusters
}

/// Performs a bounded same-origin BFS crawl starting from `seed`.
pub async fn crawl_and_cluster(
    seed: AuditTarget,
    crawl_budget: CrawlBudget,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
) -> CrawlSummary {
    let started = Instant::now();
    let mut queue: VecDeque<(AuditTarget, usize)> = VecDeque::new();
    let mut queued_urls: HashSet<String> = HashSet::new();
    queued_urls.insert(seed.as_str().to_owned());
    queue.push_back((seed.clone(), 0));

    if crawl_budget.max_depth > 0 && crawl_budget.max_pages > 1 {
        for u in seed_sitemap_urls(&seed, exec_budget, policy).await {
            if queued_urls.insert(u.as_str().to_owned()) {
                queue.push_back((u, 1));
            }
        }
    }

    let mut pages = Vec::new();
    let mut page_reports = Vec::new();
    let mut investigated_count = 0usize;
    let mut budget_exhausted = false;

    while let Some((target, depth)) = queue.pop_front() {
        let remaining = crawl_budget.max_duration.saturating_sub(started.elapsed());
        if remaining.is_zero() || investigated_count >= crawl_budget.max_pages {
            budget_exhausted = true;
            pages.push(DiscoveredPage {
                url: target,
                page_type: PageType::Unknown,
                depth,
                status: PageCrawlStatus::SkippedBudget,
            });
            continue;
        }

        let per_page_budget = ExecutionBudget {
            audit_timeout: exec_budget.audit_timeout.min(remaining),
            http_timeout: exec_budget.http_timeout.min(remaining),
            ..exec_budget
        };
        let snap = collection::collect_http(&target, &per_page_budget, policy).await;
        investigated_count += 1;

        let (status, page_type, discovered) = match &snap.http {
            CollectorOutcome::Captured { data } => {
                let obs = DocumentObservations::from_html(&data.body_text);
                let pt = classify_page(&target, &obs);
                let links = if depth < crawl_budget.max_depth {
                    prioritise_representative_urls(discover_same_origin_links(
                        &target, &obs, policy,
                    ))
                } else {
                    Vec::new()
                };
                (PageCrawlStatus::Investigated, pt, links)
            }
            CollectorOutcome::Partial { data, .. } => {
                let obs = DocumentObservations::from_html(&data.body_text);
                (
                    PageCrawlStatus::PartiallyInvestigated,
                    classify_page(&target, &obs),
                    Vec::new(),
                )
            }
            CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => {
                (PageCrawlStatus::Unreachable, PageType::Unknown, Vec::new())
            }
        };

        for next in discovered {
            if queued_urls.insert(next.as_str().to_owned()) {
                queue.push_back((next, depth + 1));
            }
        }

        let report = analysis::run_all(&snap);
        if matches!(
            status,
            PageCrawlStatus::Investigated | PageCrawlStatus::PartiallyInvestigated
        ) {
            page_reports.push((target.clone(), page_type, report));
        }

        pages.push(DiscoveredPage {
            url: target,
            page_type,
            depth,
            status,
        });
    }

    let systemic_issues = cluster_systemic_issues(&page_reports);
    CrawlSummary {
        seed,
        pages,
        systemic_issues,
        budget_exhausted,
    }
}

async fn seed_sitemap_urls(
    seed: &AuditTarget,
    exec_budget: ExecutionBudget,
    policy: TargetPolicy,
) -> Vec<AuditTarget> {
    let Ok(seed_url) = Url::parse(seed.as_str()) else {
        return Vec::new();
    };
    let Ok(sm_url) = seed_url.join("/sitemap.xml") else {
        return Vec::new();
    };
    let Ok(sm_target) = AuditTarget::parse(sm_url.as_str(), policy) else {
        return Vec::new();
    };
    if Origin::from_target(&sm_target) != Origin::from_target(seed) {
        return Vec::new();
    }
    let sm_budget = ExecutionBudget {
        audit_timeout: exec_budget.audit_timeout.min(Duration::from_secs(5)),
        http_timeout: exec_budget.http_timeout.min(Duration::from_secs(5)),
        ..exec_budget
    };
    let sm_snap = collection::collect_http(&sm_target, &sm_budget, policy).await;
    if let CollectorOutcome::Captured { data } = sm_snap.http
        && data.status_code == 200
    {
        return prioritise_representative_urls(parse_sitemap_urls(&data.body_text, seed, policy));
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{EvidenceSnapshot, HttpEvidence, HttpHeader, Measurement, MeasurementUnit};

    #[test]
    fn discovers_same_origin_links_and_filters_external_and_fragments() {
        let base = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let html = r##"
            <html><body>
                <a href="/about#team">About</a>
                <a href="/about">About dup</a>
                <a href="https://example.org/contact">Contact</a>
                <a href="https://other.example.com/offsite">Offsite</a>
                <a href="mailto:info@example.org">Email</a>
                <a href="#top">Top</a>
            </body></html>
        "##;
        let obs = DocumentObservations::from_html(html);
        let links = discover_same_origin_links(&base, &obs, TargetPolicy::PublicOnly);
        let strs: Vec<&str> = links.iter().map(AuditTarget::as_str).collect();
        assert_eq!(
            strs,
            vec!["https://example.org/about", "https://example.org/contact"]
        );
    }

    #[test]
    fn rejects_cross_scheme_and_cross_port_scope_escapes() {
        let base = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let html = r#"
            <html><body>
                <a href="http://example.org/downgrade">HTTP downgrade</a>
                <a href="https://example.org:8443/admin">Alternate port</a>
                <a href="https://example.org/valid">Valid same origin</a>
            </body></html>
        "#;
        let obs = DocumentObservations::from_html(html);
        let links = discover_same_origin_links(&base, &obs, TargetPolicy::PublicOnly);
        let strs: Vec<&str> = links.iter().map(AuditTarget::as_str).collect();
        assert_eq!(strs, vec!["https://example.org/valid"]);
    }

    #[test]
    fn classifies_representative_page_types() {
        let home = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let login =
            AuditTarget::parse("https://example.org/login", TargetPolicy::PublicOnly).unwrap();
        let privacy =
            AuditTarget::parse("https://example.org/privacy", TargetPolicy::PublicOnly).unwrap();
        let empty_obs = DocumentObservations::from_html("<html><body></body></html>");

        assert_eq!(classify_page(&home, &empty_obs), PageType::Homepage);
        assert_eq!(classify_page(&login, &empty_obs), PageType::Auth);
        assert_eq!(classify_page(&privacy, &empty_obs), PageType::Legal);
    }

    #[test]
    fn clusters_recurring_findings_across_pages_into_systemic_issues() {
        let make_page_report = |url: &str| {
            let target = AuditTarget::parse(url, TargetPolicy::PublicOnly).unwrap();
            let html = "<html><body><h1>Hi</h1><img src='/logo.png'></body></html>";
            let snap = EvidenceSnapshot {
                target: target.clone(),
                captured_at_unix_secs: 0,
                http: CollectorOutcome::Captured {
                    data: HttpEvidence {
                        final_url: url.to_owned(),
                        status_code: 200,
                        redirect_chain: Vec::new(),
                        headers: vec![HttpHeader {
                            name: "content-type".to_owned(),
                            value: "text/html".to_owned(),
                        }],
                        elapsed_ms: Measurement::Measured {
                            value: 15,
                            unit: MeasurementUnit::Milliseconds,
                        },
                        body_bytes: html.len(),
                        body_truncated: false,
                        body_text: html.to_owned(),
                    },
                },
                tls: CollectorOutcome::default(),
                browser: CollectorOutcome::default(),
                lighthouse: CollectorOutcome::default(),
                axe: CollectorOutcome::default(),
            };
            (target, PageType::Unknown, analysis::run_all(&snap))
        };

        let reports = vec![
            make_page_report("http://example.org/"),
            make_page_report("http://example.org/about"),
            make_page_report("http://example.org/pricing"),
        ];
        let clusters = cluster_systemic_issues(&reports);
        let alt_cluster = clusters
            .iter()
            .find(|c| c.rule_id.0 == "a11y.images.alt")
            .unwrap();
        assert_eq!(alt_cluster.affected_urls.len(), 3);
        assert_eq!(alt_cluster.recurrence_confidence, Confidence::High);
        assert_eq!(alt_cluster.shared_cause_confidence, Confidence::Low);
    }

    #[test]
    fn parses_sitemap_and_prioritises_journey_pages_before_legal() {
        let base = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let xml = r"
            <urlset>
                <url><loc>https://example.org/privacy</loc></url>
                <url><loc>https://other.example.com/offsite</loc></url>
                <url><loc>https://example.org/checkout</loc></url>
                <url><loc>https://example.org/blog</loc></url>
            </urlset>
        ";
        let parsed = parse_sitemap_urls(xml, &base, TargetPolicy::PublicOnly);
        assert_eq!(parsed.len(), 3);
        let ordered = prioritise_representative_urls(parsed);
        let paths: Vec<&str> = ordered.iter().map(AuditTarget::as_str).collect();
        assert_eq!(
            paths,
            vec![
                "https://example.org/checkout",
                "https://example.org/blog",
                "https://example.org/privacy",
            ]
        );
    }
}
