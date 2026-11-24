//! Stratified, memory-aware sampling plans with explicit selection rationale.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::discovery::{PageType, detect_locale_from_url};
use crate::domain::AuditTarget;
use crate::patrol::memory::ApplicationMemory;

/// Explicit justification for why a URL was included in a [`SamplingPlan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    /// Primary entry URL of the application.
    InitialCoverage,
    /// Journey-critical path (e.g. checkout, cart, login, pricing, product).
    CriticalJourney,
    /// Representative of a structural template or general page pool.
    TemplateRepresentative,
    /// Representative of a distinct language or market variant.
    LocaleRepresentative,
    /// Page that exhibited actionable findings in a previous patrol.
    PreviouslyDefective,
    /// Newly discovered URL absent from prior application memory.
    RecentlyChanged,
    /// Page whose prior observation exceeded the freshness TTL.
    HistoricalCoverageGap,
    /// Healthy page sampled on a rotating basis to prevent blind spots.
    RotatingExploration,
}

/// Diagnostic depth assigned to a sampled page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticDepth {
    /// Broad low-cost Level 1 HTTP + static HTML/header diagnostics.
    Level1Deterministic,
    /// Expensive Level 2 rendered browser/Lighthouse/axe diagnostics.
    Level2Deep,
}

/// Single page selected for inspection during a patrol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleSelection {
    /// Normalised target URL.
    pub url: AuditTarget,
    /// Why this page was chosen.
    pub reason: SelectionReason,
    /// Assigned diagnostic depth.
    pub depth: DiagnosticDepth,
    /// Locale tag inferred from URL path if present.
    pub locale: Option<String>,
    /// Prior page type if remembered.
    pub page_type: Option<PageType>,
}

/// Inspectable sampling plan produced before patrol execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingPlan {
    /// Pages selected for active inspection in priority order.
    pub selections: Vec<SampleSelection>,
    /// Unchanged, fresh, previously healthy URLs whose observations can be reused.
    pub reused_urls: Vec<String>,
    /// Total candidate URLs considered.
    pub total_discovered: usize,
}

fn is_journey_critical(target: &AuditTarget) -> bool {
    let p = Url::parse(target.as_str())
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    p.contains("checkout")
        || p.contains("cart")
        || p.contains("product")
        || p.contains("pricing")
        || p.contains("login")
}

/// Builds a stratified [`SamplingPlan`] from `discovered` URLs and optional `memory`.
///
/// On a first encounter (`memory.is_none()`), prioritises the seed URL, distinct
/// locale entry points, journey-critical paths, and template representatives.
/// On subsequent patrols, prioritises previously defective pages, newly discovered
/// URLs, stale coverage gaps, and a rotating healthy control sample while marking
/// unchanged fresh healthy pages in `reused_urls`.
#[must_use]
pub fn build_sampling_plan(
    seed: &AuditTarget,
    discovered: &[AuditTarget],
    memory: Option<&ApplicationMemory>,
    max_pages: usize,
    max_deep: usize,
    now_unix_secs: u64,
    freshness_ttl_secs: u64,
) -> SamplingPlan {
    let mut candidates: Vec<AuditTarget> = Vec::with_capacity(discovered.len() + 1);
    let mut seen_urls = HashSet::new();
    if seen_urls.insert(seed.as_str().to_owned()) {
        candidates.push(seed.clone());
    }
    for url in discovered {
        if seen_urls.insert(url.as_str().to_owned()) {
            candidates.push(url.clone());
        }
    }

    let total_discovered = candidates.len();
    let mut selections: Vec<SampleSelection> = Vec::new();
    let mut selected_set: HashSet<String> = HashSet::new();
    let mut reused_urls: Vec<String> = Vec::new();
    let mut deep_used = 0usize;

    match memory {
        None => plan_initial_patrol(
            seed,
            &candidates,
            max_pages,
            max_deep,
            &mut deep_used,
            &mut selected_set,
            &mut selections,
        ),
        Some(mem) => plan_returning_patrol(
            seed,
            &candidates,
            mem,
            max_pages,
            max_deep,
            now_unix_secs,
            freshness_ttl_secs,
            &mut deep_used,
            &mut selected_set,
            &mut selections,
            &mut reused_urls,
        ),
    }

    SamplingPlan {
        selections,
        reused_urls,
        total_discovered,
    }
}

fn plan_initial_patrol(
    seed: &AuditTarget,
    candidates: &[AuditTarget],
    max_pages: usize,
    max_deep: usize,
    deep_used: &mut usize,
    selected_set: &mut HashSet<String>,
    selections: &mut Vec<SampleSelection>,
) {
    try_push_selection(
        seed,
        SelectionReason::InitialCoverage,
        true,
        Some(PageType::Homepage),
        max_pages,
        max_deep,
        deep_used,
        selected_set,
        selections,
    );
    let mut seen_locales = HashSet::new();
    for url in candidates {
        if let Some(loc) = detect_locale_from_url(url)
            && seen_locales.insert(loc.tag)
        {
            try_push_selection(
                url,
                SelectionReason::LocaleRepresentative,
                true,
                None,
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }
    for url in candidates {
        if is_journey_critical(url) {
            try_push_selection(
                url,
                SelectionReason::CriticalJourney,
                true,
                None,
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }
    for url in candidates {
        try_push_selection(
            url,
            SelectionReason::TemplateRepresentative,
            false,
            None,
            max_pages,
            max_deep,
            deep_used,
            selected_set,
            selections,
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn plan_returning_patrol(
    seed: &AuditTarget,
    candidates: &[AuditTarget],
    mem: &ApplicationMemory,
    max_pages: usize,
    max_deep: usize,
    now_unix_secs: u64,
    freshness_ttl_secs: u64,
    deep_used: &mut usize,
    selected_set: &mut HashSet<String>,
    selections: &mut Vec<SampleSelection>,
    reused_urls: &mut Vec<String>,
) {
    let seed_rec = mem.page_records.get(seed.as_str());
    let seed_defective = seed_rec.is_some_and(|r| r.open_finding_count > 0);
    try_push_selection(
        seed,
        if seed_defective {
            SelectionReason::PreviouslyDefective
        } else {
            SelectionReason::InitialCoverage
        },
        seed_defective,
        seed_rec.map(|r| r.page_type),
        max_pages,
        max_deep,
        deep_used,
        selected_set,
        selections,
    );

    for url in candidates {
        if let Some(rec) = mem.page_records.get(url.as_str())
            && rec.open_finding_count > 0
        {
            try_push_selection(
                url,
                SelectionReason::PreviouslyDefective,
                true,
                Some(rec.page_type),
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }

    for url in candidates {
        if !mem.page_records.contains_key(url.as_str()) {
            try_push_selection(
                url,
                SelectionReason::RecentlyChanged,
                true,
                None,
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }

    for url in candidates {
        if let Some(rec) = mem.page_records.get(url.as_str())
            && now_unix_secs.saturating_sub(rec.last_inspected_unix_secs) >= freshness_ttl_secs
        {
            try_push_selection(
                url,
                SelectionReason::HistoricalCoverageGap,
                false,
                Some(rec.page_type),
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }

    // Ensure at least one representative per remembered template family is covered.
    let mut covered_templates: HashSet<&str> = selections
        .iter()
        .filter_map(|s| {
            mem.page_records
                .get(s.url.as_str())
                .and_then(|r| r.template_fingerprint.as_deref())
        })
        .collect();
    for url in candidates {
        if let Some(rec) = mem.page_records.get(url.as_str())
            && let Some(tpl) = rec.template_fingerprint.as_deref()
            && covered_templates.insert(tpl)
        {
            try_push_selection(
                url,
                SelectionReason::TemplateRepresentative,
                false,
                Some(rec.page_type),
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }

    // Sort remaining fresh healthy candidates oldest-inspected first so rotating
    // exploration genuinely cycles across all healthy pages over consecutive patrols.
    let mut healthy_pool: Vec<(&AuditTarget, u64, PageType)> = candidates
        .iter()
        .filter(|url| !selected_set.contains(url.as_str()))
        .filter_map(|url| {
            mem.page_records
                .get(url.as_str())
                .map(|rec| (url, rec.last_inspected_unix_secs, rec.page_type))
        })
        .collect();
    healthy_pool.sort_by_key(|(_, ts, _)| *ts);

    let mut rotated = false;
    for (url, _, page_type) in healthy_pool {
        if rotated {
            reused_urls.push(url.as_str().to_owned());
        } else {
            rotated = true;
            try_push_selection(
                url,
                SelectionReason::RotatingExploration,
                false,
                Some(page_type),
                max_pages,
                max_deep,
                deep_used,
                selected_set,
                selections,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn try_push_selection(
    url: &AuditTarget,
    reason: SelectionReason,
    want_deep: bool,
    page_type: Option<PageType>,
    max_pages: usize,
    max_deep: usize,
    deep_used: &mut usize,
    selected_set: &mut HashSet<String>,
    selections: &mut Vec<SampleSelection>,
) {
    if selections.len() >= max_pages || !selected_set.insert(url.as_str().to_owned()) {
        return;
    }
    let depth = if want_deep && *deep_used < max_deep {
        *deep_used += 1;
        DiagnosticDepth::Level2Deep
    } else {
        DiagnosticDepth::Level1Deterministic
    };
    let locale = detect_locale_from_url(url).map(|l| l.tag);
    selections.push(SampleSelection {
        url: url.clone(),
        reason,
        depth,
        locale,
        page_type,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TargetPolicy;
    use crate::patrol::memory::{EvidenceFreshness, RememberedPage};

    #[test]
    fn subsequent_patrol_reuses_fresh_healthy_pages_and_prioritises_defective() {
        let seed = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let en = AuditTarget::parse("https://example.org/en-gb/about", TargetPolicy::PublicOnly)
            .unwrap();
        let de =
            AuditTarget::parse("https://example.org/de/kontakt", TargetPolicy::PublicOnly).unwrap();
        let checkout =
            AuditTarget::parse("https://example.org/checkout", TargetPolicy::PublicOnly).unwrap();
        let discovered = vec![en.clone(), de.clone(), checkout.clone()];

        let first = build_sampling_plan(&seed, &discovered, None, 10, 2, 1_000, 3_600);
        assert_eq!(first.selections.len(), 4);
        assert_eq!(first.reused_urls, Vec::<String>::new());

        let mut mem = ApplicationMemory::new(&seed, 1_000);
        mem.patrol_count = 1;
        for (url, open) in [
            (seed.as_str(), 0usize),
            (en.as_str(), 0usize),
            (de.as_str(), 0usize),
            (checkout.as_str(), 2usize),
        ] {
            mem.page_records.insert(
                url.to_owned(),
                RememberedPage {
                    url: url.to_owned(),
                    locale: None,
                    page_type: PageType::Unknown,
                    template_fingerprint: None,
                    content_hash: None,
                    etag: None,
                    last_modified: None,
                    latest_report: None,
                    last_inspected_unix_secs: 1_000,
                    open_finding_count: open,
                    healthy_streak: usize::from(open == 0),
                    freshness: EvidenceFreshness::CurrentlyVerified,
                },
            );
        }

        let second = build_sampling_plan(&seed, &discovered, Some(&mem), 10, 2, 1_100, 3_600);
        assert!(
            second
                .selections
                .iter()
                .any(|s| s.url == checkout && s.reason == SelectionReason::PreviouslyDefective)
        );
        assert!(
            second
                .selections
                .iter()
                .any(|s| s.reason == SelectionReason::RotatingExploration)
        );
        assert_eq!(second.reused_urls.len(), 1);
    }

    #[test]
    fn rotating_exploration_selects_oldest_inspected_healthy_page() {
        let seed = AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap();
        let newer =
            AuditTarget::parse("https://example.org/newer", TargetPolicy::PublicOnly).unwrap();
        let older =
            AuditTarget::parse("https://example.org/older", TargetPolicy::PublicOnly).unwrap();
        let discovered = vec![newer.clone(), older.clone()];

        let mut mem = ApplicationMemory::new(&seed, 2_000);
        mem.patrol_count = 1;
        for (url, ts) in [
            (seed.as_str(), 2_000_u64),
            (newer.as_str(), 1_900_u64),
            (older.as_str(), 1_500_u64),
        ] {
            mem.page_records.insert(
                url.to_owned(),
                RememberedPage {
                    url: url.to_owned(),
                    locale: None,
                    page_type: PageType::Unknown,
                    template_fingerprint: None,
                    content_hash: None,
                    etag: None,
                    last_modified: None,
                    latest_report: None,
                    last_inspected_unix_secs: ts,
                    open_finding_count: 0,
                    healthy_streak: 1,
                    freshness: EvidenceFreshness::CurrentlyVerified,
                },
            );
        }

        let plan = build_sampling_plan(&seed, &discovered, Some(&mem), 10, 2, 2_100, 3_600);
        let rot = plan
            .selections
            .iter()
            .find(|s| s.reason == SelectionReason::RotatingExploration)
            .unwrap();
        assert_eq!(rot.url, older);
        assert_eq!(plan.reused_urls, vec![newer.as_str()]);
    }
}
