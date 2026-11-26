//! Large-scale sampling evaluation (2,000 URLs, 8 locales, 12 template families).
//!
//! Verifies that `build_sampling_plan`:
//! 1. Covers all 8 locales on Patrol #1 without inspecting all 2,000 pages.
//! 2. Covers all 12 template families on Patrol #2, prioritises defective pages,
//!    and enforces anti-starvation so `PreviouslyDefective` pages never crowd out
//!    `RecentlyChanged` and `RotatingExploration`.

use std::collections::{BTreeSet, HashSet};

use netzzwergenwacht::discovery::PageType;
use netzzwergenwacht::domain::{AuditTarget, TargetPolicy};
use netzzwergenwacht::patrol::memory::{ApplicationMemory, EvidenceFreshness, RememberedPage};
use netzzwergenwacht::patrol::sampling::{SelectionReason, build_sampling_plan};

#[test]
fn sampling_scales_across_2000_urls_8_locales_and_12_templates_without_starvation() {
    let locales = [
        "en-gb", "en-us", "de-de", "fr-fr", "es-es", "it-it", "nl-nl", "pl-pl",
    ];
    let seed = AuditTarget::parse("https://shop.example.org/", TargetPolicy::PublicOnly).unwrap();

    let mut discovered = Vec::with_capacity(2_000);
    for (loc_idx, loc) in locales.iter().enumerate() {
        for i in 0..250 {
            let path = if i == 0 {
                format!("https://shop.example.org/{loc}/checkout")
            } else {
                format!("https://shop.example.org/{loc}/product-{loc_idx}-{i}")
            };
            discovered.push(AuditTarget::parse(&path, TargetPolicy::PublicOnly).unwrap());
        }
    }
    assert_eq!(discovered.len(), 2_000);

    // Patrol #1: first encounter with max_pages = 25 must cover all 8 locales.
    let p1 = build_sampling_plan(&seed, &discovered, None, 25, 4, 1_000, 3_600);
    assert_eq!(p1.selections.len(), 25);
    assert_eq!(p1.total_discovered, 2_001);
    let p1_locales: BTreeSet<&str> = p1
        .selections
        .iter()
        .filter_map(|s| s.locale.as_deref())
        .collect();
    assert_eq!(p1_locales.len(), 8);

    // Build institutional memory for 1,995 pages across 12 template families
    // with 12 defective pages (1 per template family) + 15 additional defective
    // pages (total 27 > max_pages = 25) to verify both anti-starvation AND full
    // coverage of all 12 distinct template families.
    let mut mem = ApplicationMemory::new(&seed, 1_000);
    mem.patrol_count = 1;
    for (idx, url) in discovered.iter().take(1_995).enumerate() {
        let tpl = format!("tpl-{:02}", idx % 12);
        let open_finding_count = usize::from(idx < 27);
        mem.page_records.insert(
            url.as_str().to_owned(),
            RememberedPage {
                url: url.as_str().to_owned(),
                locale: None,
                page_type: PageType::Listing,
                template_fingerprint: Some(tpl),
                content_hash: None,
                etag: None,
                last_modified: None,
                latest_report: None,
                last_inspected_unix_secs: 1_000 + (idx as u64 % 50),
                open_finding_count,
                healthy_streak: usize::from(open_finding_count == 0),
                freshness: EvidenceFreshness::CurrentlyVerified,
            },
        );
    }

    let p2 = build_sampling_plan(&seed, &discovered, Some(&mem), 25, 4, 1_100, 3_600);
    assert_eq!(p2.selections.len(), 25);

    // Known defects must NOT starve newly discovered URLs or rotating exploration.
    assert!(
        p2.selections
            .iter()
            .any(|s| s.reason == SelectionReason::RecentlyChanged)
    );
    assert!(
        p2.selections
            .iter()
            .any(|s| s.reason == SelectionReason::RotatingExploration)
    );
    let defect_count = p2
        .selections
        .iter()
        .filter(|s| s.reason == SelectionReason::PreviouslyDefective)
        .count();
    assert!(defect_count <= 20);

    // Distinct templates covered must include all 12 template families!
    let templates_covered: HashSet<&str> = p2
        .selections
        .iter()
        .filter_map(|s| {
            mem.page_records
                .get(s.url.as_str())
                .and_then(|r| r.template_fingerprint.as_deref())
        })
        .collect();
    assert_eq!(templates_covered.len(), 12);
    assert!(p2.reused_urls.len() > 1_900);
}
