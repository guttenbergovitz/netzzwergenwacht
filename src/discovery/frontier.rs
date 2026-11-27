//! Bounded, deduplicating crawl frontier.
//!
//! The frontier decides which URL is fetched next. It is deliberately separate from the
//! acquisition workers so that ordering, deduplication and queue bounds can be tested without
//! a network. Ordering is priority first (see [`DiscoverySource`]) and discovery order second,
//! which keeps crawl output deterministic even when acquisitions complete out of order.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::domain::AuditTarget;

/// Where a URL was first discovered.
///
/// The source drives crawl priority and later provenance reporting. A URL discovered twice keeps
/// its first source; later discoveries are counted as duplicates rather than merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// The operator-supplied seed URL.
    Seed,
    /// A sitemap or sitemap index declared a same-origin URL.
    Sitemap,
    /// A `robots.txt` `Sitemap:` directive.
    RobotsSitemap,
    /// An internal HTML link.
    Link,
    /// A canonical declaration.
    Canonical,
    /// An `hreflang` alternative.
    Hreflang,
    /// A pagination relationship.
    Pagination,
    /// A URL retained from a previous run.
    PreviousRun,
}

impl DiscoverySource {
    /// Lower values are fetched earlier.
    ///
    /// Seeds and sitemap members outrank links because they define the application surface.
    /// Canonical and hreflang targets rank below ordinary links because they are usually
    /// already reachable by a link, and following them first would duplicate work.
    #[must_use]
    pub const fn priority(self) -> u8 {
        match self {
            Self::Seed => 0,
            Self::Sitemap | Self::RobotsSitemap => 1,
            Self::Link => 2,
            Self::Hreflang | Self::Pagination | Self::Canonical => 3,
            Self::PreviousRun => 4,
        }
    }
}

/// A URL waiting to be acquired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierEntry {
    /// Normalised target to acquire.
    pub target: AuditTarget,
    /// Link-following depth from the seed (`0` for the seed itself).
    pub depth: usize,
    /// First discovery source for this URL.
    pub source: DiscoverySource,
}

/// Result of offering a URL to the frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// The URL was accepted and queued.
    Enqueued,
    /// The URL was already queued or already acquired.
    Duplicate,
    /// The URL was rejected because the bounded queue is full.
    QueueFull,
}

#[derive(Debug)]
struct Queued {
    priority: u8,
    sequence: u64,
    entry: FrontierEntry,
}

impl PartialEq for Queued {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl Eq for Queued {}

impl PartialOrd for Queued {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Queued {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so that `BinaryHeap` (a max-heap) yields the lowest priority value first,
        // and FIFO within one priority value.
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

/// Deduplicating, priority-ordered, bounded crawl queue.
#[derive(Debug)]
pub struct CrawlFrontier {
    heap: BinaryHeap<Queued>,
    seen: HashSet<String>,
    max_queued: usize,
    sequence: u64,
    duplicates: usize,
    rejected_full: usize,
}

impl CrawlFrontier {
    /// Creates a frontier that never holds more than `max_queued` entries.
    ///
    /// A zero bound is raised to one so that a misconfiguration degrades to a slow crawl rather
    /// than a silent empty one.
    #[must_use]
    pub fn new(max_queued: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            seen: HashSet::new(),
            max_queued: max_queued.max(1),
            sequence: 0,
            duplicates: 0,
            rejected_full: 0,
        }
    }

    /// Offers `target` to the frontier.
    ///
    /// A URL is identified by its normalised string form. An offer is idempotent: the second
    /// offer of the same URL is counted as a duplicate and does not queue.
    pub fn enqueue(
        &mut self,
        target: AuditTarget,
        depth: usize,
        source: DiscoverySource,
    ) -> EnqueueOutcome {
        let key = target.as_str().to_owned();
        if self.seen.contains(&key) {
            self.duplicates += 1;
            return EnqueueOutcome::Duplicate;
        }
        if self.heap.len() >= self.max_queued {
            self.rejected_full += 1;
            return EnqueueOutcome::QueueFull;
        }
        self.seen.insert(key);
        self.sequence = self.sequence.saturating_add(1);
        self.heap.push(Queued {
            priority: source.priority(),
            sequence: self.sequence,
            entry: FrontierEntry {
                target,
                depth,
                source,
            },
        });
        EnqueueOutcome::Enqueued
    }

    /// Records a URL as observed without queueing it, so a later offer is treated as a duplicate.
    ///
    /// Used for targets rejected by scope or policy: they must not be fetched, and they must not
    /// be re-evaluated on every page that links to them.
    pub fn mark_seen(&mut self, target: &AuditTarget) {
        self.seen.insert(target.as_str().to_owned());
    }

    /// Removes and returns the next entry, or `None` when the frontier is empty.
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        self.heap.pop().map(|queued| queued.entry)
    }

    /// Number of URLs waiting to be acquired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }

    /// Whether nothing is waiting to be acquired.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Number of distinct URLs the frontier has ever accepted.
    #[must_use]
    pub fn accepted_count(&self) -> usize {
        self.seen.len()
    }

    /// Number of duplicate offers rejected.
    #[must_use]
    pub fn duplicate_count(&self) -> usize {
        self.duplicates
    }

    /// Number of offers rejected because the bounded queue was full.
    #[must_use]
    pub fn queue_full_count(&self) -> usize {
        self.rejected_full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::TargetPolicy;

    fn target(path: &str) -> AuditTarget {
        AuditTarget::parse(
            &format!("https://example.org{path}"),
            TargetPolicy::PublicOnly,
        )
        .unwrap()
    }

    #[test]
    fn duplicate_offers_are_recorded_once() {
        let mut frontier = CrawlFrontier::new(16);
        assert_eq!(
            frontier.enqueue(target("/a"), 1, DiscoverySource::Link),
            EnqueueOutcome::Enqueued
        );
        assert_eq!(
            frontier.enqueue(target("/a"), 2, DiscoverySource::Sitemap),
            EnqueueOutcome::Duplicate
        );
        assert_eq!(frontier.len(), 1);
        assert_eq!(frontier.duplicate_count(), 1);
        assert_eq!(frontier.accepted_count(), 1);
    }

    #[test]
    fn seeds_are_served_before_deeper_links() {
        let mut frontier = CrawlFrontier::new(16);
        frontier.enqueue(target("/deep"), 3, DiscoverySource::Link);
        frontier.enqueue(target("/map"), 1, DiscoverySource::Sitemap);
        frontier.enqueue(target("/"), 0, DiscoverySource::Seed);
        let order: Vec<&str> = std::iter::from_fn(|| frontier.pop())
            .map(|entry| entry.target.as_str().to_owned())
            .collect::<Vec<_>>()
            .into_iter()
            .map(|value| {
                if value.ends_with("example.org/") {
                    "/"
                } else {
                    "other"
                }
            })
            .collect();
        assert_eq!(order, vec!["/", "other", "other"]);
    }

    #[test]
    fn equal_priority_preserves_discovery_order() {
        let mut frontier = CrawlFrontier::new(16);
        for path in ["/a", "/b", "/c"] {
            frontier.enqueue(target(path), 1, DiscoverySource::Link);
        }
        let first = frontier.pop().map(|entry| entry.target.as_str().to_owned());
        assert_eq!(first.as_deref(), Some("https://example.org/a"));
    }

    #[test]
    fn bounded_queue_rejects_rather_than_grows() {
        let mut frontier = CrawlFrontier::new(2);
        assert_eq!(
            frontier.enqueue(target("/a"), 1, DiscoverySource::Link),
            EnqueueOutcome::Enqueued
        );
        assert_eq!(
            frontier.enqueue(target("/b"), 1, DiscoverySource::Link),
            EnqueueOutcome::Enqueued
        );
        assert_eq!(
            frontier.enqueue(target("/c"), 1, DiscoverySource::Link),
            EnqueueOutcome::QueueFull
        );
        assert_eq!(frontier.len(), 2);
        assert_eq!(frontier.queue_full_count(), 1);
        // A rejected URL is not marked seen, so a later offer can still be accepted.
        frontier.pop();
        assert_eq!(
            frontier.enqueue(target("/c"), 1, DiscoverySource::Link),
            EnqueueOutcome::Enqueued
        );
    }

    #[test]
    fn marked_targets_are_not_queued_later() {
        let mut frontier = CrawlFrontier::new(8);
        frontier.mark_seen(&target("/private"));
        assert_eq!(
            frontier.enqueue(target("/private"), 1, DiscoverySource::Link),
            EnqueueOutcome::Duplicate
        );
        assert!(frontier.is_empty());
    }
}
