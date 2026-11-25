//! Bounded investigation queries over previously collected browser events.

use serde::Serialize;

use crate::domain::{
    BrowserTimelineEvent, CollectorOutcome, EvidenceRef, EvidenceSnapshot, EvidenceSource,
    TimelineEnd,
};

/// One page of browser timeline evidence from a captured snapshot.
#[derive(Debug, Serialize)]
pub struct BrowserTimelinePage<'a> {
    /// Source events in receive order.
    pub events: &'a [BrowserTimelineEvent],
    /// Offset of the next retained page.
    pub next_offset: Option<usize>,
    /// Whether collection discarded later events.
    pub truncated: bool,
    /// Why observation ended.
    pub end: TimelineEnd,
    /// Whether the enclosing browser collection was partial.
    pub browser_partial: bool,
}

/// Reads up to 16 events without starting a browser.
///
/// Returns `None` when timeline evidence is unavailable.
#[must_use]
pub fn query_browser_timeline(
    snapshot: &EvidenceSnapshot,
    offset: usize,
) -> Option<BrowserTimelinePage<'_>> {
    let (data, browser_partial) = match &snapshot.browser {
        CollectorOutcome::Captured { data } => (data, false),
        CollectorOutcome::Partial { data, .. } => (data, true),
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => return None,
    };
    let timeline = data.timeline.as_ref()?;
    let start = offset.min(timeline.events.len());
    let end = start.saturating_add(16).min(timeline.events.len());
    Some(BrowserTimelinePage {
        events: &timeline.events[start..end],
        next_offset: (end < timeline.events.len()).then_some(end),
        truncated: timeline.truncated,
        end: timeline.end,
        browser_partial,
    })
}

pub(super) fn timeline_context(snapshot: Option<&EvidenceSnapshot>) -> String {
    snapshot
        .and_then(|snapshot| query_browser_timeline(snapshot, 0))
        .and_then(|page| serde_json::to_string(&page).ok())
        .map_or_else(
            || "browser timeline unavailable".to_owned(),
            |json| json.replace('<', r"\u003c"),
        )
}

pub(super) fn cited_event_refs(snapshot: &EvidenceSnapshot, sequences: &[u32]) -> Vec<EvidenceRef> {
    query_browser_timeline(snapshot, 0)
        .into_iter()
        .flat_map(|page| page.events)
        .filter(|event| sequences.contains(&event.sequence))
        .map(|event| {
            EvidenceRef::new(
                EvidenceSource::BrowserRuntime,
                format!("timeline-event={}", event.sequence),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AuditTarget, BrowserEventDetail, BrowserEvidence, BrowserTimeline, TargetPolicy,
    };

    #[test]
    fn queries_retained_events_and_validates_citations_against_the_supplied_page() {
        let mut snapshot = EvidenceSnapshot {
            target: AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly).unwrap(),
            captured_at_unix_secs: 0,
            http: CollectorOutcome::default(),
            tls: CollectorOutcome::default(),
            browser: CollectorOutcome::Captured {
                data: BrowserEvidence::default(),
            },
            lighthouse: CollectorOutcome::default(),
            axe: CollectorOutcome::default(),
        };
        assert!(query_browser_timeline(&snapshot, 0).is_none());
        let mut timeline = BrowserTimeline {
            events: Vec::new(),
            truncated: false,
            end: TimelineEnd::ObservationEnded,
        };
        let CollectorOutcome::Captured { data } = &mut snapshot.browser else {
            panic!("expected captured browser evidence");
        };
        data.timeline = Some(timeline.clone());
        assert_eq!(
            query_browser_timeline(&snapshot, 0).unwrap().events.len(),
            0
        );

        timeline.events = (1..=17)
            .map(|sequence| BrowserTimelineEvent {
                sequence,
                time: None,
                request: None,
                frame: None,
                loader: None,
                detail: BrowserEventDetail::NetworkFailure,
            })
            .collect();
        snapshot.browser = CollectorOutcome::Partial {
            data: BrowserEvidence {
                timeline: Some(timeline),
                ..BrowserEvidence::default()
            },
            warnings: vec!["fixture warning".to_owned()],
        };
        let page = query_browser_timeline(&snapshot, 0).unwrap();
        assert!(page.browser_partial);
        assert_eq!(page.next_offset, Some(16));
        assert_eq!(
            query_browser_timeline(&snapshot, 16).unwrap().events[0].sequence,
            17
        );
        assert_eq!(cited_event_refs(&snapshot, &[1, 1, 17, 100]).len(), 1);
    }
}
