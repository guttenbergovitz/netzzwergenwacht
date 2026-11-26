//! Contract tests for the offline Evidence Query Engine.
//!
//! These tests pin the honesty contract of `src/investigation/evidence_query.rs`:
//! an unavailable collector must never look like an empty result, pagination must
//! stay bounded, and raw untrusted page text must never reach prompt context.

use netzzwergenwacht::domain::{
    AuditTarget, BrowserEvidence, CollectorOutcome, EvidenceSnapshot, RenderedBlockKind,
    RenderedContentBlock, RenderedContentLimits, RenderedContentSegmentation,
    RenderedCssVisibility, RenderedTextFingerprint, TargetPolicy,
};
use netzzwergenwacht::investigation::{
    EvidenceQueryStatus, RenderedBlockFilter, cited_rendered_block_refs,
    query_browser_evidence_from_snapshot, query_rendered_content, rendered_content_context,
};

const SECRET_TEXT: &str = "untrusted prose must never reach prompts";

fn target() -> AuditTarget {
    AuditTarget::parse("https://example.org/", TargetPolicy::PublicOnly)
        .expect("parse example target")
}

fn snapshot_with_browser(browser: CollectorOutcome<BrowserEvidence>) -> EvidenceSnapshot {
    EvidenceSnapshot {
        target: target(),
        captured_at_unix_secs: 1_700_000_000,
        http: CollectorOutcome::Skipped {
            reason: "http not exercised by this test".to_owned(),
        },
        tls: CollectorOutcome::Skipped {
            reason: "tls not exercised by this test".to_owned(),
        },
        browser,
        lighthouse: CollectorOutcome::Skipped {
            reason: "lighthouse not exercised by this test".to_owned(),
        },
        axe: CollectorOutcome::Skipped {
            reason: "axe not exercised by this test".to_owned(),
        },
    }
}

fn block(node: u32) -> RenderedContentBlock {
    RenderedContentBlock {
        node,
        kind: RenderedBlockKind::Paragraph,
        visibility: RenderedCssVisibility::Visible,
        visible_text: format!("{SECRET_TEXT} {node}"),
        text_truncated: false,
        identity: None,
        text_fingerprint: Some(RenderedTextFingerprint {
            version: 1,
            digest: format!("{node:064x}"),
        }),
    }
}

fn segmentation(blocks: Vec<RenderedContentBlock>) -> RenderedContentSegmentation {
    RenderedContentSegmentation {
        viewport_width: 1280,
        viewport_height: 720,
        blocks,
        limits: RenderedContentLimits {
            nodes: false,
            depth: false,
            blocks: false,
        },
        id_census_complete: Some(true),
        page_key: Some("a".repeat(64)),
    }
}

fn captured_snapshot(blocks: Vec<RenderedContentBlock>) -> EvidenceSnapshot {
    snapshot_with_browser(CollectorOutcome::Captured {
        data: BrowserEvidence {
            rendered_content: Some(segmentation(blocks)),
            ..BrowserEvidence::default()
        },
    })
}

#[test]
fn uncollected_browser_is_skipped_not_an_empty_result() {
    let snapshot = snapshot_with_browser(CollectorOutcome::default());

    assert!(
        query_browser_evidence_from_snapshot(&snapshot).is_none(),
        "the default skipped state must be reported as uncollected, not as an empty capture"
    );

    let page = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
    assert!(
        matches!(page.status, EvidenceQueryStatus::Skipped { .. }),
        "expected Skipped status, got {:?}",
        page.status
    );
    assert!(
        page.blocks.is_empty(),
        "a skipped collector cannot report blocks"
    );
}

#[test]
fn failed_browser_preserves_the_collector_error() {
    let snapshot = snapshot_with_browser(CollectorOutcome::Failed {
        error: "chromium unavailable".to_owned(),
    });

    match query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0).status {
        EvidenceQueryStatus::Failed { error } => {
            assert!(error.contains("chromium"), "unexpected error: {error}");
        }
        other => panic!("expected Failed status, got {other:?}"),
    }
}

#[test]
fn captured_browser_without_segmentation_is_unavailable() {
    let snapshot = snapshot_with_browser(CollectorOutcome::Captured {
        data: BrowserEvidence::default(),
    });

    assert!(
        matches!(
            query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0).status,
            EvidenceQueryStatus::Unavailable { .. }
        ),
        "a capture without rendered segmentation must report Unavailable"
    );
}

#[test]
fn pagination_is_bounded_and_never_exposes_raw_text() {
    let blocks: Vec<RenderedContentBlock> = (1..=20).map(block).collect();
    let snapshot = captured_snapshot(blocks);

    let first = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 0);
    assert_eq!(first.status, EvidenceQueryStatus::Captured);
    assert_eq!(first.total_matching, 20);
    assert_eq!(first.blocks.len(), 16);
    assert_eq!(first.next_offset, Some(16));

    let second = query_rendered_content(&snapshot, &RenderedBlockFilter::default(), 16);
    assert_eq!(second.blocks.len(), 4);
    assert_eq!(second.next_offset, None);

    let context = rendered_content_context(Some(&snapshot));
    assert!(
        !context.contains(SECRET_TEXT),
        "prompt context must not contain raw rendered text"
    );
    assert!(
        context.contains("text_fingerprint"),
        "prompt context must expose the text fingerprint instead"
    );
}

#[test]
fn citations_accept_only_nodes_on_the_supplied_page() {
    let snapshot = captured_snapshot((1..=20).map(block).collect());

    let refs = cited_rendered_block_refs(&snapshot, &[1, 999]);
    assert_eq!(refs.len(), 1, "only node 1 exists on page 0");
    assert!(
        refs[0].detail.contains("rendered-block-node=1"),
        "unexpected citation detail: {}",
        refs[0].detail
    );
}
