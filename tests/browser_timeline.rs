//! Exercises the existing CDP collector against a controlled loopback page.

use std::time::Duration;

use netzzwergenwacht::adapters::browser::run_browser_with_policy;
use netzzwergenwacht::domain::{
    AuditTarget, BrowserEventDetail, CollectorOutcome, TargetPolicy, TimelineEnd,
    TimelineRuntimeKind,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut input = [0; 4096];
                let bytes = socket.read(&mut input).await.unwrap();
                let request = String::from_utf8_lossy(&input[..bytes]);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, extra, body) = match path {
                    "/start" => ("302 Found", "Location: /page?token=fixture-secret\r\n", ""),
                    "/page?token=fixture-secret" => (
                        "200 OK",
                        "",
                        "<img src='/missing'><img src='/disconnect'><script>throw new Error('fixture-runtime-secret')</script>",
                    ),
                    "/rendered-content" => (
                        "200 OK",
                        "",
                        r#"<style>.hide { display: none }</style>
                           <main><p>Shared <span>para</span>graph</p><div class="hide"><p>Hidden paragraph</p></div></main>
                           <script>const paragraph = document.createElement('p'); paragraph.textContent = 'Generated paragraph'; document.querySelector('main').append(paragraph);</script>"#,
                    ),
                    "/rendered-limits" => (
                        "200 OK",
                        "",
                        r#"<main><p id="unicode"></p><p id="long"></p><p style="-webkit-text-security: disc">masked secret</p></main>
                           <script>
                             document.querySelector('#unicode').textContent = 'before' + String.fromCharCode(0xDC00) + 'after';
                             document.querySelector('#long').textContent = 'x'.repeat(511) + '😀tail';
                             for (let i = 0; i < 260; i++) document.querySelector('main').append(document.createElement('p'));
                           </script>"#,
                    ),
                    "/identity-before" => (
                        "200 OK",
                        "",
                        r#"<main><p id="stable-private-fixture-key">Before</p><section><p>Unlabelled</p></section>
                          <article><p id="repeated-key">Repeated</p></article><div id="repeated-key">Outside paragraph</div>
                          <footer><p>One</p><p>Two</p></footer></main>"#,
                    ),
                    "/identity-after" => (
                        "200 OK",
                        "",
                        r#"<header>Banner</header><main><p id="stable-private-fixture-key">After</p><section><p>Unlabelled</p></section>
                          <article><p id="repeated-key">Repeated again</p></article><div id="repeated-key">Outside paragraph</div>
                          <footer><p>One</p><p>Two</p></footer></main>
                          <script>history.replaceState(null, '', '/identity-before');</script>"#,
                    ),
                    "/disconnect" => return,
                    "/missing" => ("404 Not Found", "", ""),
                    _ => ("204 No Content", "", ""),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    (address, server)
}

#[tokio::test]
#[ignore = "requires Node.js and Chromium"]
async fn live_browser_timeline_distinguishes_redirect_http_error_disconnect_and_runtime() {
    let (address, server) = spawn_fixture().await;
    let target = AuditTarget::parse(
        &format!("http://{address}/start"),
        TargetPolicy::AllowPrivate,
    )
    .unwrap();
    let outcome =
        run_browser_with_policy(&target, Duration::from_secs(35), TargetPolicy::AllowPrivate).await;
    server.abort();
    let evidence = match outcome {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        other => panic!("browser collection failed: {other:?}"),
    };
    let timeline = evidence.timeline.unwrap();
    assert_eq!(timeline.end, TimelineEnd::ObservationEnded);
    assert!(
        timeline
            .events
            .windows(2)
            .all(|pair| pair[0].sequence + 1 == pair[1].sequence)
    );
    let redirect = timeline
        .events
        .iter()
        .find(|event| {
            matches!(
                event.detail,
                BrowserEventDetail::Redirect {
                    status: Some(302),
                    ..
                }
            )
        })
        .unwrap();
    let request = redirect.request.as_ref().unwrap();
    assert_eq!(request.hop, Some(0));
    assert!(timeline.events.iter().any(|event| {
        event.sequence > redirect.sequence
            && event
                .request
                .as_ref()
                .is_some_and(|candidate| candidate.id == request.id && candidate.hop == Some(1))
            && matches!(
                event.detail,
                BrowserEventDetail::Response {
                    status: Some(200),
                    ..
                }
            )
    }));
    for predicate in [
        (|event: &BrowserEventDetail| {
            matches!(
                event,
                BrowserEventDetail::Response {
                    status: Some(404),
                    ..
                }
            )
        }) as fn(&BrowserEventDetail) -> bool,
        |event| matches!(event, BrowserEventDetail::NetworkFailure),
        |event| {
            matches!(
                event,
                BrowserEventDetail::RuntimeError {
                    category: TimelineRuntimeKind::UncaughtException
                }
            )
        },
    ] {
        assert!(
            timeline.events.iter().any(|event| predicate(&event.detail)),
            "{timeline:?}"
        );
    }
    assert!(
        !serde_json::to_string(&timeline)
            .unwrap()
            .contains("fixture-secret")
    );
    assert!(
        !serde_json::to_string(&timeline)
            .unwrap()
            .contains("fixture-runtime-secret")
    );
}

#[tokio::test]
#[ignore = "requires Node.js and Chromium"]
async fn live_browser_distinguishes_source_and_rendered_paragraphs() {
    use netzzwergenwacht::analysis::document::DocumentObservations;
    use netzzwergenwacht::collection::collect_http;
    use netzzwergenwacht::domain::{ExecutionBudget, RenderedBlockKind, RenderedCssVisibility};

    let (address, server) = spawn_fixture().await;
    let policy = TargetPolicy::AllowPrivate;
    let target = AuditTarget::parse(&format!("http://{address}/rendered-content"), policy).unwrap();
    let source = collect_http(&target, &ExecutionBudget::default(), policy).await;
    let rendered = run_browser_with_policy(&target, Duration::from_secs(35), policy).await;
    server.abort();

    let CollectorOutcome::Captured { data: http } = source.http else {
        panic!("expected captured source HTML");
    };
    let source = DocumentObservations::from_html(&http.body_text);
    assert_eq!(
        source
            .content
            .paragraphs
            .iter()
            .map(|block| block.text.as_str())
            .collect::<Vec<_>>(),
        ["Shared paragraph", "Hidden paragraph"]
    );

    let CollectorOutcome::Captured { data } = rendered else {
        panic!("expected complete rendered capture: {rendered:?}");
    };
    let content = data.rendered_content.unwrap();
    assert_eq!(
        (content.viewport_width, content.viewport_height),
        (1280, 720)
    );
    let paragraphs: Vec<_> = content
        .blocks
        .iter()
        .filter(|block| block.kind == RenderedBlockKind::Paragraph)
        .map(|block| (block.visibility, block.visible_text.as_str()))
        .collect();
    assert_eq!(
        paragraphs,
        [
            (RenderedCssVisibility::Visible, "Shared paragraph"),
            (RenderedCssVisibility::Hidden, ""),
            (RenderedCssVisibility::Visible, "Generated paragraph"),
        ]
    );
    let main = content
        .blocks
        .iter()
        .find(|block| block.kind == RenderedBlockKind::Main)
        .unwrap();
    assert_eq!(main.visible_text, "Shared paragraph Generated paragraph");
}

#[tokio::test]
#[ignore = "requires Node.js and Chromium"]
async fn live_browser_preserves_evidence_when_rendered_content_hits_limits() {
    use netzzwergenwacht::domain::RenderedBlockKind;

    let (address, server) = spawn_fixture().await;
    let policy = TargetPolicy::AllowPrivate;
    let target = AuditTarget::parse(&format!("http://{address}/rendered-limits"), policy).unwrap();
    let outcome = run_browser_with_policy(&target, Duration::from_secs(35), policy).await;
    server.abort();
    let CollectorOutcome::Partial { data, warnings } = outcome else {
        panic!("expected partial rendered capture: {outcome:?}");
    };
    assert!(
        warnings
            .iter()
            .any(|message| message.contains("segmentation reached"))
    );
    let content = data.rendered_content.unwrap();
    assert!(content.limits.blocks);
    assert_eq!(content.blocks.len(), 256);
    let mut paragraphs = content
        .blocks
        .iter()
        .filter(|block| block.kind == RenderedBlockKind::Paragraph);
    assert_eq!(
        paragraphs.next().unwrap().visible_text,
        "before\u{fffd}after"
    );
    let clipped = paragraphs.next().unwrap();
    assert!(clipped.text_truncated);
    assert_eq!(clipped.visible_text, "x".repeat(511));
    assert_eq!(paragraphs.next().unwrap().visible_text, "");
}

#[tokio::test]
#[ignore = "requires Node.js and Chromium"]
async fn live_browser_matches_identity_across_banner_and_text_changes() {
    use netzzwergenwacht::analysis::element_identity::{
        ElementMatch, MatchBasis, match_rendered_blocks,
    };

    let (address, server) = spawn_fixture().await;
    let mut captures = Vec::new();
    for route in ["identity-before", "identity-after"] {
        let policy = TargetPolicy::AllowPrivate;
        let target = AuditTarget::parse(&format!("http://{address}/{route}"), policy).unwrap();
        let result = run_browser_with_policy(&target, Duration::from_secs(35), policy).await;
        let CollectorOutcome::Captured { data } = result else {
            panic!("expected complete browser capture: {result:?}");
        };
        captures.push(data);
    }
    server.abort();

    let matches = match_rendered_blocks(&captures[0], &captures[1]).unwrap();
    let before = captures[0].rendered_content.as_ref().unwrap();
    let after = captures[1].rendered_content.as_ref().unwrap();
    let locate = |text: &str| {
        before
            .blocks
            .iter()
            .find(|block| {
                block.visible_text == text
                    && block.kind == netzzwergenwacht::domain::RenderedBlockKind::Paragraph
            })
            .unwrap()
            .node
    };

    let ElementMatch::Matched {
        current,
        basis: MatchBasis::UniqueId,
    } = matches[&locate("Before")]
    else {
        panic!("unique ID should survive changed text");
    };
    assert_ne!(current, locate("Before"));
    assert!(
        after
            .blocks
            .iter()
            .any(|block| block.node == current && block.visible_text == "After")
    );
    assert!(matches!(
        matches[&locate("Unlabelled")],
        ElementMatch::Matched {
            basis: MatchBasis::UniqueStructure,
            ..
        }
    ));
    assert_eq!(matches[&locate("Repeated")], ElementMatch::Ambiguous);
    assert_eq!(matches[&locate("One")], ElementMatch::Ambiguous);
    assert!(
        !serde_json::to_string(after)
            .unwrap()
            .contains("stable-private-fixture-key")
    );
}
