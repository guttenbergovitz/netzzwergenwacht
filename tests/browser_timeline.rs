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
                    "/disconnect" => return,
                    "/missing" => ("404 Not Found", "", ""),
                    _ => ("204 No Content", "", ""),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n{extra}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
