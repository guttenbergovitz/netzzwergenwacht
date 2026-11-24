//! Chaos and cancellation tests for bounded collection and deterministic
//! handling of stalled, dropped, or cancelled network exchanges.

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use netzzwergenwacht::analysis;
use netzzwergenwacht::brigade::DwarfId;
use netzzwergenwacht::collection;
use netzzwergenwacht::domain::{AuditTarget, CollectorOutcome, ExecutionBudget, TargetPolicy};

#[tokio::test]
async fn stalled_server_respects_audit_timeout_and_never_hangs() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        if let Ok((_socket, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let target =
        AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
    let budget = ExecutionBudget {
        audit_timeout: Duration::from_millis(150),
        http_timeout: Duration::from_secs(5),
        ..ExecutionBudget::default()
    };

    let start = Instant::now();
    let snap = collection::collect_http(&target, &budget, TargetPolicy::AllowPrivate).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "collection should abort promptly near audit_timeout, took {elapsed:?}"
    );
    assert!(matches!(snap.http, CollectorOutcome::Failed { .. }));
    assert!(matches!(snap.tls, CollectorOutcome::Skipped { .. }));

    server.abort();
}

#[tokio::test]
async fn mid_stream_drop_does_not_fabricate_passing_document_checks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let partial_response = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/html; charset=utf-8\r\n",
                "Content-Length: 4096\r\n",
                "\r\n",
                "<html><body><p>truncated"
            );
            let _ = socket.write_all(partial_response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let target =
        AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
    let budget = ExecutionBudget {
        audit_timeout: Duration::from_secs(2),
        http_timeout: Duration::from_secs(2),
        ..ExecutionBudget::default()
    };

    let snap = collection::collect_http(&target, &budget, TargetPolicy::AllowPrivate).await;
    assert!(!matches!(snap.http, CollectorOutcome::Captured { .. }));

    let report = analysis::run_all(&snap);
    for id in [
        DwarfId::Struktur,
        DwarfId::Zugaenglichkeits,
        DwarfId::Such,
        DwarfId::Inhalts,
    ] {
        let analyser = report.analysers.iter().find(|a| a.dwarf_id == id).unwrap();
        assert_eq!(analyser.findings.len(), 0);
    }

    let _ = server.await;
}

#[tokio::test]
async fn cancelled_collection_future_drops_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        if let Ok((_socket, _)) = listener.accept().await {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let target =
        AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
    let budget = ExecutionBudget::default();

    let cancelled = tokio::select! {
        _ = collection::collect_http(&target, &budget, TargetPolicy::AllowPrivate) => false,
        () = tokio::time::sleep(Duration::from_millis(50)) => true,
    };
    assert!(cancelled);

    server.abort();
}
