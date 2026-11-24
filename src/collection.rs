//! Bounded HTTP collection engine.
//!
//! Only the collection engine performs network I/O. It produces an immutable
//! [`EvidenceSnapshot`] governed by [`ExecutionBudget`] and [`TargetPolicy`].

use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;
use reqwest::redirect::Policy;
use tokio::net::lookup_host;
use url::Url;

use crate::domain::{
    AuditTarget, CollectorOutcome, EvidenceSnapshot, ExecutionBudget, HttpEvidence, HttpHeader,
    Measurement, RedirectHop, TargetPolicy, is_forbidden_ip,
};

const USER_AGENT: &str = concat!("NetzZwergenWacht/", env!("CARGO_PKG_VERSION"));

/// Performs a single bounded HTTP `GET` collection pass for `target`.
///
/// Enforces [`ExecutionBudget`] timeouts, redirect caps, streaming payload size
/// limits, and [`TargetPolicy`] SSRF/DNS-pinning defences on every hop.
pub async fn collect_http(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> EvidenceSnapshot {
    let captured_at_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let http = match execute_bounded_get(target, budget, policy).await {
        Ok(evidence) if evidence.body_truncated => CollectorOutcome::Partial {
            warnings: vec![format!(
                "response body truncated at {} bytes budget",
                budget.max_response_bytes
            )],
            data: evidence,
        },
        Ok(evidence) => CollectorOutcome::Captured { data: evidence },
        Err(error) => CollectorOutcome::Failed { error },
    };

    EvidenceSnapshot {
        target: target.clone(),
        captured_at_unix_secs,
        http,
    }
}

async fn execute_bounded_get(
    initial_target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> Result<HttpEvidence, String> {
    let started = Instant::now();
    let mut current_target = initial_target.clone();
    let mut redirect_chain = Vec::new();

    loop {
        let pinned_addrs = resolve_and_validate(&current_target, policy).await?;
        let host_for_pin = strip_ipv6_brackets(current_target.host());

        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(budget.http_timeout)
            .user_agent(USER_AGENT)
            .resolve_to_addrs(host_for_pin, &pinned_addrs)
            .build()
            .map_err(|e| format!("failed to build HTTP client: {e}"))?;

        let mut response = client
            .get(current_target.as_str())
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        let status = response.status();
        if is_redirect_status(status) {
            if redirect_chain.len() >= budget.max_redirects {
                return Err(format!(
                    "exceeded maximum redirect limit of {}",
                    budget.max_redirects
                ));
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| format!("redirect status {status} missing valid Location header"))?;

            let next_url = resolve_redirect_url(current_target.as_str(), location)?;
            let next_target = AuditTarget::parse(next_url.as_str(), policy)
                .map_err(|e| format!("redirect target rejected: {e}"))?;

            redirect_chain.push(RedirectHop {
                from_url: current_target.as_str().to_owned(),
                status_code: status.as_u16(),
                to_url: next_target.as_str().to_owned(),
            });

            current_target = next_target;
            continue;
        }

        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.as_str().to_ascii_lowercase(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            })
            .collect();

        let (body, body_truncated) =
            read_bounded_body(&mut response, budget.max_response_bytes).await?;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

        return Ok(HttpEvidence {
            final_url: current_target.as_str().to_owned(),
            status_code: status.as_u16(),
            redirect_chain,
            headers,
            elapsed_ms: Measurement::Measured {
                value: elapsed_ms,
                unit: "ms".to_owned(),
            },
            body_bytes: body.len(),
            body_truncated,
            body_text: String::from_utf8_lossy(&body).into_owned(),
        });
    }
}

async fn resolve_and_validate(
    target: &AuditTarget,
    policy: TargetPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let host = strip_ipv6_brackets(target.host());
    let addrs: Vec<SocketAddr> = lookup_host((host, target.port()))
        .await
        .map_err(|e| format!("DNS lookup failed for {host}: {e}"))?
        .collect();

    if addrs.is_empty() {
        return Err(format!("DNS lookup returned no addresses for {host}"));
    }

    if policy == TargetPolicy::PublicOnly {
        for addr in &addrs {
            if is_forbidden_ip(addr.ip()) {
                return Err(format!(
                    "resolved IP {} for {host} is forbidden under PublicOnly policy",
                    addr.ip()
                ));
            }
        }
    }

    Ok(addrs)
}

fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host)
}

const fn is_redirect_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn resolve_redirect_url(base: &str, location: &str) -> Result<Url, String> {
    let base_url = Url::parse(base).map_err(|e| format!("invalid base URL {base}: {e}"))?;
    base_url
        .join(location)
        .map_err(|e| format!("invalid redirect Location '{location}': {e}"))
}

async fn read_bounded_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), String> {
    let mut buf = Vec::new();
    let mut truncated = false;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("failed reading response body: {e}"))?
    {
        let remaining = max_bytes.saturating_sub(buf.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        if chunk.len() > remaining {
            buf.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        buf.extend_from_slice(&chunk);
    }

    Ok((buf, truncated))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    async fn spawn_mock_server(responses: Vec<&'static str>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut req_buf = [0_u8; 1024];
                let _ = socket.read(&mut req_buf).await;
                socket.write_all(response.as_bytes()).await.unwrap();
                let _ = socket.shutdown().await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn collects_html_response_within_budget() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 27\r\nConnection: close\r\n\r\n<html><title>Hi</title></html>",
        ])
        .await;

        let target =
            AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
        let snapshot = collect_http(
            &target,
            &ExecutionBudget::default(),
            TargetPolicy::AllowPrivate,
        )
        .await;

        match snapshot.http {
            CollectorOutcome::Captured { data } => {
                assert_eq!(data.status_code, 200);
                assert!(!data.body_truncated);
                assert!(data.body_text.contains("<title>Hi</title>"));
                assert!(matches!(data.elapsed_ms, Measurement::Measured { .. }));
            }
            other => panic!("expected Captured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn follows_redirects_and_records_chain() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 301 Moved Permanently\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        ])
        .await;

        let target =
            AuditTarget::parse(&format!("http://{addr}/start"), TargetPolicy::AllowPrivate)
                .unwrap();
        let snapshot = collect_http(
            &target,
            &ExecutionBudget::default(),
            TargetPolicy::AllowPrivate,
        )
        .await;

        match snapshot.http {
            CollectorOutcome::Captured { data } => {
                assert_eq!(data.status_code, 200);
                assert_eq!(data.redirect_chain.len(), 1);
                assert_eq!(data.redirect_chain[0].status_code, 301);
                assert!(data.final_url.ends_with("/final"));
            }
            other => panic!("expected Captured, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncates_body_at_max_response_bytes_as_partial() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef",
        ])
        .await;

        let target =
            AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
        let budget = ExecutionBudget {
            max_response_bytes: 5,
            ..ExecutionBudget::default()
        };

        let snapshot = collect_http(&target, &budget, TargetPolicy::AllowPrivate).await;
        match snapshot.http {
            CollectorOutcome::Partial { data, warnings } => {
                assert!(data.body_truncated);
                assert_eq!(data.body_bytes, 5);
                assert_eq!(data.body_text, "01234");
                assert_eq!(warnings.len(), 1);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enforces_redirect_limit() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ])
        .await;

        let target =
            AuditTarget::parse(&format!("http://{addr}/"), TargetPolicy::AllowPrivate).unwrap();
        let budget = ExecutionBudget {
            max_redirects: 0,
            http_timeout: Duration::from_secs(5),
            ..ExecutionBudget::default()
        };

        let snapshot = collect_http(&target, &budget, TargetPolicy::AllowPrivate).await;
        assert!(matches!(snapshot.http, CollectorOutcome::Failed { .. }));
    }
}
