//! Bounded HTTP collection engine.
//!
//! Only the collection engine performs network I/O. It produces an immutable
//! [`EvidenceSnapshot`] governed by [`ExecutionBudget`] and [`TargetPolicy`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;
use reqwest::redirect::Policy;
use reqwest::tls::TlsInfo;
use tokio::net::lookup_host;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::domain::{
    AuditTarget, CaaLookupOutcome, CollectorOutcome, EvidenceSnapshot, ExecutionBudget,
    HttpEvidence, HttpHeader, Measurement, MeasurementUnit, RedirectHop, TargetPolicy,
    TargetScheme, TlsEvidence, is_forbidden_ip,
};

const USER_AGENT: &str = concat!("NetzZwergenWacht/", env!("CARGO_PKG_VERSION"));

/// Performs a single bounded HTTP `GET` collection pass for `target`.
///
/// Enforces [`ExecutionBudget`] end-to-end deadlines, per-request timeouts,
/// redirect caps, streaming payload size limits, and [`TargetPolicy`]
/// SSRF/DNS-pinning defences on every hop.
pub async fn collect_http(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> EvidenceSnapshot {
    collect_http_with_caa_endpoint(target, budget, policy, None).await
}

/// Performs the same bounded HTTP collection as [`collect_http`], additionally
/// querying DNS CAA records through `caa_doh_endpoint` when one is configured.
///
/// The endpoint must be supplied explicitly by the caller; with `None` the hostname is
/// never sent to an external resolver, which keeps default operation local-first.
pub async fn collect_http_with_caa_endpoint(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    caa_doh_endpoint: Option<&str>,
) -> EvidenceSnapshot {
    collect_http_with_source(
        target,
        budget,
        policy,
        caa_doh_endpoint,
        ClientSource::Fresh,
    )
    .await
}

/// Performs the same bounded collection as [`collect_http`] while reusing a pooled HTTP client
/// from `cache` for hosts that were already resolved and validated during this crawl.
///
/// Unlike [`collect_http_with_caa_endpoint`], this entry point never queries DNS CAA: additional
/// external dependencies stay an explicit per-page decision rather than an implicit crawl default.
pub async fn collect_http_cached(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    cache: &CrawlHttpCache,
) -> EvidenceSnapshot {
    collect_http_with_source(target, budget, policy, None, ClientSource::Cached(cache)).await
}

/// What a bounded subresource acquisition actually observed.
///
/// The body is streamed, counted and discarded: `byte_len` reports the bytes read before the read
/// stopped, and `truncated` states whether the byte cap was reached, so a truncated read is never
/// presented as the complete size of the resource.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceFetch {
    /// Response status code, when a response was received.
    pub status_code: Option<u16>,
    /// Declared `Content-Type`.
    pub content_type: Option<String>,
    /// Declared `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// Bytes read from the body before the read stopped.
    pub byte_len: Option<u64>,
    /// Declared `Cache-Control`.
    pub cache_control: Option<String>,
    /// Whether the response carried an `ETag`.
    pub etag_present: bool,
    /// Whether the response carried `Last-Modified`.
    pub last_modified_present: bool,
    /// Whether the byte cap stopped the read, making `byte_len` a lower bound.
    pub truncated: bool,
    /// Transport or validation failure, if any.
    pub error: Option<String>,
}

/// Acquires one subresource without retaining its body.
///
/// Runs under the caller's [`ExecutionBudget`] and [`TargetPolicy`]: the target is resolved and
/// validated by the shared client cache, redirects are not followed (a redirect status is itself an
/// observation), and the read stops at `max_bytes`.
pub async fn fetch_resource(
    target: &AuditTarget,
    policy: TargetPolicy,
    cache: &CrawlHttpCache,
    http_timeout: std::time::Duration,
    max_bytes: usize,
) -> ResourceFetch {
    let cap = u64::try_from(max_bytes.max(1)).unwrap_or(u64::MAX);
    let client = match cache.client_for(target, http_timeout, policy).await {
        Ok(client) => client,
        Err(error) => {
            return ResourceFetch {
                error: Some(error),
                ..ResourceFetch::default()
            };
        }
    };

    let response = match client.get(target.as_str()).send().await {
        Ok(response) => response,
        Err(error) => {
            return ResourceFetch {
                error: Some(format!("resource request failed: {error}")),
                ..ResourceFetch::default()
            };
        }
    };

    let status_code = response.status().as_u16();
    let headers = response.headers().clone();
    let mut read = response;
    let mut observed: u64 = 0;
    let mut truncated = false;
    loop {
        match read.chunk().await {
            Ok(Some(chunk)) => {
                observed = observed.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                if observed >= cap {
                    truncated = true;
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                return ResourceFetch {
                    status_code: Some(status_code),
                    content_type: header_text(&headers, reqwest::header::CONTENT_TYPE),
                    content_encoding: header_text(&headers, reqwest::header::CONTENT_ENCODING),
                    byte_len: Some(observed),
                    truncated: false,
                    error: Some(format!("resource body read failed: {error}")),
                    ..ResourceFetch::default()
                };
            }
        }
    }

    ResourceFetch {
        status_code: Some(status_code),
        content_type: header_text(&headers, reqwest::header::CONTENT_TYPE),
        content_encoding: header_text(&headers, reqwest::header::CONTENT_ENCODING),
        byte_len: Some(observed),
        cache_control: header_text(&headers, reqwest::header::CACHE_CONTROL),
        etag_present: headers.contains_key(reqwest::header::ETAG),
        last_modified_present: headers.contains_key(reqwest::header::LAST_MODIFIED),
        truncated,
        error: None,
    }
}

/// Reads a response header as bounded text, dropping control characters and capping the length.
fn header_text(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Probes a synthetic non-existent URL on the target origin to establish a soft-404 baseline,
/// performing a confirmation re-fetch on a second synthetic path if the first probe returns HTTP 200.
pub async fn probe_soft_404_baseline(
    origin_target: &AuditTarget,
    policy: TargetPolicy,
    budget: &ExecutionBudget,
) -> Option<crate::analysis::network::Soft404Baseline> {
    let mut probe_url = url::Url::parse(origin_target.as_str()).ok()?;
    probe_url.set_path("/__nzw-soft404-probe-9f4c2a7e1b");
    probe_url.set_query(None);
    probe_url.set_fragment(None);
    let probe_target = AuditTarget::parse(probe_url.as_str(), policy).ok()?;

    let (probe_http, _) = tokio::time::timeout(
        budget.audit_timeout,
        execute_bounded_get(&probe_target, budget, policy, ClientSource::Fresh),
    )
    .await
    .ok()?
    .ok()?;

    let probe_obs =
        crate::analysis::document::DocumentObservations::from_html(&probe_http.body_text);
    let probe_simhash = crate::analysis::graph::compute_text_simhash(&probe_obs.main_content_text);

    let (confirmation_url, confirmation_status, confirmation_simhash) = if probe_http.status_code
        == 200
    {
        let mut confirm_url = url::Url::parse(origin_target.as_str()).ok()?;
        confirm_url.set_path("/__nzw-soft404-confirm-3e8d1b5a4c");
        confirm_url.set_query(None);
        confirm_url.set_fragment(None);
        if let Ok(confirm_target) = AuditTarget::parse(confirm_url.as_str(), policy)
            && let Ok(Ok((confirm_http, _))) = tokio::time::timeout(
                budget.audit_timeout,
                execute_bounded_get(&confirm_target, budget, policy, ClientSource::Fresh),
            )
            .await
        {
            let confirm_obs =
                crate::analysis::document::DocumentObservations::from_html(&confirm_http.body_text);
            let confirm_hash =
                crate::analysis::graph::compute_text_simhash(&confirm_obs.main_content_text);
            (
                Some(confirm_url.to_string()),
                Some(confirm_http.status_code),
                confirm_hash,
            )
        } else {
            (Some(confirm_url.to_string()), None, None)
        }
    } else {
        (None, None, None)
    };

    Some(crate::analysis::network::Soft404Baseline {
        probe_url: probe_url.to_string(),
        probe_status: probe_http.status_code,
        probe_simhash,
        probe_body_bytes: probe_http.body_bytes,
        confirmation_url,
        confirmation_status,
        confirmation_simhash,
    })
}

/// Default well-known origin paths inspected by [`ProbeCollector`].
pub const DEFAULT_WELL_KNOWN_PROBE_PATHS: &[&str] = &[
    "/.well-known/security.txt",
    "/llms.txt",
    "/humans.txt",
    "/ads.txt",
    "/.well-known/assetlinks.json",
];

/// Captured response metadata for a single well-known origin path probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WellKnownProbeObservation {
    /// Final resolved URL after redirects.
    pub final_url: String,
    /// HTTP status code returned by the origin.
    pub status_code: u16,
    /// `Content-Type` header value, if present.
    pub content_type: Option<String>,
    /// Observed response body byte length.
    pub body_bytes: usize,
    /// Bounded UTF-8 preview (up to 4096 bytes) for downstream deterministic checks.
    pub body_preview: String,
}

/// Outcome for one path probed by [`ProbeCollector`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WellKnownPathProbe {
    /// Origin-relative path probed (for example `"/.well-known/security.txt"`).
    pub path: String,
    /// Explicit probe outcome (`Captured`, `Failed`, or `Skipped`).
    pub outcome: CollectorOutcome<WellKnownProbeObservation>,
}

/// Aggregated origin-level probe evidence (custom-404 baseline + well-known files).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OriginProbes {
    /// Normalised origin URL (`scheme://host[:port]`).
    pub origin: String,
    /// Random-URL baseline + confirmation re-fetch used for soft-404 verification.
    pub soft_404_baseline: Option<crate::analysis::network::Soft404Baseline>,
    /// Bounded well-known path probe outcomes.
    pub well_known: Vec<WellKnownPathProbe>,
}

/// Bounded origin probe collector enforcing request-count and payload-size caps.
#[derive(Debug, Clone, Copy)]
pub struct ProbeCollector {
    /// Maximum number of well-known paths probed per origin.
    pub max_well_known_probes: usize,
    /// Maximum response bytes retained in [`WellKnownProbeObservation::body_preview`].
    pub max_preview_bytes: usize,
}

impl Default for ProbeCollector {
    fn default() -> Self {
        Self {
            max_well_known_probes: 8,
            max_preview_bytes: 4_096,
        }
    }
}

impl ProbeCollector {
    /// Collects [`OriginProbes`] for `origin_target` within `budget` and `policy`.
    pub async fn collect_origin_probes(
        &self,
        origin_target: &AuditTarget,
        policy: TargetPolicy,
        budget: &ExecutionBudget,
        paths: &[&str],
    ) -> OriginProbes {
        let origin = Url::parse(origin_target.as_str()).map_or_else(
            |_| origin_target.as_str().to_owned(),
            |u| u.origin().ascii_serialization(),
        );
        let soft_404_baseline = probe_soft_404_baseline(origin_target, policy, budget).await;

        let effective_paths: &[&str] = if paths.is_empty() {
            DEFAULT_WELL_KNOWN_PROBE_PATHS
        } else {
            paths
        };

        let mut well_known = Vec::new();
        for (idx, &raw_path) in effective_paths.iter().enumerate() {
            if idx >= self.max_well_known_probes {
                well_known.push(WellKnownPathProbe {
                    path: raw_path.to_owned(),
                    outcome: CollectorOutcome::Skipped {
                        reason: format!(
                            "probe skipped at max_well_known_probes={} budget",
                            self.max_well_known_probes
                        ),
                    },
                });
                continue;
            }
            let outcome = self
                .probe_single_path(origin_target, raw_path, policy, budget)
                .await;
            well_known.push(WellKnownPathProbe {
                path: raw_path.to_owned(),
                outcome,
            });
        }

        OriginProbes {
            origin,
            soft_404_baseline,
            well_known,
        }
    }

    async fn probe_single_path(
        &self,
        origin_target: &AuditTarget,
        raw_path: &str,
        policy: TargetPolicy,
        budget: &ExecutionBudget,
    ) -> CollectorOutcome<WellKnownProbeObservation> {
        let Ok(mut probe_url) = Url::parse(origin_target.as_str()) else {
            return CollectorOutcome::Failed {
                error: "invalid origin URL".to_owned(),
            };
        };
        let normalised_path = if raw_path.starts_with('/') {
            raw_path.to_owned()
        } else {
            format!("/{raw_path}")
        };
        probe_url.set_path(&normalised_path);
        probe_url.set_query(None);
        probe_url.set_fragment(None);

        let Ok(probe_target) = AuditTarget::parse(probe_url.as_str(), policy) else {
            return CollectorOutcome::Skipped {
                reason: "probe URL blocked by target policy".to_owned(),
            };
        };

        match tokio::time::timeout(
            budget.http_timeout,
            execute_bounded_get(&probe_target, budget, policy, ClientSource::Fresh),
        )
        .await
        {
            Ok(Ok((http, _))) => {
                let content_type = http
                    .headers
                    .iter()
                    .find(|h| h.name == "content-type")
                    .map(|h| h.value.clone());
                let body_preview: String = http
                    .body_text
                    .chars()
                    .take(self.max_preview_bytes)
                    .collect();
                CollectorOutcome::Captured {
                    data: WellKnownProbeObservation {
                        final_url: http.final_url,
                        status_code: http.status_code,
                        content_type,
                        body_bytes: http.body_bytes,
                        body_preview,
                    },
                }
            }
            Ok(Err(err)) => CollectorOutcome::Failed { error: err.error },
            Err(_) => CollectorOutcome::Failed {
                error: format!(
                    "probe timed out after {} ms",
                    budget.http_timeout.as_millis()
                ),
            },
        }
    }
}

/// Where the HTTP client for one request comes from.
#[derive(Clone, Copy)]
enum ClientSource<'a> {
    /// A dedicated client, as used by single-page collection.
    Fresh,
    /// A dedicated client configured with an explicit `User-Agent` header.
    FreshWithUserAgent(&'a str),
    /// A client reused for the crawl, keyed by host and pinned address set.
    Cached(&'a CrawlHttpCache),
}

/// Predefined `User-Agent` profiles for agent-access and cloaking comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserAgentProfile {
    /// Default `NetzZwergenWacht` auditor user-agent.
    Default,
    /// Desktop Chromium browser user-agent.
    DesktopBrowser,
    /// Mobile Safari browser user-agent.
    MobileBrowser,
    /// Search engine crawler user-agent.
    SearchCrawler,
    /// AI agent / LLM crawler user-agent.
    AiAgent,
}

impl UserAgentProfile {
    /// HTTP `User-Agent` string sent for this profile.
    #[must_use]
    pub const fn header_value(self) -> &'static str {
        match self {
            Self::Default => USER_AGENT,
            Self::DesktopBrowser => {
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            }
            Self::MobileBrowser => {
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
            }
            Self::SearchCrawler => {
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            }
            Self::AiAgent => "GPTBot/1.0 (+https://openai.com/gptbot)",
        }
    }
}

/// Comparison result for one [`UserAgentProfile`] fetch against a baseline profile.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UserAgentComparison {
    /// Profile tested.
    pub profile: UserAgentProfile,
    /// Observed HTTP status code (`None` if request failed).
    pub status_code: Option<u16>,
    /// Captured body byte count.
    pub body_bytes: usize,
    /// Primary-content `SimHash`, if sufficient text was captured.
    pub main_simhash: Option<u64>,
    /// Whether this profile received a 401/403/406/429 refusal.
    pub blocked_or_refused: bool,
    /// Whether this profile diverged materially from the baseline response (cloaking signal).
    pub cloaking_suspected: bool,
}

/// Evaluates whether `candidate` response exhibits access refusal or cloaking relative to `baseline`.
#[must_use]
pub fn evaluate_cloaking(
    baseline_status: u16,
    baseline_simhash: Option<u64>,
    baseline_bytes: usize,
    candidate_status: u16,
    candidate_simhash: Option<u64>,
    candidate_bytes: usize,
) -> (bool, bool) {
    let blocked_or_refused = matches!(candidate_status, 401 | 403 | 406 | 429);
    let status_diverged = baseline_status == 200 && candidate_status != 200;
    let content_diverged = if let (Some(a), Some(b)) = (baseline_simhash, candidate_simhash) {
        (a ^ b).count_ones() > 12
    } else {
        let max_b = baseline_bytes.max(candidate_bytes);
        max_b > 256 && baseline_bytes.abs_diff(candidate_bytes) * 100 > max_b * 40
    };
    (blocked_or_refused, status_diverged || content_diverged)
}

/// Collects HTTP evidence for `target` using an explicit [`UserAgentProfile`].
pub async fn collect_http_with_user_agent_profile(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    profile: UserAgentProfile,
) -> EvidenceSnapshot {
    collect_http_with_source(
        target,
        budget,
        policy,
        None,
        ClientSource::FreshWithUserAgent(profile.header_value()),
    )
    .await
}

/// Fetches `target` across `profiles` and compares responses against the first profile
/// (typically [`UserAgentProfile::DesktopBrowser`]) to detect agent blocking and cloaking.
pub async fn probe_user_agent_profiles(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    profiles: &[UserAgentProfile],
) -> Vec<UserAgentComparison> {
    if profiles.is_empty() {
        return Vec::new();
    }

    let mut snapshots = Vec::with_capacity(profiles.len());
    for &profile in profiles {
        let snap = collect_http_with_user_agent_profile(target, budget, policy, profile).await;
        snapshots.push((profile, snap));
    }

    let baseline_http = snapshots.first().and_then(|(_, s)| match &s.http {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => Some(data),
        _ => None,
    });
    let baseline_simhash = baseline_http.and_then(|h| {
        let obs = crate::analysis::document::DocumentObservations::from_html(&h.body_text);
        crate::analysis::graph::compute_text_simhash(&obs.main_content_text)
    });

    snapshots
        .iter()
        .enumerate()
        .map(|(idx, (profile, snap))| {
            let (CollectorOutcome::Captured { data: http }
            | CollectorOutcome::Partial { data: http, .. }) = &snap.http
            else {
                return UserAgentComparison {
                    profile: *profile,
                    status_code: None,
                    body_bytes: 0,
                    main_simhash: None,
                    blocked_or_refused: false,
                    cloaking_suspected: false,
                };
            };
            let obs = crate::analysis::document::DocumentObservations::from_html(&http.body_text);
            let simhash = crate::analysis::graph::compute_text_simhash(&obs.main_content_text);
            let (blocked, cloaking) = if idx == 0 {
                (matches!(http.status_code, 401 | 403 | 406 | 429), false)
            } else if let Some(base) = baseline_http {
                evaluate_cloaking(
                    base.status_code,
                    baseline_simhash,
                    base.body_bytes,
                    http.status_code,
                    simhash,
                    http.body_bytes,
                )
            } else {
                (matches!(http.status_code, 401 | 403 | 406 | 429), false)
            };
            UserAgentComparison {
                profile: *profile,
                status_code: Some(http.status_code),
                body_bytes: http.body_bytes,
                main_simhash: simhash,
                blocked_or_refused: blocked,
                cloaking_suspected: cloaking,
            }
        })
        .collect()
}

/// Result of checking a single opt-in external link target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalLinkCheck {
    /// External URL checked.
    pub url: String,
    /// Observed HTTP status code, if a response was received.
    pub status_code: Option<u16>,
    /// `true` when the external link returned 404/410/5xx or failed transport.
    pub broken: bool,
    /// Explicit collector outcome (`Captured` status, `Skipped` by policy, or `Failed`).
    pub outcome: CollectorOutcome<u16>,
}

/// Checks up to `max_links` distinct external URLs concurrently under `budget` and `policy`.
///
/// Only runs when explicitly opted into (e.g. `--check-external`). Private/loopback targets
/// remain governed by `policy`, and `403`/`429` bot-blocks are recorded without false-flagging
/// the link as broken.
pub async fn check_external_links(
    urls: &[String],
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    max_links: usize,
) -> Vec<ExternalLinkCheck> {
    let mut unique = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for u in urls {
        if unique.len() >= max_links {
            break;
        }
        if seen.insert(u.clone()) {
            unique.push(u.clone());
        }
    }

    let sem = Arc::new(Semaphore::new(budget.max_concurrency.max(1)));
    let budget = *budget;
    let mut join_set = JoinSet::new();

    for (idx, raw_url) in unique.into_iter().enumerate() {
        let sem = Arc::clone(&sem);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let Ok(target) = AuditTarget::parse(&raw_url, policy) else {
                return (
                    idx,
                    ExternalLinkCheck {
                        url: raw_url,
                        status_code: None,
                        broken: false,
                        outcome: CollectorOutcome::Skipped {
                            reason: "blocked by target policy or invalid URL".to_owned(),
                        },
                    },
                );
            };
            match tokio::time::timeout(
                budget.http_timeout,
                execute_bounded_get(&target, &budget, policy, ClientSource::Fresh),
            )
            .await
            {
                Ok(Ok((http, _))) => {
                    let broken = http.status_code == 404
                        || http.status_code == 410
                        || http.status_code >= 500;
                    (
                        idx,
                        ExternalLinkCheck {
                            url: raw_url,
                            status_code: Some(http.status_code),
                            broken,
                            outcome: CollectorOutcome::Captured {
                                data: http.status_code,
                            },
                        },
                    )
                }
                Ok(Err(err)) => (
                    idx,
                    ExternalLinkCheck {
                        url: raw_url,
                        status_code: None,
                        broken: true,
                        outcome: CollectorOutcome::Failed { error: err.error },
                    },
                ),
                Err(_) => (
                    idx,
                    ExternalLinkCheck {
                        url: raw_url,
                        status_code: None,
                        broken: true,
                        outcome: CollectorOutcome::Failed {
                            error: format!(
                                "external check timed out after {} ms",
                                budget.http_timeout.as_millis()
                            ),
                        },
                    },
                ),
            }
        });
    }

    let mut ordered = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(item) = res {
            ordered.push(item);
        }
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    ordered.into_iter().map(|(_, item)| item).collect()
}

async fn collect_http_with_source(
    target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    caa_doh_endpoint: Option<&str>,
    source: ClientSource<'_>,
) -> EvidenceSnapshot {
    tracing::debug!(
        target = target.as_str(),
        "starting HTTP evidence collection"
    );
    let started = Instant::now();
    let captured_at_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if let ClientSource::Cached(cache) = source {
        cache
            .wait_if_backed_off(target.host(), budget.http_timeout)
            .await;
    }

    let outcome = tokio::time::timeout(
        budget.audit_timeout,
        execute_bounded_get(target, budget, policy, source),
    )
    .await;

    if let ClientSource::Cached(cache) = source
        && let Ok(Ok((ref evidence, _))) = outcome
    {
        let retry_after = evidence
            .headers
            .iter()
            .find(|h| h.name == "retry-after")
            .map(|h| h.value.as_str());
        let refusal =
            classify_http_refusal(evidence.status_code, &evidence.headers, &evidence.body_text);
        cache.record_response_outcome(target.host(), evidence.status_code, retry_after, refusal);
    }

    let (http, mut tls) = match outcome {
        Ok(Ok((evidence, tls))) if evidence.body_truncated => (
            CollectorOutcome::Partial {
                warnings: vec![format!(
                    "response body truncated at {} bytes budget",
                    budget.max_response_bytes
                )],
                data: evidence,
            },
            tls,
        ),
        Ok(Ok((evidence, tls))) => (CollectorOutcome::Captured { data: evidence }, tls),
        Ok(Err(failed)) => {
            tracing::warn!(target = target.as_str(), error = %failed.error, "HTTP collection failed");
            (
                CollectorOutcome::Failed {
                    error: failed.error,
                },
                failed.tls.unwrap_or_else(|| CollectorOutcome::Skipped {
                    reason: "TLS outcome unavailable because HTTP collection failed".to_owned(),
                }),
            )
        }
        Err(_) => {
            tracing::warn!(
                target = target.as_str(),
                timeout_ms = budget.audit_timeout.as_millis(),
                "HTTP collection exceeded audit_timeout"
            );
            (
                CollectorOutcome::Failed {
                    error: format!(
                        "audit collection exceeded {} ms deadline",
                        budget.audit_timeout.as_millis()
                    ),
                },
                CollectorOutcome::Skipped {
                    reason: "TLS outcome unavailable because audit collection timed out".to_owned(),
                },
            )
        }
    };

    if let CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } = &mut tls {
        let remaining = budget.audit_timeout.saturating_sub(started.elapsed());
        let (records, outcome) =
            lookup_dns_caa_records(caa_doh_endpoint, target.host(), remaining).await;
        data.caa_records = records;
        data.caa_query_succeeded = matches!(
            outcome,
            CaaLookupOutcome::RecordsObserved | CaaLookupOutcome::NoRecordsObserved
        );
        data.caa_lookup_outcome = outcome;
    }

    EvidenceSnapshot {
        target: target.clone(),
        captured_at_unix_secs,
        http,
        tls,
        browser: CollectorOutcome::default(),
        lighthouse: CollectorOutcome::default(),
        axe: CollectorOutcome::default(),
    }
}

/// Looks up DNS CAA records for `host` through an explicitly configured DNS-over-HTTPS
/// endpoint.
///
/// Local-first operation is the default: when no endpoint is configured the lookup is
/// not attempted and the outcome is [`CaaLookupOutcome::NotAttempted`], so the
/// investigated hostname is never transmitted to a third party implicitly. The helper
/// returns the observed records together with an explicit outcome so that "no records
/// published" stays distinguishable from "the lookup failed".
/// Maps a DNS response code to a CAA lookup outcome.
///
/// A success response without `Answer` records is a valid empty observation, so
/// callers must not treat it as a failed acquisition.
const fn caa_outcome_for_dns_status(status: Option<u64>) -> CaaLookupOutcome {
    match status {
        Some(0) => CaaLookupOutcome::NoRecordsObserved,
        Some(3) => CaaLookupOutcome::NameDoesNotExist,
        Some(2) => CaaLookupOutcome::ServerFailure,
        Some(5) => CaaLookupOutcome::Refused,
        _ => CaaLookupOutcome::InvalidResponse,
    }
}

async fn lookup_dns_caa_records(
    endpoint: Option<&str>,
    host: &str,
    remaining: std::time::Duration,
) -> (Vec<String>, CaaLookupOutcome) {
    let Some(endpoint) = endpoint else {
        return (Vec::new(), CaaLookupOutcome::NotAttempted);
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        return (Vec::new(), CaaLookupOutcome::Unsupported);
    }
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() {
        return (Vec::new(), CaaLookupOutcome::Unsupported);
    }
    if ["localhost", "local", "invalid"].iter().any(|suffix| {
        lower == *suffix
            || lower
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    }) {
        return (Vec::new(), CaaLookupOutcome::PolicyBlocked);
    }
    if remaining.is_zero() {
        return (Vec::new(), CaaLookupOutcome::Timeout);
    }
    let Ok(mut url) = Url::parse(endpoint) else {
        return (Vec::new(), CaaLookupOutcome::Unsupported);
    };
    if url.scheme() != "https" {
        return (Vec::new(), CaaLookupOutcome::Unsupported);
    }
    url.query_pairs_mut()
        .append_pair("name", &lower)
        .append_pair("type", "CAA");
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .timeout(remaining.min(std::time::Duration::from_secs(3)))
        .user_agent(USER_AGENT)
        .build()
    else {
        return (Vec::new(), CaaLookupOutcome::Unsupported);
    };

    let query = async {
        let response = client
            .get(url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body = response.bytes().await.ok()?;
        if body.len() > 64 * 1024 {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
        Some(value)
    };

    let Some(body) = tokio::time::timeout(remaining, query).await.ok().flatten() else {
        return (Vec::new(), CaaLookupOutcome::Timeout);
    };

    let outcome =
        caa_outcome_for_dns_status(body.get("Status").and_then(serde_json::Value::as_u64));
    if !matches!(outcome, CaaLookupOutcome::NoRecordsObserved) {
        return (Vec::new(), outcome);
    }
    let Some(answers) = body.get("Answer").and_then(serde_json::Value::as_array) else {
        // A successful answer without an `Answer` section is an empty observation.
        return (Vec::new(), outcome);
    };
    let mut records = Vec::new();
    for answer in answers {
        if answer.get("type").and_then(serde_json::Value::as_u64) != Some(257) {
            continue;
        }
        let Some(data) = answer.get("data").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let sanitized: String = data.chars().filter(|c| !c.is_control()).take(256).collect();
        let sanitized = sanitized.trim();
        if sanitized.is_empty() {
            continue;
        }
        records.push(sanitized.to_owned());
        if records.len() >= 16 {
            break;
        }
    }
    if records.is_empty() {
        (records, CaaLookupOutcome::NoRecordsObserved)
    } else {
        (records, CaaLookupOutcome::RecordsObserved)
    }
}

/// Copies DNS CAA observations into the browser evidence so runtime views never need a
/// second lookup. Only observed values are copied; unobserved browser security state
/// stays `None`.
pub fn hydrate_browser_tls_and_caa(snapshot: &mut EvidenceSnapshot) {
    let tls = match &snapshot.tls {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => data,
        CollectorOutcome::Failed { .. } | CollectorOutcome::Skipped { .. } => return,
    };
    // Certificate metadata comes from the completed TLS handshake; negotiated protocol,
    // cipher suite and browser security state are not observed by this collector and stay
    // absent rather than being inferred from the certificate.
    let leaf_certificate = crate::domain::TlsLeafCertificateDiagnostics {
        san_count: u32::try_from(tls.san_entries.len()).unwrap_or(u32::MAX),
        san_entries: tls.san_entries.clone(),
        not_before_unix_secs: tls.not_before_unix_secs,
        not_after_unix_secs: tls.not_after_unix_secs,
        public_key_algorithm: tls.public_key_algorithm.clone(),
        signature_algorithm: tls.signature_algorithm.clone(),
        self_signed: tls.self_signed,
        certificate_transparency_status: crate::domain::CertificateTransparencyStatus::Unknown,
        signed_certificate_timestamp_count: 0,
    };
    let diagnostics = crate::domain::TlsAndCaaDiagnostics {
        protocol_version: None,
        cipher_suite: None,
        browser_security_state: None,
        leaf_certificate: Some(leaf_certificate),
        caa_records: tls.caa_records.clone(),
        caa_query_succeeded: tls.caa_query_succeeded,
        caa_lookup_outcome: tls.caa_lookup_outcome,
    };
    if let CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } =
        &mut snapshot.browser
    {
        data.tls_and_caa = Some(diagnostics);
    }
}

/// Outcome of a conditional HTTP revalidation check (`If-None-Match` / `If-Modified-Since`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionalCheckOutcome {
    /// Server confirmed `304 Not Modified` or an identical `ETag` on the target URL.
    Unchanged,
    /// Resource changed, redirected, failed, or lacked verifiable validator headers.
    ChangedOrUnverifiable,
}

/// Performs a bounded conditional `GET` using `etag` / `last_modified` without
/// following redirects or downloading a full body on `304`.
pub async fn check_if_unchanged(
    target: &AuditTarget,
    etag: Option<&str>,
    last_modified: Option<&str>,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> ConditionalCheckOutcome {
    if etag.is_none() && last_modified.is_none() {
        return ConditionalCheckOutcome::ChangedOrUnverifiable;
    }
    let Ok(pinned_addrs) = resolve_and_validate(target, policy).await else {
        return ConditionalCheckOutcome::ChangedOrUnverifiable;
    };
    let host_for_pin = strip_ipv6_brackets(target.host());
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(budget.http_timeout)
        .user_agent(USER_AGENT)
        .resolve_to_addrs(host_for_pin, &pinned_addrs)
        .build()
    else {
        return ConditionalCheckOutcome::ChangedOrUnverifiable;
    };
    let mut req = client.get(target.as_str());
    if let Some(tag) = etag {
        req = req.header("If-None-Match", tag);
    }
    if let Some(lm) = last_modified {
        req = req.header("If-Modified-Since", lm);
    }
    let Ok(resp) = req.send().await else {
        return ConditionalCheckOutcome::ChangedOrUnverifiable;
    };
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return ConditionalCheckOutcome::Unchanged;
    }
    if resp.status().is_success()
        && let Some(expected_tag) = etag
        && resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|actual| actual == expected_tag)
    {
        return ConditionalCheckOutcome::Unchanged;
    }
    ConditionalCheckOutcome::ChangedOrUnverifiable
}

/// Bounded cache of HTTP clients shared by one crawl.
///
/// A crawl resolves each host once per distinct pinned address set and reuses the resulting
/// client, so connection pools, TLS sessions and resolved addresses are shared between pages
/// instead of rebuilt for every request. Reuse does not weaken SSRF defence: a cached client can
/// only reach the addresses that were validated when it was created, and a fresh resolution that
/// yields different addresses produces a different cache key and therefore a new client.
/// Classification of HTTP 403/429/503 refusal, rate-limit, or WAF challenge responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    /// Explicit rate limiting (`429`, `Retry-After`, or `X-RateLimit-Remaining: 0`).
    RateLimited,
    /// Interactive or automated WAF challenge (e.g. Cloudflare Turnstile/JS challenge).
    WafChallenge,
    /// Hard bot-protection or IP/UA access block (`403` / `406` with WAF markers).
    BotBlocked,
    /// Temporary upstream overload / maintenance (`503`).
    UpstreamUnavailable,
}

#[derive(Debug, Clone)]
struct HostBackoffState {
    consecutive_throttles: u32,
    next_allowed_at: Option<Instant>,
    last_refusal: Option<RefusalKind>,
}

/// Parses an integer-seconds `Retry-After` header value, capped at 30 seconds.
#[must_use]
pub fn parse_retry_after_secs(raw: &str) -> Option<u64> {
    let secs = raw.trim().parse::<u64>().ok()?;
    Some(secs.min(30))
}

/// Classifies an HTTP response as rate-limited, WAF-challenged, bot-blocked, or upstream-unavailable.
#[must_use]
pub fn classify_http_refusal(
    status: u16,
    headers: &[HttpHeader],
    body_text: &str,
) -> Option<RefusalKind> {
    let has_header = |name: &str, needle: Option<&str>| -> bool {
        headers.iter().any(|h| {
            h.name == name && needle.is_none_or(|n| h.value.to_ascii_lowercase().contains(n))
        })
    };

    if status == 429 || has_header("x-ratelimit-remaining", Some("0")) {
        return Some(RefusalKind::RateLimited);
    }

    let body_lower = body_text
        .chars()
        .take(4096)
        .collect::<String>()
        .to_ascii_lowercase();
    let waf_challenge = has_header("cf-mitigated", Some("challenge"))
        || body_lower.contains("just a moment...")
        || body_lower.contains("attention required!")
        || body_lower.contains("checking your browser before accessing");
    if waf_challenge && matches!(status, 403 | 429 | 503) {
        return Some(RefusalKind::WafChallenge);
    }

    let bot_markers = has_header("x-sucuri-id", None)
        || has_header("x-datadome", None)
        || has_header("x-px-vid", None)
        || (has_header("server", Some("cloudflare")) && status == 403)
        || body_lower.contains("access denied")
        || body_lower.contains("request blocked");
    if status == 403 && bot_markers {
        return Some(RefusalKind::BotBlocked);
    }

    if status == 503 {
        return if has_header("retry-after", None) {
            Some(RefusalKind::RateLimited)
        } else {
            Some(RefusalKind::UpstreamUnavailable)
        };
    }

    None
}

/// Reusable per-crawl pool of pinned HTTP clients plus per-host rate-limit backoff state.
///
/// Reuses resolved and SSRF-validated clients across crawl requests without weakening
/// DNS pinning, and coordinates per-host `Retry-After` / exponential backoff across concurrent workers.
pub struct CrawlHttpCache {
    capacity: usize,
    clients: Mutex<HashMap<String, reqwest::Client>>,
    host_backoff: Mutex<HashMap<String, HostBackoffState>>,
}

impl CrawlHttpCache {
    /// Creates a cache holding at most `capacity` clients.
    ///
    /// When the cache is full a new host evicts the whole set rather than growing without bound;
    /// eviction costs a rebuild and never affects results.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            clients: Mutex::new(HashMap::new()),
            host_backoff: Mutex::new(HashMap::new()),
        }
    }

    /// Sleeps briefly if `host` currently has an active rate-limit backoff window,
    /// bounded by `max_wait` so [`ExecutionBudget`] deadlines are respected.
    pub async fn wait_if_backed_off(&self, host: &str, max_wait: std::time::Duration) {
        let key = strip_ipv6_brackets(host).to_ascii_lowercase();
        let remaining = self.host_backoff.lock().ok().and_then(|map| {
            let state = map.get(&key)?;
            let until = state.next_allowed_at?;
            until.checked_duration_since(Instant::now())
        });
        if let Some(delay) = remaining
            && !delay.is_zero()
        {
            tokio::time::sleep(delay.min(max_wait)).await;
        }
    }

    /// Updates per-host backoff and refusal classification from an observed HTTP response.
    pub fn record_response_outcome(
        &self,
        host: &str,
        status: u16,
        retry_after: Option<&str>,
        refusal: Option<RefusalKind>,
    ) {
        let key = strip_ipv6_brackets(host).to_ascii_lowercase();
        let Ok(mut map) = self.host_backoff.lock() else {
            return;
        };
        if (200..400).contains(&status) {
            map.remove(&key);
            return;
        }

        let entry = map.entry(key).or_insert(HostBackoffState {
            consecutive_throttles: 0,
            next_allowed_at: None,
            last_refusal: None,
        });
        entry.last_refusal = refusal;

        if matches!(
            refusal,
            Some(RefusalKind::RateLimited | RefusalKind::UpstreamUnavailable)
        ) {
            entry.consecutive_throttles = entry.consecutive_throttles.saturating_add(1);
            let delay = retry_after.and_then(parse_retry_after_secs).map_or_else(
                || {
                    let shift = entry.consecutive_throttles.saturating_sub(1).min(5);
                    std::time::Duration::from_millis(500 * (1_u64 << shift))
                        .min(std::time::Duration::from_secs(30))
                },
                std::time::Duration::from_secs,
            );
            entry.next_allowed_at = Some(Instant::now() + delay);
        } else if matches!(
            refusal,
            Some(RefusalKind::WafChallenge | RefusalKind::BotBlocked)
        ) {
            entry.next_allowed_at = Some(Instant::now() + std::time::Duration::from_secs(1));
        }
    }

    /// Returns the most recent refusal/WAF classification observed for `host`, if any.
    #[must_use]
    pub fn last_refusal_for_host(&self, host: &str) -> Option<RefusalKind> {
        let key = strip_ipv6_brackets(host).to_ascii_lowercase();
        self.host_backoff
            .lock()
            .ok()
            .and_then(|map| map.get(&key).and_then(|s| s.last_refusal))
    }

    /// Number of clients currently cached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.lock().map_or(0, |clients| clients.len())
    }

    /// `true` when no client is cached yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    async fn client_for(
        &self,
        target: &AuditTarget,
        http_timeout: std::time::Duration,
        policy: TargetPolicy,
    ) -> Result<reqwest::Client, String> {
        let pinned_addrs = resolve_and_validate(target, policy).await?;
        let host_for_pin = strip_ipv6_brackets(target.host());
        let key = format!(
            "{host_for_pin}|{pinned_addrs:?}|{}",
            http_timeout.as_millis()
        );

        if let Ok(clients) = self.clients.lock()
            && let Some(client) = clients.get(&key)
        {
            return Ok(client.clone());
        }

        let client = build_pinned_client(host_for_pin, &pinned_addrs, http_timeout)?;

        if let Ok(mut clients) = self.clients.lock() {
            if clients.len() >= self.capacity {
                clients.clear();
            }
            clients.insert(key, client.clone());
        }
        Ok(client)
    }
}

/// Collects HTTP and TLS evidence for multiple targets with concurrency bounded
/// by `budget.max_concurrency`, preserving input target order.
pub async fn collect_batch(
    targets: Vec<AuditTarget>,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
) -> Vec<EvidenceSnapshot> {
    let limit = budget.max_concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(limit));
    let budget = *budget;
    let mut join_set = JoinSet::new();

    for (idx, target) in targets.into_iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        join_set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let snapshot = collect_http(&target, &budget, policy).await;
            (idx, snapshot)
        });
    }

    let mut ordered: Vec<(usize, EvidenceSnapshot)> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        if let Ok(pair) = res {
            ordered.push(pair);
        }
    }
    ordered.sort_by_key(|(idx, _)| *idx);
    ordered.into_iter().map(|(_, snap)| snap).collect()
}

struct FailedHttpAttempt {
    error: String,
    tls: Option<CollectorOutcome<TlsEvidence>>,
}

impl From<String> for Box<FailedHttpAttempt> {
    fn from(error: String) -> Self {
        Self::new(FailedHttpAttempt { error, tls: None })
    }
}

/// Maps a `reqwest::Version` to its canonical protocol label (`"HTTP/1.1"`, `"HTTP/2"`, etc.).
#[must_use]
pub const fn http_version_label(version: reqwest::Version) -> &'static str {
    match version {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2",
        reqwest::Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/unknown",
    }
}

/// Classifies a `reqwest::Error` into a typed [`crate::domain::TransportErrorKind`].
#[must_use]
pub fn classify_reqwest_error(err: &reqwest::Error) -> crate::domain::TransportErrorKind {
    if err.is_timeout() {
        return crate::domain::TransportErrorKind::Timeout;
    }
    if err.is_redirect() {
        return crate::domain::TransportErrorKind::RedirectLimit;
    }
    crate::domain::classify_transport_error_message(&format_error_chain(err))
}

async fn handle_http_send_error(
    current_target: &AuditTarget,
    policy: TargetPolicy,
    timeout: std::time::Duration,
    err: &reqwest::Error,
) -> Box<FailedHttpAttempt> {
    let kind = classify_reqwest_error(err);
    let error_msg = format!(
        "HTTP request failed [kind={}]: {}",
        kind.as_str(),
        format_error_chain(err)
    );
    let tls_probe = if current_target.scheme() == TargetScheme::Https {
        probe_tls_certificate_unverified(current_target, policy, timeout, &error_msg).await
    } else {
        None
    };
    Box::new(FailedHttpAttempt {
        error: error_msg,
        tls: tls_probe,
    })
}

async fn execute_bounded_get(
    initial_target: &AuditTarget,
    budget: &ExecutionBudget,
    policy: TargetPolicy,
    source: ClientSource<'_>,
) -> Result<(HttpEvidence, CollectorOutcome<TlsEvidence>), Box<FailedHttpAttempt>> {
    let started = Instant::now();
    let mut current_target = initial_target.clone();
    let mut redirect_chain = Vec::new();

    loop {
        let client = match source {
            ClientSource::Cached(cache) => {
                cache
                    .client_for(&current_target, budget.http_timeout, policy)
                    .await?
            }
            ClientSource::Fresh | ClientSource::FreshWithUserAgent(_) => {
                let ua = match source {
                    ClientSource::FreshWithUserAgent(ua) => ua,
                    _ => USER_AGENT,
                };
                let pinned_addrs = resolve_and_validate(&current_target, policy).await?;
                let host_for_pin = strip_ipv6_brackets(current_target.host());
                build_pinned_client_with_ua(host_for_pin, &pinned_addrs, budget.http_timeout, ua)?
            }
        };

        let mut response = match client.get(current_target.as_str()).send().await {
            Ok(resp) => resp,
            Err(err) => {
                return Err(handle_http_send_error(
                    &current_target,
                    policy,
                    budget.http_timeout,
                    &err,
                )
                .await);
            }
        };

        let status = response.status();
        if is_redirect_status(status) {
            if redirect_chain.len() >= budget.max_redirects {
                return Err(Box::<FailedHttpAttempt>::from(format!(
                    "exceeded maximum redirect limit of {}",
                    budget.max_redirects
                )));
            }

            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    Box::<FailedHttpAttempt>::from(format!(
                        "redirect status {status} missing valid Location header"
                    ))
                })?;

            let next_url = resolve_redirect_url(current_target.as_str(), location)?;
            let next_target = AuditTarget::parse(next_url.as_str(), policy).map_err(|e| {
                Box::<FailedHttpAttempt>::from(format!("redirect target rejected: {e}"))
            })?;

            redirect_chain.push(RedirectHop {
                from_url: current_target.as_str().to_owned(),
                status_code: status.as_u16(),
                to_url: next_target.as_str().to_owned(),
            });

            current_target = next_target;
            continue;
        }

        let headers: Vec<HttpHeader> = response
            .headers()
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.as_str().to_ascii_lowercase(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            })
            .collect();

        let tls = extract_tls_evidence(&current_target, &response, captured_now_i64());

        let body_cap = if is_non_textual_content_type(&headers) {
            0
        } else {
            budget.max_response_bytes
        };
        let (raw_body, body_truncated) = read_bounded_body(&mut response, body_cap).await?;
        let (body, decoded_truncated) =
            decode_body_encoding(&raw_body, &headers, current_target.as_str(), body_cap);
        let body_truncated = body_truncated || decoded_truncated;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let body_text = decode_body_text(&body, &headers);

        return Ok((
            HttpEvidence {
                final_url: current_target.as_str().to_owned(),
                status_code: status.as_u16(),
                redirect_chain,
                headers,
                elapsed_ms: Measurement::Measured {
                    value: elapsed_ms,
                    unit: MeasurementUnit::Milliseconds,
                },
                body_bytes: body.len(),
                body_truncated,
                body_text,
            },
            tls,
        ));
    }
}

/// Builds a pinned HTTP client that advertises compression (`Accept-Encoding`) while disabling
/// `reqwest`'s automatic decompression so `Content-Encoding` and `Content-Length` headers remain
/// intact for deterministic evidence inspection.
fn build_pinned_client(
    host_for_pin: &str,
    pinned_addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    build_pinned_client_with_ua(host_for_pin, pinned_addrs, timeout, USER_AGENT)
}

fn build_pinned_client_with_ua(
    host_for_pin: &str,
    pinned_addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
    user_agent: &str,
) -> Result<reqwest::Client, String> {
    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("gzip, br, zstd, deflate"),
    );

    reqwest::Client::builder()
        .no_proxy()
        .tls_info(true)
        .redirect(Policy::none())
        .timeout(timeout)
        .user_agent(user_agent)
        .default_headers(default_headers)
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .resolve_to_addrs(host_for_pin, pinned_addrs)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

/// Decodes response bytes into UTF-8 using the charset declared in HTTP `Content-Type`,
/// HTML `<meta charset>` / `<meta http-equiv="content-type">`, or BOM, falling back to lossy UTF-8.
fn decode_body_text(body: &[u8], headers: &[HttpHeader]) -> String {
    let header_charset = headers
        .iter()
        .find(|h| h.name == "content-type")
        .and_then(|h| extract_charset_param(&h.value));
    let label = header_charset.or_else(|| sniff_html_meta_charset(body));
    if let Some(ref charset) = label
        && let Some(encoding) = encoding_rs::Encoding::for_label(charset.as_bytes())
        && encoding != encoding_rs::UTF_8
    {
        return encoding.decode_without_bom_handling(body).0.into_owned();
    }
    if let Some((encoding, bom_len)) = encoding_rs::Encoding::for_bom(body)
        && encoding != encoding_rs::UTF_8
    {
        return encoding
            .decode_without_bom_handling(&body[bom_len..])
            .0
            .into_owned();
    }
    String::from_utf8_lossy(body).into_owned()
}

fn extract_charset_param(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let idx = lower.find("charset=")?;
    let rest = value[idx + 8..].trim_start();
    let raw = if let Some(quoted) = rest.strip_prefix('"') {
        quoted.split('"').next().unwrap_or_default()
    } else if let Some(quoted) = rest.strip_prefix('\'') {
        quoted.split('\'').next().unwrap_or_default()
    } else {
        rest.split([';', ' ', '\t', '\r', '\n', '>'])
            .next()
            .unwrap_or_default()
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn sniff_html_meta_charset(body: &[u8]) -> Option<String> {
    let head = &body[..body.len().min(2048)];
    let ascii = String::from_utf8_lossy(head);
    let lower = ascii.to_ascii_lowercase();
    let meta_pos = lower.find("<meta")?;
    let rest = &ascii[meta_pos..];
    extract_charset_param(rest)
}

/// Returns `true` when `content-type` is clearly binary/non-HTML (PDF, archive, media, font)
/// so page acquisition avoids downloading up to 10 MiB of non-document bytes.
fn is_non_textual_content_type(headers: &[HttpHeader]) -> bool {
    let Some(ct) = headers
        .iter()
        .find(|h| h.name == "content-type")
        .map(|h| h.value.to_ascii_lowercase())
    else {
        return false;
    };
    ct.starts_with("image/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct.starts_with("font/")
        || ct.contains("application/pdf")
        || ct.contains("application/zip")
        || ct.contains("application/octet-stream")
}

/// Decompresses `raw_body` when `content-encoding` specifies `gzip`, `br`, `zstd`, or `deflate`
/// (or when a `.gz` / `application/gzip` payload starts with the gzip magic header), bounding
/// output to `max_bytes` to prevent decompression bombs.
fn decode_body_encoding(
    raw_body: &[u8],
    headers: &[HttpHeader],
    url: &str,
    max_bytes: usize,
) -> (Vec<u8>, bool) {
    use std::io::Read as _;

    let encoding = headers
        .iter()
        .find(|h| h.name == "content-encoding")
        .map(|h| h.value.to_ascii_lowercase());
    let is_gzip_payload = encoding.as_deref().is_some_and(|e| e.contains("gzip"))
        || (encoding.is_none()
            && raw_body.starts_with(&[0x1f, 0x8b])
            && (url.to_ascii_lowercase().ends_with(".gz")
                || headers.iter().any(|h| {
                    h.name == "content-type" && h.value.to_ascii_lowercase().contains("gzip")
                })));

    let cap = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    let mut out = Vec::new();
    let res = if is_gzip_payload {
        let decoder = flate2::read::GzDecoder::new(raw_body);
        decoder.take(cap.saturating_add(1)).read_to_end(&mut out)
    } else if let Some(ref enc) = encoding {
        if enc.contains("br") {
            let decoder = brotli::Decompressor::new(raw_body, 4096);
            decoder.take(cap.saturating_add(1)).read_to_end(&mut out)
        } else if enc.contains("zstd") {
            match zstd::stream::read::Decoder::new(raw_body) {
                Ok(decoder) => decoder.take(cap.saturating_add(1)).read_to_end(&mut out),
                Err(e) => Err(e),
            }
        } else if enc.contains("deflate") {
            let decoder = flate2::read::ZlibDecoder::new(raw_body);
            decoder.take(cap.saturating_add(1)).read_to_end(&mut out)
        } else {
            return (raw_body.to_vec(), false);
        }
    } else {
        return (raw_body.to_vec(), false);
    };

    match res {
        Ok(_) => {
            let truncated = out.len() > max_bytes;
            if truncated {
                out.truncate(max_bytes);
            }
            (out, truncated)
        }
        Err(_) if !out.is_empty() => {
            if out.len() > max_bytes {
                out.truncate(max_bytes);
            }
            (out, true)
        }
        Err(_) => (raw_body.to_vec(), false),
    }
}

fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut current = err.source();
    let mut depth = 0usize;
    while let Some(source) = current
        && depth < 6
    {
        let text = source.to_string();
        if parts.last().is_none_or(|prev| prev != &text) {
            parts.push(text);
        }
        current = source.source();
        depth += 1;
    }
    parts.join(": ")
}

/// Performs a strictly diagnostic-only TLS handshake when verified HTTPS collection failed,
/// capturing peer certificate metadata (for example expiry) without ever reading HTTP content.
async fn probe_tls_certificate_unverified(
    target: &AuditTarget,
    policy: TargetPolicy,
    timeout: std::time::Duration,
    verification_error: &str,
) -> Option<CollectorOutcome<TlsEvidence>> {
    let pinned_addrs = resolve_and_validate(target, policy).await.ok()?;
    let host_for_pin = strip_ipv6_brackets(target.host());
    let client = reqwest::Client::builder()
        .no_proxy()
        .tls_info(true)
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .timeout(timeout.min(std::time::Duration::from_secs(5)))
        .user_agent(USER_AGENT)
        .resolve_to_addrs(host_for_pin, &pinned_addrs)
        .build()
        .ok()?;
    let response = client.head(target.as_str()).send().await.ok()?;
    match extract_tls_evidence(target, &response, captured_now_i64()) {
        CollectorOutcome::Captured { data } | CollectorOutcome::Partial { data, .. } => {
            Some(CollectorOutcome::Partial {
                data,
                warnings: vec![format!(
                    "TLS verification failed ({verification_error}); certificate captured via diagnostic probe"
                )],
            })
        }
        other => Some(other),
    }
}

fn captured_now_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn extract_tls_evidence(
    target: &AuditTarget,
    response: &reqwest::Response,
    now_unix_secs: i64,
) -> CollectorOutcome<TlsEvidence> {
    if target.scheme() != TargetScheme::Https {
        return CollectorOutcome::Skipped {
            reason: "target did not use HTTPS".to_owned(),
        };
    }

    let Some(tls_info) = response.extensions().get::<TlsInfo>() else {
        return CollectorOutcome::Failed {
            error: "TLS handshake info unavailable from HTTP client".to_owned(),
        };
    };

    let Some(der) = tls_info.peer_certificate() else {
        return CollectorOutcome::Failed {
            error: "no peer certificate presented during TLS handshake".to_owned(),
        };
    };

    match X509Certificate::from_der(der) {
        Ok((_, cert)) => {
            let not_before = Some(cert.validity().not_before.timestamp());
            let not_after = cert.validity().not_after.timestamp();
            let days_until_expiry = (not_after - now_unix_secs).div_euclid(86_400);
            let subject_alt_names = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|ext| {
                    ext.value
                        .general_names
                        .iter()
                        .filter_map(|gn| match gn {
                            x509_parser::extensions::GeneralName::DNSName(dns) => {
                                Some((*dns).to_owned())
                            }
                            x509_parser::extensions::GeneralName::IPAddress(ip) => {
                                Some(format!("{ip:?}"))
                            }
                            _ => None,
                        })
                        .take(32)
                        .collect()
                })
                .unwrap_or_default();
            let signature_algorithm = Some(cert.signature_algorithm.algorithm.to_id_string());
            let spki = cert.public_key();
            let public_key_algorithm = Some(spki.algorithm.algorithm.to_id_string());
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let self_signed = subject == issuer;
            CollectorOutcome::Captured {
                data: TlsEvidence {
                    subject,
                    issuer,
                    not_before_unix_secs: not_before,
                    not_after_unix_secs: not_after,
                    days_until_expiry,
                    san_entries: subject_alt_names,
                    signature_algorithm,
                    public_key_algorithm,
                    self_signed,
                    caa_records: Vec::new(),
                    caa_query_succeeded: false,
                    caa_lookup_outcome: CaaLookupOutcome::NotAttempted,
                },
            }
        }
        Err(err) => CollectorOutcome::Failed {
            error: format!("failed to parse X.509 peer certificate: {err}"),
        },
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

    #[tokio::test]
    async fn collect_batch_preserves_order_with_bounded_concurrency() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\na",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb",
        ])
        .await;

        let t1 =
            AuditTarget::parse(&format!("http://{addr}/1"), TargetPolicy::AllowPrivate).unwrap();
        let t2 =
            AuditTarget::parse(&format!("http://{addr}/2"), TargetPolicy::AllowPrivate).unwrap();
        let budget = ExecutionBudget {
            max_concurrency: 1,
            ..ExecutionBudget::default()
        };

        let snaps = collect_batch(
            vec![t1.clone(), t2.clone()],
            &budget,
            TargetPolicy::AllowPrivate,
        )
        .await;
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].target, t1);
        assert_eq!(snaps[1].target, t2);
    }

    #[tokio::test]
    async fn check_if_unchanged_respects_304_and_missing_validators() {
        let addr = spawn_mock_server(vec![
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nETag: \"v2\"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        ])
        .await;
        let target =
            AuditTarget::parse(&format!("http://{addr}/page"), TargetPolicy::AllowPrivate).unwrap();
        let budget = ExecutionBudget::default();

        // No validators -> unverifiable without any HTTP request.
        assert_eq!(
            check_if_unchanged(&target, None, None, &budget, TargetPolicy::AllowPrivate).await,
            ConditionalCheckOutcome::ChangedOrUnverifiable
        );
        // 304 Not Modified -> Unchanged.
        assert_eq!(
            check_if_unchanged(
                &target,
                Some("\"v1\""),
                None,
                &budget,
                TargetPolicy::AllowPrivate
            )
            .await,
            ConditionalCheckOutcome::Unchanged
        );
        // Changed ETag -> ChangedOrUnverifiable.
        assert_eq!(
            check_if_unchanged(
                &target,
                Some("\"v1\""),
                None,
                &budget,
                TargetPolicy::AllowPrivate
            )
            .await,
            ConditionalCheckOutcome::ChangedOrUnverifiable
        );
    }
}

#[cfg(test)]
mod caa_tests {
    use std::time::Duration;

    use super::{caa_outcome_for_dns_status, lookup_dns_caa_records};
    use crate::domain::CaaLookupOutcome;

    #[test]
    fn dns_response_codes_map_to_explicit_caa_outcomes() {
        assert_eq!(
            caa_outcome_for_dns_status(Some(0)),
            CaaLookupOutcome::NoRecordsObserved
        );
        assert_eq!(
            caa_outcome_for_dns_status(Some(2)),
            CaaLookupOutcome::ServerFailure
        );
        assert_eq!(
            caa_outcome_for_dns_status(Some(3)),
            CaaLookupOutcome::NameDoesNotExist
        );
        assert_eq!(
            caa_outcome_for_dns_status(Some(5)),
            CaaLookupOutcome::Refused
        );
        assert_eq!(
            caa_outcome_for_dns_status(None),
            CaaLookupOutcome::InvalidResponse
        );
        assert_eq!(
            caa_outcome_for_dns_status(Some(99)),
            CaaLookupOutcome::InvalidResponse
        );
    }

    #[tokio::test]
    async fn absent_resolver_configuration_is_not_attempted() {
        let (records, outcome) =
            lookup_dns_caa_records(None, "example.org", Duration::from_secs(1)).await;
        assert_eq!(records.len(), 0, "expected no CAA records");
        assert_eq!(outcome, CaaLookupOutcome::NotAttempted);
    }

    #[tokio::test]
    async fn loopback_and_local_names_are_policy_blocked() {
        let (records, outcome) = lookup_dns_caa_records(
            Some("https://cloudflare-dns.com/dns-query"),
            "localhost",
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(records.len(), 0, "expected no CAA records");
        assert_eq!(outcome, CaaLookupOutcome::PolicyBlocked);

        let (_, outcome) = lookup_dns_caa_records(
            Some("https://cloudflare-dns.com/dns-query"),
            "127.0.0.1",
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(outcome, CaaLookupOutcome::Unsupported);
    }

    #[tokio::test]
    async fn collect_http_sends_accept_encoding_and_preserves_content_encoding() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        const GZIP_BODY: &[u8] = &[
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 179, 201, 40, 201, 205, 177, 179, 73, 202, 79, 169,
            180, 75, 28, 5, 163, 96, 20, 140, 2, 42, 0, 27, 125, 112, 145, 98, 163, 15, 46, 95, 0,
            83, 170, 7, 45, 102, 4, 0, 0,
        ];

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();

        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0_u8; 4096];
            let n = sock.read(&mut buf).await.expect("read");
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(req);

            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                GZIP_BODY.len()
            );
            sock.write_all(header.as_bytes()).await.expect("write hdr");
            sock.write_all(GZIP_BODY).await.expect("write body");
            let _ = sock.shutdown().await;
        });

        let target = crate::domain::AuditTarget::parse(
            &format!("http://{addr}/"),
            crate::domain::TargetPolicy::AllowPrivate,
        )
        .expect("target");
        let budget = crate::domain::ExecutionBudget::default();
        let snapshot =
            super::collect_http(&target, &budget, crate::domain::TargetPolicy::AllowPrivate).await;

        let req_text = rx.await.expect("req");
        let lower_req = req_text.to_ascii_lowercase();
        assert!(
            lower_req.contains("accept-encoding:") && lower_req.contains("gzip"),
            "expected Accept-Encoding with gzip, got:\n{req_text}"
        );

        let crate::domain::CollectorOutcome::Captured { data } = snapshot.http else {
            panic!("expected captured HTTP, got: {:?}", snapshot.http);
        };
        assert!(
            data.body_text.contains("<html><body>"),
            "expected decompressed HTML body, got: {}",
            &data.body_text[..data.body_text.len().min(80)]
        );
        assert!(
            data.headers
                .iter()
                .any(|h| h.name == "content-encoding" && h.value.contains("gzip")),
            "expected content-encoding header to be preserved, got: {:?}",
            data.headers
        );
    }

    #[test]
    fn decode_body_text_decodes_windows_1250_and_iso_8859_2() {
        let (encoded, _, _) = encoding_rs::WINDOWS_1250.encode("Zażółć gęślą jaźń");
        let headers = vec![crate::domain::HttpHeader {
            name: "content-type".to_owned(),
            value: "text/html; charset=windows-1250".to_owned(),
        }];
        let decoded = super::decode_body_text(&encoded, &headers);
        assert_eq!(decoded, "Zażółć gęślą jaźń");
    }

    #[test]
    fn classifies_refusal_waf_and_tracks_per_host_backoff() {
        assert_eq!(super::parse_retry_after_secs("5"), Some(5));
        assert_eq!(super::parse_retry_after_secs("999"), Some(30));
        assert_eq!(super::parse_retry_after_secs("invalid"), None);

        let cf_headers = vec![crate::domain::HttpHeader {
            name: "cf-mitigated".to_owned(),
            value: "challenge".to_owned(),
        }];
        assert_eq!(
            super::classify_http_refusal(403, &cf_headers, "<html>Just a moment...</html>"),
            Some(super::RefusalKind::WafChallenge)
        );
        assert_eq!(
            super::classify_http_refusal(429, &[], ""),
            Some(super::RefusalKind::RateLimited)
        );
        assert_eq!(
            super::classify_http_refusal(503, &[], ""),
            Some(super::RefusalKind::UpstreamUnavailable)
        );

        let cache = super::CrawlHttpCache::new(4);
        cache.record_response_outcome(
            "api.example.com",
            429,
            Some("2"),
            Some(super::RefusalKind::RateLimited),
        );
        assert_eq!(
            cache.last_refusal_for_host("api.example.com"),
            Some(super::RefusalKind::RateLimited)
        );
        assert_eq!(cache.last_refusal_for_host("other.example.com"), None);

        cache.record_response_outcome("api.example.com", 200, None, None);
        assert_eq!(cache.last_refusal_for_host("api.example.com"), None);
    }

    #[tokio::test]
    async fn probe_collector_captures_well_known_and_soft_404_baseline_within_bounds() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            for _ in 0..8 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let (status, body) = match path {
                        "/.well-known/security.txt" => {
                            ("200 OK", "Contact: mailto:sec@example.com\n")
                        }
                        _ => ("404 Not Found", "not found"),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let target = crate::domain::AuditTarget::parse(
            &format!("http://{addr}/"),
            crate::domain::TargetPolicy::AllowPrivate,
        )
        .expect("target");
        let collector = super::ProbeCollector {
            max_well_known_probes: 2,
            max_preview_bytes: 512,
        };
        let probes = collector
            .collect_origin_probes(
                &target,
                crate::domain::TargetPolicy::AllowPrivate,
                &crate::domain::ExecutionBudget::default(),
                &["/.well-known/security.txt", "/llms.txt", "/humans.txt"],
            )
            .await;

        assert_eq!(probes.well_known.len(), 3);
        assert!(matches!(
            &probes.well_known[0].outcome,
            crate::domain::CollectorOutcome::Captured { data }
                if data.status_code == 200 && data.body_preview.contains("mailto:sec@example.com")
        ));
        assert!(matches!(
            &probes.well_known[1].outcome,
            crate::domain::CollectorOutcome::Captured { data } if data.status_code == 404
        ));
        assert!(matches!(
            &probes.well_known[2].outcome,
            crate::domain::CollectorOutcome::Skipped { .. }
        ));
        assert_eq!(
            probes.soft_404_baseline.as_ref().map(|b| b.probe_status),
            Some(404)
        );
    }

    #[test]
    fn parses_alt_svc_protocols_and_classifies_transport_errors() {
        let http = crate::domain::HttpEvidence {
            final_url: "https://example.com/".to_owned(),
            status_code: 200,
            redirect_chain: Vec::new(),
            headers: vec![crate::domain::HttpHeader {
                name: "alt-svc".to_owned(),
                value: r#"h3=":443"; ma=86400, h2=":443""#.to_owned(),
            }],
            elapsed_ms: crate::domain::Measurement::Unavailable {
                reason: "unit test".to_owned(),
            },
            body_bytes: 0,
            body_truncated: false,
            body_text: String::new(),
        };
        assert_eq!(http.alt_svc_protocols(), vec!["h3", "h2"]);
        assert!(http.supports_http3_alt_svc());
        assert_eq!(
            super::http_version_label(reqwest::Version::HTTP_2),
            "HTTP/2"
        );

        assert_eq!(
            crate::domain::classify_transport_error_message("certificate expired"),
            crate::domain::TransportErrorKind::CertificateExpired
        );
        assert_eq!(
            crate::domain::classify_transport_error_message("unknown issuer in chain"),
            crate::domain::TransportErrorKind::CertificateUntrusted
        );
        assert_eq!(
            crate::domain::classify_transport_error_message("operation timed out"),
            crate::domain::TransportErrorKind::Timeout
        );
    }

    #[tokio::test]
    async fn probes_user_agent_profiles_for_blocking_and_cloaking() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            for _ in 0..3 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
                    let (status, body) = if req.contains("gptbot") {
                        (
                            "403 Forbidden",
                            "<html><body>Access denied for AI crawlers</body></html>".to_owned(),
                        )
                    } else if req.contains("googlebot") {
                        (
                            "200 OK",
                            format!(
                                "<html><body><main>{}</main></body></html>",
                                "seo keyword spam ".repeat(40)
                            ),
                        )
                    } else {
                        (
                            "200 OK",
                            format!(
                                "<html><body><main>{}</main></body></html>",
                                "genuine human product description ".repeat(30)
                            ),
                        )
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let target = crate::domain::AuditTarget::parse(
            &format!("http://{addr}/"),
            crate::domain::TargetPolicy::AllowPrivate,
        )
        .expect("target");
        let results = super::probe_user_agent_profiles(
            &target,
            &crate::domain::ExecutionBudget::default(),
            crate::domain::TargetPolicy::AllowPrivate,
            &[
                super::UserAgentProfile::DesktopBrowser,
                super::UserAgentProfile::AiAgent,
                super::UserAgentProfile::SearchCrawler,
            ],
        )
        .await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].status_code, Some(200));
        assert!(!results[0].blocked_or_refused);
        assert!(!results[0].cloaking_suspected);

        assert_eq!(results[1].status_code, Some(403));
        assert!(results[1].blocked_or_refused);
        assert!(results[1].cloaking_suspected);

        assert_eq!(results[2].status_code, Some(200));
        assert!(!results[2].blocked_or_refused);
        assert!(results[2].cloaking_suspected);
    }

    #[tokio::test]
    async fn checks_external_links_within_cap_and_distinguishes_broken_from_403() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            for _ in 0..3 {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/");
                    let status = match path {
                        "/ok" => "200 OK",
                        "/blocked" => "403 Forbidden",
                        _ => "404 Not Found",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        let urls = vec![
            format!("http://{addr}/ok"),
            format!("http://{addr}/blocked"),
            format!("http://{addr}/missing"),
            format!("http://{addr}/ignored-by-cap"),
        ];
        let results = super::check_external_links(
            &urls,
            &crate::domain::ExecutionBudget::default(),
            crate::domain::TargetPolicy::AllowPrivate,
            3,
        )
        .await;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].status_code, Some(200));
        assert!(!results[0].broken);
        assert_eq!(results[1].status_code, Some(403));
        assert!(!results[1].broken);
        assert_eq!(results[2].status_code, Some(404));
        assert!(results[2].broken);
    }
}
