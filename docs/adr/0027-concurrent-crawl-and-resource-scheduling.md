# 0027. Concurrent Crawl and Resource Scheduling

## Status

Accepted — 2026-11-27

## Context

`discovery::crawl_and_cluster` walks a `VecDeque` and calls `collection::collect_http` once per
iteration. Throughput is therefore one request per round trip, regardless of budget, and the crawl
holds no shared client, no per-origin limit and no in-flight deduplication. Two pages that
reference the same stylesheet cause two independent fetches if either is fetched at all.

The existing collection layer already enforces the properties that must survive concurrency:
target validation, policy checks, redirect handling, payload caps and process-group cleanup. Any
scheduling design must reuse it rather than bypass it.

## Decision

Acquisition is scheduled, not looped.

- **Bounded worker pools.** A fixed number of acquisition workers consume from a bounded queue.
  Concurrency is configured, never implicit, and never one task per discovered URL.
- **Two limits, both enforced.** A global concurrency limit and a per-origin limit. The per-origin
  limit is lower by default, because most audits target a single origin and politeness matters
  more than peak throughput.
- **Deduplicated frontier.** A URL enters the frontier at most once per run. Identity is the
  normalised URL (scheme, host, case-normalised path, sorted query where applicable). A second
  discovery of the same identity records provenance and does not enqueue a duplicate.
- **Single-flight resource acquisition.** A resource representation keyed by
  `(normalised URL, representation discriminator)` is fetched at most once while in flight or
  retained. N page references produce one acquisition and N page-to-resource relationships.
- **Shared client infrastructure.** One HTTP client per run, with connection reuse, keep-alive and
  a DNS policy that preserves the existing validation. Connection reuse must not permit a
  resolved-address change to bypass target validation: a redirect or a new host is revalidated
  before use.
- **Priority scheduling.** The frontier is a priority queue. Seeds, sitemap entries, shallow pages
  and business-relevant page types outrank deep listing pages. Priority is derived from depth,
  discovery source and page classification, and ties break on discovery order so results are
  deterministic.
- **Rate limiting.** A token-bucket per origin. A rate limit is a delay, not a failure.
- **Backpressure.** Queues are bounded. When a queue is full, discovery blocks or drops with an
  explicit recorded reason; it never grows without limit.
- **Deadline enforcement.** No acquisition starts after the global deadline. In-flight requests
  are cancelled through the existing cooperative cancellation channel, and their outcome is
  recorded as `Cancelled`, not as `Failed`.
- **Retry classification.** Only transport-level, idempotent-retryable failures are retried, with
  bounded attempts and backoff. A 4xx is a result, not a retry. A policy block is terminal.
- **Explicit partial completion.** A crawl that ends by deadline, budget or cancellation reports
  which URLs were queued, in flight, skipped and unvisited. It never reports itself as complete.
- **Deterministic ordering.** Pages, resources and findings are emitted in stable identity order
  regardless of completion order. Completion order may influence nothing user-visible.

## Alternatives considered

**Unbounded `tokio::spawn` per URL with a semaphore.** Rejected: the semaphore bounds concurrency
but not queue growth, and per-URL task bodies duplicate connection and deduplication logic.

**Futures unordered over a vector of URLs.** Rejected: the URL set is not known in advance; the
frontier grows as pages are parsed.

**Per-origin concurrency only.** Rejected: a multi-origin audit would then be bounded only by the
number of origins, which is unbounded.

**A dedicated crawl crate.** Rejected for now: the frontier is small enough that the scheduling
semantics — priority, deduplication, single-flight, cancellation, coverage — are the hard part,
and they are project-specific. A dependency would hide them.

## Consequences

- `CrawlSummary` gains queue and worker accounting: queued, in flight, completed, failed,
  cancelled, skipped by budget and skipped by policy.
- Discovery source becomes part of every discovered URL record, because priority and orphan
  reasoning both depend on it.
- Tests must cover duplicate discovery, duplicate in-flight resource requests, per-origin limiting,
  queue saturation, deadline expiry and cancellation, all against a loopback fixture server.
- Sequential `crawl_and_cluster` is retained only as a compatibility wrapper if callers depend on
  it; otherwise it is replaced outright.
