# Evidence store

The evidence store is the durable, application-wide record of what reconnaissance
observed. It exists because a page-level `EvidenceSnapshot` cannot hold an
application: a crawl discovers hundreds of URLs, acquires shared subresources once
each, clusters findings across templates, and needs its coverage denominators to
survive the process that produced them.

Implementation: `src/evidence_store.rs`. Engine decision: ADR 0032, amended by
ADR 0033 (Turso Database, MVCC).

## What is stored in schema version 2

| Table | Contents |
| --- | --- |
| `runs` | One row per recorded crawl: identity, seed, recording time, completeness, the full page and resource coverage counters, and the robots outcome |
| `pages` | One row per discovered URL with depth, inferred page type and explicit crawl status |
| `resources` | One row per acquired subresource with kind, status, HTTP status, declared content type and encoding, observed byte length, `Cache-Control`, `ETag`/`Last-Modified` presence, truncation and failure reason |
| `systemic_issues` | One row per cross-page cluster with rule identity, affected breadth, classification and summary |

`PRAGMA user_version` carries the schema version. Migrations are forward-only: a
store written by a newer build is refused with an explicit version pair rather than
partially interpreted, and an older store is upgraded in place by applying each
step in order.

Version 2 added the five resource fields that version 1 used in memory and then
dropped. Its header flags are nullable rather than defaulted, so a row written by
version 1 reads back as *not stored* instead of claiming that a response carried no
`ETag`. The reader keeps that distinction: `etag_present == Some(false)` is an
observed absence, `None` is an absence of evidence.

## Contracts

- **Typed facade.** Callers see `EvidenceStore`, `CrawlRecord`, `StoredCoverage`,
  `StoredPage`, `StoredResourceCoverage`, `StoredRun`, `StoredSystemicIssue`. No
  engine type appears in a signature.
- **Atomic batches.** A run row, its pages, its resources and its clusters are
  written in one `BEGIN CONCURRENT` transaction. A finding can never reference
  evidence that was not committed.
- **Idempotent observations.** Page, resource and cluster rows are keyed on their
  stable identity and inserted with `ON CONFLICT DO NOTHING`, so a retried batch
  cannot duplicate evidence. A repeated `run_id` is refused, because two different
  crawls under one identity would silently merge.
- **Bounded writes.** At most four write connections, independent of crawl
  concurrency, with a bounded exponential backoff on `Busy`, `BusySnapshot` or a
  conflict error. Exhausting the retry budget reports `WriteConflict`; it never
  becomes a successful collection.
- **Bounded reads.** Every read clamps its limit to 256 rows. Absence is `None`,
  never a zeroed record.
- **Local only.** A single file on disk. No service, no remote endpoint, no
  synchronisation.

## Producers

`nzw scan` is the first production writer. It opens `.nzw/evidence/evidence.db`
(overridable with `--evidence-dir`), records one run per reconnaissance and prints
the coverage it retained. A failed store write is reported on stderr and exits
non-zero: a persistence failure must not look like a successful run.

`nzw patrol` and `nzw investigate` do not write to the store yet. Patrol still runs
its own sampling pipeline rather than the concurrent crawl, and unifying the two is
scheduled with the adaptive-sampling work; until then the store has exactly one
producer and the patrol report remains its only record.

## What is not stored yet

Schema version 2 deliberately stops at the observations the crawler already
produces. Not yet persisted:

- per-page findings and their evidence references;
- page-to-resource edges, which shared-resource blast-radius analysis needs;
- typed observation bodies beyond the coverage counters;
- historical comparisons and cache entries.

Each of these is an explicit migration rather than a silent widening of an existing
column, and each must keep the ADR 0016 measurement-honesty contracts: a missing
observation is absent, not zero.

## Recovery behaviour

Verified by tests and by the adoption spike (ADR 0033):

- a statement failing mid-transaction leaves no rows after `ROLLBACK`;
- a connection dropped without `COMMIT` publishes nothing after reopen;
- the journal mode remains `mvcc` across a reopen;
- foreign keys reject an orphan row when enabled.
