# ADR 0032: Evidence Store Technology

## Status

Accepted — 2026-11-27.

Amends the conditional decision recorded in ADR 0028 by resolving the spike it
required. ADR 0028 remains the authoritative description of the conceptual data
model, cache layers and retention rules; this record covers only the storage
technology choice and the measurements behind it.

## Context

ADR 0028 left the storage technology open: SQLite via a pure-Rust embedded
binding, conditional on a measured spike, with a typed append-only segment store
as the fallback. The reconnaissance engine needs four aggregates repeatedly
during a run and afterwards:

1. systemic ranking — findings grouped by rule, ordered by affected population;
2. template family population — pages per template with the affected share;
3. shared resource dependents — pages per resource, ordered by leverage;
4. coverage denominators — pages partitioned by acquisition outcome.

The question was not "which database is fashionable" but whether an embedded
SQLite file earns its dependency, build cost and migration obligation, given
that the project already persists JSONL reports.

## Measurement

`tests/evidence_store_spike.rs` builds a deterministic synthetic population and
loads it twice: once into SQLite (`rusqlite` with `bundled`), once into the JSONL
representation the project already uses, aggregated in memory. Both
implementations must return identical answers; the harness asserts that, so a
divergence is a correctness defect rather than measurement noise.

Measurements from one machine (Apple silicon, release profile, 2026-11-27), two
populations of identical shape:

| Operation | 5 000 pages | 50 000 pages |
| --- | --- | --- |
| SQLite insert, one transaction | 52 ms | 431 ms |
| JSONL write | 6 ms | 52 ms |
| JSONL read and parse | 9 ms | 88 ms |
| SQLite file size | 1.7 MB | 17.8 MB |
| JSONL file size | 2.5 MB | 26.1 MB |
| Systemic ranking — SQLite | 0.80 ms | 6.5 ms |
| Systemic ranking — in memory | 0.44 ms | 4.6 ms |
| Template population — SQLite | 6.4 ms | 59 ms |
| Template population — in memory | 1.2 ms | 12.5 ms |
| Resource dependents — SQLite | 5.3 ms | 66 ms |
| Resource dependents — in memory | 0.76 ms | 8.4 ms |
| Coverage — SQLite | 0.83 ms | 8.2 ms |
| Coverage — in memory | 0.03 ms | 0.33 ms |

Population at 50 000 pages: 50 000 pages, 3 125 resources, 150 000 page-to-resource
edges, 120 000 findings.

## Decision

Adopt SQLite through `rusqlite` with the `bundled` feature as the durable
application-wide evidence store.

## Rationale

SQLite is **slower** than the in-memory path for whole-population aggregates at
both measured scales. That is reported plainly rather than hidden, because it
decides what the store is for: it is not a faster cache, it is a durable one.

The measurements support the choice for reasons that are not latency:

- **Bounded memory.** The in-memory path is faster only because everything is
  resident. The 50 000-page population is a 26 MB file and a substantially
  larger parsed structure; a store that must materialise the whole population to
  answer "which resources have the most dependents" cannot be pointed at a large
  application without an unbounded memory commitment.
- **Incremental access.** A run that is interrupted, or a query issued days
  later, reads only the pages it needs instead of reparsing 26 MB.
- **Transactions.** A crawl writes pages, resources, edges, findings and
  coverage as one unit. Torn writes would make coverage denominators disagree
  with the findings they are supposed to bound.
- **Selective queries are what the engine actually issues.** The four measured
  aggregates scan the whole population. Most real queries — dependents of one
  resource, findings for one template, a page's observations — are index lookups,
  where SQLite's advantage is structural rather than measured here.
- **No server, no daemon, one file.** Consistent with local-first operation, and
  the file can be deleted, copied or inspected with standard tools.

## Rejected alternatives

- **JSONL only, aggregated in memory.** Adequate at 5 000 pages; requires full
  loads, unbounded memory, and hand-written aggregation for every new question.
  Retained for reports and patrol memory, where append-only history is the right
  shape.
- **`redb`.** Pure Rust and dependency-light, but a key-value store: every
  aggregate above would be a hand-written index maintained by this project, which
  is the problem a query language exists to solve.
- **External database server.** Violates local-first operation and adds an
  operational dependency for a tool people run on a laptop.
- **DuckDB or a columnar engine.** Better for analytical scans, but the write
  path is transactional per-run and the read path is selective; the dependency
  and build cost are not justified by measurements that already show millisecond
  aggregates.

## Consequences

- `Cargo.lock` grows; the bundled SQLite amalgamation is compiled by `cc`. The
  build cost is accepted, and the crate remains buildable offline.
- Schema migrations become an obligation: a `schema_version` table, forward-only
  migrations applied on open, and a refusal to open a database written by a newer
  schema rather than a silent reinterpretation.
- Write concurrency: one writer at a time, WAL enabled for concurrent readers.
  The crawl writes once per phase rather than once per page.
- Observation identity, provenance, completeness and retention semantics remain
  exactly as ADR 0028 and ADR 0017 define them. Storage changes where evidence
  lives, not what it means.
- Response bodies are still not retained by default. The store records
  observations, not page archives.
- The spike harness stays in the repository as an ignored test so the decision can
  be re-measured rather than re-argued.
