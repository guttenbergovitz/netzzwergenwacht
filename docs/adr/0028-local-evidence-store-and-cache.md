# 0028. Local Evidence Store and Cache

## Status

Accepted — 2026-11-27

## Context

The only durable evidence today is append-only JSONL of `AuditReport`, one line per run, loaded
whole. That is adequate for regression diffs between two reports and nothing else. It cannot
answer "which pages share this stylesheet", cannot retain a resource body for re-analysis, cannot
distinguish a fresh observation from a reused one, and cannot be queried without deserialising
everything.

The directive requires an application-wide evidence store. The question is which one.

## Decision

Introduce a local evidence store, and decide the storage technology on evidence rather than
familiarity.

**Storage technology: SQLite via a pure-Rust embedded binding, adopted only if the spike in
Wave TA-2 confirms the required properties.** The store must satisfy all of the following:

- Embedded, no server process, single-file, created on demand.
- Supports the queries this product actually needs: per-page lookup, per-resource reverse lookup,
  per-run listing, range scans by timestamp and severity, bounded aggregation.
- Transactional writes with a clear boundary per capture.
- Schema migration with an explicit version recorded in the file.
- Concurrent readers with a single writer, or serialised writes through one owner task.
- Pure Rust or vendored C, so `cargo build --locked` remains the only build requirement.

If the spike shows that a SQLite binding cannot meet latency or dependency constraints, the
fallback is a set of typed append-only segment files with an in-memory index rebuilt on open.
That fallback is strictly worse for ad-hoc queries and is recorded here so the choice is not
silently re-litigated.

### Data model

The conceptual entities are `application`, `run`, `page`, `resource`, `capture`, `observation`,
`relationship`, `finding`, `coverage_record`. The physical schema reuses the existing typed Rust
contracts (`EvidenceSnapshot`, `AuditReport`, `AnalyserResult`, `Finding`, resource observations)
rather than inventing parallel types.

### Observation identity and provenance

Every retained observation records: application identity, run identity, target URL or resource
identity, capture timestamp, collector identity, collector version, observation schema version,
execution profile, browser context where applicable, acquisition outcome, completeness, and the
identity of any source observation from which it was derived. Derived observations additionally
record their derivation method.

Absence of evidence remains absence. A missing observation is stored as missing, never as zero,
false or an empty inventory. ADR 0016 and ADRs 0017–0021 govern the representation.

### Cache

Four distinct things, never conflated:

| Layer | Content | Mutability |
| --- | --- | --- |
| HTTP representation cache | Status, headers, content hash, optionally a redacted body | Mutable, expiring |
| Resource content cache | Resource body or its hash plus metadata | Mutable, expiring |
| Parsed observation cache | Typed observations derived from a capture | Derived, invalidated by collector version |
| Historical evidence store | Immutable captures and their findings | Append-only |

Cache eligibility is a key, not a guess: normalised URL, method, representation-relevant request
headers, authentication context, cookie context, `Vary` semantics, execution profile, content
hash, collector version and observation schema version. An observation made under one profile
never substitutes for another.

Freshness follows HTTP semantics where available: `Cache-Control`, `Expires`, `ETag`,
`Last-Modified`. Conditional validation is preferred over refetching. When validation is
impossible, the reuse is recorded as stale reuse with its reason; `no-store` responses are never
retained.

### Retention

Bounded by default: a configurable number of runs and a configurable size ceiling per
application. Response bodies are not retained by default; a body is retained only when the
operator opts in, and then only after redaction. Sensitive material — credentials, session
tokens, `Set-Cookie` values — is never written.

### Operations

Fresh reconnaissance, cached reconnaissance, conditional refresh, explicit cache bypass, cache
inspection, cache statistics, invalidation and cleanup are first-class operations, not debugging
shortcuts.

## Alternatives considered

**Keep JSONL and add an index.** Rejected as the primary store: append-only lines cannot express
resource relationships or bounded aggregation without loading everything, and every query becomes
a linear scan.

**Embed an external database server (PostgreSQL).** Rejected: contradicts local-first operation
and adds an operational dependency for a desktop and CI tool.

**Full graph database.** Rejected: the relationship set is small and typed. A relational or
segment store satisfies it; a graph engine adds a query language and a dependency for no
demonstrated query.

**Retain raw HTML by default.** Rejected: it is the largest and most sensitive artefact. Bodies
are opt-in and redacted.

## Consequences

- `nzw` gains cache and evidence-store commands in Wave TA-7.
- Reports record whether each observation was fresh or reused, so a finding never implies a
  network request that did not happen.
- Re-analysis without acquisition becomes possible: rules can run against retained evidence when
  their prerequisites are compatible.
- Tests must cover hit, miss, stale, conditional validation, changed representation, incompatible
  profile, collector version change, transaction failure, migration and retention cleanup.
