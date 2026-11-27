# 0030. Application-Wide Evidence Querying

## Status

Accepted — 2026-11-27

## Context

The Evidence Query Engine is a genuine asset: 21+ typed, paginated, offline queries over a single
`EvidenceSnapshot`, with citation validation and status preservation. Its limitation is its input.
An agent can inspect one page thoroughly and cannot ask a single question about an application.

The workaround in use — putting a compact JSON context into a prompt — does not scale, leaks page
detail into prompts, and cannot be paginated.

## Decision

Extend the query engine from snapshot scope to application scope without replacing it.

- **Two scopes, one vocabulary.** The existing snapshot queries remain as they are. Application
  queries are added over the evidence store. Both return the same `EvidenceQueryStatus`, both are
  paginated with the same page size, both validate citations.
- **Typed tools, bounded output.** No query returns an unbounded list, and no query returns the
  whole store. Result size limits are part of the tool contract, not a caller courtesy.
- **Aggregation is explicit.** A query that aggregates states its population, its denominator and
  its missing-value count. A percentage whose denominator includes unknown values is not
  produced.
- **Citation integrity.** A citation names an observation that exists in the relevant scope,
  belongs to the relevant run, was actually exposed to the consumer and supports the observation
  family being cited. Existence alone is not support; hypothesis evaluation keeps that
  distinction.
- **Selectors.** Queries accept page, route-family, template, locale, resource, severity, domain
  and time selectors. Unknown selectors are errors, not silent empty results.
- **Historical comparison.** Capture comparison compares compatible captures only: same
  observation family, compatible collector and schema versions, compatible execution profile.
  Incompatible captures report `NotComparable` with the reason.
- **Query budgets.** Queries are cheap but not free. They carry a budget for result count,
  aggregation work and wall time, and a query that exceeds it reports truncation rather than
  silently returning a prefix.

### Query catalogue

The catalogue is reconciled with existing tool identifiers rather than duplicated: an existing
snapshot tool keeps its name and gains no shadow. New application-scope tools are added only for
evidence that cannot be expressed over one snapshot, such as crawl coverage, page families,
resource dependents, systemic findings, distributions, outliers, locale inconsistencies and
historical comparison.

## Alternatives considered

**Send a serialised application summary to the model and let it reason over text.** Rejected:
unbounded prompt size, no pagination, no citation validation, and it invites the model to invent
detail that was never observed.

**Let agents write SQL.** Rejected: untyped, unbounded, unauditable, and it exposes the schema as
a public contract accidentally.

**A separate agent-only API.** Rejected: it duplicates the query engine and would drift from the
one the workbench uses.

## Consequences

- The investigation prompt carries a prioritised reconnaissance summary plus tool descriptions,
  never raw evidence.
- Every agent-facing query must be usable offline against retained evidence, and must work when
  the run that produced the evidence has finished.
- Tests must cover pagination, invalid citations, missing evidence, query budget exhaustion and
  provider failure while preserving deterministic results.
