# 0017. Observation availability, completeness and heuristic labelling

## Status

Accepted

## Context

ADR 0016 forbids reporting missing evidence as `0`, `false` or an empty collection, but
it does not say how absence, partial coverage and heuristic estimates are represented at
the field, collector and snapshot levels. The codebase consequently mixes conventions:
some fields are `Option<T>`, some carry `*_truncated` flags, some collectors report
`CollectorOutcome`, and a few producers still coerce `null` to `0` before serialisation.

Downstream consumers (analysers, offline queries, prompts, reports, TUI) cannot always
tell a measured zero from an unobserved value, nor an inventory that was inspected and
found empty from one that was never acquired.

## Decision

1. **Field-level absence uses `Option<T>`.** A nullable field means "not observed" or
   "not applicable"; `Some(0)` and `Some(false)` mean an observed zero or negative
   condition. No producer may substitute a numeric or boolean default for absence.
2. **Collector-level absence uses `CollectorOutcome<T>`.** `Captured` and `Partial`
   carry the value; `Failed`, `Skipped` and `Unavailable` explain why no value exists.
   A failed acquisition never becomes an empty `Captured` inventory.
3. **Truncation is recorded per inventory.** A retained-subset inventory is reported as
   `Partial` (or with an explicit `*_truncated` flag), never as a complete inventory.
   An empty inventory is only meaningful when the relevant scope was fully inspected.
4. **Unsupported is distinct from unavailable.** When the instrument cannot produce an
   observation in principle (for example, a browser API absent from the runtime), the
   value stays `None` and the accompanying capability note says "unsupported"; when
   acquisition was possible but did not complete, the collector outcome says `Failed`
   or `Skipped`.
5. **Heuristic observations are labelled as such.** Any value produced by a heuristic
   that is not a direct instrument measurement carries a name that includes the method
   (`heuristic`, `estimated`, `candidate`, `potentially`) or an explicit `*_source`
   field. A heuristic may not be serialised into a field that claims a direct
   measurement.
6. **Derived measurements record their inputs and method.** Where a value is computed
   from other observations (for example a session-window CLS or a summed transfer
   size), the derivation is deterministic and documented, and the value is absent when
   any required input is absent.
7. **Legacy snapshots remain readable.** New optional fields default to absence on
   deserialisation; they are omitted from serialisation when absent so old artefacts
   remain distinguishable from observed empty values.

## Consequences

- Producers must decide the absence representation before adding a field.
- Consumers must render unavailable, partial, unsupported and observed values
  differently; the TUI uses `Unobserved`, `Unsupported`, `Partial` and measured values.
- Some previously non-optional fields become `Option<T>`, which is a breaking change for
  external consumers of the JSON schema but acceptable while the schema is pre-1.0.
- Existing `*_truncated` flags are retained rather than replaced by a second hierarchy.
