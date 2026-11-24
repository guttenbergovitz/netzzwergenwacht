# Domain Model

> **Status**: Target Design (initial core types established in `src/domain.rs`).

The Rust domain model replaces Python's untyped `dict` payloads and dual `Issue`/`DetailedIssue` classes with explicit algebraic types.

## 1. Core Types

- **`AuditTarget`**: Validated external target (`http`/`https` URL, canonicalised host, port, scheme, and authorisation policy flag for active checks).
- **`AuditId` / `AuditRun`**: Unique run identifier, UTC timestamp, engine version, and active `AuditProfile` (`Core`, `Standard`, `Full`).
- **`ExecutionBudget`**: Explicit resource limits (HTTP timeout, max redirects, max response bytes, max concurrency, browser timeout, optional LLM token budget).
- **`AuditLifecycleState`**: `Pending` -> `Collecting` -> `Analysing` -> `Persisting` -> `Synthesising` -> `Completed` | `Partial` | `Failed` | `Cancelled`.
- **`RuleId`**: Strongly typed identifier (e.g. `RuleId("sec.headers.hsts")`) paired with `RuleVersion` for deterministic reproducibility.
- **`FindingCategory`**: `Reliability`, `Security`, `Performance`, `Accessibility`, `Seo`, `Content`, `Visual`.
- **`FindingKind`**:
  - `Deterministic` (verified by exact rule over captured evidence)
  - `Heuristic` (pattern/threshold indicator with documented assumptions)
  - `Inferred` (cross-domain correlation)
  - `AiInterpretation` (LLM-generated synthesis; never authoritative)
- **`Severity`**: `Critical`, `High`, `Medium`, `Low`, `Info`.
- **`Confidence`**: `High`, `Medium`, `Low`.
- **`Finding`**: Normalised finding with `RuleId`, `FindingCategory`, `FindingKind`, `Severity`, `Confidence`, `title`, `summary`, `evidence_refs: Vec<EvidenceRef>`, `fingerprint: FindingFingerprint`, and optional `remediation`.
- **`Measurement<T>`**: `Measured { value: T, unit: Unit, provenance: Provenance }` | `Unavailable { reason: String }` | `Failed { error: String }` | `Skipped { reason: String }`.

## 2. Invariants

- An `AuditTarget` cannot be constructed from an invalid or unsupported URL scheme.
- A `Finding` must reference at least one `EvidenceRef` or explicitly record why no evidence was required.
- `Measurement<T>` prevents representing a failed measurement as `0`.
