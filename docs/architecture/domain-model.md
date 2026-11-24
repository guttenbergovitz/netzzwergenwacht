# Domain Model

> **Status**: Implemented in `src/domain.rs` and `src/brigade.rs` (Phase 1 core contracts).

The Rust domain model replaces Python's untyped `dict` payloads and dual `Issue`/`DetailedIssue` classes with explicit algebraic types.

## 1. Core Types

- **`AuditTarget` & `TargetPolicy`**: Validated external target (`http`/`https`, canonicalised host, port, no embedded credentials, SSRF IP guardrails under `TargetPolicy::PublicOnly`). Custom `Deserialize` validates invariants on deserialisation.
- **`ExecutionBudget`**: Explicit resource limits (`audit_timeout` end-to-end deadline including DNS/redirects, `http_timeout`, `max_redirects`, `max_response_bytes`, `max_concurrency`).
- **`DwarfId` & `DwarfProfile`**: Central typed identity registry (`src/brigade.rs`) separating German display names and character descriptions from analytical logic.
- **`EvidenceLevel`**: `Source` (Level 1), `Rendered` (Level 2), `Behavioural` (Level 3).
- **`RuleId`**: Strongly typed identifier (e.g. `RuleId("sec.headers.hsts")`).
- **`FindingCategory`**: `Reliability`, `Security`, `Performance`, `Semantics`, `Accessibility`, `Seo`, `Content`, `Visual`, `Browser`.
- **`FindingKind`**: `Deterministic`, `Heuristic`, `Inferred`, `AiInterpretation`.
- **`Severity`**: `Critical`, `High`, `Medium`, `Low`, `Info`.
- **`Confidence`**: `High`, `Medium`, `Low`.
- **`MeasurementUnit` & `Measurement<T>`**: Typed units (`Milliseconds`, `Bytes`, `Count`) and `Measured` | `Unavailable` | `Failed` | `Skipped` states preventing silent `0` coercion.
- **`EvidenceSource` & `EvidenceRef`**: Typed snapshot source location (`HttpStatus`, `HttpFinalUrl`, `HttpRedirectChain`, `HttpHeaders`, `HttpTiming`, `HttpBody`) paired with observed detail.
- **`Finding` & `CheckStatus`**: Normalised findings with mandatory `evidence_refs` and per-rule execution statuses (`Passed`, `Failed`, `Skipped`, `Unavailable`).

## 2. Invariants

- An `AuditTarget` cannot be constructed or deserialised from an invalid URL, unsupported scheme, or embedded credentials.
- Every `Finding` emitted by an analyser references at least one `EvidenceRef` (verified by contract tests).
- `Measurement<T>` prevents representing a failed or unavailable measurement as `0`.
