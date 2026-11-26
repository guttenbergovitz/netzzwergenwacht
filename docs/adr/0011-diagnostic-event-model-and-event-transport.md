# 0011. Diagnostic Event Model and Event Transport

## Status

Accepted

## Context

Previously, only `src/investigation/events.rs` recorded structured events (`InvestigationEvent`), and only by appending to an in-memory `Vec<InvestigationEvent>` returned after an investigation completed. Collection (`src/collection.rs`), deterministic analysis (`src/analysis/mod.rs`), discovery (`src/discovery/mod.rs`), and patrol (`src/patrol/mod.rs`) had no unified streaming event contract.

Zwergenleitstand requires real-time visibility into collector lifecycles, specialist analyser execution, target discovery, findings, hypothesis evaluation, and resource budget consumption without coupling the diagnostic engine's execution speed to terminal rendering or risking unbounded memory growth.

## Decision

1. **Introduce a unified typed `DiagnosticEvent` contract in `src/events.rs`**:
   - Every event carries:
     - `run_id: RunId` (identifying the diagnostic execution session),
     - `sequence: u64` (monotonically increasing per-run sequence assigned by the emitter),
     - `timestamp_ms: u64` (elapsed milliseconds since run start, plus wall-clock start time on `RunStarted`),
     - `context: EventContext` (`target`, `page`, `collector`, `dwarf`, `operation`),
     - `payload: DiagnosticEventPayload`.
   - `DiagnosticEventPayload` models explicit operational semantics:
     - Run lifecycle: `RunStarted`, `RunCompleted`, `RunPartial`, `RunFailed`, `RunCancelled`.
     - Target surface: `TargetDiscovered`, `TargetQueued`, `TargetStarted`, `TargetCompleted`, `TargetSkipped`, `TargetFailed`.
     - Collection: `CollectionStarted`, `CollectionProgress`, `CollectionCompleted`, `CollectionPartial`, `CollectionFailed`, `CollectionSkipped`.
     - Analysis & observations: `AnalysisStarted`, `AnalysisCompleted`, `ObservationCaptured`, `FindingRecorded`.
     - Agentic investigation: `SpecialistActivated`, `HypothesisProposed`, `HypothesisEvaluationStarted`, `HypothesisEvaluated`, `ToolInvocationStarted`, `ToolInvocationCompleted`, `ToolInvocationRejected`, `ToolInvocationFailed`.
     - Governance: `BudgetUpdated`, `CoverageUpdated`, `Warning`, `Error`.
2. **Bridge existing `InvestigationEvent` values deterministically**:
   - `src/investigation/` continues to record `InvestigationEvent` for audit provenance while also emitting mapped `DiagnosticEvent` items to an optional `DiagnosticEventSink`.
3. **Use bounded MPSC transport (`tokio::sync::mpsc`) with tiered backpressure**:
   - The transport channel has a fixed capacity (default 256 events).
   - **Critical lifecycle and state events** (`Run*`, `CollectionStarted`/`Completed`/`Partial`/`Failed`/`Skipped`, `Analysis*`, `FindingRecorded`, `Hypothesis*`, `ToolInvocation*`) use bounded async delivery with a short timeout fallback so the engine never deadlocks if a consumer stalls.
   - **High-frequency progress events** (`CollectionProgress`, `TargetDiscovered`, `BudgetUpdated`) use non-blocking `try_send`. If the channel is full, the sink increments an explicit `dropped_progress_events` atomic counter surfaced to the consumer on the next delivered event or state tick.
   - The TUI retains a bounded ring buffer (`VecDeque`, capped at 512 recent events) for its activity log while folding authoritative counters and entity states into `AppState`.
4. **Authoritative results never depend on event delivery**:
   - The diagnostic engine returns its authoritative `AuditReport`, `EvidenceSnapshot`, `InvestigationOutcome`, or `PatrolReport` directly upon task completion. Even if progress events are coalesced or dropped under extreme load, final findings and evidence remain complete.

## Consequences

- All diagnostic subsystems can run headlessly with `DiagnosticEventSink::noop()` at near-zero cost or stream structured events to Zwergenleitstand and `--events` CLI consumers.
- Memory consumption is strictly bounded regardless of crawl duration or event frequency.
- Operators see accurate distinction between scheduled, running, completed, partial, skipped, policy-blocked, failed, and cancelled operations.
