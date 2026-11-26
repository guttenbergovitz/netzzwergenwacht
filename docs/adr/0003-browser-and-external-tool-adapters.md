# 0003. Browser and External Tool Adapters

## Status

Accepted

## Context

Phase 1 established Level 1 (Source) HTTP and HTML5 auditing. Level 2 (Rendered) capabilities—Core Web Vitals, JavaScript console/network errors, rendered-DOM accessibility, and viewport layout integrity—require a real browser engine and established measurement tools (Lighthouse, axe-core, Chromium).

Reimplementing a CSS layout engine, JS runtime, or full WCAG accessibility engine in pure Rust would be brittle and counterproductive.

## Decision

1. **Typed Subprocess Adapter Contracts (`src/adapters/`)**:
   - External tools (Lighthouse, Chromium, axe-core) are invoked as bounded subprocesses behind typed adapter contracts (`CollectorOutcome<LighthouseMetrics>`, `CollectorOutcome<BrowserEvidence>`, `CollectorOutcome<AxeEvidence>`).
   - Every adapter records tool version and execution status, enforces `tokio::time::timeout` and `kill_on_drop(true)`, and never fails the core audit if the external binary is absent (`CollectorOutcome::Unavailable` / `Skipped`).
2. **Opt-In Execution**:
   - `nzw check` remains HTTP-only (Level 1) by default; Level 2 adapters are opt-in (e.g. `--lighthouse`).
3. **Pure Deterministic Analysers**:
   - `BrowserZwerg` (`analysis::browser`), `GestaltungsZwerg` (`analysis::visual`), and Level 2 rules in `LeistungsZwerg` and `ZugänglichkeitsZwerg` remain pure functions over `&EvidenceSnapshot`, tested offline with controlled JSON/DOM fixtures.

## Consequences

- **Easier**: Deterministic offline unit testing of all Level 2 analysers; zero mandatory Chromium/Node runtime for core `nzw check`.
- **Harder**: Running Level 2 adapters in production requires `lighthouse` / `chromium` to be available on `PATH`.
- **Trade-offs**: Subprocess invocation has higher per-target startup overhead than an in-process CDP pool, which can be revisited in a future ADR if batch browser throughput requires it.
