# Architecture Overview

> **Status**: Target Architecture (Phase 0 design; Phase 1 implementation pending).

NetzZwergenWacht (NZW) is redesigned as an **evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis**.

## 1. Pipeline Overview

```text
CLI / Configuration
        |
Audit Orchestrator
        |
Collection Engine
        |
Shared Evidence Snapshot
        |
Deterministic Analysers (Zwerge)
        |
Normalised Findings
        |
Evidence Persistence (JSONL)
        |
Optional AI Intelligence (Rig)
        |
Reports / Export / Regression Analysis
```

## 2. Core Architectural Boundaries

1. **Collection vs. Analysis Separation**:
   - Only the **Collection Engine** performs network I/O, TLS handshakes, browser sessions, and external tool invocations.
   - **Deterministic Analysers** are pure, offline functions over an immutable `EvidenceSnapshot` and explicit `AuditConfig`.
2. **Evidence First**:
   - Every finding links to an `EvidenceRef` inside the `EvidenceSnapshot`.
   - Failed or skipped collections produce typed `MeasurementStatus::Failed` / `Unavailable` / `Skipped` records—never synthetic zeros.
3. **Deterministic Core, Optional AI**:
   - All core auditing, reporting, and regression diffing work without any LLM provider or API key.
   - AI intelligence is a post-analysis consumer of normalised findings and redacted evidence summaries.
4. **Resource Governance**:
   - Every stage operates under explicit `ExecutionBudget` limits (concurrency, wall-clock timeout, response bytes, browser sessions, LLM tokens).
5. **Zwerg Identity**:
   - German-named Zwerg domains (`SicherheitsZwerg`, `LeistungsZwerg`, `ZugaenglichkeitsZwerg`, `SEOZwerg`, `InhaltZwerg`, `VisualZwerg`, `WebBrowserZwerg`) are preserved as logical analyser modules where they clarify domain ownership without obscuring technical contracts.
