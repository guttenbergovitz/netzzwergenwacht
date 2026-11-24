# Original Agentic Vision (`./legacy` Recovery)

## 1. Purpose of This Document

Before extending `NetzZwergenWacht` with autonomous investigation capabilities, we inspected the frozen Python prototype under `legacy/src/netzzwergenwacht/agents/` (`kommander_zwerg.py`, `working_autonomous_crew.py`, `autonomous_communication.py`, and specialist agent wrappers) and reconciled its intent with the deterministic Rust core.

## 2. What the Python Prototype Got Right (Retain)

1. **The Virtual Brigade Identity**:
   - `KommanderZwergAgent` acted as a strategic coordinator leading specialist dwarfs (`SicherheitsZwerg`, `LeistungsZwerg`, `ZugaenglichkeitsZwerg`, `SEOZwerg`, `InhaltZwerg`, `VisualZwerg`, `WebBrowserZwerg`) and `DokumentalistZwergAgent`.
   - The core product premise was **not** a raw scanner CLI; it was an on-demand diagnostic team translating technical observations into stakeholder decisions.
2. **Delegated Investigation Tasks**:
   - `KommanderZwergAgent.analyze_initial_findings` inspected initial reconnaissance data and generated `InvestigationTask` assignments for relevant specialists when critical issues were detected.
3. **Structured Cross-Agent Intent**:
   - `autonomous_communication.py` modelled `MessageType` (`REPORT`, `REQUEST`, `SUGGESTION`, `DELEGATION`, `COLLABORATION`, `SUMMARY`) and `Priority` levels to coordinate findings across domains.

## 3. What Was Architecturally Flawed (Redesign / Reject)

| Legacy Concept | Observed Behaviour in `./legacy` | Decision | Rust Target Design |
|---|---|---|---|
| **CrewAI 9-Agent Loop** | `WorkingAutonomousCrew` instantiated 9 heavyweight CrewAI/LangChain `Agent` objects (~260 transitive packages) | **Reject** | Use a single hierarchical orchestrator (`KommandantZwerg`) invoking typed diagnostic tools and focused specialist capabilities only when needed. |
| **Print-Based Communication Hub** | `AgentCommunicationHub` printed emoji-formatted strings (`"Jawohl!"`, `"Code Crimson"`) to stdout | **Reject** | Exchange structured observations through a typed `InvestigationContext` stored in memory and serialised cleanly. |
| **Post-Scan Prose Wrapping** | Legacy agents mostly summarised pre-collected dictionaries rather than formulating falsifiable hypotheses and requesting targeted follow-up diagnostics | **Redesign** | Implement an explicit `DiagnosticHypothesis` -> typed tool invocation -> `HypothesisEvaluation` loop. |
| **Unbounded Execution** | No token/request/time budget ledger; `asyncio.gather` without semaphores or SSRF/payload caps | **Redesign** | Enforce `ExecutionBudget` / `InvestigationBudget` outside the LLM. |
| **LLM-Adjacent Measurements** | Static heuristics claimed WCAG/EAA compliance and mixed prose with raw facts | **Reject** | Keep deterministic collection/analysis strictly separated from `FindingKind::AiInterpretation` and `DiagnosticHypothesis`. |
