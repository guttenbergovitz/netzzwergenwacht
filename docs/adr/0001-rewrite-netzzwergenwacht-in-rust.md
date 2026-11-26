# ADR 0001: Rewrite NetzZwergenWacht in Rust

- **Status**: Accepted
- **Decision Date**: 2026-11-24
- **Branch**: `rewrite/rust` (preserving Python reference on `main`)

---

## 1. Context

NetzZwergenWacht (NZW) began as an experimental Python project for automated website quality analysis, browser automation, and LLM-powered multi-agent reporting using German-named "Zwerge" (dwarfs).

The Python prototype successfully validated the core concept across seven analysis domains (`WebBrowserZwerg`, `SicherheitsZwerg`, `LeistungsZwerg`, `SEOZwerg`, `ZugaenglichkeitsZwerg`, `InhaltZwerg`, `VisualZwerg`), a Typer/Rich CLI, PDF/JSON reporting, and OpenAI/CrewAI integration.

However, extending the Python codebase has hit structural limits. Continuing to build on the prototype would compound architectural debt, duplicate logic, and keep unreliable measurements and heavy AI dependencies entangled with core auditing.

We have decided to redesign and rewrite NetzZwergenWacht in **Rust** as an **evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis**.

This is a deliberate architectural reorientation, not a mechanical translation of Python code or a purely performance-motivated language switch.

---

## 2. Lessons Learned & Identified Limitations in the Python Implementation

Direct inspection of the Python codebase on `main` revealed the following concrete issues:

1. **Duplicated Logic Between Basic and Detailed Analysis Modes**:
   Every dwarf implements parallel `analyze()` (`Issue`) and `analyze_detailed()` (`DetailedIssue`) pipelines. In `src/netzzwergenwacht/dwarfs/zugaenglichkeits_zwerg.py`, this duplication caused method drift where `analyze()` called deleted non-detailed methods and `analyze_detailed()` referenced non-existent `*_detailed` helpers.
2. **Independent Browser Sessions and Repeated Resource Collection**:
   Across the seven dwarfs, `httpx.AsyncClient` is instantiated independently 21 times and `async_playwright()` is launched independently 6 times (`leistungs_zwerg.py`, `web_browser_zwerg.py`, `visual_zwerg.py`). A single `nzw analyze` run repeatedly fetches the same URL and spawns multiple Chromium instances.
3. **Excessively Large Analyser Modules**:
   The seven dwarf files total over 10,700 lines (`zugaenglichkeits_zwerg.py` alone is 2,457 lines; `visual_zwerg.py` is 1,860 lines; `inhalt_zwerg.py` is 1,683 lines), mixing HTTP fetching, HTML parsing, heuristic rules, and reporting data shaping.
4. **Heavy Mandatory AI-Related Dependencies**:
   `pyproject.toml` declares `openai`, `crewai`, `crewai-tools`, `langchain`, and `langchain-openai` as core runtime dependencies, pulling ~260 transitive packages even when running deterministic `nzw check`.
5. **Incomplete Functionality Presented as Implemented**:
   `WebBrowserZwerg._analyze_with_playwright_detailed` attaches `page.on("console", ...)` and `page.on("requestfailed", ...)` *after* `page.goto()` and contains `# TODO: Add more browser-based checks`. Several `agents/` modules were abandoned WiP stubs (`crew_orchestrator.py`, `simple_autonomous_crew.py`, etc., cleaned up prior to this rewrite).
6. **Unreliable or Overly Simplified Performance Measurements**:
   `LeistungsZwerg` measures `time.time()` around `httpx.AsyncClient.get()` as `page_load_time_ms` and samples local host CPU via `psutil.cpu_percent(interval=1)` during external website audits.
7. **Accessibility Heuristics Presented as Compliance Assessments**:
   `ZugaenglichkeitsZwerg` describes itself as *"EU Accessibility Act compliance analysis for WCAG 2.1 AA requirements"* and computes an `eaa_compliance_score` from static BeautifulSoup regex/tag heuristics without rendered DOM or assistive-technology evaluation.
8. **Misleading Aggregate Quality Scores**:
   `DwarfOrchestrator._create_comprehensive_report` (`src/netzzwergenwacht/dwarfs/base.py`) computes `overall_score = sum(scores) / len(scores)` while only reading `performance_metrics.performance_score`, silently ignoring security, accessibility, SEO, content, and visual dimensions.
9. **Insufficient Distinction Between Observations, Findings, and Recommendations**:
   `Issue` and `DetailedIssue` conflate raw observed facts, heuristic thresholds, and remediation advice without explicit provenance, confidence, or measurement-failure semantics (failed checks can silently fall back to `0` or empty dicts).
10. **Lack of Persistent Audit History and Regression Analysis**:
    Results are written as one-off JSON/text/PDF files with no stable finding fingerprints, audit run history, or baseline diffing.
11. **Lack of Clearly Enforced Resource Budgets**:
    `DwarfOrchestrator` runs `asyncio.gather(*tasks, return_exceptions=True)` without concurrency semaphores, global deadlines, response-size caps, or token/cost budgets. `SicherheitsZwerg` invokes `nmap.PortScanner()` without explicit target-authorisation gates.

---

## 3. Reasons for Selecting Rust

The primary motivations are architectural and verification-focused:

- **Stronger Domain Modelling**: Algebraic data types (`enum`, newtypes, `Result`) model validated targets, execution budgets, evidence provenance, measurement units, partial vs. complete results, and explicit failure states.
- **Explicit Contracts and Invariants**: Compile-time type checking prevents silent schema drift between collection, analysis, and reporting layers.
- **Controlled Asynchronous Execution and Concurrency**: Tokio provides structured concurrency primitives (`Semaphore`, `CancellationToken`, `timeout`, bounded channels) to enforce resource budgets.
- **Explicit Error Handling and Failure Propagation**: No uncaught exceptions or silent `0` fallbacks; unavailable measurements are represented as typed `Unavailable` / `Failed` states.
- **Reduced Dependency Footprint & Distribution**: A single compiled core binary without Python runtime or ~260 transitive AI packages; AI/browser capabilities remain strictly optional.
- **Improved Verifiability**: Both human-written and AI-assisted code must satisfy the compiler, `clippy`, and typed contract tests before merging.

Performance improvements over Python are desirable where they occur, but **correctness, reliability, and maintainability are the primary drivers**. We make no unbenchmarked performance claims.

---

## 4. Alternatives Considered

1. **Incremental Refactor in Python (Strict Typing + Modularisation)**:
   - *Rejected*: Retains dynamic runtime semantics, heavy CrewAI/LangChain dependency graph (unless split into multiple packages), and weaker compile-time enforcement against schema/contract drift as the codebase grows.
2. **TypeScript / Node.js Rewrite**:
   - *Rejected*: Natural fit for Playwright/Lighthouse/axe-core, but weaker algebraic modelling than Rust, still requires a JS runtime for distribution, and offers fewer guarantees around memory/response-size governance.
3. **Go Rewrite**:
   - *Rejected*: Strong concurrency and single-binary distribution, but lacks sum types/enums and exhaustive pattern matching needed for rich evidence/provenance domain modelling.

---

## 5. Expected Benefits

- Single shared collection pass producing an immutable `EvidenceSnapshot` consumed by all deterministic analysers.
- Zero mandatory AI dependencies for core auditing.
- Clear separation of observed facts, measured metrics, deterministic rules, heuristics, and AI interpretations.
- Explicit resource budgets (concurrency, timeouts, response size, browser sessions, LLM tokens).
- Persistent audit history (JSONL initially) enabling stable finding fingerprints and regression detection.
- Automated `rustfmt`, `clippy`, unit/integration/fixture tests, and `cargo-audit` quality gates.

---

## 6. Costs, Risks, and Trade-offs

- **Higher Initial Engineering Effort**: Rust's borrow checker and strict type system slow initial prototyping compared to Python.
- **Browser & Standards Ecosystem**: Mature web measurement engines (Chromium, Lighthouse, axe-core) live in the Node.js/Chromium ecosystem; integrating them requires explicit subprocess/CDP adapter contracts rather than native Rust crates.
- **LLM Ecosystem Maturity**: Rust LLM frameworks (e.g., `rig-core`) evolve rapidly and have smaller ecosystems than Python's LangChain/OpenAI SDKs; Rig will be validated via a focused technical spike before full adoption.
- **Dual-Maintenance Window**: The Python implementation remains on `main` as a reference during early phases, so new features must not be added to Python.

---

## 7. Architectural Principles

1. **Evidence First**: Every finding traces to captured evidence. Failed/unavailable measurements never masquerade as `0`. Absence of evidence is not evidence of absence.
2. **Deterministic Core**: Collection and deterministic analysis run offline from AI. Identical snapshots + rule versions + config yield equivalent results.
3. **Type-Driven Architecture**: Explicit domain types over `serde_json::Value` maps and stringly-typed contracts.
4. **Resource Governance**: Bounded concurrency, timeouts, response-size caps, cancellation, and graceful degradation.
5. **Reuse Established Implementations**: Integrate Lighthouse, axe-core, Chromium, and `rustls` behind typed adapter contracts with recorded versions and provenance. Never present automated accessibility checks as proof of legal/WCAG compliance.
6. **Zwerg Identity**: Retain German-named Zwerg domains where they clarify identity without obscuring technical meaning.

---

## 8. Migration Strategy

Incremental vertical slices on `rewrite/rust` (detailed in `docs/migration/rewrite-strategy.md` and `docs/roadmap.md`):

- **Phase 0**: Discovery, capability inventory, ADR, architecture docs, Cargo skeleton & CI gates. *(Current iteration)*
- **Phase 1**: Minimal deterministic core (validated targets, bounded HTTP collection, `EvidenceSnapshot`, basic rules, CLI, JSON output).
- **Phase 2**: Controlled browser automation, Lighthouse & axe-core adapters, domain analysers, fixture validation.
- **Phase 3**: Persistent JSONL audit history, finding fingerprints, regression diffing, quality gates.
- **Phase 4**: Optional intelligence via Rig spike, structured AI correlation/remediation, prompt-injection boundaries, token budgets.
- **Phase 5**: Production hardening, resource benchmarks, chaos/cancellation tests, packaging.

The Python implementation on `main` will not be merged over or deleted until the Rust vertical slices cover the retained core capabilities and `rewrite/rust` is explicitly approved for merge.

---

## 9. Success Criteria

This decision will be considered successful when:

1. A single `nzw` binary performs bounded HTTP + browser collection once per target and produces deterministic, evidence-backed JSON/CLI reports with zero LLM dependencies.
2. Failed/partial collections and external tool errors are surfaced explicitly in typed reports rather than coerced to `0` or omitted.
3. All deterministic analysers pass against controlled offline HTTP/DOM test fixtures.
4. Audit runs can be persisted and diffed by stable finding fingerprints to detect regressions.
5. Optional AI analysis adds value (correlation, remediation, executive/technical synthesis) behind strict token budgets and untrusted-data boundaries without altering deterministic findings.
