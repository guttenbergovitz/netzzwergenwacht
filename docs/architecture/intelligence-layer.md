# Intelligence Layer

> **Status**: Planned for Phase 4 (optional; core auditing has zero AI dependencies).

The **Intelligence Layer** provides optional, post-analysis AI synthesis using **Rig (`rig-core`)**, subject to a Phase 4 technical spike validating its API and provider ergonomics.

## 1. Strict Boundaries

- **Non-Authoritative**: AI agents must never fabricate measurements, override deterministic findings, or claim verified compliance. All AI outputs are tagged `FindingKind::AiInterpretation`.
- **Single-Pipeline First**: Do not recreate the Python CrewAI multi-agent hierarchy (`KommanderZwerg`, `DokumentalistZwerg`, 7 wrappers) unless benchmarks demonstrate measurable quality gains over a simpler structured synthesis pipeline.
- **Typed Tooling Only**: Any agent-triggered diagnostic follow-up must invoke typed, explicitly authorised tools governed by `ExecutionBudget`.
- **Token & Cost Budgets**: Every LLM call enforces `max_tokens`, `max_requests`, and timeout budgets.

## 2. Responsibilities

- Cross-domain finding correlation (e.g. CSP headers impacting third-party scripts/performance).
- Risk interpretation and prioritisation in business/technical terms.
- Concrete remediation suggestions grounded in `EvidenceRef`s.
- Regression narrative across persisted audit runs.
- Executive and technical report summaries.

## 3. Prompt-Injection Defence

Externally collected HTML, titles, meta tags, headers, and console logs are **untrusted data**. Before passing evidence summaries to an LLM:
- Strip or escape control/instruction patterns where appropriate.
- Separate system instructions from untrusted evidence payloads using explicit structured delimiters.
- Never allow untrusted page text to authorise active scans or external network calls.
