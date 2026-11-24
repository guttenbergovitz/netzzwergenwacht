# Intelligence Layer (`KommandantZwerg`)

> **Status**: Planned for Phase 4 (optional; core auditing has zero AI dependencies).

The **Intelligence Layer** preserves the **KommandantZwerg** identity for optional, post-analysis AI synthesis using **Rig (`rig-core`)**, subject to a Phase 4 technical spike.

Meanwhile, **DokumentationsZwerg** belongs to the deterministic reporting layer (with optional AI-assisted narrative synthesis in Phase 4) and operates independently of LLMs.

## 1. Strict Boundaries

- **Non-Authoritative**: `KommandantZwerg` must never fabricate measurements, override deterministic findings, or claim verified compliance. All AI outputs are tagged `FindingKind::AiInterpretation`.
- **Single-Pipeline First**: Do not recreate the Python CrewAI multi-agent hierarchy unless benchmarks demonstrate measurable quality gains over a simpler structured synthesis pipeline.
- **Typed Tooling Only**: Any agent-triggered diagnostic follow-up must invoke typed, explicitly authorised tools governed by `ExecutionBudget`.
- **Token & Cost Budgets**: Every LLM call enforces `max_tokens`, `max_requests`, and timeout budgets.

## 2. Prompt-Injection Defence

Externally collected HTML, titles, meta tags, headers, and console logs are **untrusted data**. Before passing evidence summaries to an LLM:
- Separate system instructions from untrusted evidence payloads using explicit structured delimiters.
- Never allow untrusted page text to authorise active scans or external network calls.
