# ADR 0005: Agentic Investigation Architecture & Rig Evaluation

- **Status**: Accepted (Amends [ADR 0004](0004-optional-intelligence-kommandant.md))
- **Date**: 2026-11-24

## 1. Context

ADR 0004 introduced `src/intelligence/mod.rs` as a minimal post-analysis OpenAI-compatible summary generator. Re-evaluating the original product vision (`docs/migration/original-agentic-vision.md`) and competitive landscape (`docs/product/competitive-landscape.md`) confirmed that post-audit summarisation is too narrow: `NetzZwergenWacht` is an **agentic web quality investigation system** where `KommandantZwerg` plans investigations, invokes typed diagnostic tools, formulates falsifiable hypotheses, requests targeted follow-up evidence, and evaluates competing explanations.

## 2. Rig (`rig-core` / `rig`) Technical Evaluation

We evaluated the current `rig-core` (v0.46.0) / `rig` architecture against our requirements:

- **Strengths**:
  - Clean `rig_core::tool::Tool` trait (`NAME`, `Args: Deserialize`, `Output`, `Error`, `parameters()` via `schemars`, `call(&self, &mut ToolContext, Args)`).
  - Unified multi-provider abstraction (`OpenAI`, `Anthropic`, `Ollama`, etc.) and `AgentBuilder` multi-turn tool loop.
- **Current Constraints & Gaps for NZW**:
  - `rig-core` is not in the offline build cache of the current environment, and NZW requires strict external budget enforcement (`BudgetLedger` across wall-clock time, tool calls, and tokens), serialisable `InvestigationState`, explicit `DiagnosticHypothesis` lifecycle (`Proposed` -> `Supported` / `Rejected` / `Inconclusive`), and deterministic offline testing with mock providers.
  - Therefore, we define NZW's **domain-owned** `InvestigationContext`, `DiagnosticTool` trait, `DiagnosticHypothesis`, and `KommandantOrchestrator` in `src/investigation/` first, designed to be **Rig-compatible** (matching `Tool` + `schemars` parameter schemas and provider-agnostic completion) so `rig-core` can be plugged in as a backend adapter once network/CI crate resolution is approved.

## 3. Architectural Decision

1. **Hierarchical Orchestrator, Not a 9-Agent Chat Swarm**:
   - `KommandantZwerg` drives a bounded investigation state machine (`Requested -> Scoped -> Planned -> Investigating -> Evaluating -> Reporting -> Completed | PartiallyCompleted | BudgetExhausted | Cancelled | Failed`).
   - Deterministic analysers (`NetzZwerg`, `SicherheitsZwerg`, `LeistungsZwerg`, `StrukturZwerg`, `ZugänglichkeitsZwerg`, `SuchZwerg`, `InhaltsZwerg`, `BrowserZwerg`, `GestaltungsZwerg`) remain pure functions over `&EvidenceSnapshot`, exposed to the orchestrator through explicitly authorised, typed `DiagnosticTool` wrappers.
2. **Hypothesis-Driven Loop**:
   - Every follow-up diagnostic action is justified by a `DiagnosticHypothesis` recorded in `InvestigationContext`, and evaluated against newly gathered evidence (supporting, rejecting, or leaving the hypothesis inconclusive).
3. **Strict Separation of Authority**:
   - AI reasoning never modifies deterministic `Finding`s, never bypasses `TargetPolicy` or `ExecutionBudget`, and never fabricates measurements.

## 4. Consequences

- The existing `OpenAiCompatibleProvider` in `src/intelligence/mod.rs` remains useful for simple single-shot `--ai` synthesis, while `src/investigation/` provides the typed agentic investigation domain and orchestrator loop.
- Rig (`rig-core`) adoption as an optional backend crate is deferred to a dedicated online dependency-addition step after the domain loop is proven with mock providers.
