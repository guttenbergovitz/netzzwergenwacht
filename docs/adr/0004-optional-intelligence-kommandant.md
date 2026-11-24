# ADR 0004: Optional Intelligence Layer (`KommandantZwerg`)

- **Status**: Accepted
- **Date**: 2026-11-24

## Context

`NetzZwergenWacht` preserves the **KommandantZwerg** identity for optional, post-analysis AI synthesis (`docs/architecture/intelligence-layer.md`). Phase 1–3 established a strictly deterministic core with zero AI dependencies. For Phase 4, we need optional cross-domain correlation and prioritised remediation while keeping the binary lean, offline-testable, and free of CrewAI-style multi-agent complexity.

## Decision

1. **Provider-Independent Trait (`LlmProvider`) + Minimal HTTP Client**:
   - Rather than pulling in a large orchestration framework, `src/intelligence/mod.rs` defines a small `LlmProvider` trait and an `OpenAiCompatibleProvider` backed by the existing `reqwest` (`rustls`, `.no_proxy()`) and `serde_json` dependencies.
   - This supports OpenAI-compatible endpoints (`NZW_LLM_API_KEY`, `NZW_LLM_BASE_URL`, `NZW_LLM_MODEL`) with zero additional crate dependencies and enables deterministic unit tests via mock providers.
2. **Non-Authoritative Contract**:
   - `KommandantZwerg` consumes `&AuditReport` after deterministic analysers finish. It never modifies deterministic `Finding`s, never invents measurements, and tags all generated correlation findings as `FindingKind::AiInterpretation`.
3. **Budget & Prompt-Injection Guardrails**:
   - Every invocation is bounded by `LlmBudget` (`max_tokens`, `max_requests`, `timeout`).
   - External page data (titles, URLs, error excerpts) is treated as untrusted data: `build_sanitised_prompt` truncates excerpts, escapes delimiter tags, and wraps the payload in `<untrusted_audit_evidence>` tags separated from system instructions.

## Consequences

- `nzw check` remains 100% deterministic and key-free by default; `--ai` is strictly opt-in.
- If `--ai` is requested without `NZW_LLM_API_KEY` or if the LLM endpoint fails, the deterministic audit report and exit code are preserved and a diagnostic warning is emitted to `stderr`.
