# Execution and Resource Model

> **Status**: Target Design (Phase 1 HTTP budgets; Phase 2 browser/tool budgets; Phase 5 hardening).

All execution in NetzZwergenWacht is governed by explicit `ExecutionBudget` constraints and Tokio structured concurrency.

## 1. Resource Budgets

| Resource | Budget Control | Default Policy (Target) |
|---|---|---|
| HTTP requests | Concurrency semaphore, per-request timeout, max redirects | Bounded per target; explicit redirect cap |
| Response payload | Streaming byte cap (`max_response_bytes`) | Truncate/abort with `Partial` or `Failed` status |
| Browser sessions | Dedicated semaphore, navigation & script timeouts | Max 1–2 concurrent Chromium contexts |
| External tools | Subprocess timeout, stdout/stderr byte cap | Kill on timeout; record `Failed` |
| Audit wall-clock | Top-level `tokio::time::timeout` + `CancellationToken` | Graceful partial report on timeout/Ctrl-C |
| Retries | Bounded exponential backoff on transient transport errors | Never retry 4xx or non-idempotent actions |
| LLM usage (Phase 4) | Max requests, max input/output tokens, cost cap | Skip synthesis cleanly if budget exceeded |

## 2. Cancellation & Graceful Degradation

- A shared `CancellationToken` propagates shutdown across collectors and external subprocesses.
- If a secondary collector (e.g. Lighthouse) times out or is unavailable, the audit completes with `AuditLifecycleState::Partial` and records the exact failure in the report rather than discarding already-collected deterministic findings.
