# 0008. Rig and NetzZwergenWacht Responsibility Boundary

## Status

Accepted

## Context

`rig-core` (v0.42.0) provides provider-agnostic LLM completions, typed `PortableTool` / `Tool` definitions, and multi-turn agentic reasoning primitives. Without an explicit boundary, agent frameworks tend to absorb security policy, budget enforcement, or authoritative finding state.

## Decision

Partition responsibilities strictly between `rig-core` and NetzZwergenWacht (`nzw`):

### Responsibilities Owned by Rig
- Provider abstraction and chat-completion transport.
- Typed diagnostic tool schemas (`PortableTool`) exposed to `KommandantZwerg` and specialist dwarfs.
- Multi-turn hypothesis formulation, tool selection, and structured reasoning outputs.

### Responsibilities Owned by NetzZwergenWacht
- Application identity (`ApplicationId`), `Origin`, and `InvestigationScope` enforcement.
- `TargetPolicy` (SSRF protection, private/loopback IP blocking, browser/subresource egress rules).
- `ExecutionBudget` and `BudgetLedger` enforcement outside the LLM (tool call caps, LLM turn caps, wall-clock deadlines, payload caps).
- Evidence integrity (`Measurement<T>`, `CollectorOutcome<T>`, `EvidenceRef`, `FindingFingerprint`).
- Institutional `ApplicationMemory`, historical comparability, `PolicyConfig` gates, and versioned `PatrolReport` / `AuditReport` contracts.

Prompts are guidance, not security boundaries. Every tool invocation and scope check is enforced in Rust before any network or subprocess action occurs.

## Consequences

- Model outputs cannot expand target scope, bypass `TargetPolicy`, or fabricate passing measurements.
- `DiagnosticBackend` and `LlmProvider` remain testable with deterministic mock providers while `rig-core` `PortableTool` schemas stay identical to production tool definitions.
