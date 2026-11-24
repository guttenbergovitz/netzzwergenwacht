# 0007. Autonomous Web Quality Patrol Architecture

## Status

Accepted

## Context

`nzw check` and `nzw investigate` assume a human operator manually commissions each audit or supplies an explicit investigation objective. Overloaded Product Owners, Project Managers, and CTOs need recurring, low-supervision visibility into application quality without re-explaining how to inspect a site on every run.

We need an autonomous patrol lifecycle that:
1. Learns application topology (origins, locales, page types, structural template families).
2. Persists structured institutional memory across patrols without growing an unbounded LLM chat transcript.
3. Plans stratified, budget-aware sampling with explicit selection reasons and evidence reuse for unchanged healthy pages.
4. Escalates only material anomalies to agentic specialist investigation.

## Decision

Introduce a modular `patrol` subsystem (`src/patrol/`) alongside extended `discovery` cartography:

1. **Patrol Lifecycle**: Target validation -> Application cartography (sitemap/sitemap-index + link discovery + locale & template fingerprinting) -> Historical memory retrieval -> Stratified `SamplingPlan` -> Broad Level 1 deterministic checks (with reuse of unchanged healthy page observations) -> Deterministic `PatrolAnomaly` detection -> Selective `KommandantZwerg` / specialist escalation -> Historical comparison -> Change-oriented `PatrolReport` -> Memory update.
2. **Institutional Memory**: Persist structured `ApplicationMemory` per canonical `Origin` (`ApplicationId`) as versioned JSON (`<memory_dir>/<app_id>.json`) for this vertical slice, keeping JSON/JSONL interchange intact. Scaling to large multi-application portfolios with indexed queries will be evaluated against SQLite in a dedicated follow-up ADR before portfolio scheduling is enabled.
3. **Honest Coverage & Quiet Patrols**: `PatrolReport` separates execution status from application quality, records `SelectionReason` for every sampled URL, tracks `reused_page_count`, and produces concise change-oriented summaries when no material anomalies occur.

## Consequences

- Subsequent patrols of the same application avoid redundant deep work on unchanged healthy pages while maintaining rotating exploration and immediate re-checks on previously defective or changed pages.
- Deterministic checks remain the zero-LLM foundation; LLM tokens are spent only when anomalies warrant specialist reasoning.
- Local JSON memory files are human-inspectable and zero-dependency, at the trade-off of whole-file read/write per patrol until SQLite is introduced.
